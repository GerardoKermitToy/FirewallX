#pragma once

#include <windows.h>
#include "FoldedText.h"
#include "NumericHash.h"
#include "DebugCounters.h"
#include "StorageMaintenance.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pmkext {

#pragma pack(push, 1)
struct ProcessCreated {
    uint64_t pid;
    uint64_t parent_pid;
};

struct ProcessTerminated {
    uint64_t pid;
};
#pragma pack(pop)

static_assert(sizeof(ProcessCreated) == 16, "layout mismatch with info.rs");
static_assert(sizeof(ProcessTerminated) == 8, "layout mismatch with info.rs");
static_assert(alignof(ProcessCreated) == 1, "packing is broken");
static_assert(alignof(ProcessTerminated) == 1, "packing is broken");

using ProcessEventPathRef = std::shared_ptr<const std::wstring>;

// Ключ matcher-а разделяется всеми процессами одного исполняемого файла.
struct ProcessRulePath {
    ProcessEventPathRef text;
    std::wstring folded;
    uint64_t hash;

    explicit ProcessRulePath(std::wstring value)
        : text(std::make_shared<const std::wstring>(std::move(value))),
          folded(FoldCaseCopy(*text)), hash(HashFoldedText(folded)) {}
};
using ProcessRulePathRef = std::shared_ptr<const ProcessRulePath>;

struct ProcessRuleSource {
    uint64_t pid = 0;
    ProcessRulePathRef path;

    explicit operator bool() const { return path != nullptr; }
};

// Создаётся лениво только для pending-запроса. Не удерживает process HANDLE;
// сохраняет родство и кеш предка после удаления узлов из основной таблицы.
struct ProcessLineage {
    uint64_t pid = 0;
    ProcessRulePathRef path;
    std::shared_ptr<ProcessLineage> parent;
    mutable ProcessRuleSource ruleRoot;
    mutable const void* cacheOwner = nullptr;
    mutable uint64_t cacheGeneration = 0;
    mutable uint64_t cacheAncestry = 0;
    mutable uint64_t visited = 0;

    ~ProcessLineage() {
        // Не рекурсивно и без проверки use_count: слабый индекс вправе удержать
        // предка параллельно освобождению pending. Меняем узел только внутри
        // его собственного деструктора, когда weak_ptr уже не может оживить его.
        thread_local std::shared_ptr<ProcessLineage>* releasing = nullptr;
        if (releasing) {
            *releasing = std::move(parent);
            return;
        }
        std::shared_ptr<ProcessLineage> next;
        releasing = &next;
        auto node = std::move(parent);
        while (node) {
            node.reset();
            node = std::move(next);
        }
        releasing = nullptr;
    }
};
using ProcessLineageRef = std::shared_ptr<const ProcessLineage>;

struct ProcessInfo {
    uint64_t pid = 0;
    uint64_t parent_pid = 0;
    ProcessEventPathRef path;
    DWORD path_error = ERROR_NOT_FOUND;
    // Число сохранённых непосредственных ветвей, включая умерших детей
    // с живыми потомками. Ноль позволяет удалить завершённый узел сразу.
    size_t children = 0;
    bool terminated = true;
    // false: родитель известен только из записи ребёнка, собственного события нет.
    bool observed = false;
};

// Таблица обновляется только событиями: таймеров, опроса живости и хранения
// process HANDLE здесь нет. Новый Create после Terminated начинает экземпляр
// PID заново, не меняя родство потомков и pending прежнего экземпляра.
// Все операции потокобезопасны; наружу возвращаются копии с общим неизменяемым
// путём, поэтому удаление процесса не инвалидирует результат find()/snapshot().
class ProcessTable {
public:
    using PathResolver = std::wstring (*)(uint64_t, DWORD&);

    explicit ProcessTable(PathResolver resolver = queryPath) : resolver_(resolver) {}
    ProcessTable(const ProcessTable&) = delete;
    ProcessTable& operator=(const ProcessTable&) = delete;

    // Оконная копия и локальный matcher используют одну таблицу своего процесса.
    static ProcessTable& Instance() {
        static ProcessTable table;
        return table;
    }

    uint64_t version() const { return version_.load(std::memory_order_acquire); }

    bool applyCreated(const ProcessCreated* values, uint32_t count) {
        if (count && !values) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!enabled_) return false;
        bool changed = false;
        for (uint32_t i = 0; i < count; ++i) {
            const auto& value = values[i];
            const auto found = entries_.find(value.pid);
            if (found != entries_.end() && found->second.info.observed) {
                // Дубль живого процесса ничего не меняет и не запрашивает путь.
                if (!found->second.info.terminated) continue;
                // Потомки держат прежний экземпляр, а индекс PID — только новый.
                auto previous = entries_.extract(found);
                previous.key() = ++retiredId_;
                previous.mapped().retiredId = retiredId_;
                // Перенос узла map сохраняет адрес и не выделяет Entry заново.
                retired_.insert(std::move(previous));
            }
            Entry& entry = ensureEntry(value.pid);
            changed = true;
            // Позднее событие placeholder-а меняет происхождение уже известных
            // потомков и сохранённых pending. Новый лист не сбрасывает их кеши.
            if (entry.info.children || entry.lineage) ++ancestryVersion_;
            entry.info.observed = true;
            entry.info.terminated = false;
            entry.info.parent_pid = value.parent_pid;
            lateLineages_.erase(value.pid);
            if (value.pid != value.parent_pid) {
                Entry& parent = ensureEntry(value.parent_pid);
                entry.parent = &parent;
                ++parent.info.children;
            }
            DWORD error = ERROR_NOT_FOUND;
            std::wstring path = resolver_ ? resolver_(value.pid, error) : std::wstring();
            entry.info.path_error = error;
            entry.rulePath = internPath(std::move(path));
            entry.info.path = entry.rulePath ? entry.rulePath->text : nullptr;
            if (entry.lineage) {
                entry.lineage->path = entry.rulePath;
                auto parent = retainLocked(entry.parent);
                bool cycle = false;
                for (auto* node = parent.get(); node; node = node->parent.get())
                    if (node == entry.lineage.get()) { cycle = true; break; }
                if (!cycle) entry.lineage->parent = std::move(parent);
            }
        }
        trimStorageLocked();
        if (changed) ++version_;
        return true;
    }

    bool applyTerminated(const ProcessTerminated* values, uint32_t count) {
        if (count && !values) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!enabled_) return false;
        bool changed = false;
        for (uint32_t i = 0; i < count; ++i) {
            lateLineages_.erase(values[i].pid);
            const auto found = entries_.find(values[i].pid);
            if (found == entries_.end()) continue;
            Entry& entry = found->second;
            changed |= !entry.info.terminated || !entry.info.observed;
            entry.info.observed = true;
            entry.info.terminated = true;
            prune(&entry);
        }
        trimStorageLocked();
        if (changed) ++version_;
        return true;
    }

    bool find(uint64_t pid, ProcessInfo& result) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = entries_.find(pid);
        if (found == entries_.end()) return false;
        result = found->second.info;
        return true;
    }

    ProcessLineageRef retain(uint64_t pid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = entries_.find(pid);
        if (found != entries_.end()) return retainLocked(&found->second);
        if (!enabled_) return {};
        // Сетевое событие может опередить Create. Общий узел будет заполнен
        // самим событием процесса, без сканирования pending в Ingest.
        const auto late = lateLineages_.find(pid);
        if (late != lateLineages_.end()) {
            if (auto node = late->second.lock()) return node;
        }
        auto node = std::make_shared<ProcessLineage>();
        node->pid = pid;
        rememberLate(node);
        return node;
    }

    ProcessRulePathRef rulePath(uint64_t pid, const ProcessLineage* retained = nullptr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        // Pending принадлежит исходному экземпляру, а не новому владельцу PID.
        if (retained) return retained->pid == pid ? retained->path : nullptr;
        const auto found = entries_.find(pid);
        return found == entries_.end() ? nullptr : found->second.rulePath;
    }

    // Предикат читает только готовый ключ пути и вызывается при заполнении кеша.
    // Владелец и его поколение разделяют независимые RuleStore. «Не наследовать»
    // проверяется вызывающим для самого процесса, не обрывая родство его детей.
    template <class Enabled>
    ProcessRuleSource oldestRuleAncestor(uint64_t pid, const void* owner,
                                         uint64_t generation, Enabled&& enabled,
                                         const ProcessLineage* retained = nullptr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = entries_.find(pid);
        if (retained && (found == entries_.end() || found->second.lineage.get() != retained))
            return retainedAncestor(retained, owner, generation, enabled);
        if (found == entries_.end()) return {};
        Entry* node = found->second.parent;
        if (!node) return {};
        const auto cached = [&](const Entry& entry) {
            return entry.cacheOwner == owner && entry.cacheGeneration == generation &&
                   entry.cacheAncestry == ancestryVersion_;
        };
        Entry* root = nullptr;
        if (cached(*node)) {
            root = node->ruleRoot;
        } else {
            std::vector<Entry*> pending;
            while (node && !cached(*node)) {
                // Повреждённое циклическое родство не должно блокировать reader.
                if (pending.size() >= entries_.size() + retired_.size()) return {};
                pending.push_back(node);
                node = node->parent;
            }
            if (node) root = node->ruleRoot;
            for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
                Entry& entry = **it;
                if (!root && entry.info.pid != 0 && entry.info.pid != 4 &&
                    entry.rulePath && enabled(*entry.rulePath))
                    root = &entry;
                entry.ruleRoot = root;
                entry.cacheOwner = owner;
                entry.cacheGeneration = generation;
                entry.cacheAncestry = ancestryVersion_;
            }
        }
        // Предок удерживается деревом до последнего потомка; возвращённый путь
        // остаётся действительным и после удаления всей ветви.
        return root ? ProcessRuleSource{root->info.pid, root->rulePath}
                    : ProcessRuleSource{};
    }

    std::vector<ProcessInfo> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ProcessInfo> result;
        result.reserve(entries_.size());
        for (const auto& item : entries_) result.push_back(item.second.info);
        return result;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    size_t pathCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return paths_.size();
    }

    // Только размеры; занятый мьютекс пропускается без ожидания.
    void ReadDebugCounters(DebugCounters::Snapshot& out) const {
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (!lock.owns_lock()) return;
        auto& v = out.values;
        v[DebugCounters::ProcessEntries] = entries_.size();
        v[DebugCounters::ProcessRetired] = retired_.size();
        v[DebugCounters::ProcessLateLineages] = lateLineages_.size();
        v[DebugCounters::ProcessPaths] = paths_.size();
    }

    // Отключение и очистка используют тот же замок, что и приём пакета:
    // после возврата даже уже начавший обработку reader не заполнит таблицу.
    // Включение также начинает локальное хранение с пустого состояния.
    void setEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = enabled;
        clearLocked();
    }

    bool enabled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enabled_;
    }

    // Фоновая уборка касается только просроченных слабых ссылок. Сведения
    // о процессах по-прежнему меняются исключительно событиями драйвера.
    void maintain() {
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (!lock.owns_lock() || lateLineages_.empty()) return;
        if (GetTickCount64() - lateSweptAt_ >= kLateSweepMs) sweepLateLocked();
    }

    // Только для границы transport-сессии, не для повторного запроса снимка:
    // старые непрочитанные записи драйвер намеренно сохраняет при перезапуске.
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        clearLocked();
    }

private:
    friend struct ProcessTableTestAccess;
    static constexpr size_t kMinLateSweepAdds = 64;
    static constexpr ULONGLONG kLateSweepMs = 5000;

    struct Entry {
        ProcessInfo info;
        uint64_t retiredId = 0;
        Entry* parent = nullptr;
        ProcessRulePathRef rulePath;
        mutable std::shared_ptr<ProcessLineage> lineage;
        mutable Entry* ruleRoot = nullptr;
        mutable const void* cacheOwner = nullptr;
        mutable uint64_t cacheGeneration = 0;
        mutable uint64_t cacheAncestry = 0;
    };
    struct InternedPath {
        ProcessRulePathRef path;
        size_t users;
    };

    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, Entry, NumericIdHash> entries_;
    // Старые экземпляры переносятся сюда без перевыделения памяти и смены адреса.
    std::unordered_map<uint64_t, Entry, NumericIdHash> retired_;
    uint64_t retiredId_ = 0;
    mutable std::unordered_map<uint64_t, std::weak_ptr<ProcessLineage>, NumericIdHash> lateLineages_;
    mutable size_t lateAdds_ = 0;
    mutable size_t lateSweepEvery_ = kMinLateSweepAdds;
    mutable ULONGLONG lateSweptAt_ = 0;
    inline static std::atomic<uint64_t> traversal_{0};
    // Ключ — view в неизменяемую строку значения, второй копии пути в ключе нет.
    std::unordered_map<std::wstring_view, InternedPath> paths_;
    PathResolver resolver_;
    bool enabled_ = true;
    uint64_t ancestryVersion_ = 1;
    std::atomic<uint64_t> version_{1};

    void clearLocked() {
        decltype(entries_){}.swap(entries_);
        decltype(retired_){}.swap(retired_);
        decltype(lateLineages_){}.swap(lateLineages_);
        decltype(paths_){}.swap(paths_);
        lateAdds_ = 0;
        lateSweepEvery_ = kMinLateSweepAdds;
        lateSweptAt_ = 0;
        ++ancestryVersion_;
        ++version_;
    }

    void trimStorageLocked() {
        TrimHashTable(entries_);
        TrimHashTable(retired_);
        TrimHashTable(paths_);
        TrimHashTable(lateLineages_);
    }

    void sweepLateLocked() const {
        for (auto it = lateLineages_.begin(); it != lateLineages_.end();) {
            if (it->second.expired()) it = lateLineages_.erase(it);
            else ++it;
        }
        TrimHashTable(lateLineages_);
        lateAdds_ = 0;
        lateSweepEvery_ = (std::max)(kMinLateSweepAdds, lateLineages_.size());
        lateSweptAt_ = GetTickCount64();
    }

    void rememberLate(const std::shared_ptr<ProcessLineage>& node) const {
        // Бюджет фиксируется после уборки: сравнение с текущим растущим size()
        // могло навсегда отодвигать проход при добавлении новых уникальных PID.
        if (++lateAdds_ >= lateSweepEvery_) sweepLateLocked();
        lateLineages_[node->pid] = node;
    }

    Entry& ensureEntry(uint64_t pid) {
        const auto inserted = entries_.try_emplace(pid);
        if (inserted.second) {
            Entry& entry = inserted.first->second;
            entry.info.pid = pid;
            const auto late = lateLineages_.find(pid);
            if (late != lateLineages_.end()) entry.lineage = late->second.lock();
        }
        return inserted.first->second;
    }

    std::shared_ptr<ProcessLineage> retainLocked(const Entry* entry) const {
        std::vector<const Entry*> pending;
        while (entry && !entry->lineage) {
            if (pending.size() >= entries_.size() + retired_.size()) return {};
            pending.push_back(entry);
            entry = entry->parent;
        }
        auto parent = entry ? entry->lineage : nullptr;
        for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
            auto node = std::make_shared<ProcessLineage>();
            node->pid = (*it)->info.pid;
            node->path = (*it)->rulePath;
            node->parent = std::move(parent);
            const Entry& source = **it;
            if (source.ruleRoot)
                node->ruleRoot = {source.ruleRoot->info.pid, source.ruleRoot->rulePath};
            node->cacheOwner = source.cacheOwner;
            node->cacheGeneration = source.cacheGeneration;
            node->cacheAncestry = source.cacheAncestry;
            (*it)->lineage = node;
            if (!(*it)->info.observed) rememberLate(node);
            parent = std::move(node);
        }
        return parent;
    }

    template <class Enabled>
    ProcessRuleSource retainedAncestor(const ProcessLineage* retained, const void* owner,
                                      uint64_t generation, Enabled& enabled) const {
        const auto cached = [&](const ProcessLineage& node) {
            return node.cacheOwner == owner && node.cacheGeneration == generation &&
                   node.cacheAncestry == ancestryVersion_;
        };
        const ProcessLineage* node = retained->parent.get();
        if (!node) return {};
        if (cached(*node)) return node->ruleRoot;
        std::vector<const ProcessLineage*> pending;
        const uint64_t traversal = ++traversal_;
        while (node && !cached(*node)) {
            if (node->visited == traversal) return {};
            node->visited = traversal;
            pending.push_back(node);
            node = node->parent.get();
        }
        ProcessRuleSource root = node ? node->ruleRoot : ProcessRuleSource{};
        for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
            const ProcessLineage& current = **it;
            if (!root && current.pid != 0 && current.pid != 4 &&
                current.path && enabled(*current.path))
                root = {current.pid, current.path};
            current.ruleRoot = root;
            current.cacheOwner = owner;
            current.cacheGeneration = generation;
            current.cacheAncestry = ancestryVersion_;
        }
        return root;
    }

    ProcessRulePathRef internPath(std::wstring value) {
        if (value.empty()) return {};
        const auto found = paths_.find(value);
        if (found != paths_.end()) {
            ++found->second.users;
            return found->second.path;
        }
        auto path = std::make_shared<const ProcessRulePath>(std::move(value));
        paths_.emplace(std::wstring_view(*path->text), InternedPath{ path, 1 });
        return path;
    }

    void releasePath(const ProcessEventPathRef& text) {
        if (!text) return;
        const auto found = paths_.find(*text);
        if (found != paths_.end() && --found->second.users == 0) paths_.erase(found);
    }

    void prune(Entry* entry) {
        // Каждый узел стирается один раз; нет рекурсии и сканирования списка.
        // Умерший ребёнок с живым внуком удерживает всю цепочку предков.
        while (entry && entry->info.terminated && entry->info.children == 0) {
            Entry* const parent = entry->parent;
            releasePath(entry->info.path);
            const uint64_t pid = entry->info.pid;
            if (entry->retiredId) retired_.erase(entry->retiredId);
            else entries_.erase(pid);
            if (parent) --parent->info.children;
            entry = parent;
        }
    }

    static std::wstring queryPath(uint64_t pid, DWORD& error) {
        wchar_t buffer[1024];
        if (pid == 4) {
            // У System нет обычного user-mode образа; путь ядра известен системе.
            const UINT size = GetSystemDirectoryW(buffer, static_cast<UINT>(std::size(buffer)));
            if (size && size < std::size(buffer)) {
                error = ERROR_SUCCESS;
                return std::wstring(buffer, size) + L"\\ntoskrnl.exe";
            }
            error = size ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
            return {};
        }
        if (pid == 0 || pid > MAXDWORD) {
            error = ERROR_INVALID_PARAMETER;
            return {};
        }

        struct Handle {
            HANDLE value;
            ~Handle() { if (value) CloseHandle(value); }
        } process{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid)) };
        if (!process.value) {
            error = GetLastError();
            return {};
        }
        DWORD size = static_cast<DWORD>(std::size(buffer));
        if (QueryFullProcessImageNameW(process.value, 0, buffer, &size)) {
            error = ERROR_SUCCESS;
            return std::wstring(buffer, size);
        }
        error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) return {};

        // Длинный путь — редкий случай; обычное событие не выделяет этот буфер.
        std::unique_ptr<wchar_t[]> large(new wchar_t[32768]);
        size = 32768;
        if (QueryFullProcessImageNameW(process.value, 0, large.get(), &size)) {
            error = ERROR_SUCCESS;
            return std::wstring(large.get(), size);
        }
        error = GetLastError();
        return {};
    }
};

} // namespace pmkext
