#include "ServiceInfo.h"
#include "StringRes.h"
#include "TableBuffer.h"
#include "NumericHash.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>

namespace {

constexpr int    kMaxRounds  = 64;
constexpr size_t kStartBytes = 96 * 1024;

// Дескриптор SCM и рабочий буфер живут между опросами. Раньше каждый секундный
// такт заново открывал диспетчер и выделял/обнулял 96 КБ.
class Enumerator {
public:
    ~Enumerator() { Close(); }

    bool Run(DWORD serviceState, std::vector<ServiceEntry>& out) {
        out.clear();
        if (!Open()) [[unlikely]] return false;
        if (buf_.size() < kStartBytes) [[unlikely]] buf_.reset(kStartBytes);

        size_t maxUsed = 1;
        DWORD resume = 0;
        for (int round = 0; round < kMaxRounds; ++round) {
            DWORD needed = 0;
            DWORD returned = 0;
            // Драйверы (SERVICE_DRIVER) не перечисляем: у них нет процесса, а
            // значит условие «сервис» они выполнить не могут по определению.
            const BOOL done = EnumServicesStatusExW(
                scm_, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, serviceState,
                buf_.data(), static_cast<DWORD>(buf_.size()),
                &needed, &returned, &resume, nullptr);
            const DWORD error = done ? ERROR_SUCCESS : GetLastError();
            if (!done && error != ERROR_MORE_DATA) [[unlikely]] {
                // Дескриптор мог пережить перезапуск/сбой SCM. Следующая попытка
                // должна открыть новый, а не повторять запрос через испорченный.
                Close();
                return false;
            }

            const auto* services =
                reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf_.data());
            size_t used = static_cast<size_t>(returned) * sizeof(*services);
            for (DWORD i = 0; i < returned; ++i) {
                if (!services[i].lpServiceName || !*services[i].lpServiceName) [[unlikely]]
                    continue;

                ServiceEntry entry;
                entry.name = services[i].lpServiceName;
                entry.display = services[i].lpDisplayName
                    ? services[i].lpDisplayName : L"";
                used += (entry.name.size() + entry.display.size() + 2) * sizeof(wchar_t);
                entry.state = services[i].ServiceStatusProcess.dwCurrentState;
                entry.type = services[i].ServiceStatusProcess.dwServiceType;
                entry.pid = services[i].ServiceStatusProcess.dwProcessId;
                // У остановленного сервиса владельца нет: нулевой либо
                // остаточный PID в runtime-карту попасть не должен.
                if (entry.state == SERVICE_STOPPED) entry.pid = 0;
                out.push_back(std::move(entry));
            }

            maxUsed = std::max(maxUsed, used);
            if (done) {
                // Строки уже скопированы в out. Размер считаем в том же проходе,
                // а не по адресам строк: SCM вправе размещать их у конца буфера.
                buf_.Trim(maxUsed, kStartBytes);
                return true;
            }
            if (returned != 0) continue;

            // В буфер не поместилась даже одна запись. Увеличиваем его с
            // запасом; отсутствие роста означало бы бесконечный цикл.
            const size_t wanted = static_cast<size_t>(needed) + 8192;
            if (wanted <= buf_.size() || wanted > MAXDWORD) return false;
            buf_.reset(wanted);
        }
        return false;
    }

    void Close() {
        if (scm_) {
            CloseServiceHandle(scm_);
            scm_ = nullptr;
        }
        buf_.reset();
    }

private:
    bool Open() {
        if (scm_) [[likely]] return true;
        // SC_MANAGER_ENUMERATE_SERVICE доступен обычному пользователю.
        scm_ = OpenSCManagerW(nullptr, nullptr,
                              SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        return scm_ != nullptr;
    }

    SC_HANDLE   scm_ = nullptr;
    TableBuffer buf_;
};

// ---------------------------------------------------------------- каталог UI

struct CatalogSnapshot {
    std::vector<ServiceEntry>                list;
    std::unordered_map<std::wstring, size_t> byName; // UPPER -> индекс
    bool valid = false;
};

class CatalogManager {
public:
    std::vector<ServiceEntry> All(bool refresh) {
        std::lock_guard<std::mutex> lock(mtx_);
        EnsureLocked(refresh);
        return snap_.list;
    }

    std::wstring DisplayName(const std::wstring& name) {
        if (name.empty()) return {};
        std::lock_guard<std::mutex> lock(mtx_);
        EnsureLocked(false);
        const auto it = snap_.byName.find(FoldCaseCopy(name));
        return it == snap_.byName.end()
            ? std::wstring() : snap_.list[it->second].display;
    }

    bool Installed(const std::wstring& name) {
        if (name.empty()) return false;
        std::lock_guard<std::mutex> lock(mtx_);
        EnsureLocked(false);
        return snap_.byName.count(FoldCaseCopy(name)) != 0;
    }

private:
    void EnsureLocked(bool refresh) {
        if (snap_.valid && !refresh) [[likely]] return;

        std::vector<ServiceEntry> list;
        if (!enumerator_.Run(SERVICE_STATE_ALL, list)) {
            // Частичный каталог не заменяет последний полный. До первого
            // успешного опроса окно выбора покажет пустой список.
            return;
        }

        CatalogSnapshot next;
        next.list = std::move(list);
        std::sort(next.list.begin(), next.list.end(),
                  [](const ServiceEntry& a, const ServiceEntry& b) {
                      return CompareStringOrdinal(a.name.c_str(), -1,
                          b.name.c_str(), -1, TRUE) == CSTR_LESS_THAN;
                  });
        for (size_t i = 0; i < next.list.size(); ++i)
            next.byName.emplace(FoldCaseCopy(next.list[i].name), i);
        next.valid = true;
        snap_ = std::move(next);
    }

    std::mutex      mtx_;
    Enumerator      enumerator_;
    CatalogSnapshot snap_;
};

CatalogManager& Catalog() {
    static CatalogManager manager;
    return manager;
}

// ------------------------------------------------------------- runtime-карта

struct RuntimeSnapshot {
    std::unordered_map<DWORD, ServiceInfo::HostedServices, NumericIdHash> byPid;
    uint64_t version = 0;
    uint64_t refreshTicket = 0;          // последний подтверждённый запрос опроса
    bool valid = false;
};

ServiceInfo::HostedServices EmptyServices() {
    static const ServiceInfo::HostedServices empty =
        std::make_shared<const std::vector<ServiceEntry>>();
    return empty;
}

bool SameRuntimeMapping(const RuntimeSnapshot& a, const RuntimeSnapshot& b) {
    if (a.byPid.size() != b.byPid.size()) [[unlikely]] return false;

    for (const auto& pair : a.byPid) {
        const auto found = b.byPid.find(pair.first);
        if (found == b.byPid.end()) [[unlikely]] return false;

        const auto& left = *pair.second;
        const auto& right = *found->second;
        if (left.size() != right.size()) [[unlikely]] return false;
        for (size_t i = 0; i < left.size(); ++i) {
            // Display name, состояние и тип не участвуют в вердикте. Версию
            // меняет только набор ключевых имён данного PID.
            if (!ServiceInfo::SameName(left[i].name, right[i].name)) [[unlikely]] return false;
        }
    }
    return true;
}

class RuntimeManager {
public:
    RuntimeManager() {
        snapshot_.store(std::make_shared<const RuntimeSnapshot>(),
                        std::memory_order_release);
    }

    ~RuntimeManager() { Shutdown(); }

    std::shared_ptr<const RuntimeSnapshot> Snapshot() const {
        return snapshot_.load(std::memory_order_acquire);
    }

    bool Refresh(bool force) {
        std::lock_guard<std::mutex> refreshLock(refreshMtx_);

        const ULONGLONG now = GetTickCount64();
        const ULONGLONG last = lastAttempt_.load(std::memory_order_acquire);
        if (!force && last && now - last < ServiceInfo::kCacheTtlMs)
            return Snapshot()->valid;
        lastAttempt_.store(now, std::memory_order_release);

        // Запрос, пришедший во время перечисления, ждёт следующего опроса:
        // начатый раньше снимок ещё мог не увидеть новый PID службы.
        uint64_t refreshTicket = 0;
        {
            std::lock_guard<std::mutex> lock(stateMtx_);
            refreshTicket = requestedRefresh_;
            startedRefresh_ = refreshTicket;
        }
        std::vector<ServiceEntry> active;
        if (!enumerator_.Run(SERVICE_ACTIVE, active)) [[unlikely]] {
            // Частичный снимок опаснее прежнего полного: если потерять одного
            // соседа по svchost, ограниченное правило ошибочно подойдёт.
            return false;
        }

        std::unordered_map<DWORD, std::vector<ServiceEntry>> byPid;
        for (ServiceEntry& entry : active) {
            if (!entry.pid) continue;
            byPid[entry.pid].push_back(std::move(entry));
        }
        auto next = std::make_shared<RuntimeSnapshot>();
        next->byPid.reserve(byPid.size());
        for (auto& pair : byPid) {
            auto& hosted = pair.second;
            std::sort(hosted.begin(), hosted.end(),
                      [](const ServiceEntry& a, const ServiceEntry& b) {
                          return CompareStringOrdinal(a.name.c_str(), -1,
                              b.name.c_str(), -1, TRUE) == CSTR_LESS_THAN;
                      });
            next->byPid.emplace(pair.first,
                std::make_shared<const std::vector<ServiceEntry>>(std::move(hosted)));
        }

        const std::shared_ptr<const RuntimeSnapshot> previous = Snapshot();
        next->valid = true;
        const bool mappingChanged = !previous->valid ||
                                    !SameRuntimeMapping(*previous, *next);
        next->version = mappingChanged ? ++versionSeq_ : previous->version;
        next->refreshTicket = refreshTicket;
        const bool refreshCompleted = refreshTicket > previous->refreshTicket;

        // Даже при той же версии публикуем новый снимок: display/state нужны
        // редкому UI-пути создания заготовки, хотя на вердикт они не влияют.
        snapshot_.store(std::move(next), std::memory_order_release);
        if (mappingChanged || refreshCompleted) [[unlikely]] NotifyChanged();
        return true;
    }

    ServiceInfo::HostedServices ServicesOfPid(DWORD pid, bool refresh) {
        if (!pid) return EmptyServices();
        if (refresh) Refresh(false);

        const std::shared_ptr<const RuntimeSnapshot> snap = Snapshot();
        if (!snap->valid) [[unlikely]] {
            RequestRefresh();
            return EmptyServices();
        }

        const auto it = snap->byPid.find(pid);
        if (it == snap->byPid.end()) return EmptyServices();

        // Ссылка владеет только списком этого PID: старые снимки и службы других
        // процессов освобождаются независимо, без копирования строк на событии.
        return it->second;
    }

    uint64_t Version(bool refresh) {
        if (refresh) Refresh(true);
        return Snapshot()->version;
    }

    uint64_t RequestRefresh() {
        std::lock_guard<std::mutex> lock(stateMtx_);
        if (!enabled_ || stopping_) return 0;
        if (requestedRefresh_ == startedRefresh_) ++requestedRefresh_;
        refreshRequested_ = true;
        cv_.notify_all();
        return requestedRefresh_;
    }

    bool RefreshComplete(uint64_t ticket) const {
        return Snapshot()->refreshTicket >= ticket;
    }

    void SetMonitoring(bool enabled) {
        std::lock_guard<std::mutex> lock(stateMtx_);
        if (stopping_) return;
        if (enabled && !worker_.joinable())
            worker_ = std::thread([this]() { WorkerLoop(); });
        enabled_ = enabled;
        cv_.notify_all();
    }

    void SetNotification(HWND window, UINT message) {
        if (!window) {
            // Сначала снимаем HWND для новых отправок, затем номер сообщения.
            // Уже начатый NotifyChanged мог прочитать прежний HWND.
            notifyWindow_.store(nullptr, std::memory_order_release);
            notifyMessage_.store(0, std::memory_order_relaxed);
            return;
        }
        notifyMessage_.store(message, std::memory_order_relaxed);
        notifyWindow_.store(window, std::memory_order_release);
    }

    void Invalidate() {
        lastAttempt_.store(0, std::memory_order_release);
        std::lock_guard<std::mutex> lock(stateMtx_);
        if (enabled_) refreshRequested_ = true;
        cv_.notify_all();
    }

    void Shutdown() {
        SetNotification(nullptr, 0);
        {
            std::lock_guard<std::mutex> lock(stateMtx_);
            if (stopping_) return;
            stopping_ = true;
            enabled_ = false;
            cv_.notify_all();
        }
        if (worker_.joinable()) worker_.join();

        // После join никто больше не использует рабочий дескриптор.
        std::lock_guard<std::mutex> refreshLock(refreshMtx_);
        enumerator_.Close();
    }

private:
    void NotifyChanged() const {
        const HWND window = notifyWindow_.load(std::memory_order_acquire);
        if (!window) return;
        const UINT message = notifyMessage_.load(std::memory_order_relaxed);
        if (message) PostMessageW(window, message, 0, 0);
    }

    void WorkerLoop() {
        std::unique_lock<std::mutex> lock(stateMtx_);
        while (!stopping_) {
            if (!enabled_) {
                cv_.wait(lock, [this]() { return stopping_ || enabled_; });
                continue;
            }

            const bool force = refreshRequested_;
            refreshRequested_ = false;
            const ULONGLONG now = GetTickCount64();
            const ULONGLONG last = lastAttempt_.load(std::memory_order_acquire);
            if (!force && last && now - last < ServiceInfo::kCacheTtlMs) {
                const ULONGLONG waitMs = ServiceInfo::kCacheTtlMs - (now - last);
                cv_.wait_for(lock, std::chrono::milliseconds(waitMs), [this]() {
                    return stopping_ || !enabled_ || refreshRequested_;
                });
                continue;
            }

            lock.unlock();
            Refresh(force);
            lock.lock();
        }
    }

    mutable std::atomic<std::shared_ptr<const RuntimeSnapshot>> snapshot_;
    std::atomic<ULONGLONG> lastAttempt_{ 0 };
    std::atomic<HWND> notifyWindow_{ nullptr };
    std::atomic<UINT> notifyMessage_{ 0 };

    std::mutex refreshMtx_;
    Enumerator enumerator_;
    uint64_t versionSeq_ = 0;

    std::mutex              stateMtx_;
    std::condition_variable cv_;
    std::thread             worker_;
    uint64_t requestedRefresh_ = 0;
    uint64_t startedRefresh_ = 0;
    bool enabled_ = false;
    bool stopping_ = false;
    bool refreshRequested_ = false;
};

RuntimeManager& Runtime() {
    static RuntimeManager manager;
    return manager;
}

} // namespace

std::wstring ServiceEntry::StateTextRu() const {
    if (!installed) return LoadStringRes(IDS_SVCPROC_NOT_INSTALLED);
    UINT id = IDS_SVCPROC_UNKNOWN;
    switch (state) {
    case SERVICE_RUNNING:          id = IDS_SVCPROC_RUNNING;  break;
    case SERVICE_STOPPED:          id = IDS_SVCPROC_STOPPED;  break;
    case SERVICE_START_PENDING:    id = IDS_SVCPROC_STARTING; break;
    case SERVICE_STOP_PENDING:     id = IDS_SVCPROC_STOPPING; break;
    case SERVICE_PAUSED:           id = IDS_SVCPROC_PAUSED;   break;
    case SERVICE_PAUSE_PENDING:    id = IDS_SVCPROC_PAUSING;  break;
    case SERVICE_CONTINUE_PENDING: id = IDS_SVCPROC_RESUMING; break;
    default: break;
    }
    return LoadStringRes(id);
}

namespace ServiceInfo {

bool SameName(const std::wstring& a, const std::wstring& b) {
    return EqualNoCase(a, b);
}

std::vector<ServiceEntry> All(bool refresh) {
    return Catalog().All(refresh);
}

std::wstring DisplayName(const std::wstring& name) {
    return Catalog().DisplayName(name);
}

bool Installed(const std::wstring& name) {
    return Catalog().Installed(name);
}

HostedServices ServicesOfPid(DWORD pid, bool refresh) {
    return Runtime().ServicesOfPid(pid, refresh);
}

void SetMonitoring(bool enabled) {
    Runtime().SetMonitoring(enabled);
}

void SetNotification(HWND window, UINT message) {
    Runtime().SetNotification(window, message);
}

void Shutdown() {
    Runtime().Shutdown();
}

uint64_t Version(bool refresh) {
    return Runtime().Version(refresh);
}

uint64_t RequestRefresh() {
    return Runtime().RequestRefresh();
}

bool RefreshComplete(uint64_t ticket) {
    return Runtime().RefreshComplete(ticket);
}

void Invalidate() {
    Runtime().Invalidate();
}

} // namespace ServiceInfo
