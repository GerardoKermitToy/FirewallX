#include "ProcessCache.h"
#include "StringRes.h"
#include "SystemInfo.h"
#include "StorageMaintenance.h"
#include <shellapi.h>
#include <shlwapi.h>
#include <utility>

void ProcessCache::SetIconSize(int iconSize) {
    const int next = iconSize > 0 ? iconSize : 16;
    if (iconSize_ == next) return;
    iconSize_ = next;
    for (auto& kv : byPid_) {
        kv.second.icon.reset();
        kv.second.iconEntry_ = nullptr;
    }
    iconByPath_.clear();
    TrimHashTable(iconByPath_);
    generic_.reset();
}

void ProcessCache::AcquireIcon(Info& info) {
    std::wstring key = FoldCaseCopy(info.path);
    for (;;) {
        auto it = iconByPath_.find(key);
        if (it == iconByPath_.end()) {
            // Shell может прокачать сообщения: до возврата не держим ни
            // итератор, ни ссылку на запись, которую вложенный Sweep удалит.
            ProcessIconRef icon = IconFor(info);
            if (icon && icon->size() != iconSize_) continue;
            it = iconByPath_.try_emplace(std::move(key), IconEntry{ std::move(icon) }).first;
            it->second.key = &it->first;
        }
        IconEntry& entry = it->second;
        ++entry.users;
        info.iconEntry_ = &entry;
        info.icon = entry.icon;
        return;
    }
}

void ProcessCache::ReleaseIcon(Info& info) {
    IconEntry* entry = std::exchange(info.iconEntry_, nullptr);
    info.icon.reset();
    if (entry && --entry->users == 0)
        iconByPath_.erase(*entry->key);
}

ProcessIconRef ProcessCache::GenericIcon() {
    if (generic_) [[likely]] return generic_;
    ProcessIcon icon(static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
                                                   IMAGE_ICON, iconSize_, iconSize_,
                                                   LR_COPYFROMRESOURCE)), iconSize_);
    if (icon.handle()) generic_ = std::make_shared<ProcessIcon>(std::move(icon));
    return generic_;
}

ProcessIconRef ProcessCache::IconFor(const Info& info) {
    const int size = iconSize_;
    const std::wstring& path = info.path;
    const HANDLE process = info.pathInfo && info.pathInfo->process
        ? info.pathInfo->process->h : nullptr;
    HICON handle = ExtractApplicationIcon(path, size, process);
    if (!handle)
        handle = static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
            IMAGE_ICON, size, size, LR_COPYFROMRESOURCE));
    ProcessIcon icon(handle, size);
    return icon.handle() ? std::make_shared<ProcessIcon>(std::move(icon)) : GenericIcon();
}

const ProcessCache::Info& ProcessCache::Get(DWORD pid) {
    return Get(pid, ProcessImagePathRef(pid));
}

const ProcessCache::Info& ProcessCache::Get(
    DWORD pid, const ProcessPathRef& current) {
    // Пока запись SystemInfo сохраняется, для PID возвращается тот же объект пути.
    // Смена указателя требует обновить метаданные,
    // но сама по себе не доказывает переиспользование PID: запись могла быть
    // вытеснена. Длинный путь на каждом такте не сравнивается посимвольно.

    auto it = byPid_.find(pid);
    if (it != byPid_.end() && it->second.pathInfo == current &&
        it->second.iconEntry_) [[likely]]
        return it->second;

    Info info;
    info.pathInfo = current;
    if (current) info.path = current->text;

    if (pid == 0) {
        info.name = LoadStringRes(IDS_PROC_SYSTEM_ICMP);
    } else if (pid == 4) {
        info.name = L"SYSTEM";
    } else if (!info.path.empty()) {
        const wchar_t* base = PathFindFileNameW(info.path.c_str());
        info.name = FoldCaseCopy(base);
    } else {
        info.name = L"PID " + std::to_wstring(pid) +
                    LoadStringRes(IDS_PROC_PATH_UNAVAILABLE);
    }
    AcquireIcon(info);

    // За время извлечения значка вложенный обработчик мог изменить byPid_.
    it = byPid_.find(pid);
    if (it != byPid_.end()) {
        ReleaseIcon(it->second);
        it->second = std::move(info);
        return it->second;
    }
    return byPid_.emplace(pid, std::move(info)).first->second;
}

void ProcessCache::RefreshNames() {
    // Пересобираем только подписи: путь и связанный с ним значок остаются
    // прежними, поэтому смена языка не вызывает повторных запросов к системе.
    for (auto& entry : byPid_) {
        const DWORD pid = entry.first;
        Info& info = entry.second;
        if (pid == 0) {
            info.name = LoadStringRes(IDS_PROC_SYSTEM_ICMP);
        } else if (pid == 4) {
            info.name = L"SYSTEM";
        } else if (!info.path.empty()) {
            const wchar_t* base = PathFindFileNameW(info.path.c_str());
            info.name = FoldCaseCopy(base);
        } else {
            info.name = L"PID " + std::to_wstring(pid) +
                        LoadStringRes(IDS_PROC_PATH_UNAVAILABLE);
        }
    }
}

// ---------------------------------------------------------------------------
// Снятие записей завершившихся процессов.
//
// Отсрочка (kProcessGraceMs) соблюдается и здесь, иначе она не работала бы
// вовсе: список ещё показывает соединения закрывшейся программы, а её имя,
// путь и иконка уже были бы удалены — и вместо «FIREFOX.EXE» со значком
// осталось бы «PID 1234 (путь недоступен)». Сведения удаляются после общего
// окна хранения завершившегося процесса.
// ---------------------------------------------------------------------------
void ProcessCache::Sweep() {
    for (auto it = byPid_.begin(); it != byPid_.end();) {
        // Системные номера (0 и 4) существуют всегда и опросу не подлежат.
        if (IsSystemPid(it->first)) { ++it; continue; }

        const ULONGLONG dead = ProcessDeadFor(it->first);
        if (dead > kProcessGraceMs) {
            ReleaseIcon(it->second);
            it = byPid_.erase(it);
        } else {
            ++it;
        }
    }
    TrimHashTable(byPid_);
    TrimHashTable(iconByPath_);
}
