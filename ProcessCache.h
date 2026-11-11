#pragma once
#include "Common.h"
#include "ProcessIcon.h"
#include "DebugCounters.h"
#include <memory>
#include <unordered_map>

struct ProcessPathInfo;

// ---------------------------------------------------------------------------
// Кеш «pid -> имя, путь, иконка».
//
// SystemInfo держит открытый дескриптор процесса, поэтому номер не может быть
// отдан другой программе, пока сведения о завершившемся процессе нужны UI.
// ---------------------------------------------------------------------------
class ProcessCache {
    struct IconEntry;
public:
    ProcessCache() = default;
    ProcessCache(const ProcessCache&) = delete;
    ProcessCache& operator=(const ProcessCache&) = delete;

    struct Info {
        std::wstring name;      // FIREFOX.EXE
        std::wstring path;      // C:\Program Files\...\firefox.exe
        // Тот же неизменяемый объект использует matcher: по указателю можно
        // отличить сменившийся процесс без повторного сравнения длинного пути.
        std::shared_ptr<const ProcessPathInfo> pathInfo;
        ProcessIconRef icon;

    private:
        friend class ProcessCache;
        IconEntry* iconEntry_ = nullptr;
    };
    void SetIconSize(int iconSize);
    const Info& Get(DWORD pid);
    // Monitor уже получил неизменяемый путь в фоновом потоке. Передача той же
    // ссылки убирает второй захват системного кеша при публикации снимка в UI.
    const Info& Get(DWORD pid,
                    const std::shared_ptr<const ProcessPathInfo>& pathInfo);
    // Имена некоторых записей зависят от текущего языка интерфейса. Пути и
    // иконки не меняются, поэтому обновляется только текст уже известных PID.
    void RefreshNames();
    // Общий значок интерфейса без записи в PID-кеше. Только поток UI.
    ProcessIconRef InterfaceIcon() { return GenericIcon(); }
    void Sweep();               // выбросить мёртвые PID
    // Как и сам кеш, вызывается только из потока интерфейса.
    void ReadDebugCounters(DebugCounters::Snapshot& out) const {
        out.values[DebugCounters::CachedProcesses] = byPid_.size();
        out.values[DebugCounters::CachedIcons] = iconByPath_.size();
    }

private:
#ifdef FIREWALLX_TEST_PROCESS_CACHE
    friend struct ProcessCacheTestAccess;
#endif
    struct IconEntry {
        ProcessIconRef icon;
        size_t users = 0;       // записи byPid_, а не ссылки интерфейса
        // Адрес ключа unordered_map сохраняется при rehash. Запись удаляется
        // только после последнего PID, поэтому указатель остаётся действителен.
        const std::wstring* key = nullptr;
    };

    void AcquireIcon(Info& info);
    void ReleaseIcon(Info& info);
    ProcessIconRef IconFor(const Info& info);
    ProcessIconRef GenericIcon();

    int iconSize_ = 16;
    ProcessIconRef generic_;
    std::unordered_map<DWORD, Info> byPid_;
    std::unordered_map<std::wstring, IconEntry> iconByPath_;
};
