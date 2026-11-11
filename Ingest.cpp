#include "Ingest.h"
#include "NdisTransport.h"
#include "FlowStore.h"
#include "OwnerLookup.h"
#include "StringRes.h"
#include "StorageMaintenance.h"
#include "SystemInfo.h"
#include "ThreadSuspend.h"
#include "ServiceControl.h"
#include "AppInfo.h"
#include "MacroAddr.h"
#include "ServiceInfo.h"
#include "network_interface_watcher.h"
#include "duplex_pipe/duplex_pipe_client.h"
#include "duplex_pipe/duplex_pipe_server.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cwctype>
#include <iterator>
#include <limits>
#include <new>
#include <mutex>
#include <sddl.h>
#include <vector>

#ifdef FIREWALLX_TEST_VERDICTS
#include "tests/ingest_work_probe.h"
#endif

// ---------------------------------------------------------------------------
// В службе KextClient владеет драйвером, а pipe без изменения передаёт
// команды от desktop и полные записи от драйвера.
// ---------------------------------------------------------------------------
namespace {

SRWLOCK                     g_driverLock = SRWLOCK_INIT;
// Оба маршрута службы перечитывают общую БД и политику независимо друг от друга.
std::mutex                  g_serviceReloadMutex;
struct DriverControlLock {
    DriverControlLock() noexcept { AcquireSRWLockExclusive(&g_driverLock); }
    ~DriverControlLock() { ReleaseSRWLockExclusive(&g_driverLock); }
    DriverControlLock(const DriverControlLock&) = delete;
    DriverControlLock& operator=(const DriverControlLock&) = delete;
};
pmkext::KextClient*          g_driver = nullptr;
duplex_pipe::Client*         g_servicePipe = nullptr;
HANDLE                       g_driverThread = nullptr;
std::atomic<bool>                    g_driverStop{ false };
std::atomic<bool>                    g_driverReady{ false };
std::atomic<DWORD>                   g_driverStartError{ ERROR_IO_PENDING };
std::atomic<HWND>                    g_driverFailureWindow{ nullptr };
std::atomic<UINT>                    g_driverFailureMessage{ 0 };
DriverVerdictSession                 g_verdictSession;

enum class VerdictTransport : uint8_t {
    None,
    Direct,
    Pipe,
};
VerdictTransport                     g_verdictTransport = VerdictTransport::None;

// Раздельные события не дают перепутать штатную остановку, обрыв pipe и
// завершение первоначального запуска. Они закрываются только после join().
HANDLE g_driverWake = nullptr;
HANDLE g_proxyWake = nullptr;
HANDLE g_driverStarted = nullptr;

constexpr DWORD kStatsIntervalMs = 1000;
constexpr DWORD kStopSliceMs = 100;
constexpr DWORD kProxyStartTimeoutMs = 30000;

// Диагностическое логирование вердиктов оконного режима. Для включения нужно
// вручную заменить false на true; других способов включить логирование нет.
// Файл создаётся рядом с FirewallX.exe в формате UTF-8 с BOM.
constexpr bool kLogDesktopRuleVerdicts = false;
constexpr wchar_t kDesktopRuleVerdictLogFile[] =
    L"FirewallX_rule_verdicts.txt";

// KextClient вызывает on_connection_* одним reader-потоком. Один и тот же PID
// обычно приходит сотнями событий подряд, а ProcessImagePathRef прежде на каждом
// из них брал общий мьютекс SystemInfo. Короткий потоковый кеш не ослабляет защиту
// от переиспользования PID: системная запись с открытым process handle всё равно
// перепроверяется не реже общего kProcessAliveTtlMs.
ProcessPathRef EventProcessPath(DWORD pid) {
#ifdef FIREWALLX_TEST_VERDICTS
    ++IngestWorkProbe::counts.processPathReads;
#endif
    struct Entry {
        ProcessPathRef path;
        ULONGLONG checkedAt = 0;
        ULONGLONG touchedAt = 0;
    };
    struct Cache {
        std::unordered_map<DWORD, Entry> entries;
        ULONGLONG sweptAt = 0;
    };
    thread_local Cache cache;

    const ULONGLONG now = GetTickCount64();
    Entry& entry = cache.entries[pid];
    entry.touchedAt = now;
    if (entry.path && entry.checkedAt &&
        now - entry.checkedAt <= kProcessAliveTtlMs) [[likely]]
        return entry.path;

    entry.path = ProcessImagePathRef(pid);
    entry.checkedAt = now;

    if (!cache.sweptAt || now - cache.sweptAt >= kProcessSweepMs) [[unlikely]] {
        cache.sweptAt = now;
        for (auto it = cache.entries.begin(); it != cache.entries.end();) {
            it = now - it->second.touchedAt > kProcessForgetMs
                ? cache.entries.erase(it) : std::next(it);
        }
        TrimHashTable(cache.entries);
    }
    return entry.path;
}

void LogDesktopRuleVerdict(uint64_t driverPid, DWORD rulePid,
                           const FlowKey& key, Dir dir,
                           pmkext::Verdict verdict,
                           const std::wstring& ruleName) {
    if constexpr (!kLogDesktopRuleVerdicts) {
        return;
    } else {
        if (key.proto != Proto::Tcp) return;

        static std::mutex logMtx;
        std::lock_guard<std::mutex> lock(logMtx);

        const wchar_t* direction = L"неизвестное";
        if (dir == Dir::In) direction = L"входящее";
        else if (dir == Dir::Out) direction = L"исходящее";

        SYSTEMTIME now{};
        GetLocalTime(&now);
        wchar_t timestamp[64]{};
        _snwprintf_s(timestamp, _TRUNCATE,
                     L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
                     static_cast<unsigned>(now.wYear),
                     static_cast<unsigned>(now.wMonth),
                     static_cast<unsigned>(now.wDay),
                     static_cast<unsigned>(now.wHour),
                     static_cast<unsigned>(now.wMinute),
                     static_cast<unsigned>(now.wSecond),
                     static_cast<unsigned>(now.wMilliseconds));

        std::wstring line = timestamp;
        const auto endpoint = [](const IpAddr& address, uint16_t port) {
            std::wstring host = IpToPlainString(address);
            if (address.family == AF_INET6) host = L"[" + host + L"]";
            return host + L": " + std::to_wstring(port);
        };
        line += L"; pid от драйвера: ";
        line += std::to_wstring(static_cast<unsigned long long>(driverPid));
        line += L"; pid поиска правила: ";
        line += std::to_wstring(static_cast<unsigned long long>(rulePid));
        line += L"; направление: ";
        line += direction;
        line += L"; local: ";
        line += endpoint(key.local, key.lport);
        line += L"; remote: ";
        line += endpoint(key.remote, key.rport);
        line += L"; вердикт: ";
        line += std::to_wstring(static_cast<unsigned>(verdict));
        line += L"; правило: ";
        for (const wchar_t c : ruleName) {
            // Имя правила не должно ломать однострочный формат файла.
            line += (c == L'\r' || c == L'\n' || c == L'\t' || c == L';')
                ? L' ' : c;
        }
        line += L"\r\n";

        const std::string utf8 = WideToUtf8(line);
        if (utf8.empty()) return;

        const std::wstring path = ModuleDirFile(kDesktopRuleVerdictLogFile);
        HANDLE file = CreateFileW(
            path.c_str(), FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;

        LARGE_INTEGER size{};
        if (GetFileSizeEx(file, &size) && size.QuadPart == 0) {
            static constexpr uint8_t kUtf8Bom[] = { 0xEF, 0xBB, 0xBF };
            DWORD written = 0;
            WriteFile(file, kUtf8Bom, sizeof(kUtf8Bom), &written, nullptr);
        }

        const uint8_t* data = reinterpret_cast<const uint8_t*>(utf8.data());
        size_t left = utf8.size();
        while (left) {
            const DWORD part = static_cast<DWORD>(
                (left > MAXDWORD) ? MAXDWORD : left);
            DWORD written = 0;
            if (!WriteFile(file, data, part, &written, nullptr) || !written)
                break;
            data += written;
            left -= written;
        }
        CloseHandle(file);
    }
}

void NotifyDriverStartFailure(HWND window, UINT message, DWORD error) noexcept {
    if (window && message && error != ERROR_SUCCESS && error != ERROR_OPERATION_ABORTED)
        PostMessageW(window, message, error, 0);
}

void SignalDriverStart(DWORD status, bool& signalled) noexcept {
    if (signalled) return;
    g_driverStartError.store(status, std::memory_order_release);
    g_driverReady.store(status == ERROR_SUCCESS, std::memory_order_release);
    if (g_driverStarted) SetEvent(g_driverStarted);
    signalled = true;
    NotifyDriverStartFailure(g_driverFailureWindow.load(std::memory_order_relaxed),
                             g_driverFailureMessage.load(std::memory_order_relaxed), status);
}

// Поколение открывается до приёма записей и закрывается при остановке либо
// ошибке транспорта, не обязательно после reader-а. Оно проверяется под g_driverLock —
// тем же замком, под которым выбирается direct/pipe transport для ответа.
uint64_t BeginVerdictSessionLocked(VerdictTransport transport) noexcept {
    const uint64_t session = g_verdictSession.Begin();
    g_verdictTransport = transport;
    return session;
}

uint64_t EndVerdictSessionLocked(uint64_t expected = 0) noexcept {
    const uint64_t ended = g_verdictSession.End(expected);
    if (ended) {
        g_verdictTransport = VerdictTransport::None;
    }
    return ended;
}

uint64_t ActivateDriverSession(pmkext::KextClient* driver) noexcept {
    uint64_t session = 0;
    AcquireSRWLockExclusive(&g_driverLock);
    if (driver && g_driver == driver)
        session = BeginVerdictSessionLocked(VerdictTransport::Direct);
    ReleaseSRWLockExclusive(&g_driverLock);

    if (session) Ingest::Instance().BeginDriverSession(session);
    return session;
}

void DeactivateDriverSession(uint64_t session) noexcept {
    uint64_t ended = 0;
    AcquireSRWLockExclusive(&g_driverLock);
    ended = EndVerdictSessionLocked(session);
    ReleaseSRWLockExclusive(&g_driverLock);

    if (ended) Ingest::Instance().EndDriverSession(ended);
}

// После рукопожатия pipe передаёт запись драйвера без собственной оболочки;
// здесь проверяется только штатный пятибайтовый заголовок потока драйвера.
RPC_STATUS ReceiveDriverRecord(
    void* context,
    const byte* data,
    unsigned long dataSize) noexcept {
    auto* const driver = static_cast<pmkext::KextClient*>(context);
    if (!driver || !data || dataSize < 5) [[unlikely]] return ERROR_INVALID_DATA;

    const auto* const record = reinterpret_cast<const uint8_t*>(data);
    const uint32_t payloadSize = pmkext::detail::load<uint32_t>(record + 1);
    if (payloadSize != dataSize - 5) [[unlikely]] return ERROR_INVALID_DATA;

    driver->dispatchOne(
        static_cast<pmkext::InfoType>(record[0]),
        record + 5,
        payloadSize);
    return ERROR_SUCCESS;
}

bool ServiceProxyExpected() noexcept {
    FirewallX::ServiceState state;
    std::wstring error;
    return FirewallX::ServiceQuery(state, error) && state.installed &&
           state.state != 0 && state.state != SERVICE_STOPPED;
}

void RunMaintenanceLoop(pmkext::KextClient* driver) {
    unsigned ticks = 0;
    while (!g_driverStop.load(std::memory_order_relaxed)) {
        // Раз в минуту просим драйвер удалить записи законченных соединений,
        // чтобы освободить его память и прекратить поздние bandwidth-отчёты.
        // Окно показа завершённых строк FlowStore отсчитывает независимо.
        if ((++ticks % 60) == 0) [[unlikely]] driver->sendCleanEndedConnections();

        if (g_driverWake) {
            if (WaitForSingleObject(g_driverWake, kStatsIntervalMs) == WAIT_OBJECT_0) [[unlikely]]
                break;
        } else {
            for (DWORD spent = 0; spent < kStatsIntervalMs &&
                 !g_driverStop.load(std::memory_order_relaxed);
                 spent += kStopSliceMs) {
                Sleep(kStopSliceMs);
            }
        }
    }
}

enum class ProxySessionResult {
    Unavailable,
    Disconnected,
    Stopped,
};

struct ProxySessionContext {
    pmkext::KextClient* driver;
    duplex_pipe::Client* client;
    std::atomic<uint64_t> verdictSession{ 0 };
};

void ProxyConnectionChanged(
    void* context,
    duplex_pipe::ClientConnectionEvent event) noexcept {
    auto* const session = static_cast<ProxySessionContext*>(context);
    // Connected приходит до старта pipe-reader: предыдущая transport-сессия
    // не должна оставлять процессы, завершившиеся во время разрыва связи.
    if (event == duplex_pipe::ClientConnectionEvent::Connected)
        session->driver->clearProcessEvents();
    uint64_t startedSession = 0;
    uint64_t endedSession = 0;
    bool wake = false;
    bool disconnectedSource = false;

    AcquireSRWLockExclusive(&g_driverLock);
    if (g_driver == session->driver) {
        if (event == duplex_pipe::ClientConnectionEvent::Connected) {
            g_servicePipe = session->client;
            startedSession = BeginVerdictSessionLocked(VerdictTransport::Pipe);
            session->verdictSession.store(
                startedSession, std::memory_order_release);
        } else {
            const uint64_t expected = session->verdictSession.exchange(
                0, std::memory_order_acq_rel);
            endedSession = expected ? EndVerdictSessionLocked(expected) : 0;
            if (g_servicePipe == session->client) {
                g_servicePipe = nullptr;
                g_driverReady.store(false, std::memory_order_release);
                disconnectedSource = true;
                wake = true;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_driverLock);

    // Connected вызывается до запуска pipe reader: старое состояние очищается
    // раньше, чем первая запись новой transport-сессии сможет попасть в Ingest.
    if (startedSession) {
        Ingest::Instance().BeginDriverSession(startedSession);
        Ingest::Instance().SourceChanged(false);
    }
    if (endedSession) Ingest::Instance().EndDriverSession(endedSession);
    if (disconnectedSource) Ingest::Instance().SourceChanged(true);
    if (wake && g_proxyWake) SetEvent(g_proxyWake);
}

ProxySessionResult RunProxySession(pmkext::KextClient* driver,
                                   bool& startupSignalled,
                                   DWORD& error) {
    const HANDLE proxyReady = OpenEventW(
        SYNCHRONIZE | EVENT_MODIFY_STATE,
        FALSE,
        AppInfo::kServiceProxyReadyEvent);
    if (!proxyReady) {
        error = GetLastError();
        return ProxySessionResult::Unavailable;
    }
    ResetEvent(proxyReady);

    duplex_pipe::Client client;
    ProxySessionContext session{ driver, &client };
    client.SetConnectionCallback(ProxyConnectionChanged, &session);
    client.SetReceiveCallback(ReceiveDriverRecord, driver);

    if (g_proxyWake) ResetEvent(g_proxyWake);
    const RPC_STATUS status = client.Start();
    if (status != ERROR_SUCCESS) {
        client.Stop();
        CloseHandle(proxyReady);
        error = status;
        return ProxySessionResult::Unavailable;
    }

    AcquireSRWLockShared(&g_driverLock);
    const bool connected =
        g_driver == driver && g_servicePipe == &client;
    ReleaseSRWLockShared(&g_driverLock);
    if (!connected) {
        client.Stop();
        CloseHandle(proxyReady);
        error = ERROR_BROKEN_PIPE;
        return ProxySessionResult::Disconnected;
    }

    // Ждём подтверждения именно фактического переключения processLocally.
    // Raw pipe при этом остаётся прозрачным: барьер идёт отдельным событием.
    HANDLE routeWaits[3] = { proxyReady, g_proxyWake, g_driverWake };
    const DWORD route = WaitForMultipleObjects(
        3, routeWaits, FALSE, kProxyStartTimeoutMs);
    const DWORD routeError = route == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    CloseHandle(proxyReady);

    if (route != WAIT_OBJECT_0) {
        client.Stop();
        if (g_driverStop.load(std::memory_order_relaxed) ||
            route == WAIT_OBJECT_0 + 2) {
            error = ERROR_OPERATION_ABORTED;
            return ProxySessionResult::Stopped;
        }
        error = route == WAIT_TIMEOUT ? ERROR_SERVICE_REQUEST_TIMEOUT :
            (routeError == ERROR_SUCCESS ? ERROR_BROKEN_PIPE : routeError);
        return route == WAIT_OBJECT_0 + 1
            ? ProxySessionResult::Disconnected
            : ProxySessionResult::Unavailable;
    }

    AcquireSRWLockShared(&g_driverLock);
    const bool routeConnected =
        g_driver == driver && g_servicePipe == &client;
    ReleaseSRWLockShared(&g_driverLock);
    if (!routeConnected) {
        client.Stop();
        error = ERROR_BROKEN_PIPE;
        return ProxySessionResult::Disconnected;
    }

    // Кеш мог остаться от локальной службы или прежней оконной политики.
    // Барьер маршрута уже пройден: все новые запросы решает этот desktop.
    error = portmaster_clear_cache();
    if (error != ERROR_SUCCESS) {
        client.Stop();
        return ProxySessionResult::Disconnected;
    }

    // В proxy-режиме IOCTL заменяется той же командой через WriteFile службы.
    // Каждый новый desktop получает полный снимок, а не только будущие события.
    const byte startProcesses = static_cast<byte>(pmkext::CommandType::StartProcessMonitoring);
    error = client.SendRaw(&startProcesses, sizeof(startProcesses));
    if (error != ERROR_SUCCESS) {
        client.Stop();
        return ProxySessionResult::Disconnected;
    }

    // Connected-callback зафиксировал источник до запуска reader thread.
    // Route barrier пройден: UI может безопасно перечитать системные таблицы.
    Ingest::Instance().NotifySourceChanged();

    driver->g_running = true;
    g_driverReady.store(true, std::memory_order_release);
    SignalDriverStart(ERROR_SUCCESS, startupSignalled);

    HANDLE waits[2] = { g_driverWake, g_proxyWake };
    const DWORD waitStatus = WaitForMultipleObjects(
        2, waits, FALSE, INFINITE);
    const DWORD waitError =
        waitStatus == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;

    g_driverReady.store(false, std::memory_order_release);
    driver->g_running = false;

    uint64_t endedSession = 0;
    const uint64_t expectedSession = session.verdictSession.exchange(
        0, std::memory_order_acq_rel);
    AcquireSRWLockExclusive(&g_driverLock);
    if (g_servicePipe == &client) g_servicePipe = nullptr;
    endedSession = expectedSession
        ? EndVerdictSessionLocked(expectedSession) : 0;
    ReleaseSRWLockExclusive(&g_driverLock);
    if (endedSession) Ingest::Instance().EndDriverSession(endedSession);

    client.Stop();

    if (g_driverStop.load(std::memory_order_relaxed) ||
        waitStatus == WAIT_OBJECT_0) {
        error = ERROR_OPERATION_ABORTED;
        return ProxySessionResult::Stopped;
    }
    if (waitStatus != WAIT_OBJECT_0 + 1) {
        error = waitError == ERROR_SUCCESS ? ERROR_GEN_FAILURE : waitError;
        return ProxySessionResult::Unavailable;
    }

    error = ERROR_BROKEN_PIPE;
    return ProxySessionResult::Disconnected;
}

void RunDesktopDriver(pmkext::KextClient* driver, bool& startupSignalled) {
    DWORD proxyError = ERROR_FILE_NOT_FOUND;
    ULONGLONG firstFailure = 0;

    while (ServiceProxyExpected()) {
        if (g_driverStop.load(std::memory_order_relaxed)) {
            SignalDriverStart(ERROR_OPERATION_ABORTED, startupSignalled);
            return;
        }

        const ProxySessionResult result =
            RunProxySession(driver, startupSignalled, proxyError);
        if (result == ProxySessionResult::Stopped) return;
        // Несовместимый wire-API не исправится повторным подключением.
        if (proxyError == ERROR_REVISION_MISMATCH) {
            SignalDriverStart(proxyError, startupSignalled);
            return;
        }

        if (!startupSignalled) {
            if (firstFailure == 0) firstFailure = GetTickCount64();
            if (GetTickCount64() - firstFailure >= kProxyStartTimeoutMs) {
                SignalDriverStart(proxyError, startupSignalled);
                return;
            }
        }
        if (g_driverWake &&
            WaitForSingleObject(g_driverWake, kStopSliceMs) == WAIT_OBJECT_0) {
            SignalDriverStart(ERROR_OPERATION_ABORTED, startupSignalled);
            return;
        }
    }

    if (!driver->open()) {
        SignalDriverStart(driver->lastError(), startupSignalled);
        return;
    }

    const uint64_t verdictSession = ActivateDriverSession(driver);
    if (!verdictSession) {
        driver->close();
        SignalDriverStart(ERROR_INVALID_HANDLE, startupSignalled);
        return;
    }

    const DWORD cacheStatus = portmaster_clear_cache();
    if (cacheStatus != ERROR_SUCCESS) {
        DeactivateDriverSession(verdictSession);
        driver->close();
        SignalDriverStart(cacheStatus, startupSignalled);
        return;
    }

    // Прямой дескриптор — новый источник относительно proxy либо периода до
    // запуска. UI уведомляется после готовности устройства, но до reader thread:
    // UI запросит фоновый снимок уже существующих соединений, не дожидаясь
    // следующего секундного такта.
    Ingest::Instance().SourceChanged();

    if (!driver->startReadLoop() || !driver->ioctlStartProcessMonitoring()) {
        const DWORD error = driver->lastError();
        driver->stopReadLoop();
        DeactivateDriverSession(verdictSession);
        driver->close();
        SignalDriverStart(error, startupSignalled);
        return;
    }

    driver->g_running = true;
    g_driverReady.store(true, std::memory_order_release);
    SignalDriverStart(ERROR_SUCCESS, startupSignalled);
    RunMaintenanceLoop(driver);

    g_driverReady.store(false, std::memory_order_release);
    driver->g_running = false;
    driver->stopReadLoop();
    DeactivateDriverSession(verdictSession);
    driver->close();
}

struct ServiceProxyContext {
    duplex_pipe::Server* server = nullptr;
    pmkext::KextClient* driver = nullptr;
    const std::wstring* rulesPath = nullptr;
    SRWLOCK processLock = SRWLOCK_INIT;
    bool processLocally = false;
    bool clientConnected = false;
    HANDLE localRequest = nullptr;
    HANDLE localReady = nullptr;
    HANDLE proxyReady = nullptr;
};

// Переключение выполняется под тем же барьером, который держит пересылка
// записи. После захвата exclusive ни одна новая запись не сможет увидеть старый
// снимок: она либо была целиком отправлена desktop, либо дождётся локального
// режима. Ошибка загрузки также безопасна — RuleStore оставляет пустой снимок.
void SwitchServiceToLocalLocked(
    ServiceProxyContext& proxy,
    bool reloadIfAlreadyLocal) noexcept {
    const bool changed = !proxy.processLocally || reloadIfAlreadyLocal;
    if (changed && proxy.rulesPath)
        Ingest::Instance().ReloadServiceRules(*proxy.rulesPath);
    if (changed) Ingest::Instance().SetAppInterfacesActive(true);
    if (changed) Ingest::Instance().SourceChanged(false);
    proxy.processLocally = true;

    // Запрос локальной сетевой политики может прийти ещё до закрытия pipe.
    // Процессы собираем только после фактического отключения получателя.
    if (!proxy.clientConnected && !g_driverStop.load(std::memory_order_relaxed) &&
        !proxy.driver->processEventsEnabled()) {
        proxy.driver->setProcessEventsEnabled(true);
        if (!proxy.driver->ioctlStartProcessMonitoring()) {
            const DWORD error = proxy.driver->lastError();
            proxy.driver->setProcessEventsEnabled(false);
            g_driverStartError.store(error, std::memory_order_release);
            g_driverReady.store(false, std::memory_order_release);
            g_driverStop.store(true, std::memory_order_release);
            // Не выдаём неполную таблицу за готовый снимок. Контроллер штатно
            // закроет устройство; из reader/pipe callback close() не вызывается.
            if (g_driverWake) SetEvent(g_driverWake);
        }
    }
}

void SwitchServiceToLocal(
    ServiceProxyContext& proxy,
    bool reloadIfAlreadyLocal) noexcept {
    AcquireSRWLockExclusive(&proxy.processLock);
    SwitchServiceToLocalLocked(proxy, reloadIfAlreadyLocal);
    ReleaseSRWLockExclusive(&proxy.processLock);
}

// Подключившийся desktop снова становится получателем записей. Отключившийся
// клиент переводит службу на локальную обработку только после перечитывания БД.
void ServiceProxyConnectionChanged(
    void* context,
    duplex_pipe::ClientConnectionEvent event) noexcept {
    auto* const proxy = static_cast<ServiceProxyContext*>(context);
    if (!proxy) return;

    if (event == duplex_pipe::ClientConnectionEvent::Disconnected) {
        AcquireSRWLockExclusive(&proxy->processLock);
        proxy->clientConnected = false;
        SwitchServiceToLocalLocked(*proxy, false);
        ReleaseSRWLockExclusive(&proxy->processLock);
        return;
    }

    AcquireSRWLockExclusive(&proxy->processLock);
    proxy->clientConnected = true;
    proxy->driver->setProcessEventsEnabled(false);
    Ingest::Instance().SetAppInterfacesActive(false);
    Ingest::Instance().SourceChanged(false);
    proxy->processLocally = false;
    // Пока все записи получает desktop, локальному matcher-у снимок не нужен.
    ServiceInfo::SetMonitoring(false);
    // Сигнал выставляется под тем же барьером, что и маршрут. Следующая запись
    // драйвера не начнёт пересылку раньше этой точки.
    if (proxy->proxyReady) SetEvent(proxy->proxyReady);
    ReleaseSRWLockExclusive(&proxy->processLock);
}

// Команда от desktop уже имеет точный формат драйвера; после рукопожатия
// она проходит через pipe и сразу записывается в устройство без обёртки.
RPC_STATUS ForwardDriverCommand(
    void* context,
    const byte* command,
    unsigned long commandSize) noexcept {
    auto* const driver = static_cast<pmkext::KextClient*>(context);
    if (driver->writeRaw(command, commandSize)) [[likely]] return ERROR_SUCCESS;
    const DWORD error = driver->lastError();
    return error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error;
}

bool ForwardDriverRecord(
    void* context,
    const uint8_t* record,
    uint32_t recordSize) noexcept {
    auto* const proxy = static_cast<ServiceProxyContext*>(context);
    AcquireSRWLockExclusive(&proxy->processLock);
    bool forwarded = false;
    if (!proxy->processLocally) {
        forwarded = proxy->server->SendRaw(
            reinterpret_cast<const byte*>(record),
            recordSize) == ERROR_SUCCESS;
        if (!forwarded) [[unlikely]] {
            // Ошибка отправки также означает потерю получателя. Повторный
            // Disconnected callback не должен второй раз перезапускать снимок.
            proxy->clientConnected = false;
            SwitchServiceToLocalLocked(*proxy, false);
        }
    }
    ReleaseSRWLockExclusive(&proxy->processLock);
    return forwarded;
}

void RunServiceLoop(pmkext::KextClient* driver, ServiceProxyContext& proxy) {
    unsigned ticks = 0;
    HANDLE waits[2] = { g_driverWake, proxy.localRequest };
    while (!g_driverStop.load(std::memory_order_relaxed)) {
        const DWORD waitStatus = WaitForMultipleObjects(
            2, waits, FALSE, kStatsIntervalMs);
        if (waitStatus == WAIT_OBJECT_0) [[unlikely]] break;
        if (waitStatus == WAIT_OBJECT_0 + 1) [[unlikely]] {
            SwitchServiceToLocal(proxy, true);
            SetEvent(proxy.localReady);
            continue;
        }
        if (waitStatus != WAIT_TIMEOUT) [[unlikely]] break;

        FlowStore::Instance().Maintain();
        pmkext::ProcessTable::Instance().maintain();
        if ((++ticks % 60) == 0) [[unlikely]] driver->sendCleanEndedConnections();
    }
}

void RunServiceDriver(pmkext::KextClient* driver, bool& startupSignalled) {
    if (!driver->open()) {
        SignalDriverStart(driver->lastError(), startupSignalled);
        return;
    }

    duplex_pipe::Server server;
    const std::wstring rulesPath = ModuleDirFile(AppInfo::kRulesDb);
    ServiceProxyContext proxy;
    proxy.server = &server;
    proxy.driver = driver;
    proxy.rulesPath = &rulesPath;

    PSECURITY_DESCRIPTOR eventDescriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &eventDescriptor,
            nullptr)) {
        const DWORD error = GetLastError();
        driver->close();
        SignalDriverStart(error, startupSignalled);
        return;
    }
    SECURITY_ATTRIBUTES eventSecurity{
        sizeof(SECURITY_ATTRIBUTES), eventDescriptor, FALSE
    };
    proxy.localRequest = CreateEventW(
        &eventSecurity, FALSE, FALSE, AppInfo::kServiceLocalRequestEvent);
    proxy.localReady = CreateEventW(
        &eventSecurity, FALSE, FALSE, AppInfo::kServiceLocalReadyEvent);
    proxy.proxyReady = CreateEventW(
        &eventSecurity, FALSE, FALSE, AppInfo::kServiceProxyReadyEvent);
    LocalFree(eventDescriptor);
    if (!proxy.localRequest || !proxy.localReady || !proxy.proxyReady) {
        const DWORD error = GetLastError();
        if (proxy.localRequest) CloseHandle(proxy.localRequest);
        if (proxy.localReady) CloseHandle(proxy.localReady);
        if (proxy.proxyReady) CloseHandle(proxy.proxyReady);
        driver->close();
        SignalDriverStart(error, startupSignalled);
        return;
    }
    server.SetReceiveCallback(ForwardDriverCommand, driver);
    server.SetConnectionCallback(ServiceProxyConnectionChanged, &proxy);

    const RPC_STATUS pipeStatus = server.Start();
    if (pipeStatus != ERROR_SUCCESS) {
        CloseHandle(proxy.localRequest);
        CloseHandle(proxy.localReady);
        CloseHandle(proxy.proxyReady);
        driver->close();
        SignalDriverStart(pipeStatus, startupSignalled);
        return;
    }

    const uint64_t verdictSession = ActivateDriverSession(driver);
    if (!verdictSession) {
        server.Stop();
        CloseHandle(proxy.localRequest);
        CloseHandle(proxy.localReady);
        CloseHandle(proxy.proxyReady);
        driver->close();
        SignalDriverStart(ERROR_INVALID_HANDLE, startupSignalled);
        return;
    }

    // Драйвер может пережить оконный процесс: его прежняя AllowAll-политика
    // не должна стать разрешением локальной службы после её запуска.
    const DWORD cacheStatus = portmaster_clear_cache();
    if (cacheStatus != ERROR_SUCCESS) {
        DeactivateDriverSession(verdictSession);
        server.Stop();
        CloseHandle(proxy.localRequest);
        CloseHandle(proxy.localReady);
        CloseHandle(proxy.proxyReady);
        driver->close();
        SignalDriverStart(cacheStatus, startupSignalled);
        return;
    }

    AcquireSRWLockExclusive(&proxy.processLock);
    Ingest::Instance().SetAppInterfacesActive(!proxy.clientConnected);
    ReleaseSRWLockExclusive(&proxy.processLock);

    driver->onRawRecord = ForwardDriverRecord;
    driver->onRawRecordContext = &proxy;
    if (!driver->startReadLoop() || !driver->ioctlStartProcessMonitoring()) {
        const DWORD error = driver->lastError();
        driver->stopReadLoop();
        driver->onRawRecord = nullptr;
        driver->onRawRecordContext = nullptr;
        DeactivateDriverSession(verdictSession);
        server.Stop();
        CloseHandle(proxy.localRequest);
        CloseHandle(proxy.localReady);
        CloseHandle(proxy.proxyReady);
        driver->close();
        SignalDriverStart(error, startupSignalled);
        return;
    }

    driver->g_running = true;
    g_driverReady.store(true, std::memory_order_release);
    SignalDriverStart(ERROR_SUCCESS, startupSignalled);
    RunServiceLoop(driver, proxy);

    g_driverReady.store(false, std::memory_order_release);
    driver->g_running = false;
    driver->stopReadLoop();
    DeactivateDriverSession(verdictSession);
    driver->onRawRecord = nullptr;
    driver->onRawRecordContext = nullptr;
    server.Stop();
    CloseHandle(proxy.localRequest);
    CloseHandle(proxy.localReady);
    CloseHandle(proxy.proxyReady);
    driver->close();
}

void DriverLoop(pmkext::KextClient* driver) noexcept {
    bool startupSignalled = false;
    if (!driver) {
        SignalDriverStart(ERROR_INVALID_PARAMETER, startupSignalled);
        return;
    }

    if (FirewallX::IsService())
        RunServiceDriver(driver, startupSignalled);
    else
        RunDesktopDriver(driver, startupSignalled);

    SignalDriverStart(ERROR_OPERATION_ABORTED, startupSignalled);
}

DWORD WINAPI DriverThreadProc(void* context) noexcept {
    DriverLoop(static_cast<pmkext::KextClient*>(context));
    return 0;
}

// Создать обязательство может только фактически работающий transport. Сам
// объект move-only, поэтому дальше его можно либо припарковать, либо один раз
// передать process_verdict. external_connection_id копируется без проверки и
// используется лишь для отправки ответа драйверу.
DriverVerdictRequest RegisterDriverVerdictRequest(
    uint64_t externalConnectionId) noexcept {
#ifdef FIREWALLX_TEST_VERDICTS
    return test_register_driver_verdict_request(externalConnectionId);
#else
    AcquireSRWLockShared(&g_driverLock);
    const bool routeReady =
        (g_verdictTransport == VerdictTransport::Direct && !g_servicePipe) ||
        (g_verdictTransport == VerdictTransport::Pipe && g_servicePipe);
    DriverVerdictRequest request = g_driver && routeReady
        ? g_verdictSession.Receive(externalConnectionId)
        : DriverVerdictRequest();
    ReleaseSRWLockShared(&g_driverLock);
    return request;
#endif
}

uint64_t SuspendDriverRequestThread(
    const DriverVerdictRequest& request, DWORD pid, uint64_t threadId) noexcept {
    if (FirewallX::IsService() || !threadId) return 0;

    uint64_t token = 0;
    uint64_t externalConnectionId = 0;
    AcquireSRWLockShared(&g_driverLock);
    // TID уже находится в событии API v3, в том числе при пересылке через pipe.
    // Замок сохраняет transport и поколение до приостановки потока.
    const bool routeReady =
        (g_verdictTransport == VerdictTransport::Direct && !g_servicePipe) ||
        (g_verdictTransport == VerdictTransport::Pipe && g_servicePipe);
    if (g_driver && routeReady &&
        g_verdictSession.Inspect(request, externalConnectionId)) {
        token = ThreadSuspend::Acquire(pid, threadId);
    }
    ReleaseSRWLockShared(&g_driverLock);
    return token;
}

template <class End>
void ForgetSniOnConnectionEnd(const End* connection) {
    if (!connection) return;

    Ingest& ingest = Ingest::Instance();
    const Proto proto = ProtoFromNumber(connection->protocol);
    const bool tcpSni = proto == Proto::Tcp &&
        (connection->remote_port == 443 || connection->remote_port == 8443);
    const bool quicSni = proto == Proto::Udp && connection->remote_port == 443;
    if (!tcpSni && !quicSni) return;

    const FlowKey key = MakeFlowKey(
        proto,
        IpFromRaw(connection->local_ip), IpFromRaw(connection->remote_ip),
        connection->local_port, connection->remote_port);
    if (proto == Proto::Udp) {
        ingest.ForgetQuicSniState(key);
    } else if (ingest.mode() == IngestMode::Desktop) {
        ingest.ForgetTlsAssembly(key);
    }
}

} // namespace

#ifdef FIREWALLX_TEST_VERDICTS
// Регрессионная цель перехватывает ответы и сброс кеша без реального драйвера.
bool test_process_verdict(DriverVerdictRequest request, pmkext::Verdict verdict);
DWORD test_clear_driver_cache();
#endif

bool process_verdict(DriverVerdictRequest request, pmkext::Verdict verdict)
{
#ifdef FIREWALLX_TEST_VERDICTS
    return test_process_verdict(std::move(request), verdict);
#else
    const uint64_t session = request.session();
    uint64_t externalConnectionId = 0;
    uint64_t endedSession = 0;
    bool sent = false;
    bool wakeProxy = false;
    bool wakeDriver = false;

    AcquireSRWLockExclusive(&g_driverLock);
    pmkext::KextClient* const driver = g_driver;
    duplex_pipe::Client* const pipe = g_servicePipe;
    const VerdictTransport transport = g_verdictTransport;
    const bool routeReady =
        (transport == VerdictTransport::Pipe && pipe) ||
        (transport == VerdictTransport::Direct && !pipe);
    if (driver &&
        g_verdictSession.Consume(request, externalConnectionId)) [[likely]] {
        if (!routeReady) [[unlikely]] {
            g_driverReady.store(false, std::memory_order_release);
            endedSession = EndVerdictSessionLocked(session);
            wakeProxy = transport == VerdictTransport::Pipe;
            wakeDriver = transport == VerdictTransport::Direct;
        } else if (transport == VerdictTransport::Pipe) {
            const pmkext::CmdVerdictMessage command{
                static_cast<uint8_t>(pmkext::CommandType::Verdict),
                { externalConnectionId, static_cast<uint8_t>(verdict) }
            };
            sent = pipe->SendRaw(
                reinterpret_cast<const byte*>(&command),
                sizeof(command)) == ERROR_SUCCESS;
            if (!sent && g_servicePipe == pipe) [[unlikely]] {
                g_servicePipe = nullptr;
                g_driverReady.store(false, std::memory_order_release);
                endedSession = EndVerdictSessionLocked(session);
                wakeProxy = true;
            }
        } else {
            sent = driver->sendVerdict(externalConnectionId, verdict);
            if (!sent && g_driver == driver) [[unlikely]] {
                g_driverReady.store(false, std::memory_order_release);
                endedSession = EndVerdictSessionLocked(session);
                wakeDriver = true;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_driverLock);

    // Сначала закрываем поколение Ingest, затем разрешаем transport loop начать
    // новую сессию. Старые окна и Answer-объекты уже не смогут пройти gate.
    if (endedSession) {
        Ingest::Instance().EndDriverSession(endedSession);
        Ingest::Instance().SourceChanged(true);
    }
    if (wakeProxy && g_proxyWake) SetEvent(g_proxyWake);
    if (wakeDriver && g_driverWake) SetEvent(g_driverWake);
    return sent;
#endif
}

namespace {

DWORD SendDriverControlCommand(pmkext::CommandType type, bool optional) {
    DWORD status = optional ? ERROR_SUCCESS : ERROR_NOT_READY;
    const byte command = static_cast<byte>(type);
    uint64_t endedSession = 0;
    bool wakeProxy = false;
    bool wakeDriver = false;

    AcquireSRWLockExclusive(&g_driverLock);
    pmkext::KextClient* const driver = g_driver;
    duplex_pipe::Client* const pipe = g_servicePipe;
    const VerdictTransport transport = g_verdictTransport;
    if (driver && g_verdictSession.active()) {
        if (transport == VerdictTransport::Pipe && pipe) {
            // Ровно один байт штатной команды драйвера, без расширения pipe-ABI.
            status = pipe->SendRaw(&command, sizeof(command));
        } else if (transport == VerdictTransport::Direct && !pipe) {
            const bool sent = type == pmkext::CommandType::GetBandwidthStats
                ? driver->sendGetBandwidthStats() : driver->sendClearCache();
            status = sent ? ERROR_SUCCESS : driver->lastError();
            if (!sent && status == ERROR_SUCCESS) status = ERROR_WRITE_FAULT;
        } else {
            status = ERROR_INVALID_HANDLE;
        }
        if (status != ERROR_SUCCESS) {
            if (transport == VerdictTransport::Pipe) g_servicePipe = nullptr;
            g_driverReady.store(false, std::memory_order_release);
            endedSession = EndVerdictSessionLocked();
            wakeProxy = transport == VerdictTransport::Pipe;
            wakeDriver = transport == VerdictTransport::Direct;
        }
    }
    ReleaseSRWLockExclusive(&g_driverLock);

    if (endedSession) {
        Ingest::Instance().EndDriverSession(endedSession);
        Ingest::Instance().SourceChanged(true);
    }
    if (wakeProxy && g_proxyWake) SetEvent(g_proxyWake);
    if (wakeDriver && g_driverWake) SetEvent(g_driverWake);
    return status;
}

} // namespace

DWORD portmaster_clear_cache() {
#ifdef FIREWALLX_TEST_VERDICTS
    return test_clear_driver_cache();
#else
    return SendDriverControlCommand(pmkext::CommandType::ClearCache, true);
#endif
}

bool portmaster_request_bandwidth_stats() {
    return SendDriverControlCommand(
        pmkext::CommandType::GetBandwidthStats, false) == ERROR_SUCCESS;
}

bool portmaster_set_app_interface(const std::wstring& path, uint64_t luid) {
    const DriverControlLock lock;
    bool sent = false;
    if (g_driver && g_verdictSession.active()) {
        if (g_verdictTransport == VerdictTransport::Direct && !g_servicePipe) {
            sent = g_driver->setAppInterface(path, luid);
        } else if (g_verdictTransport == VerdictTransport::Pipe && g_servicePipe) {
            sent = g_driver->setAppInterfaceWithSender(path, luid,
                [](const uint8_t* command, size_t size) {
                    return g_servicePipe->SendRaw(command, static_cast<unsigned long>(size));
                });
        }
    }
    return sent;
}

bool portmaster_enable_route_policies() {
    const DriverControlLock lock;
    static bool called = false;
    static bool enabled = false;
    if (!called && g_driver && g_verdictSession.active()) {
        called = true;
        enabled = g_driver->enableRoutePolicies();
    }
    return enabled;
}

bool portmaster_running() {
    return g_driverReady.load(std::memory_order_acquire);
}

bool portmaster_service_connected() {
    AcquireSRWLockShared(&g_driverLock);
    const bool connected = g_servicePipe != nullptr;
    ReleaseSRWLockShared(&g_driverLock);
    return connected;
}

bool portmaster_service_process_locally() {
    AcquireSRWLockShared(&g_driverLock);
    const uint64_t expected = g_servicePipe ? g_verdictSession.active() : 0;
    ReleaseSRWLockShared(&g_driverLock);

    bool acknowledged = true;
    if (expected) {
        HANDLE request = OpenEventW(
            EVENT_MODIFY_STATE, FALSE, AppInfo::kServiceLocalRequestEvent);
        if (!request) return false;
        HANDLE ready = OpenEventW(
            SYNCHRONIZE | EVENT_MODIFY_STATE,
            FALSE,
            AppInfo::kServiceLocalReadyEvent);
        if (!ready) {
            CloseHandle(request);
            return false;
        }

        ResetEvent(ready);
        const bool signalled = SetEvent(request) != FALSE;
        acknowledged = signalled &&
            WaitForSingleObject(ready, INFINITE) == WAIT_OBJECT_0;
        CloseHandle(ready);
        CloseHandle(request);

        // После подтверждения службы новых записей в pipe не будет. Ждём,
        // пока reader дочитает ранее отправленные записи и завершит callbacks.
        duplex_pipe::DrainWait drain;
        AcquireSRWLockShared(&g_driverLock);
        const bool started = acknowledged && g_servicePipe &&
            g_verdictSession.active() == expected && drain.Start(*g_servicePipe);
        ReleaseSRWLockShared(&g_driverLock);
        acknowledged = started && drain.Wait();
        AcquireSRWLockShared(&g_driverLock);
        acknowledged = acknowledged && g_servicePipe &&
            g_verdictSession.active() == expected;
        ReleaseSRWLockShared(&g_driverLock);
        if (acknowledged) Ingest::Instance().SourceChanged();
    }

    const bool ndisAcknowledged = firewallxndisfilter_service_process_locally();
    AcquireSRWLockShared(&g_driverLock);
    const uint64_t current = g_servicePipe ? g_verdictSession.active() : 0;
    ReleaseSRWLockShared(&g_driverLock);
    return acknowledged && ndisAcknowledged && current == expected;
}

bool portmaster_service_flush_verdicts() {
    AcquireSRWLockShared(&g_driverLock);
    const bool flushed = !g_servicePipe || g_servicePipe->FlushSent();
    ReleaseSRWLockShared(&g_driverLock);
    return flushed && firewallxndisfilter_service_flush_verdicts();
}

bool portmaster_wait_ready(DWORD timeoutMs) {
    AcquireSRWLockShared(&g_driverLock);
    const HANDLE started = g_driver ? g_driverStarted : nullptr;
    ReleaseSRWLockShared(&g_driverLock);
    if (!started) return false;
    if (WaitForSingleObject(started, timeoutMs) != WAIT_OBJECT_0) return false;
    return g_driverReady.load(std::memory_order_acquire);
}

DWORD portmaster_last_error() {
    return g_driverStartError.load(std::memory_order_acquire);
}

pmkext::KextClient* portmaster_get_driver()
{
    return g_driver;
}

void portmaster_prepare_desktop_exit(bool serviceInstalled) {
    if (!serviceInstalled) return;

    AcquireSRWLockExclusive(&g_driverLock);
    if (g_driver) {
        g_driver->keepServiceOnClose.store(true, std::memory_order_release);
        // В proxy-режиме desktop не владеет службой драйвера, поэтому его
        // close() не будет настраивать регистрацию.
        if (g_servicePipe) g_driver->configureServiceBootStart();
    }
    ReleaseSRWLockExclusive(&g_driverLock);
}

void portmaster_start(HWND failureWindow, UINT failureMessage) {
    firewallxndisfilter_start();
    AcquireSRWLockShared(&g_driverLock);
    const bool alreadyStarted = g_driver != nullptr;
    ReleaseSRWLockShared(&g_driverLock);
    if (alreadyStarted) return;

    auto* const driver = new (std::nothrow) pmkext::KextClient(
        &pmkext::ProcessTable::Instance());
    if (!driver) {
        g_driverStartError.store(
            ERROR_NOT_ENOUGH_MEMORY,
            std::memory_order_release);
        NotifyDriverStartFailure(failureWindow, failureMessage, ERROR_NOT_ENOUGH_MEMORY);
        return;
    }

    // Обработчики назначаются ДО startReadLoop (требование клиента).
    driver->onConnectionV4 = [](
        const pmkext::ConnectionFixedV4* connection,
        const uint8_t* payload,
        uint32_t payloadSize) noexcept {
        on_connection_v4(connection, payload, payloadSize);
    };
    driver->onConnectionV6 = [](
        const pmkext::ConnectionFixedV6* connection,
        const uint8_t* payload,
        uint32_t payloadSize) noexcept {
        on_connection_v6(connection, payload, payloadSize);
    };
    driver->onProcessCreated = [](const pmkext::ProcessCreated*, uint32_t) noexcept {
        Ingest::Instance().ProcessEventsChanged();
    };
    driver->onBandwidthStatsV4 = [](
        uint8_t protocol,
        const pmkext::BandwidthValueV4* stats,
        uint32_t count) noexcept {
        FlowStore::Instance().AddBandwidthBatch(protocol, stats, count);
    };
    driver->onBandwidthStatsV6 = [](
        uint8_t protocol,
        const pmkext::BandwidthValueV6* stats,
        uint32_t count) noexcept {
        FlowStore::Instance().AddBandwidthBatch(protocol, stats, count);
    };
    driver->onConnectionEndV4 = [](
        const pmkext::ConnectionEndV4* connection) noexcept {
        ForgetSniOnConnectionEnd(connection);
        on_connection_end_v4(connection);
    };
    driver->onConnectionEndV6 = [](
        const pmkext::ConnectionEndV6* connection) noexcept {
        ForgetSniOnConnectionEnd(connection);
        on_connection_end_v6(connection);
    };

    const HANDLE wake = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const HANDLE proxyWake = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const HANDLE started = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!wake || !proxyWake || !started) {
        const DWORD error = GetLastError();
        if (wake) CloseHandle(wake);
        if (proxyWake) CloseHandle(proxyWake);
        if (started) CloseHandle(started);
        delete driver;
        g_driverStartError.store(error, std::memory_order_release);
        NotifyDriverStartFailure(failureWindow, failureMessage, error);
        return;
    }

    DWORD threadError = ERROR_SUCCESS;
    AcquireSRWLockExclusive(&g_driverLock);
    if (g_driver) {
        ReleaseSRWLockExclusive(&g_driverLock);
        CloseHandle(wake);
        CloseHandle(proxyWake);
        CloseHandle(started);
        delete driver;
        return;
    }

    if (g_driverWake) CloseHandle(g_driverWake);
    if (g_proxyWake) CloseHandle(g_proxyWake);
    if (g_driverStarted) CloseHandle(g_driverStarted);
    g_driverWake = wake;
    g_proxyWake = proxyWake;
    g_driverStarted = started;
    g_servicePipe = nullptr;
    g_driverStop.store(false, std::memory_order_relaxed);
    g_driverReady.store(false, std::memory_order_release);
    g_driverStartError.store(ERROR_IO_PENDING, std::memory_order_release);
    g_driverFailureWindow.store(failureWindow, std::memory_order_relaxed);
    g_driverFailureMessage.store(failureMessage, std::memory_order_relaxed);
    g_driver = driver;

    DWORD threadId = 0;
    g_driverThread = CreateThread(
        nullptr, 0, DriverThreadProc, driver, 0, &threadId);
    if (!g_driverThread) {
        threadError = GetLastError();
        g_driver = nullptr;
        g_driverWake = nullptr;
        g_proxyWake = nullptr;
        g_driverStarted = nullptr;
        g_driverStartError.store(threadError, std::memory_order_release);
    }
    ReleaseSRWLockExclusive(&g_driverLock);

    if (threadError != ERROR_SUCCESS) {
        CloseHandle(wake);
        CloseHandle(proxyWake);
        CloseHandle(started);
        delete driver;
        NotifyDriverStartFailure(failureWindow, failureMessage, threadError);
    }
}

void portmaster_stop() {
    firewallxndisfilter_stop();
    g_driverStop.store(true, std::memory_order_relaxed);

    AcquireSRWLockExclusive(&g_driverLock);
    if (g_driver) g_driver->g_running = false;
    if (g_driverWake) SetEvent(g_driverWake);
    if (g_proxyWake) SetEvent(g_proxyWake);
    const HANDLE thread = g_driverThread;
    ReleaseSRWLockExclusive(&g_driverLock);

    if (thread) WaitForSingleObject(thread, INFINITE);

    AcquireSRWLockExclusive(&g_driverLock);
    pmkext::KextClient* const dead = g_driver;
    const uint64_t endedSession = EndVerdictSessionLocked();
    g_driver = nullptr;
    g_servicePipe = nullptr;
    g_driverReady.store(false, std::memory_order_release);
    if (g_driverThread) {
        CloseHandle(g_driverThread);
        g_driverThread = nullptr;
    }
    if (g_driverWake) {
        CloseHandle(g_driverWake);
        g_driverWake = nullptr;
    }
    if (g_proxyWake) {
        CloseHandle(g_proxyWake);
        g_proxyWake = nullptr;
    }
    if (g_driverStarted) {
        CloseHandle(g_driverStarted);
        g_driverStarted = nullptr;
    }
    ReleaseSRWLockExclusive(&g_driverLock);

    if (endedSession) Ingest::Instance().EndDriverSession(endedSession);
    if (dead) delete dead;
}

namespace {

// Отображаемое имя выводится из пути и pid, поэтому в припаркованной группе
// не хранится и на горячем пути не собирается вовсе. Формулировки совпадают
// с ProcessCache::Get.
std::wstring DisplayNameFor(DWORD pid, const std::wstring& path) {
    if (!path.empty()) return PathBaseUpper(path);   // та же свёртка, что в Util.cpp
    if (pid == 0) return LoadStringRes(IDS_PROC_SYSTEM_ICMP);
    if (pid == 4) return L"SYSTEM";
    return L"PID " + std::to_wstring(pid) +
           LoadStringRes(IDS_PROC_PATH_UNAVAILABLE);
}

// Разрешающее правило обычно завершает обработку соединения навсегда.
// Для исходящего HTTP(S) нужен только Accept на payload-слое 4, а на слое 3 —
// для чистого SYN либо чистого ACK без TCP payload. Для входящего HTTP(S) на
// слое 3 Accept получает только чистый SYN+ACK. Остальные сочетания сначала
// получают PermanentAccept; незавершённый TLS ClientHello или QUIC Initial
// дополнительно заменяет его на Accept до завершения сборки.
constexpr pmkext::Verdict VerdictOf(RuleAction action, uint8_t payloadLayer,
                                     uint16_t tcpFlags, bool hasTcpPayload,
                                     Proto proto, Dir dir,
                                     uint16_t remotePort) {
    constexpr uint16_t kTcpSyn = 0x002;
    constexpr uint16_t kTcpAck = 0x010;
    constexpr uint16_t kTcpSynAck = kTcpSyn | kTcpAck;

    if (action == RuleAction::Block) return pmkext::Verdict::Drop;
    const bool webPort = remotePort == 80 || remotePort == 8080 ||
                         remotePort == 443 || remotePort == 8443;
    // Все исключения, зависящие от TCP-флагов, закрыты общей проверкой
    // протокола. Значение tcpFlags у UDP/SCTP и любого другого протокола не
    // может повлиять на вердикт.
    const bool layer3Tcp = payloadLayer == 3 && proto == Proto::Tcp;
    const bool outgoingTcpPayload = payloadLayer == 4 && proto == Proto::Tcp &&
        dir == Dir::Out;
    const bool outgoingTcpSyn = layer3Tcp && dir == Dir::Out &&
        tcpFlags == kTcpSyn;
    // ACK должен быть и единственным флагом, и не нести полезной нагрузки.
    const bool outgoingTcpAck = layer3Tcp && dir == Dir::Out &&
        tcpFlags == kTcpAck && !hasTcpPayload;
    const bool incomingTcpSynAck = layer3Tcp && dir == Dir::In &&
        tcpFlags == kTcpSynAck;
    if (webPort &&
        (outgoingTcpPayload || outgoingTcpSyn || outgoingTcpAck ||
         incomingTcpSynAck))
        return pmkext::Verdict::Accept;
    return pmkext::Verdict::PermanentAccept;
}

constexpr bool IsTlsClientHelloCandidate(uint8_t payloadLayer,
                                         uint16_t tcpFlags,
                                         bool hasTcpPayload, Proto proto,
                                         Dir dir, uint16_t remotePort) {
    constexpr uint16_t kTcpAck = 0x010;
    return payloadLayer == 3 && proto == Proto::Tcp && dir == Dir::Out &&
           (remotePort == 443 || remotePort == 8443) &&
           (tcpFlags & kTcpAck) != 0 && hasTcpPayload;
}

constexpr bool IsHttpHostCandidate(uint8_t payloadLayer, uint16_t tcpFlags,
                                   bool hasTcpPayload, Proto proto, Dir dir,
                                   uint16_t remotePort) {
    constexpr uint16_t kTcpAck = 0x010;
    return payloadLayer == 3 && proto == Proto::Tcp && dir == Dir::Out &&
           (remotePort == 80 || remotePort == 8080) &&
           (tcpFlags & kTcpAck) != 0 && hasTcpPayload;
}

constexpr bool IsQuicSniCandidate(uint8_t payloadLayer, size_t payloadLen,
                                  Proto proto, Dir dir,
                                  uint16_t remotePort) {
    return payloadLayer == 3 && payloadLen != 0 && proto == Proto::Udp &&
           dir == Dir::Out && remotePort == 443;
}

constexpr bool IsDnsQueryCandidate(uint8_t payloadLayer, size_t payloadLen,
                                    Proto proto, Dir dir, uint16_t remotePort) {
    return payloadLayer == 3 && payloadLen != 0 && proto == Proto::Udp &&
           dir == Dir::Out &&
           (remotePort == 53 || remotePort == 5353 || remotePort == 5355);
}

// Защита контракта на этапе компиляции: одинаковые «флаги» не должны включать
// TCP-исключения для протокола, у которого TCP-заголовка вообще нет.
static_assert(VerdictOf(RuleAction::Allow, 3, 0x002, false, Proto::Tcp,
                        Dir::Out, 443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x010, false, Proto::Tcp,
                        Dir::Out, 443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x010, true, Proto::Tcp,
                        Dir::Out, 443) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x012, false, Proto::Tcp,
                        Dir::In, 443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x002, false, Proto::Udp,
                        Dir::Out, 443) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x010, false, Proto::Udp,
                        Dir::Out, 443) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x012, false, Proto::Udp,
                        Dir::In, 443) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Allow, 4, 0, false, Proto::Tcp,
                        Dir::Out, 443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 4, 0, false, Proto::Udp,
                        Dir::Out, 443) == pmkext::Verdict::PermanentAccept);
static_assert(IsTlsClientHelloCandidate(3, 0x010, true, Proto::Tcp,
                                       Dir::Out, 443));
static_assert(IsTlsClientHelloCandidate(3, 0x018, true, Proto::Tcp,
                                       Dir::Out, 443));
static_assert(!IsTlsClientHelloCandidate(3, 0x018, false, Proto::Tcp,
                                        Dir::Out, 443));
static_assert(!IsTlsClientHelloCandidate(3, 0x018, true, Proto::Udp,
                                        Dir::Out, 443));
static_assert(VerdictOf(RuleAction::Allow, 3, 0x002, false, Proto::Tcp,
                        Dir::Out, 8443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x010, false, Proto::Tcp,
                        Dir::Out, 8443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x018, true, Proto::Tcp,
                        Dir::Out, 8443) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Allow, 4, 0, false, Proto::Tcp,
                        Dir::Out, 8443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x012, false, Proto::Tcp,
                        Dir::In, 8443) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 4, 0, false, Proto::Udp,
                        Dir::Out, 8443) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Block, 3, 0x002, false, Proto::Tcp,
                        Dir::Out, 8443) == pmkext::Verdict::Drop);
static_assert(IsTlsClientHelloCandidate(3, 0x010, true, Proto::Tcp,
                                       Dir::Out, 8443));
static_assert(IsTlsClientHelloCandidate(3, 0x018, true, Proto::Tcp,
                                       Dir::Out, 8443));
static_assert(!IsTlsClientHelloCandidate(3, 0x018, false, Proto::Tcp,
                                        Dir::Out, 8443));
static_assert(!IsTlsClientHelloCandidate(3, 0x008, true, Proto::Tcp,
                                        Dir::Out, 8443));
static_assert(!IsTlsClientHelloCandidate(4, 0x018, true, Proto::Tcp,
                                        Dir::Out, 8443));
static_assert(!IsTlsClientHelloCandidate(3, 0x018, true, Proto::Tcp,
                                        Dir::In, 8443));
static_assert(!IsTlsClientHelloCandidate(3, 0x018, true, Proto::Udp,
                                        Dir::Out, 8443));
static_assert(!IsTlsClientHelloCandidate(3, 0x018, true, Proto::Tcp,
                                        Dir::Out, 9443));
static_assert(IsHttpHostCandidate(3, 0x010, true, Proto::Tcp, Dir::Out, 80));
static_assert(IsHttpHostCandidate(3, 0x018, true, Proto::Tcp, Dir::Out, 80));
static_assert(!IsHttpHostCandidate(3, 0x010, false, Proto::Tcp, Dir::Out, 80));
static_assert(!IsHttpHostCandidate(3, 0x008, true, Proto::Tcp, Dir::Out, 80));
static_assert(!IsHttpHostCandidate(4, 0x018, true, Proto::Tcp, Dir::Out, 80));
static_assert(!IsHttpHostCandidate(3, 0x018, true, Proto::Tcp, Dir::In, 80));
static_assert(!IsHttpHostCandidate(3, 0x018, true, Proto::Tcp, Dir::Out, 443));
static_assert(!IsHttpHostCandidate(3, 0x018, true, Proto::Udp, Dir::Out, 80));
static_assert(VerdictOf(RuleAction::Allow, 4, 0, false, Proto::Tcp,
                        Dir::Out, 8080) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x002, false, Proto::Tcp,
                        Dir::Out, 8080) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x012, false, Proto::Tcp,
                        Dir::In, 8080) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x010, false, Proto::Tcp,
                        Dir::Out, 8080) == pmkext::Verdict::Accept);
static_assert(VerdictOf(RuleAction::Allow, 3, 0x018, true, Proto::Tcp,
                        Dir::Out, 8080) == pmkext::Verdict::PermanentAccept);
static_assert(VerdictOf(RuleAction::Block, 3, 0x002, false, Proto::Tcp,
                        Dir::Out, 8080) == pmkext::Verdict::Drop);
static_assert(IsHttpHostCandidate(3, 0x010, true, Proto::Tcp, Dir::Out, 8080));
static_assert(IsHttpHostCandidate(3, 0x018, true, Proto::Tcp, Dir::Out, 8080));
static_assert(!IsHttpHostCandidate(3, 0x010, false, Proto::Tcp, Dir::Out, 8080));
static_assert(!IsHttpHostCandidate(3, 0x008, true, Proto::Tcp, Dir::Out, 8080));
static_assert(!IsHttpHostCandidate(4, 0x018, true, Proto::Tcp, Dir::Out, 8080));
static_assert(!IsHttpHostCandidate(3, 0x018, true, Proto::Tcp, Dir::In, 8080));
static_assert(!IsHttpHostCandidate(3, 0x018, true, Proto::Udp, Dir::Out, 8080));
static_assert(!IsHttpHostCandidate(3, 0x018, true, Proto::Tcp, Dir::Out, 8081));
static_assert(IsQuicSniCandidate(3, 1200, Proto::Udp, Dir::Out, 443));
static_assert(!IsQuicSniCandidate(4, 1200, Proto::Udp, Dir::Out, 443));
static_assert(!IsQuicSniCandidate(3, 0, Proto::Udp, Dir::Out, 443));
static_assert(!IsQuicSniCandidate(3, 1200, Proto::Tcp, Dir::Out, 443));
static_assert(IsDnsQueryCandidate(3, 79, Proto::Udp, Dir::Out, 53));
static_assert(!IsDnsQueryCandidate(4, 79, Proto::Udp, Dir::Out, 53));
static_assert(!IsDnsQueryCandidate(3, 0, Proto::Udp, Dir::Out, 53));
static_assert(!IsDnsQueryCandidate(3, 79, Proto::Tcp, Dir::Out, 53));
static_assert(!IsDnsQueryCandidate(3, 79, Proto::Udp, Dir::In, 53));
static_assert(IsDnsQueryCandidate(3, 79, Proto::Udp, Dir::Out, 5355));
static_assert(!IsDnsQueryCandidate(4, 79, Proto::Udp, Dir::Out, 5355));
static_assert(!IsDnsQueryCandidate(3, 0, Proto::Udp, Dir::Out, 5355));
static_assert(!IsDnsQueryCandidate(3, 79, Proto::Tcp, Dir::Out, 5355));
static_assert(!IsDnsQueryCandidate(3, 79, Proto::Udp, Dir::In, 5355));
static_assert(IsDnsQueryCandidate(3, 79, Proto::Udp, Dir::Out, 5353));
static_assert(!IsDnsQueryCandidate(4, 79, Proto::Udp, Dir::Out, 5353));
static_assert(!IsDnsQueryCandidate(3, 0, Proto::Udp, Dir::Out, 5353));
static_assert(!IsDnsQueryCandidate(3, 79, Proto::Tcp, Dir::Out, 5353));
static_assert(!IsDnsQueryCandidate(3, 79, Proto::Udp, Dir::In, 5353));

std::shared_ptr<const std::wstring> MakeDomainLabel(const std::string& domain) {
    if (domain.empty()) return {};

    std::wstring label = Utf8ToWide(domain);
    if (label.empty()) return {};
    label.insert(label.begin(), L'[');
    label.push_back(L']');
    return std::make_shared<const std::wstring>(std::move(label));
}

std::shared_ptr<const std::wstring> ReadDnsDomainLabel(const uint8_t* packet,
                                                       size_t packetLen) {
#ifdef FIREWALLX_TEST_VERDICTS
    ++IngestWorkProbe::counts.dnsParses;
#endif
    return MakeDomainLabel(GetDnsQueryDomain(packet, packetLen));
}

std::shared_ptr<const std::wstring> ReadTlsDomainLabel(const uint8_t* payload,
                                                       size_t payloadLen) {
    return MakeDomainLabel(GetTlsClientHelloDomain(payload, payloadLen));
}

std::shared_ptr<const std::wstring> ReadHttpDomainLabel(const uint8_t* packet,
                                                        size_t packetLen) {
    if (!packet || packetLen == 0 ||
        packetLen > std::numeric_limits<uint32_t>::max()) return {};

    const std::string_view host = getHttpHost(
        packet, static_cast<uint32_t>(packetLen));
    if (host.empty()) return {};
    return MakeDomainLabel(std::string(host));
}

bool IsBlockingVerdict(pmkext::Verdict verdict) {
    switch (verdict) {
    case pmkext::Verdict::Block:
    case pmkext::Verdict::PermanentBlock:
    case pmkext::Verdict::Drop:
    case pmkext::Verdict::PermanentDrop:
        return true;
    default:
        return false;
    }
}

bool IsAllowingVerdict(pmkext::Verdict verdict) {
    switch (verdict) {
    case pmkext::Verdict::Accept:
    case pmkext::Verdict::PermanentAccept:
    case pmkext::Verdict::RedirectNameServer:
    case pmkext::Verdict::RedirectTunnel:
    case pmkext::Verdict::RedirectSplitTunnel:
        return true;
    default:
        return false;
    }
}

// Снятие записей по сроку без полного обхода растущей карты. Каждое касание
// добавляет короткую запись в FIFO; старая запись не трогает более свежий tick.
template <class Map, class Queue>
void ExpireQueued(Map& map, Queue& queue, ULONGLONG now, ULONGLONG ttl) {
    while (!queue.empty() && now - queue.front().tick > ttl) {
        const auto expired = queue.front();
        queue.pop_front();
        const auto it = map.find(expired.key);
        if (it != map.end() && it->second.tick == expired.tick)
            map.erase(it);
    }
}

// Что удалось извлечь из payload одного события.
struct PacketFacts {
    IpPacketInfo ip;
    bool         parsed = false;
    uint16_t     tcpFlags = 0;
    bool         hasTcpPayload = false;
    uint32_t     tcpSequence = 0;
    const uint8_t* tcpPayload = nullptr;
    size_t       tcpPayloadBytes = 0;
    uint64_t     bytes = 0;
    IcmpInfo     icmp;
};

// Флаги находятся в четырнадцатом байте TCP-заголовка. До него достаточно
// первых 14 байт, но дополнительно проверяем минимальный размер и Data Offset,
// чтобы случайные данные усечённого/повреждённого пакета не были приняты за TCP.
bool ReadTcpFacts(const uint8_t* packet, size_t len,
                  const IpPacketInfo& ip, PacketFacts& facts) {
#ifdef FIREWALLX_TEST_VERDICTS
    ++IngestWorkProbe::counts.tcpReads;
#endif
    constexpr size_t kTcpMinHeaderBytes = 20;
    constexpr size_t kTcpFlagsOffset = 13;
    constexpr uint16_t kTcpSyn = 0x002;

    if (!packet || ip.fragment || ip.proto != DriverProto::kTcp ||
        ip.payloadBytes < kTcpMinHeaderBytes || ip.headerBytes > len ||
        len - ip.headerBytes <= kTcpFlagsOffset)
        return false;

    const uint8_t* const tcp = packet + ip.headerBytes;
    const size_t capturedTcpBytes = len - ip.headerBytes;
    const size_t tcpHeaderBytes = static_cast<size_t>(tcp[12] >> 4) * 4u;
    if (tcpHeaderBytes < kTcpMinHeaderBytes ||
        tcpHeaderBytes > ip.payloadBytes || tcpHeaderBytes > capturedTcpBytes) [[unlikely]]
        return false;

    // В младшем байте — восемь обычных флагов, в бите 8 — NS из младшего
    // бита предыдущего байта. Поэтому даже NS+ACK не считается чистым ACK.
    facts.tcpFlags = static_cast<uint16_t>(tcp[kTcpFlagsOffset]) |
                     static_cast<uint16_t>((tcp[12] & 0x01u) << 8);

    const uint32_t sequence =
        (static_cast<uint32_t>(tcp[4]) << 24) |
        (static_cast<uint32_t>(tcp[5]) << 16) |
        (static_cast<uint32_t>(tcp[6]) << 8) |
         static_cast<uint32_t>(tcp[7]);
    // SYN занимает одно sequence-значение перед первым байтом данных.
    facts.tcpSequence = sequence + ((facts.tcpFlags & kTcpSyn) ? 1u : 0u);

    const size_t declaredPayloadBytes = ip.payloadBytes - tcpHeaderBytes;
    facts.hasTcpPayload = declaredPayloadBytes != 0;
    facts.tcpPayloadBytes = std::min(
        declaredPayloadBytes, capturedTcpBytes - tcpHeaderBytes);
    if (facts.tcpPayloadBytes)
        facts.tcpPayload = tcp + tcpHeaderBytes;
    return true;
}

// ---------------------------------------------------------------------------
// Разбор payload: ОДИН проход даёт тип ICMP, флаги и наличие полезной нагрузки
// TCP, размер пакета и адреса.
// ---------------------------------------------------------------------------
PacketFacts ReadPacket(const uint8_t* payload, size_t len, uint8_t protocol,
                       uint16_t remotePort) {
    PacketFacts f;
    if (!payload || !len) return f;

    const bool icmpProto = ProtoIsIcmp(ProtoFromNumber(protocol));

    if (ParseIpPacket(payload, len, f.ip)) {
        f.parsed = true;
        // ParseIpPacket обычно берёт размер из заголовка, даже при усечённом
        // payload; для нулевого IPv6 Payload Length используется доступный len.
        f.bytes = f.ip.totalBytes;
        if (icmpProto && f.ip.icmp.known()) f.icmp = f.ip.icmp;
        // Флаги, sequence и TCP payload нужны только исключениям HTTP(S).
        if (protocol == DriverProto::kTcp &&
            (remotePort == 80 || remotePort == 8080 ||
             remotePort == 443 || remotePort == 8443))
            ReadTcpFacts(payload, len, f.ip, f);
        return f;
    }

    f.bytes = len;
    if (icmpProto && len >= 2) {
        f.icmp.type = payload[0];
        f.icmp.code = payload[1];
        f.icmp.v6   = protocol == DriverProto::kIcmpV6;
    }
    return f;
}

// Заголовки известных протоколов не входят в полезную нагрузку FirewallXNdisFilter.
// Для неизвестного формата считаем тело IP; у ESP доступны только открытые
// SPI/Sequence Number: IV, padding и аутентификацию без параметров SA не отделить.
uint64_t NdisProtocolPayloadBytes(const uint8_t* data, size_t bytes, uint8_t protocol) {
    size_t header = 0;
    switch (protocol) {
    case 1:     // ICMP
    case 2:     // IGMP
    case 46:    // RSVP
    case 50:    // ESP: открытый заголовок
    case 58:    // ICMPv6
    case 112:   // VRRP
    case 136:   // UDP-Lite
        header = 8;
        break;
    case 33: {  // DCCP: Data Offset включает опции и заголовок подтверждения.
        if (bytes < 12) return 0;
        const uint8_t type = (data[8] >> 1) & 0x0f;
        if (type > 9) return 0;
        const bool extended = (data[8] & 1) != 0;
        size_t minimum = extended ? 16u : 12u;
        if (type == 0) minimum += 4; // Request: Service Code.
        else if (type != 2) {
            minimum += extended ? 8u : 4u; // Acknowledgement Number.
            if (type == 1 || type == 7) minimum += 4; // Response/Reset.
        }
        header = static_cast<size_t>(data[4]) * 4u;
        if (header < minimum) return 0;
        break;
    }
    case 47: {  // GRE v0: Checksum, Key и Sequence Number — необязательные поля.
        if (bytes < 4) return 0;
        const uint16_t flags = static_cast<uint16_t>((data[0] << 8) | data[1]);
        // Не угадываем длину старого Source Routing и других версий GRE.
        if (flags & ~0xb000u) return 0;
        header = 4;
        for (uint16_t flag : {uint16_t{0x8000}, uint16_t{0x2000}, uint16_t{0x1000}})
            if (flags & flag) header += 4;
        break;
    }
    case 51:    // AH: длина задаётся в 32-битных словах без первых двух слов.
        if (bytes < 2) return 0;
        header = (static_cast<size_t>(data[1]) + 2) * 4u;
        if (header < 12) return 0;
        break;
    case 59:    // IPv6 No Next Header: следующих данных нет.
        return 0;
    case 88:    // EIGRP
        header = 20;
        break;
    case 89:    // OSPFv2/v3
        if (!bytes || (data[0] != 2 && data[0] != 3)) return 0;
        header = data[0] == 2 ? 24 : 16;
        break;
    case 97:    // EtherIP
        if (bytes < 2 || data[0] != 0x30 || data[1] != 0) return 0;
        header = 2;
        break;
    case 103:   // PIM
    case 108:   // IPComp
        header = 4;
        break;
    case 132: { // SCTP: только данные DATA/I-DATA, без контрольных chunks и padding.
        if (bytes < 12) return 0;
        uint64_t result = 0;
        size_t offset = 12;
        while (bytes - offset >= 4) {
            const uint8_t* chunk = data + offset;
            const size_t length = static_cast<size_t>((chunk[2] << 8) | chunk[3]);
            if (length < 4) return 0;
            if (chunk[0] == 0 || chunk[0] == 64) {
                const size_t chunkHeader = chunk[0] == 0 ? 16 : 20;
                if (length < chunkHeader) return 0;
                const size_t captured = std::min(length, bytes - offset);
                if (captured > chunkHeader) result += captured - chunkHeader;
            }
            const size_t padded = (length + 3u) & ~size_t{3};
            if (padded > bytes - offset) break;
            offset += padded;
        }
        return result;
    }
    default:
        break;
    }
    return bytes > header ? bytes - header : 0;
}

// Считаем только захваченные данные в пределах длины IP-пакета. Заголовки
// IPv4/IPv6 с расширениями уже разобраны; у продолжения фрагмента заголовок
// протокола отсутствует, поэтому повторно его не вычитаем.
uint64_t NdisPayloadBytes(const PacketFacts& facts, const uint8_t* payload,
                           size_t len, uint8_t protocol) {
    if (!facts.parsed || facts.ip.proto != protocol ||
        ProtoInOsTables(ProtoFromNumber(protocol))) return 0;

    const size_t end = std::min(facts.ip.totalBytes, len);
    if (facts.ip.headerBytes >= end) return 0;
    const size_t bytes = end - facts.ip.headerBytes;
    if (facts.ip.fragment) return bytes;
    return NdisProtocolPayloadBytes(payload + facts.ip.headerBytes, bytes, protocol);
}

// ---------------------------------------------------------------------------
// Направление события: ЕДИНСТВЕННОЕ место, где решается, в «отправлено» или
// в «получено» попадут байты пакета.
//
//   src == local,  dst == remote  -> исходящий
//   src == remote, dst == local   -> входящий
//   src == dst                    -> петля: разделяем по типу ICMP
//   ни то, ни другое              -> остаётся поле события
// ---------------------------------------------------------------------------
Dir ResolveDir(const PacketFacts& pf, Proto proto,
               const IpAddr& local, const IpAddr& remote, Dir driverDir) {
    if (!pf.parsed || !pf.ip.hasAddrs) return driverDir;

    if (pf.ip.src == pf.ip.dst) {
        if (ProtoIsIcmp(proto) && pf.icmp.known())
            return IcmpIsReply(pf.icmp.type, pf.icmp.v6) ? Dir::In : Dir::Out;
        return driverDir;
    }
    if (pf.ip.src == local  && pf.ip.dst == remote) return Dir::Out;
    if (pf.ip.src == remote && pf.ip.dst == local)  return Dir::In;
    return driverDir;
}

} // namespace

// ---------------------------------------------------------------------------

Ingest& Ingest::Instance() {
    static Ingest inst;
    return inst;
}

Ingest& Ingest::ForSource(TrafficSource source) {
    if (source == TrafficSource::Host) return Instance();
    static Ingest ndis(TrafficSource::Ndis);
    return ndis;
}

bool Ingest::SendVerdict(DriverVerdictRequest request, pmkext::Verdict verdict) {
    if (source_ == TrafficSource::Host) return process_verdict(std::move(request), verdict);
    using Verdict = firewallxndisfilter::Client::Verdict;
    Verdict native;
    switch (verdict) {
    case pmkext::Verdict::Accept: native = Verdict::Accept; break;
    case pmkext::Verdict::PermanentAccept: native = Verdict::PermanentAccept; break;
    case pmkext::Verdict::Block: native = Verdict::Block; break;
    case pmkext::Verdict::PermanentBlock: native = Verdict::PermanentBlock; break;
    case pmkext::Verdict::Drop: native = Verdict::Drop; break;
    case pmkext::Verdict::PermanentDrop: native = Verdict::PermanentDrop; break;
    default: return false;
    }
    return firewallxndisfilter_process_verdict(std::move(request), native);
}

std::wstring_view Ingest::Flow::appPath() const {
    return app ? std::wstring_view(app->text) : std::wstring_view();
}

std::wstring_view Ingest::Flow::foldedAppPath() const {
    return app ? std::wstring_view(app->folded) : std::wstring_view();
}

uint64_t Ingest::Flow::appPathHash() const {
    return app ? app->foldedHash : kFoldedTextHashBasis;
}

MatchQuery Ingest::Flow::ToQuery() const {
    // Одно отображение на всю программу: см. MakeMatchQuery в Rules.h.
    MatchQuery q = MakeMatchQuery(
        appPath(), pid, key, dir, icmpType, icmpCode,
        app ? app->process.get() : nullptr, conditionFlags);
    PrepareMatchAppPath(q, foldedAppPath(), appPathHash());
    q.lineage = lineage.get();
    if (interfaceIndex) q.interfaceIndex = interfaceIndex;
    q.interfaceName = interfaceName.get();
    return q;
}

// ---------------------------------------------------------------------------
// Ключ кеша формы соединения.
//
// Включает ВСЁ, что читает RuleStore::MatchVerdict: путь, протокол,
// направление, оба адреса, оба порта, тип и код ICMP, интерфейс, маску WFP и признак PID 0.
// Без наследования ненулевые PID не различаются; с ним в ключ входит весь PID.
// Конкретный PID и дескриптор нужны лишь условию «сервис», а при наличии таких
// правил кеш выключен целиком (см. SyncRulesLocked).
// payload_layer,
// TCP-флаги и наличие полезной нагрузки TCP тоже не входят в ключ: matcher их не
// читает, кеш хранит RuleAction, а конкретный driver-verdict вычисляется для
// каждого события.
// Путь начинает FNV-проход уже готовым хэшем из ProcessPathInfo: посимвольная
// свёртка выполняется один раз при первом чтении пути процесса.
// ---------------------------------------------------------------------------
uint64_t Ingest::ShapeKeyOf(const Flow& f, bool inheritance) {
#ifdef FIREWALLX_TEST_VERDICTS
    ++IngestWorkProbe::counts.shapeHashes;
#endif
    uint64_t h = f.appPathHash();
    const auto mix = [&h](const void* p, size_t n) {
        const uint8_t* q = static_cast<const uint8_t*>(p);
        for (size_t i = 0; i < n; ++i) { h ^= q[i]; h *= 1099511628211ull; }
    };
    const uint8_t pr = ProtoNumber(f.key.proto);
    const uint8_t dr = static_cast<uint8_t>(f.dir);
    const uint8_t pidZero = f.pid == 0 ? 1 : 0;
    mix(&pidZero, 1);
    mix(&f.interfaceIndex, sizeof(f.interfaceIndex));
    const bool flagsKnown = f.conditionFlags.has_value();
    mix(&flagsKnown, sizeof(flagsKnown));
    if (f.conditionFlags) mix(&*f.conditionFlags, sizeof(*f.conditionFlags));
    // Один exe может иметь разные группы правил в зависимости от предков.
    if (inheritance) mix(&f.pid, sizeof(f.pid));
    mix(&pr, 1);
    mix(&dr, 1);
    mix(&f.key.local.family,  2); mix(f.key.local.b,  f.key.local.len());
    mix(&f.key.remote.family, 2); mix(f.key.remote.b, f.key.remote.len());
    mix(&f.key.lport, 2);
    mix(&f.key.rport, 2);
    const int16_t t = static_cast<int16_t>(f.icmpType);
    const int16_t c = static_cast<int16_t>(f.icmpCode);
    mix(&t, 2);
    mix(&c, 2);
    return h;
}

bool Ingest::ReloadServicePolicy() {
    std::lock_guard reloadLock(g_serviceReloadMutex);
    std::unique_lock policyLock(policyMtx_);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!rules_ || mode_.load(std::memory_order_relaxed) != IngestMode::Service)
            return false;
    }
    const FirewallPolicy policy = FirewallPolicySetting::Load();
#ifdef FIREWALLX_TEST_VERDICTS
    if (IngestWorkProbe::afterServicePolicyLoad) IngestWorkProbe::afterServicePolicyLoad();
#endif
    std::lock_guard<std::mutex> lock(mtx_);
    if (!rules_ || mode_.load(std::memory_order_relaxed) != IngestMode::Service)
        return false;
    if (policy_.load(std::memory_order_relaxed) != policy) {
        policy_.store(policy, std::memory_order_relaxed);
        verdicts_ = decltype(verdicts_){};
        verdictExpiry_.clear();
    }
    return true;
}

bool Ingest::ReloadServiceRules(const std::wstring& path) {
    // Последовательность чтения и публикации должна быть общей для обоих
    // источников: более ранняя загрузка не может затереть свежую политику.
    std::lock_guard reloadLock(g_serviceReloadMutex);
    std::unique_lock policyLock(policyMtx_);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!rules_ || mode_.load(std::memory_order_relaxed) != IngestMode::Service)
            return false;
    }
    const FirewallPolicy policy = FirewallPolicySetting::Load();
    if (source_ == TrafficSource::Ndis) net::SharedNetworkInterfaces().Refresh();
#ifdef FIREWALLX_TEST_VERDICTS
    if (IngestWorkProbe::afterServicePolicyLoad) IngestWorkProbe::afterServicePolicyLoad();
#endif

    // Пока записи проксировались desktop-клиенту, служебный процесс мог долго
    // не обращаться к SCM. При возврате к локальной обработке состав служб
    // перечитывается вместе с правилами, а не ждёт фонового такта.
    //
    // Монитор приостанавливается до загрузки: это исключает лишний параллельный
    // опрос между Invalidate и обязательной синхронной подготовкой снимка.
    if (source_ == TrafficSource::Host) {
        ServiceInfo::SetMonitoring(false);
        ServiceInfo::Invalidate();
    }

    bool refreshServices = false;
    bool loaded = false;
    RuleStore* reloadedRules = nullptr;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!rules_ || mode_.load(std::memory_order_relaxed) != IngestMode::Service)
            return false;

        reloadedRules = rules_;
        std::wstring error;
        loaded = rules_->LoadOnce(path, error);
        policy_.store(policy, std::memory_order_relaxed);

        // В том числе после ошибки: LoadOnce уже заменил прежний набор пустым
        // снимком, поэтому кеши его решений также недействительны.
        verdicts_ = decltype(verdicts_){};
        verdictExpiry_.clear();
        rulesVersion_ = 0;
        shapeCacheOn_ = false;
        shapeCacheRules_ = nullptr;
        // В service mode после reload нет обязательного вызова FlushVerdicts,
        // поэтому согласуем кеш сразу. Для правил с изменчивыми условиями
        // SyncRulesLocked оставит его выключенным.
        if (loaded) SyncRulesLocked();
        refreshServices = source_ == TrafficSource::Host && loaded && rules_->serviceConds();
    }

    // NDIS мог ещё не запуститься или не подключиться к окну. Его локальный
    // маршрут всё равно должен получить политику при возвращении хоста службе.
    if (source_ == TrafficSource::Host) {
        Ingest& ndis = ForSource(TrafficSource::Ndis);
        std::unique_lock ndisPolicyLock(ndis.policyMtx_);
        std::lock_guard<std::mutex> lock(ndis.mtx_);
        if (ndis.rules_ == reloadedRules &&
            ndis.mode_.load(std::memory_order_relaxed) == IngestMode::Service) {
            ndis.policy_.store(policy, std::memory_order_relaxed);
            ndis.verdicts_ = decltype(ndis.verdicts_){};
            ndis.verdictExpiry_.clear();
        }
    }

    // Снимок подготавливается до подтверждения переключения на службу. При
    // временной ошибке SCM фоновый монитор повторит попытку через короткий TTL.
    // До успеха читается последний полный снимок, если он уже был опубликован;
    // без такого снимка сервисное условие не совпадает.
    if (refreshServices) ServiceInfo::Version(true);
    if (source_ == TrafficSource::Host) ServiceInfo::SetMonitoring(refreshServices);
    // После ухода desktop драйвер не должен сохранять решения прежнего снимка.
    // В том числе после ошибки загрузки: действует перечитанная политика,
    // а Learning без правила по-прежнему задаёт Drop.
    if (source_ == TrafficSource::Host) portmaster_clear_cache();
    else firewallxndisfilter_clear_cache();
    return loaded;
}

void Ingest::Attach(RuleStore* rules, HWND ui, IngestMode mode,
                    FirewallPolicy policy) {
    if (source_ == TrafficSource::Host)
        ForSource(TrafficSource::Ndis).Attach(rules, ui, mode, policy);
    const UINT msg = RegisterWindowMessageW(L"FirewallX.Ingest.Pending");
    const UINT sourceMsg = RegisterWindowMessageW(L"FirewallX.Ingest.SourceChanged");

    std::unique_lock policyLock(policyMtx_);
    std::lock_guard<std::mutex> lk(mtx_);
    rules_ = rules;
    if (source_ == TrafficSource::Host && rules_)
        rules_->SetAppInterfaceHandler(portmaster_set_app_interface, portmaster_enable_route_policies);
    ui_.store(ui, std::memory_order_relaxed);
    mode_.store(mode, std::memory_order_relaxed);
    policy_.store(FirewallPolicies::IsValid(policy) ? policy : FirewallPolicy::Learning,
                  std::memory_order_relaxed);
    if (msg) msg_.store(msg, std::memory_order_relaxed);
    if (sourceMsg) sourceMsg_.store(sourceMsg, std::memory_order_relaxed);
    if (mode == IngestMode::Service) {
        // В службе SNI нигде не публикуется; незавершённые desktop-сборки ей
        // не нужны и не должны удерживать память после переключения маршрута.
        tlsAssemblies_ = decltype(tlsAssemblies_){};
        tlsAssemblyExpiry_.clear();
        for (auto& state : quicSniStates_)
            quic_sni::FreeQuicSniState(&state.second.state);
        quicSniStates_ = decltype(quicSniStates_){};
        quicSniSweptAt_ = 0;
    }

    // Хранилище другое — прежние решения к нему не относятся. Первичная
    // синхронизация выполняется при Attach, вне обработки событий.
    verdicts_ = decltype(verdicts_){};
    verdictExpiry_.clear();
    rulesVersion_ = rules_ ? rules_->version() : 0;
    shapeCacheOn_ = rules_ && !rules_->volatileConds();
    inheritanceOn_ = source_ == TrafficSource::Host && rules_ && rules_->inheritanceConds();
    shapeCacheRules_ = rules_;
}

DWORD Ingest::SetPolicy(FirewallPolicy policy) {
    if (!FirewallPolicies::IsValid(policy)) return ERROR_INVALID_PARAMETER;
    if (source_ == TrafficSource::Host)
        ForSource(TrafficSource::Ndis).SetPolicy(policy);

    std::unique_lock policyLock(policyMtx_);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (mode_.load(std::memory_order_relaxed) != IngestMode::Desktop)
            return ERROR_NOT_SUPPORTED;
        if (policy_.load(std::memory_order_relaxed) == policy)
            return ERROR_SUCCESS;
        policy_.store(policy, std::memory_order_relaxed);
        verdicts_ = decltype(verdicts_){};
        verdictExpiry_.clear();
    }

    policyLock.unlock();
    Notify();
    return ERROR_SUCCESS;
}

void Ingest::ProcessEventsChanged() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!waiting_ || !rules_ || !rules_->inheritanceConds()) return;
    }
    FlushVerdicts();
    Notify();
}

void Ingest::Detach() {
    if (source_ == TrafficSource::Host) ForSource(TrafficSource::Ndis).Detach();
    std::lock_guard<std::mutex> lk(mtx_);
    if (source_ == TrafficSource::Host && rules_) rules_->SetAppInterfacesActive(false);
    rules_ = nullptr;
    ui_.store(nullptr, std::memory_order_relaxed);
    verdicts_ = decltype(verdicts_){};
    verdictExpiry_.clear();
    rulesVersion_ = 0;
    shapeCacheOn_ = false;
    shapeCacheRules_ = nullptr;
    // Припаркованные обязательства НЕ сбрасываются: отсоединение хранилища
    // правил не означает, что соединения перестали ждать вердикта.
}

void Ingest::NotifySourceChanged() {
    const HWND ui = ui_.load(std::memory_order_relaxed);
    const UINT msg = sourceMsg_.load(std::memory_order_relaxed);
    if (ui && msg && IsWindow(ui)) PostMessageW(ui, msg, 0, 0);
}

void Ingest::SourceChanged(bool notifyUi) {
    if (source_ == TrafficSource::Host) OwnerLookup::Invalidate();
    if (notifyUi) NotifySourceChanged();
}

void Ingest::ClearDriverSessionLocked() {
    // Ответы, оставшиеся в pending при обрыве transport-а, больше нельзя
    // отправить в драйвер. Сначала освобождаем их удержания, иначе поток мог
    // бы остаться приостановленным после закрытия окна.
    for (auto& group : pending_) {
        for (PendingRequest& pending : group.second.requests) {
            ThreadSuspend::Release(pending.threadSuspendToken);
            pending.threadSuspendToken = 0;
        }
    }
    pending_ = PendingMap{};
    pendingIndex_ = decltype(pendingIndex_){};
    tlsAssemblies_ = decltype(tlsAssemblies_){};
    tlsAssemblyExpiry_.clear();
    for (auto& state : quicSniStates_)
        quic_sni::FreeQuicSniState(&state.second.state);
    quicSniStates_ = decltype(quicSniStates_){};
    quicSniSweptAt_ = 0;
    verdicts_ = decltype(verdicts_){};
    verdictExpiry_.clear();

    // pendingSeq_ намеренно не обнуляется: очередь UI может ещё содержать
    // идентификаторы старых групп, и они не должны совпасть с новыми.
    rulesVersion_ = 0;
    shapeCacheOn_ = false;
    shapeCacheRules_ = nullptr;
    calls_ = 0;
    answered_ = 0;
    waiting_ = 0;
    sweep_ = 0;
}

void Ingest::BeginDriverSession(uint64_t session) {
    if (!session) return;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // Begin публикуется вне transport-замка. Монотонный номер не позволяет
        // запоздавшему callback старого подключения затереть более новую сессию.
        if (session <= newestDriverSession_) return;
        ClearDriverSessionLocked();
        newestDriverSession_ = session;
        driverSession_ = session;
        if (source_ == TrafficSource::Host && rules_) {
            rules_->SetAppInterfacesActive(false);
            if (mode() != IngestMode::Service) rules_->SetAppInterfacesActive(true);
        }
        rulesVersion_ = rules_ ? rules_->version() : 0;
        shapeCacheOn_ = rules_ && !rules_->volatileConds();
        inheritanceOn_ = source_ == TrafficSource::Host && rules_ && rules_->inheritanceConds();
        shapeCacheRules_ = rules_;
    }

    // Новый transport получает отдельное поколение состояния. Ни строки,
    // ни история владельцев прежнего поколения в него не переносятся.
    if (source_ == TrafficSource::Host) {
        FlowStore::Instance().ResetHost();
        OwnerLookup::ResetSession();
    } else {
        FlowStore::Instance().CancelNdisBandwidthPoll();
    }
    Notify();
}

void Ingest::SetAppInterfacesActive(bool active) {
    if (source_ != TrafficSource::Host) return;
    std::lock_guard lock(mtx_);
    if (rules_) rules_->SetAppInterfacesActive(active);
}

void Ingest::EndDriverSession(uint64_t session) {
    if (!session) return;
    bool ended = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (driverSession_ == session) {
            if (source_ == TrafficSource::Host && rules_) rules_->SetAppInterfacesActive(false);
            ClearDriverSessionLocked();
            driverSession_ = 0;
            ended = true;
        }
    }
    if (!ended) return;

    if (source_ == TrafficSource::Host) {
        FlowStore::Instance().ResetHost();
        OwnerLookup::ResetSession();
    } else {
        FlowStore::Instance().CancelNdisBandwidthPoll();
    }
    Notify();
}

void Ingest::ExpireTlsAssembliesLocked(ULONGLONG now) {
    while (!tlsAssemblyExpiry_.empty() &&
           now - tlsAssemblyExpiry_.front().tick > kTlsAssemblyTtlMs) {
        const TlsAssemblyExpiry expired = tlsAssemblyExpiry_.front();
        tlsAssemblyExpiry_.pop_front();
        const auto assembly = tlsAssemblies_.find(expired.key);
        if (assembly != tlsAssemblies_.end() &&
            assembly->second.tick == expired.tick) {
            tlsAssemblies_.erase(assembly);
        }
    }
}

void Ingest::ExpireQuicSniStatesLocked(ULONGLONG now) {
    constexpr ULONGLONG kSweepMs = 1000;
    if (quicSniStates_.empty() ||
        (quicSniSweptAt_ && now - quicSniSweptAt_ < kSweepMs)) return;
    quicSniSweptAt_ = now;

    // Очередь на каждый пакет только дублировала бы историю касаний. Достаточно
    // раз в секунду обойти состояния незавершённых ClientHello; erase вызывает
    // деструктор владельца и освобождает также буферы дешифрования и CRYPTO.
    for (auto it = quicSniStates_.begin(); it != quicSniStates_.end();) {
        it = now - it->second.tick > kQuicSniTtlMs
            ? quicSniStates_.erase(it) : std::next(it);
    }
}

void Ingest::ForgetTlsAssembly(const FlowKey& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    tlsAssemblies_.erase(key);
}

void Ingest::ForgetQuicSniState(const FlowKey& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    const auto state = quicSniStates_.find(key);
    if (state == quicSniStates_.end()) return;

    quic_sni::FreeQuicSniState(&state->second.state);
    quicSniStates_.erase(state);
}

void Ingest::ExpireSniAssemblies() {
    if (source_ == TrafficSource::Host) ForSource(TrafficSource::Ndis).ExpireSniAssemblies();
    if (mode_.load(std::memory_order_relaxed) != IngestMode::Desktop) return;
    std::lock_guard<std::mutex> lock(mtx_);
    const ULONGLONG now = GetTickCount64();
    ExpireTlsAssembliesLocked(now);
    ExpireQuicSniStatesLocked(now);
    TrimHashTable(tlsAssemblies_);
    TrimHashTable(quicSniStates_);
}

Ingest::TlsVerdictPlan Ingest::PrepareAllowedTls(
    uint64_t driverSession, const FlowKey& key,
    uint32_t tcpSequence, const uint8_t* tcpPayload,
    size_t tcpPayloadLen) {
    TlsVerdictPlan plan;
    std::lock_guard<std::mutex> lock(mtx_);
    if (driverSession_ != driverSession ||
        mode_.load(std::memory_order_relaxed) != IngestMode::Desktop)
        return plan;

    const ULONGLONG now = GetTickCount64();
    ExpireTlsAssembliesLocked(now);

    auto assembly = tlsAssemblies_.find(key);
    if (assembly != tlsAssemblies_.end()) {
        // Если транспорт сообщил заявленную длину, но не передал сами байты,
        // сохранённая часть остаётся незавершённой и соединение нужно продолжить.
        if (!tcpPayload || tcpPayloadLen == 0) {
            assembly->second.tick = now;
            tlsAssemblyExpiry_.push_back(TlsAssemblyExpiry{ key, now });
            plan.verdict = pmkext::Verdict::Accept;
            return plan;
        }

        if (assembly->second.buffer.Append(
                tcpSequence, tcpPayload, tcpPayloadLen)) {
            const TlsClientHelloProgress progress =
                assembly->second.buffer.progress();
            if (progress == TlsClientHelloProgress::Incomplete) {
                assembly->second.tick = now;
                tlsAssemblyExpiry_.push_back(TlsAssemblyExpiry{ key, now });
                plan.verdict = pmkext::Verdict::Accept;
                return plan;
            }
            if (progress == TlsClientHelloProgress::Complete)
                plan.assembledPayload = assembly->second.buffer.Take();
            tlsAssemblies_.erase(assembly);
            return plan;
        }

        // Пропуск sequence или несовпавший ретрансмит разрывает прежнюю сборку.
        // Текущий сегмент всё ещё может оказаться началом нового ClientHello.
        tlsAssemblies_.erase(assembly);
    }

    if (!tcpPayload || tcpPayloadLen == 0) return plan;

    TlsClientHelloInspector inspector;
    inspector.Append(tcpPayload, tcpPayloadLen);
    const TlsClientHelloProgress progress = inspector.progress();
    if (progress == TlsClientHelloProgress::Incomplete) {
        tlsAssemblies_.try_emplace(
            key, tcpSequence, tcpPayload, tcpPayloadLen,
            std::move(inspector), now);
        tlsAssemblyExpiry_.push_back(TlsAssemblyExpiry{ key, now });
        plan.verdict = pmkext::Verdict::Accept;
    } else if (progress == TlsClientHelloProgress::Complete) {
        plan.parseCurrentPayload = true;
    }
    return plan;
}

Ingest::QuicVerdictPlan Ingest::PrepareAllowedQuic(
    uint64_t driverSession, const FlowKey& key,
    const uint8_t* packetPayload, size_t packetPayloadLen) {
    QuicVerdictPlan plan;
    if (!packetPayload || packetPayloadLen == 0 ||
        packetPayloadLen > std::numeric_limits<uint32_t>::max()) [[unlikely]] {
        return plan;
    }

    std::lock_guard<std::mutex> lock(mtx_);
    if (driverSession_ != driverSession ||
        mode_.load(std::memory_order_relaxed) != IngestMode::Desktop) {
        return plan;
    }

    const ULONGLONG now = GetTickCount64();
    auto [state, inserted] = quicSniStates_.try_emplace(key);
    // Секундный таймер мог ещё не убрать старую сборку этого tuple.
    if (!inserted && now - state->second.tick > kQuicSniTtlMs)
        quic_sni::FreeQuicSniState(&state->second.state);
    quic_sni::QuicSniResult result = quic_sni::ExtractQuicInitialSni(
        &state->second.state, packetPayload,
        static_cast<uint32_t>(packetPayloadLen));

    if (result.status == quic_sni::QuicSniStatus::NeedMorePackets) {
        state->second.tick = now;
        plan.verdict = pmkext::Verdict::Accept;
        return plan;
    }

    if (result.status == quic_sni::QuicSniStatus::SniFound &&
        mode_.load(std::memory_order_relaxed) == IngestMode::Desktop) {
        plan.domainLabel = MakeDomainLabel(result.sni);
    }
    // Терминальный результат уже освободил внутреннее состояние. Удаляем
    // отдельного владельца tuple; его деструктор безопасно повторит Free для
    // nullptr.
    quicSniStates_.erase(state);
    return plan;
}

std::shared_ptr<const std::wstring> Ingest::ParseTlsDomainLabel(
    const TlsVerdictPlan& plan,
    const uint8_t* currentPayload, size_t currentPayloadLen) {
    if (!plan.assembledPayload.empty())
        return ReadTlsDomainLabel(
            plan.assembledPayload.data(), plan.assembledPayload.size());
    if (plan.parseCurrentPayload)
        return ReadTlsDomainLabel(currentPayload, currentPayloadLen);
    return {};
}

size_t Ingest::Fire(std::vector<Answer>& out) {
    // Ingest::mtx_ не удерживается. Только успешно отправленный verdict публикуется
    // в мониторинг; объект старой сессии gate отклонит и поглотит.
    size_t sent = 0;
    for (Answer& answer : out) {
        bool ruleVerdictLogged = false;
        for (PendingRequest& pending : answer.requests) {
            pmkext::Verdict verdict = answer.once
                ? (answer.action == RuleAction::Allow
                    ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::PermanentDrop)
                : VerdictOf(
                    answer.action, pending.payloadLayer, pending.tcpFlags,
                    pending.hasTcpPayload, answer.flow.key.proto,
                    answer.flow.dir, answer.flow.key.rport);

            TlsVerdictPlan tlsPlan;
            if (!answer.once &&
                mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
                answer.action == RuleAction::Allow &&
                IsTlsClientHelloCandidate(
                    pending.payloadLayer, pending.tcpFlags,
                    pending.hasTcpPayload, answer.flow.key.proto,
                    answer.flow.dir, answer.flow.key.rport)) {
                tlsPlan = PrepareAllowedTls(
                    pending.request.session(), answer.flow.key,
                    pending.tlsSequence,
                    pending.tlsPayload.empty()
                        ? nullptr : pending.tlsPayload.data(),
                    pending.tlsPayload.size());
                verdict = tlsPlan.verdict;
            }

            QuicVerdictPlan quicPlan;
            if (!answer.once &&
                mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
                answer.action == RuleAction::Allow &&
                IsQuicSniCandidate(
                    pending.payloadLayer, pending.quicPayload.size(),
                    answer.flow.key.proto, answer.flow.dir,
                    answer.flow.key.rport)) {
                quicPlan = PrepareAllowedQuic(
                    pending.request.session(), answer.flow.key,
                    pending.quicPayload.data(), pending.quicPayload.size());
                verdict = quicPlan.verdict;
            }

            const bool verdictSent = SendVerdict(std::move(pending.request), verdict);
            // Поток был остановлен только ради этого обязательства. Сначала
            // отправляем verdict в драйвер, затем снимаем удержание; при ошибке
            // transport-а тоже нельзя оставлять поток остановленным навсегда.
            if (pending.threadSuspendToken) {
                ThreadSuspend::Release(pending.threadSuspendToken);
                pending.threadSuspendToken = 0;
            }
            if (!verdictSent) [[unlikely]] continue;
            std::shared_ptr<const std::wstring> domainLabel = quicPlan.domainLabel
                ? quicPlan.domainLabel : pending.dnsDomainLabel;
            if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop) {
                const auto tlsDomainLabel = ParseTlsDomainLabel(
                    tlsPlan,
                    pending.tlsPayload.empty()
                        ? nullptr : pending.tlsPayload.data(),
                    pending.tlsPayload.size());
                if (tlsDomainLabel) domainLabel = tlsDomainLabel;
                if (answer.action == RuleAction::Allow &&
                    IsHttpHostCandidate(
                        pending.payloadLayer, pending.tcpFlags,
                        pending.hasTcpPayload, answer.flow.key.proto,
                        answer.flow.dir, answer.flow.key.rport) &&
                    !pending.httpPayload.empty()) {
                    domainLabel = ReadHttpDomainLabel(
                        pending.httpPayload.data(), pending.httpPayload.size());
                }
            }
            PublishFlowVerdict(answer.flow, verdict, domainLabel,
                               pending.flowGeneration, answer.preferredInterfaceBlocked);
            if constexpr (kLogDesktopRuleVerdicts) {
                if (!ruleVerdictLogged &&
                    mode_.load(std::memory_order_relaxed) ==
                        IngestMode::Desktop &&
                    answer.ruleName && answer.flow.key.proto == Proto::Tcp) {
                    LogDesktopRuleVerdict(
                        answer.flow.driverPid, answer.flow.pid,
                        answer.flow.key, answer.flow.dir,
                        verdict, *answer.ruleName);
                    ruleVerdictLogged = true;
                }
            }
            ++sent;
        }
    }
    return sent;
}

// ---------------------------------------------------------------------------
// Согласование с набором правил.
//
// version() обычно читает только атомики; родство также меняет версию. Пока версия та же,
// кеш формы соединения действителен; при смене он сбрасывается целиком, и
// тогда же (ОДИН раз, а не на событие) выясняется, допустимо ли кеширование
// вообще: условия с изменчивым значением его запрещают.
// ---------------------------------------------------------------------------
bool Ingest::SyncRulesLocked() {
    if (!rules_) return false;
    const uint64_t ver = rules_->version();
    if (ver == rulesVersion_) [[likely]] return shapeCacheOn_;

    verdicts_ = decltype(verdicts_){};
    verdictExpiry_.clear();
    rulesVersion_ = ver;
    shapeCacheOn_ = !rules_->volatileConds();
    inheritanceOn_ = source_ == TrafficSource::Host && rules_->inheritanceConds();
    shapeCacheRules_ = rules_;
    return shapeCacheOn_;
}

// ------------------------------------------------------ сборка по группе

AskRequest Ingest::RequestOf(uint64_t groupId, const PendingGroup& g) {
    const Flow& f = g.flow;

    AskRequest r;
    r.key        = f.key;
    r.interfaceIndex = f.interfaceIndex;
    r.interfaceName = f.interfaceName;
    r.pid        = f.pid;
    r.dir        = f.dir;
    r.icmpType   = f.icmpType;
    r.icmpCode   = f.icmpCode;
    r.conditionFlags = f.conditionFlags;
    r.ownerAmbiguous = f.ownerAmbiguous;
    r.lineage = f.lineage;
    if (f.app) {
        r.appPath = f.app->text;
        r.foldedAppPath = f.app->folded;
        r.appPathHash = f.app->foldedHash;
        r.process = f.app->process;
    }
    // Имя выводится здесь, а не на событии транспорта: этот путь проходят
    // только те группы, которые действительно показываются пользователю.
    r.appName    = f.key.source == TrafficSource::Ndis
        ? (f.interfaceName && !f.interfaceName->empty() ? *f.interfaceName :
            LoadStringResFmt(IDS_INTERFACE_UNKNOWN, f.interfaceIndex))
        : DisplayNameFor(f.pid, r.appPath);
    r.id         = AskRequestId{ g.driverSession, groupId, f.key.source };
    return r;
}

void Ingest::MakeIncoming(uint64_t driverPid, DWORD pid, Dir dir,
                          const FlowKey& key, const IcmpInfo& icmp,
                          bool ownerAmbiguous, Incoming& out) {
    Flow& f = out.flow;
    f.key = key;
    f.driverPid = driverPid;
    f.pid = pid;
    f.dir = dir;                        // уже разрешено в ResolveDir
    f.ownerAmbiguous = ownerAmbiguous;

    if (ProtoIsIcmp(key.proto)) {
        f.icmpType = icmp.type;
        f.icmpCode = icmp.code;
    } else {
        f.icmpType = -1;
        f.icmpCode = -1;
    }

    // Ненулевой PID уже является точным владельцем события. Путь нужен
    // RuleStore и сохраняется в общей записи без повторных запросов.
    f.app = key.source == TrafficSource::Host && FirewallPolicies::UsesRules(policy())
        ? EventProcessPath(f.pid) : nullptr;
}

// ---------------------------------------------------- pending-группы

bool Ingest::SamePendingFlow(const Flow& a, const Flow& b) {
    if (a.interfaceIndex != b.interfaceIndex || a.pid != b.pid || a.dir != b.dir || a.key != b.key ||
        a.icmpType != b.icmpType || a.icmpCode != b.icmpCode ||
        a.conditionFlags != b.conditionFlags ||
        a.ownerAmbiguous != b.ownerAmbiguous)
        return false;

    const bool sameInterface = a.interfaceName == b.interfaceName ||
        (a.interfaceName && b.interfaceName && *a.interfaceName == *b.interfaceName);
    return sameInterface && a.foldedAppPath() == b.foldedAppPath() && a.lineage == b.lineage;
}

Ingest::PendingMap::iterator Ingest::FindPendingLocked(const Incoming& in,
                                                       uint64_t askKey) {
    const auto range = pendingIndex_.equal_range(askKey);
    for (auto idx = range.first; idx != range.second; ++idx) {
        auto it = pending_.find(idx->second);
        if (it != pending_.end() &&
            it->second.driverSession == in.request.session() &&
            SamePendingFlow(it->second.flow, in.flow))
            return it;
    }
    return pending_.end();
}

Ingest::PendingMap::iterator Ingest::AddPendingLocked(const Incoming& in,
                                                      uint64_t askKey) {
    PendingGroup g;
    g.flow = in.flow;
    g.keyHash = askKey;
    g.driverSession = in.request.session();
    return AddPendingLocked(std::move(g));
}

Ingest::PendingMap::iterator Ingest::AddPendingLocked(PendingGroup group) {
    uint64_t id = 0;
    do {
        id = ++pendingSeq_;
    } while (!id || pending_.count(id));

    const uint64_t askKey = group.keyHash;
    auto inserted = pending_.emplace(id, std::move(group));
    pendingIndex_.emplace(askKey, id);
    return inserted.first;
}

Ingest::PendingMap::iterator
Ingest::ErasePendingLocked(PendingMap::iterator it) {
    if (it == pending_.end()) return it;

    const uint64_t id = it->first;
    const auto range = pendingIndex_.equal_range(it->second.keyHash);
    for (auto idx = range.first; idx != range.second; ++idx) {
        if (idx->second != id) continue;
        pendingIndex_.erase(idx);
        break;
    }
    return pending_.erase(it);
}
// ------------------------------------------------------------- карта потоков

// Вердикт уточняет только строку, созданную исходным on_connection_*.
// После END либо удаления этого поколения поздний ответ не означает нового
// соединения и не должен возвращать старую попытку в список.
void Ingest::PublishFlowVerdict(
    const Flow& f, pmkext::Verdict verdict,
    const std::shared_ptr<const std::wstring>& tlsDomainLabel,
    uint64_t generation, bool preferredInterfaceBlocked) {
    if (!generation) return;
    const bool blocking = IsBlockingVerdict(verdict);
    if (blocking) {
        if (f.dir != Dir::In && f.key.source != TrafficSource::Ndis &&
            !preferredInterfaceBlocked) return;
    } else if (!IsAllowingVerdict(verdict)) {
        return;
    }

    FlowStore::ConnEvent ev;
    ev.pid = f.pid;
    ev.interfaceIndex = f.interfaceIndex;
    ev.interfaceName = f.interfaceName;
    ev.ownerAmbiguous = f.ownerAmbiguous;
    ev.dir = f.dir;
    ev.icmpType = f.icmpType;
    ev.icmpCode = f.icmpCode;
    ev.conditionFlags = f.conditionFlags;
    ev.tlsDomainLabel = tlsDomainLabel;

    if (blocking) FlowStore::Instance().NoteBlocked(f.key, ev, generation);
    else          FlowStore::Instance().NoteAllowed(f.key, ev, generation);
}

uint64_t Ingest::NoteFlow(
    const Incoming& in, uint64_t packetBytes,
    const std::shared_ptr<const std::wstring>& tlsDomainLabel,
    bool blocked) {
    // В службе список соединений никто не читает.
    if (mode_.load(std::memory_order_relaxed) == IngestMode::Service) return 0;

    const Flow& f = in.flow;

    FlowStore::ConnEvent ev;
    ev.interfaceIndex = f.interfaceIndex;
    ev.interfaceName = f.interfaceName;
    ev.pid      = f.pid;            // может быть 0: пакетный уровень WFP
    ev.ownerAmbiguous = f.ownerAmbiguous;
    ev.dir      = f.dir;            // разрешённое направление
    ev.icmpType = f.icmpType;
    ev.icmpCode = f.icmpCode;
    ev.conditionFlags = f.conditionFlags;
    ev.tlsDomainLabel = tlsDomainLabel;

    // -----------------------------------------------------------------------
    // Размер payload события в счётчики TCP и UDP НЕ идёт ни при каких
    // условиях.
    //
    // Для обоих протоколов приращения даёт on_bandwidthstats_*; если Windows
    // предоставила ненулевые TCP EStats конкретного соединения, FlowStore
    // выбирает только их. Payload события — отдельный пакет, а не весь трафик:
    // сложение и удвоило бы байты, и дало бы ложный всплеск скорости на такте
    // появления строки.
    //
    // Размер сохраняется исключительно для протоколов, которых нет в таблицах
    // ОС (ICMP, IGMP, GRE, ESP…): там события — единственный источник байт.
    // -----------------------------------------------------------------------
    // У FirewallXNdisFilter для этих протоколов сюда поступает полезная нагрузка
    // пакета уровня 3, без IP- и распознанных заголовков протокола.
    ev.bytes = ProtoInOsTables(f.key.proto) ? 0 : packetBytes;

    return blocked
        ? FlowStore::Instance().NoteBlockedConnection(f.key, ev)
        : FlowStore::Instance().NoteConnection(f.key, ev);
}

// ---------------------------------------------- закрытие обязательств группы

void Ingest::SettleLocked(std::vector<Answer>& out, PendingGroup& g,
                          RuleAction action,
                          const RuleNameRef* ruleName,
                          bool preferredInterfaceBlocked) {
    const size_t count = g.requests.size();
    Answer answer{ std::move(g.requests), action, g.flow };
    answer.preferredInterfaceBlocked = preferredInterfaceBlocked;
    if constexpr (kLogDesktopRuleVerdicts) {
        if (ruleName) answer.ruleName = *ruleName;
    }
    out.push_back(std::move(answer));
    waiting_  -= count;
    answered_ += count;
}

// Pending-группы здесь намеренно не обходятся. Ни истечение времени, ни
// завершение процесса не задают вердикт за пользователя; очистке подлежат
// только вспомогательные кеши решений и незавершённые сборки SNI.
void Ingest::Maintain() {
    std::lock_guard<std::mutex> lk(mtx_);
    const ULONGLONG now = GetTickCount64();
    ExpireVerdicts(now);
    ExpireTlsAssembliesLocked(now);
    ExpireQuicSniStatesLocked(now);
    TrimHashTable(tlsAssemblies_);
    TrimHashTable(quicSniStates_);
}

void Ingest::CacheMatchedShape(const Flow& flow, RuleAction action,
                               RuleStore* matchedRules,
                               uint64_t matchedVersion,
                               uint64_t driverSession,
                               const PreparedShapeKey* preparedKey,
                               const RuleNameRef* ruleName,
                               bool preferredInterfaceBlocked) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Решение уже отправлено, поэтому кеш — только ускорение будущих событий.
    // Если правила за это время изменились, старый результат просто не пишем.
    if (driverSession_ != driverSession || rules_ != matchedRules ||
        matchedRules->version() != matchedVersion) [[unlikely]] return;
    if (shapeCacheRules_ != matchedRules ||
        rulesVersion_ != matchedVersion || !shapeCacheOn_) [[unlikely]] return;

    // Готовый хэш относится к версии, при которой читался кеш. После смены
    // версии мог измениться режим наследования, поэтому старый ключ не подходит.
    const uint64_t shapeKey = preparedKey && preparedKey->rulesVersion == matchedVersion
        ? preparedKey->value : ShapeKeyOf(flow, inheritanceOn_);
    Shape& s = verdicts_[shapeKey];
    s.action = action;
    s.preferredInterfaceBlocked = preferredInterfaceBlocked;
    s.tick = GetTickCount64();
    verdictExpiry_.push_back(ExpiryRecord{ shapeKey, s.tick });
    if constexpr (kLogDesktopRuleVerdicts) {
        if (ruleName) s.ruleName = *ruleName;
        else          s.ruleName.reset();
    } else {
        (void)ruleName;
    }
}

// -------------------------------------------------------------- приём события

void Ingest::Ingress(Incoming in, uint64_t packetBytes) {
    if (!in.request) [[unlikely]] return;
    const uint64_t driverSession = in.request.session();

    // Неизвестный путь НЕ является причиной обходить matcher. Глобальное
    // правило — особенно правило с условием «сервис» — не зависит от пути и
    // может корректно вычислиться по известному PID. Если правило не найдётся
    // в Learning, такой несистемный процесс ниже получит Drop без создания
    // опасного глобального правила из окна запроса.

    bool            answerNow = false;
    pmkext::Verdict verdict = pmkext::Verdict::Undecided;
    bool            needNotify = false;
    bool            ruleApplied = false;
    bool            allowActionApplied = false;
    bool            preferredInterfaceBlocked = false;
    RuleNameRef     ruleName;
    std::shared_ptr<const std::wstring> dnsDomainLabel;
    bool            collectRuleLog = false;
    bool            maintenanceDue = false;
    bool            cacheMatchedShape = false;
    bool            sessionExpired = false;
    RuleAction      matchedRuleAction = RuleAction::Allow;
    uint64_t        matchedRuleVersion = 0;
    // В desktop тот же PID записывает NoteFlow одним захватом FlowStore. Отдельная
    // запись нужна только службе: там отображаемое хранилище выключено, но индекс
    // владельцев сохраняется для поздних событий с PID 0.
    const bool      rememberReportedOwner =
        source_ == TrafficSource::Host &&
        mode_.load(std::memory_order_relaxed) == IngestMode::Service &&
        in.flow.driverPid != 0 && ProtoInOsTables(in.flow.key.proto);

    // Хэш формы вычисляется только при чтении существующего кеша. Первый
    // успешный matcher пишет новый кеш уже после отправки текущего вердикта.
    PreparedShapeKey shapeKey;
    bool shapeKeyReady = false;

    // Для уровня 2: запрос сопоставления, если кеш формы не сработал.
    // Копируется под мьютексом, затем RuleStore вызывается ВНЕ замка.
    MatchQuery matchQuery;
    RuleStore* matchRules = nullptr;
    FirewallPolicy matchPolicy = FirewallPolicy::Learning;
    bool needMatch = false;

    // Вызывается только под mtx_ и только после известного промаха matcher-а.
    // Поэтому дорогой хэш всех полей pending не строится для разрешённых либо
    // заблокированных правилом соединений.
    const auto parkLocked = [&]() {
        // Только промах matcher-а удерживает родство. Разные экземпляры одного
        // PID не объединяются в pending даже при одинаковом EXE и соединении.
        if (source_ == TrafficSource::Host && rules_)
            in.flow.lineage = rules_->RetainProcess(in.flow.pid);
        const Flow& f = in.flow;
        const uint64_t askKey = AskHashPrepared(
            f.appPathHash(), f.pid, f.key, f.dir, f.icmpType, f.icmpCode,
            f.ownerAmbiguous, f.interfaceIndex, f.interfaceName.get(), f.conditionFlags);

        ++waiting_;
        auto it = FindPendingLocked(in, askKey);
        if (it == pending_.end()) {
            it = AddPendingLocked(in, askKey);
            needNotify = true;
        }
        if constexpr (kShowPayloadInRuleEditor) {
            if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
                it->second.ruleEditorPayload.empty() &&
                in.packetPayload && in.packetPayloadLen) {
                it->second.ruleEditorPayload.assign(
                    in.packetPayload, in.packetPayload + in.packetPayloadLen);
            }
        }
        PendingRequest pending{
            std::move(in.request), in.payloadLayer, in.tcpFlags,
            in.hasTcpPayload, in.tcpSequence,
            0 };
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
            IsDnsQueryCandidate(in.payloadLayer, in.packetPayloadLen,
                                f.key.proto, f.dir, f.key.rport) && in.packetPayload) {
            dnsDomainLabel = ReadDnsDomainLabel(
                in.packetPayload, in.packetPayloadLen);
            pending.dnsDomainLabel = dnsDomainLabel;
        }
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
            IsTlsClientHelloCandidate(
                in.payloadLayer, in.tcpFlags, in.hasTcpPayload,
                in.flow.key.proto, in.flow.dir, in.flow.key.rport) &&
            in.tcpPayload && in.tcpPayloadLen) {
            pending.tlsPayload.assign(
                in.tcpPayload, in.tcpPayload + in.tcpPayloadLen);
        }
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
            IsHttpHostCandidate(
                in.payloadLayer, in.tcpFlags, in.hasTcpPayload,
                in.flow.key.proto, in.flow.dir, in.flow.key.rport) &&
            in.packetPayload && in.packetPayloadLen) {
            pending.httpPayload.assign(
                in.packetPayload, in.packetPayload + in.packetPayloadLen);
        }
        if (IsQuicSniCandidate(
                in.payloadLayer, in.packetPayloadLen, in.flow.key.proto,
                in.flow.dir, in.flow.key.rport) && in.packetPayload) {
            pending.quicPayload.assign(
                in.packetPayload, in.packetPayload + in.packetPayloadLen);
        }
        // Публикуем строку и её поколение до выдачи обязательства UI. Иначе
        // быстрый ответ мог бы опередить NoteFlow и создать лишнюю строку.
        pending.flowGeneration = NoteFlow(in, packetBytes, dnsDomainLabel);
        it->second.requests.push_back(std::move(pending));
        // Для исходящего pending с доступным TID делается попытка остановить только
        // поток, указанный драйвером напрямую либо через TID-канал службы.
        // mtx_ не даёт отправить verdict или очистить группу раньше записи токена.
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
            source_ == TrafficSource::Host &&
            in.flow.dir == Dir::Out && !IsSystemPid(in.flow.pid)) {
            PendingRequest& parked = it->second.requests.back();
            parked.threadSuspendToken = SuspendDriverRequestThread(
                parked.request, in.flow.pid, in.threadId);
        }
    };

    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (driverSession_ != driverSession) [[unlikely]] return;
        ++calls_;
        const ULONGLONG now = GetTickCount64();
        if constexpr (kLogDesktopRuleVerdicts) {
            collectRuleLog =
                mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
                in.flow.key.proto == Proto::Tcp;
        }

        matchPolicy = policy_.load(std::memory_order_relaxed);
        if (rules_ && FirewallPolicies::UsesRules(matchPolicy)) {
            const bool cacheOn = SyncRulesLocked() && !verdicts_.empty() &&
                (source_ != TrafficSource::Host || !in.flow.appPath().empty() || !rules_->preferredInterfaceConds());

            // Уровень 1: та же ФОРМА соединения уже сопоставлялась.
            // Крайние политики не читают даже кеш действий правил.
            if (cacheOn) {
                shapeKey = { ShapeKeyOf(in.flow, inheritanceOn_), rulesVersion_ };
                shapeKeyReady = true;
                auto sit = verdicts_.find(shapeKey.value);
                if (sit != verdicts_.end() && now - sit->second.tick <= kVerdictTtlMs) {
                    // Касания в одной миллисекунде имеют один срок истечения.
                    if (sit->second.tick != now) {
                        sit->second.tick = now;
                        verdictExpiry_.push_back(ExpiryRecord{ shapeKey.value, now });
                    }
                    verdict = VerdictOf(
                        sit->second.action, in.payloadLayer, in.tcpFlags,
                        in.hasTcpPayload, in.flow.key.proto,
                        in.flow.dir, in.flow.key.rport);
                    allowActionApplied =
                        sit->second.action == RuleAction::Allow;
                    preferredInterfaceBlocked = sit->second.preferredInterfaceBlocked;
                    if constexpr (kLogDesktopRuleVerdicts) {
                        if (collectRuleLog) {
                            ruleApplied = true;
                            ruleName = sit->second.ruleName;
                        }
                    }
                    ++answered_;
                    answerNow = true;
                }
            }
        }

        // Уровень 2: правило либо решение выбранной политики. В том числе
        // без RuleStore: крайние политики и defaults не зависят от его наличия.
        if (!answerNow) {
            matchQuery = in.flow.ToQuery();
            matchRules = rules_;
            needMatch = true;
        }

        // Уборка не участвует в выборе текущего решения. Раз в 512 событий
        // продвигаются FIFO сроков вспомогательных кешей. Pending-группы живут
        // до пользовательского решения либо завершения driver-сессии.
        maintenanceDue = ((++sweep_ & 0x1FFu) == 0);
    }

    // -------------------------------------------------------------------------
    // Уровень 2: сопоставление с правилами ВНЕ мьютекса Ingest.
    //
    // RuleStore вызывается без Ingest::mtx_: сопоставление может пройти много
    // кандидатов, а опубликованный ServiceInfo-снимок и макро-адреса имеют свои
    // независимые механизмы синхронизации. MatchQuery скопирован под мьютексом
    // выше, поэтому его appPath (wstring_view) остаётся действительным: общий
    // ProcessPathInfo удерживается событием, а после парковки — pending-группой.
    // -------------------------------------------------------------------------
    if (needMatch) {
        // Результат относится к версии, которую RuleStore вернул под своим
        // мьютексом. Если правила успели измениться до повторного захвата mtx_,
        // сопоставление повторяется: старое действие нельзя ни выдать текущему
        // соединению, ни записать в кеш уже новой версии.
        bool lookedUpPolicyPath = false;
        const auto loadPolicyPath = [&]() {
            if (lookedUpPolicyPath || source_ != TrafficSource::Host || in.flow.app || !matchRules ||
                (matchPolicy != FirewallPolicy::BlockAll && matchPolicy != FirewallPolicy::AllowAll) ||
                !matchRules->preferredInterfaceConds()) return false;
            lookedUpPolicyPath = true;
            in.flow.app = EventProcessPath(in.flow.pid);
            matchQuery = in.flow.ToQuery();
            return true;
        };
        for (;;) {
            // При крайних политиках путь нужен только для предпочтений EXE.
            // Проверка выполняется и после matcher-а: настройку могли включить
            // между первым чтением и получением версии результата.
            loadPolicyPath();
            RuleNameRef* matchedRuleName = nullptr;
            if constexpr (kLogDesktopRuleVerdicts) {
                if (collectRuleLog) matchedRuleName = &ruleName;
            }
            // В службе Learning сохраняет прежний алгоритм: правила,
            // технические ICMP-исключения и Drop вместо интерактивного запроса.
            const bool learning = matchPolicy == FirewallPolicy::Learning;
            if (learning && !matchRules && !in.flow.interfaceName) {
                const auto name = net::SharedNetworkInterfaces().GetInterfaceName(matchQuery.interfaceIndex);
                in.flow.interfaceName = std::make_shared<const std::wstring>(name.value_or(std::wstring()));
            }
            // При повторе из-за смены версии исходное имя уже нельзя переопределять.
            matchQuery.interfaceName = in.flow.interfaceName.get();
#ifdef FIREWALLX_TEST_VERDICTS
            if (IngestWorkProbe::beforePolicyMatch) IngestWorkProbe::beforePolicyMatch();
#endif
            const auto decision = FirewallPolicies::Evaluate(
                mode() == IngestMode::Service && learning
                    ? FirewallPolicy::Block : matchPolicy,
                matchRules, matchQuery, matchedRuleName, learning, &in.flow.interfaceName);
            if (loadPolicyPath()) continue;

            bool retry = false;
            {
                // Берём мьютекс заново для записи результата в кеши и счётчики.
                // Политика стабильна: HandleFixed держит shared policyMtx_.
                std::lock_guard<std::mutex> lk(mtx_);

                if (driverSession_ != driverSession) [[unlikely]] {
                    // Transport уже сменился. Старый move-only объект больше
                    // не авторизован gate-ом и не должен попасть ни в pending,
                    // ни в кеш решений нового поколения.
                    sessionExpired = true;
                } else if (rules_ != matchRules) [[unlikely]] {
                    matchRules = rules_;
                    retry = true;
                } else if (matchRules && matchRules->version() != decision.rulesVersion) [[unlikely]] {
                    // Индекс уже относится к другой версии; старое действие
                    // нельзя ни применить, ни записать в кеш новой версии.
                    retry = true;
                } else {
                    if (decision.decided) {
                        verdict = VerdictOf(
                            decision.action, in.payloadLayer, in.tcpFlags,
                            in.hasTcpPayload, in.flow.key.proto,
                            in.flow.dir, in.flow.key.rport);
                        matchedRuleAction = decision.action;
                        allowActionApplied = decision.action == RuleAction::Allow;
                        preferredInterfaceBlocked = decision.preferredInterfaceBlocked;
                        if constexpr (kLogDesktopRuleVerdicts) {
                            ruleApplied = collectRuleLog && decision.matchedRule;
                        }
                        ++answered_;
                        answerNow = true;
                    }

                    // Кешируются только совпавшие правила, не defaults политики:
                    // внешние значения макросов/сервисов могут смениться отдельно.
                    // После первого промаха запрос уже привязан к исходному имени.
                    // Его решение нельзя кешировать только по переиспользуемому IfIndex.
                    if (decision.matchedRule && shapeCacheOn_ && !in.flow.interfaceName &&
                        (source_ != TrafficSource::Host || !in.flow.appPath().empty() || !matchRules->preferredInterfaceConds())) {
                        cacheMatchedShape = true;
                        matchedRuleVersion = decision.rulesVersion;
                    }

                    // Только Learning может остаться без решения. Если путь
                    // обычного процесса недоступен или владелец неоднозначен,
                    // спрашивать нельзя: новое правило оказалось бы глобальным.
                    if (!answerNow &&
                        (in.flow.ownerAmbiguous ||
                         (source_ == TrafficSource::Host &&
                          !IsSystemPid(in.flow.pid) && in.flow.appPath().empty()))) {
                        verdict = pmkext::Verdict::Drop;
                        ++answered_;
                        answerNow = true;
                    }
                    if (!answerNow) parkLocked();
                }
            }

            if (!retry) [[likely]] break;
        }
    }

    if (sessionExpired) [[unlikely]] return;

    if (answerNow) {
        // В Desktop до verdict проверяется полнота накопленного TCP ClientHello
        // и дешифруется QUIC Initial. QUIC при необходимости сохраняет состояние
        // до следующего UDP-пакета; TCP SNI и HTTP Host разбираются после ответа.
        TlsVerdictPlan tlsPlan;
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
            allowActionApplied && IsTlsClientHelloCandidate(
                in.payloadLayer, in.tcpFlags, in.hasTcpPayload,
                in.flow.key.proto, in.flow.dir, in.flow.key.rport)) {
            tlsPlan = PrepareAllowedTls(
                driverSession, in.flow.key, in.tcpSequence,
                in.tcpPayload, in.tcpPayloadLen);
            verdict = tlsPlan.verdict;
        }

        QuicVerdictPlan quicPlan;
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
            allowActionApplied && IsQuicSniCandidate(
                in.payloadLayer, in.packetPayloadLen, in.flow.key.proto,
                in.flow.dir, in.flow.key.rport)) {
            quicPlan = PrepareAllowedQuic(
                driverSession, in.flow.key,
                in.packetPayload, in.packetPayloadLen);
            verdict = quicPlan.verdict;
        }

        // Текущий ответ важнее мониторинга, истории владельца,
        // диагностического файла и редкой уборки.
        if (!SendVerdict(std::move(in.request), verdict)) [[unlikely]] return;

        std::shared_ptr<const std::wstring> domainLabel = quicPlan.domainLabel;
        if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop) {
            const auto tlsDomainLabel = ParseTlsDomainLabel(
                tlsPlan, in.tcpPayload, in.tcpPayloadLen);
            if (tlsDomainLabel) domainLabel = tlsDomainLabel;
            if (allowActionApplied && IsHttpHostCandidate(
                    in.payloadLayer, in.tcpFlags, in.hasTcpPayload,
                    in.flow.key.proto, in.flow.dir, in.flow.key.rport)) {
                domainLabel = ReadHttpDomainLabel(
                    in.packetPayload, in.packetPayloadLen);
            }
            // Pending разбирает DNS при парковке. Немедленный путь делает это
            // после verdict; пустой результат не запускает повтор в NoteFlow.
            if (!domainLabel && IsDnsQueryCandidate(
                    in.payloadLayer, in.packetPayloadLen,
                    in.flow.key.proto, in.flow.dir, in.flow.key.rport) &&
                in.packetPayload) {
                domainLabel = ReadDnsDomainLabel(
                    in.packetPayload, in.packetPayloadLen);
            }
        }

        // Точный PID запоминается после отправки текущего ответа: этому событию
        // история не нужна, а позднее packet-layer событие получит владельца.
        if (rememberReportedOwner) {
            OwnerLookup::NoteReportedOwner(
                in.flow.key, static_cast<DWORD>(in.flow.driverPid));
        }
        const bool blockImmediately = IsBlockingVerdict(verdict) &&
            (in.flow.dir == Dir::In || in.flow.key.source == TrafficSource::Ndis ||
             preferredInterfaceBlocked);
        const uint64_t generation = NoteFlow(
            in, packetBytes, domainLabel, blockImmediately);
        // Недоступный предпочтительный интерфейс публикует и исходящие попытки
        // заблокированными, без ожидания строки в системной таблице соединений.
        // Обычные исходящие блокировки хоста сохраняют прежний порядок учёта.
        if (IsBlockingVerdict(verdict) && !blockImmediately)
            PublishFlowVerdict(in.flow, verdict, {}, generation);

        if (cacheMatchedShape) {
            CacheMatchedShape(
                in.flow, matchedRuleAction, matchRules, matchedRuleVersion,
                driverSession, shapeKeyReady ? &shapeKey : nullptr,
                collectRuleLog ? &ruleName : nullptr, preferredInterfaceBlocked);
        }

        if constexpr (kLogDesktopRuleVerdicts) {
            if (collectRuleLog &&
                mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
                ruleApplied && ruleName && in.flow.key.proto == Proto::Tcp)
                LogDesktopRuleVerdict(
                    in.flow.driverPid, in.flow.pid, in.flow.key, in.flow.dir,
                    verdict, *ruleName);
        }
        if (maintenanceDue) [[unlikely]] Maintain();
        return;
    }

    // Строка pending уже опубликована вместе с поколением под mtx_.
    if (maintenanceDue) [[unlikely]] Maintain();
    if (needNotify) Notify();
}


template <class Fixed>
void Ingest::HandleFixed(const Fixed& e, const uint8_t* payload, size_t len) {
    std::shared_lock policyLock(policyMtx_);
    DriverVerdictRequest request =
        RegisterDriverVerdictRequest(e.external_connection_id);
    if (!request) [[unlikely]] return;

    const PacketFacts pf = ReadPacket(payload, len, e.protocol, e.remote_port);
    // Технические ICMP-исключения проверяются в Ingress после правил:
    // событие должно пройти обычный учёт и попасть в главное окно.
	

    const IpAddr   local  = IpFromRaw(e.local_ip);
    const IpAddr   remote = IpFromRaw(e.remote_ip);
    const Proto    proto  = ProtoFromNumber(e.protocol);
    const uint16_t lport  = e.local_port;
    const FlowKey  key    = MakeFlowKey(proto, local, remote,
                                        lport, e.remote_port);

    // Новый TCP SYN к remote 443/8443 начинает новое поколение tuple. Это защищает
    // от наследования незавершённого ClientHello при переиспользовании портов,
    // даже если ConnectionEnd прежнего соединения не был доставлен.
    if (mode_.load(std::memory_order_relaxed) == IngestMode::Desktop &&
        proto == Proto::Tcp && (key.rport == 443 || key.rport == 8443) &&
        (pf.tcpFlags & 0x002u) != 0) {
        ForgetTlsAssembly(key);
    }

    // Поле события — основа, заголовок пакета — проверка (и единственный
    // источник ответа для петли).
    const Dir dir = ResolveDir(pf, proto, local, remote,
                               DirFromDriver(e.direction));

    // Точный PID текущего события не требует OwnerLookup или системных таблиц.
    // Путь всё равно нужен matcher-у и берётся из общего кеша SystemInfo.
    bool ownerAmbiguous = false;
    const DWORD reportedPid = static_cast<DWORD>(e.process_id);
    const DWORD pid = reportedPid
        ? reportedPid
        : OwnerLookup::ResolveEventOwner(0, key, dir, &ownerAmbiguous);

    Incoming in(std::move(request), e.payload_layer, pf.tcpFlags,
                pf.hasTcpPayload, pf.tcpSequence,
                pf.tcpPayload, pf.tcpPayloadBytes, payload, len);
    in.threadId = e.tid;
    MakeIncoming(e.process_id, pid, dir, key, pf.icmp, ownerAmbiguous, in);
    in.flow.interfaceIndex = e.interface_index;
    in.flow.conditionFlags = e.condition_flags;

    Ingress(std::move(in), pf.bytes);
}

void Ingest::HandleV4(const pmkext::ConnectionFixedV4& e,
                      const uint8_t* payload, size_t len) {
    HandleFixed(e, payload, len);
}

void Ingest::HandleV6(const pmkext::ConnectionFixedV6& e,
                      const uint8_t* payload, size_t len) {
    HandleFixed(e, payload, len);
}

// Событие FirewallXNdisFilter не содержит PID/TID и не определяет владельца; направление приходит от драйвера.
template <class Fixed>
void Ingest::HandleNdisFixed(const Fixed& e, const uint8_t* payload, size_t len) {
    std::shared_lock policyLock(policyMtx_);
    DriverVerdictRequest request = firewallxndisfilter_register_request(e.id);
    if (!request) return;
    const bool reverse = net::SharedNetworkInterfaces().ReverseNdisTraffic(e.interface_index);
    const PacketFacts facts = ReadPacket(payload, len, e.protocol, reverse ? e.local_port : e.remote_port);
    FlowKey key = MakeFlowKey(ProtoFromNumber(e.protocol),
        IpFromRaw(e.local_ip), IpFromRaw(e.remote_ip), e.local_port, e.remote_port);
    if (reverse) {
        std::swap(key.local, key.remote);
        std::swap(key.lport, key.rport);
    }
    key.source = TrafficSource::Ndis;
    key.interfaceIndex = e.interface_index;
    Dir dir = DirFromDriver(e.direction);
    if (reverse) dir = dir == Dir::In ? Dir::Out : Dir::In;
    if (mode() == IngestMode::Desktop && key.proto == Proto::Tcp &&
        (key.rport == 443 || key.rport == 8443) &&
        (facts.tcpFlags & 0x002u) != 0) ForgetTlsAssembly(key);
    Incoming incoming(std::move(request), e.payload_layer, facts.tcpFlags,
        facts.hasTcpPayload, facts.tcpSequence, facts.tcpPayload,
        facts.tcpPayloadBytes, payload, len);
    MakeIncoming(0, 0, dir, key, facts.icmp, false, incoming);
    incoming.flow.interfaceIndex = e.interface_index;
    const uint64_t bytes = e.payload_layer == 3
        ? NdisPayloadBytes(facts, payload, len, e.protocol) : 0;
    Ingress(std::move(incoming), bytes);
}

void Ingest::HandleNdis(const firewallxndisfilter::Client::ConnectionV4& e,
                          const uint8_t* payload, size_t len) {
    HandleNdisFixed(e, payload, len);
}

void Ingest::HandleNdis(const firewallxndisfilter::Client::ConnectionV6& e,
                          const uint8_t* payload, size_t len) {
    HandleNdisFixed(e, payload, len);
}

// ------------------------------------------------------------------ UI-поток

// Завершение процесса не делает запрос недействительным: исходные путь и
// условия уже принадлежат pending-группе, а вердикт остаётся решением
// пользователя. Сервисным правилам сначала даём свежий снимок SCM: иначе
// новый PID на мгновение попадёт в Ask, пока секундный монитор не увидит службу.
void Ingest::TakePending(std::vector<AskRequest>& out) {
    TakePendingLocal(out);
    if (source_ == TrafficSource::Host) {
        std::vector<AskRequest> ndis;
        ForSource(TrafficSource::Ndis).TakePendingLocal(ndis);
        out.insert(out.end(), std::make_move_iterator(ndis.begin()),
                   std::make_move_iterator(ndis.end()));
    }
}

void Ingest::TakePendingLocal(std::vector<AskRequest>& out) {
    out.clear();
    std::vector<AskRequestId> ready;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool serviceRules = source_ == TrafficSource::Host && rules_ && rules_->serviceConds();
        for (auto& kv : pending_) {
            PendingGroup& group = kv.second;
            if (group.driverSession != driverSession_ || group.accepted) continue;
            if (serviceRules && group.flow.pid) {
                if (!group.serviceRefresh)
                    group.serviceRefresh = ServiceInfo::RequestRefresh();
                if (group.serviceRefresh &&
                    !ServiceInfo::RefreshComplete(group.serviceRefresh)) continue;
            }
            ready.push_back({group.driverSession, kv.first});
        }
    }
    if (ready.empty()) return;

    // Перепроверяем ДО выдачи в очередь, в том числе когда полный опрос не
    // изменил semantic Version(). Новые группы, появившиеся во время проверки,
    // сюда не включаются: их снимок ещё не был подтверждён.
    FlushVerdicts();

    std::lock_guard<std::mutex> lk(mtx_);
    for (AskRequestId id : ready) {
        if (id.driverSession != driverSession_) continue;
        const auto it = pending_.find(id.groupId);
        if (it == pending_.end() || it->second.driverSession != id.driverSession ||
            it->second.accepted) continue;
        it->second.accepted = true;
        out.push_back(RequestOf(it->first, it->second));
    }
}

void Ingest::Republish() {
    if (source_ == TrafficSource::Host) ForSource(TrafficSource::Ndis).Republish();
    bool any = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& kv : pending_) {
            if (kv.second.driverSession != driverSession_ ||
                !kv.second.accepted) continue;
            kv.second.accepted = false;
            any = true;
        }
    }
    if (any) Notify();
}

// Действительность запроса задаётся только наличием группы в текущей
// driver-сессии. Жив ли процесс сейчас, на это не влияет: PID используется как
// исходное условие события, а путь удерживается самой группой.
bool Ingest::GetPending(AskRequestId id, AskRequest& out) const {
    if (id.source != source_) return ForSource(id.source).GetPending(id, out);
    std::lock_guard<std::mutex> lk(mtx_);
    if (!id || id.driverSession != driverSession_) return false;
    auto it = pending_.find(id.groupId);
    if (it == pending_.end() || it->second.driverSession != id.driverSession)
        return false;
    out = RequestOf(it->first, it->second);
    return true;
}

std::vector<uint8_t> Ingest::GetPendingPayload(AskRequestId id) const {
    if (id.source != source_) return ForSource(id.source).GetPendingPayload(id);
    std::lock_guard<std::mutex> lk(mtx_);
    if (!id || id.driverSession != driverSession_) return {};
    auto it = pending_.find(id.groupId);
    if (it == pending_.end() || it->second.driverSession != id.driverSession)
        return {};
    return it->second.ruleEditorPayload;
}

bool Ingest::IsPending(AskRequestId id) const {
    if (id.source != source_) return ForSource(id.source).IsPending(id);
    std::lock_guard<std::mutex> lk(mtx_);
    if (!id || id.driverSession != driverSession_) return false;
    auto it = pending_.find(id.groupId);
    return it != pending_.end() &&
           it->second.driverSession == id.driverSession;
}

bool Ingest::AnswerOnce(AskRequestId id, RuleAction action) {
    if (id.source != source_) return ForSource(id.source).AnswerOnce(id, action);
    std::shared_lock policyLock(policyMtx_);
    std::vector<Answer> fire;
    bool more = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!id || id.driverSession != driverSession_) return false;
        auto it = pending_.find(id.groupId);
        if (it == pending_.end() || it->second.driverSession != id.driverSession ||
            it->second.requests.empty()) return false;

        PendingGroup& group = it->second;
        Answer answer;
        if (rules_) {
            uint64_t version = 0;
            answer.preferredInterfaceBlocked =
                rules_->PreferredInterfaceBlocked(group.flow.ToQuery(), version);
            if (answer.preferredInterfaceBlocked) action = RuleAction::Block;
        }
        answer.flow = group.flow;
        answer.action = action;
        answer.once = true;
        answer.requests.push_back(std::move(group.requests.front()));
        // Обязательства допускают только move-конструирование, не присваивание:
        // удаление через vector::erase нарушило бы этот защитный контракт.
        std::vector<PendingRequest> remaining(
            std::make_move_iterator(group.requests.begin() + 1),
            std::make_move_iterator(group.requests.end()));
        group.requests.swap(remaining);
        fire.push_back(std::move(answer));
        --waiting_;
        ++answered_;

        // Даже одинаковые пакеты — разные обязательства. Старый идентификатор
        // поглощается целиком, чтобы повторный ответ не затронул следующий пакет.
        PendingGroup rest = std::move(group);
        ErasePendingLocked(it);
        if (!rest.requests.empty()) {
            rest.accepted = false;
            AddPendingLocked(std::move(rest));
            more = true;
        }
        TrimHashTable(pending_);
        TrimHashTable(pendingIndex_);
    }
    Fire(fire);
    if (more) Notify();
    return true;
}

// Припаркованное обязательство закрывается правилом либо выбранной политикой.
// Само завершение процесса не является решением и не удаляет группу.
size_t Ingest::FlushVerdicts() {
    const size_t ndisSent = source_ == TrafficSource::Host
        ? ForSource(TrafficSource::Ndis).FlushVerdicts() : 0;
    std::shared_lock policyLock(policyMtx_);
    const FirewallPolicy activePolicy = policy();
    std::vector<Answer> fire;

    // Копируем pending-группы для сопоставления ВНЕ мьютекса
    std::vector<std::pair<uint64_t, Flow>> pendingCopy;
    RuleStore* activeRules = nullptr;
    uint64_t activeSession = 0;

    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!driverSession_) return ndisSent;
        activeRules = rules_;
        activeSession = driverSession_;

        // Набор правил только что изменился: прежние решения по форме
        // соединения недействительны.
        SyncRulesLocked();

        // Копируем все pending-группы, включая группы уже завершившихся
        // процессов: новое правило должно закрыть их на общих основаниях.
        pendingCopy.reserve(pending_.size());
        for (const auto& kv : pending_) {
            pendingCopy.emplace_back(kv.first, kv.second.flow);
        }
    }

    // Сопоставление ВНЕ мьютекса Ingest - устраняет deadlock
    struct PendingVerdict {
        uint64_t         id = 0;
        RuleAction       action = RuleAction::Allow;
        bool             preferredInterfaceBlocked = false;
        uint64_t         rulesVersion = 0;
        RuleNameRef      ruleName;
    };
    bool collectRuleLog = false;
    if constexpr (kLogDesktopRuleVerdicts) {
        collectRuleLog = mode_.load(std::memory_order_relaxed) ==
                          IngestMode::Desktop;
    }

    std::vector<PendingVerdict> verdicts;
    verdicts.reserve(pendingCopy.size());

    for (const auto& pair : pendingCopy) {
        const bool logThis = collectRuleLog && pair.second.key.proto == Proto::Tcp;
        RuleNameRef matchedRuleName;
        RuleNameRef* matchedName = nullptr;
        if constexpr (kLogDesktopRuleVerdicts) {
            if (logThis) matchedName = &matchedRuleName;
        }
        const auto decision = FirewallPolicies::Evaluate(
            activePolicy, activeRules, pair.second.ToQuery(), matchedName);
        if (decision.decided) {
            PendingVerdict result;
            result.id = pair.first;
            result.action = decision.action;
            result.preferredInterfaceBlocked = decision.preferredInterfaceBlocked;
            result.rulesVersion = decision.rulesVersion;
            if constexpr (kLogDesktopRuleVerdicts) {
                if (logThis) result.ruleName = std::move(matchedRuleName);
            }
            verdicts.push_back(std::move(result));
        }
        // Без решения остаётся только Learning без подходящего правила.
        // В остальных политиках ожидающее обязательство закрывается сразу.
    }

    // Берём мьютекс заново для применения вердиктов
    {
        std::lock_guard<std::mutex> lk(mtx_);

        if (driverSession_ == activeSession && rules_ == activeRules) {
            for (const PendingVerdict& vPair : verdicts) {
                if (activeRules && activeRules->version() != vPair.rulesVersion)
                    continue;
                auto it = pending_.find(vPair.id);
                if (it == pending_.end()) continue;  // группа уже обработана

                SettleLocked(
                    fire, it->second, vPair.action,
                    (collectRuleLog &&
                     it->second.flow.key.proto == Proto::Tcp)
                        ? &vPair.ruleName : nullptr, vPair.preferredInterfaceBlocked);
                ErasePendingLocked(it);
            }
        }
        TrimHashTable(pending_);
        TrimHashTable(pendingIndex_);
    }

    return ndisSent + Fire(fire);
}

void Ingest::ExpireVerdicts(ULONGLONG now) {
    ExpireQueued(verdicts_, verdictExpiry_, now, kVerdictTtlMs);
    TrimHashTable(verdicts_);
}

void Ingest::Notify() {
    HWND ui = ui_.load(std::memory_order_relaxed);
    const UINT msg = msg_.load(std::memory_order_relaxed);
    if (ui && msg && IsWindow(ui)) PostMessageW(ui, msg, 0, 0);
}

void Ingest::ReadDebugCounters(DebugCounters::Snapshot& out) const {
    std::unique_lock lock(mtx_, std::try_to_lock);
    if (!lock.owns_lock()) return;
    auto& v = out.values;
    v[DebugCounters::PendingGroups] = pending_.size();
    v[DebugCounters::PendingIndex] = pendingIndex_.size();
    v[DebugCounters::WaitingRequests] = waiting_;
    v[DebugCounters::Verdicts] = verdicts_.size();
    v[DebugCounters::VerdictExpiry] = verdictExpiry_.size();
    v[DebugCounters::TlsAssemblies] = tlsAssemblies_.size();
    v[DebugCounters::TlsExpiry] = tlsAssemblyExpiry_.size();
    v[DebugCounters::QuicStates] = quicSniStates_.size();
    if (source_ == TrafficSource::Host) {
        DebugCounters::Snapshot ndis;
        ForSource(TrafficSource::Ndis).ReadDebugCounters(ndis);
        for (size_t id = DebugCounters::PendingGroups; id <= DebugCounters::QuicStates; ++id) {
            if (v[id] && ndis.values[id]) *v[id] += *ndis.values[id];
            else v[id].reset();
        }
    }
}

uint64_t Ingest::calls() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return calls_ + (source_ == TrafficSource::Host ? ForSource(TrafficSource::Ndis).calls() : 0);
}
uint64_t Ingest::answered() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return answered_ + (source_ == TrafficSource::Host ? ForSource(TrafficSource::Ndis).answered() : 0);
}
uint64_t Ingest::waiting() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return waiting_ + (source_ == TrafficSource::Host ? ForSource(TrafficSource::Ndis).waiting() : 0);
}

// --------------------------------------------------------- точки входа API
// Подсказка ниже касается обеих функций on_connection_v4 и on_connection_v6
// Если payload_len > 0 то для icmp это целый Ipv4/Ipv6 пакет, для других
// протоколов это может быть часть пакета.
// На каждый on_connection_v4 и on_connection_v6 должен быть отправлен вердикт
// с помощью process_verdict, сразу или когда-нибудь потом.
// -------------------------------------------------------------------------
void on_connection_v4(const pmkext::ConnectionFixedV4* event_, const uint8_t* payload, size_t payload_len) {
    if (!event_) [[unlikely]] return;

    if(0)
    {
        // Дописываем исходное событие в файл рядом с exe до его обработки.
        static std::mutex logMtx;
        std::lock_guard<std::mutex> lock(logMtx);

        SYSTEMTIME now{};
        GetLocalTime(&now);
        const auto& e = *event_;
        char line[512]{};
        const int length = _snprintf_s(
            line, _TRUNCATE,
            "%04u-%02u-%02u %02u:%02u:%02u.%03u; "
            "external_connection_id=%llu; process_id=%llu; direction=%u; protocol=%u; "
            "local=%u.%u.%u.%u:%u; remote=%u.%u.%u.%u:%u; "
            "payload_layer=%u; payload_len=%zu\r\n",
            static_cast<unsigned>(now.wYear),
            static_cast<unsigned>(now.wMonth),
            static_cast<unsigned>(now.wDay),
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            static_cast<unsigned>(now.wMilliseconds),
            static_cast<unsigned long long>(e.external_connection_id),
            static_cast<unsigned long long>(e.process_id),
            static_cast<unsigned>(e.direction),
            static_cast<unsigned>(e.protocol),
            static_cast<unsigned>(e.local_ip[0]),
            static_cast<unsigned>(e.local_ip[1]),
            static_cast<unsigned>(e.local_ip[2]),
            static_cast<unsigned>(e.local_ip[3]),
            static_cast<unsigned>(e.local_port),
            static_cast<unsigned>(e.remote_ip[0]),
            static_cast<unsigned>(e.remote_ip[1]),
            static_cast<unsigned>(e.remote_ip[2]),
            static_cast<unsigned>(e.remote_ip[3]),
            static_cast<unsigned>(e.remote_port),
            static_cast<unsigned>(e.payload_layer),
            payload_len);

        if (length > 0) {
            const std::wstring path = ModuleDirFile(L"on_connection_v4.txt");
            HANDLE file = CreateFileW(
                path.c_str(), FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr);
                CloseHandle(file);
            }
        }
    }

    Ingest::Instance().HandleV4(*event_, payload, payload_len);
}

void on_connection_v6(const pmkext::ConnectionFixedV6* event_, const uint8_t* payload, size_t payload_len) {
    if (!event_) [[unlikely]] return;
    Ingest::Instance().HandleV6(*event_, payload, payload_len);
}