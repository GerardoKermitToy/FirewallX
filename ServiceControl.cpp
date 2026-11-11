#include "ServiceControl.h"
#include "AppInfo.h"
#include "StringRes.h"
#include "Ingest.h"
#include "Rules.h"
#include "ServiceInfo.h"
#include "MacroAddr.h"
#include "FlowStore.h"
#include "ProcessProtectionOptions.h"
#include <shellapi.h>
#include "PortmasterKextClient.hpp"

namespace FirewallX {

Mode g_runMode = Mode::Desktop;

namespace {

constexpr DWORD kWaitStepMs  = 200;
constexpr DWORD kWaitTotalMs = 45000;

SERVICE_STATUS_HANDLE g_ssh = nullptr;
SERVICE_STATUS        g_status{};
HANDLE                g_stopEvent = nullptr;
DWORD                 g_checkPoint = 1;

// Членство в известной группе NT (S-1-5-<rid>) для текущего маркера доступа
bool TokenHasWellKnownRid(DWORD rid) {
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID sid = nullptr;
    if (!AllocateAndInitializeSid(&nt, 1, rid, 0, 0, 0, 0, 0, 0, 0, &sid)) return false;
    BOOL member = FALSE;
    if (!CheckTokenMembership(nullptr, sid, &member)) member = FALSE;
    FreeSid(sid);
    return member != FALSE;
}

bool ArgIsServiceSwitch(const wchar_t* a) {
    if (!a || !*a) return false;
    if (*a != L'-' && *a != L'/') return false;
    const wchar_t* p = a;
    while (*p == L'-' || *p == L'/') ++p;
    return _wcsicmp(p, L"service") == 0 || _wcsicmp(p, L"svc") == 0;
}

bool HasServiceSwitch(const wchar_t* cmdLine) {
    if (!cmdLine || !*cmdLine) return false;
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(cmdLine, &argc);
    if (!argv) return false;
    bool found = false;
    for (int i = 1; i < argc && !found; ++i) found = ArgIsServiceSwitch(argv[i]);
    LocalFree(argv);
    return found;
}

// ------------------------------------------------------------ тело службы

void ReportStatus(DWORD state, DWORD exitCode, DWORD waitHint) {
    g_status.dwServiceType  = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = (state == SERVICE_RUNNING)
        ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : g_checkPoint++;
    if (g_ssh) SetServiceStatus(g_ssh, &g_status);
}

DWORD WINAPI HandlerEx(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        ReportStatus(g_status.dwCurrentState, NO_ERROR, 0);
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_ssh = RegisterServiceCtrlHandlerExW(AppInfo::kServiceName, &HandlerEx, nullptr);
    if (!g_ssh) return;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    const DWORD protectionStatus = ProcessProtectionOptions::ApplySaved();
    if (protectionStatus != ERROR_SUCCESS) {
        ReportStatus(SERVICE_STOPPED, protectionStatus, 0);
        return;
    }

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    // При старте и после каждого отключения desktop-клиента правила читаются
    // целиком. LoadOnce закрывает файл базы сразу после загрузки: дальше работаем
    // с копией в памяти, файл не удерживается и не блокирует оконную копию
    // программы. Повторное чтение выполняется callback-ом Server уже после
    // освобождения активного pipe-соединения.
    //
    // Ошибка чтения не мешает запуску: набор правил остаётся пустым,
    // решение задаётся выбранной политикой. В Learning соединения без правила
    // по-прежнему блокируются, кроме технических ICMP-исключений.
    RuleStore rules;
    // Служебный процесс проходит в wWinMain до инициализации интерфейса, где
    // привилегия включается для desktop. Она нужна здесь отдельно: путь процесса
    // определяет App-группу, а без него CondService у недоступного процесса
    // мог бы примениться только из глобального правила при известном PID службы.
    EnableDebugPrivilege();

    // Карта потоков в службе не читается: наполнять её — напрасная работа
    // в самом частом обработчике. Один флаг снимает её с горячего пути.
    FlowStore::Instance().Enable(false);
    std::wstring loadErr;
    rules.LoadOnce(ModuleDirFile(AppInfo::kRulesDb), loadErr);

    // В локальном маршруте используется тот же RuleStore::MatchVerdict, что и
    // в desktop, включая CondService. Первый runtime-снимок готовим до запуска
    // драйвера, а следующие — фоновым потоком, чтобы сетевые события никогда
    // не выполняли RPC к SCM.
    const bool monitorServices = rules.serviceConds();
    ServiceInfo::Invalidate();
    if (monitorServices) ServiceInfo::Version(true);
    ServiceInfo::SetMonitoring(monitorServices);
    AddrMacros::Version(true);

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 45000);

    // С этого момента on_connection_v4/v6 обслуживаются по сохранённой политике.
    // Learning в службе не спрашивает пользователя: промах правил, кроме
    // технических ICMP-исключений, по-прежнему даёт немедленный Drop.
    Ingest::Instance().Attach(&rules, nullptr, IngestMode::Service,
                              FirewallPolicySetting::Load());
    portmaster_start();
    if (!portmaster_wait_ready(30000)) {
        DWORD error = portmaster_last_error();
        if (error == ERROR_SUCCESS || error == ERROR_IO_PENDING)
            error = ERROR_SERVICE_REQUEST_TIMEOUT;
        portmaster_stop();
        Ingest::Instance().Detach();
        ServiceInfo::Shutdown();
        AddrMacros::Shutdown();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        ReportStatus(SERVICE_STOPPED, error, 0);
        return;
    }
    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Полезной работы нет. Ожидание на событии, а не Sleep в цикле:
    // процессор не расходуется, а команда остановки обрабатывается мгновенно.
    WaitForSingleObject(g_stopEvent, INFINITE);

    ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);

    portmaster_stop();
    // После portmaster_stop обработчики транспорта уже завершены. До разрушения
    // локального rules убираем его заимствованный указатель из Ingest; сам Match
    // выполняется вне Ingest::mtx_, и один Detach не заменяет остановку транспорта.
    Ingest::Instance().Detach();
    ServiceInfo::Shutdown();
    AddrMacros::Shutdown();

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

// --------------------------------------------------------- работа с SCM

SC_HANDLE OpenManager(DWORD access, std::wstring& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, access);
    if (!scm) error = FormatWinError(GetLastError());
    return scm;
}

SC_HANDLE OpenSvc(SC_HANDLE scm, DWORD access, std::wstring& error, bool* missing) {
    if (missing) *missing = false;
    SC_HANDLE svc = OpenServiceW(scm, AppInfo::kServiceName, access);
    if (!svc) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            if (missing) *missing = true;
            error = LoadStringRes(IDS_SVCERR_NOT_INSTALLED);
        } else {
            error = FormatWinError(err);
        }
    }
    return svc;
}

bool WaitForState(SC_HANDLE svc, DWORD want, std::wstring& error) {
    SERVICE_STATUS_PROCESS ssp{};
    DWORD need = 0;
    for (DWORD spent = 0; spent <= kWaitTotalMs; spent += kWaitStepMs) {
        if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &need)) {
            error = FormatWinError(GetLastError());
            return false;
        }
        if (ssp.dwCurrentState == want) return true;
        if (want == SERVICE_RUNNING &&
            ssp.dwCurrentState == SERVICE_STOPPED &&
            ssp.dwWin32ExitCode != NO_ERROR) {
            error = FormatWinError(ssp.dwWin32ExitCode);
            return false;
        }
        Sleep(kWaitStepMs);
    }
    error = LoadStringRes(IDS_SVCERR_TIMEOUT);
    return false;
}

} // namespace

// ------------------------------------------------------------- режим запуска

Mode DetectRunMode(const wchar_t* cmdLine) {
    if (HasServiceSwitch(cmdLine)) {
        g_runMode = Mode::Service;
        return g_runMode;
    }
    // S-1-5-6: этот SID выдаётся только процессам, запущенным диспетчером служб
    if (TokenHasWellKnownRid(SECURITY_SERVICE_RID)) {
        g_runMode = Mode::Service;
        return g_runMode;
    }
    DWORD session = 0xFFFFFFFFu;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &session) && session == 0 &&
        !TokenHasWellKnownRid(SECURITY_INTERACTIVE_RID)) {
        g_runMode = Mode::Service;
        return g_runMode;
    }
    g_runMode = Mode::Desktop;
    return g_runMode;
}

void ForceDesktopMode() { g_runMode = Mode::Desktop; }

std::wstring RunModeText() {
    return LoadStringRes(IsService() ? IDS_SVCMODE_SERVICE : IDS_SVCMODE_APP);
}

bool RunAsService(int& exitCode) {
    exitCode = 0;
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(AppInfo::kServiceName), &ServiceMain },
        { nullptr, nullptr }
    };
    if (StartServiceCtrlDispatcherW(table)) return true;

    const DWORD err = GetLastError();
    // Процесс запущен не диспетчером служб: эвристика ошиблась либо ключ
    // --service указан вручную. Возвращаемся к оконному режиму.
    if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) return false;

    exitCode = static_cast<int>(err);
    return true;
}

// ------------------------------------------------------------ состояние

std::wstring ServiceState::Text() const {
    if (!installed) return LoadStringRes(IDS_SVCSTATE_NOT_INSTALLED);
    UINT id = IDS_SVCSTATE_INSTALLED;
    switch (state) {
    case SERVICE_RUNNING:          id = IDS_SVCSTATE_RUNNING;  break;
    case SERVICE_STOPPED:          id = IDS_SVCSTATE_STOPPED;  break;
    case SERVICE_START_PENDING:    id = IDS_SVCSTATE_STARTING; break;
    case SERVICE_STOP_PENDING:     id = IDS_SVCSTATE_STOPPING; break;
    case SERVICE_PAUSED:           id = IDS_SVCSTATE_PAUSED;   break;
    case SERVICE_PAUSE_PENDING:    id = IDS_SVCSTATE_PAUSING;  break;
    case SERVICE_CONTINUE_PENDING: id = IDS_SVCSTATE_RESUMING; break;
    default: break;
    }
    return LoadStringRes(id);
}

std::wstring ServiceState::FullText() const {
    std::wstring s = std::wstring(AppInfo::kServiceName) + L": " + Text();
    if (installed)
        s += LoadStringRes(autoStart ? IDS_SVCSTART_AUTO : IDS_SVCSTART_MANUAL);
    return s;
}

bool ServiceQuery(ServiceState& out, std::wstring& error) {
    out = ServiceState{};
    error.clear();

    SC_HANDLE scm = OpenManager(SC_MANAGER_CONNECT, error);
    if (!scm) return false;

    bool missing = false;
    SC_HANDLE svc = OpenSvc(scm, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
                            error, &missing);
    if (!svc) {
        CloseServiceHandle(scm);
        if (missing) { error.clear(); return true; }   // не установлена — не ошибка
        return false;
    }
    out.installed = true;

    SERVICE_STATUS_PROCESS ssp{};
    DWORD need = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &need)) {
        out.state   = ssp.dwCurrentState;
        out.running = ssp.dwCurrentState == SERVICE_RUNNING;
        out.pending = ssp.dwCurrentState == SERVICE_START_PENDING ||
                      ssp.dwCurrentState == SERVICE_STOP_PENDING;
    }

    DWORD cbCfg = 0;
    QueryServiceConfigW(svc, nullptr, 0, &cbCfg);
    if (cbCfg) {
        std::vector<BYTE> buf(cbCfg);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(svc, cfg, cbCfg, &cbCfg))
            out.autoStart = cfg->dwStartType == SERVICE_AUTO_START;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool ServiceInstall(std::wstring& error) {
    error.clear();

    const std::wstring exe = ModulePath();
    if (exe.empty()) { error = LoadStringRes(IDS_SVCERR_NO_PATH); return false; }
    const std::wstring bin = L"\"" + exe + L"\" " + AppInfo::kServiceSwitch;

    SC_HANDLE scm = OpenManager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE, error);
    if (!scm) return false;

    const std::wstring display = AppInfo::ServiceDisplay();
    SC_HANDLE svc = CreateServiceW(scm, AppInfo::kServiceName, display.c_str(),
                                   SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS,
                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                   SERVICE_ERROR_NORMAL, bin.c_str(),
                                   nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            error = LoadStringRes(IDS_SVCERR_ALREADY_INSTALLED);
        else if (err == ERROR_SERVICE_MARKED_FOR_DELETE)
            error = LoadStringRes(IDS_SVCERR_PENDING_DELETE);
        else                                             error = FormatWinError(err);
        CloseServiceHandle(scm);
        return false;
    }

    std::wstring descText = AppInfo::ServiceDesc();
    SERVICE_DESCRIPTIONW desc{ descText.data() };
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool ServiceStop(std::wstring& error) {
    error.clear();

    SC_HANDLE scm = OpenManager(SC_MANAGER_CONNECT, error);
    if (!scm) return false;

    bool missing = false;
    SC_HANDLE svc = OpenSvc(scm, SERVICE_STOP | SERVICE_QUERY_STATUS, error, &missing);
    if (!svc) { CloseServiceHandle(scm); return false; }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD need = 0;
    bool ok = true;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &need) &&
        ssp.dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS st{};
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
            const DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                error = FormatWinError(err);
                ok = false;
            }
        }
        if (ok) ok = WaitForState(svc, SERVICE_STOPPED, error);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool ServiceStart(std::wstring& error) {
    error.clear();

    SC_HANDLE scm = OpenManager(SC_MANAGER_CONNECT, error);
    if (!scm) return false;

    bool missing = false;
    SC_HANDLE svc = OpenSvc(scm, SERVICE_START | SERVICE_QUERY_STATUS, error, &missing);
    if (!svc) { CloseServiceHandle(scm); return false; }

    bool ok = true;
    if (!StartServiceW(svc, 0, nullptr)) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) ok = true;
        else { error = FormatWinError(err); ok = false; }
    }
    if (ok) ok = WaitForState(svc, SERVICE_RUNNING, error);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool ServiceRemove(std::wstring& error) {
    error.clear();

    // остановка перед удалением: иначе служба уйдёт в состояние
    // «помечена на удаление» и исчезнет только после перезагрузки
    std::wstring ignored;
    ServiceStop(ignored);

    SC_HANDLE scm = OpenManager(SC_MANAGER_CONNECT, error);
    if (!scm) return false;

    bool missing = false;
    SC_HANDLE svc = OpenSvc(scm, DELETE, error, &missing);
    if (!svc) { CloseServiceHandle(scm); return false; }

    bool ok = true;    
    if (!DeleteService(svc)) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE)
            error = LoadStringRes(IDS_SVCERR_ALREADY_DELETING);
        else
            error = FormatWinError(err);
        ok = false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

} // namespace FirewallX