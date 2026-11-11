// PortmasterKextClient.hpp  (API v3)
//
// Клиент драйвера PortmasterKext: открытие устройства, команды (write),
// IOCTL и фоновый разбор потока Info-записей.
//
// Форматы соответствуют command.rs / info.rs / common.rs API v3.
// Несовместим с оригинальным Portmaster Windows Kernel Extension и API v2.
//
// Требования: C++17, Windows Vista+ (CancelIoEx), MSVC / clang-cl.
// Интерфейсные политики требуют нового portmaster-kext.sys и Windows 11.
// Для setAppInterface() нужна fwpuclnt.lib, для enableRoutePolicies() — nsi.lib,
// которую CMake создаёт из nsi.def; NSI используется только для чтения.
//
// Потоковая модель:
//   * команды и IOCTL можно вызывать из любых потоков одновременно
//     (у каждого потока свой event);
//   * callback'и вызываются из потока чтения; указатели в них живут только
//     до возврата из callback'а;
//   * callback'и нужно установить ДО startReadLoop();
//   * останавливать и закрывать клиент нужно из внешнего потока: защита от
//     self-join в stopReadLoop() не делает close() безопасным внутри callback'а.

#pragma once

#ifndef _WIN32
#  error "PortmasterKextClient: only Windows is supported"
#endif

#ifdef __clang__
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif


#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>   // CTL_CODE, METHOD_BUFFERED
#include <winsvc.h>
#include <fwpmu.h>
#include <netiodef.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "FoldedText.h"
#include "ServiceControl.h"
#include "TrafficAttributionOptions.h"
#include "ReadBuffer.h"
#include "ProcessEvents.h"

//#pragma comment(lib, "advapi32.lib")

namespace pmkext {

// ---------------------------------------------------------------------
// Команды в драйвер (device.rs::write / command.rs)
// ---------------------------------------------------------------------
enum class CommandType : uint8_t {
    Shutdown              = 0,
    Verdict               = 1,
    UpdateV4              = 2,
    UpdateV6              = 3,
    ClearCache            = 4,
    GetLogs               = 5,
    GetBandwidthStats     = 6,
    PrintMemoryStats      = 7,
    CleanEndedConnections = 8,
    StartProcessMonitoring = 9,
    SetAppInterface       = 10,
};

// connection.rs::Verdict
enum class Verdict : uint8_t {
    Undecided          = 0,
    Undeterminable     = 1,
    Accept             = 2,
    PermanentAccept    = 3,
    Block              = 4,
    PermanentBlock     = 5,
    Drop               = 6,
    PermanentDrop      = 7,
    RedirectNameServer = 8,
    RedirectTunnel     = 9,
    Failed             = 10,
    RedirectSplitTunnel = 11,
};

#pragma pack(push, 1)
struct CmdVerdict {
    uint64_t id;
    uint8_t  verdict;
};
struct CmdVerdictMessage {
    uint8_t    command;
    CmdVerdict payload;
};
struct CmdUpdateV4 {
    uint8_t  protocol;
    uint8_t  local_address[4];
    uint16_t local_port;
    uint8_t  remote_address[4];
    uint16_t remote_port;
    uint8_t  verdict;
};
struct CmdUpdateV6 {
    uint8_t  protocol;
    uint8_t  local_address[16];
    uint16_t local_port;
    uint8_t  remote_address[16];
    uint16_t remote_port;
    uint8_t  verdict;
};
#pragma pack(pop)

static_assert(sizeof(CmdVerdict)        ==  9, "layout mismatch with command.rs");
static_assert(sizeof(CmdVerdictMessage) == 10, "layout mismatch with command.rs");
static_assert(sizeof(CmdUpdateV4)       == 14, "layout mismatch with command.rs");
static_assert(sizeof(CmdUpdateV6)       == 38, "layout mismatch with command.rs");

// ---------------------------------------------------------------------
// IOCTL коды (common.rs)
// ---------------------------------------------------------------------
namespace detail {

constexpr uint32_t kIoctlType        = 40000;
constexpr uint32_t kFileReadAccess   = 0x0001;   // == FILE_READ_ACCESS
constexpr uint32_t kFileWriteAccess  = 0x0002;   // == FILE_WRITE_ACCESS

constexpr uint32_t ctl_code(uint32_t dev, uint32_t fn,
                            uint32_t method, uint32_t access) {
    return (dev << 16) | (access << 14) | (fn << 2) | method;
}

// Невыровненное little-endian чтение без UB.
template <class T>
inline T load(const uint8_t* p) noexcept {
    T v{};
    std::memcpy(&v, p, sizeof(T));
    return v;
}

// RAII над HANDLE события. Manual-reset: перед каждой операцией ResetEvent.
struct EventHandle {
    HANDLE h;
    EventHandle() noexcept : h(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
    ~EventHandle() { if (h) CloseHandle(h); }
    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;
};

// Канонический app ID строится Windows по пути EXE, а не по PID.
inline DWORD buildAppInterfaceCommand(const std::wstring& path, uint64_t luid,
                                      std::vector<uint8_t>& command) {
    command.clear();
    if (path.empty() || path.find(L'\0') != std::wstring::npos)
        return ERROR_INVALID_PARAMETER;

    FWP_BYTE_BLOB* appId = nullptr;
    const DWORD status = FwpmGetAppIdFromFileName0(path.c_str(), &appId);
    if (status != ERROR_SUCCESS) return status;
    struct AppIdGuard {
        FWP_BYTE_BLOB* value;
        ~AppIdGuard() {
            if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value));
        }
    } guard{appId};
    constexpr uint32_t kMaxAppIdSize = 65534;
    if (!appId || !appId->data || appId->size < 4 ||
        appId->size > kMaxAppIdSize || (appId->size & 1) != 0)
        return ERROR_INVALID_DATA;

    // Команда 10: LUID:u64 LE, размер app ID:u32 LE, UTF-16LE с завершающим NUL.
    command.resize(13 + appId->size);
    command[0] = static_cast<uint8_t>(CommandType::SetAppInterface);
    for (unsigned i = 0; i < 8; ++i)
        command[1 + i] = static_cast<uint8_t>(luid >> (i * 8));
    for (unsigned i = 0; i < 4; ++i)
        command[9 + i] = static_cast<uint8_t>(appId->size >> (i * 8));
    std::memcpy(command.data() + 13, appId->data, appId->size);
    return ERROR_SUCCESS;
}

// Прямой импорт из nsi.lib: никакой динамической загрузки и NSI-записи.
extern "C" __declspec(dllimport) DWORD WINAPI NsiGetAllParameters(
    DWORD, const NPI_MODULEID*, DWORD, const void*, DWORD,
    void*, DWORD, void*, DWORD, void*, DWORD);

// Подмена операций позволяет проверять fallback без изменения настроек Windows.
struct RoutePolicyOperations {
    decltype(&NsiGetAllParameters) query = NsiGetAllParameters;
    decltype(&GetSystemDirectoryW) systemDirectory = GetSystemDirectoryW;
    decltype(&CreateProcessW) createProcess = CreateProcessW;
    decltype(&WaitForSingleObject) wait = WaitForSingleObject;
    decltype(&GetExitCodeProcess) exitCode = GetExitCodeProcess;
    decltype(&TerminateProcess) terminate = TerminateProcess;
    decltype(&CloseHandle) close = CloseHandle;
    decltype(&GetLastError) lastError = GetLastError;
};

inline bool routePoliciesEnabled(const RoutePolicyOperations& operations, bool ipv6) {
    if (!operations.query) return false;
    // Приватный ABI глобальной IP-таблицы Windows 11 используется только для
    // проверки: ошибка чтения или значение, отличное от 1, требуют netsh.
    static_assert(sizeof(NPI_MODULEID) == 24);
    static_assert(offsetof(NPI_MODULEID, Guid) == 8);
    NPI_MODULEID module{};
    module.Length = sizeof(module);
    module.Type = MIT_GUID;
    module.Guid = {ipv6 ? 0xeb004a01u : 0xeb004a00u, 0x9b1a, 0x11d4,
                   {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc}};
    std::array<BYTE, 0x9c> globals;
    globals.fill(0xff);
    const DWORD status = operations.query(
        1, &module, 6, nullptr, 0, globals.data(),
        static_cast<DWORD>(globals.size()), nullptr, 0, nullptr, 0);
    return status == ERROR_SUCCESS && globals[0x98] == 1;
}

inline DWORD enableFamilyRoutePolicies(const RoutePolicyOperations& operations,
                                       const wchar_t* family) {
    wchar_t directory[MAX_PATH]{};
    const UINT length = operations.systemDirectory(directory, MAX_PATH);
    if (length == 0) return operations.lastError();
    if (length >= MAX_PATH) return ERROR_INSUFFICIENT_BUFFER;
    const std::wstring executable = std::wstring(directory) + L"\\netsh.exe";
    std::wstring command = L"\"" + executable + L"\" interface " + family +
        L" set global routepolicies=enabled store=active";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    // Только системный EXE, без shell, PATH, унаследованных HANDLE и вывода в UI.
    startup.dwFlags = STARTF_USESTDHANDLES;
    PROCESS_INFORMATION process{};
    if (!operations.createProcess(executable.c_str(), command.data(), nullptr, nullptr,
                                  FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                                  &startup, &process))
        return operations.lastError();
    operations.close(process.hThread);
    const DWORD wait = operations.wait(process.hProcess, 10'000);
    if (wait != WAIT_OBJECT_0) {
        const DWORD error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : operations.lastError();
        operations.terminate(process.hProcess, error);
        operations.wait(process.hProcess, 1'000);
        operations.close(process.hProcess);
        return error;
    }
    DWORD exitCode = 0;
    const BOOL haveExitCode = operations.exitCode(process.hProcess, &exitCode);
    const DWORD error = haveExitCode ? exitCode : operations.lastError();
    operations.close(process.hProcess);
    return error;
}

inline DWORD enableRoutePolicies(const RoutePolicyOperations& operations) {
    for (bool ipv6 : {false, true}) {
        if (routePoliciesEnabled(operations, ipv6)) continue;
        const DWORD error = enableFamilyRoutePolicies(operations, ipv6 ? L"ipv6" : L"ipv4");
        if (error != ERROR_SUCCESS) return error;
    }
    return ERROR_SUCCESS;
}

} // namespace detail

constexpr uint32_t IOCTL_VERSION =
    detail::ctl_code(detail::kIoctlType, 0x800, METHOD_BUFFERED,
                     detail::kFileReadAccess | detail::kFileWriteAccess);
constexpr uint32_t IOCTL_SHUTDOWN_REQUEST =
    detail::ctl_code(detail::kIoctlType, 0x801, METHOD_BUFFERED,
                     detail::kFileReadAccess | detail::kFileWriteAccess);

// Слот 0x802 принадлежал удалённому GetThreadId и не переиспользуется.
constexpr uint32_t IOCTL_START_PROCESS_MONITORING =
    detail::ctl_code(detail::kIoctlType, 0x803, METHOD_BUFFERED,
                     detail::kFileReadAccess | detail::kFileWriteAccess);
static_assert(IOCTL_START_PROCESS_MONITORING == 0x9c40e00c, "IOCTL mismatch with common.rs");

constexpr uint32_t IOCTL_SET_APP_INTERFACE =
    detail::ctl_code(detail::kIoctlType, 0x804, METHOD_BUFFERED,
                     detail::kFileReadAccess | detail::kFileWriteAccess);
static_assert(IOCTL_SET_APP_INTERFACE == 0x9c40e010, "IOCTL mismatch with common.rs");

// ---------------------------------------------------------------------
// Структуры из драйвера (info.rs, API v3)
// ---------------------------------------------------------------------
enum class InfoType : uint8_t {
    LogLine              = 0,
    // Значения 1 и 2 зарезервированы для старого формата соединений.
    ConnectionIpv4       = 7,
    ConnectionIpv6       = 8,
    ConnectionEndEventV4 = 3,
    ConnectionEndEventV6 = 4,
    BandwidthStatsV4     = 5,
    BandwidthStatsV6     = 6,
    ProcessCreated       = 9,
    ProcessTerminated    = 10,
};

// TID = 0 означает отсутствие атрибуции. Нулевые индексы могут быть штатными
// значениями WFP либо означать недоступные метаданные на данном слое.
// condition_flags — полная исходная маска FWP_CONDITION_FLAG_* из Flags классификации WFP
// как на ALE-, так и на IP-пакетных слоях.
#pragma pack(push, 1)
struct ConnectionFixedV4 {
    uint64_t external_connection_id, process_id;
    uint64_t tid;
    uint32_t compartment_id, condition_flags, interface_index, sub_interface_index;
    uint8_t  direction, protocol;
    uint8_t  local_ip[4], remote_ip[4];
    uint16_t local_port, remote_port;
    uint8_t  payload_layer;
};

struct ConnectionFixedV6 {
    uint64_t external_connection_id, process_id;
    uint64_t tid;
    uint32_t compartment_id, condition_flags, interface_index, sub_interface_index;
    uint8_t  direction, protocol;
    uint8_t  local_ip[16], remote_ip[16];
    uint16_t local_port, remote_port;
    uint8_t  payload_layer;
};
struct ConnectionEndV4 {
    uint64_t process_id;
    uint8_t  direction, protocol;
    uint8_t  local_ip[4], remote_ip[4];
    uint16_t local_port, remote_port;
};
struct ConnectionEndV6 {
    uint64_t process_id;
    uint8_t  direction, protocol;
    uint8_t  local_ip[16], remote_ip[16];
    uint16_t local_port, remote_port;
};
struct BandwidthValueV4 {
    uint8_t  local_ip[4];  uint16_t local_port;
    uint8_t  remote_ip[4]; uint16_t remote_port;
    uint64_t transmitted_bytes, received_bytes;
};

struct BandwidthValueV6 {
    uint8_t  local_ip[16];  uint16_t local_port;
    uint8_t  remote_ip[16]; uint16_t remote_port;
    uint64_t transmitted_bytes, received_bytes;
};

#pragma pack(pop)

// Ловим рассинхронизацию с Rust-стороной на этапе компиляции.
static_assert(sizeof(ConnectionFixedV4) == 55, "layout mismatch with info.rs");
static_assert(sizeof(ConnectionFixedV6) == 79, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV4, tid) == 16, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV6, tid) == 16, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV4, compartment_id) == 24, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV6, compartment_id) == 24, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV4, condition_flags) == 28, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV6, condition_flags) == 28, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV4, interface_index) == 32, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV6, interface_index) == 32, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV4, sub_interface_index) == 36, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV6, sub_interface_index) == 36, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV4, direction) == 40, "layout mismatch with info.rs");
static_assert(offsetof(ConnectionFixedV6, direction) == 40, "layout mismatch with info.rs");
static_assert(sizeof(ConnectionEndV4)   == 22, "layout mismatch with info.rs");
static_assert(sizeof(ConnectionEndV6)   == 46, "layout mismatch with info.rs");
static_assert(sizeof(BandwidthValueV4)  == 28, "layout mismatch with info.rs");
static_assert(sizeof(BandwidthValueV6)  == 52, "layout mismatch with info.rs");
static_assert(alignof(BandwidthValueV4) == 1, "packing is broken");
static_assert(alignof(BandwidthValueV6) == 1, "packing is broken");

// ---------------------------------------------------------------------
// Клиент драйвера
// ---------------------------------------------------------------------
class KextClient {
public:

        const wchar_t* devicePath  = L"\\\\.\\PortmasterKext";
        const wchar_t* serviceName = L"PortmasterKext";
        const wchar_t* driverFile  = L"portmaster-kext.sys"; // рядом с exe
        DWORD openTimeoutMs   = 2000;   // ретраи CreateFile после старта драйвера
        DWORD serviceTimeoutMs = 30000;
        std::atomic<bool> keepServiceOnClose{ false };
		bool g_running = false;


    // ---- callback'и (zero-copy; данные валидны только внутри вызова) ----
    using ConnectionV4Callback = void (*)(
        const ConnectionFixedV4*, const uint8_t*, uint32_t) noexcept;
    using ConnectionV6Callback = void (*)(
        const ConnectionFixedV6*, const uint8_t*, uint32_t) noexcept;
    using ConnectionEndV4Callback = void (*)(const ConnectionEndV4*) noexcept;
    using ConnectionEndV6Callback = void (*)(const ConnectionEndV6*) noexcept;
    using LogLineCallback = void (*)(uint8_t, const char*, uint32_t) noexcept;
    using BandwidthV4Callback = void (*)(
        uint8_t, const BandwidthValueV4*, uint32_t) noexcept;
    using BandwidthV6Callback = void (*)(
        uint8_t, const BandwidthValueV6*, uint32_t) noexcept;
    using ProcessCreatedCallback = void (*)(const ProcessCreated*, uint32_t) noexcept;
    using ProcessTerminatedCallback = void (*)(const ProcessTerminated*, uint32_t) noexcept;
    using ErrorCallback = void (*)(const char*, DWORD) noexcept;
    using RawRecordCallback = bool (*)(
        void*, const uint8_t*, uint32_t) noexcept;

    ConnectionV4Callback onConnectionV4 = nullptr;
    ConnectionV6Callback onConnectionV6 = nullptr;
    ConnectionEndV4Callback onConnectionEndV4 = nullptr;
    ConnectionEndV6Callback onConnectionEndV6 = nullptr;
    LogLineCallback onLogLine = nullptr;
    BandwidthV4Callback onBandwidthStatsV4 = nullptr;
    BandwidthV6Callback onBandwidthStatsV6 = nullptr;
    // Таблица уже обновлена до вызова callback; одинаковые пути разделяются.
    ProcessCreatedCallback onProcessCreated = nullptr;
    ProcessTerminatedCallback onProcessTerminated = nullptr;
    ErrorCallback onError = nullptr;
    RawRecordCallback onRawRecord = nullptr;
    void* onRawRecordContext = nullptr;

    explicit KextClient(ProcessTable* processes = nullptr)
        : processes_(processes ? processes : &localProcesses_) {}
    ~KextClient() { close(); }
    KextClient(const KextClient&)            = delete;
    KextClient& operator=(const KextClient&) = delete;

    DWORD lastError() const { return lastError_.load(std::memory_order_relaxed); }
    bool  isOpen()    const { return hDevice_ != INVALID_HANDLE_VALUE; }

    const ProcessTable& processes() const noexcept { return *processes_; }
    void clearProcessEvents() { processes_->clear(); }
    // Переключение локального хранения не останавливает wire-поток драйвера.
    void setProcessEventsEnabled(bool enabled) { processes_->setEnabled(enabled); }
    bool processEventsEnabled() const { return processes_->enabled(); }

    // Явный вызов до установки интерфейсных политик; открытый драйвер не нужен.
    // NSI подтверждает каждый стек отдельно; иначе netsh включает только его
    // active-настройку. Нужны права администратора; persistent не меняется.
    // До 10 секунд на семейство. Ошибка Win32/netsh доступна через lastError().
    // При ошибке IPv6 уже включённый IPv4 не откатывается.
    bool enableRoutePolicies() {
        const DWORD error = detail::enableRoutePolicies({});
        lastError_.store(error);
        return error == ERROR_SUCCESS;
    }

    // open()/startReadLoop() сами не включают сбор: нужен явный IOCTL либо write.
    bool open() {
        if (isOpen()) return true;
        if (!readEvent_.h || !stopEvent_.h) {
            lastError_.store(ERROR_NO_SYSTEM_RESOURCES); return false;
        }
        if (true && !ensureServiceRunning()) return false;

        // Символическая ссылка устройства может появиться чуть позже старта.
        const ULONGLONG deadline = GetTickCount64() + openTimeoutMs;
        for (;;) {
            hDevice_ = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
                                   0, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                   nullptr);
            if (hDevice_ != INVALID_HANDLE_VALUE) break;
            lastError_.store(GetLastError());
            if (GetTickCount64() >= deadline) return false;
            Sleep(50);
        }

        // До любых команд и запуска reader-а проверяем минимальную версию wire-API.
        // Несовместимый дескриптор закрываем без отправки Shutdown.
        uint8_t version[4]{};
        constexpr uint8_t kMinimumVersion[4] = {3, 0, 0, 0};
        const bool gotVersion = ioctlGetVersion(version);
        if (!gotVersion || std::memcmp(version, kMinimumVersion, sizeof(version)) < 0) {
            const DWORD error = gotVersion ? ERROR_REVISION_MISMATCH : lastError();
            CloseHandle(hDevice_);
            hDevice_ = INVALID_HANDLE_VALUE;
            lastError_.store(error);
            return false;
        }

        if (!buffer_.Reserve(kInitialBuffer)) {
            lastError_.store(ERROR_NOT_ENOUGH_MEMORY);
            CloseHandle(hDevice_);
            hDevice_ = INVALID_HANDLE_VALUE;
            return false;
        }
        head_ = tail_ = 0;
        clearProcessEvents();
        return true;
    }

    void close() {
        stopReadLoop();

        if (hDevice_ != INVALID_HANDLE_VALUE) {
            // Просьба о выгрузке: драйвер снимает свои callout'ы WFP, пока
            // связь с ним ещё есть. Дескриптор закрывается сразу после —
            // пока он открыт, драйвер считается используемым и не выгрузится.
            ioctlShutdownRequest();
            CloseHandle(hDevice_);
            hDevice_ = INVALID_HANDLE_VALUE;
        }

        buffer_.Reset();
        head_ = tail_ = 0;
        clearProcessEvents();
        {
            std::lock_guard<std::mutex> lock(appInterfaceMutex_);
            appInterfaceCommands_.clear();
        }

        // Останавливаем службу, за которую клиент принял ответственность при open().
        // keepServiceOnClose сохраняет регистрацию и задаёт загрузочный старт.
        if (serviceOwned_) {
            stopAndRemoveService(
                !keepServiceOnClose.load(std::memory_order_acquire));
            serviceOwned_ = false;
        }
    }

    bool configureServiceBootStart() {
        constexpr wchar_t kServiceKey[] =
            L"SYSTEM\\CurrentControlSet\\Services\\PortmasterKext";
        HKEY key = nullptr;
        const LSTATUS opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE, kServiceKey, 0, KEY_SET_VALUE, &key);
        if (opened != ERROR_SUCCESS) {
            lastError_.store(static_cast<DWORD>(opened));
            return false;
        }

        const DWORD start = SERVICE_BOOT_START;
        const LSTATUS written = RegSetValueExW(
            key, L"Start", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&start), sizeof(start));
        RegCloseKey(key);
        if (written != ERROR_SUCCESS) {
            lastError_.store(static_cast<DWORD>(written));
            return false;
        }
        return true;
    }

    // Запрашивает остановку драйвера. При remove=true оконный процесс удаляет
    // регистрацию службы; при remove=false она сохраняется с загрузочным стартом.
    // Возвращает результат операций регистрации; код ошибки доступен в lastError().
    // close() этот результат игнорирует.
    bool stopAndRemoveService(bool remove = true) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) { lastError_.store(GetLastError()); return false; }

        const DWORD access = SERVICE_STOP | SERVICE_QUERY_STATUS |
                             (remove ? DELETE : 0);
        SC_HANDLE svc = OpenServiceW(scm, serviceName, access);
        if (!svc) {
            const DWORD err = GetLastError();
            CloseServiceHandle(scm);
            // Службы нет — цель достигнута.
            if (err == ERROR_SERVICE_DOES_NOT_EXIST) return true;
            lastError_.store(err);
            return false;
        }

        DWORD state = 0;
        if (queryState(svc, state) && state != SERVICE_STOPPED) {
            SERVICE_STATUS st{};
            if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
                const DWORD err = GetLastError();
                if (err != ERROR_SERVICE_NOT_ACTIVE) lastError_.store(err);
            }
            // Драйвер выгружается не мгновенно: удаление до остановки оставило
            // бы службу в состоянии «помечена на удаление» до перезагрузки.
            waitForState(svc, SERVICE_STOPPED, serviceTimeoutMs);
        }

        bool ok = true;
        if (remove && !FirewallX::IsService())
        {
            if (!DeleteService(svc)) {
                const DWORD err = GetLastError();
                if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
                    lastError_.store(err);
                    ok = false;
                }
            }
        } else if (!remove && !configureServiceBootStart()) {
            ok = false;
        }

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok;
    }

    // ---------------- Команды (write) ----------------
    // Пишет готовый wire-буфер команды без разбора и преобразования.
    bool writeRaw(const void* data, size_t size) {
        if (!isOpen()) { lastError_.store(ERROR_INVALID_HANDLE); return false; }
        if (!data || size == 0 || size > MAXDWORD) [[unlikely]] {
            lastError_.store(ERROR_INVALID_DATA);
            return false;
        }

        HANDLE ev = threadEvent();
        if (!ev) [[unlikely]] { lastError_.store(ERROR_NO_SYSTEM_RESOURCES); return false; }

        ResetEvent(ev);
        OVERLAPPED ov{};
        ov.hEvent = ev;
        const BOOL immediate = WriteFile(
            hDevice_, data, static_cast<DWORD>(size), nullptr, &ov);
        return completeSync(ov, immediate, nullptr);
    }

    bool sendShutdown()              { return writeCmd(CommandType::Shutdown); }
    bool sendClearCache()            { return writeCmd(CommandType::ClearCache); }
    bool sendGetLogs()               { return writeCmd(CommandType::GetLogs); }
    bool sendGetBandwidthStats()     { return writeCmd(CommandType::GetBandwidthStats); }
    bool sendPrintMemoryStats()      { return writeCmd(CommandType::PrintMemoryStats); }
    bool sendCleanEndedConnections() { return writeCmd(CommandType::CleanEndedConnections); }
    bool sendStartProcessMonitoring() { return writeCmd(CommandType::StartProcessMonitoring); }

    bool sendVerdict(uint64_t id, Verdict verdict) {
        CmdVerdict c{ id, static_cast<uint8_t>(verdict) };
        return writeCmd(CommandType::Verdict, &c, sizeof(c));
    }

    bool sendUpdateV4(uint8_t protocol, const uint8_t localAddr[4], uint16_t localPort,
                      const uint8_t remoteAddr[4], uint16_t remotePort, Verdict verdict) {
        CmdUpdateV4 c{};
        c.protocol = protocol;
        std::memcpy(c.local_address, localAddr, 4);
        c.local_port = localPort;
        std::memcpy(c.remote_address, remoteAddr, 4);
        c.remote_port = remotePort;
        c.verdict = static_cast<uint8_t>(verdict);
        return writeCmd(CommandType::UpdateV4, &c, sizeof(c));
    }

    bool sendUpdateV6(uint8_t protocol, const uint8_t localAddr[16], uint16_t localPort,
                      const uint8_t remoteAddr[16], uint16_t remotePort, Verdict verdict) {
        CmdUpdateV6 c{};
        c.protocol = protocol;
        std::memcpy(c.local_address, localAddr, 16);
        c.local_port = localPort;
        std::memcpy(c.remote_address, remoteAddr, 16);
        c.remote_port = remotePort;
        c.verdict = static_cast<uint8_t>(verdict);
        return writeCmd(CommandType::UpdateV6, &c, sizeof(c));
    }

    // ---------------- IOCTL ----------------
    bool deviceIoctl(uint32_t code, void* out, DWORD outSize, DWORD* returned,
                     const void* input = nullptr, DWORD inputSize = 0) {
        if (!isOpen()) { lastError_.store(ERROR_INVALID_HANDLE); return false; }
        if (!input && inputSize != 0) {
            lastError_.store(ERROR_INVALID_PARAMETER); return false;
        }
        HANDLE ev = threadEvent();
        if (!ev) [[unlikely]] { lastError_.store(ERROR_NO_SYSTEM_RESOURCES); return false; }

        ResetEvent(ev);
        OVERLAPPED ov{};
        ov.hEvent = ev;
        const BOOL immediate = DeviceIoControl(hDevice_, code, const_cast<void*>(input), inputSize,
                                              out, outSize, nullptr, &ov);
        return completeSync(ov, immediate, returned);
    }

    bool ioctlGetVersion(uint8_t versionOut[4]) {
        DWORD n = 0;
        if (!deviceIoctl(IOCTL_VERSION, versionOut, 4, &n)) return false;
        if (n != 4) { lastError_.store(ERROR_INVALID_DATA); return false; }
        return true;
    }

    bool ioctlShutdownRequest() {
        return deviceIoctl(IOCTL_SHUTDOWN_REQUEST, nullptr, 0, nullptr);
    }

    // Повторный запрос пересобирает снимок в драйвере, но не очищает локальную
    // таблицу: старые непрочитанные события остаются в том же wire-потоке.
    bool ioctlStartProcessMonitoring() {
        return deviceIoctl(IOCTL_START_PROCESS_MONITORING, nullptr, 0, nullptr);
    }

    // Предпочитаемый интерфейс для всех экземпляров EXE по полному пути, не PID.
    // luid — NET_LUID::Value (не индекс); 0 удаляет политику этого приложения.
    // По умолчанию IOCTL, viaWrite=true — команда 10 через WriteFile.
    // Применяется к новым IPv4/IPv6-соединениям; политика живёт до cleanup
    // дескриптора/Shutdown. enableRoutePolicies() вызывается отдельно.
    bool setAppInterface(const std::wstring& path, uint64_t luid, bool viaWrite = false) {
        if (!isOpen()) { lastError_.store(ERROR_INVALID_HANDLE); return false; }
        return setAppInterfaceWithSender(path, luid, [&](const uint8_t* command, size_t size) {
            const bool sent = viaWrite ? writeRaw(command, size) :
                deviceIoctl(IOCTL_SET_APP_INTERFACE, nullptr, 0, nullptr,
                            command + 1, static_cast<DWORD>(size - 1));
            return sent ? ERROR_SUCCESS : lastError();
        });
    }

    // Тот же кеш используется raw pipe без открытого локального устройства.
    // sender синхронно отправляет полную команду и возвращает код ошибки Win32.
    template <class Sender>
    bool setAppInterfaceWithSender(const std::wstring& path, uint64_t luid, Sender&& sender) {
        if (path.empty() || path.find(L'\0') != std::wstring::npos) {
            lastError_.store(ERROR_INVALID_PARAMETER);
            return false;
        }
        std::lock_guard<std::mutex> lock(appInterfaceMutex_);
        auto found = appInterfaceCommands_.find(path);
        if (found == appInterfaceCommands_.end()) {
            std::vector<uint8_t> command;
            const DWORD error = detail::buildAppInterfaceCommand(path, luid, command);
            if (error != ERROR_SUCCESS) { lastError_.store(error); return false; }
            found = appInterfaceCommands_.emplace(path, std::move(command)).first;
        } else {
            // App ID не зависит от LUID: меняем только восемь байт готовой команды.
            for (unsigned i = 0; i < 8; ++i)
                found->second[1 + i] = static_cast<uint8_t>(luid >> (i * 8));
        }
        const DWORD error = sender(found->second.data(), found->second.size());
        lastError_.store(error);
        // При ошибке сохраняем App ID для повтора даже после удаления EXE.
        if (error == ERROR_SUCCESS && luid == 0) appInterfaceCommands_.erase(found);
        return error == ERROR_SUCCESS;
    }

    // ---------------- Чтение потока событий ----------------
    bool startReadLoop() {
        if (!isOpen()) { lastError_.store(ERROR_INVALID_HANDLE); return false; }
        if (loopRunning_.load(std::memory_order_acquire)) return true;
        if (readThread_) {
            WaitForSingleObject(readThread_, INFINITE);
            CloseHandle(readThread_);
            readThread_ = nullptr;
            readThreadId_ = 0;
        }
        if (!readEvent_.h || !stopEvent_.h) {
            lastError_.store(ERROR_NO_SYSTEM_RESOURCES); return false;
        }

        ResetEvent(stopEvent_.h);
        readOv_ = OVERLAPPED{};
        readOv_.hEvent = readEvent_.h;
        loopRunning_.store(true, std::memory_order_release);
        readThread_ = CreateThread(
            nullptr, 0, ReadThreadProc, this, 0, &readThreadId_);
        if (!readThread_) {
            loopRunning_.store(false, std::memory_order_release);
            lastError_.store(GetLastError());
            readThreadId_ = 0;
            return false;
        }
        return true;
    }

    void stopReadLoop() {
        if (!readThread_) return;
        // Защита от self-join, если вызвано из callback'а.
        if (readThreadId_ == GetCurrentThreadId()) return;

        SetEvent(stopEvent_.h);
        // Сигнал остановки прерывает ожидание reader-а; тот отменяет свой ReadFile.
        // Дополнительно отправляем штатную команду Shutdown драйверу.
        //if (hDevice_ != INVALID_HANDLE_VALUE) CancelIoEx(hDevice_, &readOv_);
		sendShutdown();
        WaitForSingleObject(readThread_, INFINITE);
        CloseHandle(readThread_);
        readThread_ = nullptr;
        readThreadId_ = 0;
    }

    void dispatchOne(InfoType type, const uint8_t* data, uint32_t size) {
        switch (type) {
        case InfoType::LogLine: {
            if (size < 1 || !onLogLine) return;
            onLogLine(data[0], reinterpret_cast<const char*>(data + 1), size - 1);
            return;
        }
        case InfoType::ConnectionIpv4: {
            constexpr uint32_t kFixed = sizeof(ConnectionFixedV4);
            if (size < kFixed + 4) [[unlikely]] return;
            const uint32_t payloadSize = detail::load<uint32_t>(data + kFixed);
            if (payloadSize > size - kFixed - 4) [[unlikely]] return;      // битая запись
            if (!onConnectionV4)
                return;
            onConnectionV4(reinterpret_cast<const ConnectionFixedV4*>(data), data + kFixed + 4, reinterpret_cast<const ConnectionFixedV4*>(data)->payload_layer == 3 ? payloadSize : 0);
            return;
        }
        case InfoType::ConnectionIpv6: {
            constexpr uint32_t kFixed = sizeof(ConnectionFixedV6);
            if (size < kFixed + 4) [[unlikely]] return;
            const uint32_t payloadSize = detail::load<uint32_t>(data + kFixed);
            if (payloadSize > size - kFixed - 4) [[unlikely]] return;
            if (!onConnectionV6) return;
            onConnectionV6(reinterpret_cast<const ConnectionFixedV6*>(data), data + kFixed + 4, reinterpret_cast<const ConnectionFixedV6*>(data)->payload_layer == 3 ? payloadSize : 0);
            return;
        }
        case InfoType::ConnectionEndEventV4: {
            if (size < sizeof(ConnectionEndV4) || !onConnectionEndV4) return;
            ConnectionEndV4 e;
            std::memcpy(&e, data, sizeof(e));
            onConnectionEndV4(&e);
            return;
        }
        case InfoType::ConnectionEndEventV6: {
            if (size < sizeof(ConnectionEndV6) || !onConnectionEndV6) return;
            ConnectionEndV6 e;
            std::memcpy(&e, data, sizeof(e));
            onConnectionEndV6(&e);
            return;
        }
        case InfoType::BandwidthStatsV4:
            dispatchBandwidth<BandwidthValueV4>(data, size, onBandwidthStatsV4);
            return;
        case InfoType::BandwidthStatsV6:
            dispatchBandwidth<BandwidthValueV6>(data, size, onBandwidthStatsV6);
            return;
        case InfoType::ProcessCreated: {
            if (size % sizeof(ProcessCreated) || (size && !data)) [[unlikely]] return;
            const auto* values = reinterpret_cast<const ProcessCreated*>(data);
            const uint32_t count = size / sizeof(ProcessCreated);
            if (processes_->applyCreated(values, count) && onProcessCreated)
                onProcessCreated(values, count);
            return;
        }
        case InfoType::ProcessTerminated: {
            if (size % sizeof(ProcessTerminated) || (size && !data)) [[unlikely]] return;
            const auto* values = reinterpret_cast<const ProcessTerminated*>(data);
            const uint32_t count = size / sizeof(ProcessTerminated);
            if (processes_->applyTerminated(values, count) && onProcessTerminated)
                onProcessTerminated(values, count);
            return;
        }
        default:
            return;   // неизвестный тип — пропускаем (forward compatibility)
        }
    }

private:
    friend struct KextClientTestAccess;
    static constexpr size_t kInitialBuffer = 512 * 1024;
    static constexpr int    kMaxErrorStreak = 16;

    HANDLE               hDevice_ = INVALID_HANDLE_VALUE;
    detail::EventHandle  readEvent_;   // событие цикла чтения (постоянное)
    detail::EventHandle  stopEvent_;   // manual-reset сигнал остановки
    OVERLAPPED           readOv_{};
    HANDLE               readThread_ = nullptr;
    DWORD                readThreadId_ = 0;
    std::atomic<bool>    loopRunning_{ false };
    std::atomic<DWORD>   lastError_{ 0 };
    // Клиент принял управление службой в ensureServiceRunning, даже если она
    // уже существовала. close() выполнит её остановку и обработку регистрации.
    bool                 serviceOwned_ = false;
    struct AppInterfacePathHash {
        size_t operator()(const std::wstring& path) const {
            return static_cast<size_t>(HashTextNoCase(path));
        }
    };
    struct AppInterfacePathEqual {
        bool operator()(const std::wstring& a, const std::wstring& b) const {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i)
                if (FoldCaseChar(a[i]) != FoldCaseChar(b[i])) return false;
            return true;
        }
    };
    std::mutex appInterfaceMutex_;
    std::unordered_map<std::wstring, std::vector<uint8_t>,
                       AppInterfacePathHash, AppInterfacePathEqual> appInterfaceCommands_;
    ProcessTable         localProcesses_;
    ProcessTable*        processes_;

    // Накопитель: [head_, tail_) — непрочитанные байты.
    read_buffer::Buffer<kInitialBuffer> buffer_;
    size_t head_ = 0, tail_ = 0;
    int    errorStreak_ = 0;

    // Один event на поток на все синхронные операции этого потока.
    static HANDLE threadEvent() {
        thread_local detail::EventHandle ev;
        return ev.h;
    }

    // Дожидается завершения overlapped-операции. Гарантирует, что при выходе
    // ядро больше не ссылается на стековые буферы/OVERLAPPED вызывающего.
    bool completeSync(OVERLAPPED& ov, BOOL immediate, DWORD* transferred) {
        if (!immediate) {
            const DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) [[unlikely]] { lastError_.store(err); return false; }
        }
        DWORD n = 0;
        if (!GetOverlappedResult(hDevice_, &ov, &n, TRUE)) [[unlikely]] {
            const DWORD err = GetLastError();
            if (!HasOverlappedIoCompleted(&ov)) { // упало само ожидание
                CancelIoEx(hDevice_, &ov);
                DWORD dummy = 0;
                GetOverlappedResult(hDevice_, &ov, &dummy, TRUE);
            }
            lastError_.store(err);
            return false;
        }
        if (transferred) *transferred = n;
        return true;
    }

    bool writeCmd(CommandType type, const void* data = nullptr, size_t size = 0) {
        uint8_t* buf = static_cast<uint8_t*>(alloca(1 + size));
        buf[0] = static_cast<uint8_t>(type);
        if (size) std::memcpy(buf + 1, data, size);
        return writeRaw(buf, 1 + size);
    }

    // ------------------- поток чтения -------------------
    static DWORD WINAPI ReadThreadProc(void* context) noexcept {
        static_cast<KextClient*>(context)->readLoop();
        return 0;
    }

    void readLoop() {
        for (;;) {
            if (stopRequested(0)) [[unlikely]] break;

            if (!ensureWritable(1)) [[unlikely]] {
                lastError_.store(ERROR_NOT_ENOUGH_MEMORY);
                break;
            }

            uint8_t* dst = buffer_.Data() + tail_;
            const size_t available = buffer_.Capacity() - tail_;
            const DWORD want = available > MAXDWORD ? MAXDWORD : static_cast<DWORD>(available);

            ResetEvent(readEvent_.h);
            DWORD read = 0;
            if (!ReadFile(hDevice_, dst, want, &read, &readOv_)) {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    HANDLE waits[2] = { readEvent_.h, stopEvent_.h };
                    const DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                    if (w != WAIT_OBJECT_0) [[unlikely]] {          // стоп или сбой ожидания
                        CancelIoEx(hDevice_, &readOv_);
                        DWORD dummy = 0;
                        GetOverlappedResult(hDevice_, &readOv_, &dummy, TRUE);
                        break;
                    }
                    if (!GetOverlappedResult(hDevice_, &readOv_, &read, FALSE)) [[unlikely]] {
                        if (!handleReadError(GetLastError())) break;
                        continue;
                    }
                } else {
                    if (!handleReadError(err)) break;
                    continue;
                }
            }

            errorStreak_ = 0;
            if (read == 0) [[unlikely]] {    // не крутим CPU впустую
                if (stopRequested(1)) break;
                continue;
            }
            tail_ += read;
            dispatchAvailable();
        }
        head_ = tail_ = 0;
        buffer_.ReleaseLarge();
        loopRunning_.store(false, std::memory_order_release);
    }

    bool stopRequested(DWORD waitMs) const {
        return WaitForSingleObject(stopEvent_.h, waitMs) == WAIT_OBJECT_0;
    }

    // true — можно пробовать снова, false — выходим из цикла.
    bool handleReadError(DWORD err) {
        if (err == ERROR_OPERATION_ABORTED) return false;   // CancelIoEx
        if (stopRequested(0)) return false;

        switch (err) {                                       // фатальные
        case ERROR_INVALID_HANDLE:
        case ERROR_DEVICE_NOT_CONNECTED:
        case ERROR_NO_SUCH_DEVICE:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_ACCESS_DENIED:
            lastError_.store(err);
            if (onError) onError("ReadFile: fatal", err);
            return false;
        default:
            break;
        }
        if (++errorStreak_ > kMaxErrorStreak) {
            lastError_.store(err);
            if (onError) onError("ReadFile: too many errors", err);
            return false;
        }
        if (onError) onError("ReadFile: retry", err);
        return !stopRequested(50);   // пауза вместо busy-loop
    }

    bool ensureWritable(size_t need) {
        if (buffer_.Capacity() - tail_ >= need) [[likely]] return true;
        const size_t pending = tail_ - head_;
        if (head_ != 0) {
            if (pending) std::memmove(buffer_.Data(), buffer_.Data() + head_, pending);
            head_ = 0;
            tail_ = pending;
        }
        if (buffer_.Capacity() - tail_ >= need) return true;
        if (need > SIZE_MAX - tail_) [[unlikely]] return false;

        size_t required = tail_ + need;
        if (pending >= 5) {
            // Длина известна из wire-заголовка: одно точное выделение вместо
            // последовательных удвоений и копирования уже прочитанного снимка.
            const size_t recordSize = size_t(detail::load<uint32_t>(buffer_.Data() + 1)) + 5;
            if (required < recordSize) required = recordSize;
        }
        return buffer_.Reserve(required, pending);
    }

    // Записи: [InfoType u8][size u32 LE][data size байт]. Прикладного лимита нет.
    void dispatchAvailable() {
        while (tail_ - head_ >= 5) {
            const uint8_t* rec = buffer_.Data() + head_;
            const uint32_t size = detail::load<uint32_t>(rec + 1);
            const size_t recordSize = size_t(size) + 5;
            if (tail_ - head_ < recordSize) break;

            const auto type = static_cast<InfoType>(rec[0]);
            // Успешная raw-пересылка полностью заменяет локальный разбор:
            // служба не хранит процессы и не запрашивает их пути за desktop.
            bool forwarded = false;
            // Raw Win32 message использует DWORD. Не усекаем длину при переводе:
            // запись за пределами этого API всё равно разбирается локально.
            if (onRawRecord && recordSize <= MAXDWORD)
                forwarded = onRawRecord(onRawRecordContext, rec, static_cast<uint32_t>(recordSize));
            if (!forwarded)
                dispatchOne(type, rec + 5, size);
            buffer_.RecordCompleted(recordSize);
            head_ += recordSize;
        }
        if (head_ == tail_) head_ = tail_ = 0;
        const size_t pending = tail_ - head_;
        size_t required = pending;
        if (pending >= 5)
            required = size_t(detail::load<uint32_t>(buffer_.Data() + head_ + 1)) + 5;
        if (buffer_.NeedsTrim(required)) [[unlikely]] {
            if (pending && head_) std::memmove(buffer_.Data(), buffer_.Data() + head_, pending);
            head_ = 0;
            tail_ = pending;
            buffer_.Trim(pending, required);
        }
    }

    template <class Value, class Cb>
    static void dispatchBandwidth(const uint8_t* data, uint32_t size, const Cb& cb) 
    {
        if (size < 5) [[unlikely]] return;
        const uint32_t count = detail::load<uint32_t>(data + 1);
        const size_t   need  = size_t(count) * sizeof(Value);
        if (need > size_t(size) - 5) [[unlikely]] return;   // ключевая проверка (было OOB)
        if (!cb) return;
        // alignof(Value) == 1 (packed) — приведение корректно, копий нет.
        cb(data[0], reinterpret_cast<const Value*>(data + 5), count);
    }

    // ------------------- служба драйвера -------------------
    static bool queryState(SC_HANDLE svc, DWORD& state) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<BYTE*>(&ssp),
                                  sizeof(ssp), &needed)) return false;
        state = ssp.dwCurrentState;
        return true;
    }

    // Опрос до дедлайна: промежуточные состояния не считаются провалом.
    static bool waitForState(SC_HANDLE svc, DWORD desired, DWORD timeoutMs) {
        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        for (;;) {
            DWORD state = 0;
            if (!queryState(svc, state)) return false;
            if (state == desired) return true;
            if (GetTickCount64() >= deadline) return false;
            Sleep(50);
        }
    }

    static bool exeDirectory(std::wstring& dir) {
        std::wstring path(MAX_PATH, L'\0');
        for (;;) {
            const DWORD n = GetModuleFileNameW(nullptr, path.data(),
                                               static_cast<DWORD>(path.size()));
            if (n == 0) return false;
            if (n < path.size()) { path.resize(n); break; }
            if (path.size() >= 32768) return false;
            path.resize(path.size() * 2);      // путь был усечён
        }
        const size_t slash = path.find_last_of(L'\\');
        if (slash == std::wstring::npos) return false;
        dir.assign(path, 0, slash + 1);
        return true;
    }

    bool driverPath(const wchar_t* fileName, std::wstring& out) {
        if (!exeDirectory(out)) {
            lastError_.store(ERROR_BAD_PATHNAME); return false;
        }
        out += fileName;
        if (GetFileAttributesW(out.c_str()) == INVALID_FILE_ATTRIBUTES) {
            lastError_.store(ERROR_FILE_NOT_FOUND); return false;
        }
        return true;
    }

    bool ensureServiceRunning() {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE| SC_MANAGER_MODIFY_BOOT_CONFIG);
        if (!scm) { lastError_.store(GetLastError()); return false; }

        constexpr DWORD kAccess = SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS;
        SC_HANDLE svc = OpenServiceW(scm, serviceName, kAccess);
        if (!svc) {
            const DWORD err = GetLastError();
            if (err != ERROR_SERVICE_DOES_NOT_EXIST || !true) {
                lastError_.store(err);
                CloseServiceHandle(scm);
                return false;
            }
            std::wstring path;
            if (!driverPath(driverFile, path)) {
                CloseServiceHandle(scm);
                return false;
            }
            svc = CreateServiceW(scm, serviceName, serviceName, kAccess,
                                 SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                 SERVICE_ERROR_NORMAL, path.c_str(),
                                 nullptr, nullptr, nullptr, nullptr, nullptr);
            if (!svc) {
                const DWORD cerr = GetLastError();
                if (cerr == ERROR_SERVICE_EXISTS)     // гонка с другим процессом
                    svc = OpenServiceW(scm, serviceName, kAccess);
                if (!svc) {
                    lastError_.store(cerr);
                    CloseServiceHandle(scm);
                    return false;
                }
            }
			const std::wstring parameters_path =
				L"SYSTEM\\CurrentControlSet\\Services\\" + std::wstring(serviceName) + L"\\Parameters";
			HKEY parameters = nullptr;
			LSTATUS registry_status = RegCreateKeyExW(
				HKEY_LOCAL_MACHINE, parameters_path.c_str(), 0, nullptr,
				REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &parameters, nullptr);
			if (registry_status != ERROR_SUCCESS) {
				lastError_.store(GetLastError());
				CloseServiceHandle(scm);
				return false;
			}
			const DWORD ignore_special_ports = 1;
			registry_status = RegSetValueExW(
				parameters, L"IgnoreSpecialPorts", 0, REG_DWORD,
				reinterpret_cast<const BYTE*>(&ignore_special_ports), sizeof(ignore_special_ports));
			RegCloseKey(parameters);
			if (registry_status != ERROR_SUCCESS) {
				lastError_.store(GetLastError());
				CloseServiceHandle(scm);
				return false;
			}
        }


        // Настройка читается драйвером при загрузке. Общая точка запуска
        // применяет её и для службы, и для прямого оконного подключения.
        const DWORD optionStatus = TrafficAttributionOptions::ApplySaved();
        if (optionStatus != ERROR_SUCCESS) {
            lastError_.store(optionStatus);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }

        // Помечаем владение до старта: служба уже существует (создали её мы или
        // нашли готовой), и если StartService провалится на полпути, снять её
        // всё равно нужно.
        serviceOwned_ = true;

        const bool ok = startServiceAndWait(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok;
    }

    bool startServiceAndWait(SC_HANDLE svc) {
        DWORD state = 0;
        if (queryState(svc, state) && state == SERVICE_RUNNING) {
            SERVICE_STATUS st{};
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            waitForState(svc, SERVICE_STOPPED, serviceTimeoutMs);
        }
        if (!StartServiceW(svc, 0, nullptr)) {
            const DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                lastError_.store(err);   // ERROR_SERVICE_MARKED_FOR_DELETE и т.п.
                return false;
            }
        }
        if (!waitForState(svc, SERVICE_RUNNING, serviceTimeoutMs)) {
            lastError_.store(ERROR_SERVICE_REQUEST_TIMEOUT);
            return false;
        }
        return true;
    }
};

} // namespace pmkext