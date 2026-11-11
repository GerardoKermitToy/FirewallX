#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct TransportState {
    std::vector<uint8_t> payload;
    DWORD error = ERROR_SUCCESS;
    DWORD transferred = 0;
    unsigned ioctls = 0;
    unsigned writes = 0;
    bool pending = false;
} transport;

unsigned appIdQueries = 0;

DWORD WINAPI MockGetAppIdFromFileName(PCWSTR path, FWP_BYTE_BLOB** appId) {
    ++appIdQueries;
    return FwpmGetAppIdFromFileName0(path, appId);
}

struct TempAppFile {
    std::wstring path;

    TempAppFile() {
        wchar_t directory[MAX_PATH]{};
        wchar_t temporary[MAX_PATH]{};
        const DWORD length = GetTempPathW(MAX_PATH, directory);
        Check(length != 0 && length < MAX_PATH &&
              GetTempFileNameW(directory, L"kif", 0, temporary) != 0,
              "cannot create a temporary application path");
        path = temporary;
        const std::wstring unicodePath = path + L"_Тест_应用_é_🚀.exe";
        if (!MoveFileW(path.c_str(), unicodePath.c_str())) {
            DeleteFileW(path.c_str());
            throw std::runtime_error("cannot create a Unicode application path");
        }
        path = unicodePath;
    }

    ~TempAppFile() { DeleteFileW(path.c_str()); }
};

// Реальное устройство не открывается: перехватываются только операции клиента.
BOOL MockDeviceIoControl(HANDLE, DWORD code, LPVOID input, DWORD inputSize,
                         LPVOID output, DWORD outputSize, LPDWORD,
                         LPOVERLAPPED overlapped) {
    if (code != 0x9c40e004) {
        Check(code == 0x9c40e010 && input && inputSize >= 12 &&
              !output && outputSize == 0 && overlapped && overlapped->hEvent,
              "invalid application-interface IOCTL");
        ++transport.ioctls;
        const auto* bytes = static_cast<const uint8_t*>(input);
        transport.payload.assign(bytes, bytes + inputSize);
    }
    if (transport.error != ERROR_SUCCESS) {
        SetLastError(transport.error);
        return FALSE;
    }
    transport.transferred = 0;
    if (transport.pending) { SetLastError(ERROR_IO_PENDING); return FALSE; }
    return TRUE;
}

BOOL MockWriteFile(HANDLE, LPCVOID data, DWORD size, LPDWORD,
                    LPOVERLAPPED overlapped) {
    Check(data && size >= 13 && overlapped && overlapped->hEvent,
          "invalid application-interface write");
    ++transport.writes;
    const auto* bytes = static_cast<const uint8_t*>(data);
    transport.payload.assign(bytes, bytes + size);
    if (transport.error != ERROR_SUCCESS) {
        SetLastError(transport.error);
        return FALSE;
    }
    transport.transferred = size;
    if (transport.pending) { SetLastError(ERROR_IO_PENDING); return FALSE; }
    return TRUE;
}

BOOL MockGetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD transferred, BOOL wait) {
    Check(wait == TRUE, "operation must finish before its buffers are released");
    *transferred = transport.transferred;
    return TRUE;
}

} // namespace

#define DeviceIoControl MockDeviceIoControl
#define WriteFile MockWriteFile
#define GetOverlappedResult MockGetOverlappedResult
#define FwpmGetAppIdFromFileName0 MockGetAppIdFromFileName
#include "PortmasterKextClient.hpp"
#undef DeviceIoControl
#undef WriteFile
#undef GetOverlappedResult
#undef FwpmGetAppIdFromFileName0

namespace FirewallX {
Mode g_runMode = Mode::Desktop;
}

namespace pmkext {
struct KextClientTestAccess {
    static void Attach(KextClient& client, HANDLE device) { client.hDevice_ = device; }
};
}

namespace {

void TestAppInterface() {
    static_assert(static_cast<uint8_t>(pmkext::CommandType::SetAppInterface) == 10);
    static_assert(pmkext::IOCTL_SET_APP_INTERFACE == 0x9c40e010);
    pmkext::KextClient client;
    Check(!client.setAppInterface(L"C:\\app.exe", 1) &&
          client.lastError() == ERROR_INVALID_HANDLE, "closed device accepted a policy");

    TempAppFile file;
    appIdQueries = 0;

    FWP_BYTE_BLOB* appId = nullptr;
    Check(FwpmGetAppIdFromFileName0(file.path.c_str(), &appId) == ERROR_SUCCESS && appId,
          "cannot resolve canonical WFP application identity");
    struct AppIdGuard {
        FWP_BYTE_BLOB* value;
        ~AppIdGuard() { FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
    } guard{appId};

    HANDLE device = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(device != nullptr, "cannot create a mock device handle");
    pmkext::KextClientTestAccess::Attach(client, device);
    constexpr uint64_t luid = 0xfedcba9876543210ull;
    std::vector<uint8_t> expected;
    for (unsigned i = 0; i < 8; ++i)
        expected.push_back(static_cast<uint8_t>(luid >> (i * 8)));
    for (unsigned i = 0; i < 4; ++i)
        expected.push_back(static_cast<uint8_t>(appId->size >> (i * 8)));
    expected.insert(expected.end(), appId->data, appId->data + appId->size);

    for (bool pending : {false, true}) {
        transport = {};
        transport.pending = pending;
        Check(client.setAppInterface(file.path, luid) && transport.ioctls == 1 &&
              transport.writes == 0 && transport.payload == expected,
              "IOCTL must carry the full LUID and canonical UTF-16 app ID");
        Check(client.setAppInterface(file.path, luid, true) && transport.writes == 1 &&
              transport.payload.front() == 10 &&
              std::vector<uint8_t>(transport.payload.begin() + 1,
                                   transport.payload.end()) == expected,
              "write must carry command 10 followed by the same payload");
    }

    Check(appIdQueries == 1, "repeated policies must reuse the canonical application ID");
    transport = {};
    Check(client.setAppInterface(file.path, 0), "zero LUID must remove a policy");
    for (size_t i = 0; i < 8; ++i)
        Check(transport.payload[i] == 0, "removal must encode a zero LUID");
    Check(transport.ioctls == 1 && appIdQueries == 1,
          "removal must reach the driver without resolving the application ID again");
    Check(!client.setAppInterface(L"", 1) &&
          client.lastError() == ERROR_INVALID_PARAMETER, "empty path accepted");
    Check(!client.setAppInterface(std::wstring(L"C:\\app\0hidden.exe", 17), 1) &&
          client.lastError() == ERROR_INVALID_PARAMETER && transport.ioctls == 1,
          "embedded NUL must fail before driver I/O");
    Check(!client.deviceIoctl(pmkext::IOCTL_SET_APP_INTERFACE, nullptr, 0, nullptr,
                              nullptr, 1) && client.lastError() == ERROR_INVALID_PARAMETER,
          "null IOCTL input accepted with nonzero size");
    for (bool viaWrite : {false, true}) {
        transport.error = ERROR_ACCESS_DENIED;
        Check(!client.setAppInterface(file.path, luid, viaWrite) &&
              client.lastError() == ERROR_ACCESS_DENIED,
              "driver errors must propagate through lastError");
    }
    transport = {};
    client.close();
}

void TestAppInterfaceAfterDelete() {
    for (unsigned mode = 0; mode < 3; ++mode) {
        for (bool failInitial : {false, true}) {
            TempAppFile file;
            pmkext::KextClient client;
            if (mode != 2) {
                HANDLE device = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                Check(device != nullptr, "cannot create a mock device handle");
                pmkext::KextClientTestAccess::Attach(client, device);
            }
            const uint8_t* cachedCommand = nullptr;
            const auto send = [&](const std::wstring& path, uint64_t luid) {
                if (mode != 2) return client.setAppInterface(path, luid, mode == 1);
                return client.setAppInterfaceWithSender(path, luid,
                    [&](const uint8_t* command, size_t size) -> DWORD {
                        Check(command && size >= 13 && command[0] == 10,
                              "raw sender must receive the complete driver command");
                        Check(!cachedCommand || cachedCommand == command,
                              "cached raw command must not be copied or reallocated");
                        cachedCommand = command;
                        ++transport.writes;
                        transport.payload.assign(command, command + size);
                        return transport.error;
                    });
            };
            const auto wireCommand = [&] {
                auto bytes = transport.payload;
                if (mode == 0) bytes.insert(bytes.begin(), 10);
                return bytes;
            };
            const unsigned queries = appIdQueries;
            transport = {};
            transport.error = failInitial ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
            constexpr uint64_t firstLuid = 0xfedcba9876543210ull;
            Check(send(file.path, firstLuid) == !failInitial && appIdQueries == queries + 1,
                  "initial application identity must be resolved exactly once");
            auto expected = wireCommand();
            Check(expected.size() > 13, "initial command must contain the canonical app ID");
            Check(DeleteFileW(file.path.c_str()) != FALSE, "cannot delete the application file");
            FWP_BYTE_BLOB* missingId = nullptr;
            const DWORD missingError = FwpmGetAppIdFromFileName0(file.path.c_str(), &missingId);
            if (missingId) FwpmFreeMemory0(reinterpret_cast<void**>(&missingId));
            Check(missingError == ERROR_FILE_NOT_FOUND,
                  "native WFP lookup must fail after the application file is deleted");

            const std::wstring upperPath = FoldCaseCopy(file.path);
            constexpr uint64_t nextLuid = 0x0123456789abcdefull;
            for (unsigned i = 0; i < 8; ++i)
                expected[1 + i] = static_cast<uint8_t>(nextLuid >> (i * 8));
            transport = {};
            Check(send(upperPath, nextLuid) && wireCommand() == expected &&
                  appIdQueries == queries + 1,
                  "LUID changes must reuse the app ID after deletion regardless of path case");

            for (size_t i = 1; i <= 8; ++i) expected[i] = 0;
            transport.error = ERROR_ACCESS_DENIED;
            Check(!send(file.path, 0) && client.lastError() == ERROR_ACCESS_DENIED &&
                  wireCommand() == expected && appIdQueries == queries + 1,
                  "failed policy removal must keep the cached application identity");
            transport.error = ERROR_SUCCESS;
            Check(send(upperPath, 0) && wireCommand() == expected &&
                  appIdQueries == queries + 1,
                  "policy removal retry must succeed without the application file");

            const unsigned sent = transport.ioctls + transport.writes;
            Check(!send(file.path, nextLuid) && client.lastError() == ERROR_FILE_NOT_FOUND &&
                  appIdQueries == queries + 2 && sent == transport.ioctls + transport.writes,
                  "successful removal must release the cached command");
            client.close();
        }
    }
}

void TestAppInterfaceCacheLifetime() {
    TempAppFile first;
    TempAppFile second;
    pmkext::KextClient client;
    unsigned sent = 0;
    const auto sender = [&](const uint8_t*, size_t) -> DWORD {
        ++sent;
        return ERROR_SUCCESS;
    };
    const unsigned queries = appIdQueries;
    Check(client.setAppInterfaceWithSender(first.path, 1, sender) &&
          client.setAppInterfaceWithSender(second.path, 2, sender) &&
          appIdQueries == queries + 2,
          "different executable paths must have independent cached identities");
    Check(DeleteFileW(first.path.c_str()) && DeleteFileW(second.path.c_str()),
          "cannot delete application files for the cache lifetime test");
    Check(client.setAppInterfaceWithSender(first.path, 0, sender) &&
          client.setAppInterfaceWithSender(second.path, 3, sender) &&
          appIdQueries == queries + 2,
          "removing one policy must preserve another application's identity");
    client.close();
    Check(!client.setAppInterfaceWithSender(second.path, 0, sender) &&
          client.lastError() == ERROR_FILE_NOT_FOUND && appIdQueries == queries + 3 && sent == 4,
          "closing a client must release cached application identities");
}

struct RouteState {
    std::array<BYTE, 2> enabled{0, 0};
    std::array<DWORD, 2> status{ERROR_SUCCESS, ERROR_SUCCESS};
    std::array<bool, 2> populate{true, true};
    std::array<unsigned, 2> queries{};
    std::array<DWORD, 2> exitCodes{};
    UINT directoryLength = 19;
    DWORD error = ERROR_ACCESS_DENIED;
    DWORD waitResult = WAIT_OBJECT_0;
    bool createOk = true;
    bool exitOk = true;
    unsigned directories = 0;
    unsigned creates = 0;
    unsigned commandMask = 0;
    unsigned closes = 0;
    unsigned terminated = 0;
} route;

DWORD WINAPI Query(DWORD store, const NPI_MODULEID* module, DWORD table,
                    const void* key, DWORD keySize, void* rw, DWORD rwSize,
                    void* ro, DWORD roSize, void* dynamic, DWORD dynamicSize) {
    Check(store == 1 && table == 6 && module && module->Length == sizeof(*module) &&
          module->Type == MIT_GUID && !key && keySize == 0 && rw && rwSize == 0x9c &&
          !ro && roSize == 0 && !dynamic && dynamicSize == 0,
          "invalid read-only active NSI request");
    const bool ipv6 = module->Guid.Data1 == 0xeb004a01;
    const GUID expected{ipv6 ? 0xeb004a01u : 0xeb004a00u, 0x9b1a, 0x11d4,
                        {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc}};
    Check(std::memcmp(&module->Guid, &expected, sizeof(expected)) == 0,
          "wrong NSI family module");
    ++route.queries[ipv6];
    if (route.populate[ipv6]) static_cast<BYTE*>(rw)[0x98] = route.enabled[ipv6];
    return route.status[ipv6];
}

UINT WINAPI SystemDirectory(LPWSTR path, UINT size) {
    ++route.directories;
    Check(size == MAX_PATH, "unexpected system directory buffer");
    if (route.directoryLength == 19) {
        constexpr wchar_t directory[] = L"C:\\Windows\\System32";
        std::memcpy(path, directory, sizeof(directory));
    }
    return route.directoryLength;
}

BOOL WINAPI CreateProcess(LPCWSTR executable, LPWSTR command, LPSECURITY_ATTRIBUTES processSA,
                          LPSECURITY_ATTRIBUTES threadSA, BOOL inherit, DWORD flags,
                          LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
                          LPPROCESS_INFORMATION process) {
    ++route.creates;
    const std::wstring commandLine(command);
    const bool ipv6 = commandLine.find(L" interface ipv6 ") != std::wstring::npos;
    Check(std::wstring(executable) == L"C:\\Windows\\System32\\netsh.exe" &&
          commandLine == L"\"C:\\Windows\\System32\\netsh.exe\" interface " +
              std::wstring(ipv6 ? L"ipv6" : L"ipv4") +
              L" set global routepolicies=enabled store=active",
          "wrong system netsh command");
    Check(!processSA && !threadSA && inherit == FALSE && flags == CREATE_NO_WINDOW &&
          !environment && !directory && startup->cb == sizeof(*startup) &&
          startup->dwFlags == STARTF_USESTDHANDLES && !startup->hStdInput &&
          !startup->hStdOutput && !startup->hStdError,
          "netsh must not inherit handles or show a window");
    route.commandMask |= ipv6 ? 2u : 1u;
    if (!route.createOk) return FALSE;
    process->hProcess = reinterpret_cast<HANDLE>(uintptr_t{2} + ipv6);
    process->hThread = reinterpret_cast<HANDLE>(uintptr_t{4} + ipv6);
    return TRUE;
}

DWORD WINAPI Wait(HANDLE, DWORD timeout) {
    Check(timeout == 10'000 || (timeout == 1'000 && route.terminated != 0),
          "netsh waits must be bounded");
    return timeout == 1'000 ? WAIT_OBJECT_0 : route.waitResult;
}
BOOL WINAPI ExitCode(HANDLE process, LPDWORD code) {
    *code = route.exitCodes[reinterpret_cast<uintptr_t>(process) - 2];
    return route.exitOk;
}
BOOL WINAPI Terminate(HANDLE, UINT code) {
    Check(code == (route.waitResult == WAIT_TIMEOUT ? ERROR_TIMEOUT : route.error),
          "wrong netsh termination code");
    ++route.terminated;
    return TRUE;
}
BOOL WINAPI Close(HANDLE) { ++route.closes; return TRUE; }
DWORD WINAPI LastError() { return route.error; }

pmkext::detail::RoutePolicyOperations Operations() {
    return {Query, SystemDirectory, CreateProcess, Wait, ExitCode, Terminate, Close, LastError};
}
DWORD Enable() { return pmkext::detail::enableRoutePolicies(Operations()); }

void TestRoutePolicies() {
    // Реальный импорт проверяется только чтением: netsh здесь не вызывается.
    const pmkext::detail::RoutePolicyOperations native{};
    (void)pmkext::detail::routePoliciesEnabled(native, false);
    (void)pmkext::detail::routePoliciesEnabled(native, true);

    route = {};
    route.enabled = {1, 1};
    Check(Enable() == ERROR_SUCCESS && route.queries == std::array<unsigned, 2>{1, 1} &&
          route.creates == 0 && route.directories == 0,
          "confirmed enabled families must never look up or launch netsh");
    route = {};
    Check(Enable() == ERROR_SUCCESS && route.creates == 2 && route.commandMask == 3 &&
          route.closes == 4, "disabled families must each use netsh and release handles");
    for (size_t family = 0; family < 2; ++family) {
        for (BYTE value : {BYTE{0}, BYTE{2}, BYTE{0xff}}) {
            route = {};
            route.enabled = {1, 1};
            route.enabled[family] = value;
            Check(Enable() == ERROR_SUCCESS && route.creates == 1 &&
                  route.commandMask == (1u << family), "unconfirmed family fallback is wrong");
        }
        for (DWORD error : {DWORD{ERROR_ACCESS_DENIED}, DWORD{ERROR_NOT_SUPPORTED},
                            DWORD{ERROR_INVALID_PARAMETER}}) {
            route = {};
            route.enabled = {1, 1};
            route.status[family] = error;
            Check(Enable() == ERROR_SUCCESS && route.creates == 1 &&
                  route.commandMask == (1u << family), "NSI query failure must use fallback");
        }
        route = {};
        route.enabled = {1, 1};
        route.populate[family] = false;
        Check(Enable() == ERROR_SUCCESS && route.commandMask == (1u << family),
              "unpopulated successful NSI query must not confirm enabled state");
    }
    route = {};
    auto operations = Operations();
    operations.query = nullptr;
    Check(pmkext::detail::enableRoutePolicies(operations) == ERROR_SUCCESS &&
          route.commandMask == 3, "missing query must fall back for both families");

    route = {};
    route.directoryLength = 0;
    Check(Enable() == ERROR_ACCESS_DENIED && route.creates == 0,
          "system-directory errors must propagate");
    route = {};
    route.directoryLength = MAX_PATH;
    Check(Enable() == ERROR_INSUFFICIENT_BUFFER && route.creates == 0,
          "truncated system directory must not launch netsh");
    route = {};
    route.createOk = false;
    Check(Enable() == ERROR_ACCESS_DENIED && route.closes == 0,
          "process creation errors must propagate");
    for (DWORD wait : {DWORD{WAIT_TIMEOUT}, DWORD{WAIT_FAILED}}) {
        route = {};
        route.waitResult = wait;
        const DWORD expected = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_ACCESS_DENIED;
        Check(Enable() == expected &&
              route.terminated == 1 && route.closes == 2,
              "wait errors must terminate netsh and close both handles");
    }
    route = {};
    route.exitOk = false;
    Check(Enable() == ERROR_ACCESS_DENIED && route.closes == 2,
          "exit-code query errors must propagate");
    for (size_t family = 0; family < 2; ++family) {
        route = {};
        route.exitCodes[family] = 7;
        Check(Enable() == 7 && route.creates == family + 1 &&
              route.closes == 2 * route.creates,
              "nonzero netsh exit must stop configuration without leaking handles");
    }
}

} // namespace

int main() {
    try {
        TestAppInterface();
        TestAppInterfaceAfterDelete();
        TestAppInterfaceCacheLifetime();
        TestRoutePolicies();
        std::cout << "PASS: application-interface API and read-only NSI/netsh fallback\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
