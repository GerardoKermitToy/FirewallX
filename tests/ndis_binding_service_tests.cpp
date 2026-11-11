// Все вызовы SCM подменены: реальные службы, драйвер и сеть не используются.
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <vector>

namespace scm_test {

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct State {
    DWORD managerError = ERROR_SUCCESS, serviceError = ERROR_SUCCESS;
    std::vector<std::string> calls;
} state;

int managerToken = 0, serviceToken = 0;
SC_HANDLE Manager() { return reinterpret_cast<SC_HANDLE>(&managerToken); }
SC_HANDLE Service() { return reinterpret_cast<SC_HANDLE>(&serviceToken); }

SC_HANDLE OpenManager(LPCWSTR machine, LPCWSTR database, DWORD access) {
    state.calls.emplace_back("manager");
    Check(!machine && !database && access == SC_MANAGER_CONNECT, "SCM must be local and read-only");
    if (state.managerError) { SetLastError(state.managerError); return nullptr; }
    return Manager();
}

SC_HANDLE OpenDriver(SC_HANDLE manager, LPCWSTR name, DWORD access) {
    state.calls.emplace_back("service");
    Check(manager == Manager() && name && std::wcscmp(name, L"FirewallXNdisFilter") == 0 &&
          access == SERVICE_QUERY_STATUS, "only the exact driver service may be opened read-only");
    if (state.serviceError) { SetLastError(state.serviceError); return nullptr; }
    return Service();
}

BOOL CloseService(SC_HANDLE handle) {
    Check(handle == Manager() || handle == Service(), "unexpected SCM handle closed");
    state.calls.emplace_back(handle == Service() ? "close-service" : "close-manager");
    SetLastError(ERROR_INVALID_PARAMETER);
    return TRUE;
}

} // namespace scm_test

#define OpenSCManagerW scm_test::OpenManager
#define OpenServiceW scm_test::OpenDriver
#define CloseServiceHandle scm_test::CloseService
#include "NdisBinding.h"
#undef OpenSCManagerW
#undef OpenServiceW
#undef CloseServiceHandle

int main() {
    try {
        using namespace scm_test;
        Check(ndis_binding::detail::RequireDriverService() == S_OK, "installed service was rejected");
        Check(state.calls == std::vector<std::string>{"manager", "service", "close-service", "close-manager"},
              "service existence check made extra calls or leaked handles");
        for (const DWORD error : {ERROR_SERVICE_DOES_NOT_EXIST, ERROR_ACCESS_DENIED, ERROR_SERVICE_MARKED_FOR_DELETE}) {
            state = {};
            state.serviceError = error;
            Check(ndis_binding::detail::RequireDriverService() == HRESULT_FROM_WIN32(error),
                  "service absence or SCM error was not preserved");
            Check(state.calls == std::vector<std::string>{"manager", "service", "close-manager"},
                  "failed service open must close only the SCM handle");
        }
        state = {};
        state.managerError = ERROR_ACCESS_DENIED;
        Check(ndis_binding::detail::RequireDriverService() == E_ACCESSDENIED, "SCM access failure was hidden");
        Check(state.calls == std::vector<std::string>{"manager"}, "failed SCM open used a null handle");
        std::puts("PASS: 5 read-only service-existence, absence, error and handle-lifetime cases; no status polling, fake SCM only.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
