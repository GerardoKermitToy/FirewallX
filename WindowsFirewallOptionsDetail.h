#pragma once
#include <windows.h>
#include <netfw.h>

namespace WindowsFirewallOptions::Detail {

// Подмена методов политики позволяет проверить профили и ошибки API,
// не включая и не отключая настоящий брандмауэр Windows во время тестов.
struct PolicyApi {
    void* context;
    HRESULT (*getEnabled)(void*, NET_FW_PROFILE_TYPE2, VARIANT_BOOL*);
    HRESULT (*setEnabled)(void*, NET_FW_PROFILE_TYPE2, VARIANT_BOOL);
};

HRESULT GetEnabled(const PolicyApi& api, bool& enabled);
HRESULT SetEnabled(const PolicyApi& api, bool enabled);

} // namespace WindowsFirewallOptions::Detail
