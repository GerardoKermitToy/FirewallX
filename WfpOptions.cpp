#include "WfpOptions.h"
#include <fwpmu.h>

namespace WfpOptions {
namespace {

DWORD OpenEngine(HANDLE& engine) {
    engine = nullptr;
    return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr,
                           &engine);
}

void CloseEngine(HANDLE engine) {
    if (engine) FwpmEngineClose0(engine);
}

} // namespace

DWORD GetNetEvents(bool& enabled) {
    enabled = false;

    HANDLE engine = nullptr;
    DWORD status = OpenEngine(engine);
    if (status != ERROR_SUCCESS) return status;

    FWP_VALUE0* value = nullptr;
    status = FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS,
                                  &value);
    if (status == ERROR_SUCCESS) {
        if (!value || value->type != FWP_UINT32) {
            status = ERROR_INVALID_DATA;
        } else {
            enabled = value->uint32 != 0;
        }
    }

    if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value));
    CloseEngine(engine);
    return status;
}

DWORD SetNetEvents(bool enabled) {
    HANDLE engine = nullptr;
    DWORD status = OpenEngine(engine);
    if (status != ERROR_SUCCESS) return status;

    FWP_VALUE0 value{};
    value.type = FWP_UINT32;
    value.uint32 = enabled ? 1u : 0u;
    status = FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS,
                                  &value);

    CloseEngine(engine);
    return status;
}

} // namespace WfpOptions
