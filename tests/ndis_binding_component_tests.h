#pragma once
#include "NdisBindingPath.h"

namespace ndis_binding_tests {

// Эти COM-объекты живут на стеке; инспектор не сохраняет их за пределами вызова.
class Component final : public INetCfgComponent {
public:
    GUID instance{}, componentClass{};
    HRESULT instanceStatus = S_OK, classStatus = S_OK;
    unsigned classCalls = 0, nameCalls = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** out) override {
        if (out) *out = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 1; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetDisplayName(LPWSTR*) override { ++nameCalls; return E_POINTER; }
    HRESULT STDMETHODCALLTYPE SetDisplayName(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetHelpText(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetId(LPWSTR*) override { ++nameCalls; return E_POINTER; }
    HRESULT STDMETHODCALLTYPE GetCharacteristics(LPDWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetInstanceGuid(GUID* out) override {
        if (!out) return E_POINTER;
        *out = instance;
        return instanceStatus;
    }
    HRESULT STDMETHODCALLTYPE GetPnpDevNodeId(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetClassGuid(GUID* out) override {
        ++classCalls;
        if (!out) return E_POINTER;
        *out = componentClass;
        return classStatus;
    }
    HRESULT STDMETHODCALLTYPE GetBindName(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDeviceStatus(ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE OpenParamKey(HKEY*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RaisePropertyUi(HWND, DWORD, IUnknown*) override { return E_NOTIMPL; }
};

inline bool ComponentIdentityTests() {
    using namespace ndis_binding::detail;
    const GUID adapterId = {7, 8, 9, {1, 2, 3, 4, 5, 6, 7, 8}};
    Component adapter;
    adapter.instance = adapterId;
    adapter.componentClass = GUID_DEVCLASS_NET;
    adapter.classStatus = E_POINTER;
    if (AdapterGuid(&adapter, {adapterId}) != adapterId || adapter.classCalls || adapter.nameCalls) return false;
    const auto rejects = [](auto&& action) {
        try { action(); } catch (const Error&) { return true; }
        return false;
    };
    if (!rejects([&] { AdapterGuid(&adapter, {}); })) return false;
    adapter.classStatus = S_OK;
    if (AdapterGuid(&adapter, {}) != adapterId) return false;
    adapter.componentClass = GUID_DEVCLASS_NETSERVICE;
    if (AdapterGuid(&adapter, {}) != GUID_NULL) return false;
    adapter.classStatus = S_FALSE;
    if (!rejects([&] { AdapterGuid(&adapter, {}); })) return false;
    adapter.instanceStatus = E_POINTER;
    if (!rejects([&] { AdapterGuid(&adapter, {adapterId}); })) return false;
    adapter.instanceStatus = S_OK;
    adapter.instance = GUID_NULL;
    if (!rejects([&] { AdapterGuid(&adapter, {}); })) return false;
    return rejects([&] { AdapterGuid(nullptr, {}); });
}

} // namespace ndis_binding_tests
