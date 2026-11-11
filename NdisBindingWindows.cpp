#include "NdisBindingPath.h"
#include "NdisBindingAsync.h"
#include "NdisBindingProcess.h"
#include <netcfgn.h>
#include <array>
#include <new>
#include <utility>

namespace ndis_binding {
namespace {
using namespace detail;

struct RegistryKey {
    HKEY value = nullptr;
    explicit RegistryKey(REGSAM access) {
        CheckWin32(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kConfigKey, 0, access | KEY_WOW64_64KEY, &value));
    }
    ~RegistryKey() { if (value) RegCloseKey(value); }
};

struct ComSession {
    ComSession() {
        Check(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
        const auto hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            CoUninitialize();
            Check(hr);
        }
    }
    ~ComSession() { CoUninitialize(); }
};

struct Path {
    Binding binding;
    ComPtr<INetCfgBindingPath> path;
};

class WindowsSystem final : public System {
    ComSession com_;
    const std::atomic<bool>& stopped_;
    ComPtr<INetCfg> config_;
    ComPtr<INetCfgLock> lock_;
    bool locked_ = false, initialized_ = false;

    ComPtr<INetCfgComponent> Component() {
        ComPtr<INetCfgComponent> component;
        const auto hr = config_->FindComponent(kComponentId, &component);
        Check(hr);
        if (hr != S_OK || !component) throw Error{ HRESULT_FROM_WIN32(ERROR_SERVICE_DOES_NOT_EXIST) };
        GUID instance{}, componentClass{};
        if (component->GetInstanceGuid(&instance) != S_OK ||
            component->GetClassGuid(&componentClass) != S_OK ||
            instance != kFilterId || componentClass != GUID_DEVCLASS_NETSERVICE) throw Error{ E_UNEXPECTED };
        return component;
    }

    std::vector<Path> Paths() {
        auto component = Component();
        ComPtr<INetCfgComponentBindings> bindings;
        Check(component.As(&bindings));
        ComPtr<IEnumNetCfgBindingPath> enumerator;
        if (bindings->EnumBindingPaths(EBP_BELOW, &enumerator) != S_OK || !enumerator) throw Error{ E_UNEXPECTED };
        const auto adapters = ReadAdapterInventory(config_.Get());
        std::vector<Path> paths;
        for (;;) {
            Path entry;
            ULONG fetched = 0;
            const auto hr = enumerator->Next(1, &entry.path, &fetched);
            if (hr == S_FALSE && fetched == 0 && !entry.path) break;
            Check(hr);
            if (hr != S_OK || fetched != 1 || !entry.path) throw Error{ E_UNEXPECTED };
            const auto enabled = entry.path->IsEnabled();
            if (enabled != S_OK && enabled != S_FALSE) { Check(enabled); throw Error{ E_UNEXPECTED }; }
            entry.binding = { InspectPath(entry.path.Get(), adapters), enabled == S_OK };
            paths.push_back(std::move(entry));
        }
        return paths;
    }

    void WriteFlag(const wchar_t* name, DWORD value) {
        RegistryKey key(KEY_QUERY_VALUE | KEY_SET_VALUE);
        CheckWin32(RegSetValueExW(key.value, name, 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value)));
        CheckWin32(RegFlushKey(key.value));
    }

public:
    explicit WindowsSystem(const std::atomic<bool>& stopped) : stopped_(stopped) {}
    ~WindowsSystem() override {
        if (initialized_) { config_->Cancel(); config_->Uninitialize(); }
        if (locked_) lock_->ReleaseWriteLock();
    }
    bool Stopped() const override { return stopped_.load(); }
    void OpenNetwork() override {
        Check(CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&config_)));
        const auto hr = config_->Initialize(nullptr);
        Check(hr);
        if (hr != S_OK) throw Error{ E_UNEXPECTED };
        initialized_ = true;
    }
    void LockNetwork() override {
        Check(CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&config_)));
        Check(config_.As(&lock_));
        const auto started = GetTickCount64();
        for (;;) {
            if (Stopped()) throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
            LPWSTR holder = nullptr;
            const auto hr = lock_->AcquireWriteLock(250, L"FirewallX FirewallXNdisFilter", &holder);
            CoTaskMemFree(holder);
            if (hr == S_OK) { locked_ = true; break; }
            Check(hr);
            if (hr != S_FALSE) throw Error{ E_UNEXPECTED };
            if (GetTickCount64() - started >= 5000) throw Error{ HRESULT_FROM_WIN32(ERROR_TIMEOUT) };
        }
        const auto hr = config_->Initialize(nullptr);
        Check(hr);
        if (hr != S_OK) throw Error{ E_UNEXPECTED };
        initialized_ = true;
    }
    void RequireInstalled() override { Component(); }
    Targets ResolveTargets() override {
        const auto paths = Paths();
        std::vector<std::wstring> excluded;
        Check(ReadExcludedInterfaces(excluded));
        std::vector<Binding> bindings;
        Targets adapters;
        for (const auto& entry : paths) {
            if (Stopped()) throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
            bindings.push_back(entry.binding);
            const auto& guid = entry.binding.adapter;
            if (std::any_of(adapters.begin(), adapters.end(), [&](const Adapter& adapter) {
                    return adapter.guid == guid;
                })) continue;
            NET_LUID luid{};
            GUID roundTrip{};
            CheckWin32(ConvertInterfaceGuidToLuid(&guid, &luid));
            CheckWin32(ConvertInterfaceLuidToGuid(&luid, &roundTrip));
            if (!luid.Value || roundTrip != guid) throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
            MIB_IF_ROW2 row{};
            row.InterfaceLuid = luid;
            CheckWin32(GetIfEntry2(&row));
            if (row.InterfaceGuid != guid || row.InterfaceLuid.Value != luid.Value) {
                throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
            }
            adapters.push_back({guid, luid.Value, row.AdminStatus == NET_IF_ADMIN_STATUS_UP, false, row.Alias});
        }
        auto targets = SelectBindingTargets(bindings, adapters);
        MarkExcludedByName(targets, excluded);
        return targets;
    }
    Configuration ReadConfiguration() override {
        RegistryKey key(KEY_QUERY_VALUE);
        return detail::ReadConfiguration([](void* context, const wchar_t* name, DWORD flags,
                                            void* data, DWORD* size) -> LSTATUS {
            return RegGetValueW(static_cast<HKEY>(context), nullptr, name, flags, nullptr, data, size);
        }, key.value);
    }
    std::vector<Binding> ReadBindings() override {
        std::vector<Binding> bindings;
        for (const auto& entry : Paths()) bindings.push_back(entry.binding);
        return bindings;
    }
    void SetRecoveryAllowed(bool allowed) override { WriteFlag(L"AutoRepairAllowed", allowed ? 1u : 0u); }
    void Disarm() override { WriteFlag(L"AllowBindings", 0); }
    void Arm() override { WriteFlag(L"AllowBindings", 1); }
    void SetBinding(const Adapter& adapter, bool enabled) override {
        auto paths = Paths();
        unsigned targets = 0;
        bool changed = false, reboot = false;
        for (auto& entry : paths) {
            if (entry.binding.adapter != adapter.guid) continue;
            ++targets;
            if (entry.binding.enabled == enabled) continue;
            if (Stopped()) throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
            NET_LUID current{};
            GUID roundTrip{};
            if (ConvertInterfaceGuidToLuid(&adapter.guid, &current) != NO_ERROR ||
                current.Value != adapter.luid || ConvertInterfaceLuidToGuid(&current, &roundTrip) != NO_ERROR ||
                roundTrip != adapter.guid) throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
            const auto hr = entry.path->Enable(enabled ? TRUE : FALSE);
            Check(hr);
            if (hr != S_OK && hr != NETCFG_S_REBOOT) throw Error{ E_UNEXPECTED };
            changed = true;
            reboot = reboot || hr == NETCFG_S_REBOOT;
        }
        if (!targets) throw Error{ HRESULT_FROM_WIN32(ERROR_NOT_FOUND) };
        paths.clear();
        if (!changed) return;
        const auto hr = config_->Apply();
        Check(hr);
        if (hr != S_OK && hr != NETCFG_S_REBOOT) throw Error{ E_UNEXPECTED };
        if (reboot || hr == NETCFG_S_REBOOT) throw Error{ HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED) };
        Check(config_->Uninitialize());
        initialized_ = false;
        Check(config_->Initialize(nullptr));
        initialized_ = true;
    }
};
} // namespace

detail::Inspection detail::InspectWindows(const std::atomic<bool>& stopped, std::span<const AttachedAdapter> attached) {
    WindowsSystem system(stopped);
    return Inspect(system, attached);
}

detail::Targets detail::FindWindowsMissing(const std::atomic<bool>& stopped, std::span<const AttachedAdapter> attached) {
    static TargetResolver resolver;
    std::vector<AttachedAdapter> snapshot(attached.begin(), attached.end());
    return resolver.Resolve(stopped, [snapshot = std::move(snapshot)](const std::atomic<bool>& cancel) {
        WindowsSystem system(cancel);
        return FindMissing(system, snapshot);
    });
}

std::optional<detail::Adapter> detail::InspectWindowsAddition(const std::atomic<bool>& stopped, uint64_t luid,
                                                            std::span<const AttachedAdapter> attached) {
    if (stopped.load()) throw Error{HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)};
    MIB_IF_ROW2 row{};
    row.InterfaceLuid.Value = luid;
    CheckWin32(GetIfEntry2(&row));
    // Совместимость определяет путь NetCfg, а не физический тип или имя интерфейса.
    WindowsSystem system(stopped);
    return InspectAddition(system, luid, attached);
}

HRESULT detail::AddTargetWindows(const std::atomic<bool>& stopped, uint64_t luid) {
    WindowsSystem system(stopped);
    return AddTarget(system, luid);
}

HRESULT detail::ApplyNamedTargetWindows(const std::atomic<bool>& stopped, std::wstring_view name) {
    WindowsSystem system(stopped);
    return ApplyNamedTarget(system, name);
}

HRESULT detail::PrepareWindows(const std::atomic<bool>& stopped, bool forceReattach, bool resumeLegacy) {
    if (resumeLegacy) Check(RequireDriverService());
    WindowsSystem system(stopped);
    return detail::Prepare(system, forceReattach, resumeLegacy);
}

} // namespace ndis_binding
