#pragma once
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <netcfgx.h>
#include <devguid.h>
#include <wrl/client.h>
#include <algorithm>
#include <memory>
#include "NdisBinding.h"

namespace ndis_binding::detail {
using Microsoft::WRL::ComPtr;

inline std::vector<GUID> ReadAdapterInventory(INetCfg* config) {
    ComPtr<IEnumNetCfgComponent> enumerator;
    if (config->EnumComponents(&GUID_DEVCLASS_NET, &enumerator) != S_OK || !enumerator) throw Error{ E_UNEXPECTED };
    std::vector<GUID> adapters;
    for (;;) {
        ComPtr<INetCfgComponent> component;
        ULONG fetched = 0;
        const auto hr = enumerator->Next(1, &component, &fetched);
        if (hr == S_FALSE && fetched == 0 && !component) break;
        Check(hr);
        if (hr != S_OK || fetched != 1 || !component) throw Error{ E_UNEXPECTED };
        GUID guid{};
        Check(component->GetInstanceGuid(&guid));
        if (guid == GUID_NULL || std::find(adapters.begin(), adapters.end(), guid) != adapters.end()) throw Error{ E_UNEXPECTED };
        adapters.push_back(guid);
    }
    // Динамический vNIC может отсутствовать в EnumComponents(Net). NETIO дополняет
    // инвентарь независимо от GetClassGuid, который у такого объекта бывает E_POINTER.
    MIB_IF_TABLE2* raw = nullptr;
    const auto status = GetIfTable2(&raw);
    const auto release = [](MIB_IF_TABLE2* table) { if (table) FreeMibTable(table); };
    std::unique_ptr<MIB_IF_TABLE2, decltype(release)> table(raw, release);
    CheckWin32(status);
    if (!table) throw Error{ E_UNEXPECTED };
    for (ULONG index = 0; index != table->NumEntries; ++index) {
        const auto& row = table->Table[index];
        if (row.InterfaceGuid == GUID_NULL || !row.InterfaceLuid.Value) throw Error{ E_UNEXPECTED };
        if (std::find(adapters.begin(), adapters.end(), row.InterfaceGuid) != adapters.end()) continue;
        adapters.push_back(row.InterfaceGuid);
    }
    if (std::find(adapters.begin(), adapters.end(), kFilterId) != adapters.end()) throw Error{ E_UNEXPECTED };
    return adapters;
}

inline GUID AdapterGuid(INetCfgComponent* component, const std::vector<GUID>& adapters) {
    if (!component) throw Error{ E_UNEXPECTED };
    GUID instance{};
    if (component->GetInstanceGuid(&instance) != S_OK || instance == GUID_NULL) throw Error{ E_UNEXPECTED };
    if (std::find(adapters.begin(), adapters.end(), instance) != adapters.end()) return instance;
    GUID componentClass{};
    if (component->GetClassGuid(&componentClass) != S_OK) throw Error{ E_UNEXPECTED };
    return componentClass == GUID_DEVCLASS_NET ? instance : GUID_NULL;
}

inline GUID InspectPath(INetCfgBindingPath* path, const std::vector<GUID>& adapters) {
    // Владелец уже проверен в Component(); здесь нужен только нижний адаптер.
    ComPtr<IEnumNetCfgBindingInterface> interfaces;
    if (path->EnumBindingInterfaces(&interfaces) != S_OK || !interfaces) throw Error{ E_UNEXPECTED };
    GUID adapter{};
    for (unsigned steps = 0;; ++steps) {
        ComPtr<INetCfgBindingInterface> binding;
        ULONG fetched = 0;
        const auto hr = interfaces->Next(1, &binding, &fetched);
        if (hr == S_FALSE && fetched == 0 && !binding) break;
        Check(hr);
        if (hr != S_OK || fetched != 1 || !binding || steps == 64) throw Error{ E_UNEXPECTED };
        ComPtr<INetCfgComponent> lower;
        if (binding->GetLowerComponent(&lower) != S_OK) throw Error{ E_UNEXPECTED };
        const auto guid = AdapterGuid(lower.Get(), adapters);
        if (guid == GUID_NULL) continue;
        if (adapter != GUID_NULL) throw Error{ E_UNEXPECTED };
        adapter = guid;
    }
    if (adapter == GUID_NULL) throw Error{ E_UNEXPECTED };
    return adapter;
}

} // namespace ndis_binding::detail
