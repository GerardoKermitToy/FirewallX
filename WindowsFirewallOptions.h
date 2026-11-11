#pragma once
#include <windows.h>

namespace WindowsFirewallOptions {

// COM должен быть инициализирован в вызывающем потоке. Флажок установлен,
// если брандмауэр включён хотя бы для одного из трёх профилей Windows.
HRESULT GetEnabled(bool& enabled);
// Меняет состояние доменного, частного и общедоступного профилей через API.
HRESULT SetEnabled(bool enabled);

} // namespace WindowsFirewallOptions
