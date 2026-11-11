#pragma once
#include <windows.h>

namespace TrafficAttributionOptions::Detail {

// Подмена реестра позволяет проверить запись параметра и повторное применение
// из базы, не меняя конфигурацию настоящего драйвера Windows во время тестов.
struct RegistryApi {
    decltype(&::RegCreateKeyExW) create;
    decltype(&::RegSetValueExW) set;
    decltype(&::RegCloseKey) close;
};

DWORD Apply(const RegistryApi& api, bool enabled);
DWORD ApplySaved(const RegistryApi& api);

} // namespace TrafficAttributionOptions::Detail
