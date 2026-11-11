#pragma once
#include <windows.h>

namespace ProcessProtectionOptions::Detail {

// Подмена API проверяет параметры и ошибки, не меняя необратимые политики
// процесса, в котором выполняются остальные тесты.
struct MitigationApi {
    decltype(&::SetProcessMitigationPolicy) set;
};

DWORD Apply(const MitigationApi& api, bool enabled);
DWORD ApplySaved(const MitigationApi& api);

} // namespace ProcessProtectionOptions::Detail
