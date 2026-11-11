#pragma once
#include <windows.h>
#include <ntsecapi.h>

namespace WfpOptions::Detail {

// Подмена только API политики позволяет проверить весь маршрут чтения и
// записи без изменения реальной политики аудита Windows во время тестов.
struct AuditApi {
    decltype(&::AuditEnumerateSubCategories) enumerate;
    decltype(&::AuditQuerySystemPolicy) query;
    decltype(&::AuditSetSystemPolicy) set;
    decltype(&::AuditFree) free;
};

DWORD GetAudit(const AuditApi& api, bool& enabled);
DWORD SetAudit(const AuditApi& api, bool enabled);

} // namespace WfpOptions::Detail
