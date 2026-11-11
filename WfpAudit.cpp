#include "WfpOptions.h"
#include <initguid.h>
#include "WfpAuditDetail.h"
#include <array>
#include <vector>

namespace WfpOptions {
namespace {

const Detail::AuditApi kAuditApi{
    ::AuditEnumerateSubCategories, ::AuditQuerySystemPolicy,
    ::AuditSetSystemPolicy, ::AuditFree
};

// GUID не зависит от языка Windows. Изменения правил службы MPSSVC —
// отдельная подкатегория, не относящаяся к этому переключателю аудита WFP.
const std::array<GUID, 3> kWfpSubCategories{
    Audit_ObjectAccess_FirewallPacketDrops,
    Audit_ObjectAccess_FirewallConnection,
    Audit_PolicyChange_WfpIPSecPolicy
};

constexpr ULONG kAuditEvents = POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE;

template<class T>
class AuditBuffer {
public:
    explicit AuditBuffer(const Detail::AuditApi& api) : api_(api) {}
    ~AuditBuffer() { if (buffer_) api_.free(buffer_); }
    AuditBuffer(const AuditBuffer&) = delete;
    AuditBuffer& operator=(const AuditBuffer&) = delete;

    T** Out() { return &buffer_; }
    T* Get() const { return buffer_; }

private:
    const Detail::AuditApi& api_;
    T* buffer_ = nullptr;
};

class SecurityPrivilege {
public:
    ~SecurityPrivilege() {
        // Восстанавливаем только SeSecurityPrivilege, не трогая SE_DEBUG и
        // другие привилегии, которые могли измениться за время вызова API.
        if (changed_)
            AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
        if (token_) CloseHandle(token_);
    }

    bool Enable() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                              &token_))
            return false;
        TOKEN_PRIVILEGES wanted{};
        wanted.PrivilegeCount = 1;
        wanted.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!LookupPrivilegeValueW(nullptr, SE_SECURITY_NAME, &wanted.Privileges[0].Luid))
            return false;
        DWORD bytes = 0;
        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(token_, FALSE, &wanted, sizeof(previous_),
                                   &previous_, &bytes) || GetLastError() != ERROR_SUCCESS)
            return false;
        changed_ = true;
        return true;
    }

private:
    HANDLE token_ = nullptr;
    TOKEN_PRIVILEGES previous_{};
    bool changed_ = false;
};

DWORD AvailableSubCategories(const Detail::AuditApi& api, std::vector<GUID>& available) {
    AuditBuffer<GUID> categories(api);
    ULONG count = 0;
    if (!api.enumerate(nullptr, TRUE, categories.Out(), &count))
        return GetLastError();
    if (count && !categories.Get()) return ERROR_INVALID_DATA;

    // Запрашиваем только реально поддерживаемые подкатегории и не повторяем
    // их даже при наличии дублей в перечислении.
    for (const GUID& wfp : kWfpSubCategories) {
        for (ULONG i = 0; i < count; ++i) {
            if (IsEqualGUID(wfp, categories.Get()[i])) {
                available.push_back(wfp);
                break;
            }
        }
    }
    return available.empty() ? ERROR_NOT_SUPPORTED : ERROR_SUCCESS;
}

} // namespace

namespace Detail {

DWORD GetAudit(const AuditApi& api, bool& enabled) {
    enabled = false;
    std::vector<GUID> available;
    DWORD status = AvailableSubCategories(api, available);
    if (status != ERROR_SUCCESS) return status;

    AuditBuffer<AUDIT_POLICY_INFORMATION> policies(api);
    if (!api.query(available.data(), static_cast<ULONG>(available.size()), policies.Out()))
        return GetLastError();
    if (!policies.Get()) return ERROR_INVALID_DATA;

    for (size_t i = 0; i < available.size(); ++i) {
        if (policies.Get()[i].AuditingInformation & kAuditEvents) {
            enabled = true;
            break;
        }
    }
    return ERROR_SUCCESS;
}

DWORD SetAudit(const AuditApi& api, bool enabled) {
    std::vector<GUID> available;
    const DWORD status = AvailableSubCategories(api, available);
    if (status != ERROR_SUCCESS) return status;

    std::vector<AUDIT_POLICY_INFORMATION> policies;
    policies.reserve(available.size());
    for (const GUID& guid : available) {
        AUDIT_POLICY_INFORMATION policy{};
        policy.AuditSubCategoryGuid = guid;
        // Ноль означает «не менять», а не «выключить». Для полного отключения
        // нужен POLICY_AUDIT_EVENT_NONE. AuditCategoryGuid API игнорирует.
        policy.AuditingInformation = enabled ? kAuditEvents : POLICY_AUDIT_EVENT_NONE;
        policies.push_back(policy);
    }
    // Все доступные подкатегории передаются одним вызовом; остальные категории
    // аудита, включая правила службы Windows Firewall, не перезаписываются.
    return api.set(policies.data(), static_cast<ULONG>(policies.size()))
        ? ERROR_SUCCESS : GetLastError();
}

} // namespace Detail

DWORD GetAudit(bool& enabled) {
    const DWORD status = Detail::GetAudit(kAuditApi, enabled);
    if (status != ERROR_ACCESS_DENIED && status != ERROR_PRIVILEGE_NOT_HELD)
        return status;

    SecurityPrivilege privilege;
    if (!privilege.Enable()) return status;
    return Detail::GetAudit(kAuditApi, enabled);
}

DWORD SetAudit(bool enabled) {
    SecurityPrivilege privilege;
    // Право на объект политики также может разрешать запись без привилегии;
    // окончательный результат проверки доступа возвращает сам Audit API.
    privilege.Enable();
    return Detail::SetAudit(kAuditApi, enabled);
}

} // namespace WfpOptions
