#include "WfpAuditDetail.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

AUDIT_POLICY_INFORMATION Policy(const GUID& guid, ULONG flags) {
    AUDIT_POLICY_INFORMATION policy{};
    policy.AuditSubCategoryGuid = guid;
    policy.AuditingInformation = flags;
    return policy;
}

struct MockAudit {
    inline static MockAudit* active = nullptr;
    std::vector<AUDIT_POLICY_INFORMATION> policies{
        Policy(Audit_ObjectAccess_FirewallPacketDrops, POLICY_AUDIT_EVENT_NONE),
        Policy(Audit_ObjectAccess_FirewallConnection, POLICY_AUDIT_EVENT_NONE),
        Policy(Audit_PolicyChange_WfpIPSecPolicy, POLICY_AUDIT_EVENT_NONE),
        Policy(Audit_ObjectAccess_FileSystem, POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE),
        Policy(Audit_PolicyChange_MpsscvRulePolicy, POLICY_AUDIT_EVENT_SUCCESS)
    };
    std::vector<GUID> available;
    std::vector<GUID> queried;
    std::vector<AUDIT_POLICY_INFORMATION> written;
    DWORD enumerateError = ERROR_SUCCESS;
    DWORD queryError = ERROR_SUCCESS;
    DWORD setError = ERROR_SUCCESS;
    bool nullEnumeration = false;
    bool nullQuery = false;
    bool partialWrite = false;
    unsigned allocations = 0;
    unsigned frees = 0;
    unsigned queryCalls = 0;
    unsigned setCalls = 0;

    MockAudit() {
        active = this;
        for (const auto& policy : policies) available.push_back(policy.AuditSubCategoryGuid);
    }
    ~MockAudit() { active = nullptr; }

    AUDIT_POLICY_INFORMATION* Find(const GUID& guid) {
        const auto it = std::find_if(policies.begin(), policies.end(), [&](const auto& policy) {
            return IsEqualGUID(policy.AuditSubCategoryGuid, guid);
        });
        return it == policies.end() ? nullptr : &*it;
    }

    static BOOLEAN NTAPI Enumerate(const GUID* category, BOOLEAN all, GUID** output, ULONG* count) {
        auto& mock = *active;
        Check(category == nullptr && all, "перечислены не все подкатегории Windows");
        if (mock.enumerateError != ERROR_SUCCESS) {
            SetLastError(mock.enumerateError);
            return FALSE;
        }
        *count = static_cast<ULONG>(mock.available.size());
        *output = nullptr;
        if (mock.available.empty() || mock.nullEnumeration) return TRUE;
        *output = static_cast<GUID*>(std::malloc(mock.available.size() * sizeof(GUID)));
        Check(*output != nullptr, "не удалось выделить буфер GUID");
        std::memcpy(*output, mock.available.data(), mock.available.size() * sizeof(GUID));
        ++mock.allocations;
        return TRUE;
    }

    static BOOLEAN NTAPI Query(const GUID* guids, ULONG count, AUDIT_POLICY_INFORMATION** output) {
        auto& mock = *active;
        ++mock.queryCalls;
        mock.queried.assign(guids, guids + count);
        if (mock.queryError != ERROR_SUCCESS) {
            SetLastError(mock.queryError);
            return FALSE;
        }
        *output = nullptr;
        if (mock.nullQuery) return TRUE;
        *output = static_cast<AUDIT_POLICY_INFORMATION*>(
            std::malloc(static_cast<size_t>(count) * sizeof(AUDIT_POLICY_INFORMATION)));
        Check(*output != nullptr, "не удалось выделить буфер политики");
        ++mock.allocations;
        for (ULONG i = 0; i < count; ++i) {
            const auto* policy = mock.Find(guids[i]);
            Check(policy != nullptr, "запрошена неподдерживаемая подкатегория");
            (*output)[i] = *policy;
        }
        return TRUE;
    }

    static BOOLEAN NTAPI Set(PCAUDIT_POLICY_INFORMATION policies, ULONG count) {
        auto& mock = *active;
        ++mock.setCalls;
        mock.written.assign(policies, policies + count);
        if (mock.setError != ERROR_SUCCESS && !mock.partialWrite) {
            SetLastError(mock.setError);
            return FALSE;
        }
        const ULONG applied = mock.partialWrite ? 1 : count;
        for (ULONG i = 0; i < applied; ++i) {
            auto* policy = mock.Find(policies[i].AuditSubCategoryGuid);
            Check(policy != nullptr, "изменяется неподдерживаемая подкатегория");
            policy->AuditingInformation = policies[i].AuditingInformation;
        }
        if (mock.setError != ERROR_SUCCESS) {
            SetLastError(mock.setError);
            return FALSE;
        }
        return TRUE;
    }

    static void NTAPI Free(void* memory) {
        ++active->frees;
        std::free(memory);
    }

    void CheckBuffers() const {
        Check(allocations == frees, "буферы Audit API не освобождены");
    }
};

const WfpOptions::Detail::AuditApi kApi{
    MockAudit::Enumerate, MockAudit::Query, MockAudit::Set, MockAudit::Free
};

void TestAnyEnabled() {
    MockAudit mock;
    // Проверяем все 64 комбинации шести флагов: успех/неуспех для каждой
    // из трёх подкатегорий. Аудит других категорий всегда включён.
    for (unsigned combination = 0; combination < 64; ++combination) {
        for (unsigned i = 0; i < 3; ++i) {
            const ULONG flags = (combination >> (2 * i)) & 3;
            mock.policies[i].AuditingInformation = flags ? flags : POLICY_AUDIT_EVENT_NONE;
        }
        bool enabled = true;
        Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_SUCCESS, "чтение комбинации аудита");
        Check(enabled == (combination != 0), "флажок не соответствует хотя бы одному виду аудита");
        Check(mock.queried.size() == 3, "запрошены не все три подкатегории WFP");
        Check(IsEqualGUID(mock.queried[2], Audit_PolicyChange_WfpIPSecPolicy),
              "аудит изменения политики WFP не учтён");
        mock.CheckBuffers();
    }
    for (unsigned i = 0; i < 3; ++i) mock.policies[i].AuditingInformation = 0;
    bool enabled = true;
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_SUCCESS && !enabled,
          "нулевые флаги ошибочно считаются включённым аудитом");
    mock.CheckBuffers();
}

void TestSetAll() {
    MockAudit mock;
    mock.policies[0].AuditingInformation = POLICY_AUDIT_EVENT_SUCCESS;
    mock.policies[1].AuditingInformation = POLICY_AUDIT_EVENT_FAILURE;
    for (const bool wanted : { true, false }) {
        const unsigned before = mock.setCalls;
        Check(WfpOptions::Detail::SetAudit(kApi, wanted) == ERROR_SUCCESS, "изменение аудита");
        Check(mock.setCalls == before + 1, "подкатегории меняются не одним вызовом API");
        Check(mock.written.size() == 3, "изменены не все доступные подкатегории WFP");
        const ULONG expected = wanted
            ? POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE : POLICY_AUDIT_EVENT_NONE;
        for (unsigned i = 0; i < 3; ++i)
            Check(mock.policies[i].AuditingInformation == expected, "не все флаги аудита изменены");
        Check(mock.policies[3].AuditingInformation ==
              (POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE), "изменён аудит файлов");
        Check(mock.policies[4].AuditingInformation == POLICY_AUDIT_EVENT_SUCCESS,
              "изменён аудит правил службы MPSSVC");
        bool enabled = !wanted;
        Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_SUCCESS && enabled == wanted,
              "повторное чтение не соответствует изменённому аудиту");
        mock.CheckBuffers();
    }
}

void TestAvailableSubset() {
    MockAudit mock;
    mock.available = { Audit_ObjectAccess_FileSystem, Audit_ObjectAccess_FirewallConnection,
                       Audit_ObjectAccess_FirewallConnection };
    for (const bool wanted : { true, false }) {
        Check(WfpOptions::Detail::SetAudit(kApi, wanted) == ERROR_SUCCESS, "изменение части подкатегорий");
        Check(mock.written.size() == 1, "дубли или неподдерживаемые подкатегории переданы API");
        Check(IsEqualGUID(mock.written[0].AuditSubCategoryGuid, Audit_ObjectAccess_FirewallConnection),
              "изменена не та подкатегория");
        bool enabled = !wanted;
        Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_SUCCESS && enabled == wanted,
              "состояние единственной доступной подкатегории неверно");
        mock.CheckBuffers();
    }
    mock.available = { Audit_PolicyChange_WfpIPSecPolicy };
    mock.policies[2].AuditingInformation = POLICY_AUDIT_EVENT_FAILURE;
    bool enabled = false;
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_SUCCESS && enabled,
          "единственный аудит изменения политики не отмечает флажок");
    mock.CheckBuffers();
}

void TestErrors() {
    MockAudit mock;
    bool enabled = true;
    mock.enumerateError = ERROR_ACCESS_DENIED;
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_ACCESS_DENIED && !enabled,
          "ошибка перечисления скрыта");
    Check(WfpOptions::Detail::SetAudit(kApi, true) == ERROR_ACCESS_DENIED && mock.setCalls == 0,
          "запись выполнена после ошибки перечисления");
    mock.enumerateError = ERROR_SUCCESS;
    mock.queryError = ERROR_PRIVILEGE_NOT_HELD;
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_PRIVILEGE_NOT_HELD && !enabled,
          "ошибка чтения скрыта");
    mock.queryError = ERROR_SUCCESS;
    mock.setError = ERROR_ACCESS_DENIED;
    Check(WfpOptions::Detail::SetAudit(kApi, false) == ERROR_ACCESS_DENIED,
          "ошибка записи скрыта");
    // После частичной записи ошибку не выдаём за полностью выключенный аудит.
    mock.partialWrite = true;
    Check(WfpOptions::Detail::SetAudit(kApi, true) == ERROR_ACCESS_DENIED, "частичная запись скрыла ошибку");
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_SUCCESS && enabled,
          "включённый после частичной записи метод не учтён");
    mock.CheckBuffers();
}

void TestUnavailableAndInvalidBuffers() {
    MockAudit mock;
    bool enabled = true;
    for (const auto& available : { std::vector<GUID>{}, std::vector<GUID>{ Audit_ObjectAccess_FileSystem } }) {
        mock.available = available;
        Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_NOT_SUPPORTED && !enabled,
              "отсутствие WFP ошибочно считается выключенным аудитом");
        Check(WfpOptions::Detail::SetAudit(kApi, true) == ERROR_NOT_SUPPORTED,
              "запись выполнена без доступных подкатегорий WFP");
        Check(mock.queryCalls == 0 && mock.setCalls == 0, "API вызван с пустым списком WFP");
        mock.CheckBuffers();
    }
    mock.available = { Audit_ObjectAccess_FirewallConnection };
    mock.nullEnumeration = true;
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_INVALID_DATA,
          "пустой буфер непустого перечисления принят");
    mock.nullEnumeration = false;
    mock.nullQuery = true;
    Check(WfpOptions::Detail::GetAudit(kApi, enabled) == ERROR_INVALID_DATA,
          "пустой буфер политики принят");
    mock.CheckBuffers();
}

} // namespace

int main() {
    try {
        TestAnyEnabled();
        TestSetAll();
        TestAvailableSubset();
        TestErrors();
        TestUnavailableAndInvalidBuffers();
        std::cout << "wfp_audit_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
