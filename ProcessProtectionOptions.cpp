#include "ProcessProtectionOptions.h"
#include "ProcessProtectionOptionsDetail.h"
#include "Settings.h"

namespace ProcessProtectionOptions {
namespace {

const Detail::MitigationApi kMitigationApi{ SetProcessMitigationPolicy };

} // namespace

bool Load() {
    return Settings::GetBool(Settings::Key::kDllInjectionProtection, false);
}

bool Save(bool enabled) {
    return Settings::SetBool(Settings::Key::kDllInjectionProtection, enabled);
}

namespace Detail {

DWORD Apply(const MitigationApi& api, bool enabled) {
    // Снятие флажка не ослабляет политики текущего процесса или политики ОС.
    if (!enabled) return ERROR_SUCCESS;

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
    signature.MicrosoftSignedOnly = 1;
    if (!api.set(ProcessSignaturePolicy, &signature, sizeof(signature)))
        return GetLastError();

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode{};
    dynamicCode.ProhibitDynamicCode = 1;
    if (!api.set(ProcessDynamicCodePolicy, &dynamicCode, sizeof(dynamicCode)))
        return GetLastError();

    return ERROR_SUCCESS;
}

DWORD ApplySaved(const MitigationApi& api) {
    return Apply(api, Load());
}

} // namespace Detail

DWORD ApplySaved() {
    return Detail::ApplySaved(kMitigationApi);
}

} // namespace ProcessProtectionOptions
