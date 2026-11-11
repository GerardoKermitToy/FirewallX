#pragma once
#include <cstring>
#include <cwchar>

namespace {
struct ConfigFixture {
    DWORD version = 4, allowed = 1, recovery = 1;
    bool missingRecovery = false, flipAllowed = false, flipVersion = false, flipRecovery = false;
    unsigned versionReads = 0, allowedReads = 0, recoveryReads = 0;

    static LSTATUS Read(void* context, const wchar_t* name, DWORD flags, void* out, DWORD* size) {
        auto& self = *static_cast<ConfigFixture*>(context);
        CheckTest(flags == RRF_RT_REG_DWORD && out && *size == sizeof(DWORD));
        DWORD value = 0;
        if (std::wcscmp(name, L"ConfigVersion") == 0) {
            value = self.version + (self.flipVersion && self.versionReads++ ? 1u : 0u);
        } else if (std::wcscmp(name, L"AllowBindings") == 0) {
            value = self.flipAllowed && self.allowedReads++ ? 1u - self.allowed : self.allowed;
        } else if (std::wcscmp(name, L"AutoRepairAllowed") == 0) {
            if (self.missingRecovery) return ERROR_FILE_NOT_FOUND;
            value = self.flipRecovery && self.recoveryReads++ ? 1u - self.recovery : self.recovery;
        } else return ERROR_FILE_NOT_FOUND;
        std::memcpy(out, &value, sizeof(value));
        *size = sizeof(value);
        return ERROR_SUCCESS;
    }
    Configuration ReadConfig() { return ndis_binding::detail::ReadConfiguration(Read, this); }
};

void BindingConfigTests() {
    ConfigFixture registry;
    const auto config = registry.ReadConfig();
    CheckTest(config.allowed && config.recovery == RecoveryPermission::Allowed);
    for (const DWORD version : {0u, 2u, 3u, 5u}) {
        ConfigFixture old; old.version = version;
        CheckTest(Rejected([&] { old.ReadConfig(); }) == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH));
    }
    for (const bool recovery : {false, true}) {
        ConfigFixture invalid;
        if (recovery) invalid.recovery = 2; else invalid.allowed = 2;
        Rejected([&] { invalid.ReadConfig(); });
    }
    ConfigFixture legacy; legacy.missingRecovery = true;
    CheckTest(legacy.ReadConfig().recovery == RecoveryPermission::Legacy);
    ConfigFixture installer; installer.recovery = 0; installer.allowed = 0;
    const auto disarmed = installer.ReadConfig();
    CheckTest(!disarmed.allowed && disarmed.recovery == RecoveryPermission::InstallerControlled);
    for (const unsigned field : {0u, 1u, 2u}) {
        ConfigFixture raced;
        if (field == 0) raced.flipVersion = true;
        if (field == 1) raced.flipAllowed = true;
        if (field == 2) raced.flipRecovery = true;
        CheckTest(Rejected([&] { raced.ReadConfig(); }) == HRESULT_FROM_WIN32(ERROR_RETRY));
    }
}
} // namespace
