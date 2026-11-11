#include "NdisBinding.h"

namespace ndis_binding::detail {
namespace {

template<class T> T ReadScalar(ConfigurationReader read, void* context, const wchar_t* name, DWORD flags) {
    T value{};
    DWORD size = sizeof(value);
    CheckWin32(read(context, name, flags, &value, &size));
    if (size != sizeof(value)) throw Error{ E_UNEXPECTED };
    return value;
}

RecoveryPermission ReadRecovery(ConfigurationReader read, void* context) {
    DWORD value = 0, size = sizeof(value);
    const auto status = read(context, L"AutoRepairAllowed", RRF_RT_REG_DWORD, &value, &size);
    if (status == ERROR_FILE_NOT_FOUND) return RecoveryPermission::Legacy;
    CheckWin32(status);
    if (size != sizeof(value) || value > 1) throw Error{ E_UNEXPECTED };
    return value ? RecoveryPermission::Allowed : RecoveryPermission::InstallerControlled;
}

} // namespace

Configuration ReadConfiguration(ConfigurationReader read, void* context) {
    if (!read) throw Error{ E_INVALIDARG };
    const auto version = ReadScalar<DWORD>(read, context, L"ConfigVersion", RRF_RT_REG_DWORD);
    if (version != kConfigVersion) throw Error{ HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH) };
    const auto allowed = ReadScalar<DWORD>(read, context, L"AllowBindings", RRF_RT_REG_DWORD);
    if (allowed > 1) throw Error{ E_UNEXPECTED };
    const auto recovery = ReadRecovery(read, context);
    // Несогласованный снимок не становится разрешением на восстановление.
    if (ReadScalar<DWORD>(read, context, L"ConfigVersion", RRF_RT_REG_DWORD) != version ||
        ReadScalar<DWORD>(read, context, L"AllowBindings", RRF_RT_REG_DWORD) != allowed ||
        ReadRecovery(read, context) != recovery) throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
    return {allowed == 1, recovery};
}

} // namespace ndis_binding::detail
