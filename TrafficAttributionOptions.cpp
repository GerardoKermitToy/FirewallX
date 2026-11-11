#include "TrafficAttributionOptions.h"
#include "TrafficAttributionOptionsDetail.h"
#include "Settings.h"

namespace TrafficAttributionOptions {
namespace {

constexpr wchar_t kParametersKey[] =
    L"SYSTEM\\CurrentControlSet\\Services\\PortmasterKext\\Parameters";
constexpr wchar_t kFallbackValue[] = L"EnableInboundUdpCacheMissPidFallback";
const Detail::RegistryApi kRegistryApi{ RegCreateKeyExW, RegSetValueExW, RegCloseKey };

} // namespace

bool Load() {
    return Settings::GetBool(Settings::Key::kPreciseTrafficAttribution, true);
}

bool Save(bool enabled) {
    return Settings::SetBool(Settings::Key::kPreciseTrafficAttribution, enabled);
}

namespace Detail {

DWORD Apply(const RegistryApi& api, bool enabled) {
    HKEY key = nullptr;
    const LSTATUS opened = api.create(
        HKEY_LOCAL_MACHINE, kParametersKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE, nullptr, &key, nullptr);
    if (opened != ERROR_SUCCESS) return static_cast<DWORD>(opened);

    const DWORD value = enabled ? 1 : 0;
    const LSTATUS written = api.set(
        key, kFallbackValue, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    api.close(key);
    // Функции реестра возвращают код ошибки непосредственно, не через GetLastError.
    return static_cast<DWORD>(written);
}

DWORD ApplySaved(const RegistryApi& api) {
    return Apply(api, Load());
}

} // namespace Detail

DWORD Apply(bool enabled) {
    return Detail::Apply(kRegistryApi, enabled);
}

DWORD ApplySaved() {
    return Detail::ApplySaved(kRegistryApi);
}

} // namespace TrafficAttributionOptions
