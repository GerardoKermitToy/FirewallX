#include "FirewallPolicy.h"
#include "Settings.h"

namespace FirewallPolicySetting {

FirewallPolicy Load() {
    std::wstring stored;
    if (!Settings::GetString(Settings::Key::kDesktopPolicy, stored))
        return FirewallPolicy::Learning;

    // Сравнение целой строки не превращает повреждённое значение вроде
    // «0abc» в BlockAll. Неизвестная настройка не перезаписывается.
    size_t count = 0;
    const auto* policies = FirewallPolicies::All(count);
    for (size_t i = 0; i < count; ++i)
        if (stored == std::to_wstring(static_cast<int>(policies[i].policy)))
            return policies[i].policy;
    return FirewallPolicy::Learning;
}

bool Save(FirewallPolicy policy) {
    return FirewallPolicies::IsValid(policy) &&
           Settings::SetInt(Settings::Key::kDesktopPolicy, static_cast<int>(policy));
}

} // namespace FirewallPolicySetting
