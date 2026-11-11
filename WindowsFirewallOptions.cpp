#include "Common.h"
#include "WindowsFirewallOptions.h"
#include "WindowsFirewallOptionsDetail.h"
#include <array>

namespace WindowsFirewallOptions {
namespace {

constexpr std::array<NET_FW_PROFILE_TYPE2, 3> kProfiles{
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC
};

class Policy {
public:
    Policy() = default;
    ~Policy() { if (policy_) policy_->Release(); }
    Policy(const Policy&) = delete;
    Policy& operator=(const Policy&) = delete;

    HRESULT Open() {
        return CoCreateInstance(CLSID_NetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
                                IID_INetFwPolicy2,
                                reinterpret_cast<void**>(&policy_));
    }

    Detail::PolicyApi Api() const {
        return { policy_, GetEnabled, SetEnabled };
    }

private:
    INetFwPolicy2* policy_ = nullptr;

    static HRESULT GetEnabled(void* context, NET_FW_PROFILE_TYPE2 profile,
                              VARIANT_BOOL* enabled) {
        return static_cast<INetFwPolicy2*>(context)->get_FirewallEnabled(profile, enabled);
    }

    static HRESULT SetEnabled(void* context, NET_FW_PROFILE_TYPE2 profile,
                              VARIANT_BOOL enabled) {
        return static_cast<INetFwPolicy2*>(context)->put_FirewallEnabled(profile, enabled);
    }
};

} // namespace

namespace Detail {

HRESULT GetEnabled(const PolicyApi& api, bool& enabled) {
    enabled = false;
    bool anyEnabled = false;
    for (const auto profile : kProfiles) {
        VARIANT_BOOL value = VARIANT_FALSE;
        const HRESULT status = api.getEnabled(api.context, profile, &value);
        if (FAILED(status)) return status;
        anyEnabled = anyEnabled || value != VARIANT_FALSE;
    }
    // Ошибку чтения любого профиля не выдаём за известное состояние.
    enabled = anyEnabled;
    return S_OK;
}

HRESULT SetEnabled(const PolicyApi& api, bool enabled) {
    HRESULT result = S_OK;
    const VARIANT_BOOL value = enabled ? VARIANT_TRUE : VARIANT_FALSE;
    // API принимает один профиль, а не объединённую маску. При ошибке
    // пробуем остальные профили и возвращаем первую ошибку вызывающему коду.
    for (const auto profile : kProfiles) {
        const HRESULT status = api.setEnabled(api.context, profile, value);
        if (FAILED(status) && SUCCEEDED(result)) result = status;
    }
    return result;
}

} // namespace Detail

HRESULT GetEnabled(bool& enabled) {
    enabled = false;
    Policy policy;
    const HRESULT status = policy.Open();
    if (FAILED(status)) return status;
    return Detail::GetEnabled(policy.Api(), enabled);
}

HRESULT SetEnabled(bool enabled) {
    Policy policy;
    const HRESULT status = policy.Open();
    if (FAILED(status)) return status;
    return Detail::SetEnabled(policy.Api(), enabled);
}

} // namespace WindowsFirewallOptions
