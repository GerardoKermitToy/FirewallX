#include "WindowsFirewallOptionsDetail.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

constexpr std::array<NET_FW_PROFILE_TYPE2, 3> kProfiles{
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC
};

struct MockPolicy {
    std::array<VARIANT_BOOL, 3> enabled{};
    std::array<HRESULT, 3> readResults{};
    std::array<HRESULT, 3> writeResults{};
    std::vector<NET_FW_PROFILE_TYPE2> reads;
    std::vector<std::pair<NET_FW_PROFILE_TYPE2, VARIANT_BOOL>> writes;

    static size_t Index(NET_FW_PROFILE_TYPE2 profile) {
        const auto it = std::find(kProfiles.begin(), kProfiles.end(), profile);
        Check(it != kProfiles.end(), "API вызван с неизвестным профилем или объединённой маской");
        return static_cast<size_t>(it - kProfiles.begin());
    }

    static HRESULT Get(void* context, NET_FW_PROFILE_TYPE2 profile, VARIANT_BOOL* value) {
        auto& mock = *static_cast<MockPolicy*>(context);
        mock.reads.push_back(profile);
        const size_t i = Index(profile);
        if (FAILED(mock.readResults[i])) return mock.readResults[i];
        *value = mock.enabled[i];
        return mock.readResults[i];
    }

    static HRESULT Set(void* context, NET_FW_PROFILE_TYPE2 profile, VARIANT_BOOL value) {
        auto& mock = *static_cast<MockPolicy*>(context);
        mock.writes.emplace_back(profile, value);
        const size_t i = Index(profile);
        if (SUCCEEDED(mock.writeResults[i])) mock.enabled[i] = value;
        return mock.writeResults[i];
    }

    WindowsFirewallOptions::Detail::PolicyApi Api() {
        return { this, Get, Set };
    }

    void CheckWrites(VARIANT_BOOL expected) const {
        Check(writes.size() == kProfiles.size(), "изменены не все три профиля брандмауэра");
        for (size_t i = 0; i < kProfiles.size(); ++i) {
            Check(writes[i].first == kProfiles[i], "изменён неверный профиль брандмауэра");
            Check(writes[i].second == expected, "API получил неверный VARIANT_BOOL");
        }
    }
};

void TestAnyEnabled() {
    MockPolicy mock;
    // Проверяем все восемь сочетаний, включая включённый неактивный профиль.
    for (unsigned combination = 0; combination < 8; ++combination) {
        for (size_t i = 0; i < kProfiles.size(); ++i)
            mock.enabled[i] = (combination & (1u << i)) ? VARIANT_TRUE : VARIANT_FALSE;
        mock.reads.clear();
        bool enabled = true;
        Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == S_OK,
              "не удалось прочитать сочетание профилей");
        Check(enabled == (combination != 0), "флажок не учитывает хотя бы один включённый профиль");
        Check(mock.reads == std::vector<NET_FW_PROFILE_TYPE2>(kProfiles.begin(), kProfiles.end()),
              "прочитаны не все три профиля брандмауэра");
        Check(mock.writes.empty(), "чтение меняет состояние брандмауэра");
    }
    mock.enabled = { VARIANT_FALSE, static_cast<VARIANT_BOOL>(1), VARIANT_FALSE };
    bool enabled = false;
    Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == S_OK && enabled,
          "ненулевой VARIANT_BOOL не учтён");
}

void TestSetAll() {
    for (unsigned combination = 0; combination < 8; ++combination) {
        for (const bool wanted : { true, false }) {
            MockPolicy mock;
            for (size_t i = 0; i < kProfiles.size(); ++i)
                mock.enabled[i] = (combination & (1u << i)) ? VARIANT_TRUE : VARIANT_FALSE;
            Check(WindowsFirewallOptions::Detail::SetEnabled(mock.Api(), wanted) == S_OK,
                  "не удалось изменить профили брандмауэра");
            const VARIANT_BOOL expected = wanted ? VARIANT_TRUE : VARIANT_FALSE;
            mock.CheckWrites(expected);
            for (const auto value : mock.enabled)
                Check(value == expected, "состояние одного из профилей не изменено");
            bool enabled = !wanted;
            Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == S_OK &&
                  enabled == wanted, "повторное чтение не соответствует записанному состоянию");
        }
    }
}

void TestReadErrors() {
    for (size_t failedProfile = 0; failedProfile < kProfiles.size(); ++failedProfile) {
        for (const HRESULT error : { E_ACCESSDENIED, HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE) }) {
            MockPolicy mock;
            mock.enabled.fill(VARIANT_TRUE);
            mock.readResults[failedProfile] = error;
            bool enabled = true;
            Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == error,
                  "ошибка чтения профиля скрыта");
            Check(!enabled, "частичное чтение возвращает известное состояние");
            Check(mock.reads.size() == failedProfile + 1, "чтение продолжилось после ошибки");
            Check(mock.writes.empty(), "при ошибке чтения меняется состояние брандмауэра");
        }
    }
}

void TestPartialWrites() {
    for (size_t failedProfile = 0; failedProfile < kProfiles.size(); ++failedProfile) {
        for (const bool wanted : { true, false }) {
            MockPolicy mock;
            const VARIANT_BOOL before = wanted ? VARIANT_FALSE : VARIANT_TRUE;
            const VARIANT_BOOL expected = wanted ? VARIANT_TRUE : VARIANT_FALSE;
            mock.enabled.fill(before);
            mock.writeResults[failedProfile] = E_ACCESSDENIED;
            Check(WindowsFirewallOptions::Detail::SetEnabled(mock.Api(), wanted) == E_ACCESSDENIED,
                  "ошибка изменения профиля скрыта");
            mock.CheckWrites(expected);
            for (size_t i = 0; i < kProfiles.size(); ++i)
                Check(mock.enabled[i] == (i == failedProfile ? before : expected),
                      "ошибка одного профиля помешала изменить остальные");
            bool enabled = false;
            Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == S_OK && enabled,
                  "частичная запись ошибочно показана как полностью выключенный брандмауэр");

            mock.writeResults.fill(S_OK);
            mock.writes.clear();
            Check(WindowsFirewallOptions::Detail::SetEnabled(mock.Api(), wanted) == S_OK,
                  "повторное изменение после ошибки не выполнено");
            mock.CheckWrites(expected);
            Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == S_OK &&
                  enabled == wanted, "состояние после повторного изменения неверно");
        }
    }
    MockPolicy mock;
    mock.writeResults = { E_ACCESSDENIED, HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE), E_FAIL };
    Check(WindowsFirewallOptions::Detail::SetEnabled(mock.Api(), true) == E_ACCESSDENIED,
          "первая ошибка заменена последующей");
    mock.CheckWrites(VARIANT_TRUE);
}

void TestSuccessfulHresults() {
    MockPolicy mock;
    mock.readResults.fill(S_FALSE);
    mock.writeResults.fill(S_FALSE);
    Check(WindowsFirewallOptions::Detail::SetEnabled(mock.Api(), true) == S_OK,
          "успешный HRESULT ошибочно принят за ошибку записи");
    mock.CheckWrites(VARIANT_TRUE);
    bool enabled = false;
    Check(WindowsFirewallOptions::Detail::GetEnabled(mock.Api(), enabled) == S_OK && enabled,
          "успешный HRESULT ошибочно принят за ошибку чтения");
}

} // namespace

int main() {
    try {
        TestAnyEnabled();
        TestSetAll();
        TestReadErrors();
        TestPartialWrites();
        TestSuccessfulHresults();
        std::cout << "windows_firewall_options_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
