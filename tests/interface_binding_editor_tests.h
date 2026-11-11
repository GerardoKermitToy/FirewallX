#pragma once
#include "NdisBinding.h"
#include "Settings.h"

namespace {
struct InterfaceBindingEditorProbe {
    static inline InterfaceBindingEditorProbe* active = nullptr;
    static inline std::vector<std::wstring> applied;
    static constexpr int kCheck = 413;
    static constexpr int kReverse = 415;
    bool initial = false, accept = false, expectControl = true;
    bool inspected = false, correct = false;

    static void Applied(const std::wstring& name) { applied.push_back(name); }
    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.inspected = true;
        HWND check = GetDlgItem(dialog, kCheck);
        HWND reverse = GetDlgItem(dialog, kReverse);
        probe.correct = probe.expectControl == (check != nullptr) &&
                        probe.expectControl == (reverse != nullptr);
        if (check && reverse) {
            probe.correct = probe.correct && IsWindowEnabled(check) && IsWindowEnabled(reverse) &&
                (SendMessageW(check, BM_GETCHECK, 0, 0) == BST_CHECKED) == probe.initial &&
                (SendMessageW(reverse, BM_GETCHECK, 0, 0) == BST_CHECKED) == probe.initial;
            SendMessageW(check, BM_CLICK, 0, 0);
            SendMessageW(reverse, BM_CLICK, 0, 0);
        }
        PostMessageW(dialog, WM_COMMAND, probe.accept ? IDOK : IDCANCEL, 0);
    }
};

void TestInterfaceBindingEditor() {
    const std::wstring name = L"Отсутствующий адаптер café 网络";
    const auto key = ndis_binding::InterfacePreferenceKey(name);
    const std::wstring reverseKey = Settings::Key::kNdisReverseTrafficPrefix + name;
    AppRulesEditor::SetInterfaceBindingTestHandler(InterfaceBindingEditorProbe::Applied);
    for (const bool initial : {false, true}) {
        for (const bool accept : {false, true}) {
            Check(Settings::SetBool(key.c_str(), initial) && Settings::SetBool(reverseKey.c_str(), initial),
                  "cannot seed interface preferences");
            InterfaceBindingEditorProbe probe;
            probe.initial = initial;
            probe.accept = accept;
            InterfaceBindingEditorProbe::active = &probe;
            InterfaceBindingEditorProbe::applied.clear();
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceBindingEditorProbe::Inspect);
            Check(timer != 0, "cannot create interface binding editor probe");
            RuleStore store;
            const bool result = AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store,
                                                    name, name, false, false, true);
            KillTimer(nullptr, timer);
            Check(probe.inspected && probe.correct && result == accept, "interface checkbox is incorrect");
            Check(Settings::GetBool(key.c_str(), !initial) == (accept ? !initial : initial) &&
                      Settings::GetBool(reverseKey.c_str(), !initial) == (accept ? !initial : initial),
                  "interface checkboxes did not preserve OK/cancel semantics");
            Check(InterfaceBindingEditorProbe::applied.size() == (accept ? 1u : 0u),
                  "interface binding was applied for a cancelled edit");
            if (accept) Check(InterfaceBindingEditorProbe::applied[0] == name, "wrong interface name was applied");
        }
    }
    for (const auto scope : {RuleScope::Global, RuleScope::PostApp, RuleScope::App}) {
        InterfaceBindingEditorProbe probe;
        probe.expectControl = false;
        InterfaceBindingEditorProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceBindingEditorProbe::Inspect);
        Check(timer != 0, "cannot create non-interface scope probe");
        RuleStore store;
        AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store, name, name,
                            scope == RuleScope::Global, scope == RuleScope::PostApp, false);
        KillTimer(nullptr, timer);
        Check(probe.inspected && probe.correct, "interface checkbox appeared in another scope");
    }
    InterfaceBindingEditorProbe::active = nullptr;
    AppRulesEditor::SetInterfaceBindingTestHandler(nullptr);
    Check(Settings::Remove(key.c_str()) && Settings::Remove(reverseKey.c_str()),
          "cannot remove test interface preferences");
}
} // namespace
