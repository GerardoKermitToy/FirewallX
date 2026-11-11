// Настоящие окна настроек и редакторов запускаются без драйвера и базы пользователя.
#include "SettingsWindow.h"
#include "Settings.h"
#include "StringRes.h"
#include "TreeList.h"
#include "UiKit.h"

#include <commctrl.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::wstring Text(HWND window) {
    wchar_t text[1024]{};
    GetWindowTextW(window, text, static_cast<int>(std::size(text)));
    return text;
}

struct Probe {
    enum class Step { Settings, Editor, NewRule, SaveRule, SaveGroup, ConfirmDelete, Deleted, Done, Failed };
    Step step = Step::Settings;
    RuleStore* store = nullptr;
    HWND settings = nullptr, editor = nullptr, ruleEditor = nullptr;
    size_t changes = 0;
    bool inheritanceOnly = false, keyboardDelete = false;
    std::wstring groupName;
    ULONGLONG deadline = 0;
    std::string error;

    struct Find {
        std::wstring title;
        HWND owner = nullptr;
        HWND window = nullptr;
    };

    static BOOL CALLBACK FindWindow(HWND window, LPARAM context) {
        auto& find = *reinterpret_cast<Find*>(context);
        if (IsWindowVisible(window) && Text(window) == find.title &&
            GetWindow(window, GW_OWNER) == find.owner) {
            find.window = window;
            return FALSE;
        }
        return TRUE;
    }

    static HWND Window(UINT titleId, HWND owner = nullptr) {
        Find find{ LoadStringRes(titleId), owner };
        EnumThreadWindows(GetCurrentThreadId(), FindWindow, reinterpret_cast<LPARAM>(&find));
        return find.window;
    }

    static void Check(bool value, const char* message) {
        if (!value) throw std::runtime_error(message);
    }

    static void Command(HWND window, int id) {
        PostMessageW(window, WM_COMMAND, MAKEWPARAM(id, BN_CLICKED),
                     reinterpret_cast<LPARAM>(GetDlgItem(window, id)));
    }

    int SelectGroup() const {
        HWND list = GetDlgItem(settings, 603);
        const std::wstring name = groupName.empty()
            ? (inheritanceOnly ? LoadStringRes(IDS_APPED_GLOBAL_HEADER) : L"FirewallX inactive test interface")
            : groupName;
        for (int row = 0; row < ListView_GetItemCount(list); ++row) {
            wchar_t text[256]{};
            ListView_GetItemText(list, row, 0, text, static_cast<int>(std::size(text)));
            if (text != name) continue;
            ListView_SetItemState(list, row, LVIS_SELECTED | LVIS_FOCUSED,
                                 LVIS_SELECTED | LVIS_FOCUSED);
            return row;
        }
        throw std::runtime_error("settings have no Ndis rule group");
    }

    void Tick() {
        static Step previous = Step::Failed;
        if (step != previous) {
            std::cerr << "settings Ndis step " << static_cast<int>(step) << '\n';
            previous = step;
        }
        if (step == Step::Done || step == Step::Failed) return;
        Check(GetTickCount64() < deadline, "Ndis settings editor test timed out");
        switch (step) {
        case Step::Settings: {
            settings = Window(IDS_SETTINGS_TITLE);
            if (!settings) return;
            HDC dc = GetDC(settings);
            SendMessageW(settings, WM_CTLCOLORBTN, reinterpret_cast<WPARAM>(dc),
                         reinterpret_cast<LPARAM>(GetDlgItem(settings, IDOK)));
            const bool systemBackground = GetBkColor(dc) == GetSysColor(COLOR_BTNFACE);
            NMCUSTOMDRAW primary{};
            primary.hdr = {GetDlgItem(settings, IDOK), IDOK, NM_CUSTOMDRAW};
            primary.dwDrawStage = CDDS_PREPAINT;
            primary.hdc = dc;
            const LRESULT buttonStyle = SendMessageW(settings, WM_NOTIFY, IDOK,
                                                     reinterpret_cast<LPARAM>(&primary));
            ReleaseDC(settings, dc);
            Check(systemBackground && buttonStyle == CDRF_DODEFAULT,
                  "settings close button has custom accent styling");
            HWND tabs = GetDlgItem(settings, 600);
            Check(TabCtrl_GetItemCount(tabs) == 3, "interface tab missing");
            const std::wstring autoText = LoadStringRes(IDS_SETTINGS_AUTO_CREATE_RULES);
            HWND autoLabel = FindWindowExW(settings, nullptr, L"Static", autoText.c_str());
            Check(autoLabel && IsWindowVisible(autoLabel), "automatic rule setting is missing");
            const int autoLabelId = GetDlgCtrlID(autoLabel);
            HWND autoCheck = GetDlgItem(settings, autoLabelId - 1);
            HWND protection = GetDlgItem(settings, autoLabelId - 3);
            HWND fontLabel = GetDlgItem(settings, autoLabelId + 1);
            RECT protectionRect{}, autoRect{}, fontRect{}, tabsRect{};
            Check(autoCheck && protection && fontLabel && GetWindowRect(protection, &protectionRect) &&
                  GetWindowRect(autoCheck, &autoRect) && GetWindowRect(fontLabel, &fontRect) &&
                  GetWindowRect(tabs, &tabsRect) && protectionRect.bottom <= autoRect.top &&
                  autoRect.bottom <= fontRect.top && fontRect.bottom < tabsRect.bottom,
                  "automatic rule setting overlaps existing controls");
            const bool enabled = Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false);
            Check((SendMessageW(autoCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) == enabled,
                  "automatic rule checkbox does not reflect the saved setting");
            SendMessageW(autoCheck, BM_CLICK, 0, 0);
            Check(Settings::GetBool(Settings::Key::kAutoCreatePresetRules, enabled) != enabled,
                  "automatic rule setting was not saved");
            SendMessageW(autoCheck, BM_CLICK, 0, 0);
            Check(Settings::GetBool(Settings::Key::kAutoCreatePresetRules, !enabled) == enabled,
                  "automatic rule setting could not be restored");
            TabCtrl_SetCurSel(tabs, inheritanceOnly ? 1 : 2);
            NMHDR changed{ tabs, 600, TCN_SELCHANGE };
            SendMessageW(settings, WM_NOTIFY, 600, reinterpret_cast<LPARAM>(&changed));
            Check(!IsWindowVisible(autoLabel) && !IsWindowVisible(autoCheck),
                  "automatic rule controls remained visible on another tab");
            const int row = SelectGroup();
            if (inheritanceOnly) {
                Check(IsWindowEnabled(GetDlgItem(settings, 606)) != FALSE,
                      "cannot delete application with inheritance settings only");
                step = Step::ConfirmDelete;
                if (keyboardDelete) {
                    NMLVKEYDOWN key{};
                    key.hdr = {GetDlgItem(settings, 603), 603, LVN_KEYDOWN};
                    key.wVKey = VK_DELETE;
                    SendMessageW(settings, WM_NOTIFY, 603, reinterpret_cast<LPARAM>(&key));
                } else {
                    Command(settings, 606);
                }
                break;
            }
            Check(IsWindowVisible(GetDlgItem(settings, 605)) == FALSE &&
                  IsWindowVisible(GetDlgItem(settings, 607)) == FALSE,
                  "interface tab offers executable controls");
            NMLVCUSTOMDRAW draw{};
            draw.nmcd.hdr = {GetDlgItem(settings, 603), 603, NM_CUSTOMDRAW};
            draw.nmcd.dwDrawStage = CDDS_ITEMPREPAINT | CDDS_SUBITEM;
            draw.nmcd.dwItemSpec = row;
            SendMessageW(settings, WM_NOTIFY, 603, reinterpret_cast<LPARAM>(&draw));
            Check(draw.clrText == Ui::DialogPalette().block, "inactive interface group does not use the dialog warning color");
            wchar_t tipText[1024]{};
            NMLVGETINFOTIPW tip{};
            tip.hdr.hwndFrom = GetDlgItem(settings, 603);
            tip.hdr.idFrom = 603;
            tip.hdr.code = LVN_GETINFOTIPW;
            tip.iItem = row;
            tip.pszText = tipText;
            tip.cchTextMax = static_cast<int>(std::size(tipText));
            SendMessageW(settings, WM_NOTIFY, 603, reinterpret_cast<LPARAM>(&tip));
            Check(tipText == LoadStringRes(IDS_INTERFACE_DESC) + L"\n" + LoadStringRes(IDS_INTERFACE_INACTIVE), "Ndis group tooltip is missing");
            step = Step::Editor;
            Command(settings, 604);
            break;
        }
        case Step::Editor:
            editor = Window(IDS_RULE_EDITOR_TITLE, settings);
            if (!editor) return;
            Check(GetDlgItem(editor, 400) != nullptr,
                  "settings rejected the Ndis group as an application without an executable");
            Check(ListView_GetItemCount(GetDlgItem(editor, 400)) == 1,
                  "settings opened rules from the wrong group");
            step = Step::NewRule;
            Command(editor, 401);
            break;
        case Step::NewRule:
            ruleEditor = Window(IDS_RED_TITLE_CREATE, editor);
            if (!ruleEditor) return;
            Check(Text(GetDlgItem(ruleEditor, 302)) == L"FirewallX inactive test interface",
                  "new rule editor has the wrong Ndis scope");
            step = Step::SaveRule;
            Command(ruleEditor, IDOK);
            break;
        case Step::SaveRule:
            if (IsWindow(ruleEditor) || !IsWindowEnabled(editor)) return;
            Check(ListView_GetItemCount(GetDlgItem(editor, 400)) == 2,
                  "new Ndis rule was not added to the editor");
            step = Step::SaveGroup;
            Command(editor, IDOK);
            break;
        case Step::SaveGroup:
            if (IsWindow(editor) || !IsWindowEnabled(settings)) return;
            Check(store->InterfaceRules(L"FirewallX inactive test interface").size() == 2 && store->ForApp(L"C:\\Test\\sample.exe").size() == 1 &&
                      store->GlobalCount() == 1 && store->PostAppCount() == 1 && changes == 1,
                  "settings did not save the edited Ndis group independently");
            SelectGroup();
            step = Step::ConfirmDelete;
            Command(settings, 606);
            break;
        case Step::ConfirmDelete: {
            HWND confirm = Window(IDS_RULE_EDITOR_TITLE, settings);
            if (!confirm) return;
            Check(GetDlgItem(confirm, IDYES) != nullptr, "group deletion did not ask for confirmation");
            step = Step::Deleted;
            Command(confirm, IDYES);
            break;
        }
        case Step::Deleted:
            if (!IsWindowEnabled(settings)) return;
            if (inheritanceOnly) {
                Check(store->Count() == 0 && changes == 1 &&
                      store->GetInheritance(L"C:\\Test\\inheritance-only.exe") == RuleInheritance::Default,
                      "settings did not remove inheritance-only application");
                groupName.clear();
                SelectGroup();
                Check(!IsWindowEnabled(GetDlgItem(settings, 606)),
                      "empty special group became deletable");
                step = Step::Done;
                Command(settings, IDOK);
                break;
            }
            Check(store->InterfaceRules(L"FirewallX inactive test interface").empty() && store->Count() == 3 && changes == 2,
                  "settings deleted the wrong group or retained Ndis rules");
            for (const auto& entry : store->Interfaces())
                Check(entry.name != L"FirewallX inactive test interface",
                      "empty inactive interface group was retained");
            step = Step::Done;
            Command(settings, IDOK);
            break;
        default:
            break;
        }
    }

    static BOOL CALLBACK CloseWindow(HWND window, LPARAM) {
        const std::wstring title = Text(window);
        if (title == LoadStringRes(IDS_SETTINGS_TITLE) || title == LoadStringRes(IDS_RULE_EDITOR_TITLE) ||
            title == LoadStringRes(IDS_RED_TITLE_CREATE) || title == LoadStringRes(IDS_RED_TITLE_EDIT))
            PostMessageW(window, WM_CLOSE, 0, 0);
        return TRUE;
    }

    void Abort(const char* message) {
        std::cerr << "settings Ndis failed at step " << static_cast<int>(step) << ": " << message << '\n';
        error = message;
        step = Step::Failed;
        EnumThreadWindows(GetCurrentThreadId(), CloseWindow, 0);
    }
};

Probe* active = nullptr;

void CALLBACK Tick(HWND, UINT, UINT_PTR, DWORD) {
    if (!active) return;
    try {
        active->Tick();
    } catch (const std::exception& error) {
        active->Abort(error.what());
    }
}

} // namespace

void TestSettingsInheritanceOnly() {
    const std::wstring path = L"C:\\Test\\inheritance-only.exe";
    for (RuleInheritance mode : {RuleInheritance::Enabled, RuleInheritance::Never,
                                 RuleInheritance::EnabledAndNever})
    for (bool keyboard : {false, true}) {
        RuleStore store;
        store.SetInheritance(path, mode);
        Probe probe;
        probe.store = &store;
        probe.inheritanceOnly = true;
        probe.keyboardDelete = keyboard;
        for (const AppEntry& app : store.Apps())
            if (app.path == path) probe.groupName = app.name;
        Probe::Check(!probe.groupName.empty(), "inheritance-only application missing from settings");
        probe.deadline = GetTickCount64() + 30000;
        active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, Tick);
        Probe::Check(timer != 0, "cannot start inheritance settings test timer");
        const bool changed = SettingsWindow::Run(nullptr, GetModuleHandleW(nullptr), store,
            ListSkin::Classic, [&] { ++probe.changes; }, {});
        KillTimer(nullptr, timer);
        active = nullptr;
        Probe::Check(probe.error.empty(), probe.error.c_str());
        Probe::Check(changed && probe.step == Probe::Step::Done,
                     "inheritance-only application deletion did not complete");
    }
    std::cout << "settings inheritance-only: button and Delete passed for all flags\n";
}

void TestSettingsNdis() {
    TestSettingsInheritanceOnly();
    RuleStore store;
    for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp, RuleScope::Interface }) {
        Rule rule;
        rule.scope = scope;
        rule.conds = CondNone;
        rule.appPath = scope == RuleScope::App ? L"C:\\Test\\sample.exe"
            : scope == RuleScope::Interface ? L"FirewallX inactive test interface" : L"";
        store.Add(rule);
    }
    Probe probe;
    probe.store = &store;
    probe.deadline = GetTickCount64() + 30000;
    active = &probe;
    const UINT_PTR timer = SetTimer(nullptr, 0, 20, Tick);
    Probe::Check(timer != 0, "cannot start settings editor test timer");
    const bool changed = SettingsWindow::Run(nullptr, GetModuleHandleW(nullptr), store,
        ListSkin::Classic, [&] { ++probe.changes; }, {});
    KillTimer(nullptr, timer);
    active = nullptr;
    Probe::Check(probe.error.empty(), probe.error.c_str());
    Probe::Check(changed && probe.step == Probe::Step::Done,
                 "settings editor test did not complete");
    std::cout << "settings Ndis: editor, new rule, save, delete, tooltip and counts passed\n";
}
