#include "SettingsWindow.h"
#include "AppRulesEditor.h"
#include "RuleGroupListUi.h"
#include "StringRes.h"
#include "UiKit.h"
#include "TreeList.h"
#include "WfpOptions.h"
#include "StartupOptions.h"
#include "WindowsFirewallOptions.h"
#include "TrafficAttributionOptions.h"
#include "ProcessProtectionOptions.h"
#include "Settings.h"
#include "Ingest.h"
#include <commctrl.h>
#include <commdlg.h>
#include <algorithm>
#include <deque>

namespace {

class SettingsDialog : public Ui::Modal {
public:
    RuleStore* store = nullptr;
    std::function<void()> onRulesChanged;
    std::function<void()> onFontChanged;
    ListSkin skin = ListSkin::Classic;
    bool changed = false;

protected:
    bool ModernStyle() const override { return true; }

    enum {
        IDC_TABS = 600, IDC_FILTER_LABEL, IDC_FILTER, IDC_LIST, IDC_RULES,
        IDC_ADD, IDC_DEL, IDC_CLEANUP, IDC_COUNT, IDC_NET_EVENTS, IDC_NET_EVENTS_LABEL,
        IDC_START_WITH_WINDOWS, IDC_START_WITH_WINDOWS_LABEL,
        IDC_WFP_AUDIT, IDC_WFP_AUDIT_LABEL,
        IDC_WINDOWS_FIREWALL, IDC_WINDOWS_FIREWALL_LABEL,
        IDC_PRECISE_TRAFFIC_ATTRIBUTION, IDC_PRECISE_TRAFFIC_ATTRIBUTION_LABEL,
        IDC_MUTE_MESSAGE_BEEP, IDC_MUTE_MESSAGE_BEEP_LABEL,
        IDC_SYSTEM_SCALING, IDC_SYSTEM_SCALING_LABEL,
        IDC_DLL_PROTECTION, IDC_DLL_PROTECTION_LABEL,
        IDC_AUTO_CREATE_RULES, IDC_AUTO_CREATE_RULES_LABEL,
        IDC_CONNECTION_FONT_LABEL, IDC_CONNECTION_FONT_VALUE,
        IDC_CONNECTION_FONT_CHOOSE, IDC_CONNECTION_FONT_RESET
    };

    void OnInit() override {
        const auto& m = M();
        icons_.Create(m.dpi);
        SetHeader(LoadStringRes(IDS_SETTINGS_HEADER),
                  LoadStringRes(IDS_SETTINGS_SUBHEADER));

        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        const int y = headerH() + m.margin();
        const int tabH = clientH() - y - m.margin() - m.btnH() - m.gap();

        tabs_ = Add(WC_TABCONTROLW, L"",
                    WS_TABSTOP | TCS_TABS | TCS_SINGLELINE,
                    0, x, y, w, tabH, IDC_TABS);
        if (tabs_) {
            std::wstring general = LoadStringRes(IDS_SETTINGS_TAB_GENERAL);
            std::wstring rules = LoadStringRes(IDS_SETTINGS_TAB_RULES);
            TCITEMW item{};
            item.mask = TCIF_TEXT;
            item.pszText = general.data();
            TabCtrl_InsertItem(tabs_, 0, &item);
            item.pszText = rules.data();
            TabCtrl_InsertItem(tabs_, 1, &item);
            std::wstring interfaces = LoadStringRes(IDS_SETTINGS_TAB_INTERFACES);
            item.pszText = interfaces.data();
            TabCtrl_InsertItem(tabs_, 2, &item);
        }

        RECT content{ 0, 0, w, tabH };
        if (tabs_) TabCtrl_AdjustRect(tabs_, FALSE, &content);
        const int cx = x + content.left;
        const int cy = y + content.top;
        const int cw = std::max(0, static_cast<int>(content.right - content.left));
        const int ch = std::max(0, static_cast<int>(content.bottom - content.top));

        const int netEventsX = cx + m.gap();
        const int netEventsW = std::max(0, cw - 2 * m.gap());
        const int netEventsLabelX = netEventsX + m.Sc(24);
        const int netEventsLabelW = std::max(0, netEventsW - m.Sc(24));

        bool startupEnabled = false;
        const HRESULT startupReadStatus = StartupOptions::GetEnabled(startupEnabled);
        const DWORD startupStyle = SUCCEEDED(startupReadStatus)
            ? BS_AUTOCHECKBOX : BS_AUTO3STATE;
        const int startupY = cy + m.gap();
        HWND startup = Add(L"BUTTON", L"",
                           WS_TABSTOP | startupStyle, 0,
                           netEventsX, startupY, m.checkH(), m.checkH(),
                           IDC_START_WITH_WINDOWS);
        Label(LoadStringRes(IDS_SETTINGS_START_WITH_WINDOWS), netEventsLabelX,
              startupY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_START_WITH_WINDOWS_LABEL, SS_NOTIFY);
        std::wstring startupTip = LoadStringRes(IDS_SETTINGS_START_WITH_WINDOWS_TIP);
        if (SUCCEEDED(startupReadStatus)) {
            SetChecked(IDC_START_WITH_WINDOWS, startupEnabled);
        } else {
            SendMessageW(startup, BM_SETCHECK, BST_INDETERMINATE, 0);
            Enable(IDC_START_WITH_WINDOWS, false);
            Enable(IDC_START_WITH_WINDOWS_LABEL, false);
            startupTip = LoadStringResFmt(IDS_SETTINGS_START_WITH_WINDOWS_READ_ERROR,
                                           static_cast<unsigned>(startupReadStatus));
        }
        AddToolTip(startup, startupTip);
        AddToolTip(Item(IDC_START_WITH_WINDOWS_LABEL), startupTip);

        bool netEventsEnabled = false;
        const DWORD readStatus = WfpOptions::GetNetEvents(netEventsEnabled);
        const std::wstring netEventsText = LoadStringRes(IDS_SETTINGS_NET_EVENTS);
        const DWORD netEventsStyle = readStatus == ERROR_SUCCESS
            ? BS_AUTOCHECKBOX : BS_AUTO3STATE;
        const int netEventsY = startupY + m.checkH() + m.gap();
        const int netEventsLabelY = netEventsY +
            std::max(0, (m.checkH() - m.labelH()) / 2);
        HWND netEvents = Add(L"BUTTON", L"",
                             WS_TABSTOP | netEventsStyle, 0,
                             netEventsX, netEventsY, m.checkH(), m.checkH(),
                             IDC_NET_EVENTS);
        Label(netEventsText, netEventsLabelX, netEventsLabelY,
              netEventsLabelW, m.labelH(), IDC_NET_EVENTS_LABEL, SS_NOTIFY);
        std::wstring netEventsTip = LoadStringRes(IDS_SETTINGS_NET_EVENTS_TIP);
        if (readStatus == ERROR_SUCCESS) {
            SetChecked(IDC_NET_EVENTS, netEventsEnabled);
        } else {
            // Не показываем неизвестное состояние как «выключено».
            SendMessageW(netEvents, BM_SETCHECK, BST_INDETERMINATE, 0);
            Enable(IDC_NET_EVENTS, false);
            Enable(IDC_NET_EVENTS_LABEL, false);
            netEventsTip = LoadStringResFmt(IDS_SETTINGS_NET_EVENTS_READ_ERROR,
                                             static_cast<unsigned>(readStatus));
        }
        AddToolTip(netEvents, netEventsTip);
        AddToolTip(Item(IDC_NET_EVENTS_LABEL), netEventsTip);

        bool auditEnabled = false;
        const DWORD auditReadStatus = WfpOptions::GetAudit(auditEnabled);
        const int auditY = netEventsY + m.checkH() + m.gap();
        HWND audit = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                         netEventsX, auditY, m.checkH(), m.checkH(), IDC_WFP_AUDIT);
        Label(LoadStringRes(IDS_SETTINGS_WFP_AUDIT), netEventsLabelX,
              auditY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_WFP_AUDIT_LABEL, SS_NOTIFY);
        SyncAuditState(auditEnabled, auditReadStatus);
        const std::wstring auditTip = auditReadStatus == ERROR_SUCCESS
            ? LoadStringRes(IDS_SETTINGS_WFP_AUDIT_TIP)
            : LoadStringResFmt(IDS_SETTINGS_WFP_AUDIT_READ_ERROR,
                               static_cast<unsigned>(auditReadStatus));
        AddToolTip(audit, auditTip);
        AddToolTip(Item(IDC_WFP_AUDIT_LABEL), auditTip);

        bool firewallEnabled = false;
        const HRESULT firewallReadStatus = WindowsFirewallOptions::GetEnabled(firewallEnabled);
        const int firewallY = auditY + m.checkH() + m.gap();
        HWND firewall = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                            netEventsX, firewallY, m.checkH(), m.checkH(),
                            IDC_WINDOWS_FIREWALL);
        Label(LoadStringRes(IDS_SETTINGS_WINDOWS_FIREWALL), netEventsLabelX,
              firewallY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_WINDOWS_FIREWALL_LABEL, SS_NOTIFY);
        SyncFirewallState(firewallEnabled, firewallReadStatus);
        const std::wstring firewallTip = SUCCEEDED(firewallReadStatus)
            ? LoadStringRes(IDS_SETTINGS_WINDOWS_FIREWALL_TIP)
            : LoadStringResFmt(IDS_SETTINGS_WINDOWS_FIREWALL_READ_ERROR,
                               static_cast<unsigned>(firewallReadStatus));
        AddToolTip(firewall, firewallTip);
        AddToolTip(Item(IDC_WINDOWS_FIREWALL_LABEL), firewallTip);

        const int attributionY = firewallY + m.checkH() + m.gap();
        HWND attribution = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                               netEventsX, attributionY, m.checkH(), m.checkH(),
                               IDC_PRECISE_TRAFFIC_ATTRIBUTION);
        Label(LoadStringRes(IDS_SETTINGS_PRECISE_TRAFFIC_ATTRIBUTION), netEventsLabelX,
              attributionY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_PRECISE_TRAFFIC_ATTRIBUTION_LABEL, SS_NOTIFY);
        SetChecked(IDC_PRECISE_TRAFFIC_ATTRIBUTION, TrafficAttributionOptions::Load());
        const std::wstring attributionTip =
            LoadStringRes(IDS_SETTINGS_PRECISE_TRAFFIC_ATTRIBUTION_TIP);
        AddToolTip(attribution, attributionTip);
        AddToolTip(Item(IDC_PRECISE_TRAFFIC_ATTRIBUTION_LABEL), attributionTip);

        const int muteY = attributionY + m.checkH() + m.gap();
        HWND mute = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                        netEventsX, muteY, m.checkH(), m.checkH(), IDC_MUTE_MESSAGE_BEEP);
        Label(LoadStringRes(IDS_SETTINGS_MUTE_MESSAGE_BEEP), netEventsLabelX,
              muteY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_MUTE_MESSAGE_BEEP_LABEL, SS_NOTIFY);
        SetChecked(IDC_MUTE_MESSAGE_BEEP,
                   Settings::GetBool(Settings::Key::kMuteMessageBeep, false));
        const std::wstring muteTip = LoadStringRes(IDS_SETTINGS_MUTE_MESSAGE_BEEP_TIP);
        AddToolTip(mute, muteTip);
        AddToolTip(Item(IDC_MUTE_MESSAGE_BEEP_LABEL), muteTip);

        const int scalingY = muteY + m.checkH() + m.gap();
        HWND scaling = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                           netEventsX, scalingY, m.checkH(), m.checkH(), IDC_SYSTEM_SCALING);
        Label(LoadStringRes(IDS_SETTINGS_SYSTEM_SCALING), netEventsLabelX,
              scalingY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_SYSTEM_SCALING_LABEL, SS_NOTIFY);
        SetChecked(IDC_SYSTEM_SCALING,
                   Settings::GetBool(Settings::Key::kSystemDpiScaling, false));
        const std::wstring scalingTip = LoadStringRes(IDS_SETTINGS_SYSTEM_SCALING_TIP) +
            L" " + LoadStringRes(IDS_SETTINGS_SYSTEM_SCALING_RESTART);
        AddToolTip(scaling, scalingTip);
        AddToolTip(Item(IDC_SYSTEM_SCALING_LABEL), scalingTip);

        const int protectionY = scalingY + m.checkH() + m.gap();
        HWND protection = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                              netEventsX, protectionY, m.checkH(), m.checkH(), IDC_DLL_PROTECTION);
        Label(LoadStringRes(IDS_SETTINGS_DLL_PROTECTION), netEventsLabelX,
              protectionY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_DLL_PROTECTION_LABEL, SS_NOTIFY);
        SetChecked(IDC_DLL_PROTECTION, ProcessProtectionOptions::Load());
        const std::wstring protectionTip = LoadStringRes(IDS_SETTINGS_DLL_PROTECTION_TIP) +
            L" " + LoadStringRes(IDS_SETTINGS_DLL_PROTECTION_RESTART);
        AddToolTip(protection, protectionTip);
        AddToolTip(Item(IDC_DLL_PROTECTION_LABEL), protectionTip);

        const int autoRulesY = protectionY + m.checkH() + m.gap();
        HWND autoRules = Add(L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, 0,
                             netEventsX, autoRulesY, m.checkH(), m.checkH(), IDC_AUTO_CREATE_RULES);
        Label(LoadStringRes(IDS_SETTINGS_AUTO_CREATE_RULES), netEventsLabelX,
              autoRulesY + std::max(0, (m.checkH() - m.labelH()) / 2),
              netEventsLabelW, m.labelH(), IDC_AUTO_CREATE_RULES_LABEL, SS_NOTIFY);
        SetChecked(IDC_AUTO_CREATE_RULES, Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false));
        const std::wstring autoRulesTip = LoadStringRes(IDS_SETTINGS_AUTO_CREATE_RULES_TIP);
        AddToolTip(autoRules, autoRulesTip);
        AddToolTip(Item(IDC_AUTO_CREATE_RULES_LABEL), autoRulesTip);

        const int fontLabelY = autoRulesY + m.checkH() + m.section();
        const int fontWidth = cw - 2 * m.gap();
        Label(LoadStringResFmt(IDS_SETTINGS_CONNECTION_FONT,
                              ListSkinSetting::Name(skin).c_str()),
              netEventsX, fontLabelY, fontWidth, m.labelH(), IDC_CONNECTION_FONT_LABEL);
        const int fontY = fontLabelY + m.labelH() + m.gapS();
        const int valueWidth = fontWidth - 2 * m.btnW() - 2 * m.gap();
        ReadOnly(L"", netEventsX, fontY + (m.btnH() - m.editH()) / 2,
                 valueWidth, m.editH(), IDC_CONNECTION_FONT_VALUE);
        HWND chooseFont = Button(LoadStringRes(IDS_SETTINGS_CONNECTION_FONT_CHOOSE),
                                 netEventsX + valueWidth + m.gap(), fontY,
                                 m.btnW(), m.btnH(), IDC_CONNECTION_FONT_CHOOSE);
        Button(LoadStringRes(IDS_BTN_RESET), netEventsX + fontWidth - m.btnW(), fontY,
               m.btnW(), m.btnH(), IDC_CONNECTION_FONT_RESET);
        const std::wstring fontTip = LoadStringRes(IDS_SETTINGS_CONNECTION_FONT_TIP);
        AddToolTip(Item(IDC_CONNECTION_FONT_LABEL), fontTip);
        AddToolTip(Item(IDC_CONNECTION_FONT_VALUE), fontTip);
        AddToolTip(chooseFont, fontTip);
        UpdateFontValue();

        const int lblW = m.Sc(52);
        Label(LoadStringRes(IDS_FILTER_LABEL), cx, cy + m.Sc(4),
              lblW, m.labelH(), IDC_FILTER_LABEL);
        Edit(L"", cx + lblW, cy, cw - lblW, m.editH(), IDC_FILTER);

        const int listY = cy + m.editH() + m.gap();
        const int btnW = m.btnW();
        // Оставляем одинаковый отступ слева и справа от колонки кнопок.
        const int buttonGap = m.gap();
        const int listW = std::max(m.Sc(120),
                                   cw - btnW - 2 * buttonGap);
        const int bx = cx + listW + buttonGap;
        int listH = cy + ch - listY - m.gapS() - m.labelH();
        if (listH < m.Sc(130)) listH = m.Sc(130);

        ListView(cx, listY, listW, listH, IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT |
                                               LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);
        ListView_SetImageList(lv, icons_.handle(), LVSIL_SMALL);

        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        col.iSubItem = 0;
        col.fmt = LVCFMT_LEFT;
        std::wstring colApp = LoadStringRes(IDS_ALLRULES_COL_APP);
        std::wstring colCount = LoadStringRes(IDS_ALLRULES_COL_COUNT);
        col.pszText = colApp.data();
        col.cx = listW - m.Sc(110);
        ListView_InsertColumn(lv, 0, &col);
        col.iSubItem = 1;
        col.fmt = LVCFMT_RIGHT;
        col.pszText = colCount.data();
        col.cx = m.Sc(84);
        ListView_InsertColumn(lv, 1, &col);

        int by = listY;
        Button(LoadStringRes(IDS_BTN_RULES), bx, by, btnW, m.btnH(), IDC_RULES, true);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_ADD_ELLIPSIS), bx, by, btnW, m.btnH(), IDC_ADD);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_DELETE), bx, by, btnW, m.btnH(), IDC_DEL);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_CLEANUP), bx, by, btnW, m.btnH(), IDC_CLEANUP);

        const int countY = listY + listH + m.gapS();
        Label(L"", cx, countY, cw, m.labelH(), IDC_COUNT);
        for (int id = IDC_FILTER_LABEL; id <= IDC_CONNECTION_FONT_RESET; ++id) {
            HWND control = Item(id);
            wchar_t cls[32]{};
            GetClassNameW(control, cls, static_cast<int>(std::size(cls)));
            const UINT type = static_cast<UINT>(GetWindowLongPtrW(control, GWL_STYLE)) & BS_TYPEMASK;
            if (_wcsicmp(cls, L"Static") == 0 ||
                (_wcsicmp(cls, L"Button") == 0 &&
                 (type == BS_AUTOCHECKBOX || type == BS_AUTO3STATE)))
                SetControlBackground(id, tabs_);
        }
        // Рамка списка рисуется самим контролом: фон вкладки закрывает рамку родителя.
        StyleField(lv);

        SetWindowSubclass(hwnd(), &SettingsDialog::InterfaceEvents, 1,
                          reinterpret_cast<DWORD_PTR>(this));
        store->WatchInterfaces(hwnd(), true);
        Fill();
        if (tabs_) {
            TabCtrl_SetCurSel(tabs_, 0);
            SwitchTab(0);
        }

        Button(LoadStringRes(IDS_BTN_CLOSE), x + w - m.btnW(),
               clientH() - m.margin() - m.btnH(), m.btnW(), m.btnH(), IDOK, true);
    }

    bool OnCommand(int id, int code) override {
        if (id == IDC_NET_EVENTS_LABEL && code == STN_CLICKED) {
            if (IsWindowEnabled(Item(IDC_NET_EVENTS)))
                SendMessageW(Item(IDC_NET_EVENTS), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_NET_EVENTS && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_NET_EVENTS);
            const DWORD status = WfpOptions::SetNetEvents(wanted);
            if (status != ERROR_SUCCESS) {
                SetChecked(IDC_NET_EVENTS, !wanted);
                const std::wstring message =
                    LoadStringResFmt(IDS_SETTINGS_NET_EVENTS_ERROR,
                                     static_cast<unsigned>(status));
                Ui::ShowMessage(hwnd(), message.c_str(),
                            LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                            MB_ICONWARNING | MB_OK);
            } else {
                changed = true;
            }
            return true;
        }

        if (id == IDC_START_WITH_WINDOWS_LABEL && code == STN_CLICKED) {
            if (IsWindowEnabled(Item(IDC_START_WITH_WINDOWS)))
                SendMessageW(Item(IDC_START_WITH_WINDOWS), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_START_WITH_WINDOWS && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_START_WITH_WINDOWS);
            const HRESULT status = StartupOptions::SetEnabled(wanted);
            if (FAILED(status)) {
                SetChecked(IDC_START_WITH_WINDOWS, !wanted);
                const std::wstring message =
                    LoadStringResFmt(IDS_SETTINGS_START_WITH_WINDOWS_ERROR,
                                     static_cast<unsigned>(status));
                Ui::ShowMessage(hwnd(), message.c_str(),
                            LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                            MB_ICONWARNING | MB_OK);
            } else {
                changed = true;
            }
            return true;
        }

        if (id == IDC_WFP_AUDIT_LABEL && code == STN_CLICKED) {
            if (IsWindowEnabled(Item(IDC_WFP_AUDIT)))
                SendMessageW(Item(IDC_WFP_AUDIT), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_WFP_AUDIT && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_WFP_AUDIT);
            const DWORD status = WfpOptions::SetAudit(wanted);
            // После записи показываем фактическое состояние, в том числе
            // если API сообщил об ошибке и часть методов осталась включена.
            bool enabled = false;
            const DWORD readStatus = WfpOptions::GetAudit(enabled);
            SyncAuditState(enabled, readStatus);
            if (status == ERROR_SUCCESS) changed = true;
            const DWORD error = status != ERROR_SUCCESS ? status : readStatus;
            if (error != ERROR_SUCCESS) {
                const UINT messageId = status != ERROR_SUCCESS
                    ? IDS_SETTINGS_WFP_AUDIT_ERROR : IDS_SETTINGS_WFP_AUDIT_READ_ERROR;
                const std::wstring message =
                    LoadStringResFmt(messageId, static_cast<unsigned>(error));
                Ui::ShowMessage(hwnd(), message.c_str(),
                            LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                            MB_ICONWARNING | MB_OK);
            }
            return true;
        }

        if (id == IDC_WINDOWS_FIREWALL_LABEL && code == STN_CLICKED) {
            if (IsWindowEnabled(Item(IDC_WINDOWS_FIREWALL)))
                SendMessageW(Item(IDC_WINDOWS_FIREWALL), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_WINDOWS_FIREWALL && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_WINDOWS_FIREWALL);
            const HRESULT status = WindowsFirewallOptions::SetEnabled(wanted);
            // Изменение профилей не атомарно: после записи читаем реальное состояние.
            bool enabled = false;
            const HRESULT readStatus = WindowsFirewallOptions::GetEnabled(enabled);
            SyncFirewallState(enabled, readStatus);
            if (SUCCEEDED(status)) changed = true;
            const HRESULT error = FAILED(status) ? status : readStatus;
            if (FAILED(error)) {
                const UINT messageId = FAILED(status)
                    ? IDS_SETTINGS_WINDOWS_FIREWALL_ERROR
                    : IDS_SETTINGS_WINDOWS_FIREWALL_READ_ERROR;
                const std::wstring message =
                    LoadStringResFmt(messageId, static_cast<unsigned>(error));
                Ui::ShowMessage(hwnd(), message.c_str(),
                            LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                            MB_ICONWARNING | MB_OK);
            }
            return true;
        }

        if (id == IDC_PRECISE_TRAFFIC_ATTRIBUTION_LABEL && code == STN_CLICKED) {
            SendMessageW(Item(IDC_PRECISE_TRAFFIC_ATTRIBUTION), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_PRECISE_TRAFFIC_ATTRIBUTION && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_PRECISE_TRAFFIC_ATTRIBUTION);
            if (!TrafficAttributionOptions::Save(wanted)) {
                SetChecked(IDC_PRECISE_TRAFFIC_ATTRIBUTION, !wanted);
                const std::wstring message = LoadStringResFmt(
                    IDS_SETTINGS_PRECISE_TRAFFIC_ATTRIBUTION_SAVE_ERROR,
                    Settings::lastError().c_str());
                Ui::ShowMessage(hwnd(), message.c_str(),
                            LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
                return true;
            }

            changed = true;
            const DWORD status = TrafficAttributionOptions::Apply(wanted);
            const UINT restartId = portmaster_service_connected()
                ? IDS_SETTINGS_PRECISE_TRAFFIC_ATTRIBUTION_RESTART_SERVICE
                : IDS_SETTINGS_PRECISE_TRAFFIC_ATTRIBUTION_RESTART_APP;
            std::wstring message = LoadStringRes(restartId);
            if (status != ERROR_SUCCESS) {
                // Настройка уже сохранена: при следующем запуске запись повторится.
                message = LoadStringResFmt(IDS_SETTINGS_PRECISE_TRAFFIC_ATTRIBUTION_REG_ERROR,
                                          static_cast<unsigned>(status)) + L"\n\n" + message;
            }
            Ui::ShowMessage(hwnd(), message.c_str(), LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                        (status == ERROR_SUCCESS ? MB_ICONINFORMATION : MB_ICONWARNING) | MB_OK);
            return true;
        }

        if (id == IDC_MUTE_MESSAGE_BEEP_LABEL && code == STN_CLICKED) {
            SendMessageW(Item(IDC_MUTE_MESSAGE_BEEP), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_MUTE_MESSAGE_BEEP && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_MUTE_MESSAGE_BEEP);
            if (!Settings::SetBool(Settings::Key::kMuteMessageBeep, wanted)) {
                SetChecked(IDC_MUTE_MESSAGE_BEEP, !wanted);
                const std::wstring message = LoadStringResFmt(
                    IDS_SETTINGS_MUTE_MESSAGE_BEEP_SAVE_ERROR, Settings::lastError().c_str());
                Ui::ShowMessage(hwnd(), message.c_str(),
                                LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
            } else {
                changed = true;
            }
            return true;
        }

        if (id == IDC_SYSTEM_SCALING_LABEL && code == STN_CLICKED) {
            SendMessageW(Item(IDC_SYSTEM_SCALING), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_SYSTEM_SCALING && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_SYSTEM_SCALING);
            if (!Settings::SetBool(Settings::Key::kSystemDpiScaling, wanted)) {
                SetChecked(IDC_SYSTEM_SCALING, !wanted);
                const std::wstring message = LoadStringResFmt(
                    IDS_SETTINGS_SYSTEM_SCALING_SAVE_ERROR, Settings::lastError().c_str());
                Ui::ShowMessage(hwnd(), message.c_str(),
                                LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
            } else {
                changed = true;
            }
            return true;
        }

        if (id == IDC_DLL_PROTECTION_LABEL && code == STN_CLICKED) {
            SendMessageW(Item(IDC_DLL_PROTECTION), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_DLL_PROTECTION && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_DLL_PROTECTION);
            if (!ProcessProtectionOptions::Save(wanted)) {
                SetChecked(IDC_DLL_PROTECTION, !wanted);
                const std::wstring message = LoadStringResFmt(
                    IDS_SETTINGS_DLL_PROTECTION_SAVE_ERROR, Settings::lastError().c_str());
                Ui::ShowMessage(hwnd(), message.c_str(),
                                LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
            } else {
                changed = true;
                Ui::ShowMessage(hwnd(), LoadStringRes(IDS_SETTINGS_DLL_PROTECTION_RESTART).c_str(),
                                LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONINFORMATION | MB_OK);
            }
            return true;
        }

        if (id == IDC_AUTO_CREATE_RULES_LABEL && code == STN_CLICKED) {
            SendMessageW(Item(IDC_AUTO_CREATE_RULES), BM_CLICK, 0, 0);
            return true;
        }

        if (id == IDC_AUTO_CREATE_RULES && code == BN_CLICKED) {
            const bool wanted = Checked(IDC_AUTO_CREATE_RULES);
            if (!Settings::SetBool(Settings::Key::kAutoCreatePresetRules, wanted)) {
                SetChecked(IDC_AUTO_CREATE_RULES, !wanted);
                const std::wstring message = LoadStringResFmt(
                    IDS_SETTINGS_AUTO_CREATE_RULES_SAVE_ERROR, Settings::lastError().c_str());
                Ui::ShowMessage(hwnd(), message.c_str(),
                                LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
            } else {
                changed = true;
            }
            return true;
        }

        if (id == IDC_CONNECTION_FONT_CHOOSE && code == BN_CLICKED) {
            ChooseConnectionFont();
            return true;
        }

        if (id == IDC_CONNECTION_FONT_RESET && code == BN_CLICKED) {
            if (ListFontSetting::Reset(skin)) FontChanged();
            else FontSaveError();
            return true;
        }

        if (id == IDC_FILTER && code == EN_CHANGE) {
            Fill(true);
            return true;
        }

        switch (id) {
        case IDC_RULES: {
            const int sel = Selected();
            if (sel < 0) return true;
            const AppEntry e = shown_[static_cast<size_t>(sel)];
            if (AppRulesEditor::Run(hwnd(), inst(), *store, e.path, e.name,
                                    e.global, e.postapp, e.interfaceGroup)) {
                StoreChanged();
                Fill();
            }
            return true;
        }
        case IDC_ADD: {
            std::wstring path = BrowseExe();
            if (path.empty()) return true;
            if (AppRulesEditor::Run(hwnd(), inst(), *store, path,
                                    PathBaseUpper(path), false)) {
                StoreChanged();
                Fill();
            }
            return true;
        }
        case IDC_DEL: {
            const int sel = Selected();
            if (sel < 0) return true;
            const AppEntry e = shown_[static_cast<size_t>(sel)];
            if (e.rules == 0 && (e.global || e.postapp || e.interfaceGroup)) return true;

            // Здесь подтверждение остаётся: удаляются СРАЗУ все правила
            // выбранной группы и отменить это действие уже нельзя.
            std::wstring question;
            if (e.global) {
                question = LoadStringResFmt(IDS_ALLRULES_DEL_GLOBAL_FMT,
                                             static_cast<unsigned>(e.rules));
            } else if (e.postapp) {
                question = LoadStringResFmt(IDS_ALLRULES_DEL_POSTAPP_FMT,
                                             static_cast<unsigned>(e.rules));
            } else if (e.interfaceGroup) {
                question = LoadStringResFmt(IDS_INTERFACE_DELETE_FMT, e.name.c_str(),
                                           static_cast<unsigned>(e.rules));
            } else {
                question = LoadStringResFmt(IDS_ALLRULES_DEL_APP_FMT,
                                             e.name.c_str(), e.path.c_str(),
                                             static_cast<unsigned>(e.rules));
            }
            if (Ui::ShowMessage(hwnd(), question.c_str(),
                            LoadStringRes(IDS_RULE_EDITOR_TITLE).c_str(),
                            MB_ICONWARNING | MB_YESNO) != IDYES)
                return true;

            if (e.global)       store->RemoveGlobals();
            else if (e.postapp) store->RemovePostApps();
            else if (e.interfaceGroup)  store->Replace(RuleScope::Interface, e.path, e.name, {});
            else                store->RemoveApp(e.path);
            StoreChanged();
            Fill();
            SetFocus(Item(IDC_LIST));
            return true;
        }
        case IDC_CLEANUP: {
            if (Ui::ShowMessage(hwnd(), LoadStringRes(IDS_ALLRULES_CLEANUP_CONFIRM).c_str(),
                                LoadStringRes(IDS_CONFIRM_TITLE).c_str(),
                                MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
                return true;
            if (store->RemoveMissingApps() != 0) StoreChanged();
            Fill();
            SetFocus(Item(IDC_LIST));
            return true;
        }
        default:
            return false;
        }
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
        if (hdr->idFrom == IDC_TABS && hdr->code == TCN_SELCHANGE) {
            SwitchTab(TabCtrl_GetCurSel(tabs_));
            res = 0;
            return true;
        }

        if (hdr->idFrom != IDC_LIST) return false;

        switch (hdr->code) {
        case NM_DBLCLK:
            OnCommand(IDC_RULES, 0);
            res = 0;
            return true;

        // Del в списке равнозначен кнопке «Удалить».
        case LVN_KEYDOWN: {
            auto* kd = reinterpret_cast<LPNMLVKEYDOWN>(hdr);
            if (kd->wVKey == VK_DELETE) {
                OnCommand(IDC_DEL, 0);
                res = 0;
                return true;
            }
            return false;
        }
        case NM_CUSTOMDRAW: {
            auto* cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(hdr);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) {
                res = CDRF_NOTIFYITEMDRAW;
                return true;
            }
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                res = CDRF_NOTIFYSUBITEMDRAW;
                return true;
            }
            if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
                const int i = static_cast<int>(cd->nmcd.dwItemSpec);
                const bool valid = i >= 0 && i < static_cast<int>(shown_.size());
                const bool off = valid && shown_[static_cast<size_t>(i)].rules > 0 &&
                                 shown_[static_cast<size_t>(i)].enabled == 0;
                // Имя приложения выглядит ссылкой, счётчик остаётся обычным текстом.
                cd->clrTextBk = i & 1 ? colors().alternate : colors().surface;
                if (valid && shown_[static_cast<size_t>(i)].interfaceGroup &&
                    !shown_[static_cast<size_t>(i)].active)
                    cd->clrText = colors().block;
                else if (cd->iSubItem == 0)
                    cd->clrText = off ? colors().secondary : GetSysColor(COLOR_HOTLIGHT);
                else
                    cd->clrText = colors().text;
                res = CDRF_NEWFONT;
                return true;
            }
            res = CDRF_DODEFAULT;
            return true;
        }
        case LVN_GETINFOTIPW: {
            auto* tip = reinterpret_cast<LPNMLVGETINFOTIPW>(hdr);
            if (tip->iItem >= 0 && tip->iItem < static_cast<int>(shown_.size()) &&
                tip->pszText && tip->cchTextMax > 1) {
                const AppEntry& e = shown_[static_cast<size_t>(tip->iItem)];
                std::wstring text;
                if (e.global)
                    text = LoadStringRes(IDS_ALLRULES_GLOBAL_DESC);
                else if (e.postapp)
                    text = LoadStringRes(IDS_ALLRULES_POSTAPP_DESC);
                else if (e.interfaceGroup) {
                    text = LoadStringRes(IDS_INTERFACE_DESC);
                    if (!e.active) text += L"\n" + LoadStringRes(IDS_INTERFACE_INACTIVE);
                }
                else
                    text = e.path;
                wcsncpy_s(tip->pszText, static_cast<size_t>(tip->cchTextMax),
                          text.c_str(), _TRUNCATE);
            }
            res = 0;
            return true;
        }
        case LVN_ITEMCHANGED: {
            auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
            if ((nl->uChanged & LVIF_STATE) &&
                ((nl->uOldState ^ nl->uNewState) & LVIS_SELECTED))
                SyncSelection();
            res = 0;
            return true;
        }
        default:
            return false;
        }
    }

private:
    static LRESULT CALLBACK InterfaceEvents(HWND window, UINT message, WPARAM wp,
                                            LPARAM lp, UINT_PTR id, DWORD_PTR data) {
        auto* self = reinterpret_cast<SettingsDialog*>(data);
        if (message == RuleStore::kInterfacesChanged) {
            if (self->InterfacesTab()) self->Fill();
            return 0;
        }
        if (message == WM_NCDESTROY) {
            self->store->WatchInterfaces(window, false);
            RemoveWindowSubclass(window, &SettingsDialog::InterfaceEvents, id);
        }
        return DefSubclassProc(window, message, wp, lp);
    }

    bool InterfacesTab() const { return tabs_ && TabCtrl_GetCurSel(tabs_) == 2; }

    HWND tabs_ = nullptr;
    HWND list_ = nullptr;
    Ui::IconCache icons_;
    std::vector<AppEntry> shown_;
    HWND tooltip_ = nullptr;
    std::deque<std::wstring> tooltipTexts_;

    void AddToolTip(HWND item, const std::wstring& text) {
        if (!item) return;
        // Адреса текстов подсказок должны оставаться действительными
        // до закрытия окна, в том числе при добавлении новой подсказки.
        tooltipTexts_.push_back(text);
        if (!tooltip_) {
            tooltip_ = CreateWindowExW(WS_EX_TOPMOST | Ui::LayoutStyle(), TOOLTIPS_CLASSW, nullptr,
                                       WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                                       CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                                       hwnd(), nullptr, inst(), nullptr);
            if (!tooltip_) return;
            SendMessageW(tooltip_, TTM_SETMAXTIPWIDTH, 0, M().Sc(420));
        }

        TOOLINFOW ti{};
        ti.cbSize = sizeof(ti);
        ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
        ti.hwnd = hwnd();
        ti.uId = reinterpret_cast<UINT_PTR>(item);
        ti.lpszText = tooltipTexts_.back().data();
        SendMessageW(tooltip_, TTM_ADDTOOLW, 0,
                     reinterpret_cast<LPARAM>(&ti));
    }

    void UpdateFontValue() {
        const auto value = ListFontSetting::Load(skin, M().dpi);
        std::wstring size = std::to_wstring(value.sizeTenths / 10);
        if (value.sizeTenths % 10)
            size += L"." + std::to_wstring(value.sizeTenths % 10);
        SetText(IDC_CONNECTION_FONT_VALUE,
                LoadStringResFmt(IDS_SETTINGS_CONNECTION_FONT_VALUE_FMT,
                                 Ui::LtrText(value.face).c_str(), Ui::LtrText(size).c_str()));
    }

    void FontSaveError() {
        const std::wstring message = LoadStringResFmt(
            IDS_SETTINGS_CONNECTION_FONT_SAVE_ERROR, Settings::lastError().c_str());
        Ui::ShowMessage(hwnd(), message.c_str(), LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                        MB_ICONWARNING | MB_OK);
    }

    void FontChanged() {
        changed = true;
        UpdateFontValue();
        if (onFontChanged) onFontChanged();
    }

    void ChooseConnectionFont() {
        const auto current = ListFontSetting::Load(skin, M().dpi);
        LOGFONTW font = ListFontSetting::Resolve(skin, M().dpi);
        font.lfUnderline = font.lfStrikeOut = FALSE;
        CHOOSEFONTW choice{};
        choice.lStructSize = sizeof(choice);
        choice.hwndOwner = hwnd();
        choice.lpLogFont = &font;
        choice.iPointSize = current.sizeTenths;
        choice.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT | CF_FORCEFONTEXIST |
                       CF_SCALABLEONLY | CF_NOVERTFONTS | CF_LIMITSIZE;
        choice.nSizeMin = ListFontSetting::kMinPointSize;
        choice.nSizeMax = ListFontSetting::kMaxPointSize;
        if (!ChooseFontW(&choice)) {
            const DWORD error = CommDlgExtendedError();
            if (error) {
                const std::wstring message = LoadStringResFmt(
                    IDS_SETTINGS_CONNECTION_FONT_CHOOSE_ERROR, static_cast<unsigned>(error));
                Ui::ShowMessage(hwnd(), message.c_str(), LoadStringRes(IDS_SETTINGS_TITLE).c_str(),
                                MB_ICONWARNING | MB_OK);
            }
            return;
        }

        const ListFontSetting::Value wanted{font.lfFaceName, choice.iPointSize,
                                            font.lfWeight, font.lfItalic != FALSE};
        if (wanted == current) return;
        if (ListFontSetting::Save(skin, wanted)) FontChanged();
        else FontSaveError();
    }

    void SyncAuditState(bool enabled, DWORD status) {
        const bool known = status == ERROR_SUCCESS;
        HWND check = Item(IDC_WFP_AUDIT);
        SendMessageW(check, BM_SETSTYLE,
                     known ? BS_AUTOCHECKBOX : BS_AUTO3STATE, TRUE);
        SendMessageW(check, BM_SETCHECK,
                     known ? (enabled ? BST_CHECKED : BST_UNCHECKED) : BST_INDETERMINATE, 0);
        Enable(IDC_WFP_AUDIT, known);
        Enable(IDC_WFP_AUDIT_LABEL, known);
    }

    void SyncFirewallState(bool enabled, HRESULT status) {
        const bool known = SUCCEEDED(status);
        HWND check = Item(IDC_WINDOWS_FIREWALL);
        SendMessageW(check, BM_SETSTYLE,
                     known ? BS_AUTOCHECKBOX : BS_AUTO3STATE, TRUE);
        SendMessageW(check, BM_SETCHECK,
                     known ? (enabled ? BST_CHECKED : BST_UNCHECKED) : BST_INDETERMINATE, 0);
        Enable(IDC_WINDOWS_FIREWALL, known);
        Enable(IDC_WINDOWS_FIREWALL_LABEL, known);
    }

    void StoreChanged() {
        changed = true;
        if (onRulesChanged) onRulesChanged();
    }

    void SwitchTab(int index) {
        const bool rules = index == 1 || index == 2;
        const int generalIds[] = { IDC_NET_EVENTS, IDC_NET_EVENTS_LABEL,
                                   IDC_START_WITH_WINDOWS,
                                   IDC_START_WITH_WINDOWS_LABEL,
                                   IDC_WFP_AUDIT, IDC_WFP_AUDIT_LABEL,
                                   IDC_WINDOWS_FIREWALL, IDC_WINDOWS_FIREWALL_LABEL,
                                   IDC_PRECISE_TRAFFIC_ATTRIBUTION,
                                   IDC_PRECISE_TRAFFIC_ATTRIBUTION_LABEL,
                                   IDC_MUTE_MESSAGE_BEEP, IDC_MUTE_MESSAGE_BEEP_LABEL,
                                   IDC_SYSTEM_SCALING, IDC_SYSTEM_SCALING_LABEL,
                                   IDC_DLL_PROTECTION, IDC_DLL_PROTECTION_LABEL,
                                   IDC_AUTO_CREATE_RULES, IDC_AUTO_CREATE_RULES_LABEL,
                                   IDC_CONNECTION_FONT_LABEL, IDC_CONNECTION_FONT_VALUE,
                                   IDC_CONNECTION_FONT_CHOOSE, IDC_CONNECTION_FONT_RESET };
        for (int id : generalIds) {
            if (HWND item = Item(id)) ShowWindow(item, rules ? SW_HIDE : SW_SHOW);
        }

        const int ids[] = { IDC_FILTER_LABEL, IDC_FILTER, IDC_LIST, IDC_RULES,
                            IDC_ADD, IDC_DEL, IDC_CLEANUP, IDC_COUNT };
        for (int id : ids) {
            if (HWND item = Item(id)) ShowWindow(item, rules ? SW_SHOW : SW_HIDE);
        }
        ShowWindow(Item(IDC_ADD), index == 1 ? SW_SHOW : SW_HIDE);
        ShowWindow(Item(IDC_CLEANUP), index == 1 ? SW_SHOW : SW_HIDE);
        if (rules) Fill(true);
    }

    int Selected() const {
        HWND lv = Item(IDC_LIST);
        const int i = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
        return (i >= 0 && i < static_cast<int>(shown_.size())) ? i : -1;
    }

    void Fill(bool resetScroll = false) {
        const int selectedRow = Selected();
        const AppEntry selected = selectedRow >= 0 ? shown_[static_cast<size_t>(selectedRow)] : AppEntry{};
        const std::wstring filter = FoldCaseCopy(Text(IDC_FILTER));
        const bool interfaces = InterfacesTab();
        const std::vector<AppEntry> all = interfaces ? store->Interfaces() : store->Apps();
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT;
        std::wstring title = LoadStringRes(interfaces ? IDS_INTERFACE_COLUMN : IDS_ALLRULES_COL_APP);
        column.pszText = title.data();
        ListView_SetColumn(Item(IDC_LIST), 0, &column);

        shown_.clear();
        for (const AppEntry& e : all) {
            if (!filter.empty() &&
                FoldCaseCopy(e.name).find(filter) == std::wstring::npos &&
                FoldCaseCopy(e.path).find(filter) == std::wstring::npos)
                continue;
            shown_.push_back(e);
        }

        RuleGroupListUi::Fill(Item(IDC_LIST), icons_, shown_,
                              selectedRow >= 0 ? &selected : nullptr, resetScroll);

        // Фильтр может скрыть специальные группы, поэтому считаем приложения
        // отдельно в полном и отфильтрованном списках.
        const auto isApp = [](const AppEntry& e) { return !e.global && !e.postapp && !e.interfaceGroup; };
        const size_t apps = std::count_if(all.begin(), all.end(), isApp);
        const size_t listed = std::count_if(shown_.begin(), shown_.end(), isApp);
        if (interfaces) {
            size_t count = 0;
            for (const auto& entry : all) count += entry.rules;
            SetText(IDC_COUNT, LoadStringResFmt(IDS_INTERFACE_STATS_FMT,
                static_cast<unsigned>(shown_.size()), static_cast<unsigned>(all.size()),
                static_cast<unsigned>(count)));
        } else SetText(IDC_COUNT, LoadStringResFmt(IDS_ALLRULES_STATS_FMT,
                                            static_cast<unsigned>(listed),
                                            static_cast<unsigned>(apps),
                                            static_cast<unsigned>(store->Count()),
                                            static_cast<unsigned>(store->GlobalCount()),
                                            static_cast<unsigned>(store->PostAppCount())));
        SyncSelection();
    }

    void SyncSelection() {
        const int sel = Selected();
        const bool has = sel >= 0;
        Enable(IDC_RULES, has);
        const AppEntry* entry = has ? &shown_[static_cast<size_t>(sel)] : nullptr;
        Enable(IDC_DEL, entry &&
                       (entry->rules > 0 || (!entry->global && !entry->postapp && !entry->interfaceGroup)));
    }

    std::wstring BrowseExe() {
        wchar_t buf[MAX_PATH * 2]{};
        // В ресурсе фильтр хранится с разделителями «|»; перед вызовом
        // GetOpenFileNameW преобразуем их в нули формата lpstrFilter.
        std::wstring filter = LoadStringRes(IDS_ALLRULES_FILE_FILTER);
        for (wchar_t& ch : filter) if (ch == L'|') ch = L'\0';
        filter.push_back(L'\0');

        const std::wstring title = LoadStringRes(IDS_ALLRULES_CHOOSE_APP);
        OPENFILENAMEW ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd();
        ofn.lpstrFilter = filter.c_str();
        ofn.lpstrFile = buf;
        ofn.nMaxFile = static_cast<DWORD>(std::size(buf));
        ofn.lpstrTitle = title.c_str();
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
        return GetOpenFileNameW(&ofn) ? std::wstring(buf) : std::wstring();
    }
};

} // namespace

bool SettingsWindow::Run(HWND owner, HINSTANCE inst, RuleStore& store, ListSkin skin,
                         const std::function<void()>& onRulesChanged,
                         const std::function<void()>& onFontChanged) {
    SettingsDialog d;
    d.store = &store;
    d.skin = skin;
    d.onRulesChanged = onRulesChanged;
    d.onFontChanged = onFontChanged;
    d.Run(owner, inst, LoadStringRes(IDS_SETTINGS_TITLE), 760, 705);
    return d.changed;
}
