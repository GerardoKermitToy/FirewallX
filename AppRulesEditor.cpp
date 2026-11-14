#include "AppRulesEditor.h"
#include "RuleDialogs.h"
#include "RuleEditor.h"
#include "RuleInheritanceUi.h"
#include "RuleInterfaceUi.h"
#include "NdisBinding.h"
#include "network_interface_watcher.h"
#include "NdisTransport.h"
#include "Settings.h"
#include "StringRes.h"
#include "UiKit.h"
#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>
#include <memory>

namespace {

// Список правил и расшифровка используют общие метрики редакторов.
class Editor : public Ui::Modal {
public:
    std::wstring appPath, appName;
    bool global = false;
    bool postapp = false;
    bool interfaceGroup = false;
    uint64_t selectedRuleId = 0;
    std::vector<Rule> rules;
    bool inheritanceAvailable = false;
    RuleInheritance inheritance = RuleInheritance::Default;
    bool preferredInterfaceAvailable = false;
    std::wstring preferredInterface;
    bool blockOtherInterfaces = false;
    bool interfaceBindingAvailable = false;
    bool excludeTransit = false;
    bool originalExcludeTransit = false;
    bool reverseTraffic = false;
    bool originalReverseTraffic = false;

protected:
    enum {
        IDC_LIST = 400, IDC_NEW, IDC_EDIT, IDC_DUP, IDC_DEL,
        IDC_UP, IDC_DOWN, IDC_ORDER, IDC_SCOPE, IDC_EXPLAIN, IDC_INHERITANCE, IDC_INHERITANCE_NEVER,
        IDC_PREFERRED_INTERFACE, IDC_EXCLUDE_TRANSIT, IDC_BLOCK_OTHER_INTERFACES, IDC_REVERSE_TRAFFIC
    };

    bool ModernStyle() const override { return true; }
    bool StyledFooter() const override { return true; }
    int InitialFocusId() const override { return rules.empty() ? IDC_NEW : IDC_LIST; }

    void OnInit() override {
        const auto& m = M();
        interfaces_.Watch(hwnd(), [this] {
            interfaces_.Refresh(rules);
            RefreshPreferredInterfaces();
            InvalidateRect(Item(IDC_LIST), nullptr, TRUE);
        });

        UINT headerStrId, descStrId;
        if (interfaceGroup) {
            headerStrId = 0;
            descStrId = IDS_INTERFACE_DESC;
        } else if (global) {
            headerStrId = IDS_APPED_GLOBAL_HEADER;
            descStrId = IDS_APPED_GLOBAL_DESC;
        } else if (postapp) {
            headerStrId = IDS_RULE_POSTAPP_APP;
            descStrId = IDS_APPED_POSTAPP_DESC;
        } else {
            headerStrId = 0;
            descStrId = IDS_APPED_APP_DESC;
        }

        SetHeaderApp(interfaceGroup ? std::wstring() : appPath,
                     (global || postapp) ? LoadStringRes(headerStrId) : appName,
                     LoadStringRes(descStrId));

        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = headerH() + m.margin();

        if (interfaceGroup) {
            Check(LoadStringRes(IDS_INTERFACE_EXCLUDE_TRANSIT), x, y, w, m.editH(), IDC_EXCLUDE_TRANSIT);
            SetChecked(IDC_EXCLUDE_TRANSIT, excludeTransit);
            Enable(IDC_EXCLUDE_TRANSIT, interfaceBindingAvailable);
            y += m.editH() + m.gapS();
            Check(LoadStringRes(IDS_INTERFACE_REVERSE_TRAFFIC), x, y, w, m.editH(), IDC_REVERSE_TRAFFIC);
            SetChecked(IDC_REVERSE_TRAFFIC, reverseTraffic);
            Enable(IDC_REVERSE_TRAFFIC, interfaceBindingAvailable);
            y += m.editH() + m.section();
        }
        if (preferredInterfaceAvailable) {
            y += SectionHeader(LoadStringRes(IDS_APP_INTERFACE_LABEL), x, y, w);
            Combo(x, y, w, m.editH() * 8, IDC_PREFERRED_INTERFACE);
            y += m.editH() + m.gapS();
            Check(LoadStringRes(IDS_APP_INTERFACE_BLOCK_OTHERS), x, y, w, m.editH(), IDC_BLOCK_OTHER_INTERFACES);
            SetChecked(IDC_BLOCK_OTHER_INTERFACES, blockOtherInterfaces);
            Enable(IDC_BLOCK_OTHER_INTERFACES, !preferredInterface.empty());
            y += m.editH() + m.section();
            RefreshPreferredInterfaces();
        }
        if (inheritanceAvailable) {
            y += SectionHeader(LoadStringRes(IDS_INHERITANCE_SECTION), x, y, w);
            y += CheckPair(LoadStringRes(IDS_INHERITANCE_ENABLED), LoadStringRes(IDS_INHERITANCE_NEVER),
                           x, y, w, IDC_INHERITANCE, IDC_INHERITANCE_NEVER);
            RuleInheritanceUi::Set(Item(IDC_INHERITANCE), Item(IDC_INHERITANCE_NEVER), inheritance);
            y += m.gapS();
            const std::wstring note = LoadStringRes(IDS_INHERITANCE_NOTE);
            const int noteH = std::max(m.labelH(), TextHeight(note, w));
            Note(note, x, y, w, noteH);
            y += noteH + m.section();
        }
        y += SectionHeader(LoadStringRes(IDS_APPED_SECTION_RULES), x, y, w);

        // Высоту списка считаем от остатка: нижние блоки фиксированы, всё
        // свободное место достаётся списку — пустых провалов не остаётся.
        const int btnW     = m.btnW();
        const int listW    = w - btnW - m.gap();
        const int okTop    = clientH() - m.margin() - m.btnH();
        const int explainH = m.Sc(126);
        const int capH     = m.labelH() + m.gapS();
        const int navH     = m.btnH() + m.section();
        int listH = okTop - m.section() - y - (navH + capH + explainH);
        if (listH < m.Sc(130)) listH = m.Sc(130);

        ListView(x, y, listW, listH, IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        ListView_SetBkColor(lv, colors().surface);
        ListView_SetTextBkColor(lv, colors().surface);
        if (HWND header = ListView_GetHeader(lv))
            SendMessageW(header, WM_SETFONT, reinterpret_cast<WPARAM>(semibold()), TRUE);
        const struct { UINT id; int w; int fmt; } cols[] = {
            { IDS_APPED_COL_NUM,    44, LVCFMT_LEFT },
            { IDS_APPED_COL_RULE,    0, LVCFMT_LEFT },
            { IDS_APPED_COL_ACTION, 96, LVCFMT_LEFT },
        };
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        for (int i = 0; i < 3; ++i) {
            std::wstring title = LoadStringRes(cols[i].id);
            col.iSubItem = i;
            col.fmt = cols[i].fmt;
            col.pszText = title.data();
            col.cx = cols[i].w ? m.Sc(cols[i].w)
                               : listW - m.Sc(44) - m.Sc(96) - m.Sc(26);
            ListView_InsertColumn(lv, i, &col);
        }

        int by = y;
        const int bx = x + listW + m.gap();
        Button(LoadStringRes(IDS_BTN_NEW),    bx, by, btnW, m.btnH(), IDC_NEW);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_EDIT),   bx, by, btnW, m.btnH(), IDC_EDIT);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_COPY),   bx, by, btnW, m.btnH(), IDC_DUP);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_DELETE), bx, by, btnW, m.btnH(), IDC_DEL);
        y += listH + m.gap();

        const int navW = m.btnWNarrow();
        Button(LoadStringRes(IDS_BTN_UP),   x, y, navW, m.btnH(), IDC_UP);
        Button(LoadStringRes(IDS_BTN_DOWN), x + navW + m.gap(), y,
               navW, m.btnH(), IDC_DOWN);
        // Вторичная подпись занимает оставшееся место справа от кнопок;
        // слишком длинный текст обрезается с многоточием в Ui::Modal::Note.
        Note(LoadStringRes(IDS_APPED_HINT_ORDER),
             x + 2 * (navW + m.gap()) + m.gap(), y + m.Sc(6),
             w - 2 * (navW + m.gap()) - m.gap(), m.labelH(), IDC_ORDER);
        y += m.btnH() + m.section();

        // Заголовок второго раздела и приоритет выбранного правила стоят на
        // одной линии: линия-разделитель заполняет промежуток между ними.
        const int noteW = m.Sc(214);
        const int capY = y;
        y += SectionHeader(LoadStringRes(IDS_APPED_SECTION_EXPLAIN),
                           x, capY, w - noteW - m.gap());
        Note(L"", x + w - noteW, capY, noteW, m.labelH(), IDC_SCOPE, SS_RIGHT);

        Link(x, y, w, explainH, IDC_EXPLAIN);
        FitFooter(y + explainH + m.gap());

        Fill();
        if (!rules.empty()) {
            const auto selected = std::find_if(rules.begin(), rules.end(), [this](const Rule& rule) {
                return selectedRuleId != 0 && rule.id == selectedRuleId;
            });
            SelectRow(selected == rules.end() ? 0 : static_cast<int>(selected - rules.begin()));
        }
        OkCancel();
    }

    bool OnCommand(int id, int code) override {
        switch (id) {
        case IDC_REVERSE_TRAFFIC:
            if (code == BN_CLICKED) reverseTraffic = Checked(id);
            return true;
        case IDC_EXCLUDE_TRANSIT:
            if (code == BN_CLICKED) excludeTransit = Checked(id);
            return true;
        case IDC_BLOCK_OTHER_INTERFACES:
            if (code == BN_CLICKED) blockOtherInterfaces = Checked(id);
            return true;
        case IDC_PREFERRED_INTERFACE:
            if (code == CBN_SELCHANGE) {
                const LRESULT selected = SendMessageW(Item(id), CB_GETCURSEL, 0, 0);
                if (selected >= 0 && static_cast<size_t>(selected) < preferredChoices_.size()) {
                    preferredInterface = preferredChoices_[static_cast<size_t>(selected)];
                    Enable(IDC_BLOCK_OTHER_INTERFACES, !preferredInterface.empty());
                }
            }
            return true;
        case IDC_INHERITANCE:
        case IDC_INHERITANCE_NEVER:
            if (code == BN_CLICKED)
                inheritance = RuleInheritanceUi::Selected(Item(IDC_INHERITANCE), Item(IDC_INHERITANCE_NEVER));
            return true;
        case IDC_NEW: {
            Rule r;
            if (interfaceGroup)
                r.scope = RuleScope::Interface;
            else if (global)
                r.scope = RuleScope::Global;
            else if (postapp)
                r.scope = RuleScope::PostApp;
            else
                r.scope = RuleScope::App;
            r.appPath = (global || postapp) ? std::wstring() : appPath;
            r.appName = appName;
            r.proto   = Proto::Tcp;
            r.dir     = Dir::Out;
            // CondProto задан явно: снятое условие означало бы «любой протокол»,
            // а новое правило разумнее начинать с конкретного.
            r.conds   = CondProto | CondDirection;
            r.action  = RuleAction::Allow;
            r.enabled = true;
            r.autoName = true;
            r.priority = static_cast<int>(rules.size());
            r.SyncName();
            if (RuleEditor::Run(hwnd(), inst(), r, false, {},
                                inheritanceAvailable ? &inheritance : nullptr)) {
                SyncInheritance();
                rules.push_back(r);
                Fill();
                SelectRow(static_cast<int>(rules.size()) - 1);
            }
            return true;
        }
        case IDC_EDIT: {
            const int sel = Selected();
            if (sel < 0) return true;
            Rule r = rules[static_cast<size_t>(sel)];
            if (RuleEditor::Run(hwnd(), inst(), r, true, {},
                                inheritanceAvailable ? &inheritance : nullptr)) {
                SyncInheritance();
                rules[static_cast<size_t>(sel)] = r;
                Fill();
                SelectRow(sel);
            }
            return true;
        }
        case IDC_DUP: {
            const int sel = Selected();
            if (sel < 0) return true;
            Rule r = rules[static_cast<size_t>(sel)];
            r.id = 0;                                  // копия — новое правило
            if (r.autoName) r.SyncName();
            else            r.name += LoadStringRes(IDS_APPED_COPY_SUFFIX);
            rules.insert(rules.begin() + sel + 1, r);
            Fill();
            SelectRow(sel + 1);
            return true;
        }
        case IDC_DEL: {
            const int sel = Selected();
            if (sel < 0) return true;
            // Подтверждения нет: правки живут в локальном списке и попадают
            // в хранилище только по «OK», а «Отмена» отбрасывает их целиком.
            // Удаляем только одну строку, чтобы не сбрасывать прокрутку списка.
            HWND lv = Item(IDC_LIST);
            loading_ = true;
            SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
            rules.erase(rules.begin() + sel);
            interfaces_.Refresh(rules);
            ListView_DeleteItem(lv, sel);
            for (int row = sel; row < static_cast<int>(rules.size()); ++row) {
                rules[static_cast<size_t>(row)].priority = row;
                const std::wstring num = std::to_wstring(row + 1);
                ListView_SetItemText(lv, row, 0, const_cast<LPWSTR>(num.c_str()));
            }
            SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
            InvalidateRect(lv, nullptr, TRUE);
            loading_ = false;
            SelectRow(sel < static_cast<int>(rules.size())
                        ? sel : static_cast<int>(rules.size()) - 1);
            return true;
        }
        case IDC_UP:
        case IDC_DOWN: {
            const int sel = Selected();
            if (sel < 0) return true;
            const int dst = sel + (id == IDC_UP ? -1 : 1);
            if (dst < 0 || dst >= static_cast<int>(rules.size())) return true;
            std::swap(rules[static_cast<size_t>(sel)], rules[static_cast<size_t>(dst)]);
            Fill();
            SelectRow(dst);
            return true;
        }
        default:
            (void)code;
            return false;
        }
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
        if (hdr->idFrom == IDC_EXPLAIN &&
            (hdr->code == NM_CLICK || hdr->code == NM_RETURN)) {
            const int sel = Selected();
            if (sel >= 0) {
                auto* link = reinterpret_cast<PNMLINK>(hdr);
                Rule& r = rules[static_cast<size_t>(sel)];
                if (RuleDialogs::FollowLink(hwnd(), inst(), r, link->item.szID)) {
                    if (r.autoName) r.SyncName();
                    Fill();
                    SelectRow(sel);
                }
            }
            res = 0;
            return true;
        }
        if (hdr->idFrom == IDC_LIST && hdr->code == NM_CUSTOMDRAW) {
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
                const int row = static_cast<int>(cd->nmcd.dwItemSpec);
                const bool selected = (ListView_GetItemState(Item(IDC_LIST), row, LVIS_SELECTED) &
                                       LVIS_SELECTED) != 0;
                if (!selected && row >= 0 && row < static_cast<int>(rules.size())) {
                    const Rule& rule = rules[static_cast<size_t>(row)];
                    cd->clrTextBk = row & 1 ? colors().alternate : colors().surface;
                    cd->clrText = !rule.enabled ? colors().secondary
                        : cd->iSubItem == 2 ? (rule.blocks() ? colors().block : colors().allow)
                                           : colors().text;
                    if (cd->iSubItem == 2) SelectObject(cd->nmcd.hdc, semibold());
                }
                if (row >= 0 && row < static_cast<int>(rules.size()) &&
                    interfaces_.Unavailable(rules[static_cast<size_t>(row)]))
                    cd->clrText = colors().block;
                res = CDRF_NEWFONT;
                return true;
            }
            res = CDRF_DODEFAULT;
            return true;
        }
        if (hdr->idFrom == IDC_LIST && hdr->code == NM_DBLCLK) {
            OnCommand(IDC_EDIT, 0);
            res = 0;
            return true;
        }
        // Del в списке равнозначен кнопке «Удалить»
        if (hdr->idFrom == IDC_LIST && hdr->code == LVN_KEYDOWN) {
            auto* kd = reinterpret_cast<LPNMLVKEYDOWN>(hdr);
            if (kd->wVKey == VK_DELETE) {
                OnCommand(IDC_DEL, 0);
                res = 0;
                return true;
            }
            return false;
        }
        if (hdr->idFrom == IDC_LIST && hdr->code == LVN_ITEMCHANGED) {
            auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
            if (!loading_ && (nl->uChanged & LVIF_STATE)) {
                if ((nl->uOldState ^ nl->uNewState) & LVIS_STATEIMAGEMASK) {
                    const bool on = ((nl->uNewState & LVIS_STATEIMAGEMASK) >> 12) == 2;
                    if (nl->iItem >= 0 && nl->iItem < static_cast<int>(rules.size())) {
                        rules[static_cast<size_t>(nl->iItem)].enabled = on;
                        ListView_RedrawItems(Item(IDC_LIST), nl->iItem, nl->iItem);
                    }
                }
                if ((nl->uOldState ^ nl->uNewState) & LVIS_SELECTED)
                    SyncSelection();
            }
            res = 0;
            return true;
        }
        return false;
    }

private:
    bool loading_ = false;
    RuleInterfaceUi interfaces_;
    std::vector<std::wstring> preferredChoices_;

    void RefreshPreferredInterfaces() {
        if (!preferredInterfaceAvailable) return;
        HWND combo = Item(IDC_PREFERRED_INTERFACE);
        if (!combo) return;
        preferredChoices_.clear();
        preferredChoices_.emplace_back();
        const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
        if (snapshot) {
            for (const auto& entry : snapshot->interfaces)
                if (entry.up && entry.luid && !entry.name.empty())
                    preferredChoices_.push_back(entry.name);
        }
        std::sort(preferredChoices_.begin() + 1, preferredChoices_.end(), [](const auto& a, const auto& b) {
            return CompareNoCase(a, b) < 0;
        });
        SendMessageW(combo, WM_SETREDRAW, FALSE, 0);
        SendMessageW(combo, CB_RESETCONTENT, 0, 0);
        int selected = 0;
        for (size_t i = 0; i < preferredChoices_.size(); ++i) {
            const auto& name = preferredChoices_[i];
            const std::wstring text = i ? name : LoadStringRes(IDS_APP_INTERFACE_DEFAULT);
            SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
            if (name == preferredInterface) selected = static_cast<int>(i);
        }
        if (!preferredInterface.empty() && !selected) {
            // Пропавший выбор сохраняется, а не превращается в «По умолчанию».
            const std::wstring text = LoadStringResFmt(IDS_APP_INTERFACE_OFFLINE_FMT, preferredInterface.c_str());
            selected = static_cast<int>(preferredChoices_.size());
            preferredChoices_.push_back(preferredInterface);
            SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
        }
        SendMessageW(combo, CB_SETCURSEL, selected, 0);
        SendMessageW(combo, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(combo, nullptr, TRUE);
    }

    void SyncInheritance() {
        if (inheritanceAvailable)
            RuleInheritanceUi::Set(Item(IDC_INHERITANCE), Item(IDC_INHERITANCE_NEVER), inheritance);
    }

    int Selected() const {
        HWND lv = Item(IDC_LIST);
        const int i = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
        return (i >= 0 && i < static_cast<int>(rules.size())) ? i : -1;
    }
    void SelectRow(int i) {
        if (i < 0 || i >= static_cast<int>(rules.size())) { SyncSelection(); return; }
        ListView_SetItemState(Item(IDC_LIST), i, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(Item(IDC_LIST), i, FALSE);
        SetFocus(Item(IDC_LIST));      // Del подряд: фокус остаётся в списке
        SyncSelection();
    }
    void Fill() {
        interfaces_.Refresh(rules);
        loading_ = true;
        HWND lv = Item(IDC_LIST);
        SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(lv);
        int row = 0;
        for (Rule& r : rules) {
            r.priority = row;                   // приоритет = позиция в списке
            NormalizeRuleConds(r);              // страховка после правок
            const std::wstring num = std::to_wstring(row + 1);
            LVITEMW it{};
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = const_cast<LPWSTR>(num.c_str());
            ListView_InsertItem(lv, &it);
            ListView_SetItemText(lv, row, 1, const_cast<LPWSTR>(r.name.c_str()));
            const std::wstring act = r.ActionTextRu();
            ListView_SetItemText(lv, row, 2, const_cast<LPWSTR>(act.c_str()));
            ListView_SetCheckState(lv, row, r.enabled ? TRUE : FALSE);
            ++row;
        }
        SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(lv, nullptr, TRUE);
        loading_ = false;
        SyncSelection();
    }
    void SyncSelection() {
        const int sel = Selected();
        const bool has = sel >= 0;
        Enable(IDC_EDIT, has);
        Enable(IDC_DUP,  has);
        Enable(IDC_DEL,  has);
        Enable(IDC_UP,   has && sel > 0);
        Enable(IDC_DOWN, has && sel + 1 < static_cast<int>(rules.size()));

        if (has) {
            const Rule& r = rules[static_cast<size_t>(sel)];
            SetText(IDC_SCOPE, RuleScopeLine(r));
            SetLinkText(IDC_EXPLAIN, RuleExplainMarkup(r), true);
        } else {
            SetText(IDC_SCOPE, std::wstring());
            SetLinkText(IDC_EXPLAIN, LoadStringRes(IDS_APPED_NO_RULE_SELECTED));
        }
    }
};

#ifdef FIREWALLX_TEST_VERDICTS
void (*bindingTestHandler)(const std::wstring&) = nullptr;
#endif

struct BindingUpdate {
    std::wstring name;
};

DWORD WINAPI ApplyBindingUpdate(void* argument) noexcept {
    std::unique_ptr<BindingUpdate> update(static_cast<BindingUpdate*>(argument));
    try {
        HRESULT status = ndis_binding::ApplyInterfaceBinding(update->name);
        if (status == S_FALSE) status = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        if (FAILED(status)) {
            Ui::ShowMessage(nullptr, LoadStringResFmt(IDS_INTERFACE_EXCLUDE_APPLY_ERROR,
                static_cast<unsigned>(status)).c_str(), LoadStringRes(IDS_ERROR_TITLE).c_str(), MB_ICONWARNING);
        }
    } catch (...) {}
    return 0;
}

} // namespace

#ifdef FIREWALLX_TEST_VERDICTS
void AppRulesEditor::SetInterfaceBindingTestHandler(void (*handler)(const std::wstring&)) {
    bindingTestHandler = handler;
}
#endif

bool AppRulesEditor::Run(HWND owner, HINSTANCE inst, RuleStore& store,
                         const std::wstring& appPath, const std::wstring& appName,
                         bool global, bool postapp, bool interfaceGroup, DWORD pid,
                         uint64_t selectedRuleId) {
    if (!global && !postapp && !interfaceGroup && appPath.empty()) {
        Ui::ShowMessage(owner, LoadStringRes(IDS_APPED_NO_PATH).c_str(),
                    LoadStringRes(IDS_RULE_EDITOR_TITLE).c_str(), MB_ICONWARNING);
        return false;
    }

    Editor d;
    d.global  = global;
    d.postapp = postapp;
    d.interfaceGroup = interfaceGroup;
    d.selectedRuleId = selectedRuleId;
    d.appPath = (global || postapp) ? std::wstring() : appPath;
    d.inheritanceAvailable = !global && !postapp && !interfaceGroup &&
                             RuleStore::CanSetInheritance(appPath, pid);
    if (d.inheritanceAvailable) d.inheritance = store.GetInheritance(appPath);
    d.preferredInterfaceAvailable = !global && !postapp && !interfaceGroup;
    if (d.preferredInterfaceAvailable) {
        d.preferredInterface = store.GetPreferredInterface(appPath);
        d.blockOtherInterfaces = store.GetBlockOtherInterfaces(appPath);
    }
    if (interfaceGroup) {
        d.appName = appPath;
        if (!appPath.empty()) {
            d.interfaceBindingAvailable = true;
            const auto key = ndis_binding::InterfacePreferenceKey(appPath);
            d.excludeTransit = Settings::GetBool(key.c_str(), false);
            d.originalExcludeTransit = d.excludeTransit;
            const std::wstring reverseKey = Settings::Key::kNdisReverseTrafficPrefix + appPath;
            d.reverseTraffic = Settings::GetBool(reverseKey.c_str(), false);
            d.originalReverseTraffic = d.reverseTraffic;
        }
    } else if (global)
        d.appName = LoadStringRes(IDS_APPED_ALL_PROCESSES);
    else if (postapp)
        d.appName = LoadStringRes(IDS_RULE_POSTAPP_APP);
    else
        d.appName = appName.empty() ? PathBaseUpper(appPath) : appName;

    if (interfaceGroup)
        d.rules = store.InterfaceRules(appPath);
    else if (global)
        d.rules = store.Globals();
    else if (postapp)
        d.rules = store.PostApps();
    else
        d.rules = store.ForApp(appPath);

    UINT titleStrId = global ? IDS_APPED_GLOBAL_RULES :
                      postapp ? IDS_APPED_POSTAPP_RULES :
                      IDS_RULE_EDITOR_TITLE;

    if (!d.Run(owner, inst, LoadStringRes(titleStrId), 640,
               616 + (d.inheritanceAvailable ? 80 : 0) + (d.preferredInterfaceAvailable ? 94 : 0) +
               (d.interfaceGroup ? 68 : 0)))
        return false;

    RuleScope scope = interfaceGroup ? RuleScope::Interface :
                      global ? RuleScope::Global :
                      postapp ? RuleScope::PostApp :
                      RuleScope::App;
    store.Replace(scope, d.appPath, d.appName, d.rules);
    if (d.inheritanceAvailable) store.SetInheritance(d.appPath, d.inheritance);
    if (d.preferredInterfaceAvailable)
        store.SetPreferredInterface(d.appPath, d.preferredInterface, d.blockOtherInterfaces);
    if (d.interfaceBindingAvailable && d.reverseTraffic != d.originalReverseTraffic) {
        const std::wstring key = Settings::Key::kNdisReverseTrafficPrefix + d.appPath;
        if (!Settings::SetBool(key.c_str(), d.reverseTraffic)) {
            Ui::ShowMessage(owner, LoadStringResFmt(IDS_INTERFACE_EXCLUDE_SAVE_ERROR,
                Settings::lastError().c_str()).c_str(), LoadStringRes(IDS_ERROR_TITLE).c_str(), MB_ICONERROR);
        } else {
            auto& watcher = net::SharedNetworkInterfaces();
            if (!watcher.SetReverseNdisTraffic(d.appPath, d.reverseTraffic)) watcher.RequestRefresh();
            firewallxndisfilter_clear_cache();
        }
    }
    if (d.interfaceBindingAvailable && d.excludeTransit != d.originalExcludeTransit) {
        const auto key = ndis_binding::InterfacePreferenceKey(d.appPath);
        if (!Settings::SetBool(key.c_str(), d.excludeTransit)) {
            Ui::ShowMessage(owner, LoadStringResFmt(IDS_INTERFACE_EXCLUDE_SAVE_ERROR,
                Settings::lastError().c_str()).c_str(), LoadStringRes(IDS_ERROR_TITLE).c_str(), MB_ICONERROR);
        } else {
#ifdef FIREWALLX_TEST_VERDICTS
            if (bindingTestHandler) {
                bindingTestHandler(d.appPath);
                return true;
            }
#endif
            auto update = std::make_unique<BindingUpdate>();
            update->name = d.appPath;
            // NetCfg может надолго задержаться: оконный поток его не ожидает.
            HANDLE thread = CreateThread(nullptr, 0, ApplyBindingUpdate, update.get(), 0, nullptr);
            if (thread) {
                update.release();
                CloseHandle(thread);
            } else {
                const HRESULT status = HRESULT_FROM_WIN32(GetLastError());
                Ui::ShowMessage(owner, LoadStringResFmt(IDS_INTERFACE_EXCLUDE_APPLY_ERROR,
                    static_cast<unsigned>(status)).c_str(), LoadStringRes(IDS_ERROR_TITLE).c_str(), MB_ICONWARNING);
            }
        }
    }
    return true;
}