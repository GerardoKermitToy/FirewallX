#include "RuleDialogs.h"
#include "RuleInterfaceUi.h"
#include "ServiceInfo.h"
#include "StringRes.h"
#include "UiKit.h"
#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>
#include <cwctype>
#include <unordered_map>

namespace {

std::wstring Trim(const std::wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && iswspace(s[a])) ++a;
    while (b > a && iswspace(s[b - 1])) --b;
    return s.substr(a, b - a);
}

// Проверяем весь токен, а не только числовое начало, как _wtol.
// Ограничение до умножения исключает переполнение при сколь угодно длинном вводе.
bool ParseDecimalNumber(const std::wstring& text, uint32_t maxValue, uint32_t& out) {
    const std::wstring s = Trim(text);
    if (s.empty()) return false;

    uint32_t value = 0;
    for (wchar_t c : s) {
        if (c < L'0' || c > L'9') return false;
        const uint32_t digit = static_cast<uint32_t>(c - L'0');
        if (value > maxValue / 10u ||
            (value == maxValue / 10u && digit > maxValue % 10u)) return false;
        value = value * 10u + digit;
    }
    out = value;
    return true;
}

bool ParsePortNumber(const std::wstring& text, uint16_t& out) {
    uint32_t value = 0;
    if (!ParseDecimalNumber(text, 65535u, value) || value == 0) return false;
    out = static_cast<uint16_t>(value);
    return true;
}

// Ширина колонки списка без «желобка» справа: раньше колонка была уже клиента,
// и справа оставалась пустая белая полоса.
int ListColumnWidth(HWND lv, int fallbackW, UINT dpi) {
    RECT rc{};
    int w = fallbackW;
    if (lv && GetClientRect(lv, &rc) && rc.right > rc.left) w = rc.right - rc.left;
    const int sb = GetSystemMetricsForDpi(SM_CXVSCROLL, dpi);
    return std::max(w - (sb > 0 ? sb : 16) - 2, 40);
}

// --------------------------------------------------- выбор интерфейса

class InterfaceDlg : public Ui::Modal {
public:
    std::wstring name;

protected:
    enum { IDC_INTERFACE = 200, IDC_HINT };
    bool ModernStyle() const override { return true; }
    int InitialFocusId() const override { return IDC_INTERFACE; }

    void OnInit() override {
        const auto& m = M();
        SetHeader(LoadStringRes(IDS_INTERFACE_FILTER_TITLE),
                  LoadStringRes(IDS_INTERFACE_FILTER_NOTE));
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = headerH() + m.margin();
        Label(LoadStringRes(IDS_INTERFACE_FILTER_NAME), x, y, w, m.labelH());
        y += m.labelH() + m.gapS();
        HWND combo = Add(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL |
            CBS_DROPDOWN | CBS_AUTOHSCROLL, 0, x, y, w, m.editH() * 8, IDC_INTERFACE);
        SendMessageW(combo, CB_LIMITTEXT, 0, 0);
        y += m.editH() + m.gap();
        const int hintH = m.labelH() * 7;
        HWND hint = Hint(x, y, w, hintH, IDC_HINT);
        ShowScrollBar(hint, SB_VERT, TRUE);
        FitFooter(y + hintH + m.section());
        OkCancel();
        RefreshInterfaces(name);
        interfaces_.Watch(hwnd(), [this] { RefreshInterfaces(Text(IDC_INTERFACE)); });
    }

    bool OnCommand(int id, int code) override {
        if (id != IDC_INTERFACE) return false;
        if (code == CBN_EDITCHANGE || code == CBN_SELCHANGE) {
            std::wstring selected = Text(IDC_INTERFACE);
            if (code == CBN_SELCHANGE) {
                // CBN_SELCHANGE приходит раньше обновления поля ввода.
                HWND combo = Item(IDC_INTERFACE);
                const LRESULT index = SendMessageW(combo, CB_GETCURSEL, 0, 0);
                const LRESULT length = SendMessageW(combo, CB_GETLBTEXTLEN, index, 0);
                if (index != CB_ERR && length != CB_ERR) {
                    selected.resize(static_cast<size_t>(length) + 1);
                    SendMessageW(combo, CB_GETLBTEXT, index,
                                 reinterpret_cast<LPARAM>(selected.data()));
                    selected.resize(static_cast<size_t>(length));
                }
            }
            UpdateHint(selected);
            return true;
        }
        return false;
    }

    bool OnOk() override {
        name = Text(IDC_INTERFACE);
        return !name.empty();
    }

private:
    RuleInterfaceUi interfaces_;

    void RefreshInterfaces(const std::wstring& selected) {
        HWND combo = Item(IDC_INTERFACE);
        const DWORD editSelection = static_cast<DWORD>(SendMessageW(combo, CB_GETEDITSEL, 0, 0));
        const bool dropped = SendMessageW(combo, CB_GETDROPPEDSTATE, 0, 0) != FALSE;
        const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
        SendMessageW(combo, WM_SETREDRAW, FALSE, 0);
        SendMessageW(combo, CB_RESETCONTENT, 0, 0);
        // Имена не делятся по запятым и не нормализуются: это ключ из entry.name.
        LRESULT selection = CB_ERR;
        if (snapshot) {
            for (const auto& entry : snapshot->interfaces) {
                if (entry.name.empty()) continue;
                const LRESULT index = SendMessageW(combo, CB_ADDSTRING, 0,
                    reinterpret_cast<LPARAM>(entry.name.c_str()));
                if (entry.name == selected && index >= 0) selection = index;
            }
        }
        if (selection != CB_ERR)
            SendMessageW(combo, CB_SETCURSEL, selection, 0);
        else
            SetWindowTextW(combo, selected.c_str());
        SendMessageW(combo, CB_SETEDITSEL, 0, editSelection);
        SendMessageW(combo, WM_SETREDRAW, TRUE, 0);
        if (dropped) SendMessageW(combo, CB_SHOWDROPDOWN, TRUE, 0);
        InvalidateRect(combo, nullptr, TRUE);
        UpdateHint(selected, snapshot);
    }

    void UpdateHint(const std::wstring& selected) {
        UpdateHint(selected, net::SharedNetworkInterfaces().GetSnapshot());
    }

    void UpdateHint(const std::wstring& selected,
                    const net::NetworkInterfaceWatcher::SnapshotPtr& snapshot) {
        Enable(IDOK, !selected.empty());
        if (selected.empty()) {
            SetText(IDC_HINT, LoadStringRes(IDS_INTERFACE_FILTER_EMPTY));
            return;
        }
        std::wstring text = LoadStringRes(IDS_INTERFACE_FILTER_UNAVAILABLE);
        auto& watcher = net::SharedNetworkInterfaces();
        if (snapshot) {
            for (const auto& entry : snapshot->interfaces) {
                if (entry.name != selected) continue;
                if (watcher.GetInterfaceNumberByName(selected, snapshot))
                    text = LoadStringRes(IDS_INTERFACE_FILTER_ACTIVE);
                text += L"\r\n" + LoadStringResFmt(IDS_INTERFACE_FILTER_INDEX_FMT,
                                                entry.number, entry.ipv6_number);
                std::wstring addresses;
                for (const auto& address : entry.unicast) {
                    if (!addresses.empty()) addresses += L", ";
                    addresses += Ui::LtrText(IpToPlainString(address.address) + L"/" +
                                            std::to_wstring(address.prefix_length));
                }
                const auto list = [](const std::vector<IpAddr>& values) {
                    std::wstring result;
                    for (const auto& address : values) {
                        if (!result.empty()) result += L", ";
                        result += Ui::LtrText(IpToPlainString(address));
                    }
                    return result.empty() ? LoadStringRes(IDS_RED_DASH) : result;
                };
                if (addresses.empty()) addresses = LoadStringRes(IDS_RED_DASH);
                text += L"\r\n" + LoadStringResFmt(IDS_INTERFACE_FILTER_IP_FMT, addresses.c_str());
                text += L"\r\n" + LoadStringResFmt(IDS_INTERFACE_FILTER_GATEWAY_FMT,
                                                list(entry.gateways).c_str());
                text += L"\r\n" + LoadStringResFmt(IDS_INTERFACE_FILTER_DNS_FMT,
                                                list(entry.dns_servers).c_str());
                break;
            }
        }
        SetText(IDC_HINT, text);
    }
};

// --------------------------------------------------- выбор протокола
//
// Протокол — номер 0..255 (поле «Protocol» IPv4 / «Next Header» IPv6). Список
// известных номеров нужен для удобства, но правило можно создать для любого:
// номер вводится в поле, а алиас («TCP», «GRE») тоже принимается.

class ProtoDlg : public Ui::Modal {
public:
    Proto proto = Proto::Tcp;
    bool  any = false;              // условие «протокол» не проверяется

protected:
    bool ModernStyle() const override { return true; }

    enum { IDC_ANY = 100, IDC_LIST, IDC_NUMLBL, IDC_NUM, IDC_HINT };

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = m.margin();

        Check(LoadStringRes(IDS_RDP_ANY_PROTO), x, y, w, m.checkH(), IDC_ANY);
        y += m.checkH() + m.gap();

        y += SectionHeader(LoadStringRes(IDS_RDP_KNOWN), x, y, w);

        const int hintH  = m.labelH() * 2 + m.Sc(6);
        const int bottom = m.gap() + m.editH() + m.gapS() + hintH +
                           m.section() + m.btnH() + m.margin();
        int lh = clientH() - y - bottom;
        if (lh < m.Sc(150)) lh = m.Sc(150);

        ListView(x, y, w, lh, IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        const struct { UINT id; int w; int fmt; } cols[] = {
            { IDS_RDP_COL_PROTO,   112, LVCFMT_LEFT  },
            { IDS_RDP_COL_NUM,      48, LVCFMT_RIGHT },
            { IDS_RDP_COL_PURPOSE,   0, LVCFMT_LEFT  },
        };
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        for (int i = 0; i < 3; ++i) {
            c.iSubItem = i;
            c.fmt = cols[i].fmt;
            std::wstring colTitle = LoadStringRes(cols[i].id);
            c.pszText = colTitle.data();
            c.cx = cols[i].w ? m.Sc(cols[i].w)
                             : ListColumnWidth(lv, w, m.dpi) - m.Sc(112) - m.Sc(48);
            ListView_InsertColumn(lv, i, &c);
        }
        y += lh + m.gap();

        const int lblW = m.Sc(214);
        Label(LoadStringRes(IDS_RDP_INPUT_LABEL), x, y + m.Sc(4), lblW,
              m.labelH(), IDC_NUMLBL);
        LtrEdit(L"", x + lblW + m.gapS(), y, m.Sc(96), m.editH(), IDC_NUM);
        y += m.editH() + m.gapS();
        Hint(x, y, w, hintH, IDC_HINT);

        FillList();
        SetChecked(IDC_ANY, any);
        SetText(IDC_NUM, std::to_wstring(ProtoNumber(proto)));
        SelectNumber(ProtoNumber(proto));
        SyncMode();
        OkCancel();
    }

    bool OnCommand(int id, int code) override {
        if (id == IDC_ANY) { SyncMode(); return true; }
        if (id == IDC_NUM && code == EN_CHANGE) {
            if (!sync_) UpdateHint();
            return true;
        }
        (void)code;
        return false;
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
        if (hdr->idFrom != IDC_LIST) return false;

        if (hdr->code == LVN_ITEMCHANGED) {
            auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
            if (!sync_ && (nl->uChanged & LVIF_STATE) &&
                (nl->uNewState & LVIS_SELECTED) && !(nl->uOldState & LVIS_SELECTED)) {
                LVITEMW it{};
                it.mask = LVIF_PARAM;
                it.iItem = nl->iItem;
                if (ListView_GetItem(hdr->hwndFrom, &it)) {
                    sync_ = true;
                    SetText(IDC_NUM, std::to_wstring(static_cast<uint8_t>(it.lParam)));
                    sync_ = false;
                    UpdateHint();
                }
            }
            res = 0;
            return true;
        }
        if (hdr->code == NM_DBLCLK) {
            if (OnOk()) EndOk();
            res = 0;
            return true;
        }
        return false;
    }

    bool OnOk() override {
        any = Checked(IDC_ANY);
        if (any) return true;               // номер сохраняем как было

        uint8_t n = 0;
        if (!ParseProtoToken(Text(IDC_NUM), n)) {
            Ui::ShowMessage(hwnd(),
                LoadStringRes(IDS_RDP_ERR_BAD_INPUT).c_str(),
                LoadStringRes(IDS_PROTO_DIALOG_TITLE).c_str(), MB_ICONWARNING);
            return false;
        }
        proto = ProtoFromNumber(n);
        return true;
    }

private:
    bool sync_ = false;                     // подстановка выполняется программно

    void FillList() {
        HWND lv = Item(IDC_LIST);
        size_t n = 0;
        const KnownProto* p = KnownProtos(n);
        for (size_t i = 0; i < n; ++i) {
            LVITEMW it{};
            it.mask = LVIF_TEXT | LVIF_PARAM;
            it.iItem = static_cast<int>(i);
            it.lParam = static_cast<LPARAM>(p[i].num);
            it.pszText = const_cast<LPWSTR>(p[i].alias);
            ListView_InsertItem(lv, &it);
            ListView_SetItemText(lv, static_cast<int>(i), 1,
                const_cast<LPWSTR>(std::to_wstring(p[i].num).c_str()));
            ListView_SetItemText(lv, static_cast<int>(i), 2,
                const_cast<LPWSTR>(p[i].name));
        }
    }

    void SelectNumber(uint8_t num) {
        HWND lv = Item(IDC_LIST);
        const int cnt = ListView_GetItemCount(lv);
        for (int i = 0; i < cnt; ++i) {
            LVITEMW it{};
            it.mask = LVIF_PARAM;
            it.iItem = i;
            if (!ListView_GetItem(lv, &it)) continue;
            if (static_cast<uint8_t>(it.lParam) != num) continue;
            sync_ = true;
            ListView_SetItemState(lv, i, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(lv, i, FALSE);
            sync_ = false;
            return;
        }
    }

    void SyncMode() {
        const bool anyOn = Checked(IDC_ANY);
        Enable(IDC_LIST,   !anyOn);
        Enable(IDC_NUM,    !anyOn);
        Enable(IDC_NUMLBL, !anyOn);
        UpdateHint();
    }

    void UpdateHint() {
        if (Checked(IDC_ANY)) {
            SetText(IDC_HINT,
                LoadStringRes(IDS_RDP_NOTE_ANY));
            return;
        }
        uint8_t n = 0;
        if (!ParseProtoToken(Text(IDC_NUM), n)) {
            SetText(IDC_HINT,
                LoadStringRes(IDS_RDP_NOTE_INPUT));
            return;
        }
        std::wstring s = std::to_wstring(n) + LoadStringRes(IDS_RDP_DASH);
        const wchar_t* a = ProtoAlias(n);
        const std::wstring d = ProtoDesc(n);
        if (a) {
            s += a;
            if (!d.empty()) { s += L", "; s += d; }
        } else {
            s += LoadStringRes(IDS_RDP_UNKNOWN_NUM);
        }
        s += L"\r\n";

        const Proto p = ProtoFromNumber(n);
        if (ProtoIsIcmp(p))          s += LoadStringRes(IDS_RDP_ICMP_ONLY);
        else if (ProtoHasPorts(p))   s += LoadStringRes(IDS_RDP_HAS_PORTS);
        else                         s += LoadStringRes(IDS_RDP_NEITHER);
        SetText(IDC_HINT, s);
    }
};

// Диалога выбора направления больше нет: значений два, и щелчок по ссылке
// в расшифровке правила переключает их напрямую — как у действия.

// ------------------------------------------------------- выбор адреса

class AddrDlg : public Ui::Modal {
public:
    std::vector<AddrItem> items;

protected:
    bool ModernStyle() const override { return true; }

    // порядок важен: CheckRadioButton работает диапазоном IDC_IP..IDC_MACRO
    enum {
        IDC_IP = 160, IDC_SUBNET, IDC_IPV6, IDC_MACRO,
        IDC_IP4, IDC_MASKLBL, IDC_MASK4, IDC_IP6, IDC_COMBO,
        IDC_LIST, IDC_ADD, IDC_EDIT, IDC_DEL, IDC_HINT
    };

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        const int btnW = m.btnW();
        int y = m.margin();

        // ---- раздел 1: тип адреса ----
        y += SectionHeader(LoadStringRes(IDS_RDA_SECTION_ENTER), x, y, w);

        const int rx = x + m.Sc(4);
        const int rw = w - m.Sc(4);
        const int rh = m.radioH() + m.Sc(2);
        Radio(LoadStringRes(IDS_RDA_RADIO_IP), rx, y, rw, rh, IDC_IP, true);                 y += rh;
        Radio(LoadStringRes(IDS_RDA_RADIO_SUBNET), rx, y, rw, rh, IDC_SUBNET);
        y += rh;
        Radio(LoadStringRes(IDS_RDA_RADIO_IPV6), rx, y, rw, rh, IDC_IPV6);                   y += rh;
        Radio(LoadStringRes(IDS_RDA_RADIO_MACRO), rx, y, rw, rh, IDC_MACRO);
        y += rh + m.gapS();

        // Поля ввода всех режимов стоят на одной линии и переключаются
        // видимостью: раскладка не «прыгает» при смене типа адреса.
        const int inputY = y;
        const int ipW    = m.Sc(184);
        const int maskLW = m.Sc(46);
        IpEdit(rx, inputY, ipW, m.editH(), IDC_IP4);
        Label(LoadStringRes(IDS_RDA_MASK_LABEL), rx + ipW + m.gap(), inputY + m.Sc(4), maskLW, m.labelH(),
              IDC_MASKLBL);
        IpEdit(rx + ipW + m.gap() + maskLW + m.gapS(), inputY, ipW, m.editH(), IDC_MASK4);
        LtrEdit(L"", rx, inputY, rw, m.editH(), IDC_IP6);
        Combo(rx, inputY, m.Sc(268), m.editH() * 8, IDC_COMBO);
        y = inputY + m.editH() + m.section();

        // ---- раздел 2: список адресов правила ----
        y += SectionHeader(LoadStringRes(IDS_RDA_SECTION_LIST), x, y, w);

        const int listW = w - btnW - m.gap();
        const int listH = m.Sc(148);
        ListView(x, y, listW, listH, IDC_LIST,
                 LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        LVCOLUMNW col{};
        col.mask = LVCF_WIDTH | LVCF_SUBITEM;
        col.cx = ListColumnWidth(lv, listW, m.dpi);
        ListView_InsertColumn(lv, 0, &col);

        int by = y;
        Button(LoadStringRes(IDS_BTN_ADD), x + listW + m.gap(), by, btnW, m.btnH(), IDC_ADD);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_CHANGE), x + listW + m.gap(), by, btnW, m.btnH(), IDC_EDIT);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_DELETE),  x + listW + m.gap(), by, btnW, m.btnH(), IDC_DEL);
        y += listH + m.gap();

        // подсказка занимает всю ширину: у макросов список значений длинный
        const int hintH = clientH() - y - m.margin() - m.btnH() - m.section();
        Hint(x, y, w, std::max(hintH, m.Sc(56)), IDC_HINT);

        FillMacroCombo();
        SetChecked(IDC_IP, true);
        SyncMode();
        Fill();
        OkCancel();
    }

    bool OnCommand(int id, int code) override {
        switch (id) {
        case IDC_IP: case IDC_SUBNET: case IDC_IPV6: case IDC_MACRO:
            SyncMode();
            return true;
        case IDC_COMBO:
            if (code == CBN_SELCHANGE) { SyncMode(); return true; }
            return false;
        case IDC_ADD: {
            AddrItem a;
            if (Read(a)) { items.push_back(a); editIndex_ = -1; Fill(); }
            return true;
        }
        case IDC_EDIT: {
            const int sel = Selected();
            if (sel < 0) return true;
            if (editIndex_ == sel) {
                AddrItem a;
                if (Read(a, &items[static_cast<size_t>(sel)])) {
                    items[static_cast<size_t>(sel)] = a;
                    editIndex_ = -1;
                    Fill();
                    Select(sel);
                }
            } else {
                editIndex_ = sel;
                LoadToEditor(items[static_cast<size_t>(sel)]);
            }
            return true;
        }
        case IDC_DEL: {
            const int sel = Selected();
            if (sel < 0) return true;
            items.erase(items.begin() + sel);
            editIndex_ = -1;
            Fill();
            if (!items.empty()) {
                Select(sel < static_cast<int>(items.size())
                        ? sel : static_cast<int>(items.size()) - 1);
                SetFocus(Item(IDC_LIST));   // Del подряд
            }
            return true;
        }
        default:
            (void)code;
            return false;
        }
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
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
        }
        if (hdr->idFrom == IDC_LIST && hdr->code == LVN_ITEMCHANGED) {
            auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
            if ((nl->uChanged & LVIF_STATE) &&
                ((nl->uOldState ^ nl->uNewState) & LVIS_SELECTED))
                SyncSelection();
            res = 0;
            return true;
        }
        return false;
    }

    bool OnOk() override {
        // «ОК» также применяет запись, загруженную для изменения.
        if (editIndex_ >= 0) {
            AddrItem a;
            if (!Read(a, &items[static_cast<size_t>(editIndex_)])) return false;
            items[static_cast<size_t>(editIndex_)] = a;
            editIndex_ = -1;
        }
        return true;
    }

private:
    int editIndex_ = -1;

    int Selected() const {
        HWND lv = Item(IDC_LIST);
        const int i = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
        return (i >= 0 && i < static_cast<int>(items.size())) ? i : -1;
    }
    void SyncSelection() {
        const bool has = Selected() >= 0;
        Enable(IDC_EDIT, has);
        Enable(IDC_DEL, has);
    }
    void Select(int i) {
        ListView_SetItemState(Item(IDC_LIST), i, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        SyncSelection();
    }
    void FillMacroCombo() {
        HWND cb = Item(IDC_COMBO);
        if (!cb) return;
        size_t n = 0;
        const AddrMacros::Def* d = AddrMacros::All(n);
        for (size_t i = 0; i < n; ++i) {
            const int idx = static_cast<int>(
                SendMessageW(cb, CB_ADDSTRING, 0,
                             reinterpret_cast<LPARAM>(d[i].name)));
            SendMessageW(cb, CB_SETITEMDATA, static_cast<WPARAM>(idx),
                         static_cast<LPARAM>(static_cast<uint8_t>(d[i].id)));
        }
        SendMessageW(cb, CB_SETCURSEL, 0, 0);
    }
    AddrMacro SelectedMacro() const {
        HWND cb = Item(IDC_COMBO);
        if (!cb) return AddrMacro::None;
        const int i = static_cast<int>(SendMessageW(cb, CB_GETCURSEL, 0, 0));
        if (i < 0) return AddrMacro::None;
        return static_cast<AddrMacro>(static_cast<uint8_t>(
            SendMessageW(cb, CB_GETITEMDATA, static_cast<WPARAM>(i), 0)));
    }
    void SelectMacro(AddrMacro m) {
        HWND cb = Item(IDC_COMBO);
        if (!cb) return;
        const int n = static_cast<int>(SendMessageW(cb, CB_GETCOUNT, 0, 0));
        for (int i = 0; i < n; ++i) {
            const auto id = static_cast<AddrMacro>(static_cast<uint8_t>(
                SendMessageW(cb, CB_GETITEMDATA, static_cast<WPARAM>(i), 0)));
            if (id == m) { SendMessageW(cb, CB_SETCURSEL, static_cast<WPARAM>(i), 0); return; }
        }
    }
    void Fill() {
        HWND lv = Item(IDC_LIST);
        ListView_DeleteAllItems(lv);
        int row = 0;
        for (const AddrItem& a : items) {
            const std::wstring t = a.Text();
            LVITEMW it{};
            it.mask = LVIF_TEXT;
            it.iItem = row++;
            it.pszText = const_cast<LPWSTR>(t.c_str());
            ListView_InsertItem(lv, &it);
        }
        SyncSelection();
    }
    void SyncMode() {
        const bool v4     = Checked(IDC_IP);
        const bool subnet = Checked(IDC_SUBNET);
        const bool v6     = Checked(IDC_IPV6);
        const bool macro  = Checked(IDC_MACRO);

        ShowWindow(Item(IDC_IP4),     (v4 || subnet) ? SW_SHOW : SW_HIDE);
        ShowWindow(Item(IDC_MASK4),   subnet ? SW_SHOW : SW_HIDE);
        ShowWindow(Item(IDC_MASKLBL), subnet ? SW_SHOW : SW_HIDE);
        ShowWindow(Item(IDC_IP6),     v6 ? SW_SHOW : SW_HIDE);
        ShowWindow(Item(IDC_COMBO),   macro ? SW_SHOW : SW_HIDE);

        if (macro) {
            const AddrMacro m = SelectedMacro();
            std::wstring s = AddrMacros::Description(m);
            s += LoadStringRes(IDS_RDA_CURRENT_VALUE);
            s += AddrMacros::ValuesText(m);
            s += LoadStringRes(IDS_RDA_RESOLVED_LATER);
            SetText(IDC_HINT, s);
            return;
        }
        SetText(IDC_HINT, v6 ? LoadStringRes(IDS_RDA_EXAMPLE_IPV6)
                : subnet    ? LoadStringRes(IDS_RDA_EXAMPLE_SUBNET)
                            : LoadStringRes(IDS_RDA_EXAMPLE_IP));
    }
    void LoadToEditor(const AddrItem& a) {
        if (a.isMacro()) {
            CheckRadioButton(hwnd(), IDC_IP, IDC_MACRO, IDC_MACRO);
            SelectMacro(a.macro);
            SyncMode();
            return;
        }
        if (a.addr.family == AF_INET6) {
            CheckRadioButton(hwnd(), IDC_IP, IDC_MACRO, IDC_IPV6);
            SyncMode();
            SetText(IDC_IP6, a.Text());
            return;
        }
        CheckRadioButton(hwnd(), IDC_IP, IDC_MACRO,
                         a.prefix >= 0 ? IDC_SUBNET : IDC_IP);
        SyncMode();
        uint32_t host = 0;
        std::memcpy(&host, a.addr.b, 4);
        SendMessageW(Item(IDC_IP4), IPM_SETADDRESS, 0, static_cast<LPARAM>(ntohl(host)));
        if (a.prefix >= 0) {
            const IpAddr mask = PrefixToMask(AF_INET, a.prefix);
            uint32_t mh = 0;
            std::memcpy(&mh, mask.b, 4);
            SendMessageW(Item(IDC_MASK4), IPM_SETADDRESS, 0, static_cast<LPARAM>(ntohl(mh)));
        }
    }
    bool Read(AddrItem& out, const AddrItem* replaced = nullptr) {
        if (Checked(IDC_MACRO)) {
            const AddrMacro m = SelectedMacro();
            if (m == AddrMacro::None) {
                Ui::ShowMessage(hwnd(), LoadStringRes(IDS_ERR_SELECT_MACRO).c_str(),
                            LoadStringRes(IDS_RED_ADDR_DIALOG).c_str(), MB_ICONWARNING);
                return false;
            }
            out = AddrItem{};
            out.macro = m;
            return CheckUnique(out, replaced);
        }

        if (Checked(IDC_IPV6)) {
            if (!RuleDialogs::ParseIpv6Address(Text(IDC_IP6), out)) {
                Ui::ShowMessage(hwnd(), LoadStringRes(IDS_ERR_INVALID_IPV6).c_str(),
                            LoadStringRes(IDS_RED_ADDR_DIALOG).c_str(), MB_ICONWARNING);
                return false;
            }
            return CheckUnique(out, replaced);
        }

        DWORD packed = 0;
        if (SendMessageW(Item(IDC_IP4), IPM_GETADDRESS, 0,
                         reinterpret_cast<LPARAM>(&packed)) != 4) {
            Ui::ShowMessage(hwnd(), LoadStringRes(IDS_ERR_INVALID_IPV4).c_str(),
                        LoadStringRes(IDS_RED_ADDR_DIALOG).c_str(), MB_ICONWARNING);
            return false;
        }
        out = AddrItem{};
        out.addr = IpAddr::V4(htonl(packed));
        out.prefix = -1;

        if (Checked(IDC_SUBNET)) {
            DWORD mp = 0;
            if (SendMessageW(Item(IDC_MASK4), IPM_GETADDRESS, 0,
                             reinterpret_cast<LPARAM>(&mp)) != 4) {
                Ui::ShowMessage(hwnd(), LoadStringRes(IDS_ERR_SUBNET_REQUIRED).c_str(),
                            LoadStringRes(IDS_RED_ADDR_DIALOG).c_str(), MB_ICONWARNING);
                return false;
            }
            int prefix = 0;
            if (!MaskToPrefix(IpAddr::V4(htonl(mp)), prefix)) {
                Ui::ShowMessage(hwnd(),
                    LoadStringRes(IDS_RDA_ERR_MASK_CONTIGUOUS).c_str(),
                    LoadStringRes(IDS_RED_ADDR_DIALOG).c_str(), MB_ICONWARNING);
                return false;
            }
            out.prefix = prefix;
            ApplyPrefix(out.addr, prefix, false);
        }
        return CheckUnique(out, replaced);
    }
    bool CheckUnique(const AddrItem& address, const AddrItem* replaced) {
        // При редактировании запись не считается своим дубликатом.
        const bool dup = std::any_of(items.begin(), items.end(),
            [&](const AddrItem& x) { return &x != replaced && x == address; });
        if (!dup) return true;
        Ui::ShowMessage(hwnd(),
            LoadStringRes(address.isMacro() ? IDS_ERR_MACRO_EXISTS : IDS_ERR_ADDR_EXISTS).c_str(),
            LoadStringRes(IDS_RED_ADDR_DIALOG).c_str(), MB_ICONINFORMATION);
        return false;
    }
};

// -------------------------------------------------------- выбор порта

class PortDlg : public Ui::Modal {
public:
    std::vector<PortItem> items;

protected:
    bool ModernStyle() const override { return true; }

    enum { IDC_EDIT = 200, IDC_LIST };

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = m.margin();

        Label(LoadStringRes(IDS_RDPO_PROMPT),
              x, y, w, m.labelH());
        y += m.labelH();
        Label(LoadStringRes(IDS_RDPO_EXAMPLE), x, y, w, m.labelH());
        y += m.labelH() + m.gapS();

        LtrEdit(RuleDialogs::PortsToText(items).c_str(), x, y, w, m.editH(), IDC_EDIT);
        y += m.editH() + m.section();

        Label(LoadStringRes(IDS_RDPO_KNOWN_SERVICES),
              x, y, w, m.labelH());
        y += m.labelH() + m.gapS();

        const int listH = clientH() - y - m.margin() - m.btnH() - m.section();
        ListView(x, y, w, listH, IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        const struct { UINT id; int w; } cols[] = {
            { IDS_RDPO_COL_NAME, 140 }, { IDS_RDPO_COL_PORT, 70 },
            { IDS_RDPO_COL_DESC, 300 }
        };
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (int i = 0; i < 3; ++i) {
            c.iSubItem = i;
            std::wstring colTitle = LoadStringRes(cols[i].id);
            c.pszText = colTitle.data();
            c.cx = m.Sc(cols[i].w);
            ListView_InsertColumn(lv, i, &c);
        }

        size_t n = 0;
        const KnownPort* kp = KnownPorts(n);
        for (size_t i = 0; i < n; ++i) {
            LVITEMW it{};
            it.mask = LVIF_TEXT | LVIF_PARAM;
            it.iItem = static_cast<int>(i);
            it.lParam = static_cast<LPARAM>(kp[i].port);
            it.pszText = const_cast<LPWSTR>(kp[i].name);
            ListView_InsertItem(lv, &it);
            ListView_SetItemText(lv, static_cast<int>(i), 1,
                const_cast<LPWSTR>(std::to_wstring(kp[i].port).c_str()));
            ListView_SetItemText(lv, static_cast<int>(i), 2,
                const_cast<LPWSTR>(kp[i].desc));
        }

        OkCancel();
        SetFocus(Item(IDC_EDIT));
        SendMessageW(Item(IDC_EDIT), EM_SETSEL, 0, -1);
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
        if (hdr->idFrom == IDC_LIST &&
            (hdr->code == NM_DBLCLK || hdr->code == LVN_ITEMACTIVATE)) {
            auto* ia = reinterpret_cast<LPNMITEMACTIVATE>(hdr);
            if (ia->iItem >= 0) {
                LVITEMW it{};
                it.mask = LVIF_PARAM;
                it.iItem = ia->iItem;
                if (ListView_GetItem(hdr->hwndFrom, &it))
                    SetText(IDC_EDIT, std::to_wstring(static_cast<uint16_t>(it.lParam)));
            }
            res = 0;
            return true;
        }
        return false;
    }

    bool OnOk() override {
        std::vector<PortItem> parsed;
        std::wstring err;
        if (!RuleDialogs::ParsePortList(Text(IDC_EDIT), parsed, err)) {
            Ui::ShowMessage(hwnd(), err.c_str(), LoadStringRes(IDS_PORT_DIALOG_TITLE).c_str(), MB_ICONWARNING);
            return false;
        }
        items = std::move(parsed);
        return true;
    }
};

// ---------------------------------------------------- выбор типов ICMP

class IcmpDlg : public Ui::Modal {
public:
    std::vector<IcmpTypeItem> items;
    bool v6 = false;

protected:
    bool ModernStyle() const override { return true; }

    enum { IDC_LIST = 240, IDC_EXTRA, IDC_HINT, IDC_ALL, IDC_NONE };

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = m.margin();

        Label(v6 ? LoadStringRes(IDS_RDI_PROMPT_V6)
                 : LoadStringRes(IDS_RDI_PROMPT_V4),
              x, y, w, m.labelH());
        y += m.labelH() + m.gapS();

        const int btnW = m.btnWNarrow();
        const int listW = w - btnW - m.gap();
        const int listH = clientH() - y - m.margin() - m.btnH() - m.section() -
                          m.editH() - m.labelH() * 2 - m.gap() * 2;

        ListView(x, y, listW, listH > m.Sc(120) ? listH : m.Sc(120), IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        c.iSubItem = 0;
        c.fmt = LVCFMT_LEFT;
        c.cx = m.Sc(56);
        std::wstring colType = LoadStringRes(IDS_RDI_COL_TYPE);
        c.pszText = colType.data();
        ListView_InsertColumn(lv, 0, &c);
        c.iSubItem = 1;
        c.cx = listW - m.Sc(56) - m.Sc(26);
        std::wstring colPurpose = LoadStringRes(IDS_RDI_COL_PURPOSE);
        c.pszText = colPurpose.data();
        ListView_InsertColumn(lv, 1, &c);

        size_t n = 0;
        const KnownIcmpType* kt = KnownIcmpTypes(v6, n);
        for (size_t i = 0; i < n; ++i) {
            const std::wstring num = std::to_wstring(kt[i].type);
            LVITEMW it{};
            it.mask = LVIF_TEXT | LVIF_PARAM;
            it.iItem = static_cast<int>(i);
            it.lParam = static_cast<LPARAM>(kt[i].type);
            it.pszText = const_cast<LPWSTR>(num.c_str());
            ListView_InsertItem(lv, &it);
            ListView_SetItemText(lv, static_cast<int>(i), 1,
                                 const_cast<LPWSTR>(kt[i].name));
        }

        int by = y;
        Button(LoadStringRes(IDS_BTN_ALL),   x + listW + m.gap(), by, btnW, m.btnH(), IDC_ALL);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_CLEAR), x + listW + m.gap(), by, btnW, m.btnH(), IDC_NONE);

        y += (listH > m.Sc(120) ? listH : m.Sc(120)) + m.gap();

        Label(LoadStringRes(IDS_RDI_EXTRA_LABEL), x, y, w, m.labelH());
        y += m.labelH() + m.gapS();
        LtrEdit(L"", x, y, w, m.editH(), IDC_EXTRA);
        y += m.editH() + m.gapS();
        Hint(x, y, w, m.labelH() + m.Sc(6), IDC_HINT);
        SetText(IDC_HINT, v6 ? LoadStringRes(IDS_RDI_EXAMPLE_V6)
                             : LoadStringRes(IDS_RDI_EXAMPLE_V4));

        LoadItems();
        OkCancel();
    }

    bool OnCommand(int id, int code) override {
        switch (id) {
        case IDC_ALL:
        case IDC_NONE: {
            HWND lv = Item(IDC_LIST);
            const int n = ListView_GetItemCount(lv);
            for (int i = 0; i < n; ++i)
                ListView_SetCheckState(lv, i, id == IDC_ALL ? TRUE : FALSE);
            return true;
        }
        default:
            (void)code;
            return false;
        }
    }

    bool OnOk() override {
        std::vector<IcmpTypeItem> out;

        HWND lv = Item(IDC_LIST);
        const int n = ListView_GetItemCount(lv);
        for (int i = 0; i < n; ++i) {
            if (!ListView_GetCheckState(lv, i)) continue;
            LVITEMW it{};
            it.mask = LVIF_PARAM;
            it.iItem = i;
            if (!ListView_GetItem(lv, &it)) continue;
            IcmpTypeItem t;
            t.type = static_cast<uint8_t>(it.lParam);
            t.code = -1;                       // любой код данного типа
            out.push_back(t);
        }

        std::vector<IcmpTypeItem> extra;
        std::wstring err;
        if (!RuleDialogs::ParseIcmpTypeList(Text(IDC_EXTRA), extra, err)) {
            Ui::ShowMessage(hwnd(), err.c_str(), LoadStringRes(IDS_RDI_TITLE_V4).c_str(), MB_ICONWARNING);
            return false;
        }
        for (const IcmpTypeItem& t : extra) {
            const bool dup = std::any_of(out.begin(), out.end(),
                [&](const IcmpTypeItem& x) { return x.type == t.type && x.code == t.code; });
            if (!dup) out.push_back(t);
        }

        if (out.empty()) {
            Ui::ShowMessage(hwnd(),
                LoadStringRes(IDS_RDI_ERR_NONE_CHECKED).c_str(),
                LoadStringRes(IDS_RDI_TITLE_V4).c_str(), MB_ICONWARNING);
            return false;
        }
        items = std::move(out);
        return true;
    }

private:
    // отмеченные галочками — типы без кода; всё прочее уходит в поле ввода
    void LoadItems() {
        HWND lv = Item(IDC_LIST);
        const int n = ListView_GetItemCount(lv);

        std::vector<IcmpTypeItem> rest;
        for (const IcmpTypeItem& t : items) {
            if (t.code >= 0) { rest.push_back(t); continue; }
            bool found = false;
            for (int i = 0; i < n && !found; ++i) {
                LVITEMW it{};
                it.mask = LVIF_PARAM;
                it.iItem = i;
                if (!ListView_GetItem(lv, &it)) continue;
                if (static_cast<uint8_t>(it.lParam) != t.type) continue;
                ListView_SetCheckState(lv, i, TRUE);
                found = true;
            }
            if (!found) rest.push_back(t);
        }
        SetText(IDC_EXTRA, RuleDialogs::IcmpTypesToText(rest));
    }
};

// ------------------------------------------------------- выбор флагов WFP

class WfpFlagsDlg : public Ui::Modal {
public:
    uint32_t flags = 0;

protected:
    bool ModernStyle() const override { return true; }
    enum { IDC_LIST = 320, IDC_ALL, IDC_NONE };

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = m.margin();
        const std::wstring note = LoadStringRes(IDS_WFP_FLAGS_NOTE);
        const int noteH = std::max(m.labelH() * 2, TextHeight(note, w));
        Note(note, x, y, w, noteH);
        y += noteH + m.gap();

        const int btnW = m.btnWNarrow();
        const int listW = w - btnW - m.gap();
        const int listH = clientH() - y - m.margin() - m.btnH() - m.section();
        ListView(x, y, listW, listH, IDC_LIST,
                 LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        LVCOLUMNW column{};
        column.mask = LVCF_WIDTH;
        column.cx = listW - m.Sc(26);
        ListView_InsertColumn(lv, 0, &column);
        Ui::KeepLeftToRight(lv);

        // Неизвестные биты доступны; REAUTHORIZE пользователю не предлагается.
        for (unsigned bit = 0; bit < 32; ++bit) {
            const uint32_t mask = uint32_t{1} << bit;
            if (!(mask & kSelectableWfpConditionFlags)) continue;
            const std::wstring name = WfpConditionFlagText(bit);
            std::wstring text = LoadStringResFmt(IDS_WFP_FLAG_LABEL_FMT, name.c_str(), mask);
            LVITEMW item{};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = ListView_GetItemCount(lv);
            item.lParam = static_cast<LPARAM>(mask);
            item.pszText = text.data();
            ListView_InsertItem(lv, &item);
            ListView_SetCheckState(lv, item.iItem, (flags & mask) ? TRUE : FALSE);
        }
        Button(LoadStringRes(IDS_BTN_ALL), x + listW + m.gap(), y, btnW, m.btnH(), IDC_ALL);
        Button(LoadStringRes(IDS_BTN_CLEAR), x + listW + m.gap(), y + m.btnH() + m.gapS(),
               btnW, m.btnH(), IDC_NONE);
        OkCancel();
    }

    bool OnCommand(int id, int) override {
        if (id != IDC_ALL && id != IDC_NONE) return false;
        HWND lv = Item(IDC_LIST);
        for (int row = 0; row < ListView_GetItemCount(lv); ++row)
            ListView_SetCheckState(lv, row, id == IDC_ALL ? TRUE : FALSE);
        return true;
    }

    bool OnOk() override {
        flags = 0;
        HWND lv = Item(IDC_LIST);
        for (int row = 0; row < ListView_GetItemCount(lv); ++row) {
            if (!ListView_GetCheckState(lv, row)) continue;
            LVITEMW item{};
            item.mask = LVIF_PARAM;
            item.iItem = row;
            if (ListView_GetItem(lv, &item)) flags |= static_cast<uint32_t>(item.lParam);
        }
        return true;
    }
};

// ------------------------------------------------------- выбор сервисов
//
// Отметки хранятся НЕ в списке, а в отдельной карте «ключ -> имя как введено»:
// список перестраивается на каждое изменение фильтра, и состояние галочек
// иначе терялось бы. По той же причине отмеченный сервис показывается всегда,
// даже если фильтр его исключает: иначе он молча пропадал бы из вида,
// оставаясь в правиле.

class ServiceDlg : public Ui::Modal {
public:
    std::vector<ServiceItem> items;

protected:
    bool ModernStyle() const override { return true; }

    enum { IDC_FILTER = 280, IDC_RUNNING, IDC_LIST, IDC_ALL, IDC_NONE,
           IDC_REFRESH, IDC_EXTRA, IDC_HINT };

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = m.margin();

        y += SectionHeader(LoadStringRes(IDS_RDS_SECTION), x, y, w);

        const int lblW = m.Sc(46);
        const int runW = m.Sc(186);
        Label(LoadStringRes(IDS_FILTER_LABEL), x, y + m.Sc(4), lblW, m.labelH());
        Edit(L"", x + lblW, y, w - lblW - runW - m.gap(), m.editH(), IDC_FILTER);
        Check(LoadStringRes(IDS_RDS_ONLY_RUNNING), x + w - runW, y + m.Sc(3), runW,
              m.checkH(), IDC_RUNNING);
        y += m.editH() + m.gap();

        const int btnW  = m.btnW();
        const int hintH = m.labelH() * 2 + m.Sc(8);
        const int bottom = m.margin() + m.btnH() + m.section() + hintH + m.gapS() +
                           m.editH() + m.gapS() + m.labelH() + m.gap();
        int listH = clientH() - y - bottom;
        if (listH < m.Sc(170)) listH = m.Sc(170);
        const int listW = w - btnW - m.gap();

        ListView(x, y, listW, listH, IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        const int nameW  = m.Sc(158);
        const int stateW = m.Sc(112);
        const int pidW   = m.Sc(56);
        const struct { UINT id; int w; int fmt; } cols[] = {
            { IDS_RDS_COL_SERVICE, nameW,  LVCFMT_LEFT  },
            { IDS_RDS_COL_DISPLAY, 0,      LVCFMT_LEFT  },
            { IDS_RDS_COL_STATE,   stateW, LVCFMT_LEFT  },
            { IDS_RDS_COL_PID,     pidW,   LVCFMT_RIGHT },
        };
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        for (int i = 0; i < 4; ++i) {
            c.iSubItem = i;
            c.fmt = cols[i].fmt;
            std::wstring colTitle = LoadStringRes(cols[i].id);
            c.pszText = colTitle.data();
            c.cx = cols[i].w ? cols[i].w
                             : std::max(m.Sc(90),
                                        ListColumnWidth(lv, listW, m.dpi) -
                                        nameW - stateW - pidW);
            ListView_InsertColumn(lv, i, &c);
        }

        int by = y;
        Button(LoadStringRes(IDS_RDS_BTN_CHECK_ALL), x + listW + m.gap(), by, btnW, m.btnH(), IDC_ALL);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_RDS_BTN_UNCHECK_ALL),    x + listW + m.gap(), by, btnW, m.btnH(), IDC_NONE);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_REFRESH),     x + listW + m.gap(), by, btnW, m.btnH(), IDC_REFRESH);
        y += listH + m.gap();

        Label(LoadStringRes(IDS_RDS_EXTRA_LABEL), x, y, w, m.labelH());
        y += m.labelH() + m.gapS();
        LtrEdit(L"", x, y, w, m.editH(), IDC_EXTRA);
        y += m.editH() + m.gapS();
        Hint(x, y, w, hintH, IDC_HINT);

        for (const ServiceItem& s : items)
            if (!s.name.empty()) picked_[FoldCaseCopy(s.name)] = s.name;

        // Каталог остановленных служб не участвует в секундном runtime-опросе,
        // поэтому при каждом открытии читаем его заново. Кнопка ниже позволяет
        // повторить запрос, если состояние изменилось уже в открытом окне.
        LoadSnapshot(true);
        Fill();
        OkCancel();
    }

    bool OnCommand(int id, int code) override {
        if (id == IDC_FILTER && code == EN_CHANGE) { Fill(); return true; }
        switch (id) {
        case IDC_RUNNING:
            Fill();
            return true;
        case IDC_ALL:
        case IDC_NONE: {
            // Действуют на ПОКАЗАННЫЕ строки: иначе «Отметить все» при
            // включённом фильтре добавляло бы в правило весь список служб.
            loading_ = true;
            HWND lv = Item(IDC_LIST);
            const bool on = (id == IDC_ALL);
            for (size_t i = 0; i < shown_.size(); ++i) {
                ListView_SetCheckState(lv, static_cast<int>(i), on ? TRUE : FALSE);
                SetPicked(all_[shown_[i]].name, on);
            }
            loading_ = false;
            UpdateHint();
            return true;
        }
        case IDC_REFRESH:
            LoadSnapshot(true);
            Fill();
            return true;
        default:
            return false;
        }
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
        if (hdr->idFrom != IDC_LIST) return false;

        if (hdr->code == LVN_ITEMCHANGED) {
            auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
            if (!loading_ && (nl->uChanged & LVIF_STATE) &&
                ((nl->uOldState ^ nl->uNewState) & LVIS_STATEIMAGEMASK)) {
                const bool on = ((nl->uNewState & LVIS_STATEIMAGEMASK) >> 12) == 2;
                const int i = nl->iItem;
                if (i >= 0 && i < static_cast<int>(shown_.size())) {
                    SetPicked(all_[shown_[static_cast<size_t>(i)]].name, on);
                    UpdateHint();
                }
            }
            res = 0;
            return true;
        }
        if (hdr->code == NM_DBLCLK) {
            auto* ia = reinterpret_cast<LPNMITEMACTIVATE>(hdr);
            if (ia->iItem >= 0 && ia->iItem < static_cast<int>(shown_.size())) {
                HWND lv = Item(IDC_LIST);
                const BOOL on = ListView_GetCheckState(lv, ia->iItem);
                ListView_SetCheckState(lv, ia->iItem, on ? FALSE : TRUE);
            }
            res = 0;
            return true;
        }
        return false;
    }

    bool OnOk() override {
        std::vector<ServiceItem> out;
        for (const Row& r : all_) {
            if (!IsPicked(r.name)) continue;
            ServiceItem s;
            s.name    = r.name;
            s.display = r.display;
            out.push_back(std::move(s));
        }

        std::vector<ServiceItem> extra;
        std::wstring err;
        if (!RuleDialogs::ParseServiceList(Text(IDC_EXTRA), extra, err)) {
            Ui::ShowMessage(hwnd(), err.c_str(), LoadStringRes(IDS_SERVICE_DIALOG_TITLE).c_str(), MB_ICONWARNING);
            return false;
        }
        for (ServiceItem& e : extra) {
            const bool dup = std::any_of(out.begin(), out.end(),
                [&](const ServiceItem& x) { return ServiceInfo::SameName(x.name, e.name); });
            if (!dup) out.push_back(std::move(e));
        }

        // Пустой список допустим: он означает «любой сервис».
        items = std::move(out);
        return true;
    }

private:
    struct Row {
        std::wstring name, display, state;
        DWORD pid = 0;
        bool  running = false;
    };

    std::vector<Row>    all_;
    std::vector<size_t> shown_;                                  // индексы в all_
    std::unordered_map<std::wstring, std::wstring> picked_;       // UPPER -> имя
    bool loading_ = false;

    bool IsPicked(const std::wstring& name) const {
        return picked_.count(FoldCaseCopy(name)) != 0;
    }
    void SetPicked(const std::wstring& name, bool on) {
        const std::wstring key = FoldCaseCopy(name);
        if (on) picked_[key] = name;
        else    picked_.erase(key);
    }

    void LoadSnapshot(bool refresh) {
        all_.clear();
        for (const ServiceEntry& e : ServiceInfo::All(refresh)) {
            Row r;
            r.name    = e.name;
            r.display = e.display;
            r.state   = e.StateTextRu();
            r.pid     = e.pid;
            r.running = e.running();
            all_.push_back(std::move(r));
        }

        // Сервисы правила, которых на этом компьютере нет: правило переносимо
        // между машинами, поэтому такие имена не теряем и показываем явно.
        for (const auto& kv : picked_) {
            const bool known = std::any_of(all_.begin(), all_.end(),
                [&](const Row& r) { return ServiceInfo::SameName(r.name, kv.second); });
            if (known) continue;
            Row r;
            r.name  = kv.second;
            if (r.name.find(L'*') == std::wstring::npos)
                r.state = LoadStringRes(IDS_RDS_NOT_INSTALLED);
            all_.push_back(std::move(r));
        }

        std::sort(all_.begin(), all_.end(), [](const Row& a, const Row& b) {
            return CompareStringOrdinal(a.name.c_str(), -1,
                b.name.c_str(), -1, TRUE) == CSTR_LESS_THAN;
        });
    }

    void Fill() {
        loading_ = true;
        const std::wstring f = FoldCaseCopy(Text(IDC_FILTER));
        const bool onlyRun = Checked(IDC_RUNNING);

        HWND lv = Item(IDC_LIST);
        SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(lv);
        shown_.clear();

        for (size_t i = 0; i < all_.size(); ++i) {
            const Row& r = all_[i];
            const bool on = IsPicked(r.name);
            if (!on) {
                if (onlyRun && !r.running) continue;
                if (!f.empty() &&
                    FoldCaseCopy(r.name).find(f) == std::wstring::npos &&
                    FoldCaseCopy(r.display).find(f) == std::wstring::npos) continue;
            }
            const int row = static_cast<int>(shown_.size());
            LVITEMW it{};
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = const_cast<LPWSTR>(r.name.c_str());
            ListView_InsertItem(lv, &it);
            ListView_SetItemText(lv, row, 1, const_cast<LPWSTR>(r.display.c_str()));
            ListView_SetItemText(lv, row, 2, const_cast<LPWSTR>(r.state.c_str()));
            const std::wstring pid = r.pid ? std::to_wstring(r.pid) : std::wstring(LoadStringRes(IDS_RED_DASH));
            ListView_SetItemText(lv, row, 3, const_cast<LPWSTR>(pid.c_str()));
            ListView_SetCheckState(lv, row, on ? TRUE : FALSE);
            shown_.push_back(i);
        }
        SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(lv, nullptr, TRUE);
        loading_ = false;
        UpdateHint();
    }

    void UpdateHint() {
        std::wstring s = LoadStringResFmt(IDS_RDS_STATS_FMT,
                                          static_cast<unsigned>(picked_.size()),
                                          static_cast<unsigned>(shown_.size()),
                                          static_cast<unsigned>(all_.size()));
        s += picked_.empty()
            ? LoadStringRes(IDS_RDS_NOTE_EMPTY)
            : LoadStringRes(IDS_RDS_NOTE_EXCLUSIVE);
        SetText(IDC_HINT, s);
    }
};

} // namespace

namespace RuleDialogs {

bool ParseIpv6Address(const std::wstring& text, AddrItem& out) {
    std::wstring s = Trim(text);
    int prefix = -1;
    const size_t slash = s.find(L'/');
    if (slash != std::wstring::npos) {
        uint32_t value = 0;
        if (!ParseDecimalNumber(s.substr(slash + 1), 128u, value)) return false;
        prefix = static_cast<int>(value);
        s = Trim(s.substr(0, slash));
    }
    IpAddr a{};
    if (!ParseIpAddr(s, a) || a.family != AF_INET6) return false;
    out = AddrItem{};
    out.addr = a;
    out.prefix = prefix;
    if (prefix >= 0) ApplyPrefix(out.addr, prefix, false);
    return true;
}

std::wstring PortsToText(const std::vector<PortItem>& v) {
    std::wstring s;
    for (const PortItem& p : v) {
        if (!s.empty()) s += L", ";
        s += (p.from == p.to) ? std::to_wstring(p.from)
                              : std::to_wstring(p.from) + L"-" + std::to_wstring(p.to);
    }
    return s;
}

bool ParsePortList(const std::wstring& text, std::vector<PortItem>& out, std::wstring& err) {
    out.clear();
    const std::wstring s = Trim(text);
    if (s.empty()) return true;

    size_t pos = 0;
    while (pos <= s.size()) {
        const size_t comma = s.find(L',', pos);
        std::wstring item = Trim(s.substr(pos, comma == std::wstring::npos
                                              ? std::wstring::npos : comma - pos));
        if (!item.empty()) {
            const size_t dash = item.find(L'-');
            uint16_t lo = 0, hi = 0;
            bool valid = false;
            if (dash == std::wstring::npos) {
                valid = ParsePortNumber(item, lo);
                hi = lo;
            } else {
                valid = ParsePortNumber(item.substr(0, dash), lo) &&
                        ParsePortNumber(item.substr(dash + 1), hi);
            }
            if (!valid) {
                err = LoadStringRes(IDS_RDPO_ERR_BAD_PORT) + item;
                return false;
            }
            if (lo > hi) std::swap(lo, hi);
            out.push_back(PortItem{ lo, hi });
        }
        if (comma == std::wstring::npos) break;
        pos = comma + 1;
    }
    return true;
}

std::wstring IcmpTypesToText(const std::vector<IcmpTypeItem>& v) {
    std::wstring s;
    for (const IcmpTypeItem& t : v) {
        if (!s.empty()) s += L", ";
        s += std::to_wstring(t.type);
        if (t.code >= 0) s += L":" + std::to_wstring(t.code);
    }
    return s;
}

// «8», «3:1», «11:0, 128»
bool ParseIcmpTypeList(const std::wstring& text, std::vector<IcmpTypeItem>& out,
                       std::wstring& err) {
    out.clear();
    const std::wstring s = Trim(text);
    if (s.empty()) return true;

    size_t pos = 0;
    while (pos <= s.size()) {
        const size_t comma = s.find(L',', pos);
        std::wstring item = Trim(s.substr(pos, comma == std::wstring::npos
                                              ? std::wstring::npos : comma - pos));
        if (!item.empty()) {
            uint32_t type = 0;
            int code = -1;
            const size_t colon = item.find(L':');
            if (!ParseDecimalNumber(item.substr(0, colon), 255u, type)) {
                err = LoadStringRes(IDS_RDI_ERR_TYPE_RANGE) + item;
                return false;
            }
            if (colon != std::wstring::npos) {
                const std::wstring cs = Trim(item.substr(colon + 1));
                if (cs.empty()) {
                    err = LoadStringRes(IDS_RDI_ERR_NO_CODE) + item;
                    return false;
                }
                uint32_t parsedCode = 0;
                if (!ParseDecimalNumber(cs, 255u, parsedCode)) {
                    err = LoadStringRes(IDS_RDI_ERR_CODE_RANGE) + item;
                    return false;
                }
                code = static_cast<int>(parsedCode);
            }
            IcmpTypeItem t;
            t.type = static_cast<uint8_t>(type);
            t.code = code;
            out.push_back(t);
        }
        if (comma == std::wstring::npos) break;
        pos = comma + 1;
    }
    return true;
}

std::wstring ServicesToText(const std::vector<ServiceItem>& v) {
    std::wstring s;
    for (const ServiceItem& x : v) {
        if (!s.empty()) s += L", ";
        s += x.name;
    }
    return s;
}

bool ParseServiceList(const std::wstring& text, std::vector<ServiceItem>& out,
                      std::wstring& err) {
    out.clear();
    const std::wstring s = Trim(text);
    if (s.empty()) return true;

    size_t pos = 0;
    while (pos <= s.size()) {
        const size_t comma = s.find(L',', pos);
        std::wstring item = Trim(s.substr(pos, comma == std::wstring::npos
                                              ? std::wstring::npos : comma - pos));
        if (!item.empty()) {
            // Ограничения имени сервиса задаёт CreateService. Обратный слэш
            // проверяется ещё и потому, что он служит разделителем в базе.
            if (item.size() > 255) {
                err = LoadStringRes(IDS_RDS_ERR_NAME_TOO_LONG) + item;
                return false;
            }
            if (item.find_first_of(L"\\/") != std::wstring::npos) {
                err = LoadStringRes(IDS_RDS_ERR_NAME_SLASH) + item;
                return false;
            }
            const bool dup = std::any_of(out.begin(), out.end(),
                [&](const ServiceItem& x) { return ServiceInfo::SameName(x.name, item); });
            if (!dup) {
                ServiceItem x;
                x.name    = item;
                x.display = ServiceInfo::DisplayName(item);
                out.push_back(std::move(x));
            }
        }
        if (comma == std::wstring::npos) break;
        pos = comma + 1;
    }
    return true;
}

bool ChooseProtocol(HWND owner, HINSTANCE inst, Proto& proto, bool& anyProto) {
    ProtoDlg d;
    d.proto = proto;
    d.any = anyProto;
    if (!d.Run(owner, inst, LoadStringRes(IDS_PROTO_DIALOG_TITLE), 520, 470)) return false;
    proto = d.proto;
    anyProto = d.any;
    return true;
}

bool ChooseAddresses(HWND owner, HINSTANCE inst, const wchar_t* title,
                     std::vector<AddrItem>& items) {
    AddrDlg d;
    d.items = items;
    DeduplicateAddresses(d.items);
    if (!d.Run(owner, inst, title ? title : LoadStringRes(IDS_RED_ADDR_DIALOG), 556, 520)) return false;
    items = d.items;
    return true;
}

bool ChoosePorts(HWND owner, HINSTANCE inst, const wchar_t* title,
                 std::vector<PortItem>& items) {
    PortDlg d;
    d.items = items;
    if (!d.Run(owner, inst, title ? title : LoadStringRes(IDS_PORT_DIALOG_TITLE), 540, 470)) return false;
    items = d.items;
    return true;
}

bool ChooseIcmpTypes(HWND owner, HINSTANCE inst, bool v6,
                     std::vector<IcmpTypeItem>& items) {
    IcmpDlg d;
    d.items = items;
    d.v6 = v6;
    if (!d.Run(owner, inst, v6 ? LoadStringRes(IDS_RDI_TITLE_V6) : LoadStringRes(IDS_RDI_TITLE_V4),
               560, 520)) return false;
    items = d.items;
    return true;
}

bool ChooseServices(HWND owner, HINSTANCE inst, std::vector<ServiceItem>& items) {
    ServiceDlg d;
    d.items = items;
    if (!d.Run(owner, inst, LoadStringRes(IDS_SERVICE_DIALOG_TITLE), 660, 560)) return false;
    items = d.items;
    return true;
}

bool ChooseInterface(HWND owner, HINSTANCE inst, std::wstring& name) {
    InterfaceDlg d;
    d.name = name;
    if (!d.Run(owner, inst, LoadStringRes(IDS_INTERFACE_FILTER_TITLE), 556, 390)) return false;
    name = std::move(d.name);
    return true;
}

bool ChooseWfpFlags(HWND owner, HINSTANCE inst, uint32_t& flags) {
    WfpFlagsDlg d;
    d.flags = flags;
    if (!d.Run(owner, inst, LoadStringRes(IDS_WFP_FLAGS_TITLE), 760, 560)) return false;
    flags = d.flags;
    return true;
}

bool ShowSaveError(HWND owner, const RuleStore& store, uint64_t& reportedVersion,
                   decltype(&MessageBoxW) showMessage) {
    const std::wstring error = store.dbError();
    const uint64_t version = store.version();
    if (error.empty() || reportedVersion == version) return false;

    // Отмечаем до MessageBox: его цикл сообщений может повторно вызвать проверку.
    const uint64_t previous = reportedVersion;
    reportedVersion = version;
    const int result = showMessage(owner,
        LoadStringResFmt(IDS_RULES_SAVE_FAILED_FMT, error.c_str()).c_str(),
        LoadStringRes(IDS_RULES_TITLE).c_str(), Ui::MessageBoxFlags(MB_ICONWARNING | MB_OK));
    if (!result) reportedVersion = previous;
    return result != 0;
}

bool FollowLink(HWND owner, HINSTANCE inst, Rule& r, const wchar_t* linkId) {
    if (!linkId) return false;

    if (wcscmp(linkId, RuleLink::kProto) == 0) {
        Proto p = r.proto;
        bool  any = !r.protoFixed();
        if (!ChooseProtocol(owner, inst, p, any)) return false;

        // SetProto снимает неприменимые условия и очищает несовместимые значения.
        r.SetProto(p, !any);
        return true;
    }

    // Направление — переключатель: значений два, и диалог был лишним шагом
    if (wcscmp(linkId, RuleLink::kDir) == 0) {
        r.ToggleDirection();
        return true;
    }

    // Фильтр PID существует только в PostApp: снятый флаг означает «любой».
    if (wcscmp(linkId, RuleLink::kPid) == 0) {
        if (!r.isPostApp()) return false;
        r.conds ^= CondPidZero;
        return true;
    }

    if (wcscmp(linkId, RuleLink::kInterface) == 0) {
        if (r.isInterface()) return false;
        return ChooseInterface(owner, inst, r.interfaceName);
    }

    if (wcscmp(linkId, RuleLink::kWfpFlags) == 0) {
        if (!ChooseWfpFlags(owner, inst, r.conditionFlags)) return false;
        if (!r.conditionFlags) r.conds &= ~CondWfpFlags;
        return true;
    }

    if (wcscmp(linkId, RuleLink::kService) == 0)
        return ChooseServices(owner, inst, r.services);

    if (wcscmp(linkId, RuleLink::kRAddr) == 0)
        return ChooseAddresses(owner, inst, LoadStringRes(IDS_RED_ADDR_DIALOG), r.remoteAddrs);
    if (wcscmp(linkId, RuleLink::kLAddr) == 0)
        return ChooseAddresses(owner, inst, LoadStringRes(IDS_RED_ADDR_DIALOG), r.localAddrs);
    if (wcscmp(linkId, RuleLink::kRPort) == 0) {
        if (!r.hasPorts()) return false;
        return ChoosePorts(owner, inst, LoadStringRes(IDS_PORT_DIALOG_TITLE), r.remotePorts);
    }
    if (wcscmp(linkId, RuleLink::kLPort) == 0) {
        if (!r.hasPorts()) return false;
        return ChoosePorts(owner, inst, LoadStringRes(IDS_PORT_DIALOG_TITLE), r.localPorts);
    }
    if (wcscmp(linkId, RuleLink::kIcmpType) == 0) {
        if (!r.isIcmp()) return false;
        return ChooseIcmpTypes(owner, inst, r.isIcmpV6(), r.icmpTypes);
    }

    // Действие — тоже переключатель
    if (wcscmp(linkId, RuleLink::kAction) == 0) {
        r.ToggleAction();
        return true;
    }
    return false;
}

} // namespace RuleDialogs