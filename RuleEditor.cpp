#include "RuleEditor.h"
#include "RuleDialogs.h"
#include "RuleInheritanceUi.h"
#include "RuleInterfaceUi.h"
#include "StringRes.h"
#include "UiKit.h"
#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>

namespace {

// Подпись условия хранится идентификатором ресурса
struct CondRow { UINT textId; uint32_t flag; };

// «Где протокол» — тоже условие: снятая галочка означает «любой протокол».
// Без этого нельзя одним правилом описать весь трафик приложения: номеров
// протокола 256.
//
// «Где сервис» стоит рядом с направлением, а не среди адресов и портов:
// оно описывает не соединение, а процесс, который его открыл.
const CondRow kConds[] = {
    { IDS_COND_PROTO,        CondProto      },
    { IDS_COND_DIRECTION,    CondDirection  },
    { IDS_COND_SERVICE,      CondService    },
    { IDS_COND_INTERFACE,    CondInterface  },
    { IDS_COND_WFP_FLAGS,    CondWfpFlags   },
    { IDS_COND_ICMP_TYPE,    CondIcmpType   },
    { IDS_COND_REMOTE_ADDR,  CondRemoteAddr },
    { IDS_COND_REMOTE_PORT,  CondRemotePort },
    { IDS_COND_LOCAL_ADDR,   CondLocalAddr  },
    { IDS_COND_LOCAL_PORT,   CondLocalPort  },
    { IDS_COND_PID,          CondPidZero    },  // последняя строка — только для PostApp
};

constexpr int kPayloadHeight = 48;
constexpr int kPayloadSectionHeight = 16 + 4 + kPayloadHeight + 14;

std::wstring EncodeBase64(std::span<const uint8_t> bytes) {
    constexpr wchar_t alphabet[] =
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::wstring text;
    text.reserve(((bytes.size() + 2) / 3) * 4);
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const size_t count = std::min<size_t>(3, bytes.size() - i);
        uint32_t value = static_cast<uint32_t>(bytes[i]) << 16;
        if (count > 1) value |= static_cast<uint32_t>(bytes[i + 1]) << 8;
        if (count > 2) value |= bytes[i + 2];
        text += alphabet[(value >> 18) & 63];
        text += alphabet[(value >> 12) & 63];
        text += count > 1 ? alphabet[(value >> 6) & 63] : L'=';
        text += count > 2 ? alphabet[value & 63] : L'=';
    }
    return text;
}

LRESULT CALLBACK PayloadProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                             UINT_PTR id, DWORD_PTR) {
    // Обычный EDIT поддерживает копирование, но не выделение всего через Ctrl+A.
    if (msg == WM_CHAR && wp == 1) {
        SendMessageW(hwnd, EM_SETSEL, 0, -1);
        return 0;
    }
    if (msg == WM_NCDESTROY) RemoveWindowSubclass(hwnd, PayloadProc, id);
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// Условие применимо к выбранному протоколу?
// Сервис к протоколу отношения не имеет: он описывает процесс.
bool CondApplies(const Rule& r, uint32_t flag) {
    if (flag == CondPidZero) return r.isPostApp();
    if (flag == CondInterface) return !r.isInterface();
    if (flag == CondIcmpType) return r.isIcmp();
    if (flag == CondRemotePort || flag == CondLocalPort) return r.hasPorts();
    return true;
}

// Заполнен ли СПИСОК значений условия. У протокола и направления списка нет.
bool CondHasList(const Rule& r, uint32_t flag) {
    switch (flag) {
    case CondInterface:  return !r.interfaceName.empty();
    case CondWfpFlags:   return (r.conditionFlags & kSelectableWfpConditionFlags) != 0;
    case CondService:    return !r.services.empty();
    case CondIcmpType:   return !r.icmpTypes.empty();
    case CondRemoteAddr: return !r.remoteAddrs.empty();
    case CondLocalAddr:  return !r.localAddrs.empty();
    case CondRemotePort: return !r.remotePorts.empty();
    case CondLocalPort:  return !r.localPorts.empty();
    default: return false;
    }
}

// Можно ли оставить условие включённым.
//
// Протокол и направление значение имеют всегда. У сервиса пустой список тоже
// осмыслен — это «любой сервис», то есть «процесс обслуживает хотя бы один
// сервис», — поэтому условие не снимается автоматически. PID тоже не имеет
// списка: включённый флаг означает 0, выключенный — «любой».
bool CondKeepEnabled(const Rule& r, uint32_t flag) {
    if (flag == CondProto || flag == CondDirection || flag == CondService ||
        flag == CondPidZero) return true;
    return CondHasList(r, flag);
}

// Текст колонки «значение». Пустая строка = значения нет вовсе; «—» = условие
// к текущему протоколу не относится.
std::wstring CondValueText(const Rule& r, uint32_t flag) {
    if (!CondApplies(r, flag)) return LoadStringRes(IDS_RED_DASH);
    switch (flag) {
    case CondInterface:  return r.interfaceName;
    case CondWfpFlags:   return CondHasList(r, flag) ? r.ConditionFlagsText() : std::wstring();
    case CondProto:      return r.ProtoText();
    case CondDirection:  return r.DirTextRu();
    case CondPidZero:    return r.PidText();
    case CondService:    return r.ServicesText();     // пустой список -> «любой»
    case CondIcmpType:   return r.icmpTypes.empty()   ? std::wstring() : r.IcmpTypesText();
    case CondRemoteAddr: return r.remoteAddrs.empty() ? std::wstring() : r.AddrsText(true);
    case CondLocalAddr:  return r.localAddrs.empty()  ? std::wstring() : r.AddrsText(false);
    case CondRemotePort: return r.remotePorts.empty() ? std::wstring() : r.PortsText(true);
    case CondLocalPort:  return r.localPorts.empty()  ? std::wstring() : r.PortsText(false);
    default: return std::wstring();
    }
}

std::wstring InapplicableText(const Rule& r, uint32_t flag) {
    if (flag == CondIcmpType) {
        return LoadStringRes(r.protoFixed() ? IDS_RED_ICMP_ONLY
                                           : IDS_RED_ICMP_SET_PROTO);
    }
    if (!r.protoFixed())
        return LoadStringRes(IDS_RED_PORTS_ONLY);
    return LoadStringResFmt(IDS_RED_PROTO_NO_PORTS_FMT, r.ProtoText().c_str());
}

class Editor : public Ui::Modal {
public:
    Rule work;
    bool editing = false;
    bool topmost = false;
    std::wstring payloadBase64;
    bool inheritanceAvailable = false;
    RuleInheritance inheritance = RuleInheritance::Default;

protected:
    enum {
        IDC_CONDS = 300, IDC_HINT, IDC_APP, IDC_SCOPE, IDC_EXPLAIN,
        IDC_NAME, IDC_AUTONAME, IDC_COPY, IDC_PASTE, IDC_PAYLOAD, IDC_INHERITANCE, IDC_INHERITANCE_NEVER
    };

    bool ModernStyle() const override { return true; }
    bool Topmost() const override { return topmost; }
    bool StyledFooter() const override { return true; }
    int InitialFocusId() const override { return IDC_CONDS; }

    void OnInit() override {
        const auto& m = M();
        loading_ = true;
        dim_ = colors().secondary;
        for (const auto& row : kConds) {
            if (row.flag == CondPidZero && !work.isPostApp()) continue;
            if (row.flag == CondInterface && work.isInterface()) continue;
            conds_.push_back(row);
        }
        interfaces_.Watch(hwnd(), [this] { RefreshConds(); });

        std::wstring app = work.ScopeTextRu();
        if (app.empty()) app = LoadStringRes(IDS_RED_APP_NOT_SET);
        std::wstring desc = editing ? LoadStringRes(IDS_RED_EDIT_HINT)
                                    : LoadStringRes(IDS_RED_CREATE_HINT);
        desc += LoadStringRes(work.isInterface() ? IDS_INTERFACE_DESC
            : work.isGlobal() ? IDS_RED_GLOBAL_NOTE
            : work.isPostApp() ? IDS_RED_POSTAPP_NOTE : IDS_RED_APP_NOTE);
        // Значок берётся из самого файла: одноимённые программы в разных
        // каталогах иначе не различить, а правило привязано именно к пути.
        SetHeaderApp(work.isInterface() ? std::wstring() : work.appPath, app, desc);

        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = headerH() + m.margin();

        Label(LoadStringRes(IDS_RED_STEP1), x, y, w, m.labelH());
        y += m.labelH() + m.gapS();

        const int condH = m.rowH() * CondCount() + m.Sc(8);
        ListView(x, y, w, condH, IDC_CONDS,
                 LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
        HWND lv = Item(IDC_CONDS);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT |
                                              LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        const int nameW = m.Sc(190);
        const int valW  = std::max(m.Sc(90), w - nameW - m.Sc(26));
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        std::wstring colCond  = LoadStringRes(IDS_RED_COL_COND);
        std::wstring colValue = LoadStringRes(IDS_RED_COL_VALUE);
        col.iSubItem = 0;
        col.fmt = LVCFMT_LEFT;
        col.cx = nameW;
        col.pszText = colCond.data();
        ListView_InsertColumn(lv, 0, &col);
        col.iSubItem = 1;
        col.cx = valW;
        col.pszText = colValue.data();
        ListView_InsertColumn(lv, 1, &col);

        for (int i = 0; i < CondCount(); ++i) {
            std::wstring label = LoadStringRes(conds_[i].textId);
            LVITEMW it{};
            it.mask = LVIF_TEXT;
            it.iItem = i;
            it.pszText = label.data();
            ListView_InsertItem(lv, &it);
        }
        y += condH + m.gapS();

        Note(L"", x, y, w, m.labelH(), IDC_HINT);
        y += m.labelH() + m.section();

        const int noteW = m.Sc(230);
        Label((work.isGlobal() || work.isPostApp() || work.isInterface()) ? LoadStringRes(IDS_RED_STEP2_SCOPE)
                              : LoadStringRes(IDS_RED_STEP2_APP),
              x, y, w - noteW - m.gap(), m.labelH());
        Note(L"", x + w - noteW, y, noteW, m.labelH(), IDC_SCOPE, SS_RIGHT);
        y += m.labelH() + m.gapS();
        HWND application = ReadOnly(L"", x, y, w, m.editH(), IDC_APP);
        if (!work.isGlobal() && !work.appPath.empty()) Ui::KeepLeftToRight(application);
        y += m.editH() + m.section();

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

        if (!payloadBase64.empty()) {
            Label(LoadStringRes(IDS_RED_PAYLOAD), x, y, w, m.labelH());
            y += m.labelH() + m.gapS();
            HWND payload = Add(L"EDIT", L"",
                WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                WS_EX_CLIENTEDGE, x, y, w, m.Sc(kPayloadHeight), IDC_PAYLOAD);
            Ui::KeepLeftToRight(payload);
            // Полный Base64 остаётся одной строкой: переносы в поле только визуальные.
            SendMessageW(payload, EM_SETLIMITTEXT, 0, 0);
            SetWindowTextW(payload, payloadBase64.c_str());
            SetWindowSubclass(payload, PayloadProc, 0, 0);
            y += m.Sc(kPayloadHeight) + m.section();
        }

        Label(LoadStringRes(IDS_RED_STEP3),
              x, y, w, m.labelH());
        y += m.labelH() + m.gapS();
        const int explainH = m.Sc(150);
        Link(x, y, w, explainH, IDC_EXPLAIN);
        y += explainH + m.section();

        Label(LoadStringRes(IDS_RED_STEP4), x, y, w, m.labelH());
        y += m.labelH() + m.gapS();
        Edit(L"", x, y, w, m.editH(), IDC_NAME);
        y += m.editH() + m.gap();

        Check(LoadStringRes(IDS_RED_AUTONAME), x, y, m.Sc(230), m.checkH(), IDC_AUTONAME);
        Button(LoadStringRes(IDS_BTN_COPY), x + w - 2 * m.btnW() - m.gap(), y - m.Sc(3),
               m.btnW(), m.btnH(), IDC_COPY);
        Button(LoadStringRes(IDS_RED_BTN_PASTE),   x + w - m.btnW(), y - m.Sc(3),
               m.btnW(), m.btnH(), IDC_PASTE);
        FitFooter(y - m.Sc(3) + m.btnH() + m.section());

        Enable(IDC_PASTE, RuleClipboard::Has());
        loading_ = false;

        Load();
        OkCancel(LoadStringRes(IDS_RED_BTN_OK));
    }

    bool OnCommand(int id, int code) override {
        if (id == IDC_NAME && code == EN_CHANGE && !loading_) {
            work.autoName = false;
            work.name = Text(IDC_NAME);
            SetChecked(IDC_AUTONAME, false);
            return true;
        }
        switch (id) {
        case IDC_AUTONAME:
            work.autoName = Checked(IDC_AUTONAME);
            if (!work.autoName) work.name = Text(IDC_NAME);
            ApplyName();
            return true;
        case IDC_COPY:
            RuleClipboard::Set(work);
            Enable(IDC_PASTE, true);
            return true;
        case IDC_PASTE: {
            Rule c;
            if (!RuleClipboard::Get(c)) return true;
            const uint64_t     id2   = work.id;
            const RuleScope    scope = work.scope;
            const std::wstring path  = work.appPath;
            const std::wstring name  = work.appName;
            const int          prio  = work.priority;
            const bool         enabled = work.enabled;
            work = c;
            work.id       = id2;
            work.scope    = scope;
            work.appPath  = path;
            work.appName  = name;
            work.priority = prio;
            work.enabled  = enabled;
            NormalizeRuleConds(work);
            work.SyncName();
            Load();
            return true;
        }
        default:
            return false;
        }
    }

    bool OnNotify(LPNMHDR hdr, LRESULT& res) override {
        if (hdr->idFrom == IDC_EXPLAIN &&
            (hdr->code == NM_CLICK || hdr->code == NM_RETURN)) {
            auto* link = reinterpret_cast<PNMLINK>(hdr);
            if (RuleDialogs::FollowLink(hwnd(), inst(), work, link->item.szID)) {
                RefreshConds();
                RefreshExplain();
            }
            res = 0;
            return true;
        }
        if (hdr->idFrom == IDC_CONDS && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(hdr);
            switch (cd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                res = CDRF_NOTIFYITEMDRAW;
                return true;
            case CDDS_ITEMPREPAINT:
                res = CDRF_NOTIFYSUBITEMDRAW;
                return true;
            case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
                const int i = static_cast<int>(cd->nmcd.dwItemSpec);
                const bool sel = (ListView_GetItemState(Item(IDC_CONDS), i, LVIS_SELECTED) &
                                  LVIS_SELECTED) != 0;
                if (!sel && i >= 0 && i < CondCount()) {
                    const uint32_t flag = conds_[i].flag;
                    const bool on = (work.conds & flag) != 0;
                    cd->clrTextBk = i & 1 ? colors().alternate : colors().surface;
                    cd->clrText = !CondApplies(work, flag) || (cd->iSubItem == 1 && !on)
                        ? dim_ : colors().text;
                    if (flag == CondInterface && interfaces_.Unavailable(work))
                        cd->clrText = colors().block;
                    if (cd->iSubItem == 1 && on && CondApplies(work, flag))
                        SelectObject(cd->nmcd.hdc, semibold());
                }
                res = CDRF_NEWFONT;
                return true;
            }
            default:
                res = CDRF_DODEFAULT;
                return true;
            }
        }
        if (hdr->idFrom == IDC_CONDS && hdr->code == LVN_ITEMCHANGED && !loading_) {
            auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
            if ((nl->uChanged & LVIF_STATE) &&
                ((nl->uOldState ^ nl->uNewState) & LVIS_STATEIMAGEMASK)) {
                const bool checked = ((nl->uNewState & LVIS_STATEIMAGEMASK) >> 12) == 2;
                const int idx = nl->iItem;
                if (idx >= 0 && idx < CondCount()) {
                    const bool already = (work.conds & conds_[idx].flag) != 0;
                    if (already != checked) Toggle(idx, checked);
                }
            }
            res = 0;
            return true;
        }
        return false;
    }

    bool OnOk() override {
        if (inheritanceAvailable)
            inheritance = RuleInheritanceUi::Selected(Item(IDC_INHERITANCE), Item(IDC_INHERITANCE_NEVER));
        if (!work.autoName) {
            std::wstring n = Text(IDC_NAME);
            work.name = n.empty() ? work.BuildAutoName() : n;
        }
        NormalizeRuleConds(work);
        work.SyncName();
        return true;
    }

private:
    bool     loading_ = false;
    COLORREF dim_ = 0;
    std::vector<CondRow> conds_;
    RuleInterfaceUi interfaces_;

    int CondCount() const {
        return static_cast<int>(conds_.size());
    }

    void Load() {
        loading_ = true;
        std::wstring line;
        if (work.isInterface())
            line = work.appPath.empty() ? work.appName : work.appPath;
        else if (work.isGlobal() || work.isPostApp())
            line = LoadStringRes(IDS_RED_ALL_PROCESSES);
        else
            line = work.appPath.empty() ? LoadStringRes(IDS_RED_PATH_UNAVAILABLE) : work.appPath;
        SetText(IDC_APP, line);
        SetText(IDC_SCOPE, RuleScopeLine(work));
        loading_ = false;
        RefreshConds();
        RefreshExplain();
        ApplyName();
    }

    // Значения, взятые из соединения, но ещё не включённые как условие.
    // Протокол и направление сюда не относятся: у них значение есть всегда.
    bool HasPrefill() const {
        for (const CondRow& c : kConds)
            if (CondApplies(work, c.flag) && !(work.conds & c.flag) &&
                CondHasList(work, c.flag)) return true;
        return false;
    }

    void RefreshConds() {
        interfaces_.Refresh(std::span<const Rule>(&work, 1));
        const bool prev = loading_;
        loading_ = true;
        HWND lv = Item(IDC_CONDS);
        SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
        for (int i = 0; i < CondCount(); ++i) {
            const uint32_t flag = conds_[i].flag;
            ListView_SetCheckState(lv, i, (work.conds & flag) ? TRUE : FALSE);
            const std::wstring v = CondValueText(work, flag);
            ListView_SetItemText(lv, i, 1, const_cast<LPWSTR>(v.c_str()));
        }
        SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(lv, nullptr, TRUE);

        SetText(IDC_HINT, HasPrefill()
            ? LoadStringRes(IDS_RED_HINT_FROM_CONN)
            : LoadStringRes(IDS_RED_HINT_SIMULTANEOUS));
        loading_ = prev;
    }

    void RefreshExplain() {
        SetLinkText(IDC_EXPLAIN, RuleExplainMarkup(work), true);
        SetText(IDC_SCOPE, RuleScopeLine(work));
        if (work.autoName) ApplyName();
    }

    void ApplyName() {
        const bool prev = loading_;
        loading_ = true;
        SetText(IDC_NAME, work.autoName ? work.BuildAutoName() : work.name);
        SetChecked(IDC_AUTONAME, work.autoName);
        loading_ = prev;
    }

    void Toggle(int index, bool checked) {
        const uint32_t flag = conds_[index].flag;
        if (!checked) {
            work.conds &= ~flag;              // значение сохраняем
            NormalizeRuleConds(work);         // порты и тип могли потерять смысл
            RefreshConds();
            RefreshExplain();
            return;
        }
        if (!CondApplies(work, flag)) {
            Ui::ShowMessage(hwnd(), InapplicableText(work, flag).c_str(),
                        LoadStringRes(IDS_RED_RULE_WORD).c_str(),
                        MB_ICONINFORMATION);
            RefreshConds();
            return;
        }
        // SetProto должен видеть прежнее состояние условия протокола,
        // поэтому его флаг выставляется только после выбора в диалоге.
        if (flag != CondProto) work.conds |= flag;

        // диалог выбора нужен только там, где значения ещё нет
        switch (flag) {
        case CondProto: {
            Proto p = work.proto;
            bool any = false;
            if (RuleDialogs::ChooseProtocol(hwnd(), inst(), p, any))
                work.SetProto(p, !any);
            break;
        }
        case CondWfpFlags:
            if (!(work.conditionFlags & kSelectableWfpConditionFlags))
                RuleDialogs::ChooseWfpFlags(hwnd(), inst(), work.conditionFlags);
            break;
        case CondInterface:
            if (work.interfaceName.empty())
                RuleDialogs::ChooseInterface(hwnd(), inst(), work.interfaceName);
            break;
        case CondService:
            // Отмена выбора не должна включать условие «любой сервис».
            if (work.services.empty() &&
                !RuleDialogs::ChooseServices(hwnd(), inst(), work.services))
                work.conds &= ~flag;
            break;
        case CondIcmpType:
            if (work.icmpTypes.empty())
                RuleDialogs::ChooseIcmpTypes(hwnd(), inst(), work.isIcmpV6(), work.icmpTypes);
            break;
        case CondRemoteAddr:
            if (work.remoteAddrs.empty())
                RuleDialogs::ChooseAddresses(hwnd(), inst(), LoadStringRes(IDS_RED_ADDR_DIALOG), work.remoteAddrs);
            break;
        case CondLocalAddr:
            if (work.localAddrs.empty())
                RuleDialogs::ChooseAddresses(hwnd(), inst(), LoadStringRes(IDS_RED_ADDR_DIALOG), work.localAddrs);
            break;
        case CondRemotePort:
            if (work.remotePorts.empty())
                RuleDialogs::ChoosePorts(hwnd(), inst(), LoadStringRes(IDS_PORT_DIALOG_TITLE), work.remotePorts);
            break;
        case CondLocalPort:
            if (work.localPorts.empty())
                RuleDialogs::ChoosePorts(hwnd(), inst(), LoadStringRes(IDS_PORT_DIALOG_TITLE), work.localPorts);
            break;
        default:
            break;
        }
        // условие без значений бесполезно — снимаем флаг обратно
        if (!CondKeepEnabled(work, flag)) work.conds &= ~flag;

        NormalizeRuleConds(work);
        RefreshConds();
        RefreshExplain();
    }
};

} // namespace

bool RuleEditor::Run(HWND owner, HINSTANCE inst, Rule& rule, bool editing,
                     std::span<const uint8_t> payload, RuleInheritance* inheritance, bool topmost) {
    Editor d;
    d.work = rule;
    NormalizeRuleConds(d.work);
    d.editing = editing;
    d.topmost = topmost;
    d.inheritanceAvailable = inheritance && rule.scope == RuleScope::App &&
                             RuleStore::CanSetInheritance(rule.appPath);
    if (d.inheritanceAvailable) d.inheritance = *inheritance;
    if (!editing) d.payloadBase64 = EncodeBase64(payload);
    // Интерфейсное условие отсутствует в собственной группе интерфейса.
    const int height = 756 + (d.work.isPostApp() ? 20 : 0) +
        (d.work.isInterface() ? 0 : 20) +
        (d.payloadBase64.empty() ? 0 : kPayloadSectionHeight) +
        (d.inheritanceAvailable ? 80 : 0);
    if (!d.Run(owner, inst, editing ? LoadStringRes(IDS_RED_TITLE_EDIT) : LoadStringRes(IDS_RED_TITLE_CREATE),
                560, height))
        return false;
    rule = d.work;
    if (d.inheritanceAvailable) *inheritance = d.inheritance;
    return true;
}