#include "AllRulesWindow.h"
#include "AppRulesEditor.h"
#include "StringRes.h"
#include "UiKit.h"
#include <commctrl.h>
#include <commdlg.h>
#include <windowsx.h>
#include <algorithm>

namespace {

class AllRules : public Ui::Modal {
public:
    RuleStore* store = nullptr;
    std::function<void()> onChanged;
    bool changed = false;

protected:
    bool ModernStyle() const override { return true; }

    enum { IDC_FILTER = 500, IDC_LIST, IDC_RULES, IDC_ADD, IDC_DEL, IDC_CLEANUP, IDC_COUNT };

    void OnInit() override {
        const auto& m = M();
        icons_.Create(m.dpi);

        SetHeader(LoadStringRes(IDS_ALLRULES_HEADER),
                  LoadStringRes(IDS_ALLRULES_SUBHEADER));

        const int x = m.margin();
        const int w = clientW() - 2 * m.margin();
        int y = headerH() + m.margin();

        const int lblW = m.Sc(52);
        Label(LoadStringRes(IDS_FILTER_LABEL), x, y + m.Sc(4), lblW, m.labelH());
        Edit(L"", x + lblW, y, w - lblW, m.editH(), IDC_FILTER);
        y += m.editH() + m.gap();

        const int btnW = m.btnW();
        const int listW = w - btnW - m.gap();
        const int listH = clientH() - y - m.margin() - m.btnH() - m.section() - m.labelH();

        ListView(x, y, listW, listH, IDC_LIST,
                 LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS);
        HWND lv = Item(IDC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                              LVS_EX_INFOTIP);
        ListView_SetImageList(lv, icons_.handle(), LVSIL_SMALL);

        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        c.iSubItem = 0;
        c.fmt = LVCFMT_LEFT;
        std::wstring colApp   = LoadStringRes(IDS_ALLRULES_COL_APP);
        std::wstring colCount = LoadStringRes(IDS_ALLRULES_COL_COUNT);
        c.pszText = colApp.data();
        c.cx = listW - m.Sc(110);
        ListView_InsertColumn(lv, 0, &c);
        c.iSubItem = 1;
        c.fmt = LVCFMT_RIGHT;
        c.pszText = colCount.data();
        c.cx = m.Sc(84);
        ListView_InsertColumn(lv, 1, &c);

        int by = y;
        Button(LoadStringRes(IDS_BTN_RULES), x + listW + m.gap(), by,
               btnW, m.btnH(), IDC_RULES, true);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_ADD_ELLIPSIS), x + listW + m.gap(), by,
               btnW, m.btnH(), IDC_ADD);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_DELETE), x + listW + m.gap(), by,
               btnW, m.btnH(), IDC_DEL);
        by += m.btnH() + m.gapS();
        Button(LoadStringRes(IDS_BTN_CLEANUP), x + listW + m.gap(), by,
               btnW, m.btnH(), IDC_CLEANUP);

        y += listH + m.gap();
        Note(L"", x, y, w, m.labelH(), IDC_COUNT, SS_CENTERIMAGE);

        Fill();
        OkCancel(LoadStringRes(IDS_BTN_CLOSE), LoadStringRes(IDS_BTN_CANCEL));
        ShowWindow(Item(IDCANCEL), SW_HIDE);      // окно закрывается одной кнопкой
    }

    bool OnCommand(int id, int code) override {
        if (id == IDC_FILTER && code == EN_CHANGE) { Fill(); return true; }
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
            // Здесь подтверждение остаётся: удаляются СРАЗУ ВСЕ правила
            // приложения и прямо в хранилище — отменить это уже нельзя.
            // Групп три: у постоянных групп пути нет, и подстановка e.path
            // в вопрос о приложении дала бы пустую строку.
            std::wstring q;
            if (e.global)
                q = LoadStringResFmt(IDS_ALLRULES_DEL_GLOBAL_FMT,
                                     static_cast<unsigned>(e.rules));
            else if (e.postapp)
                q = LoadStringResFmt(IDS_ALLRULES_DEL_POSTAPP_FMT,
                                     static_cast<unsigned>(e.rules));
            else
                q = LoadStringResFmt(IDS_ALLRULES_DEL_APP_FMT,
                                     e.name.c_str(), e.path.c_str(),
                                     static_cast<unsigned>(e.rules));
            if (Ui::ShowMessage(hwnd(), q.c_str(),
                            LoadStringRes(IDS_RULE_EDITOR_TITLE).c_str(),
                            MB_ICONWARNING | MB_YESNO) != IDYES) return true;
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
        if (hdr->idFrom != IDC_LIST) return false;

        switch (hdr->code) {
        case NM_DBLCLK:
            OnCommand(IDC_RULES, 0);
            res = 0;
            return true;

        // Del в списке равнозначен кнопке «Удалить»
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
                // подсвечиваем ссылкой только имя, счётчик оставляем обычным
                cd->clrTextBk = i & 1 ? colors().alternate : colors().surface;
                if (cd->iSubItem == 0)
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
                else if (e.interfaceGroup)
                    text = LoadStringRes(IDS_INTERFACE_DESC);
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
    void StoreChanged() {
        changed = true;
        if (onChanged) onChanged();
    }

    Ui::IconCache          icons_;
    std::vector<AppEntry>  shown_;

    int Selected() const {
        HWND lv = Item(IDC_LIST);
        const int i = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
        return (i >= 0 && i < static_cast<int>(shown_.size())) ? i : -1;
    }

    void Fill() {
        const std::wstring filter = FoldCaseCopy(Text(IDC_FILTER));
        const std::vector<AppEntry> all = store->Apps();

        shown_.clear();
        for (const AppEntry& e : all) {
            if (!filter.empty() &&
                FoldCaseCopy(e.name).find(filter) == std::wstring::npos &&
                FoldCaseCopy(e.path).find(filter) == std::wstring::npos) continue;
            shown_.push_back(e);
        }

        HWND lv = Item(IDC_LIST);
        SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(lv);
        int row = 0;
        for (const AppEntry& e : shown_) {
            LVITEMW it{};
            it.mask = LVIF_TEXT | LVIF_IMAGE;
            it.iItem = row;
            it.iImage = icons_.Get(e.path);
            it.pszText = const_cast<LPWSTR>(e.name.c_str());
            ListView_InsertItem(lv, &it);
            std::wstring cnt = std::to_wstring(e.rules);
            if (e.enabled != e.rules)
                cnt += L" (" + std::to_wstring(e.enabled) +
                       LoadStringRes(IDS_ALLRULES_ENABLED_SUFFIX);
            ListView_SetItemText(lv, row, 1, const_cast<LPWSTR>(cnt.c_str()));
            ++row;
        }
        SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(lv, nullptr, TRUE);

        // Считаем приложения отдельно в полном и отфильтрованном списках:
        // фильтр может скрыть любую из специальных групп Global и PostApp.
        const auto isApp = [](const AppEntry& e) { return !e.global && !e.postapp && !e.interfaceGroup; };
        const size_t apps = std::count_if(all.begin(), all.end(), isApp);
        const size_t listed = std::count_if(shown_.begin(), shown_.end(), isApp);
        SetText(IDC_COUNT, LoadStringResFmt(IDS_ALLRULES_STATS_FMT,
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
        Enable(IDC_DEL, entry && (entry->rules > 0 || (!entry->global && !entry->postapp && !entry->interfaceGroup)));
    }

    std::wstring BrowseExe() {
        wchar_t buf[MAX_PATH * 2]{};
        // В ресурсе фильтр хранится с разделителями «|»; перед вызовом
        // GetOpenFileNameW преобразуем их в нули формата lpstrFilter.
        std::wstring filter = LoadStringRes(IDS_ALLRULES_FILE_FILTER);
        for (wchar_t& ch : filter) if (ch == L'|') ch = L'\0';
        filter.push_back(L'\0');            // двойной ноль в конце списка

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

bool AllRulesWindow::Run(HWND owner, HINSTANCE inst, RuleStore& store,
                         const std::function<void()>& onChanged) {
    AllRules d;
    d.store = &store;
    d.onChanged = onChanged;
    d.Run(owner, inst, LoadStringRes(IDS_ALLRULES_EDITOR_TITLE), 640, 560);
    return d.changed;
}