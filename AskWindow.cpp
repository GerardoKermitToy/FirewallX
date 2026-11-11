#include "AskWindow.h"
#include "UiKit.h"
#include "StringRes.h"
#include "SystemInfo.h"

#include <algorithm>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#endif

namespace {

const wchar_t* kClass = L"FirewallXAskWnd";

enum { IDC_ACT0 = 700, IDC_PRESETS = 704, IDC_ALLOW_ONCE = 705, IDC_BLOCK_ONCE = 706 };

// Подписи хранятся идентификаторами ресурсов; descId == 0 -> одна строка
struct ActionDef {
    AskAction action;
    UINT      titleId;
    UINT      descId;
};

const ActionDef kActions[4] = {
    { AskAction::Allow,     IDS_ACTION_ALLOW,       IDS_ACTION_ALLOW_DESC       },
    { AskAction::Block,     IDS_ACTION_BLOCK,       IDS_ACTION_BLOCK_DESC       },
    { AskAction::Terminate, IDS_ACTION_TERMINATE,   IDS_ACTION_TERMINATE_DESC   },
    { AskAction::Preset,    IDS_ACTION_USE_PRESETS, IDS_ACTION_USE_PRESETS_DESC },
};

COLORREF Blend(COLORREF a, COLORREF b, int pctB) {
    const int p = std::clamp(pctB, 0, 100);
    const auto mix = [p](int x, int y) { return (x * (100 - p) + y * p) / 100; };
    return RGB(mix(GetRValue(a), GetRValue(b)),
               mix(GetGValue(a), GetGValue(b)),
               mix(GetBValue(a), GetBValue(b)));
}

bool UsableOwner(HWND h) {
    return h && IsWindow(h) && IsWindowVisible(h) && !IsIconic(h);
}

// Рабочая область монитора, на котором находится окно (или курсор)
RECT WorkAreaFor(HWND h) {
    HMONITOR mon = nullptr;
    if (UsableOwner(h)) {
        mon = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
    } else {
        POINT pt{};
        GetCursorPos(&pt);
        mon = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
    }
    MONITORINFO mi{ sizeof(mi) };
    if (mon && GetMonitorInfoW(mon, &mi)) return mi.rcWork;

    RECT work{ 0, 0, 1280, 800 };
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    return work;
}

} // namespace

// --------------------------------------------------------------- служебное

void AskWindow::MakeFonts() {
    // Дескриптор кэша запоминаем: в FreeResources повторно запрашивать его
    // нельзя (см. комментарий к baseFont_ в заголовке).
    baseFont_ = Ui::MessageFont(dpi_);

    fBody_ = Ui::CreateDialogFont(dpi_);
    fBold_ = Ui::CreateDialogFont(dpi_, 9, FW_SEMIBOLD);
    fAct_  = Ui::CreateDialogFont(dpi_, 11, FW_SEMIBOLD);
    fBig_  = Ui::CreateDialogFont(dpi_, 11, FW_SEMIBOLD);
    if (!fBody_) fBody_ = baseFont_;    // крайний случай: кэш UiKit, не владеем
    if (!fBold_) fBold_ = fBody_;
    if (!fAct_)  fAct_  = fBody_;
    if (!fBig_)  fBig_  = fBold_;
}

void AskWindow::FreeResources() {
    // При fallback несколько полей могут ссылаться на один собственный шрифт.
    const HFONT fonts[] = { fBig_, fAct_, fBody_, fBold_ };
    for (size_t i = 0; i < std::size(fonts); ++i) {
        if (fonts[i] && fonts[i] != baseFont_ &&
            std::find(fonts, fonts + i, fonts[i]) == fonts + i)
            DeleteObject(fonts[i]);
    }
    fBig_ = fAct_ = fBody_ = fBold_ = nullptr;
    baseFont_ = nullptr;                // кэшем UiKit мы не владели
    icon_.reset();
    if (appIcon_) { DestroyIcon(appIcon_); appIcon_ = nullptr; }
    if (bandBr_)  { DeleteObject(bandBr_); bandBr_ = nullptr; }
    if (bodyBr_)  { DeleteObject(bodyBr_); bodyBr_ = nullptr; }
    if (warn_) { DestroyIcon(warn_); warn_ = nullptr; }
    for (int i = 0; i < 4; ++i) { btn_[i] = nullptr; hot_[i] = false; }
    presetsCombo_ = nullptr;
    for (HWND& button : once_) button = nullptr;
    presets_.clear();
}

int AskWindow::MeasureWrapped(HFONT f, const std::wstring& s, int width) const {
    if (!hwnd_) return Sc(18);
    HDC dc = GetDC(hwnd_);
    if (!dc) return Sc(18);
    HGDIOBJ old = f ? SelectObject(dc, f) : nullptr;
    RECT rc{ 0, 0, width, 0 };
    DrawTextW(dc, s.c_str(), -1, &rc, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    if (old) SelectObject(dc, old);
    ReleaseDC(hwnd_, dc);
    return rc.bottom - rc.top;
}

// Центрируем по главному окну; если оно недоступно — по рабочей области
// монитора с курсором. Результат обязательно укладывается в рабочую область,
// поэтому окно не уезжает под панель задач при большом главном окне.
void AskWindow::PlaceCentered() {
    if (!hwnd_) return;

    RECT frame{ 0, 0, cw_, ch_ };
    AdjustWindowRectExForDpi(&frame, style_, FALSE, exStyle_, dpi_);
    const int fw = frame.right - frame.left;
    const int fh = frame.bottom - frame.top;

    const RECT work = WorkAreaFor(owner_);

    RECT base = work;
    if (UsableOwner(owner_)) {
        RECT o{};
        if (GetWindowRect(owner_, &o) && o.right > o.left && o.bottom > o.top)
            base = o;
    }

    int x = base.left + ((base.right - base.left) - fw) / 2;
    int y = base.top  + ((base.bottom - base.top) - fh) / 2;

    x = std::clamp<int>(x, work.left, std::max<int>(work.left, work.right - fw));
    y = std::clamp<int>(y, work.top,  std::max<int>(work.top,  work.bottom - fh));

    SetWindowPos(hwnd_, HWND_TOPMOST, x, y, fw, fh, SWP_NOACTIVATE);
}

// ------------------------------------------------------------ создание окна

bool AskWindow::Show(HWND owner, HINSTANCE inst, ProcessIconRef icon,
                     const AskRequest& req, size_t queued,
                     const std::function<bool()>& canShow, const RuleStore* rules) {
    Close();

    owner_   = (owner && IsWindow(owner)) ? owner : nullptr;
    inst_    = inst;
    icon_    = std::move(icon);
    req_     = req;
    rules_   = rules;
    queued_  = queued;
    decided_ = false;

    dpi_ = owner_ ? GetDpiForWindow(owner_) : GetDpiForSystem();
    if (!dpi_) dpi_ = 96;

    WNDCLASSEXW wc{ sizeof(wc) };
    if (!GetClassInfoExW(inst, kClass, &wc)) {
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_DBLCLKS;
        wc.lpfnWndProc   = &AskWindow::Thunk;
        wc.hInstance     = inst;
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr;
        wc.lpszClassName = kClass;
        RegisterClassExW(&wc);
    }

    cw_ = Sc(520);
    ch_ = Sc(430);                      // уточняется в Build()

    style_   = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    exStyle_ = WS_EX_TOPMOST | WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME |
               Ui::LayoutStyle();

    HWND h = CreateWindowExW(exStyle_, kClass, LoadStringRes(IDS_WND_ASKDIALOG).c_str(), style_,
                             CW_USEDEFAULT, CW_USEDEFAULT, cw_, ch_,
                             owner_, nullptr, inst, this);
    if (!h) {
        icon_.reset();
        return false;
    }
    hwnd_ = h;

    // Build() уже посчитал итоговую высоту клиентской области
    PlaceCentered();

    // Shell при извлечении значка может прокачать вложенные сообщения, а SCM
    // тем временем — опубликовать новый снимок. Решённый запрос не должен даже
    // на мгновение появиться на экране или подать звуковой сигнал.
    if ((canShow && !canShow()) || !IsWindow(hwnd_)) {
        Close();
        return false;
    }

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
    SetForegroundWindow(hwnd_);
    if (btn_[0]) SetFocus(btn_[0]);
    Ui::PlayMessageBeep(MB_ICONWARNING);
    return true;
}

void AskWindow::Close() {
    if (hwnd_ && IsWindow(hwnd_)) {
        decided_ = true;                // не звать onDecision из-за DestroyWindow
        DestroyWindow(hwnd_);
    }
    hwnd_ = nullptr;
    icon_.reset();
}

void AskWindow::Restore() {
    if (!visible()) return;
    PlaceCentered();
    Ui::RestorePopup(hwnd_);
}

LRESULT CALLBACK AskWindow::Thunk(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        auto* self = static_cast<AskWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        if (self) self->hwnd_ = h;
        return DefWindowProcW(h, m, wp, lp);
    }
    auto* self = reinterpret_cast<AskWindow*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    return self ? self->Proc(h, m, wp, lp) : DefWindowProcW(h, m, wp, lp);
}

// Подсветка под курсором + курсор-рука: у BS_OWNERDRAW своего hot-состояния нет
LRESULT CALLBACK AskWindow::BtnProc(HWND h, UINT m, WPARAM wp, LPARAM lp,
                                   UINT_PTR id, DWORD_PTR ref) {
    auto* self = reinterpret_cast<AskWindow*>(ref);
    const size_t i = static_cast<size_t>(id);

    switch (m) {
    case WM_MOUSEMOVE:
        if (self && i < 4 && !self->hot_[i]) {
            self->hot_[i] = true;
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            InvalidateRect(h, nullptr, TRUE);
        }
        break;
    case WM_MOUSELEAVE:
        if (self && i < 4) { self->hot_[i] = false; InvalidateRect(h, nullptr, TRUE); }
        break;
    case WM_SETCURSOR:
        SetCursor(LoadCursorW(nullptr, IDC_HAND));
        return TRUE;
    case WM_NCDESTROY:
        RemoveWindowSubclass(h, &AskWindow::BtnProc, id);
        break;
    default:
        break;
    }
    return DefSubclassProc(h, m, wp, lp);
}

// --------------------------------------------------------------- раскладка

void AskWindow::Build() {
    MakeFonts();
    colors_ = Ui::DialogPalette();
    bandBr_ = CreateSolidBrush(colors_.surface);
    bodyBr_ = CreateSolidBrush(colors_.page);
    LoadIconWithScaleDown(nullptr, IDI_WARNING, Sc(44), Sc(44), &warn_);

    // Для пакетного приложения берём PNG из пакета, для обычного — значок EXE.
    // Крупный значок загружается отдельно, без растягивания маленького из списка.
    const int big = Sc(32);
    const HWND building = hwnd_;
    HICON loaded = ExtractApplicationIcon(req_.appPath, big,
                                          req_.process ? req_.process->h : nullptr);
    // Shell может прокачать сообщения и закрыть окно ещё до конца WM_CREATE.
    if (hwnd_ != building || !IsWindow(building)) {
        if (loaded) DestroyIcon(loaded);
        return;
    }
    appIcon_ = loaded;
    if (!appIcon_ && !icon_)
        appIcon_ = static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
                                                IMAGE_ICON, big, big, LR_COPYFROMRESOURCE));

    const int pad = Sc(16);
    const int titleX = pad + Sc(44) + Sc(12);

    const std::wstring title = LoadStringRes(IDS_ASK_PERMISSION_REQUIRED);
    const int titleH = MeasureWrapped(fBig_, title, cw_ - titleX - pad);
    bandH_ = std::max(Sc(72), pad + titleH + pad);

    int y = bandH_ + pad;
    questionY_ = y;
    y += Sc(19) + Sc(14);

    // ширина колонки подписей — по самой длинной
    labelW_ = Sc(112);
    if (hwnd_) {
        HDC dc = GetDC(hwnd_);
        if (dc) {
            HGDIOBJ old = SelectObject(dc, fBody_);
            // Длина берётся из самой строки: у перевода она другая
            const std::wstring lp = LoadStringRes(IDS_ASK_PROCESS);
            const std::wstring lr = LoadStringRes(IDS_ASK_REMOTE_ADDR);
            SIZE a{}, b{};
            GetTextExtentPoint32W(dc, lp.c_str(), static_cast<int>(lp.size()), &a);
            GetTextExtentPoint32W(dc, lr.c_str(), static_cast<int>(lr.size()), &b);
            labelW_ = std::max<LONG>(a.cx, b.cx) + Sc(10);
            if (old) SelectObject(dc, old);
            ReleaseDC(hwnd_, dc);
        }
    }

    infoY_ = y;
    y += Sc(23) * 2 + Sc(18);

    const int bx = pad - Sc(6);
    const int bw = cw_ - 2 * bx;
    for (int i = 0; i < 4; ++i) {
        const int bh = kActions[i].descId ? Sc(44) : Sc(28);
        const std::wstring caption = LoadStringRes(kActions[i].titleId);
        btn_[i] = CreateWindowExW(0, L"BUTTON", caption.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | BS_NOTIFY,
            bx, y, bw, bh, hwnd_,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_ACT0 + i)),
            inst_, nullptr);
        if (btn_[i])
            SetWindowSubclass(btn_[i], &AskWindow::BtnProc,
                              static_cast<UINT_PTR>(i),
                              reinterpret_cast<DWORD_PTR>(this));
        y += bh + Sc(6);
    }

    // Выбор применяется по подтверждению пункта, а большая кнопка также
    // применяет уже показанную предустановку. Программный выбор ничего не сохраняет.
    presets_ = RulePresets::Suggest(rules_ ? RequestForRuleCreation(req_, *rules_) : req_);
    const int comboX = bx + Sc(32);
    presetsCombo_ = CreateWindowExW(0, WC_COMBOBOXW, nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
        comboX, y, cw_ - comboX - pad, Sc(230), hwnd_,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PRESETS)), inst_, nullptr);
    if (presetsCombo_) {
        SendMessageW(presetsCombo_, WM_SETFONT, reinterpret_cast<WPARAM>(fBody_), FALSE);
        // По умолчанию выбираем наиболее полный подходящий набор правил.
        LRESULT defaultIndex = 0;
        size_t defaultRuleCount = 0;
        for (size_t i = 0; i < presets_.size(); ++i) {
            const LRESULT index = SendMessageW(presetsCombo_, CB_ADDSTRING, 0,
                reinterpret_cast<LPARAM>(presets_[i].title.c_str()));
            if (index >= 0) {
                SendMessageW(presetsCombo_, CB_SETITEMDATA, index, static_cast<LPARAM>(i));
                if (presets_[i].rules.size() > defaultRuleCount) {
                    defaultIndex = index;
                    defaultRuleCount = presets_[i].rules.size();
                }
            }
        }
        const std::wstring other = LoadStringRes(IDS_PRESET_OTHER);
        const LRESULT index = SendMessageW(presetsCombo_, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(other.c_str()));
        if (index >= 0) SendMessageW(presetsCombo_, CB_SETITEMDATA, index, -1);
        SendMessageW(presetsCombo_, CB_SETCURSEL, static_cast<WPARAM>(defaultIndex), 0);
    }
    y += Sc(30) + Sc(6);

    queueY_ = y;
    y += Sc(18) + pad;
    footerY_ = y;
    const int onceW = (cw_ - 2 * pad - Sc(8)) / 2;
    const UINT onceTitles[] = { IDS_ACTION_ALLOW_ONCE, IDS_ACTION_BLOCK_ONCE };
    const int onceIds[] = { IDC_ALLOW_ONCE, IDC_BLOCK_ONCE };
    for (int i = 0; i < 2; ++i) {
        const std::wstring caption = LoadStringRes(onceTitles[i]);
        once_[i] = CreateWindowExW(0, WC_BUTTONW, caption.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            pad + i * (onceW + Sc(8)), y + Sc(12), onceW, Sc(28), hwnd_,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(onceIds[i])), inst_, nullptr);
        if (once_[i])
            SendMessageW(once_[i], WM_SETFONT, reinterpret_cast<WPARAM>(fBody_), FALSE);
    }
    ch_ = y + Sc(52);
}

// ------------------------------------------------------------- отрисовка

void AskWindow::Paint(HDC dc) {
    const int saved = SaveDC(dc);
    const DWORD layout = GetLayout(dc);
    if (layout != GDI_ERROR) SetLayout(dc, layout | LAYOUT_BITMAPORIENTATIONPRESERVED);
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int pad = Sc(16);

    // полоса заголовка
    RECT band{ rc.left, rc.top, rc.right, bandH_ };
    if (bandBr_) FillRect(dc, &band, bandBr_);
    RECT body{ rc.left, bandH_, rc.right, rc.bottom };
    if (bodyBr_) FillRect(dc, &body, bodyBr_);
    HBRUSH border = CreateSolidBrush(colors_.border);
    RECT line{ rc.left, footerY_, rc.right, footerY_ + std::max(1, Sc(1)) };
    FillRect(dc, &line, border);
    RECT headerLine{ rc.left, bandH_ - 1, rc.right, bandH_ };
    FillRect(dc, &headerLine, border);
    DeleteObject(border);

    SetBkMode(dc, TRANSPARENT);

    const int ico = Sc(44);
    if (warn_)
        DrawIconEx(dc, pad, (bandH_ - ico) / 2, warn_, ico, ico,
                   0, nullptr, DI_NORMAL | DI_NOMIRROR);

    HGDIOBJ old = SelectObject(dc, fBig_);
    SetTextColor(dc, colors_.text);
    const std::wstring title = LoadStringRes(IDS_ASK_PERMISSION_REQUIRED);
    const bool rtl = (exStyle_ & WS_EX_LAYOUTRTL) != 0;
    RECT tr{ pad + ico + Sc(12), 0, rc.right - pad, bandH_ };
    RECT measured = tr;
    // Зеркальный DC уже располагает логический левый край текста рядом со значком.
    const UINT titleFlags = DT_WORDBREAK | DT_NOPREFIX | (rtl ? DT_RTLREADING : 0);
    DrawTextW(dc, title.c_str(), -1, &measured, DT_CALCRECT | titleFlags);
    tr.top = (bandH_ - (measured.bottom - measured.top)) / 2;
    DrawTextW(dc, title.c_str(), -1, &tr, titleFlags);

    // вопрос
    SelectObject(dc, fBody_);
    SetTextColor(dc, colors_.text);
    const std::wstring q = LoadStringResFmt(IDS_ASK_REQUESTS_FMT,
                                            req_.DirPhrase().c_str());
    RECT qr{ pad, questionY_, rc.right - pad, questionY_ + Sc(20) };
    DrawTextW(dc, q.c_str(), -1, &qr,
              DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

    // иконка процесса
    const int infoIcon = Sc(32);
    const int ix = pad;
    if (appIcon_) {
        DrawIconEx(dc, ix, infoY_ + Sc(4), appIcon_, infoIcon, infoIcon,
                   0, nullptr, DI_NORMAL | DI_NOMIRROR);
    } else if (icon_) {
        const int size = icon_->size();
        DrawIconEx(dc, ix + (infoIcon - size) / 2,
                   infoY_ + Sc(4) + (infoIcon - size) / 2,
                   icon_->handle(), size, size, 0, nullptr, DI_NORMAL | DI_NOMIRROR);
    }

    const int lx = ix + infoIcon + Sc(14);
    const int vx = lx + labelW_;
    const int rowH = Sc(23);

    const auto row = [&](int y, const wchar_t* label, const std::wstring& value,
                         bool bold, bool pathEllipsis, bool ltr) {
        SelectObject(dc, fBody_);
        SetTextColor(dc, colors_.secondary);
        RECT lr{ lx, y, vx - Sc(6), y + rowH };
        DrawTextW(dc, label, -1, &lr,
                  DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

        SelectObject(dc, bold ? fBold_ : fBody_);
        SetTextColor(dc, colors_.text);
        RECT vr{ vx, y, rc.right - pad, y + rowH };
        const std::wstring display = ltr && (exStyle_ & WS_EX_LAYOUTRTL)
            ? Ui::LtrText(value) : value;
        DrawTextW(dc, display.c_str(), -1, &vr,
                  DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX |
                  (pathEllipsis ? DT_PATH_ELLIPSIS : DT_END_ELLIPSIS));
    };

    const std::wstring pathText = req_.appPath.empty()
        ? (LoadStringRes(IDS_ASK_PATH_UNAVAILABLE) + req_.appName)
        : req_.appPath;
    row(infoY_,        LoadStringRes(IDS_ASK_PROCESS).c_str(),
        pathText,          false, true, !req_.appPath.empty());
    row(infoY_ + rowH, LoadStringRes(IDS_ASK_REMOTE_ADDR).c_str(),
        req_.RemoteText(), true,  false, true);

    // нижняя строка: очередь и область действия правила
    SelectObject(dc, fBody_);
    SetTextColor(dc, colors_.secondary);
    std::wstring note;
    if (queued_)
        note = LoadStringResFmt(IDS_ASK_MORE_IN_QUEUE_FMT,
                                static_cast<unsigned>(queued_));
    if (req_.key.source == TrafficSource::Ndis && req_.interfaceName && req_.interfaceName->empty()) {
        note += LoadStringRes(IDS_ACTION_ALLOW_ONCE) + L" / " + LoadStringRes(IDS_ACTION_BLOCK_ONCE);
    } else {
        // Правило хоста без пути автоматически создаётся только в PostApp.
        const UINT scopeStrId = req_.key.source == TrafficSource::Ndis ? IDS_INTERFACE_RULE
            : req_.appPath.empty() ? IDS_ASK_POSTAPP_RULE : IDS_ASK_APP_RULE;
        note += LoadStringRes(scopeStrId);
    }
    RECT nr{ pad, queueY_, rc.right - pad, queueY_ + Sc(20) };
    DrawTextW(dc, note.c_str(), -1, &nr,
              DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

    if (old) SelectObject(dc, old);
    RestoreDC(dc, saved);
}

void AskWindow::DrawAction(const DRAWITEMSTRUCT& dis) {
    const int i = static_cast<int>(dis.CtlID) - IDC_ACT0;
    if (i < 0 || i > 3) return;

    HDC dc = dis.hDC;
    if (!dc) return;
    RECT rc = dis.rcItem;
    const bool hot   = hot_[i];
    const bool focus = (dis.itemState & ODS_FOCUS) != 0;
    const bool pressed = (dis.itemState & ODS_SELECTED) != 0;
    const bool disabled = (dis.itemState & ODS_DISABLED) != 0;
    const COLORREF action = disabled ? colors_.secondary
        : i == 0 ? colors_.allow : i == 1 ? colors_.block : colors_.accent;
    COLORREF fill = colors_.surface;
    if (colors_.highContrast) {
        if (hot || pressed) fill = colors_.accent;
    } else if (hot || pressed) {
        fill = Blend(fill, colors_.accent, pressed ? 16 : 8);
    }
    HBRUSH bg = CreateSolidBrush(fill);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    HBRUSH border = CreateSolidBrush(hot || focus ? colors_.accent : colors_.border);
    FrameRect(dc, &rc, border);
    DeleteObject(border);
    const COLORREF titleColor = colors_.highContrast && (hot || pressed)
        ? GetSysColor(COLOR_HIGHLIGHTTEXT) : action;

    SetBkMode(dc, TRANSPARENT);
    const int arrowW = Sc(26);
    const int tx = rc.left + Sc(6) + arrowW;

    HGDIOBJ old = SelectObject(dc, fAct_);
    SetTextColor(dc, titleColor);
    RECT ar{ rc.left + Sc(6), rc.top + Sc(2), rc.left + Sc(6) + arrowW,
             rc.top + Sc(2) + Sc(22) };
    const wchar_t arrow = (exStyle_ & WS_EX_LAYOUTRTL) ? 0x2190 : 0x2192;
    DrawTextW(dc, &arrow, 1, &ar,
              DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);

    const std::wstring title = LoadStringRes(kActions[i].titleId);
    RECT tr{ tx, rc.top + Sc(2), rc.right - Sc(6), rc.top + Sc(2) + Sc(22) };
    DrawTextW(dc, title.c_str(), -1, &tr,
              DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

    if (kActions[i].descId) {
        const std::wstring desc = LoadStringRes(kActions[i].descId);
        SelectObject(dc, fBody_);
        SetTextColor(dc, colors_.highContrast && (hot || pressed)
            ? GetSysColor(COLOR_HIGHLIGHTTEXT) : colors_.secondary);
        RECT dr{ tx, rc.top + Sc(23), rc.right - Sc(6), rc.bottom - Sc(2) };
        DrawTextW(dc, desc.c_str(), -1, &dr,
                  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    if (old) SelectObject(dc, old);

    if (focus && !(dis.itemState & ODS_NOFOCUSRECT)) {
        RECT fr = rc;
        InflateRect(&fr, -Sc(2), -Sc(1));
        DrawFocusRect(dc, &fr);
    }
}

void AskWindow::Decide(AskAction a) {
    if (decided_) return;
    decided_ = true;

    // копии: обработчик может открыть модальный конструктор правила
    const AskRequest req = req_;
    AskDecision decision;
    decision.action = a;
    if (a == AskAction::Preset) {
        const LRESULT selected = presetsCombo_
            ? SendMessageW(presetsCombo_, CB_GETCURSEL, 0, 0) : CB_ERR;
        const LRESULT index = selected >= 0
            ? SendMessageW(presetsCombo_, CB_GETITEMDATA, selected, 0) : CB_ERR;
        if (index >= 0 && static_cast<size_t>(index) < presets_.size())
            decision.presetRules = presets_[static_cast<size_t>(index)].rules;
        else
            decision.action = AskAction::Custom;
    }
    auto cb = onDecision;

    HWND h = hwnd_;
    hwnd_ = nullptr;
    if (h && IsWindow(h)) DestroyWindow(h);

    // ВАЖНО: после этой строки к членам объекта не обращаемся — обработчик
    // вправе переиспользовать AskWindow (показать следующий запрос).
    if (cb) cb(req, decision);
}

LRESULT AskWindow::Proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE:
        hwnd_ = h;
        Build();
        return 0;

    case WM_ERASEBKGND:
        return 1;                       // всё рисуем в WM_PAINT

    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(h, &ps);
        if (dc) Paint(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkColor(dc, colors_.page);
        SetTextColor(dc, colors_.text);
        return reinterpret_cast<LRESULT>(bodyBr_);
    }
    case WM_DRAWITEM: {
        auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if (dis && dis->CtlType == ODT_BUTTON) { DrawAction(*dis); return TRUE; }
        break;
    }
    case WM_COMMAND: {
        const int id = LOWORD(wp);
        if (id == IDCANCEL) {
            // IsDialogMessageW преобразует Escape в команду IDCANCEL.
            Decide(AskAction::None);
            return 0;
        }
        if (id == IDC_PRESETS && HIWORD(wp) == CBN_SELENDOK) {
            Decide(AskAction::Preset);
            return 0;
        }
        if ((id == IDC_ALLOW_ONCE || id == IDC_BLOCK_ONCE) && HIWORD(wp) == BN_CLICKED) {
            Decide(id == IDC_ALLOW_ONCE ? AskAction::AllowOnce : AskAction::BlockOnce);
            return 0;
        }
        if (id >= IDC_ACT0 && id <= IDC_ACT0 + 3 && HIWORD(wp) == BN_CLICKED) {
            Decide(kActions[id - IDC_ACT0].action);
            return 0;                   // к членам после Decide не обращаемся
        }
        break;
    }
    case WM_KEYDOWN:
        if (wp == VK_ESCAPE) { Decide(AskAction::None); return 0; }
        break;

    case WM_CLOSE:
        Decide(AskAction::None);        // закрыли крестиком = отложить
        return 0;

    case WM_DESTROY:
        FreeResources();
        return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}