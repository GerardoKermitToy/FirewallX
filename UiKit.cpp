#include "UiKit.h"
#include "StringRes.h"
#include "Settings.h"
#include "ProcessIcon.h"
#include <shellapi.h>
#include <uxtheme.h>
#include <algorithm>
#include <map>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#endif

namespace {

const wchar_t* kModalClass = L"FirewallXUiModal";
std::map<UINT, HFONT> g_msg, g_semi, g_mono, g_list;

// Состояние модальных окон меняется только из потока интерфейса.
int g_modalDepth = 0;
HWND g_modalWindow = nullptr;

struct ModalScope {
    ModalScope() : previous(g_modalWindow) { ++g_modalDepth; }
    ~ModalScope() {
        Restore();
        if (g_modalDepth > 0) --g_modalDepth;
    }
    void SetWindow(HWND window) { g_modalWindow = window; }
    void Restore() { g_modalWindow = previous; }
    HWND previous;
};

bool UsableOwner(HWND owner) {
    return owner && IsWindow(owner) && IsWindowVisible(owner) && !IsIconic(owner);
}

RECT PopupWorkArea(HWND owner) {
    HMONITOR monitor = nullptr;
    if (UsableOwner(owner)) {
        monitor = MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST);
    } else {
        POINT cursor{};
        GetCursorPos(&cursor);
        monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTOPRIMARY);
    }
    MONITORINFO info{sizeof(info)};
    if (monitor && GetMonitorInfoW(monitor, &info)) return info.rcWork;
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    return work;
}

POINT ClampPopupPosition(const RECT& window, const RECT& work, POINT position) {
    position.x = std::clamp<LONG>(position.x, work.left,
        std::max(work.left, work.right - (window.right - window.left)));
    position.y = std::clamp<LONG>(position.y, work.top,
        std::max(work.top, work.bottom - (window.bottom - window.top)));
    return position;
}

struct PopupSearch {
    HWND owner;
    HWND window = nullptr;
    unsigned depth = 0;
};

BOOL CALLBACK FindEnabledPopup(HWND window, LPARAM param) {
    auto& search = *reinterpret_cast<PopupSearch*>(param);
    if (!IsWindowEnabled(window)) return TRUE;
    const DWORD style = static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE));
    // Внутренние списки ComboBox и подсказки не являются модальными диалогами.
    if ((style & WS_CAPTION) != WS_CAPTION) return TRUE;
    unsigned depth = 0;
    for (HWND owner = GetWindow(window, GW_OWNER); owner; owner = GetWindow(owner, GW_OWNER)) {
        ++depth;
        if (owner != search.owner) continue;
        if (depth > search.depth) {
            search.window = window;
            search.depth = depth;
        }
        break;
    }
    return TRUE;
}

// приглушённый цвет для служебных подписей и описания в плашке заголовка
constexpr COLORREF kSecondaryText = RGB(0x5A, 0x5A, 0x62);

COLORREF Blend(COLORREF a, COLORREF b, int pctB) {
    const int p = std::clamp(pctB, 0, 100);
    const auto mix = [p](int x, int y) { return (x * (100 - p) + y * p) / 100; };
    return RGB(mix(GetRValue(a), GetRValue(b)),
               mix(GetGValue(a), GetGValue(b)),
               mix(GetBValue(a), GetBValue(b)));
}

// Метрики интерфейса для нужного DPI. Двухуровневый fallback + страховка от
// нулевого lfHeight: иначе CreateFontIndirectW отдаёт крошечный системный шрифт,
// по которому SysLink свёрстывает строки со слипшимся межстрочным интервалом.
bool QueryUiLogFont(UINT dpi, LOGFONTW& out) {
    NONCLIENTMETRICSW ncm{ sizeof(ncm) };
    if (SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, dpi)) {
        out = ncm.lfMessageFont;
    } else {
        ncm = NONCLIENTMETRICSW{ sizeof(ncm) };
        if (!SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
            return false;
        out = ncm.lfMessageFont;
        out.lfHeight = MulDiv(out.lfHeight, static_cast<int>(dpi), 96);
    }
    if (out.lfHeight == 0)
        out.lfHeight = -MulDiv(9, static_cast<int>(dpi), 72);   // ~9 pt
    if (out.lfFaceName[0] == L'\0')
        wcscpy_s(out.lfFaceName, L"Segoe UI");
    return true;
}

HFONT MakeFont(UINT dpi, int weight, const wchar_t* face) {
    LOGFONTW lf{};
    if (!QueryUiLogFont(dpi, lf)) return nullptr;
    if (weight) lf.lfWeight = weight;
    if (face)   wcscpy_s(lf.lfFaceName, face);
    return CreateFontIndirectW(&lf);
}

// Шрифт заданного КЕГЛЯ, а не размера из метрик оболочки.
HFONT MakeFontPt(UINT dpi, int pt, int weight, const wchar_t* face) {
    LOGFONTW lf{};
    if (!QueryUiLogFont(dpi, lf)) return nullptr;
    lf.lfHeight = -MulDiv(pt, static_cast<int>(dpi), 72);
    lf.lfWidth  = 0;
    if (weight) lf.lfWeight = weight;
    if (face)   wcscpy_s(lf.lfFaceName, face);
    return CreateFontIndirectW(&lf);
}

HFONT MakeEditorFont(UINT dpi, int pt, int weight) {
    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(pt, static_cast<int>(dpi), 72);
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcscpy_s(lf.lfFaceName, weight >= FW_SEMIBOLD ? L"Segoe UI Semibold" : L"Segoe UI");
    return CreateFontIndirectW(&lf);
}

bool ClassIs(HWND h, const wchar_t* name) {
    wchar_t buf[64]{};
    if (!GetClassNameW(h, buf, static_cast<int>(std::size(buf)))) return false;
    return _wcsicmp(buf, name) == 0;
}

const wchar_t* kLtrLayout = L"FirewallX.LeftToRight";

void SetLayoutTree(HWND window, bool rtl) {
    if (!window || !IsWindow(window)) return;
    if (GetPropW(window, kLtrLayout)) rtl = false;
    const bool edit = ClassIs(window, L"Edit");
    const LONG_PTR previous = GetWindowLongPtrW(window, GWL_EXSTYLE);
    LONG_PTR next = previous & ~static_cast<LONG_PTR>(WS_EX_LAYOUTRTL | WS_EX_RTLREADING |
                                                      WS_EX_RIGHT | WS_EX_LEFTSCROLLBAR);
    // EDIT не наследует зеркальный DC: Windows заменяет его RTLREADING.
    // Одного снятия LAYOUTRTL поэтому недостаточно ни для пути, ни при
    // возвращении с арабского на обычный язык.
    if (rtl) next |= edit ? WS_EX_RTLREADING | WS_EX_RIGHT | WS_EX_LEFTSCROLLBAR
                         : WS_EX_LAYOUTRTL;
    if (edit) {
        const LONG_PTR style = GetWindowLongPtrW(window, GWL_STYLE);
        if (!(style & ES_CENTER)) {
            const LONG_PTR alignment = (style & ~static_cast<LONG_PTR>(ES_RIGHT)) |
                                       (rtl ? ES_RIGHT : ES_LEFT);
            if (alignment != style) SetWindowLongPtrW(window, GWL_STYLE, alignment);
        }
    }
    if (next != previous) {
        SetWindowLongPtrW(window, GWL_EXSTYLE, next);
        SetWindowPos(window, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    }
    // Уже созданные контролы, включая заголовки таблиц, сами направление
    // при смене языка родителя не обновляют.
    for (HWND child = GetWindow(window, GW_CHILD); child;) {
        HWND following = GetWindow(child, GW_HWNDNEXT);
        SetLayoutTree(child, rtl);
        child = following;
    }
}

} // namespace

namespace Ui {

bool InitializeDpiAwareness() {
    const bool systemScaling = Settings::GetBool(Settings::Key::kSystemDpiScaling, false);
    // Манифест уже задаёт PerMonitorV2 для процесса, поэтому SetProcess... его
    // не переопределит. Все окна создаются потоком интерфейса и наследуют его
    // контекст. UNAWARE соответствует режиму «Система», не «Система (расширенная)».
    return SetThreadDpiAwarenessContext(systemScaling
        ? DPI_AWARENESS_CONTEXT_UNAWARE
        : DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != nullptr;
}

bool IsRightToLeft() {
    const UiLang language = CurrentUiLang();
    return language == UiLang::Arabic || language == UiLang::Persian;
}

DWORD LayoutStyle() { return IsRightToLeft() ? WS_EX_LAYOUTRTL : 0; }

void ApplyLayout(HWND window) {
    if (!window || !IsWindow(window)) return;
    SetLayoutTree(window, IsRightToLeft());
    RedrawWindow(window, nullptr, nullptr,
        RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
}

void KeepLeftToRight(HWND window) {
    if (!window) return;
    SetPropW(window, kLtrLayout, reinterpret_cast<HANDLE>(static_cast<INT_PTR>(1)));
    SetLayoutTree(window, false);
}

UINT PopupFlags(UINT flags) {
    if (!IsRightToLeft()) return flags;
    if (!(flags & (TPM_CENTERALIGN | TPM_RIGHTALIGN))) flags |= TPM_RIGHTALIGN;
    return flags | TPM_LAYOUTRTL;
}

bool AppendSubMenu(HMENU menu, HMENU submenu, const wchar_t* caption) {
    if (!submenu) return false;
    if (AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(submenu), caption))
        return true;
    CleanupMenuBitmaps(submenu);
    DestroyMenu(submenu);
    return false;
}

void CleanupMenuBitmaps(HMENU menu) {
    if (!menu) return;
    const int count = GetMenuItemCount(menu);
    for (int i = 0; i < count; ++i) {
        MENUITEMINFOW mii{};
        mii.cbSize = sizeof(mii);
        mii.fMask = MIIM_BITMAP | MIIM_SUBMENU;
        if (GetMenuItemInfoW(menu, i, TRUE, &mii)) {
            if (mii.hbmpItem && mii.hbmpItem != HBMMENU_CALLBACK &&
                mii.hbmpItem != HBMMENU_POPUP_CLOSE &&
                mii.hbmpItem != HBMMENU_POPUP_RESTORE &&
                mii.hbmpItem != HBMMENU_POPUP_MAXIMIZE &&
                mii.hbmpItem != HBMMENU_POPUP_MINIMIZE &&
                mii.hbmpItem != HBMMENU_MBAR_RESTORE &&
                mii.hbmpItem != HBMMENU_MBAR_MINIMIZE &&
                mii.hbmpItem != HBMMENU_MBAR_CLOSE &&
                mii.hbmpItem != HBMMENU_SYSTEM) {
                DeleteObject(mii.hbmpItem);
            }
            if (mii.hSubMenu)
                CleanupMenuBitmaps(mii.hSubMenu);
        }
    }
}

UINT MessageBoxFlags(UINT flags) {
    return flags | (IsRightToLeft() ? MB_RIGHT | MB_RTLREADING : 0);
}

int WINAPI ShowMessage(HWND owner, LPCWSTR text, LPCWSTR title, UINT flags) {
    return MessageBoxW(owner, text, title, MessageBoxFlags(flags));
}

void PlayMessageBeep(UINT type, decltype(&::MessageBeep) play) {
    if (!Settings::GetBool(Settings::Key::kMuteMessageBeep, false)) play(type);
}

std::wstring LtrText(const std::wstring& text) {
    constexpr wchar_t ltrEmbedding = 0x202A;
    constexpr wchar_t endEmbedding = 0x202C;
    return text.empty() ? text : ltrEmbedding + text + endEmbedding;
}

int ModalDepth() { return g_modalDepth; }

HWND ModalWindow(HWND owner) {
    HWND window = g_modalWindow;
    if (!window || !IsWindow(window)) {
        if (!owner || !IsWindow(owner) || IsWindowEnabled(owner)) return nullptr;
        window = owner;
    }
    if (IsWindowEnabled(window)) return window;
    // Системный диалог не входит в ModalDepth. GetLastActivePopup и
    // GW_ENABLEDPOPUP могут пропустить скрытое окно, поэтому проверяем владение.
    PopupSearch search{window};
    EnumThreadWindows(GetWindowThreadProcessId(window, nullptr), FindEnabledPopup,
                      reinterpret_cast<LPARAM>(&search));
    return search.window;
}

bool RestorePopup(HWND window) {
    if (!window || !IsWindow(window)) return false;
    const bool hidden = !IsWindowVisible(window) || IsIconic(window);
    if (IsIconic(window)) ShowWindow(window, SW_SHOWNOACTIVATE);

    RECT rect{};
    if (!GetWindowRect(window, &rect)) return false;
    RECT work = PopupWorkArea(GetWindow(window, GW_OWNER));
    MONITORINFO info{sizeof(info)};
    HMONITOR monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONULL);
    if (monitor && GetMonitorInfoW(monitor, &info)) work = info.rcWork;
    const POINT position = ClampPopupPosition(rect, work, POINT{rect.left, rect.top});
    const bool moved = position.x != rect.left || position.y != rect.top;
    if (moved)
        SetWindowPos(window, nullptr, position.x, position.y, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    if (hidden) ShowWindow(window, SW_SHOWNOACTIVATE);
    return hidden || moved;
}

HFONT MessageFont(UINT dpi) {
    auto it = g_msg.find(dpi);
    if (it != g_msg.end()) [[likely]] return it->second;
    HFONT f = MakeFont(dpi, 0, nullptr);
    if (!f) return static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    g_msg[dpi] = f;
    return f;
}

HFONT SemiBoldFont(UINT dpi) {
    auto it = g_semi.find(dpi);
    if (it != g_semi.end()) [[likely]] return it->second;
    HFONT f = MakeFont(dpi, FW_SEMIBOLD, nullptr);
    if (!f) return static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    g_semi[dpi] = f;
    return f;
}

HFONT MonoFont(UINT dpi) {
    auto it = g_mono.find(dpi);
    if (it != g_mono.end()) [[likely]] return it->second;
    HFONT f = MakeFont(dpi, 0, L"Consolas");
    if (!f) return static_cast<HFONT>(GetStockObject(SYSTEM_FIXED_FONT));
    g_mono[dpi] = f;
    return f;
}

// Кегль по умолчанию (kListFontPt) для классического оформления и заголовка;
// пользовательский шрифт строк выбирается отдельно в TreeList.
HFONT ListFont(UINT dpi) {
    auto it = g_list.find(dpi);
    if (it != g_list.end()) [[likely]] return it->second;
    HFONT f = MakeFontPt(dpi, kListFontPt, 0, kListFontFace);
    if (!f) return MessageFont(dpi);
    g_list[dpi] = f;
    return f;
}

void ReleaseFonts() {
    for (auto& kv : g_msg)  DeleteObject(kv.second);
    for (auto& kv : g_semi) DeleteObject(kv.second);
    for (auto& kv : g_mono) DeleteObject(kv.second);
    for (auto& kv : g_list) DeleteObject(kv.second);
    g_msg.clear(); g_semi.clear(); g_mono.clear(); g_list.clear();
}

// ------------------------------------------------------------- IconCache

bool IconCache::Create(UINT dpi) {
    Destroy();
    size_ = MulDiv(16, static_cast<int>(dpi), 96);
    il_ = ImageList_Create(size_, size_, ILC_COLOR32 | ILC_MASK, 64, 128);
    return il_ != nullptr;
}

void IconCache::Destroy() {
    if (il_) { ImageList_Destroy(il_); il_ = nullptr; }
    map_.clear();
}

int IconCache::Get(const std::wstring& path) {
    if (!il_) return -1;
    auto it = map_.find(path);
    if (it != map_.end()) return it->second;

    HICON ico = ExtractApplicationIcon(path, size_);
    // Для списка программ нужен запасной значок приложения, а не ассоциация
    // расширения. SHGetFileInfo ради заглушки дорого инициализирует Shell.
    if (!ico)
        ico = static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
            IMAGE_ICON, size_, size_, LR_COPYFROMRESOURCE));
    int index = -1;
    if (ico) {
        index = ImageList_ReplaceIcon(il_, -1, ico);
        DestroyIcon(ico);
    }
    map_[path] = index;
    return index;
}

// ----------------------------------------------------------------- Modal

DialogColors DialogPalette(bool modern) {
    HIGHCONTRASTW contrast{sizeof(contrast)};
    const bool highContrast = SystemParametersInfoW(SPI_GETHIGHCONTRAST,
        sizeof(contrast), &contrast, 0) && (contrast.dwFlags & HCF_HIGHCONTRASTON);
    const bool styled = modern && !highContrast;
    return {
        GetSysColor(COLOR_BTNFACE),
        GetSysColor(COLOR_WINDOW),
        styled ? RGB(0x20, 0x2A, 0x36) : GetSysColor(COLOR_WINDOWTEXT),
        styled ? RGB(0x5F, 0x6B, 0x7A) : GetSysColor(COLOR_GRAYTEXT),
        styled ? RGB(0xD5, 0xDC, 0xE4) : GetSysColor(COLOR_WINDOWTEXT),
        GetSysColor(COLOR_HIGHLIGHT),
        styled ? RGB(0xF7, 0xF9, 0xFB) : GetSysColor(COLOR_WINDOW),
        styled ? RGB(0x17, 0x66, 0x44) : GetSysColor(COLOR_WINDOWTEXT),
        styled ? RGB(0xB4, 0x23, 0x2A) : GetSysColor(COLOR_WINDOWTEXT),
        highContrast
    };
}

HFONT CreateDialogFont(UINT dpi, int pt, int weight) {
    return MakeEditorFont(dpi, pt, weight);
}

LRESULT DrawDialogList(NMLVCUSTOMDRAW& draw, const DialogColors& colors) {
    if (draw.nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
    if (draw.nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
        draw.clrTextBk = draw.nmcd.dwItemSpec & 1 ? colors.alternate : colors.surface;
        draw.clrText = IsWindowEnabled(draw.nmcd.hdr.hwndFrom)
            ? colors.text : GetSysColor(COLOR_GRAYTEXT);
    }
    return CDRF_DODEFAULT;
}

void Modal::CreateOwnFonts() {
    HFONT f = m_.modern ? MakeEditorFont(m_.dpi, 9, FW_NORMAL)
                        : MakeFont(m_.dpi, 0, nullptr);
    if (f) { font_ = f; ownFont_ = true; }
    else   { font_ = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT)); ownFont_ = false; }

    HFONT s = m_.modern ? MakeEditorFont(m_.dpi, 9, FW_SEMIBOLD)
                        : MakeFont(m_.dpi, FW_SEMIBOLD, nullptr);
    if (s) { semibold_ = s; ownSemi_ = true; }
    else   { semibold_ = font_; ownSemi_ = false; }
    titleFont_ = m_.modern ? MakeEditorFont(m_.dpi, 9, FW_SEMIBOLD) : nullptr;
    ownTitle_ = titleFont_ != nullptr;
    if (!titleFont_) titleFont_ = semibold_;
}

void Modal::DestroyOwnFonts() {
    if (ownFont_ && font_) DeleteObject(font_);
    if (ownSemi_ && semibold_) DeleteObject(semibold_);
    if (ownTitle_ && titleFont_) DeleteObject(titleFont_);
    font_ = semibold_ = titleFont_ = nullptr;
    ownFont_ = ownSemi_ = ownTitle_ = false;
}

// ---------------------------------------------------------------------------
// Закрытие модального окна.
//
// Порядок ЕДИНСТВЕННЫЙ верный: разрушая активное окно, система ищет, кому
// передать активность, и ОТКЛЮЧЁННОЕ окно пропускает. У вложенного диалога
// отключены все окна программы, поэтому подходящего окна внутри процесса не
// находится, и активность уходит другой программе. После этого наш процесс
// больше не владеет передним планом, и SetForegroundWindow система отклоняет.
//
//   1. включить владельца — теперь ему есть куда передать активность;
//   2. скрыть модальное окно: активность уходит уже включённому владельцу;
//   3. назначить владельца активным явно (страховка);
//   4. и только теперь разрушить модальное окно.
// ---------------------------------------------------------------------------
void Modal::Dismiss() {
    HWND self  = hwnd_;
    HWND owner = (owner_ && IsWindow(owner_)) ? owner_ : nullptr;

    const bool hadFocus = self && IsWindow(self) &&
                          (GetActiveWindow() == self || GetForegroundWindow() == self);

    // Владелец мог быть отключён другим диалогом ещё до нашего открытия.
    if (owner && ownerEnabled_) EnableWindow(owner, TRUE); // 1
    HWND target = owner && IsWindowEnabled(owner) ? owner : ModalWindow();
    if (self && IsWindow(self)) ShowWindow(self, SW_HIDE);   // 2
    if (hadFocus && target) SetActiveWindow(target); // 3
    if (self && IsWindow(self)) DestroyWindow(self); // 4

    if (hadFocus && target && IsWindow(target) && GetForegroundWindow() != target) {
        SetForegroundWindow(target);
        SetActiveWindow(target);
    }
}

bool Modal::Run(HWND owner, HINSTANCE inst, const std::wstring& title, int cw, int ch) {
    inst_ = inst;
    owner_ = (owner && IsWindow(owner)) ? GetAncestor(owner, GA_ROOT) : nullptr;
    ownerEnabled_ = owner_ && IsWindowEnabled(owner_);
    ModalScope scope;
    hints_.clear();
    notes_.clear();
    hair_.clear();
    surfaces_.clear();
    footerY_ = 0;
    hdrTitle_ = hdrDesc_ = nullptr;
    hdrH_ = 0;
    hdrIcon_ = nullptr;
    hdrIconOwned_ = false;
    hdrIconSize_ = 0;
    hdrTextX_ = 0;
    done_ = ok_ = initDone_ = false;

    m_.dpi = owner_ ? GetDpiForWindow(owner_) : GetDpiForSystem();
    if (!m_.dpi) m_.dpi = 96;
    m_.modern = ModernStyle();
    colors_ = DialogPalette(m_.modern);

    // шрифты нужны уже в OnInit (WM_CREATE), поэтому создаём до CreateWindow
    CreateOwnFonts();
    cw_ = m_.Sc(cw);
    ch_ = m_.Sc(ch);

    WNDCLASSEXW wc{ sizeof(wc) };
    if (!GetClassInfoExW(inst, kModalClass, &wc)) {
        wc.cbSize = sizeof(wc);
        wc.style = CS_DBLCLKS;
        wc.lpfnWndProc   = &Modal::Proc;
        wc.hInstance     = inst;
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr; // фон рисуем сами
        wc.lpszClassName = kModalClass;
        RegisterClassExW(&wc);
    }

    const DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    const DWORD ex    = WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT | LayoutStyle() |
                        (Topmost() ? WS_EX_TOPMOST : 0);
    RECT r{ 0, 0, cw_, ch_ };
    AdjustWindowRectExForDpi(&r, style, FALSE, ex, m_.dpi);

    // OnInit вызывается из WM_CREATE, поэтому hwnd_ выставляется в WM_NCCREATE
    HWND h = CreateWindowExW(ex, kModalClass, title.c_str(), style,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             r.right - r.left, r.bottom - r.top,
                             owner_, nullptr, inst, this);
    if (!h) { DestroyOwnFonts(); return false; }
    hwnd_ = h;

    RECT wr{};
    GetWindowRect(hwnd_, &wr);
    const RECT work = PopupWorkArea(owner_);
    RECT base = work;
    // У свёрнутого владельца GetWindowRect возвращает координаты около -32000.
    if (UsableOwner(owner_)) GetWindowRect(owner_, &base);
    const POINT position = ClampPopupPosition(wr, work, POINT{
        base.left + ((base.right - base.left) - (wr.right - wr.left)) / 2,
        base.top + ((base.bottom - base.top) - (wr.bottom - wr.top)) / 3});
    SetWindowPos(hwnd_, nullptr, position.x, position.y, 0, 0,
                 SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    scope.SetWindow(hwnd_);

    // ---- порядок ОТКРЫТИЯ ----
    // Владелец отключается ПОСЛЕ показа модального окна: отключение активного
    // окна освобождает активность, и если модального окна на экране ещё нет,
    // забрать её может чужая программа.
    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
    SetForegroundWindow(hwnd_);
    if (owner_) EnableWindow(owner_, FALSE);
    FocusFirst();

    MSG msg{};
    while (!done_) {
        const BOOL got = GetMessageW(&msg, nullptr, 0, 0);
        if (got == 0) {
            // WM_QUIT нельзя проглатывать: внешний цикл сообщений иначе
            // никогда не завершится, а диалог останется неразрушенным
            PostQuitMessage(static_cast<int>(msg.wParam));
            ok_ = false;
            break;
        }
        if (got < 0) { ok_ = false; break; }     // ошибка GetMessage
        if (!IsDialogMessageW(hwnd_, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // Закрываемое окно нельзя повторно показать из обработчика владельца.
    scope.Restore();
    Dismiss();
    ReleaseHeaderIcon(); // страховка, если WM_DESTROY не пришёл
    DestroyOwnFonts();
    hwnd_ = nullptr;
    owner_ = nullptr;
    return ok_;
}

LRESULT CALLBACK Modal::Proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        auto* self = static_cast<Modal*>(cs->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        if (self) self->hwnd_ = h; // ключевой момент: до WM_CREATE
        return DefWindowProcW(h, m, wp, lp);
    }
    auto* self = reinterpret_cast<Modal*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    return self ? self->Handle(h, m, wp, lp) : DefWindowProcW(h, m, wp, lp);
}

void Modal::EraseBackground(HDC dc) {
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    if (!faceBr_) faceBr_ = CreateSolidBrush(colors_.page);
    if (!winBr_) winBr_ = CreateSolidBrush(colors_.surface);
    FillRect(dc, &rc, faceBr_);
    if (hdrH_ > 0) {
        RECT top{rc.left, 0, rc.right, hdrH_};
        FillRect(dc, &top, winBr_);
        if (hdrIcon_ && hdrIconSize_ > 0) {
            DrawIconEx(dc, m_.margin(), (hdrH_ - 1 - hdrIconSize_) / 2, hdrIcon_,
                       hdrIconSize_, hdrIconSize_, 0, nullptr, DI_NORMAL | DI_NOMIRROR);
        }
    }
    if (m_.modern && StyledFooter() && footerY_ > 0) {
        RECT footer{rc.left, footerY_, rc.right, rc.bottom};
        FillRect(dc, &footer, winBr_);
    }
    if (!hairBr_) hairBr_ = CreateSolidBrush(m_.modern ? colors_.border
        : Blend(GetSysColor(COLOR_BTNFACE), GetSysColor(COLOR_BTNTEXT), 22));
    if (hdrH_ > 0) {
        RECT edge{rc.left, hdrH_ - 1, rc.right, hdrH_};
        FillRect(dc, &edge, hairBr_);
    }
    for (const RECT& surface : surfaces_) {
        FillRect(dc, &surface, winBr_);
        FrameRect(dc, &surface, hairBr_);
    }
    for (const RECT& line : hair_) FillRect(dc, &line, hairBr_);
}

void Modal::Surface(int x, int y, int w, int h) {
    surfaces_.push_back(RECT{x, y, x + w, y + h});
}

LRESULT Modal::ColorControl(HDC dc, HWND ctl) {
    if (!faceBr_) faceBr_ = CreateSolidBrush(colors_.page);
    if (!winBr_) winBr_ = CreateSolidBrush(colors_.surface);
    if (!hintBr_) hintBr_ = CreateSolidBrush(RGB(0xFF, 0xFF, 0xE1));
    const COLORREF secondary = m_.modern ? colors_.secondary : kSecondaryText;
    if (ctl && (ctl == hdrTitle_ || ctl == hdrDesc_)) {
        SetBkColor(dc, colors_.surface);
        SetTextColor(dc, ctl == hdrDesc_ ? secondary : colors_.text);
        return reinterpret_cast<LRESULT>(winBr_);
    }
    const auto background = controlBackgrounds_.find(ctl);
    if (background != controlBackgrounds_.end()) {
        POINT origin{};
        MapWindowPoints(ctl, background->second, &origin, 1);
        const int saved = SaveDC(dc);
        if (saved) {
            OffsetWindowOrgEx(dc, origin.x, origin.y, nullptr);
            SendMessageW(background->second, WM_PRINTCLIENT,
                         reinterpret_cast<WPARAM>(dc), PRF_CLIENT);
            RestoreDC(dc, saved);
        }
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, IsWindowEnabled(ctl) ? colors_.text : GetSysColor(COLOR_GRAYTEXT));
        return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
    }
    for (HWND h : notes_) {
        if (h != ctl) continue;
        SetBkColor(dc, colors_.page);
        SetTextColor(dc, secondary);
        return reinterpret_cast<LRESULT>(faceBr_);
    }
    for (HWND h : hints_) {
        if (h != ctl) continue;
        SetBkColor(dc, RGB(0xFF, 0xFF, 0xE1));
        SetTextColor(dc, colors_.text);
        return reinterpret_cast<LRESULT>(hintBr_);
    }
    if (ctl && (ClassIs(ctl, L"Edit") || ClassIs(ctl, L"SysLink") || ClassIs(ctl, L"ListBox"))) {
        SetBkColor(dc, colors_.surface);
        SetTextColor(dc, colors_.text);
        return reinterpret_cast<LRESULT>(winBr_);
    }
    if (ctl && ClassIs(ctl, L"Button")) {
        const UINT type = static_cast<UINT>(GetWindowLongPtrW(ctl, GWL_STYLE)) & BS_TYPEMASK;
        if (type == BS_CHECKBOX || type == BS_AUTOCHECKBOX ||
            type == BS_3STATE || type == BS_AUTO3STATE) {
            // Стандартные окна сохраняют белую страницу вкладки, а редакторы
            // используют собственную подложку без полос вокруг флажков.
            SetBkColor(dc, m_.modern ? colors_.page : colors_.surface);
            SetTextColor(dc, colors_.text);
            return reinterpret_cast<LRESULT>(m_.modern ? faceBr_ : winBr_);
        }
    }
    if (ctl && ClassIs(ctl, L"Static")) {
        if (m_.modern) {
            SetBkColor(dc, colors_.page);
            SetTextColor(dc, colors_.text);
            return reinterpret_cast<LRESULT>(faceBr_);
        }
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, colors_.text);
        return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
    }
    if (m_.modern && StyledFooter() && ctl && footerY_ > 0) {
        RECT rect{};
        GetWindowRect(ctl, &rect);
        MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&rect), 2);
        if (rect.top >= footerY_) {
            SetBkColor(dc, colors_.surface);
            SetTextColor(dc, colors_.text);
            return reinterpret_cast<LRESULT>(winBr_);
        }
    }
    SetBkColor(dc, colors_.page);
    SetTextColor(dc, GetSysColor(COLOR_BTNTEXT));
    return reinterpret_cast<LRESULT>(faceBr_);
}

void Modal::FocusFirst() {
    HWND next = InitialFocusId() ? Item(InitialFocusId()) : nullptr;
    if (!next || !IsWindowEnabled(next)) next = GetNextDlgTabItem(hwnd_, nullptr, FALSE);
    if (next) SetFocus(next);
}

// Уведомление от контрола, созданного САМИМ диалогом. Всё остальное —
// заголовок списка, всплывающая подсказка, внутренний редактор — присылает
// структуры иного вида, приводить их к NMLISTVIEW/NMLVCUSTOMDRAW нельзя.
bool Modal::NotifyFromChild(LPNMHDR hdr) const {
    if (!hdr || !hwnd_ || !hdr->hwndFrom) return false;
    if (!IsWindow(hdr->hwndFrom)) return false;
    if (GetParent(hdr->hwndFrom) != hwnd_) return false;
    return GetDlgItem(hwnd_, static_cast<int>(hdr->idFrom)) == hdr->hwndFrom;
}

LRESULT Modal::Handle(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE:
        hwnd_ = h; // страховка, если NCCREATE был перехвачен
        OnInit();
        initDone_ = true;
        return 0;

    case WM_ERASEBKGND:
        EraseBackground(reinterpret_cast<HDC>(wp));
        return 1;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN:
        return ColorControl(reinterpret_cast<HDC>(wp), reinterpret_cast<HWND>(lp));

    case WM_COMMAND: {
        const int id = LOWORD(wp), code = HIWORD(wp);
        if (initDone_ && OnCommand(id, code)) return 0;
        if (id == IDOK)     { if (OnOk()) EndOk(); return 0; }
        if (id == IDCANCEL) { OnCancel(); EndCancel(); return 0; }
        break;
    }
    case WM_NOTIFY: {
        LPNMHDR hdr = reinterpret_cast<LPNMHDR>(lp);
        if (m_.modern && StyledFooter() && !colors_.highContrast && hdr &&
            hdr->hwndFrom == Item(IDOK) && hdr->code == NM_CUSTOMDRAW)
            return DrawPrimaryButton(*reinterpret_cast<NMCUSTOMDRAW*>(hdr), colors_, semibold_, m_.dpi);
        LRESULT res = 0;
        if (initDone_ && NotifyFromChild(hdr)) {
            if (OnNotify(hdr, res)) return res;
            if (m_.modern && hdr->code == NM_CUSTOMDRAW && ClassIs(hdr->hwndFrom, WC_LISTVIEWW))
                return DrawDialogList(*reinterpret_cast<NMLVCUSTOMDRAW*>(hdr), colors_);
        }
        break;
    }
    case WM_CLOSE:
        OnCancel();
        EndCancel();
        return 0;

    case WM_DESTROY:
        if (faceBr_) { DeleteObject(faceBr_); faceBr_ = nullptr; }
        if (winBr_)  { DeleteObject(winBr_);  winBr_  = nullptr; }
        if (hintBr_) { DeleteObject(hintBr_); hintBr_ = nullptr; }
        if (hairBr_) { DeleteObject(hairBr_); hairBr_ = nullptr; }
        ReleaseHeaderIcon();
        // дескрипторы дочерних окон становятся недействительными
        hdrTitle_ = hdrDesc_ = nullptr;
        hints_.clear();
        notes_.clear();
        controlBackgrounds_.clear();
        // Окно разрушено ИЗВНЕ (например, вместе с владельцем): это равносильно
        // отмене. Собственное разрушение приходит уже после done_ = true.
        if (!done_) { ok_ = false; done_ = true; }
        return 0;

    case WM_NCDESTROY:
        // дочерние окна уже уничтожены — шрифты больше нигде не выбраны
        DestroyOwnFonts();
        return DefWindowProcW(h, m, wp, lp);
    }
    return DefWindowProcW(h, m, wp, lp);
}

// Окно НЕ разрушается: это делает Dismiss после выхода из цикла сообщений.
void Modal::EndOk()     { ok_ = true;  done_ = true; }
void Modal::EndCancel() { ok_ = false; done_ = true; }

int Modal::MeasureBlock(HFONT f, const std::wstring& s, int w, bool wrap) const {
    if (!hwnd_ || s.empty() || w <= 0) return 0;
    HDC dc = GetDC(hwnd_);
    if (!dc) return 0;
    HGDIOBJ old = f ? SelectObject(dc, f) : nullptr;
    RECT rc{ 0, 0, w, 0 };
    const UINT flags = DT_CALCRECT | DT_NOPREFIX |
                       (wrap ? DT_WORDBREAK : DT_SINGLELINE);
    DrawTextW(dc, s.c_str(), -1, &rc, flags);
    if (old) SelectObject(dc, old);
    ReleaseDC(hwnd_, dc);
    return rc.bottom - rc.top;
}

// ---------------------------------------------------------------------------
// Значок плашки.
//
// Берётся по полному пути: из EXE либо из регистрации соответствующего
// пакета. Одноимённые файлы в разных каталогах не смешиваются; редактор
// показывает именно ту программу, чьи правила правятся.
//
// Пустой путь — область «все процессы»: обобщённый значок приложения передаёт
// смысл «любая программа» точнее, чем отсутствие значка.
// ---------------------------------------------------------------------------
void Modal::LoadHeaderIcon(const std::wstring& appPath, int px) {
    ReleaseHeaderIcon();
    if (px <= 0) return;

    HICON ico = ExtractApplicationIcon(appPath, px);
    if (!ico)
        ico = static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
            IMAGE_ICON, px, px, LR_COPYFROMRESOURCE));
    if (ico) {
        hdrIcon_ = ico;
        hdrIconOwned_ = true;
        hdrIconSize_ = px;
        return;
    }

    // Крайний случай. Стоковый значок разделяемый: удалять его НЕЛЬЗЯ.
    hdrIcon_ = LoadIconW(nullptr, IDI_APPLICATION);
    hdrIconOwned_ = false;
    hdrIconSize_ = hdrIcon_ ? px : 0;
}

void Modal::ReleaseHeaderIcon() {
    if (hdrIcon_ && hdrIconOwned_) DestroyIcon(hdrIcon_);
    hdrIcon_ = nullptr;
    hdrIconOwned_ = false;
    hdrIconSize_ = 0;
}

// ---------------------------------------------------------------------------
// Плашка заголовка.
//
// Высота НЕ фиксирована: она измеряется по фактическому тексту. Описание
// переносится по словам (обычный SS_LEFT переносит текст сам), а вся плашка
// растёт вниз; производные классы отсчитывают раскладку от headerH(), поэтому
// подстраиваются без правок.
//
// Заголовку перенос не нужен: это имя приложения либо название области
// действия, и для него обрезка по ширине уместна.
// ---------------------------------------------------------------------------
void Modal::BuildHeader(const std::wstring& title, const std::wstring& desc,
                        bool withIcon, const std::wstring& appPath) {
    const int pad = M().margin();
    const int gap = M().Sc(3);

    int textX = pad;
    if (withIcon) {
        LoadHeaderIcon(appPath, M().Sc(32));
        if (hdrIconSize_ > 0) textX = pad + hdrIconSize_ + M().gap();
    }
    hdrTextX_ = textX;

    const int w = cw_ - textX - pad;

    int titleH = MeasureBlock(titleFont_, title, w, false);
    if (titleH <= 0) titleH = M().Sc(20);

    int descH = MeasureBlock(font_, desc, w, true);
    if (descH > 0) descH += M().Sc(2); // статик переносит чуть иначе
    // Предел на случай непредвиденно длинного описания: плашка не должна
    // вытеснить содержимое окна.
    const int maxDescH = M().Sc(19) * 4;
    if (descH > maxDescH) descH = maxDescH;

    hdrH_ = pad + titleH + (descH > 0 ? gap + descH : 0) + pad;
    // Значок не должен упираться в края плашки: у однострочного заголовка
    // текстовый блок ниже значка.
    if (hdrIconSize_ > 0)
        hdrH_ = std::max(hdrH_, hdrIconSize_ + 2 * M().Sc(8));

    hdrTitle_ = Add(L"STATIC", title.c_str(), SS_LEFT | SS_ENDELLIPSIS, 0,
                    textX, pad, w, titleH, -1, titleFont_);
    if (descH > 0)
        hdrDesc_ = Add(L"STATIC", desc.c_str(), SS_LEFT | SS_NOPREFIX, 0,
                       textX, pad + titleH + gap, w, descH, -1);
}

void Modal::SetHeader(const std::wstring& title, const std::wstring& desc) {
    BuildHeader(title, desc, false, std::wstring());
}

// Пустой appPath = область «все процессы»: BuildHeader подставит обобщённый
// значок приложения, потому что «любая программа» — это тоже определённый
// смысл, а не отсутствие значка.
void Modal::SetHeaderApp(const std::wstring& appPath, const std::wstring& title,
                         const std::wstring& desc) {
    BuildHeader(title, desc, true, appPath);
}

void Modal::FitFooter(int y) {
    RECT rect{};
    if (!GetWindowRect(hwnd_, &rect)) return;
    const int height = y + 2 * M().margin() + M().btnH();
    if (SetWindowPos(hwnd_, nullptr, 0, 0, rect.right - rect.left,
                     rect.bottom - rect.top + height - ch_,
                     SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE)) {
        ch_ = height;
        footerY_ = y;
    }
}

void Modal::Footer() {
    if (!m_.modern || !StyledFooter()) return;
    const int defaultTop = footerTop();
    footerY_ = footerY_ > 0 ? std::min(footerY_, defaultTop) : defaultTop;
    Hairline(0, footerY_, cw_);
}

void Modal::OkCancel(const wchar_t* okText, const wchar_t* cancelText) {
    Footer();
    const int y = ch_ - M().margin() - M().btnH();
    const int x2 = cw_ - M().margin() - M().btnW();
    const int x1 = x2 - M().gap() - M().btnW();
    Button(okText, x1, y, M().btnW(), M().btnH(), IDOK, true);
    Button(cancelText, x2, y, M().btnW(), M().btnH(), IDCANCEL);
}

void Modal::OkCancel() {
    OkCancel(LoadStringRes(IDS_BTN_OK), LoadStringRes(IDS_BTN_CANCEL));
}

void Modal::OkCancel(const wchar_t* okText) {
    OkCancel(okText, LoadStringRes(IDS_BTN_CANCEL).c_str());
}

int Modal::MeasureCaption(const wchar_t* text) const {
    if (!hwnd_ || !text || !*text) return 0;
    HDC dc = GetDC(hwnd_);
    if (!dc) return 0;
    HGDIOBJ old = semibold_ ? SelectObject(dc, semibold_) : nullptr;
    SIZE sz{};
    GetTextExtentPoint32W(dc, text, lstrlenW(text), &sz);
    if (old) SelectObject(dc, old);
    ReleaseDC(hwnd_, dc);
    return sz.cx;
}

void Modal::Hairline(int x, int y, int w) {
    if (w <= 0) return;
    const int t = std::max(1, M().Sc(1));
    hair_.push_back(RECT{ x, y, x + w, y + t });
}

int Modal::SectionHeader(const wchar_t* text, int x, int y, int w) {
    const int h = M().labelH();
    if (!text || !*text) {
        Hairline(x, y + h / 2, w);
        return h + M().gapS();
    }

    int tw = MeasureCaption(text);
    if (tw <= 0 || tw > w) tw = w;

    Add(L"STATIC", text, SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, 0,
        x, y, tw + M().Sc(2), h, -1, semibold_);

    // линия начинается за текстом и идёт до правой границы раздела
    const int lx = x + tw + M().gap();
    if (x + w - lx >= M().Sc(12)) Hairline(lx, y + h / 2, x + w - lx);
    return h + M().gapS();
}

HWND Modal::Add(const wchar_t* cls, const wchar_t* text, DWORD style, DWORD exStyle,
                int x, int y, int w, int h, int id, HFONT f) {
    if (!hwnd_) return nullptr;
    HWND c = CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style,
                             x, y, w, h, hwnd_,
                             id >= 0 ? reinterpret_cast<HMENU>(static_cast<UINT_PTR>(id))
                                     : nullptr,
                             inst_, nullptr);
    if (c && ClassIs(c, L"Edit"))
        SetLayoutTree(c, (GetWindowLongPtrW(hwnd_, GWL_EXSTYLE) & WS_EX_LAYOUTRTL) != 0);
    if (c) SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(f ? f : font_), TRUE);
    return c;
}

HWND Modal::Label(const wchar_t* text, int x, int y, int w, int h, int id, DWORD extra) {
    return Add(L"STATIC", text, SS_LEFT | extra, 0, x, y, w, h, id);
}

HWND Modal::Note(const wchar_t* text, int x, int y, int w, int h, int id, DWORD extra) {
    const DWORD overflow = m_.modern && h > M().labelH() ? 0 : SS_ENDELLIPSIS;
    HWND s = Add(L"STATIC", text, SS_LEFT | SS_NOPREFIX | overflow | extra, 0, x, y, w, h, id);
    if (s) notes_.push_back(s);
    return s;
}

HWND Modal::Group(const wchar_t* text, int x, int y, int w, int h, int id) {
    return Add(L"BUTTON", text, BS_GROUPBOX, 0, x, y, w, h, id);
}

void Modal::StyleField(HWND control) {
    if (!control || !m_.modern) return;
    // SysIPAddress добавляет утопленную рамку сам во время создания окна.
    SetWindowLongPtrW(control, GWL_EXSTYLE,
                     GetWindowLongPtrW(control, GWL_EXSTYLE) & ~WS_EX_CLIENTEDGE);
    SetWindowSubclass(control, FieldProc, 0, reinterpret_cast<DWORD_PTR>(this));
    SetWindowPos(control, nullptr, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

HWND Modal::Edit(const wchar_t* text, int x, int y, int w, int h, int id, DWORD extra) {
    HWND control = Add(L"EDIT", text, WS_TABSTOP | ES_AUTOHSCROLL | extra,
                        m_.modern ? 0 : WS_EX_CLIENTEDGE, x, y, w, h, id);
    StyleField(control);
    return control;
}

HWND Modal::LtrEdit(const wchar_t* text, int x, int y, int w, int h, int id) {
    HWND control = Edit(text, x, y, w, h, id);
    KeepLeftToRight(control);
    return control;
}

HWND Modal::ReadOnly(const wchar_t* text, int x, int y, int w, int h, int id) {
    return Edit(text, x, y, w, h, id, ES_READONLY);
}

HWND Modal::Button(const wchar_t* text, int x, int y, int w, int h, int id, bool def) {
    return Add(L"BUTTON", text,
               WS_TABSTOP | (def ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON), 0,
               x, y, w, h, id);
}

HWND Modal::Check(const wchar_t* text, int x, int y, int w, int h, int id) {
    return Add(L"BUTTON", text, WS_TABSTOP | BS_AUTOCHECKBOX, 0, x, y, w, h, id);
}

HWND Modal::Radio(const wchar_t* text, int x, int y, int w, int h, int id, bool first) {
    return Add(L"BUTTON", text,
               WS_TABSTOP | BS_AUTORADIOBUTTON | (first ? WS_GROUP : 0), 0,
               x, y, w, h, id);
}

// Без LWS_TRANSPARENT: с этим стилем фон должен рисовать родитель, чего внутри
// DC дочернего окна не происходит, и каждый SetWindowTextW накладывал новый
// текст на старые пиксели (текст выглядел жирным и смазанным).
HWND Modal::Link(int x, int y, int w, int h, int id) {
    if (m_.modern) {
        Surface(x, y, w, h);
        const int pad = M().Sc(3);
        return Add(WC_LINK, L"", WS_TABSTOP | WS_CLIPSIBLINGS, 0,
                   x + pad, y + pad, w - 2 * pad, std::max(1, h - 2 * pad), id);
    }
    return Add(WC_LINK, L"", WS_TABSTOP | WS_CLIPSIBLINGS, WS_EX_CLIENTEDGE,
               x, y, w, h, id);
}

HWND Modal::ListView(int x, int y, int w, int h, int id, DWORD lvStyle) {
    if (m_.modern) {
        Surface(x, y, w, h);
        ++x; ++y; w -= 2; h -= 2;
    }
    HWND lv = Add(WC_LISTVIEWW, L"", WS_TABSTOP | lvStyle,
                  m_.modern ? 0 : WS_EX_CLIENTEDGE, x, y, w, h, id);
    if (lv) {
        SetWindowTheme(lv, L"Explorer", nullptr);
        if (m_.modern) {
            ListView_SetBkColor(lv, colors_.surface);
            ListView_SetTextBkColor(lv, colors_.surface);
            ListView_SetTextColor(lv, colors_.text);
            if (HWND header = ListView_GetHeader(lv))
                SendMessageW(header, WM_SETFONT, reinterpret_cast<WPARAM>(semibold_), TRUE);
        }
        if (m_.modern && !(lvStyle & LVS_SHAREIMAGELISTS)) {
            HIMAGELIST rows = ImageList_Create(1, M().rowH() - M().Sc(2), ILC_COLOR32, 0, 1);
            if (rows) {
                // Без LVS_SHAREIMAGELISTS список сам освобождает эту подложку
                // и созданные им изображения флажков при уничтожении окна.
                ListView_SetImageList(lv, rows, LVSIL_SMALL);
            }
        }
    }
    return lv;
}

HWND Modal::ListBox(int x, int y, int w, int h, int id, DWORD extra) {
    HWND lb = Add(L"LISTBOX", L"",
                  WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY | extra,
                  m_.modern ? 0 : WS_EX_CLIENTEDGE, x, y, w, h, id);
    StyleField(lb);
    if (lb) SetWindowTheme(lb, L"Explorer", nullptr);
    return lb;
}

HWND Modal::Combo(int x, int y, int w, int h, int id) {
    return Add(L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, 0,
               x, y, w, h, id);
}

HWND Modal::IpEdit(int x, int y, int w, int h, int id) {
    HWND control = Add(WC_IPADDRESSW, L"", WS_TABSTOP,
                       (m_.modern ? 0 : WS_EX_CLIENTEDGE) | WS_EX_NOINHERITLAYOUT,
                       x, y, w, h, id);
    StyleField(control);
    KeepLeftToRight(control);
    return control;
}

HWND Modal::Hint(int x, int y, int w, int h, int id) {
    HWND e = Add(L"EDIT", L"", ES_MULTILINE | ES_READONLY,
                 m_.modern ? 0 : WS_EX_CLIENTEDGE, x, y, w, h, id);
    if (e) hints_.push_back(e);
    StyleField(e);
    return e;
}

std::wstring Modal::Text(int id) const {
    HWND c = Item(id);
    if (!c) return L"";
    const int n = GetWindowTextLengthW(c);
    if (n <= 0) return L"";
    std::wstring s(static_cast<size_t>(n) + 1, L'\0');
    const int got = GetWindowTextW(c, s.data(), n + 1);
    s.resize(static_cast<size_t>(got > 0 ? got : 0));
    return s;
}

void Modal::SetText(int id, const std::wstring& s) {
    if (HWND c = Item(id)) SetWindowTextW(c, s.c_str());
}

void Modal::SetControlBackground(int id, HWND background) {
    if (HWND c = Item(id)) {
        if (background) controlBackgrounds_[c] = background;
        else controlBackgrounds_.erase(c);
    }
}

void Modal::SetLinkText(int id, const std::wstring& markup, bool fitContent) {
    HWND c = Item(id);
    if (!c) return;
    SetWindowTextW(c, markup.c_str());
    // SysLink считает раскладку строк при WM_SETFONT/WM_SETTEXT: повторное
    // назначение шрифта после смены текста гарантирует верный межстрочный шаг
    SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font_), FALSE);
    if (fitContent) FitLinkHeight(c);
    InvalidateRect(c, nullptr, TRUE);   // TRUE: стереть фон, иначе текст ляжет поверх
    UpdateWindow(c);
}

void Modal::FitLinkHeight(HWND control) {
    RECT client{}, bounds{}, window{};
    if (!GetClientRect(control, &client) || !GetWindowRect(control, &bounds) ||
        !GetWindowRect(hwnd_, &window)) return;
    SIZE ideal{};
    if (!SendMessageW(control, LM_GETIDEALSIZE, client.right,
                      reinterpret_cast<LPARAM>(&ideal))) return;
    const int extra = ideal.cy - client.bottom;
    if (extra <= 0) return;
    MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&bounds), 2);
    const int below = bounds.bottom + (m_.modern ? M().Sc(3) : 0);
    const int height = window.bottom - window.top + extra;
    const RECT work = PopupWorkArea(owner_);
    const int top = std::max(work.top, std::min(window.top, work.bottom - height));
    if (!SetWindowPos(hwnd_, nullptr, window.left, top, window.right - window.left, height,
                      SWP_NOZORDER | SWP_NOACTIVATE)) return;
    ch_ += extra;
    if (footerY_ >= below) footerY_ += extra;
    for (auto& surface : surfaces_) {
        if (surface.left <= bounds.left && surface.right >= bounds.right &&
            surface.top <= bounds.top && surface.bottom == below) {
            surface.bottom += extra;
        } else if (surface.top >= below) OffsetRect(&surface, 0, extra);
    }
    for (auto& line : hair_)
        if (line.top >= below) OffsetRect(&line, 0, extra);
    for (HWND child = GetWindow(hwnd_, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        RECT rect{};
        GetWindowRect(child, &rect);
        MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&rect), 2);
        if (rect.top >= below)
            SetWindowPos(child, nullptr, rect.left, rect.top + extra, 0, 0,
                         SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    SetWindowPos(control, nullptr, 0, 0, client.right, ideal.cy,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    InvalidateRect(hwnd_, nullptr, TRUE);
}

void Modal::Enable(int id, bool on) {
    if (HWND c = Item(id)) EnableWindow(c, on ? TRUE : FALSE);
}

bool Modal::Checked(int id) const { return IsDlgButtonChecked(hwnd_, id) == BST_CHECKED; }

void Modal::SetChecked(int id, bool on) {
    CheckDlgButton(hwnd_, id, on ? BST_CHECKED : BST_UNCHECKED);
}

// Отступы поля принадлежат неклиентской области: выделение и прокрутка текста
// остаются нативными, а высота строки не зависит от высоты рамки.
LRESULT CALLBACK Modal::FieldProc(HWND window, UINT message, WPARAM wp, LPARAM lp,
                                 UINT_PTR id, DWORD_PTR data) {
    auto& self = *reinterpret_cast<Modal*>(data);
    if (message == WM_NCCALCSIZE) {
        const LRESULT result = DefSubclassProc(window, message, wp, lp);
        auto* rect = wp ? &reinterpret_cast<NCCALCSIZE_PARAMS*>(lp)->rgrc[0]
                        : reinterpret_cast<RECT*>(lp);
        int horizontal = 1, vertical = 1;
        if (ClassIs(window, L"Edit")) {
            HDC dc = GetDC(window);
            TEXTMETRICW metrics{};
            if (dc) {
                HGDIOBJ old = SelectObject(dc, self.font_);
                GetTextMetricsW(dc, &metrics);
                SelectObject(dc, old);
                ReleaseDC(window, dc);
            }
            horizontal = self.M().Sc(8);
            vertical = std::max(0, static_cast<int>(rect->bottom - rect->top - metrics.tmHeight) / 2);
            if (GetWindowLongPtrW(window, GWL_STYLE) & ES_MULTILINE) {
                const int height = static_cast<int>(rect->bottom - rect->top);
                const int line = std::max(1, static_cast<int>(metrics.tmHeight));
                const int lines = std::max(1, (height - 2) / line);
                // Отступы не должны отнимать целую строку при округлении DPI.
                vertical = std::max(1, std::min(self.M().Sc(3), (height - lines * line) / 2));
            }
        }
        InflateRect(rect, -horizontal, -vertical);
        return result;
    }
    if (message == WM_NCPAINT) {
        const LRESULT result = DefSubclassProc(window, message, wp, lp);
        HDC dc = GetWindowDC(window);
        if (dc) {
            RECT bounds{}, client{};
            GetWindowRect(window, &bounds);
            GetClientRect(window, &client);
            POINT origin{};
            ClientToScreen(window, &origin);
            OffsetRect(&client, origin.x - bounds.left, origin.y - bounds.top);
            OffsetRect(&bounds, -bounds.left, -bounds.top);
            ExcludeClipRect(dc, client.left, client.top, client.right, client.bottom);
            if (ClassIs(window, L"Edit"))
                FillRect(dc, &bounds, reinterpret_cast<HBRUSH>(self.ColorControl(dc, window)));
            HBRUSH border = CreateSolidBrush(GetFocus() == window ? self.colors_.accent : self.colors_.border);
            FrameRect(dc, &bounds, border);
            DeleteObject(border);
            ReleaseDC(window, dc);
        }
        return result;
    }
    if (message == WM_SETFOCUS || message == WM_KILLFOCUS) {
        const LRESULT result = DefSubclassProc(window, message, wp, lp);
        RedrawWindow(window, nullptr, nullptr, RDW_INVALIDATE | RDW_FRAME);
        return result;
    }
    if (message == WM_NCDESTROY) RemoveWindowSubclass(window, FieldProc, id);
    return DefSubclassProc(window, message, wp, lp);
}

LRESULT DrawPrimaryButton(NMCUSTOMDRAW& draw, const DialogColors& colors,
                          HFONT font, UINT dpi) {
    if (draw.dwDrawStage != CDDS_PREPAINT || colors.highContrast) return CDRF_DODEFAULT;
    COLORREF fill = colors.accent;
    if (draw.uItemState & CDIS_SELECTED) fill = Blend(fill, RGB(0, 0, 0), 18);
    else if (draw.uItemState & CDIS_HOT) fill = Blend(fill, colors.surface, 10);
    if (draw.uItemState & CDIS_DISABLED) return CDRF_DODEFAULT;
    Metrics m;
    m.dpi = dpi;
    HBRUSH background = CreateSolidBrush(colors.surface);
    FillRect(draw.hdc, &draw.rc, background);
    DeleteObject(background);
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, fill);
    HGDIOBJ oldBrush = SelectObject(draw.hdc, brush);
    HGDIOBJ oldPen = SelectObject(draw.hdc, pen);
    const int radius = m.Sc(5);
    RoundRect(draw.hdc, draw.rc.left, draw.rc.top, draw.rc.right, draw.rc.bottom, radius, radius);
    SelectObject(draw.hdc, oldPen);
    SelectObject(draw.hdc, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
    SetBkMode(draw.hdc, TRANSPARENT);
    SetTextColor(draw.hdc, GetSysColor(COLOR_HIGHLIGHTTEXT));
    HGDIOBJ oldFont = SelectObject(draw.hdc, font);
    RECT text = draw.rc;
    const HWND button = draw.hdr.hwndFrom;
    const int length = GetWindowTextLengthW(button);
    std::wstring caption(static_cast<size_t>(length) + 1, L'\0');
    caption.resize(static_cast<size_t>(GetWindowTextW(button, caption.data(), length + 1)));
    UINT flags = DT_CENTER | DT_VCENTER | DT_SINGLELINE;
    if (GetWindowLongPtrW(button, GWL_EXSTYLE) & (WS_EX_LAYOUTRTL | WS_EX_RTLREADING))
        flags |= DT_RTLREADING;
    if (SendMessageW(button, WM_QUERYUISTATE, 0, 0) & UISF_HIDEACCEL) flags |= DT_HIDEPREFIX;
    DrawTextW(draw.hdc, caption.c_str(), -1, &text, flags);
    SelectObject(draw.hdc, oldFont);
    if ((draw.uItemState & CDIS_FOCUS) &&
        !(SendMessageW(button, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS)) {
        InflateRect(&text, -m.Sc(4), -m.Sc(4));
        DrawFocusRect(draw.hdc, &text);
    }
    return CDRF_SKIPDEFAULT;
}

int Modal::CheckPair(const std::wstring& first, const std::wstring& second,
                     int x, int y, int w, int firstId, int secondId) {
    const int half = (w - M().gap()) / 2;
    const int needed = std::max(MeasureCaption(first.c_str()), MeasureCaption(second.c_str())) + M().Sc(28);
    const bool beside = needed <= half;
    Check(first, x, y, beside ? half : w, M().checkH(), firstId);
    Check(second, beside ? x + half + M().gap() : x,
          beside ? y : y + M().checkH() + M().gapS(),
          beside ? half : w, M().checkH(), secondId);
    return beside ? M().checkH() : 2 * M().checkH() + M().gapS();
}

} // namespace Ui
