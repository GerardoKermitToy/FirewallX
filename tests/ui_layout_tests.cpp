#include "UiKit.h"
#include "AppInfo.h"
#include "StringRes.h"
#include "TreeList.h"
#include "RulePresetsResource.h"
#include "Settings.h"
#include "icon_test_support.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <objbase.h>
#include <winsqlite/winsqlite3.h>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

bool Mirrored(HWND window) {
    return (GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_LAYOUTRTL) != 0;
}

bool RtlTextControl(HWND window) {
    return Mirrored(window) ||
        (GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_RTLREADING) != 0;
}

std::wstring WindowText(HWND window) {
    wchar_t text[512]{};
    GetWindowTextW(window, text, static_cast<int>(std::size(text)));
    return text;
}

void CALLBACK CloseDialog(HWND window, UINT, UINT_PTR timer, DWORD) {
    KillTimer(window, timer);
    PostMessageW(window, WM_COMMAND, IDOK, 0);
}

class ProbeDialog : public Ui::Modal {
public:
    bool preview = false;
    UINT dpi = 0;
    bool mirrored = false, labelMirrored = false, nameMirrored = false;
    bool checkboxMirrored = false, pathMirrored = false, addressMirrored = false;
    bool ipMirrored = false, ipChildrenLtr = true, labelOnRight = false;
    std::wstring path, address;
    std::vector<std::pair<int, std::wstring>> octets;

protected:
    void OnInit() override {
        const auto& m = M();
        dpi = m.dpi;
        SetHeader(LoadStringRes(IDS_SETTINGS_HEADER), LoadStringRes(IDS_SETTINGS_SUBHEADER));
        const int x = m.margin(), w = clientW() - 2 * x;
        int y = headerH() + m.gap();
        HWND label = Label(LoadStringRes(IDS_ASK_REMOTE_ADDR), x, y + m.Sc(4),
                           m.Sc(130), m.labelH());
        HWND ipv6 = LtrEdit(L"2001:db8::1", x + m.Sc(140), y,
                           w - m.Sc(140), m.editH(), 100);
        y += m.editH() + m.gap();
        Label(LoadStringRes(IDS_RDA_RADIO_IP), x, y + m.Sc(4), m.Sc(130), m.labelH());
        HWND ipv4 = IpEdit(x + m.Sc(140), y, m.Sc(190), m.editH(), 101);
        SendMessageW(ipv4, IPM_SETADDRESS, 0, MAKEIPADDRESS(192, 0, 2, 10));
        y += m.editH() + m.gap();
        HWND executable = ReadOnly(L"C:\\Windows\\System32\\notepad.exe",
                                   x, y, w, m.editH(), 102);
        Ui::KeepLeftToRight(executable);
        y += m.editH() + m.gap();
        HWND checkbox = Check(LoadStringRes(IDS_RED_AUTONAME), x, y,
                              w, m.checkH(), 103);
        y += m.checkH() + m.gap();
        HWND name = Edit(LoadStringRes(IDS_PRESET_BROWSER_HTTPS),
                         x, y, w, m.editH(), 104);
        OkCancel();

        mirrored = Mirrored(hwnd());
        labelMirrored = Mirrored(label);
        nameMirrored = RtlTextControl(name);
        checkboxMirrored = Mirrored(checkbox);
        pathMirrored = RtlTextControl(executable);
        addressMirrored = RtlTextControl(ipv6);
        ipMirrored = RtlTextControl(ipv4);
        path = WindowText(executable);
        address = WindowText(ipv6);
        RECT lr{}, er{};
        GetWindowRect(label, &lr);
        GetWindowRect(ipv6, &er);
        labelOnRight = lr.left > er.left;
        for (HWND child = GetWindow(ipv4, GW_CHILD); child;
             child = GetWindow(child, GW_HWNDNEXT)) {
            ipChildrenLtr = ipChildrenLtr && !RtlTextControl(child);
            RECT rect{};
            GetWindowRect(child, &rect);
            octets.emplace_back(rect.left, WindowText(child));
        }
        std::sort(octets.begin(), octets.end());
        if (preview) SetTimer(hwnd(), 1, 15000, CloseDialog);
        else PostMessageW(hwnd(), WM_COMMAND, IDOK, 0);
    }
};

void TestDialog(UiLang language) {
    SetUiLang(language);
    const bool rtl = language == UiLang::Arabic || language == UiLang::Persian;
    ProbeDialog dialog;
    Check(dialog.Run(nullptr, GetModuleHandleW(nullptr), LoadStringRes(IDS_SETTINGS_TITLE), 520, 330),
          "layout probe did not close normally");
    if (dialog.mirrored != rtl || dialog.labelMirrored != rtl ||
        dialog.nameMirrored != rtl || dialog.checkboxMirrored != rtl)
        std::cerr << "expected RTL=" << rtl << ", window=" << dialog.mirrored
                  << ", label=" << dialog.labelMirrored << ", name=" << dialog.nameMirrored
                  << ", checkbox=" << dialog.checkboxMirrored << '\n';
    Check(dialog.mirrored == rtl && dialog.labelMirrored == rtl &&
          dialog.nameMirrored == rtl && dialog.checkboxMirrored == rtl,
          "dialog or translated controls have the wrong layout");
    Check(!dialog.pathMirrored && !dialog.addressMirrored && !dialog.ipMirrored &&
          dialog.ipChildrenLtr, "technical input inherited RTL");
    Check(dialog.labelOnRight == rtl, "dialog control positions were not mirrored");
    Check(dialog.path == L"C:\\Windows\\System32\\notepad.exe" &&
          dialog.address == L"2001:db8::1", "technical input text was changed");
    Check(dialog.octets.size() == 4, "unexpected IPv4 field count");
    const wchar_t* expected[] = {L"192", L"0", L"2", L"10"};
    for (size_t i = 0; i < dialog.octets.size(); ++i)
        Check(dialog.octets[i].second == expected[i], "IPv4 octets were reordered");
}

class LabelRepaintDialog : public Ui::Modal {
public:
    bool modern = false;
    bool changed = false, clean = false, cleared = false, transparent = false;

protected:
    bool ModernStyle() const override { return modern; }

    void OnInit() override {
        const int tabW = clientW() - 2 * M().margin();
        const int tabH = clientH() - 2 * M().margin();
        HWND tabs = Add(WC_TABCONTROLW, L"", TCS_TABS, 0,
                        M().margin(), M().margin(), tabW, tabH, 200);
        std::wstring title = LoadStringRes(IDS_SETTINGS_TAB_GENERAL);
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = title.data();
        TabCtrl_InsertItem(tabs, 0, &item);
        RECT page{0, 0, tabW, tabH};
        TabCtrl_AdjustRect(tabs, FALSE, &page);
        const int x = page.left + M().gap();
        const int y = page.top + M().gap();
        const int width = page.right - page.left - 2 * M().gap();
        const int height = M().labelH();
        HWND label = Label(L"", M().margin() + x, M().margin() + y, width, height, 100);
        SetControlBackground(100, tabs);
        HWND ordinary = Label(LoadStringRes(IDS_SETTINGS_START_WITH_WINDOWS),
                              M().margin() + x, M().margin() + y + height + M().gap(),
                              width, height, 101);
        if (modern) SetControlBackground(101, tabs);
        HWND checkbox = Check(LoadStringRes(IDS_SETTINGS_MUTE_MESSAGE_BEEP),
                              M().margin() + x, M().margin() + y + 2 * (height + M().gap()),
                              width, M().checkH(), 102);
        SetControlBackground(102, tabs);
        HDC dc = CreateCompatibleDC(nullptr);
        BITMAPINFO info{};
        info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info.bmiHeader.biWidth = tabW;
        info.bmiHeader.biHeight = -tabH;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        void* bits = nullptr;
        HBITMAP bitmap = dc ? CreateDIBSection(dc, &info, DIB_RGB_COLORS,
                                              &bits, nullptr, 0) : nullptr;
        if (tabs && label && ordinary && bitmap && bits) {
            const auto oldBitmap = SelectObject(dc, bitmap);
            const RECT rect{0, 0, tabW, tabH};
            const auto erase = [&] { FillRect(dc, &rect, GetSysColorBrush(COLOR_BTNFACE)); };
            const auto capture = [&](int left, int top) {
                GdiFlush();
                const auto* pixels = static_cast<const uint32_t*>(bits);
                std::vector<uint32_t> result;
                result.reserve(static_cast<size_t>(width) * height);
                for (int row = 0; row < height; ++row) {
                    const auto* start = pixels + static_cast<size_t>(top + row) * tabW + left;
                    result.insert(result.end(), start, start + width);
                }
                return result;
            };
            const auto paint = [&] {
                const int saved = SaveDC(dc);
                IntersectClipRect(dc, 0, 0, width, height);
                SendMessageW(label, WM_PRINTCLIENT, reinterpret_cast<WPARAM>(dc), PRF_CLIENT);
                RestoreDC(dc, saved);
                return capture(0, 0);
            };
            // Эталон берём с настоящей вкладки, а не из системного серого цвета.
            erase();
            SendMessageW(tabs, WM_PRINTCLIENT, reinterpret_cast<WPARAM>(dc), PRF_CLIENT);
            const auto background = capture(x, y);
            const auto brush = SendMessageW(hwnd(), WM_CTLCOLORSTATIC,
                reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(ordinary));
            transparent = reinterpret_cast<HBRUSH>(brush) == GetStockObject(NULL_BRUSH) &&
                          GetBkMode(dc) == TRANSPARENT;
            const auto checkBrush = SendMessageW(hwnd(), WM_CTLCOLORBTN,
                reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(checkbox));
            transparent = transparent && reinterpret_cast<HBRUSH>(checkBrush) == GetStockObject(NULL_BRUSH) &&
                          GetBkMode(dc) == TRANSPARENT;
            erase();
            SetText(100, LoadStringResFmt(IDS_ALLRULES_STATS_FMT, 123u, 123u, 1234u, 12u, 34u));
            const auto before = paint();
            SetText(100, LoadStringResFmt(IDS_ALLRULES_STATS_FMT, 4u, 4u, 20u, 0u, 0u));
            const auto updated = paint();
            erase();
            const auto reference = paint();
            changed = before != reference;
            clean = updated == reference;
            SetText(100, L"");
            cleared = paint() == background;
            SelectObject(dc, oldBitmap);
        }
        if (bitmap) DeleteObject(bitmap);
        if (dc) DeleteDC(dc);
        PostMessageW(hwnd(), WM_COMMAND, IDOK, 0);
    }
};

void TestLabelRepaint() {
    SetUiLang(UiLang::English);
    for (bool modern : {false, true}) {
        LabelRepaintDialog dialog;
        dialog.modern = modern;
        Check(dialog.Run(nullptr, GetModuleHandleW(nullptr), LoadStringRes(IDS_SETTINGS_TITLE), 720, 160),
              "label repaint probe did not close normally");
        Check(dialog.transparent, "tab labels or checkboxes paint an opaque background");
        Check(dialog.changed, "label repaint probe did not draw distinct statistics");
        Check(dialog.clean, "updated label retained pixels from previous statistics");
        Check(dialog.cleared, "empty label differs from the underlying tab background");
    }
}

class StyledControlsDialog : public Ui::Modal {
public:
    bool fields = true, backgrounds = true, multiline = false, table = false, geometry = true;
    bool plainFooter = false, hintPadding = false, editPadding = false;

protected:
    bool ModernStyle() const override { return true; }

    void OnInit() override {
        const auto& m = M();
        const int x = m.margin(), width = clientW() - 2 * x;
        HWND edit = Edit(L"443", x, x, width, m.editH(), 100);
        const int hintY = x + m.editH() + m.gap();
        const int hintH = 2 * m.labelH() + m.Sc(6);
        HWND hint = Hint(x, hintY, width, hintH, 101);
        SetText(101, L"TCP\r\n443");
        const int ipY = hintY + hintH + m.gap();
        HWND ip = IpEdit(x, ipY, m.Sc(184), m.editH(), 102);
        SendMessageW(ip, IPM_SETADDRESS, 0, MAKEIPADDRESS(192, 0, 2, 10));
        const int listY = ipY + m.editH() + m.gap();
        HWND list = ListView(x, listY, width, m.Sc(100), 103, LVS_REPORT);
        LVCOLUMNW column{};
        column.mask = LVCF_WIDTH;
        column.cx = width - m.Sc(30);
        ListView_InsertColumn(list, 0, &column);
        HWND check = Check(LoadStringRes(IDS_RED_AUTONAME), x, listY + m.Sc(100) + m.gap(),
                           width, m.checkH(), 104);
        OkCancel();

        for (HWND control : {edit, hint, ip, list}) {
            fields = fields && control && !(GetWindowLongPtrW(control, GWL_EXSTYLE) & WS_EX_CLIENTEDGE);
            LOGFONTW lf{};
            HWND textControl = control == ip ? GetWindow(ip, GW_CHILD) : control;
            GetObjectW(reinterpret_cast<HFONT>(SendMessageW(textControl, WM_GETFONT, 0, 0)), sizeof(lf), &lf);
            if (std::wstring(lf.lfFaceName) != L"Segoe UI" ||
                (GetWindowLongPtrW(control, GWL_EXSTYLE) & WS_EX_CLIENTEDGE))
                std::wcerr << L"Styled control " << GetDlgCtrlID(control) << L": font=" << lf.lfFaceName
                           << L", exStyle=" << GetWindowLongPtrW(control, GWL_EXSTYLE) << L'\n';
            fields = fields && std::wstring(lf.lfFaceName) == L"Segoe UI";
        }
        LOGFONTW heading{};
        GetObjectW(reinterpret_cast<HFONT>(SendMessageW(ListView_GetHeader(list), WM_GETFONT, 0, 0)),
                   sizeof(heading), &heading);
        table = heading.lfWeight == FW_SEMIBOLD &&
                ListView_GetBkColor(list) == colors().surface;
        NMLVCUSTOMDRAW draw{};
        draw.nmcd.hdr = {list, 103, NM_CUSTOMDRAW};
        draw.nmcd.dwDrawStage = CDDS_PREPAINT;
        table = table && Ui::DrawDialogList(draw, colors()) == CDRF_NOTIFYITEMDRAW;
        draw.nmcd.dwDrawStage = CDDS_ITEMPREPAINT;
        draw.nmcd.dwItemSpec = 1;
        Ui::DrawDialogList(draw, colors());
        table = table && draw.clrTextBk == colors().alternate;

        HDC dc = GetDC(hwnd());
        HDC footerDc = CreateCompatibleDC(dc);
        HBITMAP pixel = CreateCompatibleBitmap(dc, 1, 1);
        if (footerDc && pixel) {
            HGDIOBJ previous = SelectObject(footerDc, pixel);
            SetViewportOrgEx(footerDc, 0, 1 - clientH(), nullptr);
            SendMessageW(hwnd(), WM_ERASEBKGND, reinterpret_cast<WPARAM>(footerDc), 0);
            plainFooter = GetPixel(footerDc, 0, clientH() - 1) == GetSysColor(COLOR_BTNFACE);
            NMCUSTOMDRAW primary{};
            primary.hdr = {Item(IDOK), IDOK, NM_CUSTOMDRAW};
            primary.dwDrawStage = CDDS_PREPAINT;
            primary.hdc = footerDc;
            plainFooter = plainFooter && SendMessageW(hwnd(), WM_NOTIFY, IDOK,
                reinterpret_cast<LPARAM>(&primary)) == CDRF_DODEFAULT;
            SelectObject(footerDc, previous);
        }
        if (pixel) DeleteObject(pixel);
        if (footerDc) DeleteDC(footerDc);
        SendMessageW(hwnd(), WM_CTLCOLORSTATIC, reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(hint));
        backgrounds = GetBkColor(dc) == RGB(0xFF, 0xFF, 0xE1) && GetTextColor(dc) == colors().text;
        SendMessageW(hwnd(), WM_CTLCOLORBTN, reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(check));
        backgrounds = backgrounds && GetBkColor(dc) == GetSysColor(COLOR_BTNFACE);
        HGDIOBJ old = SelectObject(dc, font());
        TEXTMETRICW metrics{};
        GetTextMetricsW(dc, &metrics);
        SelectObject(dc, old);
        ReleaseDC(hwnd(), dc);
        RECT client{};
        GetClientRect(hint, &client);
        multiline = client.bottom >= 2 * metrics.tmHeight;
        if (!multiline)
            std::cerr << "Hint client height=" << client.bottom << ", line height=" << metrics.tmHeight
                      << ", requested height=" << hintH << ", DPI=" << m.dpi << '\n';
        const int ids[] = {100, 101, 102};
        const int tops[] = {x, hintY, ipY};
        const int heights[] = {m.editH(), hintH, m.editH()};
        for (int i = 0; i < 3; ++i) {
            RECT rect{};
            GetWindowRect(Item(ids[i]), &rect);
            MapWindowPoints(nullptr, hwnd(), reinterpret_cast<POINT*>(&rect), 2);
            geometry = geometry && rect.left == x && rect.top == tops[i] &&
                       rect.bottom - rect.top == heights[i];
        }
        PostMessageW(hwnd(), WM_COMMAND, 105, 0);
    }

    bool OnCommand(int id, int) override {
        if (id != 105) return false;
        // Проверяем отступы после показа окна: они рисуются вне клиентской области EDIT.
        const auto paddingMatches = [](HWND control, COLORREF expected) {
            RedrawWindow(control, nullptr, nullptr,
                         RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
            RECT rect{};
            GetWindowRect(control, &rect);
            const int width = rect.right - rect.left, height = rect.bottom - rect.top;
            HDC dc = GetWindowDC(control);
            if (!dc) return false;
            const POINT points[] = {
                {1, 1}, {width / 2, 1}, {width - 2, 1},
                {1, height / 2}, {width - 2, height / 2},
                {1, height - 2}, {width / 2, height - 2}, {width - 2, height - 2}
            };
            bool matches = true;
            for (const POINT& point : points)
                matches = matches && GetPixel(dc, point.x, point.y) == expected;
            ReleaseDC(control, dc);
            return matches;
        };
        hintPadding = paddingMatches(Item(101), RGB(0xFF, 0xFF, 0xE1));
        editPadding = paddingMatches(Item(100), colors().surface);
        PostMessageW(hwnd(), WM_COMMAND, IDOK, 0);
        return true;
    }
};

void TestStyledControls() {
    SetUiLang(UiLang::English);
    const DPI_AWARENESS_CONTEXT previous = GetThreadDpiAwarenessContext();
    for (DPI_AWARENESS_CONTEXT context : {DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
                                          DPI_AWARENESS_CONTEXT_UNAWARE}) {
        SetThreadDpiAwarenessContext(context);
        StyledControlsDialog dialog;
        Check(dialog.Run(nullptr, GetModuleHandleW(nullptr), LoadStringRes(IDS_SETTINGS_TITLE), 520, 360),
              "styled controls probe did not close normally");
        Check(dialog.fields, "styled fields have inconsistent fonts or recessed borders");
        Check(dialog.backgrounds, "styled controls have inconsistent backgrounds");
        Check(dialog.hintPadding, "styled hint has non-yellow padding");
        Check(dialog.editPadding, "styled edit padding differs from its background");
        Check(dialog.multiline, "styled hint no longer fits two lines");
        Check(dialog.table, "styled table lost its header font or alternating rows");
        Check(dialog.geometry, "styling changed the requested field geometry");
        Check(dialog.plainFooter, "ordinary dialog has a white footer or custom primary button");
    }
    SetThreadDpiAwarenessContext(previous);
}

void TestLiveSwitch() {
    SetUiLang(UiLang::English);
    HWND window = CreateWindowExW(0, L"STATIC", L"", WS_OVERLAPPEDWINDOW,
        100, 100, 600, 300, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    Check(window != nullptr, "could not create live layout probe");
    HWND label = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
        20, 20, 100, 20, window, nullptr, nullptr, nullptr);
    HWND technical = CreateWindowExW(0, L"EDIT", L"2001:db8::1", WS_CHILD | WS_VISIBLE,
        140, 20, 200, 24, window, nullptr, nullptr, nullptr);
    Ui::KeepLeftToRight(technical);
    for (UiLang language : {UiLang::Arabic, UiLang::English, UiLang::Arabic,
                            UiLang::German, UiLang::French, UiLang::Spanish, UiLang::Hindi,
                            UiLang::Latvian, UiLang::Lithuanian, UiLang::Estonian,
                            UiLang::Romanian, UiLang::Swedish, UiLang::Persian,
                            UiLang::Arabic, UiLang::Persian, UiLang::English, UiLang::Persian,
                            UiLang::Polish, UiLang::Vietnamese, UiLang::Portuguese,
                            UiLang::Italian}) {
        SetUiLang(language);
        Ui::ApplyLayout(window);
        // Как App::Layout: повторяем раскладку в новой системе координат.
        MoveWindow(label, 20, 20, 100, 20, TRUE);
        MoveWindow(technical, 140, 20, 200, 24, TRUE);
        const bool rtl = language == UiLang::Arabic || language == UiLang::Persian;
        Check(Mirrored(window) == rtl && Mirrored(label) == rtl && !RtlTextControl(technical),
              "live language switch lost a control's layout");
        Check(WindowText(technical) == L"2001:db8::1", "live switch changed technical input");
        RECT labelRect{}, fieldRect{};
        GetWindowRect(label, &labelRect);
        GetWindowRect(technical, &fieldRect);
        Check((labelRect.left > fieldRect.left) == rtl,
              "live switch did not mirror existing control positions");
    }
    DestroyWindow(window);
}

struct ListPaintCapture {
    int items[32]{};
};

ListPaintCapture* activeListPaintCapture = nullptr;

LRESULT CALLBACK HostProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    auto* list = reinterpret_cast<TreeList*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NOTIFY && list) {
        auto* notification = reinterpret_cast<LPNMHDR>(lp);
        LRESULT result = 0;
        const bool handled = list->OnNotify(notification, result);
        if (activeListPaintCapture && notification->hwndFrom == list->hwnd() &&
            notification->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<LPNMLVCUSTOMDRAW>(notification);
            if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT &&
                draw->nmcd.dwItemSpec < std::size(activeListPaintCapture->items))
                ++activeListPaintCapture->items[draw->nmcd.dwItemSpec];
        }
        if (handled) return result;
    }
    return DefWindowProcW(window, message, wp, lp);
}

std::vector<uint32_t> CaptureListRow(HWND window, const RECT& row) {
    RECT client{};
    Check(GetClientRect(window, &client) != FALSE, "could not measure list client area");
    const int width = client.right - client.left;
    const int top = std::max(client.top, row.top);
    const int bottom = std::min(client.bottom, row.bottom);
    const int height = bottom - top;
    Check(width > 0 && height > 0, "cannot capture an invisible list row");
    struct CaptureDc {
        HWND window;
        HDC source = nullptr, memory = nullptr;
        HBITMAP bitmap = nullptr;
        HGDIOBJ previous = nullptr;
        ~CaptureDc() {
            if (memory && previous && previous != HGDI_ERROR) SelectObject(memory, previous);
            if (bitmap) DeleteObject(bitmap);
            if (memory) DeleteDC(memory);
            if (source) ReleaseDC(window, source);
        }
    } dc{window};
    dc.source = GetDC(window);
    Check(dc.source != nullptr, "could not get list device context");
    dc.memory = CreateCompatibleDC(dc.source);
    Check(dc.memory != nullptr, "could not create list capture context");
    BITMAPINFO bitmapInfo{};
    bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bitmapInfo.bmiHeader.biWidth = width;
    bitmapInfo.bmiHeader.biHeight = -height;
    bitmapInfo.bmiHeader.biPlanes = 1;
    bitmapInfo.bmiHeader.biBitCount = 32;
    bitmapInfo.bmiHeader.biCompression = BI_RGB;
    void* data = nullptr;
    dc.bitmap = CreateDIBSection(dc.source, &bitmapInfo, DIB_RGB_COLORS, &data, nullptr, 0);
    Check(dc.bitmap && data, "could not create list capture bitmap");
    dc.previous = SelectObject(dc.memory, dc.bitmap);
    Check(dc.previous && dc.previous != HGDI_ERROR, "could not select list capture bitmap");
    Check(BitBlt(dc.memory, 0, 0, width, height, dc.source, client.left, top, SRCCOPY),
          "could not capture list row pixels");
    GdiFlush();
    const auto* begin = static_cast<const uint32_t*>(data);
    std::vector<uint32_t> pixels(begin, begin + static_cast<size_t>(width) * height);
    for (uint32_t& pixel : pixels) pixel &= 0x00ffffff;
    return pixels;
}

void TestRowInvalidation(UiLang language, ListSkin skin) {
    SetUiLang(language);
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = HostProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"FirewallXRowInvalidationTests";
    RegisterClassW(&wc);
    TreeList list;
    HWND window = CreateWindowExW(Ui::LayoutStyle(), wc.lpszClassName, L"",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, 100, 100, 1000, 360,
        nullptr, nullptr, instance, &list);
    struct Cleanup {
        TreeList& list;
        HWND window;
        ~Cleanup() { list.Destroy(); if (window) DestroyWindow(window); }
    } cleanup{list, window};
    Check(window && list.Create(window, instance, 1), "could not create repaint test list");
    list.SetSkin(skin);
    MoveWindow(list.hwnd(), 0, 0, 950, 240, TRUE);
    std::vector<TreeList::Row> rows(30);
    rows[0].isGroup = true;
    rows[0].expanded = true;
    rows[0].key.group = 123;
    rows[0].col[ColProcess] = L"process.exe";
    rows[0].col[ColPid] = L"123";
    for (size_t i = 1; i < rows.size(); ++i) {
        rows[i].key.group = 123;
        rows[i].key.generation = i;
        rows[i].groupRow = 0;
        rows[i].col[ColRemote] = L"192.0.2.1:" + std::to_wstring(i);
        rows[i].lastChild = i + 1 == rows.size();
    }
    list.SetRows(std::move(rows));
    ShowWindow(window, SW_SHOWNOACTIVATE);
    RedrawWindow(list.hwnd(), nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    const auto flush = [&] {
        RedrawWindow(list.hwnd(), nullptr, nullptr, RDW_UPDATENOW | RDW_ALLCHILDREN);
    };
    const auto dirty = [&] { return GetUpdateRect(list.hwnd(), nullptr, FALSE) != FALSE; };
    Check(!dirty(), "repaint test list did not finish its initial paint");

    ListPaintCapture singleCapture{};
    activeListPaintCapture = &singleCapture;
    ListView_RedrawItems(list.hwnd(), 1, 1);
    flush();
    activeListPaintCapture = nullptr;
    Check(singleCapture.items[1], "single-row redraw did not paint the changed item");

    list.ApplyColumns();
    Check(dirty(), "changing column layout did not invalidate the list");
    list.FitColumns();
    flush();
    list.SetIconSize(20);
    Check(dirty(), "changing icon size did not invalidate the list");
    list.FitColumns();
    flush();

    for (int i = 0; i < 20; ++i) {
        auto unchanged = list.rows();
        list.SetRows(std::move(unchanged));
        Check(!dirty(), "identical rows invalidated the list");
        flush();
    }

    auto tooltipOnly = list.rows();
    tooltipOnly[0].path = L"C:\\new-process-path.exe";
    tooltipOnly[1].ruleName = L"new rule name";
    list.SetRows(std::move(tooltipOnly));
    Check(!dirty() && list.rows()[0].path == L"C:\\new-process-path.exe" &&
          list.rows()[1].ruleName == L"new rule name",
          "nonvisual row data was not updated without repainting");

    auto offscreen = list.rows();
    offscreen.back().col[ColRemote] = L"198.51.100.1:443";
    list.SetRows(std::move(offscreen));
    Check(!dirty() && list.rows().back().col[ColRemote] == L"198.51.100.1:443",
          "offscreen change invalidated the list or was lost");

    RECT changedRect{}, neighborRect{};
    Check(ListView_GetItemRect(list.hwnd(), 2, &changedRect, LVIR_BOUNDS) &&
          ListView_GetItemRect(list.hwnd(), 1, &neighborRect, LVIR_BOUNDS),
          "could not measure repaint test rows");
    auto changed = list.rows();
    changed[2].col[ColRemote] = L"203.0.113.1:443";
    list.SetRows(std::move(changed));
    HRGN region = CreateRectRgn(0, 0, 0, 0);
    Check(region != nullptr, "could not create repaint test region");
    const int regionType = GetUpdateRgn(list.hwnd(), region, FALSE);
    const bool changedDirty = RectInRegion(region, &changedRect) != FALSE;
    const bool neighborDirty = RectInRegion(region, &neighborRect) != FALSE;
    DeleteObject(region);
    Check(regionType != NULLREGION && changedDirty && !neighborDirty,
          "changing one row did not limit repaint to that row");
    flush();

    RECT firstRect{}, middleRect{}, lastRect{};
    Check(ListView_GetItemRect(list.hwnd(), 1, &firstRect, LVIR_BOUNDS) &&
          ListView_GetItemRect(list.hwnd(), 2, &middleRect, LVIR_BOUNDS) &&
          ListView_GetItemRect(list.hwnd(), 3, &lastRect, LVIR_BOUNDS),
          "could not measure separated test rows");
    const auto firstPixels = CaptureListRow(list.hwnd(), firstRect);
    const auto middlePixels = CaptureListRow(list.hwnd(), middleRect);
    const auto lastPixels = CaptureListRow(list.hwnd(), lastRect);
    auto separated = list.rows();
    separated[1].col[ColRemote] = L"198.51.100.11:443";
    separated[3].col[ColRemote] = L"198.51.100.13:443";
    ListPaintCapture captured{};
    activeListPaintCapture = &captured;
    list.SetRows(std::move(separated));
    const bool firstPaintedEarly = captured.items[1] != 0;
    region = CreateRectRgn(0, 0, 0, 0);
    Check(region != nullptr, "could not create separated-row test region");
    GetUpdateRgn(list.hwnd(), region, FALSE);
    const bool separateFirst = RectInRegion(region, &firstRect) != FALSE;
    const bool separateMiddle = RectInRegion(region, &middleRect) != FALSE;
    const bool separateLast = RectInRegion(region, &lastRect) != FALSE;
    DeleteObject(region);
    flush();
    activeListPaintCapture = nullptr;
    Check(firstPaintedEarly && !separateFirst && !separateMiddle && separateLast,
          "separated changes were not repainted independently");
    Check(captured.items[1] && captured.items[3],
          "separated changes did not paint the changed rows");
    Check(CaptureListRow(list.hwnd(), firstRect) != firstPixels &&
          CaptureListRow(list.hwnd(), middleRect) == middlePixels &&
          CaptureListRow(list.hwnd(), lastRect) != lastPixels,
          "partial repaint did not preserve unchanged pixels or update changed rows");

    // Уже ожидающее обновление не обрабатываем синхронно внутри SetRows.
    InvalidateRect(list.hwnd(), &middleRect, FALSE);
    auto pending = list.rows();
    pending[1].col[ColRecv] = L"128 B";
    pending[3].col[ColRecv] = L"256 B";
    ListPaintCapture pendingCapture{};
    activeListPaintCapture = &pendingCapture;
    list.SetRows(std::move(pending));
    const bool pendingWasPainted = pendingCapture.items[1] || pendingCapture.items[2] ||
                                   pendingCapture.items[3];
    region = CreateRectRgn(0, 0, 0, 0);
    Check(region != nullptr, "could not create pending-paint test region");
    GetUpdateRgn(list.hwnd(), region, FALSE);
    const bool pendingIncludesAll = RectInRegion(region, &firstRect) &&
        RectInRegion(region, &middleRect) && RectInRegion(region, &lastRect);
    DeleteObject(region);
    flush();
    activeListPaintCapture = nullptr;
    Check(!pendingWasPainted && pendingIncludesAll,
          "pending repaint was processed early or lost");

    // Частые изменения выгоднее объединить в один штатный WM_PAINT.
    auto dense = list.rows();
    const int denseTop = ListView_GetTopIndex(list.hwnd());
    const int denseEnd = std::min(static_cast<int>(dense.size()),
                                  denseTop + ListView_GetCountPerPage(list.hwnd()) + 2);
    Check(denseTop >= 0 && denseEnd - denseTop >= 3, "dense repaint test has too few rows");
    for (int i = denseTop; i < denseEnd; i += 2)
        dense[static_cast<size_t>(i)].col[ColRecv] = L"dense-" + std::to_wstring(i);
    ListPaintCapture denseCapture{};
    activeListPaintCapture = &denseCapture;
    list.SetRows(std::move(dense));
    const bool denseWasPainted = std::any_of(std::begin(denseCapture.items),
        std::end(denseCapture.items), [](int count) { return count != 0; });
    flush();
    activeListPaintCapture = nullptr;
    Check(!denseWasPainted, "dense changes were synchronously repainted separately");

    // Стабильное выделение не мешает обновлять разрозненные строки.
    list.Select(2);
    flush();
    auto selectedStable = list.rows();
    selectedStable[1].col[ColSent] = L"64 B";
    selectedStable[3].col[ColSent] = L"96 B";
    ListPaintCapture stableSelectionCapture{};
    activeListPaintCapture = &stableSelectionCapture;
    list.SetRows(std::move(selectedStable));
    const bool stableSelectionPainted = stableSelectionCapture.items[1] != 0;
    flush();
    activeListPaintCapture = nullptr;
    Check(stableSelectionPainted && list.Selected() == 2,
          "stable selection prevented independent repaint");

    // При перестановке выбранной строки её восстанавливает вызывающий код.
    auto reordered = list.rows();
    std::swap(reordered[2], reordered[3]);
    reordered[5].col[ColRecv] = L"512 B";
    ListPaintCapture selectionCapture{};
    activeListPaintCapture = &selectionCapture;
    list.SetRows(std::move(reordered));
    const bool selectionWasPainted = selectionCapture.items[2] || selectionCapture.items[3] ||
                                     selectionCapture.items[5];
    list.Select(3);
    flush();
    activeListPaintCapture = nullptr;
    Check(!selectionWasPainted && list.Selected() == 3,
          "row reordering painted before restoring selection");

    auto styleChanged = list.rows();
    styleChanged[2].finished = true;
    styleChanged[2].lastChild = true;
    list.SetRows(std::move(styleChanged));
    Check(dirty(), "changing row styling did not invalidate it");
    flush();

    auto labelChanged = list.rows();
    labelChanged[2].tlsDomainLabel = std::make_shared<const std::wstring>(L"[example.test]");
    list.SetRows(std::move(labelChanged));
    Check(dirty(), "changing a visible domain did not invalidate it");
    flush();
    auto equalLabel = list.rows();
    equalLabel[2].tlsDomainLabel = std::make_shared<const std::wstring>(L"[example.test]");
    list.SetRows(std::move(equalLabel));
    Check(!dirty(), "equal domain labels with different owners invalidated the list");

    // Нижняя строка видна только наполовину и тоже должна обновляться.
    RECT partialRect{};
    Check(ListView_GetItemRect(list.hwnd(), 2, &partialRect, LVIR_BOUNDS),
          "could not measure partially visible test row");
    RECT listWindow{}, initialClient{};
    GetWindowRect(list.hwnd(), &listWindow);
    GetClientRect(list.hwnd(), &initialClient);
    const int nonClientHeight = (listWindow.bottom - listWindow.top) -
                                (initialClient.bottom - initialClient.top);
    const int partialHeight = partialRect.top +
        std::max(1L, (partialRect.bottom - partialRect.top) / 2) + nonClientHeight;
    MoveWindow(list.hwnd(), 0, 0, 950, partialHeight, TRUE);
    list.FitColumns();
    flush();
    RECT client{}, visiblePart{};
    GetClientRect(list.hwnd(), &client);
    const bool havePartial = ListView_GetItemRect(list.hwnd(), 2, &partialRect, LVIR_BOUNDS) &&
        partialRect.top < client.bottom && partialRect.bottom > client.bottom &&
        IntersectRect(&visiblePart, &partialRect, &client);
    if (!havePartial)
        std::cerr << "partial row top=" << partialRect.top << " bottom=" << partialRect.bottom
                  << " client bottom=" << client.bottom << " requested=" << partialHeight << '\n';
    Check(havePartial, "could not expose a partial test row");
    auto partialChanged = list.rows();
    partialChanged[2].col[ColRecv] = L"128 B";
    list.SetRows(std::move(partialChanged));
    region = CreateRectRgn(0, 0, 0, 0);
    Check(region != nullptr, "could not create partial-row test region");
    GetUpdateRgn(list.hwnd(), region, FALSE);
    const bool partialDirty = RectInRegion(region, &visiblePart) != FALSE;
    DeleteObject(region);
    Check(partialDirty, "partially visible changed row was not invalidated");
    flush();
    MoveWindow(list.hwnd(), 0, 0, 950, 240, TRUE);
    list.FitColumns();
    flush();

    list.Select(2);
    flush();
    list.Select(2);
    Check(!dirty(), "restoring an unchanged selection invalidated the list");
    ListView_SetItemState(list.hwnd(), 2, 0, LVIS_FOCUSED);
    flush();
    auto focusRows = list.rows();
    focusRows[1].col[ColSent] = L"128 B";
    focusRows[3].col[ColSent] = L"256 B";
    ListPaintCapture focusCapture{};
    activeListPaintCapture = &focusCapture;
    list.SetRows(std::move(focusRows));
    const bool focusWasPainted = focusCapture.items[1] || focusCapture.items[3];
    list.Select(2);
    flush();
    activeListPaintCapture = nullptr;
    Check(!focusWasPainted, "row updates painted before restoring item focus");
    Check((ListView_GetItemState(list.hwnd(), 2, LVIS_SELECTED | LVIS_FOCUSED) &
           (LVIS_SELECTED | LVIS_FOCUSED)) == (LVIS_SELECTED | LVIS_FOCUSED),
          "restoring selection did not restore item focus");
    flush();

    Check(ListView_EnsureVisible(list.hwnd(), 29, FALSE), "could not scroll repaint test list");
    flush();
    const int top = ListView_GetTopIndex(list.hwnd());
    Check(top > 0, "parent row is still visible in inherited-data test");
    RECT childRect{};
    Check(ListView_GetItemRect(list.hwnd(), top, &childRect, LVIR_BOUNDS),
          "could not measure inherited-data test row");
    auto parentChanged = list.rows();
    parentChanged[0].col[ColPid] = L"456";
    list.SetRows(std::move(parentChanged));
    region = CreateRectRgn(0, 0, 0, 0);
    Check(region != nullptr, "could not create inherited-data test region");
    GetUpdateRgn(list.hwnd(), region, FALSE);
    const bool childDirty = RectInRegion(region, &childRect) != FALSE;
    DeleteObject(region);
    Check(childDirty, "parent PID change did not invalidate a visible child");
    flush();

    auto parentRenamed = list.rows();
    parentRenamed[0].col[ColProcess] = L"renamed-process.exe";
    list.SetRows(std::move(parentRenamed));
    region = CreateRectRgn(0, 0, 0, 0);
    Check(region != nullptr, "could not create inherited-name test region");
    GetUpdateRgn(list.hwnd(), region, FALSE);
    const bool childNameDirty = RectInRegion(region, &childRect) != FALSE;
    DeleteObject(region);
    Check(childNameDirty, "parent name change did not invalidate a visible child");
    flush();

    auto fewer = list.rows();
    fewer.pop_back();
    list.SetRows(std::move(fewer));
    Check(ListView_GetItemCount(list.hwnd()) == 29 && dirty(),
          "changing the row count did not update and repaint the list");
}

void BenchmarkListPaint() {
    SetUiLang(UiLang::English);
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = HostProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"FirewallXListPaintBenchmark";
    RegisterClassW(&wc);
    TreeList list;
    HWND window = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        0, 0, 1600, 1000, nullptr, nullptr, instance, &list);
    struct Cleanup {
        TreeList& list;
        HWND window;
        ~Cleanup() { list.Destroy(); if (window) DestroyWindow(window); }
    } cleanup{list, window};
    Check(window && list.Create(window, instance, 1), "could not create benchmark list");
    list.SetSkin(ListSkin::Modern);
    MoveWindow(list.hwnd(), 0, 0, 1550, 920, TRUE);
    std::vector<TreeList::Row> rows(24);
    rows[0].isGroup = true;
    rows[0].expanded = true;
    rows[0].key.group = 123;
    rows[0].col[ColProcess] = L"firewall-example.exe";
    rows[0].col[ColPid] = L"123";
    for (size_t i = 1; i < rows.size(); ++i) {
        rows[i].key.group = 123;
        rows[i].key.generation = i;
        rows[i].groupRow = 0;
        rows[i].lastChild = i + 1 == rows.size();
        rows[i].col[ColRemote] = L"192.0.2.123:443";
        rows[i].col[ColReason] = L"Allowed by example rule";
        rows[i].col[ColSent] = L"1.25 MB";
        rows[i].col[ColRecv] = L"8.35 MB";
        rows[i].col[ColSpeed] = L"12.6 KB/s";
        rows[i].col[ColProto] = L"TCP";
        rows[i].col[ColLocal] = L"192.168.1.4:12345";
        rows[i].col[ColDir] = L"Outgoing";
    }
    list.SetRows(std::move(rows));
    ShowWindow(window, SW_SHOWNOACTIVATE);
    RedrawWindow(list.hwnd(), nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    Check(ListView_GetCountPerPage(list.hwnd()) >= 16, "benchmark window is too small");
    constexpr int repeats = 60;
    for (int mode : {0, 1, 2}) {
        ListPaintCapture captured{};
        activeListPaintCapture = &captured;
        ULONG64 start = 0, end = 0;
        Check(QueryThreadCycleTime(GetCurrentThread(), &start) != FALSE, "could not read thread cycles");
        const auto wallStart = std::chrono::steady_clock::now();
        for (int i = 0; i < repeats; ++i) {
            if (mode == 1) {
                for (int index : {2, 8, 14}) {
                    ListView_RedrawItems(list.hwnd(), index, index);
                    UpdateWindow(list.hwnd());
                }
            } else if (mode == 2) {
                auto changed = list.rows();
                for (int index : {2, 8, 14})
                    changed[static_cast<size_t>(index)].col[ColRecv] = i % 2 ? L"8.36 MB" : L"8.37 MB";
                list.SetRows(std::move(changed));
                UpdateWindow(list.hwnd());
            } else {
                InvalidateRect(list.hwnd(), nullptr, FALSE);
                UpdateWindow(list.hwnd());
            }
        }
        const auto elapsed = std::chrono::steady_clock::now() - wallStart;
        Check(QueryThreadCycleTime(GetCurrentThread(), &end) != FALSE, "could not read thread cycles");
        activeListPaintCapture = nullptr;
        int draws = 0;
        for (int count : captured.items) draws += count;
        const char* label = mode == 0 ? "full" : mode == 1 ? "partial" : "setrows";
        std::cout << label << " cycles=" << end - start
                  << " wall_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                  << " item_draws=" << draws << " repeats=" << repeats << '\n';
    }
}

void CALLBACK CloseMenu(HWND window, UINT, UINT_PTR timer, DWORD) {
    KillTimer(window, timer);
    EndMenu();
}

void TestList(UiLang language, bool preview = false) {
    SetUiLang(language);
    const bool rtl = language == UiLang::Arabic || language == UiLang::Persian;
    HINSTANCE instance = GetModuleHandleW(nullptr);
    const wchar_t* className = L"FirewallXUiLayoutTests";
    WNDCLASSW wc{};
    wc.lpfnWndProc = HostProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = className;
    RegisterClassW(&wc);

    TreeList list;
    HWND window = CreateWindowExW(Ui::LayoutStyle(), className,
        LoadStringRes(IDS_APPNAME).c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        100, 100, 1400, 420, nullptr, nullptr, instance, &list);
    Check(window && list.Create(window, instance, 1), "could not create table layout probe");
    MoveWindow(list.hwnd(), 0, 0, 1350, 330, TRUE);
    list.FitColumns();
    std::vector<TreeList::Row> rows(2);
    rows[0].isGroup = true;
    rows[0].key.group = 123;
    rows[0].col[ColProcess] = L"notepad.exe";
    rows[0].col[ColPid] = L"123";
    rows[0].path = L"C:\\Windows\\System32\\notepad.exe";
    rows[1].groupRow = 0;
    rows[1].key.group = 123;
    rows[1].lastChild = true;
    rows[1].col[ColRemote] = L"[2001:db8::1]:443";
    rows[1].col[ColLocal] = L"192.0.2.10:41000";
    rows[1].col[ColProto] = L"TCP";
    rows[1].col[ColReason] = LoadStringRes(IDS_RULE_ACT_ALLOW);
    rows[1].tlsDomainLabel = std::make_shared<const std::wstring>(L"[example.com]");
    list.SetRows(std::move(rows));
    list.Select(0);
    Check(Mirrored(list.hwnd()) == rtl && Mirrored(ListView_GetHeader(list.hwnd())) == rtl,
          "table or header has the wrong layout");

    int toggles = 0;
    list.onToggle = [&](int row) { if (row == 0) ++toggles; };
    NMLVKEYDOWN key{};
    key.hdr.hwndFrom = list.hwnd();
    key.hdr.code = LVN_KEYDOWN;
    key.wVKey = rtl ? VK_LEFT : VK_RIGHT;
    LRESULT result = 0;
    Check(list.OnNotify(&key.hdr, result) && toggles == 1, "expand arrow has the wrong direction");
    key.wVKey = rtl ? VK_RIGHT : VK_LEFT;
    list.OnNotify(&key.hdr, result);
    Check(toggles == 1, "collapse arrow expanded a closed group");

    NMLVDISPINFOW display{};
    display.hdr.hwndFrom = list.hwnd();
    display.hdr.code = LVN_GETDISPINFOW;
    display.item.mask = LVIF_TEXT;
    display.item.iItem = 1;
    display.item.iSubItem = ColRemote;
    list.OnNotify(&display.hdr, result);
    const std::wstring remote = list.rows()[1].col[ColRemote];
    Check(display.item.pszText && std::wstring(display.item.pszText) ==
          (rtl ? Ui::LtrText(remote) : remote), "technical cell lost its LTR embedding");
    Check(remote == L"[2001:db8::1]:443", "display markers leaked into table data");

    if (preview) {
        HMENU menu = CreateMenu();
        HMENU view = CreatePopupMenu();
        for (UINT id : {IDS_MENU_VIEW_REFRESH, IDS_MENU_VIEW_FILTER, IDS_MENU_VIEW_EXPAND,
                        IDS_MENU_VIEW_COLLAPSE, IDS_MENU_VIEW_SORT_DEFAULT,
                        IDS_MENU_VIEW_SHOW_PASSIVE, IDS_MENU_VIEW_EXIT})
            AppendMenuW(view, MF_STRING, id, LoadStringRes(id).c_str());
        HMENU style = CreatePopupMenu();
        AppendMenuW(style, MF_STRING, IDS_MENU_VIEW_SKIN_MODERN,
                    LoadStringRes(IDS_MENU_VIEW_SKIN_MODERN).c_str());
        AppendMenuW(style, MF_STRING, IDS_MENU_VIEW_SKIN_CLASSIC,
                    LoadStringRes(IDS_MENU_VIEW_SKIN_CLASSIC).c_str());
        AppendMenuW(view, MF_POPUP, reinterpret_cast<UINT_PTR>(style),
                    LoadStringRes(IDS_MENU_VIEW_SKIN_SUB).c_str());
        HMENU languages = CreatePopupMenu();
        size_t languageCount = 0;
        const UiLangInfo* languageInfo = UiLangs(languageCount);
        for (size_t i = 0; i < languageCount; ++i)
            AppendMenuW(languages, MF_STRING, 3000 + i, languageInfo[i].nativeName);
        AppendMenuW(view, MF_POPUP, reinterpret_cast<UINT_PTR>(languages),
                    LoadStringRes(IDS_MENU_VIEW_LANG_SUB).c_str());
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(view),
                    LoadStringRes(IDS_MENU_VIEW_TITLE).c_str());
        SetMenu(window, menu);
        ShowWindow(window, SW_SHOW);
        UpdateWindow(window);
        SetForegroundWindow(window);
        POINT point{40, 35};
        MapWindowPoints(window, nullptr, &point, 1);
        SetTimer(window, 1, 15000, CloseMenu);
        TrackPopupMenu(view, Ui::PopupFlags(TPM_RIGHTBUTTON), point.x, point.y,
                       0, window, nullptr);
    }
    list.Destroy();
    DestroyWindow(window);
}

void TestRowStorageRelease() {
    SetUiLang(UiLang::English);
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = HostProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"FirewallXRowStorageTests";
    RegisterClassW(&wc);
    TreeList list;
    HWND window = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW,
        100, 100, 1200, 400, nullptr, nullptr, instance, &list);
    struct Cleanup {
        TreeList& list;
        HWND window;
        ~Cleanup() { list.Destroy(); if (window) DestroyWindow(window); }
    } cleanup{list, window};
    Check(window && list.Create(window, instance, 1), "could not create row storage test list");
    std::weak_ptr<const std::wstring> previous;
    for (size_t count : {size_t{20001}, size_t{3}, size_t{0}, size_t{2}, size_t{0}}) {
        std::vector<TreeList::Row> incoming(count);
        if (!count) incoming.reserve(20001);
        std::weak_ptr<const std::wstring> current;
        if (count) {
            incoming[0].isGroup = true;
            incoming[0].expanded = incoming[0].bold = count > 1;
            incoming[0].key.group = 123;
            incoming[0].col[ColProcess] = L"row-memory-test.exe";
            for (size_t i = 1; i < count; ++i) {
                incoming[i].key.group = 123;
                incoming[i].groupRow = 0;
                incoming[i].lastChild = i + 1 == count;
                incoming[i].col[ColRemote] = L"192.0.2.10:" + std::to_wstring(i);
            }
            auto label = std::make_shared<const std::wstring>(L"[row-memory-test.example]");
            incoming[count - 1].tlsDomainLabel = label;
            current = label;
        }
        list.SetRows(std::move(incoming));
        Check(incoming.empty() && incoming.capacity() == 0, "row array ownership was not transferred");
        Check(previous.expired(), "replacing rows retained the previous nested text owner");
        Check(list.rows().size() == count && list.rows().capacity() == count &&
              ListView_GetItemCount(list.hwnd()) == static_cast<int>(count),
              "list item count or allocated capacity differs from the visible row count");
        Check(count == 0 || !current.expired(), "visible rows lost their nested text owner");
        previous = current;
        if (count) list.Select(static_cast<int>(count - 1));
        else Check(list.Selected() < 0, "empty row replacement retained selection");
    }
}

std::vector<UINT> playedBeeps;

BOOL WINAPI CaptureMessageBeep(UINT type) {
    playedBeeps.push_back(type);
    return TRUE;
}

void TestMessageBeepSetting() {
    wchar_t directory[MAX_PATH]{}, file[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length > 0 && length < MAX_PATH, "could not get temporary directory");
    Check(GetTempFileNameW(directory, L"fxb", 0, file) != 0,
          "could not create temporary settings file");
    struct Cleanup {
        const wchar_t* file;
        ~Cleanup() { Settings::Close(); DeleteFileW(file); }
    } cleanup{file};

    std::wstring error;
    Check(Settings::Open(file, error), "could not open sound test settings");
    playedBeeps.clear();
    Ui::PlayMessageBeep(MB_ICONWARNING, CaptureMessageBeep);
    Check(playedBeeps == std::vector<UINT>{MB_ICONWARNING},
          "notification sound must be enabled by default");

    Check(Settings::SetBool(Settings::Key::kMuteMessageBeep, true), "could not mute sounds");
    for (UINT type : {MB_OK, MB_ICONWARNING, MB_ICONERROR, MB_ICONINFORMATION})
        Ui::PlayMessageBeep(type, CaptureMessageBeep);
    Check(playedBeeps.size() == 1, "muted MessageBeep reached the playback API");

    Settings::Close();
    Ui::PlayMessageBeep(MB_ICONWARNING, CaptureMessageBeep);
    Check(playedBeeps.size() == 1 &&
          Settings::GetBool(Settings::Key::kMuteMessageBeep, false),
          "mute setting did not survive reopening the database");

    Check(Settings::SetBool(Settings::Key::kMuteMessageBeep, false), "could not unmute sounds");
    Ui::PlayMessageBeep(MB_ICONINFORMATION, CaptureMessageBeep);
    Check(playedBeeps == std::vector<UINT>({MB_ICONWARNING, MB_ICONINFORMATION}),
          "unmuting did not restore playback immediately or changed the sound type");

    Settings::Close();
    Ui::PlayMessageBeep(MB_ICONERROR, CaptureMessageBeep);
    Check(playedBeeps == std::vector<UINT>({MB_ICONWARNING, MB_ICONINFORMATION, MB_ICONERROR}) &&
          !Settings::GetBool(Settings::Key::kMuteMessageBeep, true),
          "unmuted setting did not survive reopening the database");
    Check(Settings::Open(L":memory:", error), "could not open isolated UI settings");
}

void TestConnectionFontSetting() {
    wchar_t directory[MAX_PATH]{}, file[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length > 0 && length < MAX_PATH, "could not get font test directory");
    Check(GetTempFileNameW(directory, L"fxf", 0, file) != 0,
          "could not create temporary font settings file");
    struct Cleanup {
        const wchar_t* file;
        ~Cleanup() { Settings::Close(); DeleteFileW(file); }
    } cleanup{file};
    std::wstring error;
    Check(Settings::Open(file, error), "could not open font test settings");

    const auto classicDefault = ListFontSetting::Load(ListSkin::Classic, 96);
    const auto modernDefault = ListFontSetting::Load(ListSkin::Modern, 96);
    const ListFontSetting::Value classic{L"Consolas", 135, FW_NORMAL};
    const ListFontSetting::Value modern{L"Arial", 180, FW_BOLD, true};
    const std::pair<const wchar_t*, ListFontSetting::Value> legacy[] = {
        {L"135\nConsolas", classic},
        {L"180\n700\nArial", {L"Arial", 180, FW_BOLD}}
    };
    for (ListSkin skin : {ListSkin::Classic, ListSkin::Modern}) {
        const wchar_t* key = skin == ListSkin::Classic
            ? Settings::Key::kListFontClassic : Settings::Key::kListFontModern;
        for (const auto& [encoded, wanted] : legacy) {
            Check(Settings::SetString(key, encoded), "could not write legacy font setting");
            Settings::Close();
            const auto font = ListFontSetting::Resolve(skin, 192);
            Check(ListFontSetting::Load(skin, 96) == wanted &&
                  wanted.face == font.lfFaceName &&
                  font.lfHeight == -MulDiv(wanted.sizeTenths, 192, 720) &&
                  font.lfWeight == wanted.weight && !font.lfItalic,
                  "legacy font setting did not preserve its font, size and weight");
        }
        Check(ListFontSetting::Reset(skin), "could not clear legacy font setting");
    }
    Check(ListFontSetting::Save(ListSkin::Classic, classic), "could not save classic font");
    Check(ListFontSetting::Load(ListSkin::Modern, 96) == modernDefault,
          "classic font changed the modern default");
    Check(ListFontSetting::Save(ListSkin::Modern, modern), "could not save modern font");
    Settings::Close();
    Check(ListFontSetting::Load(ListSkin::Classic, 96) == classic &&
          ListFontSetting::Load(ListSkin::Modern, 96) == modern,
          "per-appearance font settings did not survive reopening the database");
    Check(ListFontSetting::Resolve(ListSkin::Classic, 96).lfHeight == -18 &&
          ListFontSetting::Resolve(ListSkin::Classic, 192).lfHeight == -36 &&
          ListFontSetting::Resolve(ListSkin::Modern, 192).lfHeight == -48,
          "font point size did not scale correctly with DPI");
    Check(ListFontSetting::Resolve(ListSkin::Classic, 96).lfWeight == FW_NORMAL &&
          !ListFontSetting::Resolve(ListSkin::Classic, 96).lfItalic &&
          ListFontSetting::Resolve(ListSkin::Modern, 96).lfWeight == FW_BOLD &&
          ListFontSetting::Resolve(ListSkin::Modern, 96).lfItalic,
          "font weight or italic style was not persisted or resolved correctly");

    for (const ListFontSetting::Value& invalid : {
            ListFontSetting::Value{L"", 120, FW_NORMAL}, {L"Arial", 0, FW_NORMAL},
            {L"Arial", 730, FW_NORMAL}, {L"bad\nfont", 120, FW_NORMAL},
            {std::wstring(LF_FACESIZE, L'x'), 120, FW_NORMAL},
            {L"Arial", 120, FW_THIN - 1}, {L"Arial", 120, FW_BLACK + 1}}) {
        Check(!ListFontSetting::Save(ListSkin::Classic, invalid), "invalid font was saved");
        Check(ListFontSetting::Load(ListSkin::Classic, 96) == classic,
              "invalid save changed the previous font");
    }
    for (const wchar_t* invalid : {L"invalid", L"0\nArial", L"180\n", L"180x\nArial",
                                  L"999999999999999999999\nArial", L"180\nbad\nfont",
                                  L"180\n400\n", L"180\n400\nbad\nfont",
                                  L"180\n0\nArial", L"180\n1000\nArial",
                                  L"180\n400x\nArial", L"180\n\nArial",
                                  L"180\n400\n2\nArial", L"180\n400\n\nArial",
                                  L"180\n400\n1\n", L"180\n400\n0\nbad\nfont"}) {
        Check(Settings::SetString(Settings::Key::kListFontClassic, invalid),
              "could not write malformed font setting");
        Check(ListFontSetting::Load(ListSkin::Classic, 96) == classicDefault &&
              ListFontSetting::Load(ListSkin::Modern, 96) == modern,
              "malformed font did not fall back independently for its appearance");
    }
    Check(ListFontSetting::Save(ListSkin::Classic, classic), "could not restore classic font");

    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = HostProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"FirewallXFontSettingTests";
    RegisterClassW(&wc);
    TreeList list;
    HWND window = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW,
        100, 100, 1200, 400, nullptr, nullptr, instance, &list);
    Check(window && list.Create(window, instance, 1), "could not create font test list");
    MoveWindow(list.hwnd(), 0, 0, 1150, 350, TRUE);
    const UINT dpi = GetDpiForWindow(list.hwnd());
    const auto fontOf = [](HWND control) {
        LOGFONTW font{};
        HFONT handle = reinterpret_cast<HFONT>(SendMessageW(control, WM_GETFONT, 0, 0));
        Check(handle && GetObjectW(handle, sizeof(font), &font), "control font is missing");
        return font;
    };
    const auto expectFont = [&](const ListFontSetting::Value& wanted) {
        const auto actual = fontOf(list.hwnd());
        Check(wanted.face == actual.lfFaceName &&
              actual.lfHeight == -MulDiv(wanted.sizeTenths, static_cast<int>(dpi), 720) &&
              actual.lfWeight == wanted.weight && (actual.lfItalic != FALSE) == wanted.italic,
              "list did not apply the current appearance's font");
    };
    expectFont(classic);
    const auto headerBefore = fontOf(ListView_GetHeader(list.hwnd()));
    std::vector<TreeList::Row> rows(3);
    rows[0].isGroup = rows[0].expanded = rows[0].bold = true;
    rows[0].col[ColProcess] = L"font-test.exe";
    rows[1].groupRow = 0;
    rows[1].col[ColRemote] = L"192.0.2.10:443";
    rows[2].isGroup = true;
    rows[2].col[ColProcess] = L"collapsed-font-test.exe";
    list.SetRows(std::move(rows));
    const auto fontForDraw = [&](int row, DWORD stage) {
        HDC dc = CreateCompatibleDC(nullptr);
        Check(dc != nullptr, "could not create custom draw test DC");
        SelectObject(dc, reinterpret_cast<HFONT>(SendMessageW(list.hwnd(), WM_GETFONT, 0, 0)));
        NMLVCUSTOMDRAW draw{};
        draw.nmcd.hdr.hwndFrom = list.hwnd();
        draw.nmcd.hdr.code = NM_CUSTOMDRAW;
        draw.nmcd.dwDrawStage = stage;
        draw.nmcd.dwItemSpec = static_cast<DWORD_PTR>(row);
        draw.nmcd.hdc = dc;
        draw.iSubItem = ColRemote;
        LRESULT result = 0;
        const bool handled = list.OnNotify(&draw.nmcd.hdr, result);
        HFONT font = static_cast<HFONT>(GetCurrentObject(dc, OBJ_FONT));
        DeleteDC(dc);
        Check(handled && font, "could not inspect the custom draw font");
        return font;
    };
    const auto expectDrawFonts = [&](const ListFontSetting::Value& wanted) {
        for (int row : {0, 1, 2}) {
            for (DWORD stage : {DWORD(CDDS_ITEMPREPAINT), DWORD(CDDS_ITEMPREPAINT | CDDS_SUBITEM)}) {
                LOGFONTW actual{};
                Check(GetObjectW(fontForDraw(row, stage), sizeof(actual), &actual) != 0,
                      "could not read the custom draw font");
                Check(actual.lfHeight == -MulDiv(wanted.sizeTenths, static_cast<int>(dpi), 720) &&
                      (actual.lfItalic != FALSE) == wanted.italic &&
                      (row == 0 || (wanted.face == actual.lfFaceName && actual.lfWeight == wanted.weight)),
                      "custom draw did not use the selected weight or italic style");
            }
        }
    };
    const auto rasterOf = [&](HFONT font) {
        const int width = MulDiv(600, static_cast<int>(dpi), 96);
        const int height = MulDiv(64, static_cast<int>(dpi), 96);
        BITMAPINFO info{};
        info.bmiHeader.biSize = sizeof(info.bmiHeader);
        info.bmiHeader.biWidth = width;
        info.bmiHeader.biHeight = -height;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        HDC dc = CreateCompatibleDC(nullptr);
        Check(dc != nullptr, "could not create font raster DC");
        void* bits = nullptr;
        HBITMAP bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (!bitmap) {
            DeleteDC(dc);
            Check(false, "could not create font raster bitmap");
        }
        const auto oldBitmap = SelectObject(dc, bitmap);
        const auto oldFont = SelectObject(dc, font);
        PatBlt(dc, 0, 0, width, height, WHITENESS);
        SetBkColor(dc, RGB(255, 255, 255));
        SetTextColor(dc, RGB(0, 0, 0));
        const wchar_t text[] = L"FIREFOX.EXE 7780 Соединений: 2";
        const bool drawn = TextOutW(dc, 0, 0, text, static_cast<int>(std::size(text) - 1)) != FALSE;
        TEXTMETRICW metric{};
        const bool measured = GetTextMetricsW(dc, &metric) != FALSE;
        GdiFlush();
        const auto* pixels = static_cast<const uint32_t*>(bits);
        std::vector<uint32_t> raster(pixels, pixels + static_cast<size_t>(width) * height);
        SelectObject(dc, oldFont);
        SelectObject(dc, oldBitmap);
        DeleteObject(bitmap);
        DeleteDC(dc);
        Check(drawn && measured, "could not rasterize the selected font");
        return std::pair{metric.tmWeight, std::move(raster)};
    };
    expectDrawFonts(classic);
    list.Select(1);
    RECT before{};
    Check(ListView_GetItemRect(list.hwnd(), 1, &before, LVIR_BOUNDS), "missing initial row");

    const ListFontSetting::Value larger{L"Consolas", 240, FW_BOLD, true};
    Check(ListFontSetting::Save(ListSkin::Classic, larger), "could not enlarge classic font");
    list.ReloadFont();
    expectFont(larger);
    expectDrawFonts(larger);
    RECT after{};
    Check(ListView_GetItemRect(list.hwnd(), 1, &after, LVIR_BOUNDS) &&
          after.bottom - after.top > before.bottom - before.top,
          "row height did not grow with the selected font");
    const auto headerAfter = fontOf(ListView_GetHeader(list.hwnd()));
    Check(headerAfter.lfHeight == headerBefore.lfHeight &&
          headerAfter.lfWeight == headerBefore.lfWeight &&
          headerAfter.lfItalic == headerBefore.lfItalic &&
          std::wstring(headerAfter.lfFaceName) == headerBefore.lfFaceName && list.Selected() == 1,
          "font reload changed the header font or lost the selected connection");
    for (ListSkin skin : {ListSkin::Classic, ListSkin::Modern}) {
        list.SetSkin(skin);
        for (const ListFontSetting::Value& style : {
                ListFontSetting::Value{L"Arial", 180, FW_BOLD},
                {L"Arial", 180, FW_BOLD, true}, {L"Arial", 180, FW_NORMAL, true},
                {L"Arial", 180, FW_NORMAL}, {L"Arial", 180, FW_LIGHT},
                {L"Arial", 180, FW_BLACK, true}}) {
            Check(ListFontSetting::Save(skin, style), "could not save font style");
            Settings::Close();
            Check(ListFontSetting::Load(skin, 96) == style, "font style did not persist");
            list.ReloadFont();
            expectFont(style);
            expectDrawFonts(style);
        }
    }
    for (ListSkin skin : {ListSkin::Classic, ListSkin::Modern}) {
        list.SetSkin(skin);
        for (const ListFontSetting::Value& style : {
                ListFontSetting::Value{L"Segoe UI Variable Display Semib", 80, FW_SEMIBOLD},
                {L"Segoe UI Variable Text Semibold", 80, FW_SEMIBOLD},
                {L"Segoe UI Variable Small Semibol", 80, FW_SEMIBOLD},
                {L"Segoe UI Semibold", 80, FW_SEMIBOLD},
                {L"Arial", 80, FW_SEMIBOLD}, {L"Arial", 80, FW_BOLD}}) {
            Check(ListFontSetting::Save(skin, style), "could not save raster font setting");
            list.ReloadFont();
            expectFont(style);
            expectDrawFonts(style);
            const auto [rowWeight, rowRaster] = rasterOf(fontForDraw(1, CDDS_ITEMPREPAINT | CDDS_SUBITEM));
            const auto [groupWeight, groupRaster] = rasterOf(fontForDraw(0, CDDS_ITEMPREPAINT | CDDS_SUBITEM));
            Check(groupWeight > rowWeight && groupRaster != rowRaster,
                  "expanded group is not heavier than the selected connection font");
            Check(rasterOf(fontForDraw(2, CDDS_ITEMPREPAINT | CDDS_SUBITEM)).second == rowRaster,
                  "collapsed group does not use the selected connection font");
        }
    }
    Check(ListFontSetting::Save(ListSkin::Classic, larger) &&
          ListFontSetting::Save(ListSkin::Modern, modern), "could not restore styled fonts");
    list.ReloadFont();
    expectFont(modern);
    expectDrawFonts(modern);
    list.SetSkin(ListSkin::Classic);
    expectFont(larger);
    expectDrawFonts(larger);
    list.OnDpiChanged();
    expectFont(larger);
    expectDrawFonts(larger);
    Check(ListFontSetting::Reset(ListSkin::Classic), "could not reset classic font");
    list.ReloadFont();
    const auto reset = fontOf(list.hwnd());
    const auto original = ListFontSetting::Resolve(ListSkin::Classic, dpi);
    Check(reset.lfHeight == original.lfHeight && reset.lfWeight == original.lfWeight &&
          reset.lfItalic == original.lfItalic &&
          std::wstring(reset.lfFaceName) == original.lfFaceName &&
          ListFontSetting::Load(ListSkin::Modern, 96) == modern,
          "reset changed another appearance or did not restore the default font");
    expectDrawFonts(ListFontSetting::Load(ListSkin::Classic, dpi));
    list.Destroy();
    DestroyWindow(window);

    Check(!Settings::Open(std::wstring(file) + L"\\unavailable.db", error),
          "invalid settings path unexpectedly opened");
    Check(!ListFontSetting::Save(ListSkin::Modern, classic) &&
          !ListFontSetting::Reset(ListSkin::Modern), "font write error was ignored");
    Check(Settings::Open(file, error) && ListFontSetting::Load(ListSkin::Modern, 96) == modern,
          "failed write damaged the saved font");
    Check(Settings::Open(L":memory:", error), "could not reopen isolated UI settings");
}

void TestColumnOrderSetting() {
    wchar_t directory[MAX_PATH]{}, file[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length > 0 && length < MAX_PATH, "could not get column order test directory");
    Check(GetTempFileNameW(directory, L"fxc", 0, file) != 0,
          "could not create temporary column order settings file");
    struct Cleanup {
        const wchar_t* file;
        ~Cleanup() { Settings::Close(); DeleteFileW(file); }
    } cleanup{file};
    std::wstring error;
    Check(Settings::Open(file, error), "could not open column order test settings");
    SetUiLang(UiLang::English);

    using Order = std::array<int, ColumnCount>;
    const Order defaults{ColProcess, ColPid, ColProto, ColLocal, ColDir, ColRemote,
                         ColReason, ColSent, ColRecv, ColSpeed};
    const auto orderOf = [](const TreeList& list) {
        Order order{};
        Check(ListView_GetColumnOrderArray(list.hwnd(), ColumnCount, order.data()),
              "could not read the current column order");
        return order;
    };
    const auto notify = [](const TreeList& list, UINT code, int col, HDITEMW* item = nullptr) {
        NMHEADERW header{};
        header.hdr.hwndFrom = ListView_GetHeader(list.hwnd());
        header.hdr.idFrom = GetDlgCtrlID(header.hdr.hwndFrom);
        header.hdr.code = code;
        header.iItem = col;
        header.pitem = item;
        return SendMessageW(list.hwnd(), WM_NOTIFY, header.hdr.idFrom,
                            reinterpret_cast<LPARAM>(&header));
    };
    const auto flushOrderChange = [](const TreeList& list) {
        MSG message{};
        while (PeekMessageW(&message, list.hwnd(), WM_APP, 0xBFFF, PM_REMOVE))
            DispatchMessageW(&message);
    };
    const auto checkPadding = [](TreeList& list, int padded) {
        for (int col = 1; col < ColumnCount; ++col) {
            HDITEMW item{};
            item.mask = HDI_FORMAT;
            Check(Header_GetItem(ListView_GetHeader(list.hwnd()), col, &item),
                  "could not read header drawing format");
            Check(!!(item.fmt & HDF_OWNERDRAW) == (col == padded),
                  "header padding did not follow the last right-aligned column");
            if (list.rows().empty()) continue;
            NMLVDISPINFOW display{};
            display.hdr.hwndFrom = list.hwnd();
            display.hdr.code = LVN_GETDISPINFOW;
            display.item.mask = LVIF_TEXT;
            display.item.iItem = 1;
            display.item.iSubItem = col;
            LRESULT result = 0;
            Check(list.OnNotify(&display.hdr, result), "cell text request was not handled");
            std::wstring expected = col == padded ? L""
                : list.rows()[col == ColPid ? 0 : 1].col[col];
            if (Mirrored(list.hwnd()) &&
                (col == ColRemote || col == ColLocal || col == ColProto || col == ColPid))
                expected = Ui::LtrText(expected);
            Check(display.item.pszText && expected == display.item.pszText,
                  "custom cell padding stayed on a non-last or non-right-aligned column");
        }
    };
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = HostProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"FirewallXColumnOrderTests";
    RegisterClassW(&wc);
    const auto probe = [&](const auto& verify) {
        TreeList list;
        HWND window = CreateWindowExW(Ui::LayoutStyle(), wc.lpszClassName, L"",
            WS_OVERLAPPEDWINDOW, 100, 100, 2500, 450, nullptr, nullptr, instance, &list);
        struct WindowCleanup {
            TreeList& list;
            HWND window;
            ~WindowCleanup() { list.Destroy(); if (window) DestroyWindow(window); }
        } cleanup{list, window};
        Check(window && list.Create(window, instance, 1), "could not create column order test list");
        MoveWindow(list.hwnd(), 0, 0, 2400, 350, TRUE);
        list.FitColumns();
        verify(list);
    };

    Order saved{};
    probe([&](TreeList& list) {
        Check(orderOf(list) == defaults, "default column order changed");
        std::vector<TreeList::Row> rows(2);
        rows[0].isGroup = true;
        rows[0].key.group = rows[1].key.group = 123;
        rows[0].col[ColPid] = L"123";
        rows[1].groupRow = 0;
        for (int col = 1; col < ColumnCount; ++col)
            if (col != ColPid) rows[1].col[col] = std::to_wstring(100 + col);
        list.SetRows(std::move(rows));
        checkPadding(list, ColSpeed);
        Check(ListView_GetExtendedListViewStyle(list.hwnd()) & LVS_EX_HEADERDRAGDROP,
              "native header drag and drop is disabled");
        Check(notify(list, HDN_BEGINDRAG, ColProcess) != FALSE,
              "the process column can be dragged");
        HDITEMW drop{};
        drop.mask = HDI_ORDER;
        drop.iOrder = 0;
        Check(notify(list, HDN_ENDDRAG, ColSpeed, &drop) != FALSE,
              "another column can be dropped before the process column");
        drop.iOrder = 2;
        Check(notify(list, HDN_ENDDRAG, ColProcess, &drop) != FALSE,
              "a process column drop was accepted");
        flushOrderChange(list);
        Check(orderOf(list) == defaults &&
              Settings::GetString(Settings::Key::kListColumnOrder).empty(),
              "a rejected drag changed the column order or settings");

        const auto moveColumn = [&](int col, int target) {
            Check(notify(list, HDN_BEGINDRAG, col) == FALSE, "column drag was rejected");
            const auto before = Settings::GetString(Settings::Key::kListColumnOrder);
            drop.iOrder = target;
            Check(notify(list, HDN_ENDDRAG, col, &drop) == FALSE, "column drop was rejected");
            Check(Settings::GetString(Settings::Key::kListColumnOrder) == before,
                  "column order was saved before the header applied the drop");
            Order order = orderOf(list);
            const auto from = std::find(order.begin(), order.end(), col);
            const auto to = order.begin() + target;
            if (from < to) std::rotate(from, from + 1, to + 1);
            else std::rotate(to, from, from + 1);
            Check(ListView_SetColumnOrderArray(list.hwnd(), ColumnCount, order.data()),
                  "could not apply the native dropped column order");
            flushOrderChange(list);
            Check(orderOf(list) == order && order.front() == ColProcess,
                  "a column move changed logical column identities or the first column");
            return order;
        };
        saved = moveColumn(ColSpeed, 1);
        checkPadding(list, ColRecv);

        // Бывшая последняя колонка теперь может расти за счёт соседей справа.
        const int processWidth = ListView_GetColumnWidth(list.hwnd(), ColProcess);
        const int speedWidth = ListView_GetColumnWidth(list.hwnd(), ColSpeed);
        notify(list, HDN_BEGINTRACKW, ColSpeed);
        ListView_SetColumnWidth(list.hwnd(), ColSpeed, speedWidth + 10);
        Check(ListView_GetColumnWidth(list.hwnd(), ColSpeed) == speedWidth + 10 &&
              ListView_GetColumnWidth(list.hwnd(), ColProcess) == processWidth,
              "resizing a moved column used the old order or moved its left neighbour");
        notify(list, HDN_ENDTRACKW, ColSpeed);
        saved = moveColumn(ColRemote, ColumnCount - 1);
        checkPadding(list, -1);

        // Новую последнюю колонку нельзя растянуть за правый край списка.
        notify(list, HDN_BEGINTRACKW, ColRemote);
        HDITEMW width{};
        width.mask = HDI_WIDTH;
        width.cxy = ListView_GetColumnWidth(list.hwnd(), ColRemote) + 10;
        Check(notify(list, HDN_ITEMCHANGINGW, ColRemote, &width) != FALSE,
              "the moved last column can grow beyond the list's right edge");
        notify(list, HDN_ENDTRACKW, ColRemote);
        Check(orderOf(list) == saved, "resizing changed the column order");

        for (ListSkin skin : {ListSkin::Modern, ListSkin::Classic}) {
            list.SetSkin(skin);
            list.ReloadFont();
            list.OnDpiChanged();
            Check(orderOf(list) == saved, "appearance, font or DPI change reset the column order");
            checkPadding(list, -1);
        }
        for (UiLang language : {UiLang::Arabic, UiLang::Persian, UiLang::English}) {
            SetUiLang(language);
            list.ApplyColumns();
            Check(orderOf(list) == saved, "language switch reset the column order");
            checkPadding(list, -1);
        }

        for (int col : {ColSent, ColPid, ColSpeed, ColRecv}) {
            saved = moveColumn(col, ColumnCount - 1);
            checkPadding(list, col);
        }
        for (int col : {ColRemote, ColLocal, ColProto, ColDir, ColReason}) {
            saved = moveColumn(col, ColumnCount - 1);
            checkPadding(list, -1);
        }
        // Условие зависит от фактического выравнивания, а не от названия колонки.
        for (int fmt : {LVCFMT_RIGHT, LVCFMT_CENTER, LVCFMT_LEFT}) {
            LVCOLUMNW column{};
            column.mask = LVCF_FMT;
            column.fmt = fmt;
            Check(ListView_SetColumn(list.hwnd(), ColReason, &column),
                  "could not change the last column's text alignment");
            saved = moveColumn(ColReason, ColumnCount - 1);
            checkPadding(list, fmt == LVCFMT_RIGHT ? ColReason : -1);
        }
        saved = moveColumn(ColSent, ColumnCount - 1);
        checkPadding(list, ColSent);
    });

    Settings::Close();
    probe([&](TreeList& list) {
        Check(orderOf(list) == saved, "column order did not survive reopening the database");
        checkPadding(list, ColSent);
        Check(!Settings::GetString(Settings::Key::kListColumnOrder).empty(),
              "column order was not saved to settings");
    });
    for (const wchar_t* invalid : {L"", L"0,5,7", L"0,5,7,8,9,1,2,3,4,4",
            L"5,0,7,8,9,1,2,3,4,6", L"0,5,7,8,9,1,2,3,4,10",
            L"0,5,7,8,9,1,2,3,4,-1", L"0,5,7,8,9,1,2,3,4,6,",
            L"0,5,7,8,9,1,2,3,4,6x"}) {
        Check(Settings::SetString(Settings::Key::kListColumnOrder, invalid),
              "could not write malformed column order settings");
        probe([&](TreeList& list) {
            Check(orderOf(list) == defaults, "malformed column order did not restore the default");
            checkPadding(list, ColSpeed);
        });
    }
    Check(Settings::Open(L":memory:", error), "could not reopen isolated UI settings");
}

void TestSystemDpiScaling() {
    wchar_t directory[MAX_PATH]{}, file[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length > 0 && length < MAX_PATH, "could not get DPI test directory");
    Check(GetTempFileNameW(directory, L"fxd", 0, file) != 0,
          "could not create temporary DPI settings file");
    struct Cleanup {
        const wchar_t* file;
        DPI_AWARENESS_CONTEXT previous = GetThreadDpiAwarenessContext();
        HWND normal = nullptr, scaled = nullptr, popup = nullptr;
        ~Cleanup() {
            if (popup) DestroyWindow(popup);
            if (scaled) DestroyWindow(scaled);
            if (normal) DestroyWindow(normal);
            SetThreadDpiAwarenessContext(previous);
            Settings::Close();
            DeleteFileW(file);
        }
    } cleanup{file};
    std::wstring error;
    Check(Settings::Open(file, error), "could not open DPI test settings");
    Check(!Settings::GetBool(Settings::Key::kSystemDpiScaling, false),
          "system scaling must be disabled by default");
    Check(Ui::InitializeDpiAwareness() && AreDpiAwarenessContextsEqual(
              GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2),
          "default DPI mode must be PerMonitorV2");
    cleanup.normal = CreateWindowExW(0, L"STATIC", L"", WS_OVERLAPPEDWINDOW,
        0, 0, 400, 300, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    Check(cleanup.normal != nullptr, "could not create normal DPI probe");

    Check(Settings::SetBool(Settings::Key::kSystemDpiScaling, true),
          "could not enable system scaling");
    Settings::Close();
    Check(Settings::GetBool(Settings::Key::kSystemDpiScaling, false),
          "enabled system scaling did not survive reopening the database");
    Check(AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(),
              DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2),
          "saving the DPI setting changed the running UI context");
    Check(Ui::InitializeDpiAwareness() && AreDpiAwarenessContextsEqual(
              GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_UNAWARE),
          "system scaling must use UNAWARE, not SYSTEM_AWARE or UNAWARE_GDISCALED");
    Check(GetDpiForSystem() == 96, "system scaling did not virtualize system DPI to 96");
    cleanup.scaled = CreateWindowExW(0, L"STATIC", L"", WS_OVERLAPPEDWINDOW,
        0, 0, 400, 300, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    HWND child = CreateWindowExW(0, L"BUTTON", L"", WS_CHILD,
        0, 0, 100, 26, cleanup.scaled, nullptr, GetModuleHandleW(nullptr), nullptr);
    cleanup.popup = CreateWindowExW(0, L"STATIC", L"", WS_POPUP,
        0, 0, 200, 100, cleanup.scaled, nullptr, GetModuleHandleW(nullptr), nullptr);
    Check(cleanup.scaled && child && cleanup.popup, "could not create scaled DPI probes");
    for (HWND window : {cleanup.scaled, child, cleanup.popup}) {
        Check(AreDpiAwarenessContextsEqual(GetWindowDpiAwarenessContext(window),
                  DPI_AWARENESS_CONTEXT_UNAWARE) && GetDpiForWindow(window) == 96,
              "a top-level window, child or popup did not inherit system scaling");
    }
    Check(AreDpiAwarenessContextsEqual(GetWindowDpiAwarenessContext(cleanup.normal),
              DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2),
          "initialization changed the DPI mode of an existing window");
    SetUiLang(UiLang::English);
    ProbeDialog dialog;
    Check(dialog.Run(cleanup.scaled, GetModuleHandleW(nullptr),
                     LoadStringRes(IDS_SETTINGS_TITLE), 520, 330) && dialog.dpi == 96,
          "modal dialog did not use 96 DPI under system scaling");
    TestList(UiLang::English);

    Check(Settings::SetBool(Settings::Key::kSystemDpiScaling, false),
          "could not disable system scaling");
    Settings::Close();
    Check(!Settings::GetBool(Settings::Key::kSystemDpiScaling, true),
          "disabled system scaling did not survive reopening the database");
    Check(AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(),
              DPI_AWARENESS_CONTEXT_UNAWARE), "disabling changed the running UI context");
    Check(Ui::InitializeDpiAwareness() && AreDpiAwarenessContextsEqual(
              GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2),
          "disabling system scaling did not restore PerMonitorV2");
    Check(GetDpiForWindow(cleanup.scaled) == 96,
          "restoring PerMonitorV2 changed an existing scaled window");

    Check(!Settings::Open(std::wstring(file) + L"\\unavailable.db", error),
          "invalid DPI settings path unexpectedly opened");
    Check(!Settings::SetBool(Settings::Key::kSystemDpiScaling, true),
          "DPI setting write error was ignored");
    Check(Settings::Open(file, error) &&
          !Settings::GetBool(Settings::Key::kSystemDpiScaling, true),
          "failed write damaged the saved DPI setting");
    Check(Settings::Open(L":memory:", error), "could not reopen isolated UI settings");
}

void TestSubMenuOwnership() {
    const std::wstring caption = LoadStringRes(IDS_MENU_VIEW_TITLE);
    for (bool attach : {false, true}) {
        HMENU root = CreateMenu();
        HMENU submenu = CreatePopupMenu();
        HMENU nested = CreatePopupMenu();
        HBITMAP bitmap = CreateBitmap(4, 4, 1, 32, nullptr);
        Check(root && submenu && nested && bitmap, "could not create menu ownership test resources");
        Check(!Ui::AppendSubMenu(root, nullptr, caption.c_str()) && GetMenuItemCount(root) == 0,
              "a missing submenu was appended");
        Check(AppendMenuW(nested, MF_STRING, 1, caption.c_str()) != FALSE,
              "could not create bitmap menu item");
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_BITMAP;
        item.hbmpItem = bitmap;
        Check(SetMenuItemInfoW(nested, 0, TRUE, &item) != FALSE,
              "could not attach the menu bitmap");
        Check(Ui::AppendSubMenu(submenu, nested, caption.c_str()),
              "could not append the nested menu");

        // Нулевой родитель даёт детерминированный отказ AppendMenuW.
        Check(Ui::AppendSubMenu(attach ? root : nullptr, submenu, caption.c_str()) == attach,
              "submenu append returned an unexpected result");
        BITMAP info{};
        if (attach) {
            Check(IsMenu(submenu) && IsMenu(nested) && GetSubMenu(root, 0) == submenu &&
                  GetObjectW(bitmap, sizeof(info), &info) != 0,
                  "successful append released the submenu or its bitmap");
            Ui::CleanupMenuBitmaps(root);
        } else {
            Check(!IsMenu(submenu) && !IsMenu(nested),
                  "failed append retained the submenu tree");
        }
        Check(GetObjectW(bitmap, sizeof(info), &info) == 0,
              "menu cleanup retained a nested bitmap");
        Check(DestroyMenu(root) != FALSE && !IsMenu(submenu) && !IsMenu(nested),
              "destroying the parent retained a submenu");
    }
}

void ProfileRuleIcons(const wchar_t* database) {
    // Диагностика настоящего Ui::IconCache: база открывается строго для чтения.
    const auto filename = std::filesystem::path(database).u8string();
    sqlite3* rawDb = nullptr;
    const int opened = sqlite3_open_v2(reinterpret_cast<const char*>(filename.c_str()),
                                       &rawDb, SQLITE_OPEN_READONLY, nullptr);
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db(rawDb, sqlite3_close);
    Check(opened == SQLITE_OK, "cannot open rule database read-only");
    sqlite3_stmt* rawQuery = nullptr;
    const int prepared = sqlite3_prepare_v2(db.get(),
        "SELECT DISTINCT app_path FROM rules ORDER BY app_path COLLATE NOCASE", -1,
        &rawQuery, nullptr);
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(rawQuery, sqlite3_finalize);
    Check(prepared == SQLITE_OK, "cannot read rule paths");
    std::vector<std::wstring> paths;
    int step = SQLITE_OK;
    while ((step = sqlite3_step(query.get())) == SQLITE_ROW) {
        const auto* path = static_cast<const wchar_t*>(sqlite3_column_text16(query.get(), 0));
        if (path) paths.emplace_back(path);
    }
    Check(step == SQLITE_DONE, "reading rule paths failed");
    std::cout << "Database paths: " << paths.size() << '\n';
    for (int pass = 1; pass <= 3; ++pass) {
        Ui::IconCache cache;
        Check(cache.Create(96), "cannot create profiling icon cache");
        double total = 0;
        size_t row = 0;
        for (const auto& path : paths) {
            const auto start = std::chrono::steady_clock::now();
            const int index = cache.Get(path);
            const double ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - start).count();
            total += ms;
            Check(index >= 0 && cache.Get(path) == index, "profiling icon was not cached");
            const auto display = std::filesystem::path(path).u8string();
            std::cout << "pass=" << pass << " path=" << row++ << " ms=" <<
                std::fixed << std::setprecision(3) << ms << " file=" <<
                reinterpret_cast<const char*>(display.c_str()) << '\n';
        }
        std::cout << "PASS " << pass << " TOTAL " << total << " ms\n";
    }
}

void TestPackagedIconCache() {
    const std::wstring path = IconTest::StoreExecutable();
    if (path.empty()) {
        std::cout << "UI packaged icon test skipped: Microsoft Store not installed\n";
        return;
    }
    Ui::IconCache cache;
    for (const UINT dpi : {96u, 120u, 144u, 192u}) {
        Check(cache.Create(dpi), "cannot create UI icon cache");
        const int size = MulDiv(16, static_cast<int>(dpi), 96);
        const int index = cache.Get(path);
        Check(index >= 0 && cache.Get(path) == index &&
              ImageList_GetImageCount(cache.handle()) == 1,
              "UI cache reloaded or lost a packaged icon");
        ProcessIcon expected(ExtractPackagedAppIcon(
            L"Microsoft.WindowsStore_8wekyb3d8bbwe!App", size), size);
        const auto actual = IconTest::RenderedPixels(size, [&](HDC dc) {
            return ImageList_Draw(cache.handle(), index, dc, 0, 0, ILD_TRANSPARENT);
        });
        const auto reference = IconTest::RenderedPixels(size, [&](HDC dc) {
            return DrawIconEx(dc, 0, 0, expected.handle(), size, size,
                               0, nullptr, DI_NORMAL | DI_NOMIRROR);
        });
        int maxDifference = 0;
        for (size_t i = 0; i < actual.size(); ++i) {
            for (const int shift : {0, 8, 16}) {
                const int a = (actual[i] >> shift) & 0xFF;
                const int b = (reference[i] >> shift) & 0xFF;
                maxDifference = std::max(maxDifference, a > b ? a - b : b - a);
            }
        }
        // Повторное преобразование premultiplied RGB допускает округление на 1.
        if (maxDifference > 1)
            std::cerr << "DPI=" << dpi << ", pixel difference=" << maxDifference << '\n';
        Check(maxDifference <= 1,
              "UI icon cache shows a placeholder instead of packaged logo");
    }
    cache.Destroy();
    Check(!cache.handle(), "UI icon cache retained its image list");
    std::cout << "UI packaged icon cache tested without PID at 96, 120, 144, 192 DPI\n";
}

void TestWindowTitle() {
    const std::wstring fullVersion =
        std::to_wstring(FIREWALLX_VER_MAJOR) + L"." +
        std::to_wstring(FIREWALLX_VER_MINOR) + L"." +
        std::to_wstring(FIREWALLX_VER_PATCH) + L"." +
        std::to_wstring(FIREWALLX_VER_BUILD);
    Check(std::wstring(AppInfo::kVersion) == fullVersion,
          "application version differs from the full resource version");
    Check(AppInfo::NameWithVersion() == std::wstring(AppInfo::kAppName) + L" " + fullVersion,
          "application name does not contain the full version");
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    const std::wstring normalTitle = AppInfo::kAppName;
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const std::wstring warning = LoadStringRes(IDS_TITLE_DRIVER_NOT_LOADED);
        Check(!warning.empty(), "driver warning is missing");
        Check(AppInfo::WindowTitle() == normalTitle,
              "initial window title is not the application name");
        Check(AppInfo::WindowTitle(true) == normalTitle + warning,
              "failed driver title lost the localized warning");
        Check(AppInfo::WindowTitle(false) == normalTitle,
              "driver warning remains after a successful start");
    }
}

void TestAboutText() {
    const std::wstring repositoryLink =
        L"<a href=\"https://github.com/GerardoKermitToy/FirewallX\">"
        L"https://github.com/GerardoKermitToy/FirewallX</a>";
    Check(AppInfo::IsAboutLink(AppInfo::kRepositoryUrl),
          "about dialog does not accept the repository link");
    Check(!AppInfo::IsAboutLink(nullptr) && !AppInfo::IsAboutLink(L"") &&
          !AppInfo::IsAboutLink(L"https://example.com.invalid/"),
          "about dialog accepts an unexpected link target");

    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        Check(LoadStringRes(IDS_AUTHOR) == AppInfo::kAuthor &&
              LoadStringRes(IDS_ABOUT_REPOSITORY) == AppInfo::kRepositoryUrl &&
              LoadStringRes(IDS_ABOUT_COPYRIGHT_PREFIX) == AppInfo::kCopyrightPrefix,
              "about dialog text does not match its resources");
        const std::wstring text = AppInfo::AboutText(L"test-mode", L"test-skin", L"test-service");
        const std::wstring heading = AppInfo::NameWithVersion() + L"\n\n" +
                                     AppInfo::kCopyrightPrefix;
        Check(text.rfind(heading, 0) == 0, "about dialog lost its copyright");
        Check(text.find(repositoryLink) != std::wstring::npos,
              "about dialog lost its repository link");
        Check(text.find(L"\n" + LoadStringRes(IDS_AUTHOR_PREFIX)) == std::wstring::npos &&
              text.find(L"\n" + LoadStringRes(IDS_ABOUT_VERSION)) == std::wstring::npos,
              "about dialog contains an extra author or version line");
        Check(text.find(L"test-mode") != std::wstring::npos &&
              text.find(L"test-skin") != std::wstring::npos &&
              text.find(L"test-service") != std::wstring::npos,
              "about dialog lost its application status");
    }
}

void TestFlags() {
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const bool rtl = languages[i].lang == UiLang::Arabic || languages[i].lang == UiLang::Persian;
        Check(Ui::IsRightToLeft() == rtl && Ui::LayoutStyle() == (rtl ? DWORD{WS_EX_LAYOUTRTL} : DWORD{0}),
              "RTL was enabled for the wrong language");
        const UINT popup = Ui::PopupFlags(TPM_RIGHTBUTTON | TPM_BOTTOMALIGN);
        Check((popup & TPM_RIGHTBUTTON) && (popup & TPM_BOTTOMALIGN) &&
              !!(popup & TPM_LAYOUTRTL) == rtl && !!(popup & TPM_RIGHTALIGN) == rtl,
              "popup lost its activation, alignment or reading flags");
        const UINT message = Ui::MessageBoxFlags(MB_ICONWARNING | MB_YESNO);
        Check((message & MB_TYPEMASK) == MB_YESNO &&
              (message & MB_ICONMASK) == MB_ICONWARNING &&
              !!(message & MB_RTLREADING) == rtl && !!(message & MB_RIGHT) == rtl,
              "message box lost its buttons, icon or RTL flags");
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    // Сбой автотеста должен вернуть ошибку, а не ждать закрытия системного окна.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    HRESULT com = E_FAIL;
    try {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        Check(SUCCEEDED(com), "could not initialize COM");
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES | ICC_INTERNET_CLASSES};
        Check(InitCommonControlsEx(&controls) != FALSE, "could not initialize common controls");
        if (argc == 2 && std::wstring(argv[1]) == L"--preview-dialog") {
            SetUiLang(UiLang::Arabic);
            ProbeDialog dialog;
            dialog.preview = true;
            dialog.Run(nullptr, GetModuleHandleW(nullptr), LoadStringRes(IDS_SETTINGS_TITLE), 520, 330);
        } else if (argc == 2 && std::wstring(argv[1]) == L"--preview-menu") {
            TestList(UiLang::Arabic, true);
        } else if (argc == 2 && std::wstring(argv[1]) == L"--benchmark-list-paint") {
            BenchmarkListPaint();
        } else if (argc == 2 && std::wstring(argv[1]) == L"--repaint-tests") {
            for (UiLang lang : {UiLang::English, UiLang::Arabic})
                for (ListSkin skin : {ListSkin::Modern, ListSkin::Classic})
                    TestRowInvalidation(lang, skin);
        } else if (argc == 3 && std::wstring(argv[1]) == L"--profile-rule-icons") {
            ProfileRuleIcons(argv[2]);
        } else {
            TestMessageBeepSetting();
            TestConnectionFontSetting();
            TestRowStorageRelease();
            for (UiLang lang : {UiLang::English, UiLang::Arabic})
                for (ListSkin skin : {ListSkin::Modern, ListSkin::Classic})
                    TestRowInvalidation(lang, skin);
            TestColumnOrderSetting();
            TestSystemDpiScaling();
            TestSubMenuOwnership();
            TestPackagedIconCache();
            TestFlags();
            TestWindowTitle();
            TestAboutText();
            TestLabelRepaint();
            TestStyledControls();
            TestLiveSwitch();
            size_t count = 0;
            const UiLangInfo* languages = UiLangs(count);
            for (size_t i = 0; i < count; ++i) {
                TestDialog(languages[i].lang);
                TestList(languages[i].lang);
            }
        }
        Ui::ReleaseFonts();
        std::cout << "UI layout tests passed\n";
        CoUninitialize();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }
}
