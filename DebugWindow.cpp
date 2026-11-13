#include "DebugWindow.h"
#include "resource.h"
#include "StringRes.h"
#include "UiKit.h"

#include <commctrl.h>
#include <uxtheme.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <new>
#include <vector>

namespace {

constexpr wchar_t kClass[] = L"FirewallXDebugWindow";
constexpr UINT_PTR kTimer = 1;
constexpr UINT_PTR kDriverMemoryTimer = 2;
constexpr int kListId = 100;
constexpr int kDriverMemoryRows = 2;

// Технические подписи окна намеренно всегда английские.
constexpr const wchar_t* kLabels[] = {
    L"FlowStore / processes",
    L"FlowStore / connections",
    L"FlowStore / owner index / TCP IPv4",
    L"FlowStore / owner index / TCP IPv6",
    L"FlowStore / owner index / UDP IPv4",
    L"FlowStore / owner index / UDP IPv6",
    L"FlowStore / local sockets / TCP IPv4",
    L"FlowStore / local sockets / TCP IPv6",
    L"FlowStore / local sockets / UDP IPv4",
    L"FlowStore / local sockets / UDP IPv6",
    L"Ingest / pending groups",
    L"Ingest / pending index",
    L"Ingest / waiting verdict requests",
    L"Ingest / verdict cache",
    L"Ingest / verdict expiry queue",
    L"Ingest / TLS assemblies",
    L"Ingest / TLS expiry queue",
    L"Ingest / QUIC SNI states",
    L"RuleStore / rules",
    L"RuleStore / rule ID index",
    L"RuleStore / enabled candidates",
    L"RuleStore / application hash buckets",
    L"ProcessCache / processes",
    L"ProcessCache / icon paths",
    L"SystemInfo / process cache",
    L"UI snapshot / processes",
    L"UI snapshot / connections",
    L"TreeList / rows",
    L"UI / connection text cache",
    L"UI / rule text cache",
    L"UI / expansion overrides",
    L"AskQueue / queued requests",
    nullptr, // Локализованная строка соединений FirewallXNdisFilter.
    L"RuleStore / inheritance hash buckets",
    L"RuleStore / inheritance settings",
    L"RuleStore / rule name references",
    nullptr, // Локализованная строка кандидатов правил интерфейсов.
    L"ProcessTable / current entries",
    L"ProcessTable / retired entries",
    L"ProcessTable / late lineage index",
    L"ProcessTable / interned paths",
};
static_assert(std::size(kLabels) == DebugCounters::Count);

// Формат ответа SystemPoolTagInformation в NtQuerySystemInformation.
struct PoolTag {
    char tag[4];
    ULONG pagedAllocs;
    ULONG pagedFrees;
    SIZE_T pagedUsed;
    ULONG nonPagedAllocs;
    ULONG nonPagedFrees;
    SIZE_T nonPagedUsed;
};

struct PoolTagInformation {
    ULONG count;
    PoolTag tags[1];
};

DebugWindow::DriverMemory ReadDriverMemory() {
    constexpr auto infoClass = static_cast<SYSTEM_INFORMATION_CLASS>(22);
    constexpr ULONG lengthMismatch = 0xC0000004;
    constexpr size_t maxBufferSize = 64 * 1024 * 1024;
    try {
        std::vector<std::byte> buffer(256 * 1024);
        for (;;) {
            ULONG length = 0;
            const NTSTATUS status = NtQuerySystemInformation(infoClass, buffer.data(),
                static_cast<ULONG>(buffer.size()), &length);
            if (static_cast<ULONG>(status) == lengthMismatch) {
                const size_t next = std::max(buffer.size() * 2, static_cast<size_t>(length));
                if (next > maxBufferSize) return {};
                buffer.resize(next);
                continue;
            }
            if (status < 0 || length > buffer.size() ||
                length < offsetof(PoolTagInformation, tags)) return {};

            ULONG count = 0;
            std::memcpy(&count, buffer.data(), sizeof(count));
            const size_t offset = offsetof(PoolTagInformation, tags);
            if (count > (length - offset) / sizeof(PoolTag)) return {};

            DebugWindow::DriverMemory result{0, 0};
            for (ULONG i = 0; i < count; ++i) {
                PoolTag entry{};
                std::memcpy(&entry, buffer.data() + offset + static_cast<size_t>(i) * sizeof(entry),
                            sizeof(entry));
                const uint64_t bytes = static_cast<uint64_t>(entry.pagedUsed) + entry.nonPagedUsed;
                if (std::memcmp(entry.tag, "PMrs", sizeof(entry.tag)) == 0)
                    *result.wfp += bytes;
                else if (std::memcmp(entry.tag, "FwXn", sizeof(entry.tag)) == 0)
                    *result.ndis += bytes;
            }
            return result;
        }
    } catch (const std::bad_alloc&) {
        return {};
    }
}

} // namespace

bool DebugWindow::Show(HWND owner, HINSTANCE inst,
                       std::function<void(DebugCounters::Snapshot&)> read,
                       std::function<DriverMemory()> readDriverMemory) {
    if (hwnd_) {
        ShowWindow(hwnd_, IsIconic(hwnd_) ? SW_RESTORE : SW_SHOW);
        SetForegroundWindow(hwnd_);
        return true;
    }

    WNDCLASSEXW wc{ sizeof(wc) };
    if (!GetClassInfoExW(inst, kClass, &wc)) {
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &DebugWindow::Thunk;
        wc.hInstance = inst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(IDI_ICON1));
        wc.hIconSm = wc.hIcon;
        wc.hbrBackground = nullptr;
        wc.lpszClassName = kClass;
        if (!RegisterClassExW(&wc)) return false;
    }

    dpi_ = owner ? GetDpiForWindow(owner) : GetDpiForSystem();
    if (!dpi_) dpi_ = 96;
    colors_ = Ui::DialogPalette();
    read_ = std::move(read);
    readDriverMemory_ = std::move(readDriverMemory);
    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    const DWORD exStyle = WS_EX_CONTROLPARENT | WS_EX_NOINHERITLAYOUT;
    RECT frame{ 0, 0, Sc(720), Sc(590) };
    AdjustWindowRectExForDpi(&frame, style, FALSE, exStyle, dpi_);
    MONITORINFO mi{ sizeof(mi) };
    GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &mi);
    RECT base = mi.rcWork;
    if (owner) GetWindowRect(owner, &base);
    const int width = std::min<int>(frame.right - frame.left, mi.rcWork.right - mi.rcWork.left);
    const int height = std::min<int>(frame.bottom - frame.top, mi.rcWork.bottom - mi.rcWork.top);
    const int x = std::clamp<int>(base.left + (base.right - base.left - width) / 2,
                                 mi.rcWork.left, mi.rcWork.right - width);
    const int y = std::clamp<int>(base.top + (base.bottom - base.top - height) / 2,
                                 mi.rcWork.top, mi.rcWork.bottom - height);
    HWND h = CreateWindowExW(exStyle, kClass, L"Debug", style,
                             x, y, width, height, owner, nullptr, inst, this);
    if (!h) {
        read_ = {};
        readDriverMemory_ = {};
        return false;
    }
    ShowWindow(h, SW_SHOW);
    SetFocus(list_);
    return true;
}

void DebugWindow::Close() {
    if (hwnd_) DestroyWindow(hwnd_);
}

bool DebugWindow::Build(HINSTANCE inst) {
    Ui::KeepLeftToRight(hwnd_);
    note_ = CreateWindowExW(0, L"STATIC", L"Process collections: 1 s. Driver pool (system-wide): 1 min.\n"
        L"Busy means a collection is locked; diagnostics never waits for it.",
        WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd_, nullptr, inst, nullptr);
    list_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_NOSORTHEADER,
        0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kListId)), inst, nullptr);
    close_ = CreateWindowExW(0, L"BUTTON", L"Close",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(IDCANCEL), inst, nullptr);
    if (!note_ || !list_ || !close_) return false;
    ListView_SetExtendedListViewStyle(list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    SetWindowTheme(list_, L"Explorer", nullptr);
    ListView_SetBkColor(list_, colors_.surface);
    ListView_SetTextBkColor(list_, colors_.surface);
    ListView_SetTextColor(list_, colors_.text);
    UpdateFonts();

    for (int col = 0; col < 2; ++col) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        column.pszText = const_cast<wchar_t*>(col ? L"Value" : L"Collection");
        column.cx = Sc(col ? 120 : 540);
        column.fmt = col ? LVCFMT_RIGHT : LVCFMT_LEFT;
        if (ListView_InsertColumn(list_, col, &column) < 0) return false;
    }
    busy_ = L"Busy";
    const wchar_t* driverLabels[] = { L"WFP driver / pool memory (PMrs) / bytes",
                                      L"NDIS driver / pool memory (FwXn) / bytes" };
    for (int i = 0; i < kDriverMemoryRows; ++i) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = i;
        item.pszText = const_cast<wchar_t*>(driverLabels[i]);
        if (ListView_InsertItem(list_, &item) < 0) return false;
        ListView_SetItemText(list_, i, 1, const_cast<wchar_t*>(L"Unavailable"));
    }
    for (size_t i = 0; i < std::size(kLabels); ++i) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(i) + kDriverMemoryRows;
        const UINT labelId = i == DebugCounters::FlowNdisConnections
            ? IDS_DEBUG_NDIS_CONNECTIONS : IDS_DEBUG_INTERFACE_CANDIDATES;
        std::wstring label = kLabels[i] ? kLabels[i] : LoadStringRes(labelId);
        item.pszText = label.data();
        if (ListView_InsertItem(list_, &item) < 0) return false;
        ListView_SetItemText(list_, item.iItem, 1, busy_.data());
    }
    Layout();
    return true;
}

void DebugWindow::Layout() {
    if (!list_) return;
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int margin = Sc(11), gap = Sc(7), buttonW = Sc(100), buttonH = Sc(26);
    const int width = std::max(0, static_cast<int>(rc.right) - 2 * margin);
    const int top = margin + Sc(40) + gap;
    const int bottom = static_cast<int>(rc.bottom) - margin - buttonH;
    MoveWindow(note_, margin, margin, width, Sc(40), TRUE);
    MoveWindow(list_, margin, top, width, std::max(0, bottom - gap - top), TRUE);
    MoveWindow(close_, std::max(margin, static_cast<int>(rc.right) - margin - buttonW),
               bottom, buttonW, buttonH, TRUE);
    RECT listRc{};
    GetClientRect(list_, &listRc);
    ListView_SetColumnWidth(list_, 0, std::max(Sc(120), static_cast<int>(listRc.right) - Sc(120)));
    ListView_SetColumnWidth(list_, 1, Sc(120));
    InvalidateRect(hwnd_, nullptr, TRUE);
}

void DebugWindow::UpdateFonts() {
    HFONT regular = Ui::CreateDialogFont(dpi_);
    HFONT bold = Ui::CreateDialogFont(dpi_, 9, FW_SEMIBOLD);
    HFONT body = regular ? regular : Ui::MessageFont(dpi_);
    for (HWND control : { note_, list_, close_ })
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(body), TRUE);
    SendMessageW(ListView_GetHeader(list_), WM_SETFONT,
                 reinterpret_cast<WPARAM>(bold ? bold : body), TRUE);
    if (font_) DeleteObject(font_);
    if (semibold_) DeleteObject(semibold_);
    font_ = regular;
    semibold_ = bold;
}

void DebugWindow::Paint(HDC dc) {
    RECT client{};
    GetClientRect(hwnd_, &client);
    FillRect(dc, &client, GetSysColorBrush(COLOR_BTNFACE));
    HBRUSH border = CreateSolidBrush(colors_.border);
    RECT list{};
    GetWindowRect(list_, &list);
    MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&list), 2);
    InflateRect(&list, 1, 1);
    FrameRect(dc, &list, border);
    DeleteObject(border);
}

void DebugWindow::Refresh() {
    DebugCounters::Snapshot sample;
    if (read_) read_(sample);
    for (size_t i = 0; i < sample.values.size(); ++i) {
        if (sample.values[i] == last_.values[i]) [[likely]] continue;
        wchar_t number[32]{};
        if (sample.values[i]) swprintf_s(number, L"%llu", *sample.values[i]);
        ListView_SetItemText(list_, static_cast<int>(i) + kDriverMemoryRows, 1,
                             sample.values[i] ? number : busy_.data());
    }
    last_ = sample;
}

void DebugWindow::RefreshDriverMemory() {
    const auto sample = readDriverMemory_ ? readDriverMemory_() : ReadDriverMemory();
    const std::optional<uint64_t> values[] = { sample.wfp, sample.ndis };
    for (int i = 0; i < kDriverMemoryRows; ++i) {
        wchar_t number[32]{};
        if (values[i]) swprintf_s(number, L"%llu", *values[i]);
        ListView_SetItemText(list_, i, 1,
                             values[i] ? number : const_cast<wchar_t*>(L"Unavailable"));
    }
}

LRESULT CALLBACK DebugWindow::Thunk(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
    }
    auto* self = reinterpret_cast<DebugWindow*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    return self ? self->Handle(h, msg, wp, lp) : DefWindowProcW(h, msg, wp, lp);
}

LRESULT DebugWindow::Handle(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        hwnd_ = h;
        if (!Build(reinterpret_cast<CREATESTRUCTW*>(lp)->hInstance)) return -1;
        Refresh();
        RefreshDriverMemory();
        if (!SetTimer(h, kTimer, 1000, nullptr)) return -1;
        if (!SetTimer(h, kDriverMemoryTimer, 60000, nullptr)) {
            KillTimer(h, kTimer);
            return -1;
        }
        return 0;
    case WM_ERASEBKGND:
        Paint(reinterpret_cast<HDC>(wp));
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(h, &ps);
        Paint(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkColor(dc, colors_.page);
        SetTextColor(dc, colors_.secondary);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
    }
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lp);
        if (!hdr || hdr->code != NM_CUSTOMDRAW) break;
        if (hdr->hwndFrom == list_)
            return Ui::DrawDialogList(*reinterpret_cast<NMLVCUSTOMDRAW*>(hdr), colors_);
        break;
    }
    case WM_TIMER:
        if (wp == kTimer) Refresh();
        else if (wp == kDriverMemoryTimer) RefreshDriverMemory();
        return 0;
    case WM_SIZE:
        if (wp != SIZE_MINIMIZED) Layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lp);
        info->ptMinTrackSize = { Sc(480), Sc(300) };
        return 0;
    }
    case WM_DPICHANGED: {
        dpi_ = HIWORD(wp);
        UpdateFonts();
        const auto* rect = reinterpret_cast<RECT*>(lp);
        SetWindowPos(h, nullptr, rect->left, rect->top,
                     rect->right - rect->left, rect->bottom - rect->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        Layout();
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDCANCEL || LOWORD(wp) == IDOK) Close();
        return 0;
    case WM_CLOSE:
        Close();
        return 0;
    case WM_DESTROY:
        KillTimer(h, kTimer);
        KillTimer(h, kDriverMemoryTimer);
        return 0;
    case WM_NCDESTROY:
        if (font_) DeleteObject(font_);
        if (semibold_) DeleteObject(semibold_);
        font_ = semibold_ = nullptr;
        hwnd_ = list_ = note_ = close_ = nullptr;
        read_ = {};
        readDriverMemory_ = {};
        last_ = {};
        busy_.clear();
        SetWindowLongPtrW(h, GWLP_USERDATA, 0);
        break;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
