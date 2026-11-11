// Окно создаётся в тестовом процессе: драйвер и служба не запускаются.
#include "DebugWindow.h"
#include "StringRes.h"

#include <commctrl.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::wstring ItemText(HWND list, int row, int column) {
    wchar_t text[256]{};
    ListView_GetItemText(list, row, column, text, static_cast<int>(std::size(text)));
    return text;
}

} // namespace

void TestDebugWindow() {
    const UiLang saved = CurrentUiLang();
    struct RestoreLanguage {
        UiLang lang;
        ~RestoreLanguage() { SetUiLang(lang); }
    } restore{saved};
    SetUiLang(UiLang::Arabic);

    DebugWindow window;
    size_t samples = 0;
    uint64_t count = 3;
    auto read = [&](DebugCounters::Snapshot& out) {
        ++samples;
        out.values[DebugCounters::FlowProcesses] = count;
        out.values[DebugCounters::FlowConnections] = 0;
    };
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read), "could not open debug window");
    const HWND first = window.hwnd();
    Check(first && samples == 1, "debug window did not sample immediately");
    HWND list = FindWindowExW(first, nullptr, WC_LISTVIEWW, nullptr);
    Check(list && ListView_GetItemCount(list) == DebugCounters::Count,
          "debug window has the wrong row count");
    Check(ItemText(list, DebugCounters::FlowNdisConnections, 0) == LoadStringRes(IDS_DEBUG_NDIS_CONNECTIONS),
          "NDIS diagnostic label is not localized");
    Check(ItemText(list, DebugCounters::FlowProcesses, 1) == L"3" &&
          ItemText(list, DebugCounters::FlowConnections, 1) == L"0" &&
          ItemText(list, DebugCounters::PendingGroups, 1) == L"Busy",
          "debug window confused zero, unavailable and nonzero counts");
    Check(!(GetWindowLongPtrW(first, GWL_EXSTYLE) & WS_EX_LAYOUTRTL),
          "English debug window inherited RTL layout");
    wchar_t title[64]{}, close[64]{}, columnText[64]{};
    GetWindowTextW(first, title, static_cast<int>(std::size(title)));
    GetDlgItemTextW(first, IDCANCEL, close, static_cast<int>(std::size(close)));
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT;
    column.pszText = columnText;
    column.cchTextMax = static_cast<int>(std::size(columnText));
    ListView_GetColumn(list, 0, &column);
    Check(std::wstring(title) == L"Debug" && std::wstring(close) == L"Close" &&
          std::wstring(columnText) == L"Collection", "debug window text was translated");

    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read) &&
          window.hwnd() == first && samples == 1, "debug window was opened twice");
    count = 7;
    // Проверяется настоящий секундный WM_TIMER, а не прямой вызов обновления.
    const ULONGLONG deadline = GetTickCount64() + 5000;
    while (samples == 1 && GetTickCount64() < deadline) {
        MsgWaitForMultipleObjectsEx(0, nullptr, 50, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (!IsDialogMessageW(window.hwnd(), &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    Check(samples > 1 && ItemText(list, DebugCounters::FlowProcesses, 1) == L"7",
          "debug window timer did not refresh counts");
    SetUiLang(UiLang::Russian);
    SendMessageW(first, WM_TIMER, 1, 0);
    Check(ItemText(list, DebugCounters::PendingGroups, 1) == L"Busy",
          "language change translated the debug window");
    SendMessageW(first, WM_COMMAND, IDCANCEL, 0);
    Check(!window.hwnd() && !IsWindow(first), "debug window did not close");
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read), "debug window did not reopen");
    list = FindWindowExW(window.hwnd(), nullptr, WC_LISTVIEWW, nullptr);
    Check(ItemText(list, DebugCounters::FlowProcesses, 1) == L"7",
          "reopened debug window retained stale values");
    Check(ItemText(list, DebugCounters::FlowNdisConnections, 0) == LoadStringRes(IDS_DEBUG_NDIS_CONNECTIONS),
          "reopened debug window did not use the selected language");
    window.Close();
    Check(!window.hwnd(), "reopened debug window did not close");
    std::cout << "debug window: English text, single instance, timer, close and reopen passed\n";
}
