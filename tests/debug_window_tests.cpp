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
    size_t samples = 0, driverSamples = 0;
    uint64_t count = 3;
    DebugWindow::DriverMemory driverMemory{123456, 0};
    auto read = [&](DebugCounters::Snapshot& out) {
        ++samples;
        out.values[DebugCounters::FlowProcesses] = count;
        out.values[DebugCounters::FlowConnections] = 0;
    };
    auto readDriverMemory = [&] {
        ++driverSamples;
        return driverMemory;
    };
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read, readDriverMemory),
          "could not open debug window");
    const HWND first = window.hwnd();
    Check(first && samples == 1 && driverSamples == 1,
          "debug window did not sample immediately");
    HWND list = FindWindowExW(first, nullptr, WC_LISTVIEWW, nullptr);
    constexpr int collectionOffset = 2;
    Check(list && ListView_GetItemCount(list) == DebugCounters::Count + collectionOffset,
          "debug window has the wrong row count");
    Check(ItemText(list, 0, 0) == L"WFP driver / pool memory (PMrs) / bytes" &&
          ItemText(list, 1, 0) == L"NDIS driver / pool memory (FwXn) / bytes" &&
          ItemText(list, 0, 1) == L"123456" && ItemText(list, 1, 1) == L"0",
          "driver memory labels or initial values are incorrect");
    Check(ItemText(list, collectionOffset + DebugCounters::FlowNdisConnections, 0) == LoadStringRes(IDS_DEBUG_NDIS_CONNECTIONS),
          "NDIS diagnostic label is not localized");
    Check(ItemText(list, collectionOffset + DebugCounters::FlowProcesses, 1) == L"3" &&
          ItemText(list, collectionOffset + DebugCounters::FlowConnections, 1) == L"0" &&
          ItemText(list, collectionOffset + DebugCounters::PendingGroups, 1) == L"Busy",
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

    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read, readDriverMemory) &&
          window.hwnd() == first && samples == 1 && driverSamples == 1,
          "debug window was opened twice");
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
    Check(samples > 1 && ItemText(list, collectionOffset + DebugCounters::FlowProcesses, 1) == L"7" &&
          driverSamples == 1, "second timer did not refresh only the collection counts");
    driverMemory = {0, std::nullopt};
    const size_t collectionSamples = samples;
    SendMessageW(first, WM_TIMER, 2, 0);
    Check(driverSamples == 2 && samples == collectionSamples &&
          ItemText(list, 0, 1) == L"0" && ItemText(list, 1, 1) == L"Unavailable",
          "driver timer did not refresh zero and unavailable values independently");
    SetUiLang(UiLang::Russian);
    SendMessageW(first, WM_TIMER, 1, 0);
    Check(ItemText(list, collectionOffset + DebugCounters::PendingGroups, 1) == L"Busy" &&
          ItemText(list, 0, 0) == L"WFP driver / pool memory (PMrs) / bytes" &&
          ItemText(list, 1, 1) == L"Unavailable",
          "language change translated the debug window");
    SendMessageW(first, WM_COMMAND, IDCANCEL, 0);
    Check(!window.hwnd() && !IsWindow(first), "debug window did not close");
    driverMemory = {999, 888};
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read, readDriverMemory),
          "debug window did not reopen");
    list = FindWindowExW(window.hwnd(), nullptr, WC_LISTVIEWW, nullptr);
    Check(driverSamples == 3 && ItemText(list, 0, 1) == L"999" && ItemText(list, 1, 1) == L"888" &&
          ItemText(list, collectionOffset + DebugCounters::FlowProcesses, 1) == L"7",
          "reopened debug window retained stale values");
    Check(ItemText(list, collectionOffset + DebugCounters::FlowNdisConnections, 0) == LoadStringRes(IDS_DEBUG_NDIS_CONNECTIONS),
          "reopened debug window did not use the selected language");
    window.Close();
    Check(!window.hwnd(), "reopened debug window did not close");

    // Проверяется и настоящий системный запрос без подставного источника.
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), read), "could not open real driver diagnostics");
    list = FindWindowExW(window.hwnd(), nullptr, WC_LISTVIEWW, nullptr);
    const auto validMemory = [](const std::wstring& text) {
        return text == L"Unavailable" ||
               (!text.empty() && text.find_first_not_of(L"0123456789") == std::wstring::npos);
    };
    Check(validMemory(ItemText(list, 0, 1)) && validMemory(ItemText(list, 1, 1)),
          "real driver diagnostics returned invalid values");
    std::wcout << L"driver pool: PMrs=" << ItemText(list, 0, 1)
               << L" FwXn=" << ItemText(list, 1, 1) << L" bytes\n";
    window.Close();
    std::cout << "debug window: English text, timers, driver pool, close and reopen passed\n";
}
