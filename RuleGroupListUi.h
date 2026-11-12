#pragma once

#include "Rules.h"
#include "StringRes.h"
#include "UiKit.h"
#include <commctrl.h>

namespace RuleGroupListUi {

inline void Fill(HWND list, Ui::IconCache& icons, const std::vector<AppEntry>& entries,
                 const AppEntry* selected, bool resetScroll) {
    SendMessageW(list, WM_SETREDRAW, FALSE, 0);
    // Обновляем строки на месте, чтобы список не терял позицию прокрутки.
    const int existing = ListView_GetItemCount(list);
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    int row = 0;
    for (const AppEntry& entry : entries) {
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_IMAGE;
        item.iItem = row;
        item.iImage = icons.Get(entry.interfaceGroup ? std::wstring() : entry.path);
        item.pszText = const_cast<LPWSTR>(entry.name.c_str());
        if (row < existing) ListView_SetItem(list, &item);
        else ListView_InsertItem(list, &item);
        if (selected && selected->path == entry.path && selected->global == entry.global &&
            selected->postapp == entry.postapp && selected->interfaceGroup == entry.interfaceGroup)
            ListView_SetItemState(list, row, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
        std::wstring count = std::to_wstring(entry.rules);
        if (entry.enabled != entry.rules)
            count += L" (" + std::to_wstring(entry.enabled) +
                     LoadStringRes(IDS_ALLRULES_ENABLED_SUFFIX);
        ListView_SetItemText(list, row, 1, const_cast<LPWSTR>(count.c_str()));
        ++row;
    }
    for (int last = existing - 1; last >= row; --last)
        ListView_DeleteItem(list, last);
    if (resetScroll && row > 0) ListView_EnsureVisible(list, 0, FALSE);
    SendMessageW(list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list, nullptr, TRUE);
}

} // namespace RuleGroupListUi
