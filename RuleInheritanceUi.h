#pragma once
#include "Rules.h"
#include "StringRes.h"

namespace RuleInheritanceUi {

inline void Set(HWND enabled, HWND never, RuleInheritance mode) {
    SendMessageW(enabled, BM_SETCHECK, RuleInheritanceEnabled(mode) ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(never, BM_SETCHECK, RuleInheritanceBlocked(mode) ? BST_CHECKED : BST_UNCHECKED, 0);
}

inline RuleInheritance Selected(HWND enabled, HWND never) {
    const bool give = SendMessageW(enabled, BM_GETCHECK, 0, 0) == BST_CHECKED;
    const bool take = SendMessageW(never, BM_GETCHECK, 0, 0) == BST_CHECKED;
    return static_cast<RuleInheritance>((give ? 1 : 0) | (take ? 2 : 0));
}

} // namespace RuleInheritanceUi
