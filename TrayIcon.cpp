#include "TrayIcon.h"
#include <algorithm>

namespace {

void CopyTruncated(wchar_t* dst, size_t cap, const std::wstring& src) {
    if (!dst || cap == 0) return;
    wcsncpy_s(dst, cap, src.c_str(), _TRUNCATE);
}

} // namespace

bool TrayIcon::Create(HWND owner, UINT callbackMsg, UINT id, HICON icon,
                      const std::wstring& tip) {
    Destroy();
    if (!owner || !callbackMsg) return false;

    nid_ = NOTIFYICONDATAW{};
    nid_.cbSize           = sizeof(nid_);
    nid_.hWnd             = owner;
    nid_.uID              = id;
    nid_.uFlags           = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    nid_.uCallbackMessage = callbackMsg;
    nid_.hIcon            = icon;
    CopyTruncated(nid_.szTip, ARRAYSIZE(nid_.szTip), tip);

    if (!Shell_NotifyIconW(NIM_ADD, &nid_)) return false;
    added_ = true;

    nid_.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &nid_);
    return true;
}

void TrayIcon::Destroy() {
    if (added_) {
        Shell_NotifyIconW(NIM_DELETE, &nid_);   // иначе в трее остаётся «призрак»
        added_ = false;
    }
    nid_ = NOTIFYICONDATAW{};
}

bool TrayIcon::Restore() {
    if (!nid_.hWnd) return false;
    added_ = Shell_NotifyIconW(NIM_ADD, &nid_) != FALSE;
    if (added_) {
        nid_.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid_);
    }
    return added_;
}

bool TrayIcon::Modify(DWORD flags) {
    if (!added_) return false;
    const UINT saved = nid_.uFlags;
    nid_.uFlags = flags;
    const BOOL ok = Shell_NotifyIconW(NIM_MODIFY, &nid_);
    nid_.uFlags = saved;
    return ok != FALSE;
}

void TrayIcon::SetIcon(HICON icon) {
    if (added_ && nid_.hIcon == icon) return;   // тот же значок
    nid_.hIcon = icon;
    Modify(NIF_ICON);
}

// ---------------------------------------------------------------------------
// Текст подсказки.
//
// Shell_NotifyIcon — МЕЖПРОЦЕССНЫЙ вызов: сообщение уходит в Explorer вместе
// с копированием всей структуры. Программа обновляет подсказку на каждом такте
// (раз в секунду), а меняется она редко: политика и число ожидающих запросов
// подолгу остаются теми же, а сама подсказка не видна, пока курсор не над значком.
//
// Поэтому сравниваем с текущим текстом: совпал — не тревожим Explorer вовсе.
// Строка уже хранится в nid_.szTip, отдельного поля не нужно.
// ---------------------------------------------------------------------------
void TrayIcon::SetTip(const std::wstring& tip) {
    wchar_t buf[ARRAYSIZE(nid_.szTip)]{};
    CopyTruncated(buf, ARRAYSIZE(buf), tip);

    if (added_ && wcscmp(buf, nid_.szTip) == 0) [[likely]] return;

    std::memcpy(nid_.szTip, buf, sizeof(buf));
    Modify(NIF_TIP | NIF_SHOWTIP);
}