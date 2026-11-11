#pragma once
#include "Common.h"
#include <shellapi.h>

// Значок в области уведомлений. Используется NOTIFYICON_VERSION_4:
// координаты щелчка приходят в wParam, событие — в LOWORD(lParam).
class TrayIcon {
public:
    ~TrayIcon() { Destroy(); }
    TrayIcon(const TrayIcon&) = delete;
    TrayIcon& operator=(const TrayIcon&) = delete;
    TrayIcon() = default;

    bool Create(HWND owner, UINT callbackMsg, UINT id, HICON icon,
                const std::wstring& tip);
    void Destroy();
    bool Restore();                       // после перезапуска Explorer
    void SetIcon(HICON icon);
    void SetTip(const std::wstring& tip);

    bool alive() const { return added_; }

private:
    bool Modify(DWORD flags);

    NOTIFYICONDATAW nid_{};
    bool            added_ = false;
};