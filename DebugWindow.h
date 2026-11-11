#pragma once
#include "Common.h"
#include "DebugCounters.h"
#include "UiKit.h"

#include <functional>
#include <string>

// Немодальное окно: таймер и сбор размеров существуют только пока оно открыто.
class DebugWindow {
public:
    ~DebugWindow() { Close(); }
    bool Show(HWND owner, HINSTANCE inst,
              std::function<void(DebugCounters::Snapshot&)> read);
    void Close();
    HWND hwnd() const { return hwnd_; }

private:
    static LRESULT CALLBACK Thunk(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(HWND, UINT, WPARAM, LPARAM);
    bool Build(HINSTANCE inst);
    void Layout();
    void Refresh();
    void UpdateFonts();
    void Paint(HDC dc);
    int Sc(int px) const { return MulDiv(px, static_cast<int>(dpi_), 96); }

    HWND hwnd_ = nullptr, list_ = nullptr, note_ = nullptr, close_ = nullptr;
    UINT dpi_ = 96;
    Ui::DialogColors colors_{};
    HFONT font_ = nullptr, semibold_ = nullptr;
    std::function<void(DebugCounters::Snapshot&)> read_;
    DebugCounters::Snapshot last_;
    std::wstring busy_;
};
