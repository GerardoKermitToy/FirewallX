#pragma once
#include "AskQueue.h"
#include "ProcessIcon.h"
#include "RulePresets.h"
#include "UiKit.h"
#include <commctrl.h>
#include <functional>

// Немодальное окно запроса решения по соединению без правила.
// Показывается по одному запросу; остальные ждут в AskQueue.
class AskWindow {
public:
    ~AskWindow() { Close(); }

    bool Show(HWND owner, HINSTANCE inst, ProcessIconRef icon,
              const AskRequest& req, size_t queued,
              const std::function<bool()>& canShow = {},
              const RuleStore* rules = nullptr);
    void Close();
    void Restore();
    // Наличие окна, в том числе временно скрытого Windows вместе с владельцем.
    bool visible() const { return hwnd_ && IsWindow(hwnd_); }
    HWND hwnd() const { return hwnd_; }
    AskRequestId requestId() const { return req_.id; }
    const AskRequest& request() const { return req_; }

    // Вызывается один раз; окно к этому моменту уже уничтожено
    std::function<void(const AskRequest&, const AskDecision&)> onDecision;

private:
    static LRESULT CALLBACK Thunk(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK BtnProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
    LRESULT Proc(HWND, UINT, WPARAM, LPARAM);

    void MakeFonts();
    void FreeResources();
    void Build();                       // контролы + расчёт высоты
    void PlaceCentered();               // центр главного окна / монитора
    void Paint(HDC dc);
    void DrawAction(const DRAWITEMSTRUCT& dis);
    void Decide(AskAction a);
    int  Sc(int px) const { return MulDiv(px, static_cast<int>(dpi_), 96); }
    int  MeasureWrapped(HFONT f, const std::wstring& s, int width) const;

    HWND       hwnd_ = nullptr;
    HWND       owner_ = nullptr;
    HINSTANCE  inst_ = nullptr;
    ProcessIconRef icon_;
    UINT       dpi_ = 96;
    DWORD      style_ = 0, exStyle_ = 0;   // нужны для AdjustWindowRectExForDpi

    AskRequest req_;
    const RuleStore* rules_ = nullptr;
    size_t     queued_ = 0;
    bool       decided_ = false;

    // Базовый шрифт из кэша UiKit: мы им НЕ владеем и удалять не должны.
    // Дескриптор запоминается при создании и НЕ запрашивается заново в
    // FreeResources: если кэш к тому моменту освобождён (Ui::ReleaseFonts),
    // повторный запрос СОЗДАЛ БЫ новый шрифт, сравнение перестало бы
    // совпадать, и наш производный шрифт был бы удалён второй раз.
    HFONT  baseFont_ = nullptr;
    HFONT  fBig_ = nullptr, fAct_ = nullptr, fBody_ = nullptr, fBold_ = nullptr;
    HICON  warn_ = nullptr, appIcon_ = nullptr;
    HBRUSH bandBr_ = nullptr, bodyBr_ = nullptr;
    Ui::DialogColors colors_{};

    int  cw_ = 0, ch_ = 0, bandH_ = 0, labelW_ = 0;
    int  infoY_ = 0, questionY_ = 0, queueY_ = 0, footerY_ = 0;
    HWND btn_[4]{};
    bool hot_[4]{};
    HWND presetsCombo_ = nullptr;
    HWND once_[2]{};
    std::vector<RulePresets::Choice> presets_;
};