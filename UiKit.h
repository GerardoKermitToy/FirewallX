#pragma once
#include "Common.h"
#include <commctrl.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace Ui {

// Вызывается в потоке интерфейса до создания любых окон.
// Системное масштабирование: 96 DPI и растяжение Windows, иначе PerMonitorV2.
// Уже созданные окна сохраняют свой контекст; изменение требует перезапуска.
bool InitializeDpiAwareness();

// Зеркальная разметка включается для арабского и персидского интерфейсов.
// Направление окна задаётся отдельно от направления технических полей.
bool  IsRightToLeft();
DWORD LayoutStyle();
// После смены направления вызывающий повторяет обычную раскладку контролов
// в координатах родителя (как App::Layout), не в экранных координатах.
void  ApplyLayout(HWND window);
void  KeepLeftToRight(HWND window);
UINT  PopupFlags(UINT flags);
// При успехе подменю принадлежит menu; при ошибке освобождаем его вместе с bitmap'ами.
bool  AppendSubMenu(HMENU menu, HMENU submenu, const wchar_t* caption);
// DestroyMenu не освобождает bitmap'ы пунктов: очищаем их до уничтожения меню.
void  CleanupMenuBitmaps(HMENU menu);
UINT  MessageBoxFlags(UINT flags);
int WINAPI ShowMessage(HWND owner, LPCWSTR text, LPCWSTR title, UINT flags);
// Настройка проверяется перед каждым сигналом и действует без перезапуска.
void PlayMessageBeep(UINT type, decltype(&::MessageBeep) play = ::MessageBeep);
// Только для отображения: управляющие символы не должны попадать в модель
// данных, пути на диске, правила или буфер обмена.
std::wstring LtrText(const std::wstring& text);

// Метрики диалогов по рекомендациям Windows UX, масштабируются по DPI
struct Metrics {
    UINT dpi = 96;
    bool modern = false;
    int Sc(int px) const { return MulDiv(px, static_cast<int>(dpi), 96); }
    int margin() const     { return Sc(11); }
    int gap() const        { return Sc(7);  }
    int gapS() const       { return Sc(4);  }
    int section() const    { return Sc(14); }
    int labelH() const     { return Sc(16); }
    int editH() const      { return Sc(23); }
    int checkH() const     { return Sc(18); }
    int radioH() const     { return Sc(20); }
    int rowH() const       { return Sc(20); }
    int btnW() const       { return Sc(88); }
    int btnWNarrow() const { return Sc(75); }
    int btnH() const       { return Sc(26); }
};

// Общая палитра отдельных окон сохраняет системные цвета в высокой контрастности.
struct DialogColors {
    COLORREF page, surface, text, secondary, border, accent, alternate;
    COLORREF allow, block;
    bool highContrast = false;
};

DialogColors DialogPalette(bool modern = true);
// Собственный шрифт окна: вызывающий освобождает его через DeleteObject.
HFONT CreateDialogFont(UINT dpi, int pt = 9, int weight = FW_NORMAL);
LRESULT DrawDialogList(NMLVCUSTOMDRAW& draw, const DialogColors& colors);
LRESULT DrawPrimaryButton(NMCUSTOMDRAW& draw, const DialogColors& colors,
                          HFONT font, UINT dpi);

// Кэш шрифтов для окон, живущих всё время работы программы (не для Modal:
// модальные окна владеют своими шрифтами сами — см. комментарий в Modal).
HFONT MessageFont(UINT dpi);
HFONT SemiBoldFont(UINT dpi);
HFONT MonoFont(UINT dpi);

// ---------------------------------------------------------------------------
// Шрифт по умолчанию для списка в КЛАССИЧЕСКОМ оформлении (ListSkin::Classic).
//
// Отдельный от MessageFont намеренно: классическая таблица должна быть
// плотной, и её кегль не должен зависеть от метрик оболочки, где он выбран
// для диалогов. Здесь задан кегль по умолчанию (kListFontPt); пользовательский
// шрифт строк TreeList выбирается отдельно через ListFontSetting.
//
// Гарнитура берётся системная. Чтобы получить вид классических таблиц
// целиком, достаточно указать здесь L"Tahoma".
// ---------------------------------------------------------------------------
inline constexpr int            kListFontPt   = 8;
inline constexpr const wchar_t* kListFontFace = nullptr;   // nullptr = шрифт системы

HFONT ListFont(UINT dpi);

void  ReleaseFonts();

// ---------------------------------------------------------------------------
// Сколько модальных окон программы открыто сейчас.
//
// Нужно тем частям интерфейса, которые показываются САМИ, без участия
// пользователя, — по таймеру или по событию из рабочего потока. Пока модальное
// окно создаётся или работает, автоматический запрос не должен открываться:
// его владелец может быть отключён, а закрытие такого запроса увело бы
// активность из программы целиком (см. Modal::Dismiss).
// ---------------------------------------------------------------------------
int  ModalDepth();
inline bool ModalActive() { return ModalDepth() > 0; }
// Возвращает доступное модальное окно, включая вложенный MessageBox.
HWND ModalWindow(HWND owner = nullptr);
// Возвращает скрытое или ушедшее за экран окно без перехвата переднего плана.
bool RestorePopup(HWND window);

class IconCache {
public:
    ~IconCache() { Destroy(); }
    bool Create(UINT dpi);
    void Destroy();
    HIMAGELIST handle() const { return il_; }
    int Get(const std::wstring& path);

private:
    HIMAGELIST il_ = nullptr;
    int        size_ = 16;
    std::unordered_map<std::wstring, int> map_;
};

// Базовый модальный диалог: единый шрифт, метрики, заголовочная плашка,
// корректные цвета контролов, стандартный ряд кнопок, Enter/Esc, табуляция.
//
// Шрифты — собственные, создаются перед CreateWindow и удаляются в WM_NCDESTROY.
class Modal {
public:
    virtual ~Modal() = default;
    // cw/ch — размеры клиентской области в пикселях при 96 DPI
    bool Run(HWND owner, HINSTANCE inst, const std::wstring& title, int cw, int ch);

protected:
    virtual bool ModernStyle() const { return false; }
    // Режим задаётся при создании HWND, до вызова OnInit.
    virtual bool Topmost() const { return false; }
    // Акцентная нижняя панель включается отдельно от оформления контролов.
    virtual bool StyledFooter() const { return false; }
    virtual int InitialFocusId() const { return 0; }
    virtual void OnInit() {}
    virtual bool OnCommand(int id, int notify) { (void)id; (void)notify; return false; }
    // ВАЖНО: сюда попадают только уведомления от контролов, созданных самим
    // диалогом (см. NotifyFromChild).
    virtual bool OnNotify(LPNMHDR hdr, LRESULT& res) { (void)hdr; (void)res; return false; }
    virtual bool OnOk() { return true; }
    virtual void OnCancel() {}

    void SetHeader(const std::wstring& title, const std::wstring& desc);

    // -----------------------------------------------------------------------
    // Плашка со значком ПРИЛОЖЕНИЯ слева от названия.
    //
    // Значок берётся по пути из EXE либо соответствующего пакета, поэтому
    // в редакторе правил видно ровно ту программу, чьи правила правятся, —
    // одного имени файла для этого мало: одноимённые файлы в разных каталогах
    // не различить.
    //
    // Пустой путь означает область «все процессы» (глобальные правила): тогда
    // показывается обобщённый значок приложения — он и передаёт смысл «любая
    // программа».
    //
    // Значок рисуется вместе с фоном плашки, отдельного контрола не создаёт:
    // статик со значком перехватывал бы мышь и мигал при перерисовке.
    // -----------------------------------------------------------------------
    void SetHeaderApp(const std::wstring& appPath, const std::wstring& title,
                      const std::wstring& desc);

    // Подписи, не переданные явно, берутся из ресурсов
    // (IDS_BTN_OK / IDS_BTN_CANCEL)
    void OkCancel();
    void OkCancel(const wchar_t* okText);          // «Отмена» — из ресурсов
    void OkCancel(const wchar_t* okText, const wchar_t* cancelText);
    void OkCancel(const std::wstring& okText) { OkCancel(okText.c_str()); }
    void OkCancel(const std::wstring& okText, const std::wstring& cancelText) {
        OkCancel(okText.c_str(), cancelText.c_str());
    }

    HWND hwnd() const { return hwnd_; }
    HWND owner() const { return owner_; }
    HWND Item(int id) const { return GetDlgItem(hwnd_, id); }
    HINSTANCE inst() const { return inst_; }
    const Metrics& M() const { return m_; }
    HFONT font() const { return font_; }
    HFONT semibold() const { return semibold_; }
    int clientW() const { return cw_; }
    int clientH() const { return ch_; }
    int headerH() const { return hdrH_; }
    int footerTop() const { return ch_ - m_.margin() - m_.btnH() - m_.gapS(); }
    void FitFooter(int y);
    void Footer();
    const DialogColors& colors() const { return colors_; }
    int TextHeight(const std::wstring& text, int width) const {
        return MeasureBlock(font_, text, width, true);
    }
    // Флажки стоят рядом, если перевод помещается; иначе — друг под другом.
    int CheckPair(const std::wstring& first, const std::wstring& second,
                  int x, int y, int w, int firstId, int secondId);

    // Завершение диалога. Окно здесь НЕ разрушается: разрушение выполняется
    // после выхода из цикла сообщений, в правильном порядке относительно
    // включения владельца (см. Dismiss).
    void EndOk();
    void EndCancel();

    HWND Add(const wchar_t* cls, const wchar_t* text, DWORD style, DWORD exStyle,
             int x, int y, int w, int h, int id, HFONT f = nullptr);
    void StyleField(HWND control);
    HWND Label(const wchar_t* text, int x, int y, int w, int h, int id = -1, DWORD extra = 0);
    // «Вторичная» подпись: тот же шрифт, приглушённый цвет
    HWND Note(const wchar_t* text, int x, int y, int w, int h, int id = -1, DWORD extra = 0);
    HWND Group(const wchar_t* text, int x, int y, int w, int h, int id = -1);

    // Перегрузки под строки из ресурсов: LoadStringRes возвращает временный
    // объект, и вызывать у него .c_str() на каждой строчке разметки шумно.
    // Текст всё равно копируется внутрь окна, так что время жизни временного
    // объекта до конца выражения достаточно.
    HWND Label(const std::wstring& text, int x, int y, int w, int h,
               int id = -1, DWORD extra = 0) {
        return Label(text.c_str(), x, y, w, h, id, extra);
    }
    HWND Note(const std::wstring& text, int x, int y, int w, int h,
              int id = -1, DWORD extra = 0) {
        return Note(text.c_str(), x, y, w, h, id, extra);
    }
    HWND Group(const std::wstring& text, int x, int y, int w, int h, int id = -1) {
        return Group(text.c_str(), x, y, w, h, id);
    }

    // Заголовок раздела: полужирная подпись и тонкая линия до правого края.
    int  SectionHeader(const wchar_t* text, int x, int y, int w);
    int  SectionHeader(const std::wstring& text, int x, int y, int w) {
        return SectionHeader(text.c_str(), x, y, w);
    }
    // Тонкая горизонтальная линия. Рисуется вместе с фоном окна.
    void Hairline(int x, int y, int w);

    HWND Edit(const wchar_t* text, int x, int y, int w, int h, int id, DWORD extra = 0);
    HWND LtrEdit(const wchar_t* text, int x, int y, int w, int h, int id);
    HWND ReadOnly(const wchar_t* text, int x, int y, int w, int h, int id);
    HWND Button(const wchar_t* text, int x, int y, int w, int h, int id, bool def = false);
    HWND Check(const wchar_t* text, int x, int y, int w, int h, int id);
    HWND Radio(const wchar_t* text, int x, int y, int w, int h, int id, bool first = false);

    HWND Edit(const std::wstring& text, int x, int y, int w, int h,
              int id, DWORD extra = 0) {
        return Edit(text.c_str(), x, y, w, h, id, extra);
    }
    HWND ReadOnly(const std::wstring& text, int x, int y, int w, int h, int id) {
        return ReadOnly(text.c_str(), x, y, w, h, id);
    }
    HWND Button(const std::wstring& text, int x, int y, int w, int h,
                int id, bool def = false) {
        return Button(text.c_str(), x, y, w, h, id, def);
    }
    HWND Check(const std::wstring& text, int x, int y, int w, int h, int id) {
        return Check(text.c_str(), x, y, w, h, id);
    }
    HWND Radio(const std::wstring& text, int x, int y, int w, int h,
               int id, bool first = false) {
        return Radio(text.c_str(), x, y, w, h, id, first);
    }
    HWND Link(int x, int y, int w, int h, int id);
    HWND ListView(int x, int y, int w, int h, int id, DWORD lvStyle);
    HWND ListBox(int x, int y, int w, int h, int id, DWORD extra = 0);
    HWND Combo(int x, int y, int w, int h, int id);
    HWND IpEdit(int x, int y, int w, int h, int id);
    HWND Hint(int x, int y, int w, int h, int id);

    std::wstring Text(int id) const;
    void SetText(int id, const std::wstring& s);
    // Подложка подписей и флажков на странице вкладки.
    void SetControlBackground(int id, HWND background);
    // Обновление SysLink: перезадаёт шрифт и стирает фон.
    // fitContent расширяет блок и сдвигает нижние элементы, не меняя их порядок.
    void SetLinkText(int id, const std::wstring& markup, bool fitContent = false);
    void Enable(int id, bool on);
    bool Checked(int id) const;
    void SetChecked(int id, bool on);

private:
    static LRESULT CALLBACK Proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(HWND, UINT, WPARAM, LPARAM);
    void    EraseBackground(HDC dc);
    void    Surface(int x, int y, int w, int h);
    static LRESULT CALLBACK FieldProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
    LRESULT ColorControl(HDC dc, HWND ctl);
    void    FitLinkHeight(HWND control);
    void    FocusFirst();
    void    CreateOwnFonts();
    void    DestroyOwnFonts();
    int     MeasureCaption(const wchar_t* text) const;
    // Высота текста при заданной ширине. wrap = перенос по словам.
    int     MeasureBlock(HFONT f, const std::wstring& s, int w, bool wrap) const;

    // Общая сборка плашки: с значком и без. hdrTextX_ задаёт левый край текста.
    void BuildHeader(const std::wstring& title, const std::wstring& desc,
                     bool withIcon, const std::wstring& appPath);
    void LoadHeaderIcon(const std::wstring& appPath, int px);
    void ReleaseHeaderIcon();

    // Закрытие окна в правильном порядке: включить владельца -> скрыть окно ->
    // отдать владельцу активность -> разрушить окно.
    void    Dismiss();

    // Уведомление пришло от НЕПОСРЕДСТВЕННОГО дочернего окна диалога?
    bool NotifyFromChild(LPNMHDR hdr) const;

    HWND      hwnd_ = nullptr;
    HWND      owner_ = nullptr;
    bool      ownerEnabled_ = false;
    HINSTANCE inst_ = nullptr;
    HFONT     font_ = nullptr, semibold_ = nullptr, titleFont_ = nullptr;
    bool      ownFont_ = false, ownSemi_ = false, ownTitle_ = false;
    Metrics   m_;
    DialogColors colors_{};
    int       footerY_ = 0;
    int       cw_ = 0, ch_ = 0, hdrH_ = 0;
    bool      done_ = false, ok_ = false, initDone_ = false;
    HWND      hdrTitle_ = nullptr, hdrDesc_ = nullptr;

    // Значок плашки. hdrIconOwned_ = false для стоковых значков (LR_SHARED):
    // их удалять нельзя.
    HICON     hdrIcon_ = nullptr;
    bool      hdrIconOwned_ = false;
    int       hdrIconSize_ = 0;
    int       hdrTextX_ = 0;

    HBRUSH    faceBr_ = nullptr, winBr_ = nullptr, hintBr_ = nullptr, hairBr_ = nullptr;
    std::vector<HWND> hints_;
    std::vector<HWND> notes_;
    std::unordered_map<HWND, HWND> controlBackgrounds_;
    std::vector<RECT> hair_, surfaces_;
};

} // namespace Ui