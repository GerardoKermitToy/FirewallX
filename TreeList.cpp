#include "TreeList.h"
#include "Settings.h"
#include "StringRes.h"
#include "UiKit.h"
#include <windowsx.h>
#include <vssym32.h>
#include <dwrite.h>
#include <wrl/client.h>
#include <algorithm>
#include <cmath>
#include <cwchar>
#include <optional>
#include <utility>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wsign-compare"
#endif

namespace {

// Подпись колонки хранится идентификатором ресурса, а не указателем: строка
// из ресурсов запрашивается при создании и обновлении колонок.
struct ColDef { UINT titleId; int width; int minWidth; int fmt; };

// ---------------------------------------------------------------------------
// Подписи и пропорции колонок. Ширины задают лишь эталонные ВЕСА: итоговые
// значения считает FitColumns пропорционально ширине окна.
//
// Наборы различаются не только длиной подписей: у современного оформления
// шрифт оболочки, поэтому подписи короче («PID», «Прот.»), иначе заголовки
// съедают место под данные.
// ---------------------------------------------------------------------------
const ColDef kColsModern[ColumnCount] = {
    { IDS_COLM_PROCESS,   320, 175, LVCFMT_LEFT  },
    { IDS_COLM_REMOTE,    215, 132, LVCFMT_LEFT  },
    { IDS_COLM_REASON,    300, 130, LVCFMT_LEFT  },
    { IDS_COLM_SENT,      135, 112, LVCFMT_RIGHT },
    { IDS_COLM_RECEIVED,  135, 104, LVCFMT_RIGHT },
    { IDS_COLM_PID,        68,  52, LVCFMT_RIGHT },
    { IDS_COLM_SPEED,     108,  82, LVCFMT_RIGHT },
    { IDS_COLM_PROTOCOL,   62,  50, LVCFMT_LEFT  },
    { IDS_COLM_LOCAL,     200, 126, LVCFMT_LEFT  },
    { IDS_COLM_DIRECTION,  62,  50, LVCFMT_LEFT  },
};

const ColDef kColsClassic[ColumnCount] = {
    { IDS_COLC_PROCESS,   250, 150, LVCFMT_LEFT  },
    { IDS_COLC_REMOTE,    175, 118, LVCFMT_LEFT  },
    { IDS_COLC_REASON,    285, 130, LVCFMT_LEFT  },
    { IDS_COLC_SENT,      120,  96, LVCFMT_RIGHT },
    { IDS_COLC_RECEIVED,  120,  92, LVCFMT_RIGHT },
    { IDS_COLC_PID,        84,  66, LVCFMT_RIGHT },
    { IDS_COLC_SPEED,      92,  72, LVCFMT_RIGHT },
    { IDS_COLC_PROTOCOL,   78,  60, LVCFMT_LEFT  },
    { IDS_COLC_LOCAL,     170, 118, LVCFMT_LEFT  },
    { IDS_COLC_DIRECTION,  94,  74, LVCFMT_LEFT  },
};

// ---------------------------------------------------------------------------
// Полное описание одного оформления.
//
// Это ЕДИНСТВЕННОЕ место, где два вида различаются. Всё остальное — метрики,
// отрисовка, раскладка колонок — читает поля этой структуры и не знает, какое
// оформление выбрано. Иначе при первой же правке виды разъехались бы.
// ---------------------------------------------------------------------------
struct SkinStyle {
    UINT          nameId;   // название оформления в STRINGTABLE
    const ColDef* cols;

    // ---- шрифты и метрики ----
    bool listFont;        // true  — компактный Ui::ListFont фиксированного кегля
                          // false — шрифт оболочки Ui::MessageFont
    int  rowWeight;       // начертание строк данных
    int  groupWeight;     // начертание раскрытой группы
    int  rowPadPx;        // добавка к высоте строки поверх высоты текста
    int  minRowPx;        // нижняя граница высоты строки; 0 — нет
    int  hdrExtraPx;      // добавка к высоте заголовка; 0 — высоту не менять

    // ---- геометрия колонки «Процесс» ----
    int  glyphMinPx;      // минимальная ширина клетки раскрывающего узла
    int  preIconPx;       // зазор «узел — значок»
    int  postIconPx;      // зазор «значок — текст»
    int  childIndentPx;   // доп. отступ текста вложенной строки; 0 — нет

    // ---- отрисовка ----
    bool explorerTheme;   // тема Explorer: бледное выделение, тонкая прокрутка
    bool guides;          // направляющие линии дерева у вложенных строк
    bool groupBand;       // подложка строки-процесса
    bool dimText;         // приглушённый текст: вложенные строки, PID, напр.
    bool accentSpeed;     // акцентный цвет ненулевой скорости
    bool actionColors;    // палитра allow/block/ask в колонке состояния
    bool blockRed;        // красное имя блокирующего правила (только «Причина»)
    bool headerRule;      // тонкая линия под строкой заголовка
    bool groupRule;       // тонкая линия перед строкой-процессом
    bool seamPatch;       // закрашивать швы полосы выделения (см. PaintSelectionSeams)
    bool zeroSpeed;       // «0 байт/с» вместо прочерка
};

const SkinStyle kSkins[2] = {
    // ---------------------------- ListSkin::Modern ----------------------------
    { IDS_SKIN_MODERN_NAME, kColsModern,
      /*listFont*/      false,
      /*rowWeight*/     TreeList::kRowFontWeight,
      /*groupWeight*/   TreeList::kGroupFontWeightModern,
      /*rowPadPx*/      7,
      /*minRowPx*/      18,
      /*hdrExtraPx*/    0,
      /*glyphMinPx*/    16,
      /*preIconPx*/     3,
      /*postIconPx*/    6,
      /*childIndentPx*/ 13,
      /*explorerTheme*/ true,
      /*guides*/        true,
      /*groupBand*/     true,
      /*dimText*/       false,
      /*accentSpeed*/   true,
      /*actionColors*/  true,
      /*blockRed*/      false,
      /*headerRule*/    false,
      /*groupRule*/     false,
      // Полосу выделения рисует тема Explorer — целиком, без швов.
      /*seamPatch*/     false,
      /*zeroSpeed*/     false },

    // ---------------------------- ListSkin::Classic ---------------------------
    { IDS_SKIN_CLASSIC_NAME, kColsClassic,
      /*listFont*/      true,
      /*rowWeight*/     TreeList::kRowFontWeight,
      /*groupWeight*/   TreeList::kGroupFontWeightClassic,
      /*rowPadPx*/      2,
      /*minRowPx*/      0,
      /*hdrExtraPx*/    11,
      /*glyphMinPx*/    13,
      /*preIconPx*/     2,
      /*postIconPx*/    4,
      /*childIndentPx*/ 0,
      /*explorerTheme*/ false,
      /*guides*/        false,
      /*groupBand*/     false,
      /*dimText*/       false,
      /*accentSpeed*/   false,
      /*actionColors*/  false,
      /*blockRed*/      true,
      /*headerRule*/    true,
      /*groupRule*/     true,
      /*seamPatch*/     true,
      /*zeroSpeed*/     true },
};

const SkinStyle& St(ListSkin s) {
    return kSkins[s == ListSkin::Classic ? 1 : 0];
}

LOGFONTW GroupFont(const LOGFONTW& base, int minimumWeight) {
    const auto heavierWeight = [minimumWeight](LONG weight) {
        return std::min<LONG>(FW_BLACK, std::max<LONG>(minimumWeight, weight + 100));
    };
    LOGFONTW result = base;
    result.lfWeight = heavierWeight(base.lfWeight);

    using Microsoft::WRL::ComPtr;
    static const auto factory = [] {
        ComPtr<IDWriteFactory> value;
        DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                            reinterpret_cast<IUnknown**>(value.GetAddressOf()));
        return value;
    }();
    if (!factory) return result;
    ComPtr<IDWriteGdiInterop> interop;
    ComPtr<IDWriteFont> font;
    ComPtr<IDWriteFontFamily> family;
    if (FAILED(factory->GetGdiInterop(&interop)) ||
        FAILED(interop->CreateFontFromLOGFONT(&base, &font)) ||
        FAILED(font->GetFontFamily(&family))) return result;

    // У именованного начертания вроде Display Semibold GDI игнорирует другой вес.
    // Выбираем реальное начертание того же семейства, не обрезая суффиксы имени.
    const LONG weight = heavierWeight(std::max(base.lfWeight, static_cast<LONG>(font->GetWeight())));
    ComPtr<IDWriteFont> group;
    if (FAILED(family->GetFirstMatchingFont(static_cast<DWRITE_FONT_WEIGHT>(weight),
            font->GetStretch(), font->GetStyle(), &group))) return result;
    LOGFONTW mapped{};
    BOOL systemFont = FALSE;
    if (SUCCEEDED(interop->ConvertFontToLOGFONT(group.Get(), &mapped, &systemFont))) {
        wcscpy_s(result.lfFaceName, mapped.lfFaceName);
        result.lfWeight = mapped.lfWeight;
    }
    return result;
}

// Порядок по умолчанию. Индексы subitem не меняются при перетаскивании.
// Настройка общая для обоих оформлений; «Процесс» всегда остаётся первым.
using ColumnOrder = std::array<int, ColumnCount>;
constexpr ColumnOrder kDefaultColumnOrder = {
    ColProcess, ColPid, ColProto, ColLocal, ColDir, ColRemote,
    ColReason, ColSent, ColRecv, ColSpeed
};

bool ValidColumnOrder(const ColumnOrder& order) {
    if (order.front() != ColProcess) return false;
    bool seen[ColumnCount]{};
    for (int col : order) {
        if (col < 0 || col >= ColumnCount || seen[col]) return false;
        seen[col] = true;
    }
    return true;
}

ColumnOrder LoadColumnOrder() {
    const std::wstring encoded = Settings::GetString(Settings::Key::kListColumnOrder);
    const wchar_t* next = encoded.c_str();
    ColumnOrder order{};
    for (int i = 0; i < ColumnCount; ++i) {
        wchar_t* end = nullptr;
        const long col = std::wcstol(next, &end, 10);
        if (end == next || col < 0 || col >= ColumnCount) return kDefaultColumnOrder;
        order[i] = static_cast<int>(col);
        if (i == ColumnCount - 1) {
            if (end != encoded.c_str() + encoded.size()) return kDefaultColumnOrder;
        } else {
            if (*end != L',') return kDefaultColumnOrder;
            next = end + 1;
        }
    }
    return ValidColumnOrder(order) ? order : kDefaultColumnOrder;
}

// порядок, в котором колонки принимают на себя остаток/нехватку пикселей
const int kStretch[ColumnCount] = {
    ColReason, ColProcess, ColRemote, ColLocal, ColSent,
    ColRecv, ColSpeed, ColDir, ColPid, ColProto
};

// Дополнительные 2 мм справа от заголовка и текста последней колонки, с учётом DPI.
int ColumnRightPadding(UINT dpi) {
    return MulDiv(20, static_cast<int>(dpi), 254);
}

// Прочерк, которым поставщик строк обозначает нулевую скорость.
const wchar_t* const kDash = L"\u2014";

// Значения Row::ruleAction (RuleAction из Rules.h). Сам заголовок правил
// списку не нужен, а зависимость от него ради трёх констант была бы лишней.
constexpr int kActionBlock = 1;
constexpr int kActionAsk   = 2;

// палитра действий современного оформления (Fluent, читаема на светлом фоне)
constexpr COLORREF kAllow = RGB(0x0F, 0x7B, 0x0F);
constexpr COLORREF kBlock = RGB(0xC4, 0x2B, 0x1C);
constexpr COLORREF kAsk   = RGB(0xA8, 0x62, 0x00);

// Особое оформление классического вида: имя блокирующего правила красное.
// Коричневая подпись домена общая для обоих видов и рисуется отдельно в первой
// колонке.
constexpr COLORREF kBlockText = RGB(0xCC, 0x00, 0x00);

// Оформление при первом запуске и при нечитаемой настройке.
constexpr ListSkin kDefaultSkin = ListSkin::Classic;

COLORREF Blend(COLORREF a, COLORREF b, int pctB) {
    const int p = std::clamp(pctB, 0, 100);
    const auto mix = [p](int x, int y) { return (x * (100 - p) + y * p) / 100; };
    return RGB(mix(GetRValue(a), GetRValue(b)),
               mix(GetGValue(a), GetGValue(b)),
               mix(GetBValue(a), GetBValue(b)));
}

// Заголовок присылает не только HDN_*, но и общие уведомления: NM_CUSTOMDRAW,
// NM_RELEASEDCAPTURE, NM_RCLICK и другие. У них СВОИ структуры, поэтому
// приводить их к NMHEADERW и читать pitem нельзя: поле попадёт на чужие байты.
// Коды HDN_* лежат в диапазоне HDN_LAST..HDN_FIRST.
bool IsHeaderItemCode(UINT code) {
    const int c = static_cast<int>(code);
    return c <= HDN_FIRST && c >= HDN_LAST;
}

} // namespace

// ------------------------------------------------------- запоминание выбора
//
// Хранилище — settings.db (Settings), а не реестр: настройка должна переезжать
// вместе с программой и её базой. При ошибке чтения выбирается оформление
// по умолчанию; ошибка записи не отменяет выбор текущего сеанса, но он
// не сохранится для следующего запуска. Отдельного сообщения здесь нет.

namespace ListSkinSetting {

ListSkin Load() {
    const int v = Settings::GetInt(Settings::Key::kListSkin,
                                   static_cast<int>(kDefaultSkin));
    return v == static_cast<int>(ListSkin::Modern) ? ListSkin::Modern
                                                   : ListSkin::Classic;
}

void Save(ListSkin s) {
    Settings::SetInt(Settings::Key::kListSkin, static_cast<int>(s));
}

std::wstring Name(ListSkin s) { return LoadStringRes(St(s).nameId); }

} // namespace ListSkinSetting

namespace ListFontSetting {
namespace {

const wchar_t* FontKey(ListSkin skin) {
    return skin == ListSkin::Modern ? Settings::Key::kListFontModern
                                    : Settings::Key::kListFontClassic;
}

bool Valid(const Value& value) {
    return !value.face.empty() && value.face.size() < LF_FACESIZE &&
           value.face.find_first_of(L"\r\n") == std::wstring::npos &&
           value.face.find(L'\0') == std::wstring::npos &&
           value.sizeTenths >= kMinPointSize * 10 &&
           value.sizeTenths <= kMaxPointSize * 10 &&
           value.weight >= FW_THIN && value.weight <= FW_BLACK;
}

LOGFONTW DefaultFont(ListSkin skin, UINT dpi) {
    HFONT font = St(skin).listFont ? Ui::ListFont(dpi) : Ui::MessageFont(dpi);
    LOGFONTW value{};
    GetObjectW(font, sizeof(value), &value);
    value.lfWeight = St(skin).rowWeight;
    return value;
}

std::optional<Value> Read(ListSkin skin) {
    const std::wstring encoded = Settings::GetString(FontKey(skin));
    const size_t first = encoded.find(L'\n');
    if (first == std::wstring::npos || first == 0) return std::nullopt;
    wchar_t* end = nullptr;
    const long size = std::wcstol(encoded.c_str(), &end, 10);
    if (end != encoded.c_str() + first || size < kMinPointSize * 10 ||
        size > kMaxPointSize * 10) return std::nullopt;

    // Старые записи содержат только размер и гарнитуру либо ещё и насыщенность.
    Value value{encoded.substr(first + 1), static_cast<int>(size), St(skin).rowWeight};
    const size_t second = encoded.find(L'\n', first + 1);
    if (second != std::wstring::npos) {
        const long weight = std::wcstol(encoded.c_str() + first + 1, &end, 10);
        if (end != encoded.c_str() + second || weight < FW_THIN || weight > FW_BLACK)
            return std::nullopt;
        value.weight = static_cast<int>(weight);
        size_t faceStart = second + 1;
        const size_t third = encoded.find(L'\n', faceStart);
        if (third != std::wstring::npos) {
            if (third != faceStart + 1 ||
                (encoded[faceStart] != L'0' && encoded[faceStart] != L'1'))
                return std::nullopt;
            value.italic = encoded[faceStart] == L'1';
            faceStart = third + 1;
        }
        value.face = encoded.substr(faceStart);
    }
    return Valid(value) ? std::optional<Value>(std::move(value)) : std::nullopt;
}

} // namespace

Value Load(ListSkin skin, UINT dpi) {
    if (const auto value = Read(skin)) return *value;
    if (!dpi) dpi = 96;
    const LOGFONTW font = DefaultFont(skin, dpi);
    const int points = St(skin).listFont ? Ui::kListFontPt
        : MulDiv(std::abs(font.lfHeight), 72, static_cast<int>(dpi));
    return {font.lfFaceName,
            std::clamp(points, kMinPointSize, kMaxPointSize) * 10,
            font.lfWeight, font.lfItalic != FALSE};
}

bool Save(ListSkin skin, const Value& value) {
    // Одна запись сохраняет гарнитуру, размер и начертание вместе: частичного выбора не бывает.
    return Valid(value) && Settings::SetString(FontKey(skin),
        std::to_wstring(value.sizeTenths) + L"\n" +
        std::to_wstring(value.weight) + L"\n" +
        (value.italic ? L"1\n" : L"0\n") + value.face);
}

bool Reset(ListSkin skin) {
    return Settings::Remove(FontKey(skin));
}

LOGFONTW Resolve(ListSkin skin, UINT dpi) {
    if (!dpi) dpi = 96;
    LOGFONTW font = DefaultFont(skin, dpi);
    if (const auto value = Read(skin)) {
        wcscpy_s(font.lfFaceName, value->face.c_str());
        font.lfHeight = -MulDiv(value->sizeTenths, static_cast<int>(dpi), 720);
        font.lfWeight = value->weight;
        font.lfItalic = value->italic;
        font.lfWidth = 0;
        font.lfCharSet = DEFAULT_CHARSET;
        font.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
    }
    return font;
}

} // namespace ListFontSetting

// ---------------------------------------------------------------- метрики

int TreeList::Scaled(int px) const {
    return MulDiv(px, static_cast<int>(dpi_), 96);
}

int TreeList::IconSize() const {
    return iconSize_ > 0 ? iconSize_ : Scaled(16);
}

int TreeList::BoxSize() const {
    int s = Scaled(9);
    if (s < 7) s = 7;
    if ((s % 2) == 0) ++s;      // нечётный размер: центр попадает точно в пиксель
    return s;
}

int TreeList::GlyphCell() const {
    return std::max(Scaled(St(skin_).glyphMinPx), BoxSize() + Scaled(4));
}

int TreeList::ContentLeft() const {
    const SkinStyle& s = St(skin_);
    return Scaled(2) + GlyphCell() + Scaled(s.preIconPx) +
           IconSize() + Scaled(s.postIconPx);
}

// Отступ текста. Вложенная строка сдвигается глубже только там, где есть
// направляющие линии: без них сдвиг лишь увеличивал бы разрыв в колонке.
int TreeList::TextLeft(bool group) const {
    const SkinStyle& s = St(skin_);
    return ContentLeft() +
           ((!group && s.childIndentPx) ? Scaled(s.childIndentPx) : 0);
}

int TreeList::GuideX() const {
    return Scaled(2) + GlyphCell() + Scaled(St(skin_).preIconPx) + IconSize() / 2;
}

int TreeList::TextHeight(HFONT font) const {
    if (!hwnd_) return Scaled(13);
    HDC dc = GetDC(hwnd_);
    if (!dc) return Scaled(13);
    if (!font) font = reinterpret_cast<HFONT>(SendMessageW(hwnd_, WM_GETFONT, 0, 0));
    HGDIOBJ old = font ? SelectObject(dc, font) : nullptr;
    TEXTMETRICW tm{};
    GetTextMetricsW(dc, &tm);
    if (old) SelectObject(dc, old);
    ReleaseDC(hwnd_, dc);
    return tm.tmHeight > 0 ? tm.tmHeight : Scaled(13);
}

// Высота строки заголовка. 0 означает «не переопределять»: современное
// оформление оставляет заголовок таким, каким его считает контрол.
int TreeList::HeaderWanted() const {
    const SkinStyle& s = St(skin_);
    if (!s.hdrExtraPx) return 0;
    HFONT font = header_
        ? reinterpret_cast<HFONT>(SendMessageW(header_, WM_GETFONT, 0, 0)) : nullptr;
    return std::max(TextHeight(font) + Scaled(s.hdrExtraPx), IconSize() + Scaled(6));
}

void TreeList::RefreshColors() {
    const COLORREF win = GetSysColor(COLOR_WINDOW);
    const COLORREF txt = GetSysColor(COLOR_WINDOWTEXT);

    // Цвета для обоих оформлений пересчитываются в ApplyStyle по текущей
    // системной палитре; при отрисовке строк используются готовые значения.
    groupBg_ = Blend(win, GetSysColor(COLOR_HOTLIGHT), 8);
    dimText_ = Blend(txt, win, 42);
    guide_   = Blend(win, txt, 30);
    accent_  = Blend(GetSysColor(COLOR_HOTLIGHT), txt, 15);
    //rule_    = Blend(win, txt, 16);
	rule_    = Blend(win, txt, 2);

    const int lum = (GetRValue(win) * 299 + GetGValue(win) * 587 +
                     GetBValue(win) * 114) / 1000;
    const bool dark = lum < 128;
    // Коричневый остаётся коричневым в обеих системных палитрах, но в тёмной
    // теме используется более светлый оттенок, чтобы домен читался на фоне окна.
    domainText_ = dark ? RGB(0xD2, 0x9A, 0x66) : RGB(0x8B, 0x45, 0x13);
    boxEdge_ = dark ? RGB(0x9A, 0x9A, 0x9A) : RGB(0x8A, 0x8A, 0x92);
    boxFill_ = dark ? RGB(0x2B, 0x2B, 0x2B) : RGB(0xFF, 0xFF, 0xFF);
    boxSign_ = dark ? RGB(0xE8, 0xE8, 0xE8) : RGB(0x1A, 0x1A, 0x1A);

    ReleaseBrushes();       // пересоздадутся при следующей перерисовке
}

COLORREF TreeList::ActionColor(int action) const {
    switch (action) {
        case kActionBlock: return kBlock;
        case kActionAsk:   return kAsk;
        default:           return kAllow;
    }
}

void TreeList::EnsureBrushes() {
    if (brushesValid_) [[likely]] return;
    ReleaseBrushes();
    brGuide_   = CreateSolidBrush(guide_);
    brRule_    = CreateSolidBrush(rule_);
    brBoxFill_ = CreateSolidBrush(boxFill_);
    brBoxEdge_ = CreateSolidBrush(boxEdge_);
    brBoxSign_ = CreateSolidBrush(boxSign_);
    brushesValid_ = brGuide_ && brRule_ && brBoxFill_ && brBoxEdge_ && brBoxSign_;
}

void TreeList::ReleaseBrushes() {
    for (HBRUSH* b : { &brGuide_, &brRule_, &brBoxFill_, &brBoxEdge_, &brBoxSign_ }) {
        if (*b) DeleteObject(*b);
        *b = nullptr;
    }
    brushesValid_ = false;
}

// Состояние выделения спрашиваем у контрола один раз на строку, а не по разу
// на каждую отрисовку её частей.
bool TreeList::RowSelected(int index) const {
    if (index == paintRow_) [[likely]] return paintSel_;
    paintRow_ = index;
    paintSel_ = hwnd_ && index >= 0 &&
                (ListView_GetItemState(hwnd_, index, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    return paintSel_;
}

// Базовый цвет текста строки — БЕЗ учёта колонки: цвета отдельных колонок
// (скорость, состояние) задаются на уровне подэлементов.
//
// Полоса выделения бывает двух видов, и от этого зависит цвет текста: тема
// Explorer заливает её светлым, поэтому текст остаётся тёмным; стандартная
// тема и классическая (тема отключена в системе) заливают её сплошным цветом,
// и текст обязан стать светлым.
COLORREF TreeList::RowTextColor(const Row& r, bool selected) const {
    const SkinStyle& s = St(skin_);
    if (selected) {
        const bool solidBand = !s.explorerTheme || !paintThemed_;
        if (!solidBand) return GetSysColor(COLOR_WINDOWTEXT);
        return GetSysColor(GetFocus() == hwnd_ ? COLOR_HIGHLIGHTTEXT
                                              : COLOR_BTNTEXT);
    }
    // Завершённое соединение приглушается в ЛЮБОМ оформлении: это не
    // украшение, а признак «строки скоро не будет». Поэтому приглушение НЕ
    // вынесено в SkinStyle — оформление не вправе его отменить.
    if (r.finished) return dimText_;
    (void)s;
    return GetSysColor(COLOR_WINDOWTEXT);
}

// ---------------------------------------------------------------------------
// Фон строки.
//
// В OnNotify явно задаётся каждому невыделенному подэлементу: структура
// NMLVCUSTOMDRAW между уведомлениями не переинициализируется, и оставленный
// цвет мог бы перейти от предыдущей строки. Для выделения OnNotify не меняет
// clrTextBk: полосу рисует сам контрол. Ветка selected ниже возвращает
// системный цвет выделения, если он потребуется вызывающему коду.
// ---------------------------------------------------------------------------
COLORREF TreeList::RowBackColor(const Row& r, bool selected) const {
    if (selected) {
        // Потерявшее фокус выделение система рисует приглушённым: тем же
        // цветом, что подложку окна.
        return GetSysColor(GetFocus() == hwnd_ ? COLOR_HIGHLIGHT : COLOR_BTNFACE);
    }
    const SkinStyle& s = St(skin_);
    if (s.groupBand && r.isGroup) return groupBg_;
    return GetSysColor(COLOR_WINDOW);
}

// Высота строки в report-режиме задаётся высотой привязанного imagelist.
// Ставим полоску шириной 1 px: горизонтально ничего не занимает, а строки
// получают ровно тот отступ, который нужен оформлению.
void TreeList::EnsureRowHeight() {
    if (!hwnd_) return;
    const SkinStyle& s = St(skin_);
    const int textH = std::max(TextHeight(), TextHeight(bold_));
    int h = std::max(IconSize() + Scaled(2), textH + Scaled(s.rowPadPx));
    if (s.minRowPx) h = std::max(h, Scaled(s.minRowPx));

    HIMAGELIST fresh = ImageList_Create(1, h, ILC_COLOR32 | ILC_MASK, 1, 1);
    if (!fresh) return;
    // сначала назначаем новый, только потом уничтожаем прежний: иначе
    // у контрола на короткое время остаётся мёртвый хэндл
    ListView_SetImageList(hwnd_, fresh, LVSIL_SMALL);   // LVS_SHAREIMAGELISTS
    if (spacer_) ImageList_Destroy(spacer_);
    spacer_ = fresh;
}

// ----------------------------------------------------- применение оформления

void TreeList::ApplyStyle() {
    if (!hwnd_) return;
    const SkinStyle& s = St(skin_);

    // Тема Explorer даёт бледное выделение и убирает разделители подписей
    // колонок; nullptr возвращает контрол к теме класса по умолчанию.
    //
    // WM_THEMECHANGED здесь НЕ отправляется намеренно. Состояние темы после
    // переключения всё равно остаётся не таким, как у свежесозданного
    // контрола, и полагаться на него нельзя; а заголовку это сообщение
    // сбрасывает шрифт и высоту, которые мы задаём строкой ниже и в
    // HdrProc. Разрывы полосы выделения, которые из этого следуют, закрывает
    // сам оформитель — PaintSelectionSeams, — и только в том оформлении,
    // которое их получает.
    SetWindowTheme(hwnd_, s.explorerTheme ? L"Explorer" : nullptr, nullptr);

    // Заголовок сохраняет шрифт оформления; пользовательский выбор меняет строки.
    HFONT headerFont = s.listFont ? Ui::ListFont(dpi_) : Ui::MessageFont(dpi_);
    const LOGFONTW chosen = ListFontSetting::Resolve(skin_, dpi_);
    HFONT previous = ownedFont_;
    ownedFont_ = CreateFontIndirectW(&chosen);
    font_ = ownedFont_ ? ownedFont_ : headerFont;
    if (font_)
        SendMessageW(hwnd_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    if (header_)
        SendMessageW(header_, WM_SETFONT, reinterpret_cast<WPARAM>(headerFont), TRUE);

    RefreshColors();
    RecreateFonts();
    EnsureRowHeight();
    // Старый шрифт удаляем только после того, как контрол получил новый.
    if (previous) DeleteObject(previous);
    styled_ = true;
}

// Подписи и выравнивание переписываются на месте, ширины не трогаем: их
// сразу после этого назначит FitColumns по новым эталонным весам.
void TreeList::ApplyColumns() {
    if (!hwnd_) return;
    HideTip();
    Ui::ApplyLayout(hwnd_);
    if (tip_) Ui::ApplyLayout(tip_);
    const ColDef* cols = St(skin_).cols;
    for (int i = 0; i < ColumnCount; ++i) {
        // Подпись живёт до конца итерации: ListView копирует текст себе
        std::wstring title = LoadStringRes(cols[i].titleId);
        LVCOLUMNW c{};
        c.mask    = LVCF_TEXT | LVCF_FMT;
        c.fmt     = cols[i].fmt;
        c.pszText = title.data();
        ListView_SetColumn(hwnd_, i, &c);
        weight_[i] = static_cast<double>(cols[i].width);
    }
    ApplyColumnPadding();
    // Направление текста и выравнивание могли измениться без замены строк.
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void TreeList::ApplyColumnPadding() {
    if (!header_) return;
    const int previous = paddedCol_;
    paddedCol_ = -1;
    const int last = Header_OrderToIndex(header_, ColumnCount - 1);
    LVCOLUMNW column{};
    column.mask = LVCF_FMT;
    if (last >= 0 && ListView_GetColumn(hwnd_, last, &column) &&
        (column.fmt & LVCFMT_JUSTIFYMASK) == LVCFMT_RIGHT)
        paddedCol_ = last;

    // При перестановке возвращаем прежнему заголовку штатную отрисовку.
    for (int col = 0; col < ColumnCount; ++col) {
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        if (!Header_GetItem(header_, col, &item)) continue;
        const int fmt = (item.fmt & ~HDF_OWNERDRAW) |
                        (col == paddedCol_ ? HDF_OWNERDRAW : 0);
        if (fmt != item.fmt) {
            item.fmt = fmt;
            Header_SetItem(header_, col, &item);
        }
    }
    if (previous != paddedCol_) InvalidateMetrics();
}

// Заставить контрол перезапросить высоту заголовка.
//
// Высота задаётся только ответом на HDM_LAYOUT, а спрашивает список её сам —
// при изменении своего размера. Пока размер не менялся, новая высота не
// применится, поэтому отправляем WM_SIZE с ТЕКУЩИМИ размерами: для контрола
// это обычная перераскладка, а нам она обходится в одну перерисовку.
void TreeList::ReLayout() {
    if (!hwnd_) return;
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    if (rc.right <= rc.left) return;
    SendMessageW(hwnd_, WM_SIZE, SIZE_RESTORED,
                 static_cast<LPARAM>(MAKELPARAM(rc.right - rc.left,
                                                rc.bottom - rc.top)));
}

void TreeList::SetSkin(ListSkin s) {
    if (skin_ == s && styled_) return;
    skin_ = s;
    if (!hwnd_) return;                 // применится при Create

    HideTip();
    ApplyStyle();
    ApplyColumns();
    InvalidateMetrics();                // подписи заголовков изменились
    RecomputeFirstColumnIdeal();
    ReLayout();                         // высота строки заголовка
    FitColumns();
    InvalidateRect(hwnd_, nullptr, TRUE);
    if (header_) InvalidateRect(header_, nullptr, TRUE);
}

void TreeList::ReloadFont() {
    if (!hwnd_) return;
    HideTip();
    ApplyStyle();
    InvalidateMetrics();
    RecomputeFirstColumnIdeal();
    ReLayout();
    FitColumns();
    InvalidateRect(hwnd_, nullptr, TRUE);
    if (header_) InvalidateRect(header_, nullptr, TRUE);
}

// --------------------------------------------------------------- создание

bool TreeList::Create(HWND parent, HINSTANCE inst, UINT ctrlId) {
    inst_ = inst;
    hwnd_ = CreateWindowExW(Ui::LayoutStyle(), WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA |
        LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS,
        0, 0, 100, 100, parent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ctrlId)),
        inst, nullptr);
    if (!hwnd_) return false;

    // LVS_EX_INFOTIP намеренно не включён: подсказку ведём сами (см. CreateTip)
    ListView_SetExtendedListViewStyle(hwnd_,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP);

    dpi_ = GetDpiForWindow(hwnd_);
    if (!dpi_) dpi_ = 96;

    // Колонки вставляются с эталонными ширинами выбранного оформления —
    // дальше их пересчитает FitColumns.
    const ColDef* cols = St(skin_).cols;
    LVCOLUMNW c{};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM;
    for (int i = 0; i < ColumnCount; ++i) {
        std::wstring title = LoadStringRes(cols[i].titleId);
        c.iSubItem = i;
        c.pszText  = title.data();
        c.cx       = Scaled(cols[i].width);
        c.fmt      = cols[i].fmt;
        ListView_InsertColumn(hwnd_, i, &c);
        weight_[i] = static_cast<double>(cols[i].width);   // веса относительные
    }
    ColumnOrder order = LoadColumnOrder();
    ListView_SetColumnOrderArray(hwnd_, ColumnCount, order.data());

    header_ = ListView_GetHeader(hwnd_);
    ApplyColumnPadding();
    // Подписка на заголовок нужна независимо от оформления: в современном
    // обработчик ничего не меняет, в классическом задаёт высоту строки
    // заголовка и рисует линию под ней.
    if (header_)
        SetWindowSubclass(header_, &TreeList::HdrProc, kHdrSubclassId,
                          reinterpret_cast<DWORD_PTR>(this));

    ApplyStyle();                       // тема, шрифты, цвета, высота строки
    InvalidateMetrics();
    RecomputeFirstColumnIdeal();

    // подписка на сообщения мыши: WM_NOTIFY от родителя их не содержит
    SetWindowSubclass(hwnd_, &TreeList::SubProc, kSubclassId,
                      reinterpret_cast<DWORD_PTR>(this));
    CreateTip();
    return true;
}

void TreeList::Destroy() {
    DestroyTip();
    if (header_ && IsWindow(header_))
        RemoveWindowSubclass(header_, &TreeList::HdrProc, kHdrSubclassId);
    if (hwnd_ && IsWindow(hwnd_)) {
        KillTimer(hwnd_, kTipTimer);
        RemoveWindowSubclass(hwnd_, &TreeList::SubProc, kSubclassId);
        SendMessageW(hwnd_, WM_SETFONT,
                     reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), FALSE);
    }
    ReleaseBrushes();
    for (HFONT* f : { &bold_, &ownedFont_ }) {
        if (*f) DeleteObject(*f);
        *f = nullptr;
    }
    if (spacer_) { ImageList_Destroy(spacer_); spacer_ = nullptr; }
    font_ = nullptr;
    hwnd_ = header_ = nullptr;
    std::vector<Row>().swap(rows_);
    textWidths_.clear();
}

// Соединения используют выбранное начертание без подмены насыщенности.
// Раскрытая группа наследует кегль и курсив; более насыщенное начертание ищем в том же семействе.
void TreeList::RecreateFonts() {
    if (bold_) DeleteObject(bold_);
    bold_ = nullptr;
    const SkinStyle& s = St(skin_);
    LOGFONTW lf{};
    HFONT base = reinterpret_cast<HFONT>(SendMessageW(hwnd_, WM_GETFONT, 0, 0));
    if (base && GetObjectW(base, sizeof(lf), &lf)) {
        lf = GroupFont(lf, s.groupWeight);
        bold_ = CreateFontIndirectW(&lf);
    }
    textWidths_.clear();      // кэш ширин зависит от шрифта
}

// Роль строки видна по начертанию, поэтому выбор собран в одном месте: им
// пользуются и штатная отрисовка подэлементов, и наша отрисовка колонки
// «Процесс». Разойдись они — в одной строке оказались бы два начертания.
HFONT TreeList::RowFont(const Row& r) const {
    return r.bold && bold_ ? bold_ : font_;
}

void TreeList::SetIconSize(int iconSize) {
    iconSize_ = iconSize > 0 ? iconSize : Scaled(16);
    // Размер значка входит и в высоту строки, и в отступ текста колонки 0,
    // поэтому обе величины пересчитываются здесь, а не только при смене DPI.
    EnsureRowHeight();
    fitDirty_ = true;
    RecomputeFirstColumnIdeal();
    if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
}

// ------------------------------------------------------ всплывающая подсказка

bool TreeList::CreateTip() {
    if (!hwnd_) return false;
    tip_ = CreateWindowExW(WS_EX_TOPMOST | Ui::LayoutStyle(), TOOLTIPS_CLASSW, nullptr,
                           WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                           CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                           hwnd_, nullptr, inst_, nullptr);
    if (!tip_) return false;

    TTTOOLINFOW ti = TipInfo();
    ti.lpszText = const_cast<LPWSTR>(L"");
    SendMessageW(tip_, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&ti));
    // без ограничения ширины tooltip игнорирует \n и остаётся однострочным
    SendMessageW(tip_, TTM_SETMAXTIPWIDTH, 0, Scaled(560));
    return true;
}

void TreeList::DestroyTip() {
    HideTip();
    if (tip_) { DestroyWindow(tip_); tip_ = nullptr; }
    tipText_.clear();
    tipRow_ = pendRow_ = -1;
}

TTTOOLINFOW TreeList::TipInfo() const {
    TTTOOLINFOW ti{};
    ti.cbSize = sizeof(ti);
    // TTF_TRACK: показом управляем только мы, автоматика контрола не участвует
    ti.uFlags = TTF_IDISHWND | TTF_TRACK | TTF_ABSOLUTE;
    ti.hwnd   = hwnd_;
    ti.uId    = reinterpret_cast<UINT_PTR>(hwnd_);
    return ti;
}

void TreeList::SetTipText(const std::wstring& text) {
    if (!tip_) return;
    tipText_ = text;
    TTTOOLINFOW ti = TipInfo();
    ti.lpszText = const_cast<LPWSTR>(tipText_.c_str());
    // текст меняется на месте: скрытия и повторного показа нет, значит
    // при переходе между строками подсказка не мигает
    SendMessageW(tip_, TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&ti));
}

void TreeList::PositionTip(POINT client) {
    if (!tip_) return;
    POINT pt = client;
    MapWindowPoints(hwnd_, nullptr, &pt, 1);
    const int offset = Ui::IsRightToLeft() ? -Scaled(16) : Scaled(16);
    SendMessageW(tip_, TTM_TRACKPOSITION, 0,
                 static_cast<LPARAM>(MAKELONG(pt.x + offset, pt.y + Scaled(20))));
}

int TreeList::HitRowForTip(POINT client, int& subItem) const {
    subItem = -1;
    if (!hwnd_) return -1;
    LVHITTESTINFO hti{};
    hti.pt = client;
    ListView_SubItemHitTest(hwnd_, &hti);
    if (hti.iItem < 0 || hti.iItem >= static_cast<int>(rows_.size())) return -1;
    subItem = hti.iSubItem;
    return hti.iItem;
}

void TreeList::ActivateTip() {
    if (!tip_ || pendRow_ < 0 || pendRow_ >= static_cast<int>(rows_.size())) return;

    // курсор мог уйти за время задержки
    POINT cur{};
    GetCursorPos(&cur);
    POINT cl = cur;
    MapWindowPoints(nullptr, hwnd_, &cl, 1);
    int sub = -1;
    if (HitRowForTip(cl, sub) != pendRow_ || sub != 0) { pendRow_ = -1; return; }

    const std::wstring text = BuildTip(pendRow_);
    if (text.empty()) { pendRow_ = -1; return; }

    SetTipText(text);
    tipRow_ = pendRow_;
    pendRow_ = -1;
    PositionTip(cl);

    TTTOOLINFOW ti = TipInfo();
    SendMessageW(tip_, TTM_TRACKACTIVATE, TRUE, reinterpret_cast<LPARAM>(&ti));
    tipVisible_ = true;
}

void TreeList::HideTip() {
    if (hwnd_ && IsWindow(hwnd_)) KillTimer(hwnd_, kTipTimer);
    pendRow_ = -1;
    if (!tip_ || !tipVisible_) return;
    TTTOOLINFOW ti = TipInfo();
    SendMessageW(tip_, TTM_TRACKACTIVATE, FALSE, reinterpret_cast<LPARAM>(&ti));
    tipVisible_ = false;
    tipRow_ = -1;
}

void TreeList::OnMouseMove(POINT client) {
    if (!tracking_) {
        TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, hwnd_, 0 };
        TrackMouseEvent(&tme);
        tracking_ = true;
    }

    int sub = -1;
    const int row = HitRowForTip(client, sub);
    if (row < 0 || sub != 0) { HideTip(); return; }

    // Тот же элемент: ничего не делаем. Текст сознательно не обновляем —
    // иначе счётчики, меняющиеся каждую секунду, дёргали бы подсказку.
    if (tipVisible_ && row == tipRow_) return;

    if (tipVisible_) {
        const std::wstring text = BuildTip(row);
        if (text.empty()) { HideTip(); return; }
        tipRow_ = row;
        SetTipText(text);
        PositionTip(client);
        return;
    }

    if (row == pendRow_) return;            // задержка уже отсчитывается
    pendRow_ = row;
    pendPt_  = client;
    KillTimer(hwnd_, kTipTimer);
    SetTimer(hwnd_, kTipTimer, kTipDelayMs, nullptr);
}

LRESULT CALLBACK TreeList::SubProc(HWND h, UINT m, WPARAM wp, LPARAM lp,
                                   UINT_PTR id, DWORD_PTR ref) {
    auto* self = reinterpret_cast<TreeList*>(ref);
    if (!self) return DefSubclassProc(h, m, wp, lp);

    switch (m) {
    case kSaveColumnOrderMsg:
        self->ApplyColumnPadding();
        self->FitColumns();
        self->SaveColumnOrder();
        InvalidateRect(h, nullptr, FALSE);
        if (self->header_) InvalidateRect(self->header_, nullptr, FALSE);
        return 0;

    case WM_DRAWITEM: {
        const auto* draw = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
        if (draw && draw->hwndItem == self->header_ &&
            static_cast<int>(draw->itemID) == self->paddedCol_) {
            self->PaintPaddedHeader(*draw);
            return TRUE;
        }
        break;
    }
    case WM_MOUSEMOVE: {
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        self->OnMouseMove(pt);
        break;
    }
    case WM_MOUSELEAVE:
        self->tracking_ = false;
        self->HideTip();
        break;

    case WM_TIMER:
        if (wp == kTipTimer) {
            KillTimer(h, kTipTimer);
            self->ActivateTip();
            return 0;
        }
        break;

    // прокрутка и ввод меняют содержимое под курсором: подсказку убираем,
    // следующее движение мыши покажет её заново
    case WM_MOUSEWHEEL:
    case WM_VSCROLL:
    case WM_HSCROLL:
    case WM_KEYDOWN:
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_KILLFOCUS:
    case WM_CAPTURECHANGED:
        self->HideTip();
        break;

    case WM_NCDESTROY:
        self->HideTip();
        RemoveWindowSubclass(h, &TreeList::SubProc, id);
        break;

    default:
        break;
    }
    return DefSubclassProc(h, m, wp, lp);
}

// ---------------------------------------------------------------------------
// Подписка на заголовок. Две задачи, и обе иначе недостижимы.
//
// HDM_LAYOUT — единственный способ задать высоту строки заголовка: список сам
// спрашивает её у заголовка, тот заполняет pwpos своей высотой, а prc->top
// задаёт границу, ниже которой размещаются строки. Правим ПОСЛЕ штатной
// обработки, поэтому позиция, ширина и прокрутка считаются как обычно.
//
// WM_PAINT — единственный надёжный способ дорисовать линию под заголовком.
// Своё NM_CUSTOMDRAW заголовок родителю СПИСКА не пересылает (в отличие от
// HDN_*), поэтому обработчик в TreeList::OnNotify до него не доходит.
//
// В современном оформлении обе задачи отпадают: HeaderWanted() возвращает 0,
// а PaintHeaderRule ничего не рисует.
// ---------------------------------------------------------------------------
LRESULT CALLBACK TreeList::HdrProc(HWND h, UINT m, WPARAM wp, LPARAM lp,
                                   UINT_PTR id, DWORD_PTR ref) {
    auto* self = reinterpret_cast<TreeList*>(ref);

    switch (m) {
    case HDM_LAYOUT: {
        const LRESULT r = DefSubclassProc(h, m, wp, lp);
        auto* hl = reinterpret_cast<HDLAYOUT*>(lp);
        if (self && r && hl && hl->prc && hl->pwpos) {
            const int want = self->HeaderWanted();
            if (want > 0 && want > hl->pwpos->cy) {
                hl->pwpos->cy = want;
                hl->prc->top  = hl->pwpos->y + want;   // строки — ниже заголовка
            }
        }
        return r;
    }
    case WM_PAINT: {
        const LRESULT r = DefSubclassProc(h, m, wp, lp);
        if (self) self->PaintHeaderRule();
        return r;
    }
    case WM_NCDESTROY:
        RemoveWindowSubclass(h, &TreeList::HdrProc, id);
        break;

    default:
        break;
    }
    return DefSubclassProc(h, m, wp, lp);
}

// ------------------------------------------------------ метрики заголовка

void TreeList::InvalidateMetrics() {
    metricsValid_ = false;
    fitDirty_     = true;
    lastFitWidth_ = -1;
}

// Все десять заголовков замеряются в ОДНОМ device context. Прежде на каждую
// колонку приходился свой GetDC/ReleaseDC, и при изменении ширины окна это
// повторялось двадцать раз на каждое WM_SIZE.
void TreeList::EnsureHeaderMetrics() {
    if (metricsValid_) [[likely]] return;
    const ColDef* cols = St(skin_).cols;

    int text[ColumnCount]{};
    if (header_) {
        HDC dc = GetDC(header_);
        if (dc) {
            HFONT hf = reinterpret_cast<HFONT>(SendMessageW(header_, WM_GETFONT, 0, 0));
            HGDIOBJ old = hf ? SelectObject(dc, hf) : nullptr;
            for (int i = 0; i < ColumnCount; ++i) {
                const std::wstring title = LoadStringRes(cols[i].titleId);
                SIZE sz{};
                GetTextExtentPoint32W(dc, title.c_str(),
                                      static_cast<int>(title.size()), &sz);
                text[i] = sz.cx;
            }
            if (old) SelectObject(dc, old);
            ReleaseDC(header_, dc);
        }
    }

    // паддинги заголовка + место под стрелку сортировки
    const int pad = Scaled(10) + Scaled(13);
    for (int i = 0; i < ColumnCount; ++i) {
        hdrIdeal_[i] = text[i] + pad + (i == paddedCol_ ? ColumnRightPadding(dpi_) : 0);
        minW_[i] = std::max(Scaled(cols[i].minWidth), hdrIdeal_[i]);
    }
    metricsValid_ = true;
}

void TreeList::RecomputeFirstColumnIdeal() {
    EnsureHeaderMetrics();

    int ideal = hdrIdeal_[ColProcess];
    for (const Row& r : rows_) {
        const Row& process = ProcessRow(r);
        // Подпись соединения может быть именем службы, а не именем группы.
        // Имя мерим самым широким применяемым начертанием; домен рисуется
        // обычным начертанием строки соединения.
        const int left = r.isGroup
            ? TextLeft(true)
            : std::max(TextLeft(true), TextLeft(false));
        int textWidth = MeasureText(r.processName(process), true);
        if (!r.isGroup && r.tlsDomainLabel && !r.tlsDomainLabel->empty())
            textWidth += Scaled(5) + MeasureText(*r.tlsDomainLabel, false);
        const int w = left + textWidth + Scaled(9);
        if (w > ideal) ideal = w;
    }
    if (ideal != col0Ideal_) {
        col0Ideal_ = ideal;
        fitDirty_  = true;          // потребность колонки-дерева изменилась
    }
    if (rows_.empty()) textWidths_.clear();
}

// Двойной щелчок по разделителю колонки «Процесс»: ширина по содержимому.
// Колонка закрепляется точно, разницу принимают остальные — сумма остаётся
// равной ширине окна.
void TreeList::AutoSizeFirstColumn() {
    RecomputeFirstColumnIdeal();
    BalanceManual(ColProcess, std::max(col0Ideal_, Scaled(110)));
    InvalidateRect(hwnd_, nullptr, FALSE);
}

// --------------------------------------------------------------- раскладка

int TreeList::DisplayIndexOf(int col) const {
    HDITEMW item{};
    item.mask = HDI_ORDER;
    return header_ && Header_GetItem(header_, col, &item) ? item.iOrder : -1;
}

void TreeList::SaveColumnOrder() {
    ColumnOrder order{};
    if (!hwnd_ || !ListView_GetColumnOrderArray(hwnd_, ColumnCount, order.data()) ||
        !ValidColumnOrder(order)) return;
    std::wstring encoded;
    for (int col : order) {
        if (!encoded.empty()) encoded += L',';
        encoded += std::to_wstring(col);
    }
    Settings::SetString(Settings::Key::kListColumnOrder, encoded);
}

void TreeList::EffectiveMins(int total, int* out) const {
    for (int i = 0; i < ColumnCount; ++i) out[i] = minW_[i];
    // измеренная потребность колонки-дерева, но не более 45 % ширины окна
    const int cap = std::max(Scaled(St(skin_).cols[ColProcess].minWidth),
                             static_cast<int>(total * 0.45));
    out[ColProcess] = std::max(out[ColProcess], std::min(col0Ideal_, cap));
}

void TreeList::ComputeWidths(int total, int* out) const {
    int minW[ColumnCount]{};
    EffectiveMins(total, minW);

    int sumMin = 0;
    double sumWeight = 0.0;
    for (int i = 0; i < ColumnCount; ++i) {
        sumMin += minW[i];
        sumWeight += weight_[i] > 0.0 ? weight_[i] : 1.0;
    }

    if (total <= sumMin || sumWeight <= 0.0) {
        std::copy(std::begin(minW), std::end(minW), out);
        return;
    }

    int assigned = 0;
    for (int i = 0; i < ColumnCount; ++i) {
        const double weight = weight_[i] > 0.0 ? weight_[i] : 1.0;
        const int want = static_cast<int>(std::llround(total * weight / sumWeight));
        out[i] = std::max(minW[i], want);
        assigned += out[i];
    }
    int diff = total - assigned;
    for (int pass = 0; pass < 4 && diff != 0; ++pass) {
        for (int idx = 0; idx < ColumnCount && diff != 0; ++idx) {
            const int c = kStretch[idx];
            if (diff > 0) { out[c] += diff; diff = 0; }
            else {
                const int take = std::min(out[c] - minW[c], -diff);
                if (take > 0) { out[c] -= take; diff += take; }
            }
        }
    }
}

// Одно LVM_SETCOLUMNWIDTH заставляет список перерисоваться целиком, а
// перерисовка здесь дорогая: своя отрисовка колонки «Процесс» на каждую строку.
// Поэтому пакет ширин пишется при выключенной перерисовке, а список
// помечается к обновлению один раз.
void TreeList::SetRedraw(bool on) {
    if (!hwnd_) return;
    // Пока разделитель тянут мышью, заголовок трогать нельзя: он сам рисует
    // перетаскивание, и выключенная перерисовка заморозила бы его.
    const bool hdr = header_ != nullptr && trackCol_ < 0;
    if (hdr) SendMessageW(header_, WM_SETREDRAW, on ? TRUE : FALSE, 0);
    SendMessageW(hwnd_, WM_SETREDRAW, on ? TRUE : FALSE, 0);
    if (!on) return;
    InvalidateRect(hwnd_, nullptr, FALSE);
    if (hdr) InvalidateRect(header_, nullptr, FALSE);
}

int TreeList::ApplyWidths(const int* w) {
    if (!hwnd_) return 0;

    int cur[ColumnCount]{};
    int changed = 0;
    for (int i = 0; i < ColumnCount; ++i) {
        cur[i] = ListView_GetColumnWidth(hwnd_, i);
        if (cur[i] != w[i]) ++changed;
    }
    if (!changed) return 0;

    inFit_ = true;                       // HDN_ITEMCHANGED — не пользователь
    const bool batch = changed > 1;
    if (batch) SetRedraw(false);
    for (int i = 0; i < ColumnCount; ++i)
        if (cur[i] != w[i]) ListView_SetColumnWidth(hwnd_, i, w[i]);
    if (batch) SetRedraw(true);
    inFit_ = false;
    return changed;
}

void TreeList::StoreWeights() {
    if (!hwnd_) return;
    for (int i = 0; i < ColumnCount; ++i) {
        const int cx = ListView_GetColumnWidth(hwnd_, i);
        if (cx > 0) weight_[i] = static_cast<double>(cx);
    }
}

void TreeList::FitColumns() {
    if (!hwnd_) return;

    RECT rc{};
    GetClientRect(hwnd_, &rc);
    int total = rc.right - rc.left;
    if (total <= 0) return;

    // Главная развязка: ширина клиентской области не изменилась и метрики в
    // силе -> текущая раскладка уже соответствует окну. Именно поэтому
    // изменение ВЫСОТЫ окна ничего не стоит; так же ведёт себя и повторный
    // вызов при неизменной ширине.
    if (total == lastFitWidth_ && metricsValid_ && !fitDirty_) [[likely]] return;

    EnsureHeaderMetrics();

    // Двух проходов достаточно: второй нужен только если после записи ширин
    // появилась либо исчезла вертикальная полоса прокрутки.
    for (int pass = 0; pass < 2; ++pass) {
        int w[ColumnCount]{};
        ComputeWidths(total, w);
        const int changed = ApplyWidths(w);

        GetClientRect(hwnd_, &rc);
        const int after = rc.right - rc.left;
        lastFitWidth_ = after;
        fitDirty_     = false;

        if (!changed || after == total || after <= 0) break;
        total = after;                            // полоса прокрутки изменила ширину
    }
}

// ------------------------------------------- ручное изменение ширины мышью

// Допустимые границы ширины для колонки, чей разделитель тянут.
// Колонки левее по порядку показа не двигаются, колонки правее могут сжаться
// только до своих минимумов — отсюда верхняя граница. Ширина за этой границей
// означала бы выезд колонок за правый край окна.
void TreeList::TrackRange(int col, int& lo, int& hi) {
    lo = hi = 0;
    if (!hwnd_ || col < 0 || col >= ColumnCount) return;

    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int total = rc.right - rc.left;
    if (total <= 0) return;

    const int pos = DisplayIndexOf(col);
    if (pos < 0) return;

    EnsureHeaderMetrics();
    int mins[ColumnCount]{};
    EffectiveMins(total, mins);

    ColumnOrder order{};
    if (!ListView_GetColumnOrderArray(hwnd_, ColumnCount, order.data())) return;
    int before = 0, minAfter = 0;
    for (int i = 0; i < ColumnCount; ++i) {
        const int c = order[i];
        if (c == col) continue;
        if (i < pos) before   += ListView_GetColumnWidth(hwnd_, c);
        else         minAfter += mins[c];
    }
    lo = mins[col];
    hi = std::max(total - before - minAfter, lo);
}

// Живая подгонка во время перетаскивания: разницу принимают только колонки
// СПРАВА по порядку показа.
//
// Колонки левее менять нельзя. Ширину растягиваемой колонки контрол считает
// как «курсор минус её левый край»; сдвинув левый край, мы заставили бы
// ширину расти самостоятельно, и следующая подгонка сдвинула бы край ещё
// левее — левые колонки схлопнулись бы до минимумов.
void TreeList::BalanceFollowers(int col) {
    if (!hwnd_ || col < 0 || col >= ColumnCount) return;

    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int total = rc.right - rc.left;
    if (total <= 0) return;

    const int pos = DisplayIndexOf(col);
    if (pos < 0) return;

    EnsureHeaderMetrics();
    int mins[ColumnCount]{};
    EffectiveMins(total, mins);

    int w[ColumnCount]{};
    int sum = 0;
    for (int i = 0; i < ColumnCount; ++i) {
        w[i] = ListView_GetColumnWidth(hwnd_, i);
        sum += w[i];
    }

    int delta = sum - total;          // > 0 — вылезли за край, < 0 — остался зазор
    if (delta == 0) return;

    for (int idx = 0; idx < ColumnCount && delta != 0; ++idx) {
        const int c = kStretch[idx];
        if (c == col || DisplayIndexOf(c) < pos) continue;
        if (delta > 0) {
            const int take = std::min(w[c] - mins[c], delta);
            if (take > 0) { w[c] -= take; delta -= take; }
        } else {
            w[c] -= delta;            // весь зазор — первой эластичной колонке
            delta = 0;
        }
    }
    ApplyWidths(w);
}

// Точная подгонка после ручного изменения ширины (отпускание разделителя,
// авторазмер по двойному щелчку). Колонка col сохраняет заданную ширину,
// остаток разбирают остальные в порядке эластичности, поэтому сумма ширин
// снова точно равна клиентской области.
//
// Пропорционального пересчёта здесь намеренно нет: он переставлял бы все
// колонки в момент отпускания кнопки — заметный «прыжок» на глазах.
void TreeList::BalanceManual(int col, int want) {
    if (!hwnd_ || col < 0 || col >= ColumnCount) return;

    RECT rc{};
    GetClientRect(hwnd_, &rc);
    int total = rc.right - rc.left;
    if (total <= 0) return;

    EnsureHeaderMetrics();

    for (int pass = 0; pass < 2; ++pass) {
        int mins[ColumnCount]{};
        EffectiveMins(total, mins);

        int w[ColumnCount]{};
        for (int i = 0; i < ColumnCount; ++i)
            w[i] = ListView_GetColumnWidth(hwnd_, i);

        int othersMin = 0;
        for (int i = 0; i < ColumnCount; ++i)
            if (i != col) othersMin += mins[i];

        // предел ширины: остальные колонки должны уместиться хотя бы минимумами
        const int maxCol = std::max(total - othersMin, mins[col]);
        w[col] = std::clamp(want, mins[col], maxCol);

        int sum = 0;
        for (int i = 0; i < ColumnCount; ++i) sum += w[i];
        int delta = sum - total;

        for (int p = 0; p < 3 && delta != 0; ++p) {
            for (int idx = 0; idx < ColumnCount && delta != 0; ++idx) {
                const int c = kStretch[idx];
                if (c == col) continue;
                if (delta > 0) {
                    const int take = std::min(w[c] - mins[c], delta);
                    if (take > 0) { w[c] -= take; delta -= take; }
                } else {
                    w[c] -= delta;
                    delta = 0;
                }
            }
        }

        const int changed = ApplyWidths(w);

        GetClientRect(hwnd_, &rc);
        const int after = rc.right - rc.left;
        // ручная настройка не должна перебиваться очередной FitColumns
        lastFitWidth_ = after;
        fitDirty_     = false;

        if (!changed || after == total || after <= 0) break;
        total = after;                // исчезла горизонтальная прокрутка и т. п.
    }

    // веса := применённые ширины: изменение размера окна сохранит пропорции
    StoreWeights();
}

void TreeList::OnDpiChanged() {
    if (!hwnd_) return;
    dpi_ = GetDpiForWindow(hwnd_);
    if (!dpi_) dpi_ = 96;
    ApplyStyle();                       // шрифты, цвета, высота строки
    InvalidateMetrics();                // шрифт заголовка и масштаб изменились
    RecomputeFirstColumnIdeal();
    HideTip();
    if (tip_) SendMessageW(tip_, TTM_SETMAXTIPWIDTH, 0, Scaled(560));
    ReLayout();
    FitColumns();
    InvalidateRect(hwnd_, nullptr, TRUE);
}

namespace {

const TreeList::Row& ProcessRowFor(const std::vector<TreeList::Row>& rows,
                                   const TreeList::Row& row) {
    if (row.isGroup || row.groupRow < 0 ||
        row.groupRow >= static_cast<int>(rows.size()))
        return row;
    const TreeList::Row& group = rows[static_cast<size_t>(row.groupRow)];
    return group.isGroup && group.key.group == row.key.group &&
           group.key.ownerAmbiguous == row.key.ownerAmbiguous ? group : row;
}

bool SameLabel(const std::shared_ptr<const std::wstring>& a,
               const std::shared_ptr<const std::wstring>& b) {
    return a == b || (a && b && *a == *b);
}

// Подсказки и данные правил хранятся в новом снимке, но не влияют на пиксели.
bool SameVisibleRow(const std::vector<TreeList::Row>& before,
                    const std::vector<TreeList::Row>& after, size_t index) {
    const TreeList::Row& a = before[index];
    const TreeList::Row& b = after[index];
    if (!(a.key == b.key) || a.isGroup != b.isGroup || a.expanded != b.expanded ||
        a.bold != b.bold || a.finished != b.finished || a.lastChild != b.lastChild ||
        a.speedActive != b.speedActive || a.ruleAction != b.ruleAction ||
        a.groupRow != b.groupRow || a.icon != b.icon ||
        !SameLabel(a.tlsDomainLabel, b.tlsDomainLabel))
        return false;
    for (int col = 0; col < ColumnCount; ++col)
        if (a.col[col] != b.col[col]) return false;
    if (!a.isGroup) {
        const TreeList::Row& oldProcess = ProcessRowFor(before, a);
        const TreeList::Row& newProcess = ProcessRowFor(after, b);
        if (a.processName(oldProcess) != b.processName(newProcess) ||
            oldProcess.col[ColPid] != newProcess.col[ColPid])
            return false;
    }
    return true;
}

} // namespace

void TreeList::SetRows(std::vector<Row>&& rows) {
    // Скорость в классической таблице всегда число: «0 байт/с», а не прочерк.
    // Поставщик строк этих случаев не различает — у него отсутствие активности
    // и нулевая скорость одно и то же значение, — поэтому приведение к виду
    // таблицы выполняется здесь, в представлении.
    if (St(skin_).zeroSpeed) {
        const std::wstring zero = LoadStringRes(IDS_SPEED_ZERO);
        for (Row& r : rows)
            if (r.col[ColSpeed] == kDash) r.col[ColSpeed] = zero;
    }

    // Пересчитываем идеал при смене строк, имён, доменных подписей или начертания.
    const bool countChanged = rows.size() != rows_.size();
    bool metricsDirty = countChanged;
    if (!metricsDirty) [[likely]] {
        for (size_t i = 0; i < rows.size(); ++i) {
            const Row& oldRow = rows_[i];
            const Row& newRow = rows[i];
            if (newRow.bold != oldRow.bold || newRow.isGroup != oldRow.isGroup ||
                !SameLabel(newRow.tlsDomainLabel, oldRow.tlsDomainLabel) ||
                newRow.processName(ProcessRowFor(rows, newRow)) !=
                    oldRow.processName(ProcessRowFor(rows_, oldRow))) [[unlikely]] {
                metricsDirty = true;
                break;
            }
        }
    }

    // При одинаковом числе строк перерисовываем только изменившиеся видимые
    // диапазоны. Имя и PID соединения могут принадлежать невидимой группе.
    bool redrawAll = countChanged;
    size_t visibleCount = 0, changedVisible = 0;
    std::vector<std::pair<int, int>> changedRanges;
    if (!countChanged && !rows.empty()) {
        const int top = ListView_GetTopIndex(hwnd_);
        const int page = ListView_GetCountPerPage(hwnd_);
        if (top < 0 || page <= 0 || static_cast<size_t>(top) >= rows.size()) {
            redrawAll = true;
        } else {
            const size_t begin = static_cast<size_t>(top);
            // Кроме целых строк учитываем возможные частичные сверху и снизу.
            const size_t end = begin + std::min(rows.size() - begin,
                                                static_cast<size_t>(page) + 2);
            visibleCount = end - begin;
            for (size_t i = begin; i < end; ++i) {
                if (!SameVisibleRow(rows_, rows, i)) {
                    ++changedVisible;
                    const int index = static_cast<int>(i);
                    if (!changedRanges.empty() && changedRanges.back().second == index - 1)
                        changedRanges.back().second = index;
                    else
                        changedRanges.emplace_back(index, index);
                }
            }
        }
    }

    // При переносе выделения вызывающий восстановит его после SetRows;
    // не рисуем промежуточное состояние до этого восстановления.
    bool selectionUnchanged = true;
    if (!redrawAll && changedRanges.size() > 1) {
        const int selected = ListView_GetNextItem(hwnd_, -1, LVNI_SELECTED);
        if (selected >= 0) {
            const size_t index = static_cast<size_t>(selected);
            selectionUnchanged = index < rows.size() && rows_[index].key == rows[index].key &&
                (ListView_GetItemState(hwnd_, selected, LVIS_FOCUSED) & LVIS_FOCUSED);
        }
    }

    // Пустой список не удерживает ни массив прежних строк, ни копии их текста
    // в подсказке, буферах RTL-отображения и кэше измерений.
    if (rows.empty()) {
        std::vector<Row>().swap(rows);
        HideTip();
        tipRow_ = -1;
        if (tip_) {
            TTTOOLINFOW ti = TipInfo();
            ti.lpszText = const_cast<LPWSTR>(L"");
            SendMessageW(tip_, TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&ti));
        }
        std::wstring().swap(tipText_);
        for (auto& text : displayText_) std::wstring().swap(text);
        textWidths_.clear();
    }
    rows_ = std::move(rows);
    paintRow_ = -1;                     // кэш состояния строк устарел
    // Подсказку не гасим: она наша, обновление списка её не касается.
    // Убираем, если сохранённый индекс подсказки вышел за границы нового списка.
    if (tipVisible_ && tipRow_ >= static_cast<int>(rows_.size())) HideTip();

    // Контрол сохраняет числовой индекс выделения при смене данных. Здесь
    // запоминаем его для проверки границ; восстановление строки по устойчивому
    // ключу и предварительный сброс чужого выделения выполняет App::RebuildRows.
    if (countChanged) {
        const int oldSelection = ListView_GetNextItem(hwnd_, -1, LVNI_SELECTED);
        ListView_SetItemCountEx(hwnd_, static_cast<int>(rows_.size()),
                                LVSICF_NOSCROLL | LVSICF_NOINVALIDATEALL);

        // Если было выделение и оно стало невалидным - сбрасываем явно.
        if (oldSelection >= 0 && oldSelection >= static_cast<int>(rows_.size())) {
            ListView_SetItemState(hwnd_, oldSelection, 0, LVIS_SELECTED | LVIS_FOCUSED);
        }
    }

    if (metricsDirty) [[unlikely]] RecomputeFirstColumnIdeal();

    FitColumns();                       // сам решит, нужна ли работа
    if (redrawAll) {
        InvalidateRect(hwnd_, nullptr, FALSE);
    } else {
        // ListView при объединении областей рисует строки между ними. Если нет
        // чужого ожидающего WM_PAINT, отделяем несколько редких изменений друг
        // от друга; плотные изменения оставляем контролу для объединения.
        const bool sparse = visibleCount && changedVisible <= (visibleCount - 1) / 2;
        const bool separate = selectionUnchanged && changedRanges.size() > 1 &&
                              changedRanges.size() <= 4 && sparse &&
                              !GetUpdateRect(hwnd_, nullptr, FALSE);
        for (size_t i = 0; i < changedRanges.size(); ++i) {
            const auto [first, last] = changedRanges[i];
            ListView_RedrawItems(hwnd_, first, last);
            if (separate && i + 1 < changedRanges.size()) UpdateWindow(hwnd_);
        }
    }
}

int TreeList::Selected() const {
    return ListView_GetNextItem(hwnd_, -1, LVNI_SELECTED);
}

// Список плоский: за строкой-группой идут её соединения, поэтому родитель —
// первая строка-группа выше по списку. Совпадение идентичности владельца
// проверяется отдельно: при активном фильтре часть строк скрыта, и полагаться
// на одну лишь геометрию порядка нельзя.
int TreeList::GroupRowOf(int index) const {
    if (index < 0 || index >= static_cast<int>(rows_.size())) return -1;
    const Row& child = rows_[static_cast<size_t>(index)];
    if (child.isGroup) return index;
    if (child.groupRow >= 0 &&
        child.groupRow < static_cast<int>(rows_.size())) [[likely]] {
        const Row& group = rows_[static_cast<size_t>(child.groupRow)];
        if (group.isGroup && group.key.group == child.key.group &&
            group.key.ownerAmbiguous == child.key.ownerAmbiguous) [[likely]]
            return child.groupRow;
    }
    // Совместимый резерв для строк, собранных внешним вызывающим без groupRow.
    for (int i = index; i >= 0; --i) {
        const Row& r = rows_[static_cast<size_t>(i)];
        if (r.isGroup && r.key.group == child.key.group &&
            r.key.ownerAmbiguous == child.key.ownerAmbiguous)
            return i;
    }
    return -1;
}

const TreeList::Row& TreeList::ProcessRow(const Row& row) const {
    return ProcessRowFor(rows_, row);
}

void TreeList::Select(int index) {
    if (index < 0 || index >= static_cast<int>(rows_.size())) return;
    constexpr UINT state = LVIS_SELECTED | LVIS_FOCUSED;
    if ((ListView_GetItemState(hwnd_, index, state) & state) == state) return;
    paintRow_ = -1;
    ListView_SetItemState(hwnd_, index, state, state);
}

void TreeList::SetSortIndicator(int col, bool asc) {
    if (!header_) return;
    const int n = Header_GetItemCount(header_);
    for (int i = 0; i < n; ++i) {
        HDITEMW hi{};
        hi.mask = HDI_FORMAT;
        if (!Header_GetItem(header_, i, &hi)) continue;
        hi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == col) hi.fmt |= asc ? HDF_SORTUP : HDF_SORTDOWN;
        Header_SetItem(header_, i, &hi);
    }
}

std::wstring TreeList::ColumnTitle(int col) const {
    if (col < 0 || col >= ColumnCount) return {};
    return LoadStringRes(St(skin_).cols[col].titleId);
}

// Подсказка колонки «Процесс»: полный путь показывается всегда, а не только
// при обрезанном имени — по имени файла один процесс от другого не отличить.
std::wstring TreeList::BuildTip(int rowIndex) const {
    if (rowIndex < 0 || rowIndex >= static_cast<int>(rows_.size()))
        return std::wstring();
    const Row& row = rows_[static_cast<size_t>(rowIndex)];
    const Row& process = ProcessRow(row);

    std::wstring s = row.processName(process);
    if (!row.isGroup && row.tlsDomainLabel && !row.tlsDomainLabel->empty()) {
        s += L" ";
        s += *row.tlsDomainLabel;
    }
    if (!process.path.empty()) {
        s += L"\n";
        s += process.path;
    } else if (row.key.group.pid() > 4) {
        s += LoadStringRes(IDS_TIP_PATH_UNAVAILABLE);
    }
    if (row.key.group.pid()) s += L"\nPID: " + std::to_wstring(row.key.group.pid());
    if (row.isGroup && !row.col[ColReason].empty()) {
        s += L"\n";
        s += row.col[ColReason];
    }
    return s;
}

int TreeList::MeasureText(const std::wstring& s, bool bold) const {
    if (s.empty() || !hwnd_) return 0;
    return textWidths_.Get(s, bold, [&] {
        HDC dc = GetDC(hwnd_);
        if (!dc) [[unlikely]] return 0;
        HFONT f = bold && bold_
                  ? bold_
                  : reinterpret_cast<HFONT>(SendMessageW(hwnd_, WM_GETFONT, 0, 0));
        HGDIOBJ old = f ? SelectObject(dc, f) : nullptr;
        SIZE sz{};
        GetTextExtentPoint32W(dc, s.c_str(), static_cast<int>(s.size()), &sz);
        if (old) SelectObject(dc, old);
        ReleaseDC(hwnd_, dc);
        return static_cast<int>(sz.cx);
    });
}

// -------------------------------------------------------------- отрисовка

void TreeList::PaintPaddedHeader(const DRAWITEMSTRUCT& draw) {
    // Штатный заголовок уже нарисовал фон, включая нажатие и подсветку мышью.
    // Меняем только содержимое, сохраняя текст в контроле для доступности.
    HDC hdc = draw.hDC;
    const int saved = SaveDC(hdc);
    IntersectClipRect(hdc, draw.rcItem.left, draw.rcItem.top,
                      draw.rcItem.right, draw.rcItem.bottom);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GetSysColor(COLOR_BTNTEXT));
    if (HFONT font = reinterpret_cast<HFONT>(SendMessageW(header_, WM_GETFONT, 0, 0)))
        SelectObject(hdc, font);

    RECT rc = draw.rcItem;
    rc.left += Scaled(6);
    rc.right -= Scaled(6) + ColumnRightPadding(dpi_);
    HDITEMW item{};
    item.mask = HDI_FORMAT;
    Header_GetItem(header_, static_cast<int>(draw.itemID), &item);
    HTHEME theme = GetWindowTheme(header_);
    if (item.fmt & (HDF_SORTUP | HDF_SORTDOWN)) {
        const bool up = (item.fmt & HDF_SORTUP) != 0;
        if (theme) {
            const int state = up ? HSAS_SORTEDUP : HSAS_SORTEDDOWN;
            SIZE size{ Scaled(9), Scaled(5) };
            GetThemePartSize(theme, hdc, HP_HEADERSORTARROW, state,
                             nullptr, TS_TRUE, &size);
            RECT arrow{ rc.left + (rc.right - rc.left - size.cx) / 2, rc.top,
                        0, rc.top + size.cy };
            arrow.right = arrow.left + size.cx;
            DrawThemeBackground(theme, hdc, HP_HEADERSORTARROW, state, &arrow, nullptr);
        } else {
            const LONG w = Scaled(9), h = Scaled(5);
            const LONG x = rc.right - w, y = rc.top + (rc.bottom - rc.top - h) / 2;
            POINT arrow[3]{ {x, y + (up ? h : 0)},
                            {x + w / 2, y + (up ? 0 : h)},
                            {x + w, y + (up ? h : 0)} };
            SelectObject(hdc, GetStockObject(NULL_PEN));
            SelectObject(hdc, GetSysColorBrush(COLOR_BTNTEXT));
            Polygon(hdc, arrow, 3);
            rc.right = x - Scaled(4);
        }
    }

    const std::wstring title = ColumnTitle(static_cast<int>(draw.itemID));
    UINT flags = DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX;
    if (GetWindowLongPtrW(header_, GWL_EXSTYLE) & WS_EX_LAYOUTRTL)
        flags |= DT_RTLREADING;
    if (rc.right > rc.left) {
        if (theme) {
            const int state = (draw.itemState & ODS_SELECTED) ? HIS_PRESSED
                : (draw.itemState & ODS_HOTLIGHT) ? HIS_HOT : HIS_NORMAL;
            DrawThemeText(theme, hdc, HP_HEADERITEM, state, title.c_str(), -1, flags, 0, &rc);
        } else {
            DrawTextW(hdc, title.c_str(), -1, &rc, flags);
        }
    }
    RestoreDC(hdc, saved);
}

// Линия по нижнему краю строки заголовка (классическое оформление). Вызывается
// из WM_PAINT заголовка, поэтому фон уже нарисован темой, а линия ложится
// поверх и не мешает ни подсветке под курсором, ни стрелке сортировки.
void TreeList::PaintHeaderRule() {
    if (!St(skin_).headerRule) return;
    if (!header_ || !IsWindow(header_)) return;
    EnsureBrushes();
    if (!brushesValid_) return;

    HDC dc = GetDC(header_);
    if (!dc) return;
    RECT rc{};
    if (GetClientRect(header_, &rc)) {
        const int t = std::max(1, Scaled(1));
        RECT line{ rc.left, rc.bottom - t, rc.right, rc.bottom };
        FillRect(dc, &line, brRule_);
    }
    ReleaseDC(header_, dc);
}

// Линия ПЕРЕД строкой-процессом (классическое оформление).
//
// Рисуется по верхнему краю, а не по нижнему, и только для групп. Из этого
// сразу получается нужный результат: между двумя процессами линия есть,
// между последним соединением одного процесса и следующим процессом — есть,
// а между процессом и его собственными соединениями и между соединениями
// линии нет.
//
// Для первой строки списка линия не нужна: там уже стоит линия заголовка.
// На выделенной строке тоже не нужна — она легла бы поверх полосы выделения.
void TreeList::PaintRowRule(HDC hdc, int index) {
    if (!St(skin_).groupRule) return;
    if (index <= 0 || !hwnd_ || !hdc) return;
    if (RowSelected(index)) return;

    EnsureBrushes();
    if (!brushesValid_) return;

    RECT rc{};
    if (!ListView_GetItemRect(hwnd_, index, &rc, LVIR_BOUNDS)) return;

    RECT client{};
    GetClientRect(hwnd_, &client);
    const int t = std::max(1, Scaled(1));
    // По ширине — до правого края окна: сумму ширин колонок FitColumns держит
    // равной клиентской области, поэтому линия не обрывается на последней
    // колонке и не выходит за неё.
    RECT line{ client.left, rc.top, client.right, rc.top + t };
    FillRect(hdc, &line, brRule_);
}

// Раскрывающий узел: квадрат с рамкой и знаком «+» / «−».
//
// Инверсия под сплошной полосой выделения нужна только когда тема отключена
// в системе: там полоса заливается COLOR_HIGHLIGHT, и обычный узел на ней
// сливался бы. Случай редкий, поэтому кисти создаются на месте.
void TreeList::PaintExpander(HDC hdc, const RECT& cell, bool expanded,
                             bool selected) {
    const int box = BoxSize();
    RECT r{};
    r.left   = cell.left + (cell.right - cell.left - box) / 2;
    r.top    = cell.top  + (cell.bottom - cell.top - box) / 2;
    r.right  = r.left + box;
    r.bottom = r.top  + box;

    const int th  = std::max(1, Scaled(1));    // толщина штриха
    const int pad = std::max(2, Scaled(2));    // отступ от рамки
    const int cx  = r.left + box / 2;
    const int cy  = r.top  + box / 2;

    if (selected && !paintThemed_) {
        HBRUSH bg = CreateSolidBrush(GetSysColor(COLOR_HIGHLIGHT));
        HBRUSH fr = CreateSolidBrush(GetSysColor(COLOR_HIGHLIGHTTEXT));
        FillRect(hdc, &r, bg);
        FrameRect(hdc, &r, fr);
        RECT hbar{ r.left + pad, cy - th / 2, r.right - pad, cy - th / 2 + th };
        FillRect(hdc, &hbar, fr);
        if (!expanded) {
            RECT vbar{ cx - th / 2, r.top + pad, cx - th / 2 + th, r.bottom - pad };
            FillRect(hdc, &vbar, fr);
        }
        DeleteObject(bg);
        DeleteObject(fr);
        return;
    }

    EnsureBrushes();
    if (!brushesValid_) return;

    FillRect(hdc, &r, brBoxFill_);
    FrameRect(hdc, &r, brBoxEdge_);

    RECT hbar{ r.left + pad, cy - th / 2, r.right - pad, cy - th / 2 + th };
    FillRect(hdc, &hbar, brBoxSign_);
    if (!expanded) {
        RECT vbar{ cx - th / 2, r.top + pad, cx - th / 2 + th, r.bottom - pad };
        FillRect(hdc, &vbar, brBoxSign_);
    }
}

// Направляющие линии дерева (современное оформление): вертикаль от группы
// и короткий отвод к тексту. Последний дочерний элемент обрывает вертикаль
// на середине строки.
void TreeList::PaintGuides(HDC hdc, const RECT& rc, const Row& row) {
    EnsureBrushes();
    if (!brushesValid_) return;

    const int gx  = rc.left + GuideX();
    const int mid = rc.top + (rc.bottom - rc.top) / 2;
    const int th  = std::max(1, Scaled(1));

    RECT v{ gx, rc.top, gx + th, row.lastChild ? mid + th : rc.bottom };
    FillRect(hdc, &v, brGuide_);
    RECT h{ gx, mid, rc.left + TextLeft(false) - Scaled(5), mid + th };
    FillRect(hdc, &h, brGuide_);
}

// Правые границы колонок в координатах СПИСКА. Берутся у заголовка: он
// сдвигается вместе с горизонтальной прокруткой, поэтому его левый край,
// переведённый в координаты списка, уже содержит нужное смещение.
int TreeList::ColumnEdges(int* out) const {
    if (!header_ || !hwnd_) return 0;

    const int n = Header_GetItemCount(header_);
    int count = 0;
    for (int i = 0; i < n && count < ColumnCount; ++i) {
        RECT ir{};
        if (!Header_GetItemRect(header_, i, &ir)) continue;
        MapWindowPoints(header_, hwnd_, reinterpret_cast<POINT*>(&ir), 2);
        out[count++] = ir.right;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Швы полосы выделения.
//
// В нетемизированном пути отрисовки список заливает фон КАЖДОГО подэлемента
// отдельным прямоугольником. Прямоугольники не смыкаются: на стыках остаётся
// то, чем область была стёрта, — белый фон окна. Отсюда вертикальные белые
// линии на границах колонок внутри синей полосы, причём только после
// переключения оформления: у свежесозданного контрола этот путь не включался.
//
// Цвет для заливки НЕ выбирается, а СНИМАЕТСЯ с уже нарисованной полосы
// (GetPixel слева от шва). Это принципиально: цвет полосы зависит от темы,
// системной палитры и наличия фокуса, и любое собственное значение рано или
// поздно разошлось бы с тем, что нарисовал контрол.
//
// Функция вызывается только оформлением, которое эти швы получает
// (SkinStyle::seamPatch), поэтому на второе оформление повлиять не может.
// ---------------------------------------------------------------------------
void TreeList::PaintSelectionSeams(HDC hdc, int index) {
    if (!St(skin_).seamPatch) return;
    if (!hwnd_ || !hdc || index < 0) return;
    if (!RowSelected(index)) return;         // швы видны только на полосе

    RECT rc{};
    if (!ListView_GetItemRect(hwnd_, index, &rc, LVIR_BOUNDS)) return;
    if (rc.bottom <= rc.top) return;

    int edges[ColumnCount]{};
    const int n = ColumnEdges(edges);
    if (n <= 0) return;

    const int mid  = rc.top + (rc.bottom - rc.top) / 2;
    const int seam = std::max(2, Scaled(2));   // с запасом: шов бывает шире 1 px

    for (int i = 0; i < n; ++i) {
        const int x = edges[i];
        // последняя граница совпадает с краем клиентской области — там шва нет
        if (x <= rc.left || x >= rc.right) continue;

        // Проба берётся заметно левее шва, внутри заведомо залитой части
        // подэлемента. CLR_INVALID означает, что точка вне области отсечения:
        // такой шов просто пропускаем — он и не виден.
        const COLORREF band = GetPixel(hdc, x - seam - 2, mid);
        if (band == CLR_INVALID) continue;

        HBRUSH br = CreateSolidBrush(band);
        if (!br) continue;
        RECT gap{ x - seam, rc.top, x + seam, rc.bottom };
        FillRect(hdc, &gap, br);
        DeleteObject(br);
    }
}

void TreeList::PaintFirstColumn(LPNMLVCUSTOMDRAW cd) {
    const int idx = static_cast<int>(cd->nmcd.dwItemSpec);
    if (idx < 0 || idx >= static_cast<int>(rows_.size())) return;
    const Row& row = rows_[static_cast<size_t>(idx)];
    const SkinStyle& s = St(skin_);

    HDC hdc = cd->nmcd.hdc;
    RECT rc{};
    if (!ListView_GetSubItemRect(hwnd_, idx, 0, LVIR_BOUNDS, &rc)) return;
    // ширина колонки снята один раз на всю перерисовку (CDDS_PREPAINT)
    rc.right = rc.left + paintCol0W_;
    if (rc.right <= rc.left) return;

    const int saved = SaveDC(hdc);
    const DWORD layout = GetLayout(hdc);
    if (layout != GDI_ERROR) SetLayout(hdc, layout | LAYOUT_BITMAPORIENTATIONPRESERVED);
    IntersectClipRect(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SetBkMode(hdc, TRANSPARENT);           // фон строки уже нарисован ListView

    const int rowH = rc.bottom - rc.top;
    const bool selected = RowSelected(idx);

    if (row.isGroup) {
        RECT cell{ rc.left + Scaled(2), rc.top,
                   rc.left + Scaled(2) + GlyphCell(), rc.bottom };
        PaintExpander(hdc, cell, row.expanded, selected);
        if (row.icon) {
            const int iw = IconSize();
            DrawIconEx(hdc,
                       rc.left + Scaled(2) + GlyphCell() + Scaled(s.preIconPx),
                       rc.top + (rowH - iw) / 2, row.icon->handle(), iw, iw,
                       0, nullptr, DI_NORMAL | DI_NOMIRROR);
        }
    } else if (s.guides) {
        PaintGuides(hdc, rc, row);
    }

	// Эту колонку контрол не рисует, поэтому основной цвет считаем сами — тем же
    // правилом, по которому его выберет контрол для остальных колонок
    // (см. RowTextColor: сплошная полоса выделения -> COLOR_HIGHLIGHTTEXT).
    const COLORREF textColor = RowTextColor(row, selected);
    SetTextColor(hdc, textColor);

    RECT t{ rc.left + TextLeft(row.isGroup), rc.top,
            rc.right - Scaled(4), rc.bottom };
    HFONT oldFont = nullptr;
    // То же начертание, что у остальных колонок строки: колонку «Процесс»
    // рисуем сами, и расхождение внутри одной строки бросалось бы в глаза.
    if (HFONT f = RowFont(row)) oldFont = static_cast<HFONT>(SelectObject(hdc, f));
    const std::wstring& ownerName = row.processName(ProcessRow(row));
    const bool showDomain = !row.isGroup && row.tlsDomainLabel &&
                            !row.tlsDomainLabel->empty();
    if (!showDomain) {
        DrawTextW(hdc, ownerName.c_str(), -1, &t,
                  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    } else {
        // Имя и домен обрезаются независимо, чтобы узкая колонка не скрывала
        // целиком одну из частей. Если одна часть короткая, она получает ровно
        // свою ширину, а всё оставшееся место отдаётся другой.
        const int available = std::max(
            0, static_cast<int>(t.right - t.left));
        const int gap = std::min(Scaled(5), available);
        const int nameFull = MeasureText(ownerName, row.bold);
        const int domainFull = MeasureText(*row.tlsDomainLabel, row.bold);
        int nameSlot = nameFull;
        int domainSlot = domainFull;

        if (nameSlot + gap + domainSlot > available) {
            const int textSpace = std::max(0, available - gap);
            const int half = textSpace / 2;
            if (nameFull <= half) {
                nameSlot = nameFull;
                domainSlot = textSpace - nameSlot;
            } else if (domainFull <= half) {
                domainSlot = domainFull;
                nameSlot = textSpace - domainSlot;
            } else {
                nameSlot = half;
                domainSlot = textSpace - nameSlot;
            }
        }

        RECT nameRect{ t.left, t.top, t.left + std::max(0, nameSlot), t.bottom };
        DrawTextW(hdc, ownerName.c_str(), -1, &nameRect,
                  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

        RECT domainRect{ nameRect.right + gap, t.top,
                         nameRect.right + gap + std::max(0, domainSlot), t.bottom };
        // Скобки принадлежат подписи, но окрашивается только само имя.
        // При обрезке сохраняем обе скобки и ставим многоточие внутри них.
        const std::wstring& label = *row.tlsDomainLabel;
        const UINT flags = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX;
        const UINT bracketFlags = DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX;
        if (label.size() >= 2 && label.front() == L'[' &&
            label.back() == L']') {
            SIZE opening{}, closing{}, domain{};
            GetTextExtentPoint32W(hdc, L"[", 1, &opening);
            GetTextExtentPoint32W(hdc, L"]", 1, &closing);
            if (domainRect.right - domainRect.left >= opening.cx + closing.cx) {
                const wchar_t* const name = label.c_str() + 1;
                const int nameLength = static_cast<int>(label.size() - 2);
                GetTextExtentPoint32W(hdc, name, nameLength, &domain);
                RECT openingRect{ domainRect.left, domainRect.top,
                                  domainRect.left + opening.cx, domainRect.bottom };
                DrawTextW(hdc, L"[", 1, &openingRect, bracketFlags);

                const int nameWidth = std::min(
                    domain.cx, domainRect.right - openingRect.right - closing.cx);
                RECT namePart{ openingRect.right, domainRect.top,
                               openingRect.right + nameWidth, domainRect.bottom };
                // Выделенная и завершённая строки сохраняют системный цвет.
                if (!row.finished && !selected) SetTextColor(hdc, domainText_);
                DrawTextW(hdc, name, nameLength, &namePart, flags);
                SetTextColor(hdc, textColor);

                RECT closingRect{ namePart.right, domainRect.top,
                                  namePart.right + closing.cx, domainRect.bottom };
                DrawTextW(hdc, L"]", 1, &closingRect, bracketFlags);
            } else {
                DrawTextW(hdc, label.c_str(), -1, &domainRect, flags);
            }
        } else {
            if (!row.finished && !selected) SetTextColor(hdc, domainText_);
            DrawTextW(hdc, label.c_str(), -1, &domainRect, flags);
            SetTextColor(hdc, textColor);
        }
    }
    if (oldFont) SelectObject(hdc, oldFont);

    RestoreDC(hdc, saved);
}

// ----------------------------------------------------------------- notify

bool TreeList::OnNotify(LPNMHDR hdr, LRESULT& result) {
    if (!hdr) return false;

    if (header_ && hdr->hwndFrom == header_) {
        // ВНИМАНИЕ: приводить к NMHEADERW можно ТОЛЬКО в ветках HDN_*.
        // Заголовок присылает и общие уведомления (NM_CUSTOMDRAW = -12,
        // NM_RELEASEDCAPTURE, NM_RCLICK и другие) с иными структурами: чтение
        // pitem у них попадает на чужую память.
        //
        // Отрисовки заголовка здесь нет намеренно: своё NM_CUSTOMDRAW
        // заголовок родителю списка не пересылает, поэтому линия под ним
        // рисуется в его собственном WM_PAINT (см. HdrProc).
        if (!IsHeaderItemCode(hdr->code)) return false;

        auto* nh = reinterpret_cast<NMHEADERW*>(hdr);

        switch (hdr->code) {
        case HDN_BEGINDRAG:
            HideTip();
            result = (nh->iItem <= ColProcess || nh->iItem >= ColumnCount) ? TRUE : FALSE;
            return true;

        case HDN_ENDDRAG:
            // Нельзя ни утащить «Процесс», ни поставить другую колонку перед ним.
            if (nh->iItem <= ColProcess || nh->iItem >= ColumnCount || !nh->pitem ||
                nh->pitem->iOrder <= 0 || nh->pitem->iOrder >= ColumnCount) {
                result = TRUE;
                return true;
            }
            // Заголовок применит новый порядок после возврата из уведомления.
            // Сохраняем уже фактический порядок, а не старый из HDN_ENDDRAG.
            PostMessageW(hwnd_, kSaveColumnOrderMsg, 0, 0);
            result = FALSE;
            return true;

        // Пользователь взялся за разделитель мышью
        case HDN_BEGINTRACKW:
        case HDN_BEGINTRACKA:
            trackCol_ = (nh->iItem >= 0 && nh->iItem < ColumnCount) ? nh->iItem : -1;
            return false;                 // тащить разрешаем

        // Ширину, которую соседям справа уже не компенсировать, не пропускаем:
        // именно из-за неё колонки уезжали за правый край окна. Отклонение
        // ничего не меняет, поэтому ни мигания, ни обратной связи нет.
        case HDN_ITEMCHANGINGW:
        case HDN_ITEMCHANGINGA: {
            if (inFit_ || trackCol_ < 0 || nh->iItem != trackCol_) return false;
            if (!nh->pitem || !(nh->pitem->mask & HDI_WIDTH)) return false;

            int lo = 0, hi = 0;
            TrackRange(nh->iItem, lo, hi);
            if (hi > 0 && (nh->pitem->cxy < lo || nh->pitem->cxy > hi)) {
                result = TRUE;            // изменение отклонено
                return true;
            }
            return false;
        }
        case HDN_ITEMCHANGEDW:
        case HDN_ITEMCHANGEDA:
            if (inFit_) return false;
            if (!nh->pitem || !(nh->pitem->mask & HDI_WIDTH)) return false;
            if (trackCol_ >= 0) {
                BalanceFollowers(trackCol_);                  // идёт перетаскивание
            } else if (nh->iItem >= 0 && nh->iItem < ColumnCount) {
                BalanceManual(nh->iItem,
                              ListView_GetColumnWidth(hwnd_, nh->iItem));
            }
            return false;

        case HDN_ENDTRACKW:
        case HDN_ENDTRACKA: {
            const int col = trackCol_;
            trackCol_ = -1;               // до подгонки: заголовок уже свободен
            if (col >= 0 && col < ColumnCount) {
                // pitem у HDN_ENDTRACK может отсутствовать: берём ширину у списка
                const bool hasWidth = nh->pitem && (nh->pitem->mask & HDI_WIDTH);
                const int want = hasWidth ? nh->pitem->cxy
                                          : ListView_GetColumnWidth(hwnd_, col);
                BalanceManual(col, want);
            }
            return false;
        }
        case HDN_DIVIDERDBLCLICKW:
        case HDN_DIVIDERDBLCLICKA:
            if (nh->iItem == ColProcess) {
                AutoSizeFirstColumn();
                result = 0;
                return true;
            }
            return false;                 // прочие колонки — авторазмер контролом

        default:
            return false;
        }
    }
    if (hdr->hwndFrom != hwnd_) return false;

    switch (hdr->code) {
    case LVN_GETDISPINFOW: {
        auto* di = reinterpret_cast<NMLVDISPINFOW*>(hdr);
        const int i = di->item.iItem;
        if (i >= 0 && i < static_cast<int>(rows_.size())) [[likely]] {
            const Row& r = rows_[static_cast<size_t>(i)];
            if (di->item.mask & LVIF_TEXT) {
                const int c = di->item.iSubItem;
                // «Процесс» и колонку с правым отступом рисуем поверх штатного фона.
                const Row& textRow = (!r.isGroup && c == ColPid)
                    ? ProcessRow(r) : r;
                const std::wstring& s =
                    (c == ColProcess || c == paddedCol_) ? empty_ :
                    (c > 0 && c < ColumnCount ? textRow.col[c] : empty_);
                if ((GetWindowLongPtrW(hwnd_, GWL_EXSTYLE) & WS_EX_LAYOUTRTL) &&
                    (c == ColRemote || c == ColLocal || c == ColProto || c == ColPid)) {
                    displayText_[c] = Ui::LtrText(s);
                    di->item.pszText = displayText_[c].data();
                } else {
                    di->item.pszText = const_cast<LPWSTR>(s.c_str());
                }
            }
            if (di->item.mask & LVIF_IMAGE)  di->item.iImage  = I_IMAGENONE;
            if (di->item.mask & LVIF_INDENT) di->item.iIndent = 0;
        }
        result = 0;
        return true;
    }
    case NM_CUSTOMDRAW: {
        auto* cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(hdr);
        const SkinStyle& s = St(skin_);

        switch (cd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            // Всё, что одинаково для всей перерисовки, снимается здесь один
            // раз: прежде это были десятки лишних сообщений на каждую строку.
            paintCol0W_  = ListView_GetColumnWidth(hwnd_, 0);
            paintThemed_ = IsAppThemed() != FALSE;
            paintRow_    = -1;
            EnsureBrushes();
            result = CDRF_NOTIFYITEMDRAW;
            return true;

        case CDDS_ITEMPREPAINT: {
            const int i = static_cast<int>(cd->nmcd.dwItemSpec);
            if (i < 0 || i >= static_cast<int>(rows_.size())) [[unlikely]] {
                result = CDRF_DODEFAULT;
                return true;
            }
            paintRow_ = -1;                  // состояние снимаем заново на строку
            const Row& r = rows_[static_cast<size_t>(i)];

            // Цвета задаются ТОЛЬКО для невыделенной строки.
            //
            // На выделенной их трогать бессмысленно: и полосу, и текст контрол
            // рисует своими цветами, а поля структуры игнорирует. Считать их
            // оттуда тоже нельзя — на этой стадии там лежат значения по
            // умолчанию (COLOR_WINDOWTEXT), а цвет выделения контрол
            // подставляет позже, у себя.
            const bool sel = RowSelected(i);
            if (!sel) {
                cd->clrTextBk = RowBackColor(r, false);
                cd->clrText   = RowTextColor(r, false);
            }
            (void)s;

            HFONT f = RowFont(r);
            if (f) SelectObject(cd->nmcd.hdc, f);
            result = CDRF_NOTIFYSUBITEMDRAW | CDRF_NOTIFYPOSTPAINT |
                     (f ? CDRF_NEWFONT : 0);
            return true;
        }
        case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
            const int i = static_cast<int>(cd->nmcd.dwItemSpec);
            if (i < 0 || i >= static_cast<int>(rows_.size())) [[unlikely]] {
                result = CDRF_DODEFAULT;
                return true;
            }
            const Row& r = rows_[static_cast<size_t>(i)];
            const bool sel = RowSelected(i);

            // Выделенную строку не раскрашиваем вовсе: контрол рисует её
            // своими цветами. Для остальных цвет задаётся ЯВНО на каждый
            // подэлемент — структура между подэлементами не
            // переинициализируется, и записанный однажды clrText иначе
            // растекался бы на все колонки, которые рисуются после.
            if (!sel) {
                cd->clrTextBk = RowBackColor(r, false);

                COLORREF fg = RowTextColor(r, false);

                // -------------------------------------------------------
                // Завершённая строка приглушается ЦЕЛИКОМ.
                //
                // Особые цвета колонок к ней не применяются: акцент скорости,
                // палитра действия правила и красное имя блокирующего правила
                // в «Причине». Иначе строка была бы бледной, а «Причина» —
                // яркой, то есть самая заметная колонка противоречила бы
                // признаку «соединения уже нет».
                //
                // Что именно завершилось, сообщает текст: поставщик строк
                // дописывает в «Причину» «соединение завершено» либо
                // «процесс завершён».
                // -------------------------------------------------------
                if (!r.finished) {
                    if (s.accentSpeed && cd->iSubItem == ColSpeed && r.speedActive)
                        fg = accent_;
                    else if (s.actionColors && cd->iSubItem == ColReason &&
                             r.ruleAction >= 0)
                        fg = ActionColor(r.ruleAction);
                    else if (s.blockRed && cd->iSubItem == ColReason &&
                             r.ruleAction == kActionBlock)
                        fg = kBlockText;
                    else if (s.dimText && (cd->iSubItem == ColPid ||
                                           cd->iSubItem == ColDir))
                        fg = dimText_;
                }
                cd->clrText = fg;
            }

            // Шрифт переназначаем и здесь: контрол вправе восстановить свой
            // между подэлементами, и тогда строка «поплыла» бы по начертанию.
            HFONT f = RowFont(r);
            if (f) SelectObject(cd->nmcd.hdc, f);
            if (cd->iSubItem == paddedCol_)
                paintPaddedText_ = sel ? RowTextColor(r, true) : cd->clrText;
            result = CDRF_NEWFONT |
                     (cd->iSubItem == paddedCol_ ? CDRF_NOTIFYPOSTPAINT : 0);
            return true;
        }
        case CDDS_ITEMPOSTPAINT | CDDS_SUBITEM: {
            const int i = static_cast<int>(cd->nmcd.dwItemSpec);
            RECT rc{};
            const int col = cd->iSubItem;
            if (col >= 0 && col == paddedCol_ && i >= 0 &&
                i < static_cast<int>(rows_.size()) &&
                ListView_GetSubItemRect(hwnd_, i, col, LVIR_BOUNDS, &rc)) {
                const Row& r = rows_[static_cast<size_t>(i)];
                const Row& textRow = (!r.isGroup && col == ColPid) ? ProcessRow(r) : r;
                const std::wstring* text = &textRow.col[col];
                if ((GetWindowLongPtrW(hwnd_, GWL_EXSTYLE) & WS_EX_LAYOUTRTL) &&
                    (col == ColRemote || col == ColLocal || col == ColProto || col == ColPid)) {
                    displayText_[col] = Ui::LtrText(*text);
                    text = &displayText_[col];
                }

                HDC hdc = cd->nmcd.hdc;
                const int saved = SaveDC(hdc);
                IntersectClipRect(hdc, rc.left, rc.top, rc.right, rc.bottom);
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, paintPaddedText_);
                const HFONT font = RowFont(r);
                SelectObject(hdc, font ? font : font_);
                rc.left += Scaled(6);
                rc.right -= Scaled(6) + ColumnRightPadding(dpi_);
                if (rc.right > rc.left)
                    DrawTextW(hdc, text->c_str(), -1, &rc,
                              DT_RIGHT | DT_SINGLELINE | DT_VCENTER |
                              DT_END_ELLIPSIS | DT_NOPREFIX);
                RestoreDC(hdc, saved);
            }
            result = CDRF_DODEFAULT;
            return true;
        }
        case CDDS_ITEMPOSTPAINT: {
            const int i = static_cast<int>(cd->nmcd.dwItemSpec);
            if (i < 0 || i >= static_cast<int>(rows_.size())) [[unlikely]] {
                result = CDRF_DODEFAULT;
                return true;
            }
            // Швы заливаются ПЕРВЫМИ: они относятся к фону, и текст колонки
            // «Процесс» должен лечь поверх них, а не наоборот.
            PaintSelectionSeams(cd->nmcd.hdc, i);
            PaintFirstColumn(cd);            // поверх готового фона строки
            if (rows_[static_cast<size_t>(i)].isGroup)
                PaintRowRule(cd->nmcd.hdc, i);
            result = CDRF_DODEFAULT;
            return true;
        }
        default:
            result = CDRF_DODEFAULT;
            return true;
        }
    }
    case NM_CLICK: {
        auto* ia = reinterpret_cast<LPNMITEMACTIVATE>(hdr);
        const int i = ia->iItem;
        if (i >= 0 && i < static_cast<int>(rows_.size()) &&
            rows_[static_cast<size_t>(i)].isGroup) {
            RECT rc{};
            ListView_GetSubItemRect(hwnd_, i, 0, LVIR_BOUNDS, &rc);
            rc.right = rc.left + Scaled(2) + GlyphCell() + Scaled(St(skin_).preIconPx);
            if (PtInRect(&rc, ia->ptAction) && onToggle) onToggle(i);
        }
        result = 0;
        return true;
    }
    case NM_DBLCLK: {
        auto* ia = reinterpret_cast<LPNMITEMACTIVATE>(hdr);
        const int i = ia->iItem;
        if (i >= 0 && i < static_cast<int>(rows_.size())) {
            if (rows_[static_cast<size_t>(i)].isGroup) {
                if (onToggle) onToggle(i);
            } else if (onActivate) {
                onActivate(i);
            }
        }
        result = 0;
        return true;
    }
    case LVN_KEYDOWN: {
        auto* kd = reinterpret_cast<LPNMLVKEYDOWN>(hdr);
        result = 0;

        const int i = Selected();
        if (i < 0 || i >= static_cast<int>(rows_.size())) return true;
        const Row& r = rows_[static_cast<size_t>(i)];

        const bool rtl = (GetWindowLongPtrW(hwnd_, GWL_EXSTYLE) & WS_EX_LAYOUTRTL) != 0;
        const bool collapse = kd->wVKey == (rtl ? VK_RIGHT : VK_LEFT) ||
                              kd->wVKey == VK_SUBTRACT;
        const bool expand = kd->wVKey == (rtl ? VK_LEFT : VK_RIGHT) ||
                            kd->wVKey == VK_ADD;

        if (r.isGroup) {
            if (!onToggle) return true;
            if (expand && !r.expanded)        onToggle(i);
            else if (collapse && r.expanded)  onToggle(i);
            else if (kd->wVKey == VK_SPACE)   onToggle(i);
            return true;
        }

        // Строка-СОЕДИНЕНИЕ. Клавиша сворачивания закрывает группу процесса — так же,
        // как в дереве проводника. Выделение переводится на группу ДО
        // свёртывания: строка-соединение вот-вот исчезнет, и без этого
        // выделение восстанавливать было бы не по чему (App::RebuildRows
        // ищет прежнюю строку по её ключу).
        if (collapse) {
            const int parent = GroupRowOf(i);
            if (parent >= 0) {
                Select(parent);
                if (onToggle) onToggle(parent);
            }
        }
        return true;
    }
    case LVN_COLUMNCLICK: {
        auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
        if (nl && onColumnClick) onColumnClick(nl->iSubItem);
        result = 0;
        return true;
    }
    case LVN_ITEMCHANGED: {
        auto* nl = reinterpret_cast<LPNMLISTVIEW>(hdr);
        if (nl->uChanged & LVIF_STATE) {
            paintRow_ = -1;                  // выделение изменилось
            // Линия перед группой на выделенной строке не рисуется, поэтому
            // при смене выделения перерисовать нужно и соседние строки:
            // проще обновить список целиком, это одна перерисовка на щелчок.
            if (St(skin_).groupRule) InvalidateRect(hwnd_, nullptr, FALSE);
            if ((nl->uNewState & LVIS_SELECTED) && !(nl->uOldState & LVIS_SELECTED)) {
                if (onSelectionChanged) onSelectionChanged(nl->iItem);
            }
        }
        result = 0;
        return true;
    }
    default:
        return false;
    }
}