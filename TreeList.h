#pragma once
#include "Common.h"
#include "ProcessIcon.h"
#include "TextWidthCache.h"
#include <commctrl.h>
#include <functional>
#include <memory>
#include <uxtheme.h>
#include <vector>

enum Column {
    ColProcess = 0, ColRemote, ColReason, ColSent, ColRecv,
    ColPid, ColSpeed, ColProto, ColLocal, ColDir, ColumnCount
};

// ---------------------------------------------------------------------------
// Оформление списка. Переключается на ходу, без пересоздания контрола.
//
//   Modern  — по умолчанию шрифт оболочки, высокие строки, тема Explorer,
//             подложка строки-процесса и направляющие линии с отступом вложенных
//             строк, основной цвет текста у PID и направления,
//             акцентный цвет ненулевой скорости и палитра «разрешено /
//             блокировано / спросить» в колонке состояния.
//
//   Classic — плотная таблица: компактный шрифт по умолчанию, строки
//             в высоту текста, стандартная тема (сплошная полоса выделения),
//             тонкая линия под заголовком и перед каждой строкой-процессом,
//             системный цвет основного текста, красное имя блокирующего правила
//             в колонке «Причина» и коричневая подпись домена рядом с процессом.
//
// Оба вида различаются ТОЛЬКО данными: см. таблицу kSkins в TreeList.cpp.
// Ни одного «if (это классический вид)» в коде отрисовки нет — иначе два
// оформления неизбежно разъехались бы при первой же правке.
// ---------------------------------------------------------------------------
enum class ListSkin : uint8_t { Modern = 0, Classic = 1 };


namespace ListSkinSetting {
    ListSkin     Load();
    void         Save(ListSkin s);
    // Название из ресурсов на текущем языке интерфейса, возвращается по значению.
    std::wstring Name(ListSkin s);
}

namespace ListFontSetting {
    struct Value {
        std::wstring face;
        int sizeTenths = 0;       // Размер в десятых долях пункта, как в CHOOSEFONT.
        int weight = FW_NORMAL;  // Насыщенность: FW_NORMAL, FW_BOLD и т.д.
        bool italic = false;     // Курсивное начертание.
        bool operator==(const Value&) const = default;
    };

    inline constexpr int kMinPointSize = 6;
    inline constexpr int kMaxPointSize = 72;

    Value Load(ListSkin skin, UINT dpi);
    bool Save(ListSkin skin, const Value& value);
    bool Reset(ListSkin skin);
    // Без сохранённого выбора возвращает прежний шрифт оформления без изменений.
    LOGFONTW Resolve(ListSkin skin, UINT dpi);
}

class TreeList {
public:
    // -----------------------------------------------------------------------
    // Насыщенность строк по умолчанию.
    //
    // kRowFontWeight — строки-соединения и свёрнутые группы;
    // kGroupFontWeightModern / kGroupFontWeightClassic — минимальный вес раскрытой группы.
    //
    // Гарнитура, кегль и начертание выбираются отдельно для каждого оформления.
    // Группы наследуют курсив; более насыщенное начертание выбирается из того же семейства.
    // Без сохранённого выбора Classic использует Ui::kListFontPt, Modern — шрифт оболочки.
    // -----------------------------------------------------------------------
    static constexpr int kRowFontWeight          = FW_NORMAL;	
    static constexpr int kGroupFontWeightModern  = FW_SEMIBOLD;	
    static constexpr int kGroupFontWeightClassic = FW_BOLD;

    struct RowKey {
        TrafficGroupKey group;
        bool     ownerAmbiguous = false;
        int      proto = -1;        // Proto строки, -1 для группы процесса
        uint64_t generation = 0;    // уникальное поколение потока FlowStore
        uint16_t lport = 0, rport = 0;
        uint64_t remoteHash = 0;    // хэш удалённого адреса

        bool operator==(const RowKey& o) const {
            return group == o.group && ownerAmbiguous == o.ownerAmbiguous &&
                   proto == o.proto && generation == o.generation &&
                   lport == o.lport && rport == o.rport &&
                   remoteHash == o.remoteHash;
        }
        bool valid() const { return group.isNdis() || ownerAmbiguous || group.pid() != 0 || proto >= 0; }
    };

    struct Row {
        bool         isGroup   = false;
        bool         expanded  = false;
        bool         bold      = false;
        // Соединение ЗАВЕРШЕНО: строка показывается приглушённым цветом
        // остаток окна kFinishedGraceMs, после чего поставщик строк её
        // снимает. Приглушение действует в ОБОИХ оформлениях и перекрывает
        // особые цвета отдельных колонок — в том числе «Причины».
        bool         finished   = false;
        bool         lastChild = false;   // направляющая линия / разметка фильтра
        bool         speedActive = false; // акцентный цвет скорости (только Modern)
        bool         pathKnown = false;   // путь известен; сама строка пути хранится у группы
        int          ruleAction = -1;     // 0 Allow, 1 Block, 2 Ask, -1 нет правила
        ProcessIconRef icon;
        int          groupRow  = -1;       // индекс строки процесса для дочерней
        RowKey       key;                 // ключ строки
        uint64_t     ruleId    = 0;       // 0 = правила нет
        std::wstring ruleName;            // имя из UI-снимка, не ключ поиска правила
        // Только у соединения: домен из TLS/QUIC SNI, HTTP Host или DNS
        // рядом с именем владельца.
        std::shared_ptr<const std::wstring> tlsDomainLabel;
        std::wstring path;                // полный путь: показывается подсказкой
        std::wstring col[ColumnCount];

        // Без однозначно определённой службы соединение наследует имя группы.
        const std::wstring& processName(const Row& process) const {
            return col[ColProcess].empty()
                ? process.col[ColProcess] : col[ColProcess];
        }
    };

    bool Create(HWND parent, HINSTANCE inst, UINT ctrlId);
    void Destroy();
    HWND hwnd() const { return hwnd_; }

    void SetIconSize(int iconSize);

    // Переключение оформления. До Create() только запоминает выбор, после —
    // применяет его целиком: тема, шрифты, цвета, высота строки, высота
    // заголовка, подписи и пропорции колонок.
    //
    // Ручные ширины колонок при переключении сбрасываются: у каждого
    // оформления свои подписи, а значит и свои минимумы и пропорции.
    void     SetSkin(ListSkin s);
    ListSkin skin() const { return skin_; }
    // Перечитывает шрифт текущего оформления, не сбрасывая ручные ширины колонок.
    void ReloadFont();

    void SetRows(std::vector<Row>&& rows);
    const std::vector<Row>& rows() const { return rows_; }
    int  Selected() const;
    void Select(int index);
    void SetSortIndicator(int col, bool asc);
    // Подпись зависит от оформления, поэтому метод больше не статический.
    // Возвращает копию локализованной подписи текущего оформления.
    std::wstring ColumnTitle(int col) const;

    // Пропорциональная раскладка под текущую ширину. Вызов при неизменной
    // ширине и неизменных метриках ничего не делает: раскладка уже
    // соответствует окну, а запись ширины колонки стоит перерисовки списка.
    void FitColumns();
    void OnDpiChanged();    // WM_DPICHANGED / смена темы

    bool OnNotify(LPNMHDR hdr, LRESULT& result);

    std::function<void(int row)> onToggle;
    std::function<void(int col)> onColumnClick;
    std::function<void(int row)> onSelectionChanged;
    // Двойной щелчок по строке-СОЕДИНЕНИЮ. Группа процесса по двойному щелчку
    // по-прежнему разворачивается: раскрытие и открытие правил — разные
    // действия, и совмещать их на одном жесте нельзя.
    std::function<void(int row)> onActivate;

    // ---- применение оформления ----
    void ApplyStyle();      // тема, шрифты, цвета, высота строки
    void ApplyColumns();    // подписи, выравнивание, эталонные пропорции (язык!)
    void ReLayout();        // заставить контрол перезапросить высоту заголовка

private:
    friend struct StorageTestAccess;

    static constexpr UINT_PTR kSubclassId    = 1;
    static constexpr UINT_PTR kHdrSubclassId = 2;
    static constexpr UINT_PTR kTipTimer      = 101;
    static constexpr UINT     kTipDelayMs    = 420;
    static constexpr UINT     kSaveColumnOrderMsg = WM_APP + 1;

    static LRESULT CALLBACK SubProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
    // Подписка на заголовок нужна для двух вещей, и обе иначе недостижимы:
    //   * высота строки заголовка — список спрашивает её сообщением HDM_LAYOUT;
    //   * линия по нижнему краю заголовка — своё NM_CUSTOMDRAW заголовок
    //     родителю списка НЕ пересылает (в отличие от HDN_*), поэтому линия
    //     рисуется в его собственном WM_PAINT.
    // В современном оформлении обработчик ничего не меняет и не рисует.
    static LRESULT CALLBACK HdrProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

    // ---- отрисовка ----
    void PaintFirstColumn(LPNMLVCUSTOMDRAW cd);
    void PaintExpander(HDC hdc, const RECT& cell, bool expanded, bool selected);
    void PaintGuides(HDC hdc, const RECT& rc, const Row& row);  // Modern
    void PaintHeaderRule();                                     // Classic
    void ApplyColumnPadding();
    void PaintPaddedHeader(const DRAWITEMSTRUCT& draw);
    void PaintRowRule(HDC hdc, int index);                      // Classic
    // Швы полосы выделения (Classic). В нетемизированном пути контрол
    // заливает КАЖДЫЙ подэлемент отдельным прямоугольником, и стыки между
    // ними остаются незакрашенными — на границах колонок видны белые
    // вертикальные линии. Здесь эти стыки закрашиваются.
    void PaintSelectionSeams(HDC hdc, int index);
    int  ColumnEdges(int* out) const;   // правые границы колонок, координаты списка
    int  HeaderWanted() const;      // 0 — высоту заголовка не переопределяем
    // Начертание строки: шрифт раскрытой группы либо выбранный шрифт контрола.
    HFONT RowFont(const Row& r) const;
    void RecreateFonts();
    void RefreshColors();
    void EnsureRowHeight();
    COLORREF ActionColor(int action) const;

    // ---- собственная всплывающая подсказка ----
    // Штатный LVS_EX_INFOTIP не годится: список обновляется раз в секунду
    // (ListView_SetItemCountEx + перерисовка), и контрол каждый раз гасит и
    // заново запрашивает свою подсказку — она мигает. Своим tooltip'ом мы
    // управляем сами и не гасим её при обычном обновлении данных.
    bool CreateTip();
    void DestroyTip();
    TTTOOLINFOW TipInfo() const;
    void SetTipText(const std::wstring& text);
    void PositionTip(POINT client);
    void ActivateTip();
    void HideTip();
    void OnMouseMove(POINT client);
    int  HitRowForTip(POINT client, int& subItem) const;

    // ---- метрики строки ----
    int  ContentLeft() const;
    int  TextLeft(bool group) const;
    int  GuideX() const;
    int  GlyphCell() const;
    int  BoxSize() const;
    int  IconSize() const;
    int  Scaled(int px) const;
    int  TextHeight(HFONT font = nullptr) const;

    int  MeasureText(const std::wstring& s, bool bold) const;   // с кэшем
    void RecomputeFirstColumnIdeal();                           // -> col0Ideal_
    void AutoSizeFirstColumn();                                 // 2xклик по разделителю
    std::wstring BuildTip(int rowIndex) const;                  // подсказка колонки 0

    // ---- раскладка колонок ----
    // Метрики заголовка зависят только от шрифта, DPI и текста заголовков,
    // поэтому замеряются один раз, а не на каждое изменение размера окна.
    void EnsureHeaderMetrics();
    void InvalidateMetrics();
    void EffectiveMins(int total, int* out) const;   // минимумы с учётом col0Ideal_
    void ComputeWidths(int total, int* out) const;   // пропорционально весам
    // Пакетная запись ширин: пока перерисовка выключена, LVM_SETCOLUMNWIDTH
    // не заставляет список перерисовываться на каждую колонку.
    int  ApplyWidths(const int* w);                  // -> число изменённых колонок
    void SetRedraw(bool on);
    void StoreWeights();                             // веса := применённые ширины
	
	// Строка-группа, к которой относится строка index. Для самой группы
    // возвращает её же, для строки-соединения — её процесс; -1 если не найдена.
    int  GroupRowOf(int index) const;
    const Row& ProcessRow(const Row& row) const;

    // ---- ручное изменение ширины мышью ----
    // Контрол меняет ширину ТОЛЬКО той колонки, за которую тянут, поэтому
    // сумма ширин перестаёт совпадать с шириной окна: колонки уезжают за
    // правый край. Разницу забирают остальные колонки, и сумма снова точно
    // равна клиентской области.
    int  DisplayIndexOf(int col) const;              // фактическая позиция в заголовке
    void SaveColumnOrder();                          // после завершения перестановки
    void TrackRange(int col, int& lo, int& hi);      // допустимые границы при drag
    void BalanceFollowers(int col);                  // живая подгонка соседей справа
    void BalanceManual(int col, int want);           // точная подгонка по отпускании

    // ---- состояние, снимаемое один раз на перерисовку ----
    void EnsureBrushes();
    void ReleaseBrushes();
    bool RowSelected(int index) const;
    COLORREF RowTextColor(const Row& r, bool selected) const;
    // Фон строки. OnNotify явно задаёт его каждому невыделенному подэлементу,
    // чтобы значение не перешло от предыдущей строки. Фон выделения оставляем
    // штатной отрисовке контрола.
    COLORREF RowBackColor(const Row& r, bool selected) const;

    HWND       hwnd_   = nullptr;
    HWND       header_ = nullptr;
    HWND       tip_    = nullptr;
    HINSTANCE  inst_   = nullptr;
    HIMAGELIST spacer_ = nullptr;      // задаёт высоту строки, владелец — мы
    HFONT      bold_   = nullptr;      // раскрытая группа
    HFONT      font_   = nullptr;      // ownedFont_ либо запасной шрифт из кэша UiKit
    HFONT      ownedFont_ = nullptr;   // основной шрифт строк, владелец — мы
    int        iconSize_ = 16;

    ListSkin   skin_    = ListSkin::Classic;
    bool       styled_  = false;       // ApplyStyle уже выполнялся

    std::vector<Row> rows_;
    std::wstring     empty_;
    // Только текст для ListView: исходные значения и копирование остаются без bidi-маркеров.
    std::wstring     displayText_[ColumnCount];

    // состояние подсказки
    std::wstring tipText_;
    int          tipRow_  = -1;        // строка, для которой подсказка показана
    int          pendRow_ = -1;        // строка, ожидающая истечения задержки
    POINT        pendPt_{};
    bool         tipVisible_ = false;
    bool         tracking_   = false;  // подписка на WM_MOUSELEAVE активна

    // Цвета обоих оформлений обновляются в ApplyStyle, а не при рисовании
    // каждой строки; переключение оформления тоже вызывает этот пересчёт.
    COLORREF groupBg_ = 0, dimText_ = 0, guide_ = 0, accent_ = 0;   // Modern
    COLORREF domainText_ = 0;                                       // подпись домена
    COLORREF rule_    = 0;                                          // Classic
    COLORREF boxFill_ = 0, boxEdge_ = 0, boxSign_ = 0;              // общее

    // Кисти отрисовки живут в объекте: прежде они создавались и удалялись
    // на каждую строку каждой перерисовки.
    HBRUSH brGuide_   = nullptr;
    HBRUSH brRule_    = nullptr;
    HBRUSH brBoxFill_ = nullptr;
    HBRUSH brBoxEdge_ = nullptr;
    HBRUSH brBoxSign_ = nullptr;
    bool   brushesValid_ = false;

    int    paddedCol_ = -1;           // последняя колонка с выравниванием вправо, иначе -1
    double weight_[ColumnCount]{};
    int    hdrIdeal_[ColumnCount]{};   // заголовок + место под стрелку
    int    minW_[ColumnCount]{};       // max(минимум колонки, hdrIdeal_)
    bool   metricsValid_ = false;
    bool   fitDirty_     = true;       // требуется пересчёт даже при той же ширине
    int    lastFitWidth_ = -1;
    bool   inFit_        = false;      // ширины меняем мы, а не пользователь
    int    trackCol_     = -1;         // колонка, чей разделитель тянут мышью
    UINT   dpi_          = 96;

    int    col0Ideal_    = 0;      // измеренная потребность колонки «Процесс»
    mutable TextWidthCache textWidths_;

    // Кэш на время одной перерисовки: заполняется в CDDS_PREPAINT и
    // CDDS_ITEMPREPAINT, чтобы не спрашивать контрол об одном и том же
    // по разу на каждую строку.
	int          paintCol0W_ = 0;
    mutable int  paintRow_   = -1;
    mutable bool paintSel_   = false;
    bool         paintThemed_ = true;
    COLORREF     paintPaddedText_ = 0;
};