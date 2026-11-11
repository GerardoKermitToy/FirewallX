#pragma once
#include "Common.h"
#include "Rules.h"
#include "BlockQueue.h"

#include <unordered_set>

enum class AskAction : uint8_t {
    None = 0, Allow, Block, Terminate, Custom, AllowOnce, BlockOnce, Preset
};

struct AskDecision {
    AskAction action = AskAction::None;
    // Правила выбранной предустановки подготовлены для исходного запроса.
    std::vector<Rule> presetRules;
};

// Идентификатор UI-запроса содержит и группу, и поколение источника. Один
// числовой groupId недостаточен: окно старой driver-сессии не должно создавать
// правило или отвечать соединению новой сессии при совпавшем номере группы.
struct AskRequestId {
    uint64_t driverSession = 0;
    uint64_t groupId = 0;
    TrafficSource source = TrafficSource::Host;

    explicit operator bool() const noexcept {
        return driverSession != 0 && groupId != 0;
    }
    bool operator==(const AskRequestId&) const = default;
};

struct AskRequestIdHash {
    size_t operator()(const AskRequestId& id) const noexcept {
        uint64_t h = id.driverSession ^ static_cast<uint64_t>(id.source);
        h ^= id.groupId + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        return static_cast<size_t>(h);
    }
};

// ---------------------------------------------------------------------------
// Соединение, для которого не нашлось правила.
//
// ЕДИНСТВЕННЫЙ источник запроса — событие транспорта on_connection_v4/v6,
// то есть Ingest::Ingress. Таблицы соединений операционной системы
// (GetExtendedTcpTable / GetExtendedUdpTable) запросов не порождают: Monitor
// читает их только для показа списка и сопоставления с УЖЕ существующими
// правилами.
//
// Протокол хранится единственным полем key.proto — это номер протокола IP.
// Отдельного признака «ICMPv6» нет: ICMPv6 — это номер 58.
//
// ---- состав полей ---------------------------------------------------------
//
// Здесь ТОЛЬКО то, что читается: условия сопоставления, сведения для показа
// и ключ обязательства. Полей «на будущее» нет намеренно — каждое из них
// заполнялось на каждое событие транспорта, а значит стоило работы, ничего
// не давая:
//
//   * state (состояние TCP) всегда оставалось нулём: событие транспорта
//     состояния не сообщает, а строки таблиц ОС запросов не порождают;
//   * firstSeen (момент первого обнаружения) не показывался ни в окне
//     запроса, ни в строке состояния, а его подсчёт требовал обращения
//     к счётчику тиков на каждое событие;
//   * pathKnown повторял проверку appPath — путь известен тогда и только
//     тогда, когда строка не пуста.
// ---------------------------------------------------------------------------
struct AskRequest {
    FlowKey      key;
    uint32_t     interfaceIndex = 0;
    // Непустой указатель фиксирует исходное имя; пустая строка — интерфейс
    // неизвестен. Старый запрос не переопределяет имя по текущему индексу.
    std::shared_ptr<const std::wstring> interfaceName;
    DWORD        pid = 0;
    // Общий владелец исходного дескриптора: UI не разрешает службы по новому
    // процессу, которому позднее мог бы достаться тот же PID.
    std::shared_ptr<const ProcessHandleInfo> process;
    pmkext::ProcessLineageRef lineage;
    Dir          dir = Dir::Unknown;
    int          icmpType = -1;         // из payload; -1 = не определён
    int          icmpCode = -1;
    std::optional<uint32_t> conditionFlags;
    bool         ownerAmbiguous = false; // локальный эндпоинт принадлежит разным PID
    std::wstring appPath, appName;
    // Подготовленная копия нужна только пока запрос живёт в UI. Она исключает
    // повторную посимвольную свёртку при проверке созданного правила.
    std::wstring foldedAppPath;
    uint64_t     appPathHash = kFoldedTextHashBasis;
    AskRequestId id;                       // группа + driver-сессия

    bool isIcmp() const     { return ProtoIsIcmp(key.proto); }
    bool isIcmpV6() const   { return ProtoIsIcmpV6(key.proto); }
    bool hasPorts() const   { return ProtoHasPorts(key.proto); }
    uint8_t protoNumber() const { return ProtoNumber(key.proto); }

    std::wstring RemoteText() const;
    std::wstring LocalText() const;
    std::wstring DirPhrase() const;
    // pid попадает в запрос: по нему условие «сервис» определяет состав
    // сервисов процесса.
    MatchQuery   ToQuery() const;
};

// Заготовки для наследующего процесса создаются в группе выбранного предка,
// иначе новое собственное правило было бы заведомо проигнорировано. Исходный
// запрос, его PID, отображение и обязательство не меняются.
AskRequest RequestForRuleCreation(const AskRequest& request, const RuleStore& rules);

// Хэш кандидатов pending-группы включает ВСЕ поля MatchQuery: PID, путь,
// протокол, направление, оба адреса, оба порта, тип/код ICMP и признак
// неоднозначного владельца, а также исходную маску WFP. Любое правило либо покрывает всю группу,
// либо не покрывает её вовсе.
//
// Сам хэш НЕ является идентификатором группы: Ingest выполняет структурное
// сравнение кандидатов и выдаёт отдельный AskRequestId. В нём есть монотонный
// номер группы и поколение driver-сессии, поэтому ни коллизия хэша, ни старое
// окно не смешивают чужие обязательства.
//
// appPath — ПРЕДСТАВЛЕНИЕ, а не копия: хэш нужен при парковке обязательства
// после промаха правил, и копировать путь для него не требуется.
uint64_t AskHash(std::wstring_view appPath, DWORD pid, const FlowKey& k, Dir dir,
                 int icmpType = -1, int icmpCode = -1,
                 bool ownerAmbiguous = false, uint32_t interfaceIndex = 0,
                 const std::wstring* interfaceName = nullptr,
                 std::optional<uint32_t> conditionFlags = std::nullopt);
uint64_t AskHashPrepared(uint64_t foldedAppPathHash, DWORD pid,
                         const FlowKey& k, Dir dir,
                         int icmpType = -1, int icmpCode = -1,
                         bool ownerAmbiguous = false, uint32_t interfaceIndex = 0,
                         const std::wstring* interfaceName = nullptr,
                         std::optional<uint32_t> conditionFlags = std::nullopt);
// ---------------------------------------------------------------------------
// Заготовка правила по одному наблюдаемому потоку.
//
// Отделена от AskRequest намеренно: строку списка соединений разрешено
// превратить в ЗАГОТОВКУ правила по явной команде пользователя, но запросом
// решения она стать не может.
// ---------------------------------------------------------------------------
struct FlowRuleSeed {
    FlowKey      key;
    uint32_t     interfaceIndex = 0;
    std::shared_ptr<const std::wstring> interfaceName;
    Dir          dir = Dir::Unknown;
    int          icmpType = -1;      // -1 => условие «тип ICMP» не ставится
    int          icmpCode = -1;
    std::optional<uint32_t> conditionFlags;
    DWORD        pid = 0;            // только для заготовки условия «сервис»
    std::wstring appPath;            // пусто => PostApp, иначе группа приложения
    std::wstring appName;
};

// Без пути автоматическое правило попадает в PostApp, а не в Global.
Rule MakeNarrowRule(const FlowRuleSeed& seed, RuleAction action);

Rule              MakeAllowRule(const AskRequest& r);
Rule              MakeBlockRule(const AskRequest& r);
// «Завершить»: при известном пути одно правило закрывает приложению всю сеть;
// без пути создаётся узкое правило только для наблюдаемой активности.
std::vector<Rule> MakeBlockAllRules(const AskRequest& r);
Rule              MakeEditorTemplate(const AskRequest& r);

// ---------------------------------------------------------------------------
// Очередь показа запросов решения.
//
// ---- очередь НЕ владеет обязательствами -----------------------------------
//
// Владелец припаркованных обязательств один — Ingest. Прежде очередь держала
// ПОЛНУЮ КОПИЮ AskRequest каждого запроса, то есть путь и имя процесса
// хранились дважды: в группе Ingest и здесь. Теперь очередь хранит только
// AskRequestId и метку паузы, а сам запрос запрашивается у Ingest в момент
// показа. Обязательство от этого не может «потеряться в очереди»: очередь —
// лишь порядок показа.
//
// Запись выбывает из очереди ровно в трёх случаях:
//   * запрос показан (Pop) — дальше он либо закрыт правилом, либо возвращён
//     сюда через Postpone;
//   * обязательство закрыто правилом/политикой (Discard / Prune) — уже отвечено;
//   * группы больше нет в Ingest — она закрыта либо завершилась driver-сессия.
//
// Ни пределов длины, ни срока хранения, ни вытеснения здесь нет: запрос ждёт
// решения пользователя столько, сколько потребуется.
// ---------------------------------------------------------------------------
class AskQueue {
public:
    // Пауза перед повторным показом отложенного запроса. Обязательство при
    // этом не отменяется: соединение продолжает ждать вердикта.
    static constexpr ULONGLONG kPostponeMs = 15 * 1000;

    bool   Push(const AskRequest& r);        // принимает только обязательства
    bool   Pop(AskRequest& out);             // пропускает отложенные
    void   Postpone(const AskRequest& r);    // вернуть в очередь с паузой
    void   MakeAllReady();                   // снять паузу перед завершением
    void   Discard(AskRequestId id);         // обязательство урегулировано
    // Синхронизация с Ingest: убрать запросы закрытых групп, в том числе после
    // решения правилом/политикой или завершения driver-сессии. Достаточно
    // проверить, осталась ли группа припаркованной.
    void   Prune();

    size_t size() const  { return q_.size(); }
    bool   contains(AskRequestId id) const { return in_.contains(id); }
    size_t ready() const;                    // можно показать прямо сейчас
    size_t held() const  { return q_.size() - ready(); }
    bool   empty() const { return q_.empty(); }

private:
    friend struct AskQueueTestAccess;
    // 24 байта на запрос вместо копии AskRequest со строками.
    struct Item {
        AskRequestId id;
        ULONGLONG holdUntil = 0;
    };

    BlockQueue<Item> q_;
    std::unordered_set<AskRequestId, AskRequestIdHash> in_;
};