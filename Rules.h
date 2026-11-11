#pragma once
#include "Common.h"
#include "MacroAddr.h"
#include "ServiceInfo.h"
#include "SnapshotArray.h"
#include "DebugCounters.h"
#include "NumericHash.h"
#include "ProcessEvents.h"
#include "network_interface_watcher.h"
#include <atomic>
#include <memory>
#include <optional>
#include <mutex>
#include <string_view>
#include <unordered_map>

class RuleDb;
struct ProcessHandleInfo;

// ---------------------------------------------------------------------------
// Условия правила.
//
// CondProto появился вместе с поддержкой любых номеров протокола: раньше
// протокол проверялся ВСЕГДА, потому что значений было три. Теперь снятое
// условие означает «любой протокол» — без него невозможно одним правилом
// закрыть приложению всю сеть (256 номеров перечислять бессмысленно).
//
// CondService проверяет НЕ путь, а состав сервисов процесса: один svchost.exe
// обслуживает несколько сервисов, поэтому правило приложения их не различает.
// Условие выполняется, когда ВСЕ сервисы, обслуживаемые данным pid, указаны
// в правиле (см. RuleStore::MatchServices). Условие не зависит от протокола
// и применимо к любому правилу, включая глобальное.
// ---------------------------------------------------------------------------
enum RuleCond : uint32_t {
    CondNone       = 0,
    CondDirection  = 1u << 0,
    CondRemoteAddr = 1u << 1,
    CondRemotePort = 1u << 2,
    CondLocalAddr  = 1u << 3,
    CondLocalPort  = 1u << 4,
    CondIcmpType   = 1u << 5,      // только для протоколов ICMP / ICMPv6
    CondProto      = 1u << 6,      // снят => правило подходит любому протоколу
    CondService    = 1u << 7,      // состав сервисов процесса
    CondPidZero    = 1u << 8,      // PID 0, только для группы PostApp; снят => любой PID
    CondInterface  = 1u << 9,      // точное имя интерфейса, кроме группы Interface
    CondWfpFlags   = 1u << 10,     // все выбранные биты исходной маски WFP
};

// Действие правила бинарно: разрешить либо блокировать.
enum class RuleAction : uint8_t { Allow = 0, Block = 1 };

// Элемент списка адресов: либо конкретный адрес/подсеть, либо макро-адрес,
// содержимое которого определяется конфигурацией сети в момент сопоставления.
struct AddrItem {
    IpAddr    addr;
    int       prefix = -1;
    AddrMacro macro = AddrMacro::None;

    bool isMacro() const { return macro != AddrMacro::None; }
    bool operator==(const AddrItem& other) const;
    bool Matches(const IpAddr& a) const;
    std::wstring Text() const;        // для интерфейса: «DNS_SERVERS», «10.0.0.0/8»
    std::wstring Token() const;       // для базы: «@DNS_SERVERS», «10.0.0.0/8»
};

struct PortItem {
    uint16_t from = 0, to = 0;
    bool Contains(uint16_t p) const { return p >= from && p <= to; }
    std::wstring Text() const;          // «443», «5000-5010», «HTTP»
};

// Тип ICMP; code < 0 — любой код данного типа
struct IcmpTypeItem {
    uint8_t type = 0;
    int     code = -1;

    bool Matches(int t, int c) const {
        if (t < 0 || t != static_cast<int>(type)) return false;
        if (code < 0) return true;
        return c == code;
    }
    std::wstring Text(bool v6) const;   // «Echo Request», «3:1», «42»
};

// ---------------------------------------------------------------------------
// Сервис Windows в условии правила.
//
// Хранится ключ сервиса (lpServiceName) или маска со знаком «*» для любого
// количества символов. Отображаемое имя зависит от языка и версии ОС, поэтому
// в базу оно не пишется, а запрашивается у диспетчера служб при показе.
// ---------------------------------------------------------------------------
bool ServiceNameMatches(std::wstring_view pattern, std::wstring_view name);

struct ServiceItem {
    std::wstring name;
    std::wstring display;               // только для интерфейса

    bool Matches(const std::wstring& svc) const;
    std::wstring Text() const;          // «Dnscache»
    std::wstring FullText() const;      // «Dnscache — DNS-клиент»
};

enum class RuleScope : uint8_t { App = 0, Global = 1, PostApp = 2, Interface = 3 };

// Настройка приложения, не условие отдельного правила. Default не создаёт
// исключения; Never запрещает наследование только самому этому приложению.
enum class RuleInheritance : uint8_t { Default = 0, Enabled = 1, Never = 2, EnabledAndNever = 3 };

inline bool RuleInheritanceEnabled(RuleInheritance mode) {
    return (static_cast<uint8_t>(mode) & 1) != 0;
}
inline bool RuleInheritanceBlocked(RuleInheritance mode) {
    return (static_cast<uint8_t>(mode) & 2) != 0;
}

struct AppInheritanceSetting {
    std::wstring appPath;
    RuleInheritance mode = RuleInheritance::Default;
};

struct Rule {
    uint64_t     id = 0;
    std::wstring name;
    bool         autoName = true;
    RuleScope    scope = RuleScope::App;
    std::wstring appPath; // Путь приложения либо точное имя интерфейса для scope Interface.
    std::wstring appName;
    bool         enabled = true;
    int          priority = 0;          // 0 — самый важный внутри своей группы

    uint32_t     conds = CondProto;     // по умолчанию протокол — условие
    Proto        proto = Proto::Tcp;    // номер протокола IP, 0..255
    Dir          dir = Dir::Out;
    RuleAction   action = RuleAction::Allow;

    std::vector<AddrItem>     remoteAddrs, localAddrs;
    std::vector<PortItem>     remotePorts, localPorts;
    std::vector<IcmpTypeItem> icmpTypes;
    std::vector<ServiceItem>  services;
    std::wstring interfaceName;         // только имя; индексы живут в RuleStore
    uint32_t     conditionFlags = 0;    // требуемые FWP_CONDITION_FLAG_*, без потери неизвестных битов

    bool isGlobal() const    { return scope == RuleScope::Global; }
    bool isPostApp() const   { return scope == RuleScope::PostApp; }
    bool isInterface() const    { return scope == RuleScope::Interface; }
    bool blocks() const      { return action != RuleAction::Allow; }
    bool protoFixed() const  { return (conds & CondProto) != 0; }

    // Свойства протокола имеют смысл только когда протокол задан условием:
    // у правила «любой протокол» ни портов, ни типа ICMP быть не может.
    bool isIcmp() const   { return protoFixed() && ProtoIsIcmp(proto); }
    bool isIcmpV6() const { return protoFixed() && ProtoIsIcmpV6(proto); }
    bool hasPorts() const { return protoFixed() && ProtoHasPorts(proto); }

    // Значение условия меняется без изменения самого правила: макро-адрес
    // разрешается по текущей конфигурации сети, а состав сервисов — по
    // текущему состоянию диспетчера служб. Решения по таким правилам
    // кешировать нельзя (см. RuleStore::volatileConds).
    bool hasVolatileConds() const;

    // Значений всего два, поэтому щелчок по ссылке в расшифровке правила
    // переключает их напрямую — отдельный диалог выбора был лишним шагом.
    void ToggleAction() {
        action = blocks() ? RuleAction::Allow : RuleAction::Block;
    }
    void ToggleDirection() {
        dir = (dir == Dir::In) ? Dir::Out : Dir::In;
    }

    // Задать протокол, нормализовать условия и очистить несовместимые списки.
    void SetProto(Proto p, bool fixed = true);

    std::wstring ProtoText() const;      // «TCP», «ICMPv6», «144»
    std::wstring ProtoCondText() const;  // то же либо «любой»
    std::wstring DirTextRu() const;
    std::wstring ActionTextRu() const;
    std::wstring ScopeTextRu() const;
    std::wstring AddrsText(bool remote) const;
    std::wstring PortsText(bool remote) const;
    std::wstring IcmpTypesText() const;
    std::wstring ServicesText() const;   // «Dnscache, W32Time» либо «любой»
    std::wstring PidText() const;        // «0» при CondPidZero, иначе «любой»
    std::wstring ConditionFlagsText() const;
    std::wstring BuildAutoName() const;
    void         SyncName();
};

// Ссылка на имя совпавшего правила: при выключенной диагностике она пустая,
// а при включённой позволяет передать одну неизменяемую строку через кеши.
using RuleNameRef = std::shared_ptr<const std::wstring>;

// Компактный результат для списка соединений. В отличие от Rule, не копирует
// векторы условий при каждом секундном обновлении.
struct RuleMatchInfo {
    uint64_t     id = 0;
    std::wstring name;
    RuleScope    scope = RuleScope::App;
    RuleAction   action = RuleAction::Allow;

    bool isGlobal() const { return scope == RuleScope::Global; }
};

// Удаляет повторяющиеся адреса, подсети и макросы, сохраняя порядок первых записей.
void DeduplicateAddresses(std::vector<AddrItem>& items);
// Снимает условия, потерявшие смысл: порты у протокола без портов, тип ICMP
// у не-ICMP, оба — у правила «любой протокол». Удаляет дубликаты адресов;
// остальные значения списков сохраняются. CondPidZero снимается вне PostApp.
// Условие интерфейса снимается в группе Interface; имя этой группы уже задано.
// Условие «сервис» не затрагивается.
void NormalizeRuleConds(Rule& r);
// Маска условий, реально проверяемая matcher-ом (в том числе двусторонние Allow).
uint32_t EffectiveRuleConds(const Rule& r);

// ---------------------------------------------------------------------------
// Условия сопоставления.
//
// appPath — ПРЕДСТАВЛЕНИЕ, а не копия: сопоставление выполняется на каждое
// событие транспорта, и выделение памяти под путь было там самой дорогой
// операцией. Отсюда требование к вызывающему: строка-источник обязана быть
// жива всё время вызова Match / MatchVerdict. Во всех точках вызова это так —
// путь принадлежит либо событию/группе Ingest (Flow::app),
// либо строке списка (ProcItem::path), либо запросу (AskRequest::appPath).
// ---------------------------------------------------------------------------
struct MatchQuery {
    TrafficSource source = TrafficSource::Host;
    uint32_t interfaceIndex = 0;
    // nullopt — поле отсутствует (NDIS или только таблицы ОС); 0 — исходная маска WFP.
    std::optional<uint32_t> conditionFlags;
    // nullptr — текущее событие, поиск по индексу. Pending и строки монитора
    // удерживают исходное имя; пустое имя запрещает новый поиск по индексу.
    const std::wstring* interfaceName = nullptr;
    // Пустой путь означает «приложение неизвестно». При активном наследовании
    // RuleStore может взять готовый путь исходного экземпляра из ProcessTable.
    // Глобальные правила и PostApp не привязаны к пути. В PostApp PID
    // ограничивается только явно включённым условием CondPidZero.
    std::wstring_view appPath;
    // Для пути процесса вызывающий обычно уже имеет неизменяемую свёрнутую
    // строку и её хэш. Если preparedAppPath=false, RuleStore оставляет
    // совместимый редкий путь и готовит ключ сам.
    std::wstring_view foldedAppPath;
    uint64_t appPathHash = kFoldedTextHashBasis;
    bool     preparedAppPath = false;
    // Владелец соединения. CondPidZero проверяет только равенство нулю.
    // Также нужен условию «сервис»: состав сервисов
    // ищется по pid; дескриптор ниже подтверждает исходный экземпляр процесса.
    // 0 — владелец неизвестен (пакетный уровень WFP), условие «сервис» не выполняется.
    DWORD    pid = 0;
    // Заимствованный дескриптор исходного экземпляра процесса. Источник запроса
    // удерживает общего владельца на всё время Match / MatchVerdict. Без живого
    // дескриптора сервисное условие не выполняется, остальные условия независимы.
    const ProcessHandleInfo* process = nullptr;
    // Заимствованное родство исходного pending; его владельцем остаётся Flow/AskRequest.
    const pmkext::ProcessLineage* lineage = nullptr;
    Proto    proto = Proto::Tcp;   // номер протокола IP из события/таблицы
    Dir      dir = Dir::Out;
    IpAddr   localAddr, remoteAddr;
    uint16_t localPort = 0, remotePort = 0;
    int      icmpType = -1;        // -1 = тип не определён (payload отсутствовал)
    int      icmpCode = -1;
};

// ---------------------------------------------------------------------------
// Единственная точка сборки условий сопоставления.
//
// Прежде это отображение существовало в трёх копиях (Ingest::Flow::ToQuery,
// AskRequest::ToQuery, Monitor::Refresh), и любое новое поле приходилось
// добавлять трижды — то есть рано или поздно не добавить куда-нибудь.
//
// appPath — представление: строка-источник обязана быть жива на время вызова
// Match / MatchVerdict.
// ---------------------------------------------------------------------------
inline MatchQuery MakeMatchQuery(std::wstring_view appPath, DWORD pid,
                                 const FlowKey& k, Dir dir,
                                 int icmpType = -1, int icmpCode = -1,
                                 const ProcessHandleInfo* process = nullptr,
                                 std::optional<uint32_t> conditionFlags = std::nullopt) {
    MatchQuery q;
    q.source     = k.source;
    q.interfaceIndex = k.interfaceIndex;
    q.conditionFlags = conditionFlags;
    q.appPath    = appPath;
    q.pid        = pid;
    q.process    = process;
    q.proto      = k.proto;
    q.dir        = dir;
    q.localAddr  = k.local;
    q.remoteAddr = k.remote;
    q.localPort  = k.lport;
    q.remotePort = k.rport;
    q.icmpType   = icmpType;
    q.icmpCode   = icmpCode;
    return q;
}

inline void PrepareMatchAppPath(MatchQuery& q,
                                std::wstring_view foldedAppPath,
                                uint64_t appPathHash) {
    q.foldedAppPath = foldedAppPath;
    q.appPathHash = appPathHash;
    q.preparedAppPath = true;
}

struct AppInterfaceSetting {
    std::wstring appPath;
    std::wstring interfaceName;
    bool blockOtherInterfaces = false;
};

struct AppEntry {
    std::wstring path, name;
    size_t rules = 0, enabled = 0;
    bool   global = false;
    bool   postapp = false;
    bool   interfaceGroup = false;
    bool   active = true;
};

// ---------------------------------------------------------------------------
// Уведомление о правках набора правил.
//
// Вызывается на КАЖДОЕ создание, изменение и удаление правила, ровно один раз
// на затронутое правило. При первоначальной загрузке из базы
// (AttachDatabase / LoadOnce) не вызывается: там набор не меняется, а лишь
// восстанавливается.
//
// Вызов выполняется ВНЕ мьютекса RuleStore, поэтому обработчик может свободно
// обращаться к хранилищу.
// ---------------------------------------------------------------------------
enum class RuleChange : uint8_t {
    Added = 0,      // правило создано
    Modified,       // изменены условия, действие либо признак «включено»
    Removed,        // правило удалено; в rule — его последнее состояние
    Reordered,      // изменён приоритет (порядок проверки) внутри группы
};

void notify_rule_changed(RuleChange change, uint64_t ruleId, const Rule& rule);

class RuleStore {
public:
    explicit RuleStore(const pmkext::ProcessTable& processes = pmkext::ProcessTable::Instance());
    ~RuleStore();

    // Постоянное подключение: правила читаются и файл остаётся открытым,
    // каждое изменение сразу перезаписывает таблицу. Оконный режим.
    bool AttachDatabase(const std::wstring& path, std::wstring& error);

    // Однократное чтение: файл открывается, правила загружаются в память,
    // файл ЗАКРЫВАЕТСЯ. Дальше хранилище работает только на чтение — записи
    // некуда идти, SaveLocked() становится пустой операцией. Служебный режим.
    bool LoadOnce(const std::wstring& path, std::wstring& error);

    void DetachDatabase();              // закрыть файл, правила оставить
    bool attached() const;
    bool readOnly() const;              // база не подключена => запись невозможна
    const std::wstring& dbPath() const  { return dbPath_; }
    std::wstring dbError() const;

    uint64_t Add(Rule& r);
    // Пакетно добавляет отсутствующие правила приложений и группы PostApp.
    // Равнозначность задаёт вызывающий; существующие правила не изменяются.
    size_t AddMissingRules(std::vector<Rule> rules, bool (*same)(const Rule&, const Rule&));
    bool     Update(const Rule& r);
    bool     Remove(uint64_t id);
    // scope обязателен: у групп без пути (Global, PostApp) appPath пуст, и
    // поиск по одному пути удалил бы правило из чужой группы.
    bool     RemoveByName(RuleScope scope, const std::wstring& appPath,
                          const std::wstring& name);
    void     RemoveApp(const std::wstring& appPath);
    // Удаляет правила и настройки отсутствующих приложений; возвращает число записей.
    size_t   RemoveMissingApps();
    void     RemoveGlobals();
    void     RemovePostApps();
    bool     SetEnabled(uint64_t id, bool on);
    bool     MovePriority(uint64_t id, int delta);
    bool     Get(uint64_t id, Rule& out) const;
    bool     GetInfo(uint64_t id, RuleMatchInfo& out) const;
    bool     Exists(uint64_t id) const;
    bool     FindByName(const std::wstring& appPath, const std::wstring& name,
                        Rule& out) const;
    bool     FindGlobalByName(const std::wstring& name, Rule& out) const;

    void Replace(RuleScope scope, const std::wstring& appPath,
                 const std::wstring& appName, std::vector<Rule> list);
    void ReplaceApp(const std::wstring& appPath, const std::wstring& appName,
                    std::vector<Rule> list) {
        Replace(RuleScope::App, appPath, appName, std::move(list));
    }
    void ReplaceGlobals(std::vector<Rule> list) {
        Replace(RuleScope::Global, std::wstring(), std::wstring(), std::move(list));
    }
    void ReplacePostApps(std::vector<Rule> list) {
        Replace(RuleScope::PostApp, std::wstring(), std::wstring(), std::move(list));
    }

    std::vector<Rule>     All() const;
    std::vector<Rule>     ForApp(const std::wstring& appPath) const;
    std::vector<Rule>     Globals() const;
    std::vector<Rule>     PostApps() const;
    std::vector<Rule>     InterfaceRules(const std::wstring& name) const;
    std::vector<AppEntry> Apps() const;
    std::vector<AppEntry> Interfaces() const;
    // Сообщение отправляется после обновления групп, без вызова UI из worker.
    static constexpr UINT kInterfacesChanged = WM_APP + 176;
    void WatchInterfaces(HWND window, bool enable);
    uint64_t interfaceVersion() const;
    size_t   Count() const;
    void ReadDebugCounters(DebugCounters::Snapshot& out) const;
    size_t   GlobalCount() const;
    size_t   PostAppCount() const;
    void     Clear();

    // Полное сопоставление: копирует найденное правило. Нужно редакторам и
    // редким UI-действиям, где требуются все условия.
    bool Match(const MatchQuery& q, Rule& out) const;
    // Проверка заготовки без добавления в хранилище: предустановки используют
    // те же условия и семантику служб, что и обычные правила.
    static bool MatchesRule(const Rule& rule, const MatchQuery& q);
    // Для однократного решения без сохраняемой группы проверяются все условия,
    // но не привязка к приложению/интерфейсу.
    static bool MatchesRuleConditions(const Rule& rule, const MatchQuery& q);

    // Для списка соединений: копирует только поля, которые действительно
    // отображаются, без строк и векторов условий полного Rule. Monitor передаёт
    // includeName=false и получает имя лениво лишь для раскрытой строки.
    bool MatchInfo(const MatchQuery& q, RuleMatchInfo& out,
                   bool includeName = true) const;

    // ---------------------------------------------------------------------
    // Горячий путь вердиктов.
    //
    // Возвращает ТОЛЬКО действие: правило не копируется. Копия Rule — это
    // шесть векторов и четыре строки с возможными вложенными выделениями
    // памяти, которые не нужны на пути «событие транспорта -> process_verdict».
    // Ненулевой matchedRuleName нужен только
    // редкому диагностическому пути и получает имя найденного правила.
    // Имя передаётся через shared_ptr, чтобы кеши не копировали строку.
    bool MatchVerdict(const MatchQuery& q, RuleAction& action,
                      RuleNameRef* matchedRuleName = nullptr) const;
    // Версия считывается под тем же мьютексом, что и индекс правил: вызывающий
    // может проверить, не изменился ли набор до применения результата.
    bool MatchVerdict(const MatchQuery& q, RuleAction& action,
                      uint64_t& matchedVersion,
                      RuleNameRef* matchedRuleName = nullptr,
                      std::shared_ptr<const std::wstring>* unmatchedInterfaceName = nullptr,
                      bool* preferredInterfaceBlocked = nullptr) const;

    // Среди ВКЛЮЧЁННЫХ правил есть условие, значение которого меняется без
    // изменения самого правила: макро-адрес (конфигурация сети) либо сервис
    // (состояние диспетчера служб). Пока это так, кешировать решения по форме
    // соединения нельзя — см. Ingest.
    bool volatileConds() const;
    // Нужен оконному потоку, чтобы перепроверять pending-группы при изменении
    // состава сервисов без искусственной правки набора правил.
    bool serviceConds() const;
    // Нужен UI для периодической сверки версии значений макро-адресов.
    bool macroConds() const;

    // Внешние кеши учитывают также изменения родства, когда оно влияет на правила.
    uint64_t version() const;
    bool inheritanceConds() const { return inheritanceUsed_.load(std::memory_order_relaxed); }
    RuleInheritance GetInheritance(std::wstring_view appPath) const;
    bool SetInheritance(const std::wstring& appPath, RuleInheritance mode);
    static bool CanSetInheritance(std::wstring_view appPath, DWORD pid = MAXDWORD);

    // Пустое имя — обычная маршрутизация. Флажок хранится независимо от имени.
    // Предпочтение принадлежит EXE и никогда не берётся у предка процесса.
    std::wstring GetPreferredInterface(std::wstring_view appPath) const;
    bool GetBlockOtherInterfaces(std::wstring_view appPath) const;
    bool SetPreferredInterface(const std::wstring& appPath, const std::wstring& name,
                               std::optional<bool> blockOtherInterfaces = std::nullopt);
    bool PreferredInterfaceBlocked(const MatchQuery& query, uint64_t& matchedVersion) const;
    bool preferredInterfaceConds() const { return appInterfacesUsed_.load(std::memory_order_relaxed); }
    using AppInterfaceHandler = std::function<bool(const std::wstring&, uint64_t)>;
    void SetAppInterfaceHandler(AppInterfaceHandler handler,
                                std::function<bool()> enableRoutePolicies = {});
    // Новый transport повторяет все предпочтения до начала приёма соединений.
    // Служба при проксировании desktop отключает применение своего старого снимка.
    void SetAppInterfacesActive(bool active);

    // Пусто => собственная группа. Непустой результат полностью заменяет её,
    // даже когда у выбранного предка нет подходящих или включённых правил.
    pmkext::ProcessRuleSource InheritedSource(const MatchQuery& query) const;
    pmkext::ProcessLineageRef RetainProcess(DWORD pid) const { return processes_.retain(pid); }

private:
    friend struct StorageTestAccess;
    // Отложенное уведомление: собирается под мьютексом, рассылается после его
    // освобождения (см. Fire / комментарий к notify_rule_changed).
    struct Change { RuleChange kind; Rule rule; };
    using Changes = std::vector<Change>;

    static void Fire(const Changes& list);

    // ---------------------------------------------------------------------
    // Ленивое разрешение состава сервисов процесса.
    //
    // Чтение опубликованного ServiceInfo runtime-снимка выполняется ТОЛЬКО
    // если проверка реально дошла до правила с условием «сервис». Прежде список
    // запрашивался в начале каждого Match, если хотя бы одно правило набора
    // упоминало сервисы, — и копировался целиком.
    // ---------------------------------------------------------------------
    struct Hosted {
        DWORD pid = 0;
        const ProcessHandleInfo* process = nullptr;
        bool  resolved = false;
        ServiceInfo::HostedServices list;
        std::wstring_view inheritedPath;
        const std::vector<ServiceEntry>& Get();
    };

    // Скомпилированный кандидат: всё, что нужно для ДЕШЁВОГО отказа, без
    // обращения к большому объекту Rule. 16 байт, включая индекс фильтра.
    // conds — эффективная маска: направление разрешающего TCP/UDP-правила
    // с заданным IP или портом снимается здесь, но сохраняется в самом Rule.
    struct Cand {
        uint32_t idx = 0;          // позиция в rules_
        uint32_t interfaceFilter = 0; // позиция + 1; 0 — без фильтра
        uint16_t conds = 0;
        uint8_t  proto = 0;
        uint8_t  dir = 0;
        // Только внешние границы списка: разрывы проверяет MatchPorts.
        uint16_t remotePortFirst = 0;
        uint16_t remotePortLast = UINT16_MAX;
    };
    static_assert(sizeof(Cand) == 16);
    // Правила одного приложения. Список нужен потому, что ключ карты —
    // хэш пути: совпадение хэшей разных путей маловероятно, но возможно.
    struct AppBucket {
        // Коллизия 64-битного хэша проверяется точным сравнением уже свёрнутых
        // строк; повторный towupper на каждом соединении не нужен.
        std::wstring foldedPath;
        std::span<const Cand> items;
    };

    static bool MatchAddrs(const std::vector<AddrItem>& v, const IpAddr& a);
    static bool MatchPorts(const std::vector<PortItem>& v, uint16_t p);
    static bool MatchIcmp(const std::vector<IcmpTypeItem>& v, int type, int code);
    // hosted — сервисы, которые обслуживает процесс
    static bool MatchServices(const std::vector<ServiceItem>& v,
                              const std::vector<ServiceEntry>& hosted);
    // Протокол и направление уже проверены по Cand в FindLocked.
    static bool MatchRemainingConds(const Rule& r, const MatchQuery& q, Hosted& hosted);
    static bool SameGroup(const Rule& a, const Rule& b);

    // Чтение по ID выполняется под мьютексом и включает выключенные правила.
    const Rule* FindByIdLocked(uint64_t id) const;
    // Единственная точка поиска: и Match, и MatchVerdict работают через неё.
    const Rule* FindLocked(const MatchQuery& q, Hosted& hosted) const;
    std::span<const Cand> FindAppLocked(const MatchQuery& q) const;
    void RebuildIndexLocked();
    void RefreshInterfaces() const;
    void SyncInterfacesLocked() const;
    void RebuildInterfaceIndexLocked() const;
    struct InterfaceFilter {
        std::wstring name;
        uint32_t index = 0, ipv6Index = 0;
        bool Matches(const MatchQuery& query) const;
    };
    static InterfaceFilter ResolveInterfaceFilter(
        const std::wstring& name, const net::NetworkInterfaceWatcher::SnapshotPtr& snapshot);
    mutable std::vector<InterfaceFilter> interfaceFilters_;
    struct InterfaceGroup {
        std::wstring name;
        uint32_t index = 0, ipv6Index = 0;
        size_t rules = 0, enabled = 0;
        std::span<const Cand> items;
    };
    mutable std::vector<InterfaceGroup> interfaces_;
    mutable std::unordered_map<uint32_t, std::span<const Cand>> idxInterface_;
    std::vector<HWND> interfaceWindows_;
    mutable std::atomic<uint64_t> interfaceVersion_{1};
    mutable std::atomic<uint64_t> interfaceSnapshotVersion_{0};
    uint64_t interfaceSubscription_ = 0;
    RuleInheritance InheritanceLocked(std::wstring_view path, uint64_t hash) const;
    pmkext::ProcessRuleSource InheritedSourceLocked(const MatchQuery& query) const;
    std::vector<AppInheritanceSetting> InheritanceSettingsLocked() const;
    void LoadInheritanceLocked(std::vector<AppInheritanceSetting> settings);
    void InheritanceChangedLocked();
    void SyncProcessVersionLocked() const;
    struct AppInterfacePreference {
        AppInterfaceSetting setting;
        std::wstring foldedPath;
        bool available = false;
        bool applied = false;
        uint64_t luid = 0;
        uint64_t appliedLuid = 0;
        uint32_t index = 0;
        uint32_t ipv6Index = 0;
    };
    std::vector<AppInterfaceSetting> AppInterfaceSettingsLocked() const;
    void UpdateAppInterfacesUsedLocked();
    void LoadAppInterfacesLocked(std::vector<AppInterfaceSetting> settings);
    bool SyncAppInterfacesLocked(const net::NetworkInterfaceWatcher::SnapshotPtr& snapshot) const;
    void ApplyAppInterfacesLocked() const;
    void ResetAppInterfaceLocked(const std::wstring& appPath);
    bool RemoveAppInterfaceLocked(std::wstring_view appPath);
    enum class AppInterfaceBlock { None, Unavailable, OtherInterface };
    AppInterfaceBlock PreferredInterfaceBlockedLocked(const MatchQuery& query) const;
    mutable std::unordered_map<uint64_t, std::vector<AppInterfacePreference>, PreparedHash64> appInterfaces_;
    mutable std::vector<std::wstring> appInterfaceResets_;
    AppInterfaceHandler appInterfaceHandler_;
    std::function<bool()> enableRoutePolicies_;
    mutable bool routePoliciesAttempted_ = false;
    mutable bool routePoliciesReady_ = false;
    std::atomic<bool> appInterfacesUsed_{false};
    bool appInterfacesActive_ = false;
    Rule unavailableInterfaceRule_;
    RuleNameRef unavailableInterfaceRuleName_;
    Rule otherInterfaceRule_;
    RuleNameRef otherInterfaceRuleName_;

    void NormalizeLocked();
    void SaveLocked(bool rebuildIndex = true);
    int  MaxPriorityLocked(const Rule& r) const;

    const pmkext::ProcessTable& processes_;
    mutable std::mutex    mtx_;
    std::vector<Rule>     rules_;
    uint64_t              nextId_ = 1;
    mutable std::atomic<uint64_t> version_{ 1 };
    mutable std::atomic<uint64_t> processVersion_{ 0 };
    std::atomic<bool> inheritanceUsed_{ false };
    uint64_t inheritanceGeneration_ = 0;
    // Готовый хэш пути исключает его повторную свёртку на сетевом событии.
    // Точное сравнение в корзине защищает от коллизии хэша.
    std::unordered_map<uint64_t, std::vector<AppInheritanceSetting>, PreparedHash64> inheritance_;

    // ID -> позиция: все правила, включая выключенные. Позиции обновляются
    // вместе с индексом сопоставления после сортировки или изменения rules_.
    std::unordered_map<uint64_t, size_t> idxId_;

    // Индекс сопоставления. Содержит только ВКЛЮЧЁННЫЕ правила, поэтому
    // проверка «включено» из горячего пути ушла совсем. Перестраивается
    // при каждой правке набора — то есть по действию пользователя, а не
    // по событию сети.
    // Один точный массив для всех включённых кандидатов. Группы хранят лишь
    // диапазоны: нет отдельных резервов Global/PostApp и массивов на приложение.
    // Неизменяемые имена по позиции в rules_: горячий путь только копирует ссылку.
    SnapshotArray<RuleNameRef>                           idxRuleNames_;
    SnapshotArray<Cand>                                  idxCandidates_;
    std::span<const Cand>                                idxGlobal_;
    std::unordered_map<uint64_t, std::vector<AppBucket>, PreparedHash64> idxApp_;
    std::span<const Cand>                                idxPostApp_;
    bool                                                  servicesUsed_ = false;
    bool                                                  macrosUsed_ = false;
    bool                                                  volatileConds_ = false;

    std::unique_ptr<RuleDb> db_;
    std::wstring            dbPath_;
    mutable std::wstring    dbErr_;
};

namespace RuleClipboard {
    void Set(const Rule& r);
    bool Get(Rule& out);
    bool Has();
}

namespace RuleLink {
    inline constexpr wchar_t kProto[]    = L"proto";
    inline constexpr wchar_t kDir[]      = L"dir";      // переключатель, не диалог
    inline constexpr wchar_t kRAddr[]    = L"raddr";
    inline constexpr wchar_t kRPort[]    = L"rport";
    inline constexpr wchar_t kLAddr[]    = L"laddr";
    inline constexpr wchar_t kLPort[]    = L"lport";
    inline constexpr wchar_t kIcmpType[] = L"icmptype";
    inline constexpr wchar_t kInterface[] = L"interface";
    inline constexpr wchar_t kWfpFlags[]  = L"wfpflags";
    inline constexpr wchar_t kService[]  = L"service";
    inline constexpr wchar_t kPid[]      = L"pid";      // переключатель «любой / 0», только PostApp
    inline constexpr wchar_t kAction[]   = L"action";   // переключатель, не диалог
}

// REAUTHORIZE не предлагается пользователю и не попадает в автоподстановку.
inline constexpr uint32_t kSelectableWfpConditionFlags = ~uint32_t{0x00000004};
// Название доступного в интерфейсе бита, включая неизвестные биты 0..31.
std::wstring WfpConditionFlagText(unsigned bit);
std::wstring InterfaceDisplayName(uint32_t index);

std::wstring RuleExplainMarkup(const Rule& r);
std::wstring RuleScopeLine(const Rule& r);

struct KnownPort { const wchar_t* name; uint16_t port; const wchar_t* desc; };
const KnownPort* KnownPorts(size_t& count);
const wchar_t*   WellKnownPortName(uint16_t port);

// Справочники типов ICMP: отдельные таблицы для IPv4 и IPv6
struct KnownIcmpType { uint8_t type; const wchar_t* name; };
const KnownIcmpType* KnownIcmpTypes(bool v6, size_t& count);
const wchar_t*       IcmpTypeNameOf(uint8_t type, bool v6);   // nullptr если неизвестен