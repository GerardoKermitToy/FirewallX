#pragma once
#include "Common.h"
#include "DebugCounters.h"
#include "SnapshotArray.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>
#include "PortmasterKextClient.hpp"
#include "FirewallXNdisFilter.hpp"

enum BytesSource : uint8_t {
    BytesNone = 0,
    BytesEstats = 1,
    BytesDriver = 2,
};

#pragma pack(push, 1)
struct BandwidthEntryV4 {
    uint8_t local_ip[4];
    uint16_t local_port;
    uint8_t remote_ip[4];
    uint16_t remote_port;
    uint64_t transmitted_bytes;
    uint64_t received_bytes;
};
struct BandwidthEntryV6 {
    uint8_t local_ip[16];
    uint16_t local_port;
    uint8_t remote_ip[16];
    uint16_t remote_port;
    uint64_t transmitted_bytes;
    uint64_t received_bytes;
};
struct ConnectionEndV4Record {
    uint64_t process_id;
    uint8_t direction;
    uint8_t protocol;
    uint8_t local_ip[4];
    uint8_t remote_ip[4];
    uint16_t local_port;
    uint16_t remote_port;
};
struct ConnectionEndV6Record {
    uint64_t process_id;
    uint8_t direction;
    uint8_t protocol;
    uint8_t local_ip[16];
    uint8_t remote_ip[16];
    uint16_t local_port;
    uint16_t remote_port;
};
#pragma pack(pop)

void on_bandwidthstats_V4(const pmkext::BandwidthValueV4* entry_, uint8_t protocol);
void on_bandwidthstats_V6(const pmkext::BandwidthValueV6* entry_, uint8_t protocol);
void on_connection_end_v4(const pmkext::ConnectionEndV4* entry_);
void on_connection_end_v6(const pmkext::ConnectionEndV6* entry_);

// Событие завершения и смерть процесса не удаляют строку немедленно. В течение
// четырёх секунд интерфейс ещё показывает её приглушённой вместе с последними
// счётчиками, после чего запись удаляется из единого хранилища.
inline constexpr ULONGLONG kFinishedGraceMs = 4 * 1000;
inline constexpr ULONGLONG kBlockedGraceMs = kFinishedGraceMs;

// ---------------------------------------------------------------------------
// Единое хранилище отображаемых соединений.
//
// Основной контейнер processes_ разделён по источнику: PID хоста либо индекс
// Ethernet-интерфейса NDIS. PID 0 и PID 4 хоста никогда не исключаются. Каждому
// поколению tuple соответствует одна ConnectionRecord: в ней же находятся
// счётчики драйвера, поэтому второй live unordered_map с тем же FlowId не нужен.
// Большая часть строк приходит только из таблиц ОС; редкие driver-поля для них
// вынесены в создаваемый по требованию DriverDetails.
//
// DriverTrafficTables и SystemTrafficTables остаются диагностическим API: Take
// восстанавливает их из ConnectionRecord для тестов, production-путь их не
// поддерживает и не копирует.
//
// Bandwidth-запись не содержит PID. Единственным маршрутом от её полного tuple
// к процессу служит ConnectionOwnerIndexes: четыре таблицы с тем же делением по
// протоколу и семейству. Поэтому перенос PID 0 к точному PID перемещает в одной
// критической секции уже целую запись вместе со счётчиками.
// ---------------------------------------------------------------------------
class FlowStore {
public:
    struct DriverTrafficEntry {
        uint64_t sent = 0, recv = 0;
        uint64_t periodSent = 0, periodRecv = 0;
        // Принятый bandwidth-отчёт обновляет время записи, даже если оба
        // переданных приращения равны нулю.
        ULONGLONG lastChangedAt = 0;
        // Ненулевое значение ставит on_connection_end_*; после этого новые
        // отчёты не отменяют обязательное удаление.
        ULONGLONG removeAfter = 0;
        uint64_t generation = 0;
    };

    // FlowId разделяет повторные использования одного tuple: END помечает
    // конкретное поколение, и новое соединение не удаляет его раньше четырёх секунд.
    using DriverTrafficTable =
        std::unordered_map<FlowId, DriverTrafficEntry, FlowIdHash>;

    struct DriverTrafficTables {
        DriverTrafficTable tcpV4;
        DriverTrafficTable tcpV6;
        DriverTrafficTable udpV4;
        DriverTrafficTable udpV6;
    };

    struct SystemTrafficEntry {
        uint64_t sent = 0, recv = 0;
        DWORD state = 0;
        DWORD localScope = 0, remoteScope = 0;
        ULONGLONG observedAt = 0;
        uint64_t revision = 0;
        uint64_t generation = 0;
        bool countersRead = false;

        // System traffic вытесняет driver traffic, как только хотя бы один
        // накопительный системный счётчик становится ненулевым.
        bool hasTraffic() const { return sent != 0 || recv != 0; }
    };

    using SystemTrafficTable =
        std::unordered_map<FlowKey, SystemTrafficEntry, FlowKeyHash>;

    struct SystemTrafficTables {
        SystemTrafficTable tcpV4;
        SystemTrafficTable tcpV6;
    };

    // Приращение и его интервал принадлежат одному источнику, а не таймеру UI.
    // Нулевое начало означает, что граница первого отчёта ещё неизвестна.
    struct TrafficPeriod {
        ULONGLONG begin = 0, end = 0;

        void Include(ULONGLONG from, ULONGLONG to) {
            if (!end || from < begin) begin = from;
            if (to > end) end = to;
        }
        ULONGLONG elapsedMs() const {
            return begin && end > begin ? end - begin : 0;
        }
    };

    // Поля, которых нет у строк, пришедших только из таблиц ОС. Один объект
    // создаётся при первом событии драйвера либо при замораживании старого
    // поколения. shared_ptr даёт copy-on-write для редкого диагностического Take:
    // production-снимок сам DriverDetails никогда не копирует.
    struct DriverDetails {
        uint32_t interfaceIndex = 0;
        std::optional<uint32_t> conditionFlags; // маска последнего события WFP, не объединение битов
        // Исходное имя переживает исчезновение адаптера и повторное использование IfIndex.
        std::shared_ptr<const std::wstring> interfaceName;
        std::shared_ptr<const std::wstring> tlsDomainLabel;
        uint64_t sent = 0, recv = 0;
        uint64_t periodSent = 0, periodRecv = 0;
        TrafficPeriod period;
        ULONGLONG lastBandwidthAt = 0;
        ULONGLONG lastChangedAt = 0;
        uint64_t packetSent = 0, packetRecv = 0;
        uint64_t events = 0;
        IcmpInfo icmp;
        IcmpInfo icmpOut, icmpIn;
        uint64_t frozenSent = 0, frozenRecv = 0;
        bool countersActive = false;
        bool frozenCountersKnown = false;
        bool frozenFromSystem = false;
    };

    struct ConnectionRecord {
        FlowKey key;
        uint64_t generation = 0;
        DWORD pid = 0;
        DWORD state = 0;
        DWORD localScope = 0, remoteScope = 0;
        Dir dir = Dir::Unknown;
        bool driverBacked = false;
        bool systemBacked = false;
        bool retired = false;
        bool ownerAmbiguous = false;
        bool endReceived = false;
        bool systemTrafficAuthoritative = false;
        bool currentSystemCountersRead = false;

        // Номер последнего системного снимка своей категории. Он заменяет
        // предварительный полный проход, который каждую секунду сбрасывал
        // systemBacked у всех соединений перед применением новых строк.
        uint64_t systemRevision = 0;
        ULONGLONG lastActivity = 0;
        ULONGLONG removeAfter = 0;
        ULONGLONG blockedAt = 0;

        // После первого EStats-отсчёта хотя бы с одним ненулевым направлением
        // соединение больше никогда не возвращается к данным драйвера. Текущая
        // строка нужна диагностике, последняя ненулевая — production-снимку.
        uint64_t currentSystemSent = 0, currentSystemRecv = 0;
        uint64_t lastSystemSent = 0, lastSystemRecv = 0;
        // Приращение вычисляется при применении EStats и снимается TakeDisplay.
        // Отдельная RowState на каждое соединение для этого больше не нужна.
        uint64_t systemPeriodSent = 0, systemPeriodRecv = 0;
        TrafficPeriod systemPeriod;
        ULONGLONG lastSystemReadAt = 0;

        std::shared_ptr<DriverDetails> driver;
    };

    // generation глобально уникален для всей сессии, поэтому второй FlowKey в
    // ключе хэш-таблицы только дублировал тот же ключ внутри ConnectionRecord.
    using ConnectionTable = std::unordered_map<uint64_t, ConnectionRecord>;

    struct ProcessConnections {
        ULONGLONG removeAfter = 0;
        ConnectionTable connections;
    };

    // Диагностические таблицы существуют только в полном View. Даже пустая
    // unordered_map в MSVC выделяет служебную память; шесть таких таблиц на
    // каждый PID не должны создаваться в рабочем хранилище.
    struct ProcessConnectionRecord : ProcessConnections {
        DriverTrafficTables driverTraffic;
        SystemTrafficTables systemTraffic;
    };

    using ProcessConnectionTable =
        std::unordered_map<TrafficGroupKey, ProcessConnectionRecord, TrafficGroupKeyHash>;

    struct ConnectionOwnerIndexEntry {
        uint64_t connectionGeneration = 0;
        ULONGLONG lastAccessAt = 0;
        uint64_t lastSystemRevision = 0;
        DWORD pid = 0;
        bool localListener = false;
        bool ownerAmbiguous = false;
        bool ended = false;
        // ended включает временную блокировку, а endReceived — только настоящий
        // END, после которого прежний PID больше не подтверждает новые события.
        bool endReceived = false;
    };

    using ConnectionOwnerIndex =
        std::unordered_map<FlowKey, ConnectionOwnerIndexEntry, FlowKeyHash>;

    struct ConnectionOwnerIndexes {
        ConnectionOwnerIndex tcpV4;
        ConnectionOwnerIndex tcpV6;
        ConnectionOwnerIndex udpV4;
        ConnectionOwnerIndex udpV6;
    };

    struct ConnEvent {
        uint32_t interfaceIndex = 0;
        std::optional<uint32_t> conditionFlags;
        std::shared_ptr<const std::wstring> interfaceName;
        DWORD pid = 0;
        bool ownerAmbiguous = false;
        Dir dir = Dir::Unknown;
        int icmpType = -1;
        int icmpCode = -1;
        uint64_t bytes = 0;
        std::shared_ptr<const std::wstring> tlsDomainLabel;
    };

    struct SystemTcpConnection {
        FlowKey key;
        DWORD pid = 0;
        DWORD state = 0;
        DWORD localScope = 0, remoteScope = 0;
        uint64_t sent = 0, recv = 0;
        ULONGLONG countersAt = 0;
        bool countersRead = false;
    };

    struct SystemUdpEndpoint {
        IpAddr local;
        uint16_t port = 0;
        DWORD pid = 0;
    };

    struct SystemSnapshot {
        std::vector<SystemTcpConnection> tcpV4;
        std::vector<SystemTcpConnection> tcpV6;
        std::vector<SystemUdpEndpoint> udpV4;
        std::vector<SystemUdpEndpoint> udpV6;
        bool tcpV4Valid = false;
        bool tcpV6Valid = false;
        bool udpV4Valid = false;
        bool udpV6Valid = false;
    };

    struct View {
        ProcessConnectionTable processes;
        ConnectionOwnerIndexes ownerIndexes;
        size_t removedConnections = 0;
    };

    // Компактный снимок для Monitor. Он содержит только поля, переживающие
    // фильтр пассивных строк; внутренние служебные поля ConnectionRecord и сам
    // DriverDetails в него не копируются.
    struct DisplayConnection {
        uint32_t interfaceIndex = 0;
        std::optional<uint32_t> conditionFlags;
        std::shared_ptr<const std::wstring> interfaceName;
        FlowKey key;
        std::shared_ptr<const std::wstring> tlsDomainLabel;
        uint64_t flowGeneration = 0;
        uint64_t sent = 0, recv = 0;
        uint64_t periodSent = 0, periodRecv = 0;
        TrafficPeriod period;
        ULONGLONG lastActivity = 0;
        ULONGLONG removeAfter = 0;
        ULONGLONG blockedAt = 0;
        uint64_t pktSent = 0, pktRecv = 0;
        uint64_t driverEvents = 0;
        DWORD state = 0;
        Dir dir = Dir::Unknown;
        BytesSource bytesFrom = BytesNone;
        bool ownerAmbiguous = false;
        bool localListener = false;
        IcmpInfo icmp;
        IcmpInfo icmpOut, icmpIn;

        double bytesPerSecond() const {
            const ULONGLONG periodMs = period.elapsedMs();
            return periodMs
                ? (static_cast<double>(periodSent) +
                   static_cast<double>(periodRecv)) * 1000.0 / periodMs
                : 0.0;
        }
    };

    struct DisplayProcess {
        TrafficGroupKey group;
        ULONGLONG removeAfter = 0;
        double speed = 0.0;
        size_t connCount = 0;
        bool ownerAmbiguous = false;
        // Диапазон в общем массиве DisplayView, без отдельного выделения на PID.
        std::span<DisplayConnection> connections;
    };

    struct DisplayView {
        SnapshotArray<DisplayProcess> processes;
        SnapshotArray<DisplayConnection> connections;
        size_t flowCount = 0;
        size_t hiddenCount = 0;
        size_t driverOnlyFlows = 0;
        size_t removedConnections = 0;
    };

    static FlowStore& Instance();
    // Только размеры; занятый мьютекс пропускается без ожидания.
    void ReadDebugCounters(DebugCounters::Snapshot& out) const;

    // В служебном процессе нет UI и системных снимков. Индекс владельцев всё
    // равно поддерживается: он нужен поздним on_connection_* с PID 0.
    void Enable(bool on) { enabled_.store(on, std::memory_order_relaxed); }
    bool enabled() const { return enabled_.load(std::memory_order_relaxed); }

    // Ненулевой PID события возвращается как есть. Для PID 0 сначала проверяется
    // exact tuple. Только первое входящее событие без exact-записи допускает
    // поиск по локальному сокету; конфликт сохраняется без выбора одного PID.
    // Завершённое поколение не допускает этого резервного поиска.
    DWORD ResolveEventOwner(DWORD reportedPid, const FlowKey& key,
                            bool* found = nullptr, bool* ambiguous = nullptr,
                            Dir dir = Dir::Unknown);
    // Только on_connection_* с PID, отличным от 0 и 4, вправе безусловно
    // исправить владельца exact tuple в индексе.
    void AssignReportedOwner(const FlowKey& key, DWORD pid);
    DWORD ResolveLocalEndpoint(Proto proto, const IpAddr& local, uint16_t port,
                               bool* ambiguous = nullptr) const;

    // Системные TCP/UDP таблицы публикуются одним снимком. Каждое успешно
    // прочитанное семейство заменяет прежние записи целиком.
    void ReplaceSystemSnapshot(const SystemSnapshot& snapshot);

    // Границы bandwidth-измерения задаёт общий цикл Monitor. Пустые наборы
    // драйвер не отправляет, поэтому время прихода записей не задаёт интервал.
    void BeginBandwidthPoll(ULONGLONG requestedAt);
    void CancelBandwidthPoll();
    // Интервал статистики NDIS задаёт её собственный опрос, не таблицы ОС.
    void BeginNdisBandwidthPoll(ULONGLONG requestedAt);
    void CancelNdisBandwidthPoll();
    void AddBandwidth(const FlowKey& key, uint64_t sent, uint64_t recv);
    // KextClient передаёт bandwidth уже массивом. Весь массив применяется под
    // одним замком и с одной отметкой времени вместо lock/unlock на каждую строку.
    void AddBandwidthBatch(uint8_t protocol,
                           const pmkext::BandwidthValueV4* entries,
                           uint32_t count);
    void AddBandwidthBatch(uint8_t protocol,
                           const pmkext::BandwidthValueV6* entries,
                           uint32_t count);
    void AddNdisBandwidthBatch(uint8_t protocol,
                                const firewallxndisfilter::Client::BandwidthV4* entries, uint32_t count, uint32_t interfaceIndex = 0);
    void AddNdisBandwidthBatch(uint8_t protocol,
                                const firewallxndisfilter::Client::BandwidthV6* entries, uint32_t count, uint32_t interfaceIndex = 0);
    // Возвращает поколение строки либо 0, когда отображаемый учёт выключен.
    uint64_t NoteConnection(const FlowKey& key, const ConnEvent& event);
    // Создаёт/обновляет строку и сразу помечает её заблокированной под одним
    // захватом мьютекса. Используется для немедленного блокирующего решения.
    uint64_t NoteBlockedConnection(const FlowKey& key, const ConnEvent& event);
    // Отложенный вердикт меняет только исходное живое поколение. Завершённая
    // или уже удалённая строка не восстанавливается и не подменяется новой.
    void NoteAllowed(const FlowKey& key, const ConnEvent& event,
                     uint64_t generation = 0);
    void NoteBlocked(const FlowKey& key, const ConnEvent& event,
                     uint64_t generation = 0);
    // Ненулевой PID END ограничивает выбор записи; чужое событие не закрывает
    // текущего владельца tuple. PID 0 допускает подтверждённого владельца индекса.
    // Локальная пара завершается атомарно, только по первому END текущего
    // поколения; исторический END не затрагивает новую обратную сторону.
    void CloseFlow(const FlowKey& key, DWORD pid, Dir dir,
                   uint64_t generation = 0);
    void ClearCounters(const FlowKey& key, uint64_t generation = 0);

    // Полный диагностический снимок внутренних таблиц. Используется тестами;
    // производственный Monitor берёт плоский TakeDisplay ниже.
    void Take(View& out, ULONGLONG inactiveMs = 2 * 60 * 1000);
    // Секундный снимок Monitor: одновременно выполняет уборку, выбирает источник
    // счётчиков и отбрасывает пассивные строки до копирования. showPassive меняет
    // только состав снимка, а не число объектов в основном хранилище.
    // Без includeConnections остаётся сводка процессов для трея. Уборка и сброс
    // интервалов продолжаются, но строки соединений и скорости не вычисляются.
    void TakeDisplay(DisplayView& out,
                     ULONGLONG inactiveMs = 2 * 60 * 1000,
                     bool showPassive = true,
                     bool includeConnections = true);
    // Служба не создаёт UI-снимок, но раз в секунду освобождает неиспользуемые
    // записи тех же четырёх индексов.
    void Maintain();

    void Reset();
    // Смена Portmaster-сессии не затрагивает независимые соединения NDIS.
    void ResetHost();

    static constexpr ULONGLONG kInactiveMs = 2 * 60 * 1000;
    static constexpr ULONGLONG kOtherInactiveMs = 30 * 1000;

private:
    friend struct StorageTestAccess;
    FlowStore() = default;

    struct LocalSocketOwner {
        DWORD pid = 0;
        bool ownerAmbiguous = false;
    };
    using LocalSocketTable =
        std::unordered_map<IpEndpoint, LocalSocketOwner, IpEndpointHash>;
    struct LocalSocketTables {
        LocalSocketTable tcpV4;
        LocalSocketTable tcpV6;
        LocalSocketTable udpV4;
        LocalSocketTable udpV6;
    };

    static DriverTrafficTable* DriverTableFor(DriverTrafficTables& tables,
                                               const FlowKey& key);
    static const DriverTrafficTable* DriverTableFor(
        const DriverTrafficTables& tables, const FlowKey& key);
    static DriverDetails& EnsureDriverDetails(ConnectionRecord& connection);
    static const DriverDetails* DriverDetailsOf(
        const ConnectionRecord& connection);
    static SystemTrafficTable* SystemTableFor(SystemTrafficTables& tables,
                                               const FlowKey& key);
    static const SystemTrafficTable* SystemTableFor(
        const SystemTrafficTables& tables, const FlowKey& key);
    static ConnectionOwnerIndex* OwnerIndexFor(ConnectionOwnerIndexes& indexes,
                                                const FlowKey& key);
    static const ConnectionOwnerIndex* OwnerIndexFor(
        const ConnectionOwnerIndexes& indexes, const FlowKey& key);
    static LocalSocketTable* SocketTableFor(LocalSocketTables& tables,
                                             Proto proto, uint16_t family);
    static const LocalSocketTable* SocketTableFor(
        const LocalSocketTables& tables, Proto proto, uint16_t family);
    bool ResolveSocketLocked(Proto proto, const IpAddr& local, uint16_t port,
                             DWORD& pid, bool& ambiguous) const;

    ConnectionRecord* VerdictConnectionLocked(
        const FlowKey& key, DWORD pid, uint64_t generation);
    ConnectionRecord* NdisConnectionLocked(const FlowKey& key, bool newAttempt = false);
    template <class Value>
    void AddNdisBandwidth(uint8_t protocol, const Value* entries, uint32_t count, uint32_t interfaceIndex);
    uint64_t NextGenerationLocked();
    ProcessConnections& GroupLocked(TrafficGroupKey group);
    ConnectionOwnerIndexEntry& OwnerLocked(const FlowKey& key,
                                            ULONGLONG now);
    ConnectionRecord* CurrentConnectionLocked(
        const FlowKey& key, const ConnectionOwnerIndexEntry& owner);
    const ConnectionRecord* CurrentConnectionLocked(
        const FlowKey& key, const ConnectionOwnerIndexEntry& owner) const;
    ConnectionRecord& StartConnectionLocked(
        const FlowKey& key, ConnectionOwnerIndexEntry& owner, DWORD pid,
        ULONGLONG now, bool forceNew);
    ConnectionRecord& StartOtherConnectionLocked(
        const FlowKey& key, DWORD pid, ULONGLONG now, bool forceNew);
    ConnectionRecord* NoteConnectionLocked(const FlowKey& key,
                                            const ConnEvent& event,
                                            ULONGLONG now);
    void MarkBlockedLocked(ConnectionRecord& connection,
                           const ConnEvent& event, ULONGLONG now);
    void MoveCurrentFlowLocked(const FlowKey& key,
                               ConnectionOwnerIndexEntry& owner, DWORD pid);
    void FreezeConnectionLocked(ConnectionRecord& connection);
    void AddBandwidthLocked(const FlowKey& key, uint64_t sent,
                            uint64_t recv, ULONGLONG now,
                            const TrafficPeriod* period = nullptr);
    bool MarkConnectionForRemovalLocked(const FlowKey& key, DWORD pid,
                                        uint64_t generation,
                                        ULONGLONG now);

    void BeginSystemCategoryLocked(Proto proto, uint16_t family);
    void ApplyTcpSnapshotLocked(const std::vector<SystemTcpConnection>& rows,
                                uint16_t family, uint64_t revision,
                                ULONGLONG now);
    void ApplyUdpSnapshotLocked(const std::vector<SystemUdpEndpoint>& rows,
                                uint16_t family, uint64_t revision,
                                ULONGLONG now);
    void FinishSystemSnapshotsLocked(uint8_t validCategories,
                                     ULONGLONG now);
    void RefreshListenerFlagsLocked(Proto proto, uint16_t family);
    struct DeadProcessProbe {
        DWORD pid = 0;
        ULONGLONG deadFor = 0;
    };
    void ProbeDeadProcesses(std::vector<DeadProcessProbe>& out) const;
    void PrepareProcessesLocked(const std::vector<DeadProcessProbe>& dead,
                                ULONGLONG now);
    void ResetPeriodsLocked();

    bool ExpireConnectionLocked(ConnectionRecord& connection,
                                ULONGLONG now, ULONGLONG inactiveMs);
    void ExpireLocked(ULONGLONG now, ULONGLONG inactiveMs);
    static bool OwnerExpired(const ConnectionOwnerIndexEntry& owner,
                             ULONGLONG now, ULONGLONG inactiveMs);
    void ExpireOwnerIndexesLocked(ULONGLONG now, ULONGLONG inactiveMs);
    void RemoveProcessesLocked(const std::vector<DWORD>& pids);
    void RemoveEmptyProcessesLocked();

    mutable std::mutex mtx_;
    std::atomic<bool> enabled_{ true };

    std::unordered_map<TrafficGroupKey, ProcessConnections, TrafficGroupKeyHash> processes_;
    // Гостевые tuple никогда не участвуют в индексах владельцев Windows.
    std::unordered_map<FlowKey, uint64_t, FlowKeyHash> ndisConnections_;
    ConnectionOwnerIndexes ownerIndexes_;
    LocalSocketTables localSockets_;
    uint64_t generationSeq_ = 0;
    uint64_t systemRevision_[4]{};
    ULONGLONG bandwidthTick_[4]{};
    TrafficPeriod bandwidthPoll_;
    TrafficPeriod ndisBandwidthPoll_;
    bool bandwidthPollManaged_ = false;
    ULONGLONG lastTakeAt_ = 0;
    size_t removedSinceTake_ = 0;
};
