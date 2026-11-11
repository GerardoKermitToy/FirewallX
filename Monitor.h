#pragma once
#include "Common.h"
#include "FlowStore.h"
#include "ProcessIcon.h"
#include "ServiceInfo.h"
#include "Rules.h"
#include "FirewallPolicy.h"
#include "TableBuffer.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

struct ProcessPathInfo;

inline constexpr bool TcpHalfClosed(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_FIN_WAIT1:
    case MIB_TCP_STATE_FIN_WAIT2:
    case MIB_TCP_STATE_CLOSE_WAIT:
    case MIB_TCP_STATE_CLOSING:
    case MIB_TCP_STATE_LAST_ACK:
    case MIB_TCP_STATE_TIME_WAIT:
    case MIB_TCP_STATE_CLOSED:
    case MIB_TCP_STATE_DELETE_TCB:
        return true;
    default:
        return false;
    }
}

inline constexpr bool TcpTransferDone(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSING:
    case MIB_TCP_STATE_LAST_ACK:
    case MIB_TCP_STATE_TIME_WAIT:
    case MIB_TCP_STATE_CLOSED:
    case MIB_TCP_STATE_DELETE_TCB:
        return true;
    default:
        return false;
    }
}

struct ConnItem {
    uint32_t interfaceIndex = 0;
    std::shared_ptr<const std::wstring> interfaceName;
    FlowKey key;
    std::shared_ptr<const std::wstring> tlsDomainLabel;
    uint64_t flowGeneration = 0;
    // UI назначает индекс перед перестройкой; он перемещается вместе со строкой.
    size_t textIndex = 0;
    uint64_t sent = 0, recv = 0;
    double speed = 0.0;
    ULONGLONG lastActivity = 0;
    ULONGLONG blockedAt = 0;
    uint64_t pktSent = 0, pktRecv = 0;
    uint64_t driverEvents = 0;
    uint64_t ruleId = 0;
    DWORD pid = 0;
    DWORD state = 0;
    Dir dir = Dir::Unknown;
    BytesSource bytesFrom = BytesNone;
    bool ownerAmbiguous = false;
    bool processExited = false;
    bool finished = false;
    bool ruleGlobal = false;
    bool byPolicy = false;
    bool autoAllowedIcmp = false;
    FirewallPolicy policy = FirewallPolicy::Learning;
    int ruleAction = -1;
    std::optional<uint32_t> conditionFlags;
    IcmpInfo icmp;
    IcmpInfo icmpOut, icmpIn;

    bool bytesKnown() const { return bytesFrom != BytesNone; }
};

struct ProcItem {
    TrafficGroupKey group;
    std::wstring name, path;
    std::shared_ptr<const ProcessPathInfo> pathInfo;
    ServiceInfo::HostedServices hostedServices;
    bool pathKnown = false;
    bool ownerAmbiguous = false;
    ProcessIconRef icon;
    uint64_t sent = 0, recv = 0;
    bool bytesKnown = false;
    double speed = 0.0;
    uint64_t order = 0;
    size_t ruleHits = 0;
    bool finished = false;
    std::span<ConnItem> conns;

    // Имя службы нужно только строкам соединений; заголовок группы и правила
    // сохраняют имя процесса. При нескольких службах владельца не угадываем.
    std::wstring_view serviceName() const {
        if (!ownerAmbiguous && hostedServices && hostedServices->size() == 1)
            return hostedServices->front().name;
        return {};
    }
};

struct Snapshot {
    // В трее procs хранит краткую сводку: PID, признаки владельца/завершения
    // и порядок, без имён, путей, значков и соединений. connCount сохраняет
    // число соединений; такой снимок не заменяет полные строки UI.
    bool displayReady = false;
    SnapshotArray<ProcItem> procs;
    // Все соединения снимка принадлежат одному массиву; ProcItem хранит диапазон.
    SnapshotArray<ConnItem> conns;
    uint64_t totalSent = 0, totalRecv = 0;
    size_t connCount = 0;
    size_t hiddenCount = 0;
    size_t driverOnlyFlows = 0;
    size_t closedDropped = 0;
    size_t ruleMatches = 0;
    size_t flowCount = 0;
};

std::wstring IcmpLabel(const IcmpInfo& info);

class Monitor {
public:
    ~Monitor() { Stop(); }

    // Системные таблицы и FlowStore обрабатываются рабочим потоком. UI только
    // забирает уже готовый снимок, поэтому секундное обновление не блокирует
    // обработку оконных сообщений даже при десятках тысяч соединений.
    void Start(std::wstring& warnings, HWND notifyWindow,
               UINT notifyMessage);
    void Stop();
    void RequestRefresh();
    bool TakeLatest(Snapshot& out);
    // Скрытое окно не требует полных строк; секундный опрос и учёт трафика
    // продолжаются независимо от этого флага.
    void SetDisplayEnabled(bool on);

    // Настраивается до Start. Запрос native bandwidth выполняется тем же
    // worker-ом непосредственно перед чтением системных таблиц и EStats.
    void SetBandwidthRequest(bool (*request)()) { bandwidthRequest_ = request; }

    void SetRuleStore(RuleStore* rules);
    void SetPolicy(FirewallPolicy policy) {
        policy_.store(policy, std::memory_order_relaxed);
    }
    void SetShowPassive(bool on) {
        showPassive_.store(on, std::memory_order_relaxed);
    }
    bool showPassive() const {
        return showPassive_.load(std::memory_order_relaxed);
    }

    bool estatsAvailable() const { return estatsOk_; }
    const std::wstring& estatsNote() const { return estatsNote_; }

    static const std::wstring& TcpStateRu(DWORD state);
    static std::wstring ConnectionStatus(const ConnItem& connection,
                                         std::wstring_view ruleName,
                                         ULONGLONG now);

private:
    friend struct StorageTestAccess;
    static constexpr uint64_t kEstatsKeepTicks = 3;
    static constexpr uint32_t kEstatsMaxTries = 4;

    struct EstatsId {
        FlowKey key;
        DWORD pid = 0;
        DWORD localScope = 0, remoteScope = 0;

        bool operator==(const EstatsId& other) const {
            return pid == other.pid && localScope == other.localScope &&
                   remoteScope == other.remoteScope && key == other.key;
        }
    };

    struct EstatsIdHash {
        size_t operator()(const EstatsId& id) const noexcept {
            uint64_t hash = static_cast<uint64_t>(FlowKeyHash{}(id.key));
            hash ^= static_cast<uint64_t>(id.pid) << 1;
            hash ^= static_cast<uint64_t>(id.localScope) << 17;
            hash ^= static_cast<uint64_t>(id.remoteScope) << 33;
            return static_cast<size_t>(hash ^ (hash >> 32));
        }
    };

    struct EstatsSlot {
        uint64_t tick = 0;
        uint32_t tries = 0;
        DWORD state = 0;
        bool enabled = false;
    };

    struct OrderSlot {
        uint64_t order = 0;
        uint64_t seenTick = 0;
    };

    // Кэш существует только для отображаемых строк и только когда набор правил
    // не зависит от сервисов или макро-адресов. generation глобально уникален,
    // поэтому копировать в ключ весь FlowKey и PID не требуется.
    struct RuleCacheEntry {
        uint32_t interfaceIndex = 0;
        std::shared_ptr<const std::wstring> interfaceName;
        uint64_t seenTick = 0;
        uint64_t rulesVersion = 0;
        uint64_t ruleId = 0;
        const ProcessPathInfo* pathInfo = nullptr;
        Dir dir = Dir::Unknown;
        RuleScope scope = RuleScope::App;
        RuleAction action = RuleAction::Allow;
        int icmpType = -1;
        int icmpCode = -1;
        std::optional<uint32_t> conditionFlags;
        bool ownerAmbiguous = false;
        bool found = false;
    };

    void CollectSystemSnapshot(FlowStore::SystemSnapshot& snapshot);
    void BuildSnapshot(Snapshot& out, bool buildDisplay);
    void PruneCaches(bool cacheRuleMatches);
    void WorkerLoop();
    template <class Table>
    size_t AddTcpRows(const TableBuffer& buffer,
                      std::vector<FlowStore::SystemTcpConnection>& rows);
    template <class Table>
    size_t AddUdpRows(const TableBuffer& buffer,
                      std::vector<FlowStore::SystemUdpEndpoint>& rows);
    void ApplyEstats(FlowStore::SystemTcpConnection& connection);

    static bool EstatsUseful(DWORD state);

    bool (*bandwidthRequest_)() = nullptr;
    RuleStore* rules_ = nullptr;
    std::atomic<FirewallPolicy> policy_{ FirewallPolicy::Learning };
    std::atomic<bool> showPassive_{ false };
    bool estatsOk_ = true;
    std::wstring estatsNote_;

    // Запросы обновления сливаются: если UI попросил ещё один снимок, пока
    // предыдущий строится, после него выполняется ровно один актуальный проход.
    std::mutex requestMtx_;
    std::condition_variable requestCv_;
    std::thread worker_;
    bool stopRequested_ = false;
    bool refreshRequested_ = false;
    bool displayEnabled_ = true;
    uint64_t displayVersion_ = 0;

    // Готовый и текущий UI-снимки меняются местами за O(1). Старый снимок затем
    // разбирается и переиспользуется рабочим потоком, а не уничтожается в WndProc.
    std::mutex publishMtx_;
    Snapshot published_;
    bool publishedReady_ = false;
    HWND notifyWindow_ = nullptr;
    UINT notifyMessage_ = 0;

    TableBuffer tableBuffer_;
    std::unordered_map<uint64_t, RuleCacheEntry> ruleCache_;
    std::unordered_map<EstatsId, EstatsSlot, EstatsIdHash> estatsOn_;
    std::unordered_map<TrafficGroupKey, OrderSlot, TrafficGroupKeyHash> procOrder_;

    FlowStore::SystemSnapshot system_;
    FlowStore::DisplayView view_;
    uint64_t orderSeq_ = 0;
    uint64_t tick_ = 0;
};
