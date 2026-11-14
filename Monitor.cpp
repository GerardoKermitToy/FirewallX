#include "Monitor.h"
#include "StringRes.h"
#include "SystemInfo.h"
#include "StorageMaintenance.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iterator>

namespace {

constexpr int kTableTries = 4;

enum class Which : uint8_t { Tcp, Udp };

bool FetchTable(Which which, ULONG family, TableBuffer& buffer) {
    if (buffer.size() < TableBuffer::kInitialBytes) [[unlikely]]
        buffer.reset(TableBuffer::kInitialBytes);
    for (int attempt = 0; attempt < kTableTries; ++attempt) {
        DWORD size = static_cast<DWORD>(buffer.size());
        const DWORD error = which == Which::Tcp
            ? GetExtendedTcpTable(buffer.data(), &size, FALSE, family,
                                  TCP_TABLE_OWNER_PID_ALL, 0)
            : GetExtendedUdpTable(buffer.data(), &size, FALSE, family,
                                  UDP_TABLE_OWNER_PID, 0);
        if (error == NO_ERROR) [[likely]] return true;
        if (error == ERROR_NO_DATA) {
            *reinterpret_cast<DWORD*>(buffer.data()) = 0;
            return true;
        }
        if (error != ERROR_INSUFFICIENT_BUFFER) [[unlikely]] return false;
        buffer.reset(static_cast<size_t>(size) + TableBuffer::kSlackBytes);
    }
    return false;
}

IpAddr TcpLocal(const MIB_TCPROW_OWNER_PID& row) {
    return IpAddr::V4(row.dwLocalAddr);
}
IpAddr TcpLocal(const MIB_TCP6ROW_OWNER_PID& row) {
    return IpAddr::V6(row.ucLocalAddr);
}
IpAddr TcpRemote(const MIB_TCPROW_OWNER_PID& row) {
    return IpAddr::V4(row.dwRemoteAddr);
}
IpAddr TcpRemote(const MIB_TCP6ROW_OWNER_PID& row) {
    return IpAddr::V6(row.ucRemoteAddr);
}
DWORD TcpLocalScope(const MIB_TCPROW_OWNER_PID&) { return 0; }
DWORD TcpLocalScope(const MIB_TCP6ROW_OWNER_PID& row) {
    return row.dwLocalScopeId;
}
DWORD TcpRemoteScope(const MIB_TCPROW_OWNER_PID&) { return 0; }
DWORD TcpRemoteScope(const MIB_TCP6ROW_OWNER_PID& row) {
    return row.dwRemoteScopeId;
}
IpAddr UdpLocal(const MIB_UDPROW_OWNER_PID& row) {
    return IpAddr::V4(row.dwLocalAddr);
}
IpAddr UdpLocal(const MIB_UDP6ROW_OWNER_PID& row) {
    return IpAddr::V6(row.ucLocalAddr);
}

struct StatusStrings {
    UiLang lang = UiLang::Russian;
    bool ready = false;

    std::wstring exited;
    std::wstring finished;
    std::wstring blocked;
    std::wstring autoAllowedIcmp;
    std::wstring separator;
    std::wstring packetsUp;
    std::wstring events;
    std::wstring sizeUnknown;
    std::wstring loopback;
    std::wstring timeAgo;
    std::wstring icmpType;
    std::wstring icmpCode;
    std::wstring globalPrefix;
    std::wstring noCounters;
    std::wstring driverBytes;
    std::wstring udpData;
    std::wstring udpEndpoint;
    std::wstring tcpEstablished;
    std::wstring tcpSynSent;
    std::wstring tcpSynReceived;
    std::wstring tcpFinWait1;
    std::wstring tcpFinWait2;
    std::wstring tcpCloseWait;
    std::wstring tcpClosing;
    std::wstring tcpLastAck;
    std::wstring tcpTimeWait;
    std::wstring tcpListen;
    std::wstring tcpClosed;
    std::wstring tcpDeleteTcb;
    std::wstring tcpFallback = L"TCP";
};

const StatusStrings& StatusText() {
    thread_local StatusStrings text;
    const UiLang lang = CurrentUiLang();
    if (text.ready && text.lang == lang) [[likely]] return text;

    text.lang = lang;
    text.ready = true;
    text.exited         = StringResRef(IDS_MON_EXITED);
    text.finished       = StringResRef(IDS_MON_FINISHED);
    text.blocked        = StringResRef(IDS_ACTION_BLOCK);
    text.autoAllowedIcmp = StringResRef(IDS_MON_AUTO_ALLOWED_ICMP);
    text.separator      = StringResRef(IDS_MON_SEPARATOR);
    text.packetsUp      = StringResRef(IDS_MON_PACKETS_UP);
    text.events         = StringResRef(IDS_MON_EVENTS);
    text.sizeUnknown    = StringResRef(IDS_MON_SIZE_UNKNOWN);
    text.loopback       = StringResRef(IDS_MON_LOOPBACK);
    text.timeAgo        = StringResRef(IDS_MON_TIME_AGO);
    text.icmpType       = StringResRef(IDS_MON_ICMP_TYPE);
    text.icmpCode       = StringResRef(IDS_MON_ICMP_CODE);
    text.globalPrefix   = StringResRef(IDS_REASON_GLOBAL_PREFIX);
    text.noCounters     = StringResRef(IDS_REASON_NO_COUNTERS);
    text.driverBytes    = StringResRef(IDS_REASON_DRIVER_BYTES);
    text.udpData        = StringResRef(IDS_REASON_UDP_DATA);
    text.udpEndpoint    = StringResRef(IDS_REASON_UDP_ENDPOINT);
    text.tcpEstablished = StringResRef(IDS_TCP_ESTABLISHED);
    text.tcpSynSent     = StringResRef(IDS_TCP_SYN_SENT);
    text.tcpSynReceived = StringResRef(IDS_TCP_SYN_RCVD);
    text.tcpFinWait1    = StringResRef(IDS_TCP_FIN_WAIT1);
    text.tcpFinWait2    = StringResRef(IDS_TCP_FIN_WAIT2);
    text.tcpCloseWait   = StringResRef(IDS_TCP_CLOSE_WAIT);
    text.tcpClosing     = StringResRef(IDS_TCP_CLOSING);
    text.tcpLastAck     = StringResRef(IDS_TCP_LAST_ACK);
    text.tcpTimeWait    = StringResRef(IDS_TCP_TIME_WAIT);
    text.tcpListen      = StringResRef(IDS_TCP_LISTEN);
    text.tcpClosed      = StringResRef(IDS_TCP_CLOSED);
    text.tcpDeleteTcb   = StringResRef(IDS_TCP_DELETE_TCB);
    return text;
}

void AppendPart(std::wstring& text, const std::wstring& part,
                const StatusStrings& strings) {
    if (part.empty()) return;
    if (!text.empty()) text += strings.separator;
    text += part;
}

template <class T>
void ResizeSystemRows(std::vector<T>& rows, size_t count) {
    if (rows.capacity() != count)
        rows = std::vector<T>(count);
    else
        rows.resize(count);
}

std::wstring FlowFacts(const ConnItem& connection, ULONGLONG now) {
    const StatusStrings& strings = StatusText();
    std::wstring text;
    const std::wstring outgoing = IcmpLabel(connection.icmpOut);
    const std::wstring incoming = IcmpLabel(connection.icmpIn);
    if (!outgoing.empty() || !incoming.empty()) {
        std::wstring types;
        if (!outgoing.empty()) types += L"↑" + outgoing;
        if (!incoming.empty()) {
            if (!types.empty()) types += L" ";
            types += L"↓" + incoming;
        }
        AppendPart(text, types, strings);
    }

    if (connection.pktSent || connection.pktRecv) {
        AppendPart(text,
            strings.packetsUp +
            std::to_wstring(connection.pktSent) + L" ↓" +
            std::to_wstring(connection.pktRecv), strings);
    } else if (connection.driverEvents) {
        AppendPart(text,
            strings.events +
            std::to_wstring(connection.driverEvents) +
            strings.sizeUnknown, strings);
    }

    if (connection.key.local == connection.key.remote &&
        ProtoIsIcmp(connection.key.proto))
        AppendPart(text, strings.loopback, strings);

    if (connection.lastActivity) {
        const ULONGLONG idle = (now - connection.lastActivity) / 1000;
        if (idle >= 2)
            AppendPart(text, std::to_wstring(idle) + strings.timeAgo,
                       strings);
    }
    return text;
}

} // namespace

static_assert(kProcessGraceMs >= kFinishedGraceMs,
              "кеш процессов обязан переживать окно удаления записи процесса");

std::wstring IcmpLabel(const IcmpInfo& info) {
    if (!info.known()) return std::wstring();
    const StatusStrings& strings = StatusText();
    std::wstring text;
    if (const wchar_t* name = IcmpTypeNameOf(
            static_cast<uint8_t>(info.type), info.v6))
        text = name;
    else
        text = strings.icmpType + std::to_wstring(info.type);
    if (info.code > 0)
        text += strings.icmpCode + std::to_wstring(info.code);
    return text;
}

const std::wstring& Monitor::TcpStateRu(DWORD state) {
    const StatusStrings& strings = StatusText();
    switch (state) {
    case MIB_TCP_STATE_ESTAB:      return strings.tcpEstablished;
    case MIB_TCP_STATE_SYN_SENT:   return strings.tcpSynSent;
    case MIB_TCP_STATE_SYN_RCVD:   return strings.tcpSynReceived;
    case MIB_TCP_STATE_FIN_WAIT1:  return strings.tcpFinWait1;
    case MIB_TCP_STATE_FIN_WAIT2:  return strings.tcpFinWait2;
    case MIB_TCP_STATE_CLOSE_WAIT: return strings.tcpCloseWait;
    case MIB_TCP_STATE_CLOSING:    return strings.tcpClosing;
    case MIB_TCP_STATE_LAST_ACK:   return strings.tcpLastAck;
    case MIB_TCP_STATE_TIME_WAIT:  return strings.tcpTimeWait;
    case MIB_TCP_STATE_LISTEN:     return strings.tcpListen;
    case MIB_TCP_STATE_CLOSED:     return strings.tcpClosed;
    case MIB_TCP_STATE_DELETE_TCB: return strings.tcpDeleteTcb;
    default:                       return strings.tcpFallback;
    }
}

std::wstring Monitor::ConnectionStatus(const ConnItem& connection,
                                       std::wstring_view ruleName,
                                       ULONGLONG now) {
    const StatusStrings& strings = StatusText();
    const bool ruleFound = connection.ruleId != 0;
    const bool hasReason = ruleFound || connection.byPolicy ||
                           connection.autoAllowedIcmp;
    const bool blocked = connection.blockedAt != 0;
    std::wstring status;

    if (ruleFound) {
        if (connection.ruleGlobal) status = strings.globalPrefix;
        status.append(ruleName);
    } else if (connection.autoAllowedIcmp) {
        status = strings.autoAllowedIcmp;
    } else if (connection.byPolicy) {
        status = FirewallPolicies::Name(connection.policy);
    }

    if (blocked && ProtoInOsTables(connection.key.proto)) {
        if (!hasReason) status = ProtoToString(connection.key.proto);
    } else if (connection.key.proto == Proto::Tcp) {
        if (!hasReason) {
            status = TcpStateRu(connection.state);
            if (!connection.bytesKnown())
                status += strings.noCounters;
            else if (connection.bytesFrom == BytesDriver)
                status += strings.driverBytes;
        }
    } else if (connection.key.proto == Proto::Udp) {
        if (!hasReason) {
            if (connection.bytesFrom == BytesDriver) {
                status = strings.udpData;
                if (connection.lastActivity) {
                    const ULONGLONG idle =
                        (now - connection.lastActivity) / 1000;
                    if (idle >= 2)
                        status += strings.separator +
                                  std::to_wstring(idle) +
                                  strings.timeAgo;
                }
            } else {
                status = strings.udpEndpoint;
            }
        }
    } else {
        const std::wstring facts = FlowFacts(connection, now);
        if (hasReason)
            AppendPart(status, facts, strings);
        else {
            status = ProtoToString(connection.key.proto);
            if (!facts.empty()) status += L" " + facts;
        }
    }

    if (blocked) AppendPart(status, strings.blocked, strings);
    if (connection.processExited)
        AppendPart(status, strings.exited, strings);
    else if (connection.finished)
        AppendPart(status, strings.finished, strings);
    return status;
}

void Monitor::SetRuleStore(RuleStore* rules) {
    if (rules_ != rules) {
        ruleCache_.clear();
        TrimHashTable(ruleCache_);
    }
    rules_ = rules;
}

void Monitor::Start(std::wstring& warnings, HWND notifyWindow,
                    UINT notifyMessage) {
    Stop();

    estatsOk_ = true;
    estatsNote_.clear();
    if (!IsElevated()) {
        estatsNote_ = LoadStringRes(IDS_ESTATS_NEED_ADMIN);
        estatsOk_ = false;
        warnings += estatsNote_ + L"; ";
    }

    {
        std::lock_guard<std::mutex> lock(requestMtx_);
        stopRequested_ = false;
        refreshRequested_ = true;
        notifyWindow_ = notifyWindow;
        notifyMessage_ = notifyMessage;
    }
    worker_ = std::thread(&Monitor::WorkerLoop, this);
    requestCv_.notify_one();
}

void Monitor::Stop() {
    {
        std::lock_guard<std::mutex> lock(requestMtx_);
        stopRequested_ = true;
        refreshRequested_ = false;
        notifyWindow_ = nullptr;
        notifyMessage_ = 0;
    }
    requestCv_.notify_all();
    if (worker_.joinable()) worker_.join();

    {
        std::lock_guard<std::mutex> lock(publishMtx_);
        published_ = Snapshot{};
        publishedReady_ = false;
    }

    ruleCache_.clear();
    TrimHashTable(ruleCache_);
    estatsOn_.clear();
    TrimHashTable(estatsOn_);
    procOrder_.clear();
    TrimHashTable(procOrder_);
    system_ = FlowStore::SystemSnapshot{};
    view_ = FlowStore::DisplayView{};

    tableBuffer_.reset();

    tick_ = 0;
}

void Monitor::RequestRefresh() {
    {
        std::lock_guard<std::mutex> lock(requestMtx_);
        if (stopRequested_ || !worker_.joinable()) return;
        refreshRequested_ = true;
    }
    requestCv_.notify_one();
}

void Monitor::SetDisplayEnabled(bool on) {
    {
        std::lock_guard<std::mutex> lock(requestMtx_);
        if (displayEnabled_ == on) [[likely]] return;
        displayEnabled_ = on;
        ++displayVersion_;
        refreshRequested_ = true;
        // Готовый снимок до смены видимости годится для подсказки трея, но
        // восстановленное окно должно дождаться нового полного снимка.
        std::lock_guard<std::mutex> publishLock(publishMtx_);
        published_.displayReady = false;
    }
    requestCv_.notify_one();
}

bool Monitor::TakeLatest(Snapshot& out) {
    std::lock_guard<std::mutex> lock(publishMtx_);
    if (!publishedReady_) return false;
    using std::swap;
    swap(out, published_);
    publishedReady_ = false;
    return true;
}

void Monitor::WorkerLoop() {
    using Clock = std::chrono::steady_clock;
    auto nextPoll = Clock::time_point{};
    Snapshot working;
    for (;;) {
        bool buildDisplay = false;
        uint64_t displayVersion = 0;
        {
            std::unique_lock<std::mutex> lock(requestMtx_);
            requestCv_.wait(lock, [this]() {
                return stopRequested_ || refreshRequested_;
            });
            if (stopRequested_) [[unlikely]] return;
            // Внеочередное обновление UI не создаёт короткий цикл измерения.
            requestCv_.wait_until(lock, nextPoll, [this]() {
                return stopRequested_;
            });
            if (stopRequested_) [[unlikely]] return;
            refreshRequested_ = false;
            buildDisplay = displayEnabled_;
            displayVersion = displayVersion_;
        }

        nextPoll = Clock::now() + std::chrono::seconds(1);
        BuildSnapshot(working, buildDisplay);

        HWND notifyWindow = nullptr;
        UINT notifyMessage = 0;
        {
            std::lock_guard<std::mutex> lock(requestMtx_);
            if (stopRequested_) [[unlikely]] return;
            // Окно могло скрыться и снова появиться, пока снимок строился.
            // Такой проход не должен перезаписать таблицу устаревшими строками.
            if (displayVersion != displayVersion_) [[unlikely]]
                working.displayReady = false;
            {
                std::lock_guard<std::mutex> publishLock(publishMtx_);
                using std::swap;
                swap(published_, working);
                publishedReady_ = true;
            }
            notifyWindow = notifyWindow_;
            notifyMessage = notifyMessage_;
        }
        if (notifyWindow && notifyMessage)
            PostMessageW(notifyWindow, notifyMessage, 0, 0);
    }
}

bool Monitor::EstatsUseful(DWORD state) {
    if (state == MIB_TCP_STATE_LISTEN) return false;
    return !TcpTransferDone(state);
}

void Monitor::ApplyEstats(FlowStore::SystemTcpConnection& connection) {
    if (!estatsOk_ || connection.state == MIB_TCP_STATE_LISTEN) return;

    const EstatsId id{
        connection.key, connection.pid,
        connection.localScope, connection.remoteScope
    };
    auto slot = estatsOn_.find(id);
    if (slot != estatsOn_.end() && tick_ - slot->second.tick > 1) [[unlikely]] {
        // Между двумя наблюдениями tuple отсутствовал. Новый TCB не наследует
        // включённую подписку и базу прежнего соединения.
        estatsOn_.erase(slot);
        slot = estatsOn_.end();
    }
    if (slot == estatsOn_.end()) {
        if (!EstatsUseful(connection.state)) return;
        slot = estatsOn_.emplace(id, EstatsSlot{}).first;
    }

    EstatsSlot& state = slot->second;
    if (state.state != connection.state) [[unlikely]] {
        state.state = connection.state;
        state.tries = 0;
    }
    state.tick = tick_;

    const bool ipv4 = connection.key.local.family == AF_INET;
    MIB_TCPROW row4{};
    MIB_TCP6ROW row6{};
    if (ipv4) {
        row4.dwState = connection.state;
        std::memcpy(&row4.dwLocalAddr, connection.key.local.b, 4);
        std::memcpy(&row4.dwRemoteAddr, connection.key.remote.b, 4);
        row4.dwLocalPort = htons(connection.key.lport);
        row4.dwRemotePort = htons(connection.key.rport);
    } else {
        row6.State = static_cast<MIB_TCP_STATE>(connection.state);
        std::memcpy(&row6.LocalAddr, connection.key.local.b, 16);
        std::memcpy(&row6.RemoteAddr, connection.key.remote.b, 16);
        row6.dwLocalScopeId = connection.localScope;
        row6.dwRemoteScopeId = connection.remoteScope;
        row6.dwLocalPort = htons(connection.key.lport);
        row6.dwRemotePort = htons(connection.key.rport);
    }

    if (!state.enabled) {
        if (!EstatsUseful(connection.state) ||
            state.tries >= kEstatsMaxTries) return;
        ++state.tries;
        TCP_ESTATS_DATA_RW_v0 rw{};
        rw.EnableCollection = TRUE;
        const DWORD enabled = ipv4
            ? SetPerTcpConnectionEStats(
                &row4, TcpConnectionEstatsData,
                reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0)
            : SetPerTcp6ConnectionEStats(
                &row6, TcpConnectionEstatsData,
                reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0);
        if (enabled != NO_ERROR) [[unlikely]] {
            if (enabled == ERROR_ACCESS_DENIED) {
                estatsOk_ = false;
                estatsNote_ = LoadStringRes(IDS_ESTATS_ACCESS_DENIED);
            }
            return;
        }
        state.enabled = true;
        state.tries = 0;
    }

    TCP_ESTATS_DATA_ROD_v0 data{};
    const DWORD read = ipv4
        ? GetPerTcpConnectionEStats(
            &row4, TcpConnectionEstatsData, nullptr, 0, 0,
            nullptr, 0, 0, reinterpret_cast<PUCHAR>(&data), 0, sizeof(data))
        : GetPerTcp6ConnectionEStats(
            &row6, TcpConnectionEstatsData, nullptr, 0, 0,
            nullptr, 0, 0, reinterpret_cast<PUCHAR>(&data), 0, sizeof(data));
    if (read != NO_ERROR) [[unlikely]] {
        state.enabled = false;
        return;
    }

    connection.sent = data.DataBytesOut;
    connection.recv = data.DataBytesIn;
    connection.countersAt = GetTickCount64();
    connection.countersRead = true;
}

template <class Table>
size_t Monitor::AddTcpRows(
    const TableBuffer& buffer,
    std::vector<FlowStore::SystemTcpConnection>& rows) {
    const auto* table = reinterpret_cast<const Table*>(buffer.data());
    ResizeSystemRows(rows, table->dwNumEntries);
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const auto& source = table->table[index];
        FlowStore::SystemTcpConnection& connection = rows[index];
        connection = FlowStore::SystemTcpConnection{};
        connection.pid = source.dwOwningPid;
        connection.state = source.dwState;
        connection.localScope = TcpLocalScope(source);
        connection.remoteScope = TcpRemoteScope(source);
        connection.key.proto = Proto::Tcp;
        connection.key.local = TcpLocal(source);
        connection.key.lport = ntohs(static_cast<u_short>(source.dwLocalPort));
        connection.key.remote.family = connection.key.local.family;
        if (source.dwState != MIB_TCP_STATE_LISTEN) {
            connection.key.remote = TcpRemote(source);
            connection.key.rport = ntohs(
                static_cast<u_short>(source.dwRemotePort));
            ApplyEstats(connection);
        }
    }
    return offsetof(Table, table) + table->dwNumEntries * sizeof(table->table[0]);
}

template <class Table>
size_t Monitor::AddUdpRows(
    const TableBuffer& buffer,
    std::vector<FlowStore::SystemUdpEndpoint>& rows) {
    const auto* table = reinterpret_cast<const Table*>(buffer.data());
    ResizeSystemRows(rows, table->dwNumEntries);
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const auto& source = table->table[index];
        FlowStore::SystemUdpEndpoint& endpoint = rows[index];
        endpoint = FlowStore::SystemUdpEndpoint{};
        endpoint.local = UdpLocal(source);
        endpoint.port = ntohs(static_cast<u_short>(source.dwLocalPort));
        endpoint.pid = source.dwOwningPid;
    }
    return offsetof(Table, table) + table->dwNumEntries * sizeof(table->table[0]);
}

void Monitor::CollectSystemSnapshot(FlowStore::SystemSnapshot& snapshot) {
    snapshot.tcpV4Valid = false;
    snapshot.tcpV6Valid = false;
    snapshot.udpV4Valid = false;
    snapshot.udpV6Valid = false;

    size_t used = 0;
    snapshot.tcpV4Valid = FetchTable(Which::Tcp, AF_INET, tableBuffer_);
    if (snapshot.tcpV4Valid) [[likely]]
        used = std::max(used, AddTcpRows<MIB_TCPTABLE_OWNER_PID>(tableBuffer_, snapshot.tcpV4));
    else
        ResizeSystemRows(snapshot.tcpV4, 0);

    snapshot.tcpV6Valid = FetchTable(Which::Tcp, AF_INET6, tableBuffer_);
    if (snapshot.tcpV6Valid) [[likely]]
        used = std::max(used, AddTcpRows<MIB_TCP6TABLE_OWNER_PID>(tableBuffer_, snapshot.tcpV6));
    else
        ResizeSystemRows(snapshot.tcpV6, 0);

    snapshot.udpV4Valid = FetchTable(Which::Udp, AF_INET, tableBuffer_);
    if (snapshot.udpV4Valid) [[likely]]
        used = std::max(used, AddUdpRows<MIB_UDPTABLE_OWNER_PID>(tableBuffer_, snapshot.udpV4));
    else
        ResizeSystemRows(snapshot.udpV4, 0);

    snapshot.udpV6Valid = FetchTable(Which::Udp, AF_INET6, tableBuffer_);
    if (snapshot.udpV6Valid) [[likely]]
        used = std::max(used, AddUdpRows<MIB_UDP6TABLE_OWNER_PID>(tableBuffer_, snapshot.udpV6));
    else
        ResizeSystemRows(snapshot.udpV6, 0);
    tableBuffer_.Trim(used);
}

void Monitor::PruneCaches(bool cacheRuleMatches) {
    for (auto it = estatsOn_.begin(); it != estatsOn_.end();) {
        it = tick_ - it->second.tick > kEstatsKeepTicks
            ? estatsOn_.erase(it) : std::next(it);
    }
    TrimHashTable(estatsOn_);

    if (cacheRuleMatches) {
        for (auto it = ruleCache_.begin(); it != ruleCache_.end();) {
            it = it->second.seenTick == tick_ ? std::next(it)
                                              : ruleCache_.erase(it);
        }
    } else {
        ruleCache_.clear();
    }
    TrimHashTable(ruleCache_);

    for (auto it = procOrder_.begin(); it != procOrder_.end();) {
        it = it->second.seenTick == tick_ ? std::next(it)
                                          : procOrder_.erase(it);
    }
    TrimHashTable(procOrder_);
}

void Monitor::BuildSnapshot(Snapshot& out, bool buildDisplay) {
    // Snapshot возвращается worker-у после O(1)-обмена с UI. Массивы имеют
    // точный текущий размер, без запаса ёмкости и отдельных массивов на процесс.
    out.displayReady = buildDisplay;
    out.totalSent = 0;
    out.totalRecv = 0;
    out.connCount = 0;
    out.hiddenCount = 0;
    out.driverOnlyFlows = 0;
    out.closedDropped = 0;
    out.ruleMatches = 0;
    out.flowCount = 0;

    ++tick_;
    pmkext::ProcessTable::Instance().maintain();
    FlowStore& store = FlowStore::Instance();
    if (bandwidthRequest_) {
        store.BeginBandwidthPoll(GetTickCount64());
        if (!bandwidthRequest_()) store.CancelBandwidthPoll();
    }
    // Пока читаются таблицы ОС и EStats, reader применяет ответы драйвера.
    CollectSystemSnapshot(system_);

    store.ReplaceSystemSnapshot(system_);
    store.TakeDisplay(
        view_, FlowStore::kInactiveMs,
        showPassive_.load(std::memory_order_relaxed), buildDisplay);
    out.flowCount = view_.flowCount;
    out.hiddenCount = view_.hiddenCount;
    out.driverOnlyFlows = view_.driverOnlyFlows;
    out.closedDropped = view_.removedConnections;

    // Volatile-условия всё равно требуют нового matcher-прохода. В этом режиме
    // не держим пустой RuleCacheEntry для десятков тысяч соединений.
    // Один снимок использует одну политику; крайние режимы не приписывают
    // соединению действие правила, которое Ingest намеренно обошёл.
    const FirewallPolicy currentPolicy = policy_.load(std::memory_order_relaxed);
    const bool useRules = buildDisplay && FirewallPolicies::UsesRules(currentPolicy);
    const bool cacheRuleMatches = useRules && rules_ && !rules_->volatileConds();
    const uint64_t rulesVersion = useRules && rules_ ? rules_->version() : 0;

    out.procs.reset(view_.processes.size());
    out.conns.reset(view_.connections.size());
    size_t outputProcessCount = 0;
    size_t connectionIndex = 0;

    for (FlowStore::DisplayProcess& storedProcess : view_.processes) {
        const TrafficGroupKey group = storedProcess.group;
        const DWORD processId = group.pid();
        const bool processFinished = storedProcess.removeAfter != 0;

        ProcItem& node = out.procs[outputProcessCount++];
        node.group = group;
        node.name.clear();
        node.path.clear();
        if (!buildDisplay) {
            // UI больше не заполнит эти строки: сводка трея не должна держать
            // прежние буферы имён и путей при неизменном числе процессов.
            TrimCapacity(node.name);
            TrimCapacity(node.path);
        }
        node.pathInfo = buildDisplay && group.isHost() ? ProcessImagePathRef(processId) : nullptr;
        node.hostedServices = buildDisplay && group.isHost()
            ? ServiceInfo::ServicesOfPid(processId) : nullptr;
        node.pathKnown = node.pathInfo && !node.pathInfo->text.empty();
        node.ownerAmbiguous = storedProcess.ownerAmbiguous;
        node.icon.reset();
        node.sent = 0;
        node.recv = 0;
        node.bytesKnown = false;
        node.speed = storedProcess.speed;
        node.ruleHits = 0;
        node.finished = processFinished;
        node.conns = out.conns.span().subspan(
            connectionIndex, storedProcess.connections.size());

        auto [processOrder, newProcessOrder] =
            procOrder_.try_emplace(group);
        if (newProcessOrder) [[unlikely]] processOrder->second.order = ++orderSeq_;
        processOrder->second.seenTick = tick_;
        node.order = processOrder->second.order;

        if (!buildDisplay) {
            out.connCount += storedProcess.connCount;
            continue;
        }

        for (FlowStore::DisplayConnection& display :
             storedProcess.connections) {
            ConnItem& connection = out.conns[connectionIndex++];
            connection = ConnItem{};
            connection.key = display.key;
            connection.tlsDomainLabel = std::move(display.tlsDomainLabel);
            connection.flowGeneration = display.flowGeneration;
            connection.sent = display.sent;
            connection.recv = display.recv;
            connection.lastActivity = display.lastActivity;
            connection.blockedAt = display.blockedAt;
            connection.pktSent = display.pktSent;
            connection.pktRecv = display.pktRecv;
            connection.driverEvents = display.driverEvents;
            connection.pid = processId;
            connection.state = display.state;
            connection.interfaceIndex = display.interfaceIndex;
            connection.interfaceName = std::move(display.interfaceName);
            connection.dir = display.dir;
            connection.bytesFrom = display.bytesFrom;
            connection.ownerAmbiguous = display.ownerAmbiguous;
            connection.processExited = processFinished;
            connection.finished = processFinished ||
                (display.removeAfter != 0 && display.blockedAt == 0);
            connection.conditionFlags = display.conditionFlags;
            connection.icmp = display.icmp;
            connection.icmpOut = display.icmpOut;
            connection.icmpIn = display.icmpIn;

            if (connection.bytesKnown() &&
                (connection.bytesFrom != BytesDriver ||
                 !connection.finished)) {
                connection.speed = display.bytesPerSecond();
            }

            if (useRules && rules_) {
                // При попадании в кеш условия сопоставления собирать не нужно.
                const auto matchInfo = [&](RuleMatchInfo& info) {
                    const std::wstring_view appPath = node.pathInfo
                        ? std::wstring_view(node.pathInfo->text)
                        : std::wstring_view{};
                    MatchQuery query = MakeMatchQuery(
                        appPath, connection.pid, connection.key,
                        connection.dir, connection.icmp.type,
                        connection.icmp.code,
                        node.pathInfo ? node.pathInfo->process.get() : nullptr,
                        connection.conditionFlags);
                    query.interfaceIndex = connection.interfaceIndex;
                    query.interfaceName = connection.interfaceName.get();
                    if (node.pathInfo) {
                        PrepareMatchAppPath(
                            query, node.pathInfo->folded,
                            node.pathInfo->foldedHash);
                    }
                    return rules_->MatchInfo(query, info, false);
                };

                bool found = false;
                uint64_t ruleId = 0;
                RuleScope scope = RuleScope::App;
                RuleAction action = RuleAction::Allow;
                if (cacheRuleMatches && node.pathInfo) {
                    RuleCacheEntry& cached =
                        ruleCache_[connection.flowGeneration];
                    cached.seenTick = tick_;
                    const bool valid =
                        cached.interfaceIndex == connection.interfaceIndex &&
                        cached.interfaceName == connection.interfaceName &&
                        cached.rulesVersion == rulesVersion &&
                        cached.pathInfo == node.pathInfo.get() &&
                        cached.dir == connection.dir &&
                        cached.icmpType == connection.icmp.type &&
                        cached.icmpCode == connection.icmp.code &&
                        cached.conditionFlags == connection.conditionFlags &&
                        cached.ownerAmbiguous == connection.ownerAmbiguous;
                    if (!valid) [[unlikely]] {
                        RuleMatchInfo fresh;
                        cached.found = matchInfo(fresh);
                        cached.ruleId = cached.found ? fresh.id : 0;
                        cached.scope = fresh.scope;
                        cached.action = fresh.action;
                        cached.rulesVersion = rulesVersion;
                        cached.interfaceIndex = connection.interfaceIndex;
                        cached.interfaceName = connection.interfaceName;
                        cached.pathInfo = node.pathInfo.get();
                        cached.dir = connection.dir;
                        cached.icmpType = connection.icmp.type;
                        cached.icmpCode = connection.icmp.code;
                        cached.conditionFlags = connection.conditionFlags;
                        cached.ownerAmbiguous = connection.ownerAmbiguous;
                    }
                    found = cached.found;
                    ruleId = cached.ruleId;
                    scope = cached.scope;
                    action = cached.action;
                } else {
                    RuleMatchInfo fresh;
                    found = matchInfo(fresh);
                    if (found) {
                        ruleId = fresh.id;
                        scope = fresh.scope;
                        action = fresh.action;
                    }
                }

                if (found) {
                    connection.ruleId = ruleId;
                    connection.ruleGlobal = scope == RuleScope::Global;
                    connection.ruleAction = static_cast<int>(action);
                    ++out.ruleMatches;
                    ++node.ruleHits;
                }
            }

            if (!connection.ruleId &&
                (currentPolicy != FirewallPolicy::Learning ||
                 ProtoIsIcmp(connection.key.proto))) {
                MatchQuery query;
                query.proto = connection.key.proto;
                query.remoteAddr = connection.key.remote;
                query.icmpType = connection.icmp.type;
                query.icmpCode = connection.icmp.code;
                const auto decision = FirewallPolicies::Evaluate(
                    currentPolicy, nullptr, query, nullptr,
                    currentPolicy == FirewallPolicy::Learning);
                connection.autoAllowedIcmp = decision.autoAllowedIcmp &&
                                            !connection.blockedAt;
                connection.byPolicy = decision.decided && !decision.autoAllowedIcmp;
                connection.policy = currentPolicy;
                if (decision.decided)
                    connection.ruleAction = static_cast<int>(decision.action);
            }

            // Текст причины нужен только раскрытой строке либо фильтру и
            // строится лениво в App::RebuildRows.
            if (connection.blockedAt)
                connection.ruleAction = static_cast<int>(RuleAction::Block);

            if (connection.bytesKnown()) {
                node.sent += connection.sent;
                node.recv += connection.recv;
                node.bytesKnown = true;
            }
            node.ownerAmbiguous = node.ownerAmbiguous ||
                                  connection.ownerAmbiguous;
        }

        std::sort(node.conns.begin(), node.conns.end(),
                  [](const ConnItem& left, const ConnItem& right) {
                      return left.flowGeneration < right.flowGeneration;
                  });
        if (!node.finished) {
            node.finished = std::all_of(
                node.conns.begin(), node.conns.end(),
                [](const ConnItem& connection) { return connection.finished; });
        }
        out.totalSent += node.sent;
        out.totalRecv += node.recv;
        out.connCount += node.conns.size();
    }

    PruneCaches(cacheRuleMatches);

    if (buildDisplay) {
        std::sort(out.procs.begin(), out.procs.end(),
                  [](const ProcItem& left, const ProcItem& right) {
                      return left.order < right.order;
                  });
    }
}
