#include "FlowStore.h"
#include "MacroAddr.h"
#include "SystemInfo.h"
#include "StorageMaintenance.h"
#include "network_interface_watcher.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <unordered_set>
#include <utility>

namespace {

// Снимок удерживает строку без копии и отдельного выделения памяти на соединение.
// Повторные события того же интерфейса не ищут имя заново; пустое имя тоже фиксируется.
void CaptureInterface(FlowStore::DriverDetails& details, uint32_t index,
                      const std::shared_ptr<const std::wstring>& name = {}) {
    if (name) {
        details.interfaceIndex = index;
        details.interfaceName = name;
        return;
    }
    if (details.interfaceName && details.interfaceIndex == index) return;
    details.interfaceIndex = index;
    static const auto unknown = std::make_shared<const std::wstring>();
    details.interfaceName = unknown;
    if (!index) return;
    const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
    if (snapshot) {
        for (const auto& entry : snapshot->interfaces) {
            if (entry.number == index || entry.ipv6_number == index) {
                details.interfaceName = std::shared_ptr<const std::wstring>(snapshot, &entry.name);
                break;
            }
        }
    }
}

size_t CategoryIndex(Proto proto, uint16_t family) {
    if (proto == Proto::Tcp) return family == AF_INET ? 0u : 1u;
    return family == AF_INET ? 2u : 3u;
}

IpAddr AddressOf(const IpEndpoint& endpoint) {
    IpAddr address;
    address.family = endpoint.family;
    std::memcpy(address.b, endpoint.b, endpoint.len());
    return address;
}

template <class Table>
void AddSocketOwner(Table& table, const IpAddr& local, uint16_t port,
                    DWORD pid) {
    const IpEndpoint endpoint = MakeIpEndpoint(local, port);
    auto [it, inserted] = table.try_emplace(endpoint);
    auto& owner = it->second;
    if (inserted) {
        owner.pid = pid;
        return;
    }
    if (owner.ownerAmbiguous) return;
    if (owner.pid && pid && owner.pid != pid) {
        owner.pid = 0;
        owner.ownerAmbiguous = true;
        return;
    }
    if (!owner.pid && pid) owner.pid = pid;
}

bool IsPassiveDisplayConnection(
    const FlowStore::ConnectionRecord& connection,
    uint64_t sent, uint64_t recv,
    uint64_t periodSent, uint64_t periodRecv,
    ULONGLONG lastActivity, ULONGLONG now) {
    if (connection.key.source == TrafficSource::Ndis) return false;
    constexpr ULONGLONG kUdpFreshMs = 60 * 1000;
    constexpr ULONGLONG kOtherFreshMs = 8 * 1000;
    const bool hasActivity = sent != 0 || recv != 0 ||
                             periodSent != 0 || periodRecv != 0;

    if (connection.key.proto == Proto::Tcp) {
        const bool fresh = lastActivity &&
                           now - lastActivity <= kUdpFreshMs;
        switch (connection.state) {
        case MIB_TCP_STATE_LISTEN:
        case MIB_TCP_STATE_CLOSED:
        case MIB_TCP_STATE_DELETE_TCB:
        case MIB_TCP_STATE_TIME_WAIT:
            return !hasActivity && !fresh;
        default:
            return !connection.key.rport && connection.key.remote.isAny() &&
                   !hasActivity && !fresh;
        }
    }

    if (connection.key.proto == Proto::Udp) {
        const bool fresh = lastActivity &&
                           now - lastActivity <= kUdpFreshMs;
        const bool concrete = connection.key.rport != 0 ||
                              !connection.key.remote.isAny();
        if (concrete && (fresh || hasActivity)) return false;
        if (!concrete && fresh) return false;
        return true;
    }

    return !lastActivity || now - lastActivity > kOtherFreshMs;
}

bool IsDisplayState(const FlowStore::ConnectionRecord& connection) {
    return connection.key.proto != Proto::Tcp || connection.driverBacked ||
           connection.state == MIB_TCP_STATE_LISTEN ||
           connection.state == MIB_TCP_STATE_ESTAB;
}

struct DisplayTraffic {
    uint64_t sent = 0, recv = 0;
    uint64_t periodSent = 0, periodRecv = 0;
    FlowStore::TrafficPeriod period;
    ULONGLONG lastActivity = 0;
    BytesSource bytesFrom = BytesNone;
    bool passive = false;
};

DisplayTraffic DisplayTrafficOf(
    const FlowStore::ProcessConnections& process,
    const FlowStore::ConnectionRecord& connection,
    ULONGLONG lastTakeAt, ULONGLONG now) {
    DisplayTraffic traffic;
    const FlowStore::DriverDetails* details = connection.driver.get();
    if (!connection.retired && connection.systemTrafficAuthoritative) {
        traffic.sent = connection.lastSystemSent;
        traffic.recv = connection.lastSystemRecv;
        traffic.periodSent = connection.systemPeriodSent;
        traffic.periodRecv = connection.systemPeriodRecv;
        traffic.period = connection.systemPeriod;
        traffic.bytesFrom = BytesEstats;
    } else if (!connection.retired && details && details->countersActive) {
        traffic.sent = details->sent;
        traffic.recv = details->recv;
        traffic.periodSent = details->periodSent;
        traffic.periodRecv = details->periodRecv;
        // Пакетные события измеряются между снимками UI, bandwidth-отчёты —
        // собственным интервалом драйвера, независимо от системных таблиц.
        traffic.period = (ProtoInOsTables(connection.key.proto) ||
                          (connection.key.source == TrafficSource::Ndis &&
                           details->lastBandwidthAt))
            ? details->period : FlowStore::TrafficPeriod{ lastTakeAt, now };
        traffic.bytesFrom = BytesDriver;
    } else if (!ProtoInOsTables(connection.key.proto) && details &&
               details->events) {
        traffic.sent = details->sent;
        traffic.recv = details->recv;
        traffic.periodSent = details->periodSent;
        traffic.periodRecv = details->periodRecv;
        traffic.period = { lastTakeAt, now };
        traffic.bytesFrom = BytesDriver;
    } else if (details && details->frozenCountersKnown) {
        traffic.sent = details->frozenSent;
        traffic.recv = details->frozenRecv;
        traffic.bytesFrom = details->frozenFromSystem
            ? BytesEstats : BytesDriver;
    }
    traffic.lastActivity = connection.lastActivity;
    if (traffic.bytesFrom == BytesDriver && details)
        traffic.lastActivity = std::max(
            traffic.lastActivity, details->lastChangedAt);
    traffic.passive = !process.removeAfter && !connection.removeAfter &&
        !connection.blockedAt && IsPassiveDisplayConnection(
            connection, traffic.sent, traffic.recv,
            traffic.periodSent, traffic.periodRecv, traffic.lastActivity, now);
    return traffic;
}

} // namespace

void FlowStore::ReadDebugCounters(DebugCounters::Snapshot& out) const {
    std::unique_lock lock(mtx_, std::try_to_lock);
    if (!lock.owns_lock()) return;
    auto& v = out.values;
    v[DebugCounters::FlowProcesses] = processes_.size();
    // Обходим только процессы: size() вложенной таблицы не обходит соединения.
    size_t connections = 0;
    for (const auto& [pid, process] : processes_) {
        (void)pid;
        connections += process.connections.size();
    }
    v[DebugCounters::FlowConnections] = connections;
    v[DebugCounters::FlowNdisConnections] = ndisConnections_.size();
    v[DebugCounters::OwnerTcpV4] = ownerIndexes_.tcpV4.size();
    v[DebugCounters::OwnerTcpV6] = ownerIndexes_.tcpV6.size();
    v[DebugCounters::OwnerUdpV4] = ownerIndexes_.udpV4.size();
    v[DebugCounters::OwnerUdpV6] = ownerIndexes_.udpV6.size();
    v[DebugCounters::LocalTcpV4] = localSockets_.tcpV4.size();
    v[DebugCounters::LocalTcpV6] = localSockets_.tcpV6.size();
    v[DebugCounters::LocalUdpV4] = localSockets_.udpV4.size();
    v[DebugCounters::LocalUdpV6] = localSockets_.udpV6.size();
}

FlowStore& FlowStore::Instance() {
    static FlowStore instance;
    return instance;
}

FlowStore::DriverTrafficTable* FlowStore::DriverTableFor(
    DriverTrafficTables& tables, const FlowKey& key) {
    if (key.proto == Proto::Tcp)
        return key.local.family == AF_INET ? &tables.tcpV4 : &tables.tcpV6;
    if (key.proto == Proto::Udp)
        return key.local.family == AF_INET ? &tables.udpV4 : &tables.udpV6;
    return nullptr;
}

const FlowStore::DriverTrafficTable* FlowStore::DriverTableFor(
    const DriverTrafficTables& tables, const FlowKey& key) {
    if (key.proto == Proto::Tcp)
        return key.local.family == AF_INET ? &tables.tcpV4 : &tables.tcpV6;
    if (key.proto == Proto::Udp)
        return key.local.family == AF_INET ? &tables.udpV4 : &tables.udpV6;
    return nullptr;
}

FlowStore::DriverDetails& FlowStore::EnsureDriverDetails(
    ConnectionRecord& connection) {
    if (!connection.driver) {
        connection.driver = std::make_shared<DriverDetails>();
    } else if (connection.driver.use_count() != 1) {
        // Полный диагностический View мог сохранить прежнее состояние. Перед
        // изменением отделяем live-копию, чтобы уже выданный снимок не менялся.
        connection.driver = std::make_shared<DriverDetails>(*connection.driver);
    }
    return *connection.driver;
}

const FlowStore::DriverDetails* FlowStore::DriverDetailsOf(
    const ConnectionRecord& connection) {
    return connection.driver.get();
}

FlowStore::SystemTrafficTable* FlowStore::SystemTableFor(
    SystemTrafficTables& tables, const FlowKey& key) {
    if (key.proto != Proto::Tcp) return nullptr;
    return key.local.family == AF_INET ? &tables.tcpV4 : &tables.tcpV6;
}

const FlowStore::SystemTrafficTable* FlowStore::SystemTableFor(
    const SystemTrafficTables& tables, const FlowKey& key) {
    if (key.proto != Proto::Tcp) return nullptr;
    return key.local.family == AF_INET ? &tables.tcpV4 : &tables.tcpV6;
}

FlowStore::ConnectionOwnerIndex* FlowStore::OwnerIndexFor(
    ConnectionOwnerIndexes& indexes, const FlowKey& key) {
    if (key.source == TrafficSource::Ndis) return nullptr;
    if (key.proto == Proto::Tcp)
        return key.local.family == AF_INET ? &indexes.tcpV4 : &indexes.tcpV6;
    if (key.proto == Proto::Udp)
        return key.local.family == AF_INET ? &indexes.udpV4 : &indexes.udpV6;
    return nullptr;
}

const FlowStore::ConnectionOwnerIndex* FlowStore::OwnerIndexFor(
    const ConnectionOwnerIndexes& indexes, const FlowKey& key) {
    if (key.source == TrafficSource::Ndis) return nullptr;
    if (key.proto == Proto::Tcp)
        return key.local.family == AF_INET ? &indexes.tcpV4 : &indexes.tcpV6;
    if (key.proto == Proto::Udp)
        return key.local.family == AF_INET ? &indexes.udpV4 : &indexes.udpV6;
    return nullptr;
}

FlowStore::LocalSocketTable* FlowStore::SocketTableFor(
    LocalSocketTables& tables, Proto proto, uint16_t family) {
    if (proto == Proto::Tcp)
        return family == AF_INET ? &tables.tcpV4 : &tables.tcpV6;
    if (proto == Proto::Udp)
        return family == AF_INET ? &tables.udpV4 : &tables.udpV6;
    return nullptr;
}

const FlowStore::LocalSocketTable* FlowStore::SocketTableFor(
    const LocalSocketTables& tables, Proto proto, uint16_t family) {
    if (proto == Proto::Tcp)
        return family == AF_INET ? &tables.tcpV4 : &tables.tcpV6;
    if (proto == Proto::Udp)
        return family == AF_INET ? &tables.udpV4 : &tables.udpV6;
    return nullptr;
}

bool FlowStore::ResolveSocketLocked(Proto proto, const IpAddr& local,
                                    uint16_t port, DWORD& pid,
                                    bool& ambiguous) const {
    pid = 0;
    ambiguous = false;
    bool found = false;

    const auto consider = [&](const LocalSocketTable* table,
                              const IpEndpoint& endpoint) {
        if (!table) return;
        const auto it = table->find(endpoint);
        if (it == table->end()) return;
        found = true;
        if (it->second.ownerAmbiguous) {
            ambiguous = true;
            return;
        }
        const DWORD candidate = it->second.pid;
        if (!candidate) return;
        if (!pid) pid = candidate;
        else if (pid != candidate) ambiguous = true;
    };

    const LocalSocketTable* same = SocketTableFor(localSockets_, proto,
                                                   local.family);
    consider(same, MakeIpEndpoint(local, port));
    if (!local.isAny()) consider(same, MakeIpWildcard(local.family, port));

    // Независимый IPv6 wildcard может принимать IPv4, если IPV6_V6ONLY снят.
    // IP Helper не сообщает этот флаг, поэтому такой endpoint рассматривается
    // вместе с IPv4-кандидатами; конфликт PID остаётся неоднозначным.
    if (local.family == AF_INET) {
        const LocalSocketTable* v6 = SocketTableFor(localSockets_, proto,
                                                     AF_INET6);
        consider(v6, MakeIpWildcard(AF_INET6, port));
    }

    if (ambiguous) pid = 0;
    return found;
}

uint64_t FlowStore::NextGenerationLocked() {
    ++generationSeq_;
    if (!generationSeq_) [[unlikely]] ++generationSeq_;
    return generationSeq_;
}

FlowStore::ProcessConnections& FlowStore::GroupLocked(TrafficGroupKey group) {
    return processes_.try_emplace(group).first->second;
}

FlowStore::ConnectionOwnerIndexEntry& FlowStore::OwnerLocked(
    const FlowKey& key, ULONGLONG now) {
    ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key);
    auto [it, inserted] = index->try_emplace(key);
    ConnectionOwnerIndexEntry& owner = it->second;
    owner.lastAccessAt = now;
    (void)inserted;
    return owner;
}

FlowStore::ConnectionRecord* FlowStore::CurrentConnectionLocked(
    const FlowKey& key, const ConnectionOwnerIndexEntry& owner) {
    if (!owner.connectionGeneration) return nullptr;
    const uint64_t id = owner.connectionGeneration;

    if (auto process = processes_.find(owner.pid); process != processes_.end()) [[likely]] {
        if (auto connection = process->second.connections.find(id);
            connection != process->second.connections.end() &&
            connection->second.key == key)
            return &connection->second;
    }

    // PID 4 намеренно не назначается индексом из on_connection_*. До первого
    // системного снимка запись может уже находиться в процессе 4 при owner.pid=0.
    for (auto& process : processes_) {
        auto connection = process.second.connections.find(id);
        if (connection != process.second.connections.end() &&
            connection->second.key == key)
            return &connection->second;
    }
    return nullptr;
}

const FlowStore::ConnectionRecord* FlowStore::CurrentConnectionLocked(
    const FlowKey& key, const ConnectionOwnerIndexEntry& owner) const {
    if (!owner.connectionGeneration) return nullptr;
    const uint64_t id = owner.connectionGeneration;

    if (auto process = processes_.find(owner.pid); process != processes_.end()) [[likely]] {
        if (auto connection = process->second.connections.find(id);
            connection != process->second.connections.end() &&
            connection->second.key == key)
            return &connection->second;
    }
    for (const auto& process : processes_) {
        auto connection = process.second.connections.find(id);
        if (connection != process.second.connections.end() &&
            connection->second.key == key)
            return &connection->second;
    }
    return nullptr;
}

FlowStore::ConnectionRecord* FlowStore::VerdictConnectionLocked(
    const FlowKey& key, DWORD pid, uint64_t generation) {
    ConnectionRecord* connection = nullptr;
    const TrafficGroupKey group = key.source == TrafficSource::Ndis
        ? TrafficGroupKey::Ndis(key.interfaceIndex) : TrafficGroupKey::Host(pid);
    if (auto process = processes_.find(group); process != processes_.end()) {
        if (auto found = process->second.connections.find(generation);
            found != process->second.connections.end())
            connection = &found->second;
    }
    // Пока пользователь выбирал ответ, системный снимок мог уточнить PID.
    if (!connection) {
        if (const ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key)) {
            const auto owner = index->find(key);
            if (owner != index->end() && owner->second.connectionGeneration == generation)
                connection = CurrentConnectionLocked(key, owner->second);
        }
    }
    return connection && connection->key == key &&
           !connection->endReceived && !connection->retired
        ? connection : nullptr;
}

void FlowStore::FreezeConnectionLocked(ConnectionRecord& connection) {
    const DriverDetails* current = DriverDetailsOf(connection);
    if (current && current->frozenCountersKnown) return;

    if (connection.systemTrafficAuthoritative) {
        DriverDetails& details = EnsureDriverDetails(connection);
        details.frozenSent = connection.lastSystemSent;
        details.frozenRecv = connection.lastSystemRecv;
        details.frozenCountersKnown = true;
        details.frozenFromSystem = true;
        return;
    }

    if (current && (current->countersActive ||
        (!ProtoInOsTables(connection.key.proto) && current->events))) {
        DriverDetails& details = EnsureDriverDetails(connection);
        details.frozenSent = details.sent;
        details.frozenRecv = details.recv;
        details.frozenCountersKnown = true;
        details.frozenFromSystem = false;
    }
}

void FlowStore::MoveCurrentFlowLocked(const FlowKey& key,
                                      ConnectionOwnerIndexEntry& owner,
                                      DWORD pid) {
    const DWORD oldPid = owner.pid;
    const uint64_t generation = owner.connectionGeneration;
    if (oldPid == pid) {
        if (ConnectionRecord* connection = CurrentConnectionLocked(key, owner))
            connection->pid = pid;
        GroupLocked(pid);
        return;
    }

    owner.pid = pid;
    if (!generation) {
        GroupLocked(pid);
        return;
    }

    const uint64_t id = generation;
    TrafficGroupKey sourceGroup;
    bool sourceFound = false;
    if (auto expected = processes_.find(oldPid); expected != processes_.end() &&
        expected->second.connections.count(id)) {
        sourceGroup = expected->first;
        sourceFound = true;
    } else {
        for (const auto& process : processes_) {
            if (process.second.connections.count(id)) {
                sourceGroup = process.first;
                sourceFound = true;
                break;
            }
        }
    }

    // Вставка нового PID может вызвать rehash processes_. Поэтому через неё
    // переносится только числовой ключ источника, а итератор ищется заново.
    ProcessConnections& destination = GroupLocked(pid);
    if (!sourceFound || sourceGroup == TrafficGroupKey::Host(pid)) {
        if (auto connection = destination.connections.find(id);
            connection != destination.connections.end())
            connection->second.pid = pid;
        return;
    }

    auto source = processes_.find(sourceGroup);
    if (source == processes_.end()) return;
    ProcessConnections& from = source->second;
    if (auto connection = from.connections.find(id);
        connection != from.connections.end()) {
        // Переносим сам узел, без освобождения и нового выделения памяти.
        auto node = from.connections.extract(connection);
        node.mapped().pid = pid;
        auto inserted = destination.connections.insert(std::move(node));
        if (!inserted.inserted)
            inserted.position->second = std::move(inserted.node.mapped());
    }

}

FlowStore::ConnectionRecord& FlowStore::StartConnectionLocked(
    const FlowKey& key, ConnectionOwnerIndexEntry& owner, DWORD pid,
    ULONGLONG now, bool forceNew) {
    if (forceNew && owner.connectionGeneration) [[unlikely]] {
        if (ConnectionRecord* previous = CurrentConnectionLocked(key, owner)) {
            previous->retired = true;
            if (!previous->removeAfter)
                previous->removeAfter = now + kFinishedGraceMs;
            FreezeConnectionLocked(*previous);
        }
        owner.connectionGeneration = 0;
    }

    if (!owner.connectionGeneration) [[unlikely]]
        owner.connectionGeneration = NextGenerationLocked();
    // Создание поколения не подтверждает владельца: конфликт снимает только
    // вызывающий после точного PID либо однозначного системного снимка.
    owner.pid = pid;
    owner.ended = false;
    owner.endReceived = false;

    ProcessConnections& process = GroupLocked(pid);
    const uint64_t id = owner.connectionGeneration;
    auto [it, inserted] = process.connections.try_emplace(id);
    ConnectionRecord& connection = it->second;
    if (inserted) [[unlikely]] {
        connection.key = key;
        connection.generation = owner.connectionGeneration;
        connection.pid = pid;
        // Наличие строки в системной таблице не означает сетевую активность.
        // Время выставляют только события драйвера и bandwidth-отчёты; иначе
        // новый TCP listener или UDP endpoint минуту не считался пассивным.
    } else {
        connection.pid = pid;
    }
    connection.ownerAmbiguous = owner.ownerAmbiguous;
    return connection;
}

FlowStore::ConnectionRecord& FlowStore::StartOtherConnectionLocked(
    const FlowKey& key, DWORD pid, ULONGLONG now, bool forceNew) {
    ProcessConnections& process = GroupLocked(pid);
    ConnectionRecord* current = nullptr;
    for (auto& item : process.connections) {
        ConnectionRecord& candidate = item.second;
        if (!(candidate.key == key) || candidate.retired) continue;
        if (!current || candidate.generation > current->generation)
            current = &candidate;
    }
    if (current && !forceNew && !current->removeAfter) return *current;
    if (current && (forceNew || current->removeAfter)) {
        current->retired = true;
        if (!current->removeAfter) current->removeAfter = now + kFinishedGraceMs;
        FreezeConnectionLocked(*current);
    }

    ConnectionRecord connection;
    connection.key = key;
    connection.generation = NextGenerationLocked();
    connection.pid = pid;
    return process.connections.emplace(connection.generation,
                                       std::move(connection)).first->second;
}

DWORD FlowStore::ResolveEventOwner(DWORD reportedPid, const FlowKey& key,
                                   bool* found, bool* ambiguous, Dir dir) {
    if (found) *found = false;
    if (ambiguous) *ambiguous = false;
    if (reportedPid) {
        if (found) *found = true;
        return reportedPid;
    }

    ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key);
    if (!index) return 0;

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = index->find(key);
    if (it == index->end()) {
        if (dir != Dir::In) return 0;
        // Отсутствие первого exact tuple не делает известный локальный сокет
        // бесхозным. Возвращаем точный PID либо сохраняем конфликт владельцев.
        DWORD socketPid = 0;
        bool socketAmbiguous = false;
        if (!ResolveSocketLocked(key.proto, key.local, key.lport,
                                 socketPid, socketAmbiguous))
            return 0;
        socketAmbiguous = socketAmbiguous || !socketPid;
        if (found) *found = true;
        if (ambiguous) *ambiguous = socketAmbiguous;
        return socketAmbiguous ? 0 : socketPid;
    }
    // История завершённого поколения не подтверждает владельца нового события
    // с тем же tuple. Ненулевой PID драйвера выше остаётся точным источником.
    if (it->second.endReceived) return 0;
    it->second.lastAccessAt = now;
    if (found) *found = true;
    if (ambiguous) *ambiguous = it->second.ownerAmbiguous;
    return it->second.ownerAmbiguous ? 0 : it->second.pid;
}

void FlowStore::AssignReportedOwner(const FlowKey& key, DWORD pid) {
    if (!pid || pid == 4) return;
    ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key);
    if (!index) return;

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    ConnectionOwnerIndexEntry& owner = OwnerLocked(key, now);
    if (!enabled_.load(std::memory_order_relaxed)) {
        // В службе нет NoteConnection для нового поколения. Точное событие
        // драйвера само подтверждает, что tuple снова принадлежит этому PID.
        owner.pid = pid;
        owner.ownerAmbiguous = false;
        owner.ended = false;
        owner.endReceived = false;
        return;
    }
    if (owner.pid != pid) {
        if (owner.ended) {
            // Закрытое поколение соединения остаётся у прежнего процесса до
            // конца окна. Следующий NoteConnection создаст для нового PID новый
            // экземпляр соединения.
            owner.pid = pid;
        } else {
            MoveCurrentFlowLocked(key, owner, pid);
        }
    }
    owner.ownerAmbiguous = false;
}

DWORD FlowStore::ResolveLocalEndpoint(Proto proto, const IpAddr& local,
                                      uint16_t port, bool* ambiguous) const {
    std::lock_guard<std::mutex> lock(mtx_);
    DWORD pid = 0;
    bool conflict = false;
    const bool found = ResolveSocketLocked(proto, local, port, pid, conflict);
    if (ambiguous) *ambiguous = found && conflict;
    return found && !conflict ? pid : 0;
}

FlowStore::ConnectionRecord* FlowStore::NoteConnectionLocked(
    const FlowKey& key, const ConnEvent& event, ULONGLONG now) {
    ConnectionRecord* connection = nullptr;
    if (key.source == TrafficSource::Ndis) {
        if (!enabled_.load(std::memory_order_relaxed)) return nullptr;
        connection = NdisConnectionLocked(key, true);
    } else if (ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key)) {
        ConnectionOwnerIndexEntry& owner = OwnerLocked(key, now);
        DWORD pid = event.pid;

        if (pid && pid != 4) {
            if (owner.pid != pid) {
                if (!owner.ended)
                    MoveCurrentFlowLocked(key, owner, pid);
                else
                    owner.pid = pid;
            }
            owner.ownerAmbiguous = false;
        } else if (!pid) {
            // Новое поколение не наследует PID уже завершённого обмена.
            pid = owner.endReceived || owner.ownerAmbiguous ? 0 : owner.pid;
        }

        if (event.ownerAmbiguous) {
            pid = 0;
            if (!owner.ended)
                MoveCurrentFlowLocked(key, owner, 0);
            else
                owner.pid = 0;
            owner.ownerAmbiguous = true;
        }

        if (event.pid == 4 && owner.pid != 4) {
            // PID 4 учитывается в основном контейнере, но именно событие драйвера
            // не меняет PID индекса — это отдельное явное требование.
            ConnectionRecord& item = StartOtherConnectionLocked(
                key, 4, now, false);
            if (!owner.connectionGeneration)
                owner.connectionGeneration = item.generation;
            connection = &item;
        } else {
            const bool forceNew = owner.ended;
            connection = &StartConnectionLocked(
                key, owner, pid, now, forceNew);
        }

    } else {
        if (!enabled_.load(std::memory_order_relaxed)) return nullptr;
        connection = &StartOtherConnectionLocked(
            key, event.pid, now, false);
    }

    if (!enabled_.load(std::memory_order_relaxed) || !connection) return nullptr;

    connection->driverBacked = true;
    connection->lastActivity = now;
    // Событие драйвера снова подтверждает существование текущего экземпляра.
    // Временная метка исчезновения из системной таблицы к нему больше не
    // относится; END, блокировка и retired-поколение остаются необратимыми.
    if (!connection->endReceived && !connection->blockedAt &&
        !connection->retired)
        connection->removeAfter = 0;
    if (connection->dir == Dir::Unknown) connection->dir = event.dir;
    connection->ownerAmbiguous = connection->ownerAmbiguous ||
                                 event.ownerAmbiguous;

    DriverDetails& details = EnsureDriverDetails(*connection);
    CaptureInterface(details, event.interfaceIndex ? event.interfaceIndex : key.interfaceIndex,
                     event.interfaceName);
    details.conditionFlags = key.source == TrafficSource::Host
        ? event.conditionFlags : std::nullopt;
    if (ProtoInOsTables(key.proto)) details.countersActive = true;
    details.lastChangedAt = now;
    if (event.tlsDomainLabel) details.tlsDomainLabel = event.tlsDomainLabel;

    const bool inbound = event.dir == Dir::In;
    if (event.icmpType >= 0) {
        IcmpInfo info;
        info.type = event.icmpType;
        info.code = event.icmpCode;
        info.v6 = ProtoIsIcmpV6(key.proto);
        if (!details.icmp.known()) details.icmp = info;
        (inbound ? details.icmpIn : details.icmpOut) = info;
    }
    ++details.events;

    if (!ProtoInOsTables(key.proto) && event.bytes) {
        details.countersActive = true;
        if (inbound) {
            details.recv += event.bytes;
            details.periodRecv += event.bytes;
            ++details.packetRecv;
        } else {
            details.sent += event.bytes;
            details.periodSent += event.bytes;
            ++details.packetSent;
        }
    }
    return connection;
}

uint64_t FlowStore::NoteConnection(const FlowKey& key, const ConnEvent& event) {
    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    const ConnectionRecord* connection = NoteConnectionLocked(key, event, now);
    return connection ? connection->generation : 0;
}

uint64_t FlowStore::NoteBlockedConnection(const FlowKey& key,
                                          const ConnEvent& event) {
    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    ConnectionRecord* connection = NoteConnectionLocked(key, event, now);
    if (!connection || connection->endReceived || connection->retired) return 0;

    if (ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key)) {
        const auto owner = index->find(key);
        if (owner != index->end() &&
            owner->second.connectionGeneration == connection->generation)
            owner->second.ended = true;
    }
    MarkBlockedLocked(*connection, event, now);
    return connection->generation;
}

void FlowStore::MarkBlockedLocked(ConnectionRecord& connection,
                                  const ConnEvent& event, ULONGLONG now) {
    connection.driverBacked = true;
    connection.blockedAt = now;
    connection.removeAfter = now + kBlockedGraceMs;
    connection.dir = event.dir;
    connection.ownerAmbiguous = connection.ownerAmbiguous ||
                                 event.ownerAmbiguous;

    DriverDetails& details = EnsureDriverDetails(connection);
    // Поздний вердикт не переопределяет интерфейс уже опубликованной строки.
    if (!details.interfaceName)
        CaptureInterface(details, event.interfaceIndex
                                     ? event.interfaceIndex
                                     : connection.key.interfaceIndex,
                         event.interfaceName);
    details.icmp.type = event.icmpType;
    details.icmp.code = event.icmpCode;
    details.icmp.v6 = ProtoIsIcmpV6(connection.key.proto);
    (event.dir == Dir::In ? details.icmpIn : details.icmpOut) = details.icmp;
    if (!details.events) details.events = 1;
    FreezeConnectionLocked(connection);
}

void FlowStore::NoteAllowed(const FlowKey& key, const ConnEvent& event,
                            uint64_t generation) {
    if ((key.source == TrafficSource::Host && !ProtoInOsTables(key.proto)) ||
        !enabled_.load(std::memory_order_relaxed)) return;

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    ConnectionRecord* connection = generation
        ? VerdictConnectionLocked(key, event.pid, generation) : nullptr;
    if (generation && !connection) return;
    if (key.source == TrafficSource::Ndis) {
        if (!connection) connection = NdisConnectionLocked(key);
        if (!connection || connection->retired) return;
        connection->blockedAt = 0;
        connection->removeAfter = 0;
        if (connection->dir == Dir::Unknown) connection->dir = event.dir;
        DriverDetails& details = EnsureDriverDetails(*connection);
        if (!details.interfaceName)
            CaptureInterface(details, event.interfaceIndex ? event.interfaceIndex : key.interfaceIndex,
                             event.interfaceName);
        details.countersActive = true;
        if (event.tlsDomainLabel) details.tlsDomainLabel = event.tlsDomainLabel;
        return;
    }
    ConnectionOwnerIndexEntry& owner = OwnerLocked(key, now);
    const bool closing = owner.ended;
    if (!generation) {
        DWORD pid = event.pid;
        if (pid && pid != 4) {
            if (owner.pid != pid) {
                if (!owner.ended)
                    MoveCurrentFlowLocked(key, owner, pid);
                else
                    owner.pid = pid;
            }
            owner.ownerAmbiguous = false;
        } else if (!pid) {
            pid = owner.ownerAmbiguous ? 0 : owner.pid;
        }

        if (event.ownerAmbiguous) {
            pid = 0;
            if (!owner.ended)
                MoveCurrentFlowLocked(key, owner, 0);
            else
                owner.pid = 0;
            owner.ownerAmbiguous = true;
        }

        if (closing) {
            connection = CurrentConnectionLocked(key, owner);
            if (!connection) return;
        } else if (event.pid == 4 && owner.pid != 4) {
            connection = &StartOtherConnectionLocked(
                key, 4, now, false);
            if (!owner.connectionGeneration)
                owner.connectionGeneration = connection->generation;
        } else {
            connection = &StartConnectionLocked(
                key, owner, pid, now, false);
        }
        connection->ownerAmbiguous = owner.ownerAmbiguous;
    }
    connection->driverBacked = true;
    if (!closing && !connection->endReceived) {
        connection->blockedAt = 0;
        connection->removeAfter = 0;
    }
    if (connection->dir == Dir::Unknown) connection->dir = event.dir;

    DriverDetails& details = EnsureDriverDetails(*connection);
    if (!details.interfaceName)
        CaptureInterface(details, event.interfaceIndex ? event.interfaceIndex : key.interfaceIndex,
                         event.interfaceName);
    details.countersActive = true;
    details.lastChangedAt = now;
    if (event.tlsDomainLabel) details.tlsDomainLabel = event.tlsDomainLabel;
}

void FlowStore::NoteBlocked(const FlowKey& key, const ConnEvent& event,
                            uint64_t generation) {
    if (!enabled_.load(std::memory_order_relaxed)) return;

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    ConnectionRecord* connection = generation
        ? VerdictConnectionLocked(key, event.pid, generation) : nullptr;
    if (generation && !connection) return;

    if (key.source == TrafficSource::Ndis) {
        if (!connection) connection = NdisConnectionLocked(key);
    } else if (generation) {
        if (ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key)) {
            const auto owner = index->find(key);
            if (owner != index->end() && owner->second.connectionGeneration == generation)
                owner->second.ended = true;
        }
    } else if (ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key)) {
        ConnectionOwnerIndexEntry& owner = OwnerLocked(key, now);
        DWORD pid = event.pid;
        if (pid && pid != 4) {
            if (owner.pid != pid && !owner.ended)
                MoveCurrentFlowLocked(key, owner, pid);
            owner.pid = pid;
            owner.ownerAmbiguous = false;
        } else if (!pid) {
            pid = owner.endReceived || owner.ownerAmbiguous ? 0 : owner.pid;
        }

        if (event.ownerAmbiguous) {
            pid = 0;
            if (!owner.ended)
                MoveCurrentFlowLocked(key, owner, 0);
            else
                owner.pid = 0;
            owner.ownerAmbiguous = true;
        }

        if (event.pid == 4 && owner.pid != 4) {
            connection = &StartOtherConnectionLocked(
                key, 4, now, false);
            if (!owner.connectionGeneration)
                owner.connectionGeneration = connection->generation;
        } else {
            connection = &StartConnectionLocked(
                key, owner, pid, now, owner.ended);
        }
        owner.ended = true;
    } else {
        connection = &StartOtherConnectionLocked(
            key, event.pid, now, false);
    }

    MarkBlockedLocked(*connection, event, now);
}

void FlowStore::BeginBandwidthPoll(ULONGLONG requestedAt) {
    std::lock_guard<std::mutex> lock(mtx_);
    bandwidthPoll_ = TrafficPeriod{ bandwidthPoll_.end, requestedAt };
    bandwidthPollManaged_ = true;
}

void FlowStore::CancelBandwidthPoll() {
    std::lock_guard<std::mutex> lock(mtx_);
    bandwidthPoll_ = TrafficPeriod{};
}

void FlowStore::BeginNdisBandwidthPoll(ULONGLONG requestedAt) {
    std::lock_guard<std::mutex> lock(mtx_);
    ndisBandwidthPoll_ = TrafficPeriod{ ndisBandwidthPoll_.end, requestedAt };
}

void FlowStore::CancelNdisBandwidthPoll() {
    std::lock_guard<std::mutex> lock(mtx_);
    ndisBandwidthPoll_ = TrafficPeriod{};
}

void FlowStore::AddBandwidthLocked(const FlowKey& key, uint64_t sent,
                                   uint64_t recv, ULONGLONG now,
                                   const TrafficPeriod* period) {
    ConnectionOwnerIndexEntry& owner = OwnerLocked(key, now);
    if (key.proto == Proto::Udp && !owner.pid && !owner.ownerAmbiguous) {
        DWORD endpointPid = 0;
        bool endpointAmbiguous = false;
        if (ResolveSocketLocked(Proto::Udp, key.local, key.lport,
                                endpointPid, endpointAmbiguous)) {
            if (endpointAmbiguous) {
                owner.ownerAmbiguous = true;
            } else if (endpointPid) {
                if (owner.connectionGeneration)
                    MoveCurrentFlowLocked(key, owner, endpointPid);
                else
                    owner.pid = endpointPid;
            }
        }
    }
    DWORD pid = owner.ownerAmbiguous ? 0 : owner.pid;

    ConnectionRecord* connection = CurrentConnectionLocked(key, owner);
    if (!connection && owner.ended) return;
    if (!connection) {
        connection = &StartConnectionLocked(
            key, owner, pid, now, false);
    }

    DriverDetails& details = EnsureDriverDetails(*connection);
    details.sent += sent;
    details.recv += recv;
    details.periodSent += sent;
    details.periodRecv += recv;
    const TrafficPeriod sample = period
        ? *period : TrafficPeriod{ details.lastBandwidthAt, now };
    details.period.Include(sample.begin, sample.end);
    details.lastBandwidthAt = now;
    details.lastChangedAt = now;
    details.countersActive = true;
    // Пометка END необратима для этого поколения. Запоздалый отчёт может
    // дополнить итоговые числа в окне показа, но не продлевает само окно.
    connection->lastActivity = now;
    connection->driverBacked = true;
}

void FlowStore::AddBandwidth(const FlowKey& key, uint64_t sent,
                             uint64_t recv) {
    if (!enabled_.load(std::memory_order_relaxed) ||
        !ProtoInOsTables(key.proto)) return;

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    AddBandwidthLocked(key, sent, recv, now);
}

void FlowStore::AddBandwidthBatch(
    uint8_t protocol, const pmkext::BandwidthValueV4* entries,
    uint32_t count) {
    const Proto proto = ProtoFromNumber(protocol);
    if ((!entries && count) || !enabled_.load(std::memory_order_relaxed) ||
        !ProtoInOsTables(proto)) return;

    std::lock_guard<std::mutex> lock(mtx_);
    const ULONGLONG now = GetTickCount64();
    const size_t category = CategoryIndex(proto, AF_INET);
    const TrafficPeriod period = bandwidthPollManaged_
        ? bandwidthPoll_ : TrafficPeriod{ bandwidthTick_[category], now };
    bandwidthTick_[category] = now;
    for (uint32_t index = 0; index < count; ++index) {
        const pmkext::BandwidthValueV4& entry = entries[index];
        const FlowKey key = MakeFlowKey(
            proto, IpFromRaw(entry.local_ip), IpFromRaw(entry.remote_ip),
            entry.local_port, entry.remote_port);
        AddBandwidthLocked(
            key, entry.transmitted_bytes, entry.received_bytes, now,
            &period);
    }
}

void FlowStore::AddBandwidthBatch(
    uint8_t protocol, const pmkext::BandwidthValueV6* entries,
    uint32_t count) {
    const Proto proto = ProtoFromNumber(protocol);
    if ((!entries && count) || !enabled_.load(std::memory_order_relaxed) ||
        !ProtoInOsTables(proto)) return;

    std::lock_guard<std::mutex> lock(mtx_);
    const ULONGLONG now = GetTickCount64();
    const size_t category = CategoryIndex(proto, AF_INET6);
    const TrafficPeriod period = bandwidthPollManaged_
        ? bandwidthPoll_ : TrafficPeriod{ bandwidthTick_[category], now };
    bandwidthTick_[category] = now;
    for (uint32_t index = 0; index < count; ++index) {
        const pmkext::BandwidthValueV6& entry = entries[index];
        const FlowKey key = MakeFlowKey(
            proto, IpFromRaw(entry.local_ip), IpFromRaw(entry.remote_ip),
            entry.local_port, entry.remote_port);
        AddBandwidthLocked(
            key, entry.transmitted_bytes, entry.received_bytes, now,
            &period);
    }
}

bool FlowStore::MarkConnectionForRemovalLocked(const FlowKey& key, DWORD pid,
                                               uint64_t generation,
                                               ULONGLONG now) {
    ConnectionOwnerIndexEntry* owner = nullptr;
    bool canEndIndexed = true;
    if (ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, key)) {
        auto it = index->find(key);
        if (it != index->end()) {
            owner = &it->second;
            owner->lastAccessAt = now;
            DWORD indexedPid = owner->pid;
            // Событие PID 4 может храниться в записи при PID 0 в индексе.
            if (!indexedPid) {
                if (const ConnectionRecord* current = CurrentConnectionLocked(key, *owner))
                    indexedPid = current->pid;
            }
            // Ненулевой PID END не заменяется текущим владельцем: запоздалое
            // событие другого процесса вправе закрыть только его старую запись.
            canEndIndexed = !pid || !indexedPid || pid == indexedPid;
            if (!generation && canEndIndexed)
                generation = owner->connectionGeneration;
            if (!pid && generation == owner->connectionGeneration)
                pid = indexedPid;
        }
    }

    ConnectionRecord* chosen = nullptr;

    // Обычный END приходит после on_connection_*: индекс уже содержит точные
    // PID и поколение, а ConnectionTable индексирована глобально уникальным
    // generation. Прямой find превращает завершение в O(1); полный обход
    // остаётся только для действительно опередившего либо неполного события.
    if (generation) {
        if (auto process = processes_.find(pid); process != processes_.end()) {
            if (auto connection = process->second.connections.find(generation);
                connection != process->second.connections.end() &&
                connection->second.key == key) {
                chosen = &connection->second;
            }
        }
    }

    const auto consider = [&](ConnectionRecord& connection) {
        if (!(connection.key == key)) return;
        if (generation && connection.generation != generation) return;
        if (pid && connection.pid && connection.pid != pid) return;
        if (!chosen || connection.generation > chosen->generation)
            chosen = &connection;
    };

    if (!chosen) {
        if (auto process = processes_.find(pid); process != processes_.end()) {
            for (auto& item : process->second.connections) {
                consider(item.second);
                if (chosen && generation) break;
            }
        }
    }
    if (!chosen) {
        for (auto& process : processes_) {
            for (auto& item : process.second.connections) {
                consider(item.second);
                if (chosen && generation) break;
            }
            if (chosen && generation) break;
        }
    }

    const ULONGLONG removeAfter = now + kFinishedGraceMs;
    if (chosen) {
        if (!chosen->endReceived) {
            chosen->endReceived = true;
            chosen->removeAfter = removeAfter;
        }
        chosen->blockedAt = 0;
        FreezeConnectionLocked(*chosen);
        generation = chosen->generation;
        pid = chosen->pid;
    }

    if (owner && canEndIndexed &&
        (!generation || owner->connectionGeneration == generation)) {
        // Только первый END текущего поколения разрешает завершить локальную пару.
        const bool firstEnd = !owner->endReceived;
        owner->ended = true;
        owner->endReceived = true;
        return firstEnd;
    }
    return false;
}

void FlowStore::CloseFlow(const FlowKey& key, DWORD pid, Dir dir,
                          uint64_t generation) {
    (void)dir;
    const auto isLocal = [](const IpAddr& address) {
        return address.isLoopback() ||
               AddrMacros::Matches(AddrMacro::MyComputer, address);
    };
    const bool closeReverse = (key.proto == Proto::Udp || key.proto == Proto::Tcp) &&
        isLocal(key.local) && isLocal(key.remote);

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    if (!MarkConnectionForRemovalLocked(key, pid, generation, now) || !closeReverse) return;

    const FlowKey reverse = MakeFlowKey(
        key.proto, key.remote, key.local, key.rport, key.lport);
    if (reverse == key) return;
    // Обе стороны завершаются под одним замком: новое поколение не вклинится
    // между проверкой прямой стороны и выбором владельца обратной.
    MarkConnectionForRemovalLocked(reverse, 0, 0, now);
}

void FlowStore::ClearCounters(const FlowKey& key, uint64_t generation) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& process : processes_) {
        for (auto& item : process.second.connections) {
            ConnectionRecord& connection = item.second;
            if (!(connection.key == key) ||
                (generation && connection.generation != generation) ||
                !connection.driver)
                continue;
            DriverDetails& details = EnsureDriverDetails(connection);
            details.sent = details.recv = 0;
            details.periodSent = details.periodRecv = 0;
            details.period = TrafficPeriod{};
            details.lastBandwidthAt = 0;
            details.countersActive = false;
        }
    }
}

void FlowStore::BeginSystemCategoryLocked(Proto proto, uint16_t family) {
    if (LocalSocketTable* sockets = SocketTableFor(localSockets_, proto, family))
        sockets->clear();
}

void FlowStore::ApplyTcpSnapshotLocked(
    const std::vector<SystemTcpConnection>& rows, uint16_t family,
    uint64_t revision, ULONGLONG now) {
    LocalSocketTable* sockets = SocketTableFor(localSockets_, Proto::Tcp, family);
    for (const SystemTcpConnection& row : rows) {
        if (row.state == MIB_TCP_STATE_LISTEN)
            AddSocketOwner(*sockets, row.key.local, row.key.lport, row.pid);
    }
    TrimHashTable(*sockets);

    for (const SystemTcpConnection& row : rows) {
        ConnectionOwnerIndexEntry& owner = OwnerLocked(row.key, now);
        const bool duplicate = owner.lastSystemRevision == revision;
        const bool gap = owner.lastSystemRevision != 0 &&
                         owner.lastSystemRevision + 1 < revision;

        const DWORD previousPid = owner.pid;
        const bool changedOwner = row.pid && previousPid &&
                                  row.pid != previousPid;
        DWORD targetPid = row.pid;
        if (!duplicate && owner.ownerAmbiguous && row.pid) {
            owner.ownerAmbiguous = false;
            if (!owner.ended)
                MoveCurrentFlowLocked(row.key, owner, row.pid);
            else
                owner.pid = row.pid;
        }
        if (!targetPid && owner.connectionGeneration && !owner.ownerAmbiguous)
            targetPid = owner.pid;

        if (duplicate && row.pid && owner.pid && row.pid != owner.pid) {
            if (!owner.ended) MoveCurrentFlowLocked(row.key, owner, 0);
            owner.pid = 0;
            owner.ownerAmbiguous = true;
            targetPid = 0;
        } else if (!owner.ownerAmbiguous && targetPid != owner.pid) {
            if (!owner.ended)
                MoveCurrentFlowLocked(row.key, owner, targetPid);
            else if (targetPid)
                owner.pid = targetPid;
        }

        const bool forceNew = owner.ended &&
            (gap || changedOwner || row.state == MIB_TCP_STATE_LISTEN);
        ConnectionRecord* connection = CurrentConnectionLocked(row.key, owner);
        const bool systemReopened = connection && connection->removeAfter &&
            !connection->endReceived && !connection->driverBacked;
        if (!owner.ended || forceNew) {
            connection = &StartConnectionLocked(
                row.key, owner, owner.ownerAmbiguous ? 0 : targetPid,
                now, forceNew || systemReopened);
        }

        owner.lastSystemRevision = revision;
        owner.lastAccessAt = now;

        if (connection) {
            if (!owner.ended && !connection->blockedAt &&
                !connection->retired) {
                connection->removeAfter = 0;
                connection->endReceived = false;
                if (const DriverDetails* details = DriverDetailsOf(*connection);
                    details && details->frozenCountersKnown)
                    EnsureDriverDetails(*connection).frozenCountersKnown = false;
            }
            connection->systemBacked = true;
            connection->systemRevision = revision;
            connection->state = row.state;
            connection->localScope = row.localScope;
            connection->remoteScope = row.remoteScope;
            connection->ownerAmbiguous = owner.ownerAmbiguous;
            connection->currentSystemSent = row.sent;
            connection->currentSystemRecv = row.recv;
            connection->currentSystemCountersRead = row.countersRead;
            if (row.countersRead) {
                const ULONGLONG countersAt = row.countersAt
                    ? row.countersAt : now;
                const bool hasTraffic = row.sent != 0 || row.recv != 0;
                const bool monotonic = row.sent >= connection->lastSystemSent &&
                                       row.recv >= connection->lastSystemRecv;
                if (connection->systemTrafficAuthoritative && monotonic &&
                    connection->lastSystemReadAt &&
                    countersAt > connection->lastSystemReadAt) {
                    connection->systemPeriodSent +=
                        row.sent - connection->lastSystemSent;
                    connection->systemPeriodRecv +=
                        row.recv - connection->lastSystemRecv;
                    connection->systemPeriod.Include(
                        connection->lastSystemReadAt, countersAt);
                }
                if (hasTraffic) {
                    connection->systemTrafficAuthoritative = true;
                    connection->lastSystemSent = row.sent;
                    connection->lastSystemRecv = row.recv;
                }
                // Ошибка чтения не сдвигает базу времени. Сброс счётчиков требует
                // новой базы, но не возвращает соединение к данным драйвера.
                connection->lastSystemReadAt = hasTraffic ||
                    !connection->systemTrafficAuthoritative ? countersAt : 0;
            }
            if (connection->dir == Dir::Unknown) {
                if (row.state == MIB_TCP_STATE_LISTEN ||
                    row.state == MIB_TCP_STATE_SYN_RCVD)
                    connection->dir = Dir::In;
                else if (row.state == MIB_TCP_STATE_SYN_SENT)
                    connection->dir = Dir::Out;
            }
        }
    }
}

void FlowStore::ApplyUdpSnapshotLocked(
    const std::vector<SystemUdpEndpoint>& rows, uint16_t family,
    uint64_t revision, ULONGLONG now) {
    LocalSocketTable* sockets = SocketTableFor(localSockets_, Proto::Udp, family);
    for (const SystemUdpEndpoint& row : rows)
        AddSocketOwner(*sockets, row.local, row.port, row.pid);
    TrimHashTable(*sockets);

    FlowKey selector;
    selector.proto = Proto::Udp;
    selector.local.family = family;
    ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, selector);

    const auto bindExact = [&](ConnectionOwnerIndex& exactIndex,
                               bool sameFamily) {
        for (auto& item : exactIndex) {
            // Пустая удалённая сторона — синтетическая строка самого UDP-сокета.
            // Она обрабатывается после exact tuple и не должна считать сама себя
            // подтверждением наличия конкретного обмена.
            if (!item.first.rport && item.first.remote.isAny()) continue;
            ConnectionOwnerIndexEntry& owner = item.second;
            DWORD socketPid = 0;
            bool socketAmbiguous = false;
            if (!ResolveSocketLocked(Proto::Udp, item.first.local,
                                     item.first.lport, socketPid,
                                     socketAmbiguous))
                continue;

            // Точный PID on_connection_* сильнее UDP-таблицы, в которой удалённой
            // стороны нет. Однозначный снимок подтверждает только неизвестного
            // либо неоднозначного владельца, не заменяя уже известный PID.
            if (!owner.ended && (!owner.pid || owner.ownerAmbiguous) &&
                !socketAmbiguous && socketPid) {
                owner.ownerAmbiguous = false;
                MoveCurrentFlowLocked(item.first, owner, socketPid);
            }
            if (!owner.pid && socketAmbiguous) owner.ownerAmbiguous = true;
            if (sameFamily) owner.lastSystemRevision = revision;

            if (ConnectionRecord* connection = CurrentConnectionLocked(
                    item.first, owner)) {
                connection->systemBacked = true;
                if (sameFamily) connection->systemRevision = revision;
                connection->ownerAmbiguous = owner.ownerAmbiguous;
            }
        }
    };
    bindExact(*index, true);
    // IPv6 wildcard может быть единственным сокетом для IPv4 datagram. После
    // чтения UDP/IPv6 сразу связываем с ним и IPv4 exact tuple этого же такта.
    if (family == AF_INET6) bindExact(ownerIndexes_.udpV4, false);

    // Для каждого актуального конкретного tuple отмечаем максимум два сокета:
    // точную привязку и wildcard того же порта. Прежний код для КАЖДОГО UDP
    // endpoint заново обходил все процессы и все соединения — O(S * C).
    std::unordered_set<IpEndpoint, IpEndpointHash> concreteSockets;
    concreteSockets.reserve(sockets->size());
    const auto markSocket = [&](const IpEndpoint& endpoint,
                                const ConnectionRecord& connection) {
        const auto socket = sockets->find(endpoint);
        if (socket == sockets->end()) return;
        if (socket->second.pid && connection.pid &&
            !socket->second.ownerAmbiguous &&
            socket->second.pid != connection.pid)
            return;
        concreteSockets.insert(socket->first);
    };

    for (const auto& process : processes_) {
        for (const auto& item : process.second.connections) {
            const ConnectionRecord& connection = item.second;
            if (connection.key.proto != Proto::Udp ||
                (!connection.key.rport && connection.key.remote.isAny()) ||
                connection.key.lport == 0)
                continue;

            if (connection.key.local.family == family) {
                if (connection.systemRevision != revision) continue;
                markSocket(MakeIpEndpoint(connection.key.local,
                                          connection.key.lport), connection);
                markSocket(MakeIpWildcard(family, connection.key.lport),
                           connection);
            } else if (family == AF_INET6 &&
                       connection.key.local.family == AF_INET &&
                       connection.systemBacked &&
                       connection.systemRevision ==
                           systemRevision_[CategoryIndex(Proto::Udp, AF_INET)]) {
                markSocket(MakeIpWildcard(AF_INET6, connection.key.lport),
                           connection);
            }
        }
    }

    // Общая строка UDP endpoint нужна только пока для сокета нет ни одного
    // конкретного driver tuple. Иначе один фактический обмен отображался бы
    // дважды: как remote endpoint и как сам локальный сокет.
    for (const auto& socket : *sockets) {
        const IpAddr local = AddressOf(socket.first);
        FlowKey key = MakeFlowKey(Proto::Udp, local, IpAddr{},
                                  socket.first.port, 0);
        key.remote.family = family;

        auto syntheticOwner = index->find(key);
        ConnectionRecord* synthetic = syntheticOwner == index->end()
            ? nullptr : CurrentConnectionLocked(key, syntheticOwner->second);
        if (synthetic && synthetic->driverBacked) {
            ConnectionOwnerIndexEntry& owner = syntheticOwner->second;
            const DWORD targetPid = socket.second.ownerAmbiguous
                ? 0 : socket.second.pid;
            if (!owner.ended && owner.pid != targetPid)
                MoveCurrentFlowLocked(key, owner, targetPid);
            synthetic = CurrentConnectionLocked(key, owner);
            owner.ownerAmbiguous = socket.second.ownerAmbiguous;
            owner.lastSystemRevision = revision;
            owner.lastAccessAt = now;
            if (synthetic) {
                synthetic->systemBacked = true;
                synthetic->systemRevision = revision;
                synthetic->ownerAmbiguous = socket.second.ownerAmbiguous;
            }
            continue;
        }

        const bool concreteFound = concreteSockets.count(socket.first) != 0;

        if (concreteFound) {
            if (syntheticOwner != index->end()) {
                const uint64_t generation =
                    syntheticOwner->second.connectionGeneration;
                if (generation) {
                    const uint64_t id = generation;
                    for (auto& process : processes_) {
                        auto connection = process.second.connections.find(id);
                        if (connection == process.second.connections.end() ||
                            !(connection->second.key == key))
                            continue;
                        if (!connection->second.driverBacked) {
                            process.second.connections.erase(connection);
                            ++removedSinceTake_;
                        }
                        break;
                    }
                }
                index->erase(syntheticOwner);
            }
            continue;
        }

        ConnectionOwnerIndexEntry& owner = OwnerLocked(key, now);
        const DWORD targetPid = socket.second.ownerAmbiguous
            ? 0 : socket.second.pid;
        if (!owner.ended && owner.pid != targetPid)
            MoveCurrentFlowLocked(key, owner, targetPid);
        owner.ownerAmbiguous = socket.second.ownerAmbiguous;
        owner.lastSystemRevision = revision;

        ConnectionRecord* connection = CurrentConnectionLocked(key, owner);
        const bool systemReopened = connection && connection->removeAfter &&
            !connection->endReceived && !connection->driverBacked;
        if (!owner.ended) {
            connection = &StartConnectionLocked(
                key, owner, targetPid, now, systemReopened);
        }
        if (connection) {
            if (!owner.ended && !connection->blockedAt &&
                !connection->retired) {
                connection->removeAfter = 0;
                connection->endReceived = false;
                if (const DriverDetails* details = DriverDetailsOf(*connection);
                    details && details->frozenCountersKnown)
                    EnsureDriverDetails(*connection).frozenCountersKnown = false;
            }
            connection->systemBacked = true;
            connection->systemRevision = revision;
            connection->ownerAmbiguous = socket.second.ownerAmbiguous;
        }
    }
}

void FlowStore::RefreshListenerFlagsLocked(Proto proto, uint16_t family) {
    FlowKey selector;
    selector.proto = proto;
    selector.local.family = family;
    ConnectionOwnerIndex* index = OwnerIndexFor(ownerIndexes_, selector);
    if (!index) return;

    for (auto& item : *index) {
        DWORD socketPid = 0;
        bool ambiguous = false;
        const bool found = ResolveSocketLocked(
            proto, item.first.local, item.first.lport, socketPid, ambiguous);
        item.second.localListener = found &&
            (item.second.pid == 0 || socketPid == 0 || ambiguous ||
             socketPid == item.second.pid);
    }
}

void FlowStore::FinishSystemSnapshotsLocked(uint8_t validCategories,
                                            ULONGLONG now) {
    // Все четыре категории завершаются одним проходом. Прежде TCP/IPv4,
    // TCP/IPv6, UDP/IPv4 и UDP/IPv6 по очереди перечитывали каждое соединение.
    for (auto& process : processes_) {
        for (auto it = process.second.connections.begin();
             it != process.second.connections.end();) {
            ConnectionRecord& connection = it->second;
            if (connection.key.source == TrafficSource::Ndis ||
                !ProtoInOsTables(connection.key.proto)) {
                ++it;
                continue;
            }

            const size_t category = CategoryIndex(
                connection.key.proto, connection.key.local.family);
            if ((validCategories & (uint8_t{ 1 } << category)) == 0) {
                ++it;
                continue;
            }

            const bool observed =
                connection.systemRevision == systemRevision_[category];
            connection.systemBacked = observed;
            if (observed || connection.removeAfter) {
                ++it;
                continue;
            }

            const DriverDetails* details = DriverDetailsOf(connection);
            const bool hasDriver = details && details->countersActive;
            if (!connection.driverBacked && !hasDriver) {
                // Исчезнувшая системная строка может быть следствием смерти
                // процесса. Не удаляем единственное свидетельство до Take:
                // секундный проход сначала пометит весь PID и выдержит общее
                // четырёхсекундное окно. Если строка вернётся, Apply снимет метку.
                if (!connection.removeAfter) {
                    connection.removeAfter = now + kFinishedGraceMs;
                    FreezeConnectionLocked(connection);
                }
            }
            ++it;
        }
    }
    RemoveEmptyProcessesLocked();
}

void FlowStore::ReplaceSystemSnapshot(const SystemSnapshot& snapshot) {
    if (!enabled_.load(std::memory_order_relaxed)) return;
    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);

    uint8_t validCategories = 0;
    const auto replaceTcp = [&](const std::vector<SystemTcpConnection>& rows,
                                uint16_t family, bool valid) {
        if (!valid) [[unlikely]] return;
        const size_t category = CategoryIndex(Proto::Tcp, family);
        validCategories |= uint8_t{ 1 } << category;
        BeginSystemCategoryLocked(Proto::Tcp, family);
        uint64_t& revision = systemRevision_[category];
        ++revision;
        if (!revision) [[unlikely]] ++revision;
        ApplyTcpSnapshotLocked(rows, family, revision, now);
    };
    const auto replaceUdp = [&](const std::vector<SystemUdpEndpoint>& rows,
                                uint16_t family, bool valid) {
        if (!valid) [[unlikely]] return;
        const size_t category = CategoryIndex(Proto::Udp, family);
        validCategories |= uint8_t{ 1 } << category;
        BeginSystemCategoryLocked(Proto::Udp, family);
        uint64_t& revision = systemRevision_[category];
        ++revision;
        if (!revision) [[unlikely]] ++revision;
        ApplyUdpSnapshotLocked(rows, family, revision, now);
    };

    replaceTcp(snapshot.tcpV4, AF_INET, snapshot.tcpV4Valid);
    replaceTcp(snapshot.tcpV6, AF_INET6, snapshot.tcpV6Valid);
    replaceUdp(snapshot.udpV4, AF_INET, snapshot.udpV4Valid);
    replaceUdp(snapshot.udpV6, AF_INET6, snapshot.udpV6Valid);
    if (validCategories)
        FinishSystemSnapshotsLocked(validCategories, now);

    // IPv6 wildcard может обслуживать IPv4. После замены обоих семейств
    // пересчитываем флаги ещё раз, чтобы IPv4 не жил один такт по прежнему
    // IPv6-снимку.
    if (snapshot.tcpV4Valid || snapshot.tcpV6Valid) {
        RefreshListenerFlagsLocked(Proto::Tcp, AF_INET);
        RefreshListenerFlagsLocked(Proto::Tcp, AF_INET6);
    }
    if (snapshot.udpV4Valid || snapshot.udpV6Valid) {
        RefreshListenerFlagsLocked(Proto::Udp, AF_INET);
        RefreshListenerFlagsLocked(Proto::Udp, AF_INET6);
    }
}

void FlowStore::RemoveProcessesLocked(const std::vector<DWORD>& pids) {
    if (pids.empty()) return;

    const std::unordered_set<DWORD> removed(pids.begin(), pids.end());
    const auto resetOwner = [&](ConnectionOwnerIndex& index) {
        for (auto& item : index) {
            ConnectionOwnerIndexEntry& owner = item.second;
            if (!removed.count(owner.pid)) continue;
            owner.pid = 0;
            owner.connectionGeneration = 0;
            owner.ownerAmbiguous = false;
            owner.localListener = false;
            owner.ended = false;
            owner.endReceived = false;
        }
    };
    // Все умершие PID обрабатываются четырьмя проходами по индексам. Прежний
    // вызов на каждый PID повторял эти проходы N раз при массовом завершении.
    resetOwner(ownerIndexes_.tcpV4);
    resetOwner(ownerIndexes_.tcpV6);
    resetOwner(ownerIndexes_.udpV4);
    resetOwner(ownerIndexes_.udpV6);

    for (DWORD pid : pids) {
        if (auto it = processes_.find(pid); it != processes_.end()) {
            removedSinceTake_ += it->second.connections.size();
            processes_.erase(it);
        }
    }
}

void FlowStore::RemoveEmptyProcessesLocked() {
    for (auto it = processes_.begin(); it != processes_.end();) {
        const ProcessConnections& process = it->second;
        it = process.connections.empty() && !process.removeAfter
            ? processes_.erase(it) : std::next(it);
    }
    TrimHashTable(processes_);
}

bool FlowStore::ExpireConnectionLocked(
    ConnectionRecord& connection, ULONGLONG now, ULONGLONG inactiveMs) {
    bool expired = connection.removeAfter && now >= connection.removeAfter;
    const bool ndis = connection.key.source == TrafficSource::Ndis;
    if (ndis) {
        expired = expired || (!connection.removeAfter && connection.lastActivity &&
            now - connection.lastActivity >= kNdisInactiveMs);
    } else if (!expired && !ProtoInOsTables(connection.key.proto)) {
        expired = !connection.removeAfter && connection.lastActivity &&
                  now - connection.lastActivity > kOtherInactiveMs;
    } else if (!expired) {
        const DriverDetails* details = DriverDetailsOf(connection);
        if (details && details->countersActive && details->lastChangedAt &&
            now - details->lastChangedAt > inactiveMs) {
            bool localListener = false;
            if (const ConnectionOwnerIndex* index = OwnerIndexFor(
                    ownerIndexes_, connection.key)) {
                const auto owner = index->find(connection.key);
                localListener = owner != index->end() &&
                                owner->second.localListener;
            }
            if (!localListener) {
                DriverDetails& mutableDetails = EnsureDriverDetails(connection);
                mutableDetails.countersActive = false;
                mutableDetails.sent = mutableDetails.recv = 0;
                mutableDetails.periodSent = mutableDetails.periodRecv = 0;
                mutableDetails.period = TrafficPeriod{};
                mutableDetails.lastBandwidthAt = 0;
                details = &mutableDetails;
            }
        }

        const bool hasDriver = details && details->countersActive;
        expired = !connection.systemBacked && !hasDriver &&
                  connection.lastActivity &&
                  now - connection.lastActivity > inactiveMs;
    }
    if (!expired) [[likely]] return false;

    if (ndis) {
        const auto indexed = ndisConnections_.find(connection.key);
        if (indexed != ndisConnections_.end() && indexed->second == connection.generation)
            ndisConnections_.erase(indexed);
    }
    if (ConnectionOwnerIndex* index = OwnerIndexFor(
            ownerIndexes_, connection.key)) {
        auto owner = index->find(connection.key);
        if (owner != index->end() && !owner->second.ended &&
            owner->second.connectionGeneration == connection.generation)
            owner->second.connectionGeneration = 0;
    }
    ++removedSinceTake_;
    return true;
}

void FlowStore::ExpireLocked(ULONGLONG now, ULONGLONG inactiveMs) {
    for (auto process = processes_.begin(); process != processes_.end();) {
        ConnectionTable& connections = process->second.connections;
        for (auto it = connections.begin(); it != connections.end();) {
            it = ExpireConnectionLocked(it->second, now, inactiveMs)
                ? connections.erase(it) : std::next(it);
        }
        if (connections.empty() && !process->second.removeAfter) {
            process = processes_.erase(process);
        } else {
            TrimHashTable(connections);
            ++process;
        }
    }
    TrimHashTable(processes_);
    TrimHashTable(ndisConnections_);

    ExpireOwnerIndexesLocked(now, inactiveMs);
}

bool FlowStore::OwnerExpired(const ConnectionOwnerIndexEntry& owner,
                             ULONGLONG now, ULONGLONG inactiveMs) {
    // Сокет защищает действующий обмен, но не историю завершённых или
    // заблокированных tuple: сам listener может оставаться открыт часами.
    const bool protectedByListener = owner.localListener && !owner.ended;
    return !protectedByListener && owner.lastAccessAt &&
           now - owner.lastAccessAt > inactiveMs;
}

void FlowStore::ExpireOwnerIndexesLocked(ULONGLONG now, ULONGLONG inactiveMs) {
    const auto expire = [&](ConnectionOwnerIndex& index) {
        for (auto it = index.begin(); it != index.end();) {
            it = OwnerExpired(it->second, now, inactiveMs)
                ? index.erase(it) : std::next(it);
        }
        TrimHashTable(index);
    };
    expire(ownerIndexes_.tcpV4);
    expire(ownerIndexes_.tcpV6);
    expire(ownerIndexes_.udpV4);
    expire(ownerIndexes_.udpV6);
}

void FlowStore::Maintain() {
    if (enabled_.load(std::memory_order_relaxed)) return;
    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    ExpireOwnerIndexesLocked(now, kInactiveMs);
}

void FlowStore::ProbeDeadProcesses(
    std::vector<DeadProcessProbe>& out) const {
    std::vector<DWORD> probes;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        probes.reserve(processes_.size());
        for (const auto& process : processes_) {
            if (process.first.isHost() && !IsSystemPid(process.first.pid()))
                probes.push_back(process.first.pid());
        }
    }

    out.clear();
    out.reserve(probes.size());
    for (DWORD pid : probes) {
        const ULONGLONG age = ProcessDeadFor(pid);
        if (age) out.push_back(DeadProcessProbe{ pid, age });
    }
}

void FlowStore::PrepareProcessesLocked(
    const std::vector<DeadProcessProbe>& dead, ULONGLONG now) {
    for (const DeadProcessProbe& probe : dead) {
        auto process = processes_.find(probe.pid);
        if (process == processes_.end()) continue;

        const ULONGLONG left = probe.deadFor >= kFinishedGraceMs
            ? 0 : kFinishedGraceMs - probe.deadFor;
        const ULONGLONG deadline = now + left;
        if (!process->second.removeAfter ||
            deadline < process->second.removeAfter)
            process->second.removeAfter = deadline;
    }

    std::vector<DWORD> removePids;
    removePids.reserve(dead.size());
    for (const auto& process : processes_) {
        if (process.first.isHost() && !IsSystemPid(process.first.pid()) && process.second.removeAfter &&
            now >= process.second.removeAfter)
            removePids.push_back(process.first.pid());
    }
    RemoveProcessesLocked(removePids);
}

void FlowStore::ResetPeriodsLocked() {
    // Приращение относится к интервалу между двумя снимками. Накопительные
    // значения и время последнего изменения остаются нетронутыми.
    for (auto& process : processes_) {
        for (auto& item : process.second.connections) {
            ConnectionRecord& connection = item.second;
            connection.systemPeriodSent = 0;
            connection.systemPeriodRecv = 0;
            connection.systemPeriod = TrafficPeriod{};
            if (!connection.driver) continue;
            DriverDetails& details = EnsureDriverDetails(connection);
            details.periodSent = 0;
            details.periodRecv = 0;
            details.period = TrafficPeriod{};
        }
    }
}

void FlowStore::Take(View& out, ULONGLONG inactiveMs) {
    std::vector<DeadProcessProbe> dead;
    ProbeDeadProcesses(dead);

    std::lock_guard<std::mutex> lock(mtx_);
    const ULONGLONG now = GetTickCount64();
    PrepareProcessesLocked(dead, now);
    ExpireLocked(now, inactiveMs);
    out.processes.clear();
    out.processes.reserve(processes_.size());
    // Обе группы traffic-таблиц остаются частью полного диагностического View,
    // но не поддерживаются отдельными live-картами. Восстанавливаем их из
    // ConnectionRecord; производственный TakeDisplay этот путь не проходит.
    for (const auto& processItem : processes_) {
        ProcessConnectionRecord& process =
            out.processes.try_emplace(processItem.first).first->second;
        static_cast<ProcessConnections&>(process) = processItem.second;
        for (const auto& connectionItem : process.connections) {
            const ConnectionRecord& connection = connectionItem.second;
            const DriverDetails* details = DriverDetailsOf(connection);
            if (ProtoInOsTables(connection.key.proto) && details &&
                details->countersActive) {
                DriverTrafficEntry traffic;
                traffic.sent = details->sent;
                traffic.recv = details->recv;
                traffic.periodSent = details->periodSent;
                traffic.periodRecv = details->periodRecv;
                traffic.lastChangedAt = details->lastChangedAt;
                traffic.removeAfter = connection.removeAfter;
                traffic.generation = connection.generation;
                DriverTableFor(process.driverTraffic, connection.key)->emplace(
                    FlowId{ connection.key, connection.generation }, traffic);
            }

            if (connection.key.proto != Proto::Tcp ||
                !connection.systemBacked || connection.retired)
                continue;

            SystemTrafficTable* table = SystemTableFor(
                process.systemTraffic, connection.key);
            SystemTrafficEntry traffic;
            traffic.sent = connection.currentSystemSent;
            traffic.recv = connection.currentSystemRecv;
            traffic.state = connection.state;
            traffic.localScope = connection.localScope;
            traffic.remoteScope = connection.remoteScope;
            traffic.observedAt = now;
            traffic.revision = connection.systemRevision;
            traffic.generation = connection.generation;
            traffic.countersRead = connection.currentSystemCountersRead;
            table->insert_or_assign(connection.key, traffic);
        }
    }
    TrimHashTable(out.processes);
    out.ownerIndexes = ConnectionOwnerIndexes(ownerIndexes_);
    out.removedConnections = removedSinceTake_;
    removedSinceTake_ = 0;
    ResetPeriodsLocked();
    lastTakeAt_ = now;
}

void FlowStore::TakeDisplay(DisplayView& out, ULONGLONG inactiveMs,
                            bool showPassive, bool includeConnections) {
    std::vector<DeadProcessProbe> dead;
    ProbeDeadProcesses(dead);

    std::lock_guard<std::mutex> lock(mtx_);
    const ULONGLONG now = GetTickCount64();
    PrepareProcessesLocked(dead, now);

    out.flowCount = 0;
    out.hiddenCount = 0;
    out.driverOnlyFlows = 0;
    // Сначала удаляем просроченные строки и считаем точный размер снимка.
    // В обычном режиме без фильтра пассивности здесь не выбираются счётчики
    // и не копируются строки; второй проход сразу заполняет конечные массивы.
    size_t processCount = 0;
    size_t connectionCount = 0;
    for (auto processItem = processes_.begin(); processItem != processes_.end();) {
        ProcessConnections& process = processItem->second;
        size_t visible = 0;
        for (auto it = process.connections.begin();
             it != process.connections.end();) {
            const ConnectionRecord& stored = it->second;
            if (ExpireConnectionLocked(it->second, now, inactiveMs)) [[unlikely]] {
                it = process.connections.erase(it);
                continue;
            }
            ++it;
            if (IsDisplayState(stored) &&
                (showPassive || !DisplayTrafficOf(
                    process, stored, lastTakeAt_, now).passive))
                ++visible;
        }
        if (visible) ++processCount;
        connectionCount += visible;
        if (process.connections.empty() && !process.removeAfter) {
            processItem = processes_.erase(processItem);
        } else {
            TrimHashTable(process.connections);
            ++processItem;
        }
    }
    TrimHashTable(processes_);
    TrimHashTable(ndisConnections_);
    out.processes.reset(processCount);
    out.connections.reset(includeConnections ? connectionCount : 0);
    size_t processIndex = 0;
    size_t connectionIndex = 0;

    for (auto& processItem : processes_) {
        ProcessConnections& process = processItem.second;
        DisplayProcess* displayProcess = nullptr;
        const size_t connectionBegin = connectionIndex;
        double processSpeed = 0.0;

        for (auto& connectionItem : process.connections) {
            ConnectionRecord& stored = connectionItem.second;
            ++out.flowCount;
            if (stored.driverBacked && !stored.systemBacked)
                ++out.driverOnlyFlows;

            const bool displayState = IsDisplayState(stored);
            const DisplayTraffic traffic = displayState
                ? DisplayTrafficOf(process, stored, lastTakeAt_, now)
                : DisplayTraffic{};
            const DriverDetails* details = DriverDetailsOf(stored);
            if (details && (details->periodSent || details->periodRecv ||
                            details->period.end)) {
                DriverDetails& mutableDetails = EnsureDriverDetails(stored);
                mutableDetails.periodSent = 0;
                mutableDetails.periodRecv = 0;
                mutableDetails.period = TrafficPeriod{};
                details = &mutableDetails;
            }
            stored.systemPeriodSent = 0;
            stored.systemPeriodRecv = 0;
            stored.systemPeriod = TrafficPeriod{};

            // Из системных TCP-строк показываем только LISTEN и ESTABLISHED.
            // Периоды скрытых строк тоже сбрасываются ровно один раз.
            if (!displayState) continue;
            if (traffic.passive) {
                ++out.hiddenCount;
                if (!showPassive) continue;
            }
            const bool finished = process.removeAfter != 0 ||
                (stored.removeAfter != 0 && stored.blockedAt == 0);

            if (!displayProcess) {
                displayProcess = &out.processes[processIndex++];
                displayProcess->group = processItem.first;
                displayProcess->removeAfter = process.removeAfter;
                displayProcess->connCount = 0;
                displayProcess->ownerAmbiguous = false;
            }
            ++displayProcess->connCount;
            displayProcess->ownerAmbiguous = displayProcess->ownerAmbiguous ||
                                             stored.ownerAmbiguous;
            if (!includeConnections) continue;

            DisplayConnection& display = out.connections[connectionIndex++];
            display = DisplayConnection{};
            display.key = stored.key;
            display.interfaceIndex = stored.key.source == TrafficSource::Ndis
                ? stored.key.interfaceIndex : details ? details->interfaceIndex : 0;
            display.interfaceName = details ? details->interfaceName : nullptr;
            display.flowGeneration = stored.generation;
            display.sent = traffic.sent;
            display.recv = traffic.recv;
            display.periodSent = traffic.periodSent;
            display.periodRecv = traffic.periodRecv;
            display.period = traffic.period;
            display.lastActivity = traffic.lastActivity;
            display.removeAfter = stored.removeAfter;
            display.blockedAt = stored.blockedAt;
            display.state = stored.state;
            display.dir = stored.dir;
            display.bytesFrom = traffic.bytesFrom;
            display.ownerAmbiguous = stored.ownerAmbiguous;
            if (details) {
                display.tlsDomainLabel = details->tlsDomainLabel;
                display.conditionFlags = details->conditionFlags;
                display.pktSent = details->packetSent;
                display.pktRecv = details->packetRecv;
                display.driverEvents = details->events;
                display.icmp = details->icmp;
                display.icmpOut = details->icmpOut;
                display.icmpIn = details->icmpIn;
            }

            if (stored.key.proto == Proto::Tcp &&
                stored.dir == Dir::Unknown &&
                stored.state != MIB_TCP_STATE_SYN_SENT &&
                stored.state != MIB_TCP_STATE_SYN_RCVD &&
                stored.state != MIB_TCP_STATE_LISTEN) {
                if (const ConnectionOwnerIndex* index = OwnerIndexFor(
                        ownerIndexes_, stored.key)) {
                    const auto owner = index->find(stored.key);
                    // Индексы очищаются после соединений, как и прежде.
                    // Снимок не должен видеть уже просроченного владельца.
                    display.localListener = owner != index->end() &&
                        owner->second.localListener &&
                        !OwnerExpired(owner->second, now, inactiveMs);
                }
            }

            if (traffic.bytesFrom != BytesDriver || !finished)
                processSpeed += display.bytesPerSecond();
        }

        if (displayProcess) {
            displayProcess->speed = processSpeed;
            displayProcess->connections = out.connections.span().subspan(
                connectionBegin, connectionIndex - connectionBegin);
        }
    }
    ExpireOwnerIndexesLocked(now, inactiveMs);
    out.removedConnections = removedSinceTake_;
    removedSinceTake_ = 0;
    lastTakeAt_ = now;
}

// Гостевое соединение индексируется отдельно: ни PID, ни живой сокет Windows ему не нужны.
FlowStore::ConnectionRecord* FlowStore::NdisConnectionLocked(
    const FlowKey& key, bool newAttempt) {
    const TrafficGroupKey group = TrafficGroupKey::Ndis(key.interfaceIndex);
    auto indexed = ndisConnections_.find(key);
    if (indexed != ndisConnections_.end()) {
        auto process = processes_.find(group);
        if (process != processes_.end()) {
            auto found = process->second.connections.find(indexed->second);
            if (found != process->second.connections.end() && !found->second.retired) {
                ConnectionRecord& connection = found->second;
                if (!newAttempt || !connection.removeAfter) return &connection;
                connection.retired = true;
                FreezeConnectionLocked(connection);
            }
        }
        ndisConnections_.erase(indexed);
    }
    ConnectionRecord connection;
    connection.key = key;
    connection.generation = NextGenerationLocked();
    const uint64_t generation = connection.generation;
    ConnectionRecord& result = GroupLocked(group).connections.emplace(
        generation, std::move(connection)).first->second;
    ndisConnections_.emplace(key, generation);
    return &result;
}

template <class Value>
void FlowStore::AddNdisBandwidth(uint8_t protocol, const Value* entries, uint32_t count, uint32_t interfaceIndex) {
    if ((!entries && count) || !enabled_.load(std::memory_order_relaxed)) return;
    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(mtx_);
    for (uint32_t i = 0; i < count; ++i) {
        const Value& entry = entries[i];
        FlowKey key = MakeFlowKey(ProtoFromNumber(protocol), IpFromRaw(entry.local_ip),
            IpFromRaw(entry.remote_ip), entry.local_port, entry.remote_port);
        key.source = TrafficSource::Ndis;
        key.interfaceIndex = interfaceIndex;
        ConnectionRecord* connection = NdisConnectionLocked(key);
        DriverDetails& details = EnsureDriverDetails(*connection);
        CaptureInterface(details, interfaceIndex);
        details.sent += entry.transmitted_bytes;
        details.recv += entry.received_bytes;
        details.periodSent += entry.transmitted_bytes;
        details.periodRecv += entry.received_bytes;
        const TrafficPeriod period = ndisBandwidthPoll_.end
            ? ndisBandwidthPoll_ : TrafficPeriod{ details.lastBandwidthAt, now };
        details.period.Include(period.begin, period.end);
        details.lastBandwidthAt = now;
        details.countersActive = true;
        connection->driverBacked = true;
        details.lastChangedAt = now;
        connection->lastActivity = now;
    }
}

void FlowStore::AddNdisBandwidthBatch(uint8_t protocol,
    const firewallxndisfilter::Client::BandwidthV4* entries, uint32_t count, uint32_t interfaceIndex) {
    AddNdisBandwidth(protocol, entries, count, interfaceIndex);
}

void FlowStore::AddNdisBandwidthBatch(uint8_t protocol,
    const firewallxndisfilter::Client::BandwidthV6* entries, uint32_t count, uint32_t interfaceIndex) {
    AddNdisBandwidth(protocol, entries, count, interfaceIndex);
}

void FlowStore::ResetHost() {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = processes_.begin(); it != processes_.end();) {
        it = it->first.isNdis() ? std::next(it) : processes_.erase(it);
    }
    ownerIndexes_ = ConnectionOwnerIndexes{};
    localSockets_ = LocalSocketTables{};
    for (uint64_t& revision : systemRevision_) revision = 0;
    for (ULONGLONG& tick : bandwidthTick_) tick = 0;
    bandwidthPoll_ = TrafficPeriod{};
    bandwidthPollManaged_ = false;
}

void FlowStore::Reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    processes_ = decltype(processes_){};
    ndisConnections_ = decltype(ndisConnections_){};
    ndisBandwidthPoll_ = TrafficPeriod{};
    ownerIndexes_ = ConnectionOwnerIndexes{};
    localSockets_ = LocalSocketTables{};
    for (uint64_t& revision : systemRevision_) revision = 0;
    for (ULONGLONG& tick : bandwidthTick_) tick = 0;
    bandwidthPoll_ = TrafficPeriod{};
    bandwidthPollManaged_ = false;
    lastTakeAt_ = 0;
    removedSinceTake_ = 0;
    // generationSeq_ намеренно не обнуляется: RowKey старой и новой сессий не
    // должны совпасть, пока UI ещё держит предыдущий снимок.
}

namespace {

uint64_t FixUdpTx(uint64_t transmitted) {
    return transmitted;
}

template <class Value>
void AddDriverBandwidth(const Value* entry, uint8_t protocol) {
    if (!entry) return;
    const Proto proto = ProtoFromNumber(protocol);
    if (!ProtoInOsTables(proto)) return;

    const FlowKey key = MakeFlowKey(
        proto, IpFromRaw(entry->local_ip), IpFromRaw(entry->remote_ip),
        entry->local_port, entry->remote_port);
    const uint64_t sent = proto == Proto::Udp
        ? FixUdpTx(entry->transmitted_bytes) : entry->transmitted_bytes;
    FlowStore::Instance().AddBandwidth(key, sent, entry->received_bytes);
}

template <class Record>
void NoteConnectionEnd(const Record* entry) {
    if (!entry) return;
    const FlowKey key = MakeFlowKey(
        ProtoFromNumber(entry->protocol),
        IpFromRaw(entry->local_ip), IpFromRaw(entry->remote_ip),
        entry->local_port, entry->remote_port);
    FlowStore::Instance().CloseFlow(
        key, static_cast<DWORD>(entry->process_id), DirFromDriver(entry->direction));
}

} // namespace

void on_bandwidthstats_V4(const pmkext::BandwidthValueV4* entry_,
                          uint8_t protocol) {
    AddDriverBandwidth(entry_, protocol);
}

void on_bandwidthstats_V6(const pmkext::BandwidthValueV6* entry_,
                          uint8_t protocol) {
    AddDriverBandwidth(entry_, protocol);
}

void on_connection_end_v4(const pmkext::ConnectionEndV4* entry_) {
    if (!entry_) return;

    if(0)
    {
        // Дописываем исходное событие завершения в файл рядом с exe до его обработки.
        static std::mutex logMtx;
        std::lock_guard<std::mutex> lock(logMtx);

        SYSTEMTIME now{};
        GetLocalTime(&now);
        const auto& e = *entry_;
        char line[512]{};
        const int length = _snprintf_s(
            line, _TRUNCATE,
            "%04u-%02u-%02u %02u:%02u:%02u.%03u; "
            "process_id=%llu; direction=%u; protocol=%u; "
            "local=%u.%u.%u.%u:%u; remote=%u.%u.%u.%u:%u\r\n",
            static_cast<unsigned>(now.wYear),
            static_cast<unsigned>(now.wMonth),
            static_cast<unsigned>(now.wDay),
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            static_cast<unsigned>(now.wMilliseconds),
            static_cast<unsigned long long>(e.process_id),
            static_cast<unsigned>(e.direction),
            static_cast<unsigned>(e.protocol),
            static_cast<unsigned>(e.local_ip[0]),
            static_cast<unsigned>(e.local_ip[1]),
            static_cast<unsigned>(e.local_ip[2]),
            static_cast<unsigned>(e.local_ip[3]),
            static_cast<unsigned>(e.local_port),
            static_cast<unsigned>(e.remote_ip[0]),
            static_cast<unsigned>(e.remote_ip[1]),
            static_cast<unsigned>(e.remote_ip[2]),
            static_cast<unsigned>(e.remote_ip[3]),
            static_cast<unsigned>(e.remote_port));

        if (length > 0) {
            const std::wstring path = ModuleDirFile(L"on_connection_end_v4.txt");
            HANDLE file = CreateFileW(
                path.c_str(), FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr);
                CloseHandle(file);
            }
        }
    }

    NoteConnectionEnd(entry_);
}

void on_connection_end_v6(const pmkext::ConnectionEndV6* entry_) {
    NoteConnectionEnd(entry_);
}
