#include "FlowStore.h"
#include "MacroAddr.h"

#include <algorithm>
#include <cstdlib>
#include <type_traits>
#include <cstring>
#include <iostream>
#include <iterator>

namespace {

[[noreturn]] void Fail(const char* text) {
    std::cerr << text << '\n';
    std::exit(1);
}

void Check(bool value, const char* text) {
    if (!value) Fail(text);
}

IpAddr V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    const uint8_t bytes[4] = { a, b, c, d };
    return IpAddr::Raw4(bytes);
}

IpAddr V6(uint8_t last) {
    uint8_t bytes[16]{};
    bytes[15] = last;
    return IpAddr::Raw6(bytes);
}

FlowKey Tcp4(uint16_t localPort = 41000, uint16_t remotePort = 443) {
    return MakeFlowKey(Proto::Tcp, V4(10, 0, 0, 2), V4(10, 0, 0, 3),
                       localPort, remotePort);
}

FlowKey Tcp6(uint16_t localPort = 41001, uint16_t remotePort = 443) {
    return MakeFlowKey(Proto::Tcp, V6(2), V6(3), localPort, remotePort);
}

FlowKey Udp4(uint16_t localPort = 53000, uint16_t remotePort = 53) {
    return MakeFlowKey(Proto::Udp, V4(10, 0, 0, 2), V4(8, 8, 8, 8),
                       localPort, remotePort);
}

FlowKey Udp6(uint16_t localPort = 53001, uint16_t remotePort = 53) {
    return MakeFlowKey(Proto::Udp, V6(2), V6(4), localPort, remotePort);
}

FlowStore::ConnEvent Event(DWORD pid) {
    FlowStore::ConnEvent event;
    event.pid = pid;
    event.dir = Dir::Out;
    return event;
}

FlowStore::View Take(ULONGLONG inactiveMs = FlowStore::kInactiveMs) {
    FlowStore::View view;
    FlowStore::Instance().Take(view, inactiveMs);
    return view;
}

const FlowStore::ProcessConnectionRecord& Process(
    const FlowStore::View& view, TrafficGroupKey group) {
    const auto it = view.processes.find(group);
    Check(it != view.processes.end(), "process record is missing");
    return it->second;
}

const FlowStore::DisplayProcess& DisplayProcess(
    const FlowStore::DisplayView& view, TrafficGroupKey group) {
    for (const FlowStore::DisplayProcess& process : view.processes)
        if (process.group == group) return process;
    Fail("display process record is missing");
}

const FlowStore::DisplayConnection* DisplayConnection(
    const FlowStore::DisplayProcess& process, const FlowKey& key) {
    for (const FlowStore::DisplayConnection& connection : process.connections)
        if (connection.key == key) return &connection;
    return nullptr;
}

const FlowStore::ConnectionRecord* Connection(
    const FlowStore::ProcessConnectionRecord& process, const FlowKey& key) {
    const FlowStore::ConnectionRecord* result = nullptr;
    for (const auto& item : process.connections) {
        if (!(item.second.key == key)) continue;
        if (!result || item.second.generation > result->generation)
            result = &item.second;
    }
    return result;
}

const FlowStore::DriverTrafficEntry* DriverTraffic(
    const FlowStore::ProcessConnectionRecord& process, const FlowKey& key) {
    const FlowStore::DriverTrafficTable* table = nullptr;
    if (key.proto == Proto::Tcp)
        table = key.local.family == AF_INET
            ? &process.driverTraffic.tcpV4 : &process.driverTraffic.tcpV6;
    else if (key.proto == Proto::Udp)
        table = key.local.family == AF_INET
            ? &process.driverTraffic.udpV4 : &process.driverTraffic.udpV6;
    if (!table) return nullptr;
    const FlowStore::ConnectionRecord* connection = Connection(process, key);
    if (!connection) return nullptr;
    const auto it = table->find(FlowId{ key, connection->generation });
    return it == table->end() ? nullptr : &it->second;
}

void OpenDriverFlow(const FlowKey& key, DWORD pid, Dir dir = Dir::Out) {
    FlowStore& store = FlowStore::Instance();
    FlowStore::ConnEvent event = Event(pid);
    event.dir = dir;
    store.NoteConnection(key, event);
    store.NoteAllowed(key, event);
}

void EndDriverFlow(const FlowKey& key, DWORD pid, Dir dir) {
    const auto fill = [&](auto& entry) {
        entry.process_id = pid;
        entry.protocol = ProtoNumber(key.proto);
        entry.direction = dir == Dir::In ? 1 : 0;
        std::memcpy(entry.local_ip, key.local.b, sizeof(entry.local_ip));
        std::memcpy(entry.remote_ip, key.remote.b, sizeof(entry.remote_ip));
        entry.local_port = key.lport;
        entry.remote_port = key.rport;
    };
    if (key.local.family == AF_INET) {
        pmkext::ConnectionEndV4 entry{};
        fill(entry);
        on_connection_end_v4(&entry);
    } else {
        pmkext::ConnectionEndV6 entry{};
        fill(entry);
        on_connection_end_v6(&entry);
    }
}

void TestSystemPidsAreNormalProcessKeys() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    FlowStore::ConnEvent icmp = Event(0);
    icmp.bytes = 84;
    icmp.icmpType = 8;
    store.NoteConnection(
        MakeFlowKey(Proto::Icmp, V4(127, 0, 0, 1), V4(127, 0, 0, 1), 0, 0),
        icmp);
    OpenDriverFlow(Tcp4(), 4);

    const FlowStore::View view = Take();
    Check(view.processes.count(0) == 1, "PID 0 was excluded");
    Check(view.processes.count(4) == 1, "PID 4 was excluded");
    Check(!Process(view, 0).connections.empty(), "PID 0 has no connections");
    Check(!Process(view, 4).connections.empty(), "PID 4 has no connections");
}

void TestFourDriverTrafficTables() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const DWORD pid = 1100;
    const FlowKey tcp4 = Tcp4();
    const FlowKey tcp6 = Tcp6();
    const FlowKey udp4 = Udp4();
    const FlowKey udp6 = Udp6();

    OpenDriverFlow(tcp4, pid);
    OpenDriverFlow(tcp6, pid);
    OpenDriverFlow(udp4, pid);
    OpenDriverFlow(udp6, pid);
    store.AddBandwidth(tcp4, 1, 2);
    store.AddBandwidth(tcp6, 3, 4);
    store.AddBandwidth(udp4, 5, 6);
    store.AddBandwidth(udp6, 7, 8);

    const FlowStore::View view = Take();
    const auto& traffic = Process(view, pid).driverTraffic;
    Check(traffic.tcpV4.size() == 1, "TCP/IPv4 driver table is wrong");
    Check(traffic.tcpV6.size() == 1, "TCP/IPv6 driver table is wrong");
    Check(traffic.udpV4.size() == 1, "UDP/IPv4 driver table is wrong");
    Check(traffic.udpV6.size() == 1, "UDP/IPv6 driver table is wrong");
    Check(traffic.tcpV4.begin()->second.lastChangedAt != 0,
          "driver traffic has no last-change timestamp");
}

void TestBandwidthBatchUsesOneSnapshotPath() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    const DWORD pid = 1150;
    const FlowKey first = Tcp4(41100, 80);
    const FlowKey second = Tcp4(41101, 443);
    OpenDriverFlow(first, pid);
    OpenDriverFlow(second, pid);

    pmkext::BandwidthValueV4 entries[2]{};
    const FlowKey keys[2] = { first, second };
    for (size_t index = 0; index < std::size(entries); ++index) {
        std::memcpy(entries[index].local_ip, keys[index].local.b, 4);
        std::memcpy(entries[index].remote_ip, keys[index].remote.b, 4);
        entries[index].local_port = keys[index].lport;
        entries[index].remote_port = keys[index].rport;
        entries[index].transmitted_bytes = 10 + index;
        entries[index].received_bytes = 20 + index;
    }

    store.AddBandwidthBatch(DriverProto::kTcp, entries,
                            static_cast<uint32_t>(std::size(entries)));
    const FlowStore::View view = Take();
    const auto& process = Process(view, pid);
    const auto* firstTraffic = DriverTraffic(process, first);
    const auto* secondTraffic = DriverTraffic(process, second);
    Check(firstTraffic && firstTraffic->sent == 10 &&
          firstTraffic->recv == 20,
          "first bandwidth batch entry was lost");
    Check(secondTraffic && secondTraffic->sent == 11 &&
          secondTraffic->recv == 21,
          "second bandwidth batch entry was lost");
}

void TestUnknownBandwidthMovesToReportedPid() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Tcp4(42000);

    store.AddBandwidth(key, 17, 9);
    FlowStore::View view = Take();
    Check(DriverTraffic(Process(view, 0), key) != nullptr,
          "unknown bandwidth was not assigned to PID 0");

    store.AssignReportedOwner(key, 1200);
    OpenDriverFlow(key, 1200);
    view = Take();
    const auto* traffic = DriverTraffic(Process(view, 1200), key);
    Check(traffic && traffic->sent == 17 && traffic->recv == 9,
          "reported PID did not move driver traffic from PID 0");
    const auto owner = view.ownerIndexes.tcpV4.find(key);
    Check(owner != view.ownerIndexes.tcpV4.end() && owner->second.pid == 1200 &&
          owner->second.lastAccessAt != 0,
          "reported PID did not update the owner index and access time");
}

void TestOwnerTransfersPreserveConnection() {
    FlowStore& store = FlowStore::Instance();
    const FlowKey keys[] = { Tcp4(42100), Tcp6(42101), Udp4(53100), Udp6(53101) };
    const DWORD destinations[] = { 2300, 2400, 2300, 2400 };
    for (const FlowKey& key : keys)
    for (DWORD initialPid : { DWORD{ 0 }, DWORD{ 4 } }) {
        store.Reset();
        FlowStore::ConnEvent event = Event(initialPid);
        event.icmpType = 3;
        event.icmpCode = 1;
        event.tlsDomainLabel =
            std::make_shared<const std::wstring>(L"[transfer.example]");
        store.NoteConnection(key, event);
        store.NoteAllowed(key, event);
        store.AddBandwidth(key, 17, 9);

        // Один адресат уже существует и содержит постороннее соединение.
        FlowKey unrelated = key;
        ++unrelated.lport;
        OpenDriverFlow(unrelated, destinations[1]);
        uint64_t generation = 0;
        DWORD previousPid = initialPid;
        for (size_t index = 0; index < std::size(destinations); ++index) {
            const DWORD pid = destinations[index];
            store.AssignReportedOwner(key, pid);
            Check(store.ResolveEventOwner(0, key) == pid,
                  "transfer did not update the indexed owner");

            FlowStore::DisplayView display;
            store.TakeDisplay(display, FlowStore::kInactiveMs, true);
            const auto* connection = DisplayConnection(DisplayProcess(display, pid), key);
            Check(connection != nullptr, "transfer lost the displayed connection");
            if (!generation) generation = connection->flowGeneration;
            Check(connection->flowGeneration == generation && connection->dir == Dir::Out &&
                  connection->sent == 17 + index * 5 && connection->recv == 9 + index * 3 &&
                  connection->periodSent == (index == 0 ? 17u : 5u) &&
                  connection->periodRecv == (index == 0 ? 9u : 3u) &&
                  connection->bytesFrom == BytesDriver && connection->driverEvents == 1 &&
                  connection->icmp.type == 3 && connection->icmp.code == 1 &&
                  connection->tlsDomainLabel == event.tlsDomainLabel,
                  "transfer changed generation, counters or driver metadata");
            Check(display.flowCount == 2 && display.removedConnections == 0 &&
                  DisplayConnection(DisplayProcess(display, destinations[1]), unrelated),
                  "transfer changed unrelated connections or removal counts");
            for (const auto& process : display.processes)
                if (process.group == TrafficGroupKey::Host(previousPid))
                    Check(!DisplayConnection(process, key),
                          "transfer left a duplicate under the previous PID");
            previousPid = pid;
            if (index + 1 < std::size(destinations)) store.AddBandwidth(key, 5, 3);
        }

        // После END новое поколение не должно переместить или заменить старое.
        store.CloseFlow(key, previousPid, Dir::Out);
        store.AssignReportedOwner(key, destinations[0]);
        store.NoteConnection(key, Event(destinations[0]));
        const FlowStore::View view = Take();
        const auto* closed = Connection(Process(view, previousPid), key);
        const auto* current = Connection(Process(view, destinations[0]), key);
        Check(closed && closed->generation == generation && closed->retired &&
              closed->removeAfter && closed->driver && closed->driver->sent == 32 &&
              current && current->generation != generation && !current->removeAfter,
              "tuple reuse lost or replaced the transferred generation");
    }
}

void TestPidFourDoesNotOverwriteOwnerIndex() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Tcp4(42001);
    OpenDriverFlow(key, 4);

    const FlowStore::View view = Take();
    const auto owner = view.ownerIndexes.tcpV4.find(key);
    Check(owner != view.ownerIndexes.tcpV4.end(),
          "PID 4 event did not create an accessible index entry");
    Check(owner->second.pid == 0,
          "PID 4 event overwrote the owner index");
    Check(Connection(Process(view, 4), key) != nullptr,
          "PID 4 connection was not stored under PID 4");
}

void TestTwoCurrentSystemTrafficTables() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    FlowStore::SystemSnapshot snapshot;
    FlowStore::SystemTcpConnection row4;
    row4.key = Tcp4(43000);
    row4.pid = 0;
    row4.state = MIB_TCP_STATE_ESTAB;
    row4.sent = 100;
    row4.recv = 50;
    row4.countersRead = true;
    snapshot.tcpV4.push_back(row4);
    snapshot.tcpV4Valid = true;

    FlowStore::SystemTcpConnection row6;
    row6.key = Tcp6(43001);
    row6.pid = 4;
    row6.state = MIB_TCP_STATE_ESTAB;
    row6.sent = 200;
    row6.recv = 75;
    row6.countersRead = true;
    snapshot.tcpV6.push_back(row6);
    snapshot.tcpV6Valid = true;
    store.ReplaceSystemSnapshot(snapshot);

    FlowStore::View view = Take();
    const auto& pid0 = Process(view, 0);
    const auto& pid4 = Process(view, 4);
    const auto* originalConnection = Connection(pid0, row4.key);
    Check(originalConnection != nullptr, "system connection is missing");
    const uint64_t originalGeneration = originalConnection->generation;
    Check(pid0.systemTraffic.tcpV4.at(row4.key).sent == 100,
          "TCP/IPv4 system traffic is missing");
    Check(pid4.systemTraffic.tcpV6.at(row6.key).recv == 75,
          "TCP/IPv6 system traffic is missing");
    Check(pid0.systemTraffic.tcpV4.at(row4.key).hasTraffic(),
          "nonzero system traffic was not made authoritative");
    FlowStore::SystemTrafficEntry zeroSystem;
    Check(!zeroSystem.hasTraffic(),
          "0/0 system traffic incorrectly became authoritative");
    zeroSystem.recv = 1;
    Check(zeroSystem.hasTraffic(),
          "one nonzero system counter was ignored");
    Check(pid0.systemTraffic.tcpV6.empty() &&
          pid4.systemTraffic.tcpV4.empty(),
          "system traffic families were mixed");

    FlowStore::SystemSnapshot next;
    next.tcpV4Valid = true;
    store.ReplaceSystemSnapshot(next);
    view = Take();
    const auto old = view.processes.find(0);
    Check(old == view.processes.end() || old->second.systemTraffic.tcpV4.empty(),
          "system table was not replaced by the current empty snapshot");

    snapshot.tcpV4[0].sent = 0;
    snapshot.tcpV4[0].recv = 0;
    store.ReplaceSystemSnapshot(snapshot);
    view = Take();
    const auto* restored = Connection(Process(view, 0), row4.key);
    Check(restored && !restored->removeAfter &&
          restored->generation != originalGeneration &&
          !restored->systemTrafficAuthoritative,
          "returning system row reused stale connection state");
}

void TestSystemTrafficPermanentlySupersedesDriverTraffic() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Tcp4(43500);
    OpenDriverFlow(key, 0);
    store.AddBandwidth(key, 40, 20);

    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    FlowStore::SystemTcpConnection row;
    row.key = key;
    row.pid = 0;
    row.state = MIB_TCP_STATE_ESTAB;
    row.sent = 100;
    row.recv = 0;
    row.countersRead = true;
    snapshot.tcpV4.push_back(row);
    store.ReplaceSystemSnapshot(snapshot);

    FlowStore::View view = Take();
    const auto* connection = Connection(Process(view, 0), key);
    Check(connection && connection->systemTrafficAuthoritative &&
          connection->lastSystemSent == 100,
          "one-sided nonzero y2 did not permanently supersede y1");

    snapshot.tcpV4[0].sent = 0;
    snapshot.tcpV4[0].recv = 0;
    snapshot.tcpV4[0].countersRead = false;
    store.ReplaceSystemSnapshot(snapshot);
    view = Take();
    const auto& process = Process(view, 0);
    connection = Connection(process, key);
    Check(connection && connection->systemTrafficAuthoritative &&
          connection->lastSystemSent == 100,
          "temporary 0/0 y2 returned the connection to y1");
    Check(process.systemTraffic.tcpV4.at(key).sent == 0 &&
          process.systemTraffic.tcpV4.at(key).recv == 0,
          "y2 did not retain the current 0/0 system record");
}

void TestUdpSnapshotHasNoSystemTrafficTable() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    FlowStore::SystemSnapshot snapshot;
    snapshot.udpV4Valid = true;
    snapshot.udpV4.push_back(FlowStore::SystemUdpEndpoint{
        V4(0, 0, 0, 0), 5353, 4
    });
    store.ReplaceSystemSnapshot(snapshot);

    const FlowStore::View view = Take();
    const auto& process = Process(view, 4);
    Check(!process.connections.empty(), "UDP endpoint did not create a connection");
    Check(process.systemTraffic.tcpV4.empty() &&
          process.systemTraffic.tcpV6.empty(),
          "UDP created a system traffic entry");
}

void TestSystemRowsDoNotInventActivity() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    FlowKey listener;
    listener.proto = Proto::Tcp;
    listener.local = V4(0, 0, 0, 0);
    listener.remote.family = AF_INET;
    listener.lport = 5356;

    FlowKey udpEndpoint = MakeFlowKey(
        Proto::Udp, V4(0, 0, 0, 0), IpAddr{}, 5357, 0);
    udpEndpoint.remote.family = AF_INET;

    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    FlowStore::SystemTcpConnection tcp;
    tcp.key = listener;
    tcp.pid = 4;
    tcp.state = MIB_TCP_STATE_LISTEN;
    snapshot.tcpV4.push_back(tcp);
    snapshot.udpV4Valid = true;
    snapshot.udpV4.push_back(FlowStore::SystemUdpEndpoint{
        udpEndpoint.local, udpEndpoint.lport, 4
    });
    store.ReplaceSystemSnapshot(snapshot);

    const FlowStore::View view = Take();
    const auto& process = Process(view, 4);
    const auto* tcpConnection = Connection(process, listener);
    const auto* udpConnection = Connection(process, udpEndpoint);
    Check(tcpConnection && tcpConnection->lastActivity == 0,
          "system TCP listener invented network activity");
    Check(udpConnection && udpConnection->lastActivity == 0,
          "system UDP endpoint invented network activity");
}

void TestUdpEndpointDoesNotDuplicateConcreteFlow() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Udp4(5354, 53);
    OpenDriverFlow(key, 0);
    store.AddBandwidth(key, 8, 3);

    FlowStore::SystemSnapshot snapshot;
    snapshot.udpV4Valid = true;
    snapshot.udpV4.push_back(FlowStore::SystemUdpEndpoint{
        key.local, key.lport, 0
    });
    store.ReplaceSystemSnapshot(snapshot);

    const FlowStore::View view = Take();
    const auto& process = Process(view, 0);
    Check(process.connections.size() == 1,
          "UDP endpoint duplicated a concrete driver flow");
    Check(Connection(process, key) != nullptr,
          "concrete UDP flow disappeared during endpoint merge");
}

void TestUdpBandwidthUsesCurrentLocalEndpointOwner() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Udp4(5355, 53);

    FlowStore::SystemSnapshot snapshot;
    snapshot.udpV4Valid = true;
    snapshot.udpV4.push_back(FlowStore::SystemUdpEndpoint{
        key.local, key.lport, 4
    });
    store.ReplaceSystemSnapshot(snapshot);
    store.AddBandwidth(key, 9, 2);
    store.ReplaceSystemSnapshot(snapshot);

    const FlowStore::View view = Take();
    const auto& process = Process(view, 4);
    Check(DriverTraffic(process, key) != nullptr,
          "UDP bandwidth ignored the current local endpoint owner");
    const auto owner = view.ownerIndexes.udpV4.find(key);
    Check(owner != view.ownerIndexes.udpV4.end() && owner->second.pid == 4,
          "UDP exact owner index was not filled from the local endpoint");
}

void TestListenerProtectsDriverTraffic() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const DWORD pid = 1300;
    const FlowKey flow = Tcp4(44000);
    OpenDriverFlow(flow, pid);
    store.AddBandwidth(flow, 10, 5);

    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    FlowStore::SystemTcpConnection listener;
    listener.key.proto = Proto::Tcp;
    listener.key.local = V4(0, 0, 0, 0);
    listener.key.remote.family = AF_INET;
    listener.key.lport = flow.lport;
    listener.pid = pid;
    listener.state = MIB_TCP_STATE_LISTEN;
    snapshot.tcpV4.push_back(listener);
    store.ReplaceSystemSnapshot(snapshot);

    ::Sleep(20);
    const FlowStore::View view = Take(0);
    const auto owner = view.ownerIndexes.tcpV4.find(flow);
    Check(owner != view.ownerIndexes.tcpV4.end() &&
          owner->second.localListener,
          "local listener was not reflected in the owner index");
    Check(DriverTraffic(Process(view, pid), flow) != nullptr,
          "listener-protected driver traffic expired");
}

void TestEndedOwnersExpireWithListener() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        for (bool blocked : { false, true }) {
            store.Reset();
            OpenDriverFlow(key, pid);
            store.AddBandwidth(key, 10, 5);

            FlowStore::SystemSnapshot snapshot;
            if (key.proto == Proto::Tcp) {
                FlowStore::SystemTcpConnection listener;
                listener.key = key;
                listener.key.local = IpAddr{};
                listener.key.local.family = key.local.family;
                listener.key.remote = listener.key.local;
                listener.key.rport = 0;
                listener.pid = pid;
                listener.state = MIB_TCP_STATE_LISTEN;
                if (key.local.family == AF_INET) {
                    snapshot.tcpV4Valid = true;
                    snapshot.tcpV4.push_back(listener);
                } else {
                    snapshot.tcpV6Valid = true;
                    snapshot.tcpV6.push_back(listener);
                }
            } else {
                FlowStore::SystemUdpEndpoint endpoint{ key.local, key.lport, pid };
                if (key.local.family == AF_INET) {
                    snapshot.udpV4Valid = true;
                    snapshot.udpV4.push_back(endpoint);
                } else {
                    snapshot.udpV6Valid = true;
                    snapshot.udpV6.push_back(endpoint);
                }
            }
            store.ReplaceSystemSnapshot(snapshot);

            const auto indexOf = [&](const FlowStore::View& view)
                -> const FlowStore::ConnectionOwnerIndex& {
                if (key.proto == Proto::Tcp)
                    return key.local.family == AF_INET
                        ? view.ownerIndexes.tcpV4 : view.ownerIndexes.tcpV6;
                return key.local.family == AF_INET
                    ? view.ownerIndexes.udpV4 : view.ownerIndexes.udpV6;
            };

            // Действующий обмен защищён сокетом даже при нулевом сроке простоя.
            ::Sleep(20);
            const auto active = Take(0);
            Check(indexOf(active).count(key) == 1 &&
                  indexOf(active).at(key).localListener &&
                  DriverTraffic(Process(active, pid), key) != nullptr,
                  "listener-protected active flow expired");

            if (blocked) store.NoteBlocked(key, Event(pid));
            else EndDriverFlow(key, pid, Dir::Out);
            store.ReplaceSystemSnapshot(snapshot);
            const auto retained = Take();
            Check(indexOf(retained).count(key) == 1 &&
                  indexOf(retained).at(key).ended &&
                  indexOf(retained).at(key).localListener,
                  "ended owner was not retained within the inactivity timeout");

            // Открытый порт не продлевает жизнь истории завершённого tuple.
            ::Sleep(20);
            const auto expired = Take(0);
            Check(indexOf(expired).count(key) == 0,
                  "local listener retained an inactive ended owner");
            bool found = false;
            store.ResolveEventOwner(0, key, &found, nullptr, Dir::Out);
            Check(!found, "expired owner remained available to event lookup");
        }
    }
}

void TestInactiveEntriesWithoutListenerExpire() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Udp4(45000);
    OpenDriverFlow(key, 1400);
    store.AddBandwidth(key, 3, 2);

    ::Sleep(20);
    const FlowStore::View view = Take(0);
    const auto process = view.processes.find(1400);
    Check(process == view.processes.end() ||
          DriverTraffic(process->second, key) == nullptr,
          "inactive driver traffic without a listener was retained");
    Check(view.ownerIndexes.udpV4.count(key) == 0,
          "inactive owner index without a listener was retained");
}

void TestLocalConnectionEndClosesReverseFlow() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    for (Proto proto : { Proto::Tcp, Proto::Udp }) {
        std::vector<FlowKey> keys = {
            MakeFlowKey(proto, V4(127, 0, 0, 1), V4(127, 23, 45, 67),
                        54000, 54001),
            MakeFlowKey(proto, V6(1), V6(1), 54002, 54003),
        };
        for (const MacroEntry& entry : AddrMacros::Resolve(AddrMacro::AllMyAddresses)) {
            const IpAddr loopback = entry.addr.family == AF_INET
                ? V4(127, 0, 0, 1) : V6(1);
            keys.push_back(MakeFlowKey(
                proto, entry.addr, loopback, 54004, 54005));
            keys.push_back(MakeFlowKey(
                proto, entry.addr, entry.addr, 54006, 54007));
        }

        for (const FlowKey& key : keys)
        for (Dir dir : { Dir::Out, Dir::In })
        for (bool driverEnd : { false, true }) {
            store.Reset();
            const FlowKey reverse = MakeFlowKey(
                key.proto, key.remote, key.local, key.rport, key.lport);
            OpenDriverFlow(key, pid, dir);
            OpenDriverFlow(reverse, 4, dir == Dir::In ? Dir::Out : Dir::In);
            store.AddBandwidth(key, 11, 7);
            store.AddBandwidth(reverse, 7, 11);
            if (driverEnd) EndDriverFlow(key, pid, dir);
            else store.CloseFlow(key, pid, dir);

            const FlowStore::View view = Take();
            const auto* forward = Connection(Process(view, pid), key);
            const auto* backward = Connection(Process(view, 4), reverse);
            Check(forward && forward->endReceived && forward->removeAfter,
                  "local END did not close the original flow");
            Check(backward && backward->endReceived && backward->removeAfter,
                  "local END did not close the reverse flow in another process");
            Check(forward->driver && forward->driver->frozenCountersKnown &&
                  forward->driver->frozenSent == 11 && forward->driver->frozenRecv == 7 &&
                  backward->driver && backward->driver->frozenCountersKnown &&
                  backward->driver->frozenSent == 7 && backward->driver->frozenRecv == 11,
                  "local END lost the final counters");
        }
    }
}

void TestLocalStaleEndKeepsCurrentPair() {
    FlowStore& store = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    const DWORD oldPid = currentPid + 4;
    const DWORD reversePid = currentPid + 8;
    enum class History { Missing, Ended, Retired };
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (bool ipv6 : { false, true })
    for (Dir dir : { Dir::Out, Dir::In })
    for (History history : { History::Missing, History::Ended, History::Retired }) {
        store.Reset();
        const IpAddr local = ipv6 ? V6(1) : V4(127, 0, 0, 1);
        const FlowKey key = MakeFlowKey(proto, local, local, 54010, 54011);
        const FlowKey reverse = MakeFlowKey(proto, local, local, key.rport, key.lport);
        const Dir reverseDir = dir == Dir::In ? Dir::Out : Dir::In;
        uint64_t oldGeneration = 0;
        ULONGLONG oldDeadline = 0;
        if (history != History::Missing) {
            OpenDriverFlow(key, oldPid, dir);
            store.AddBandwidth(key, 10, 4);
            if (history == History::Ended) {
                EndDriverFlow(key, oldPid, dir);
            } else {
                FlowStore::ConnEvent blocked = Event(oldPid);
                blocked.dir = dir;
                store.NoteBlocked(key, blocked);
            }
            const auto original = Take();
            const auto* old = Connection(Process(original, oldPid), key);
            Check(old && old->removeAfter, "old local flow was not marked for removal");
            oldGeneration = old->generation;
            oldDeadline = old->removeAfter;
        }

        OpenDriverFlow(key, currentPid, dir);
        OpenDriverFlow(reverse, reversePid, reverseDir);
        store.AddBandwidth(key, 3, 2);
        store.AddBandwidth(reverse, 2, 3);
        const auto before = Take();
        const uint64_t forwardGeneration = Connection(Process(before, currentPid), key)->generation;
        const uint64_t reverseGeneration = Connection(Process(before, reversePid), reverse)->generation;
        Check(forwardGeneration != oldGeneration, "local tuple reuse did not create a new generation");

        // Старого поколения может уже не быть либо оно ещё хранится в истории.
        EndDriverFlow(key, oldPid, dir);
        if (oldGeneration) store.CloseFlow(key, 0, dir, oldGeneration);
        Check(store.ResolveEventOwner(0, key) == currentPid &&
              store.ResolveEventOwner(0, reverse) == reversePid,
              "stale local END invalidated the current pair's owners");
        const auto after = Take();
        const auto* forward = Connection(Process(after, currentPid), key);
        const auto* backward = Connection(Process(after, reversePid), reverse);
        Check(forward && forward->generation == forwardGeneration && !forward->endReceived &&
              !forward->removeAfter && forward->driver && forward->driver->sent == 3 &&
              forward->driver->recv == 2 && !forward->driver->frozenCountersKnown,
              "stale local END changed the current forward flow");
        Check(backward && backward->generation == reverseGeneration && !backward->endReceived &&
              !backward->removeAfter && backward->driver && backward->driver->sent == 2 &&
              backward->driver->recv == 3 && !backward->driver->frozenCountersKnown,
              "stale local END changed the current reverse flow");
        if (history != History::Missing) {
            const auto* old = Connection(Process(after, oldPid), key);
            Check(old && old->generation == oldGeneration && old->endReceived && old->retired &&
                  old->removeAfter >= oldDeadline &&
                  (history != History::Ended || old->removeAfter == oldDeadline) &&
                  !old->blockedAt && old->driver &&
                  old->driver->frozenSent == 10 && old->driver->frozenRecv == 4,
                  "stale local END did not preserve the matching history");
        }

        EndDriverFlow(key, currentPid, dir);
        const auto ended = Take();
        forward = Connection(Process(ended, currentPid), key);
        backward = Connection(Process(ended, reversePid), reverse);
        Check(forward && forward->endReceived && backward && backward->endReceived,
              "matching local END did not close the current pair");
    }
}

void TestRepeatedLocalEndKeepsNewReverseFlow() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    const DWORD reversePid = pid + 4;
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (bool ipv6 : { false, true })
    for (Dir dir : { Dir::Out, Dir::In }) {
        store.Reset();
        const IpAddr local = ipv6 ? V6(1) : V4(127, 0, 0, 1);
        const FlowKey key = MakeFlowKey(proto, local, local, 54012, 54013);
        const FlowKey reverse = MakeFlowKey(proto, local, local, key.rport, key.lport);
        const Dir reverseDir = dir == Dir::In ? Dir::Out : Dir::In;
        OpenDriverFlow(key, pid, dir);
        OpenDriverFlow(reverse, reversePid, reverseDir);
        EndDriverFlow(key, pid, dir);
        const auto original = Take();
        const ULONGLONG forwardDeadline = Connection(Process(original, pid), key)->removeAfter;
        const uint64_t oldReverseGeneration = Connection(Process(original, reversePid), reverse)->generation;

        OpenDriverFlow(reverse, reversePid, reverseDir);
        store.AddBandwidth(reverse, 7, 5);
        const auto before = Take();
        const uint64_t reverseGeneration = Connection(Process(before, reversePid), reverse)->generation;
        Check(reverseGeneration != oldReverseGeneration, "reverse tuple reuse did not create a new generation");

        // Прямая сторона всё ещё завершена: повторный END не закрывает новую обратную.
        EndDriverFlow(key, pid, dir);
        Check(store.ResolveEventOwner(0, reverse) == reversePid,
              "repeated local END invalidated the new reverse owner");
        const auto after = Take();
        const auto* forward = Connection(Process(after, pid), key);
        const auto* backward = Connection(Process(after, reversePid), reverse);
        Check(forward && forward->endReceived && forward->removeAfter == forwardDeadline,
              "repeated local END restarted the forward grace period");
        Check(backward && backward->generation == reverseGeneration && !backward->endReceived &&
              !backward->removeAfter && backward->driver && backward->driver->sent == 7 &&
              backward->driver->recv == 5 && !backward->driver->frozenCountersKnown,
              "repeated local END closed or froze the new reverse generation");
    }
}

void TestServiceLocalEndKeepsCurrentPair() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    const DWORD reversePid = pid + 4;
    store.Enable(false);
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (bool ipv6 : { false, true })
    for (Dir dir : { Dir::Out, Dir::In })
    for (DWORD reportedPid : { DWORD{ 0 }, pid }) {
        store.Reset();
        const IpAddr local = ipv6 ? V6(1) : V4(127, 0, 0, 1);
        const FlowKey key = MakeFlowKey(proto, local, local, 54014, 54015);
        const FlowKey reverse = MakeFlowKey(proto, local, local, key.rport, key.lport);
        store.AssignReportedOwner(key, pid);
        store.AssignReportedOwner(reverse, reversePid);
        EndDriverFlow(key, pid + 8, dir);
        Check(store.ResolveEventOwner(0, key) == pid &&
              store.ResolveEventOwner(0, reverse) == reversePid,
              "foreign service local END invalidated the current pair");

        EndDriverFlow(key, reportedPid, dir);
        Check(store.ResolveEventOwner(0, key) == 0 &&
              store.ResolveEventOwner(0, reverse) == 0,
              "matching service local END did not close both owner indexes");
        store.AssignReportedOwner(reverse, reversePid);
        EndDriverFlow(key, reportedPid, dir);
        Check(store.ResolveEventOwner(0, reverse) == reversePid,
              "repeated service local END invalidated the new reverse owner");
    }
    store.Enable(true);
}

void TestConnectionEndLeavesNonLocalReverseFlow() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    IpAddr external6 = V6(2);
    external6.b[0] = 0x20;
    external6.b[1] = 0x01;
    external6.b[2] = 0x0d;
    external6.b[3] = 0xb8;
    for (Proto proto : { Proto::Tcp, Proto::Udp }) {
        const FlowKey keys[] = {
            MakeFlowKey(proto, V4(127, 0, 0, 1), V4(192, 0, 2, 1),
                        54100, 54101),
            MakeFlowKey(proto, V4(192, 0, 2, 1), V4(127, 0, 0, 1),
                        54102, 54103),
            MakeFlowKey(proto, V6(1), external6, 54104, 54105),
            MakeFlowKey(proto, external6, V6(1), 54106, 54107),
        };
        for (const FlowKey& key : keys)
        for (Dir dir : { Dir::Out, Dir::In }) {
            store.Reset();
            const FlowKey reverse = MakeFlowKey(
                key.proto, key.remote, key.local, key.rport, key.lport);
            OpenDriverFlow(key, pid, dir);
            OpenDriverFlow(reverse, 4, dir == Dir::In ? Dir::Out : Dir::In);
            store.AddBandwidth(key, 11, 7);
            store.AddBandwidth(reverse, 7, 11);
            EndDriverFlow(key, pid, dir);

            const FlowStore::View view = Take();
            const auto* forward = Connection(Process(view, pid), key);
            const auto* backward = Connection(Process(view, 4), reverse);
            Check(forward && forward->endReceived && forward->removeAfter,
                  "END did not close the original non-local flow");
            Check(backward && !backward->endReceived && !backward->removeAfter,
                  "END closed a non-local reverse flow");
            Check(backward->driver && !backward->driver->frozenCountersKnown &&
                  backward->driver->sent == 7 && backward->driver->recv == 11,
                  "END froze or changed the counters of a non-local reverse flow");
        }
    }
}

void TestConnectionEndKeepsReportedPid() {
    FlowStore& store = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    const DWORD oldPid = currentPid + 4;
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        OpenDriverFlow(key, currentPid, Dir::In);
        store.AddBandwidth(key, 7, 3);
        const auto before = Take();
        const uint64_t generation = Connection(Process(before, currentPid), key)->generation;

        // Старой записи уже нет: чужой END не должен выбирать текущую вместо неё.
        EndDriverFlow(key, oldPid, Dir::In);
        Check(store.ResolveEventOwner(0, key) == currentPid,
              "foreign END invalidated the current owner without an old record");
        const auto after = Take();
        const auto* current = Connection(Process(after, currentPid), key);
        Check(current && current->generation == generation && !current->endReceived &&
              !current->removeAfter && current->driver && current->driver->sent == 7 &&
              current->driver->recv == 3 && !current->driver->frozenCountersKnown,
              "foreign END closed or froze the current connection");

        // Явно указанное поколение тоже не позволяет подменять ненулевой PID.
        store.CloseFlow(key, oldPid, Dir::In, generation);
        Check(store.ResolveEventOwner(0, key) == currentPid,
              "explicit generation allowed END to ignore the reported PID");
        EndDriverFlow(key, 0, Dir::In);
        Check(store.ResolveEventOwner(0, key) == 0,
              "END without a PID did not use the confirmed indexed owner");
        const auto ended = Take();
        current = Connection(Process(ended, currentPid), key);
        Check(current && current->endReceived && current->removeAfter,
              "END without a PID did not close the current generation");
    }
}

void TestStaleEndKeepsCurrentGeneration() {
    FlowStore& store = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    const DWORD oldPid = currentPid + 4;
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        OpenDriverFlow(key, oldPid, Dir::In);
        store.AddBandwidth(key, 10, 4);
        const auto original = Take();
        const uint64_t oldGeneration = Connection(Process(original, oldPid), key)->generation;
        EndDriverFlow(key, oldPid, Dir::In);
        OpenDriverFlow(key, currentPid, Dir::In);
        store.AddBandwidth(key, 3, 2);
        const auto before = Take();
        const uint64_t currentGeneration = Connection(Process(before, currentPid), key)->generation;
        Check(currentGeneration != oldGeneration, "tuple reuse did not create a new generation");
        const ULONGLONG oldDeadline = Connection(Process(before, oldPid), key)->removeAfter;

        // Повторный END старого процесса относится только к его истории.
        EndDriverFlow(key, oldPid, Dir::In);
        store.CloseFlow(key, oldPid, Dir::In, oldGeneration);
        Check(store.ResolveEventOwner(0, key) == currentPid,
              "stale END invalidated the new generation's owner");
        const auto after = Take();
        const auto* old = Connection(Process(after, oldPid), key);
        const auto* current = Connection(Process(after, currentPid), key);
        Check(old && old->generation == oldGeneration && old->endReceived && old->retired &&
              old->removeAfter == oldDeadline && old->driver && old->driver->frozenSent == 10 &&
              old->driver->frozenRecv == 4,
              "stale END changed closed history or restarted its grace period");
        Check(current && current->generation == currentGeneration && !current->endReceived &&
              !current->removeAfter && current->driver && current->driver->sent == 3 &&
              current->driver->recv == 2 && !current->driver->frozenCountersKnown,
              "stale END changed the new generation or its counters");

        EndDriverFlow(key, currentPid, Dir::In);
        Check(store.ResolveEventOwner(0, key) == 0,
              "matching END did not invalidate the new generation's owner");
    }
}

void TestEndSelectsRetiredGeneration() {
    FlowStore& store = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    const DWORD oldPid = currentPid + 4;
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() })
    for (bool explicitGeneration : { false, true }) {
        store.Reset();
        OpenDriverFlow(key, oldPid, Dir::In);
        store.AddBandwidth(key, 10, 4);
        FlowStore::ConnEvent blocked = Event(oldPid);
        blocked.dir = Dir::In;
        store.NoteBlocked(key, blocked);
        const auto original = Take();
        const uint64_t oldGeneration = Connection(Process(original, oldPid), key)->generation;
        OpenDriverFlow(key, currentPid, Dir::In);
        store.AddBandwidth(key, 3, 2);

        // Старое поколение ещё не получало END. Явный generation достаточен и без PID.
        if (explicitGeneration) store.CloseFlow(key, 0, Dir::In, oldGeneration);
        else EndDriverFlow(key, oldPid, Dir::In);
        Check(store.ResolveEventOwner(0, key) == currentPid,
              "historical END invalidated the current generation");
        const auto after = Take();
        const auto* old = Connection(Process(after, oldPid), key);
        const auto* current = Connection(Process(after, currentPid), key);
        Check(old && old->generation == oldGeneration && old->endReceived && old->retired &&
              old->removeAfter && !old->blockedAt && old->driver && old->driver->frozenSent == 10,
              "END did not close the matching retired generation");
        Check(current && current->generation != oldGeneration && !current->endReceived &&
              !current->removeAfter && current->driver && current->driver->sent == 3,
              "historical END changed the current generation or its counters");
    }
}

void TestSystemEndKeepsOtherOwner() {
    FlowStore& store = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        OpenDriverFlow(key, currentPid, Dir::In);
        OpenDriverFlow(key, 4, Dir::In);
        EndDriverFlow(key, 4, Dir::In);
        Check(store.ResolveEventOwner(0, key) == currentPid,
              "PID 4 END invalidated another confirmed owner");
        const auto view = Take();
        const auto* current = Connection(Process(view, currentPid), key);
        const auto* system = Connection(Process(view, 4), key);
        Check(current && !current->endReceived && !current->removeAfter &&
              system && system->endReceived && system->removeAfter,
              "PID 4 END did not select its own connection history");

        // У самостоятельной строки PID 4 индекс намеренно сохраняет PID 0.
        for (DWORD reportedPid : { DWORD{ 0 }, DWORD{ 4 } }) {
            store.Reset();
            OpenDriverFlow(key, 4, Dir::In);
            EndDriverFlow(key, currentPid, Dir::In);
            const auto stillOpen = Take();
            system = Connection(Process(stillOpen, 4), key);
            Check(system && !system->endReceived && !system->removeAfter,
                  "foreign END closed a PID 4 connection through its PID 0 index");
            EndDriverFlow(key, reportedPid, Dir::In);
            const auto ended = Take();
            system = Connection(Process(ended, 4), key);
            Check(system && system->endReceived && system->removeAfter,
                  "END could not close PID 4 through an index with PID 0");
        }
    }
}

void TestServiceEndKeepsReportedPid() {
    FlowStore& store = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    store.Enable(false);
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        store.AssignReportedOwner(key, currentPid);
        for (DWORD oldPid : { currentPid + 4, DWORD{ 4 } }) {
            EndDriverFlow(key, oldPid, Dir::In);
            Check(store.ResolveEventOwner(0, key) == currentPid,
                  "foreign service END invalidated a generationless owner index");
        }
        EndDriverFlow(key, currentPid, Dir::In);
        Check(store.ResolveEventOwner(0, key) == 0,
              "matching service END did not invalidate its owner");
        store.AssignReportedOwner(key, currentPid);
        EndDriverFlow(key, 0, Dir::In);
        Check(store.ResolveEventOwner(0, key) == 0,
              "service END without PID did not use the confirmed owner");
    }
    store.Enable(true);
}

void TestTupleReuseKeepsMarkedGeneration() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Tcp4(45500);

    OpenDriverFlow(key, 0);
    store.AddBandwidth(key, 10, 4);
    store.CloseFlow(key, 0, Dir::Out);
    FlowStore::View view = Take();
    const FlowStore::ConnectionRecord* oldConnection =
        Connection(Process(view, 0), key);
    Check(oldConnection && oldConnection->removeAfter,
          "old tuple generation was not marked");
    const uint64_t oldGeneration = oldConnection->generation;

    OpenDriverFlow(key, 0);
    store.AddBandwidth(key, 3, 2);
    view = Take();
    const auto& process = Process(view, 0);
    const FlowStore::ConnectionRecord* newConnection = Connection(process, key);
    Check(newConnection && newConnection->generation != oldGeneration,
          "reused tuple kept the old generation");
    Check(process.connections.size() == 2,
          "reused tuple removed z1 before the grace period");
    Check(process.driverTraffic.tcpV4.size() == 2,
          "reused tuple removed y1 before the grace period");

    const auto oldTraffic = process.driverTraffic.tcpV4.find(
        FlowId{ key, oldGeneration });
    const auto newTraffic = process.driverTraffic.tcpV4.find(
        FlowId{ key, newConnection->generation });
    Check(oldTraffic != process.driverTraffic.tcpV4.end() &&
          oldTraffic->second.removeAfter && oldTraffic->second.sent == 10,
          "old marked y1 generation was changed by tuple reuse");
    Check(newTraffic != process.driverTraffic.tcpV4.end() &&
          !newTraffic->second.removeAfter && newTraffic->second.sent == 3,
          "new y1 generation inherited old removal state");
}

void TestFirstInboundOwnerKeepsExactAndEndPriority() {
    FlowStore& store = FlowStore::Instance();
    const DWORD socketPid = GetCurrentProcessId();
    const DWORD exactPid = socketPid + 4;
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        FlowStore::SystemSnapshot snapshot;
        const bool ipv6 = key.local.family == AF_INET6;
        if (key.proto == Proto::Tcp) {
            IpAddr any{};
            any.family = key.local.family;
            FlowStore::SystemTcpConnection row;
            row.key = MakeFlowKey(key.proto, key.local, any, key.lport, 0);
            row.pid = socketPid;
            row.state = MIB_TCP_STATE_LISTEN;
            (ipv6 ? snapshot.tcpV6 : snapshot.tcpV4).push_back(row);
            (ipv6 ? snapshot.tcpV6Valid : snapshot.tcpV4Valid) = true;
        } else {
            (ipv6 ? snapshot.udpV6 : snapshot.udpV4).push_back({ key.local, key.lport, socketPid });
            (ipv6 ? snapshot.udpV6Valid : snapshot.udpV4Valid) = true;
        }
        store.ReplaceSystemSnapshot(snapshot);

        bool found = true;
        bool ambiguous = true;
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::Out) == 0 &&
              !found && !ambiguous,
              "outbound event inherited a listener or unrelated local socket owner");
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous) == 0 && !found && !ambiguous,
              "unknown direction enabled the inbound socket fallback");
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == socketPid &&
              found && !ambiguous,
              "first inbound event lost the known local socket owner");
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous) == 0 && !found && !ambiguous,
              "socket lookup created an unconfirmed exact tuple");
        FlowKey other = key;
        ++other.lport;
        Check(store.ResolveEventOwner(0, other, &found, &ambiguous, Dir::In) == 0 &&
              !found && !ambiguous, "socket fallback matched a different local port");
        other = key;
        other.local.b[other.local.len() - 1] ^= 1;
        Check(store.ResolveEventOwner(0, other, &found, &ambiguous, Dir::In) == 0 &&
              !found && !ambiguous, "socket fallback matched a different bound address");
        for (DWORD reportedPid : { exactPid, DWORD{4} })
            Check(store.ResolveEventOwner(reportedPid, key, &found, &ambiguous, Dir::In) ==
                      reportedPid && found && !ambiguous,
                  "local socket overrode the nonzero driver PID");

        // Локальный сокет не заменяет точного либо неоднозначного владельца tuple.
        OpenDriverFlow(key, exactPid, Dir::In);
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == exactPid &&
              found && !ambiguous, "local socket overrode an existing exact owner");
        FlowStore::ConnEvent event = Event(0);
        event.dir = Dir::In;
        event.ownerAmbiguous = true;
        store.NoteConnection(key, event);
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == 0 &&
              found && ambiguous, "local socket cleared an existing exact owner conflict");

        event.pid = exactPid;
        event.ownerAmbiguous = false;
        store.NoteConnection(key, event);
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == exactPid &&
              found && !ambiguous, "precise event PID did not resolve the owner conflict");

        // Даже известный сокет не подтверждает владельца завершённого поколения.
        store.CloseFlow(key, exactPid, Dir::In);
        Check(store.ResolveLocalEndpoint(key.proto, key.local, key.lport) == socketPid,
              "test lost the local socket after END");
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == 0 &&
              !found && !ambiguous, "socket fallback revived an ended exact tuple");
        event.pid = 0;
        store.NoteConnection(key, event);
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == 0 &&
              found && !ambiguous, "old socket snapshot assigned the reopened unknown tuple");
        store.Reset();
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous, Dir::In) == 0 &&
              !found && !ambiguous, "reset left a stale local socket fallback");
    }
}

void TestEndedOwnerDoesNotFollowUnknownGeneration() {
    FlowStore& store = FlowStore::Instance();
    const DWORD originalPid = GetCurrentProcessId();
    const FlowKey keys[] = { Tcp4(), Tcp6(), Udp4(), Udp6() };
    for (const FlowKey& key : keys) {
        store.Reset();
        OpenDriverFlow(key, originalPid);
        store.AddBandwidth(key, 10, 4);
        const auto originalView = Take();
        const uint64_t originalGeneration =
            Connection(Process(originalView, originalPid), key)->generation;
        Check(store.ResolveEventOwner(0, key) == originalPid,
              "active exact tuple lost its confirmed owner");

        store.CloseFlow(key, originalPid, Dir::Out);
        bool found = true;
        bool ambiguous = true;
        Check(store.ResolveEventOwner(0, key, &found, &ambiguous) == 0 &&
              !found && !ambiguous,
              "ended tuple supplied its old owner to a new event");
        Check(store.ResolveEventOwner(4, key) == 4,
              "ended tuple overrode the nonzero PID of a new event");

        // Новое событие без PID не должно снова активировать старого владельца.
        OpenDriverFlow(key, 0);
        store.AddBandwidth(key, 3, 2);
        Check(store.ResolveEventOwner(0, key) == 0,
              "new unknown generation inherited the old owner after publication");
        const auto view = Take();
        const auto& original = Process(view, originalPid);
        const auto previous = original.connections.find(originalGeneration);
        const auto* current = Connection(Process(view, 0), key);
        Check(previous != original.connections.end() && previous->second.retired &&
              previous->second.endReceived && previous->second.removeAfter &&
              previous->second.driver && previous->second.driver->sent == 10 &&
              previous->second.driver->recv == 4,
              "unknown tuple reuse moved or changed the closed generation");
        Check(current && current->generation != originalGeneration &&
              !current->endReceived && !current->removeAfter &&
              current->driver && current->driver->sent == 3 && current->driver->recv == 2,
              "unknown tuple reuse mixed generations or counters");
    }
}

void TestBlockedReuseDoesNotInheritEndedOwner() {
    FlowStore& store = FlowStore::Instance();
    const DWORD originalPid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        OpenDriverFlow(key, originalPid);
        store.AddBandwidth(key, 10, 4);
        store.CloseFlow(key, originalPid, Dir::Out);

        // Fire pending-ответа может публиковать блокировку без NoteConnection.
        FlowStore::ConnEvent blocked = Event(0);
        blocked.dir = Dir::In;
        store.NoteBlocked(key, blocked);
        const auto view = Take();
        const auto* previous = Connection(Process(view, originalPid), key);
        const auto* current = Connection(Process(view, 0), key);
        Check(previous && previous->endReceived && previous->retired &&
              previous->driver && previous->driver->sent == 10 &&
              current && current->generation != previous->generation && current->blockedAt,
              "blocked unknown generation inherited or moved the closed owner");
        Check(store.ResolveEventOwner(0, key) == 0,
              "blocked generation supplied an old owner to a new event");
    }
}

void TestBlockedOwnerRemainsConfirmedUntilEnd() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        OpenDriverFlow(key, pid, Dir::In);
        FlowStore::ConnEvent blocked = Event(pid);
        blocked.dir = Dir::In;
        store.NoteBlocked(key, blocked);
        Check(store.ResolveEventOwner(0, key) == pid,
              "temporary block invalidated the confirmed owner before END");

        OpenDriverFlow(key, 0, Dir::In);
        Check(store.ResolveEventOwner(0, key) == pid,
              "repeated attempt lost the confirmed owner of a blocked tuple");
        store.CloseFlow(key, pid, Dir::In);
        Check(store.ResolveEventOwner(0, key) == 0,
              "actual END did not invalidate the blocked tuple owner");
    }
}

void TestAmbiguousOwnerSurvivesEventPublications() {
    FlowStore& store = FlowStore::Instance();
    const DWORD confirmedPid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        for (auto publish : {
            +[](FlowStore& target, const FlowKey& key, const FlowStore::ConnEvent& event) {
                target.NoteConnection(key, event);
            },
            +[](FlowStore& target, const FlowKey& key, const FlowStore::ConnEvent& event) {
                target.NoteAllowed(key, event);
            },
            +[](FlowStore& target, const FlowKey& key, const FlowStore::ConnEvent& event) {
                target.NoteBlocked(key, event);
            } }) {
            store.Reset();
            FlowStore::ConnEvent event = Event(0);
            event.dir = Dir::In;
            event.ownerAmbiguous = true;
            publish(store, key, event);

            const auto checkAmbiguous = [&]() {
                bool found = false;
                bool ambiguous = false;
                Check(store.ResolveEventOwner(0, key, &found, &ambiguous) == 0 &&
                      found && ambiguous,
                      "event publication lost ambiguous ownership in the index");
                const auto view = Take();
                const auto* connection = Connection(Process(view, 0), key);
                Check(connection && connection->ownerAmbiguous,
                      "event publication lost ambiguous ownership in the connection");
                FlowStore::DisplayView summary;
                store.TakeDisplay(summary, FlowStore::kInactiveMs, false, false);
                Check(DisplayProcess(summary, 0).ownerAmbiguous,
                      "tray summary lost ambiguous process ownership");
            };
            checkAmbiguous();

            // Событие без нового подтверждения PID не снимает прежний конфликт.
            event.ownerAmbiguous = false;
            publish(store, key, event);
            checkAmbiguous();
            store.AddBandwidth(key, 1, 2);
            checkAmbiguous();

            event.pid = confirmedPid;
            publish(store, key, event);
            bool ambiguous = true;
            Check(store.ResolveEventOwner(0, key, nullptr, &ambiguous) == confirmedPid &&
                  !ambiguous,
                  "confirmed event PID did not clear ambiguous ownership");
            const auto view = Take();
            const auto* connection = Connection(Process(view, confirmedPid), key);
            Check(connection && !connection->ownerAmbiguous,
                  "confirmed event PID left the connection ambiguous");
        }
    }
}

void TestSystemSnapshotResolvesAmbiguousOwner() {
    FlowStore& store = FlowStore::Instance();
    const DWORD confirmedPid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        FlowStore::ConnEvent event = Event(0);
        event.dir = Dir::In;
        store.NoteConnection(key, event);

        FlowStore::SystemSnapshot snapshot;
        if (key.proto == Proto::Tcp) {
            auto& rows = key.local.family == AF_INET ? snapshot.tcpV4 : snapshot.tcpV6;
            (key.local.family == AF_INET ? snapshot.tcpV4Valid : snapshot.tcpV6Valid) = true;
            FlowStore::SystemTcpConnection row;
            row.key = key;
            row.pid = confirmedPid;
            row.state = MIB_TCP_STATE_ESTAB;
            rows.push_back(row);
            row.pid += 4;
            rows.push_back(row);
        } else {
            auto& rows = key.local.family == AF_INET ? snapshot.udpV4 : snapshot.udpV6;
            (key.local.family == AF_INET ? snapshot.udpV4Valid : snapshot.udpV6Valid) = true;
            rows.push_back({ key.local, key.lport, confirmedPid });
            rows.push_back({ key.local, key.lport, confirmedPid + 4 });
        }
        store.ReplaceSystemSnapshot(snapshot);
        bool ambiguous = false;
        Check(store.ResolveEventOwner(0, key, nullptr, &ambiguous) == 0 && ambiguous,
              "conflicting system snapshot did not keep ambiguous ownership");

        store.NoteConnection(key, event);
        store.AddBandwidth(key, 3, 2);
        Check(store.ResolveEventOwner(0, key, nullptr, &ambiguous) == 0 && ambiguous,
              "unknown event or bandwidth report cleared a system owner conflict");

        // Следующий снимок уже однозначно подтверждает владельца того же потока.
        if (key.proto == Proto::Tcp) {
            auto& rows = key.local.family == AF_INET ? snapshot.tcpV4 : snapshot.tcpV6;
            rows.resize(1);
        } else {
            auto& rows = key.local.family == AF_INET ? snapshot.udpV4 : snapshot.udpV6;
            rows.resize(1);
        }
        store.ReplaceSystemSnapshot(snapshot);
        Check(store.ResolveEventOwner(0, key, nullptr, &ambiguous) == confirmedPid &&
              !ambiguous,
              "unambiguous system snapshot did not confirm the current owner");
        const auto view = Take();
        const auto* connection = Connection(Process(view, confirmedPid), key);
        Check(connection && !connection->ownerAmbiguous && connection->driver &&
              connection->driver->sent == 3 && connection->driver->recv == 2,
              "owner confirmation lost counters or left the connection ambiguous");
    }
}

void TestAmbiguousBandwidthCannotConfirmOwner() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    for (const FlowKey& key : { Udp4(), Udp6() }) {
        store.Reset();
        FlowStore::SystemSnapshot snapshot;
        auto& rows = key.local.family == AF_INET ? snapshot.udpV4 : snapshot.udpV6;
        (key.local.family == AF_INET ? snapshot.udpV4Valid : snapshot.udpV6Valid) = true;
        rows.push_back({ key.local, key.lport, pid });
        rows.push_back({ key.local, key.lport, pid + 4 });
        store.ReplaceSystemSnapshot(snapshot);

        // Первый exact tuple создан bandwidth-отчётом, в котором PID отсутствует.
        store.AddBandwidth(key, 3, 2);
        bool ambiguous = false;
        Check(store.ResolveEventOwner(0, key, nullptr, &ambiguous) == 0 && ambiguous,
              "first bandwidth report lost the ambiguous socket owner");
        const auto view = Take();
        const auto* connection = Connection(Process(view, 0), key);
        Check(connection && connection->ownerAmbiguous && connection->driver &&
              connection->driver->sent == 3 && connection->driver->recv == 2,
              "first bandwidth report lost counters or ambiguous ownership");
    }
}

void TestServiceReportedOwnerReopensExactTuple() {
    FlowStore& store = FlowStore::Instance();
    const DWORD originalPid = GetCurrentProcessId();
    store.Enable(false);
    for (const FlowKey& key : { Tcp4(), Tcp6(), Udp4(), Udp6() }) {
        store.Reset();
        store.AssignReportedOwner(key, originalPid);
        Check(store.ResolveEventOwner(0, key) == originalPid,
              "service mode lost the confirmed current owner");
        store.CloseFlow(key, originalPid, Dir::Out);
        Check(store.ResolveEventOwner(0, key) == 0,
              "service mode reused the owner of an ended tuple");

        // Повторный tuple может принадлежать как другому, так и тому же PID.
        for (DWORD reportedPid : { originalPid + 4, originalPid }) {
            store.AssignReportedOwner(key, reportedPid);
            Check(store.ResolveEventOwner(0, key) == reportedPid,
                  "fresh service event did not confirm the new tuple owner");
            store.CloseFlow(key, reportedPid, Dir::Out);
            Check(store.ResolveEventOwner(0, key) == 0,
                  "service END did not invalidate the reported owner");
        }
    }
    store.Enable(true);
}

PROCESS_INFORMATION StartDisposableProcess() {
    wchar_t command[] = L"ping.exe -n 30 127.0.0.1";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        L"C:\\Windows\\System32\\ping.exe", command,
        nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr, nullptr, &startup, &process);
    Check(created != FALSE, "failed to create disposable process");
    return process;
}

void TestFourSecondRemovalForEndAndDeadProcess() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    const FlowKey ended = Tcp4(46000);
    OpenDriverFlow(ended, 0);
    store.AddBandwidth(ended, 21, 12);
    store.CloseFlow(ended, 0, Dir::Out);

    PROCESS_INFORMATION child = StartDisposableProcess();
    const DWORD deadPid = child.dwProcessId;
    const FlowKey deadFlow = Tcp4(46001);
    const FlowKey hiddenFlow = Tcp4(46002);
    FlowStore::SystemSnapshot childSnapshot;
    childSnapshot.tcpV4Valid = true;
    FlowStore::SystemTcpConnection childConnection;
    childConnection.key = deadFlow;
    childConnection.pid = deadPid;
    childConnection.state = MIB_TCP_STATE_ESTAB;
    childSnapshot.tcpV4.push_back(childConnection);
    FlowStore::SystemTcpConnection hiddenConnection;
    hiddenConnection.key = hiddenFlow;
    hiddenConnection.pid = 4;
    hiddenConnection.state = MIB_TCP_STATE_CLOSE_WAIT;
    childSnapshot.tcpV4.push_back(hiddenConnection);
    store.ReplaceSystemSnapshot(childSnapshot);

    TerminateProcess(child.hProcess, 0);
    WaitForSingleObject(child.hProcess, INFINITE);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);

    // Monitor сначала публикует уже пустую таблицу ОС и лишь затем проверяет
    // процессы. System-only строка обязана пережить этот порядок вызовов.
    FlowStore::SystemSnapshot afterExit;
    afterExit.tcpV4Valid = true;
    store.ReplaceSystemSnapshot(afterExit);

    FlowStore::View view = Take();
    const auto* endingConnection = Connection(Process(view, 0), ended);
    const auto* endingTraffic = DriverTraffic(Process(view, 0), ended);
    Check(endingConnection && endingConnection->removeAfter,
          "connection END did not mark z1 for removal");
    Check(endingTraffic && endingTraffic->removeAfter,
          "connection END did not mark y1 for removal");
    const auto dead = view.processes.find(deadPid);
    Check(dead != view.processes.end() && dead->second.removeAfter,
          "dead process was not marked for removal");
    const auto* hidden = Connection(Process(view, 4), hiddenFlow);
    Check(hidden && hidden->removeAfter,
          "hidden system connection was removed before its grace period");

    ::Sleep(static_cast<DWORD>(kFinishedGraceMs + 150));
    FlowStore::DisplayView summary;
    store.TakeDisplay(summary, FlowStore::kInactiveMs, false, false);
    Check(summary.processes.empty() && summary.flowCount == 0 &&
          summary.removedConnections >= 3,
          "tray summary did not remove ended, hidden connections or dead processes");
    view = Take();
    const auto pid0 = view.processes.find(0);
    Check(pid0 == view.processes.end() ||
          Connection(pid0->second, ended) == nullptr,
          "ended connection survived the four-second grace period");
    Check(view.processes.count(deadPid) == 0,
          "dead process survived the four-second grace period");
    const auto pid4 = view.processes.find(4);
    Check(pid4 == view.processes.end() ||
          Connection(pid4->second, hiddenFlow) == nullptr,
          "hidden system connection survived the four-second grace period");
}

void TestDisplayViewSelectsCounters() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Tcp4(46500);
    OpenDriverFlow(key, 1700);
    store.AddBandwidth(key, 13, 7);

    FlowStore::DisplayView display;
    store.TakeDisplay(display);
    Check(display.flowCount == 1, "display view has a wrong flow count");
    const auto* driver = DisplayConnection(DisplayProcess(display, 1700), key);
    Check(driver && driver->bytesFrom == BytesDriver &&
          driver->sent == 13 && driver->recv == 7 &&
          driver->periodSent == 13 && driver->periodRecv == 7,
          "display view did not select driver counters");

    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    FlowStore::SystemTcpConnection row;
    row.key = key;
    row.pid = 1700;
    row.state = MIB_TCP_STATE_ESTAB;
    row.sent = 101;
    row.recv = 55;
    row.countersAt = 1000;
    row.countersRead = true;
    snapshot.tcpV4.push_back(row);
    store.ReplaceSystemSnapshot(snapshot);
    store.TakeDisplay(display);

    const auto* system = DisplayConnection(DisplayProcess(display, 1700), key);
    Check(system && system->bytesFrom == BytesEstats &&
          system->sent == 101 && system->recv == 55 &&
          system->periodSent == 0 && system->periodRecv == 0,
          "display view did not select system counters");

    snapshot.tcpV4[0].sent = 121;
    snapshot.tcpV4[0].recv = 65;
    snapshot.tcpV4[0].countersAt = 2000;
    store.ReplaceSystemSnapshot(snapshot);
    store.TakeDisplay(display);
    system = DisplayConnection(DisplayProcess(display, 1700), key);
    Check(system && system->periodSent == 20 && system->periodRecv == 10,
          "system counter delta was not kept in the connection record");
}

void TestDisplayCleanupKeepsSourcesAndFilters() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    for (bool showPassive : { false, true })
    for (bool includeConnections : { false, true }) {
        store.Reset();
        const FlowKey expired[] = {
            Tcp4(46700), Tcp6(46701), Udp4(53700), Udp6(53701)
        };
        for (const FlowKey& key : expired) {
            OpenDriverFlow(key, 0);
            store.AddBandwidth(key, 100, 50);
        }

        FlowStore::SystemSnapshot snapshot;
        snapshot.tcpV4Valid = true;
        snapshot.tcpV6Valid = true;
        const FlowKey protectedKeys[] = { Tcp4(46702), Tcp6(46703) };
        const FlowKey systemKeys[] = { Tcp4(46704), Tcp6(46705) };
        for (size_t index = 0; index < std::size(protectedKeys); ++index) {
            const FlowKey& key = protectedKeys[index];
            OpenDriverFlow(key, pid);
            store.AddBandwidth(key, 17, 9);

            auto& rows = key.local.family == AF_INET
                ? snapshot.tcpV4 : snapshot.tcpV6;
            FlowStore::SystemTcpConnection listener;
            listener.key = key;
            listener.key.local = IpAddr{};
            listener.key.local.family = key.local.family;
            listener.key.remote = listener.key.local;
            listener.key.rport = 0;
            listener.pid = pid;
            listener.state = MIB_TCP_STATE_LISTEN;
            rows.push_back(listener);

            FlowStore::SystemTcpConnection system;
            system.key = systemKeys[index];
            system.pid = pid;
            system.state = MIB_TCP_STATE_ESTAB;
            system.sent = 100;
            system.recv = 50;
            system.countersAt = 1000;
            system.countersRead = true;
            rows.push_back(system);
        }
        store.ReplaceSystemSnapshot(snapshot);
        for (auto* rows : { &snapshot.tcpV4, &snapshot.tcpV6 }) {
            rows->back().sent = 130;
            rows->back().recv = 65;
            rows->back().countersAt = 2000;
        }
        store.ReplaceSystemSnapshot(snapshot);

        const FlowKey other = MakeFlowKey(
            Proto::Icmp, V4(10, 0, 0, 2), V4(10, 0, 0, 3), 0, 0);
        FlowStore::ConnEvent packet = Event(pid);
        packet.bytes = 84;
        packet.icmpType = 8;
        store.NoteConnection(other, packet);

        // Короткий TCP/UDP TTL не меняет срок других протоколов и не снимает
        // защиту listener. Удаление должно предшествовать обоим фильтрам UI.
        ::Sleep(20);
        FlowStore::DisplayView display;
        store.TakeDisplay(display, 0, showPassive, includeConnections);
        Check(display.flowCount == 7 && display.hiddenCount == 2 &&
              display.driverOnlyFlows == 3 && display.removedConnections == 4 &&
              display.processes.size() == 1,
              "display cleanup changed counts or retained expired connections");
        const auto& process = DisplayProcess(display, pid);
        Check(process.connCount == (showPassive ? 7u : 5u),
              "display cleanup changed passive filtering");
        if (!includeConnections) {
            Check(process.connections.empty() && process.speed == 0.0,
                  "summary cleanup copied rows or calculated speed");
        } else {
            for (const FlowKey& key : protectedKeys) {
                const auto* connection = DisplayConnection(process, key);
                Check(connection && connection->bytesFrom == BytesDriver &&
                      connection->sent == 17 && connection->recv == 9 &&
                      connection->periodSent == 17 && connection->periodRecv == 9,
                      "display cleanup reset listener-protected traffic");
            }
            for (const FlowKey& key : systemKeys) {
                const auto* connection = DisplayConnection(process, key);
                Check(connection && connection->bytesFrom == BytesEstats &&
                      connection->sent == 130 && connection->recv == 65 &&
                      connection->periodSent == 30 && connection->periodRecv == 15 &&
                      connection->period.elapsedMs() == 1000 &&
                      connection->bytesPerSecond() == 45.0,
                      "display cleanup changed EStats totals, deltas or timing");
            }
            const auto* connection = DisplayConnection(process, other);
            Check(connection && connection->sent == 84 && connection->pktSent == 1,
                  "TCP/UDP cleanup expired another protocol or lost its traffic");
        }

        const auto full = Take(0);
        Check(full.removedConnections == 0 && full.processes.count(0) == 0 &&
              Process(full, pid).connections.size() == 7,
              "display cleanup left expired connections or their empty process");
        for (const FlowKey& key : expired) {
            const auto& owners = key.proto == Proto::Tcp
                ? (key.local.family == AF_INET
                    ? full.ownerIndexes.tcpV4 : full.ownerIndexes.tcpV6)
                : (key.local.family == AF_INET
                    ? full.ownerIndexes.udpV4 : full.ownerIndexes.udpV6);
            Check(owners.count(key) == 0,
                  "display cleanup left an expired owner in an index");
        }
    }
}

void TestDisplayExcludesExpiredListenerOwner() {
    FlowStore& store = FlowStore::Instance();
    const DWORD pid = GetCurrentProcessId();
    for (const FlowKey& key : { Tcp4(46706), Tcp6(46707) })
    for (bool blocked : { false, true }) {
        store.Reset();
        FlowStore::ConnEvent event = Event(pid);
        event.dir = Dir::Unknown;
        const uint64_t generation = store.NoteConnection(key, event);
        store.NoteAllowed(key, event, generation);
        store.AddBandwidth(key, 17, 9);

        FlowStore::SystemSnapshot snapshot;
        snapshot.tcpV4Valid = key.local.family == AF_INET;
        snapshot.tcpV6Valid = key.local.family == AF_INET6;
        auto& rows = snapshot.tcpV4Valid ? snapshot.tcpV4 : snapshot.tcpV6;
        FlowStore::SystemTcpConnection row;
        row.key = key;
        row.pid = pid;
        row.state = MIB_TCP_STATE_ESTAB;
        rows.push_back(row);
        row.key.local = IpAddr{};
        row.key.local.family = key.local.family;
        row.key.remote = row.key.local;
        row.key.rport = 0;
        row.state = MIB_TCP_STATE_LISTEN;
        rows.push_back(row);
        store.ReplaceSystemSnapshot(snapshot);

        if (blocked) store.NoteBlocked(key, event, generation);
        else store.CloseFlow(key, pid, Dir::Unknown, generation);

        // Строка ещё подтверждается ОС и находится в четырёхсекундном окне,
        // но история завершённого владельца уже истекла по короткому TTL.
        ::Sleep(20);
        FlowStore::DisplayView display;
        store.TakeDisplay(display, 0, false);
        const auto* connection = DisplayConnection(DisplayProcess(display, pid), key);
        Check(connection && connection->dir == Dir::Unknown &&
              !connection->localListener && connection->flowGeneration == generation &&
              connection->bytesFrom == BytesDriver &&
              connection->sent == 17 && connection->recv == 9 &&
              connection->removeAfter && (connection->blockedAt != 0) == blocked &&
              display.removedConnections == 0,
              "display cleanup changed a retained flow or exposed an expired owner");
        const auto full = Take(0);
        const auto& owners = snapshot.tcpV4Valid
            ? full.ownerIndexes.tcpV4 : full.ownerIndexes.tcpV6;
        Check(owners.count(key) == 0 &&
              Connection(Process(full, pid), key) != nullptr,
              "owner expiration changed the connection grace period");
    }
}

void TestSummaryKeepsConnectionFacts() {
    FlowStore& store = FlowStore::Instance();
    for (const FlowKey& key : { Tcp4(46510), Tcp6(46511), Udp4(53510), Udp6(53511) }) {
        store.Reset();
        FlowStore::DisplayView display;
        FlowStore::ConnEvent event = Event(0);
        event.dir = Dir::In;
        event.ownerAmbiguous = true;
        const uint64_t original = store.NoteConnection(key, event);
        store.NoteAllowed(key, event, original);
        store.AddBandwidth(key, 123, 456);
        store.TakeDisplay(display, FlowStore::kInactiveMs, true, false);

        // Подпись появляется уже в трее, когда ни одной полной копии строки нет.
        event.tlsDomainLabel = std::make_shared<const std::wstring>(L"[hidden-domain.example]");
        const std::weak_ptr<const std::wstring> label = event.tlsDomainLabel;
        store.NoteAllowed(key, event, original);
        event.tlsDomainLabel.reset();
        for (int pass = 0; pass < 3; ++pass) {
            store.TakeDisplay(display, FlowStore::kInactiveMs, true, false);
            const auto& process = DisplayProcess(display, 0);
            Check(display.connections.empty() && process.connections.empty() &&
                  process.connCount == 1 && process.ownerAmbiguous && !label.expired(),
                  "tray summary lost connection facts or copied full rows");
        }

        // END и повторный tuple в трее должны оставить два независимых поколения.
        EndDriverFlow(key, 0, Dir::In);
        FlowStore::ConnEvent next = Event(0);
        next.tlsDomainLabel = std::make_shared<const std::wstring>(L"[new-domain.example]");
        const uint64_t replacement = store.NoteConnection(key, next);
        store.NoteAllowed(key, next, replacement);
        store.AddBandwidth(key, 7, 9);
        FlowKey blockedKey = key;
        ++blockedKey.lport;
        FlowStore::ConnEvent blocked = Event(0);
        blocked.dir = Dir::In;
        const uint64_t blockedGeneration = store.NoteConnection(blockedKey, blocked);
        store.NoteBlocked(blockedKey, blocked, blockedGeneration);
        store.TakeDisplay(display, FlowStore::kInactiveMs, true, false);
        Check(display.connections.empty() && DisplayProcess(display, 0).connCount == 3,
              "tray summary dropped an ended, replacement or blocked connection");

        store.TakeDisplay(display, FlowStore::kInactiveMs, true);
        const auto& process = DisplayProcess(display, 0);
        const auto byGeneration = [&](uint64_t generation)
            -> const FlowStore::DisplayConnection* {
            for (const auto& connection : process.connections)
                if (connection.flowGeneration == generation) return &connection;
            return nullptr;
        };
        const auto* ended = byGeneration(original);
        const auto* current = byGeneration(replacement);
        const auto* denied = byGeneration(blockedGeneration);
        Check(original && replacement != original && ended && current && denied &&
              process.connections.size() == 3,
              "restored display lost connection generations created in the tray");
        Check(ended->key == key && ended->dir == Dir::In && ended->ownerAmbiguous &&
              ended->removeAfter && !ended->blockedAt && ended->lastActivity &&
              ended->sent == 123 && ended->recv == 456 && ended->driverEvents == 1 &&
              ended->tlsDomainLabel && *ended->tlsDomainLabel == L"[hidden-domain.example]",
              "restored ended connection lost its owner, direction, traffic or domain");
        Check(current->key == key && current->dir == Dir::Out && !current->removeAfter &&
              !current->blockedAt && current->sent == 7 && current->recv == 9 &&
              current->tlsDomainLabel && *current->tlsDomainLabel == L"[new-domain.example]",
              "tuple reuse in the tray mixed old and new connection facts");
        Check(denied->key == blockedKey && denied->dir == Dir::In &&
              denied->blockedAt && denied->removeAfter,
              "restored display lost the blocked state recorded in the tray");
    }

    for (bool ipv6 : { false, true }) {
        store.Reset();
        const FlowKey key = ipv6
            ? MakeFlowKey(Proto::IcmpV6, V6(2), V6(3), 0, 0)
            : MakeFlowKey(Proto::Icmp, V4(10, 0, 0, 2), V4(10, 0, 0, 3), 0, 0);
        FlowStore::ConnEvent request = Event(0);
        request.icmpType = ipv6 ? 128 : 8;
        request.icmpCode = 0;
        request.bytes = 84;
        const uint64_t generation = store.NoteConnection(key, request);
        FlowStore::DisplayView display;
        store.TakeDisplay(display, FlowStore::kInactiveMs, true, false);
        FlowStore::ConnEvent reply = request;
        reply.dir = Dir::In;
        reply.icmpType = ipv6 ? 129 : 0;
        reply.bytes = 96;
        Check(store.NoteConnection(key, reply) == generation,
              "ICMP reply in the tray changed the connection generation");
        store.TakeDisplay(display, FlowStore::kInactiveMs, true, false);
        store.TakeDisplay(display, FlowStore::kInactiveMs, true);
        const auto* connection = DisplayConnection(DisplayProcess(display, 0), key);
        Check(connection && connection->flowGeneration == generation &&
              connection->bytesFrom == BytesDriver && connection->sent == 84 &&
              connection->recv == 96 && connection->pktSent == 1 && connection->pktRecv == 1 &&
              connection->driverEvents == 2 && connection->icmpOut.type == request.icmpType &&
              connection->icmpIn.type == reply.icmpType && connection->icmpOut.code == 0 &&
              connection->icmpIn.code == 0 && connection->icmpOut.v6 == ipv6 &&
              connection->icmpIn.v6 == ipv6,
              "restored ICMP display lost packet counts, bytes, direction or types");
    }
}

void TestSummaryKeepsCountersAndSampling() {
    FlowStore& store = FlowStore::Instance();
    const auto testDriver = [&](const FlowKey& key, auto& entry) {
        store.Reset();
        OpenDriverFlow(key, 0);
        std::memcpy(entry.local_ip, key.local.b, sizeof(entry.local_ip));
        std::memcpy(entry.remote_ip, key.remote.b, sizeof(entry.remote_ip));
        entry.local_port = key.lport;
        entry.remote_port = key.rport;
        entry.transmitted_bytes = 10;
        entry.received_bytes = 20;
        FlowStore::DisplayView display;
        for (ULONGLONG tick = 1000; tick <= 4000; tick += 1000) {
            store.BeginBandwidthPoll(tick);
            store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 1);
            store.TakeDisplay(display, FlowStore::kInactiveMs, false, tick == 4000);
            const auto& process = DisplayProcess(display, 0);
            Check(process.connCount == 1 && !process.ownerAmbiguous,
                  "tray summary changed connection count or owner ambiguity");
            if (tick != 4000) {
                Check(process.connections.empty() && process.speed == 0.0,
                      "tray summary copied connections or calculated process speed");
            } else {
                const auto* connection = DisplayConnection(process, key);
                Check(connection && connection->sent == 40 && connection->recv == 80 &&
                      connection->periodSent == 10 && connection->periodRecv == 20 &&
                      connection->period.elapsedMs() == 1000 &&
                      connection->bytesPerSecond() == 30.0 && process.speed == 30.0,
                      "restored driver display lost totals or accumulated hidden periods");
            }
        }
    };
    for (const FlowKey& key : { Tcp4(46501), Udp4(46502) }) {
        pmkext::BandwidthValueV4 entry{};
        testDriver(key, entry);
    }
    for (const FlowKey& key : { Tcp6(46501), Udp6(46502) }) {
        pmkext::BandwidthValueV6 entry{};
        testDriver(key, entry);
    }

    for (bool ipv6 : { false, true }) {
        store.Reset();
        const FlowKey key = ipv6 ? Tcp6(46503) : Tcp4(46503);
        FlowStore::SystemSnapshot snapshot;
        snapshot.tcpV4Valid = !ipv6;
        snapshot.tcpV6Valid = ipv6;
        auto& rows = ipv6 ? snapshot.tcpV6 : snapshot.tcpV4;
        rows.emplace_back();
        auto& row = rows.back();
        row.key = key;
        row.state = MIB_TCP_STATE_ESTAB;
        row.countersRead = true;
        FlowStore::DisplayView display;
        for (ULONGLONG tick = 1000; tick <= 4000; tick += 1000) {
            row.countersAt = tick;
            row.sent = tick / 10;
            row.recv = tick / 5;
            store.ReplaceSystemSnapshot(snapshot);
            store.TakeDisplay(display, FlowStore::kInactiveMs, false, tick == 4000);
            const auto& process = DisplayProcess(display, 0);
            if (tick != 4000) {
                Check(process.connections.empty() && process.speed == 0.0,
                      "tray summary copied EStats connections or calculated speed");
            } else {
                const auto* connection = DisplayConnection(process, key);
                Check(connection && connection->bytesFrom == BytesEstats &&
                      connection->sent == 400 && connection->recv == 800 &&
                      connection->periodSent == 100 && connection->periodRecv == 200 &&
                      connection->period.elapsedMs() == 1000 &&
                      connection->bytesPerSecond() == 300.0 && process.speed == 300.0,
                      "restored EStats display lost totals or accumulated hidden periods");
            }
        }
    }
}

void TestEstatsSpeedUsesSampleIntervals() {
    FlowStore& store = FlowStore::Instance();
    for (bool ipv6 : { false, true }) {
        store.Reset();
        const FlowKey key = ipv6 ? Tcp6(46510) : Tcp4(46510);
        FlowStore::SystemSnapshot snapshot;
        snapshot.tcpV4Valid = !ipv6;
        snapshot.tcpV6Valid = ipv6;
        auto& rows = ipv6 ? snapshot.tcpV6 : snapshot.tcpV4;
        rows.emplace_back();
        auto& row = rows.back();
        row.key = key;
        row.state = MIB_TCP_STATE_ESTAB;
        row.countersRead = true;
        row.countersAt = 1000;
        row.sent = 100;
        row.recv = 50;

        FlowStore::DisplayView display;
        const auto sample = [&]() {
            store.ReplaceSystemSnapshot(snapshot);
            store.TakeDisplay(display);
            const auto* connection = DisplayConnection(DisplayProcess(display, 0), key);
            Check(connection != nullptr, "EStats display connection is missing");
            return *connection;
        };
        Check(sample().bytesPerSecond() == 0.0,
              "first EStats sample invented a rate for historical traffic");

        row.countersAt = 2000;
        row.sent = 200;
        row.recv = 250;
        auto connection = sample();
        Check(connection.period.elapsedMs() == 1000 && connection.bytesPerSecond() == 300.0,
              "EStats rate did not use the counter sampling interval");

        store.TakeDisplay(display);
        Check(DisplayConnection(DisplayProcess(display, 0), key)->bytesPerSecond() == 0.0,
              "rapid display refresh counted the same EStats delta twice");

        row.countersAt = 3000;
        row.sent = row.recv = 0;
        row.countersRead = false;
        connection = sample();
        Check(connection.sent == 200 && connection.recv == 250 &&
              connection.bytesPerSecond() == 0.0,
              "failed EStats read changed counters or repeated a rate");

        row.countersAt = 5000;
        row.sent = 500;
        row.recv = 850;
        row.countersRead = true;
        connection = sample();
        Check(connection.period.elapsedMs() == 3000 && connection.periodSent == 300 &&
              connection.periodRecv == 600 && connection.bytesPerSecond() == 300.0,
              "EStats recovery compressed several seconds into one refresh");

        row.countersAt = 6000;
        Check(sample().bytesPerSecond() == 0.0,
              "unchanged EStats counters reported traffic");
        row.countersAt = 7000;
        row.sent = 600;
        row.recv = 1050;
        connection = sample();
        Check(connection.period.elapsedMs() == 1000 && connection.bytesPerSecond() == 300.0,
              "idle EStats sample did not advance the time baseline");

        row.countersAt = 8000;
        row.sent = row.recv = 0;
        connection = sample();
        Check(connection.bytesFrom == BytesEstats &&
              connection.bytesPerSecond() == 0.0,
              "reset EStats counters changed source or invented traffic");
        row.countersAt = 9000;
        row.sent = 10000;
        row.recv = 20000;
        Check(sample().bytesPerSecond() == 0.0,
              "first EStats sample after reset included historical traffic");
        row.countersAt = 10000;
        row.sent += 100;
        row.recv += 200;
        Check(sample().bytesPerSecond() == 300.0,
              "EStats rate did not resume after establishing a new baseline");
    }
}

void TestEstatsSpeedMergesUnreadSamples() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey key = Tcp4(46511);
    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    snapshot.tcpV4.emplace_back();
    auto& row = snapshot.tcpV4.back();
    row.key = key;
    row.state = MIB_TCP_STATE_ESTAB;
    row.countersRead = true;
    row.countersAt = 1000;
    row.sent = 100;
    row.recv = 50;
    store.ReplaceSystemSnapshot(snapshot);
    FlowStore::DisplayView display;
    store.TakeDisplay(display);

    row.countersAt = 2000;
    row.sent += 100;
    row.recv += 200;
    store.ReplaceSystemSnapshot(snapshot);
    row.countersAt = 4000;
    row.sent += 200;
    row.recv += 400;
    store.ReplaceSystemSnapshot(snapshot);
    store.TakeDisplay(display);
    const auto* connection = DisplayConnection(DisplayProcess(display, 0), key);
    Check(connection && connection->period.elapsedMs() == 3000 &&
          connection->periodSent == 300 && connection->periodRecv == 600 &&
          connection->bytesPerSecond() == 300.0,
          "unread EStats samples lost their complete sampling interval");
}

void TestBandwidthSpeedUsesReportIntervals() {
    FlowStore& store = FlowStore::Instance();
    const auto test = [&](auto& entry, const FlowKey& key) {
        store.Reset();
        OpenDriverFlow(key, 0);
        std::memcpy(entry.local_ip, key.local.b, sizeof(entry.local_ip));
        std::memcpy(entry.remote_ip, key.remote.b, sizeof(entry.remote_ip));
        entry.local_port = key.lport;
        entry.remote_port = key.rport;
        entry.transmitted_bytes = 10;
        entry.received_bytes = 20;
        store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 1);
        FlowStore::DisplayView display;
        store.TakeDisplay(display);
        auto connection = *DisplayConnection(DisplayProcess(display, 0), key);
        Check(connection.sent == 10 && connection.recv == 20 &&
              connection.bytesPerSecond() == 0.0,
              "first bandwidth report invented an unknown sampling interval");

        Sleep(80);
        // Дополнительный снимок UI не должен сдвигать границу отчёта драйвера.
        store.TakeDisplay(display);
        store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 1);
        store.TakeDisplay(display);
        connection = *DisplayConnection(DisplayProcess(display, 0), key);
        Check(connection.period.elapsedMs() >= 60 && connection.periodSent == 10 &&
              connection.periodRecv == 20 && connection.bytesPerSecond() <= 500.0,
              "rapid display refresh shortened the bandwidth report interval");
        store.TakeDisplay(display);
        Check(DisplayConnection(DisplayProcess(display, 0), key)->bytesPerSecond() == 0.0,
              "bandwidth rate was counted again without a new report");

        Sleep(40);
        store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 1);
        Sleep(40);
        store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 1);
        store.TakeDisplay(display);
        connection = *DisplayConnection(DisplayProcess(display, 0), key);
        Check(connection.period.elapsedMs() >= 60 && connection.periodSent == 20 &&
              connection.periodRecv == 40 && connection.bytesPerSecond() <= 1000.0,
              "multiple bandwidth reports lost their complete interval");

        Sleep(80);
        const ULONGLONG beforeEmpty = GetTickCount64();
        store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 0);
        const ULONGLONG afterEmpty = GetTickCount64();
        Sleep(40);
        const ULONGLONG beforeReport = GetTickCount64();
        store.AddBandwidthBatch(ProtoNumber(key.proto), &entry, 1);
        const ULONGLONG afterReport = GetTickCount64();
        store.TakeDisplay(display);
        connection = *DisplayConnection(DisplayProcess(display, 0), key);
        Check(connection.period.elapsedMs() >= beforeReport - afterEmpty &&
              connection.period.elapsedMs() <= afterReport - beforeEmpty,
              "empty bandwidth report did not advance its source baseline");
    };

    for (Proto proto : { Proto::Tcp, Proto::Udp }) {
        pmkext::BandwidthValueV4 entry4{};
        test(entry4, proto == Proto::Tcp ? Tcp4(46512) : Udp4(46512));
        pmkext::BandwidthValueV6 entry6{};
        test(entry6, proto == Proto::Tcp ? Tcp6(46512) : Udp6(46512));
    }
}

void TestBandwidthSpeedUsesPollBoundaries() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey keys4[] = { Tcp4(46514), Udp4(46515) };
    const FlowKey keys6[] = { Tcp6(46514), Udp6(46515) };
    pmkext::BandwidthValueV4 entries4[2]{};
    pmkext::BandwidthValueV6 entries6[2]{};
    const auto fill = [&](auto& entry, const FlowKey& key) {
        OpenDriverFlow(key, 0);
        std::memcpy(entry.local_ip, key.local.b, sizeof(entry.local_ip));
        std::memcpy(entry.remote_ip, key.remote.b, sizeof(entry.remote_ip));
        entry.local_port = key.lport;
        entry.remote_port = key.rport;
        entry.transmitted_bytes = 10;
        entry.received_bytes = 20;
    };
    for (size_t index = 0; index < 2; ++index) {
        fill(entries4[index], keys4[index]);
        fill(entries6[index], keys6[index]);
    }
    const auto send = [&](size_t index, bool ipv6) {
        if (ipv6)
            store.AddBandwidthBatch(ProtoNumber(keys6[index].proto), &entries6[index], 1);
        else
            store.AddBandwidthBatch(ProtoNumber(keys4[index].proto), &entries4[index], 1);
    };
    const auto sendAll = [&]() {
        for (size_t index = 0; index < 2; ++index) {
            send(index, false);
            send(index, true);
        }
    };
    FlowStore::DisplayView display;
    store.BeginBandwidthPoll(1000);
    sendAll();
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 0.0,
          "first managed bandwidth poll invented its start boundary");

    // Пустые категории не имеют ответа, но общий опрос сдвигает все границы.
    store.BeginBandwidthPoll(2000);
    send(1, false);
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 30.0,
          "managed bandwidth rate depended on response arrival time");

    store.BeginBandwidthPoll(3000);
    send(0, false);
    send(0, true);
    send(1, true);
    store.TakeDisplay(display);
    const auto& process = DisplayProcess(display, 0);
    for (const FlowKey& key : { keys4[0], keys6[0], keys6[1] }) {
        const auto* connection = DisplayConnection(process, key);
        Check(connection && connection->period.begin == 2000 &&
              connection->period.end == 3000 && connection->bytesPerSecond() == 30.0,
              "omitted empty categories lengthened the next bandwidth interval");
    }
    Check(process.speed == 90.0,
          "managed bandwidth process rate does not sum the current reports");

    store.BeginBandwidthPoll(4000);
    sendAll();
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 120.0,
          "TCP/UDP or IPv4/IPv6 responses used different poll boundaries");

    store.BeginBandwidthPoll(5000);
    store.CancelBandwidthPoll();
    send(1, false);
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 0.0,
          "failed bandwidth request retained an invented measurement interval");
    store.BeginBandwidthPoll(6000);
    sendAll();
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 0.0,
          "first bandwidth response after failure included unknown history");
    store.BeginBandwidthPoll(7000);
    send(1, false);
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 30.0,
          "bandwidth polling did not recover after a failed request");
}

void TestProcessSpeedIsSumOfConnectionRates() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = snapshot.tcpV6Valid = true;
    snapshot.tcpV4.emplace_back();
    snapshot.tcpV6.emplace_back();
    auto& first = snapshot.tcpV4.back();
    auto& second = snapshot.tcpV6.back();
    first.key = Tcp4(46513);
    second.key = Tcp6(46513);
    for (auto* row : { &first, &second }) {
        row->state = MIB_TCP_STATE_ESTAB;
        row->countersRead = true;
        row->countersAt = 1000;
        row->sent = 100;
        row->recv = 200;
    }
    FlowStore::DisplayView display;
    const auto sample = [&]() {
        store.ReplaceSystemSnapshot(snapshot);
        store.TakeDisplay(display);
    };
    sample();
    Check(DisplayProcess(display, 0).speed == 0.0,
          "first process snapshot included historical traffic in its speed");

    first.countersRead = false;
    first.sent = first.recv = 0;
    second.countersAt = 2000;
    second.sent += 100;
    second.recv += 200;
    sample();
    Check(DisplayProcess(display, 0).speed == 300.0,
          "failed EStats read changed the speed of another connection");

    first.countersRead = true;
    first.countersAt = second.countersAt = 3000;
    first.sent = 300;
    first.recv = 600;
    second.sent += 100;
    second.recv += 200;
    sample();
    const auto& process = DisplayProcess(display, 0);
    Check(DisplayConnection(process, first.key)->bytesPerSecond() == 300.0 &&
          DisplayConnection(process, second.key)->bytesPerSecond() == 300.0 &&
          process.speed == 600.0,
          "process speed does not equal the sum of its displayed connection rates");

    first.countersAt = second.countersAt = 4000;
    first.sent += 100;
    first.recv += 200;
    second.sent += 100;
    second.recv += 200;
    sample();
    Check(DisplayProcess(display, 0).speed == 600.0,
          "aligned connection intervals changed their total process speed");
    store.TakeDisplay(display);
    Check(DisplayProcess(display, 0).speed == 0.0,
          "process speed repeated traffic without a new counter sample");
}

void TestTrafficPeriodAndSpeedBounds() {
    FlowStore::TrafficPeriod period;
    period.Include(0, 1000);
    period.Include(1000, 2000);
    Check(period.elapsedMs() == 0,
          "unknown first report interval became known before consumption");
    period = FlowStore::TrafficPeriod{};
    period.Include(2000, 3000);
    period.Include(4000, 5000);
    Check(period.elapsedMs() == 3000,
          "traffic period did not include idle time between reports");

    FlowStore::DisplayConnection connection;
    connection.periodSent = connection.periodRecv = UINT64_MAX;
    Check(connection.bytesPerSecond() == 0.0,
          "unknown traffic interval produced a nonzero rate");
    connection.period = FlowStore::TrafficPeriod{ 1000, 2000 };
    Check(connection.bytesPerSecond() == 2.0 * static_cast<double>(UINT64_MAX),
          "rate calculation overflowed while adding both directions");
}

void TestTlsDomainLabelStaysWithConnection() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    const DWORD pid = 1750;
    const FlowKey key = Tcp4(46600, 443);
    FlowStore::ConnEvent pending = Event(pid);
    store.NoteConnection(key, pending);

    FlowStore::ConnEvent allowed = Event(pid);
    allowed.tlsDomainLabel =
        std::make_shared<const std::wstring>(L"[domain.example]");
    store.NoteAllowed(key, allowed);

    FlowStore::DisplayView display;
    store.TakeDisplay(display);
    const auto* connection = DisplayConnection(DisplayProcess(display, pid), key);
    Check(connection && connection->tlsDomainLabel &&
          *connection->tlsDomainLabel == L"[domain.example]",
          "TLS domain label was not attached to the allowed connection");
}

void TestSystemTcpDisplayStateFilter() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    const DWORD states[] = {
        MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_LISTEN,
        MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_SYN_RCVD,
        MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
        MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_CLOSE_WAIT,
        MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_LAST_ACK,
        MIB_TCP_STATE_TIME_WAIT, MIB_TCP_STATE_DELETE_TCB
    };
    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    snapshot.tcpV6Valid = true;
    for (size_t index = 0; index < std::size(states); ++index) {
        for (bool ipv6 : { false, true }) {
            FlowStore::SystemTcpConnection row;
            const uint16_t port = static_cast<uint16_t>(47000 + index);
            row.key = ipv6 ? Tcp6(port) : Tcp4(port);
            row.state = states[index];
            if (row.state == MIB_TCP_STATE_LISTEN) {
                row.key.remote = IpAddr{};
                row.key.remote.family = row.key.local.family;
                row.key.rport = 0;
            } else {
                // Трафик не должен обходить ограничение системных состояний.
                row.sent = 10;
                row.recv = 5;
                row.countersRead = true;
            }
            (ipv6 ? snapshot.tcpV6 : snapshot.tcpV4).push_back(row);
        }
    }
    store.ReplaceSystemSnapshot(snapshot);

    for (bool showPassive : { false, true }) {
        FlowStore::DisplayView display;
        store.TakeDisplay(display, FlowStore::kInactiveMs, showPassive);
        const auto& process = DisplayProcess(display, 0);
        Check(process.connections.size() == (showPassive ? 4 : 2),
              "system TCP state filtering published unexpected rows");
        for (const auto* rows : { &snapshot.tcpV4, &snapshot.tcpV6 }) {
            for (const auto& row : *rows) {
                const bool expected = row.state == MIB_TCP_STATE_ESTAB ||
                    (showPassive && row.state == MIB_TCP_STATE_LISTEN);
                Check((DisplayConnection(process, row.key) != nullptr) == expected,
                      "system TCP state filtering is wrong for IPv4 or IPv6");
            }
        }
        FlowStore::DisplayView summary;
        store.TakeDisplay(summary, FlowStore::kInactiveMs, showPassive, false);
        const auto& compact = DisplayProcess(summary, 0);
        Check(compact.connCount == process.connections.size() && compact.connections.empty() &&
              compact.speed == 0.0 && summary.flowCount == display.flowCount &&
              summary.hiddenCount == display.hiddenCount,
              "tray summary bypassed TCP state or passive filtering");
    }

    const FlowStore::View full = Take();
    Check(Process(full, 0).connections.size() == std::size(states) * 2 &&
          full.ownerIndexes.tcpV4.size() == std::size(states) &&
          full.ownerIndexes.tcpV6.size() == std::size(states),
          "display filtering removed system TCP lifecycle or owner records");

    // Исчезновение строки и пометка завершения не возвращают скрытые состояния.
    FlowStore::SystemSnapshot missing;
    missing.tcpV4Valid = true;
    missing.tcpV6Valid = true;
    store.ReplaceSystemSnapshot(missing);
    FlowStore::DisplayView finished;
    store.TakeDisplay(finished, FlowStore::kInactiveMs, true);
    Check(DisplayProcess(finished, 0).connections.size() == 4,
          "finished system TCP rows bypassed the state filter");

    // Драйверные записи сохраняются при любом состоянии системной таблицы.
    store.Reset();
    for (const auto* rows : { &snapshot.tcpV4, &snapshot.tcpV6 })
        for (const auto& row : *rows)
            OpenDriverFlow(row.key, 0);
    store.ReplaceSystemSnapshot(snapshot);
    for (bool showPassive : { false, true }) {
        FlowStore::DisplayView display;
        store.TakeDisplay(display, FlowStore::kInactiveMs, showPassive);
        Check(DisplayProcess(display, 0).connections.size() == std::size(states) * 2,
              "system TCP state filtering hid driver-backed rows");
    }
}

void TestPassiveRowsAreFilteredBeforeCopy() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();

    constexpr uint16_t firstPort = 10000;
    constexpr size_t count = 4000;
    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = true;
    snapshot.tcpV4.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        FlowStore::SystemTcpConnection row;
        row.key = Tcp4(static_cast<uint16_t>(firstPort + index), 0);
        row.key.remote = IpAddr::V4(0);
        row.pid = 0;
        row.state = MIB_TCP_STATE_LISTEN;
        snapshot.tcpV4.push_back(row);
    }
    store.ReplaceSystemSnapshot(snapshot);

    FlowStore::DisplayView filtered;
    store.TakeDisplay(filtered, FlowStore::kInactiveMs, false);
    Check(filtered.flowCount == count && filtered.hiddenCount == count,
          "passive filtering changed the number of stored flows");
    Check(filtered.processes.empty(),
          "passive rows were copied into the production display snapshot");

    FlowStore::View full = Take();
    Check(Process(full, 0).connections.size() == count,
          "passive filtering removed objects from FlowStore");

    FlowStore::DisplayView shown;
    store.TakeDisplay(shown, FlowStore::kInactiveMs, true);
    Check(DisplayProcess(shown, 0).connections.size() == count,
          "show-passive did not publish every stored object");
    // Повторно используемый полный снимок не оставляет строки в сводке трея.
    store.TakeDisplay(shown, FlowStore::kInactiveMs, true, false);
    Check(DisplayProcess(shown, 0).connCount == count &&
          DisplayProcess(shown, 0).connections.empty(),
          "tray summary retained connection rows from a previous full display");
    store.TakeDisplay(shown, FlowStore::kInactiveMs, false, false);
    Check(shown.processes.empty() && shown.flowCount == count && shown.hiddenCount == count,
          "tray summary retained processes with only hidden passive connections");
}

void TestNoElementCountLimit() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    constexpr uint16_t firstPort = 20000;
    constexpr size_t count = 2000;
    for (size_t index = 0; index < count; ++index) {
        const FlowKey key = Tcp4(
            static_cast<uint16_t>(firstPort + index), 443);
        OpenDriverFlow(key, 0);
    }

    FlowStore::View view = Take();
    Check(Process(view, 0).connections.size() == count,
          "connection table has an artificial element limit");
    Check(Process(view, 0).driverTraffic.tcpV4.size() == count,
          "driver table has an artificial element limit");
    Check(view.ownerIndexes.tcpV4.size() == count,
          "owner index has an artificial element limit");

    // END должен пользоваться индексом FlowId, а не заново обходить все уже
    // накопленные соединения процесса.
    for (size_t index = 0; index < count; ++index) {
        const FlowKey key = Tcp4(
            static_cast<uint16_t>(firstPort + index), 443);
        store.CloseFlow(key, 0, Dir::Out);
    }
    view = Take();
    size_t marked = 0;
    for (const auto& item : Process(view, 0).connections)
        if (item.second.removeAfter) ++marked;
    Check(marked == count, "indexed END lookup missed connections");
}

struct SnapshotElement {
    inline static size_t live = 0;
    std::shared_ptr<int> value;
    SnapshotElement() { ++live; }
    ~SnapshotElement() { --live; }
};

void TestSnapshotArrayLifetime() {
    static_assert(!std::is_copy_constructible_v<SnapshotArray<SnapshotElement>>);
    static_assert(std::is_nothrow_move_constructible_v<SnapshotArray<SnapshotElement>>);
    SnapshotArray<SnapshotElement> values;
    values.reset(1024);
    Check(values.size() == 1024 && SnapshotElement::live == 1024,
          "snapshot array did not allocate the exact number of elements");
    values[0].value = std::make_shared<int>(7);
    std::weak_ptr<int> reference = values[0].value;
    const auto* data = values.data();
    values.reset(1024);
    Check(values.data() == data && !reference.expired() && SnapshotElement::live == 1024,
          "unchanged snapshot size reallocated or cleared the current array");

    values.reset(3);
    Check(values.size() == 3 && SnapshotElement::live == 3 && reference.expired(),
          "smaller snapshot retained old elements or their nested ownership");
    Check(values.span().data() == values.data() && values.span().size() == 3,
          "snapshot array exposes an incorrect span");
    data = values.data();
    SnapshotArray<SnapshotElement> moved = std::move(values);
    Check(values.empty() && values.data() == nullptr && moved.data() == data,
          "moving a snapshot array left ownership or a nonempty moved-from array");
    std::swap(values, moved);
    Check(moved.empty() && values.data() == data && SnapshotElement::live == 3,
          "snapshot exchange moved or duplicated elements");
    values.reset();
    Check(values.empty() && values.data() == nullptr && SnapshotElement::live == 0,
          "empty snapshot retained an allocation");
}

void CheckDisplayStorage(const FlowStore::DisplayView& view) {
    size_t offset = 0;
    for (const auto& process : view.processes) {
        Check(process.connections.size() <= view.connections.size() - offset,
              "display process range exceeds the flat connection array");
        Check(process.connections.data() ==
              view.connections.span().subspan(offset).data(),
              "display process connections do not refer to the flat array");
        offset += process.connections.size();
    }
    Check(offset == view.connections.size(),
          "display snapshot contains unused connection elements");
}

void TestDisplayFlatStorage() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const DWORD pids[] = { 0, 4, GetCurrentProcessId() };
    constexpr size_t burst = 512;
    for (size_t process = 0; process < std::size(pids); ++process)
        for (size_t index = 0; index < burst; ++index)
            OpenDriverFlow(Tcp4(static_cast<uint16_t>(
                20000 + process * burst + index)), pids[process]);

    FlowStore::DisplayView display;
    store.TakeDisplay(display);
    Check(display.processes.size() == std::size(pids) &&
          display.connections.size() == std::size(pids) * burst,
          "flat display snapshot lost burst connections");
    CheckDisplayStorage(display);
    const auto* processes = display.processes.data();
    const auto* connections = display.connections.data();
    store.TakeDisplay(display);
    Check(display.processes.data() == processes && display.connections.data() == connections,
          "unchanged display size reallocated the flat arrays");
    CheckDisplayStorage(display);

    Sleep(150);
    for (size_t process = 0; process < std::size(pids); ++process)
        OpenDriverFlow(Tcp4(static_cast<uint16_t>(20000 + process * burst)), pids[process]);
    store.TakeDisplay(display, 100);
    Check(display.processes.size() == std::size(pids) &&
          display.connections.size() == std::size(pids) &&
          display.removedConnections == std::size(pids) * (burst - 1),
          "display snapshot retained burst-sized arrays after expiration");
    CheckDisplayStorage(display);
    for (const auto& process : display.processes)
        Check(process.connections.size() == 1 && process.connCount == 1,
              "display process retained unused burst elements");

    FlowStore::DisplayView moved = std::move(display);
    Check(display.processes.empty() && display.connections.empty(),
          "moved display snapshot retained its arrays");
    CheckDisplayStorage(moved);
    std::swap(display, moved);
    CheckDisplayStorage(display);

    store.TakeDisplay(display, FlowStore::kInactiveMs, true, false);
    Check(display.processes.size() == std::size(pids) &&
          display.connections.empty() && display.connections.data() == nullptr,
          "tray summary retained a connection allocation");
    CheckDisplayStorage(display);
    store.TakeDisplay(display);
    Check(display.connections.size() == std::size(pids),
          "restoring display did not rebuild exact connection storage");
    CheckDisplayStorage(display);

    store.Reset();
    store.TakeDisplay(display);
    Check(display.processes.data() == nullptr && display.connections.data() == nullptr,
          "empty display retained process or connection allocations");
}

} // namespace

#include "firewallxndisfilter_flow_tests.h"

int main() {
    TestNdisFlows();
    TestSnapshotArrayLifetime();
    TestDisplayFlatStorage();
    TestSystemPidsAreNormalProcessKeys();
    TestFourDriverTrafficTables();
    TestBandwidthBatchUsesOneSnapshotPath();
    TestUnknownBandwidthMovesToReportedPid();
    TestOwnerTransfersPreserveConnection();
    TestPidFourDoesNotOverwriteOwnerIndex();
    TestTwoCurrentSystemTrafficTables();
    TestSystemTrafficPermanentlySupersedesDriverTraffic();
    TestUdpSnapshotHasNoSystemTrafficTable();
    TestSystemRowsDoNotInventActivity();
    TestUdpEndpointDoesNotDuplicateConcreteFlow();
    TestUdpBandwidthUsesCurrentLocalEndpointOwner();
    TestListenerProtectsDriverTraffic();
    TestEndedOwnersExpireWithListener();
    TestInactiveEntriesWithoutListenerExpire();
    TestLocalConnectionEndClosesReverseFlow();
    TestLocalStaleEndKeepsCurrentPair();
    TestRepeatedLocalEndKeepsNewReverseFlow();
    TestServiceLocalEndKeepsCurrentPair();
    TestConnectionEndLeavesNonLocalReverseFlow();
    TestConnectionEndKeepsReportedPid();
    TestStaleEndKeepsCurrentGeneration();
    TestEndSelectsRetiredGeneration();
    TestSystemEndKeepsOtherOwner();
    TestServiceEndKeepsReportedPid();
    TestTupleReuseKeepsMarkedGeneration();
    TestFirstInboundOwnerKeepsExactAndEndPriority();
    TestEndedOwnerDoesNotFollowUnknownGeneration();
    TestBlockedReuseDoesNotInheritEndedOwner();
    TestBlockedOwnerRemainsConfirmedUntilEnd();
    TestAmbiguousOwnerSurvivesEventPublications();
    TestSystemSnapshotResolvesAmbiguousOwner();
    TestAmbiguousBandwidthCannotConfirmOwner();
    TestServiceReportedOwnerReopensExactTuple();
    TestFourSecondRemovalForEndAndDeadProcess();
    TestDisplayViewSelectsCounters();
    TestDisplayCleanupKeepsSourcesAndFilters();
    TestDisplayExcludesExpiredListenerOwner();
    TestSummaryKeepsConnectionFacts();
    TestSummaryKeepsCountersAndSampling();
    TestEstatsSpeedUsesSampleIntervals();
    TestEstatsSpeedMergesUnreadSamples();
    TestBandwidthSpeedUsesReportIntervals();
    TestBandwidthSpeedUsesPollBoundaries();
    TestProcessSpeedIsSumOfConnectionRates();
    TestTrafficPeriodAndSpeedBounds();
    TestTlsDomainLabelStaysWithConnection();
    TestSystemTcpDisplayStateFilter();
    TestPassiveRowsAreFilteredBeforeCopy();
    TestNoElementCountLimit();
    std::cout << "FlowStore unified-process tests passed\n";
    return 0;
}
