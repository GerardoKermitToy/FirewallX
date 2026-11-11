#pragma once

// Детерминированное время уборки: минуту в реальном времени тест не ждёт.
struct StorageTestAccess {
    static void ExpireAt(ULONGLONG now) {
        FlowStore& store = FlowStore::Instance();
        std::lock_guard<std::mutex> lock(store.mtx_);
        store.ExpireLocked(now, FlowStore::kInactiveMs);
    }
    static void SetLastTakeAt(ULONGLONG tick) {
        FlowStore& store = FlowStore::Instance();
        std::lock_guard<std::mutex> lock(store.mtx_);
        store.lastTakeAt_ = tick;
    }
    static size_t NdisIndexes() {
        FlowStore& store = FlowStore::Instance();
        std::lock_guard<std::mutex> lock(store.mtx_);
        return store.ndisConnections_.size();
    }
};

namespace {

FlowKey NdisKey(FlowKey key) {
    key.source = TrafficSource::Ndis;
    return key;
}

template <class Value>
Value NdisBytes(const FlowKey& key, uint64_t sent, uint64_t received) {
    Value value{};
    std::memcpy(value.local_ip, key.local.b, sizeof(value.local_ip));
    std::memcpy(value.remote_ip, key.remote.b, sizeof(value.remote_ip));
    value.local_port = key.lport;
    value.remote_port = key.rport;
    value.transmitted_bytes = sent;
    value.received_bytes = received;
    return value;
}

void NdisBandwidth(const FlowKey& key, uint64_t sent, uint64_t received) {
    if (key.local.family == AF_INET) {
        const auto value = NdisBytes<firewallxndisfilter::Client::BandwidthV4>(key, sent, received);
        FlowStore::Instance().AddNdisBandwidthBatch(ProtoNumber(key.proto), &value, 1, key.interfaceIndex);
    } else {
        const auto value = NdisBytes<firewallxndisfilter::Client::BandwidthV6>(key, sent, received);
        FlowStore::Instance().AddNdisBandwidthBatch(ProtoNumber(key.proto), &value, 1, key.interfaceIndex);
    }
}

void TestNdisFlowIsolation() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    for (const FlowKey& host : {Tcp4(), Tcp6(), Udp4(), Udp6()}) {
        const FlowKey guest = NdisKey(host);
        Check(!(host == guest), "host and Ndis tuple compare equal");
        OpenDriverFlow(host, 4);
        OpenDriverFlow(guest, 0);
        store.AddBandwidth(host, 10, 20);
        NdisBandwidth(guest, 30, 40);
        // END от Portmaster содержит тот же tuple, но не относится к гостю.
        EndDriverFlow(host, 4, Dir::Out);
        const auto view = Take();
        const auto* connection = Connection(Process(view, TrafficGroupKey::Ndis(0)), guest);
        Check(connection && !connection->endReceived && !connection->removeAfter &&
              !connection->systemBacked && connection->driver &&
              connection->driver->sent == 30 && connection->driver->recv == 40,
              "Portmaster traffic or END changed Ndis flow");
    }
    Check(StorageTestAccess::NdisIndexes() == 4, "guest tuple index is incomplete");
    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = snapshot.tcpV6Valid = true;
    snapshot.udpV4Valid = snapshot.udpV6Valid = true;
    snapshot.tcpV4.push_back({Tcp4(), 4, MIB_TCP_STATE_ESTAB});
    snapshot.tcpV6.push_back({Tcp6(), 4, MIB_TCP_STATE_ESTAB});
    snapshot.udpV4.push_back({Udp4().local, Udp4().lport, 4});
    snapshot.udpV6.push_back({Udp6().local, Udp6().lport, 4});
    store.ReplaceSystemSnapshot(snapshot);
    auto view = Take();
    for (const auto& [generation, connection] : Process(view, TrafficGroupKey::Ndis(0)).connections) {
        (void)generation;
        Check(!connection.systemBacked && !connection.systemTrafficAuthoritative,
              "Windows tables became authoritative for Ndis");
    }
    store.ResetHost();
    view = Take();
    Check(view.processes.size() == 1 && Process(view, TrafficGroupKey::Ndis(0)).connections.size() == 4,
          "Portmaster session reset removed Ndis rows");
    store.Reset();
}

void TestNdisMinuteInactivity() {
    FlowStore& store = FlowStore::Instance();
    const FlowKey other4 = MakeFlowKey(ProtoFromNumber(143), V4(10, 1, 0, 2), V4(10, 1, 0, 3), 0, 0);
    const FlowKey icmp6 = MakeFlowKey(Proto::IcmpV6, V6(2), V6(4), 0, 0);
    for (const FlowKey& key : {Tcp4(), Tcp6(), Udp4(), Udp6(), other4, icmp6}) {
        store.Reset();
        const FlowKey guest = NdisKey(key);
        const uint64_t generation = store.NoteConnection(guest, Event(0));
        NdisBandwidth(guest, 100, 200);
        auto view = Take();
        const auto* connection = Connection(Process(view, TrafficGroupKey::Ndis(0)), guest);
        Check(connection && connection->driver && connection->driver->sent == 100,
              "Ndis traffic was not stored");
        const ULONGLONG activity = connection->lastActivity;
        StorageTestAccess::ExpireAt(activity + kNdisInactiveMs - 1);
        view = Take(1);
        Check(Connection(Process(view, TrafficGroupKey::Ndis(0)), guest) != nullptr,
              "generic inactivity timeout removed Ndis before a minute");
        FlowStore::DisplayView display;
        store.TakeDisplay(display, 1, false);
        Check(DisplayConnection(DisplayProcess(display, TrafficGroupKey::Ndis(0)), guest) != nullptr,
              "passive filtering hid a live Ndis event");
        StorageTestAccess::ExpireAt(activity + kNdisInactiveMs);
        view = Take();
        Check(view.processes.count(TrafficGroupKey::Ndis(0)) == 0 && StorageTestAccess::NdisIndexes() == 0,
              "Ndis row, counters or index survived a minute of inactivity");
        store.NoteAllowed(guest, Event(0), generation);
        Check(Take().processes.count(TrafficGroupKey::Ndis(0)) == 0,
              "late verdict restored an expired Ndis flow");
    }
    store.Reset();
}

void TestNdisBandwidthBeforeConnection() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey guest = NdisKey(Udp6());
    NdisBandwidth(guest, 70, 90);
    auto view = Take();
    const auto* connection = Connection(Process(view, TrafficGroupKey::Ndis(0)), guest);
    Check(connection && connection->driver && connection->driver->sent == 70,
          "bandwidth-only Ndis event has no pseudo-process");
    const uint64_t generation = connection->generation;
    Check(store.NoteConnection(guest, Event(0)) == generation,
          "connection callback discarded existing Ndis statistics");
    view = Take();
    connection = Connection(Process(view, TrafficGroupKey::Ndis(0)), guest);
    Check(connection->driver->sent == 70 && connection->driver->recv == 90,
          "connection callback reset Ndis counters");
    store.Reset();
}

void TestNdisBatchPreservesInterfaceIdentity() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    constexpr uint32_t interfaceIndex = 0x87654321u;
    FlowKey old = NdisKey(Udp4(53000));
    FlowKey first = NdisKey(Udp4(53001));
    FlowKey second = NdisKey(Udp4(53002));
    old.interfaceIndex = first.interfaceIndex = second.interfaceIndex = interfaceIndex;
    const auto originalName = std::make_shared<const std::wstring>(L"Former interface");
    auto event = Event(0);
    event.interfaceIndex = interfaceIndex;
    event.interfaceName = originalName;
    store.NoteConnection(old, event);

    const firewallxndisfilter::Client::BandwidthV4 entries[] = {
        NdisBytes<firewallxndisfilter::Client::BandwidthV4>(old, 1, 2),
        NdisBytes<firewallxndisfilter::Client::BandwidthV4>(first, 3, 4),
        NdisBytes<firewallxndisfilter::Client::BandwidthV4>(second, 5, 6),
    };
    store.AddNdisBandwidthBatch(ProtoNumber(Proto::Udp), entries, 3, interfaceIndex);
    const auto view = Take();
    const auto& process = Process(view, TrafficGroupKey::Ndis(interfaceIndex));
    const auto* oldConnection = Connection(process, old);
    const auto* firstConnection = Connection(process, first);
    const auto* secondConnection = Connection(process, second);
    Check(oldConnection && oldConnection->driver && oldConnection->driver->interfaceName == originalName &&
              firstConnection && firstConnection->driver && firstConnection->driver->interfaceName &&
              firstConnection->driver->interfaceName->empty() && secondConnection &&
              secondConnection->driver && secondConnection->driver->interfaceName == firstConnection->driver->interfaceName &&
              oldConnection->driver->sent == 1 && firstConnection->driver->sent == 3 &&
              secondConnection->driver->sent == 5,
          "Ndis batch reused an older connection's interface identity");
    store.Reset();
}

void TestNdisBlockedGrace() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey guest = NdisKey(Tcp4());
    const auto event = Event(0);
    const uint64_t generation = store.NoteConnection(guest, event);
    store.NoteBlocked(guest, event, generation);
    auto view = Take();
    const auto* connection = Connection(Process(view, TrafficGroupKey::Ndis(0)), guest);
    Check(connection && connection->blockedAt &&
          connection->removeAfter - connection->blockedAt == kBlockedGraceMs,
          "Ndis blocking lost the short removal grace");
    StorageTestAccess::ExpireAt(connection->removeAfter);
    Check(Take().processes.count(TrafficGroupKey::Ndis(0)) == 0 && StorageTestAccess::NdisIndexes() == 0,
          "blocked Ndis event did not leave the list after the short grace");
    store.Reset();
}

void TestNdisBlockedIcmpDirection() {
    FlowStore& store = FlowStore::Instance();
    for (bool ipv6 : {false, true})
    for (Dir dir : {Dir::Out, Dir::In})
    for (bool immediate : {false, true}) {
        store.Reset();
        const FlowKey guest = NdisKey(ipv6
            ? MakeFlowKey(Proto::IcmpV6, V6(2), V6(4), 0, 0)
            : MakeFlowKey(Proto::Icmp, V4(10, 1, 0, 2), V4(10, 1, 0, 3), 0, 0));
        auto event = Event(0);
        event.dir = dir;
        event.icmpType = ipv6 ? 128 : 8;
        event.icmpCode = 0;
        event.bytes = 84;
        const uint64_t generation = immediate
            ? store.NoteBlockedConnection(guest, event)
            : store.NoteConnection(guest, event);
        if (!immediate) store.NoteBlocked(guest, event, generation);

        FlowStore::DisplayView display;
        store.TakeDisplay(display, FlowStore::kInactiveMs, true);
        const auto* connection = DisplayConnection(DisplayProcess(display, TrafficGroupKey::Ndis(0)), guest);
        Check(generation && connection && connection->flowGeneration == generation &&
                  connection->blockedAt && connection->dir == dir && connection->driverEvents == 1,
              "blocked Ndis ICMP lost its generation, direction or event count");
        const bool inbound = dir == Dir::In;
        const IcmpInfo& actual = inbound ? connection->icmpIn : connection->icmpOut;
        const IcmpInfo& opposite = inbound ? connection->icmpOut : connection->icmpIn;
        Check(actual.type == event.icmpType && actual.code == event.icmpCode &&
                  actual.v6 == ipv6 && !opposite.known(),
              "blocked Ndis ICMP was attributed to the opposite direction");
        Check(connection->pktSent == (inbound ? 0u : 1u) &&
                  connection->pktRecv == (inbound ? 1u : 0u),
              "blocked Ndis ICMP changed packet direction counters");
    }
    store.Reset();
}

void TestNdisIndependentBandwidthPeriods() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const FlowKey guest = NdisKey(Udp4());
    store.BeginNdisBandwidthPoll(1000);
    store.BeginNdisBandwidthPoll(2000);
    store.BeginBandwidthPoll(100000);
    NdisBandwidth(guest, 7, 9);
    FlowStore::DisplayView display;
    store.TakeDisplay(display);
    const auto* first = DisplayConnection(DisplayProcess(display, TrafficGroupKey::Ndis(0)), guest);
    Check(first && first->period.begin == 1000 && first->period.end == 2000 &&
              first->bytesPerSecond() == 16.0,
          "Ndis speed used the Windows sampling period");
    store.ResetHost();
    store.BeginNdisBandwidthPoll(3000);
    store.BeginBandwidthPoll(200000);
    NdisBandwidth(guest, 4, 6);
    store.TakeDisplay(display);
    const auto* next = DisplayConnection(DisplayProcess(display, TrafficGroupKey::Ndis(0)), guest);
    Check(next && next->period.begin == 2000 && next->period.end == 3000 &&
              next->bytesPerSecond() == 10.0 && next->sent == 11 && next->recv == 15,
          "host sampling or reset changed Ndis counters and speed");
    store.Reset();
}

void TestNdisEventTrafficPeriods() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const ULONGLONG begin = GetTickCount64() - 1000;
    StorageTestAccess::SetLastTakeAt(begin);
    for (Proto proto : {Proto::Icmp, Proto::IcmpV6, ProtoFromNumber(47)}) {
        const FlowKey guest = NdisKey(MakeFlowKey(proto, V4(10, 1, 0, 2), V4(10, 1, 0, 3), 0, 0));
        auto event = Event(0);
        event.bytes = 32;
        store.NoteConnection(guest, event);
    }
    FlowStore::DisplayView display;
    store.TakeDisplay(display);
    const auto& process = DisplayProcess(display, TrafficGroupKey::Ndis(0));
    for (const auto& connection : process.connections) {
        Check(connection.sent == 32 && connection.periodSent == 32 &&
                  connection.period.begin == begin && connection.period.end > begin &&
                  connection.bytesPerSecond() > 0 && connection.bytesPerSecond() <= 32.0,
              "Ndis packet payload has no UI sampling interval or speed");
    }
    Check(process.connections.size() == 3, "Ndis packet payload is missing from the display");
    store.Reset();
}

void TestExplicitTrafficGroups() {
    FlowStore& store = FlowStore::Instance();
    store.Reset();
    const DWORD pid = GetCurrentProcessId();
    const FlowKey host = Tcp4();
    const uint64_t hostGeneration = store.NoteConnection(host, Event(pid));
    for (uint32_t index : {0u, static_cast<uint32_t>(pid), 0x87654321u, UINT32_MAX}) {
        FlowKey guest = NdisKey(host);
        guest.interfaceIndex = index;
        const uint64_t generation = store.NoteConnection(guest, Event(0));
        Check(generation != hostGeneration && store.NoteConnection(guest, Event(0)) == generation,
              "interface identity aliased a host PID or changed between callbacks");
        NdisBandwidth(guest, index + uint64_t{1}, 7);
        store.NoteAllowed(guest, Event(0), generation);
        const auto view = Take();
        const auto* connection = Connection(Process(view, TrafficGroupKey::Ndis(index)), guest);
        Check(connection && connection->pid == 0 && connection->driver &&
                  connection->driver->sent == index + uint64_t{1},
              "interface was assigned a PID or used another interface's counters");
        Check(Connection(Process(view, pid), host)->generation == hostGeneration,
              "interface callback changed a host connection");
    }
    FlowStore::DisplayView summary;
    store.TakeDisplay(summary, FlowStore::kInactiveMs, true, false);
    Check(summary.processes.size() == 5 && summary.connections.empty(), "tray summary merged traffic groups");
    for (uint32_t index : {0u, static_cast<uint32_t>(pid), 0x87654321u, UINT32_MAX}) {
        const auto& group = DisplayProcess(summary, TrafficGroupKey::Ndis(index));
        Check(group.group.pid() == 0 && group.group.interfaceIndex() == index && group.connCount == 1,
              "summary lost an interface identity without connection rows");
    }
    store.ResetHost();
    const auto remaining = Take();
    Check(remaining.processes.size() == 4 && !remaining.processes.contains(TrafficGroupKey::Host(pid)),
          "host session reset removed interface groups");
    store.Reset();
}

void TestNdisFlows() {
    TestExplicitTrafficGroups();
    TestNdisEventTrafficPeriods();
    TestNdisIndependentBandwidthPeriods();
    TestNdisFlowIsolation();
    TestNdisMinuteInactivity();
    TestNdisBandwidthBeforeConnection();
    TestNdisBatchPreservesInterfaceIdentity();
    TestNdisBlockedGrace();
    TestNdisBlockedIcmpDirection();
}

} // namespace
