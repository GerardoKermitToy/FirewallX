#include "Monitor.h"
#include "StorageMaintenance.h"
#include "StringRes.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_set>

namespace {
void CheckStorage(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct AllocationState {
    size_t bytes = 0;
    size_t allocations = 0;
};

template <class T>
struct CountingAllocator {
    using value_type = T;
    AllocationState* state;

    explicit CountingAllocator(AllocationState& value) : state(&value) {}
    template <class U>
    CountingAllocator(const CountingAllocator<U>& other) : state(other.state) {}

    T* allocate(size_t count) {
        T* result = std::allocator<T>{}.allocate(count);
        state->bytes += count * sizeof(T);
        ++state->allocations;
        return result;
    }
    void deallocate(T* pointer, size_t count) noexcept {
        state->bytes -= count * sizeof(T);
        std::allocator<T>{}.deallocate(pointer, count);
    }
    template <class U>
    bool operator==(const CountingAllocator<U>& other) const { return state == other.state; }
};

FlowKey StorageKey(size_t index, Proto proto = Proto::Tcp, bool ipv6 = false) {
    IpAddr local, remote;
    local.family = remote.family = ipv6 ? AF_INET6 : AF_INET;
    local.b[0] = 10;
    remote.b[0] = 11;
    const uint32_t address = static_cast<uint32_t>(index + 1);
    std::memcpy(remote.b + (ipv6 ? 12 : 0), &address, sizeof(address));
    return MakeFlowKey(proto, local, remote, 40000, 443);
}

bool controlledTables = false;

DWORD WINAPI StorageGetExtendedTcpTable(PVOID buffer, PDWORD size, BOOL order,
                                        ULONG family, TCP_TABLE_CLASS tableClass,
                                        ULONG reserved) {
    if (!controlledTables)
        return GetExtendedTcpTable(buffer, size, order, family, tableClass, reserved);
    if (family == AF_INET6) return ERROR_NO_DATA;
    CheckStorage(family == AF_INET && tableClass == TCP_TABLE_OWNER_PID_ALL,
                 "unexpected TCP table request in snapshot fixture");
    constexpr DWORD required = sizeof(MIB_TCPTABLE_OWNER_PID);
    if (!buffer || *size < required) {
        *size = required;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    auto* table = static_cast<MIB_TCPTABLE_OWNER_PID*>(buffer);
    *table = {};
    table->dwNumEntries = 1;
    auto& row = table->table[0];
    row.dwState = MIB_TCP_STATE_ESTAB;
    row.dwLocalAddr = htonl(0x0a000001);
    row.dwRemoteAddr = htonl(0x0b000001);
    row.dwLocalPort = htons(40000);
    row.dwRemotePort = htons(443);
    row.dwOwningPid = GetCurrentProcessId();
    *size = required;
    return NO_ERROR;
}

DWORD WINAPI StorageGetExtendedUdpTable(PVOID buffer, PDWORD size, BOOL order,
                                        ULONG family, UDP_TABLE_CLASS tableClass,
                                        ULONG reserved) {
    if (!controlledTables)
        return GetExtendedUdpTable(buffer, size, order, family, tableClass, reserved);
    CheckStorage((family == AF_INET || family == AF_INET6) &&
                 tableClass == UDP_TABLE_OWNER_PID,
                 "unexpected UDP table request in snapshot fixture");
    return ERROR_NO_DATA;
}

struct ScopedSnapshotTables {
    ScopedSnapshotTables() {
        FlowStore::Instance().Reset();
        controlledTables = true;
    }
    ~ScopedSnapshotTables() {
        controlledTables = false;
        FlowStore::Instance().Reset();
    }
};

void TestHashStorage() {
    using Pair = std::pair<const uint64_t, std::shared_ptr<int>>;
    using Allocator = CountingAllocator<Pair>;
    using Table = std::unordered_map<uint64_t, std::shared_ptr<int>,
                                     std::hash<uint64_t>, std::equal_to<uint64_t>, Allocator>;
    for (float load : {0.5f, 1.0f, 2.0f}) {
        AllocationState state;
        {
            Table table(0, std::hash<uint64_t>{}, std::equal_to<uint64_t>{}, Allocator(state));
            table.max_load_factor(load);
            table.rehash(0);
            const size_t emptyBytes = state.bytes;
            for (uint64_t i = 0; i < 100000; ++i)
                table.emplace(i, std::make_shared<int>(static_cast<int>(i)));
            const size_t peakBytes = state.bytes;
            const size_t peakBuckets = table.bucket_count();
            auto* first = &table.at(0);
            for (uint64_t i = 64; i < 100000; ++i) table.erase(i);
            const size_t beforeTrim = state.allocations;
            TrimHashTable(table);
            CheckStorage(state.allocations - beforeTrim < 16,
                         "hash trimming allocated replacement nodes");
            const size_t retainedBytes = state.bytes;
            CheckStorage(table.size() == 64 && table.bucket_count() < peakBuckets / 8 &&
                         state.bytes < peakBytes / 16 && table.max_load_factor() == load &&
                         &table.at(0) == first, "hash trimming retained the peak or moved a node");
            const size_t allocations = state.allocations;
            for (size_t pass = 0; pass < 1000; ++pass) TrimHashTable(table);
            CheckStorage(state.allocations == allocations,
                         "stable hash maintenance repeatedly allocated buckets");
            for (uint64_t i = 0; i < 64; ++i)
                CheckStorage(*table.at(i) == static_cast<int>(i), "hash trimming changed a value");
            table.clear();
            TrimHashTable(table);
            CheckStorage(state.bytes == emptyBytes, "empty hash table retained historical buckets");
            std::cout << "hash storage (load " << load << "): peak=" << peakBytes
                      << ", remaining64=" << retainedBytes << ", empty=" << state.bytes << '\n';
            const size_t emptyAllocations = state.allocations;
            for (size_t pass = 0; pass < 1000; ++pass) TrimHashTable(table);
            CheckStorage(state.allocations == emptyAllocations,
                         "empty hash maintenance repeatedly allocated buckets");
        }
        CheckStorage(state.bytes == 0, "counted hash table leaked memory");
    }
}

void TestHashVariants() {
    std::unordered_set<uint64_t> groups;
    std::unordered_multimap<uint64_t, uint64_t> index;
    groups.reserve(100000);
    index.reserve(100000);
    for (uint64_t i = 0; i < 64; ++i) {
        groups.insert(i);
        index.emplace(i % 4, i);
    }
    const auto* group = &*groups.find(0);
    const auto* entry = &*index.begin();
    TrimHashTable(groups);
    TrimHashTable(index);
    CheckStorage(groups.size() == 64 && groups.bucket_count() <= 256 &&
                 &*groups.find(0) == group && index.size() == 64 &&
                 index.bucket_count() <= 256 && index.count(0) == 16,
                 "set/multimap trimming lost entries or retained peak buckets");
    const auto range = index.equal_range(entry->first);
    CheckStorage(std::any_of(range.first, range.second,
                     [&](const auto& item) { return &item == entry; }),
                 "multimap trimming moved a surviving node");
    groups.clear();
    index.clear();
    TrimHashTable(groups);
    TrimHashTable(index);
    CheckStorage(groups.bucket_count() <= 8 && index.bucket_count() <= 8,
                 "empty set/multimap retained buckets");
}

void TestCapacityStorage() {
    AllocationState state;
    std::vector<size_t, CountingAllocator<size_t>> values{CountingAllocator<size_t>(state)};
    const size_t emptyBytes = state.bytes;
    values.resize(100000);
    values[0] = 42;
    values.resize(64);
    TrimCapacity(values);
    CheckStorage(values.size() == 64 && values.capacity() == 64 && values[0] == 42,
                 "vector trimming lost data or retained the peak");
    const size_t allocations = state.allocations;
    for (size_t pass = 0; pass < 1000; ++pass) TrimCapacity(values);
    CheckStorage(state.allocations == allocations, "stable vector maintenance allocated storage");
    values.clear();
    TrimCapacity(values);
    CheckStorage(state.bytes == emptyBytes && values.capacity() == 0, "empty vector retained storage");

    std::wstring text(100000, L'x');
    text = L"short";
    TrimCapacity(text);
    CheckStorage(text == L"short" && text.capacity() < 32, "short string retained its old allocation");
    text.assign(100000, L'x');
    text.clear();
    TrimCapacity(text);
    CheckStorage(text.empty() && text.capacity() < 32, "empty string retained its old allocation");
}

void TestTableBufferStorage() {
    TableBuffer buffer;
    CheckStorage(!buffer.data() && buffer.size() == 0, "new table buffer allocated memory");
    buffer.reset(16 * 1024 * 1024);
    buffer.data()[0] = 42;
    auto* large = buffer.data();
    buffer.Trim(5 * 1024 * 1024);
    CheckStorage(buffer.data() == large && buffer.data()[0] == 42,
                 "table buffer was resized for a small load fluctuation");
    buffer.Trim(60000);
    CheckStorage(buffer.size() == 60000 + TableBuffer::kSlackBytes,
                 "table buffer retained the previous peak");
    auto* stable = buffer.data();
    for (size_t pass = 0; pass < 1000; ++pass) buffer.Trim(60000 + pass % 100);
    CheckStorage(buffer.data() == stable, "stable table buffer repeatedly allocated memory");
    buffer.Trim(sizeof(DWORD));
    CheckStorage(buffer.size() < 4 * TableBuffer::kInitialBytes, "idle table buffer retained a large allocation");
    buffer.Trim(0);
    CheckStorage(!buffer.data() && buffer.size() == 0, "failed table reads retained the raw buffer");
    buffer.reset(TableBuffer::kInitialBytes);
    CheckStorage(buffer.data() && buffer.size() == TableBuffer::kInitialBytes,
                 "released table buffer could not be reused");
    auto* owned = buffer.data();
    TableBuffer moved = std::move(buffer);
    CheckStorage(moved.data() == owned && !buffer.data() && buffer.size() == 0,
                 "moving the raw buffer lost storage or left a stale size");
    buffer.reset(TableBuffer::kInitialBytes);
    moved = std::move(buffer);
    CheckStorage(moved.data() && !buffer.data() && buffer.size() == 0,
                 "move assignment retained the old raw buffer");
}
} // namespace

// Вне ScopedSnapshotTables вызовы идут в настоящие API Windows: проверка
// сборщика таблиц остаётся реальной. Подменяется только источник таблиц,
// построение снимка и освобождение строк выполняет исходный Monitor.
#define GetExtendedTcpTable StorageGetExtendedTcpTable
#define GetExtendedUdpTable StorageGetExtendedUdpTable
#include "../Monitor.cpp"
#undef GetExtendedUdpTable
#undef GetExtendedTcpTable

struct StorageTestAccess {
    static void TestFlowStore() {
        FlowStore store;
        constexpr ULONGLONG now = 1000000;
        constexpr size_t count = 20000;
        auto& process = store.GroupLocked(0);
        for (size_t i = 0; i < count; ++i) {
            FlowStore::ConnectionRecord connection;
            connection.key = StorageKey(i);
            connection.generation = i + 1;
            connection.state = MIB_TCP_STATE_ESTAB;
            connection.lastActivity = 1;
            connection.systemBacked = i < 64;
            connection.lastSystemSent = 123;
            process.connections.emplace(i + 1, std::move(connection));
        }
        auto* retained = &process.connections.at(1);
        const size_t connectionBuckets = process.connections.bucket_count();
        for (DWORD pid = 10000; pid < 12000; ++pid) store.GroupLocked(pid);
        const size_t processBuckets = store.processes_.bucket_count();
        std::array<size_t, 4> ownerBuckets{};
        std::array<FlowStore::ConnectionOwnerIndex*, 4> indexes{
            &store.ownerIndexes_.tcpV4, &store.ownerIndexes_.tcpV6,
            &store.ownerIndexes_.udpV4, &store.ownerIndexes_.udpV6
        };
        for (size_t category = 0; category < indexes.size(); ++category) {
            for (size_t i = 0; i < count; ++i) {
                auto& owner = (*indexes[category])[StorageKey(
                    i, category < 2 ? Proto::Tcp : Proto::Udp, category % 2 != 0)];
                owner.lastAccessAt = i < 64 ? now : 1;
            }
            ownerBuckets[category] = indexes[category]->bucket_count();
        }
        store.ExpireLocked(now, 1000);
        CheckStorage(store.processes_.size() == 1 &&
                     store.processes_.bucket_count() < processBuckets / 8,
                     "FlowStore retained removed process buckets");
        CheckStorage(process.connections.size() == 64 &&
                     process.connections.bucket_count() < connectionBuckets / 8 &&
                     &process.connections.at(1) == retained && retained->lastSystemSent == 123,
                     "FlowStore retained connection buckets or changed a surviving record");
        for (size_t category = 0; category < indexes.size(); ++category)
            CheckStorage(indexes[category]->size() == 64 &&
                         indexes[category]->bucket_count() < ownerBuckets[category] / 8,
                         "FlowStore retained expired owner buckets");

        // Служебный режим убирает те же owner-индексы без построения UI-снимка.
        store.Enable(false);
        for (auto* index : indexes)
            for (auto& item : *index)
                item.second.lastAccessAt = GetTickCount64() - FlowStore::kInactiveMs - 1000;
        store.Maintain();
        for (auto* index : indexes)
            CheckStorage(index->empty() && index->bucket_count() <= 8,
                         "service maintenance retained expired owner storage");
        store.Enable(true);

        std::array<FlowStore::LocalSocketTable*, 4> sockets{
            &store.localSockets_.tcpV4, &store.localSockets_.tcpV6,
            &store.localSockets_.udpV4, &store.localSockets_.udpV6
        };
        for (size_t category = 0; category < sockets.size(); ++category) {
            for (size_t i = 0; i < count; ++i) {
                const FlowKey key = StorageKey(i, Proto::Tcp, category % 2 != 0);
                (*sockets[category])[MakeIpEndpoint(key.remote, 40000)] = {};
            }
        }
        FlowStore::SystemSnapshot snapshot;
        store.ReplaceSystemSnapshot(snapshot);
        for (auto* table : sockets)
            CheckStorage(table->size() == count, "invalid system snapshot discarded valid socket data");
        snapshot.tcpV4Valid = snapshot.tcpV6Valid = true;
        snapshot.udpV4Valid = snapshot.udpV6Valid = true;
        store.ReplaceSystemSnapshot(snapshot);
        for (auto* table : sockets)
            CheckStorage(table->empty() && table->bucket_count() <= 8,
                         "empty system snapshot retained socket buckets");

        // TakeDisplay использует собственный совмещённый проход удаления.
        for (auto& item : process.connections) {
            item.second.removeAfter = item.first <= 32 ? 0 : 1;
            item.second.systemBacked = item.first <= 32;
        }
        for (size_t i = 64; i < count; ++i) {
            FlowStore::ConnectionRecord connection;
            connection.key = StorageKey(i);
            connection.generation = i + 1;
            connection.removeAfter = 1;
            process.connections.emplace(i + 1, std::move(connection));
        }
        const size_t displayBuckets = process.connections.bucket_count();
        FlowStore::DisplayView display;
        store.TakeDisplay(display);
        CheckStorage(process.connections.size() == 32 &&
                     process.connections.bucket_count() < displayBuckets / 8 &&
                     display.processes.size() == 1 && display.connections.size() == 32,
                     "display maintenance retained buckets after partial expiry");
        for (auto& item : process.connections) item.second.removeAfter = 1;
        store.TakeDisplay(display);
        CheckStorage(store.processes_.empty() && store.processes_.bucket_count() <= 8 &&
                     display.processes.empty() && display.connections.empty(),
                     "display maintenance retained drained process storage");
        store.GroupLocked(0).connections.reserve(count);
        store.processes_.reserve(count);
        store.Reset();
        CheckStorage(store.processes_.empty() && store.processes_.bucket_count() <= 8,
                     "FlowStore reset retained process storage");
        CheckStorage(sizeof(FlowStore::ProcessConnections) < sizeof(FlowStore::ProcessConnectionRecord),
                     "working process record still embeds diagnostic maps");
        std::cout << "process record: working=" << sizeof(FlowStore::ProcessConnections)
                  << ", diagnostic=" << sizeof(FlowStore::ProcessConnectionRecord) << '\n';
    }

    static void TestNdisStorage() {
        constexpr size_t count = 20000;
        for (bool display : {false, true}) {
            FlowStore store;
            for (unsigned pass = 0; pass < 3; ++pass) {
                const ULONGLONG now = GetTickCount64();
                FlowKey firstKey;
                FlowStore::ConnectionRecord* retained = nullptr;
                for (size_t i = 0; i < count; ++i) {
                    FlowKey key = StorageKey(i);
                    key.source = TrafficSource::Ndis;
                    auto* connection = store.NdisConnectionLocked(key);
                    connection->lastActivity = now;
                    connection->driverBacked = true;
                    connection->state = MIB_TCP_STATE_ESTAB;
                    connection->removeAfter = i < 32 ? 0 : 1;
                    if (i == 0) {
                        firstKey = key;
                        retained = connection;
                    }
                }
                const size_t peak = store.ndisConnections_.bucket_count();
                FlowStore::DisplayView view;
                if (display) store.TakeDisplay(view);
                else store.ExpireLocked(now, FlowStore::kInactiveMs);
                CheckStorage(store.ndisConnections_.size() == 32 &&
                             store.ndisConnections_.bucket_count() < peak / 8 &&
                             store.NdisConnectionLocked(firstKey) == retained,
                             "Ndis maintenance retained peak index buckets or moved a live connection");
                const size_t stable = store.ndisConnections_.bucket_count();
                if (display) store.TakeDisplay(view);
                else store.ExpireLocked(now, FlowStore::kInactiveMs);
                CheckStorage(store.ndisConnections_.bucket_count() == stable,
                             "stable Ndis index repeatedly reallocated storage");
                for (auto& item : store.processes_.at(TrafficGroupKey::Ndis(0)).connections)
                    item.second.removeAfter = 1;
                if (display) store.TakeDisplay(view);
                else store.ExpireLocked(now, FlowStore::kInactiveMs);
                CheckStorage(store.ndisConnections_.empty() &&
                             store.ndisConnections_.bucket_count() <= 8 && store.processes_.empty(),
                             "drained Ndis index retained historical storage");
            }
        }
    }

    static void TestMonitor() {
        Monitor monitor;
        constexpr size_t count = 20000;
        monitor.tick_ = 100;
        const auto fill = [&] {
            for (size_t i = 0; i < count; ++i) {
                auto& rule = monitor.ruleCache_[i + 1];
                rule.seenTick = i < 32 ? 100 : 99;
                rule.ruleId = i + 10;
                Monitor::EstatsId id{StorageKey(i), 1234};
                auto& estats = monitor.estatsOn_[id];
                estats.tick = i < 32 ? 97 : 96;
                estats.enabled = true;
                monitor.procOrder_[static_cast<DWORD>(i)].seenTick = i < 32 ? 100 : 99;
            }
        };
        fill();
        const size_t ruleBuckets = monitor.ruleCache_.bucket_count();
        const size_t estatsBuckets = monitor.estatsOn_.bucket_count();
        const size_t orderBuckets = monitor.procOrder_.bucket_count();
        auto* cached = &monitor.ruleCache_.at(1);
        monitor.PruneCaches(true);
        CheckStorage(monitor.ruleCache_.size() == 32 && monitor.estatsOn_.size() == 32 &&
                     monitor.procOrder_.size() == 32 &&
                     monitor.ruleCache_.bucket_count() < ruleBuckets / 8 &&
                     monitor.estatsOn_.bucket_count() < estatsBuckets / 8 &&
                     monitor.procOrder_.bucket_count() < orderBuckets / 8 &&
                     &monitor.ruleCache_.at(1) == cached && cached->ruleId == 10,
                     "Monitor cache pruning retained peak storage or changed live entries");
        const size_t stableBuckets = monitor.ruleCache_.bucket_count();
        for (size_t i = 0; i < 100; ++i) monitor.PruneCaches(true);
        CheckStorage(monitor.ruleCache_.bucket_count() == stableBuckets,
                     "Monitor repeatedly shrank a stable cache");
        monitor.PruneCaches(false);
        CheckStorage(monitor.ruleCache_.empty() && monitor.ruleCache_.bucket_count() <= 8,
                     "disabled rule cache retained buckets");
        ++monitor.tick_;
        monitor.PruneCaches(true);
        CheckStorage(monitor.estatsOn_.empty() && monitor.estatsOn_.bucket_count() <= 8 &&
                     monitor.procOrder_.empty() && monitor.procOrder_.bucket_count() <= 8,
                     "Monitor retained expired EStats or process-order storage");

        fill();
        RuleStore rules;
        monitor.SetRuleStore(&rules);
        CheckStorage(monitor.ruleCache_.empty() && monitor.ruleCache_.bucket_count() <= 8,
                     "switching RuleStore retained cache buckets");
        monitor.ruleCache_[1].ruleId = 42;
        monitor.SetRuleStore(&rules);
        CheckStorage(monitor.ruleCache_.at(1).ruleId == 42, "unchanged RuleStore discarded a live cache");
        monitor.tableBuffer_.reset(16 * 1024 * 1024);
        monitor.estatsOk_ = false;
        monitor.CollectSystemSnapshot(monitor.system_);
        size_t used = 0;
        if (monitor.system_.tcpV4Valid) used = std::max(used,
            offsetof(MIB_TCPTABLE_OWNER_PID, table) + monitor.system_.tcpV4.size() * sizeof(MIB_TCPROW_OWNER_PID));
        if (monitor.system_.tcpV6Valid) used = std::max(used,
            offsetof(MIB_TCP6TABLE_OWNER_PID, table) + monitor.system_.tcpV6.size() * sizeof(MIB_TCP6ROW_OWNER_PID));
        if (monitor.system_.udpV4Valid) used = std::max(used,
            offsetof(MIB_UDPTABLE_OWNER_PID, table) + monitor.system_.udpV4.size() * sizeof(MIB_UDPROW_OWNER_PID));
        if (monitor.system_.udpV6Valid) used = std::max(used,
            offsetof(MIB_UDP6TABLE_OWNER_PID, table) + monitor.system_.udpV6.size() * sizeof(MIB_UDP6ROW_OWNER_PID));
        CheckStorage(monitor.tableBuffer_.size() <= 4 * std::max(
                         TableBuffer::kInitialBytes, used + TableBuffer::kSlackBytes),
                     "real table collection retained the raw buffer peak");
        std::cout << "raw table buffer after collection: " << monitor.tableBuffer_.size() << '\n';

        {
            ScopedSnapshotTables tables;
            // Соединение без трафика не должно исчезать из-за фильтра пассивности.
            monitor.SetShowPassive(true);
            Snapshot snapshot;
            monitor.BuildSnapshot(snapshot, false);
            const DWORD pid = GetCurrentProcessId();
            CheckStorage(!snapshot.displayReady && snapshot.procs.size() == 1 &&
                         snapshot.procs[0].group == TrafficGroupKey::Host(pid) && snapshot.connCount == 1 &&
                         snapshot.conns.empty(),
                         "controlled tray snapshot did not contain exactly one process");
            const auto* previous = snapshot.procs.data();
            for (int pass = 0; pass < 8; ++pass) {
                auto& process = snapshot.procs[0];
                process.name.assign(10000, L'n');
                process.path.assign(20000, L'p');
                CheckStorage(process.name.capacity() >= 10000 && process.path.capacity() >= 20000,
                             "process text fixture did not allocate large buffers");
                monitor.BuildSnapshot(snapshot, false);
                CheckStorage(!snapshot.displayReady && snapshot.procs.size() == 1 &&
                             snapshot.procs.data() == previous && snapshot.procs[0].group == TrafficGroupKey::Host(pid) &&
                             snapshot.connCount == 1 && snapshot.conns.empty(),
                             "controlled tray snapshot did not reuse its process array");
                CheckStorage(process.name.empty() && process.path.empty() &&
                             process.name.capacity() < 32 && process.path.capacity() < 32,
                             "tray snapshot retained process name/path buffers");
            }
        }
        monitor.Stop();
        CheckStorage(!monitor.tableBuffer_.data() && monitor.tableBuffer_.size() == 0 &&
                     monitor.ruleCache_.empty() && monitor.ruleCache_.bucket_count() <= 8 &&
                     monitor.estatsOn_.empty() && monitor.estatsOn_.bucket_count() <= 8 &&
                     monitor.procOrder_.empty() && monitor.procOrder_.bucket_count() <= 8 &&
                     monitor.system_.tcpV4.capacity() == 0 && monitor.system_.tcpV6.capacity() == 0 &&
                     monitor.system_.udpV4.capacity() == 0 && monitor.system_.udpV6.capacity() == 0,
                     "Monitor stop retained buffers or cache buckets");
    }

    static void TestInterfaceIdentity() {
        RuleStore rules;
        const auto interfaces = net::SharedNetworkInterfaces().GetSnapshot();
        CheckStorage(interfaces != nullptr, "interface identity test has no snapshot");
        const auto active = std::find_if(interfaces->interfaces.begin(), interfaces->interfaces.end(),
            [](const auto& entry) { return entry.up && entry.number && !entry.name.empty(); });
        CheckStorage(active != interfaces->interfaces.end(), "interface identity test has no active adapter");
        const BYTE local[]{10, 0, 0, 1}, remote[]{11, 0, 0, 1};
        const FlowKey key = MakeFlowKey(Proto::Tcp, IpAddr::Raw4(local), IpAddr::Raw4(remote), 40000, 443);
        FlowStore::ConnEvent event;
        event.pid = GetCurrentProcessId();
        event.interfaceIndex = active->number;
        event.dir = Dir::Out;
        {
            FlowStore flows;
            const auto generation = flows.NoteConnection(key, event);
            const auto& details = flows.processes_.at(TrafficGroupKey::Host(event.pid)).connections.at(generation).driver;
            CheckStorage(details->interfaceName && *details->interfaceName == active->name,
                         "flow interface identity was not captured from its snapshot");
            const auto name = details->interfaceName;
            for (int pass = 0; pass < 1000; ++pass) flows.NoteConnection(key, event);
            CheckStorage(details->interfaceName == name, "repeated flow events replaced the captured name");
            FlowStore::ConnEvent late = event;
            late.interfaceName = std::make_shared<const std::wstring>(L"Late replacement");
            flows.NoteBlocked(key, late, generation);
            CheckStorage(details->interfaceName == name, "late verdict replaced the original interface identity");
        }

        ScopedSnapshotTables tables;
        FlowStore& flows = FlowStore::Instance();
        const auto oldName = std::make_shared<const std::wstring>(L"Former interface Сеть 网络");
        event.interfaceName = oldName;
        const auto generation = flows.NoteConnection(key, event);
        Rule filtered;
        filtered.scope = RuleScope::Global;
        filtered.conds = CondInterface;
        filtered.interfaceName = active->name;
        filtered.action = RuleAction::Block;
        rules.Add(filtered);
        Rule fallback = filtered;
        fallback.id = 0;
        fallback.conds = CondNone;
        fallback.action = RuleAction::Allow;
        rules.Add(fallback);
        Monitor monitor;
        monitor.estatsOk_ = false;
        monitor.SetShowPassive(true);
        monitor.SetRuleStore(&rules);
        Snapshot snapshot;
        const auto check = [&](uint64_t ruleId, const std::shared_ptr<const std::wstring>& name) {
            monitor.BuildSnapshot(snapshot, true);
            const auto connection = std::find_if(snapshot.conns.begin(), snapshot.conns.end(),
                [&](const auto& item) { return item.flowGeneration == generation; });
            CheckStorage(connection != snapshot.conns.end() && connection->interfaceName == name &&
                         connection->ruleId == ruleId,
                         "monitor reassigned a stored row to the current owner of its IfIndex");
            CheckStorage(monitor.ruleCache_.contains(generation), "interface identity test did not exercise the rule cache");
        };
        check(fallback.id, oldName);
        check(fallback.id, oldName);
        event.interfaceName = std::make_shared<const std::wstring>(active->name);
        flows.NoteConnection(key, event);
        check(filtered.id, event.interfaceName);
        event.interfaceName = std::make_shared<const std::wstring>();
        flows.NoteConnection(key, event);
        check(fallback.id, event.interfaceName);
        monitor.Stop();
    }

    static void TestWfpFlagMonitorCache() {
        ScopedSnapshotTables tables;
        FlowStore& flows = FlowStore::Instance();
        const BYTE local[]{10, 0, 0, 1}, remote[]{11, 0, 0, 1};
        const FlowKey key = MakeFlowKey(Proto::Tcp, IpAddr::Raw4(local), IpAddr::Raw4(remote), 40000, 443);
        RuleStore rules;
        Rule filtered;
        filtered.scope = RuleScope::Global;
        filtered.conds = CondWfpFlags;
        filtered.conditionFlags = 1;
        filtered.action = RuleAction::Block;
        rules.Add(filtered);
        Rule fallback = filtered;
        fallback.conds = CondNone;
        fallback.action = RuleAction::Allow;
        rules.Add(fallback);
        Monitor monitor;
        monitor.estatsOk_ = false;
        monitor.SetShowPassive(true);
        monitor.SetRuleStore(&rules);
        Snapshot snapshot;
        uint64_t generation = 0;
        const auto check = [&](uint64_t ruleId, std::optional<uint32_t> flags) {
            monitor.BuildSnapshot(snapshot, true);
            const auto connection = std::find_if(snapshot.conns.begin(), snapshot.conns.end(),
                [&](const auto& item) { return item.key == key; });
            CheckStorage(connection != snapshot.conns.end() && connection->conditionFlags == flags &&
                         connection->ruleId == ruleId,
                         "monitor lost current WFP flags or reused a cached match for another mask");
            if (generation)
                CheckStorage(connection->flowGeneration == generation,
                             "monitor flag cache test unexpectedly changed the flow generation");
            generation = connection->flowGeneration;
            CheckStorage(monitor.ruleCache_.contains(generation),
                         "WFP flags test did not exercise the monitor rule cache");
        };
        // Строка только из таблицы ОС не имеет поля condition_flags.
        check(fallback.id, std::nullopt);
        check(fallback.id, std::nullopt);
        FlowStore::ConnEvent event;
        event.pid = GetCurrentProcessId();
        event.dir = Dir::Out;
        for (uint32_t flags : {1u, 2u, 3u, 0u, 0x80000001u}) {
            event.conditionFlags = flags;
            flows.NoteConnection(key, event);
            check((flags & 1u) ? filtered.id : fallback.id, flags);
            check((flags & 1u) ? filtered.id : fallback.id, flags);
        }
        event.conditionFlags = 0;
        flows.NoteConnection(key, event);
        filtered.conditionFlags = 0;
        CheckStorage(rules.Update(filtered), "cannot update WFP monitor filter");
        check(filtered.id, 0);
        event.conditionFlags.reset();
        flows.NoteConnection(key, event);
        check(fallback.id, std::nullopt);
        monitor.Stop();
    }

    static void CheckRuleIndex(const RuleStore& store) {
        size_t enabled = 0;
        size_t indexed = store.idxGlobal_.size() + store.idxPostApp_.size();
        for (const auto& item : store.idxApp_)
            for (const auto& bucket : item.second) indexed += bucket.items.size();
        for (const Rule& rule : store.rules_) if (rule.enabled) ++enabled;
        CheckStorage(store.idxCandidates_.size() == enabled && indexed == enabled,
                     "compiled rules have spare storage or missing candidates");
        CheckStorage(store.idxRuleNames_.size() == store.rules_.size(),
                     "compiled names retained spare storage or lost rule positions");
        for (size_t i = 0; i < store.rules_.size(); ++i) {
            const auto& name = store.idxRuleNames_[i];
            CheckStorage(store.rules_[i].enabled ? name && *name == store.rules_[i].name : !name,
                         "compiled name refers to a changed, disabled or deleted rule");
        }
        for (const auto& candidate : store.idxCandidates_)
            CheckStorage(candidate.idx < store.rules_.size() && store.rules_[candidate.idx].enabled,
                         "compiled candidate refers to a disabled or deleted rule");
        CheckStorage(store.rules_.empty() ? store.rules_.capacity() == 0
                                          : store.rules_.capacity() < store.rules_.size() * 4,
                     "rule vector retained its historical peak");
    }

    static void TestRules() {
        RuleStore store;
        std::vector<Rule> list(4096);
        for (Rule& rule : list) {
            rule.name = L"storage test";
            rule.autoName = false;
            rule.proto = Proto::Tcp;
        }
        store.ReplaceGlobals(list);
        CheckRuleIndex(store);
        CheckStorage(store.idxGlobal_.size() == list.size() && store.idxPostApp_.empty() && store.idxApp_.empty(),
                     "global-only rule index allocated unused groups");
        const size_t largeIdBuckets = store.idxId_.bucket_count();
        list.resize(32);
        store.ReplaceGlobals(list);
        CheckRuleIndex(store);
        CheckStorage(store.idxId_.bucket_count() < largeIdBuckets / 8,
                     "replacing a rule group retained ID buckets");
        store.Clear();
        CheckRuleIndex(store);
        CheckStorage(store.idxId_.bucket_count() <= 8 && store.idxApp_.bucket_count() <= 8,
                     "clearing rules retained index buckets");

        // Заполняем много групп без тысяч промежуточных сортировок. Дальнейшая
        // нормализация и перестройка используют обычный производственный путь.
        for (size_t i = 0; i < 8192; ++i) {
            Rule rule;
            rule.id = i + 1;
            rule.appPath = L"C:\\Storage\\app" + std::to_wstring(i / 2) + L".exe";
            rule.name = L"app storage test";
            rule.autoName = false;
            rule.enabled = i % 3 != 0;
            store.rules_.push_back(std::move(rule));
        }
        store.nextId_ = 8193;
        store.NormalizeLocked();
        store.SaveLocked();
        CheckRuleIndex(store);
        const size_t largeAppBuckets = store.idxApp_.bucket_count();
        const std::wstring keptPath = store.rules_.back().appPath;
        const uint64_t keptId = store.rules_.back().id;
        store.rules_.erase(store.rules_.begin(), store.rules_.end() - 32);
        store.NormalizeLocked();
        store.SaveLocked();
        CheckRuleIndex(store);
        CheckStorage(store.idxApp_.bucket_count() < largeAppBuckets / 8 && store.Exists(keptId),
                     "rule rebuild retained removed application buckets or lost ID lookup");
        MatchQuery query;
        query.appPath = keptPath;
        const std::wstring folded = FoldCaseCopy(keptPath);
        PrepareMatchAppPath(query, folded, HashFoldedText(folded));
        const auto candidates = store.FindAppLocked(query);
        CheckStorage(!candidates.empty(), "compact app index lost a prepared path");
        const auto* reused = store.idxCandidates_.data();
        CheckStorage(store.MovePriority(keptId, -1), "rule priority could not be changed after compaction");
        CheckStorage(store.idxCandidates_.data() == reused,
                     "reordering rules reallocated an unchanged candidate array");
        RuleAction action;
        CheckStorage(store.MatchVerdict(query, action), "matching failed after compact rule rebuild");
        store.Clear();
        CheckRuleIndex(store);

        Rule large;
        large.name.assign(100000, L'x');
        large.autoName = false;
        large.appPath = L"C:\\Storage\\large.exe";
        large.appName.assign(100000, L'x');
        large.conds = CondProto | CondRemotePort | CondLocalPort;
        large.remotePorts.resize(4096, PortItem{443, 443});
        large.localPorts.resize(4096, PortItem{40000, 40000});
        store.Add(large);
        Rule reduced = large;
        reduced.name = L"small";
        reduced.appName = L"small.exe";
        reduced.remotePorts.resize(1);
        reduced.localPorts.resize(1);
        CheckStorage(store.Update(reduced), "could not reduce a large rule");
        const Rule* stored = store.FindByIdLocked(reduced.id);
        CheckStorage(stored && stored->name.capacity() < 32 && stored->appName.capacity() < 32 &&
                     stored->remotePorts.capacity() == 1 && stored->localPorts.capacity() == 1,
                     "updating a rule retained old strings or condition vectors");
        reduced.SetProto(Proto::Icmp);
        CheckStorage(store.Update(reduced), "could not change a large rule protocol");
        stored = store.FindByIdLocked(reduced.id);
        CheckStorage(stored && stored->remotePorts.capacity() == 0 && stored->localPorts.capacity() == 0,
                     "incompatible rule conditions retained cleared storage");
        store.Clear();
        CheckRuleIndex(store);

        store.ReplaceGlobals(list);
        std::wstring error;
        CheckStorage(!store.LoadOnce(L"?:\\invalid-storage-test\\rules.db", error) && store.Count() == 0,
                     "failed rules load did not clear the previous set");
        CheckRuleIndex(store);
        CheckStorage(store.idxId_.bucket_count() <= 8 && store.idxApp_.bucket_count() <= 8,
                     "failed rules load retained old index storage");
    }
};

int main() {
    try {
        SetUiLang(UiLang::English);
        TestHashStorage();
        TestHashVariants();
        TestCapacityStorage();
        TestTableBufferStorage();
        StorageTestAccess::TestFlowStore();
        StorageTestAccess::TestNdisStorage();
        StorageTestAccess::TestMonitor();
        StorageTestAccess::TestInterfaceIdentity();
        StorageTestAccess::TestWfpFlagMonitorCache();
        StorageTestAccess::TestRules();
        std::cout << "storage retention tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
