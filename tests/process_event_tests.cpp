#include "PortmasterKextClient.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace FirewallX { Mode g_runMode = Mode::Desktop; }

namespace pmkext {
struct KextClientTestAccess {
    static void Feed(KextClient& client, const std::vector<uint8_t>& wire, size_t fragment) {
        size_t offset = 0;
        while (offset < wire.size()) {
            if (!client.ensureWritable(1)) throw std::runtime_error("buffer allocation failed");
            const size_t count = (std::min)({fragment, wire.size() - offset,
                                          client.buffer_.Capacity() - client.tail_});
            std::memcpy(client.buffer_.Data() + client.tail_, wire.data() + offset, count);
            client.tail_ += count;
            client.dispatchAvailable();
            offset += count;
        }
    }
};

struct ProcessTableTestAccess {
    static std::array<size_t, 4> Buckets(const ProcessTable& table) {
        std::lock_guard lock(table.mutex_);
        return {table.entries_.bucket_count(), table.retired_.bucket_count(),
                table.paths_.bucket_count(), table.lateLineages_.bucket_count()};
    }

    static const void* EntryAddress(const ProcessTable& table, uint64_t pid) {
        std::lock_guard lock(table.mutex_);
        return &table.entries_.at(pid);
    }

    static size_t RetiredSize(const ProcessTable& table) {
        std::lock_guard lock(table.mutex_);
        return table.retired_.size();
    }

    static size_t LateSize(const ProcessTable& table) {
        std::lock_guard lock(table.mutex_);
        return table.lateLineages_.size();
    }

    static void MakeLateSweepDue(ProcessTable& table) {
        std::lock_guard lock(table.mutex_);
        table.lateSweptAt_ = GetTickCount64() - ProcessTable::kLateSweepMs;
    }
};
}

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

size_t queries = 0;
std::wstring Resolve(uint64_t pid, DWORD& error) {
    ++queries;
    error = pid == 77 ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    return pid == 77 ? std::wstring() : L"C:\\apps\\shared.exe";
}

pmkext::ProcessInfo Get(const pmkext::ProcessTable& table, uint64_t pid) {
    pmkext::ProcessInfo result;
    Check(table.find(pid, result), "process missing");
    return result;
}

void Create(pmkext::ProcessTable& table, uint64_t pid, uint64_t parent) {
    const pmkext::ProcessCreated value{pid, parent};
    table.applyCreated(&value, 1);
}

void Exit(pmkext::ProcessTable& table, uint64_t pid) {
    const pmkext::ProcessTerminated value{pid};
    table.applyTerminated(&value, 1);
}

void TestTreeAndPaths() {
    queries = 0;
    pmkext::ProcessTable table(Resolve);
    // Начальный снимок не обязан быть упорядочен по родству.
    const pmkext::ProcessCreated values[] = {{30, 20}, {40, 10}, {20, 10}, {10, 10}};
    table.applyCreated(values, 4);
    const auto root = Get(table, 10);
    Check(table.size() == 4 && table.pathCount() == 1 && queries == 4,
          "unordered baseline or path interning failed");
    Check(root.children == 2 && Get(table, 20).children == 1,
          "child-before-parent links lost");
    Check(root.path == Get(table, 20).path && root.path == Get(table, 30).path &&
          *root.path == L"C:\\apps\\shared.exe", "paths were duplicated");

    for (unsigned i = 0; i < 100; ++i) table.applyCreated(values, 4);
    Check(queries == 4 && Get(table, 10).children == 2,
          "duplicate snapshots resolved paths or double-counted children");
    Exit(table, 10);
    Exit(table, 20);
    Check(Get(table, 10).terminated && Get(table, 20).terminated && table.size() == 4,
          "dead ancestors of live descendants were removed");
    // Дубли живого снимка проверены выше; Create после Terminated означает
    // новый экземпляр PID и проверяется отдельно в тесте переиспользования.
    Exit(table, 40);
    Check(Get(table, 10).children == 1 && table.size() == 3,
          "sibling exit removed a retained ancestor");
    Exit(table, 30);
    Check(table.size() == 0 && table.pathCount() == 0,
          "last descendant did not prune the dead ancestor chain");
    Check(root.path && *root.path == L"C:\\apps\\shared.exe",
          "returned path invalidated by cleanup");
    Exit(table, 10);
    Exit(table, 999);
    Check(table.size() == 0, "unknown exits allocated records");
}

void TestMissingParentsAndFailedPaths() {
    queries = 0;
    pmkext::ProcessTable table(Resolve);
    Create(table, 77, 9);
    auto missing = Get(table, 9);
    Check(!missing.observed && missing.terminated && missing.children == 1,
          "missing parent placeholder is incorrect");
    const auto denied = Get(table, 77);
    Check(!denied.path && denied.path_error == ERROR_ACCESS_DENIED && queries == 1,
          "failed path query was not retained");
    for (unsigned i = 0; i < 20; ++i) Create(table, 77, 9);
    Check(queries == 1, "failed path queries were retried");
    Exit(table, 77);
    Check(table.size() == 0 && table.pathCount() == 0,
          "unobserved dead parent leaked after child exit");

    Create(table, 11, 0);
    Create(table, 0, 0);
    Check(table.size() == 2 && Get(table, 0).children == 1 && Get(table, 0).observed,
          "PID zero confused with an absent parent");
    Exit(table, 11);
    Check(table.size() == 1 && !Get(table, 0).terminated,
          "live parent deleted with child");
    Exit(table, 0);
    Check(table.size() == 0, "self-parent root cannot be removed");

    constexpr uint64_t large = 0x12345678abcdef00ULL;
    Create(table, large, large);
    Check(Get(table, large).pid == large, "PID truncated to DWORD in storage");
    const auto copy = table.snapshot();
    Check(copy.size() == 1 && copy[0].pid == large, "on-demand snapshot is incorrect");
    table.clear();
    Check(table.size() == 0 && table.pathCount() == 0 && *copy[0].path == L"C:\\apps\\shared.exe",
          "clear invalidated returned data or retained the table");
}

void TestDeepChain() {
    queries = 0;
    pmkext::ProcessTable table(Resolve);
    constexpr uint64_t count = 40000;
    // Обратный порядок проверяет placeholders и стабильность ссылок при rehash.
    for (uint64_t i = count; i != 0; --i) Create(table, i, i == 1 ? 1 : i - 1);
    Check(table.size() == count && table.pathCount() == 1 && queries == count,
          "large baseline is incorrect");
    for (uint64_t i = 1; i < count; ++i) Exit(table, i);
    Check(table.size() == count, "chain pruned before the last live descendant exited");
    Exit(table, count);
    Check(table.size() == 0 && table.pathCount() == 0,
          "iterative deep-chain cleanup failed");
}

void TestConcurrentReaders() {
    pmkext::ProcessTable table(Resolve);
    std::atomic<bool> done{false};
    std::atomic<bool> valid{true};
    std::thread reader([&] {
        while (!done.load(std::memory_order_acquire)) {
            const auto snapshot = table.snapshot();
            for (const auto& entry : snapshot)
                if (entry.path && *entry.path != L"C:\\apps\\shared.exe") valid.store(false);
            pmkext::ProcessInfo info;
            if (table.find(100, info) && info.pid != 100) valid.store(false);
        }
    });
    for (uint64_t i = 100; i < 1100; ++i) {
        Create(table, i, i);
        Exit(table, i);
    }
    done.store(true, std::memory_order_release);
    reader.join();
    Check(valid.load() && table.size() == 0, "concurrent reads corrupted process state");
}

void TestCollectionDisable() {
    queries = 0;
    pmkext::ProcessTable table(Resolve);
    Create(table, 10, 10);
    Check(queries == 1 && table.size() == 1, "local collection did not start");
    table.setEnabled(false);
    Check(!table.enabled() && table.size() == 0 && table.pathCount() == 0,
          "client connect did not clear the local table and paths");
    const pmkext::ProcessCreated created{20, 10};
    const pmkext::ProcessTerminated terminated{20};
    for (unsigned i = 0; i < 1000; ++i) {
        Check(!table.applyCreated(&created, 1) && !table.applyTerminated(&terminated, 1),
              "disabled table accepted a process record");
    }
    Check(queries == 1 && table.size() == 0 && table.pathCount() == 0,
          "forwarding mode queried paths or repopulated the service table");
    table.setEnabled(true);
    Check(table.enabled() && table.size() == 0, "resume reused the old inventory");
    Create(table, 30, 30);
    pmkext::ProcessInfo old;
    Check(queries == 2 && table.size() == 1 && !table.find(10, old) && !table.find(20, old),
          "fresh collection retained a previous session's PID");
}

HANDLE resolverEntered = nullptr;
HANDLE resolverRelease = nullptr;
std::atomic<unsigned> blockingQueries{0};
std::atomic<bool> blockingValid{true};
std::wstring BlockingResolve(uint64_t, DWORD& error) {
    ++blockingQueries;
    SetEvent(resolverEntered);
    if (WaitForSingleObject(resolverRelease, 3000) != WAIT_OBJECT_0) blockingValid.store(false);
    error = ERROR_SUCCESS;
    return L"C:\\apps\\shared.exe";
}

void TestDisableDuringResolution() {
    pmkext::detail::EventHandle entered;
    pmkext::detail::EventHandle release;
    Check(entered.h && release.h, "cannot create resolver synchronization events");
    resolverEntered = entered.h;
    resolverRelease = release.h;
    blockingQueries.store(0);
    blockingValid.store(true);
    pmkext::ProcessTable table(BlockingResolve);
    std::thread writer([&] { Create(table, 10, 10); });
    const bool resolving = WaitForSingleObject(entered.h, 3000) == WAIT_OBJECT_0;
    // Запрет должен дождаться текущего запроса пути и удалить его результат.
    std::thread connected([&] { table.setEnabled(false); });
    SetEvent(release.h);
    writer.join();
    connected.join();
    Check(resolving && blockingValid.load() && blockingQueries.load() == 1 &&
          table.size() == 0 && table.pathCount() == 0 && !table.enabled(),
          "in-flight path lookup repopulated the cleared service table");
    Create(table, 20, 20);
    Check(blockingQueries.load() == 1 && table.size() == 0,
          "path resolver called after disabling collection");
}

struct Observation {
    pmkext::KextClient* client = nullptr;
    unsigned created = 0;
    unsigned terminated = 0;
    unsigned raw = 0;
    bool forward = false;
    bool valid = true;
} observed;

void OnCreated(const pmkext::ProcessCreated* values, uint32_t count) noexcept {
    ++observed.created;
    for (uint32_t i = 0; i < count; ++i) {
        pmkext::ProcessInfo info;
        observed.valid &= observed.client->processes().find(values[i].pid, info) &&
                          info.parent_pid == values[i].parent_pid;
    }
}

void OnTerminated(const pmkext::ProcessTerminated*, uint32_t) noexcept {
    ++observed.terminated;
}

bool Forward(void*, const uint8_t* bytes, uint32_t size) noexcept {
    ++observed.raw;
    // При пересылке служба не должна ни хранить PID, ни вызывать callbacks.
    if (observed.forward && size > 5 && (bytes[0] == 9 || bytes[0] == 10))
        observed.valid &= observed.client->processes().size() == 0 &&
                          observed.client->processes().pathCount() == 0;
    return observed.forward;
}

void Store(std::vector<uint8_t>& bytes, uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) {
        bytes.push_back(static_cast<uint8_t>(value));
        value >>= 8;
    }
}

std::vector<uint8_t> CreatedRecord(uint64_t pid, uint64_t parent) {
    std::vector<uint8_t> bytes{9, 16, 0, 0, 0};
    Store(bytes, pid, 8);
    Store(bytes, parent, 8);
    return bytes;
}

void TestWireAndForwarding() {
    static_assert(static_cast<uint8_t>(pmkext::CommandType::StartProcessMonitoring) == 9);
    static_assert(pmkext::IOCTL_START_PROCESS_MONITORING == 0x9c40e00c);
    for (const bool forward : {false, true}) {
        pmkext::KextClient client;
        observed = {};
        observed.client = &client;
        observed.forward = forward;
        client.onProcessCreated = OnCreated;
        client.onProcessTerminated = OnTerminated;
        client.onRawRecord = Forward;
        const uint64_t pid = GetCurrentProcessId();
        const auto wire = CreatedRecord(pid, pid);
        for (unsigned i = 0; i < 3; ++i)
            pmkext::KextClientTestAccess::Feed(client, wire, 1);
        if (forward) {
            Check(observed.created == 0 && observed.raw == 3 && observed.valid &&
                  client.processes().size() == 0 && client.processes().pathCount() == 0,
                  "forwarded process records were also collected locally");
            std::vector<uint8_t> exit{10, 8, 0, 0, 0};
            Store(exit, pid, 8);
            pmkext::KextClientTestAccess::Feed(client, exit, 2);
            Check(observed.terminated == 0 && observed.raw == 4 && observed.valid,
                  "forwarded exit invoked the local callback");
            client.setProcessEventsEnabled(false);
            client.dispatchOne(pmkext::InfoType::ProcessCreated, wire.data() + 5, 16);
            client.dispatchOne(pmkext::InfoType::ProcessTerminated, exit.data() + 5, 8);
            client.dispatchOne(pmkext::InfoType::ProcessCreated, nullptr, 0);
            Check(observed.created == 0 && observed.terminated == 0 && client.processes().size() == 0,
                  "disabled local callback/table accepted an in-flight record");
            client.setProcessEventsEnabled(true);
            observed.forward = false;
            pmkext::KextClientTestAccess::Feed(client, wire, 1);
            Check(observed.created == 1 && client.processes().size() == 1,
                  "local collection did not resume after forwarding ended");
            continue;
        }
        const auto process = Get(client.processes(), pid);
        Check(process.path && !process.path->empty() && process.path_error == ERROR_SUCCESS,
              "real process image path could not be queried");
        Check(observed.created == 3 && observed.raw == 3 && observed.valid &&
              client.processes().size() == 1 && client.processes().pathCount() == 1,
              "fragmented records, repeat snapshots or raw forwarding failed");
        std::vector<uint8_t> exit{10, 8, 0, 0, 0};
        Store(exit, pid, 8);
        pmkext::KextClientTestAccess::Feed(client, exit, 2);
        Check(observed.terminated == 1 && client.processes().size() == 0,
              "termination frame failed");
        client.dispatchOne(pmkext::InfoType::ProcessCreated, nullptr, 0);
        client.dispatchOne(pmkext::InfoType::ProcessTerminated, nullptr, 0);
        Check(observed.created == 4 && observed.terminated == 2,
              "empty process batch rejected");
        const uint8_t invalid[33]{};
        for (uint32_t size = 1; size <= sizeof(invalid); ++size) {
            if (size % 16) client.dispatchOne(pmkext::InfoType::ProcessCreated, invalid, size);
            if (size % 8) client.dispatchOne(pmkext::InfoType::ProcessTerminated, invalid, size);
        }
        client.dispatchOne(pmkext::InfoType::ProcessCreated, nullptr, 16);
        client.dispatchOne(pmkext::InfoType::ProcessTerminated, nullptr, 8);
        Check(observed.created == 4 && observed.terminated == 2 && client.processes().size() == 0,
              "malformed process batch partially applied");
        client.clearProcessEvents();
        std::vector<uint8_t> batch{9, 32, 0, 0, 0};
        Store(batch, pid, 8);
        Store(batch, 4, 8);
        Store(batch, 4, 8);
        Store(batch, 4, 8);
        pmkext::KextClientTestAccess::Feed(client, batch, 3);
        Check(observed.created == 5 && observed.valid && client.processes().size() == 2 &&
              Get(client.processes(), 4).children == 1,
              "count-free multi-entry creation batch failed");
        std::vector<uint8_t> exits{10, 16, 0, 0, 0};
        Store(exits, 4, 8);
        Store(exits, pid, 8);
        pmkext::KextClientTestAccess::Feed(client, exits, 3);
        Check(observed.terminated == 3 && client.processes().size() == 0,
              "multi-entry exit batch did not prune the parent");
        pmkext::KextClientTestAccess::Feed(client, wire, 7);
        client.close();
        Check(client.processes().size() == 0 && client.processes().pathCount() == 0,
              "closed session retained its process inventory");
    }
}

void TestDefaultResolverFailures() {
    pmkext::ProcessTable table;
    Create(table, 0, 0);
    Create(table, 4, 0);
    constexpr uint64_t tooLarge = 0x1234567800000000ULL;
    Create(table, tooLarge, tooLarge);
    Check(!Get(table, 0).path && Get(table, 0).path_error == ERROR_INVALID_PARAMETER,
          "idle process path failure missing");
    Check(Get(table, 4).path && Get(table, 4).path->find(L"ntoskrnl.exe") != std::wstring::npos,
          "System kernel image path missing");
    Check(!Get(table, tooLarge).path && Get(table, tooLarge).path_error == ERROR_INVALID_PARAMETER,
          "64-bit PID narrowed before path lookup");
}
}

#include "process_inheritance_tests.h"
#include "process_storage_tests.h"

int main() {
    try {
        TestProcessStorageRetention();
        TestRetiredProcessStorageRetention();
        TestLateLineageStorageRetention();
        TestProcessInheritanceCache();
        TestProcessInheritanceLateAncestry();
        TestProcessInheritancePidReuse();
        TestProcessInheritanceLateRetained();
        TestProcessInheritanceConcurrentRelease();
        TestProcessInheritanceSharedRetainedCache();
        TestTreeAndPaths();
        TestMissingParentsAndFailedPaths();
        TestDeepChain();
        TestConcurrentReaders();
        TestCollectionDisable();
        TestDisableDuringResolution();
        TestWireAndForwarding();
        TestDefaultResolverFailures();
        std::cout << "Process events tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
