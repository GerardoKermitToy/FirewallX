#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace DebugCounters {

// Порядок строк постоянен: секундное обновление меняет только значения.
enum Id : size_t {
    FlowProcesses, FlowConnections,
    OwnerTcpV4, OwnerTcpV6, OwnerUdpV4, OwnerUdpV6,
    LocalTcpV4, LocalTcpV6, LocalUdpV4, LocalUdpV6,
    PendingGroups, PendingIndex, WaitingRequests,
    Verdicts, VerdictExpiry, TlsAssemblies, TlsExpiry, QuicStates,
    Rules, RuleIds, RuleCandidates, RuleApps,
    CachedProcesses, CachedIcons, SystemProcesses,
    SnapshotProcesses, SnapshotConnections, TreeRows,
    ConnectionText, RuleText, ExpansionOverrides, AskQueue,
    FlowNdisConnections,
    RuleInheritanceBuckets, RuleInheritanceSettings, RuleNameReferences,
    RuleInterfaceCandidates,
    ProcessEntries, ProcessRetired, ProcessLateLineages, ProcessPaths,
    Count
};

struct Snapshot {
    // Пустое значение означает занятую блокировку, а не нулевой размер.
    std::array<std::optional<uint64_t>, Count> values{};
};

} // namespace DebugCounters
