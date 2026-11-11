#include "Rules.h"
#include "SystemInfo.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <thread>

namespace bench {

constexpr size_t kProcesses = 1000;
constexpr size_t kSharedProcesses = 500;
constexpr size_t kApps = 100;
constexpr size_t kQueries = 1000000;
constexpr DWORD kFirstPid = 1000000;
constexpr uint32_t kSeed = 0x5EED2026;
constexpr size_t kNoParent = kProcesses;

struct Process {
    size_t path = 0;
    size_t parent = kNoParent;
    ProcessPathRef info;
    std::vector<ServiceEntry> services;
};

std::array<Process, kProcesses> processes;
std::vector<std::wstring> paths;
std::vector<ServiceEntry> serviceRows;
size_t scmCalls = 0;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

DWORD Pid(size_t index) { return kFirstPid + static_cast<DWORD>(index); }

std::wstring Resolve(uint64_t pid, DWORD& error) {
    if (pid < kFirstPid || pid >= kFirstPid + kProcesses) {
        error = ERROR_NOT_FOUND;
        return {};
    }
    error = ERROR_SUCCESS;
    return paths[processes[static_cast<size_t>(pid - kFirstPid)].path];
}

SC_HANDLE WINAPI OpenManager(LPCWSTR, LPCWSTR, DWORD) {
    return reinterpret_cast<SC_HANDLE>(1);
}

BOOL WINAPI CloseManager(SC_HANDLE) { return TRUE; }

BOOL WINAPI Enumerate(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE buffer,
                     DWORD bytes, LPDWORD needed, LPDWORD returned,
                     LPDWORD resume, LPCWSTR) {
    ++scmCalls;
    *needed = *returned = 0;
    const size_t required = serviceRows.size() * sizeof(ENUM_SERVICE_STATUS_PROCESSW);
    if (bytes < required) {
        *needed = static_cast<DWORD>(required);
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    auto* rows = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer);
    for (size_t i = 0; i < serviceRows.size(); ++i) {
        rows[i] = {};
        rows[i].lpServiceName = serviceRows[i].name.data();
        rows[i].lpDisplayName = serviceRows[i].display.data();
        rows[i].ServiceStatusProcess.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
        rows[i].ServiceStatusProcess.dwCurrentState = SERVICE_RUNNING;
        rows[i].ServiceStatusProcess.dwProcessId = serviceRows[i].pid;
    }
    *returned = static_cast<DWORD>(serviceRows.size());
    *resume = 0;
    return TRUE;
}

} // namespace bench

// Подменяется только источник данных SCM. Публикация и чтение runtime-снимка
// остаются настоящими; системные службы тест не открывает и не изменяет.
#define OpenSCManagerW bench::OpenManager
#define CloseServiceHandle bench::CloseManager
#define EnumServicesStatusExW bench::Enumerate
#include "../ServiceInfo.cpp"
#undef EnumServicesStatusExW
#undef CloseServiceHandle
#undef OpenSCManagerW

namespace bench {

struct Expected {
    uint64_t id = 0;
    RuleAction action = RuleAction::Allow;
    std::wstring_view name;
    bool service = false;
    bool inherited = false;
};

struct Stats {
    uint64_t hits = 0;
    uint64_t checksum = 0;
    uint64_t nameChars = 0;
};

struct Measurement {
    double wallMs = 0;
    double userMs = 0;
    double kernelMs = 0;
    uint64_t cycles = 0;
    Stats stats;
};

using Groups = std::array<std::vector<Rule>, kApps>;

IpAddr V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    const uint8_t bytes[] = {a, b, c, d};
    return IpAddr::Raw4(bytes);
}

IpAddr Remote(size_t app, size_t rule, uint8_t host) {
    if (rule % 4 != 3)
        return V4(198, 18, static_cast<uint8_t>(app * 2 + rule % 2), host);
    uint8_t bytes[16] = {0x20, 0x01, 0x0d, 0xb8};
    bytes[5] = static_cast<uint8_t>(app);
    bytes[7] = static_cast<uint8_t>(rule);
    bytes[15] = host;
    return IpAddr::Raw6(bytes);
}

IpAddr Local(bool v6, uint8_t host) {
    if (!v6) return V4(192, 0, 2, host);
    uint8_t bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff};
    bytes[15] = host;
    return IpAddr::Raw6(bytes);
}

std::wstring ServiceName(size_t id) {
    static const wchar_t* const names[] = {
        L"BenchDnsCache", L"BenchTimeSync", L"BenchUpdate", L"BenchTelemetry",
        L"BenchBackup", L"BenchDiscovery", L"BenchPrint", L"BenchRpcHost"
    };
    return std::wstring(names[id % std::size(names)]) + L"_" + std::to_wstring(id);
}

void BuildProcesses(pmkext::ProcessTable& table) {
    paths.reserve(550);
    for (size_t i = 0; i < 550; ++i)
        paths.push_back(L"C:\\Synthetic\\Suite_" + std::to_wstring(i / 25) +
                        L"\\Application_" + std::to_wstring(i) + L".exe");
    std::mt19937 rng(kSeed);
    for (size_t i = 0; i < kProcesses; ++i)
        processes[i].path = i < kSharedProcesses ? i / 10 : i - 450;

    // Пять корней, по четыре включённых источника на ветвь: старейший важнее.
    for (size_t i = 500; i < 520; ++i)
        processes[i].parent = i < 505 ? kNoParent : i - 5;
    for (size_t i = 520; i < 540; ++i)
        processes[i].parent = 505 + (i - 520) % 15;
    for (size_t i = 540; i < 550; ++i)
        processes[i].parent = kNoParent;
    for (size_t i = 0; i < 500; ++i) {
        if (i % 10 == 0) processes[i].parent = kNoParent;
        else if (i % 3 == 0) processes[i].parent = 520 + rng() % 20;
        else processes[i].parent = 500 + rng() % 20;
    }
    for (size_t i = 550; i < kProcesses; ++i) {
        if (i % 7 == 0) processes[i].parent = 520 + rng() % 20;
        else if (i == 550 || i % 11 == 0) processes[i].parent = 500 + rng() % 20;
        else processes[i].parent = i - 1;
    }

    std::vector<pmkext::ProcessCreated> created;
    created.reserve(kProcesses);
    auto& cache = detail::aliveCache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    const ULONGLONG now = GetTickCount64();
    cache.swept = now;
    for (size_t i = 0; i < kProcesses; ++i) {
        auto& process = processes[i];
        const DWORD pid = Pid(i);
        const size_t parent = process.parent;
        created.push_back({pid, parent == kNoParent ? pid : Pid(parent)});
        // Невзведённое событие моделирует живой объект ожидания. Сохраняется
        // реальная цена WaitForSingleObject, но 1000 процессов ОС не создаются.
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        Check(event != nullptr, "CreateEvent failed");
        auto owner = std::make_shared<const ProcessHandleInfo>(event, pid, true);
        process.info = std::make_shared<const ProcessPathInfo>(paths[process.path], owner);
        auto& entry = cache.map[pid];
        entry.process = owner;
        entry.path = process.info;
        entry.probed = entry.touched = now;
        entry.alive = true;
        if (i % 5 != 0) {
            const size_t cohort = process.path % 12;
            for (size_t j = 0; j < 1 + i % 3; ++j) {
                ServiceEntry service;
                service.name = ServiceName(cohort * 4 + (i + j) % 4);
                service.display = service.name;
                service.pid = pid;
                service.state = SERVICE_RUNNING;
                service.type = SERVICE_WIN32_SHARE_PROCESS;
                process.services.push_back(service);
                serviceRows.push_back(std::move(service));
            }
        }
    }
    std::shuffle(created.begin(), created.end(), rng);
    Check(table.applyCreated(created.data(), static_cast<uint32_t>(created.size())),
          "process table setup failed");
    Check(table.size() == kProcesses && table.pathCount() == paths.size(),
          "unexpected process/path count");
    // Публикация выполняется до замеров и не запускает фоновый монитор SCM.
    Check(ServiceInfo::Version(true) != 0, "synthetic service snapshot was not published");
}

size_t RuleCount(size_t app) { return 5 + (app * 7) % 26; }

Groups BuildRules(RuleStore& store) {
    Groups groups;
    for (size_t app = 0; app < kApps; ++app) {
        auto& rules = groups[app];
        for (size_t n = 0; n < RuleCount(app); ++n) {
            Rule rule;
            rule.appPath = paths[app];
            rule.appName = L"SYNTHETIC.EXE";
            rule.autoName = false;
            rule.name = L"bench_" + std::to_wstring(app) + L"_" + std::to_wstring(n);
            rule.priority = static_cast<int>(n);
            rule.proto = n % 3 == 0 ? Proto::Udp : Proto::Tcp;
            rule.dir = n % 2 == 0 ? Dir::Out : Dir::In;
            rule.action = n % 3 == 1 ? RuleAction::Block : RuleAction::Allow;
            rule.conds = CondProto | CondDirection | CondRemotePort | CondRemoteAddr;
            const uint16_t port = static_cast<uint16_t>(10000 + n * 32);
            rule.remotePorts = {{static_cast<uint16_t>(port + 16),
                                 static_cast<uint16_t>(port + 17)},
                                {port, static_cast<uint16_t>(port + 7)}};
            const bool v6 = n % 4 == 3;
            rule.remoteAddrs = {{v6 ? Remote((app + 1) % 100, n, 0) :
                                     V4(198, 19, static_cast<uint8_t>(app), 0),
                                 v6 ? 64 : 24},
                                {Remote(app, n, 0), v6 ? 64 : 24}};
            if (n % 2 == 0) {
                rule.conds |= CondLocalPort;
                rule.localPorts = {{20000, 20007}, {30000, 31999}};
            }
            if (n % 3 == 0) {
                rule.conds |= CondLocalAddr;
                rule.localAddrs = {{Local(v6, 0), v6 ? 64 : 24}};
            }
            if (n % 5 < 2) {
                rule.conds |= CondService;
                const size_t cohort = app % 12;
                if (n % 5 == 0) {
                    for (size_t s = 0; s < 4; ++s)
                        rule.services.push_back({ServiceName(cohort * 4 + s), {}});
                } else {
                    // Отдельный отрицательный сервисный кандидат того же EXE.
                    rule.services.push_back({ServiceName(((cohort + 1) % 12) * 4), {}});
                }
            }
            rules.push_back(std::move(rule));
        }
        store.ReplaceApp(paths[app], L"SYNTHETIC.EXE", rules);
        rules = store.ForApp(paths[app]);
        Check(rules.size() == RuleCount(app), "rule group size changed");
    }
    for (size_t i = 500; i < 520; ++i)
        Check(store.SetInheritance(paths[processes[i].path], RuleInheritance::Enabled),
              "enabling inheritance failed");
    for (size_t i = 520; i < 540; ++i)
        Check(store.SetInheritance(paths[processes[i].path], RuleInheritance::Never),
              "blocking inheritance failed");
    return groups;
}

// Независимый обход исходных индексов родителей, без кешей ProcessTable.
size_t EffectiveOwner(size_t index) {
    if (index >= 520 && index < 540) return index;
    size_t result = index;
    for (size_t parent = processes[index].parent; parent != kNoParent;
         parent = processes[parent].parent) {
        if (parent >= 500 && parent < 520) result = parent;
    }
    return result;
}

bool ReferenceServices(const Rule& rule, size_t owner) {
    const auto& hosted = processes[owner].services;
    if (hosted.empty()) return false;
    for (const auto& service : hosted) {
        bool found = rule.services.empty();
        for (const auto& allowed : rule.services)
            found |= CompareStringOrdinal(service.name.c_str(), -1,
                       allowed.name.c_str(), -1, TRUE) == CSTR_EQUAL;
        if (!found) return false;
    }
    return true;
}

bool ReferenceMatch(const Rule& r, const MatchQuery& q, size_t owner,
                    uint64_t* serviceChecks = nullptr) {
    if (!r.enabled) return false;
    if ((r.conds & CondProto) && r.proto != q.proto) return false;
    const bool bidirectional = r.action == RuleAction::Allow &&
        (r.proto == Proto::Tcp || r.proto == Proto::Udp) &&
        (r.conds & (CondRemotePort | CondLocalPort | CondRemoteAddr | CondLocalAddr));
    if ((r.conds & CondDirection) && !bidirectional && q.dir != Dir::Unknown &&
        r.dir != q.dir) return false;
    const auto ports = [](const std::vector<PortItem>& list, uint16_t value) {
        if (list.empty()) return true;
        if (!value) return false;
        for (const auto& item : list)
            if (value >= item.from && value <= item.to) return true;
        return false;
    };
    const auto addrs = [](const std::vector<AddrItem>& list, const IpAddr& value) {
        if (list.empty()) return true;
        for (const auto& item : list)
            if (IpMatchesPrefix(value, item.addr, item.prefix)) return true;
        return false;
    };
    if ((r.conds & CondRemotePort) && !ports(r.remotePorts, q.remotePort)) return false;
    if ((r.conds & CondLocalPort) && !ports(r.localPorts, q.localPort)) return false;
    if ((r.conds & CondRemoteAddr) && !addrs(r.remoteAddrs, q.remoteAddr)) return false;
    if ((r.conds & CondLocalAddr) && !addrs(r.localAddrs, q.localAddr)) return false;
    if (!(r.conds & CondService)) return true;
    if (serviceChecks) ++*serviceChecks;
    return ReferenceServices(r, owner);
}

struct Workload {
    std::vector<MatchQuery> queries;
    std::vector<Expected> expected;
    Stats reference;
};

Workload BuildQueries(const Groups& groups) {
    Workload work;
    work.queries.reserve(kQueries);
    work.expected.reserve(kQueries);
    uint64_t inherited = 0, service = 0, ipv6 = 0, blocked = 0;
    uint64_t candidates = 0, remaining = 0, ownServiceChecks = 0, inheritedServiceChecks = 0;
    for (size_t pass = 0; pass < kQueries / kProcesses; ++pass) {
        for (size_t p = 0; p < kProcesses; ++p) {
            const size_t owner = EffectiveOwner(p);
            const size_t app = processes[owner].path;
            Check(app < kApps, "process has neither own nor inherited rules");
            const auto& rules = groups[app];
            std::vector<size_t> eligible;
            for (size_t r = 0; r < rules.size(); ++r)
                if (!(rules[r].conds & CondService) || ReferenceServices(rules[r], owner))
                    eligible.push_back(r);
            Check(!eligible.empty(), "no matching rule can be generated");
            const bool miss = pass % 10 == 9;
            // Половина промахов — порт, четверть — адрес, четверть — служба.
            const size_t missKind = (pass / 10) % 4;
            const size_t selected = miss && missKind == 3 ? 1 :
                eligible[(pass * 17 + p * 13) % eligible.size()];
            const Rule& target = rules[selected];
            MatchQuery query;
            query.appPath = processes[p].info->text;
            PrepareMatchAppPath(query, processes[p].info->folded,
                                processes[p].info->foldedHash);
            query.pid = Pid(p);
            query.process = processes[p].info->process.get();
            query.proto = target.proto;
            query.dir = pass % 8 == 0 ? Dir::Unknown : target.dir;
            query.localPort = static_cast<uint16_t>(30000 + pass);
            query.remotePort = static_cast<uint16_t>(10000 + selected * 32 + pass % 8);
            query.remoteAddr = Remote(app, selected, static_cast<uint8_t>(1 + pass % 254));
            query.localAddr = Local(selected % 4 == 3, static_cast<uint8_t>(1 + p % 254));
            if (miss && missKind < 2) query.remotePort = 65000;
            if (miss && missKind == 2) query.remoteAddr = V4(203, 0, 113, 17);
            Expected expected;
            expected.inherited = owner != p;
            for (const auto& rule : rules) {
                ++candidates;
                if (rule.proto == query.proto &&
                    (!(EffectiveRuleConds(rule) & CondDirection) ||
                     query.dir == Dir::Unknown || rule.dir == query.dir)) ++remaining;
                if (!ReferenceMatch(rule, query, owner,
                        owner == p ? &ownServiceChecks : &inheritedServiceChecks)) continue;
                expected.id = rule.id;
                expected.action = rule.action;
                expected.name = rule.name;
                expected.service = (rule.conds & CondService) != 0;
                break;
            }
            Check((expected.id == 0) == miss, "generator miss ratio is incorrect");
            work.queries.push_back(query);
            work.expected.push_back(expected);
            inherited += expected.inherited;
            service += expected.service;
            ipv6 += query.remoteAddr.family == AF_INET6;
            blocked += expected.id && expected.action == RuleAction::Block;
        }
    }
    std::vector<size_t> order(kQueries);
    std::iota(order.begin(), order.end(), size_t{0});
    std::mt19937 rng(kSeed ^ 0x1234);
    std::shuffle(order.begin(), order.end(), rng);
    Workload shuffled;
    shuffled.queries.reserve(kQueries);
    shuffled.expected.reserve(kQueries);
    for (const size_t i : order) {
        shuffled.queries.push_back(work.queries[i]);
        shuffled.expected.push_back(work.expected[i]);
        const auto& expected = work.expected[i];
        shuffled.reference.hits += expected.id != 0;
        shuffled.reference.checksum += expected.id ? 1 + static_cast<unsigned>(expected.action) : 0;
        shuffled.reference.nameChars += expected.name.size();
    }
    Check(shuffled.reference.hits == 900000, "expected exactly 900000 matches");
    std::cout << "DATA queries=" << kQueries << " hits=" << shuffled.reference.hits
              << " misses=" << kQueries - shuffled.reference.hits
              << " inherited=" << inherited << " service_hits=" << service
              << " ipv6=" << ipv6 << " block_hits=" << blocked
              << " candidates=" << candidates << " remaining_checks=" << remaining
              << " service_checks=" << ownServiceChecks + inheritedServiceChecks
              << " inherited_service_checks=" << inheritedServiceChecks
              << " name_chars=" << shuffled.reference.nameChars << '\n';
    return shuffled;
}

void Validate(RuleStore& store, const Workload& work, bool withRuleNames = false) {
    uint64_t nameChars = 0;
    for (size_t i = 0; i < work.queries.size(); ++i) {
        RuleMatchInfo info;
        const bool found = store.MatchInfo(work.queries[i], info, false);
        const auto& expected = work.expected[i];
        if (found != (expected.id != 0) ||
            (found && (info.id != expected.id || info.action != expected.action))) {
            std::cerr << "mismatch query=" << i << " pid=" << work.queries[i].pid
                      << " expected=" << expected.id << " actual=" << (found ? info.id : 0) << '\n';
            throw std::runtime_error("matcher disagrees with the independent reference");
        }
        if (withRuleNames) {
            RuleAction action = RuleAction::Allow;
            RuleNameRef name;
            const bool named = store.MatchVerdict(work.queries[i], action, &name);
            Check(named == found && (found ? name && *name == expected.name &&
                      action == expected.action : !name),
                  "returned rule name disagrees with the independent reference");
            nameChars += name ? name->size() : 0;
        }
    }
    std::cout << "VALIDATION queries=" << work.queries.size() << " errors=0\n";
    if (withRuleNames) {
        Check(nameChars == work.reference.nameChars, "validated name length changed");
        std::cout << "VALIDATION_NAMES queries=" << work.queries.size()
                  << " errors=0 name_chars=" << nameChars << '\n';
    }
}

uint64_t Ticks(const FILETIME& value) {
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

// Отдельная функция сохраняет узнаваемый корень стека в выборочном профиле.
template <bool withRuleNames>
__declspec(noinline) Stats RunMillion(RuleStore& store, const std::vector<MatchQuery>& queries) {
    Stats stats;
    for (const auto& query : queries) {
        RuleAction action = RuleAction::Allow;
        bool found = false;
        if constexpr (withRuleNames) {
            RuleNameRef name;
            found = store.MatchVerdict(query, action, &name);
            stats.nameChars += name ? name->size() : 0;
        } else {
            found = store.MatchVerdict(query, action);
        }
        stats.hits += found;
        stats.checksum += found ? 1 + static_cast<unsigned>(action) : 0;
    }
    return stats;
}

Measurement Measure(RuleStore& store, const Workload& work, bool withRuleNames = false) {
    FILETIME created{}, exited{}, kernelBefore{}, userBefore{}, kernelAfter{}, userAfter{};
    ULONG64 cyclesBefore = 0, cyclesAfter = 0;
    LARGE_INTEGER frequency{}, begin{}, end{};
    QueryPerformanceFrequency(&frequency);
    Check(GetThreadTimes(GetCurrentThread(), &created, &exited, &kernelBefore, &userBefore) != FALSE,
          "GetThreadTimes failed");
    QueryThreadCycleTime(GetCurrentThread(), &cyclesBefore);
    QueryPerformanceCounter(&begin);
    const Stats stats = withRuleNames ? RunMillion<true>(store, work.queries)
                                      : RunMillion<false>(store, work.queries);
    QueryPerformanceCounter(&end);
    QueryThreadCycleTime(GetCurrentThread(), &cyclesAfter);
    Check(GetThreadTimes(GetCurrentThread(), &created, &exited, &kernelAfter, &userAfter) != FALSE,
          "GetThreadTimes failed");
    Check(stats.hits == work.reference.hits && stats.checksum == work.reference.checksum &&
              stats.nameChars == (withRuleNames ? work.reference.nameChars : 0),
          "timed result differs from validated reference");
    return {1000.0 * static_cast<double>(end.QuadPart - begin.QuadPart) / frequency.QuadPart,
            static_cast<double>(Ticks(userAfter) - Ticks(userBefore)) / 10000.0,
            static_cast<double>(Ticks(kernelAfter) - Ticks(kernelBefore)) / 10000.0,
            cyclesAfter - cyclesBefore, stats};
}

void Print(const char* name, size_t round, const Measurement& m) {
    std::cout << std::fixed << std::setprecision(3)
              << "RUN mode=" << name << " round=" << round << " wall_ms=" << m.wallMs
              << " user_ms=" << m.userMs << " kernel_ms=" << m.kernelMs
              << " cpu_ms=" << m.userMs + m.kernelMs
              << " cycles_per_query=" << static_cast<double>(m.cycles) / kQueries
              << " hits=" << m.stats.hits << " misses=" << kQueries - m.stats.hits
              << " checksum=" << m.stats.checksum << " name_chars=" << m.stats.nameChars << '\n';
}

void Repeated(const char* name, RuleStore& store, const Workload& work, size_t rounds,
              bool withRuleNames = false) {
    // Прогрев не входит в статистику серии.
    Measure(store, work, withRuleNames);
    std::vector<double> cpu, wall, cycles;
    for (size_t round = 1; round <= rounds; ++round) {
        const auto result = Measure(store, work, withRuleNames);
        Print(name, round, result);
        cpu.push_back(result.userMs + result.kernelMs);
        wall.push_back(result.wallMs);
        cycles.push_back(static_cast<double>(result.cycles) / kQueries);
    }
    std::sort(cpu.begin(), cpu.end());
    std::sort(wall.begin(), wall.end());
    std::sort(cycles.begin(), cycles.end());
    std::cout << "SUMMARY mode=" << name << " rounds=" << rounds
              << " cpu_median_ms=" << cpu[rounds / 2] << " cpu_min_ms=" << cpu.front()
              << " cpu_max_ms=" << cpu.back() << " wall_median_ms=" << wall[rounds / 2]
              << " cycles_median=" << cycles[rounds / 2] << '\n';
}

void BuildNetworkOnly(RuleStore& store, const Groups& groups) {
    for (size_t app = 0; app < groups.size(); ++app) {
        auto rules = groups[app];
        for (size_t r = 0; r < rules.size(); ++r) {
            // Отрицательный кандидат остаётся в том же месте индекса, но его
            // заведомо чужая служба заменяется недостижимым в наборе портом.
            if (r % 5 == 1) rules[r].remotePorts = {{64000, 64000}};
            rules[r].conds &= ~CondService;
        }
        store.ReplaceApp(paths[app], L"SYNTHETIC.EXE", std::move(rules));
    }
    for (size_t p = 500; p < 540; ++p)
        store.SetInheritance(paths[processes[p].path], p < 520 ?
                             RuleInheritance::Enabled : RuleInheritance::Never);
}

void Diagnostics(RuleStore& store, pmkext::ProcessTable& table,
                 const Groups& groups, const Workload& work, size_t rounds, bool withRuleNames) {
    Workload variant = work;
    // Нижняя оценка цены без разрешения родства; для общего случая это НЕ замена:
    // здесь заранее подставляется эффективный PID, путь и живой дескриптор.
    RuleStore resolved(table);
    for (size_t app = 0; app < groups.size(); ++app)
        resolved.ReplaceApp(paths[app], L"SYNTHETIC.EXE", groups[app]);
    for (auto& query : variant.queries) {
        const size_t owner = EffectiveOwner(query.pid - kFirstPid);
        const auto& info = processes[owner].info;
        query.pid = Pid(owner);
        query.appPath = info->text;
        query.process = info->process.get();
        PrepareMatchAppPath(query, info->folded, info->foldedHash);
    }
    Validate(resolved, variant, withRuleNames);
    Repeated("pre_resolved_owner", resolved, variant, rounds, withRuleNames);

    // Диагностическое удаление сервисной работы сохраняет ответы ТОЛЬКО этого
    // набора. Это изоляция затрат, а не допустимая оптимизация продукта.
    RuleStore network(table);
    BuildNetworkOnly(network, groups);
    Validate(network, work, withRuleNames);
    Repeated("network_only_ablation", network, work, rounds, withRuleNames);

    variant = work;
    for (auto& query : variant.queries) {
        query.preparedAppPath = false;
        query.foldedAppPath = {};
        query.appPathHash = kFoldedTextHashBasis;
    }
    Validate(store, variant, withRuleNames);
    Repeated("unprepared_path", store, variant, rounds, withRuleNames);
}

void Profile(RuleStore& store, const Workload& work, unsigned seconds, bool withRuleNames) {
    std::thread worker([&] {
        std::cout << "PROFILE_BEGIN pid=" << GetCurrentProcessId()
                  << " tid=" << GetCurrentThreadId() << " seconds=" << seconds << std::endl;
        const auto start = std::chrono::steady_clock::now();
        size_t rounds = 0;
        do {
            Measure(store, work, withRuleNames);
            ++rounds;
        } while (std::chrono::steady_clock::now() - start < std::chrono::seconds(seconds));
        std::cout << "PROFILE_END rounds=" << rounds << " queries=" << rounds * kQueries << std::endl;
    });
    worker.join();
}

} // namespace bench

int main(int argc, char** argv) {
    try {
        size_t rounds = 7;
        unsigned profileSeconds = 0;
        bool diagnostics = true;
        bool withRuleNames = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--rounds" && i + 1 < argc) rounds = std::stoul(argv[++i]);
            else if (arg == "--profile-seconds" && i + 1 < argc)
                profileSeconds = static_cast<unsigned>(std::stoul(argv[++i]));
            else if (arg == "--baseline-only") diagnostics = false;
            else if (arg == "--with-rule-names") withRuleNames = true;
            else throw std::runtime_error("usage: rules_lookup_bench [--rounds N] [--baseline-only] [--with-rule-names] [--profile-seconds N]");
        }
        bench::Check(rounds > 0 && rounds <= 100, "rounds must be between 1 and 100");
        std::cout << "CONFIG seed=" << bench::kSeed << " processes=" << bench::kProcesses
                  << " duplicate_path_processes=500 shared_paths=50 unique_paths=500"
                  << " rule_apps=100 inheritance_enabled=20 inheritance_never=20"
                  << " service_names=48 compiler_msc=" << _MSC_FULL_VER
                  << " rule_names=" << withRuleNames << '\n';
        pmkext::ProcessTable table(bench::Resolve);
        bench::BuildProcesses(table);
        RuleStore store(table);
        const auto groups = bench::BuildRules(store);
        size_t serviceRules = 0, minimum = 100, maximum = 0, depth = 0;
        for (const auto& group : groups) {
            minimum = std::min(minimum, group.size());
            maximum = std::max(maximum, group.size());
            for (const auto& rule : group) serviceRules += (rule.conds & CondService) != 0;
        }
        for (size_t p = 0; p < bench::kProcesses; ++p) {
            size_t d = 0;
            for (size_t parent = bench::processes[p].parent; parent != bench::kNoParent;
                 parent = bench::processes[parent].parent) ++d;
            depth = std::max(depth, d);
        }
        std::cout << "DATA process_entries=" << table.size() << " interned_paths=" << table.pathCount()
                  << " rules=" << store.Count() << " rules_min=" << minimum << " rules_max=" << maximum
                  << " service_rules=" << serviceRules << " hosted_service_rows=" << bench::serviceRows.size()
                  << " max_parent_depth=" << depth << '\n';
        const auto work = bench::BuildQueries(groups);
        bench::Print("cold_ancestry", 0, bench::Measure(store, work, withRuleNames));
        bench::Validate(store, work, withRuleNames);
        const size_t reads = bench::scmCalls;
        if (profileSeconds) bench::Profile(store, work, profileSeconds, withRuleNames);
        else {
            bench::Repeated(withRuleNames ? "baseline_names" : "baseline",
                            store, work, rounds, withRuleNames);
            if (diagnostics) bench::Diagnostics(store, table, groups, work, rounds, withRuleNames);
        }
        bench::Check(bench::scmCalls == reads, "SCM was enumerated on the matching path");
        std::cout << "PASS scm_calls_during_matching=0 driver_calls=0\n";
        ServiceInfo::Shutdown();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
