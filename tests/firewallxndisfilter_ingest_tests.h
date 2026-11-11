#pragma once
#include "NdisTransport.h"
#include "duplex_pipe/duplex_pipe_common.h"
#include "duplex_pipe/pipe_transport.h"
#include <thread>

namespace {
DriverVerdictSession* ndisCaptureSession = nullptr;
std::vector<std::pair<uint64_t, firewallxndisfilter::Client::Verdict>> ndisVerdicts;
}

DriverVerdictRequest test_firewallxndisfilter_register_request(uint64_t id) {
    return ndisCaptureSession ? ndisCaptureSession->Receive(id) : DriverVerdictRequest();
}

bool test_firewallxndisfilter_process_verdict(DriverVerdictRequest request,
                                     firewallxndisfilter::Client::Verdict verdict) {
    uint64_t id = 0;
    if (!ndisCaptureSession || !ndisCaptureSession->Consume(request, id)) return false;
    ndisVerdicts.emplace_back(id, verdict);
    return true;
}

namespace {

uint32_t RuntimeTestInterface() {
    auto& watcher = net::SharedNetworkInterfaces();
    Check(watcher.Start(), "cannot start test interface watcher");
    const auto snapshot = watcher.GetSnapshot();
    for (const auto& entry : snapshot->interfaces)
        if (entry.up && entry.number && !entry.name.empty()) return entry.number;
    Check(false, "test needs an active interface");
    return 0;
}

firewallxndisfilter::Client::ConnectionV4 NdisEvent(uint64_t id = 0) {
    firewallxndisfilter::Client::ConnectionV4 event{};
    event.id = id;
    event.interface_index = RuntimeTestInterface();
    event.protocol = ProtoNumber(Proto::Udp);
    event.payload_layer = 3;
    event.local_ip[0] = 192; event.local_ip[1] = 0; event.local_ip[2] = 2; event.local_ip[3] = 10;
    event.remote_ip[0] = 198; event.remote_ip[1] = 51; event.remote_ip[2] = 100; event.remote_ip[3] = 20;
    event.local_port = 41000;
    event.remote_port = 53;
    return event;
}

void TestNdisPolicyAndVerdictRouting() {
    using Verdict = firewallxndisfilter::Client::Verdict;
    Ingest& host = Ingest::Instance();
    Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
    DriverVerdictSession nativeSession;
    ndisCaptureSession = &nativeSession;
    for (const IngestMode mode : {IngestMode::Desktop, IngestMode::Service}) {
        for (const FirewallPolicy policy : {FirewallPolicy::BlockAll, FirewallPolicy::Block,
                                            FirewallPolicy::Learning, FirewallPolicy::Allow,
                                            FirewallPolicy::AllowAll}) {
            RuleStore rules;
            Rule hostRule;
            hostRule.scope = RuleScope::Global;
            hostRule.conds = CondNone;
            hostRule.action = RuleAction::Allow;
            rules.Add(hostRule);
            IngestTestAccess::ResetSessionState(guest);
            host.Attach(&rules, nullptr, mode, policy);
            const uint64_t session = nativeSession.Begin();
            guest.BeginDriverSession(session);
            sentVerdicts.clear();
            ndisVerdicts.clear();
            const auto event = NdisEvent(0xfedcba9876543210ull);
            guest.HandleNdis(event, nullptr, 0);
            const bool waiting = mode == IngestMode::Desktop && policy == FirewallPolicy::Learning;
            Check(sentVerdicts.empty(), "Ndis callback sent a Portmaster verdict");
            if (waiting) {
                std::vector<AskRequest> requests;
                host.TakePending(requests);
                Check(requests.size() == 1 && guest.waiting() == 1 && host.waiting() == 1 &&
                          requests[0].id.source == TrafficSource::Ndis &&
                          requests[0].pid == 0 && requests[0].appPath.empty() &&
                          requests[0].appName == InterfaceDisplayName(event.interface_index) &&
                          requests[0].interfaceIndex == event.interface_index,
                      "Ndis Learning request was dropped or has the wrong identity");
                const AskRequest& request = requests[0];
                AskQueue queue;
                Check(queue.Push(request), "Ndis Learning request cannot enter AskQueue");
                AskRequest popped;
                Check(queue.Pop(popped) && popped.id == request.id,
                      "AskQueue routed Ndis request to Portmaster");
                Rule allow = MakeAllowRule(request);
                Check(allow.isInterface() && allow.appPath == requests[0].appName &&
                          !(allow.conds & (CondService | CondPidZero)),
                      "Ndis Ask created a rule outside the independent group");
                const auto blocked = MakeBlockAllRules(request);
                Check(blocked.size() == 1 && blocked.front().isInterface() &&
                          blocked.front().conds == CondNone,
                      "blocking the pseudo-process did not target its whole group");
                rules.Add(allow);
                Check(host.FlushVerdicts() == 1 && !host.IsPending(request.id),
                      "Ndis pending callback was not settled by its rule");
                Check(ndisVerdicts.size() == 1 && ndisVerdicts[0].first == event.id &&
                          ndisVerdicts[0].second == Verdict::PermanentAccept && sentVerdicts.empty(),
                      "Ndis delayed verdict used another driver or changed the native id");
            } else {
                const bool allow = policy == FirewallPolicy::Allow || policy == FirewallPolicy::AllowAll;
                Check(ndisVerdicts.size() == 1 && ndisVerdicts[0].first == event.id &&
                          ndisVerdicts[0].second == (allow ? Verdict::PermanentAccept : Verdict::Drop) &&
                          guest.waiting() == 0,
                      "Ndis callback ignored the selected policy");
            }
            guest.EndDriverSession(nativeSession.End());
            host.Detach();
        }
    }
    ndisCaptureSession = nullptr;
    FlowStore::Instance().Enable(true);
    FlowStore::Instance().Reset();
}

struct NdisReloadRaceProbe {
    static inline HANDLE hostLoaded = nullptr;
    static inline HANDLE releaseHost = nullptr;
    static inline HANDLE ndisLoaded = nullptr;

    static void PauseHost() {
        SetEvent(hostLoaded);
        WaitForSingleObject(releaseHost, 10000);
    }
    static void ObserveNdis() { SetEvent(ndisLoaded); }
};

void TestNdisServicePolicyReload() {
    using Verdict = firewallxndisfilter::Client::Verdict;
    Ingest& host = Ingest::Instance();
    Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    RuleStore rules;
    DriverVerdictSession session;
    ndisCaptureSession = &session;
    IngestTestAccess::ResetSessionState(host);
    IngestTestAccess::ResetSessionState(guest);
    Check(FirewallPolicySetting::Save(FirewallPolicy::AllowAll), "cannot save initial service policy");
    host.Attach(&rules, nullptr, IngestMode::Service, FirewallPolicy::AllowAll);

    // NDIS отсутствует, пока окно меняет политику и основной маршрут
    // возвращается к локальной обработке. Первая новая сессия не должна
    // наследовать разрешающую политику, сохранённую при запуске службы.
    Check(FirewallPolicySetting::Save(FirewallPolicy::BlockAll) &&
              host.ReloadServiceRules(L":memory:") &&
              guest.policy() == FirewallPolicy::BlockAll,
          "host handoff did not update the policy of an inactive Ndis source");
    guest.BeginDriverSession(session.Begin());
    ndisVerdicts.clear();
    auto event = NdisEvent(1);
    const auto expect = [&](Verdict verdict) {
        const size_t before = ndisVerdicts.size();
        guest.HandleNdis(event, nullptr, 0);
        Check(ndisVerdicts.size() == before + 1 &&
                  ndisVerdicts.back() == std::pair{event.id, verdict},
              "Ndis request used an outdated service policy");
        ++event.id;
    };
    expect(Verdict::Drop);

    Check(FirewallPolicySetting::Save(FirewallPolicy::AllowAll) &&
              host.ReloadServiceRules(L":memory:") &&
              guest.policy() == FirewallPolicy::AllowAll,
          "host handoff did not update an active Ndis source");
    expect(Verdict::PermanentAccept);

    // NDIS также может запуститься до возвращения основного маршрута службе:
    // перечитывание нового маршрута не зависит от прежней политики хоста.
    Check(FirewallPolicySetting::Save(FirewallPolicy::BlockAll) &&
              guest.ReloadServicePolicy() &&
              host.policy() == FirewallPolicy::AllowAll &&
              guest.policy() == FirewallPolicy::BlockAll,
          "late Ndis startup did not reload the saved policy independently");
    expect(Verdict::Drop);

    // Ошибка чтения правил не должна оставлять NDIS прежнюю политику:
    // служба всё равно применяет только что прочитанную настройку.
    Check(FirewallPolicySetting::Save(FirewallPolicy::AllowAll) &&
              !host.ReloadServiceRules(L"?:\\unavailable\\rules.db") &&
              guest.policy() == FirewallPolicy::AllowAll,
          "failed service rules reload retained the old Ndis policy");
    expect(Verdict::PermanentAccept);

    // Хост прочитал старую настройку, но ещё не опубликовал её. Новая
    // загрузка NDIS должна дождаться завершения хоста и прочитать новое значение.
    // Проверяем и запуск нового маршрута, и переход NDIS на локальную обработку.
    for (const bool fullReload : {false, true}) {
        Check(FirewallPolicySetting::Save(FirewallPolicy::AllowAll), "cannot prepare reload race");
        pipe_transport::UniqueHandle hostLoaded{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        pipe_transport::UniqueHandle releaseHost{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        pipe_transport::UniqueHandle ndisStarted{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        pipe_transport::UniqueHandle ndisLoaded{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        Check(hostLoaded.IsValid() && releaseHost.IsValid() && ndisStarted.IsValid() && ndisLoaded.IsValid(),
              "cannot create reload race events");
        NdisReloadRaceProbe::hostLoaded = hostLoaded.Get();
        NdisReloadRaceProbe::releaseHost = releaseHost.Get();
        NdisReloadRaceProbe::ndisLoaded = ndisLoaded.Get();
        bool hostReloaded = false, ndisReloaded = false;
        std::thread hostThread([&] {
            IngestWorkProbe::afterServicePolicyLoad = NdisReloadRaceProbe::PauseHost;
            hostReloaded = host.ReloadServiceRules(L":memory:");
            IngestWorkProbe::afterServicePolicyLoad = nullptr;
        });
        const bool hostPaused = WaitForSingleObject(hostLoaded.Get(), 5000) == WAIT_OBJECT_0;
        const bool saved = hostPaused && FirewallPolicySetting::Save(FirewallPolicy::BlockAll);
        std::thread ndisThread([&] {
            IngestWorkProbe::afterServicePolicyLoad = NdisReloadRaceProbe::ObserveNdis;
            SetEvent(ndisStarted.Get());
            ndisReloaded = fullReload ? guest.ReloadServiceRules(L":memory:")
                                      : guest.ReloadServicePolicy();
            IngestWorkProbe::afterServicePolicyLoad = nullptr;
        });
        const bool ndisStartedInTime = WaitForSingleObject(ndisStarted.Get(), 5000) == WAIT_OBJECT_0;
        const DWORD earlyNdisRead = WaitForSingleObject(ndisLoaded.Get(), 100);
        SetEvent(releaseHost.Get());
        hostThread.join();
        ndisThread.join();
        NdisReloadRaceProbe::hostLoaded = nullptr;
        NdisReloadRaceProbe::releaseHost = nullptr;
        NdisReloadRaceProbe::ndisLoaded = nullptr;
        Check(hostPaused && saved && ndisStartedInTime && earlyNdisRead == WAIT_TIMEOUT &&
                  hostReloaded && ndisReloaded && guest.policy() == FirewallPolicy::BlockAll,
              "concurrent service reloads published an outdated Ndis policy");
        expect(Verdict::Drop);
    }

    guest.EndDriverSession(session.End());
    host.Attach(&rules, nullptr, IngestMode::Desktop, FirewallPolicy::AllowAll);
    Check(!guest.ReloadServicePolicy() && guest.policy() == FirewallPolicy::AllowAll,
          "service startup reload changed the desktop policy");
    host.Detach();
    ndisCaptureSession = nullptr;
    Check(Settings::Remove(Settings::Key::kDesktopPolicy), "cannot reset service test policy");
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestNdisCallbacksAndSourceSessions() {
    using Native = firewallxndisfilter::Client;
    Ingest& host = Ingest::Instance();
    Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
    DriverVerdictSession hostSession, nativeSession;
    captureSession = &hostSession;
    ndisCaptureSession = &nativeSession;
    sentVerdicts.clear();
    ndisVerdicts.clear();
    RuleStore rules;
    IngestTestAccess::ResetSessionState(host);
    IngestTestAccess::ResetSessionState(guest);
    host.Attach(&rules, nullptr, IngestMode::Desktop, FirewallPolicy::AllowAll);
    host.BeginDriverSession(hostSession.Begin());
    guest.BeginDriverSession(nativeSession.Begin());
    const auto event = NdisEvent(42);
    guest.HandleNdis(event, nullptr, 0);
    const auto request = Request(L"C:\\Apps\\example.exe", Proto::Udp, 53);
    IngestTestAccess::ReceivePacket(host, hostSession, request, 42, {});
    Check(sentVerdicts.size() == 1 && sentVerdicts[0].first == 42 &&
              ndisVerdicts.size() == 1 && ndisVerdicts[0].first == 42,
          "matching native ids mixed driver verdict channels");
    FlowStore::View before;
    FlowStore::Instance().Take(before);
    Check(std::any_of(before.processes.begin(), before.processes.end(), [](const auto& p) { return p.first.isNdis(); }), "Ndis event has no pseudo-process");
    host.EndDriverSession(hostSession.End());
    FlowStore::View after;
    FlowStore::Instance().Take(after);
    Check(std::any_of(after.processes.begin(), after.processes.end(), [](const auto& p) { return p.first.isNdis(); }) && guest.calls() == 1,
          "Portmaster disconnect reset Ndis session or monitoring");
    guest.HandleNdis(event, nullptr, 0);
    Check(ndisVerdicts.size() == 2 && sentVerdicts.size() == 1,
          "Ndis stopped answering after Portmaster disconnect");

    // Проверяется реальный borrowed wire decoder, в том числе другой размер IPv6.
    Native::ConnectionV6 v6{};
    v6.id = UINT64_MAX;
    v6.protocol = ProtoNumber(Proto::Udp);
    v6.direction = 1;
    v6.payload_layer = 3;
    v6.local_ip[15] = 2;
    v6.remote_ip[15] = 3;
    v6.local_port = 5000;
    v6.remote_port = 6000;
    std::vector<uint8_t> record(5 + sizeof(v6) + sizeof(uint32_t));
    record[0] = 2;
    const uint32_t body = static_cast<uint32_t>(record.size() - 5);
    std::memcpy(record.data() + 1, &body, sizeof(body));
    std::memcpy(record.data() + 5, &v6, sizeof(v6));
    Native::Callbacks callbacks;
    callbacks.on_connection_v6 = [](void*, const Native::ConnectionV6* value,
                                    const uint8_t* payload, uint32_t size) {
        Ingest::ForSource(TrafficSource::Ndis).HandleNdis(*value, payload, size);
    };
    Native::Stream stream;
    for (size_t i = 0; i < record.size(); ++i) {
        stream.Buffer()[0] = record[i];
        Check(stream.Commit(1, callbacks) == ERROR_SUCCESS, "fragmented Ndis record was rejected");
    }
    Check(stream.PendingBytes() == 0 && ndisVerdicts.size() == 3 &&
              ndisVerdicts.back().first == UINT64_MAX && sentVerdicts.size() == 1,
          "IPv6 Ndis callback lost its 64-bit verdict id");
    record.assign(5, 0);
    record[0] = 3;
    Check(Native::DispatchRecord(record, callbacks) == ERROR_NOT_SUPPORTED,
          "Ndis decoder accepted a synthetic ConnectionEnd event");
    Check(std::wstring_view(duplex_pipe::PipeName(duplex_pipe::Channel::FirewallXNdisFilter)) ==
              LR"(\\.\pipe\FirewallX.FirewallXNdisFilter.Service)",
          "Ndis proxy uses the wrong named pipe");
    Check(std::wstring_view(duplex_pipe::PipeName(duplex_pipe::Channel::Portmaster)) !=
              duplex_pipe::PipeName(duplex_pipe::Channel::FirewallXNdisFilter),
          "drivers share the same named pipe");

    DriverVerdictRequest stale = nativeSession.Receive(90);
    guest.EndDriverSession(nativeSession.End());
    nativeSession.Begin();
    Check(!firewallxndisfilter_process_verdict(std::move(stale), Native::Verdict::Accept) &&
              ndisVerdicts.size() == 3,
          "stale Ndis request answered a new driver session");
    nativeSession.End();
    host.Detach();
    captureSession = nullptr;
    ndisCaptureSession = nullptr;
    FlowStore::Instance().Reset();
}

void TestNdisPayloadTraffic() {
    Ingest& host = Ingest::Instance();
    Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    flows.Reset();
    RuleStore rules;
    DriverVerdictSession session;
    ndisCaptureSession = &session;
    IngestTestAccess::ResetSessionState(guest);
    host.Attach(&rules, nullptr, IngestMode::Desktop, FirewallPolicy::AllowAll);
    guest.BeginDriverSession(session.Begin());
    sentVerdicts.clear();
    ndisVerdicts.clear();
    uint64_t id = 100;

    // Пакет из примера: 20 байт IPv4, 8 байт ICMP и 32 байта данных.
    const std::vector<uint8_t> echo4{
        0x45, 0x00, 0x00, 0x3c, 0x2d, 0x99, 0x00, 0x00, 0x80, 0x01,
        0x84, 0x32, 0xac, 0x13, 0xda, 0xe0, 0x01, 0x01, 0x01, 0x01,
        0x08, 0x00, 0x4d, 0x51, 0x00, 0x01, 0x00, 0x0a,
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'
    };
    const auto check = [&](bool ipv6, uint8_t protocol, const std::vector<uint8_t>& packet,
                           uint64_t expected, uint8_t layer = 3) {
        flows.Reset();
        for (uint8_t direction : {uint8_t{0}, uint8_t{1}}) {
            // Одинаковые tuple разных интерфейсов имеют разные строки и счётчики.
            for (int repeat = 0; repeat < 2; ++repeat) {
                const size_t before = ndisVerdicts.size();
                const uint64_t nativeId = id++;
                if (ipv6) {
                    firewallxndisfilter::Client::ConnectionV6 event{};
                    event.id = nativeId;
                    event.interface_index = repeat ? 0x87654321u : 101u;
                    event.protocol = protocol;
                    event.direction = direction;
                    event.payload_layer = layer;
                    event.local_ip[15] = 2;
                    event.remote_ip[15] = 3;
                    guest.HandleNdis(event, packet.data(), packet.size());
                } else {
                    auto event = NdisEvent(nativeId);
                    event.interface_index = repeat ? 0x87654321u : 101u;
                    event.protocol = protocol;
                    event.direction = direction;
                    event.payload_layer = layer;
                    event.local_port = event.remote_port = 0;
                    guest.HandleNdis(event, packet.data(), packet.size());
                }
                Check(ndisVerdicts.size() == before + 1 &&
                          ndisVerdicts.back().first == nativeId && sentVerdicts.empty(),
                      "Ndis payload accounting lost or misrouted a verdict");
                FlowStore::View view;
                flows.Take(view);
                const uint32_t index = repeat ? 0x87654321u : 101u;
                const auto process = view.processes.find(TrafficGroupKey::Ndis(index));
                Check(process != view.processes.end(), "Ndis interface has no pseudo-process");
                const auto& connections = process->second.connections;
                Check(connections.size() == 1, "Ndis payload changed connection identity");
                const auto& connection = connections.begin()->second;
                Check(connection.key.source == TrafficSource::Ndis && connection.driver &&
                          !connection.systemBacked && !connection.endReceived,
                      "Ndis payload accounting depends on host connections");
                const auto& counters = *connection.driver;
                const uint64_t sent = expected;
                const uint64_t received = direction ? expected : 0;
                if (counters.sent != sent || counters.recv != received) {
                    std::cerr << "Ndis payload: ipv6=" << ipv6 << " protocol="
                              << static_cast<unsigned>(protocol) << " layer="
                              << static_cast<unsigned>(layer) << " captured=" << packet.size()
                              << " expected=" << sent << '/' << received
                              << " actual=" << counters.sent << '/' << counters.recv << '\n';
                    Check(false, "Ndis counted headers instead of useful payload");
                }
            }
        }
    };
    const uint8_t icmp = ProtoNumber(Proto::Icmp);
    const uint8_t icmp6 = ProtoNumber(Proto::IcmpV6);
    check(false, icmp, echo4, 32);
    auto packet = echo4;
    packet.insert(packet.begin() + 20, 4, 0);
    packet[0] = 0x46;
    packet[3] = 64;
    check(false, icmp, packet, 32);
    packet = echo4;
    packet.resize(80, 0xff);
    check(false, icmp, packet, 32);
    packet.resize(38);
    check(false, icmp, packet, 10);
    packet.resize(27);
    check(false, icmp, packet, 0);
    packet.resize(20);
    packet[3] = 20;
    check(false, icmp, packet, 0);
    packet.resize(12);
    check(false, icmp, packet, 0);
    packet = echo4;
    packet[3] = 19;
    check(false, icmp, packet, 0);
    packet = echo4;
    packet[7] = 1;
    check(false, icmp, packet, 40);
    packet = echo4;
    packet[9] = 144;
    check(false, 144, packet, 40);
    check(false, icmp, packet, 0);
    check(false, icmp, echo4, 0, 2);
    check(false, icmp, echo4, 0, 4);
    check(false, icmp, {}, 0);

    std::vector<uint8_t> echo6(40, 0);
    echo6[0] = 0x60;
    echo6[5] = 40;
    echo6[6] = icmp6;
    echo6[7] = 64;
    echo6.insert(echo6.end(), echo4.begin() + 20, echo4.end());
    echo6[40] = 128;
    check(true, icmp6, echo6, 32);
    packet = echo6;
    packet.insert(packet.begin() + 40, 8, 0);
    packet[5] = 48;
    packet[6] = 0;
    packet[40] = icmp6;
    check(true, icmp6, packet, 32);
    packet.resize(100, 0xff);
    check(true, icmp6, packet, 32);
    packet.resize(66);
    check(true, icmp6, packet, 10);
    packet.resize(55);
    check(true, icmp6, packet, 0);
    packet.resize(41);
    check(true, icmp6, packet, 0);
    packet = echo6;
    packet.insert(packet.begin() + 40, 8, 0);
    packet[5] = 48;
    packet[6] = 44;
    packet[40] = icmp6;
    packet[43] = 8;
    check(true, icmp6, packet, 40);
    packet = echo6;
    packet[6] = 144;
    check(true, 144, packet, 40);
    check(true, icmp6, packet, 0);
    check(true, icmp6, echo6, 0, 2);

    // Один и тот же транспортный payload проверяется под IPv4 и IPv6.
    const auto protocolCheck = [&](uint8_t protocol, const std::vector<uint8_t>& data,
                                   uint64_t expected) {
        for (bool ipv6 : {false, true}) {
            std::vector<uint8_t> wrapped(ipv6 ? 40 : 20, 0);
            if (ipv6) {
                wrapped[0] = 0x60;
                wrapped[4] = static_cast<uint8_t>(data.size() >> 8);
                wrapped[5] = static_cast<uint8_t>(data.size());
                wrapped[6] = protocol;
            } else {
                wrapped[0] = 0x45;
                const size_t total = wrapped.size() + data.size();
                wrapped[2] = static_cast<uint8_t>(total >> 8);
                wrapped[3] = static_cast<uint8_t>(total);
                wrapped[9] = protocol;
            }
            wrapped.insert(wrapped.end(), data.begin(), data.end());
            check(ipv6, protocol, wrapped, expected);
        }
    };
    for (const auto [protocol, header] : {
             std::pair{2, 8}, std::pair{46, 8}, std::pair{50, 8},
             std::pair{88, 20}, std::pair{103, 4}, std::pair{108, 4},
             std::pair{112, 8}, std::pair{136, 8}}) {
        protocolCheck(static_cast<uint8_t>(protocol), std::vector<uint8_t>(header + 32), 32);
        protocolCheck(static_cast<uint8_t>(protocol), std::vector<uint8_t>(header - 1), 0);
    }
    protocolCheck(144, std::vector<uint8_t>(32), 32);
    protocolCheck(59, std::vector<uint8_t>(32), 0);
    for (uint8_t version : {uint8_t{2}, uint8_t{3}}) {
        packet.assign((version == 2 ? 24 : 16) + 32, 0);
        packet[0] = version;
        protocolCheck(89, packet, 32);
    }
    packet[0] = 1;
    protocolCheck(89, packet, 0);
    packet.assign(34, 0);
    packet[0] = 0x30;
    protocolCheck(97, packet, 32);
    packet[0] = 0x20;
    protocolCheck(97, packet, 0);

    for (unsigned options = 0; options < 8; ++options) {
        const uint16_t flags = static_cast<uint16_t>(((options & 1) ? 0x8000 : 0) |
            ((options & 2) ? 0x2000 : 0) | ((options & 4) ? 0x1000 : 0));
        const size_t header = 4 + 4 * ((options & 1) + ((options >> 1) & 1) +
                                     ((options >> 2) & 1));
        packet.assign(header + 32, 0);
        packet[0] = static_cast<uint8_t>(flags >> 8);
        protocolCheck(47, packet, 32);
        packet.resize(header - 1);
        protocolCheck(47, packet, 0);
    }
    packet.assign(36, 0);
    packet[1] = 1;
    protocolCheck(47, packet, 0);
    packet[0] = 0x40;
    packet[1] = 0;
    protocolCheck(47, packet, 0);
    for (size_t header : {12u, 16u, 24u}) {
        auto wrapped = echo4;
        wrapped.resize(20 + header + 32, 0);
        wrapped[3] = static_cast<uint8_t>(wrapped.size());
        wrapped[9] = 51;
        wrapped[21] = static_cast<uint8_t>(header / 4 - 2);
        check(false, 51, wrapped, 32);
        // У IPv6 AH снимается общим IP-разборщиком, а протокол события — конечный.
        wrapped = echo6;
        wrapped.insert(wrapped.begin() + 40, header, 0);
        wrapped[5] = static_cast<uint8_t>(40 + header);
        wrapped[6] = 51;
        wrapped[40] = icmp6;
        wrapped[41] = static_cast<uint8_t>(header / 4 - 2);
        check(true, icmp6, wrapped, 32);
    }
    protocolCheck(51, std::vector<uint8_t>(40), 0);

    for (bool extended : {false, true})
    for (uint8_t type : {uint8_t{2}, uint8_t{4}}) {
        const size_t minimum = (extended ? 16u : 12u) +
            (type == 4 ? (extended ? 8u : 4u) : 0u);
        const size_t header = minimum + 8;
        packet.assign(header + 32, 0);
        packet[4] = static_cast<uint8_t>(header / 4);
        packet[8] = static_cast<uint8_t>((type << 1) | (extended ? 1 : 0));
        protocolCheck(33, packet, 32);
        packet.resize(header - 1);
        protocolCheck(33, packet, 0);
        packet[4] = static_cast<uint8_t>(minimum / 4 - 1);
        protocolCheck(33, packet, 0);
        packet[4] = static_cast<uint8_t>(header / 4);
        packet[8] = 0;
        protocolCheck(33, packet, 0);
    }

    // Request/Response тоже могут нести данные: Data Offset отделяет их
    // от Service Code, подтверждения и опций, независимо от типа пакета.
    for (const auto [type, header] : {std::pair{0, 20}, std::pair{1, 28}}) {
        packet.assign(header + 32, 0);
        packet[4] = static_cast<uint8_t>(header / 4);
        packet[8] = static_cast<uint8_t>((type << 1) | 1);
        protocolCheck(33, packet, 32);
        packet.resize(header);
        protocolCheck(33, packet, 0);
    }
    packet.assign(48, 0);
    packet[4] = 4;
    packet[8] = 21;
    protocolCheck(33, packet, 0);

    const auto chunk = [](std::vector<uint8_t>& data, uint8_t type,
                          size_t header, size_t payload) {
        const size_t begin = data.size();
        const size_t length = header + payload;
        data.resize(begin + length, 0);
        data[begin] = type;
        data[begin + 2] = static_cast<uint8_t>(length >> 8);
        data[begin + 3] = static_cast<uint8_t>(length);
        data.resize((data.size() + 3) & ~size_t{3}, 0);
    };
    packet.assign(12, 0);
    chunk(packet, 0, 16, 5);
    chunk(packet, 3, 4, 8);
    chunk(packet, 64, 20, 7);
    protocolCheck(132, packet, 12);
    packet.resize(packet.size() - 4);
    protocolCheck(132, packet, 9);
    packet.assign(12, 0);
    chunk(packet, 1, 20, 0);
    protocolCheck(132, packet, 0);
    packet.assign(12, 0);
    chunk(packet, 0, 4, 0);
    protocolCheck(132, packet, 0);
    packet[14] = packet[15] = 0;
    protocolCheck(132, packet, 0);

    for (Proto proto : {Proto::Tcp, Proto::Udp}) {
        packet = echo4;
        packet[9] = ProtoNumber(proto);
        check(false, ProtoNumber(proto), packet, 0);
        packet = echo6;
        packet[6] = ProtoNumber(proto);
        check(true, ProtoNumber(proto), packet, 0);
    }
    Check(guest.waiting() == 0 && guest.calls() == guest.answered(),
          "Ndis traffic accounting changed callback obligations");
    guest.EndDriverSession(session.End());
    host.Detach();
    ndisCaptureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
    std::cout << "Ndis payload: IPv4/IPv6, ICMP, GRE, AH/ESP, SCTP, DCCP, fixed headers, bounds and TCP/UDP isolation passed\n";
}

void TestHostInterfaceVerdictIsolation() {
    Ingest& ingest = Ingest::Instance();
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    Rule global;
    global.scope = RuleScope::Global;
    global.conds = CondNone;
    global.action = RuleAction::Allow;
    rules.Add(global);
    const uint32_t index = RuntimeTestInterface();
    Rule interface = global;
    interface.id = 0;
    interface.scope = RuleScope::Interface;
    interface.appPath = InterfaceDisplayName(index);
    interface.action = RuleAction::Block;
    rules.Add(interface);
    IngestTestAccess::ResetSessionState(ingest);
    ingest.Attach(&rules, nullptr, IngestMode::Desktop, FirewallPolicy::Learning);
    ingest.BeginDriverSession(session.Begin());
    AskRequest request = Request(L"C:\\Apps\\interfaces.exe", Proto::Udp, 53);
    for (uint32_t number : {0u, index, 0u, index}) {
        request.interfaceIndex = number;
        const uint64_t id = sentVerdicts.size() + 1;
        IngestTestAccess::ReceivePacket(ingest, session, request, id, {});
        Check(sentVerdicts.size() == id && sentVerdicts.back().second ==
                  (number ? pmkext::Verdict::Drop : pmkext::Verdict::PermanentAccept),
              "shape cache reused a verdict from another interface");
    }
    ingest.EndDriverSession(session.End());
    ingest.Detach();

    RuleStore pendingRules;
    IngestTestAccess::ResetSessionState(ingest);
    ingest.Attach(&pendingRules, nullptr, IngestMode::Desktop, FirewallPolicy::Learning);
    ingest.BeginDriverSession(session.Begin());
    sentVerdicts.clear();
    request.interfaceIndex = index;
    IngestTestAccess::ReceivePacket(ingest, session, request, 10, {});
    request.interfaceIndex = 0;
    IngestTestAccess::ReceivePacket(ingest, session, request, 11, {});
    std::vector<AskRequest> requests;
    ingest.TakePending(requests);
    Check(requests.size() == 2 && requests[0].id != requests[1].id && ingest.waiting() == 2 &&
              requests[0].interfaceIndex != requests[1].interfaceIndex,
          "pending callbacks on different interfaces were merged");
    for (const auto& pending : requests)
        Check(pending.ToQuery().interfaceIndex == pending.interfaceIndex,
              "UI query lost its interface index");
    interface.id = 0;
    interface.action = RuleAction::Allow;
    pendingRules.Add(interface);
    Check(ingest.FlushVerdicts() == 1 && ingest.waiting() == 1 && sentVerdicts.size() == 1 &&
              sentVerdicts.front().first == 10,
          "interface rule settled another interface's pending obligation");
    ingest.EndDriverSession(session.End());
    ingest.Detach();
    captureSession = nullptr;
    FlowStore::Instance().Reset();
}

void TestFrozenPendingInterfaceIdentity() {
    using Verdict = firewallxndisfilter::Client::Verdict;
    Ingest& host = Ingest::Instance();
    Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
    IngestTestAccess::ResetSessionState(guest);
    RuleStore rules;
    DriverVerdictSession session;
    ndisCaptureSession = &session;
    ndisVerdicts.clear();
    host.Attach(&rules, nullptr, IngestMode::Desktop, FirewallPolicy::Learning);
    guest.BeginDriverSession(session.Begin());

    // Старый pending существовал до передачи его IfIndex другому адаптеру.
    // Сетевые настройки машины тест не меняет: удерживает исходное имя явно.
    const uint32_t index = RuntimeTestInterface();
    const std::wstring currentName = *net::SharedNetworkInterfaces().GetInterfaceName(index);
    const std::wstring originalName = currentName + L" (removed interface)";
    AskRequest old = Request(L"", Proto::Udp, 53);
    old.pid = 0;
    old.process.reset();
    old.key.source = TrafficSource::Ndis;
    old.key.interfaceIndex = old.interfaceIndex = index;
    old.interfaceName = std::make_shared<const std::wstring>(originalName);
    IngestTestAccess::ReceivePacket(guest, session, old, 810, {});
    AskRequest current = old;
    current.interfaceName.reset();
    IngestTestAccess::ReceivePacket(guest, session, current, 811, {});
    std::vector<AskRequest> pending;
    host.TakePending(pending);
    Check(pending.size() == 2 && guest.waiting() == 2,
          "same index merged pending from different interface names");
    const auto original = std::find_if(pending.begin(), pending.end(), [&](const auto& request) {
        return request.interfaceName && *request.interfaceName == originalName;
    });
    Check(original != pending.end() && original->appName == originalName,
          "pending display resolved a reused interface index");
    const AskRequest saved = *original;

    Rule replacement;
    replacement.scope = RuleScope::Interface;
    replacement.appPath = currentName;
    replacement.conds = CondNone;
    replacement.action = RuleAction::Block;
    rules.Add(replacement);
    Check(host.FlushVerdicts() == 1 && guest.waiting() == 1 &&
              ndisVerdicts.size() == 1 && ndisVerdicts.front().first == 811 &&
              host.IsPending(saved.id),
          "replacement interface rule settled an old pending callback");
    Rule allow = MakeAllowRule(saved);
    Check(allow.isInterface() && allow.appPath == originalName &&
              RuleStore::MatchesRule(allow, saved.ToQuery()),
          "automatic rule did not retain the removed interface name");
    rules.Add(allow);
    Check(host.FlushVerdicts() == 1 && !host.IsPending(saved.id) &&
              ndisVerdicts.size() == 2 && ndisVerdicts.back().first == 810 &&
              ndisVerdicts.back().second == Verdict::PermanentAccept,
          "saved offline interface rule did not settle its original callback");

    // Неизвестное при парковке имя не превращается в имя нового адаптера.
    AskRequest unknown = old;
    unknown.interfaceName = std::make_shared<const std::wstring>();
    IngestTestAccess::ReceivePacket(guest, session, unknown, 812, {});
    pending.clear();
    host.TakePending(pending);
    Check(pending.size() == 1 && pending.front().interfaceName && pending.front().interfaceName->empty(),
          "unknown pending adopted the replacement interface name");
    const size_t count = rules.Count();
    for (Rule rule : {MakeAllowRule(pending.front()), MakeBlockRule(pending.front()),
                      MakeEditorTemplate(pending.front()), MakeBlockAllRules(pending.front()).front()}) {
        Check(rule.isInterface() && rule.appPath.empty() && rules.Add(rule) == 0,
              "display placeholder was persisted as an interface rule");
    }
    Rule edited = MakeEditorTemplate(pending.front());
    Check(RuleStore::MatchesRuleConditions(edited, pending.front().ToQuery()),
          "one-time template does not cover its original request");
    edited.enabled = false;
    Check(!RuleStore::MatchesRuleConditions(edited, pending.front().ToQuery()),
          "disabled editor template became a one-time decision");
    edited.enabled = true;
    edited.remotePorts = {{54, 54}};
    Check(!RuleStore::MatchesRuleConditions(edited, pending.front().ToQuery()),
          "one-time decision ignored edited network conditions");
    Check(rules.Count() == count && host.FlushVerdicts() == 0 &&
              host.AnswerOnce(pending.front().id, RuleAction::Block) &&
              !host.IsPending(pending.front().id) && ndisVerdicts.back().first == 812 &&
              ndisVerdicts.back().second == Verdict::PermanentDrop,
          "unknown interface cannot receive a one-time decision");
    // Именованное старое событие не должно разрешить новые пакеты другого
    // интерфейса через кеш, в котором ключом остаётся только IfIndex.
    IngestTestAccess::ReceivePacket(guest, session, saved, 813, {});
    Check(ndisVerdicts.back().first == 813 &&
              ndisVerdicts.back().second == Verdict::PermanentAccept &&
              IngestTestAccess::NoCachedVerdicts(guest),
          "frozen interface decision leaked into the numeric shape cache");
    IngestTestAccess::ReceivePacket(guest, session, current, 814, {});
    Check(ndisVerdicts.back().first == 814 && ndisVerdicts.back().second == Verdict::Drop,
          "old interface verdict was reused for the current interface");
    guest.EndDriverSession(session.End());
    host.Detach();
    ndisCaptureSession = nullptr;
    FlowStore::Instance().Reset();
}

void TestNdisIntegration() {
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i)
        for (UINT id : {IDS_INTERFACE_UNKNOWN, IDS_INTERFACE_DESC, IDS_SETTINGS_TAB_INTERFACES,
                        IDS_INTERFACE_EXCLUDE_TRANSIT, IDS_INTERFACE_EXCLUDE_SAVE_ERROR,
                        IDS_INTERFACE_EXCLUDE_APPLY_ERROR,
                        IDS_INTERFACE_INACTIVE, IDS_INTERFACE_RULE, IDS_INTERFACE_COLUMN,
                        IDS_INTERFACE_STATS_FMT, IDS_INTERFACE_DELETE_FMT, IDS_DEBUG_INTERFACE_CANDIDATES})
            Check(HasString(id, languages[i].winLangId), "missing interface group translation");
    TestHostInterfaceVerdictIsolation();
    TestFrozenPendingInterfaceIdentity();
    TestNdisPolicyAndVerdictRouting();
    TestNdisServicePolicyReload();
    TestNdisCallbacksAndSourceSessions();
    TestNdisPayloadTraffic();
}

} // namespace
