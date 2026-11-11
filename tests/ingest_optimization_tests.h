#pragma once

#include <span>

namespace {
namespace IngestOptimization {

template <class Fixed>
Fixed Event(uint16_t port, uint8_t protocol = 6, uint8_t layer = 3, bool inbound = false) {
    Fixed event{};
    event.process_id = GetCurrentProcessId();
    event.direction = inbound ? 1 : 0;
    event.protocol = protocol;
    event.local_port = 41000;
    event.remote_port = port;
    event.payload_layer = layer;
    const auto local = Ip(sizeof(event.local_ip) == 4 ? L"192.0.2.10" : L"2001:db8::10");
    const auto remote = Ip(sizeof(event.remote_ip) == 4 ? L"198.51.100.20" : L"2001:db8::20");
    std::copy_n(local.b, sizeof(event.local_ip), event.local_ip);
    std::copy_n(remote.b, sizeof(event.remote_ip), event.remote_ip);
    return event;
}

template <class Fixed>
std::vector<uint8_t> Packet(const Fixed& event, uint16_t flags,
                            std::span<const uint8_t> payload = {}) {
    constexpr bool v6 = sizeof(event.local_ip) == 16;
    constexpr size_t ipSize = v6 ? 40 : 20;
    const size_t transportSize = event.protocol == 6 ? 20 : 8;
    std::vector<uint8_t> packet(ipSize + transportSize + payload.size());
    const auto put16 = [&](size_t offset, size_t value) {
        packet[offset] = static_cast<uint8_t>(value >> 8);
        packet[offset + 1] = static_cast<uint8_t>(value);
    };
    packet[0] = v6 ? 0x60 : 0x45;
    if constexpr (v6) {
        put16(4, packet.size() - ipSize);
        packet[6] = event.protocol;
        packet[7] = 64;
    } else {
        put16(2, packet.size());
        packet[8] = 64;
        packet[9] = event.protocol;
    }
    const bool inbound = event.direction == 1;
    const auto* src = inbound ? event.remote_ip : event.local_ip;
    const auto* dst = inbound ? event.local_ip : event.remote_ip;
    std::copy_n(src, sizeof(event.local_ip), packet.begin() + (v6 ? 8 : 12));
    std::copy_n(dst, sizeof(event.remote_ip), packet.begin() + (v6 ? 24 : 16));
    put16(ipSize, inbound ? event.remote_port : event.local_port);
    put16(ipSize + 2, inbound ? event.local_port : event.remote_port);
    if (event.protocol == 6) {
        packet[ipSize + 7] = 1;
        packet[ipSize + 12] = static_cast<uint8_t>(0x50 | ((flags >> 8) & 1));
        packet[ipSize + 13] = static_cast<uint8_t>(flags);
    } else {
        put16(ipSize + 4, transportSize + payload.size());
    }
    std::copy(payload.begin(), payload.end(), packet.begin() + ipSize + transportSize);
    return packet;
}

template <class Fixed>
void Receive(Ingest& ingest, const Fixed& event, const std::vector<uint8_t>& packet) {
    if constexpr (sizeof(event.local_ip) == 4)
        ingest.HandleV4(event, packet.data(), packet.size());
    else
        ingest.HandleV6(event, packet.data(), packet.size());
}

template <class Fixed>
void ImmediateBlocked() {
    FlowStore& flows = FlowStore::Instance();
    flows.Reset();

    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    Rule block;
    block.scope = RuleScope::Global;
    block.conds = CondNone;
    block.action = RuleAction::Block;
    rules.Add(block);
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr, IngestMode::Desktop,
                   FirewallPolicy::Learning);
    ingest->BeginDriverSession(session.Begin());

    auto event = Event<Fixed>(443, 6, 3, true);
    event.external_connection_id = 1;
    Receive(*ingest, event, Packet(event, 0x002));
    Check(sentVerdicts.size() == 1 &&
              sentVerdicts.front().second == pmkext::Verdict::Drop,
          "immediate inbound block returned an incorrect verdict");

    FlowStore::View view;
    flows.Take(view, 0);
    const auto process = view.processes.find(
        TrafficGroupKey::Host(static_cast<DWORD>(event.process_id)));
    const FlowStore::ConnectionRecord* blocked = nullptr;
    if (process != view.processes.end()) {
        for (const auto& item : process->second.connections) {
            if (item.second.blockedAt) {
                blocked = &item.second;
                break;
            }
        }
    }
    Check(blocked && blocked->driverBacked && blocked->blockedAt &&
              blocked->removeAfter && blocked->dir == Dir::In,
          "immediate inbound block did not publish one blocked flow");

    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    flows.Reset();
}

template <class Fixed>
void TcpVerdicts() {
    struct Case {
        uint16_t flags;
        bool payload;
        uint8_t layer;
        bool inbound;
        pmkext::Verdict webVerdict;
    };
    const Case cases[]{
        {0x002, false, 3, false, pmkext::Verdict::Accept},
        {0x010, false, 3, false, pmkext::Verdict::Accept},
        {0x010, true,  3, false, pmkext::Verdict::PermanentAccept},
        {0x018, true,  3, false, pmkext::Verdict::PermanentAccept},
        {0x012, false, 3, true,  pmkext::Verdict::Accept},
        {0x010, false, 3, true,  pmkext::Verdict::PermanentAccept},
        {0x002, false, 4, false, pmkext::Verdict::Accept},
        {0x012, false, 4, true,  pmkext::Verdict::PermanentAccept},
        {0x110, false, 3, false, pmkext::Verdict::PermanentAccept},
    };
    for (const auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (const auto action : {RuleAction::Allow, RuleAction::Block}) {
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        RuleStore rules;
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondNone;
        rule.action = action;
        rules.Add(rule);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode);
        ingest->BeginDriverSession(session.Begin());
        uint64_t id = 0;
        for (const uint16_t port : {uint16_t{22}, uint16_t{80}, uint16_t{443},
                                    uint16_t{8080}, uint16_t{8443}})
        for (const auto& c : cases) {
            auto event = Event<Fixed>(port, 6, c.layer, c.inbound);
            const std::vector<uint8_t> data(c.payload ? 1 : 0, 0);
            const auto packet = Packet(event, c.flags, data);
            const bool web = port == 80 || port == 8080 || port == 443 || port == 8443;
            const auto expected = action == RuleAction::Block ? pmkext::Verdict::Drop
                : web ? c.webVerdict : pmkext::Verdict::PermanentAccept;
            // Повтор проверяет и matcher, и уже заполненный кеш формы.
            for (int repeat = 0; repeat < 2; ++repeat) {
                event.external_connection_id = ++id;
                const auto version = rules.version();
                IngestWorkProbe::counts = {};
                Receive(*ingest, event, packet);
                Check(sentVerdicts.size() == id && sentVerdicts.back() == std::pair{id, expected},
                      "TCP work reduction changed a driver verdict");
                Check(IngestWorkProbe::counts.tcpReads == (web ? 1u : 0u),
                      "non-web TCP decoded unused flags, sequence or payload");
                if (rules.version() == version)
                    Check(IngestWorkProbe::counts.shapeHashes == 1,
                          "matched TCP event hashed its shape more than once");
            }
        }
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
              "TCP optimization lost a driver obligation");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
}

template <class Fixed>
void PolicyPaths() {
    DriverVerdictSession session;
    captureSession = &session;
    for (const auto policy : {FirewallPolicy::AllowAll, FirewallPolicy::BlockAll,
                              FirewallPolicy::Allow, FirewallPolicy::Block}) {
        sentVerdicts.clear();
        RuleStore rules;
        Rule block;
        block.scope = RuleScope::Global;
        block.conds = CondNone;
        block.action = RuleAction::Block;
        rules.Add(block);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, IngestMode::Desktop, policy);
        ingest->BeginDriverSession(session.Begin());
        auto event = Event<Fixed>(8443);
        event.external_connection_id = 1;
        IngestWorkProbe::counts = {};
        Receive(*ingest, event, Packet(event, 0x010));
        const bool usesRules = FirewallPolicies::UsesRules(policy);
        const auto expected = policy == FirewallPolicy::AllowAll
            ? pmkext::Verdict::Accept : pmkext::Verdict::Drop;
        Check(sentVerdicts.size() == 1 && sentVerdicts.front().second == expected,
              "skipping process metadata changed policy precedence");
        Check(IngestWorkProbe::counts.processPathReads == (usesRules ? 1u : 0u),
              "extreme policy requested an unused process path");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
}

template <class Fixed>
void DnsParsing() {
    const std::vector<uint8_t> query{
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1
    };
    for (const auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (const auto policy : {FirewallPolicy::Learning, FirewallPolicy::AllowAll,
                              FirewallPolicy::BlockAll})
    for (const bool valid : {false, true}) {
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        RuleStore rules;
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, policy);
        ingest->BeginDriverSession(session.Begin());
        auto event = Event<Fixed>(53, 17);
        event.external_connection_id = 1;
        const auto packet = Packet(event, 0, valid ? query : std::vector<uint8_t>{0, 0});
        IngestWorkProbe::counts = {};
        Receive(*ingest, event, packet);
        const bool pending = mode == IngestMode::Desktop && policy == FirewallPolicy::Learning;
        Check(ingest->waiting() == (pending ? 1u : 0u) && sentVerdicts.size() == (pending ? 0u : 1u),
              "DNS display changed whether the driver obligation was parked");
        Check(IngestWorkProbe::counts.dnsParses == (mode == IngestMode::Desktop ? 1u : 0u),
              "DNS payload was parsed twice or parsed unnecessarily in service mode");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
}

template <class Fixed>
void HttpConnectionLabels() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    enum class Answer { MatchedRule, Once, NewRule };
    for (const uint16_t port : {uint16_t{80}, uint16_t{8080}})
    for (const Answer answer : {Answer::MatchedRule, Answer::Once, Answer::NewRule}) {
        flows.Reset();
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        RuleStore rules;
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        const uint64_t ruleId = rules.Add(allow);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());

        auto event = Event<Fixed>(port);
        const bool v6 = sizeof(event.local_ip) == 16;
        const FlowKey key = MakeFlowKey(Proto::Tcp,
            Ip(v6 ? L"2001:db8::10" : L"192.0.2.10"),
            Ip(v6 ? L"2001:db8::20" : L"198.51.100.20"), 41000, port);
        const auto label = [&]() {
            FlowStore::DisplayView view;
            flows.TakeDisplay(view);
            for (const auto& process : view.processes) {
                if (process.group != TrafficGroupKey::Host(static_cast<DWORD>(event.process_id)))
                    continue;
                for (const auto& connection : process.connections)
                    if (connection.key == key && connection.tlsDomainLabel)
                        return *connection.tlsDomainLabel;
            }
            return std::wstring();
        };
        const auto receive = [&](uint64_t id, uint8_t layer, bool inbound,
                                 uint16_t flags, std::span<const uint8_t> data,
                                 pmkext::Verdict expected, bool pending) {
            event.external_connection_id = id;
            event.payload_layer = layer;
            event.direction = inbound ? 1 : 0;
            const auto bytes = layer == 4 ? std::vector<uint8_t>{} : Packet(event, flags, data);
            const size_t before = sentVerdicts.size();
            Receive(*ingest, event, bytes);
            if (pending) {
                std::vector<AskRequest> requests;
                ingest->TakePending(requests);
                Check(requests.size() == 1 && sentVerdicts.size() == before,
                      "HTTP request was not parked for an explicit answer");
                if (answer == Answer::Once) {
                    Check(ingest->AnswerOnce(requests.front().id, RuleAction::Allow),
                          "pending HTTP allow failed");
                } else {
                    rules.Add(allow);
                    Check(ingest->FlushVerdicts() == 1, "pending HTTP rule did not send a verdict");
                }
            }
            Check(sentVerdicts.size() == before + 1 &&
                      sentVerdicts.back() == std::pair{id, expected},
                  "HTTP connection received an unexpected verdict");
        };

        receive(1, 4, false, 0, {}, pmkext::Verdict::Accept, false);
        receive(2, 3, false, 0x002, {}, pmkext::Verdict::Accept, false);
        receive(3, 3, true, 0x012, {}, pmkext::Verdict::Accept, false);
        receive(4, 3, false, 0x010, {}, pmkext::Verdict::Accept, false);
        Check(label().empty(), "HTTP connection published a domain before the request");
        const bool pending = answer != Answer::MatchedRule;
        if (pending) Check(rules.Remove(ruleId), "cannot remove HTTP allow rule");
        const std::string request = "GET / HTTP/1.1\r\nHost: example.com:" +
            std::to_string(port) + "\r\n\r\n";
        const auto* data = reinterpret_cast<const uint8_t*>(request.data());
        receive(5, 3, false, 0x018, {data, request.size()},
                pmkext::Verdict::PermanentAccept, pending);
        Check(label() == L"[example.com]", "HTTP connection lost its Host domain");
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
              "HTTP display violated driver obligation counters");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
    flows.Reset();
    flows.Enable(wasEnabled);
}

void VerdictTouches() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    Rule allow;
    allow.scope = RuleScope::Global;
    allow.conds = CondNone;
    rules.Add(allow);
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr, IngestMode::Service);
    ingest->BeginDriverSession(session.Begin());
    const auto request = Request(L"C:\\Apps\\ttl-touch.exe", Proto::Udp, 5353);
    IngestTestAccess::ReceivePacket(*ingest, session, request, 0, {});
    constexpr size_t count = 2000;
    const auto before = GetTickCount64();
    for (uint64_t id = 1; id <= count; ++id)
        IngestTestAccess::ReceivePacket(*ingest, session, request, id, {});
    const auto elapsed = GetTickCount64() - before;
    Check(IngestTestAccess::VerdictExpirySize(*ingest) <= elapsed + 2,
          "same-millisecond cache hits added duplicate expiry records");
    Check(sentVerdicts.size() == count + 1 && ingest->calls() == ingest->answered(),
          "coalesced TTL touches lost a verdict");
    IngestTestAccess::CheckLastVerdictExpiry(*ingest);
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
}

} // namespace IngestOptimization

void TestIngestOptimizations() {
    auto& flows = FlowStore::Instance();
    const bool enabled = flows.enabled();
    flows.Enable(true);
    IngestOptimization::ImmediateBlocked<pmkext::ConnectionFixedV4>();
    IngestOptimization::ImmediateBlocked<pmkext::ConnectionFixedV6>();
    IngestOptimization::HttpConnectionLabels<pmkext::ConnectionFixedV4>();
    IngestOptimization::HttpConnectionLabels<pmkext::ConnectionFixedV6>();
    flows.Enable(false);
    IngestTestAccess::TestPreparedShapeKey();
    IngestOptimization::TcpVerdicts<pmkext::ConnectionFixedV4>();
    IngestOptimization::TcpVerdicts<pmkext::ConnectionFixedV6>();
    IngestOptimization::PolicyPaths<pmkext::ConnectionFixedV4>();
    IngestOptimization::PolicyPaths<pmkext::ConnectionFixedV6>();
    IngestOptimization::DnsParsing<pmkext::ConnectionFixedV4>();
    IngestOptimization::DnsParsing<pmkext::ConnectionFixedV6>();
    IngestOptimization::VerdictTouches();
    flows.Reset();
    flows.Enable(enabled);
}

} // namespace
