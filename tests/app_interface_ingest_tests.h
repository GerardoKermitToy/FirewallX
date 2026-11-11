#pragma once
#include "AppRulesEditor.h"

namespace {

void CheckPreferredInterfaceFlow(const AskRequest& request, IngestMode mode, bool blocked) {
    FlowStore::DisplayView view;
    FlowStore::Instance().TakeDisplay(view);
    size_t found = 0;
    for (const auto& process : view.processes) {
        if (process.group != TrafficGroupKey::Host(request.pid)) continue;
        for (const auto& connection : process.connections) {
            if (connection.key != request.key) continue;
            ++found;
            Check((connection.blockedAt != 0) == blocked && connection.dir == request.dir &&
                  (!blocked || connection.removeAfter > connection.blockedAt),
                  "preferred-interface attempt lost its blocked state in the UI snapshot");
        }
    }
    Check(found == (mode == IngestMode::Desktop ? 1u : 0u),
          "preferred-interface attempt is missing from the UI snapshot or was published by the service");
}

void TestPreferredInterfaceIngest() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    DriverVerdictSession session;
    captureSession = &session;
    const auto cacheClears = driverCacheClears;
    for (auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::Block,
                        FirewallPolicy::Learning, FirewallPolicy::Allow, FirewallPolicy::AllowAll})
    for (auto proto : {Proto::Tcp, Proto::Udp})
    for (bool ipv6 : {false, true})
    for (auto dir : {Dir::Out, Dir::In}) {
        flows.Reset();
        sentVerdicts.clear();
        RuleStore rules;
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        rules.Add(allow);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, policy);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        ingest->BeginDriverSession(session.Begin());
        rules.SetAppInterfacesActive(true);
        AskRequest request = Request(L"C:\\Apps\\preferred-interface.exe", proto, 5555);
        request.dir = dir;
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        const auto receive = [&](uint64_t id, pmkext::Verdict expected) {
            const auto before = sentVerdicts.size();
            IngestTestAccess::ReceivePacket(*ingest, session, request, id, {});
            Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() == std::pair{id, expected},
                  "cached verdict or firewall policy bypassed preferred-interface blocking");
        };
        const auto baseline = policy == FirewallPolicy::BlockAll
            ? pmkext::Verdict::Drop : pmkext::Verdict::PermanentAccept;
        receive(1, baseline);
        receive(2, baseline);
        rules.SetPreferredInterface(request.appPath, L"Unavailable preferred interface for ingest tests");
        for (uint64_t id : {3, 4}) {
            flows.Reset();
            receive(id, pmkext::Verdict::Drop);
            CheckPreferredInterfaceFlow(request, mode, true);
            if (FirewallPolicies::UsesRules(policy))
                Check(IngestTestAccess::HasCurrentShapeCache(*ingest),
                      "preferred-interface block was not tested through the shape cache");
        }
        rules.SetPreferredInterface(request.appPath, L"");
        flows.Reset();
        receive(5, baseline);
        CheckPreferredInterfaceFlow(request, mode,
                                    baseline == pmkext::Verdict::Drop && dir == Dir::In);
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered() && driverCacheClears == cacheClears,
              "preferred-interface change left obligations or cleared the driver cache");
        ingest->EndDriverSession(session.End());
    }
    for (int answerMode : {0, 1, 2})
    for (auto proto : {Proto::Tcp, Proto::Udp})
    for (bool ipv6 : {false, true})
    for (auto dir : {Dir::Out, Dir::In}) {
        flows.Reset();
        sentVerdicts.clear();
        RuleStore rules;
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\preferred-interface-pending.exe", proto, 5555);
        request.dir = dir;
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        IngestTestAccess::ReceivePacket(*ingest, session, request, 100, {});
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1 && sentVerdicts.empty(),
              "preferred-interface display test did not park its connection");
        rules.SetPreferredInterface(request.appPath, L"Unavailable interface for pending answer");
        if (!answerMode) {
            Check(ingest->FlushVerdicts() == 1, "unavailable interface did not settle the pending attempt");
        } else {
            Check(ingest->AnswerOnce(pending.front().id,
                      answerMode == 1 ? RuleAction::Allow : RuleAction::Block),
                  "unavailable interface did not settle the one-shot answer");
        }
        Check(sentVerdicts.size() == 1 && sentVerdicts.front().second ==
                  (answerMode ? pmkext::Verdict::PermanentDrop : pmkext::Verdict::Drop),
              "pending answer bypassed an unavailable preferred interface");
        CheckPreferredInterfaceFlow(request, IngestMode::Desktop, true);
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered() && driverCacheClears == cacheClears,
              "preferred-interface pending answer left obligations or cleared the driver cache");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestBlockOtherInterfacesIngest() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    const auto adapter = FilterTestInterface();
    DriverVerdictSession session;
    captureSession = &session;
    const auto cacheClears = driverCacheClears;
    for (auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::Block, FirewallPolicy::Learning,
                        FirewallPolicy::Allow, FirewallPolicy::AllowAll})
    for (auto proto : {Proto::Tcp, Proto::Udp})
    for (bool ipv6 : {false, true})
    for (auto dir : {Dir::Out, Dir::In}) {
        flows.Reset();
        sentVerdicts.clear();
        RuleStore rules;
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        rules.Add(allow);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, policy);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        ingest->BeginDriverSession(session.Begin());
        rules.SetAppInterfacesActive(true);
        AskRequest request = Request(L"C:\\Apps\\block-other-interface.exe", proto, 5555);
        request.dir = dir;
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        const auto receive = [&](uint64_t id, uint32_t index, pmkext::Verdict expected, bool checkFlow) {
            request.interfaceIndex = index;
            flows.Reset();
            const auto before = sentVerdicts.size();
            IngestTestAccess::ReceivePacket(*ingest, session, request, id, {});
            Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() == std::pair{id, expected},
                  "interface-block setting was bypassed by the verdict cache or firewall policy");
            if (checkFlow) CheckPreferredInterfaceFlow(request, mode, true);
        };
        const auto baseline = policy == FirewallPolicy::BlockAll
            ? pmkext::Verdict::Drop : pmkext::Verdict::PermanentAccept;
        Check(rules.SetPreferredInterface(request.appPath, adapter.name, false), "cannot configure test interface");
        receive(1, 0, baseline, false);
        Check(rules.SetPreferredInterface(request.appPath, adapter.name, true), "cannot enable interface blocking");
        receive(2, 0, pmkext::Verdict::Drop, true);
        receive(3, 0, pmkext::Verdict::Drop, true);
        receive(4, 1, baseline, false);
        receive(5, adapter.number, baseline, false);
        receive(6, 0, pmkext::Verdict::Drop, true);
        Check(rules.SetPreferredInterface(request.appPath, L"", true), "cannot restore default interface");
        receive(7, 0, baseline, false);
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered() && driverCacheClears == cacheClears,
              "interface-block change left obligations or cleared the driver cache");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestBlockOtherInterfacesWireEvents() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    const auto adapter = FilterTestInterface();
    const auto self = ProcessImagePathRef(GetCurrentProcessId());
    Check(self && !self->text.empty(), "cannot resolve the test process image");
    DriverVerdictSession session;
    captureSession = &session;
    for (auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::AllowAll})
    for (auto proto : {Proto::Tcp, Proto::Udp})
    for (bool ipv6 : {false, true})
    for (auto dir : {Dir::Out, Dir::In}) {
        flows.Reset();
        sentVerdicts.clear();
        pmkext::ProcessTable processes;
        RuleStore rules(processes);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, policy);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        ingest->BeginDriverSession(session.Begin());
        rules.SetAppInterfacesActive(true);
        AskRequest request = Request(self->text, proto, 5555);
        request.dir = dir;
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        const auto receive = [&](uint64_t id, uint32_t index, pmkext::Verdict expected, bool checkFlow) {
            request.interfaceIndex = index;
            flows.Reset();
            const auto before = sentVerdicts.size();
            const auto handle = [&](auto event) {
                event.external_connection_id = id;
                event.process_id = request.pid;
                event.protocol = ProtoNumber(proto);
                event.direction = dir == Dir::In ? 1 : 0;
                event.interface_index = index;
                event.payload_layer = 3;
                event.local_port = request.key.lport;
                event.remote_port = request.key.rport;
                std::memcpy(event.local_ip, request.key.local.b, sizeof(event.local_ip));
                std::memcpy(event.remote_ip, request.key.remote.b, sizeof(event.remote_ip));
                if constexpr (std::is_same_v<decltype(event), pmkext::ConnectionFixedV4>)
                    ingest->HandleV4(event, nullptr, 0);
                else
                    ingest->HandleV6(event, nullptr, 0);
            };
            if (ipv6) handle(pmkext::ConnectionFixedV6{});
            else handle(pmkext::ConnectionFixedV4{});
            Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() == std::pair{id, expected},
                  "wire event bypassed the application interface restriction");
            if (checkFlow) CheckPreferredInterfaceFlow(request, mode, true);
        };
        const auto baseline = policy == FirewallPolicy::BlockAll
            ? pmkext::Verdict::Drop : pmkext::Verdict::PermanentAccept;
        const auto pathReads = IngestWorkProbe::counts.processPathReads;
        receive(1, 0, baseline, false);
        Check(IngestWorkProbe::counts.processPathReads == pathReads,
              "extreme policy resolved process paths without interface preferences");
        Check(rules.SetPreferredInterface(self->text, adapter.name, true), "cannot configure wire event test");
        receive(2, 0, pmkext::Verdict::Drop, true);
        Check(IngestWorkProbe::counts.processPathReads > pathReads,
              "extreme policy did not resolve the process path for interface restrictions");
        receive(3, 1, baseline, false);
        receive(4, adapter.number, baseline, false);
        // Событие могло быть подготовлено до включения настройки и не содержать путь.
        request.interfaceIndex = 0;
        flows.Reset();
        IngestTestAccess::ReceivePacket(*ingest, session, request, 5, {}, 3, -1, -1, true);
        Check(sentVerdicts.size() == 5 && sentVerdicts.back() == std::pair{uint64_t{5}, pmkext::Verdict::Drop},
              "interface restriction missed an event prepared without a process path");
        CheckPreferredInterfaceFlow(request, mode, true);
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

struct InterfacePreferenceRaceProbe {
    static inline RuleStore* rules = nullptr;
    static inline std::wstring appPath, interfaceName;

    static void Enable() {
        IngestWorkProbe::beforePolicyMatch = nullptr;
        rules->SetPreferredInterface(appPath, interfaceName, true);
    }
};

void TestBlockOtherInterfacesRace() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    const auto adapter = FilterTestInterface();
    const auto self = ProcessImagePathRef(GetCurrentProcessId());
    Check(self && !self->text.empty(), "cannot resolve the race-test process image");
    DriverVerdictSession session;
    captureSession = &session;
    for (auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::AllowAll}) {
        flows.Reset();
        sentVerdicts.clear();
        pmkext::ProcessTable processes;
        RuleStore rules(processes);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, policy);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        ingest->BeginDriverSession(session.Begin());
        rules.SetAppInterfacesActive(true);
        AskRequest request = Request(self->text, Proto::Udp, 5555);
        request.interfaceIndex = 0;
        InterfacePreferenceRaceProbe::rules = &rules;
        InterfacePreferenceRaceProbe::appPath = self->text;
        InterfacePreferenceRaceProbe::interfaceName = adapter.name;
        // Настройка появляется после первоначальной проверки, но до matcher-а.
        IngestWorkProbe::beforePolicyMatch = InterfacePreferenceRaceProbe::Enable;
        const auto reads = IngestWorkProbe::counts.processPathReads;
        IngestTestAccess::ReceivePacket(*ingest, session, request, 200, {}, 3, -1, -1, true);
        Check(!IngestWorkProbe::beforePolicyMatch && IngestWorkProbe::counts.processPathReads > reads &&
              sentVerdicts.size() == 1 && sentVerdicts.front() == std::pair{uint64_t{200}, pmkext::Verdict::Drop},
              "interface preference enabled during matching was bypassed");
        CheckPreferredInterfaceFlow(request, mode, true);
        ingest->EndDriverSession(session.End());
    }
    InterfacePreferenceRaceProbe::rules = nullptr;
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestBlockOtherInterfacesPending() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    const auto adapter = FilterTestInterface();
    DriverVerdictSession session;
    captureSession = &session;
    for (bool loopback : {false, true})
    for (bool answerOnce : {false, true}) {
        flows.Reset();
        sentVerdicts.clear();
        RuleStore rules;
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\block-other-pending.exe", Proto::Tcp, 5555);
        request.interfaceIndex = loopback ? 1 : 0;
        IngestTestAccess::ReceivePacket(*ingest, session, request, 100, {});
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1 && sentVerdicts.empty(), "interface-block test did not park its request");
        rules.SetPreferredInterface(request.appPath, adapter.name, true);
        if (answerOnce) {
            Check(ingest->AnswerOnce(pending.front().id, RuleAction::Allow), "cannot settle pending request");
            Check(sentVerdicts.size() == 1 && sentVerdicts.front().second ==
                  (loopback ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::PermanentDrop),
                  "pending answer ignored the selected interface or loopback exception");
        } else if (loopback) {
            Check(ingest->FlushVerdicts() == 0 && sentVerdicts.empty(),
                  "loopback pending request was settled by interface blocking");
            Check(ingest->AnswerOnce(pending.front().id, RuleAction::Allow), "cannot settle loopback request");
        } else {
            Check(ingest->FlushVerdicts() == 1 && sentVerdicts.size() == 1 &&
                  sentVerdicts.front().second == pmkext::Verdict::Drop,
                  "pending request was not blocked after enabling interface restriction");
        }
        if (!loopback) CheckPreferredInterfaceFlow(request, IngestMode::Desktop, true);
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
              "interface-block pending test left an unanswered request");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestPreferredInterfaceCacheIsolation() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    const auto entry = FilterTestInterface();
    for (bool configured : {false, true}) {
        RuleStore rules;
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        rules.Add(allow);
        allow.id = 0;
        allow.scope = RuleScope::Interface;
        allow.appPath = entry.name;
        rules.Add(allow);
        if (configured) rules.SetPreferredInterface(L"C:\\Apps\\unrelated-preference.exe", L"Missing test interface");
        auto host = IngestTestAccess::Create();
        Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
        IngestTestAccess::ResetSessionState(guest);
        host->Attach(&rules, nullptr);
        rules.SetAppInterfaceHandler([](const auto&, uint64_t) { return true; });
        DriverVerdictSession hostSession, guestSession;
        captureSession = &hostSession;
        ndisCaptureSession = &guestSession;
        sentVerdicts.clear();
        ndisVerdicts.clear();
        host->BeginDriverSession(hostSession.Begin());
        guest.BeginDriverSession(guestSession.Begin());
        AskRequest request = Request(L"", Proto::Udp);
        request.pid = 0;
        request.process.reset();
        IngestTestAccess::ReceivePacket(*host, hostSession, request, 1, {});
        IngestTestAccess::ReceivePacket(*host, hostSession, request, 2, {});
        Check(sentVerdicts.size() == 2 && IngestTestAccess::HasCurrentShapeCache(*host) == !configured,
              "unknown host path bypassed preference-safe caching or disabled the ordinary cache");
        request.key.source = TrafficSource::Ndis;
        request.key.interfaceIndex = request.interfaceIndex = entry.number;
        IngestTestAccess::ReceivePacket(guest, guestSession, request, 3, {});
        IngestTestAccess::ReceivePacket(guest, guestSession, request, 4, {});
        Check(ndisVerdicts.size() == 2 && IngestTestAccess::HasCurrentShapeCache(guest),
              "host application preferences disabled the Hyper-V shape cache");
        host->EndDriverSession(hostSession.End());
        guest.EndDriverSession(guestSession.End());
        host->Detach();
    }
    captureSession = nullptr;
    ndisCaptureSession = nullptr;
    flows.Enable(wasEnabled);
}

struct PreferredInterfaceEditorProbe {
    static inline PreferredInterfaceEditorProbe* active = nullptr;
    static constexpr int kCombo = 412;
    static constexpr int kBlockOthers = 414;
    std::wstring initial, desired;
    bool accept = true, applicable = true;
    bool initialBlock = false, desiredBlock = false, checkboxValid = false;
    bool inspected = false, found = false, complete = false, selected = false, refreshed = false;

    static std::wstring Entry(HWND combo, LRESULT index) {
        const LRESULT length = SendMessageW(combo, CB_GETLBTEXTLEN, index, 0);
        if (length == CB_ERR) return {};
        std::wstring text(static_cast<size_t>(length) + 1, L'\0');
        SendMessageW(combo, CB_GETLBTEXT, index, reinterpret_cast<LPARAM>(text.data()));
        text.resize(static_cast<size_t>(length));
        return text;
    }

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.inspected = true;
        HWND combo = GetDlgItem(dialog, kCombo);
        HWND checkbox = GetDlgItem(dialog, kBlockOthers);
        probe.found = combo != nullptr;
        probe.checkboxValid = !combo ? !checkbox : checkbox &&
            (IsWindowEnabled(checkbox) != FALSE) == !probe.initial.empty() &&
            (SendMessageW(checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED) == probe.initialBlock;
        if (combo) {
            const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
            size_t expected = 1;
            probe.complete = Entry(combo, 0) == LoadStringRes(IDS_APP_INTERFACE_DEFAULT) &&
                (GetWindowLongPtrW(combo, GWL_STYLE) & CBS_DROPDOWNLIST) == CBS_DROPDOWNLIST;
            bool available = probe.initial.empty();
            for (const auto& entry : snapshot->interfaces) {
                if (!entry.up || !entry.luid || entry.name.empty()) continue;
                ++expected;
                available |= entry.name == probe.initial;
                probe.complete &= SendMessageW(combo, CB_FINDSTRINGEXACT, static_cast<WPARAM>(-1),
                    reinterpret_cast<LPARAM>(entry.name.c_str())) != CB_ERR;
            }
            if (!available) ++expected;
            probe.complete &= SendMessageW(combo, CB_GETCOUNT, 0, 0) == static_cast<LRESULT>(expected);
            const std::wstring expectedText = probe.initial.empty() ? LoadStringRes(IDS_APP_INTERFACE_DEFAULT) :
                available ? probe.initial : LoadStringResFmt(IDS_APP_INTERFACE_OFFLINE_FMT, probe.initial.c_str());
            probe.selected = Entry(combo, SendMessageW(combo, CB_GETCURSEL, 0, 0)) == expectedText;
            SendMessageW(dialog, RuleStore::kInterfacesChanged, 0, 0);
            probe.refreshed = Entry(combo, SendMessageW(combo, CB_GETCURSEL, 0, 0)) == expectedText;
            if (probe.desired != probe.initial) {
                const LRESULT selection = probe.desired.empty() ? 0 : SendMessageW(combo, CB_FINDSTRINGEXACT,
                    static_cast<WPARAM>(-1), reinterpret_cast<LPARAM>(probe.desired.c_str()));
                if (selection == CB_ERR) probe.complete = false;
                else {
                    SendMessageW(combo, CB_SETCURSEL, selection, 0);
                    SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(kCombo, CBN_SELCHANGE), 0);
                }
            }
            probe.checkboxValid &= checkbox && (IsWindowEnabled(checkbox) != FALSE) == !probe.desired.empty();
            if (checkbox && IsWindowEnabled(checkbox) && probe.initialBlock != probe.desiredBlock)
                SendMessageW(checkbox, BM_CLICK, 0, 0);
        }
        PostMessageW(dialog, WM_COMMAND, probe.accept ? IDOK : IDCANCEL, 0);
    }
};

void TestPreferredInterfaceEditor() {
    const UiLang original = CurrentUiLang();
    const auto entry = FilterTestInterface();
    for (UiLang language : {UiLang::Russian, UiLang::English, UiLang::Arabic}) {
        SetUiLang(language);
        for (int scenario = 0; scenario < 3; ++scenario)
        for (bool accept : {false, true}) {
            std::vector<uint64_t> commands;
            RuleStore store;
            store.SetAppInterfaceHandler([&](const auto&, uint64_t luid) { commands.push_back(luid); return true; });
            store.SetAppInterfacesActive(true);
            PreferredInterfaceEditorProbe probe;
            probe.initial = scenario == 0 ? L"" : scenario == 1 ? entry.name : L"Missing interface café 网络";
            probe.desired = scenario == 0 ? entry.name : scenario == 1 ? L"" : probe.initial;
            probe.initialBlock = scenario != 0;
            probe.desiredBlock = scenario != 2;
            probe.accept = accept;
            const std::wstring path = L"C:\\Apps\\preferred-interface-editor.exe";
            store.SetPreferredInterface(path, probe.initial, probe.initialBlock);
            const auto before = commands.size();
            PreferredInterfaceEditorProbe::active = &probe;
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, PreferredInterfaceEditorProbe::Inspect);
            Check(timer != 0, "cannot create preferred-interface editor probe");
            const bool saved = AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store, path, L"test");
            KillTimer(nullptr, timer);
            PreferredInterfaceEditorProbe::active = nullptr;
            Check(probe.inspected && probe.found && probe.complete && probe.selected && probe.refreshed && probe.checkboxValid,
                  "preferred-interface editor lost its selection or checkbox state");
            Check(saved == accept && store.GetPreferredInterface(path) == (accept ? probe.desired : probe.initial) &&
                  store.GetBlockOtherInterfaces(path) == (accept ? probe.desiredBlock : probe.initialBlock),
                  "preferred-interface editor did not preserve cancellation or store the selected settings");
            const bool changed = accept && probe.desired != probe.initial;
            Check(commands.size() == before + (changed ? 1u : 0u),
                  "preferred-interface editor applied an unchanged or cancelled selection");
            if (changed) Check(commands.back() == (probe.desired.empty() ? 0 : entry.luid),
                               "preferred-interface editor sent an incorrect LUID");
        }
        for (auto scope : {RuleScope::Global, RuleScope::PostApp, RuleScope::Interface}) {
            RuleStore store;
            PreferredInterfaceEditorProbe probe;
            probe.accept = false;
            PreferredInterfaceEditorProbe::active = &probe;
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, PreferredInterfaceEditorProbe::Inspect);
            Check(timer != 0, "cannot create preferred-interface scope probe");
            AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store, entry.name, L"test",
                                scope == RuleScope::Global, scope == RuleScope::PostApp, scope == RuleScope::Interface);
            KillTimer(nullptr, timer);
            PreferredInterfaceEditorProbe::active = nullptr;
            Check(probe.inspected && !probe.found && probe.checkboxValid,
                  "preferred interface or checkbox was offered for a rule group rather than a program");
        }
    }
    SetUiLang(original);
    Ui::ReleaseFonts();
}

} // namespace
