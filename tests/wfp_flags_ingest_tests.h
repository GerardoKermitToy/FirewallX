#pragma once

namespace {
void TestWfpFlagShapeCache() {
    auto& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    DriverVerdictSession session;
    captureSession = &session;
    const auto clears = driverCacheClears;
    const uint32_t required = 0x80000101u;
    for (IngestMode mode : {IngestMode::Desktop, IngestMode::Service})
    for (RuleScope scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp})
    for (RuleAction action : {RuleAction::Allow, RuleAction::Block})
    for (bool ipv6 : {false, true}) {
        sentVerdicts.clear();
        RuleStore rules;
        Rule filtered;
        filtered.scope = scope;
        if (scope == RuleScope::App) filtered.appPath = L"C:\\Apps\\wfp-flags.exe";
        filtered.conds = CondWfpFlags;
        filtered.conditionFlags = required;
        filtered.action = action;
        rules.Add(filtered);
        Rule fallback = filtered;
        fallback.conds = CondNone;
        fallback.action = action == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow;
        rules.Add(fallback);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, FirewallPolicy::Learning);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\wfp-flags.exe", Proto::Udp);
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        uint64_t id = 0;
        const auto receive = [&](std::optional<uint32_t> flags, RuleAction expected) {
            request.conditionFlags = flags;
            const size_t before = sentVerdicts.size();
            IngestTestAccess::ReceivePacket(*ingest, session, request, ++id, {});
            const auto verdict = expected == RuleAction::Allow
                ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop;
            Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() == std::pair{id, verdict},
                  "shape cache reused a verdict across different WFP condition masks");
        };
        for (int repeat = 0; repeat < 3; ++repeat) {
            receive(required, action);
            receive(required & ~1u, fallback.action);
            receive(required | 2u, action);
            receive(0, fallback.action);
            receive(std::nullopt, fallback.action);
        }
        filtered.conditionFlags = 0;
        Check(rules.Update(filtered), "cannot change required WFP flags");
        receive(0, action);
        receive(std::nullopt, fallback.action);
        filtered.conds = CondNone;
        Check(rules.Update(filtered), "cannot disable WFP flag filter");
        receive(std::nullopt, action);
        Check(ingest->waiting() == 0 && driverCacheClears == clears,
              "WFP flag changes reset the driver cache or left pending callbacks");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Enable(wasEnabled);
    Check(IngestTestAccess::DistinctWfpFlagIdentity(),
          "pending equality or shape identity confuses WFP masks and missing fields");
}

void TestWfpFlagTemplatePrefill() {
    for (Proto proto : {Proto::Tcp, Proto::Udp, Proto::Icmp, ProtoFromNumber(144)})
    for (bool knownPath : {false, true})
    for (TrafficSource source : {TrafficSource::Host, TrafficSource::Ndis})
    for (std::optional<uint32_t> flags : {std::optional<uint32_t>{},
             std::optional<uint32_t>{0}, std::optional<uint32_t>{4},
             std::optional<uint32_t>{0x10u}, std::optional<uint32_t>{0x14u},
             std::optional<uint32_t>{0x15u}, std::optional<uint32_t>{UINT32_MAX}}) {
        AskRequest request = Request(knownPath ? L"C:\\Apps\\wfp-template.exe" : L"", proto);
        request.key.source = source;
        request.conditionFlags = flags;
        const uint32_t expected = source == TrafficSource::Host
            ? flags.value_or(0) & ~uint32_t{4} : 0;
        const Rule rule = MakeEditorTemplate(request);
        Check(rule.conditionFlags == expected && !(rule.conds & CondWfpFlags),
              "request template lost WFP flag prefill or enabled the condition automatically");
        Check(rule.BuildAutoName().find(L"REAUTHORIZE") == std::wstring::npos,
              "request template displays REAUTHORIZE");
        for (const Rule& automatic : {MakeAllowRule(request), MakeBlockRule(request)})
            Check(automatic.conditionFlags == expected && !(automatic.conds & CondWfpFlags),
                  "RAW enabled WFP flags outside the request editor template");
        Check(request.conditionFlags == flags && request.ToQuery().conditionFlags == flags,
              "UI filtering changed the original event or matcher flags");
        FlowRuleSeed seed;
        seed.key = request.key;
        seed.appPath = request.appPath;
        seed.conditionFlags = flags;
        const Rule observed = MakeNarrowRule(seed, RuleAction::Allow);
        Check(observed.conditionFlags == expected && !(observed.conds & CondWfpFlags),
              "observed flow template did not hide REAUTHORIZE or enabled RAW automatically");
    }
}

void TestWfpFlagPendingGroups() {
    auto& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    AskRequest request = Request(L"C:\\Apps\\wfp-pending.exe", Proto::Udp);
    const auto receive = [&](uint64_t id, std::optional<uint32_t> flags) {
        request.conditionFlags = flags;
        IngestTestAccess::ReceivePacket(*ingest, session, request, id, {});
    };
    receive(1, 1);
    receive(2, 2);
    receive(3, 1);
    receive(4, 0);
    receive(5, std::nullopt);
    std::vector<AskRequest> pending;
    ingest->TakePending(pending);
    Check(pending.size() == 4 && ingest->waiting() == 5 && sentVerdicts.empty(),
          "pending callbacks with different WFP masks were grouped together");
    for (const AskRequest& item : pending) {
        Check(item.ToQuery().conditionFlags == item.conditionFlags,
              "pending query lost its original WFP flags");
        Check(MakeEditorTemplate(item).conditionFlags == item.conditionFlags.value_or(0) &&
                  !(MakeEditorTemplate(item).conds & CondWfpFlags),
              "WFP flag prefill was lost or automatically enabled");
    }
    Rule rule;
    rule.scope = RuleScope::Global;
    rule.conds = CondWfpFlags;
    rule.conditionFlags = 1;
    rules.Add(rule);
    Check(ingest->FlushVerdicts() == 2 && ingest->waiting() == 3 && sentVerdicts.size() == 2,
          "a WFP flag rule answered callbacks with different masks");
    rule.conditionFlags = 0;
    Check(rules.Update(rule) && ingest->FlushVerdicts() == 2 && ingest->waiting() == 1,
          "zero required mask matched an absent field or missed a zero WFP mask");
    rule.conds = CondNone;
    Check(rules.Update(rule) && ingest->FlushVerdicts() == 1 && ingest->waiting() == 0 &&
              ingest->calls() == ingest->answered(), "WFP pending groups lost callbacks");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    flows.Enable(wasEnabled);
}

void TestWfpFlagWireEvents() {
    auto& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    DriverVerdictSession session;
    captureSession = &session;
    for (bool ipv6 : {false, true})
    for (uint8_t layer : {uint8_t{3}, uint8_t{4}})
    for (uint32_t mask : {0u, 0x80000103u, UINT32_MAX}) {
        flows.Reset();
        sentVerdicts.clear();
        RuleStore rules;
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());
        const auto handle = [&](auto event) {
            event.external_connection_id = 100;
            event.process_id = GetCurrentProcessId();
            event.protocol = ProtoNumber(Proto::Udp);
            event.payload_layer = layer;
            event.condition_flags = mask;
            event.local_port = 41000;
            event.remote_port = 5555;
            const auto local = Ip(ipv6 ? L"2001:db8::10" : L"192.0.2.10");
            const auto remote = Ip(ipv6 ? L"2001:db8::20" : L"198.51.100.20");
            std::memcpy(event.local_ip, local.b, sizeof(event.local_ip));
            std::memcpy(event.remote_ip, remote.b, sizeof(event.remote_ip));
            if constexpr (std::is_same_v<decltype(event), pmkext::ConnectionFixedV4>)
                ingest->HandleV4(event, nullptr, 0);
            else
                ingest->HandleV6(event, nullptr, 0);
        };
        if (ipv6) handle(pmkext::ConnectionFixedV6{});
        else handle(pmkext::ConnectionFixedV4{});
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1 && pending.front().conditionFlags == mask &&
                  pending.front().ToQuery().conditionFlags == mask,
              "IPv4/IPv6 ALE or IP packet callback lost its raw WFP flags");
        FlowStore::DisplayView view;
        flows.TakeDisplay(view);
        bool found = false;
        for (const auto& process : view.processes)
            for (const auto& connection : process.connections)
                if (connection.key == pending.front().key) {
                    found = true;
                    Check(connection.conditionFlags == mask,
                          "monitor snapshot lost raw WFP flags");
                }
        Check(found, "WFP event was not published to the monitor");
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondWfpFlags;
        rule.conditionFlags = mask;
        rules.Add(rule);
        Check(ingest->FlushVerdicts() == 1 && sentVerdicts.size() == 1 &&
                  sentVerdicts.front().second == pmkext::Verdict::PermanentAccept,
              "WFP callback did not match its raw flags after rule creation");
        ingest->EndDriverSession(session.End());
    }
    flows.Reset();
    flows.Enable(wasEnabled);
    captureSession = nullptr;
}

void TestWfpFlagsNeverMatchNdis() {
    using Native = firewallxndisfilter::Client;
    Ingest& host = Ingest::Instance();
    Ingest& guest = Ingest::ForSource(TrafficSource::Ndis);
    DriverVerdictSession session;
    ndisCaptureSession = &session;
    for (IngestMode mode : {IngestMode::Desktop, IngestMode::Service})
    for (uint32_t mask : {0u, 1u, UINT32_MAX}) {
        RuleStore rules;
        Rule filtered;
        filtered.scope = RuleScope::Interface;
        filtered.appPath = InterfaceDisplayName(RuntimeTestInterface());
        filtered.conds = CondWfpFlags;
        filtered.conditionFlags = mask;
        rules.Add(filtered);
        Rule fallback = filtered;
        fallback.conds = CondNone;
        fallback.action = RuleAction::Block;
        rules.Add(fallback);
        IngestTestAccess::ResetSessionState(guest);
        host.Attach(&rules, nullptr, mode);
        guest.BeginDriverSession(session.Begin());
        ndisVerdicts.clear();
        sentVerdicts.clear();
        guest.HandleNdis(NdisEvent(10), nullptr, 0);
        Native::ConnectionV6 event{};
        event.id = 20;
        event.protocol = ProtoNumber(Proto::Udp);
        event.interface_index = RuntimeTestInterface();
        event.local_ip[15] = 2;
        event.remote_ip[15] = 3;
        event.local_port = 41000;
        event.remote_port = 5555;
        guest.HandleNdis(event, nullptr, 0);
        Check(ndisVerdicts.size() == 2 && sentVerdicts.empty() &&
                  std::all_of(ndisVerdicts.begin(), ndisVerdicts.end(), [](const auto& item) {
                      return item.second == Native::Verdict::Drop;
                  }), "a WFP flag rule matched FirewallXNdisFilter events");
        guest.EndDriverSession(session.End());
        host.Detach();
    }
    ndisCaptureSession = nullptr;
    FlowStore::Instance().Reset();
}

struct WfpFlagPickerProbe {
    static inline WfpFlagPickerProbe* active = nullptr;
    uint32_t expected = 0;
    uint32_t selected = 0;
    bool inspected = false, initialCorrect = false, cancel = false, clear = false, all = false;

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog || !GetDlgItem(dialog, 320)) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        HWND list = GetDlgItem(dialog, 320);
        probe.inspected = ListView_GetItemCount(list) == 31;
        probe.initialCorrect = true;
        uint32_t visible = 0;
        for (int row = 0; row < ListView_GetItemCount(list); ++row) {
            LVITEMW item{};
            item.mask = LVIF_PARAM;
            item.iItem = row;
            probe.inspected &= ListView_GetItem(list, &item) != FALSE;
            const uint32_t mask = static_cast<uint32_t>(item.lParam);
            wchar_t text[256]{};
            ListView_GetItemText(list, row, 0, text, static_cast<int>(std::size(text)));
            probe.inspected &= mask != 4 && std::wstring_view(text).find(L"REAUTHORIZE") == std::wstring_view::npos;
            visible |= mask;
            const bool checked = ListView_GetCheckState(list, row) != FALSE;
            probe.initialCorrect &= checked == bool(probe.expected & mask);
            ListView_SetCheckState(list, row, (probe.selected & mask) ? TRUE : FALSE);
        }
        probe.inspected &= visible == (UINT32_MAX & ~uint32_t{4});
        if (probe.clear) SendMessageW(dialog, WM_COMMAND, 322, 0);
        if (probe.all) SendMessageW(dialog, WM_COMMAND, 321, 0);
        PostMessageW(dialog, WM_COMMAND, probe.cancel ? IDCANCEL : IDOK, 0);
    }
};

void TestWfpFlagPicker() {
    const UiLang previous = CurrentUiLang();
    for (UiLang language : {UiLang::Russian, UiLang::English, UiLang::Arabic})
    for (bool cancel : {false, true})
    for (int selection : {0, 1, 2}) {
        SetUiLang(language);
        WfpFlagPickerProbe probe;
        probe.expected = 0x80000105u;
        probe.selected = 0x40000206u;
        probe.cancel = cancel;
        probe.clear = selection == 1;
        probe.all = selection == 2;
        WfpFlagPickerProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, WfpFlagPickerProbe::Inspect);
        Check(timer != 0, "cannot create WFP flag dialog probe timer");
        uint32_t flags = probe.expected;
        const bool saved = RuleDialogs::ChooseWfpFlags(nullptr, GetModuleHandleW(nullptr), flags);
        KillTimer(nullptr, timer);
        WfpFlagPickerProbe::active = nullptr;
        const uint32_t chosen = probe.clear ? 0u : probe.all ? UINT32_MAX : probe.selected;
        Check(probe.inspected && probe.initialCorrect && saved == !cancel &&
                  flags == (cancel ? probe.expected : chosen & ~uint32_t{4}),
              "WFP flag picker lost selection, exposed REAUTHORIZE or broke clear/all/cancel");
    }
    SetUiLang(previous);
    Ui::ReleaseFonts();
}
} // namespace
