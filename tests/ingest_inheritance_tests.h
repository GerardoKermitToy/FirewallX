#pragma once
#include "AppRulesEditor.h"

namespace {

struct InheritanceFlagsProbe {
    inline static InheritanceFlagsProbe* active = nullptr;
    bool group = false, found = false, inspected = false, accept = true;
    RuleInheritance initial = RuleInheritance::Default;
    RuleInheritance desired = RuleInheritance::EnabledAndNever;
    bool initialMatches = false, captionsMatch = false;
    bool paste = false;

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.inspected = true;
        const int base = probe.group ? 410 : 310;
        HWND give = GetDlgItem(dialog, base);
        HWND never = GetDlgItem(dialog, base + 1);
        probe.found = give && never;
        if (probe.found) {
            probe.initialMatches =
                (SendMessageW(give, BM_GETCHECK, 0, 0) == BST_CHECKED) == RuleInheritanceEnabled(probe.initial) &&
                (SendMessageW(never, BM_GETCHECK, 0, 0) == BST_CHECKED) == RuleInheritanceBlocked(probe.initial);
            wchar_t caption[256]{};
            GetWindowTextW(give, caption, static_cast<int>(std::size(caption)));
            probe.captionsMatch = caption == LoadStringRes(IDS_INHERITANCE_ENABLED);
            GetWindowTextW(never, caption, static_cast<int>(std::size(caption)));
            probe.captionsMatch &= caption == LoadStringRes(IDS_INHERITANCE_NEVER);
            SendMessageW(give, BM_SETCHECK, RuleInheritanceEnabled(probe.desired) ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessageW(never, BM_SETCHECK, RuleInheritanceBlocked(probe.desired) ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(base, BN_CLICKED), reinterpret_cast<LPARAM>(give));
            SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(base + 1, BN_CLICKED), reinterpret_cast<LPARAM>(never));
            if (probe.paste) SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(308, BN_CLICKED), 0);
        }
        PostMessageW(dialog, WM_COMMAND, probe.accept ? IDOK : IDCANCEL, 0);
    }
};

void TestInheritanceEditorFlags() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS};
    Check(InitCommonControlsEx(&controls) != FALSE, "inheritance editor controls init failed");
    const UiLang original = CurrentUiLang();
    for (UiLang language : {UiLang::Russian, UiLang::English, UiLang::Arabic}) {
        SetUiLang(language);
        for (bool editing : {false, true})
        for (bool accept : {false, true})
        for (RuleInheritance desired : {RuleInheritance::Default, RuleInheritance::Enabled,
                                       RuleInheritance::Never, RuleInheritance::EnabledAndNever}) {
            Rule rule = MakeEditorTemplate(Request(L"C:\\Apps\\inheritance-editor.exe"));
            const Rule before = rule;
            Rule clipboard;
            clipboard.appPath = L"C:\\Apps\\other.exe";
            clipboard.conds = CondNone;
            RuleClipboard::Set(clipboard);
            RuleInheritance mode = RuleInheritance::Never;
            InheritanceFlagsProbe probe;
            probe.initial = mode;
            probe.desired = desired;
            probe.accept = accept;
            probe.paste = true;
            InheritanceFlagsProbe::active = &probe;
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, InheritanceFlagsProbe::Inspect);
            Check(timer != 0, "inheritance editor timer creation failed");
            const bool saved = RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, editing, {}, &mode);
            KillTimer(nullptr, timer);
            InheritanceFlagsProbe::active = nullptr;
            Check(probe.inspected && probe.found && probe.initialMatches && probe.captionsMatch,
                  "inheritance flags missing, wrong initial state or untranslated");
            Check(saved == accept && mode == (accept ? desired : RuleInheritance::Never),
                  "inheritance flags were coupled or cancellation changed app settings");
            Check(rule.appPath == before.appPath, "rule paste changed application identity");
        }
        for (RuleScope scope : {RuleScope::Global, RuleScope::PostApp, RuleScope::Interface}) {
            Rule rule;
            rule.scope = scope;
            RuleInheritance mode = RuleInheritance::EnabledAndNever;
            InheritanceFlagsProbe probe;
            InheritanceFlagsProbe::active = &probe;
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, InheritanceFlagsProbe::Inspect);
            Check(timer != 0, "scope editor timer creation failed");
            RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, false, {}, &mode);
            KillTimer(nullptr, timer);
            InheritanceFlagsProbe::active = nullptr;
            Check(probe.inspected && !probe.found && mode == RuleInheritance::EnabledAndNever,
                  "inheritance flags appeared outside a process application rule");
        }
    }
    SetUiLang(original);
    for (DWORD pid : {0UL, 4UL, 12000UL})
    for (bool accept : {false, true}) {
        RuleStore rules;
        const std::wstring path = L"C:\\Apps\\inheritance-app-editor.exe";
        rules.SetInheritance(path, RuleInheritance::Never);
        InheritanceFlagsProbe probe;
        probe.group = true;
        probe.accept = accept;
        probe.initial = RuleInheritance::Never;
        InheritanceFlagsProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, InheritanceFlagsProbe::Inspect);
        Check(timer != 0, "application editor timer creation failed");
        const bool saved = AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), rules, path,
            L"editor", false, false, false, pid);
        KillTimer(nullptr, timer);
        InheritanceFlagsProbe::active = nullptr;
        const bool eligible = pid != 0 && pid != 4;
        Check(saved == accept && probe.inspected && probe.found == eligible,
              "PID 0/4 inheritance eligibility not respected by application editor");
        Check(rules.GetInheritance(path) == (eligible && accept
                  ? RuleInheritance::EnabledAndNever : RuleInheritance::Never),
              "application editor cancellation lost or saved flags unexpectedly");
    }
    Ui::ReleaseFonts();
}

std::wstring IngestInheritancePath(uint64_t pid, DWORD& error) {
    error = ERROR_SUCCESS;
    return pid == 10101 ? L"C:\\Apps\\inheritance-parent.exe" : L"C:\\Apps\\inheritance-child.exe";
}

void TestInheritanceShapeCacheAndPending() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    for (IngestMode mode : {IngestMode::Desktop, IngestMode::Service}) {
        pmkext::ProcessTable processes(IngestInheritancePath);
        const pmkext::ProcessCreated created[] = {{10102, 10101}, {10103, 4}, {10101, 4}};
        processes.applyCreated(created, static_cast<uint32_t>(std::size(created)));
        RuleStore rules(processes);
        Rule parent;
        parent.appPath = L"C:\\Apps\\inheritance-parent.exe";
        parent.conds = CondNone;
        parent.action = RuleAction::Allow;
        rules.Add(parent);
        Rule child = parent;
        child.id = 0;
        child.appPath = L"C:\\Apps\\inheritance-child.exe";
        child.action = RuleAction::Block;
        rules.Add(child);
        rules.SetInheritance(parent.appPath, RuleInheritance::Enabled);
        auto ingest = IngestTestAccess::Create();
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        ingest->Attach(&rules, nullptr, mode);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(child.appPath, Proto::Udp, 2222);
        request.process.reset();
        const std::vector<uint8_t> packet;
        for (uint64_t id = 1; id <= 6; ++id) {
            request.pid = id % 2 ? 10102 : 10103;
            IngestTestAccess::ReceivePacket(*ingest, session, request, id, packet, 4);
            Check(sentVerdicts.back() == std::make_pair(id, id % 2
                ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop),
                "shape cache mixed identical executables under different parents");
        }
        const pmkext::ProcessCreated added{10104, 10101};
        processes.applyCreated(&added, 1);
        request.pid = 10102;
        IngestTestAccess::ReceivePacket(*ingest, session, request, 8, packet, 4);
        Check(sentVerdicts.back().second == pmkext::Verdict::PermanentAccept &&
              IngestTestAccess::HasCurrentShapeCache(*ingest),
              "process event invalidated the shape cache without allowing it to refill");
        const size_t cacheClearsBefore = driverCacheClears;
        rules.SetInheritance(child.appPath, RuleInheritance::Never);
        request.pid = 10102;
        IngestTestAccess::ReceivePacket(*ingest, session, request, 7, packet, 4);
        Check(sentVerdicts.back().second == pmkext::Verdict::Drop,
              "shape cache ignored no-inherit flag");
        Check(driverCacheClears == cacheClearsBefore,
              "inheritance flag change reset the driver cache");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
    {
        pmkext::ProcessTable processes(IngestInheritancePath);
        const pmkext::ProcessCreated created[] = {{10102, 10101}, {10101, 4}};
        processes.applyCreated(created, static_cast<uint32_t>(std::size(created)));
        RuleStore rules(processes);
        rules.SetInheritance(L"C:\\Apps\\inheritance-parent.exe", RuleInheritance::Enabled);
        Rule own;
        own.appPath = L"C:\\Apps\\inheritance-child.exe";
        own.conds = CondNone;
        own.action = RuleAction::Allow;
        rules.Add(own);
        auto ingest = IngestTestAccess::Create();
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(own.appPath, Proto::Udp, 2222);
        request.pid = 10102;
        request.process.reset();
        const std::vector<uint8_t> packet;
        IngestTestAccess::ReceivePacket(*ingest, session, request, 50, packet, 4);
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1 && pending[0].pid == request.pid &&
              pending[0].appPath == request.appPath && pending[0].lineage,
              "inheritance changed displayed owner or did not retain pending lineage");
        const AskRequest forRule = RequestForRuleCreation(pending[0], rules);
        Check(forRule.pid == 10101 && forRule.appPath == L"C:\\Apps\\inheritance-parent.exe" &&
              forRule.id == pending[0].id && request.pid == 10102,
              "Ask rule template targeted ignored child rules or replaced the original obligation");
        const pmkext::ProcessTerminated exited[] = {{10102}, {10101}, {4}};
        processes.applyTerminated(exited, static_cast<uint32_t>(std::size(exited)));
        Check(ingest->FlushVerdicts() == 0 && sentVerdicts.empty() && ingest->waiting() == 1,
              "process exit changed inherited pending into own allow/drop decision");
        Rule parent = MakeBlockRule(forRule);
        rules.Add(parent);
        Check(ingest->FlushVerdicts() == 1 && sentVerdicts.size() == 1 &&
              sentVerdicts[0] == std::make_pair(uint64_t{50}, pmkext::Verdict::Drop) &&
              ingest->calls() == ingest->answered(),
              "retained pending did not match newly created parent rule");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestInheritanceLatePending() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    for (bool childKnown : {false, true}) {
        pmkext::ProcessTable processes(IngestInheritancePath);
        RuleStore rules(processes);
        rules.SetInheritance(L"C:\\Apps\\inheritance-parent.exe", RuleInheritance::Enabled);
        const pmkext::ProcessCreated child{10102, 10101};
        if (childKnown) processes.applyCreated(&child, 1);
        auto ingest = IngestTestAccess::Create();
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\inheritance-child.exe", Proto::Udp, 2222);
        request.pid = 10102;
        request.process.reset();
        IngestTestAccess::ReceivePacket(*ingest, session, request, 501, {}, 4);
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1 && pending.front().lineage,
              "pending before process creation did not retain a lazy lineage");
        const AskRequest original = pending.front();
        if (!childKnown) processes.applyCreated(&child, 1);
        const pmkext::ProcessTerminated exited{10102};
        processes.applyTerminated(&exited, 1);
        const pmkext::ProcessCreated parent{10101, 4};
        processes.applyCreated(&parent, 1);
        ingest->ProcessEventsChanged();
        const pmkext::ProcessTerminated parentExited{10101};
        processes.applyTerminated(&parentExited, 1);
        ingest->ProcessEventsChanged();
        Check(ingest->waiting() == 1 && sentVerdicts.empty(),
              "process termination answered a late-lineage pending without a rule");
        Check(RequestForRuleCreation(original, rules).pid == 10101,
              "original Ask copy did not see a late parent after process cleanup");
        AskRequest current;
        Check(ingest->GetPending(original.id, current) && current.lineage == original.lineage,
              "late ancestry replaced pending identity instead of updating the shared node");
        Rule allow;
        allow.appPath = L"C:\\Apps\\inheritance-parent.exe";
        allow.conds = CondNone;
        rules.Add(allow);
        Check(ingest->FlushVerdicts() == 1 && ingest->waiting() == 0 &&
              sentVerdicts.size() == 1 && sentVerdicts.front() ==
                  std::make_pair(uint64_t{501}, pmkext::Verdict::PermanentAccept),
              "late retained ancestor rule did not settle the original obligation");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
    flows.Enable(wasEnabled);
}

std::wstring InheritancePresetPath(uint64_t pid, DWORD& error) {
    error = ERROR_SUCCESS;
    return pid == 12102 ? L"C:\\Apps\\chrome.exe" : L"C:\\Apps\\launcher.exe";
}

void TestInheritanceChangingPresetSource() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    pmkext::ProcessTable processes(InheritancePresetPath);
    RuleStore rules(processes);
    rules.SetInheritance(L"C:\\Apps\\launcher.exe", RuleInheritance::Enabled);
    const pmkext::ProcessCreated child{12102, 12101};
    processes.applyCreated(&child, 1);
    auto ingest = IngestTestAccess::Create();
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    AskRequest request = Request(L"C:\\Apps\\chrome.exe");
    request.pid = 12102;
    request.process.reset();
    IngestTestAccess::ReceivePacket(*ingest, session, request, 601, {}, 4);
    std::vector<AskRequest> pending;
    ingest->TakePending(pending);
    Check(pending.size() == 1, "changing preset source did not produce pending");
    AskWindow window;
    bool applied = false;
    window.onDecision = [&](const AskRequest& original, const AskDecision& decision) {
        const AskRequest target = RequestForRuleCreation(original, rules);
        Check(decision.action == AskAction::Preset && target.pid == 12101 &&
              !decision.presetRules.empty() &&
              decision.presetRules.front().appPath == request.appPath,
              "preset selection did not preserve displayed rules while ancestry changed");
        const size_t count = RulePresets::ApplySelected(rules, target, decision.presetRules);
        Check(count == decision.presetRules.size() && rules.ForApp(request.appPath).empty(),
              "stale preset was dropped or stored under the ignored child");
        Check(RulePresets::ApplySelected(rules, target, decision.presetRules) == 0,
              "retargeted preset bypassed rule deduplication");
        applied = true;
    };
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), nullptr, pending.front(), 0, {}, &rules),
          "changing source Ask window creation failed");
    const pmkext::ProcessCreated parent{12101, 4};
    processes.applyCreated(&parent, 1);
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(applied && ingest->FlushVerdicts() == 1 && ingest->waiting() == 0 &&
          sentVerdicts.size() == 1 && sentVerdicts.front().second == pmkext::Verdict::Accept,
          "selected preset under a late ancestor did not resolve the pending connection");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    flows.Enable(wasEnabled);
}

std::wstring PendingReusePath(uint64_t pid, DWORD& error) {
    error = ERROR_SUCCESS;
    if (pid == 13101) return L"C:\\Apps\\old-parent.exe";
    if (pid == 13104) return L"C:\\Apps\\new-parent.exe";
    return L"C:\\Apps\\same-child.exe";
}

void TestInheritancePendingPidReuse() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    pmkext::ProcessTable processes(PendingReusePath);
    const pmkext::ProcessCreated created[] = {{13101, 4}, {13104, 4}, {13102, 13101}};
    processes.applyCreated(created, static_cast<uint32_t>(std::size(created)));
    RuleStore rules(processes);
    rules.SetInheritance(L"C:\\Apps\\old-parent.exe", RuleInheritance::Enabled);
    rules.SetInheritance(L"C:\\Apps\\new-parent.exe", RuleInheritance::Enabled);
    auto ingest = IngestTestAccess::Create();
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    AskRequest request = Request(L"C:\\Apps\\same-child.exe", Proto::Udp, 2222);
    request.pid = 13102;
    request.process.reset();
    IngestTestAccess::ReceivePacket(*ingest, session, request, 701, {}, 4);
    const pmkext::ProcessTerminated exited{13102};
    processes.applyTerminated(&exited, 1);
    const pmkext::ProcessCreated reused{13102, 13104};
    processes.applyCreated(&reused, 1);
    IngestTestAccess::ReceivePacket(*ingest, session, request, 702, {}, 4);
    IngestTestAccess::ReceivePacket(*ingest, session, request, 703, {}, 4);
    std::vector<AskRequest> pending;
    ingest->TakePending(pending);
    Check(pending.size() == 2 && ingest->waiting() == 3 &&
          pending[0].lineage != pending[1].lineage,
          "same EXE and reused PID merged pending from different process instances");
    Rule allow;
    allow.appPath = L"C:\\Apps\\old-parent.exe";
    allow.conds = CondNone;
    rules.Add(allow);
    Rule block;
    block.appPath = L"C:\\Apps\\new-parent.exe";
    block.conds = CondNone;
    block.action = RuleAction::Block;
    rules.Add(block);
    Check(ingest->FlushVerdicts() == 3 && sentVerdicts.size() == 3,
          "PID reuse pending groups did not all receive verdicts");
    for (uint64_t id : {uint64_t{701}, uint64_t{702}, uint64_t{703}})
        Check(std::find(sentVerdicts.begin(), sentVerdicts.end(), std::make_pair(id,
                  id == 701 ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop)) != sentVerdicts.end(),
              "old and new pending used the same process ancestry");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    flows.Enable(wasEnabled);
}

} // namespace
