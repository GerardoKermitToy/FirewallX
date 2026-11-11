#pragma once

namespace {

void CheckInheritanceResult(RuleStore& store, const MatchQuery& query, uint64_t id,
                            RuleAction action, RuleScope scope = RuleScope::App) {
    CheckRuleResult(store, query, id, action, scope);
}

std::wstring InheritanceTestPath(uint64_t pid, DWORD& error) {
    error = ERROR_SUCCESS;
    switch (pid) {
    case 10: return L"C:\\Inheritance\\oldest.exe";
    case 20: return L"C:\\Inheritance\\middle.exe";
    case 30: case 40: return L"C:\\Inheritance\\child.exe";
    case 50: return L"C:\\Inheritance\\grandchild.exe";
    case 60: return L"C:\\Inheritance\\other.exe";
    case 77: error = ERROR_ACCESS_DENIED; return {};
    default: return L"C:\\Inheritance\\unknown.exe";
    }
}

struct InheritanceFixture {
    pmkext::ProcessTable processes{InheritanceTestPath};
    RuleStore rules{processes};

    void Create(uint64_t pid, uint64_t parent) {
        const pmkext::ProcessCreated value{pid, parent};
        Check(processes.applyCreated(&value, 1), "inheritance process creation failed");
    }
    void Exit(uint64_t pid) {
        const pmkext::ProcessTerminated value{pid};
        Check(processes.applyTerminated(&value, 1), "inheritance process exit failed");
    }
    std::wstring Path(uint64_t pid) const {
        DWORD error;
        return InheritanceTestPath(pid, error);
    }
    MatchQuery QueryFor(DWORD pid, uint16_t port = 443) const {
        pmkext::ProcessInfo info;
        Check(processes.find(pid, info), "inheritance query process missing");
        return MakeMatchQuery(info.path ? std::wstring_view(*info.path) : std::wstring_view{},
            pid, MakeFlowKey(Proto::Tcp, kLocal, kRemote, 41000, port), Dir::Out);
    }
    Rule Add(DWORD pid, RuleAction action, uint16_t port = 0) {
        Rule rule;
        rule.appPath = Path(pid);
        rule.conds = port ? CondRemotePort | CondProto : CondNone;
        if (port) rule.remotePorts.push_back({port, port});
        rule.action = action;
        rules.Add(rule);
        return rule;
    }
    void Tree() {
        // Снимок приходит в обратном порядке: связь предков достраивается позже.
        const pmkext::ProcessCreated values[] = {
            {50, 30}, {30, 20}, {20, 10}, {10, 4}, {40, 60}, {60, 4}, {4, 0}, {0, 0}
        };
        Check(processes.applyCreated(values, static_cast<uint32_t>(std::size(values))),
              "inheritance baseline failed");
    }
};

void TestRuleInheritancePriority() {
    InheritanceFixture f;
    f.Tree();
    const Rule oldest = f.Add(10, RuleAction::Allow, 443);
    const Rule middle = f.Add(20, RuleAction::Block);
    const Rule child = f.Add(30, RuleAction::Block);
    const Rule grandchild = f.Add(50, RuleAction::Allow);
    CheckInheritanceResult(f.rules, f.QueryFor(30), child.id, RuleAction::Block);
    Check(f.rules.GetInheritance(f.Path(10)) == RuleInheritance::Default,
          "new app did not default to normal rule handling");
    f.rules.SetInheritance(f.Path(20), RuleInheritance::Enabled);
    CheckInheritanceResult(f.rules, f.QueryFor(30), middle.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Enabled);
    CheckInheritanceResult(f.rules, f.QueryFor(30), oldest.id, RuleAction::Allow);
    CheckInheritanceResult(f.rules, f.QueryFor(20), oldest.id, RuleAction::Allow);
    CheckInheritanceResult(f.rules, f.QueryFor(50), oldest.id, RuleAction::Allow);
    // Тот же EXE вне ветви наследования продолжает использовать свои правила.
    CheckInheritanceResult(f.rules, f.QueryFor(40), child.id, RuleAction::Block);
    Check(!Matches(f.rules, f.QueryFor(30, 80)),
          "unmatched oldest ancestor fell back to younger or own rules");
    f.rules.SetEnabled(oldest.id, false);
    Check(!Matches(f.rules, f.QueryFor(30)),
          "disabled oldest rule fell back to child rules");
    f.rules.Remove(oldest.id);
    Check(!Matches(f.rules, f.QueryFor(30)) &&
          f.rules.GetInheritance(f.Path(10)) == RuleInheritance::Enabled,
          "removing last parent rule removed inheritance or exposed child rules");
    const Rule replacement = f.Add(10, RuleAction::Allow);
    CheckInheritanceResult(f.rules, f.QueryFor(30), replacement.id, RuleAction::Allow);

    f.rules.SetInheritance(f.Path(30), RuleInheritance::Never);
    CheckInheritanceResult(f.rules, f.QueryFor(30), child.id, RuleAction::Block);
    // Исключение относится к этому приложению, а не стирает его родство.
    CheckInheritanceResult(f.rules, f.QueryFor(50), replacement.id, RuleAction::Allow);
    f.rules.SetInheritance(f.Path(50), RuleInheritance::Never);
    CheckInheritanceResult(f.rules, f.QueryFor(50), grandchild.id, RuleAction::Allow);
    f.rules.SetInheritance(f.Path(30), RuleInheritance::Default);
    CheckInheritanceResult(f.rules, f.QueryFor(30), replacement.id, RuleAction::Allow);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Default);
    CheckInheritanceResult(f.rules, f.QueryFor(30), middle.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(20), RuleInheritance::Default);
    CheckInheritanceResult(f.rules, f.QueryFor(30), child.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(20), RuleInheritance::EnabledAndNever);
    CheckInheritanceResult(f.rules, f.QueryFor(20), middle.id, RuleAction::Block);
    CheckInheritanceResult(f.rules, f.QueryFor(30), middle.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Enabled);
    CheckInheritanceResult(f.rules, f.QueryFor(20), middle.id, RuleAction::Block);
    CheckInheritanceResult(f.rules, f.QueryFor(30), replacement.id, RuleAction::Allow);
}

void TestRuleInheritanceScopesAndLifetime() {
    InheritanceFixture f;
    f.Tree();
    const Rule oldest = f.Add(10, RuleAction::Block, 443);
    const Rule child = f.Add(30, RuleAction::Allow);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Enabled);
    Rule post;
    post.scope = RuleScope::PostApp;
    post.conds = CondNone;
    post.action = RuleAction::Block;
    f.rules.Add(post);
    CheckInheritanceResult(f.rules, f.QueryFor(30, 80), post.id, RuleAction::Block, RuleScope::PostApp);
    Rule global;
    global.scope = RuleScope::Global;
    global.conds = CondNone;
    global.action = RuleAction::Allow;
    f.rules.Add(global);
    CheckInheritanceResult(f.rules, f.QueryFor(30), global.id, RuleAction::Allow, RuleScope::Global);
    f.rules.Remove(global.id);
    const auto source = f.rules.InheritedSource(f.QueryFor(50));
    Check(source.pid == 10 && source.path && *source.path->text == f.Path(10),
          "wrong oldest enabled ancestor selected");
    f.Exit(10);
    f.Exit(20);
    CheckInheritanceResult(f.rules, f.QueryFor(30), oldest.id, RuleAction::Block);
    Check(!f.rules.CanSetInheritance(f.Path(10), 0) &&
          !f.rules.CanSetInheritance(f.Path(10), 4) &&
          !f.rules.SetInheritance(L"", RuleInheritance::Enabled),
          "system or unavailable application allowed inheritance configuration");
    MatchQuery special = f.QueryFor(30);
    for (DWORD pid : {0UL, 4UL}) {
        special.pid = pid;
        CheckInheritanceResult(f.rules, special, child.id, RuleAction::Allow);
    }
    special = f.QueryFor(30);
    special.source = TrafficSource::Ndis;
    Check(!Matches(f.rules, special), "host inherited rules matched Hyper-V traffic");
    f.Create(77, 20);
    CheckInheritanceResult(f.rules, f.QueryFor(77), oldest.id, RuleAction::Block);
    f.processes.clear();
    Check(source.path && *source.path->text == f.Path(10),
          "clearing process tree invalidated retained rule source path");
}

void TestRuleInheritanceLateParentsAndVersions() {
    InheritanceFixture f;
    f.Create(30, 20);
    const Rule own = f.Add(30, RuleAction::Block);
    const Rule middle = f.Add(20, RuleAction::Allow);
    const Rule oldest = f.Add(10, RuleAction::Block);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Enabled);
    f.rules.SetInheritance(f.Path(20), RuleInheritance::Enabled);
    const uint64_t before = f.rules.version();
    CheckInheritanceResult(f.rules, f.QueryFor(30), own.id, RuleAction::Block);
    f.Create(20, 10);
    Check(f.rules.version() != before, "process ancestry change did not invalidate external caches");
    CheckInheritanceResult(f.rules, f.QueryFor(30), middle.id, RuleAction::Allow);
    f.Create(10, 10);
    CheckInheritanceResult(f.rules, f.QueryFor(30), oldest.id, RuleAction::Block);
    const uint64_t observed = f.rules.version();
    f.Create(10, 10);
    Check(f.rules.version() == observed, "duplicate process snapshot invalidated caches");
    f.rules.SetInheritance(f.Path(20), RuleInheritance::Never);
    CheckInheritanceResult(f.rules, f.QueryFor(20), middle.id, RuleAction::Allow);
    CheckInheritanceResult(f.rules, f.QueryFor(30), oldest.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Default);
    const uint64_t noInheritance = f.rules.version();
    f.Create(60, 60);
    Check(f.rules.version() == noInheritance, "inactive inheritance adds process-event cache churn");
}

void TestRuleInheritanceDatabase() {
    wchar_t directory[MAX_PATH]{}, filename[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length && length < MAX_PATH && GetTempFileNameW(directory, L"fxi", 0, filename),
          "inheritance temporary database creation failed");
    InheritanceFixture f;
    f.Tree();
    std::wstring error;
    {
        RuleStore writer(f.processes);
        Check(writer.AttachDatabase(filename, error), "inheritance database attach failed");
        writer.SetInheritance(f.Path(10), RuleInheritance::Enabled);
        writer.SetInheritance(f.Path(30), RuleInheritance::Never);
        Rule rule;
        rule.appPath = f.Path(10);
        rule.conds = CondNone;
        writer.Add(rule);
        writer.Remove(rule.id);
        Check(writer.dbError().empty(), "inheritance settings save failed");
    }
    for (bool service : {false, true}) {
        RuleStore loaded(f.processes);
        Check(service ? loaded.LoadOnce(filename, error) : loaded.AttachDatabase(filename, error),
              "inheritance settings reload failed");
        Check(loaded.Count() == 0 &&
              loaded.GetInheritance(FoldCaseCopy(f.Path(10))) == RuleInheritance::Enabled &&
              loaded.GetInheritance(f.Path(30)) == RuleInheritance::Never,
              "inheritance depended on an individual rule or path case");
        const auto apps = loaded.Apps();
        Check(std::any_of(apps.begin(), apps.end(), [&](const AppEntry& app) {
            return EqualNoCase(app.path, f.Path(10));
        }), "application with inheritance but no rules disappeared from editors");
        loaded.ReplaceApp(f.Path(10), L"parent", {});
        Check(loaded.GetInheritance(f.Path(10)) == RuleInheritance::Enabled,
              "replacing application rules overwrote its inheritance setting");
        if (!service) {
            loaded.RemoveApp(f.Path(30));
            Check(loaded.GetInheritance(f.Path(30)) == RuleInheritance::Default,
                  "removing app did not remove its independent settings");
            loaded.SetInheritance(f.Path(30), RuleInheritance::Never);
        } else {
            Check(!loaded.LoadOnce(std::wstring(filename) + L"\\missing.db", error) &&
                  !loaded.inheritanceConds() && loaded.GetInheritance(f.Path(10)) == RuleInheritance::Default,
                  "failed service reload retained old inheritance settings");
        }
    }
    {
        RuleStore loaded(f.processes);
        Check(loaded.AttachDatabase(filename, error), "inheritance cleanup attach failed");
        loaded.Clear();
        Check(loaded.Count() == 0 && !loaded.inheritanceConds() &&
              loaded.GetInheritance(f.Path(10)) == RuleInheritance::Default,
              "clearing settings-only store retained inheritance");
    }
    Check(DeleteFileW(filename) != FALSE, "inheritance temporary database cleanup failed");
}

void TestRuleInheritanceRetainedPending() {
    InheritanceFixture f;
    f.Tree();
    const Rule oldest = f.Add(10, RuleAction::Allow);
    const Rule middle = f.Add(20, RuleAction::Block);
    const Rule own = f.Add(30, RuleAction::Block);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Enabled);
    f.rules.SetInheritance(f.Path(20), RuleInheritance::Enabled);
    const auto retained = f.rules.RetainProcess(30);
    const std::wstring childPath = f.Path(30);
    MatchQuery query = MakeMatchQuery(childPath, 30,
        MakeFlowKey(Proto::Tcp, kLocal, kRemote, 41000, 443), Dir::Out);
    query.lineage = retained.get();
    CheckInheritanceResult(f.rules, query, oldest.id, RuleAction::Allow);
    for (uint64_t pid : {10, 20, 50, 30, 40, 60, 4, 0}) f.Exit(pid);
    Check(f.processes.size() == 0, "retaining pending prevented normal process-table cleanup");
    CheckInheritanceResult(f.rules, query, oldest.id, RuleAction::Allow);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Default);
    CheckInheritanceResult(f.rules, query, middle.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(30), RuleInheritance::Never);
    CheckInheritanceResult(f.rules, query, own.id, RuleAction::Block);
}

void TestRuleInheritanceMissingPath() {
    InheritanceFixture f;
    f.Tree();
    const Rule inherited = f.Add(10, RuleAction::Allow);
    const Rule own = f.Add(30, RuleAction::Block);
    f.rules.SetInheritance(f.Path(10), RuleInheritance::Enabled);
    f.rules.SetInheritance(f.Path(30), RuleInheritance::EnabledAndNever);
    MatchQuery query = f.QueryFor(30);
    query.appPath = {};
    PrepareMatchAppPath(query, {}, kFoldedTextHashBasis);
    Check(!f.rules.InheritedSource(query), "empty path bypassed the no-inherit flag");
    CheckInheritanceResult(f.rules, query, own.id, RuleAction::Block);
    const auto retained = f.rules.RetainProcess(30);
    query.lineage = retained.get();
    for (uint64_t pid : {10, 20, 50, 30, 40, 60, 4, 0}) f.Exit(pid);
    f.Create(30, 10);
    Check(!f.rules.InheritedSource(query), "reused PID bypassed the old pending's no-inherit flag");
    CheckInheritanceResult(f.rules, query, own.id, RuleAction::Block);
    f.rules.SetInheritance(f.Path(30), RuleInheritance::Default);
    CheckInheritanceResult(f.rules, query, inherited.id, RuleAction::Allow);
    query.source = TrafficSource::Ndis;
    Check(!Matches(f.rules, query), "missing path crossed the host/Hyper-V boundary");
}

bool reuseInheritancePath = false;
std::wstring ReusedInheritancePath(uint64_t pid, DWORD& error) {
    if (pid == 20 && reuseInheritancePath) pid = 60;
    return InheritanceTestPath(pid, error);
}

void TestRuleInheritanceReusedPid() {
    reuseInheritancePath = false;
    pmkext::ProcessTable processes(ReusedInheritancePath);
    RuleStore rules(processes);
    const pmkext::ProcessCreated created[] = {{10, 4}, {20, 10}, {30, 20}, {60, 4}};
    processes.applyCreated(created, static_cast<uint32_t>(std::size(created)));
    DWORD error;
    const auto oldPath = InheritanceTestPath(20, error);
    const auto newPath = InheritanceTestPath(60, error);
    Rule allow;
    allow.appPath = InheritanceTestPath(10, error);
    allow.conds = CondNone;
    rules.Add(allow);
    rules.SetInheritance(allow.appPath, RuleInheritance::Enabled);
    Rule block;
    block.appPath = newPath;
    block.conds = CondNone;
    block.action = RuleAction::Block;
    rules.Add(block);
    MatchQuery pending = MakeMatchQuery(oldPath, 20,
        MakeFlowKey(Proto::Tcp, kLocal, kRemote, 41000, 443), Dir::Out);
    const auto retained = rules.RetainProcess(20);
    pending.lineage = retained.get();
    const pmkext::ProcessTerminated exited{20};
    processes.applyTerminated(&exited, 1);
    reuseInheritancePath = true;
    const pmkext::ProcessCreated reused{20, 60};
    processes.applyCreated(&reused, 1);
    const auto current = MakeMatchQuery(newPath, 20,
        MakeFlowKey(Proto::Tcp, kLocal, kRemote, 41000, 443), Dir::Out);
    CheckInheritanceResult(rules, current, block.id, RuleAction::Block);
    CheckInheritanceResult(rules, pending, allow.id, RuleAction::Allow);
    Check(rules.InheritedSource(pending).pid == 10 && !rules.InheritedSource(current),
          "PID reuse mixed old and new effective rule sources");
    reuseInheritancePath = false;
}

void TestRuleInheritance() {
    TestRuleInheritanceMissingPath();
    TestRuleInheritanceReusedPid();
    TestRuleInheritanceRetainedPending();
    TestRuleInheritancePriority();
    TestRuleInheritanceScopesAndLifetime();
    TestRuleInheritanceLateParentsAndVersions();
    TestRuleInheritanceDatabase();
}

} // namespace
