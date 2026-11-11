#pragma once

namespace {

void TestProcessInheritanceCache() {
    pmkext::ProcessTable table(Resolve);
    constexpr uint64_t first = 1000;
    constexpr uint64_t count = 40000;
    std::vector<pmkext::ProcessCreated> values;
    values.reserve(count);
    // Холодная глубокая цепочка не должна использовать рекурсию.
    for (uint64_t pid = first + count; pid-- > first;)
        values.push_back({pid, pid == first ? first : pid - 1});
    table.applyCreated(values.data(), static_cast<uint32_t>(values.size()));
    size_t checks = 0;
    int owner = 0;
    const auto disabled = [&](const pmkext::ProcessRulePath&) { ++checks; return false; };
    Check(!table.oldestRuleAncestor(first + count - 1, &owner, 1, disabled),
          "disabled inheritance produced a rule source");
    Check(checks == count - 1, "cold chain did not prepare all ancestor caches");
    const auto before = checks;
    for (unsigned i = 0; i < 1000; ++i)
        Check(!table.oldestRuleAncestor(first + count - 1, &owner, 1, disabled),
              "hot disabled inheritance cache changed result");
    Check(checks == before, "hot inheritance lookup walked ancestors again");
    // Новый лист не сбрасывает готовые результаты существующих ветвей.
    Create(table, first + count, first + count - 1);
    Check(!table.oldestRuleAncestor(first + count, &owner, 1, disabled) && checks == before + 1,
          "new process invalidated unaffected inheritance caches");
    const auto enabled = [&](const pmkext::ProcessRulePath& path) {
        ++checks;
        return path.folded == FoldCaseCopy(*path.text) && path.hash == HashFoldedText(path.folded);
    };
    const auto result = table.oldestRuleAncestor(first + count, &owner, 2, enabled);
    Check(result.pid == first && result.path && *result.path->text == L"C:\\apps\\shared.exe",
          "oldest enabled process was not selected after a setting change");
    const auto ready = checks;
    for (unsigned i = 0; i < 1000; ++i)
        Check(table.oldestRuleAncestor(first + count, &owner, 2, enabled).pid == first,
              "hot enabled inheritance changed result");
    Check(checks == ready, "hot enabled inheritance repeated policy/path checks");
    Exit(table, first);
    Check(table.oldestRuleAncestor(first + count, &owner, 2, enabled).pid == first && checks == ready,
          "dead ancestor lost inherited rules or invalidated the ancestry cache");
    const auto retained = table.retain(first + count);
    Check(retained != nullptr, "pending deep lineage was not retained");
    Exit(table, first + count);
    for (unsigned i = 0; i < 1000; ++i)
        Check(table.oldestRuleAncestor(first + count, &owner, 2, enabled, retained.get()).pid == first,
              "exited pending lost its cached ancestor");
    Check(checks == ready, "retained lineage did not reuse the live ancestor cache");
    table.clear();
    Check(table.oldestRuleAncestor(first + count, &owner, 2, enabled, retained.get()).pid == first,
          "pending deep lineage was lost after process-table cleanup");
    const size_t retainedReady = checks;
    for (unsigned i = 0; i < 1000; ++i)
        Check(table.oldestRuleAncestor(first + count, &owner, 2, enabled, retained.get()).pid == first,
              "retained hot cache changed its result");
    Check(checks == retainedReady, "retained hot lookup walked the deep chain again");
    Check(!table.oldestRuleAncestor(first + count, &owner, 3, disabled, retained.get()),
          "retained cache ignored a changed inheritance generation");
    const size_t disabledReady = checks;
    for (unsigned i = 0; i < 1000; ++i)
        Check(!table.oldestRuleAncestor(first + count, &owner, 3, disabled, retained.get()),
              "retained negative cache changed its result");
    Check(checks == disabledReady, "retained negative result was not cached");
    Check(result.path && *result.path->text == L"C:\\apps\\shared.exe",
          "retained inheritance path invalidated by process cleanup");
}

void TestProcessInheritanceLateAncestry() {
    pmkext::ProcessTable table(Resolve);
    int owner = 0;
    const auto enabled = [](const pmkext::ProcessRulePath&) { return true; };
    Create(table, 30, 20);
    Check(!table.oldestRuleAncestor(30, &owner, 1, enabled),
          "unobserved parent unexpectedly provided a rule path");
    Create(table, 20, 10);
    Check(table.oldestRuleAncestor(30, &owner, 1, enabled).pid == 20,
          "late parent did not invalidate its cached placeholder");
    Create(table, 10, 4);
    Create(table, 4, 0);
    Create(table, 0, 0);
    Check(table.oldestRuleAncestor(30, &owner, 1, enabled).pid == 10,
          "late oldest ancestor not selected, or PID 0/4 became an inheritance source");
    const auto observedVersion = table.version();
    Create(table, 10, 4);
    Check(table.version() == observedVersion, "duplicate process record changed its generation");
    // Не даём замкнутому входному родству зависнуть в поиске предка.
    table.clear();
    Create(table, 10, 20);
    Create(table, 20, 10);
    Check(!table.oldestRuleAncestor(10, &owner, 1, enabled),
          "cyclic ancestry unexpectedly resolved to an oldest parent");
}

void TestProcessInheritancePidReuse() {
    queries = 0;
    pmkext::ProcessTable table(Resolve);
    const pmkext::ProcessCreated initial[] = {{10, 4}, {20, 10}, {30, 20}, {60, 4}};
    table.applyCreated(initial, static_cast<uint32_t>(std::size(initial)));
    const auto oldProcess = table.retain(20);
    const auto oldChild = table.retain(30);
    int owner = 0;
    const auto enabled = [](const pmkext::ProcessRulePath&) { return true; };
    Check(table.oldestRuleAncestor(30, &owner, 1, enabled).pid == 10,
          "PID reuse setup selected the wrong ancestor");
    Exit(table, 10);
    Exit(table, 20);
    Create(table, 20, 60);
    Check(!Get(table, 20).terminated && Get(table, 20).parent_pid == 60 && queries == 5,
          "reused PID kept the previous process record");
    Check(table.oldestRuleAncestor(20, &owner, 1, enabled).pid == 60,
          "new process inherited its previous instance's rules");
    Check(table.oldestRuleAncestor(30, &owner, 1, enabled).pid == 10 &&
          table.oldestRuleAncestor(20, &owner, 1, enabled, oldProcess.get()).pid == 10 &&
          table.oldestRuleAncestor(30, &owner, 1, enabled, oldChild.get()).pid == 10,
          "PID reuse rewrote old descendants or pending lineage");
    Create(table, 20, 60);
    Check(queries == 5 && Get(table, 60).children == 1,
          "duplicate live creation resolved the path or added children");
    Exit(table, 20);
    Create(table, 20, 60);
    Check(queries == 6 && table.oldestRuleAncestor(20, &owner, 1, enabled).pid == 60,
          "PID reuse with the same parent was treated as a duplicate");
    Exit(table, 30);
    pmkext::ProcessInfo removed;
    Check(!table.find(10, removed),
          "last old descendant did not prune its retired ancestors");
    Check(table.oldestRuleAncestor(20, &owner, 1, enabled).pid == 60 &&
          table.oldestRuleAncestor(20, &owner, 1, enabled, oldProcess.get()).pid == 10,
          "pruning retired entries damaged the new process or old pending");
    Exit(table, 20);
    Exit(table, 60);
    Check(table.size() == 0 && table.pathCount() == 0,
          "retired process entries or interned paths leaked after PID reuse");
}

void TestProcessInheritanceLateRetained() {
    pmkext::ProcessTable table(Resolve);
    int owner = 0;
    const auto enabled = [](const pmkext::ProcessRulePath&) { return true; };
    const auto pending = table.retain(30);
    Check(pending && pending == table.retain(30) && table.size() == 0,
          "pending before Create did not share a lazy lineage placeholder");
    Check(!table.oldestRuleAncestor(30, &owner, 1, enabled, pending.get()),
          "unobserved pending unexpectedly inherited rules");
    Create(table, 30, 20);
    Check(pending->path && pending->parent && pending->parent->pid == 20,
          "late child event did not populate the pending lineage");
    Check(!table.oldestRuleAncestor(30, &owner, 1, enabled, pending.get()),
          "unknown parent unexpectedly supplied rules");
    Exit(table, 30);
    Check(table.size() == 0, "retained placeholders prevented normal table pruning");
    Create(table, 20, 10);
    Check(table.oldestRuleAncestor(30, &owner, 1, enabled, pending.get()).pid == 20,
          "late pruned parent did not update the retained negative cache");
    Exit(table, 20);
    Create(table, 10, 4);
    Check(table.oldestRuleAncestor(30, &owner, 1, enabled, pending.get()).pid == 10,
          "late oldest ancestor was disconnected from exited pending");

    const auto missing = table.retain(77);
    Exit(table, 77);
    Create(table, 77, 10);
    Check(!missing->path && !missing->parent &&
          !table.oldestRuleAncestor(77, &owner, 1, enabled, missing.get()),
          "termination let an unknown old pending attach to a reused PID");
    const auto fresh = table.retain(77);
    Check(fresh != missing && fresh->parent && fresh->parent->pid == 10,
          "new pending retained an earlier process instance");
}

void TestProcessInheritanceConcurrentRelease() {
    for (unsigned attempt = 0; attempt < 128; ++attempt) {
        pmkext::ProcessTable table(Resolve);
        for (uint64_t pid = 100; pid < 164; ++pid)
            Create(table, pid, pid == 100 ? 20 : pid - 1);
        auto pending = table.retain(163);
        for (uint64_t pid = 100; pid < 164; ++pid) Exit(table, pid);
        Check(table.size() == 0, "release race setup retained ordinary process records");
        std::thread release([held = std::move(pending)]() mutable { held.reset(); });
        Create(table, 20, 10);
        release.join();
        const auto parent = table.retain(20);
        Check(parent && parent->parent && parent->parent->pid == 10,
              "pending release raced with a late parent and detached its new lineage");
    }
}

void TestProcessInheritanceSharedRetainedCache() {
    pmkext::ProcessTable table(Resolve);
    constexpr uint64_t first = 20000, depth = 4000, pendingCount = 128;
    std::vector<pmkext::ProcessCreated> created;
    for (uint64_t pid = first; pid < first + depth; ++pid)
        created.push_back({pid, pid == first ? 4 : pid - 1});
    for (uint64_t pid = first + depth; pid < first + depth + pendingCount; ++pid)
        created.push_back({pid, first + depth - 1});
    table.applyCreated(created.data(), static_cast<uint32_t>(created.size()));
    std::vector<pmkext::ProcessLineageRef> pending;
    for (uint64_t pid = first + depth; pid < first + depth + pendingCount; ++pid)
        pending.push_back(table.retain(pid));
    table.clear();
    int owner = 0;
    size_t checks = 0;
    const auto disabled = [&](const pmkext::ProcessRulePath&) { ++checks; return false; };
    for (const auto& process : pending)
        Check(!table.oldestRuleAncestor(process->pid, &owner, 1, disabled, process.get()),
              "shared retained chain unexpectedly inherited rules");
    Check(checks == depth, "shared pending chains repeated their common cold ancestor checks");
    const size_t cold = checks;
    for (unsigned repeat = 0; repeat < 100; ++repeat)
        for (const auto& process : pending)
            Check(!table.oldestRuleAncestor(process->pid, &owner, 1, disabled, process.get()),
                  "shared retained negative cache changed its result");
    Check(checks == cold, "rechecking many pending walked their retained chains again");
    pmkext::ProcessTable another(Resolve);
    int anotherOwner = 0;
    const auto enabled = [](const pmkext::ProcessRulePath&) { return true; };
    Check(another.oldestRuleAncestor(pending.front()->pid, &anotherOwner, 2,
                                   enabled, pending.front().get()).pid == first,
          "retained traversal marker collided between process tables");
    std::cout << "Retained inheritance cache: depth=" << depth << " pending=" << pendingCount
              << " cold_checks=" << cold << " hot_checks=" << checks - cold << '\n';
}

} // namespace
