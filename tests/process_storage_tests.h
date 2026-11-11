namespace {

std::wstring ResolveStoragePath(uint64_t pid, DWORD& error) {
    error = ERROR_SUCCESS;
    return L"C:\\storage\\process" + std::to_wstring(pid) + L".exe";
}

void TestProcessStorageRetention() {
    using Access = pmkext::ProcessTableTestAccess;
    pmkext::ProcessTable table(ResolveStoragePath);
    constexpr uint64_t count = 20000;
    std::vector<pmkext::ProcessCreated> created;
    std::vector<pmkext::ProcessTerminated> ended;
    for (uint64_t i = 0; i < count; ++i) {
        created.push_back({100 + i, 0});
        ended.push_back({100 + i});
    }
    for (unsigned pass = 0; pass < 3; ++pass) {
        table.applyCreated(created.data(), static_cast<uint32_t>(created.size()));
        const auto peak = Access::Buckets(table);
        const void* address = Access::EntryAddress(table, 100);
        auto retained = table.retain(100);
        table.applyTerminated(ended.data() + 64, static_cast<uint32_t>(ended.size() - 64));
        const auto compact = Access::Buckets(table);
        Check(table.size() == 65 && table.pathCount() == 64 &&
              compact[0] < peak[0] / 8 && compact[2] < peak[2] / 8 &&
              Access::EntryAddress(table, 100) == address && retained->path &&
              *retained->path->text == L"C:\\storage\\process100.exe",
              "process/path compaction retained peak buckets or moved a surviving entry");
        const auto stable = Access::Buckets(table);
        for (unsigned i = 0; i < 100; ++i)
            table.applyCreated(created.data(), 64);
        Check(Access::Buckets(table) == stable,
              "unchanged process batches repeatedly reallocated storage");
        table.applyTerminated(ended.data(), 64);
        Check(table.size() == 0 && table.pathCount() == 0 &&
              retained->path && *retained->path->text == L"C:\\storage\\process100.exe",
              "process cleanup retained entries or invalidated a pending lineage");
        retained.reset();
        Access::MakeLateSweepDue(table);
        table.maintain();
        for (size_t buckets : Access::Buckets(table))
            Check(buckets <= 8, "drained process tables retained historical buckets");
    }
}

void TestRetiredProcessStorageRetention() {
    using Access = pmkext::ProcessTableTestAccess;
    pmkext::ProcessTable table(ResolveStoragePath);
    constexpr uint64_t count = 4096;
    std::vector<pmkext::ProcessCreated> parents, children;
    std::vector<pmkext::ProcessTerminated> parentEnds, childEnds;
    for (uint64_t i = 0; i < count; ++i) {
        parents.push_back({10000 + i, 0});
        children.push_back({50000 + i, 10000 + i});
        parentEnds.push_back({10000 + i});
        childEnds.push_back({50000 + i});
    }
    table.applyCreated(parents.data(), static_cast<uint32_t>(parents.size()));
    table.applyCreated(children.data(), static_cast<uint32_t>(children.size()));
    table.applyTerminated(parentEnds.data(), static_cast<uint32_t>(parentEnds.size()));
    table.applyCreated(parents.data(), static_cast<uint32_t>(parents.size()));
    Check(Access::RetiredSize(table) == count, "PID reuse did not retain the old parents");
    const size_t peak = Access::Buckets(table)[1];
    int owner = 0;
    const auto enabled = [](const pmkext::ProcessRulePath&) { return true; };
    Check(table.oldestRuleAncestor(50000, &owner, 1, enabled).pid == 10000,
          "retired parent was disconnected before compaction");
    table.applyTerminated(childEnds.data() + 32, static_cast<uint32_t>(childEnds.size() - 32));
    Check(Access::RetiredSize(table) == 32 && Access::Buckets(table)[1] < peak / 8 &&
          table.oldestRuleAncestor(50000, &owner, 1, enabled).pid == 10000,
          "retired table retained peak buckets or invalidated cached ancestry");
    table.applyTerminated(childEnds.data(), 32);
    Check(Access::RetiredSize(table) == 0 && Access::Buckets(table)[1] <= 8,
          "last old descendant did not release retired table storage");
    table.applyTerminated(parentEnds.data(), static_cast<uint32_t>(parentEnds.size()));
    Check(table.size() == 0 && table.pathCount() == 0,
          "retired storage fixture leaked process records");
}

void TestLateLineageStorageRetention() {
    using Access = pmkext::ProcessTableTestAccess;
    pmkext::ProcessTable table(ResolveStoragePath);
    std::vector<pmkext::ProcessLineageRef> held;
    // Первый проход видит живые ссылки. После их освобождения новые уникальные
    // PID не должны отодвигать следующий проход вместе с ростом размера индекса.
    for (uint64_t pid = 1000; pid < 1064; ++pid) held.push_back(table.retain(pid));
    held.clear();
    // До ближайшего прохода допустимы прежняя партия и ещё до 64 новых записей.
    for (uint64_t pid = 100000; pid < 120000; ++pid) {
        auto transient = table.retain(pid);
        transient.reset();
        Check(Access::LateSize(table) <= 128,
              "expired late lineages grew with new unique PIDs");
    }
    Check(table.size() == 0, "late retention unexpectedly allocated process entries");
    Access::MakeLateSweepDue(table);
    table.maintain();
    Check(Access::LateSize(table) == 0 && Access::Buckets(table)[3] <= 8,
          "idle maintenance retained expired weak entries or their buckets");

    for (uint64_t pid = 200000; pid < 220000; ++pid) held.push_back(table.retain(pid));
    const size_t peak = Access::Buckets(table)[3];
    held.resize(32);
    Access::MakeLateSweepDue(table);
    table.maintain();
    Check(Access::LateSize(table) == held.size() && Access::Buckets(table)[3] < peak / 8,
          "weak-index maintenance retained peak storage or deleted live pending lineages");
    Create(table, 200000, 200000);
    Check(held[0]->path && *held[0]->path->text == L"C:\\storage\\process200000.exe" &&
          table.retain(200000) == held[0],
          "late Create did not update the original pending after weak-index compaction");
    Exit(table, 200000);
    held.clear();
    Access::MakeLateSweepDue(table);
    table.maintain();
    Check(Access::LateSize(table) == 0 && Access::Buckets(table)[3] <= 8,
          "released pending lineages required new network events to reclaim storage");

    for (uint64_t pid = 300000; pid < 300256; ++pid) held.push_back(table.retain(pid));
    std::vector<pmkext::ProcessCreated> created;
    for (uint64_t pid = 300000; pid < 300256; ++pid) created.push_back({pid, pid});
    table.applyCreated(created.data(), static_cast<uint32_t>(created.size()));
    Check(Access::LateSize(table) == 0 && Access::Buckets(table)[3] <= 8,
          "Create batch retained removed weak-index buckets");
    table.clear();
    held.clear();
    for (uint64_t pid = 400000; pid < 400256; ++pid) held.push_back(table.retain(pid));
    std::vector<pmkext::ProcessTerminated> ended;
    for (uint64_t pid = 400000; pid < 400256; ++pid) ended.push_back({pid});
    table.applyTerminated(ended.data(), static_cast<uint32_t>(ended.size()));
    Check(Access::LateSize(table) == 0 && Access::Buckets(table)[3] <= 8,
          "unknown Terminated batch retained removed weak-index buckets");
    table.clear();
}

} // анонимное пространство имён
