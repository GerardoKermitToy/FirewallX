#pragma once
#include "FirewallPolicy.h"
#include <winsqlite/winsqlite3.h>
#include <cstring>

namespace {

constexpr wchar_t kInterfaceApp[] = L"C:\\FirewallX_InterfacePreferenceTests\\first.exe";
constexpr wchar_t kOtherInterfaceApp[] = L"C:\\FirewallX_InterfacePreferenceTests\\second.exe";

struct AppInterfaceProbe {
    mutable std::mutex mutex;
    std::vector<std::pair<std::wstring, uint64_t>> commands;
    std::atomic<unsigned> enables{0};
    std::atomic<bool> sendSucceeds{true};

    void Attach(RuleStore& store) {
        store.SetAppInterfaceHandler([this](const auto& path, uint64_t luid) {
            std::lock_guard lock(mutex);
            commands.emplace_back(path, luid);
            return sendSucceeds.load();
        }, [this] { ++enables; return true; });
    }
    auto Commands() const {
        std::lock_guard lock(mutex);
        return commands;
    }
};

MatchQuery AppInterfaceQuery(std::wstring_view path = kInterfaceApp) {
    MatchQuery query;
    query.appPath = path;
    query.pid = 100;
    query.remoteAddr = Ip4(198, 51, 100, 1);
    return query;
}

void CheckAppInterfaceBlocked(RuleStore& store, std::wstring_view path = kInterfaceApp) {
    auto query = AppInterfaceQuery(path);
    for (auto proto : {Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::IcmpV6})
    for (auto dir : {Dir::In, Dir::Out}) {
        query.proto = proto;
        query.dir = dir;
        for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::Block,
                            FirewallPolicy::Learning, FirewallPolicy::Allow, FirewallPolicy::AllowAll}) {
            const auto result = FirewallPolicies::Evaluate(policy, &store, query, nullptr, true);
            Check(result.decided && result.action == RuleAction::Block,
                  "unavailable preferred interface was bypassed by a policy");
        }
    }
    query.remoteAddr = Ip4(127, 0, 0, 1);
    Check(FirewallPolicies::Evaluate(FirewallPolicy::BlockAll, &store, query).action == RuleAction::Block,
          "local traffic bypassed the unavailable preferred interface");
    Rule rule;
    RuleMatchInfo info;
    RuleNameRef name;
    RuleAction action = RuleAction::Allow;
    Check(store.Match(query, rule) && rule.blocks() &&
          store.MatchInfo(query, info) && info.action == RuleAction::Block &&
          store.MatchVerdict(query, action, &name) && action == RuleAction::Block && name,
          "preferred-interface blocking differs across match entry points");
}

void TestAppInterfacePreferences() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    SetAdapters({adapter});
    auto& watcher = net::SharedNetworkInterfaces();
    {
        AppInterfaceProbe probe;
        RuleStore store;
        probe.Attach(store);
        store.SetAppInterfacesActive(true);
        Check(store.SetPreferredInterface(kInterfaceApp, L"") && probe.Commands().empty() && probe.enables == 0,
              "default without an explicit preference configured routing");
        Check(store.SetPreferredInterface(kInterfaceApp, adapter.name) &&
              store.SetPreferredInterface(kOtherInterfaceApp, adapter.name), "cannot assign preferred interface");
        Check(probe.enables == 1 && probe.Commands().size() == 2 &&
              probe.Commands().front().second == adapter.luid, "initial preference did not use the current LUID");
        Check(store.SetPreferredInterface(FoldCaseCopy(kInterfaceApp), adapter.name) &&
              probe.Commands().size() == 2, "unchanged preference resent a routing command");
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        store.Add(allow);
        auto query = AppInterfaceQuery();
        RuleAction action;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Allow,
              "available interface suppressed an ordinary allow rule");

        auto version = store.version();
        SetAdapters({});
        NotifyInterface(MibDeleteInstance, AF_INET, adapter.number, adapter.luid);
        WaitUntil([&] { return store.version() != version; });
        CheckAppInterfaceBlocked(store);
        CheckAppInterfaceBlocked(store, kOtherInterfaceApp);
        const auto removed = probe.Commands();
        Check(removed.size() == 4 &&
              std::count(removed.begin(), removed.end(),
                         std::pair<std::wstring, uint64_t>{kInterfaceApp, 0}) == 1 &&
              std::count(removed.begin(), removed.end(),
                         std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, 0}) == 1,
              "interface removal did not reset every affected application's driver policy");
        Check(store.GetPreferredInterface(kInterfaceApp) == adapter.name,
              "interface removal lost the saved name");
        query.source = TrafficSource::Ndis;
        Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, query).action == RuleAction::Allow,
              "host application preference affected Hyper-V traffic");
        query.source = TrafficSource::Host;
        const auto reads = enumerationCalls.load();
        const auto sends = probe.Commands().size();
        const std::wstring folded = FoldCaseCopy(kInterfaceApp);
        PrepareMatchAppPath(query, folded, HashFoldedText(folded));
        for (int i = 0; i < 10000; ++i)
            Check(store.MatchVerdict(query, action) && action == RuleAction::Block,
                  "cached unavailable preference stopped blocking");
        Check(enumerationCalls == reads && probe.Commands().size() == sends,
              "preferred-interface hot path enumerated adapters or sent driver commands");

        version = store.version();
        adapter.luid += 100;
        SetAdapters({adapter});
        NotifyInterface(MibAddInstance, AF_INET, adapter.number, adapter.luid);
        WaitUntil([&] { return store.version() != version; });
        Check(store.MatchVerdict(query, action) && action == RuleAction::Allow &&
              probe.Commands().size() == sends + 2 && probe.enables == 1,
              "new adapter LUID did not reconfigure every affected program");
        Check(probe.Commands().back().second == adapter.luid, "reappearance used an obsolete LUID");

        // Удаление другого интерфейса также перепроверяет все выбранные имена.
        version = store.version();
        adapter.luid += 100;
        SetAdapters({adapter});
        NotifyInterface(MibDeleteInstance, AF_INET, 99, 9999);
        WaitUntil([&] { return store.version() != version; });
        Check(probe.Commands().size() == sends + 4 && probe.Commands().back().second == adapter.luid,
              "removal notification did not recheck all application preferences");
        const auto unchanged = probe.Commands().size();
        Check(watcher.Refresh(), "cannot publish unchanged interface snapshot");
        store.version();
        Check(probe.Commands().size() == unchanged, "unchanged LUID resent app policies");

        Check(store.SetPreferredInterface(kInterfaceApp, L""), "cannot restore default routing");
        Check(probe.Commands().back() == std::pair<std::wstring, uint64_t>{kInterfaceApp, 0},
              "restoring default did not remove the driver policy");
        const auto defaults = probe.Commands().size();
        store.SetPreferredInterface(kInterfaceApp, L"");
        Check(probe.Commands().size() == defaults, "repeated default resent a reset");
        store.RemoveApp(kOtherInterfaceApp);
        Check(probe.Commands().size() == defaults + 1 && probe.Commands().back().second == 0,
              "removing program did not reset its preferred interface");
        store.SetPreferredInterface(kInterfaceApp, adapter.name);
        Check(probe.enables == 1, "route policies were enabled again after removing all preferences");
        store.SetAppInterfacesActive(false);
        const auto inactive = probe.Commands().size();
        adapter.luid += 100;
        SetAdapters({adapter});
        Check(watcher.Refresh(), "cannot publish inactive interface update");
        store.version();
        Check(probe.Commands().size() == inactive, "inactive service overwrote desktop preferences");
        store.SetAppInterfacesActive(true);
        Check(probe.Commands().size() == inactive + 1 && probe.Commands().back().second == adapter.luid,
              "new transport did not restore the current preferred interface");
        probe.sendSucceeds = false;
        store.SetPreferredInterface(kOtherInterfaceApp, adapter.name);
        CheckAppInterfaceBlocked(store, kOtherInterfaceApp);
        probe.sendSucceeds = true;
        Check(watcher.Refresh(), "cannot retry interface application");
        store.version();
        Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store,
              AppInterfaceQuery(kOtherInterfaceApp)).action == RuleAction::Allow,
              "successful driver retry did not lift fail-closed blocking");
        const auto beforeCleanup = probe.Commands().size();
        Check(store.RemoveMissingApps() == 2 && probe.Commands().size() == beforeCleanup + 2,
              "missing-program cleanup did not remove independent interface settings");
        store.SetPreferredInterface(kInterfaceApp, adapter.name);
        store.Clear();
        Check(store.GetPreferredInterface(kInterfaceApp).empty() && probe.Commands().back().second == 0,
              "clearing the database retained an application interface policy");
    }
    AddrMacros::Shutdown();
}

void TestBlockOtherInterfaces() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    SetAdapters({adapter});
    auto& watcher = net::SharedNetworkInterfaces();
    {
        AppInterfaceProbe probe;
        RuleStore store;
        probe.Attach(store);
        store.SetAppInterfacesActive(true);
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        store.Add(allow);
        auto query = AppInterfaceQuery();
        query.interfaceIndex = 99;
        Check(store.SetPreferredInterface(kInterfaceApp, L"", true) &&
              store.GetBlockOtherInterfaces(kInterfaceApp) && probe.Commands().empty() && probe.enables == 0 &&
              !store.preferredInterfaceConds() &&
              FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, query).action == RuleAction::Allow,
              "default interface with a saved flag activated routing or blocking");
        Check(store.SetPreferredInterface(kInterfaceApp, adapter.name) && store.GetBlockOtherInterfaces(kInterfaceApp),
              "selecting an interface did not retain the block flag");
        for (auto proto : {Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::IcmpV6})
        for (auto dir : {Dir::In, Dir::Out})
        for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::Block, FirewallPolicy::Learning,
                            FirewallPolicy::Allow, FirewallPolicy::AllowAll}) {
            query.proto = proto;
            query.dir = dir;
            for (uint32_t index : {0u, 99u}) {
                query.interfaceIndex = index;
                const auto decision = FirewallPolicies::Evaluate(policy, &store, query);
                Check(decision.decided && decision.action == RuleAction::Block && decision.preferredInterfaceBlocked,
                      "other interface bypassed application blocking");
            }
        }
        for (uint32_t index : {adapter.number, adapter.ipv6_number, 1u}) {
            query.interfaceIndex = index;
            Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, query).action == RuleAction::Allow &&
                  FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query).action == RuleAction::Allow,
                  "preferred or loopback interface did not reach ordinary rules");
        }
        {
            RuleStore ordinaryRules;
            Rule deny = allow;
            deny.action = RuleAction::Block;
            ordinaryRules.Add(deny);
            ordinaryRules.SetPreferredInterface(kInterfaceApp, adapter.name, true);
            query.interfaceIndex = 1;
            const auto decision = FirewallPolicies::Evaluate(FirewallPolicy::Learning, &ordinaryRules, query);
            Check(decision.decided && decision.action == RuleAction::Block && !decision.preferredInterfaceBlocked,
                  "loopback bypassed an ordinary blocking rule");
        }
        query.interfaceIndex = adapter.number;
        RuleAction action = RuleAction::Allow;
        const std::wstring capturedOther = L"Previous interface";
        query.interfaceName = &capturedOther;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Block,
              "pending request reused an index belonging to another interface");
        query.interfaceName = &adapter.name;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Allow,
              "pending request on the selected interface was blocked");
        query.interfaceName = nullptr;
        query.interfaceIndex = 99;
        RuleNameRef name;
        action = RuleAction::Allow;
        Check(store.MatchVerdict(query, action, &name) && action == RuleAction::Block && name &&
              *name == LoadStringRes(IDS_APP_INTERFACE_OTHER_BLOCKED),
              "other-interface block was reported as an unavailable adapter");
        query.appPath = kOtherInterfaceApp;
        Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, query).action == RuleAction::Allow,
              "another application's interface preference was inherited");
        query.appPath = kInterfaceApp;
        query.source = TrafficSource::Ndis;
        Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, query).action == RuleAction::Allow,
              "application interface blocking affected Hyper-V traffic");
        query.source = TrafficSource::Host;
        const auto reads = enumerationCalls.load();
        const auto sends = probe.Commands().size();
        const auto folded = FoldCaseCopy(kInterfaceApp);
        PrepareMatchAppPath(query, folded, HashFoldedText(folded));
        for (int i = 0; i < 10000; ++i)
            Check(store.MatchVerdict(query, action) && action == RuleAction::Block,
                  "other-interface hot path stopped blocking");
        Check(enumerationCalls == reads && probe.Commands().size() == sends,
              "other-interface hot path enumerated adapters or sent driver commands");

        const auto version = store.version();
        adapter.number += 10;
        adapter.ipv6_number += 10;
        SetAdapters({adapter});
        Check(watcher.Refresh() && store.version() != version,
              "interface index change did not invalidate cached verdicts");
        query.interfaceIndex = adapter.number;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Allow,
              "new index was not associated with the selected interface");
        query.interfaceIndex = adapter.number - 10;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Block,
              "old interface index remained allowed");

        SetAdapters({});
        Check(watcher.Refresh(), "cannot remove the selected interface");
        store.version();
        query.interfaceIndex = 1;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Allow,
              "loopback was blocked when the selected interface disappeared");
        query.interfaceIndex = 99;
        Check(store.MatchVerdict(query, action) && action == RuleAction::Block,
              "unavailable interface was not blocked");
        Check(store.SetPreferredInterface(kInterfaceApp, L"", true) &&
              store.MatchVerdict(query, action) && action == RuleAction::Allow,
              "default routing retained interface blocking");
        Check(store.SetPreferredInterface(kInterfaceApp, L"", false) &&
              !store.GetBlockOtherInterfaces(kInterfaceApp), "cannot clear the block flag");
    }
    AddrMacros::Shutdown();
}

void TestBlockOtherInterfacesDatabase() {
    ResetFixture();
    const auto adapter = SampleAdapters().front();
    SetAdapters({adapter});
    wchar_t directory[MAX_PATH]{}, filename[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxb", 0, filename),
          "cannot create interface-block database fixture");
    constexpr wchar_t defaultApp[] = L"C:\\FirewallX_InterfacePreferenceTests\\default-block.exe";
    std::wstring error;
    {
        RuleStore writer;
        Check(writer.AttachDatabase(filename, error) &&
              writer.SetPreferredInterface(kInterfaceApp, adapter.name, true) &&
              writer.SetPreferredInterface(kOtherInterfaceApp, adapter.name, false) &&
              writer.SetPreferredInterface(defaultApp, L"", true) && writer.dbError().empty(),
              "cannot persist interface-block settings");
    }
    for (bool service : {false, true}) {
        AppInterfaceProbe probe;
        RuleStore loaded;
        Check(service ? loaded.LoadOnce(filename, error) : loaded.AttachDatabase(filename, error),
              "cannot reload interface-block settings");
        Check(loaded.GetBlockOtherInterfaces(FoldCaseCopy(kInterfaceApp)) &&
              !loaded.GetBlockOtherInterfaces(kOtherInterfaceApp) &&
              loaded.GetBlockOtherInterfaces(defaultApp) && loaded.GetPreferredInterface(defaultApp).empty(),
              "interface-block settings did not survive database reload");
        const auto apps = loaded.Apps();
        Check(std::count_if(apps.begin(), apps.end(), [&](const auto& app) {
            return EqualNoCase(app.path, defaultApp);
        }) == 1, "application with a default-only block flag disappeared");
        probe.Attach(loaded);
        loaded.SetAppInterfacesActive(true);
        Check(probe.Commands().size() == 2, "default-only block flag sent a routing command");
        auto query = AppInterfaceQuery(defaultApp);
        query.interfaceIndex = 99;
        Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &loaded, query).action == RuleAction::Allow,
              "reloaded default-only block flag blocked traffic");
    }
    {
        RuleStore writer;
        Check(writer.AttachDatabase(filename, error), "cannot reopen interface-block settings");
        writer.RemoveApp(defaultApp);
        Check(!writer.GetBlockOtherInterfaces(defaultApp), "removing an application retained its block flag");
        writer.Clear();
        Check(!writer.GetBlockOtherInterfaces(kInterfaceApp), "clearing the rules retained a block flag");
        Rule allow;
        allow.scope = RuleScope::Global;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        writer.Add(allow);
        Check(writer.SetPreferredInterface(kInterfaceApp, adapter.name, false), "cannot set up old database");
    }
    sqlite3* database = nullptr;
    Check(sqlite3_open16(filename, &database) == SQLITE_OK &&
          sqlite3_exec(database, "DROP TABLE app_interface_blocks;", nullptr, nullptr, nullptr) == SQLITE_OK,
          "cannot set up an older database without interface-block settings");
    sqlite3_close(database);
    {
        RuleStore loaded;
        Check(loaded.AttachDatabase(filename, error) && loaded.Count() == 1 &&
              loaded.GetPreferredInterface(kInterfaceApp) == adapter.name &&
              !loaded.GetBlockOtherInterfaces(kInterfaceApp),
              "updating an older database lost its rules or interface preference");
    }
    DeleteFileW(filename);
    AddrMacros::Shutdown();
}

void TestAppInterfaceRemovalResets() {
    for (bool returnBeforeRetry : {false, true}) {
        ResetFixture();
        const auto selected = SampleAdapters().front();
        auto other = selected;
        other.number += 1;
        other.ipv6_number += 1;
        other.luid += 1;
        other.name = L"Other active interface";
        SetAdapters({selected, other});
        auto& watcher = net::SharedNetworkInterfaces();
        {
            AppInterfaceProbe probe;
            RuleStore store;
            probe.Attach(store);
            store.SetAppInterfacesActive(true);
            constexpr wchar_t defaultApp[] = L"C:\\FirewallX_InterfacePreferenceTests\\default.exe";
            constexpr wchar_t ordinaryApp[] = L"C:\\FirewallX_InterfacePreferenceTests\\ordinary.exe";
            Check(store.SetPreferredInterface(kInterfaceApp, selected.name) &&
                  store.SetPreferredInterface(kOtherInterfaceApp, other.name) &&
                  store.SetPreferredInterface(defaultApp, selected.name) &&
                  store.SetPreferredInterface(defaultApp, L""),
                  "cannot configure explicit and default interface preferences");
            Rule allow;
            allow.appPath = ordinaryApp;
            allow.conds = CondNone;
            allow.action = RuleAction::Allow;
            store.Add(allow);
            const auto initial = probe.Commands().size();
            probe.sendSucceeds = false;
            SetAdapters({other});
            Check(watcher.Refresh(), "cannot remove the selected interface");
            store.version();
            Check(probe.Commands().size() == initial + 1 && probe.Commands().back() ==
                  std::pair<std::wstring, uint64_t>{kInterfaceApp, 0},
                  "interface removal did not reset only its explicit preference");
            CheckAppInterfaceBlocked(store);
            for (const auto* path : {kOtherInterfaceApp, defaultApp, ordinaryApp})
                Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store,
                      AppInterfaceQuery(path)).action == RuleAction::Allow,
                      "interface removal affected an unrelated or default application");
            Check(store.GetPreferredInterface(kInterfaceApp) == selected.name &&
                  store.GetPreferredInterface(defaultApp).empty() &&
                  store.GetPreferredInterface(ordinaryApp).empty(),
                  "interface removal changed explicit or default preferences");

            const auto reads = enumerationCalls.load();
            for (int i = 0; i < 1000; ++i)
                Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store,
                      AppInterfaceQuery()).action == RuleAction::Block,
                      "failed interface reset stopped blocking new requests");
            Check(enumerationCalls == reads && probe.Commands().size() == initial + 1,
                  "network requests retried a failed interface reset");

            probe.sendSucceeds = true;
            if (returnBeforeRetry) SetAdapters({selected, other});
            Check(watcher.Refresh(), "cannot retry the interface policy update");
            store.version();
            Check(probe.Commands().size() == initial + 2 && probe.Commands().back() ==
                  std::pair<std::wstring, uint64_t>{kInterfaceApp,
                      returnBeforeRetry ? selected.luid : 0},
                  "failed reset was not retried or prevented reapplying the original LUID");
            Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store,
                  AppInterfaceQuery()).action ==
                      (returnBeforeRetry ? RuleAction::Allow : RuleAction::Block),
                  "interface reset retry changed availability blocking");
            Check(watcher.Refresh(), "cannot repeat the unchanged interface snapshot");
            store.version();
            Check(probe.Commands().size() == initial + 2,
                  "unchanged snapshot resent a successful interface command");
            if (!returnBeforeRetry) {
                auto returned = selected;
                returned.luid += 100;
                SetAdapters({returned, other});
                Check(watcher.Refresh(), "cannot restore the preferred interface");
                store.version();
                Check(probe.Commands().size() == initial + 3 && probe.Commands().back() ==
                      std::pair<std::wstring, uint64_t>{kInterfaceApp, returned.luid},
                      "interface return did not restore the saved preference with the new LUID");
            }

            store.SetAppInterfacesActive(false);
            const auto inactive = probe.Commands().size();
            SetAdapters({other});
            Check(watcher.Refresh(), "cannot remove the interface while transport is inactive");
            store.version();
            Check(probe.Commands().size() == inactive,
                  "inactive transport sent a removed-interface reset");
            store.SetAppInterfacesActive(true);
            const auto activated = probe.Commands();
            Check(activated.size() == inactive + 2 &&
                  std::count(activated.begin() + inactive, activated.end(),
                      std::pair<std::wstring, uint64_t>{kInterfaceApp, 0}) == 1 &&
                  std::count(activated.begin() + inactive, activated.end(),
                      std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, other.luid}) == 1,
                  "transport activation did not update only explicitly configured applications");
            CheckAppInterfaceBlocked(store);
        }
        AddrMacros::Shutdown();
    }
}

void TestAppInterfacePreferenceDatabase() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    SetAdapters({adapter});
    auto& watcher = net::SharedNetworkInterfaces();
    wchar_t directory[MAX_PATH]{}, filename[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxp", 0, filename),
          "cannot create app-interface database fixture");
    std::wstring error;
    const std::wstring missing = L"Недоступная сеть café 网络";
    {
        RuleStore writer;
        Check(writer.AttachDatabase(filename, error), "cannot attach app-interface database");
        Check(writer.SetPreferredInterface(kInterfaceApp, adapter.name) &&
              writer.SetPreferredInterface(kOtherInterfaceApp, missing), "cannot persist named preferences");
        writer.ReplaceApp(kInterfaceApp, L"test", {});
        Check(writer.Count() == 0 && writer.dbError().empty(), "preference required an individual rule");
        writer.SetPreferredInterface(L"C:\\FirewallX_InterfacePreferenceTests\\default.exe", L"");
    }
    sqlite3* database = nullptr;
    Check(sqlite3_open16(filename, &database) == SQLITE_OK, "cannot inspect app-interface schema");
    sqlite3_stmt* statement = nullptr;
    Check(sqlite3_prepare_v2(database, "PRAGMA table_info(app_interfaces);", -1, &statement, nullptr) == SQLITE_OK,
          "cannot inspect interface preference columns");
    unsigned columns = 0;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* name = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
        Check(name && (std::strcmp(name, "app_path") == 0 || std::strcmp(name, "interface_name") == 0),
              "database persisted LUID or other derived interface state");
        ++columns;
    }
    sqlite3_finalize(statement);
    Check(columns == 2, "preferred interface schema must contain only app path and interface name");
    Check(sqlite3_prepare_v2(database, "SELECT COUNT(*) FROM app_interfaces;", -1, &statement, nullptr) == SQLITE_OK &&
          sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int(statement, 0) == 2,
          "default was persisted or named preferences were lost");
    sqlite3_finalize(statement);
    sqlite3_close(database);

    for (bool service : {false, true}) {
        adapter.luid += 1000;
        SetAdapters({adapter});
        Check(watcher.Refresh(), "cannot publish new startup LUID");
        AppInterfaceProbe probe;
        RuleStore loaded;
        Check(service ? loaded.LoadOnce(filename, error) : loaded.AttachDatabase(filename, error),
              "cannot reload interface preferences");
        Check(loaded.GetPreferredInterface(FoldCaseCopy(kInterfaceApp)) == adapter.name &&
              loaded.GetPreferredInterface(kOtherInterfaceApp) == missing,
              "stored preference depended on path case or interface availability");
        const auto apps = loaded.Apps();
        Check(std::count_if(apps.begin(), apps.end(), [](const auto& app) {
            return !app.global && !app.postapp && !app.interfaceGroup;
        }) == 2, "preference-only applications disappeared from program settings");
        probe.Attach(loaded);
        Check(probe.Commands().empty(), "preferences were applied before transport activation");
        loaded.SetAppInterfacesActive(true);
        const auto startup = probe.Commands();
        Check(probe.enables == 1 && startup.size() == 2 &&
              std::count(startup.begin(), startup.end(),
                         std::pair<std::wstring, uint64_t>{kInterfaceApp, adapter.luid}) == 1 &&
              std::count(startup.begin(), startup.end(),
                         std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, 0}) == 1,
              "startup did not apply the current LUID and reset the unavailable interface policy");
        CheckAppInterfaceBlocked(loaded, kOtherInterfaceApp);
        const auto before = probe.Commands().size();
        loaded.SetAppInterfacesActive(true);
        Check(probe.Commands().size() == before, "duplicate transport activation resent preferences");
        if (service) {
            Check(!loaded.LoadOnce(std::wstring(filename) + L"\\missing.db", error) &&
                  loaded.GetPreferredInterface(kInterfaceApp).empty(),
                  "failed service reload retained old interface settings");
        }
    }
    Check(DeleteFileW(filename) != FALSE, "cannot remove app-interface database fixture");
    AddrMacros::Shutdown();
}

std::wstring AppInterfaceProcessPath(uint64_t pid, DWORD& error) {
    error = ERROR_SUCCESS;
    return pid == 100 ? kInterfaceApp : kOtherInterfaceApp;
}

void TestAppInterfacePreferenceInheritance() {
    ResetFixture();
    SetAdapters({});
    {
        pmkext::ProcessTable processes{AppInterfaceProcessPath};
        const pmkext::ProcessCreated values[]{{100, 4}, {101, 100}};
        Check(processes.applyCreated(values, 2), "cannot create preferred-interface process tree");
        AppInterfaceProbe probe;
        RuleStore store(processes);
        store.SetInheritance(kInterfaceApp, RuleInheritance::Enabled);
        store.SetPreferredInterface(kInterfaceApp, L"Missing parent interface");
        Rule allow;
        allow.appPath = kInterfaceApp;
        allow.conds = CondNone;
        allow.action = RuleAction::Allow;
        store.Add(allow);
        CheckAppInterfaceBlocked(store);
        auto child = AppInterfaceQuery(kOtherInterfaceApp);
        child.pid = 101;
        RuleAction action;
        Check(store.MatchVerdict(child, action) && action == RuleAction::Allow,
              "child inherited its parent's unavailable preferred interface");
        child.appPath = {};
        Check(store.MatchVerdict(child, action) && action == RuleAction::Allow,
              "process-table fallback inherited a preferred interface");
        probe.Attach(store);
        store.SetAppInterfacesActive(true);
        Check(probe.enables == 1 && probe.Commands() ==
              std::vector<std::pair<std::wstring, uint64_t>>{{kInterfaceApp, 0}},
              "missing startup interface did not reset its driver policy");
        child.pid = 100;
        Check(store.MatchVerdict(child, action) && action == RuleAction::Block,
              "known original process path did not enforce its unavailable preference");

        auto adapter = SampleAdapters().front();
        adapter.name = L"Missing parent interface";
        auto& watcher = net::SharedNetworkInterfaces();
        SetAdapters({adapter});
        Check(watcher.Refresh(), "cannot restore the parent's preferred interface");
        store.version();
        Check(probe.Commands().size() == 2 && probe.Commands().back() ==
              std::pair<std::wstring, uint64_t>{kInterfaceApp, adapter.luid},
              "interface return applied the parent's preference to another executable");
        child = AppInterfaceQuery(kOtherInterfaceApp);
        child.pid = 101;
        for (auto parentMode : {RuleInheritance::Default, RuleInheritance::Enabled,
                                RuleInheritance::Never, RuleInheritance::EnabledAndNever}) {
            Check(store.SetInheritance(kInterfaceApp, parentMode), "cannot set parent inheritance");
            for (auto childMode : {RuleInheritance::Default, RuleInheritance::Enabled,
                                   RuleInheritance::Never, RuleInheritance::EnabledAndNever}) {
                Check(store.SetInheritance(kOtherInterfaceApp, childMode), "cannot set child inheritance");
                Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, child).action ==
                      RuleAction::Allow && store.GetPreferredInterface(kOtherInterfaceApp).empty() &&
                      probe.Commands().size() == 2,
                      "rule inheritance changed application-interface settings or driver commands");
            }
        }
        Check(store.SetPreferredInterface(kOtherInterfaceApp, L"") && probe.Commands().size() == 2,
              "default child preference reset the parent's policy through inheritance");
        store.RemoveApp(kOtherInterfaceApp);
        Check(probe.Commands().size() == 2 && store.GetPreferredInterface(kInterfaceApp) == adapter.name,
              "removing a child without a preference reset its parent's policy");
        Check(store.SetInheritance(kOtherInterfaceApp, RuleInheritance::Enabled) &&
              store.SetPreferredInterface(kOtherInterfaceApp, adapter.name) &&
              probe.Commands().size() == 3 && probe.Commands().back() ==
                  std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, adapter.luid},
              "explicit child preference used an inherited executable path");
        Check(store.SetPreferredInterface(kInterfaceApp, L"") && probe.Commands().size() == 4 &&
              probe.Commands().back() == std::pair<std::wstring, uint64_t>{kInterfaceApp, 0} &&
              store.GetPreferredInterface(kOtherInterfaceApp) == adapter.name,
              "resetting the parent changed the child's explicit preference");
        SetAdapters({});
        Check(watcher.Refresh(), "cannot remove the child's preferred interface");
        store.version();
        Check(probe.Commands().size() == 5 && probe.Commands().back() ==
              std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, 0},
              "interface removal reset a program without an explicit preference");
        child.appPath = {};
        Check(FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store, child).action ==
              RuleAction::Block && FirewallPolicies::Evaluate(FirewallPolicy::AllowAll, &store,
              AppInterfaceQuery()).action == RuleAction::Allow,
              "interface blocking followed inherited rules instead of the original executable");
        adapter.luid += 100;
        SetAdapters({adapter});
        Check(watcher.Refresh(), "cannot restore the child's preferred interface");
        store.version();
        Check(probe.Commands().size() == 6 && probe.Commands().back() ==
              std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, adapter.luid},
              "interface return applied a child preference to an inherited executable");
        store.RemoveApp(kOtherInterfaceApp);
        Check(probe.Commands().size() == 7 && probe.Commands().back() ==
              std::pair<std::wstring, uint64_t>{kOtherInterfaceApp, 0},
              "removing an explicitly configured child reset another executable");
        store.SetAppInterfacesActive(false);
    }
    AddrMacros::Shutdown();
}

} // namespace
