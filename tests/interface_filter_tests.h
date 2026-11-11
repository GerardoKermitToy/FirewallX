#pragma once
#include "RuleDb.h"
#include "RuleInterfaceUi.h"

struct StorageTestAccess {
    static size_t InterfaceFilterCount(const RuleStore& store) {
        std::lock_guard lock(store.mtx_);
        return store.interfaceFilters_.size();
    }
};

namespace {
void TestInterfaceFilterScopes() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    adapter.name = L"Сеть café α 网络 \U0001f310";
    SetAdapters({adapter});
    auto& watcher = net::SharedNetworkInterfaces();
    {
        RuleStore store;
        for (auto scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp}) {
            store.Clear();
            Rule rule;
            rule.scope = scope;
            if (scope == RuleScope::App) rule.appPath = L"C:\\Apps\\тест.exe";
            rule.conds = CondProto | CondInterface;
            rule.proto = Proto::Udp;
            rule.interfaceName = adapter.name;
            rule.action = RuleAction::Block;
            store.Add(rule);
            MatchQuery query;
            query.appPath = rule.appPath;
            query.proto = rule.proto;
            query.pid = 100;
            Rule found;
            RuleAction action = RuleAction::Allow;
            for (uint32_t index : {adapter.number, adapter.ipv6_number}) {
                query.interfaceIndex = index;
                Check(store.Match(query, found) && found.id == rule.id &&
                          store.MatchVerdict(query, action) && action == rule.action &&
                          RuleStore::MatchesRule(rule, query),
                      "interface filter failed for an app, Global or PostApp group");
                RuleMatchInfo info;
                Check(store.MatchInfo(query, info) && info.id == rule.id,
                      "interface filter was lost in MatchInfo");
            }
            for (uint32_t index : {0u, 11u, 999u}) {
                query.interfaceIndex = index;
                Check(!store.Match(query, found) && !RuleStore::MatchesRule(rule, query),
                      "interface filter matched an unavailable or unrelated index");
            }
            query.interfaceIndex = adapter.number;
            query.proto = Proto::Tcp;
            Check(!store.Match(query, found), "interface filter bypassed protocol conditions");
            query.proto = rule.proto;
            const std::wstring wrongName = L"Replacement";
            query.interfaceName = &wrongName;
            Check(!store.Match(query, found) && !RuleStore::MatchesRule(rule, query),
                  "frozen pending adopted another interface on a reused index");
            const std::wstring unknown;
            query.interfaceName = &unknown;
            Check(!store.Match(query, found), "unknown pending identity matched an interface filter");
            query.interfaceName = &adapter.name;
            Check(store.Match(query, found), "known pending identity did not match its interface");
            query.interfaceName = nullptr;
            rule.interfaceName += L" absent";
            Check(store.Update(rule) && !store.Match(query, found),
                  "unavailable named interface did not disable the filter");
            rule.conds &= ~CondInterface;
            Check(store.Update(rule) && store.Match(query, found),
                  "unchecked interface condition still constrained matching");
            query.source = TrafficSource::Ndis;
            Check(!store.Match(query, found), "host filter groups leaked into Hyper-V matching");
        }

        store.Clear();
        for (auto scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp}) {
            Rule rule;
            rule.scope = scope;
            rule.appPath = scope == RuleScope::App ? L"C:\\Apps\\shared.exe" : L"";
            rule.conds = CondInterface;
            rule.interfaceName = adapter.name;
            store.Add(rule);
        }
        Check(StorageTestAccess::InterfaceFilterCount(store) == 1,
              "identical interface names were resolved independently for different rules");
        const auto reads = enumerationCalls.load();
        MatchQuery query;
        query.interfaceIndex = adapter.number;
        RuleAction action;
        const auto stable = store.version();
        for (int i = 0; i < 10000; ++i)
            Check(store.MatchVerdict(query, action) && store.version() == stable,
                  "stable cached interface filter stopped matching");
        Check(enumerationCalls == reads, "interface filter hot path enumerated adapters");

        store.Clear();
        auto unnamed = adapter;
        unnamed.name.clear();
        unnamed.number = 99;
        unnamed.ipv6_number = 109;
        SetAdapters({adapter, unnamed});
        Check(watcher.Refresh(), "cannot publish a nameless interface for the filter test");
        Rule empty;
        empty.scope = RuleScope::Global;
        empty.conds = CondInterface;
        store.Add(empty);
        query.interfaceIndex = unnamed.number;
        Check(!store.MatchVerdict(query, action) && !RuleStore::MatchesRule(empty, query),
              "an empty interface filter matched a nameless adapter");
        RuleInterfaceUi ui;
        ui.Refresh(std::span<const Rule>(&empty, 1));
        Check(ui.Unavailable(empty), "an empty interface filter would not be painted red");

        Rule interfaceRule;
        interfaceRule.scope = RuleScope::Interface;
        interfaceRule.appPath = adapter.name;
        interfaceRule.conds = CondInterface;
        interfaceRule.interfaceName = L"Another interface";
        Check(!(EffectiveRuleConds(interfaceRule) & CondInterface),
              "interface group retained a redundant interface condition");
        NormalizeRuleConds(interfaceRule);
        Check(!(interfaceRule.conds & CondInterface) && interfaceRule.interfaceName.empty(),
              "interface-group normalization did not clear the redundant filter");
    }
    watcher.Stop();
}

void TestInterfaceFilterUpdates() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    adapter.name = L"Сеть для фильтра";
    SetAdapters({adapter});
    auto& watcher = net::SharedNetworkInterfaces();
    {
        RuleStore store;
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondInterface;
        rule.interfaceName = adapter.name;
        store.Add(rule);
        RuleInterfaceUi ui;
        const auto refreshUi = [&] { ui.Refresh(std::span<const Rule>(&rule, 1)); };
        refreshUi();
        Check(!ui.Unavailable(rule), "active filter would be painted red");
        MatchQuery query;
        query.interfaceIndex = adapter.number;
        Rule found;
        Check(store.Match(query, found), "initial interface filter failed");
        auto previous = store.interfaceVersion();
        std::atomic<unsigned> callbacks{0};
        const auto token = watcher.Subscribe([&](const auto&) { ++callbacks; });
        adapter.up = false;
        SetAdapters({adapter});
        NotifyInterface();
        // Подписка RuleStore зарегистрирована раньше проверочной: обновление
        // индексов должно завершиться непосредственно в ChangeCallback.
        WaitUntil([&] { return callbacks.load() != 0; });
        Check(store.interfaceVersion() != previous && !store.Match(query, found),
              "inactive interface filter retained a matching index");
        refreshUi();
        Check(ui.Unavailable(rule), "unavailable filter would not be painted red");

        const auto inactiveVersion = store.interfaceVersion();
        const auto callbackCount = callbacks.load();
        Interface other = adapter;
        other.name = L"Другой интерфейс";
        other.up = true;
        SetAdapters({adapter, other});
        NotifyInterface();
        WaitUntil([&] { return callbacks.load() > callbackCount; });
        Check(!store.Match(query, found), "reused index reactivated an absent named filter");
        Check(store.interfaceVersion() != inactiveVersion, "replacement interface was not published");

        adapter.up = true;
        adapter.number = 29;
        adapter.ipv6_number = 39;
        SetAdapters({adapter, other});
        // Синхронный Refresh не вызывает callback; matcher сам замечает поколение.
        previous = store.version();
        Check(watcher.Refresh(), "synchronous filter refresh failed");
        for (uint32_t index : {29u, 39u}) {
            query.interfaceIndex = index;
            Check(store.Match(query, found), "renumbered filter retained its old index");
        }
        query.interfaceIndex = other.number;
        Check(!store.Match(query, found) && store.version() != previous,
              "numeric verdict caches cannot see a changed filter index");
        refreshUi();
        Check(!ui.Unavailable(rule), "reactivated interface filter remained red");
        previous = store.version();
        Check(watcher.Refresh() && store.version() == previous,
              "identical snapshot invalidated interface filter caches");

        // Исчезновение и переименование проверяются отдельно от состояния down.
        SetAdapters({other});
        Check(watcher.Refresh(), "interface removal refresh failed");
        query.interfaceIndex = 29;
        Check(!store.Match(query, found), "removed interface filter still matched");
        refreshUi();
        Check(ui.Unavailable(rule), "removed interface filter remained available to UI");
        adapter.name = L"Новое имя сети";
        SetAdapters({adapter, other});
        Check(watcher.Refresh() && !store.Match(query, found), "filter followed a renamed interface");
        rule.interfaceName = adapter.name;
        Check(store.Update(rule) && store.Match(query, found), "editing the filter kept its old binding");
        rule.enabled = false;
        Check(store.Update(rule) && !store.Match(query, found), "disabled interface rule matched");
        watcher.Unsubscribe(token);
    }
    watcher.Stop();
}

void TestInterfaceFilterPersistence() {
    RuleDb database;
    std::wstring error;
    Check(database.Open(L":memory:", error), "cannot open interface filter test database");
    for (const std::wstring name : {L"Сеть, café; сеть", L"网络 \U0001f310", L"شبكة <&> ", L""}) {
        std::vector<Rule> original;
        for (auto scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp}) {
            Rule rule;
            rule.id = original.size() + 1;
            rule.scope = scope;
            if (scope == RuleScope::App) rule.appPath = L"C:\\Apps\\тест.exe";
            rule.conds = CondInterface;
            rule.interfaceName = name;
            original.push_back(rule);
        }
        Check(database.SaveAll(original, error), "cannot save Unicode interface names");
        std::vector<Rule> loaded;
        uint64_t maxId = 0;
        Check(database.Load(loaded, maxId, error) && loaded.size() == original.size() && maxId == 3,
              "interface filter persistence changed the rule count");
        for (const auto& rule : loaded) {
            Check(rule.interfaceName == name && (rule.conds & CondInterface),
                  "Unicode interface filter name did not survive SQLite roundtrip");
            Check(rule.BuildAutoName().find(name) != std::wstring::npos,
                  "automatic rule name lost the interface condition");
            Check(RuleExplainMarkup(rule).find(L"id=\"interface\"") != std::wstring::npos,
                  "interface condition is not editable from its explanation");
        }
    }
}
} // namespace
