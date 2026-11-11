#pragma once

namespace {

void TestNdisRuleGroup() {
    RuleStore store;
    const auto& interface = TestInterface();
    const auto groups = store.Interfaces();
    Check(std::any_of(groups.begin(), groups.end(), [&](const AppEntry& entry) {
        return entry.interfaceGroup && entry.active && entry.rules == 0 && entry.name == interface.name;
    }), "active interface has no empty runtime group");
    MatchQuery host = Query(Proto::Tcp, Dir::Out);
    host.interfaceIndex = interface.number;
    MatchQuery guest = host;
    guest.source = TrafficSource::Ndis;
    guest.pid = 0;
    guest.appPath = {};
    Rule global = OutboundRule(Proto::Tcp, 0);
    global.scope = RuleScope::Global;
    store.Add(global);
    Rule app = OutboundRule(Proto::Tcp, 0);
    store.Add(app);
    Rule post = global;
    post.id = 0;
    post.scope = RuleScope::PostApp;
    store.Add(post);
    Check(!Matches(store, guest), "host rules matched Ndis event");

    Rule rule = global;
    rule.id = 0;
    rule.scope = RuleScope::Interface;
    rule.appPath = interface.name;
    rule.action = RuleAction::Allow;
    rule.conds |= CondPidZero;
    store.Add(rule);
    Rule found;
    RuleAction action;
    for (const auto& query : {host, guest}) {
        Check(store.Match(query, found) && found.id == rule.id && found.isInterface() &&
                  !(found.conds & CondPidZero) && found.appPath == interface.name &&
                  Matches(store, query, &action) && action == RuleAction::Allow &&
                  RuleStore::MatchesRule(rule, query),
              "interface rules did not precede all other groups for both sources");
    }
    if (interface.ipv6_number) {
        guest.interfaceIndex = interface.ipv6_number;
        Check(Matches(store, guest), "IPv6 interface index lost its group");
        guest.interfaceIndex = interface.number;
    }
    host.interfaceIndex = 0;
    Check(store.Match(host, found) && found.id == global.id,
          "unknown interface did not fall through to global rules");
    Check(store.SetEnabled(rule.id, false) && !Matches(store, guest),
          "disabled interface group fell through to host rules for Ndis");
    store.Replace(RuleScope::Interface, interface.name, interface.name, {});
    Check(store.Count() == 3 && store.InterfaceRules(interface.name).empty() && !Matches(store, guest),
          "removing interface rules changed another group");

    Rule first = OutboundRule(Proto::Tcp, 0);
    first.scope = RuleScope::Interface;
    Rule second = first;
    second.action = RuleAction::Allow;
    store.Replace(RuleScope::Interface, interface.name, interface.name, {first, second});
    auto rules = store.InterfaceRules(interface.name);
    Check(rules.size() == 2 && Matches(store, guest, &action) && action == RuleAction::Block,
          "interface group priority is wrong");
    Check(store.MovePriority(rules[1].id, -1) && Matches(store, guest, &action) && action == RuleAction::Allow,
          "interface group cannot reorder its own rules");
    store.RemoveMissingApps();
    Check(store.InterfaceRules(interface.name).size() == 2 && store.GlobalCount() == 1 && store.PostAppCount() == 1,
          "missing-executable cleanup deleted an interface group");

    Rule offline = first;
    offline.appPath = L"FirewallX nonexistent interface";
    store.Add(offline);
    auto entries = store.Interfaces();
    Check(std::any_of(entries.begin(), entries.end(), [&](const auto& entry) {
        return entry.name == offline.appPath && !entry.active && entry.rules == 1;
    }), "inactive group with rules was discarded");
    Check(store.Remove(offline.id), "cannot remove offline interface rule");
    entries = store.Interfaces();
    Check(std::none_of(entries.begin(), entries.end(), [&](const auto& entry) {
        return entry.name == offline.appPath;
    }), "empty inactive group was retained");
}

void TestNdisRulePersistence() {
    wchar_t directory[MAX_PATH]{}, filename[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxi", 0, filename),
          "cannot create interface test database");
    const auto& interface = TestInterface();
    {
        RuleStore writer;
        std::wstring error;
        Check(writer.AttachDatabase(filename, error), "cannot attach interface test database");
        Rule rule = OutboundRule(Proto::Udp, CondRemotePort);
        rule.scope = RuleScope::Interface;
        rule.appPath = interface.name;
        writer.Add(rule);
        Check(writer.dbError().empty(), "cannot save interface scope");
    }
    {
        RuleStore reader;
        std::wstring error;
        Check(reader.LoadOnce(filename, error) && reader.InterfaceRules(interface.name).size() == 1 &&
                  reader.Count() == 1,
              "interface name was lost or empty groups were persisted");
        MatchQuery query = Query(Proto::Udp, Dir::Out);
        query.interfaceIndex = interface.number;
        Rule found;
        for (const auto source : {TrafficSource::Host, TrafficSource::Ndis}) {
            query.source = source;
            Check(reader.Match(query, found) && found.isInterface(), "restored interface rule does not match");
        }
        query.interfaceIndex = 0;
        Check(!reader.Match(query, found), "interface rule matched an unavailable index");
    }
    Check(DeleteFileW(filename) != FALSE, "cannot delete interface test database");
}

} // namespace
