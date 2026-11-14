#include "FirewallPolicy.h"
#include "Monitor.h"
#include "TreeList.h"
#include "OwnerLookup.h"
#include "Settings.h"
#include "StringRes.h"
#include "SystemInfo.h"
#include <winsqlite/winsqlite3.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace {

void Check(bool value, const char* message) {
    if (value) return;
    std::cerr << message << '\n';
    std::exit(1);
}

IpAddr V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    const uint8_t bytes[4] = { a, b, c, d };
    return IpAddr::Raw4(bytes);
}

IpAddr V6(uint8_t last) {
    uint8_t bytes[16]{};
    bytes[0] = 0x20;
    bytes[1] = 0x01;
    bytes[2] = 0x0d;
    bytes[3] = 0xb8;
    bytes[15] = last;
    return IpAddr::Raw6(bytes);
}

constexpr wchar_t kApp[] = L"C:\\Apps\\PolicyTest.exe";

MatchQuery Query(Proto proto, Dir dir, bool ipv6) {
    return MakeMatchQuery(kApp, 1000,
        MakeFlowKey(proto, ipv6 ? V6(1) : V4(192, 0, 2, 1),
                    ipv6 ? V6(2) : V4(198, 51, 100, 2), 41000, 443), dir);
}

Rule AnyRule(RuleScope scope, RuleAction action) {
    Rule rule;
    rule.scope = scope;
    if (scope == RuleScope::App) rule.appPath = kApp;
    rule.name = L"policy test rule";
    rule.autoName = false;
    rule.conds = CondNone;
    rule.action = action;
    return rule;
}

void TestDecisionMatrix() {
    size_t count = 0;
    const auto* policies = FirewallPolicies::All(count);
    Check(count == 5, "неверное число политик");
    size_t cases = 0;

    for (unsigned protocol = 0; protocol <= 255; ++protocol)
    for (Dir dir : { Dir::Out, Dir::In })
    for (bool ipv6 : { false, true })
    for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp })
    for (int match = -1; match <= 1; ++match) {
        RuleStore store;
        MatchQuery query = Query(ProtoFromNumber(static_cast<uint8_t>(protocol)), dir, ipv6);
        if (match >= 0) {
            Rule rule = AnyRule(scope, static_cast<RuleAction>(match));
            store.Add(rule);
        }
        for (size_t i = 0; i < count; ++i) {
            const auto policy = policies[i].policy;
            const auto decision = FirewallPolicies::Evaluate(policy, &store, query);
            const bool usesRules = FirewallPolicies::UsesRules(policy);
            const bool expectedMatch = usesRules && match >= 0;
            const bool expectedDecision = expectedMatch || policy != FirewallPolicy::Learning;
            const RuleAction expectedAction = expectedMatch
                ? static_cast<RuleAction>(match)
                : ((policy == FirewallPolicy::Allow || policy == FirewallPolicy::AllowAll)
                    ? RuleAction::Allow : RuleAction::Block);
            Check(decision.matchedRule == expectedMatch,
                  "политика неверно использовала совпавшее правило");
            Check(decision.decided == expectedDecision,
                  "политика неверно выбрала интерактивный запрос");
            if (expectedDecision)
                Check(decision.action == expectedAction, "политика выбрала неверное действие");
            Check(decision.rulesVersion == store.version(), "результат потерял версию правил");
            ++cases;
        }
    }
    std::cout << "Policy decision matrix passed: " << cases << " cases\n";
}

void TestIcmpExceptions() {
    for (Proto proto : { Proto::Icmp, Proto::IcmpV6 }) {
        MatchQuery query = Query(proto, Dir::Out, proto == Proto::IcmpV6);
        query.localPort = query.remotePort = 0;
        for (int type = -1; type <= 256; ++type)
        for (int code = -1; code <= 256; ++code) {
            query.icmpType = type;
            query.icmpCode = code;
            const bool valid = type >= 0 && type <= 255 && code >= 0 && code <= 255;
            const bool expected = valid && (proto == Proto::Icmp
                ? ((type == 3 && code <= 15) || (type == 11 && code <= 1) ||
                   (type == 12 && code <= 2))
                : ((type == 1 && code <= 6) || (type == 2 && code == 0) ||
                   (type == 3 && code <= 1) || (type == 4 && code <= 2) ||
                   (type >= 130 && type <= 137) || type == 143));
            const auto decision = FirewallPolicies::Evaluate(
                FirewallPolicy::Learning, nullptr, query, nullptr, true);
            Check(decision.decided == expected && decision.autoAllowedIcmp == expected &&
                  !decision.matchedRule,
                  "неверный набор технических ICMP-исключений");
            if (expected)
                Check(decision.action == RuleAction::Allow,
                      "ICMP-исключение запросило блокировку вместо авторазрешения");
        }
    }

    for (Proto proto : { Proto::Icmp, Proto::IcmpV6 })
    for (Dir dir : { Dir::Out, Dir::In })
    for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp })
    for (int match = -3; match <= 1; ++match)
    for (bool exceptions : { false, true }) {
        MatchQuery query = Query(proto, dir, proto == Proto::IcmpV6);
        query.icmpType = proto == Proto::Icmp ? 3 : 135;
        query.icmpCode = 0;
        query.localPort = query.remotePort = 0;
        RuleStore store;
        Rule rule = AnyRule(scope, match == 0 ? RuleAction::Allow : RuleAction::Block);
        if (match != -2) {
            rule.conds = CondProto | CondIcmpType;
            rule.proto = proto;
            const int type = match == -3 ? 8 : query.icmpType;
            rule.icmpTypes.push_back({ static_cast<uint8_t>(type), 0 });
            rule.enabled = match != -1;
            store.Add(rule);
        }
        for (auto policy : { FirewallPolicy::BlockAll, FirewallPolicy::Block,
                             FirewallPolicy::Learning, FirewallPolicy::Allow,
                             FirewallPolicy::AllowAll }) {
            RuleNameRef name;
            const auto decision = FirewallPolicies::Evaluate(
                policy, &store, query, &name, exceptions);
            const bool matched = FirewallPolicies::UsesRules(policy) && match >= 0;
            const bool automatic = FirewallPolicies::UsesRules(policy) && exceptions && !matched;
            Check(decision.matchedRule == matched && decision.autoAllowedIcmp == automatic,
                  "ICMP-исключение обошло правило или крайнюю политику");
            Check(decision.decided == (matched || automatic || policy != FirewallPolicy::Learning),
                  "ICMP-исключение без правила создало интерактивный запрос");
            if (decision.decided) {
                const RuleAction expected = matched ? rule.action
                    : (automatic || policy == FirewallPolicy::Allow || policy == FirewallPolicy::AllowAll
                        ? RuleAction::Allow : RuleAction::Block);
                Check(decision.action == expected, "неверное действие для ICMP-исключения");
            }
            Check(decision.rulesVersion == store.version(),
                  "ICMP-исключение потеряло версию набора правил");
            Check(matched ? name && *name == rule.name : !name,
                  "авторазрешению ICMP приписано имя правила");
        }
    }

    // Наличие типа и кода не превращает другие номера IP-протокола в ICMP.
    for (unsigned number = 0; number <= 255; ++number) {
        MatchQuery query = Query(ProtoFromNumber(static_cast<uint8_t>(number)), Dir::In, false);
        query.icmpType = 3;
        query.icmpCode = 0;
        const auto decision = FirewallPolicies::Evaluate(
            FirewallPolicy::Learning, nullptr, query, nullptr, true);
        Check(decision.autoAllowedIcmp == ProtoIsIcmp(query.proto),
              "ICMP-исключение разрешило другой IP-протокол");
    }
}

void TestRulePriorityAndDisabledRules() {
    MatchQuery query = Query(Proto::Tcp, Dir::Out, false);
    for (RuleAction globalAction : { RuleAction::Allow, RuleAction::Block }) {
        RuleStore store;
        Rule app = AnyRule(RuleScope::App,
            globalAction == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow);
        Rule global = AnyRule(RuleScope::Global, globalAction);
        store.Add(app);
        store.Add(global);
        for (auto policy : { FirewallPolicy::Block, FirewallPolicy::Learning, FirewallPolicy::Allow }) {
            RuleNameRef name;
            const auto decision = FirewallPolicies::Evaluate(policy, &store, query, &name);
            Check(decision.decided && decision.matchedRule && decision.action == globalAction,
                  "политика изменила приоритет глобальных правил");
            Check(name && *name == global.name, "результат потерял имя совпавшего правила");
        }
    }

    RuleStore store;
    Rule rule = AnyRule(RuleScope::App, RuleAction::Allow);
    rule.enabled = false;
    store.Add(rule);
    const auto blocked = FirewallPolicies::Evaluate(FirewallPolicy::Block, &store, query);
    Check(blocked.decided && !blocked.matchedRule && blocked.action == RuleAction::Block,
          "выключенное Allow-правило разрешило соединение в режиме блокировки");
    rule.action = RuleAction::Block;
    store.Update(rule);
    const auto allowed = FirewallPolicies::Evaluate(FirewallPolicy::Allow, &store, query);
    Check(allowed.decided && !allowed.matchedRule && allowed.action == RuleAction::Allow,
          "выключенное Block-правило запретило соединение в режиме разрешения");
}

void TestEndedUdpOwnerCannotSelectOldAllowRule() {
    FlowStore& flows = FlowStore::Instance();
    constexpr wchar_t newPath[] = L"C:\\Apps\\Blocked.exe";
    const DWORD originalPid = GetCurrentProcessId();
    const DWORD currentPid = originalPid + 4;
    for (bool ipv6 : { false, true }) {
        flows.Reset();
        const FlowKey key = MakeFlowKey(
            Proto::Udp, ipv6 ? V6(1) : V4(192, 0, 2, 10),
            ipv6 ? V6(2) : V4(198, 51, 100, 20), 60000, 50001);
        RuleStore rules;
        Rule originalAllow = AnyRule(RuleScope::App, RuleAction::Allow);
        originalAllow.name = L"old owner allow";
        rules.Add(originalAllow);
        Rule currentBlock = AnyRule(RuleScope::App, RuleAction::Block);
        currentBlock.appPath = newPath;
        currentBlock.name = L"new owner block";
        rules.Add(currentBlock);
        Rule unknownBlock = AnyRule(RuleScope::PostApp, RuleAction::Block);
        unknownBlock.name = L"unknown owner block";
        rules.Add(unknownBlock);

        FlowStore::ConnEvent original;
        original.pid = originalPid;
        original.dir = Dir::In;
        flows.NoteConnection(key, original);
        flows.NoteAllowed(key, original);
        Check(OwnerLookup::ResolveEventOwner(0, key, Dir::In) == originalPid,
              "активный поток потерял исходного владельца");
        flows.CloseFlow(key, originalPid, Dir::In);

        // Снимок знает нового владельца сокета. Завершённый exact tuple остаётся
        // историей, а не подтверждением владельца нового события.
        FlowStore::SystemSnapshot snapshot;
        auto& rows = ipv6 ? snapshot.udpV6 : snapshot.udpV4;
        rows.push_back({ key.local, key.lport, currentPid });
        (ipv6 ? snapshot.udpV6Valid : snapshot.udpV4Valid) = true;
        flows.ReplaceSystemSnapshot(snapshot);
        Check(OwnerLookup::ByLocalEndpoint(Proto::Udp, key.local, key.lport) == currentPid,
              "снимок не сохранил нового владельца локального сокета");

        const auto evaluateEvent = [&]() {
            bool ambiguous = false;
            const DWORD pid = OwnerLookup::ResolveEventOwner(0, key, Dir::In, &ambiguous);
            const wchar_t* path = pid == originalPid ? kApp : pid == currentPid ? newPath : L"";
            RuleNameRef name;
            const auto decision = FirewallPolicies::Evaluate(
                FirewallPolicy::Learning, &rules,
                MakeMatchQuery(path, pid, key, Dir::In), &name);
            Check(decision.decided && decision.matchedRule && decision.action == RuleAction::Block &&
                  name && *name != originalAllow.name,
                  "новое событие получило Allow по владельцу завершённого потока");
            return pid;
        };
        Check(evaluateEvent() == 0, "завершённый tuple подтвердил прежнего владельца");

        // Публикация нового события не должна повторно активировать старый PID.
        FlowStore::ConnEvent incoming;
        incoming.dir = Dir::In;
        flows.NoteConnection(key, incoming);
        Check(evaluateEvent() == 0, "публикация нового события восстановила старое Allow");

        // Следующий системный снимок связывает уже новое поколение с новым PID.
        flows.ReplaceSystemSnapshot(snapshot);
        Check(evaluateEvent() == currentPid, "новое поколение не получило актуального владельца");
        flows.Reset();
    }
}

void TestAmbiguousUdpOwnerUsesPostAppFallback() {
    FlowStore& flows = FlowStore::Instance();
    const DWORD confirmedPid = GetCurrentProcessId();
    for (bool ipv6 : { false, true }) {
        flows.Reset();
        const FlowKey key = MakeFlowKey(
            Proto::Udp, ipv6 ? V6(1) : V4(192, 0, 2, 10),
            ipv6 ? V6(2) : V4(198, 51, 100, 20), 60000, 50001);
        FlowStore::ConnEvent event;
        event.dir = Dir::In;
        flows.NoteConnection(key, event);

        FlowStore::SystemSnapshot snapshot;
        auto& rows = ipv6 ? snapshot.udpV6 : snapshot.udpV4;
        rows.push_back({ key.local, key.lport, confirmedPid });
        rows.push_back({ key.local, key.lport, confirmedPid + 4 });
        (ipv6 ? snapshot.udpV6Valid : snapshot.udpV4Valid) = true;
        flows.ReplaceSystemSnapshot(snapshot);

        RuleStore rules;
        Rule postAppAllow = AnyRule(RuleScope::PostApp, RuleAction::Allow);
        rules.Add(postAppAllow);
        Rule appBlock = AnyRule(RuleScope::App, RuleAction::Block);
        rules.Add(appBlock);

        const auto checkAllowed = [&]() {
            bool ambiguous = false;
            const DWORD pid = OwnerLookup::ResolveEventOwner(0, key, Dir::In, &ambiguous);
            Check(pid == 0 && ambiguous, "неоднозначный поток потерял признак конфликта владельцев");
            const MatchQuery query = MakeMatchQuery(L"", pid, key, Dir::In);
            for (auto policy : { FirewallPolicy::Block, FirewallPolicy::Learning }) {
                const auto decision = FirewallPolicies::Evaluate(policy, &rules, query);
                Check(decision.decided && decision.matchedRule && decision.action == RuleAction::Allow,
                      "неоднозначный владелец исключил общий резерв PostApp");
            }
        };
        checkAllowed();

        // Публикация разрешения не должна угадывать владельца сокета.
        event.ownerAmbiguous = true;
        for (int attempt = 0; attempt < 3; ++attempt) {
            flows.NoteConnection(key, event);
            checkAllowed();
            flows.NoteAllowed(key, event);
            checkAllowed();
        }
        bool socketAmbiguous = false;
        Check(OwnerLookup::ByLocalEndpoint(Proto::Udp, key.local, key.lport, &socketAmbiguous) == 0 &&
              socketAmbiguous, "публикация события изменила конфликт локальных сокетов");

        // Точный PID драйвера снимает неоднозначность и выбирает правило приложения.
        event.pid = confirmedPid;
        event.ownerAmbiguous = false;
        flows.NoteConnection(key, event);
        bool ambiguous = true;
        Check(OwnerLookup::ResolveEventOwner(0, key, Dir::In, &ambiguous) == confirmedPid &&
              !ambiguous, "подтверждённый PID не снял неоднозначность потока");
        RuleNameRef name;
        const auto confirmed = FirewallPolicies::Evaluate(
            FirewallPolicy::Learning, &rules, MakeMatchQuery(kApp, confirmedPid, key, Dir::In), &name);
        Check(confirmed.decided && confirmed.matchedRule && confirmed.action == RuleAction::Block,
              "подтверждённый владелец не получил Block-правило приложения");
        flows.Reset();
    }
}

void TestFirstInboundSocketPrefersAppRule() {
    FlowStore& flows = FlowStore::Instance();
    const DWORD socketPid = GetCurrentProcessId();
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (bool ipv6 : { false, true })
    for (int binding : { 0, 1, 2 })
    for (int ownership : { 0, 1, 2 }) {
        if (ipv6 && binding == 2) continue;
        flows.Reset();
        const FlowKey key = MakeFlowKey(
            proto, ipv6 ? V6(1) : V4(192, 0, 2, 10),
            ipv6 ? V6(2) : V4(198, 51, 100, 20), 60000, 50001);
        IpAddr bound = key.local;
        if (binding) {
            bound = IpAddr{};
            bound.family = binding == 2 ? AF_INET6 : key.local.family;
        }
        FlowStore::SystemSnapshot snapshot;
        const auto addSocket = [&](DWORD pid) {
            const bool boundV6 = bound.family == AF_INET6;
            if (proto == Proto::Tcp) {
                IpAddr any{};
                any.family = bound.family;
                FlowStore::SystemTcpConnection row;
                row.key = MakeFlowKey(proto, bound, any, key.lport, 0);
                row.pid = pid;
                row.state = MIB_TCP_STATE_LISTEN;
                (boundV6 ? snapshot.tcpV6 : snapshot.tcpV4).push_back(row);
                (boundV6 ? snapshot.tcpV6Valid : snapshot.tcpV4Valid) = true;
            } else {
                (boundV6 ? snapshot.udpV6 : snapshot.udpV4).push_back({ bound, key.lport, pid });
                (boundV6 ? snapshot.udpV6Valid : snapshot.udpV4Valid) = true;
            }
        };
        addSocket(ownership == 2 ? 0 : socketPid);
        if (ownership == 1) addSocket(socketPid + 4);
        flows.ReplaceSystemSnapshot(snapshot);

        RuleStore rules;
        Rule appBlock = AnyRule(RuleScope::App, RuleAction::Block);
        rules.Add(appBlock);
        Rule postAppAllow = AnyRule(RuleScope::PostApp, RuleAction::Allow);
        rules.Add(postAppAllow);
        FlowStore::ConnEvent event;
        event.dir = Dir::In;
        for (int attempt = 0; attempt < 3; ++attempt) {
            bool ambiguous = false;
            const DWORD pid = OwnerLookup::ResolveEventOwner(0, key, Dir::In, &ambiguous);
            Check(pid == (ownership == 0 ? socketPid : 0) && ambiguous == (ownership != 0),
                  "первое входящее событие потеряло владельца локального сокета");
            const MatchQuery query = MakeMatchQuery(pid ? kApp : L"", pid, key, Dir::In);
            const RuleAction expected = ownership == 0 ? RuleAction::Block : RuleAction::Allow;
            for (auto policy : { FirewallPolicy::Block, FirewallPolicy::Learning }) {
                const auto decision = FirewallPolicies::Evaluate(policy, &rules, query);
                Check(decision.decided && decision.matchedRule && decision.action == expected,
                      "правило приложения не имеет приоритета перед резервом PostApp");
            }

            // Публикация сохраняет выбранный PID либо неразрешённого владельца.
            event.pid = pid;
            event.ownerAmbiguous = ambiguous;
            flows.NoteConnection(key, event);
            if (expected == RuleAction::Block) flows.NoteBlocked(key, event);
            else                               flows.NoteAllowed(key, event);
        }
        bool ambiguous = true;
        Check(OwnerLookup::ResolveEventOwner(socketPid + 4, key, Dir::In, &ambiguous) ==
                  socketPid + 4 && !ambiguous,
              "локальный сокет переопределил точный PID драйвера");
        flows.Reset();
    }
}

void TestStaleEndCannotSelectPostAppAllow() {
    FlowStore& flows = FlowStore::Instance();
    const DWORD currentPid = GetCurrentProcessId();
    const DWORD oldPid = currentPid + 4;
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (bool ipv6 : { false, true })
    for (bool blocked : { false, true }) {
        flows.Reset();
        const FlowKey key = MakeFlowKey(
            proto, ipv6 ? V6(1) : V4(192, 0, 2, 10),
            ipv6 ? V6(2) : V4(198, 51, 100, 20), 60000, 50001);
        RuleStore rules;
        Rule appBlock = AnyRule(RuleScope::App, RuleAction::Block);
        rules.Add(appBlock);
        Rule postAppAllow = AnyRule(RuleScope::PostApp, RuleAction::Allow);
        rules.Add(postAppAllow);

        FlowStore::ConnEvent event;
        event.pid = currentPid;
        event.dir = Dir::In;
        flows.NoteConnection(key, event);
        if (blocked) flows.NoteBlocked(key, event);

        const auto checkBlocked = [&]() {
            bool ambiguous = false;
            const DWORD pid = OwnerLookup::ResolveEventOwner(0, key, Dir::In, &ambiguous);
            Check(pid == currentPid && !ambiguous, "запоздалый END потерял текущего владельца потока");
            const MatchQuery query = MakeMatchQuery(pid == currentPid ? kApp : L"", pid,
                                                    key, Dir::In);
            RuleNameRef name;
            const auto decision = FirewallPolicies::Evaluate(FirewallPolicy::Learning, &rules, query, &name);
            Check(decision.decided && decision.matchedRule && decision.action == RuleAction::Block,
                  "чужой END заменил Block приложения на PostApp Allow");
        };
        checkBlocked();
        for (int attempt = 0; attempt < 2; ++attempt) {
            flows.CloseFlow(key, oldPid, Dir::In);
            checkBlocked();
        }
        flows.NoteConnection(key, event);
        checkBlocked();
        flows.Reset();
    }
}

void TestLocalTraffic() {
    RuleStore store;
    Rule deny = AnyRule(RuleScope::Global, RuleAction::Block);
    store.Add(deny);
    MatchQuery query = Query(Proto::Tcp, Dir::Out, false);
    IpAddr loopback6{};
    loopback6.family = AF_INET6;
    loopback6.b[15] = 1;
    std::vector<IpAddr> local = { V4(127, 0, 0, 1), V4(127, 23, 45, 67), loopback6 };
    for (const auto& entry : AddrMacros::Resolve(AddrMacro::AllMyAddresses))
        local.push_back(entry.addr);
    for (Dir dir : { Dir::In, Dir::Out }) {
        query.dir = dir;
        for (const IpAddr& address : local) {
            query.remoteAddr = address;
            query.localAddr = address;
            const auto decision = FirewallPolicies::Evaluate(FirewallPolicy::BlockAll, &store, query);
            Check(decision.decided && decision.action == RuleAction::Allow && !decision.matchedRule,
                  "BlockAll заблокировал локальный трафик или использовал правило");
        }
        for (const IpAddr& address : { V4(198, 51, 100, 2), V6(2) }) {
            query.remoteAddr = address;
            const auto decision = FirewallPolicies::Evaluate(FirewallPolicy::BlockAll, &store, query);
            Check(decision.decided && decision.action == RuleAction::Block,
                  "BlockAll разрешил внешний трафик");
        }
    }
}

void TestMyComputerLoopbackRules() {
    IpAddr loopback6{};
    loopback6.family = AF_INET6;
    loopback6.b[15] = 1;
    const IpAddr loopback[] = {
        V4(127, 0, 0, 0), V4(127, 0, 0, 1), V4(127, 0, 0, 2),
        V4(127, 23, 45, 67), V4(127, 255, 255, 255), loopback6,
    };
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (Dir dir : { Dir::In, Dir::Out })
    for (RuleAction action : { RuleAction::Allow, RuleAction::Block })
    for (uint32_t condition : { uint32_t(CondLocalAddr), uint32_t(CondRemoteAddr),
                               uint32_t(CondLocalAddr | CondRemoteAddr) }) {
        RuleStore store;
        Rule local = AnyRule(RuleScope::Global, action);
        local.name = L"loopback rule";
        local.proto = proto;
        local.conds = CondProto | condition;
        const AddrItem item{ IpAddr{}, -1, AddrMacro::MyComputer };
        if (condition & CondLocalAddr) local.localAddrs.push_back(item);
        if (condition & CondRemoteAddr) local.remoteAddrs.push_back(item);
        store.Add(local);
        Rule fallback = AnyRule(RuleScope::Global,
            action == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow);
        store.Add(fallback);

        // Петлевой адрес выбирает правило макроса, а не противоположный fallback.
        for (const IpAddr& address : loopback) {
            MatchQuery query = Query(proto, dir, address.family == AF_INET6);
            if (condition & CondLocalAddr) query.localAddr = address;
            if (condition & CondRemoteAddr) query.remoteAddr = address;
            for (auto policy : { FirewallPolicy::Learning, FirewallPolicy::Block,
                                 FirewallPolicy::Allow }) {
                RuleNameRef name;
                const auto decision = FirewallPolicies::Evaluate(policy, &store, query, &name);
                Check(decision.decided && decision.matchedRule && decision.action == action &&
                      name && *name == local.name,
                      "петлевой адрес получил вердикт fallback вместо правила MY_COMPUTER");
            }
        }
    }
}

void TestMissingStoreAndInvalidPolicy() {
    const MatchQuery query = Query(Proto::Tcp, Dir::Out, false);
    Check(!FirewallPolicies::Evaluate(FirewallPolicy::Learning, nullptr, query).decided,
          "Learning без хранилища задал автоматический вердикт");
    for (auto policy : { FirewallPolicy::BlockAll, FirewallPolicy::Block,
                         FirewallPolicy::Allow, FirewallPolicy::AllowAll }) {
        const auto result = FirewallPolicies::Evaluate(policy, nullptr, query);
        Check(result.decided && !result.matchedRule, "неинтерактивная политика потребовала хранилище");
    }
    const auto invalid = static_cast<FirewallPolicy>(255);
    Check(!FirewallPolicies::IsValid(invalid), "принята неизвестная политика");
    Check(!FirewallPolicies::Evaluate(invalid, nullptr, query).decided,
          "неизвестная политика не вернулась в Learning");
}

void OpenSettings(const std::wstring& path) {
    std::wstring error;
    Check(Settings::Open(path, error), "не удалось открыть тестовую базу настроек");
}

void TestSettingsRoundTrip() {
    wchar_t tempDir[MAX_PATH]{};
    wchar_t tempFile[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, tempDir) != 0 &&
          GetTempFileNameW(tempDir, L"fxp", 0, tempFile) != 0,
          "не удалось создать временный файл настроек");
    const std::wstring path(tempFile);
    OpenSettings(path);
    Check(FirewallPolicySetting::Load() == FirewallPolicy::Learning,
          "политика по умолчанию не Learning");
    Check(Settings::SetInt(Settings::Key::kUiLang, 0x0419), "не удалось записать соседнюю настройку");

    size_t count = 0;
    const auto* policies = FirewallPolicies::All(count);
    for (size_t i = 0; i < count; ++i) {
        Check(FirewallPolicySetting::Save(policies[i].policy), "не удалось сохранить политику");
        Settings::Close();
        OpenSettings(path);
        Check(FirewallPolicySetting::Load() == policies[i].policy,
              "политика не восстановилась после повторного открытия базы");
        Check(Settings::GetInt(Settings::Key::kUiLang, 0) == 0x0419,
              "запись политики изменила соседнюю настройку");
    }
    for (const wchar_t* value : { L"", L"-1", L"5", L"255", L"256", L"0abc", L"2.0",
                                 L"999999999999999999999999999999" }) {
        Check(Settings::SetString(Settings::Key::kDesktopPolicy, value), "не удалось записать неверную настройку");
        Check(FirewallPolicySetting::Load() == FirewallPolicy::Learning,
              "повреждённая настройка не вернулась в Learning");
        Check(Settings::GetString(Settings::Key::kDesktopPolicy) == value,
              "чтение политики перезаписало неизвестную настройку");
    }
    Check(FirewallPolicySetting::Save(FirewallPolicy::Learning), "не удалось вернуть Learning");
    Check(!FirewallPolicySetting::Save(static_cast<FirewallPolicy>(255)),
          "сохранена неизвестная политика");
    Check(FirewallPolicySetting::Load() == FirewallPolicy::Learning,
          "попытка сохранить неизвестную политику изменила настройку");

    sqlite3* blocker = nullptr;
    const std::string utf8 = WideToUtf8(path);
    Check(sqlite3_open_v2(utf8.c_str(), &blocker, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK,
          "не удалось открыть второе подключение настроек");
    Check(sqlite3_exec(blocker, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) == SQLITE_OK,
          "не удалось заблокировать запись настроек");
    Check(!FirewallPolicySetting::Save(FirewallPolicy::AllowAll),
          "ошибка записи политики не возвращена вызывающему");
    Check(!Settings::lastError().empty(), "ошибка записи политики потеряла пояснение");
    sqlite3_exec(blocker, "ROLLBACK;", nullptr, nullptr, nullptr);
    sqlite3_close(blocker);
    Settings::Close();
    OpenSettings(path);
    Check(FirewallPolicySetting::Load() == FirewallPolicy::Learning,
          "неудачное сохранение изменило политику после перезапуска");
    Settings::Close();
    Check(DeleteFileW(path.c_str()) != FALSE, "не удалось удалить временную базу настроек");
}

std::wstring ResourceString(UINT id, WORD lang) {
    HMODULE module = GetModuleHandleW(nullptr);
    HRSRC resource = FindResourceExW(module, RT_STRING, MAKEINTRESOURCEW(id / 16 + 1), lang);
    Check(resource != nullptr, "нет строковой таблицы политики");
    HGLOBAL block = LoadResource(module, resource);
    Check(block != nullptr, "не удалось загрузить ресурс политики");
    const auto* data = static_cast<const wchar_t*>(LockResource(block));
    Check(data != nullptr, "не удалось прочитать ресурс политики");
    const size_t size = SizeofResource(module, resource) / sizeof(wchar_t);
    size_t offset = 0;
    for (UINT index = 0; index < id % 16; ++index) {
        Check(offset < size && data[offset] < size - offset, "повреждена строковая таблица политики");
        offset += 1 + data[offset];
    }
    Check(offset < size && data[offset] > 0 && data[offset] < size - offset,
          "нет перевода строки политики");
    return std::wstring(data + offset + 1, data[offset]);
}

const ConnItem* FindConnection(const Snapshot& snapshot, const FlowKey& key) {
    for (const auto& process : snapshot.procs)
        for (const auto& connection : process.conns)
            if (connection.key == key) return &connection;
    return nullptr;
}

Snapshot NextSnapshot(Monitor& monitor) {
    Snapshot snapshot;
    const ULONGLONG deadline = GetTickCount64() + 10000;
    while (!monitor.TakeLatest(snapshot)) {
        Check(GetTickCount64() < deadline, "монитор не опубликовал снимок");
        Sleep(10);
    }
    size_t offset = 0;
    for (const ProcItem& process : snapshot.procs) {
        if (!process.conns.empty()) {
            Check(process.conns.data() >= snapshot.conns.data() &&
                  process.conns.data() + process.conns.size() <= snapshot.conns.end(),
                  "диапазон процесса выходит за общий массив снимка");
        }
        for (const ConnItem& connection : process.conns)
            Check(connection.pid == process.group.pid(),
                  "диапазон процесса содержит соединения другого PID");
        offset += process.conns.size();
    }
    Check(offset == snapshot.conns.size(),
          "снимок монитора содержит неиспользуемые элементы соединений");
    if (snapshot.displayReady)
        Check(snapshot.connCount == snapshot.conns.size(),
              "размер общего массива не совпал с числом отображаемых соединений");
    return snapshot;
}

void TestMonitorDriverTrafficDirection() {
    FlowStore& flows = FlowStore::Instance();
    flows.Reset();
    const FlowKey host4 = MakeFlowKey(
        Proto::Tcp, V4(192, 0, 2, 20), V4(198, 51, 100, 20), 41200, 443);
    const FlowKey host6 = MakeFlowKey(Proto::Tcp, V6(20), V6(21), 41201, 443);
    for (const FlowKey& key : { host4, host6 }) flows.AddBandwidth(key, 10, 5);

    FlowKey guest4 = host4;
    guest4.source = TrafficSource::Ndis;
    firewallxndisfilter::Client::BandwidthV4 entry4{};
    std::memcpy(entry4.local_ip, guest4.local.b, sizeof(entry4.local_ip));
    std::memcpy(entry4.remote_ip, guest4.remote.b, sizeof(entry4.remote_ip));
    entry4.local_port = guest4.lport;
    entry4.remote_port = guest4.rport;
    entry4.transmitted_bytes = 10;
    entry4.received_bytes = 5;
    flows.AddNdisBandwidthBatch(DriverProto::kTcp, &entry4, 1);

    FlowKey guest6 = host6;
    guest6.source = TrafficSource::Ndis;
    firewallxndisfilter::Client::BandwidthV6 entry6{};
    std::memcpy(entry6.local_ip, guest6.local.b, sizeof(entry6.local_ip));
    std::memcpy(entry6.remote_ip, guest6.remote.b, sizeof(entry6.remote_ip));
    entry6.local_port = guest6.lport;
    entry6.remote_port = guest6.rport;
    entry6.transmitted_bytes = 10;
    entry6.received_bytes = 5;
    flows.AddNdisBandwidthBatch(DriverProto::kTcp, &entry6, 1);

    FlowKey known = host4;
    ++known.lport;
    FlowStore::ConnEvent event;
    event.pid = 4;
    event.dir = Dir::In;
    flows.NoteConnection(known, event);
    flows.AddBandwidth(known, 10, 5);

    Monitor monitor;
    std::wstring warnings;
    monitor.Start(warnings, nullptr, 0);
    const Snapshot snapshot = NextSnapshot(monitor);
    for (const FlowKey& key : { host4, host6, guest4, guest6 }) {
        const ConnItem* connection = FindConnection(snapshot, key);
        Check(connection && connection->dir == Dir::Unknown,
              "монитор выдумал направление трафика драйвера");
    }
    const ConnItem* connection = FindConnection(snapshot, known);
    Check(connection && connection->dir == Dir::In,
          "монитор потерял направление события драйвера");
    monitor.Stop();
    flows.Reset();
}

void TestMonitorServiceName() {
    ProcItem process;
    process.group = TrafficGroupKey::Host(1000);
    process.name = L"svchost.exe";
    process.path = L"C:\\Windows\\System32\\svchost.exe";
    const auto checkRows = [&](std::wstring_view expected) {
        TreeList::Row group;
        group.isGroup = true;
        group.col[ColProcess] = process.name;
        TreeList::Row connection;
        connection.col[ColProcess] = process.serviceName();
        Check(connection.processName(group) == expected,
              "строка соединения использует неверное имя владельца");
        Check(group.processName(group) == L"svchost.exe",
              "заголовок группы заменил имя процесса именем службы");
    };
    Check(process.serviceName().empty(),
          "процесс без снимка служб получил имя службы");
    checkRows(process.name);

    process.hostedServices = std::make_shared<const std::vector<ServiceEntry>>();
    Check(process.serviceName().empty(),
          "процесс без служб получил имя службы");
    checkRows(process.name);

    ServiceEntry service;
    service.name = L"Dnscache";
    service.display = L"DNS Client";
    service.pid = process.group.pid();
    service.state = SERVICE_RUNNING;
    process.hostedServices = std::make_shared<const std::vector<ServiceEntry>>(
        std::vector<ServiceEntry>{ service });
    Check(process.serviceName() == service.name,
          "подпись соединения использует описание вместо имени службы");
    checkRows(service.name);
    Check(process.name == L"svchost.exe" &&
          process.path == L"C:\\Windows\\System32\\svchost.exe" && process.group == TrafficGroupKey::Host(1000),
          "подпись службы изменила данные приложения для правил");

    process.ownerAmbiguous = true;
    Check(process.serviceName().empty(),
          "неоднозначному владельцу соединения приписана служба");
    checkRows(process.name);
    process.ownerAmbiguous = false;

    service.display.clear();
    process.hostedServices = std::make_shared<const std::vector<ServiceEntry>>(
        std::vector<ServiceEntry>{ service });
    checkRows(service.name);

    ServiceEntry other = service;
    other.name = L"Dhcp";
    other.display = L"DHCP Client";
    process.hostedServices = std::make_shared<const std::vector<ServiceEntry>>(
        std::vector<ServiceEntry>{ service, other });
    Check(process.serviceName().empty(),
          "процесс с несколькими службами получил имя произвольной службы");
    checkRows(process.name);
}

struct BandwidthPollProbe {
    pmkext::BandwidthValueV4 entry{};
    std::atomic<unsigned> calls{ 0 };
    std::atomic<ULONGLONG> firstAt{ 0 }, lastAt{ 0 };
    std::atomic<bool> pauseNext{ false };
    HANDLE entered = nullptr, proceed = nullptr;
};

BandwidthPollProbe* bandwidthPollProbe = nullptr;

bool RequestProbeBandwidth() {
    BandwidthPollProbe& probe = *bandwidthPollProbe;
    const ULONGLONG now = GetTickCount64();
    if (!probe.calls.fetch_add(1, std::memory_order_relaxed))
        probe.firstAt.store(now, std::memory_order_relaxed);
    probe.lastAt.store(now, std::memory_order_relaxed);
    if (probe.pauseNext.exchange(false)) {
        SetEvent(probe.entered);
        Check(WaitForSingleObject(probe.proceed, 10000) == WAIT_OBJECT_0,
              "проверка смены видимости не освободила опрос трафика");
    }
    FlowStore::Instance().AddBandwidthBatch(DriverProto::kUdp, &probe.entry, 1);
    return true;
}

void TestMonitorCoordinatedBandwidthPoll() {
    FlowStore& flows = FlowStore::Instance();
    flows.Reset();
    const FlowKey key = MakeFlowKey(
        Proto::Udp, V4(192, 0, 2, 1), V4(198, 51, 100, 2), 41122, 443);
    FlowStore::ConnEvent event;
    event.pid = GetCurrentProcessId();
    event.dir = Dir::Out;
    flows.NoteConnection(key, event);
    flows.NoteAllowed(key, event);
    BandwidthPollProbe probe;
    std::memcpy(probe.entry.local_ip, key.local.b, sizeof(probe.entry.local_ip));
    std::memcpy(probe.entry.remote_ip, key.remote.b, sizeof(probe.entry.remote_ip));
    probe.entry.local_port = key.lport;
    probe.entry.remote_port = key.rport;
    probe.entry.transmitted_bytes = 10;
    probe.entry.received_bytes = 20;
    probe.entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    probe.proceed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(probe.entered && probe.proceed, "не созданы события проверки монитора");
    bandwidthPollProbe = &probe;

    RuleStore rules;
    Rule block = AnyRule(RuleScope::Global, RuleAction::Block);
    rules.Add(block);
    Monitor monitor;
    monitor.SetRuleStore(&rules);
    monitor.SetPolicy(FirewallPolicy::AllowAll);
    monitor.SetBandwidthRequest(RequestProbeBandwidth);
    std::wstring warnings;
    monitor.Start(warnings, nullptr, 0);
    Snapshot snapshot = NextSnapshot(monitor);
    const ConnItem* connection = FindConnection(snapshot, key);
    Check(probe.calls.load(std::memory_order_relaxed) == 1 && connection &&
          connection->sent == 10 && connection->recv == 20 && connection->speed == 0.0,
          "первый опрос bandwidth не попал в снимок либо получил выдуманный интервал");

    // Частые UI-запросы сливаются в один следующий секундный цикл.
    for (int index = 0; index < 5; ++index) monitor.RequestRefresh();
    snapshot = NextSnapshot(monitor);
    connection = FindConnection(snapshot, key);
    Check(probe.calls.load(std::memory_order_relaxed) == 2 &&
          probe.lastAt.load(std::memory_order_relaxed) -
              probe.firstAt.load(std::memory_order_relaxed) >= 950,
          "внеочередное обновление UI запустило короткий опрос трафика");
    Check(connection && connection->sent == 20 && connection->recv == 40 &&
          connection->speed > 0.0 && connection->speed <= 100.0,
          "bandwidth не запрашивается до сборки следующего снимка");
    for (const ProcItem& process : snapshot.procs) {
        double speed = 0.0;
        for (const ConnItem& child : process.conns) speed += child.speed;
        Check(process.speed == speed,
              "общая скорость монитора не равна сумме отображаемых соединений");
    }
    monitor.SetPolicy(FirewallPolicy::Learning);
    monitor.SetDisplayEnabled(false);
    // Эти данные появляются после скрытия: готовой полной строки с ними нет.
    event.tlsDomainLabel = std::make_shared<const std::wstring>(L"[hidden-monitor.example]");
    flows.NoteAllowed(key, event);
    const FlowKey hiddenIcmp = MakeFlowKey(
        Proto::Icmp, V4(192, 0, 2, 1), V4(198, 51, 100, 3), 0, 0);
    FlowStore::ConnEvent packet = event;
    packet.tlsDomainLabel.reset();
    packet.bytes = 84;
    packet.icmpType = 8;
    packet.icmpCode = 0;
    const uint64_t icmpGeneration = flows.NoteConnection(hiddenIcmp, packet);
    packet.dir = Dir::In;
    packet.bytes = 96;
    packet.icmpType = 0;
    flows.NoteConnection(hiddenIcmp, packet);
    for (unsigned expectedCalls : { 3u, 4u }) {
        snapshot = NextSnapshot(monitor);
        Check(!snapshot.displayReady && snapshot.connCount >= 1 && snapshot.ruleMatches == 0 &&
              snapshot.conns.empty() && snapshot.conns.data() == nullptr &&
              probe.calls.load(std::memory_order_relaxed) == expectedCalls,
              "скрытый монитор не продолжил опрос или подготовил строки и правила");
        bool foundProcess = false;
        for (const ProcItem& process : snapshot.procs) {
            foundProcess = foundProcess || process.group == TrafficGroupKey::Host(event.pid);
            Check(process.conns.empty() && !process.pathInfo && !process.hostedServices &&
                  process.name.empty() && process.path.empty() && process.speed == 0.0 &&
                  !process.bytesKnown && !process.icon,
                  "сводка трея содержит неотображаемые данные процесса");
        }
        Check(foundProcess, "сводка трея потеряла процесс с трафиком");
        monitor.RequestRefresh();
    }
    monitor.SetDisplayEnabled(true);
    snapshot = NextSnapshot(monitor);
    connection = FindConnection(snapshot, key);
    Check(snapshot.displayReady && connection && connection->sent == 50 &&
          connection->recv == 100 && connection->speed > 0.0 && connection->speed <= 45.0 &&
          connection->ruleId == block.id,
          "восстановленный монитор потерял трафик, накопил скрытые интервалы или не вернул правила");
    Check(connection->tlsDomainLabel &&
          *connection->tlsDomainLabel == L"[hidden-monitor.example]",
          "первый полный снимок не получил домен, появившийся в трее");
    const ConnItem* restoredIcmp = FindConnection(snapshot, hiddenIcmp);
    Check(restoredIcmp && restoredIcmp->flowGeneration == icmpGeneration &&
          restoredIcmp->sent == 84 && restoredIcmp->recv == 96 &&
          restoredIcmp->pktSent == 1 && restoredIcmp->pktRecv == 1 &&
          restoredIcmp->driverEvents == 2 && restoredIcmp->icmpOut.type == 8 &&
          restoredIcmp->icmpIn.type == 0 && restoredIcmp->dir == Dir::Out,
          "первый полный снимок потерял ICMP, собранный только в трее");
    const auto owner = std::find_if(snapshot.procs.begin(), snapshot.procs.end(),
        [&](const ProcItem& process) { return process.group == TrafficGroupKey::Host(event.pid); });
    Check(owner != snapshot.procs.end() && owner->pathInfo && !owner->pathInfo->text.empty(),
          "восстановленный монитор не подготовил путь для отображения и правил");
    Check(probe.calls.load(std::memory_order_relaxed) == 5 &&
          probe.lastAt.load(std::memory_order_relaxed) -
              probe.firstAt.load(std::memory_order_relaxed) >= 3800,
          "смена видимости сократила секундные интервалы опроса драйвера");

    // Скрытие и восстановление во время сборки инвалидируют старый полный
    // снимок, даже если к концу прохода окно снова стало видимым.
    probe.pauseNext.store(true);
    monitor.RequestRefresh();
    Check(WaitForSingleObject(probe.entered, 10000) == WAIT_OBJECT_0,
          "монитор не начал управляемый опрос трафика");
    monitor.SetDisplayEnabled(false);
    monitor.SetDisplayEnabled(true);
    SetEvent(probe.proceed);
    snapshot = NextSnapshot(monitor);
    Check(!snapshot.displayReady,
          "снимок до смены видимости остался пригодным для перестройки списка");
    snapshot = NextSnapshot(monitor);
    Check(snapshot.displayReady && FindConnection(snapshot, key),
          "монитор не опубликовал актуальные строки после смены видимости");
    monitor.Stop();
    CloseHandle(probe.entered);
    CloseHandle(probe.proceed);
    bandwidthPollProbe = nullptr;
    flows.Reset();
}

void TestMonitorPolicyReasons() {
    FlowStore& flows = FlowStore::Instance();
    flows.Reset();
    FlowStore::ConnEvent event;
    event.pid = GetCurrentProcessId();
    event.dir = Dir::Out;
    const FlowKey key = MakeFlowKey(Proto::Gre, V4(192, 0, 2, 1), V4(198, 51, 100, 2), 0, 0);
    flows.NoteConnection(key, event);

    RuleStore rules;
    Rule block = AnyRule(RuleScope::Global, RuleAction::Block);
    rules.Add(block);
    Monitor monitor;
    monitor.SetRuleStore(&rules);
    monitor.SetPolicy(FirewallPolicy::AllowAll);
    std::wstring warnings;
    monitor.Start(warnings, nullptr, 0);
    Snapshot snapshot = NextSnapshot(monitor);
    const ConnItem* connection = FindConnection(snapshot, key);
    Check(connection && connection->byPolicy && connection->ruleId == 0 &&
          connection->ruleAction == static_cast<int>(RuleAction::Allow),
          "AllowAll показал игнорируемое Block-правило в списке");
    Check(Monitor::ConnectionStatus(*connection, L"", GetTickCount64()).find(
              FirewallPolicies::Name(FirewallPolicy::AllowAll)) != std::wstring::npos,
          "список не показывает причину решения по политике");

    monitor.SetPolicy(FirewallPolicy::BlockAll);
    monitor.RequestRefresh();
    snapshot = NextSnapshot(monitor);
    connection = FindConnection(snapshot, key);
    Check(connection && connection->byPolicy && connection->ruleId == 0 &&
          connection->policy == FirewallPolicy::BlockAll &&
          connection->ruleAction == static_cast<int>(RuleAction::Block),
          "смена политики не обновила действие в снимке монитора");

    monitor.SetPolicy(FirewallPolicy::Learning);
    monitor.RequestRefresh();
    snapshot = NextSnapshot(monitor);
    connection = FindConnection(snapshot, key);
    Check(connection && !connection->byPolicy && connection->ruleId == block.id,
          "Learning не вернул сопоставление правил в монитор");
    monitor.Stop();
    flows.Reset();
}

void TestMonitorIcmpExceptions() {
    FlowStore& flows = FlowStore::Instance();
    flows.Reset();
    const FlowKey v4 = MakeFlowKey(Proto::Icmp, V4(192, 0, 2, 1), V4(198, 51, 100, 2), 0, 0);
    const FlowKey v6 = MakeFlowKey(Proto::IcmpV6, V6(1), V6(2), 0, 0);
    const FlowKey echo = MakeFlowKey(Proto::Icmp, V4(192, 0, 2, 1), V4(198, 51, 100, 3), 0, 0);
    FlowStore::ConnEvent event;
    event.pid = 4;
    event.dir = Dir::In;
    event.icmpType = 3;
    event.icmpCode = 4;
    event.bytes = 64;
    flows.NoteConnection(v4, event);
    event.pid = 0;
    event.dir = Dir::Out;
    event.icmpType = 135;
    event.icmpCode = 0;
    event.bytes = 80;
    flows.NoteConnection(v6, event);
    event.icmpType = 8;
    flows.NoteConnection(echo, event);

    RuleStore rules;
    Monitor monitor;
    monitor.SetRuleStore(&rules);
    monitor.SetPolicy(FirewallPolicy::Learning);
    std::wstring warnings;
    monitor.Start(warnings, nullptr, 0);
    Snapshot snapshot = NextSnapshot(monitor);
    const auto checkAutomatic = [&](const FlowKey& key) {
        const ConnItem* connection = FindConnection(snapshot, key);
        Check(connection && connection->autoAllowedIcmp && !connection->byPolicy &&
              !connection->ruleId && !connection->blockedAt &&
              connection->ruleAction == static_cast<int>(RuleAction::Allow),
              "ICMP-исключение не показано как автоматически разрешённое");
        const std::wstring status = Monitor::ConnectionStatus(*connection, L"", GetTickCount64());
        Check(status.find(LoadStringRes(IDS_MON_AUTO_ALLOWED_ICMP)) != std::wstring::npos &&
              status.find(IcmpLabel(connection->icmp)) != std::wstring::npos,
              "статус ICMP потерял причину разрешения или тип/код пакета");
        return connection;
    };
    const ConnItem* connection = checkAutomatic(v4);
    Check(connection->pid == 4 && connection->dir == Dir::In &&
          connection->recv == 64 && connection->pktRecv == 1 && connection->driverEvents == 1,
          "входящее ICMP-исключение потеряло владельца или счётчики");
    connection = checkAutomatic(v6);
    Check(connection->pid == 0 && connection->dir == Dir::Out &&
          connection->sent == 80 && connection->pktSent == 1 && connection->driverEvents == 1,
          "исходящее ICMPv6-исключение потеряло направление или счётчики");
    connection = FindConnection(snapshot, echo);
    Check(connection && !connection->autoAllowedIcmp && connection->ruleAction == -1,
          "обычный Echo Request показан как автоматически разрешённый");

    Rule block = AnyRule(RuleScope::Global, RuleAction::Block);
    rules.Add(block);
    monitor.RequestRefresh();
    snapshot = NextSnapshot(monitor);
    for (const FlowKey& key : { v4, v6 }) {
        connection = FindConnection(snapshot, key);
        Check(connection && !connection->autoAllowedIcmp && !connection->byPolicy &&
              connection->ruleId == block.id &&
              connection->ruleAction == static_cast<int>(RuleAction::Block),
              "монитор проигнорировал Block-правило для ICMP-исключения");
        Check(Monitor::ConnectionStatus(*connection, block.name, GetTickCount64()).find(
                  LoadStringRes(IDS_MON_AUTO_ALLOWED_ICMP)) == std::wstring::npos,
              "ICMP с Block-правилом сохранил статус авторазрешения");
    }

    block.enabled = false;
    rules.Update(block);
    monitor.RequestRefresh();
    snapshot = NextSnapshot(monitor);
    checkAutomatic(v4);
    checkAutomatic(v6);

    monitor.SetPolicy(FirewallPolicy::Block);
    monitor.RequestRefresh();
    snapshot = NextSnapshot(monitor);
    for (const FlowKey& key : { v4, v6 }) {
        connection = FindConnection(snapshot, key);
        Check(connection && !connection->autoAllowedIcmp && connection->byPolicy &&
              connection->ruleAction == static_cast<int>(RuleAction::Block),
              "явная оконная политика обойдена ICMP-исключением в мониторе");
    }
    monitor.Stop();
    flows.Reset();
}

void TestPolicyResources() {
    const UiLang original = CurrentUiLang();
    size_t count = 0;
    const auto* langs = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(langs[i].lang);
        for (UINT id = IDS_MENU_POLICY; id <= IDS_TRAY_TIP_POLICY_FMT; ++id) {
            const std::wstring text = ResourceString(id, langs[i].winLangId);
            Check(LoadStringRes(id) == text, "строка политики загрузилась на другом языке");
            if (id == IDS_POLICY_SAVE_FAILED_FMT || id == IDS_POLICY_CACHE_FAILED_FMT ||
                id == IDS_TRAY_TIP_POLICY_FMT) {
                const size_t pos = text.find(L"%s");
                Check(pos != std::wstring::npos && text.find(L"%s", pos + 2) == std::wstring::npos,
                      "неверный формат сообщения политики");
                Check(LoadStringResFmt(id, L"value") ==
                      text.substr(0, pos) + L"value" + text.substr(pos + 2),
                      "неверное форматирование сообщения политики");
            }
        }
        Check(LoadStringRes(IDS_MON_AUTO_ALLOWED_ICMP) ==
                  ResourceString(IDS_MON_AUTO_ALLOWED_ICMP, langs[i].winLangId),
              "нет перевода статуса автоматического разрешения ICMP");
    }
    SetUiLang(original);
}

} // namespace

int main() {
    SetUiLang(UiLang::English);
    TestDecisionMatrix();
    TestIcmpExceptions();
    TestRulePriorityAndDisabledRules();
    TestEndedUdpOwnerCannotSelectOldAllowRule();
    TestAmbiguousUdpOwnerUsesPostAppFallback();
    TestFirstInboundSocketPrefersAppRule();
    TestStaleEndCannotSelectPostAppAllow();
    TestLocalTraffic();
    TestMyComputerLoopbackRules();
    TestMissingStoreAndInvalidPolicy();
    TestSettingsRoundTrip();
    TestPolicyResources();
    TestMonitorDriverTrafficDirection();
    TestMonitorServiceName();
    TestMonitorCoordinatedBandwidthPoll();
    TestMonitorPolicyReasons();
    TestMonitorIcmpExceptions();
    std::cout << "Firewall policy tests passed\n";
    return 0;
}
