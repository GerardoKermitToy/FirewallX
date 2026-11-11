#include "Rules.h"
#include "RuleDb.h"
#include "RuleDialogs.h"
#include "ServiceInfo.h"
#include "StringRes.h"
#include <winsqlite/winsqlite3.h>

#include <algorithm>
#include <array>
#include <barrier>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include <tuple>

namespace {

constexpr uint32_t kEndpointConds =
    CondRemoteAddr | CondRemotePort | CondLocalAddr | CondLocalPort;

void Check(bool value, const char* message) {
    if (value) return;
    std::cerr << message << '\n';
    std::exit(1);
}

IpAddr V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    const uint8_t bytes[4] = { a, b, c, d };
    return IpAddr::Raw4(bytes);
}

const IpAddr kLocal = V4(192, 0, 2, 10);
const IpAddr kRemote = V4(198, 51, 100, 20);
constexpr uint16_t kLocalPort = 41000;
constexpr uint16_t kRemotePort = 443;
const net::NetworkInterfaceWatcher::InterfaceInfo& TestInterface() {
    static const auto interface = [] {
        auto& watcher = net::SharedNetworkInterfaces();
        Check(watcher.Start(), "cannot start interface watcher");
        const auto snapshot = watcher.GetSnapshot();
        Check(snapshot != nullptr, "missing interface snapshot");
        for (const auto& entry : snapshot->interfaces)
            if (entry.up && entry.number && !entry.name.empty()) return entry;
        Check(false, "no active network interface (including loopback)");
        return net::NetworkInterfaceWatcher::InterfaceInfo{};
    }();
    return interface;
}

constexpr wchar_t kAppPath[] = L"C:\\Apps\\Example.exe";

Rule OutboundRule(Proto proto, uint32_t endpointConds) {
    Rule rule;
    rule.scope = RuleScope::App;
    rule.appPath = kAppPath;
    rule.appName = L"EXAMPLE.EXE";
    rule.name = L"test rule";
    rule.autoName = false;
    rule.proto = proto;
    rule.dir = Dir::Out;
    rule.conds = CondProto | CondDirection | endpointConds;
    rule.action = RuleAction::Block;

    if (endpointConds & CondRemoteAddr)
        rule.remoteAddrs.push_back(AddrItem{ kRemote, -1 });
    if (endpointConds & CondLocalAddr)
        rule.localAddrs.push_back(AddrItem{ kLocal, -1 });
    if (endpointConds & CondRemotePort)
        rule.remotePorts.push_back(PortItem{ kRemotePort, kRemotePort });
    if (endpointConds & CondLocalPort)
        rule.localPorts.push_back(PortItem{ kLocalPort, kLocalPort });
    return rule;
}

MatchQuery Query(Proto proto, Dir dir,
                 const IpAddr& local = kLocal,
                 const IpAddr& remote = kRemote,
                 uint16_t localPort = kLocalPort,
                 uint16_t remotePort = kRemotePort) {
    const FlowKey key = MakeFlowKey(
        proto, local, remote, localPort, remotePort);
    return MakeMatchQuery(kAppPath, 1000, key, dir);
}

bool Matches(RuleStore& store, const MatchQuery& query,
             RuleAction* action = nullptr) {
    RuleAction found = RuleAction::Allow;
    const bool matched = store.MatchVerdict(query, found);
    if (action) *action = found;
    return matched;
}

std::wstring ReferenceFoldCaseCopy(std::wstring_view text) {
    // Посимвольный эталон не использует кешированную таблицу.
    std::wstring folded(text);
    for (wchar_t& c : folded) CharUpperBuffW(&c, 1);
    return folded;
}

void CheckNoCaseTextPair(std::wstring_view a, std::wstring_view b) {
    const std::wstring foldedA = ReferenceFoldCaseCopy(a);
    const std::wstring foldedB = ReferenceFoldCaseCopy(b);
    const int expected = foldedA.compare(foldedB);
    const int actual = CompareNoCase(a, b);
    Check((actual < 0) == (expected < 0) &&
              (actual == 0) == (expected == 0) &&
              (actual > 0) == (expected > 0),
          "безрегистровое сравнение изменило порядок строк");
    Check(EqualNoCase(a, b) == (expected == 0) &&
              ServiceInfo::SameName(std::wstring(a), std::wstring(b)) == (expected == 0),
          "безрегистровое равенство расходится со сравнением");
    Check(FoldCaseCopy(a) == foldedA && FoldCaseCopy(b) == foldedB,
          "кешированная свёртка расходится с посимвольной свёрткой Windows");
    Check(HashTextNoCase(a) == HashFoldedText(foldedA) &&
              HashTextNoCase(b) == HashFoldedText(foldedB),
          "безрегистровый хэш изменился после оптимизации");
}

void TestNoCaseTextHelpers() {
    // Первый доступ из нескольких потоков не должен публиковать часть таблицы.
    const std::wstring source = L"App_Пример_αβγ_ａｂｃ";
    const std::wstring expected = L"APP_ПРИМЕР_ΑΒΓ_ＡＢＣ";
    std::array<std::thread, 8> workers;
    std::barrier start(8);
    for (std::thread& worker : workers) {
        worker = std::thread([&] {
            start.arrive_and_wait();
            Check(FoldCaseCopy(source) == expected &&
                      HashTextNoCase(source) == HashFoldedText(expected) &&
                      EqualNoCase(source, expected),
                  "параллельная инициализация таблицы свёртки дала неверный результат");
        });
    }
    for (std::thread& worker : workers) worker.join();

    // Проверяем все элементы UTF-16, включая NUL и отдельные суррогаты.
    std::wstring units(65536, L'\0');
    std::wstring folded(65536, L'\0');
    std::vector<uint16_t> order(units.size());
    for (size_t i = 0; i < units.size(); ++i) {
        units[i] = static_cast<wchar_t>(i);
        folded[i] = units[i];
        CharUpperBuffW(&folded[i], 1);
        order[i] = static_cast<uint16_t>(i);
        Check(FoldCaseChar(units[i]) == folded[i],
              "таблица свёртки неверно преобразовала элемент UTF-16");
        CheckNoCaseTextPair(std::wstring_view(units.data() + i, 1),
                            std::wstring_view(folded.data() + i, 1));
    }
    CheckNoCaseTextPair(units, folded);
    std::sort(order.begin(), order.end(), [&](uint16_t a, uint16_t b) {
        return folded[a] < folded[b];
    });
    for (size_t i = 1; i < order.size(); ++i)
        CheckNoCaseTextPair(std::wstring_view(units.data() + order[i - 1], 1),
                            std::wstring_view(units.data() + order[i], 1));

    const std::vector<std::wstring> cases = {
        L"", L"a", L"A", L"aa", L"Aa", L"ab", L"ABC",
        kAppPath, L"c:\\APPS\\EXAMPLE.EXE", L"Пример", L"ПРИМЕР",
        L"ı", L"I", L"ς", L"Σ", L"ß", L"SS",
        L"\U00010428", L"\U00010400",
        std::wstring(L"a\0b", 3), std::wstring(L"A\0B", 3),
        std::wstring(L"A\0c", 3), std::wstring(L"A\0", 2),
        std::wstring(1024, L'a'), std::wstring(1024, L'A'),
        std::wstring(1024, L'я'), std::wstring(1024, L'Я'),
    };
    for (const std::wstring& a : cases)
    for (const std::wstring& b : cases)
        CheckNoCaseTextPair(a, b);
    CheckNoCaseTextPair({}, {});
    CheckNoCaseTextPair({}, L"a");
    CheckNoCaseTextPair(L"a", {});

    std::mt19937 rng(0xF01DC45E);
    for (unsigned test = 0; test < 1000; ++test) {
        std::wstring a(2 + rng() % 128, L'\0');
        for (wchar_t& c : a) c = static_cast<wchar_t>(rng() & 0xFFFF);
        std::wstring b = ReferenceFoldCaseCopy(a);
        if (test & 1) b[rng() % b.size()] = static_cast<wchar_t>(rng() & 0xFFFF);
        if (test & 2) b.resize(1 + rng() % b.size());
        CheckNoCaseTextPair(a, b);
        // Представления не требуют терминатора и могут делить общий буфер.
        const std::wstring_view view(a);
        CheckNoCaseTextPair(view.substr(1, view.size() - 2), view.substr(1));
    }
}

void TestUnicodeAppPaths() {
    const struct { const wchar_t* rulePath; const wchar_t* queryPath; bool equal; } cases[] = {
        { kAppPath, L"c:\\APPS\\EXAMPLE.EXE", true },
        { L"C:\\Программы\\Пример.exe", L"c:\\ПРОГРАММЫ\\ПРИМЕР.EXE", true },
        { L"C:\\Ёж\\ёж.exe", L"c:\\ЁЖ\\ЁЖ.EXE", true },
        { L"C:\\Café\\Ångström.exe", L"c:\\CAFÉ\\ÅNGSTRÖM.EXE", true },
        { L"C:\\αβγ\\δ.exe", L"c:\\ΑΒΓ\\Δ.EXE", true },
        { L"C:\\աբգ\\դ.exe", L"c:\\ԱԲԳ\\Դ.EXE", true },
        { L"C:\\ａｐｐｓ\\ｅｘａｍｐｌｅ.exe", L"c:\\ＡＰＰＳ\\ＥＸＡＭＰＬＥ.EXE", true },
        { L"C:\\Программы\\Пример.exe", L"C:\\ПРОГРАММЫ\\ДРУГОЙ.EXE", false },
        { L"C:\\Café\\App.exe", L"C:\\CAFE\\APP.EXE", false },
        { L"C:\\ı\\App.exe", L"C:\\I\\APP.EXE", false },
        { L"C:\\ς\\App.exe", L"C:\\Σ\\APP.EXE", false },
        // Ordinal-сравнение Windows не сворачивает регистр суррогатных пар.
        { L"C:\\\U00010428\\App.exe", L"C:\\\U00010400\\APP.EXE", false },
    };

    for (const auto& test : cases) {
        Check((CompareStringOrdinal(test.rulePath, -1, test.queryPath, -1, TRUE) ==
                   CSTR_EQUAL) == test.equal,
              "неверный эталон безрегистрового сравнения путей Windows");
        const std::wstring ruleFolded = FoldCaseCopy(test.rulePath);
        const std::wstring queryFolded = FoldCaseCopy(test.queryPath);
        const uint64_t queryHash = HashTextNoCase(test.queryPath);
        Check((ruleFolded == queryFolded) == test.equal,
              "свёртка пути не соответствует ordinal-сравнению Windows");
        Check(HashTextNoCase(test.rulePath) == HashFoldedText(ruleFolded) &&
                  queryHash == HashFoldedText(queryFolded),
              "свёртка и безрегистровый хэш пути расходятся");
        if (test.equal)
            Check(HashTextNoCase(test.rulePath) == queryHash,
                  "одинаковые без учёта регистра пути получили разные хэши");

        for (RuleAction expected : { RuleAction::Allow, RuleAction::Block }) {
            RuleStore store;
            Rule rule = OutboundRule(Proto::Tcp, 0);
            rule.appPath = test.rulePath;
            rule.action = expected;
            store.Add(rule);
            MatchQuery query = Query(Proto::Tcp, Dir::Out);
            query.appPath = test.rulePath;
            RuleAction action = RuleAction::Allow;
            Check(Matches(store, query, &action) && action == expected,
                  "правило не совпало с исходным Unicode-путём");

            query.appPath = test.queryPath;
            Check(Matches(store, query, &action) == test.equal &&
                      (!test.equal || action == expected),
                  "обычный поиск правила неверно сравнил Unicode-путь");
            PrepareMatchAppPath(query, queryFolded, queryHash);
            Check(Matches(store, query, &action) == test.equal &&
                      (!test.equal || action == expected),
                  "подготовленный поиск правила неверно сравнил Unicode-путь");
            Check(store.ForApp(test.queryPath).size() == (test.equal ? 1u : 0u),
                  "ForApp неверно сравнил Unicode-путь");

            Rule second = rule;
            second.id = 0;
            second.appPath = test.queryPath;
            store.Add(second);
            const auto apps = store.Apps();
            const size_t appCount = static_cast<size_t>(std::count_if(
                apps.begin(), apps.end(), [](const AppEntry& app) {
                    return !app.global && !app.postapp && !app.interfaceGroup;
                }));
            Check(appCount == (test.equal ? 1u : 2u) &&
                      store.ForApp(test.queryPath).size() == (test.equal ? 2u : 1u),
                  "правила Unicode-путей объединены в неверные группы");
            store.RemoveApp(test.queryPath);
            Check(store.Count() == (test.equal ? 0u : 1u),
                  "RemoveApp неверно сравнил Unicode-путь");
        }
    }
}

void TestUnicodeServiceNames() {
    const struct { const wchar_t* name; const wchar_t* variant; bool equal; } cases[] = {
        { L"FirewallX_TestService", L"FIREWALLX_TESTSERVICE", true },
        { L"FirewallX_ТестоваяСлужба", L"FIREWALLX_ТЕСТОВАЯСЛУЖБА", true },
        { L"FirewallX_Ёж", L"FIREWALLX_ЁЖ", true },
        { L"FirewallX_Café_Ångström", L"FIREWALLX_CAFÉ_ÅNGSTRÖM", true },
        { L"FirewallX_αβγ", L"FIREWALLX_ΑΒΓ", true },
        { L"FirewallX_աբգ", L"FIREWALLX_ԱԲԳ", true },
        { L"FirewallX_ａｂｃ", L"FIREWALLX_ＡＢＣ", true },
        { L"FirewallX_Служба", L"FIREWALLX_ДРУГАЯСЛУЖБА", false },
        { L"FirewallX_Café", L"FIREWALLX_CAFE", false },
        { L"FirewallX_ı", L"FIREWALLX_I", false },
        { L"FirewallX_ς", L"FIREWALLX_Σ", false },
        { L"FirewallX_\U00010428", L"FIREWALLX_\U00010400", false },
    };

    RuleDb database;
    std::wstring error;
    Check(database.Open(L":memory:", error), "не удалось открыть тестовую базу служб");
    for (const auto& test : cases) {
        Check((CompareStringOrdinal(test.name, -1, test.variant, -1, TRUE) ==
                   CSTR_EQUAL) == test.equal,
              "неверный эталон безрегистрового сравнения имён служб Windows");
        Check(ServiceInfo::SameName(test.name, test.variant) == test.equal &&
                  ServiceInfo::SameName(test.variant, test.name) == test.equal &&
                  ServiceInfo::SameName(test.name, test.name),
              "сравнение имён служб не соответствует ordinal-сравнению Windows");
        const ServiceItem condition{ test.name, L"" };
        Check(condition.Matches(test.name) &&
                  condition.Matches(test.variant) == test.equal,
              "условие службы неверно сравнило Unicode-имя");
        Check((FoldCaseCopy(test.name) == FoldCaseCopy(test.variant)) == test.equal,
              "ключ службы расходится с безрегистровым сравнением");

        const size_t expectedCount = test.equal ? 1u : 2u;
        std::vector<ServiceItem> parsed;
        Check(RuleDialogs::ParseServiceList(
                  std::wstring(test.name) + L", " + test.variant, parsed, error) &&
                  parsed.size() == expectedCount && parsed[0].name == test.name &&
                  (test.equal || parsed[1].name == test.variant),
              "разбор списка служб неверно обработал Unicode-дубликаты");

        Rule rule = OutboundRule(Proto::Tcp, 0);
        rule.id = 1;
        rule.conds |= CondService;
        rule.services = { {test.name, L""}, {test.variant, L""} };
        Check(database.SaveAll({rule}, error), "не удалось сохранить Unicode-имена служб");
        std::vector<Rule> loaded;
        uint64_t maxId = 0;
        Check(database.Load(loaded, maxId, error) && loaded.size() == 1 &&
                  maxId == rule.id && loaded[0].services.size() == expectedCount &&
                  loaded[0].services[0].name == test.name &&
                  (test.equal || loaded[0].services[1].name == test.variant),
              "загрузка базы неверно обработала Unicode-дубликаты служб");
    }
}

void TestServiceWildcards() {
    const struct { const wchar_t* pattern; const wchar_t* name; bool match; } cases[] = {
        {L"WpnUserService_*", L"WpnUserService_4f11e", true},
        {L"WpnUserService_*", L"WPNUSERSERVICE_a123", true},
        {L"WpnUserService_*", L"WpnUserService_", true},
        {L"WpnUserService_*", L"WpnUserService", false},
        {L"WpnUserService_*", L"OtherWpnUserService_4f11e", false},
        {L"WpnUserService_4f11e", L"WpnUserService_4f11e", true},
        {L"WpnUserService_4f11e", L"WpnUserService_a123", false},
        {L"*Service", L"UserService", true},
        {L"*Service", L"UserServiceExtra", false},
        {L"Pre*Post", L"PrefixPost", true},
        {L"Pre*Post", L"PrePost", true},
        {L"Pre*Post", L"PrePostExtra", false},
        {L"a*b*c", L"AXbYYC", true},
        {L"a*b*c", L"acb", false},
        {L"a**b", L"ab", true},
        {L"*", L"AnyService", true},
        {L"*", L"", true},
        {L"", L"", true},
        {L"", L"Service", false},
        {L"Пример_*_Ёж", L"ПРИМЕР_12_ёж", true},
        {L"Пример_*_Ёж", L"ПРИМЕР_12_еж", false},
        {L"a?b", L"axb", false},
    };
    for (const auto& test : cases) {
        Check(ServiceNameMatches(test.pattern, test.name) == test.match &&
                  ServiceItem{test.pattern, L""}.Matches(test.name) == test.match,
              "wildcard service name matched incorrectly");
    }
    std::mt19937 rng(0x571CE);
    for (int test = 0; test < 5000; ++test) {
        std::wstring pattern(rng() % 20, L'a');
        std::wstring name(rng() % 20, L'a');
        for (wchar_t& c : pattern) c = L"ab*"[rng() % 3];
        for (wchar_t& c : name) c = L"aAbB"[rng() % 4];
        std::vector<bool> row(name.size() + 1);
        row[0] = true;
        for (wchar_t c : pattern) {
            std::vector<bool> next(name.size() + 1);
            if (c == L'*') next[0] = row[0];
            for (size_t i = 1; i <= name.size(); ++i)
                next[i] = c == L'*' ? (row[i] || next[i - 1])
                                     : (row[i - 1] && FoldCaseChar(c) == FoldCaseChar(name[i - 1]));
            row = std::move(next);
        }
        Check(ServiceNameMatches(pattern, name) == row[name.size()],
              "wildcard service matcher disagrees with reference");
    }

    std::wstring error;
    std::vector<ServiceItem> parsed;
    Check(RuleDialogs::ParseServiceList(L"WpnUserService_*, wpnuserservice_*, Dnscache", parsed, error) &&
              parsed.size() == 2 && parsed[0].name == L"WpnUserService_*",
          "service dialog did not preserve or deduplicate a wildcard");
    Rule rule = OutboundRule(Proto::Tcp, CondRemotePort);
    rule.id = 1;
    rule.conds |= CondService;
    rule.services = parsed;
    RuleDb database;
    Check(database.Open(L":memory:", error) && database.SaveAll({rule}, error),
          "could not save wildcard service rule");
    std::vector<Rule> loaded;
    uint64_t maxId = 0;
    Check(database.Load(loaded, maxId, error) && loaded.size() == 1 &&
              loaded[0].services.size() == 2 && loaded[0].services[0].name == L"WpnUserService_*" &&
              loaded[0].services[0].Matches(L"WpnUserService_new"),
          "wildcard service rule was not restored from the database");
}

void TestTcpReverseFlow() {
    RuleStore store;
    Rule rule = OutboundRule(Proto::Tcp, kEndpointConds);
    rule.action = RuleAction::Allow;
    store.Add(rule);

    RuleAction action = RuleAction::Block;
    Check(Matches(store, Query(Proto::Tcp, Dir::Out), &action),
          "исходящий TCP не совпал с правилом");
    Check(action == RuleAction::Allow,
          "для исходящего TCP возвращено неверное действие");
    Check(Matches(store, Query(Proto::Tcp, Dir::In), &action),
          "обратный входящий TCP не совпал с исходящим правилом");
    Check(action == RuleAction::Allow,
          "для обратного TCP возвращено неверное действие");
    Check(!Matches(store, Query(Proto::Tcp, Dir::In, kLocal, kRemote,
                                static_cast<uint16_t>(kLocalPort + 1),
                                kRemotePort)),
          "правило TCP совпало с неправильным локальным портом");
}

void TestUdpReverseFlow() {
    RuleStore store;
    Rule rule = OutboundRule(Proto::Udp, kEndpointConds);
    rule.action = RuleAction::Allow;
    store.Add(rule);

    RuleAction action = RuleAction::Block;
    Check(Matches(store, Query(Proto::Udp, Dir::In), &action) &&
              action == RuleAction::Allow,
          "обратный входящий UDP не разрешён исходящим правилом");
}

void TestReverseFlowWithOmittedFields() {
    struct Case {
        uint32_t conditions;
        const char* message;
    };
    const Case cases[] = {
        { CondRemoteAddr, "не сработало правило только с remote_ip" },
        { CondLocalAddr,  "не сработало правило только с local_ip" },
        { CondRemotePort, "не сработало правило только с remote_port" },
        { CondLocalPort,  "не сработало правило только с local_port" },
        { CondRemoteAddr | CondLocalPort,
          "не сработало правило с одним адресом и одним портом" },
        { CondLocalAddr | CondRemotePort,
          "не сработало правило с другим адресом и одним портом" },
    };

    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (Dir direction : { Dir::Out, Dir::In })
    for (const Case& test : cases) {
        RuleStore store;
        Rule rule = OutboundRule(proto, test.conditions);
        rule.action = RuleAction::Allow;
        rule.dir = direction;
        store.Add(rule);
        Check(Matches(store, Query(proto, Dir::Out)), test.message);
        Check(Matches(store, Query(proto, Dir::In)), test.message);
    }
}

void TestEmptyListsRemainWildcards() {
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (RuleAction action : { RuleAction::Allow, RuleAction::Block })
    for (Dir direction : { Dir::Out, Dir::In }) {
        RuleStore store;
        Rule rule = OutboundRule(proto, kEndpointConds);
        rule.action = action;
        rule.dir = direction;
        rule.remoteAddrs.clear();
        rule.localAddrs.clear();
        rule.remotePorts.clear();
        rule.localPorts.clear();
        store.Add(rule);

        const auto query = [&](Dir dir) {
            return Query(proto, dir, V4(203, 0, 113, 1), V4(203, 0, 113, 2),
                         50000, 50001);
        };
        Check(Matches(store, query(direction)),
              "пустые списки условий перестали означать любые адреса и порты");
        Check(!Matches(store, query(direction == Dir::Out ? Dir::In : Dir::Out)),
              "пустые списки условий ошибочно отменили проверку направления");
    }
}

void TestOnlyTcpAndUdpAreReversed() {
    for (Proto proto : { Proto::Icmp, Proto::IcmpV6, ProtoFromNumber(0),
                         ProtoFromNumber(144), ProtoFromNumber(255) })
    for (Dir direction : { Dir::Out, Dir::In }) {
        RuleStore store;
        Rule rule = OutboundRule(proto, kEndpointConds);
        rule.action = RuleAction::Allow;
        rule.dir = direction;
        store.Add(rule);

        Check(Matches(store, Query(proto, direction)),
              "исходное разрешающее правило не совпало");
        Check(!Matches(store, Query(proto, direction == Dir::Out ? Dir::In : Dir::Out)),
              "правило не-TCP/UDP ошибочно стало обратным");
    }
}

void TestAnyProtocolRuleIsNotReversed() {
    for (Dir direction : { Dir::Out, Dir::In }) {
        RuleStore store;
        Rule rule = OutboundRule(Proto::Tcp, kEndpointConds);
        rule.action = RuleAction::Allow;
        rule.dir = direction;
        rule.conds &= ~CondProto;
        store.Add(rule);

        for (Proto proto : { Proto::Tcp, Proto::Udp, Proto::Icmp }) {
            Check(Matches(store, Query(proto, direction)),
                  "правило любого протокола не совпало в заданном направлении");
            Check(!Matches(store, Query(proto, direction == Dir::Out ? Dir::In : Dir::Out)),
                  "правило любого протокола ошибочно стало обратным");
        }
    }
}

void TestBlockRulesAreNotReversed() {
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (Dir direction : { Dir::Out, Dir::In })
    for (uint32_t conditions : { 0u, kEndpointConds }) {
        RuleStore store;
        Rule rule = OutboundRule(proto, conditions);
        rule.dir = direction;
        store.Add(rule);

        RuleAction action = RuleAction::Allow;
        Check(Matches(store, Query(proto, direction), &action) &&
                  action == RuleAction::Block,
              "блокирующее правило не сработало в заданном направлении");
        Check(!Matches(store, Query(proto, direction == Dir::Out ? Dir::In : Dir::Out)),
              "блокирующее правило ошибочно применено обратно");
    }
}

IpAddr V6(uint8_t last) {
    uint8_t bytes[16]{};
    bytes[0] = 0xfd;
    bytes[15] = last;
    return IpAddr::Raw6(bytes);
}

void TestPortAddressMatrix() {
    size_t queries = 0;
    for (Proto proto : { Proto::Tcp, Proto::Udp })
    for (bool ipv6 : { false, true })
    for (RuleAction ruleAction : { RuleAction::Allow, RuleAction::Block })
    for (Dir ruleDirection : { Dir::Out, Dir::In })
    for (unsigned mask = 0; mask < 16; ++mask)
    for (unsigned lists = 0; lists < 3; ++lists) {
        const uint32_t conditions =
            ((mask & 1) ? CondRemoteAddr : 0u) |
            ((mask & 2) ? CondRemotePort : 0u) |
            ((mask & 4) ? CondLocalAddr : 0u) |
            ((mask & 8) ? CondLocalPort : 0u);
        const IpAddr local = ipv6 ? V6(10) : kLocal;
        const IpAddr remote = ipv6 ? V6(20) : kRemote;
        const int prefix = lists == 2 ? (ipv6 ? 64 : 24) : -1;
        Rule rule = OutboundRule(proto, conditions);
        rule.action = ruleAction;
        rule.dir = ruleDirection;
        rule.remoteAddrs = { AddrItem{ remote, prefix } };
        rule.localAddrs = { AddrItem{ local, prefix } };
        rule.remotePorts = { PortItem{ kRemotePort,
            static_cast<uint16_t>(kRemotePort + (lists == 2 ? 2 : 0)) } };
        rule.localPorts = { PortItem{ kLocalPort,
            static_cast<uint16_t>(kLocalPort + (lists == 2 ? 2 : 0)) } };
        if (lists == 0) {
            rule.remoteAddrs.clear();
            rule.localAddrs.clear();
            rule.remotePorts.clear();
            rule.localPorts.clear();
        }
        RuleStore store;
        store.Add(rule);

        const uint16_t localPorts[] = {
            0, kLocalPort - 1, kLocalPort, kLocalPort + 1,
            kLocalPort + 2, kLocalPort + 3, 65535
        };
        const uint16_t remotePorts[] = {
            0, kRemotePort - 1, kRemotePort, kRemotePort + 1,
            kRemotePort + 2, kRemotePort + 3, 65535
        };
        for (Dir direction : { Dir::Unknown, Dir::Out, Dir::In })
        for (unsigned localVariant = 0; localVariant < 3; ++localVariant)
        for (unsigned remoteVariant = 0; remoteVariant < 3; ++remoteVariant)
        for (uint16_t localPort : localPorts)
        for (uint16_t remotePort : remotePorts) {
            IpAddr queryLocal = local;
            IpAddr queryRemote = remote;
            // Соседний адрес остаётся в подсети, смена первого байта — нет.
            if (localVariant)
                queryLocal.b[localVariant == 1 ? queryLocal.len() - 1 : 0] ^= 1;
            if (remoteVariant)
                queryRemote.b[remoteVariant == 1 ? queryRemote.len() - 1 : 0] ^= 1;
            const auto addressMatches = [&](uint32_t condition, unsigned variant) {
                return !(conditions & condition) || lists == 0 || variant == 0 ||
                       (lists == 2 && variant == 1);
            };
            const auto portMatches = [&](uint32_t condition, uint16_t port,
                                         uint16_t expected) {
                return !(conditions & condition) || lists == 0 ||
                       (port != 0 && port >= expected &&
                        port <= expected + (lists == 2 ? 2 : 0));
            };
            const bool ignoreDirection = ruleAction == RuleAction::Allow &&
                                         conditions != 0 && lists != 0;
            const bool expected =
                (direction == Dir::Unknown || direction == ruleDirection || ignoreDirection) &&
                addressMatches(CondLocalAddr, localVariant) &&
                addressMatches(CondRemoteAddr, remoteVariant) &&
                portMatches(CondLocalPort, localPort, kLocalPort) &&
                portMatches(CondRemotePort, remotePort, kRemotePort);
            RuleAction action = RuleAction::Allow;
            const bool matched = Matches(store, Query(
                proto, direction, queryLocal, queryRemote,
                localPort, remotePort), &action);
            Check(matched == expected,
                  "комбинация адресов и портов дала неверное совпадение");
            if (matched)
                Check(action == ruleAction,
                      "матрица адресов и портов вернула неверное действие");
            ++queries;
        }
        Check(!Matches(store, Query(proto == Proto::Tcp ? Proto::Udp : Proto::Tcp,
                                    Dir::Out, local, remote)),
              "правило с адресами и портами совпало с другим протоколом");
        ++queries;
    }
    std::cout << "Port/address matrix passed: " << queries << " queries\n";
}

void TestEndpointRulePriority() {
    RuleStore store;
    Rule specific = OutboundRule(Proto::Tcp, kEndpointConds);
    const uint64_t specificId = store.Add(specific);
    Rule fallback = OutboundRule(Proto::Tcp, 0);
    fallback.action = RuleAction::Allow;
    fallback.dir = Dir::In;
    const uint64_t fallbackId = store.Add(fallback);

    const auto expect = [&](const MatchQuery& query, uint64_t id, RuleAction action) {
        RuleMatchInfo info;
        Check(store.MatchInfo(query, info, false),
              "не найдено правило после проверки адресов и портов");
        Check(info.id == id && info.action == action,
              "изменился приоритет правил с адресами и портами");
    };
    expect(Query(Proto::Tcp, Dir::Out), specificId, RuleAction::Block);
    expect(Query(Proto::Tcp, Dir::In), fallbackId, RuleAction::Allow);
    expect(Query(Proto::Tcp, Dir::Unknown), specificId, RuleAction::Block);
    expect(Query(Proto::Tcp, Dir::In, kLocal, kRemote, kLocalPort, 80),
           fallbackId, RuleAction::Allow);
    expect(Query(Proto::Tcp, Dir::In, V4(203, 0, 113, 1), kRemote),
           fallbackId, RuleAction::Allow);

    Rule global = specific;
    global.scope = RuleScope::Global;
    global.action = RuleAction::Allow;
    const uint64_t globalId = store.Add(global);
    expect(Query(Proto::Tcp, Dir::In), globalId, RuleAction::Allow);
    expect(Query(Proto::Tcp, Dir::In, kLocal, kRemote, kLocalPort, 80),
           fallbackId, RuleAction::Allow);
}

void CheckRuleResult(RuleStore& store, const MatchQuery& query,
                     uint64_t expectedId, RuleAction expectedAction,
                     RuleScope expectedScope) {
    const bool expected = expectedId != 0;
    RuleAction action = RuleAction::Allow;
    uint64_t version = 0;
    Check(store.MatchVerdict(query, action, version) == expected,
          "предварительный отбор вернул неверное совпадение для вердикта");
    Check(version == store.version(),
          "вердикт получил неверную версию индекса правил");
    if (expected)
        Check(action == expectedAction,
              "предварительный отбор вернул неверное действие");

    RuleMatchInfo info;
    Check(store.MatchInfo(query, info) == expected,
          "предварительный отбор вернул неверное совпадение для списка");
    Rule rule;
    Check(store.Match(query, rule) == expected,
          "предварительный отбор вернул неверное полное правило");
    if (expected) {
        Check(info.id == expectedId && rule.id == expectedId,
              "предварительный отбор изменил приоритет правил");
        Check(info.action == expectedAction && rule.action == expectedAction &&
                  info.scope == expectedScope && rule.scope == expectedScope &&
                  info.name == rule.name,
              "результаты трёх способов сопоставления различаются");
    }
}

void TestPostAppScopeAndPriority() {
    RuleStore store;
    Rule postApp = OutboundRule(Proto::Tcp, 0);
    postApp.scope = RuleScope::PostApp;
    postApp.conds = CondNone;
    const uint64_t postAppId = store.Add(postApp);
    Rule app = OutboundRule(Proto::Tcp, 0);
    app.conds = CondProto;
    app.action = RuleAction::Allow;
    const uint64_t appId = store.Add(app);
    Rule global = OutboundRule(Proto::Udp, 0);
    global.scope = RuleScope::Global;
    global.conds = CondProto;
    global.action = RuleAction::Allow;
    const uint64_t globalId = store.Add(global);

    // Область PostApp не зависит от пути, даже если правило собрано вне store.
    postApp.appPath = L"C:\\Apps\\Ignored.exe";
    size_t queries = 0;
    for (unsigned number = 0; number < 256; ++number)
    for (Dir dir : { Dir::Unknown, Dir::In, Dir::Out })
    for (DWORD pid : { 0u, 4u, 1000u })
    for (std::wstring_view path : { std::wstring_view{}, std::wstring_view(kAppPath),
                                   std::wstring_view(L"C:\\Apps\\Other.exe") }) {
        MatchQuery query = Query(ProtoFromNumber(static_cast<uint8_t>(number)), dir);
        query.appPath = path;
        query.pid = pid;
        Check(RuleStore::MatchesRule(postApp, query),
              "PostApp зависит от PID, пути, протокола или направления");
        if (query.proto == Proto::Udp)
            CheckRuleResult(store, query, globalId, RuleAction::Allow, RuleScope::Global);
        else if (query.proto == Proto::Tcp && path == kAppPath)
            CheckRuleResult(store, query, appId, RuleAction::Allow, RuleScope::App);
        else
            CheckRuleResult(store, query, postAppId, RuleAction::Block, RuleScope::PostApp);
        ++queries;
    }
    std::cout << "PostApp scope and priority matrix passed: " << queries << " queries\n";
}

void TestPostAppPidFilter() {
    size_t queries = 0;
    for (RuleAction action : { RuleAction::Allow, RuleAction::Block }) {
        RuleStore store;
        Rule zero = OutboundRule(Proto::Tcp, 0);
        zero.scope = RuleScope::PostApp;
        zero.conds = CondPidZero;
        zero.action = action;
        const uint64_t zeroId = store.Add(zero);
        Rule any = zero;
        any.conds = CondNone;
        any.action = zero.blocks() ? RuleAction::Allow : RuleAction::Block;
        const uint64_t anyId = store.Add(any);

        // Даже у заготовки вне хранилища путь не ограничивает PostApp.
        zero.appPath = L"C:\\Apps\\Ignored.exe";
        for (unsigned number = 0; number < 256; ++number)
        for (Dir dir : { Dir::Unknown, Dir::In, Dir::Out })
        for (DWORD pid : { DWORD{0}, DWORD{4}, DWORD{1000} })
        for (std::wstring_view path : { std::wstring_view{}, std::wstring_view(kAppPath),
                                       std::wstring_view(L"C:\\Apps\\Other.exe") }) {
            MatchQuery query = Query(ProtoFromNumber(static_cast<uint8_t>(number)), dir);
            query.pid = pid;
            query.appPath = path;
            Check(RuleStore::MatchesRule(zero, query) == (pid == 0),
                  "фильтр PID 0 зависит от пути, протокола или направления");
            Check(RuleStore::MatchesRule(any, query), "любой PID ограничивает сопоставление");
            CheckRuleResult(store, query, pid == 0 ? zeroId : anyId,
                pid == 0 ? zero.action : any.action, RuleScope::PostApp);
            ++queries;
        }

        MatchQuery query = Query(Proto::Tcp, Dir::Out);
        query.pid = 0;
        Rule app = OutboundRule(Proto::Tcp, 0);
        app.conds = CondNone;
        const uint64_t appId = store.Add(app);
        CheckRuleResult(store, query, appId, app.action, RuleScope::App);
        Rule global = app;
        global.scope = RuleScope::Global;
        const uint64_t globalId = store.Add(global);
        CheckRuleResult(store, query, globalId, global.action, RuleScope::Global);
        store.Remove(globalId);
        store.Remove(appId);

        zero.conds = CondNone;
        Check(store.Update(zero), "не удалось выбрать любой PID");
        query.pid = 1000;
        CheckRuleResult(store, query, zeroId, action, RuleScope::PostApp);
        zero.conds = CondPidZero;
        Check(store.Update(zero), "не удалось вернуть PID 0");
        CheckRuleResult(store, query, anyId, any.action, RuleScope::PostApp);
        query.pid = 0;
        Check(store.SetEnabled(zeroId, false), "не удалось выключить фильтр PID");
        CheckRuleResult(store, query, anyId, any.action, RuleScope::PostApp);
        Check(store.SetEnabled(zeroId, true) && store.MovePriority(anyId, -1),
              "не удалось изменить приоритет фильтра PID");
        CheckRuleResult(store, query, anyId, any.action, RuleScope::PostApp);
    }

    for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp }) {
        Rule rule = OutboundRule(Proto::Tcp, 0);
        rule.scope = scope;
        rule.conds = CondPidZero;
        Check(RuleStore::MatchesRule(rule, Query(Proto::Udp, Dir::In)) == !rule.isPostApp(),
              "фильтр PID влияет на другую группу правил");
        Check(((EffectiveRuleConds(rule) & CondPidZero) != 0) == rule.isPostApp(),
              "эффективная маска содержит PID вне PostApp");
        NormalizeRuleConds(rule);
        Check(((rule.conds & CondPidZero) != 0) == rule.isPostApp(),
              "нормализация не ограничила PID группой PostApp");
        rule.SetProto(ProtoFromNumber(144), false);
        Check(((rule.conds & CondPidZero) != 0) == rule.isPostApp(),
              "смена протокола сняла фильтр PID в PostApp");
    }
    std::cout << "PostApp PID matrix passed: " << queries << " queries\n";
}

void TestPostAppPidTextAndLinks() {
    Rule rule;
    rule.scope = RuleScope::PostApp;
    rule.conds = CondNone;
    const uint32_t before = rule.conds;
    const std::wstring anyName = rule.BuildAutoName();
    Check(rule.PidText() == LoadStringRes(IDS_RULE_ANY) &&
              RuleExplainMarkup(rule).find(L"id=\"pid\"") != std::wstring::npos,
          "выбор любого PID не отображается в PostApp");
    Check(RuleDialogs::FollowLink(nullptr, nullptr, rule, RuleLink::kPid) &&
              rule.conds == (before | CondPidZero) &&
              rule.PidText() == LoadStringRes(IDS_RULE_PID_ZERO) &&
              rule.BuildAutoName() != anyName &&
              RuleExplainMarkup(rule).find(LoadStringRes(IDS_HINT_CLICK_PID_ANY)) != std::wstring::npos,
          "ссылка PID не включила фильтр или не обновила описание");
    Check(RuleDialogs::FollowLink(nullptr, nullptr, rule, RuleLink::kPid) &&
              rule.conds == before && rule.BuildAutoName() == anyName,
          "любой PID оставил отдельный фильтр");
    for (RuleScope scope : { RuleScope::Global, RuleScope::App }) {
        rule.scope = scope;
        Check(!RuleDialogs::FollowLink(nullptr, nullptr, rule, RuleLink::kPid) &&
                  rule.conds == before &&
                  RuleExplainMarkup(rule).find(L"id=\"pid\"") == std::wstring::npos,
              "выбор PID доступен вне PostApp");
    }
}

void TestCandidateProtocolDirectionMatrix() {
    size_t queries = 0;
    for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp })
    for (unsigned number = 0; number < 256; ++number)
    for (unsigned mask = 0; mask < 4; ++mask)
    for (Dir ruleDirection : { Dir::Unknown, Dir::In, Dir::Out })
    for (bool enabled : { false, true }) {
        RuleStore store;
        Rule specific = OutboundRule(ProtoFromNumber(static_cast<uint8_t>(number)), 0);
        specific.scope = scope;
        specific.conds = ((mask & 1) ? CondProto : 0u) |
                         ((mask & 2) ? CondDirection : 0u);
        specific.dir = ruleDirection;
        specific.enabled = enabled;
        const uint64_t specificId = store.Add(specific);
        Rule fallback = specific;
        fallback.name = L"fallback";
        fallback.conds = CondNone;
        fallback.enabled = true;
        fallback.action = RuleAction::Allow;
        const uint64_t fallbackId = store.Add(fallback);

        const Proto queryProtos[] = {
            ProtoFromNumber(0), Proto::Icmp, Proto::Tcp, Proto::Udp,
            Proto::IcmpV6, ProtoFromNumber(144), ProtoFromNumber(255), specific.proto
        };
        for (Proto proto : queryProtos)
        for (Dir direction : { Dir::Unknown, Dir::In, Dir::Out }) {
            MatchQuery query = Query(proto, direction);
            // Эталон не использует функции предварительного отбора.
            const bool protocolMatches = !(mask & 1) || proto == specific.proto;
            const bool directionMatches = !(mask & 2) || direction == Dir::Unknown ||
                                          ruleDirection == direction;
            const bool specificMatches = enabled && protocolMatches && directionMatches;
            CheckRuleResult(store, query,
                specificMatches ? specificId : fallbackId,
                specificMatches ? RuleAction::Block : RuleAction::Allow, scope);
            ++queries;
        }
    }
    std::cout << "Candidate protocol/direction matrix passed: "
              << queries << " queries\n";
}

void TestCandidateIndexUpdates() {
    RuleStore store;
    Rule rule = OutboundRule(Proto::Tcp, 0);
    const uint64_t ruleId = store.Add(rule);
    Rule fallback = rule;
    fallback.conds = CondNone;
    fallback.action = RuleAction::Allow;
    const uint64_t fallbackId = store.Add(fallback);
    const auto expect = [&](Proto proto, Dir direction, bool specific) {
        CheckRuleResult(store, Query(proto, direction),
            specific ? ruleId : fallbackId,
            specific ? RuleAction::Block : RuleAction::Allow, RuleScope::App);
    };
    expect(Proto::Tcp, Dir::Out, true);
    expect(Proto::Tcp, Dir::In, false);
    expect(Proto::Icmp, Dir::In, false);

    rule.proto = Proto::Icmp;
    rule.dir = Dir::In;
    Check(store.Update(rule), "не удалось обновить протокол и направление правила");
    expect(Proto::Tcp, Dir::In, false);
    expect(Proto::Icmp, Dir::In, true);
    expect(Proto::Icmp, Dir::Out, false);
    expect(Proto::Icmp, Dir::Unknown, true);

    rule.conds &= ~CondProto;
    Check(store.Update(rule), "не удалось снять условие протокола");
    expect(ProtoFromNumber(255), Dir::In, true);
    expect(Proto::Udp, Dir::Out, false);
    rule.conds &= ~CondDirection;
    Check(store.Update(rule), "не удалось снять условие направления");
    expect(Proto::Udp, Dir::Out, true);

    Check(store.SetEnabled(ruleId, false), "не удалось выключить правило");
    expect(Proto::Tcp, Dir::Out, false);
    Check(store.SetEnabled(ruleId, true), "не удалось включить правило");
    expect(Proto::Tcp, Dir::Out, true);
    Check(store.MovePriority(fallbackId, -1), "не удалось изменить приоритет правила");
    expect(Proto::Tcp, Dir::Out, false);
    Check(store.Remove(fallbackId), "не удалось удалить резервное правило");
    expect(Proto::Tcp, Dir::Out, true);
    Check(store.Remove(ruleId), "не удалось удалить основное правило");
    CheckRuleResult(store, Query(Proto::Tcp, Dir::Out), 0,
                    RuleAction::Allow, RuleScope::App);
}

void TestNumericLookupHashes() {
    std::array<size_t, 4096> buckets{};
    std::unordered_map<uint64_t, uint64_t, NumericIdHash> values;
    for (uint64_t i = 0; i < 4096; ++i) {
        for (uint64_t high : {uint64_t{0}, uint64_t{1} << 32, uint64_t{0xffff} << 48}) {
            const uint64_t key = high | (i * 4);
            const size_t hash = NumericIdHash{}(key);
            ++buckets[hash & (buckets.size() - 1)];
            values.emplace(key, key ^ 0x55aa55aa55aa55aaull);
            Check(hash == NumericIdHash{}(key), "хеш ID зависит от состояния");
            if constexpr (sizeof(size_t) == sizeof(uint64_t))
                Check(PreparedHash64{}(key) == key, "готовый хеш повторно преобразуется");
        }
    }
    Check(values.size() == 4096 * 3, "хеширование смешало разные старшие биты ID");
    for (const auto& [key, value] : values)
        Check(values.at(key) == (key ^ 0x55aa55aa55aa55aaull) && value == values.at(key),
              "числовой индекс потерял ключ при коллизии");
    const size_t used = static_cast<size_t>(std::count_if(
        buckets.begin(), buckets.end(), [](size_t count) { return count != 0; }));
    Check(used > buckets.size() * 3 / 4 &&
              *std::max_element(buckets.begin(), buckets.end()) < 20,
          "PID, кратные четырём, плохо распределены по корзинам");

    RuleStore store;
    Rule rule = OutboundRule(Proto::Tcp, 0);
    store.Add(rule);
    const std::wstring folded = FoldCaseCopy(rule.appPath);
    const std::wstring other = L"C:\\Apps\\Other.exe";
    const std::wstring foldedOther = FoldCaseCopy(other);
    auto query = Query(Proto::Tcp, Dir::Out);
    PrepareMatchAppPath(query, folded, HashFoldedText(folded));
    Check(Matches(store, query), "индекс готового хеша потерял исходный путь");
    query.appPath = other;
    PrepareMatchAppPath(query, foldedOther, HashFoldedText(folded));
    Check(!Matches(store, query), "коллизия готового хеша подменила путь приложения");
}

void TestSharedRuleNames() {
    for (RuleScope scope : {RuleScope::App, RuleScope::Global,
                            RuleScope::PostApp, RuleScope::Interface}) {
        RuleNameRef retained;
        const std::wstring initial = L"Исходное имя " + std::wstring(128, L'я');
        const std::wstring renamed = L"Изменённое имя " + std::wstring(128, L'ю');
        {
            RuleStore store;
            Rule rule = OutboundRule(Proto::Tcp, 0);
            rule.scope = scope;
            if (scope == RuleScope::Interface) rule.appPath = TestInterface().name;
            rule.name = initial;
            const uint64_t id = store.Add(rule);
            MatchQuery query = Query(Proto::Tcp, Dir::Out);
            query.source = scope == RuleScope::Interface ? TrafficSource::Ndis : TrafficSource::Host;
            if (scope == RuleScope::Interface) query.interfaceIndex = TestInterface().number;
            const auto match = [&] {
                RuleNameRef name;
                RuleAction action = RuleAction::Allow;
                uint64_t version = 0;
                Check(store.MatchVerdict(query, action, version, &name) && name,
                      "не получена готовая ссылка на имя правила");
                RuleMatchInfo info;
                Check(store.MatchInfo(query, info) && *name == info.name &&
                          action == info.action && version == store.version(),
                      "ссылка на имя не соответствует совпавшему правилу или версии");
                return name;
            };
            const RuleNameRef original = match();
            Check(*original == initial && match() == original,
                  "повторное совпадение создаёт новый объект имени");

            Rule other = rule;
            other.name = L"другое правило";
            other.proto = Proto::Udp;
            const uint64_t otherId = store.Add(other);
            Check(match() == original, "рост индекса пересоздал неизменившееся имя");
            Check(store.MovePriority(id, 1) && match() == original,
                  "сортировка индекса потеряла прежнюю ссылку на имя");
            Check(store.Remove(otherId) && match() == original,
                  "сокращение индекса пересоздало неизменившееся имя");
            rule.action = RuleAction::Allow;
            Check(store.Update(rule) && match() == original,
                  "изменение действия пересоздало неизменившееся имя");

            rule.name = renamed;
            Check(store.Update(rule), "не удалось изменить имя правила");
            retained = match();
            Check(retained != original && *retained == renamed && *original == initial,
                  "переименование изменило удерживаемое старое имя");
            Check(match() == retained, "переименованное правило не переиспользует ссылку");
            Check(store.SetEnabled(id, false), "не удалось выключить именованное правило");
            RuleNameRef missing;
            RuleAction action = RuleAction::Block;
            Check(!store.MatchVerdict(query, action, &missing) && !missing,
                  "выключенное правило вернуло имя");
            Check(store.SetEnabled(id, true) && *match() == renamed,
                  "повторное включение потеряло актуальное имя");
            Check(store.Remove(id) && *retained == renamed && *original == initial,
                  "удаление правила повредило удерживаемые имена");
            Check(!store.MatchVerdict(query, action, &missing),
                  "удалённое правило осталось в индексе имён");

            rule.autoName = true;
            rule.conds |= CondRemotePort;
            rule.remotePorts = {{443, 443}};
            store.Add(rule);
            const RuleNameRef automatic = match();
            const std::wstring previous = *automatic;
            rule.remotePorts = {{80, 80}};
            Check(store.Update(rule), "не удалось обновить правило с автоименем");
            query.remotePort = 80;
            Check(*match() != previous && *automatic == previous,
                  "изменение автоимени повредило ранее выданную ссылку");
            store.Clear();
            Check(*retained == renamed && *automatic == previous,
                  "очистка хранилища повредила внешние ссылки на имена");
        }
        Check(retained && *retained == renamed,
              "ссылка на имя не пережила уничтожение RuleStore");
    }
}

void TestSharedRuleNamesDatabase() {
    wchar_t directory[MAX_PATH]{}, filename[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) != 0 &&
              GetTempFileNameW(directory, L"fxn", 0, filename) != 0,
          "не удалось создать временный файл имён правил");
    const std::wstring path = filename;
    std::wstring error;
    RuleNameRef retained;
    {
        RuleStore writer;
        Check(writer.AttachDatabase(path, error), "не удалось подключить базу имён");
        Rule rule = OutboundRule(Proto::Tcp, 0);
        rule.name = L"сохранённое имя правила";
        writer.Add(rule);
        RuleStore attached, loaded;
        Check(attached.AttachDatabase(path, error) && loaded.LoadOnce(path, error),
              "не удалось загрузить готовые имена из базы");
        const auto query = Query(Proto::Tcp, Dir::Out);
        RuleAction action = RuleAction::Allow;
        RuleNameRef first, second;
        Check(attached.MatchVerdict(query, action, &first) && first && *first == rule.name &&
                  loaded.MatchVerdict(query, action, &second) && second && *second == rule.name,
              "загрузка базы не подготовила ссылки на имена");
        rule.name = L"новое имя из базы";
        Check(writer.Update(rule) && loaded.LoadOnce(path, error) &&
                  loaded.MatchVerdict(query, action, &retained) && retained &&
                  *retained == rule.name && *second == L"сохранённое имя правила",
              "повторная загрузка не заменила имя или изменила старую ссылку");
        Check(!loaded.LoadOnce(path + L"\\missing.db", error),
              "неудачная загрузка базы неожиданно удалась");
        RuleNameRef missing;
        Check(!loaded.MatchVerdict(query, action, &missing) && !missing &&
                  *retained == rule.name,
              "ошибка загрузки оставила прежний индекс имён или повредила ссылку");
    }
    Check(retained && *retained == L"новое имя из базы",
          "закрытие базы повредило удерживаемое имя");
    Check(DeleteFileW(filename) != FALSE, "не удалось удалить временную базу имён");
}

void TestCandidateRemotePortBounds() {
    const std::vector<std::vector<PortItem>> lists = {
        {}, {{0, 0}}, {{0, 65535}}, {{80, 90}},
        {{65000, 65535}, {20, 30}, {443, 443}},
        {{500, 100}, {0, 0}, {65535, 65535}}
    };
    for (RuleScope scope : {RuleScope::App, RuleScope::Global,
                            RuleScope::PostApp, RuleScope::Interface}) {
        RuleStore store;
        Rule rule = OutboundRule(Proto::Tcp, CondRemotePort);
        rule.scope = scope;
        if (scope == RuleScope::Interface) rule.appPath = TestInterface().name;
        const uint64_t id = store.Add(rule);
        Rule fallback = rule;
        fallback.name = L"port fallback";
        fallback.conds = CondNone;
        fallback.action = RuleAction::Allow;
        const uint64_t fallbackId = store.Add(fallback);
        MatchQuery query = Query(Proto::Tcp, Dir::Out);
        query.source = scope == RuleScope::Interface ? TrafficSource::Ndis : TrafficSource::Host;
            if (scope == RuleScope::Interface) query.interfaceIndex = TestInterface().number;
        for (const auto& ports : lists) {
            rule.remotePorts = ports;
            rule.conds |= CondRemotePort;
            // Размер массива кандидатов не меняется: старые границы должны исчезнуть.
            Check(store.Update(rule), "не удалось обновить границы порта кандидата");
            for (unsigned port = 0; port <= UINT16_MAX; ++port) {
                query.remotePort = static_cast<uint16_t>(port);
                bool expected = ports.empty();
                if (port)
                    for (const auto& item : ports)
                        expected |= port >= item.from && port <= item.to;
                CheckRuleResult(store, query, expected ? id : fallbackId,
                                expected ? RuleAction::Block : RuleAction::Allow, scope);
            }
            rule.conds &= ~CondRemotePort;
            Check(store.Update(rule), "не удалось снять условие удалённого порта");
            for (uint16_t port : {uint16_t{0}, uint16_t{1}, uint16_t{80}, uint16_t{65535}}) {
                query.remotePort = port;
                CheckRuleResult(store, query, id, RuleAction::Block, scope);
            }
        }
    }
}

void TestReverseFlowIndexUpdates() {
    RuleStore store;
    Rule rule = OutboundRule(Proto::Tcp, CondRemotePort);
    rule.action = RuleAction::Allow;
    const uint64_t ruleId = store.Add(rule);
    Rule fallback = rule;
    fallback.conds = CondNone;
    fallback.action = RuleAction::Block;
    const uint64_t fallbackId = store.Add(fallback);
    const auto expect = [&](Proto proto, Dir direction, bool specific) {
        CheckRuleResult(store, Query(proto, direction),
            specific ? ruleId : fallbackId,
            specific ? rule.action : RuleAction::Block, RuleScope::App);
    };
    const auto update = [&] {
        Check(store.Update(rule), "не удалось обновить условия обратного правила");
    };
    expect(Proto::Tcp, Dir::Out, true);
    expect(Proto::Tcp, Dir::In, true);

    rule.action = RuleAction::Block;
    update();
    expect(Proto::Tcp, Dir::Out, true);
    expect(Proto::Tcp, Dir::In, false);
    rule.action = RuleAction::Allow;
    update();
    expect(Proto::Tcp, Dir::In, true);

    rule.remotePorts.clear();
    update();
    expect(Proto::Tcp, Dir::Out, true);
    expect(Proto::Tcp, Dir::In, false);
    rule.remotePorts = { PortItem{ kRemotePort, kRemotePort } };
    rule.conds &= ~CondRemotePort;
    update();
    expect(Proto::Tcp, Dir::In, false);
    rule.conds |= CondRemotePort;
    update();
    expect(Proto::Tcp, Dir::In, true);
    CheckRuleResult(store, Query(Proto::Tcp, Dir::In, kLocal, kRemote, kLocalPort, 80),
                    fallbackId, RuleAction::Block, RuleScope::App);

    rule.dir = Dir::In;
    update();
    expect(Proto::Tcp, Dir::Out, true);
    rule.proto = Proto::Udp;
    update();
    expect(Proto::Tcp, Dir::Out, false);
    expect(Proto::Udp, Dir::Out, true);
    expect(Proto::Udp, Dir::In, true);

    rule.SetProto(Proto::Icmp);
    rule.conds |= CondLocalAddr;
    rule.localAddrs = { AddrItem{ kLocal, -1 } };
    update();
    expect(Proto::Icmp, Dir::In, true);
    expect(Proto::Icmp, Dir::Out, false);
    rule.conds &= ~CondProto;
    update();
    expect(Proto::Tcp, Dir::In, true);
    expect(Proto::Tcp, Dir::Out, false);
    rule.SetProto(Proto::Tcp);
    update();
    expect(Proto::Tcp, Dir::Out, true);

    Rule stored;
    Check(store.Get(ruleId, stored) && stored.conds == rule.conds &&
              stored.dir == Dir::In,
          "снятие направления в индексе изменило сохранённые условия правила");
    rule.conds &= ~CondLocalAddr;
    update();
    expect(Proto::Tcp, Dir::In, true);
    expect(Proto::Tcp, Dir::Out, false);
}

bool SameRule(const Rule& a, const Rule& b) {
    if (std::tie(a.id, a.name, a.autoName, a.scope, a.appPath, a.appName,
                 a.enabled, a.priority, a.conds, a.proto, a.dir, a.action) !=
        std::tie(b.id, b.name, b.autoName, b.scope, b.appPath, b.appName,
                 b.enabled, b.priority, b.conds, b.proto, b.dir, b.action))
        return false;
    const auto sameItems = [](const auto& left, const auto& right, auto equal) {
        return left.size() == right.size() &&
               std::equal(left.begin(), left.end(), right.begin(), equal);
    };
    const auto sameAddress = [](const AddrItem& x, const AddrItem& y) {
        return x.addr == y.addr && x.prefix == y.prefix && x.macro == y.macro;
    };
    const auto samePort = [](const PortItem& x, const PortItem& y) {
        return x.from == y.from && x.to == y.to;
    };
    return sameItems(a.remoteAddrs, b.remoteAddrs, sameAddress) &&
           sameItems(a.localAddrs, b.localAddrs, sameAddress) &&
           sameItems(a.remotePorts, b.remotePorts, samePort) &&
           sameItems(a.localPorts, b.localPorts, samePort) &&
           sameItems(a.icmpTypes, b.icmpTypes,
               [](const IcmpTypeItem& x, const IcmpTypeItem& y) {
                   return x.type == y.type && x.code == y.code;
               }) &&
           sameItems(a.services, b.services,
               [](const ServiceItem& x, const ServiceItem& y) {
                   return x.name == y.name && x.display == y.display;
               });
}

size_t CheckRuleIdLookups(RuleStore& store, std::vector<uint64_t>& ids) {
    const std::vector<Rule> all = store.All();
    for (const Rule& rule : all)
        if (std::find(ids.begin(), ids.end(), rule.id) == ids.end())
            ids.push_back(rule.id);
    const uint64_t version = store.version();
    for (uint64_t id : ids) {
        // Эталон повторяет линейный поиск, включая первое совпадение ID.
        const auto expected = std::find_if(all.begin(), all.end(),
            [id](const Rule& rule) { return rule.id == id; });
        const bool exists = id != 0 && expected != all.end();
        Rule unchanged = OutboundRule(Proto::Tcp, kEndpointConds);
        unchanged.id = std::numeric_limits<uint64_t>::max();
        unchanged.name = L"unchanged";
        Rule actual = unchanged;
        RuleMatchInfo info;
        info.id = unchanged.id;
        info.name = unchanged.name;
        info.scope = RuleScope::PostApp;
        info.action = RuleAction::Block;
        Check(store.Exists(id) == exists && store.Get(id, actual) == exists &&
                  store.GetInfo(id, info) == exists,
              "поиск по ID отличается от линейного поиска");
        if (exists) {
            Check(SameRule(actual, *expected),
                  "чтение по ID изменило поля или списки условий правила");
            Check(info.id == expected->id && info.name == expected->name &&
                  info.scope == expected->scope && info.action == expected->action,
                  "компактное чтение по ID вернуло неверное правило");
        } else {
            Check(SameRule(actual, unchanged) && info.id == unchanged.id &&
                  info.name == unchanged.name && info.scope == RuleScope::PostApp &&
                  info.action == RuleAction::Block,
                  "отсутствующий ID изменил выходной объект");
        }
    }
    Check(store.version() == version, "чтение по ID изменило версию правил");
    return ids.size();
}

Rule IdLookupRule(unsigned number) {
    Rule rule = OutboundRule(ProtoFromNumber(static_cast<uint8_t>(number)), kEndpointConds);
    rule.scope = static_cast<RuleScope>(number % 3);
    rule.name = L"ID rule " + std::to_wstring(number);
    rule.enabled = number % 2 != 0;
    rule.action = number % 4 ? RuleAction::Allow : RuleAction::Block;
    rule.icmpTypes = { IcmpTypeItem{ 8, -1 }, IcmpTypeItem{ 3, 1 } };
    rule.services = { ServiceItem{ L"Dnscache", L"DNS" } };
    return rule;
}

void TestRuleIdIndexUpdates() {
    RuleStore store;
    std::vector<uint64_t> ids{ 0, std::numeric_limits<uint64_t>::max() };
    size_t queries = 0;
    const auto verify = [&] { queries += CheckRuleIdLookups(store, ids); };
    verify();
    for (unsigned number = 0; number < 64; ++number) {
        Rule rule = IdLookupRule(number);
        store.Add(rule);
        verify();
    }
    Rule changed;
    Check(store.Get(ids[10], changed), "не найдено правило для обновления");
    changed.name = L"changed ID rule";
    changed.scope = RuleScope::App;
    changed.appPath = L"C:\\Other\\Moved.exe";
    changed.action = RuleAction::Block;
    Check(store.Update(changed), "не удалось изменить правило и его группу");
    verify();
    Check(store.SetEnabled(changed.id, false), "не удалось выключить правило по ID");
    verify();
    Check(store.SetEnabled(changed.id, false), "повторное выключение правила не удалось");
    verify();
    Check(store.SetEnabled(changed.id, true), "не удалось включить правило по ID");
    verify();

    for (const auto& group : { store.Globals(), store.ForApp(kAppPath), store.PostApps() }) {
        Check(group.size() >= 2 && store.MovePriority(group.back().id, -1),
              "не удалось переставить правила для проверки ID");
        verify();
    }
    std::vector<Rule> app = store.ForApp(kAppPath);
    std::reverse(app.begin(), app.end());
    app.resize(2);
    app.push_back(IdLookupRule(100));
    store.ReplaceApp(kAppPath, L"EXAMPLE.EXE", std::move(app));
    verify();
    store.ReplaceGlobals({ IdLookupRule(101), IdLookupRule(102) });
    verify();
    store.ReplacePostApps({ IdLookupRule(103), IdLookupRule(104) });
    verify();

    Rule removed = store.All().back();
    Check(store.Remove(removed.id), "не удалось удалить правило по ID");
    verify();
    removed = store.Globals().front();
    Check(store.RemoveByName(removed.scope, removed.appPath, removed.name),
          "не удалось удалить правило по имени");
    verify();
    store.RemoveApp(kAppPath);
    verify();
    store.RemoveGlobals();
    verify();
    store.RemovePostApps();
    verify();
    store.Clear();
    verify();
    store.Clear();
    verify();

    // Массовая замена перемещает вектор и проверяет отсутствие предела ID-индекса.
    std::vector<Rule> many;
    for (unsigned number = 0; number < 2048; ++number)
        many.push_back(IdLookupRule(number));
    store.ReplaceApp(kAppPath, L"EXAMPLE.EXE", std::move(many));
    verify();
    store.Clear();
    verify();

    Rule first = IdLookupRule(200);
    first.id = 700;
    first.enabled = false;
    Rule duplicate = first;
    duplicate.name = L"second duplicate";
    duplicate.enabled = true;
    Rule high = IdLookupRule(201);
    high.id = std::numeric_limits<uint64_t>::max() - 1;
    store.ReplaceGlobals({ first, duplicate, high });
    verify();
    store.Clear();
    verify();
    std::cout << "Rule ID lookup tests passed: " << queries << " queries\n";
}

void TestRemoveMissingApps() {
    RuleStore empty;
    const uint64_t emptyVersion = empty.version();
    Check(empty.RemoveMissingApps() == 0 && empty.version() == emptyVersion,
          "очистка пустого хранилища изменила его версию");

    wchar_t temp[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    Check(length != 0 && length < MAX_PATH, "не удалось получить временный каталог");
    wchar_t directory[MAX_PATH]{};
    Check(GetTempFileNameW(temp, L"fxc", 0, directory) != 0 &&
              DeleteFileW(directory) && CreateDirectoryW(directory, nullptr),
          "не удалось создать каталог для проверки очистки правил");
    const std::wstring root = directory;
    const std::wstring present = root + L"\\Существующее приложение.exe";
    const std::wstring missing = root + L"\\Удалённое приложение.exe";
    const std::wstring missingParent = root + L"\\missing\\app.exe";
    const std::wstring database = root + L"\\rules.db";
    HANDLE file = CreateFileW(present.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    Check(file != INVALID_HANDLE_VALUE, "не удалось создать файл приложения");

    {
        RuleStore store;
        std::wstring error;
        Check(store.AttachDatabase(database, error), "не удалось подключить базу очистки");
        const auto addApp = [&](const std::wstring& path, bool enabled = true) {
            Rule rule = OutboundRule(Proto::Tcp, 0);
            rule.appPath = path;
            rule.enabled = enabled;
            return store.Add(rule);
        };
        const uint64_t presentId = addApp(present);
        const uint64_t disabledPresentId = addApp(FoldCaseCopy(present), false);
        std::vector<uint64_t> removedIds = {
            addApp(missing), addApp(FoldCaseCopy(missing), false),
            addApp(missingParent, false), addApp(root)
        };

        // Свободная буква моделирует отключённый съёмный носитель без обращения к диску.
        const DWORD drives = GetLogicalDrives();
        Check(drives != 0, "не удалось получить список дисков");
        for (int drive = 25; drive >= 0; --drive) {
            if (drives & (DWORD{1} << drive)) continue;
            std::wstring path = L"Z:\\FirewallX_cleanup_missing_app.exe";
            path[0] = static_cast<wchar_t>(L'A' + drive);
            removedIds.push_back(addApp(path));
            break;
        }

        Rule global = OutboundRule(Proto::Udp, 0);
        global.scope = RuleScope::Global;
        store.Add(global);
        Rule postapp = global;
        postapp.id = 0;
        postapp.scope = RuleScope::PostApp;
        store.Add(postapp);

        MatchQuery query = Query(Proto::Tcp, Dir::Out);
        query.appPath = missing;
        Check(Matches(store, query), "исходное правило отсутствующего приложения не найдено");
        const uint64_t version = store.version();
        const DWORD errorMode = GetThreadErrorMode();
        Check(store.RemoveMissingApps() == removedIds.size() &&
                  store.version() == version + 1 && GetThreadErrorMode() == errorMode,
              "очистка удалила неверное число правил, версию или режим ошибок потока");
        Check(!Matches(store, query), "очистка оставила правило в индексе сопоставления");
        for (uint64_t id : removedIds)
            Check(!store.Exists(id), "очистка оставила удалённое правило в индексе ID");
        query.appPath = present;
        Check(Matches(store, query) && store.Count() == 4 &&
                  store.Exists(presentId) && store.Exists(disabledPresentId) &&
                  store.ForApp(present).size() == 2 &&
                  store.GlobalCount() == 1 && store.PostAppCount() == 1,
              "очистка затронула существующее приложение или специальные группы");
        Check(store.dbError().empty(), "очистка не сохранила базу правил");
        const uint64_t cleanedVersion = store.version();
        Check(store.RemoveMissingApps() == 0 && store.version() == cleanedVersion,
              "повторная очистка без удалений изменила версию хранилища");

        RuleStore loaded;
        Check(loaded.LoadOnce(database, error) && loaded.Count() == 4 &&
                  loaded.ForApp(present).size() == 2 &&
                  loaded.GlobalCount() == 1 && loaded.PostAppCount() == 1,
              "очищенные правила неверно восстановились из базы");
        for (uint64_t id : removedIds)
            Check(!loaded.Exists(id), "удалённое правило осталось в базе");

        Check(CloseHandle(file) && DeleteFileW(present.c_str()),
              "не удалось удалить тестовый файл приложения");
        Check(store.RemoveMissingApps() == 2 && store.Count() == 2 &&
                  store.GlobalCount() == 1 && store.PostAppCount() == 1 &&
                  store.dbError().empty(),
              "очистка не удалила правила после удаления существовавшего файла");
        Check(loaded.LoadOnce(database, error) && loaded.Count() == 2,
              "повторная очистка не сохранилась в базе");
        const uint64_t specialVersion = store.version();
        Check(store.RemoveMissingApps() == 0 && store.version() == specialVersion,
              "очистка затронула хранилище только с глобальными и постправилами");
    }
    Check(DeleteFileW(database.c_str()) && RemoveDirectoryW(directory),
          "не удалось удалить временную базу очистки");
}

void TestPostAppPidDatabase() {
    wchar_t directory[MAX_PATH]{}, filename[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length != 0 && length < MAX_PATH &&
              GetTempFileNameW(directory, L"fxp", 0, filename) != 0,
          "не удалось создать временную базу для фильтра PID");
    std::wstring error;
    uint64_t zeroId = 0, anyId = 0;
    {
        RuleStore writer;
        Check(writer.AttachDatabase(filename, error), "не удалось открыть базу фильтра PID");
        Rule rule = OutboundRule(Proto::Tcp, 0);
        rule.scope = RuleScope::PostApp;
        rule.conds = CondPidZero;
        rule.action = RuleAction::Block;
        zeroId = writer.Add(rule);
        rule.conds = CondNone;
        rule.action = RuleAction::Allow;
        anyId = writer.Add(rule);
        Check(writer.dbError().empty(), "не удалось записать фильтр PID");
    }
    for (bool readOnly : { false, true }) {
        RuleStore loaded;
        Check(readOnly ? loaded.LoadOnce(filename, error) : loaded.AttachDatabase(filename, error),
              "не удалось загрузить базу фильтра PID");
        Rule zero, any;
        Check(loaded.Get(zeroId, zero) && zero.conds == CondPidZero &&
                  loaded.Get(anyId, any) && any.conds == CondNone,
              "база потеряла PID 0 или добавила фильтр правилу с любым PID");
        MatchQuery query = Query(Proto::Udp, Dir::In);
        query.pid = 0;
        CheckRuleResult(loaded, query, zeroId, RuleAction::Block, RuleScope::PostApp);
        query.pid = 4;
        CheckRuleResult(loaded, query, anyId, RuleAction::Allow, RuleScope::PostApp);
    }
    Check(DeleteFileW(filename) != FALSE, "не удалось удалить временную базу фильтра PID");
}

void TestRuleIdDatabaseLoading() {
    wchar_t directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length != 0 && length < MAX_PATH, "не удалось получить временный каталог");
    wchar_t filename[MAX_PATH]{};
    Check(GetTempFileNameW(directory, L"fxr", 0, filename) != 0,
          "не удалось создать временный файл правил");
    const std::wstring path = filename;
    std::vector<uint64_t> ids{ 0, std::numeric_limits<uint64_t>::max() };
    std::wstring error;
    {
        RuleStore writer;
        Rule old = IdLookupRule(300);
        writer.Add(old);
        ids.push_back(old.id);
        Check(writer.AttachDatabase(path, error), "не удалось подключить пустую базу");
        CheckRuleIdLookups(writer, ids);
        for (unsigned number = 0; number < 12; ++number) {
            Rule rule = IdLookupRule(number);
            writer.Add(rule);
        }
        Check(writer.dbError().empty(), "не удалось сохранить тестовые правила");
        CheckRuleIdLookups(writer, ids);
        writer.DetachDatabase();
        CheckRuleIdLookups(writer, ids);

        RuleStore attached;
        Check(attached.AttachDatabase(path, error), "не удалось загрузить подключённую базу");
        CheckRuleIdLookups(attached, ids);
        attached.DetachDatabase();
        CheckRuleIdLookups(attached, ids);

        RuleStore loaded;
        Check(loaded.LoadOnce(path, error), "не удалось однократно загрузить базу");
        CheckRuleIdLookups(loaded, ids);
        Check(!loaded.attached() && loaded.Count() == 12,
              "однократная загрузка изменила состав правил или оставила базу открытой");
        Check(loaded.LoadOnce(path, error), "не удалось повторно загрузить базу");
        CheckRuleIdLookups(loaded, ids);

        // Путь внутри обычного файла гарантированно не может быть базой.
        const std::wstring missing = path + L"\\missing.db";
        Check(!attached.AttachDatabase(missing, error),
              "ошибочное подключение базы неожиданно удалось");
        CheckRuleIdLookups(attached, ids);
        Check(attached.Count() == 12, "ошибка подключения изменила прежние правила");
        Check(!loaded.LoadOnce(missing, error), "ошибочная загрузка базы неожиданно удалась");
        CheckRuleIdLookups(loaded, ids);
        Check(loaded.Count() == 0, "ошибочная загрузка оставила прежние правила");
        Check(loaded.LoadOnce(path, error), "не удалось восстановить правила после ошибки");
        CheckRuleIdLookups(loaded, ids);
    }
    Check(DeleteFileW(filename) != FALSE, "не удалось удалить временный файл правил");
}

class SaveWarningProbe {
public:
    unsigned warnings = 0;
    HWND owner = nullptr;
    UINT flags = 0;
    std::wstring title, text;
    int result = IDOK;

    SaveWarningProbe() { current_ = this; }
    ~SaveWarningProbe() { current_ = nullptr; }

    // Записываем параметры предупреждения, не открывая модальный диалог.
    static int WINAPI Show(HWND owner, LPCWSTR text, LPCWSTR title, UINT flags) {
        Check(current_ != nullptr, "не задан обработчик тестового предупреждения");
        ++current_->warnings;
        current_->owner = owner;
        current_->text = text;
        current_->title = title;
        current_->flags = flags;
        return current_->result;
    }

private:
    inline static SaveWarningProbe* current_ = nullptr;
};

void TestRuleDatabaseCommitFailure() {
    wchar_t directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length != 0 && length < MAX_PATH, "не удалось получить временный каталог");
    wchar_t filename[MAX_PATH]{};
    Check(GetTempFileNameW(directory, L"fxr", 0, filename) != 0,
          "не удалось создать временный файл правил");
    const std::wstring path = filename;
    std::wstring error;
    const auto makeRule = [](const wchar_t* name) {
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondNone;
        rule.name = name;
        rule.autoName = false;
        return rule;
    };

    {
        RuleStore store;
        Check(store.AttachDatabase(path, error), "не удалось подключить тестовую базу правил");
        Rule first = makeRule(L"commit original first");
        Rule second = makeRule(L"commit original second");
        store.Add(first);
        store.Add(second);
        Check(store.Count() == 2 && store.dbError().empty(),
              "не удалось сохранить исходные правила");
        SaveWarningProbe warning;
        uint64_t reportedVersion = store.version();
        Check(!RuleDialogs::ShowSaveError(nullptr, store, reportedVersion, SaveWarningProbe::Show) &&
                  warning.warnings == 0,
              "успешная запись вызвала предупреждение об ошибке");

        sqlite3* reader = nullptr;
        const std::string utf8Path = WideToUtf8(path);
        Check(sqlite3_open(utf8Path.c_str(), &reader) == SQLITE_OK,
              "не удалось открыть второе подключение SQLite");
        // Короткий набор помещается в кеш: транзакция чтения мешает именно COMMIT.
        Check(sqlite3_exec(reader, "BEGIN; SELECT id FROM rules;", nullptr, nullptr, nullptr)
                  == SQLITE_OK,
              "не удалось удержать транзакцию чтения правил");
        Rule blocked = makeRule(L"commit blocked rule");
        store.Add(blocked);
        Check(store.Count() == 3 &&
                  store.dbError() == Utf8ToWide(sqlite3_errstr(SQLITE_BUSY)),
              "блокировка COMMIT не сохранила исходное сообщение SQLite");
        const uint64_t previousReportedVersion = reportedVersion;
        warning.result = 0;
        Check(!RuleDialogs::ShowSaveError(nullptr, store, reportedVersion, SaveWarningProbe::Show) &&
                  warning.warnings == 1 && reportedVersion == previousReportedVersion,
              "неудачный показ предупреждения пометил ошибку как уже показанную");
        warning.result = IDOK;
        Check(RuleDialogs::ShowSaveError(nullptr, store, reportedVersion, SaveWarningProbe::Show) &&
                  warning.warnings == 2 && reportedVersion == store.version() &&
                  warning.owner == nullptr && warning.flags == (MB_ICONWARNING | MB_OK) &&
                  warning.title == LoadStringRes(IDS_RULES_TITLE) &&
                  warning.text == LoadStringResFmt(IDS_RULES_SAVE_FAILED_FMT, store.dbError().c_str()),
              "ошибка записи не показала предупреждение с причиной SQLite");
        Check(!RuleDialogs::ShowSaveError(nullptr, store, reportedVersion, SaveWarningProbe::Show) &&
                  warning.warnings == 2,
              "ошибка той же версии правил показана повторно");
        Check(sqlite3_exec(reader, "ROLLBACK;", nullptr, nullptr, nullptr) == SQLITE_OK,
              "не удалось завершить транзакцию чтения правил");
        Check(sqlite3_close(reader) == SQLITE_OK, "не удалось закрыть второе подключение");

        Rule retry = makeRule(L"commit retry rule");
        store.Add(retry);
        Check(store.Count() == 4 && store.dbError().empty(),
              "сохранение не восстановилось после снятия блокировки COMMIT");
        Check(!RuleDialogs::ShowSaveError(nullptr, store, reportedVersion, SaveWarningProbe::Show) &&
                  warning.warnings == 2,
              "после восстановления записи показана прежняя ошибка");
        RuleStore persisted;
        Check(persisted.LoadOnce(path, error) && persisted.Count() == 4,
              "после повторного сохранения потеряны правила в файле");
        for (const Rule& expected : { first, second, blocked, retry }) {
            Rule actual;
            Check(persisted.Get(expected.id, actual) && actual.name == expected.name &&
                      actual.enabled == expected.enabled,
                  "повторное сохранение изменило имя или состояние правила");
        }

        Check(store.SetEnabled(first.id, false) && store.dbError().empty(),
              "последующее изменение правила не сохранилось после ошибки COMMIT");
        Check(store.Remove(second.id) && store.dbError().empty(),
              "последующее удаление правила не сохранилось после ошибки COMMIT");
        Rule actual;
        Check(persisted.LoadOnce(path, error) && persisted.Count() == 3 &&
                  persisted.Get(first.id, actual) && !actual.enabled &&
                  !persisted.Exists(second.id) && persisted.Exists(blocked.id) &&
                  persisted.Exists(retry.id),
              "последующие изменения после ошибки COMMIT потерялись при чтении файла");
    }
    Check(DeleteFileW(filename) != FALSE, "не удалось удалить временный файл правил");
}

bool g_interruptRuleLoads = false;
unsigned g_interruptedRuleRows = 0;

// Прерываем настоящее чтение после первой строки, не раскрывая RuleDb::db_.
int SQLITE_CALLBACK InterruptRuleLoad(unsigned event, void* context,
                                      void* statement, void*) {
    if (!g_interruptRuleLoads || event != SQLITE_TRACE_ROW) return 0;
    const char* sql = sqlite3_sql(static_cast<sqlite3_stmt*>(statement));
    if (sql && std::strstr(sql, "FROM rules ORDER BY")) {
        ++g_interruptedRuleRows;
        sqlite3_interrupt(static_cast<sqlite3*>(context));
    }
    return 0;
}

int SQLITE_CALLBACK InstallRuleLoadInterrupt(sqlite3* db, char**,
                                             const sqlite3_api_routines*) {
    return sqlite3_trace_v2(db, SQLITE_TRACE_ROW, InterruptRuleLoad, db);
}

void TestRuleDatabaseLoadErrors() {
    wchar_t directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, directory);
    Check(length != 0 && length < MAX_PATH, "не удалось получить временный каталог");
    wchar_t filename[MAX_PATH]{};
    Check(GetTempFileNameW(directory, L"fxr", 0, filename) != 0,
          "не удалось создать временный файл правил");
    const std::wstring path = filename;
    std::wstring error;
    const auto extension = reinterpret_cast<void (SQLITE_CALLBACK*)()>(
        InstallRuleLoadInterrupt);

    {
        RuleDb writer;
        Check(writer.Open(path, error), "не удалось открыть тестовую базу правил");
        Rule first = IdLookupRule(400);
        first.id = 40;
        first.scope = RuleScope::Global;
        first.priority = 0;
        Rule second = IdLookupRule(401);
        second.id = 90;
        second.scope = RuleScope::Global;
        second.priority = 1;
        const std::vector<Rule> original{ first, second };
        std::vector<Rule> loaded{ first };
        uint64_t maxId = 99;
        Check(writer.Load(loaded, maxId, error) && loaded.empty() && maxId == 0,
              "пустая база не загрузилась или оставила прежний результат");
        Check(writer.SaveAll(original, error), "не удалось сохранить тестовые правила");
        const auto verifyOriginal = [&](const std::vector<Rule>& list, uint64_t maximum) {
            Check(list.size() == 2 && maximum == second.id &&
                      list[0].id == first.id && list[0].name == first.name &&
                      list[1].id == second.id && list[1].name == second.name,
                  "чтение или правка после ошибки потеряли исходные правила");
        };
        Check(writer.Load(loaded, maxId, error), "не удалось прочитать тестовые правила");
        verifyOriginal(loaded, maxId);

        Check(sqlite3_auto_extension(extension) == SQLITE_OK,
              "не удалось установить проверку прерванного чтения");
        RuleDb interrupted;
        Check(interrupted.Open(path, error), "не удалось открыть базу для прерывания");
        g_interruptRuleLoads = true;
        g_interruptedRuleRows = 0;
        error.clear();
        Check(!interrupted.Load(loaded, maxId, error),
              "прерванное чтение правил ошибочно признано успешным");
        Check(g_interruptedRuleRows == 1 && loaded.empty() && maxId == 0 && !error.empty(),
              "прерванное чтение оставило частичный набор, maxId или скрыло ошибку");

        RuleStore attached;
        Rule old = IdLookupRule(402);
        attached.Add(old);
        const uint64_t version = attached.version();
        g_interruptedRuleRows = 0;
        error.clear();
        Check(!attached.AttachDatabase(path, error),
              "подключение с прерванным чтением ошибочно удалось");
        Rule kept;
        Check(g_interruptedRuleRows == 1 && !attached.attached() && attached.readOnly() &&
                  attached.Count() == 1 && attached.Get(old.id, kept) && kept.name == old.name &&
                  attached.version() == version && !error.empty() && attached.dbError() == error,
              "ошибка подключения изменила прежние правила или оставила запись в базу");
        Rule added = IdLookupRule(403);
        attached.Add(added);
        Check(writer.Load(loaded, maxId, error), "не удалось проверить файл после ошибки");
        verifyOriginal(loaded, maxId);

        RuleStore once;
        once.Add(old);
        g_interruptedRuleRows = 0;
        error.clear();
        Check(!once.LoadOnce(path, error) && g_interruptedRuleRows == 1 &&
                  once.Count() == 0 && once.readOnly() && !error.empty() && once.dbError() == error,
              "однократное прерванное чтение сохранило старый или частичный набор");
        g_interruptRuleLoads = false;
        Check(interrupted.Load(loaded, maxId, error),
              "не удалось восстановить чтение после прерывания");
        verifyOriginal(loaded, maxId);
        Check(attached.AttachDatabase(path, error) && attached.attached() &&
                  attached.Count() == 2 && attached.dbError().empty(),
              "не удалось восстановить подключение после ошибки чтения");
        Check(once.LoadOnce(path, error) && once.Count() == 2 && once.dbError().empty(),
              "не удалось восстановить однократное чтение после ошибки");
        Check(sqlite3_cancel_auto_extension(extension) == 1,
              "не удалось снять проверку прерванного чтения");

        RuleDb reader;
        Check(reader.Open(path, error), "не удалось открыть базу для проверки блокировки");
        sqlite3* locker = nullptr;
        const std::string utf8Path = WideToUtf8(path);
        Check(sqlite3_open(utf8Path.c_str(), &locker) == SQLITE_OK,
              "не удалось открыть второе подключение SQLite");
        Check(sqlite3_exec(locker, "BEGIN EXCLUSIVE;", nullptr, nullptr, nullptr) == SQLITE_OK,
              "не удалось заблокировать тестовую базу");
        error.clear();
        const ULONGLONG start = GetTickCount64();
        const bool success = reader.Load(loaded, maxId, error);
        const ULONGLONG elapsed = GetTickCount64() - start;
        Check(!success && loaded.empty() && maxId == 0 && !error.empty(),
              "блокировка базы ошибочно признана успешной загрузкой пустых правил");
        Check(elapsed >= 9000, "таймаут ожидания блокировки базы не увеличен до 10 секунд");
        Check(sqlite3_exec(locker, "ROLLBACK;", nullptr, nullptr, nullptr) == SQLITE_OK,
              "не удалось снять блокировку тестовой базы");
        Check(reader.Load(loaded, maxId, error), "не удалось прочитать базу после разблокировки");
        verifyOriginal(loaded, maxId);

        // Блокировка дольше прежних трёх секунд должна завершиться полным чтением.
        Check(sqlite3_exec(locker, "BEGIN EXCLUSIVE;", nullptr, nullptr, nullptr) == SQLITE_OK,
              "не удалось повторно заблокировать тестовую базу");
        int unlockResult = SQLITE_ERROR;
        std::thread unlocker([&] {
            Sleep(3500);
            unlockResult = sqlite3_exec(locker, "ROLLBACK;", nullptr, nullptr, nullptr);
        });
        const bool recovered = reader.Load(loaded, maxId, error);
        unlocker.join();
        Check(unlockResult == SQLITE_OK && recovered,
              "загрузка не дождалась снятия блокировки внутри нового таймаута");
        verifyOriginal(loaded, maxId);
        Check(sqlite3_close(locker) == SQLITE_OK, "не удалось закрыть второе подключение");
    }
    Check(DeleteFileW(filename) != FALSE, "не удалось удалить временный файл правил");
}

// Прежний алгоритм служит эталоном, включая ограничение длины префикса.
bool PrefixMatchesByBounds(const IpAddr& a, const IpAddr& base, int prefix) {
    if (a.family != base.family) return false;
    if (prefix < 0) return a == base;
    IpAddr lo = base, hi = base;
    ApplyPrefix(lo, prefix, false);
    ApplyPrefix(hi, prefix, true);
    return a.Cmp(lo) >= 0 && a.Cmp(hi) <= 0;
}

void TestIpPrefixEquivalence() {
    size_t cases = 0;
    const auto compare = [&](const IpAddr& a, const IpAddr& base, int prefix) {
        const bool expected = PrefixMatchesByBounds(a, base, prefix);
        Check(IpMatchesPrefix(a, base, prefix) == expected,
              "проверка префикса отличается от проверки границ подсети");
        Check(AddrItem{ base, prefix }.Matches(a) == expected,
              "адресное условие отличается от проверки границ подсети");
        ++cases;
    };
    std::mt19937 random(2309);
    for (bool ipv6 : { false, true })
    for (unsigned pattern = 0; pattern < 4; ++pattern) {
        IpAddr base = ipv6 ? V6(10) : kLocal;
        for (uint8_t& byte : base.b) {
            switch (pattern) {
            case 0: byte = 0; break;
            case 1: byte = 0xFF; break;
            case 2: byte = 0xA5; break;
            default: byte = static_cast<uint8_t>(random()); break;
            }
        }
        const int total = static_cast<int>(base.len()) * 8;
        for (int prefix = -1; prefix <= total + 2; ++prefix) {
            compare(base, base, prefix);
            IpAddr otherFamily = base;
            otherFamily.family = ipv6 ? AF_INET : AF_INET6;
            compare(otherFamily, base, prefix);

            if (prefix >= 0) {
                IpAddr lo = base, hi = base;
                ApplyPrefix(lo, prefix, false);
                ApplyPrefix(hi, prefix, true);
                compare(lo, base, prefix);
                compare(hi, base, prefix);
            }
            // Изменение сетевого бита исключает адрес, host-бита — не исключает.
            for (int bit = 0; bit < total; ++bit) {
                IpAddr changed = base;
                changed.b[bit / 8] ^= static_cast<uint8_t>(1u << (7 - bit % 8));
                compare(changed, base, prefix);
                Check(IpMatchesPrefix(changed, base, prefix) ==
                          (prefix >= 0 && bit >= prefix),
                      "неверная граница между сетевыми и host-битами");
            }
            for (unsigned sample = 0; sample < 32; ++sample) {
                IpAddr a = base;
                for (uint8_t& byte : a.b) byte = static_cast<uint8_t>(random());
                compare(a, base, prefix);
            }
        }
        for (int prefix : { std::numeric_limits<int>::min(), -37,
                            std::numeric_limits<int>::max() }) {
            compare(base, base, prefix);
            IpAddr changed = base;
            changed.b[0] ^= 0x80;
            compare(changed, base, prefix);
            changed = base;
            changed.b[base.len() - 1] ^= 1;
            compare(changed, base, prefix);
        }
    }
    // Неиспользуемые байты IPv4 не участвуют даже в точном сравнении.
    IpAddr padded = kLocal;
    for (size_t i = padded.len(); i < sizeof(padded.b); ++i) padded.b[i] = 0xFF;
    compare(padded, kLocal, -1);
    compare(padded, kLocal, 32);
    compare(padded, kLocal, std::numeric_limits<int>::max());
    std::cout << "Prefix equivalence tests passed: " << cases << " cases\n";
}

void TestMacroPrefixMatching() {
    IpAddr multicast6 = V6(1);
    multicast6.b[0] = 0xFF;
    IpAddr multicast6End = multicast6;
    for (size_t i = 1; i < multicast6End.len(); ++i) multicast6End.b[i] = 0xFF;
    IpAddr outside6 = multicast6;
    outside6.b[0] = 0xFE;
    const struct {
        IpAddr address;
        bool matches;
    } cases[] = {
        { V4(223, 255, 255, 255), false },
        { V4(224, 0, 0, 0), true },
        { V4(239, 255, 255, 255), true },
        { V4(240, 0, 0, 0), false },
        { V4(255, 255, 255, 255), false },
        { multicast6, true },
        { multicast6End, true },
        { outside6, false },
        { V6(1), false },
    };
    AddrItem item{ kRemote, 0, AddrMacro::MulticastAddresses };
    for (const auto& test : cases) {
        Check(AddrMacros::Matches(AddrMacro::MulticastAddresses, test.address) ==
                  test.matches,
              "макрос multicast неверно проверил границу подсети");
        Check(item.Matches(test.address) == test.matches,
              "адресное условие с макросом неверно проверило подсеть");
    }
    IpAddr loopback6{};
    loopback6.family = AF_INET6;
    loopback6.b[15] = 1;
    const struct {
        IpAddr address;
        bool matches;
    } loopbackCases[] = {
        { V4(126, 255, 255, 255), false },
        { V4(127, 0, 0, 0), true },
        { V4(127, 0, 0, 1), true },
        { V4(127, 0, 0, 2), true },
        { V4(127, 23, 45, 67), true },
        { V4(127, 255, 255, 255), true },
        { V4(128, 0, 0, 0), false },
        { loopback6, true },
        { V6(1), false },
    };
    item = AddrItem{ kRemote, -1, AddrMacro::MyComputer };
    for (const auto& test : loopbackCases) {
        Check(AddrMacros::Matches(AddrMacro::MyComputer, test.address) == test.matches,
              "макрос MY_COMPUTER неверно проверил границу петлевой сети");
        Check(item.Matches(test.address) == test.matches,
              "адресное условие MY_COMPUTER неверно проверило петлевую сеть");
    }
}

void TestRuleSaveErrorResources() {
    const UiLang original = CurrentUiLang();
    size_t count = 0;
    const UiLangInfo* langs = UiLangs(count);
    HMODULE module = GetModuleHandleW(nullptr);
    constexpr UINT id = IDS_RULES_SAVE_FAILED_FMT;
    const std::wstring reason = L"write failed: 50%";

    for (size_t i = 0; i < count; ++i) {
        // Читаем нужный язык напрямую: fallback не должен скрыть пропущенный перевод.
        HRSRC resource = FindResourceExW(module, RT_STRING,
            MAKEINTRESOURCEW(id / 16 + 1), langs[i].winLangId);
        Check(resource != nullptr, "нет строковой таблицы предупреждения о записи правил");
        HGLOBAL block = LoadResource(module, resource);
        Check(block != nullptr, "не удалось загрузить ресурс предупреждения о записи правил");
        const wchar_t* data = static_cast<const wchar_t*>(LockResource(block));
        Check(data != nullptr, "не удалось прочитать ресурс предупреждения о записи правил");
        const size_t size = SizeofResource(module, resource) / sizeof(wchar_t);
        size_t offset = 0;
        for (UINT index = 0; index < id % 16; ++index) {
            Check(offset < size && data[offset] < size - offset,
                  "повреждена строковая таблица предупреждения");
            offset += 1 + data[offset];
        }
        Check(offset < size && data[offset] > 0 && data[offset] < size - offset,
              "нет перевода предупреждения о записи правил");
        const std::wstring format(data + offset + 1, data[offset]);
        const size_t placeholder = format.find(L"%s");
        Check(placeholder != std::wstring::npos &&
                  format.find(L"%s", placeholder + 2) == std::wstring::npos,
              "перевод предупреждения потерял единственную причину ошибки");
        SetUiLang(langs[i].lang);
        Check(LoadStringResFmt(id, reason.c_str()) ==
                  format.substr(0, placeholder) + reason + format.substr(placeholder + 2),
              "предупреждение использовало другой язык или изменило причину ошибки");
    }
    SetUiLang(original);
}

void TestPortListErrorResources() {
    const UiLang original = CurrentUiLang();
    size_t count = 0;
    const UiLangInfo* langs = UiLangs(count);
    HMODULE module = GetModuleHandleW(nullptr);
    constexpr UINT id = IDS_RDPO_ERR_BAD_PORT;

    for (size_t i = 0; i < count; ++i) {
        // Проверяем ресурс напрямую: при его отсутствии тест должен завершиться
        // с ошибкой в консоли, а не ждать закрытия MessageBox из LoadStringRes.
        HRSRC resource = FindResourceExW(module, RT_STRING,
            MAKEINTRESOURCEW(id / 16 + 1), langs[i].winLangId);
        Check(resource != nullptr, "в тестовом exe отсутствует строковая таблица");
        HGLOBAL block = LoadResource(module, resource);
        Check(block != nullptr, "не удалось загрузить строковую таблицу тестов");
        const wchar_t* data = static_cast<const wchar_t*>(LockResource(block));
        Check(data != nullptr, "не удалось прочитать строковую таблицу тестов");
        const size_t size = SizeofResource(module, resource) / sizeof(wchar_t);
        size_t offset = 0;
        for (UINT index = 0; index < id % 16; ++index) {
            Check(offset < size && data[offset] < size - offset,
                  "повреждена строковая таблица тестов");
            offset += 1 + data[offset];
        }
        Check(offset < size && data[offset] > 0 && data[offset] < size - offset,
              "в тестовом exe отсутствует сообщение о неверном порте");
        const std::wstring expected(data + offset + 1, data[offset]);

        SetUiLang(langs[i].lang);
        std::vector<PortItem> parsed;
        std::wstring error;
        Check(!RuleDialogs::ParsePortList(L"443abc", parsed, error),
              "некорректный порт принят при проверке ресурсов");
        Check(error == expected + L"443abc",
              "ошибка порта не содержит сообщение на выбранном языке");
    }
    SetUiLang(original);
}

void TestPortListParsing() {
    struct Case {
        const wchar_t* text;
        std::vector<PortItem> expected;
    };
    const Case valid[] = {
        { L"", {} },
        { L" \t\r\n", {} },
        { L"1", {{1, 1}} },
        { L"65535", {{65535, 65535}} },
        { L"000443", {{443, 443}} },
        { L"80, 443, 5000-5010", {{80, 80}, {443, 443}, {5000, 5010}} },
        { L" 80 , \t443 , 5000 \t- 5010 ", {{80, 80}, {443, 443}, {5000, 5010}} },
        { L"5010-5000", {{5000, 5010}} },
        { L"1-65535", {{1, 65535}} },
        { L",,80,,443,,", {{80, 80}, {443, 443}} },
    };
    for (const Case& test : valid) {
        std::vector<PortItem> parsed = {{999, 999}};
        std::wstring error;
        Check(RuleDialogs::ParsePortList(test.text, parsed, error),
              "корректный список портов отклонён");
        Check(parsed.size() == test.expected.size(),
              "список портов получил неверное число элементов");
        for (size_t i = 0; i < parsed.size(); ++i)
            Check(parsed[i].from == test.expected[i].from &&
                      parsed[i].to == test.expected[i].to,
                  "список портов получил неверные границы");
    }

    const std::wstring invalid[] = {
        L"443abc", L"80;443", L"1e3", L"0x50", L"443.0", L"4 43",
        L"abc", L"+443", L"-1", L"0", L"65536",
        L"2147483648", L"4294967376", L"999999999999999999999999999999",
        L"80-443-8443", L"80junk-443", L"80-443junk", L"80-",
        L"80-0", L"0-80", L"80-65536", L"65536-80", L"80--443",
        L"80-+443", L"80-999999999999999999999999999999",
        L"999999999999999999999999999999-80", L"80, 443abc",
        std::wstring(L"443\0abc", 7),
    };
    for (const std::wstring& text : invalid) {
        std::vector<PortItem> parsed;
        std::wstring error;
        Check(!RuleDialogs::ParsePortList(text, parsed, error),
              "некорректный список портов принят");
        Check(!error.empty(), "для некорректного порта не задана ошибка");
    }
}

void TestProtocolTokenParsing() {
    for (unsigned number = 0; number <= 255; ++number) {
        uint8_t parsed = 99;
        Check(ParseProtoToken(std::to_wstring(number), parsed) && parsed == number,
              "допустимый номер протокола отклонён или изменён");
    }

    const struct { const wchar_t* text; uint8_t number; } valid[] = {
        { L" \t006\r\n", 6 }, { L"000255", 255 },
        { L"tcp", 6 }, { L" uDp ", 17 }, { L"icmpV6", 58 },
        // Сохраняем поддерживаемые CRT десятичные цифры других алфавитов.
        { L"６", 6 }, { L"٦", 6 }, { L"۶", 6 },
        { L"६", 6 }, { L"༦", 6 }, { L"２５５", 255 },
    };
    for (const auto& test : valid) {
        uint8_t parsed = 99;
        Check(ParseProtoToken(test.text, parsed) && parsed == test.number,
              "корректный номер или алиас протокола отклонён или изменён");
    }

    size_t count = 0;
    const KnownProto* known = KnownProtos(count);
    for (size_t i = 0; i < count; ++i) {
        uint8_t parsed = 99;
        Check(ParseProtoToken(known[i].alias, parsed) && parsed == known[i].num,
              "известный алиас протокола отклонён или изменён");
    }

    const std::wstring invalid[] = {
        L"²", L"6²", L"²6", L"³", L"1³", L"255²", L"6²7",
        L"", L" \t\r\n", L"256", L"２５６", L"2147483648", L"4294967302",
        L"999999999999999999999999999999", L"+6", L"-1", L"6abc",
        L"6.0", L"6 7", L"0x06", L"1e2", L"TCPjunk", L"TCP,UDP",
        std::wstring(L"6\0junk", 6),
    };
    for (const std::wstring& text : invalid) {
        uint8_t parsed = 99;
        Check(!ParseProtoToken(text, parsed),
              "некорректный номер или алиас протокола принят");
        Check(parsed == 99, "ошибка разбора изменила выходной номер протокола");
    }
}

void TestAddressDuplicates() {
    const auto item = [](const wchar_t* text, int prefix = -1) {
        AddrItem result;
        Check(ParseIpAddr(text, result.addr), "неверный адрес в тесте дубликатов");
        result.prefix = prefix;
        return result;
    };
    struct Case {
        AddrItem left, right;
        bool equal;
    };
    AddrItem dns, dnsWithUnusedFields, gateway;
    dns.macro = AddrMacro::DnsServers;
    dnsWithUnusedFields = item(L"1.1.1.1", 24);
    dnsWithUnusedFields.macro = AddrMacro::DnsServers;
    gateway.macro = AddrMacro::Gateways;
    const Case cases[] = {
        {item(L"1.1.1.1"), item(L"1.1.1.1"), true},
        {item(L"1.1.1.1"), item(L"1.1.1.1", 32), true},
        {item(L"1.1.1.1"), item(L"1.1.1.2"), false},
        {item(L"192.168.1.1", 24), item(L"192.168.1.254", 24), true},
        {item(L"192.168.1.1", 24), item(L"192.168.2.1", 24), false},
        {item(L"192.168.1.0", 24), item(L"192.168.1.0", 16), false},
        {item(L"192.168.1.1"), item(L"192.168.1.1", 24), false},
        {item(L"0.0.0.0", 0), item(L"192.168.1.1", 0), true},
        {item(L"2001:db8::abcd"), item(L"2001:0DB8:0:0:0:0:0:ABCD"), true},
        {item(L"2001:db8::abcd"), item(L"2001:db8::abcd", 128), true},
        {item(L"2001:db8::1", 64), item(L"2001:db8::ffff", 64), true},
        {item(L"2001:db8::1", 64), item(L"2001:db8:1::1", 64), false},
        {item(L"2001:db8::", 64), item(L"2001:db8::", 65), false},
        {item(L"::", 0), item(L"2001:db8::1", 0), true},
        {item(L"0.0.0.1"), item(L"::1"), false},
        {dns, dnsWithUnusedFields, true},
        {dns, gateway, false},
        {dns, item(L"0.0.0.0"), false},
    };
    for (const Case& test : cases) {
        Check((test.left == test.right) == test.equal &&
                  (test.right == test.left) == test.equal,
              "сравнение дубликатов адресов изменило смысл IP, подсети или макроса");
        std::vector<AddrItem> addresses = {test.left, test.right, test.left, test.right};
        DeduplicateAddresses(addresses);
        Check(addresses.size() == (test.equal ? 1u : 2u) &&
                  addresses.front().addr == test.left.addr &&
                  addresses.front().prefix == test.left.prefix &&
                  addresses.front().macro == test.left.macro &&
                  (test.equal || addresses.back() == test.right),
              "удаление дубликатов потеряло адрес или изменило порядок первых записей");
        const auto once = addresses;
        DeduplicateAddresses(addresses);
        Check(addresses == once, "повторное удаление дубликатов изменило список адресов");
    }
    std::vector<AddrItem> empty;
    DeduplicateAddresses(empty);
    Check(empty.empty(), "удаление дубликатов добавило адрес в пустой список");

    Rule rule = OutboundRule(Proto::Tcp, kEndpointConds);
    rule.remoteAddrs = {{kRemote, -1}, {kRemote, 32}, {kRemote, -1},
                        {V4(203, 0, 113, 10), -1}, {V4(203, 0, 113, 10), 32}};
    rule.localAddrs = {{kLocal, -1}, {kLocal, -1}, {kLocal, 32}};
    RuleStore store;
    const uint64_t id = store.Add(rule);
    Rule stored;
    Check(store.Get(id, stored) && stored.remoteAddrs.size() == 2 && stored.localAddrs.size() == 1 &&
              stored.conds == rule.conds && stored.name == rule.name,
          "добавление правила сохранило дубликаты адресов или изменило его условия");
    for (const IpAddr& remote : {kRemote, V4(203, 0, 113, 10), V4(203, 0, 113, 11)}) {
        const bool expected = remote == kRemote || remote == V4(203, 0, 113, 10);
        Check(Matches(store, Query(Proto::Tcp, Dir::Out, kLocal, remote)) == expected,
              "удаление дубликатов изменило сопоставление правила");
    }
    stored.remoteAddrs.push_back(stored.remoteAddrs.front());
    stored.localAddrs.push_back(stored.localAddrs.front());
    Check(store.Update(stored) && store.Get(id, stored) &&
              stored.remoteAddrs.size() == 2 && stored.localAddrs.size() == 1,
          "изменение правила сохранило дубликаты адресов");

    rule.conds = CondProto;
    NormalizeRuleConds(rule);
    Check(rule.conds == CondProto && rule.remoteAddrs.size() == 2 && rule.localAddrs.size() == 1,
          "нормализация снятых условий включила их или потеряла уникальные адреса");
}

void TestRuleProtocolChanges() {
    for (Proto oldProto : { Proto::Icmp, Proto::IcmpV6 }) {
        const Proto newProto = oldProto == Proto::Icmp ? Proto::IcmpV6 : Proto::Icmp;
        const uint8_t oldType = oldProto == Proto::Icmp ? 8 : 128;
        const uint8_t newType = newProto == Proto::Icmp ? 8 : 128;
        for (bool throughAny : { true, false }) {
            Rule rule = OutboundRule(oldProto, 0);
            rule.conds |= CondIcmpType;
            rule.icmpTypes = {{oldType, -1}};
            if (throughAny) {
                // Снятие галочки сохраняет значения до нового выбора протокола.
                rule.conds &= ~CondProto;
                NormalizeRuleConds(rule);
                Check(rule.icmpTypes.size() == 1 && !(rule.conds & CondIcmpType),
                      "снятие условия протокола потеряло заготовку типов ICMP");
            }
            rule.SetProto(newProto);
            Check(rule.proto == newProto && rule.protoFixed(),
                  "смена протокола не установила выбранную версию ICMP");
            Check(rule.icmpTypes.empty() && !(rule.conds & CondIcmpType),
                  "смена версии ICMP сохранила типы прежней версии");

            rule.icmpTypes = {{newType, -1}};
            rule.conds |= CondIcmpType;
            RuleStore store;
            store.Add(rule);
            MatchQuery query = Query(newProto, Dir::Out);
            query.icmpType = newType;
            query.icmpCode = 0;
            Check(Matches(store, query), "правило не совпало с новым типом ICMP");
            query.icmpType = oldType;
            Check(!Matches(store, query), "правило совпало со старым типом ICMP");
        }

        Rule unchanged = OutboundRule(oldProto, 0);
        unchanged.conds |= CondIcmpType;
        unchanged.icmpTypes = {{oldType, 0}};
        unchanged.SetProto(oldProto);
        Check((unchanged.conds & CondIcmpType) && unchanged.icmpTypes.size() == 1 &&
                  unchanged.icmpTypes[0].type == oldType && unchanged.icmpTypes[0].code == 0,
              "повторный выбор того же протокола потерял типы ICMP");
        unchanged.conds &= ~CondProto;
        NormalizeRuleConds(unchanged);
        unchanged.SetProto(oldProto);
        Check(unchanged.icmpTypes.empty() && !(unchanged.conds & CondIcmpType),
              "переход с любого протокола сохранил старую заготовку типов ICMP");
    }

    Rule rule = OutboundRule(Proto::Tcp, kEndpointConds);
    rule.SetProto(Proto::Udp);
    Check((rule.conds & (CondRemotePort | CondLocalPort)) ==
                  (CondRemotePort | CondLocalPort) &&
              rule.remotePorts.size() == 1 && rule.localPorts.size() == 1 &&
              rule.remotePorts[0].from == kRemotePort && rule.localPorts[0].from == kLocalPort,
          "смена TCP на UDP потеряла совместимые условия портов");
    rule.SetProto(Proto::Icmp);
    Check(!(rule.conds & (CondRemotePort | CondLocalPort)) &&
              rule.remotePorts.empty() && rule.localPorts.empty(),
          "переход на ICMP сохранил несовместимые порты");
    rule.icmpTypes = {{8, -1}};
    rule.conds |= CondIcmpType;
    rule.SetProto(Proto::Tcp);
    Check(!(rule.conds & CondIcmpType) && rule.icmpTypes.empty(),
          "переход на TCP сохранил несовместимые типы ICMP");
    rule = OutboundRule(Proto::Tcp, kEndpointConds);
    rule.SetProto(Proto::Tcp, false);
    Check(!rule.protoFixed() && !(rule.conds & (CondRemotePort | CondLocalPort)) &&
              rule.remotePorts.empty() && rule.localPorts.empty(),
          "выбор любого протокола сохранил несовместимые порты");
    Check((rule.conds & (CondRemoteAddr | CondLocalAddr | CondDirection)) ==
                  (CondRemoteAddr | CondLocalAddr | CondDirection) &&
              rule.remoteAddrs.size() == 1 && rule.localAddrs.size() == 1,
          "смена протокола потеряла независимые условия");
}

void TestIcmpTypeListParsing() {
    struct Case {
        const wchar_t* text;
        std::vector<IcmpTypeItem> expected;
    };
    const Case valid[] = {
        { L"", {} },
        { L" \t\r\n", {} },
        { L"0", {{0, -1}} },
        { L"255", {{255, -1}} },
        { L"8", {{8, -1}} },
        { L"0:0", {{0, 0}} },
        { L"3:0", {{3, 0}} },
        { L"3:1", {{3, 1}} },
        { L"255:255", {{255, 255}} },
        { L" 003 \t: 001 ", {{3, 1}} },
        { L"8, 3:1, 11:0, 128", {{8, -1}, {3, 1}, {11, 0}, {128, -1}} },
        { L",,8,,3:1,,", {{8, -1}, {3, 1}} },
    };
    for (const Case& test : valid) {
        std::vector<IcmpTypeItem> parsed = {{99, 99}};
        std::wstring error;
        Check(RuleDialogs::ParseIcmpTypeList(test.text, parsed, error),
              "корректный список типов ICMP отклонён");
        Check(parsed.size() == test.expected.size(),
              "список типов ICMP получил неверное число элементов");
        for (size_t i = 0; i < parsed.size(); ++i)
            Check(parsed[i].type == test.expected[i].type &&
                      parsed[i].code == test.expected[i].code,
                  "список типов ICMP получил неверный тип или код");
    }

    const std::wstring invalid[] = {
        L"abc", L"8junk", L"8;3", L"1e2", L"0x08", L"8.0", L"8 1",
        L"+8", L"-1", L"256", L"2147483648", L"4294967296",
        L"999999999999999999999999999999",
        L"3:abc", L"3:1junk", L"3:1:2", L":1", L":", L" : 1 ",
        L"3:", L"3: \t", L"3:+1", L"3:-1", L"3:256", L"3:1e2",
        L"3:0x01", L"3:1.0", L"3:1 2", L"8, 3:abc",
        L"3:999999999999999999999999999999",
        L"999999999999999999999999999999:0",
        std::wstring(L"8\0junk", 6), std::wstring(L"3:1\0junk", 8),
    };
    for (const std::wstring& text : invalid) {
        std::vector<IcmpTypeItem> parsed;
        std::wstring error;
        Check(!RuleDialogs::ParseIcmpTypeList(text, parsed, error),
              "некорректный список типов ICMP принят");
        Check(!error.empty(), "для некорректного типа или кода ICMP не задана ошибка");
    }

    std::vector<IcmpTypeItem> parsed;
    std::wstring error;
    Check(!RuleDialogs::ParseIcmpTypeList(L"3:", parsed, error) &&
              error == LoadStringRes(IDS_RDI_ERR_NO_CODE) + L"3:",
          "потеряно сообщение об отсутствующем коде ICMP");
}

void TestIpv6AddressParsing() {
    struct Case {
        const wchar_t* text;
        int prefix;
        const wchar_t* address;
    };
    const Case valid[] = {
        { L"2001:db8::1", -1, L"2001:db8::1" },
        { L" ::1 \t", -1, L"::1" },
        { L"2001:db8::1/0", 0, L"::" },
        { L"2001:db8::1/64", 64, L"2001:db8::" },
        { L"2001:db8::1/128", 128, L"2001:db8::1" },
        { L" 2001:db8::1 \t/ 064 ", 64, L"2001:db8::" },
        { L"fe80::abcd/10", 10, L"fe80::" },
        { L"2001:db8::ffff/127", 127, L"2001:db8::fffe" },
        { L"::/0", 0, L"::" },
        { L"::ffff:192.0.2.1/128", 128, L"::ffff:192.0.2.1" },
    };
    for (const Case& test : valid) {
        AddrItem parsed;
        Check(RuleDialogs::ParseIpv6Address(test.text, parsed),
              "корректный IPv6-адрес или префикс отклонён");
        IpAddr expected;
        Check(ParseIpAddr(test.address, expected), "неверный эталон IPv6-адреса");
        Check(parsed.addr == expected && parsed.prefix == test.prefix && !parsed.isMacro(),
              "разбор IPv6-адреса изменил адрес или префикс");
    }

    for (unsigned prefix = 0; prefix <= 128; ++prefix) {
        AddrItem parsed;
        Check(RuleDialogs::ParseIpv6Address(L"2001:db8::1/" + std::to_wstring(prefix), parsed) &&
                  parsed.prefix == static_cast<int>(prefix),
              "допустимая длина префикса IPv6 отклонена или изменена");
    }

    const std::wstring invalid[] = {
        L"2001:db8::1/abc", L"2001:db8::1/", L"2001:db8::1/ \t",
        L"2001:db8::1/64junk", L"2001:db8::1/64/32", L"2001:db8::1//64",
        L"2001:db8::1/+64", L"2001:db8::1/-1", L"2001:db8::1/-64",
        L"2001:db8::1/129", L"2001:db8::1/256", L"2001:db8::1/2147483648",
        L"2001:db8::1/4294967296", L"2001:db8::1/999999999999999999999999999999",
        L"2001:db8::1/64.5", L"2001:db8::1/6e1", L"2001:db8::1/0x40",
        L"2001:db8::1/6 4", L"", L" \t", L"/64", L"not-ip/64",
        L"192.0.2.1", L"192.0.2.1/24",
        std::wstring(L"2001:db8::1/64") + L'\0' + L"junk",
    };
    const IpAddr sentinel = V6(7);
    for (const std::wstring& text : invalid) {
        AddrItem parsed{sentinel, 128};
        Check(!RuleDialogs::ParseIpv6Address(text, parsed),
              "некорректный IPv6-адрес или префикс принят");
        Check(parsed.addr == sentinel && parsed.prefix == 128 && !parsed.isMacro(),
              "ошибка разбора IPv6 изменила выходной адрес");
    }

    IpAddr inside, outside;
    Check(ParseIpAddr(L"2001:db8::ffff", inside) &&
              ParseIpAddr(L"2001:db8:ffff::42", outside),
          "не удалось подготовить адреса для проверки подсети IPv6");
    AddrItem subnet;
    Check(RuleDialogs::ParseIpv6Address(L"2001:db8::1/64", subnet) &&
              subnet.Matches(inside) && !subnet.Matches(outside),
          "IPv6-подсеть расширилась за пределы заданного префикса");
    Check(RuleDialogs::ParseIpv6Address(L"2001:db8::1/0", subnet) &&
              subnet.Matches(inside) && subnet.Matches(outside),
          "явно заданный нулевой префикс IPv6 потерял смысл");
}

void TestServiceRefreshNotifications() {
    Check(ServiceInfo::RequestRefresh() == 0 && ServiceInfo::RefreshComplete(0),
          "выключенный монитор SCM создал незавершаемый запрос");
    Check(ServiceInfo::Version(true) != 0, "не удалось подготовить полный снимок SCM");
    HWND window = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                                  HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
    Check(window != nullptr, "не удалось создать окно уведомлений SCM");
    constexpr UINT message = WM_APP + 100;
    ServiceInfo::SetNotification(window, message);
    ServiceInfo::SetMonitoring(true);
    uint64_t previous = 0;
    for (unsigned round = 0; round < 4; ++round) {
        MSG notification{};
        while (PeekMessageW(&notification, window, message, message, PM_REMOVE)) {}
        const uint64_t ticket = ServiceInfo::RequestRefresh();
        Check(ticket > previous, "новый запрос SCM подтвердился прежним опросом");
        bool notified = false;
        const ULONGLONG deadline = GetTickCount64() + 5000;
        while (GetTickCount64() < deadline) {
            while (PeekMessageW(&notification, window, message, message, PM_REMOVE))
                notified = true;
            if (ServiceInfo::RefreshComplete(ticket) && notified) break;
            Sleep(1);
        }
        // Проверяется настоящий worker, включая уведомление о полном опросе
        // при неизменном наборе служб, а не только управляемый снимок Ask-теста.
        Check(ServiceInfo::RefreshComplete(ticket) && notified,
              "фоновый опрос SCM не подтвердил ticket либо не уведомил UI");
        previous = ticket;
    }
    ServiceInfo::SetMonitoring(false);
    ServiceInfo::SetNotification(nullptr, 0);
    DestroyWindow(window);
    Check(ServiceInfo::RequestRefresh() == 0, "приостановленный монитор SCM принял запрос");
    ServiceInfo::Shutdown();
}

} // анонимное пространство имён

#include "firewallxndisfilter_rule_tests.h"
#include "rule_inheritance_tests.h"
#include "wfp_flags_tests.h"

int main() {
    TestWfpConditionFlagMatching();
    TestWfpConditionFlagPersistence();
    TestWfpConditionFlagText();
    TestRuleInheritance();
    TestNdisRuleGroup();
    TestNdisRulePersistence();
    TestNoCaseTextHelpers();
    TestUnicodeServiceNames();
    TestServiceWildcards();
    TestUnicodeAppPaths();
    TestProtocolTokenParsing();
    TestIpv6AddressParsing();
    TestAddressDuplicates();
    TestRuleProtocolChanges();
    TestIcmpTypeListParsing();
    TestRuleSaveErrorResources();
    TestPortListErrorResources();
    TestPortListParsing();
    TestTcpReverseFlow();
    TestUdpReverseFlow();
    TestReverseFlowWithOmittedFields();
    TestEmptyListsRemainWildcards();
    TestOnlyTcpAndUdpAreReversed();
    TestAnyProtocolRuleIsNotReversed();
    TestBlockRulesAreNotReversed();
    TestPortAddressMatrix();
    TestEndpointRulePriority();
    TestPostAppScopeAndPriority();
    TestPostAppPidFilter();
    TestPostAppPidTextAndLinks();
    TestPostAppPidDatabase();
    TestNumericLookupHashes();
    TestSharedRuleNames();
    TestSharedRuleNamesDatabase();
    TestCandidateRemotePortBounds();
    TestCandidateProtocolDirectionMatrix();
    TestCandidateIndexUpdates();
    TestReverseFlowIndexUpdates();
    TestRuleIdIndexUpdates();
    TestRemoveMissingApps();
    TestRuleIdDatabaseLoading();
    TestRuleDatabaseCommitFailure();
    TestRuleDatabaseLoadErrors();
    TestIpPrefixEquivalence();
    TestMacroPrefixMatching();
    TestServiceRefreshNotifications();
    std::cout << "Rule matching tests passed\n";
    return 0;
}
