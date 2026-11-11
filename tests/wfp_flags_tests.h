#pragma once

namespace {
void TestWfpConditionFlagMatching() {
    const uint32_t masks[] = {0, 1, 3, 4, 0x14u, 0x02000180u, 0x80000000u, UINT32_MAX};
    for (RuleScope scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp,
                            RuleScope::Interface}) {
        RuleStore store;
        for (Proto proto : {Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::IcmpV6,
                            ProtoFromNumber(144)})
        for (RuleAction expected : {RuleAction::Allow, RuleAction::Block})
        for (uint32_t mask : masks) {
            store.Clear();
            Rule rule;
            rule.scope = scope;
            rule.appPath = scope == RuleScope::Interface ? TestInterface().name : kAppPath;
            rule.conds = CondProto | CondWfpFlags;
            rule.proto = proto;
            rule.conditionFlags = mask;
            rule.action = expected;
            store.Add(rule);
            MatchQuery query = Query(proto, Dir::Out);
            query.interfaceIndex = TestInterface().number;
            for (std::optional<uint32_t> flags : {std::optional<uint32_t>{},
                    std::optional<uint32_t>{0}, std::optional<uint32_t>{1},
                    std::optional<uint32_t>{2}, std::optional<uint32_t>{mask},
                    std::optional<uint32_t>{mask | 0x40000000u},
                    std::optional<uint32_t>{mask & (mask - 1)},
                    std::optional<uint32_t>{UINT32_MAX}}) {
                query.conditionFlags = flags;
                const bool matches = flags && (*flags & mask) == mask;
                Rule found;
                RuleMatchInfo info;
                RuleAction action = expected == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow;
                Check(store.Match(query, found) == matches &&
                          store.MatchInfo(query, info) == matches &&
                          store.MatchVerdict(query, action) == matches &&
                          RuleStore::MatchesRule(rule, query) == matches &&
                          RuleStore::MatchesRuleConditions(rule, query) == matches,
                      "WFP condition flags must contain all required bits in every matcher");
                if (matches)
                    Check(found.id == rule.id && info.id == rule.id && action == expected,
                          "WFP condition flag match lost its rule or action");
            }
            // Даже подставленная маска не превращает событие Hyper-V в WFP.
            query.source = TrafficSource::Ndis;
            query.conditionFlags = UINT32_MAX;
            Rule found;
            Check(!store.Match(query, found) && !RuleStore::MatchesRule(rule, query) &&
                      !RuleStore::MatchesRuleConditions(rule, query),
                  "WFP flag filter matched a Hyper-V event, including an empty required mask");
            query.source = TrafficSource::Host;
            query.conditionFlags.reset();
            rule.conds &= ~CondWfpFlags;
            Check(store.Update(rule) && store.Match(query, found) &&
                      RuleStore::MatchesRule(rule, query),
                  "unchecked WFP flag condition still constrained matching");
        }
    }

    const FlowKey key = MakeFlowKey(Proto::Udp, kLocal, kRemote, kLocalPort, kRemotePort);
    Check(!MakeMatchQuery(kAppPath, 1000, key, Dir::Out).conditionFlags &&
              MakeMatchQuery(kAppPath, 1000, key, Dir::Out, -1, -1, nullptr, 0).conditionFlags == 0u,
          "query construction confused a missing flags field with a zero WFP mask");
}

void TestWfpConditionFlagPersistence() {
    RuleDb database;
    std::wstring error;
    Check(database.Open(L":memory:", error), "cannot open WFP flag test database");
    std::vector<Rule> original;
    for (RuleScope scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp,
                            RuleScope::Interface})
    for (uint32_t mask : {0u, 1u, 3u, 4u, 0x14u, 0x80000000u, UINT32_MAX})
    for (bool enabled : {false, true}) {
        Rule rule;
        rule.id = original.size() + 1;
        rule.scope = scope;
        rule.appPath = scope == RuleScope::Interface ? TestInterface().name : kAppPath;
        rule.conds = enabled ? CondWfpFlags : CondNone;
        rule.conditionFlags = mask;
        NormalizeRuleConds(rule);
        Check(rule.conditionFlags == mask && bool(rule.conds & CondWfpFlags) == enabled,
              "normalization truncated WFP flags or removed the condition");
        original.push_back(rule);
    }
    Check(database.SaveAll(original, error), "cannot save WFP flags");
    std::vector<Rule> loaded;
    uint64_t maxId = 0;
    Check(database.Load(loaded, maxId, error) && loaded.size() == original.size() &&
              maxId == original.size(), "cannot reload WFP flag rules");
    for (const Rule& rule : loaded) {
        const Rule& before = original.at(static_cast<size_t>(rule.id - 1));
        Check(rule.conditionFlags == before.conditionFlags && rule.conds == before.conds,
              "SQLite lost WFP flag bits or a disabled condition's prefill");
        RuleClipboard::Set(rule);
        Rule copied;
        Check(RuleClipboard::Get(copied) && copied.conditionFlags == rule.conditionFlags &&
                  copied.conds == rule.conds, "clipboard lost WFP flags");
    }
}

void TestWfpConditionFlagText() {
    const UiLang previous = CurrentUiLang();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t index = 0; index < count; ++index) {
        SetUiLang(languages[index].lang);
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondWfpFlags;
        rule.conditionFlags = 1u | 0x80000000u;
        const std::wstring known = WfpConditionFlagText(0);
        const std::wstring unknown = WfpConditionFlagText(31);
        Check(known == L"FWP_CONDITION_FLAG_IS_LOOPBACK" &&
                  WfpConditionFlagText(4) == L"FWP_CONDITION_FLAG_IS_RAW_ENDPOINT" &&
                  unknown.find(L"80000000") != std::wstring::npos &&
                  rule.ConditionFlagsText().find(known) != std::wstring::npos &&
                  rule.ConditionFlagsText().find(unknown) != std::wstring::npos &&
                  rule.BuildAutoName().find(known) != std::wstring::npos &&
                  RuleExplainMarkup(rule).find(L"id=\"wfpflags\"") != std::wstring::npos,
              "WFP flag names, unknown bits or explanation link are missing");
        const std::wstring text = rule.ConditionFlagsText();
        rule.conditionFlags |= 0x00000004;
        Check(rule.ConditionFlagsText() == text &&
                  rule.BuildAutoName().find(L"REAUTHORIZE") == std::wstring::npos &&
                  RuleExplainMarkup(rule).find(L"REAUTHORIZE") == std::wstring::npos,
              "REAUTHORIZE leaked into displayed WFP flags");
        for (uint32_t mask : {0u, 4u}) {
            rule.conditionFlags = mask;
            Check(rule.ConditionFlagsText() == LoadStringRes(IDS_WFP_FLAGS_NONE),
                  "hidden REAUTHORIZE is displayed as a selected flag");
        }
        for (unsigned bit = 0; bit < 32; ++bit)
            Check(WfpConditionFlagText(bit).empty() == (bit == 2),
                  "a selectable WFP flag has no label or REAUTHORIZE is visible");
    }
    SetUiLang(previous);
}
} // namespace
