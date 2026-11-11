#include "FirewallPolicy.h"
#include "StringRes.h"

namespace {

const FirewallPolicies::Def kPolicies[] = {
    { FirewallPolicy::BlockAll, IDS_POLICY_BLOCK_ALL, IDS_POLICY_BLOCK_ALL_DESC },
    { FirewallPolicy::Block, IDS_POLICY_BLOCK, IDS_POLICY_BLOCK_DESC },
    { FirewallPolicy::Learning, IDS_POLICY_LEARNING, IDS_POLICY_LEARNING_DESC },
    { FirewallPolicy::Allow, IDS_POLICY_ALLOW, IDS_POLICY_ALLOW_DESC },
    { FirewallPolicy::AllowAll, IDS_POLICY_ALLOW_ALL, IDS_POLICY_ALLOW_ALL_DESC },
};

const FirewallPolicies::Def& Definition(FirewallPolicy policy) {
    for (const auto& def : kPolicies)
        if (def.policy == policy) return def;
    return kPolicies[2];
}

bool AutoAcceptIcmp(const MatchQuery& query) {
    if (query.icmpType < 0 || query.icmpType > 255 ||
        query.icmpCode < 0 || query.icmpCode > 255)
        return false;

    if (query.proto == Proto::Icmp) {
        switch (query.icmpType) {
        case 3:
            return query.icmpCode <= 15;
        case 11:
            return query.icmpCode == 0 || query.icmpCode == 1;
        case 12:
            return query.icmpCode <= 2;
        default:
            return false;
        }
    }
    if (query.proto == Proto::IcmpV6) {
        switch (query.icmpType) {
        case 1:
            return query.icmpCode <= 6;
        case 2:
            return query.icmpCode == 0;
        case 3:
            return query.icmpCode == 0 || query.icmpCode == 1;
        case 4:
            return query.icmpCode <= 2;
        case 130:
        case 131:
        case 132:
        case 133:
        case 134:
        case 135:
        case 136:
        case 137:
        case 143:
            return true;
        default:
            return false;
        }
    }
    return false;
}

bool IsLocalTraffic(const IpAddr& remote) {
    // Исключение относится к обмену внутри компьютера, а не ко всей LAN.
    // Для IPv4 разрешается весь 127.0.0.0/8, для IPv6 — ::1; собственные
    // адреса интерфейсов берутся из обновляемого снимка сетевой конфигурации.
    return remote.isLoopback() ||
           AddrMacros::Matches(AddrMacro::MyComputer, remote);
}

} // namespace

namespace FirewallPolicies {

const Def* All(size_t& count) {
    count = std::size(kPolicies);
    return kPolicies;
}

bool IsValid(FirewallPolicy policy) {
    return static_cast<unsigned>(policy) <=
           static_cast<unsigned>(FirewallPolicy::AllowAll);
}

bool UsesRules(FirewallPolicy policy) {
    return policy != FirewallPolicy::BlockAll &&
           policy != FirewallPolicy::AllowAll;
}

std::wstring Name(FirewallPolicy policy) {
    return LoadStringRes(Definition(policy).nameId);
}

std::wstring Description(FirewallPolicy policy) {
    return LoadStringRes(Definition(policy).descriptionId);
}

Decision Evaluate(FirewallPolicy policy, const RuleStore* rules,
                  const MatchQuery& query, RuleNameRef* matchedRuleName,
                  bool allowIcmpExceptions,
                  std::shared_ptr<const std::wstring>* unmatchedInterfaceName) {
    if (!IsValid(policy)) [[unlikely]] policy = FirewallPolicy::Learning;
    if (matchedRuleName) matchedRuleName->reset();

    Decision result;
    if (policy == FirewallPolicy::BlockAll || policy == FirewallPolicy::AllowAll) {
        if (rules && rules->PreferredInterfaceBlocked(query, result.rulesVersion)) {
            result.decided = true;
            result.action = RuleAction::Block;
            result.preferredInterfaceBlocked = true;
            return result;
        }
        if (!rules) result.rulesVersion = 0;
        result.decided = true;
        result.action = policy == FirewallPolicy::AllowAll ||
                        IsLocalTraffic(query.remoteAddr)
            ? RuleAction::Allow : RuleAction::Block;
        return result;
    }

    if (rules) {
        result.matchedRule = rules->MatchVerdict(
            query, result.action, result.rulesVersion, matchedRuleName,
            policy == FirewallPolicy::Learning ? unmatchedInterfaceName : nullptr,
            &result.preferredInterfaceBlocked);
        if (result.matchedRule) {
            result.decided = true;
            return result;
        }
    }

    if (allowIcmpExceptions && AutoAcceptIcmp(query)) {
        result.decided = true;
        result.action = RuleAction::Allow;
        result.autoAllowedIcmp = true;
        return result;
    }

    if (policy != FirewallPolicy::Learning) {
        result.decided = true;
        result.action = policy == FirewallPolicy::Allow
            ? RuleAction::Allow : RuleAction::Block;
    }
    return result;
}

} // namespace FirewallPolicies
