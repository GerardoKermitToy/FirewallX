#pragma once
#include "Rules.h"

// Числа — часть формата settings.db: порядок меню можно менять, значения нельзя.
enum class FirewallPolicy : uint8_t {
    BlockAll = 0,
    Block = 1,
    Learning = 2,
    Allow = 3,
    AllowAll = 4,
};

namespace FirewallPolicies {

struct Def {
    FirewallPolicy policy;
    UINT nameId;
    UINT descriptionId;
};

const Def* All(size_t& count);
bool IsValid(FirewallPolicy policy);
bool UsesRules(FirewallPolicy policy);
std::wstring Name(FirewallPolicy policy);
std::wstring Description(FirewallPolicy policy);

struct Decision {
    bool decided = false;             // false — нужен интерактивный запрос
    RuleAction action = RuleAction::Allow;
    bool matchedRule = false;         // только такие решения попадают в кеш правил
    bool preferredInterfaceBlocked = false; // блокировка из-за ограничения интерфейса приложения
    bool autoAllowedIcmp = false;     // техническое исключение без совпавшего правила
    uint64_t rulesVersion = 0;
};

// Одна логика для новых событий и уже припаркованных обязательств. Крайние
// политики обходят правила; остальные сохраняют порядок Interface / Global / App / PostApp.
// Технические ICMP-исключения в Learning действуют только после промаха
// правил: они разрешают соединение без интерактивного запроса.
Decision Evaluate(FirewallPolicy policy, const RuleStore* rules,
                  const MatchQuery& query,
                  RuleNameRef* matchedRuleName = nullptr,
                  bool allowIcmpExceptions = false,
                  std::shared_ptr<const std::wstring>* unmatchedInterfaceName = nullptr);

} // namespace FirewallPolicies

namespace FirewallPolicySetting {
FirewallPolicy Load();                // нет записи или значение неизвестно -> Learning
bool Save(FirewallPolicy policy);
}
