#pragma once
#include "AskQueue.h"

namespace RulePresets {

struct Choice {
    UINT titleId = 0;
    std::wstring title;
    std::vector<Rule> rules;
};

// Только предустановки, подходящие приложению, службе или PID 0 и самому соединению.
// «Другие...» добавляет окно запроса, а не каталог сетевых правил.
std::vector<Choice> Suggest(const AskRequest& request);

// Добавляет недостающие правила одной операцией. Имена, порядок и выключенные
// условия не участвуют в поиске дубликатов; найденное выключенное правило включается.
size_t Apply(RuleStore& store, const AskRequest& request,
             const std::vector<Rule>& rules);

// Применяет выбранные в Ask условия к актуальному источнику правил, даже если
// за время показа окна изменился эффективный предок приложения.
size_t ApplySelected(RuleStore& store, const AskRequest& request, std::vector<Rule> rules);

// Полные шаблоны для обнаруженных файлов и проверенных установленных служб.
// Условия конкретного соединения и резервное правило для всего svchost не используются.
std::vector<std::wstring> Executables();
bool ExcludedFromGeneration(std::wstring_view path);
bool MayUseService(std::wstring_view executable, std::wstring_view service);
std::vector<Rule> Generate(const std::wstring& path, const std::vector<ServiceEntry>& services);
// Системные правила IGMP для PID 0 не связаны с исполняемым файлом.
std::vector<Rule> GenerateIgmp();

// Добавляет только отсутствующие правила, не меняя выключенные пользователем.
size_t ApplyGenerated(RuleStore& store, std::vector<Rule> rules);

} // namespace RulePresets
