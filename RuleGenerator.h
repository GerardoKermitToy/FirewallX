#pragma once

#include "FileSignature.h"
#include "Rules.h"
#include "ServiceInfo.h"

#include <atomic>
#include <functional>
#include <vector>

namespace RuleGenerator {

// Дескрипторы сохраняются до добавления правил, чтобы проверенные файлы
// нельзя было заменить между проверкой подписи и применением результата.
struct Result {
    std::vector<Rule> rules;
    std::vector<FileSignature::TrustedFile> files;
    bool cancelled = false;
};

using Progress = std::function<void(size_t completed, size_t total)>;

struct ServiceCandidate {
    ServiceEntry entry;
    std::wstring image;
    std::wstring dll;
};

// Ищет ServiceDll в Parameters и, при его отсутствии, в самом ключе службы.
std::wstring ReadServiceDll(HKEY root, const std::wstring& serviceKey);

// Проверяет уже найденные файлы и создаёт полный набор шаблонов.
Result VerifyCandidates(const std::vector<std::wstring>& paths,
                        const std::vector<ServiceCandidate>& services,
                        const std::atomic_bool& cancel, const Progress& progress);

// Однократный ограниченный поиск без обхода дисков и фонового опроса.
Result Scan(const std::atomic_bool& cancel, const Progress& progress);

} // namespace RuleGenerator
