#include "RulePresets.h"
#include "RulePresetsData.h"
#include "StringRes.h"
#include "SystemInfo.h"

#include <algorithm>
#include <utility>

namespace RulePresets {
namespace {

bool Listed(std::wstring_view list, std::wstring_view value) {
    while (!list.empty()) {
        const size_t end = list.find(L';');
        if (EqualNoCase(list.substr(0, end), value)) return true;
        if (end == std::wstring_view::npos) break;
        list.remove_prefix(end + 1);
    }
    return false;
}

std::wstring_view ListedService(std::wstring_view list, std::wstring_view value) {
    while (!list.empty()) {
        const size_t end = list.find(L';');
        const std::wstring_view pattern = list.substr(0, end);
        if (ServiceNameMatches(pattern, value)) return pattern;
        if (end == std::wstring_view::npos) break;
        list.remove_prefix(end + 1);
    }
    return {};
}

std::wstring_view FileName(std::wstring_view path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring_view::npos ? path : path.substr(slash + 1);
}

bool BuildAddresses(std::span<const Data::Address> addresses, std::vector<AddrItem>& items) {
    for (const Data::Address& address : addresses) {
        AddrItem item;
        item.macro = address.macro;
        item.prefix = address.prefix;
        if (address.ip) {
            if (!ParseIpAddr(address.ip, item.addr)) return false;
            if (item.prefix >= 0) ApplyPrefix(item.addr, item.prefix, false);
        } else if (!item.isMacro()) {
            return false;
        }
        items.push_back(item);
    }
    return true;
}

std::vector<ServiceItem> BuildServiceGroup(std::wstring_view names,
                                           std::span<const ServiceEntry> hosted) {
    std::vector<ServiceItem> result;
    while (!names.empty()) {
        const size_t end = names.find(L';');
        const std::wstring_view name = names.substr(0, end);
        if (name.empty()) return {};
        ServiceItem item;
        item.name = name;
        const auto found = std::find_if(hosted.begin(), hosted.end(),
            [&](const ServiceEntry& entry) { return EqualNoCase(entry.name, name); });
        if (found != hosted.end()) item.display = found->display;
        result.push_back(std::move(item));
        if (end == std::wstring_view::npos) break;
        names.remove_prefix(end + 1);
    }
    return result;
}

bool BuildRule(const AskRequest& request, const Data::Preset& preset,
               const Data::NetworkRule& network, const ServiceItem* service,
               std::span<const ServiceItem> serviceGroup, Rule& rule) {
    if (preset.host == Data::Host::PostAppPidZero) {
        rule.scope = RuleScope::PostApp;
        rule.appName = LoadStringRes(IDS_RULE_POSTAPP_APP);
        rule.conds |= CondPidZero;
    } else {
        rule.scope = RuleScope::App;
        rule.appPath = request.appPath;
        rule.appName = request.appName;
    }
    rule.autoName = false;
    const std::wstring title = LoadStringRes(preset.titleId);
    const std::wstring name = LoadStringRes(network.nameId);
    rule.name = service
        ? LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT,
            title.c_str(), service->name.c_str(), name.c_str())
        : LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), name.c_str());
    rule.action = network.action;
    rule.SetProto(network.proto);
    rule.dir = network.dir;
    if (network.dir != Dir::Unknown) rule.conds |= CondDirection;
    rule.remotePorts.assign(network.remotePorts.begin(), network.remotePorts.end());
    rule.localPorts.assign(network.localPorts.begin(), network.localPorts.end());
    rule.icmpTypes.assign(network.icmpTypes.begin(), network.icmpTypes.end());
    if (!rule.remotePorts.empty()) rule.conds |= CondRemotePort;
    if (!rule.localPorts.empty()) rule.conds |= CondLocalPort;
    if (!rule.icmpTypes.empty()) rule.conds |= CondIcmpType;
    if (!BuildAddresses(network.remoteAddresses, rule.remoteAddrs) ||
        !BuildAddresses(network.localAddresses, rule.localAddrs)) return false;
    if (!rule.remoteAddrs.empty()) rule.conds |= CondRemoteAddr;
    if (!rule.localAddrs.empty()) rule.conds |= CondLocalAddr;
    if (service) {
        rule.conds |= CondService;
        rule.services.push_back(ServiceItem{ service->name, service->display });
    } else if (!serviceGroup.empty()) {
        rule.conds |= CondService;
        rule.services.assign(serviceGroup.begin(), serviceGroup.end());
    }
    NormalizeRuleConds(rule);
    return true;
}

void AppendRules(std::vector<Rule>& result, const AskRequest& request,
                 const Data::Preset& preset, const ServiceItem* service,
                 std::span<const ServiceItem> group) {
    std::vector<Rule> choice;
    for (const Data::NetworkRule& network : preset.rules) {
        Rule rule;
        if (!BuildRule(request, preset, network, service, group, rule)) return;
        choice.push_back(std::move(rule));
    }
    result.insert(result.end(), std::make_move_iterator(choice.begin()),
                  std::make_move_iterator(choice.end()));
}

template <class T>
void SortUnique(std::vector<T>& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

std::vector<std::wstring> AddressKeys(const std::vector<AddrItem>& addresses) {
    std::vector<std::wstring> keys;
    for (AddrItem item : addresses) {
        if (!item.isMacro()) {
            if (item.prefix < 0) item.prefix = static_cast<int>(item.addr.len()) * 8;
            ApplyPrefix(item.addr, item.prefix, false);
        }
        keys.push_back(item.Token());
    }
    SortUnique(keys);
    return keys;
}

using PortRanges = std::vector<std::pair<uint16_t, uint16_t>>;
PortRanges PortKeys(const std::vector<PortItem>& ports) {
    PortRanges sorted;
    for (const PortItem& port : ports) sorted.emplace_back(port.from, port.to);
    std::sort(sorted.begin(), sorted.end());
    PortRanges merged;
    for (const auto& range : sorted) {
        if (!merged.empty() && static_cast<unsigned>(range.first) <=
                               static_cast<unsigned>(merged.back().second) + 1) {
            merged.back().second = std::max(merged.back().second, range.second);
        } else {
            merged.push_back(range);
        }
    }
    return merged;
}

std::vector<std::wstring> ServiceKeys(const std::vector<ServiceItem>& services) {
    std::vector<std::wstring> keys;
    for (const ServiceItem& service : services) keys.push_back(FoldCaseCopy(service.name));
    SortUnique(keys);
    return keys;
}

std::vector<std::pair<uint8_t, int>> IcmpKeys(const std::vector<IcmpTypeItem>& types) {
    std::vector<std::pair<uint8_t, int>> keys;
    for (const IcmpTypeItem& type : types) {
        // Любой код типа поглощает более узкие записи того же типа.
        if (type.code >= 0 && std::any_of(types.begin(), types.end(),
            [&](const IcmpTypeItem& item) { return item.type == type.type && item.code < 0; }))
            continue;
        keys.emplace_back(type.type, type.code < 0 ? -1 : type.code);
    }
    SortUnique(keys);
    return keys;
}

uint32_t MeaningfulConds(const Rule& rule) {
    uint32_t conds = EffectiveRuleConds(rule);
    if (rule.remoteAddrs.empty()) conds &= ~CondRemoteAddr;
    if (rule.localAddrs.empty()) conds &= ~CondLocalAddr;
    if (rule.remotePorts.empty()) conds &= ~CondRemotePort;
    if (rule.localPorts.empty()) conds &= ~CondLocalPort;
    if (rule.icmpTypes.empty()) conds &= ~CondIcmpType;
    // Пустой CondService означает «любой процесс со службой», а не wildcard.
    return conds;
}

bool SameRule(const Rule& a, const Rule& b) {
    if (a.scope != b.scope || !EqualNoCase(a.appPath, b.appPath) || a.action != b.action)
        return false;
    const uint32_t conds = MeaningfulConds(a);
    if (conds != MeaningfulConds(b)) return false;
    if ((conds & CondProto) && a.proto != b.proto) return false;
    if ((conds & CondDirection) && a.dir != b.dir) return false;
    if ((conds & CondInterface) && a.interfaceName != b.interfaceName) return false;
    if ((conds & CondWfpFlags) && a.conditionFlags != b.conditionFlags) return false;
    if ((conds & CondRemoteAddr) && AddressKeys(a.remoteAddrs) != AddressKeys(b.remoteAddrs))
        return false;
    if ((conds & CondLocalAddr) && AddressKeys(a.localAddrs) != AddressKeys(b.localAddrs))
        return false;
    if ((conds & CondRemotePort) && PortKeys(a.remotePorts) != PortKeys(b.remotePorts))
        return false;
    if ((conds & CondLocalPort) && PortKeys(a.localPorts) != PortKeys(b.localPorts))
        return false;
    if ((conds & CondIcmpType) && IcmpKeys(a.icmpTypes) != IcmpKeys(b.icmpTypes))
        return false;
    if ((conds & CondService) && ServiceKeys(a.services) != ServiceKeys(b.services))
        return false;
    return true;
}

} // анонимное пространство имён

std::vector<Choice> Suggest(const AskRequest& request) {
    std::vector<Choice> choices;
    if (request.ownerAmbiguous) return choices;
    const bool postAppPidZero = request.key.source == TrafficSource::Host &&
        request.appPath.empty() && request.pid == 0;
    if (request.appPath.empty() && !postAppPidZero) return choices;
    const std::wstring_view executable = FileName(request.appPath);
    const bool svchost = EqualNoCase(executable, L"svchost.exe");
    const bool systemImage = EqualNoCase(request.appPath, SystemDirFile(
        svchost ? L"svchost.exe" : L"spoolsv.exe"));
    // Сторонние службы и группы системных служб допускаются только по
    // явным записям каталога. Обычные системные службы по-прежнему требуют
    // путь svchost/spoolsv из System32.
    const bool serviceApp = std::any_of(std::begin(Data::presets), std::end(Data::presets),
        [&](const Data::Preset& preset) {
            return preset.host == Data::Host::AppService && Listed(preset.executables, executable);
        });
    const bool serviceGroupApp = std::any_of(std::begin(Data::presets), std::end(Data::presets),
        [&](const Data::Preset& preset) {
            return preset.host == Data::Host::SystemServiceGroup && Listed(preset.executables, executable);
        });
    const bool systemGroupImage = serviceGroupApp && EqualNoCase(request.appPath,
        SystemDirFile(std::wstring(executable).c_str()));

    // SCM знает состав процесса, но не владельца отдельного пакета. Несколько
    // служб — не повод угадать одну по порту. Для явно указанной группы
    // разрешаем только процессы, все службы которых входят в этот список.
    // Без живого исходного дескриптора нельзя доверять повторно занятому PID.
    ServiceInfo::HostedServices hosted;
    const ServiceEntry* service = nullptr;
    if ((systemImage || serviceApp || systemGroupImage) && request.process &&
        request.process->pid == request.pid && request.process->alive()) {
        hosted = ServiceInfo::ServicesOfPid(request.pid, true);
        if (hosted && hosted->size() == 1 && hosted->front().pid == request.pid)
            service = &hosted->front();
    }

    const MatchQuery query = request.ToQuery();
    for (const Data::Preset& preset : Data::presets) {
        if (preset.host == Data::Host::PostAppPidZero) {
            if (!postAppPidZero || (request.dir != Dir::Out && request.dir != Dir::In)) continue;
        } else if (request.appPath.empty() || !Listed(preset.executables, executable)) {
            continue;
        }
        const bool servicePreset = preset.host == Data::Host::Service ||
                                   preset.host == Data::Host::AppService;
        const bool groupPreset = preset.host == Data::Host::SystemServiceGroup;
        std::vector<ServiceItem> serviceGroup;
        ServiceItem serviceCondition;
        if (servicePreset) {
            if (!service) continue;
            const std::wstring_view pattern = ListedService(preset.services, service->name);
            if (pattern.empty()) continue;
            if (preset.host == Data::Host::Service && !systemImage) continue;
            if (pattern.find(L'*') != std::wstring_view::npos) {
                serviceCondition.name = pattern;
            } else {
                serviceCondition = {service->name, service->display};
            }
        } else if (groupPreset) {
            if (!systemGroupImage || !hosted || hosted->empty() ||
                !std::all_of(hosted->begin(), hosted->end(), [&](const ServiceEntry& entry) {
                    return entry.pid == request.pid && !ListedService(preset.services, entry.name).empty();
                })) continue;
            serviceGroup = BuildServiceGroup(preset.services, *hosted);
            if (serviceGroup.empty()) continue;
        } else if (preset.host == Data::Host::SvchostFallback) {
            if (!systemImage || service) continue;
        } else if (preset.host == Data::Host::System) {
            if (!EqualNoCase(request.appPath, KernelImagePath())) continue;
        }

        Choice choice;
        choice.titleId = preset.titleId;
        choice.title = LoadStringRes(preset.titleId);
        if (servicePreset)
            choice.title = LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT,
                choice.title.c_str(), serviceCondition.name.c_str());
        bool valid = true;
        bool matches = false;
        for (const Data::NetworkRule& network : preset.rules) {
            Rule rule;
            if (!BuildRule(request, preset, network,
                           servicePreset ? &serviceCondition : nullptr, serviceGroup, rule)) {
                valid = false;
                break;
            }
            if (RuleStore::MatchesRule(rule, query)) matches = true;
            choice.rules.push_back(std::move(rule));
        }
        if (valid && matches) choices.push_back(std::move(choice));
    }
    return choices;
}

size_t Apply(RuleStore& store, const AskRequest& request, const std::vector<Rule>& rules) {
    const bool postAppPidZero = request.key.source == TrafficSource::Host &&
        request.appPath.empty() && request.pid == 0 && !request.ownerAmbiguous;
    if (request.appPath.empty() && !postAppPidZero) return 0;
    std::vector<Rule> list = postAppPidZero ? store.PostApps() : store.ForApp(request.appPath);
    size_t changed = 0;
    for (Rule candidate : rules) {
        if (postAppPidZero) {
            if (candidate.scope != RuleScope::PostApp || !(candidate.conds & CondPidZero)) continue;
        } else if (candidate.scope != RuleScope::App ||
                   !EqualNoCase(candidate.appPath, request.appPath)) {
            continue;
        }
        NormalizeRuleConds(candidate);
        const auto existing = std::find_if(list.begin(), list.end(),
            [&](const Rule& rule) { return SameRule(rule, candidate); });
        if (existing != list.end()) {
            if (!existing->enabled) {
                existing->enabled = true;
                ++changed;
            }
            continue;
        }
        candidate.id = 0;
        candidate.enabled = true;
        list.push_back(std::move(candidate));
        ++changed;
    }
    if (changed) {
        if (postAppPidZero) store.ReplacePostApps(std::move(list));
        else store.ReplaceApp(request.appPath, request.appName, std::move(list));
    }
    return changed;
}

bool ExcludedFromGeneration(std::wstring_view path) {
    return Listed(L"curl.exe;wget.exe;pwsh.exe;powershell.exe;python.exe;python3.exe;perl.exe",
                  FileName(path));
}

std::vector<std::wstring> Executables() {
    std::vector<std::wstring> result;
    for (const Data::Preset& preset : Data::presets) {
        std::wstring_view names = preset.executables;
        while (!names.empty()) {
            const size_t end = names.find(L';');
            const auto name = names.substr(0, end);
            if (!name.empty() && !ExcludedFromGeneration(name) &&
                std::none_of(result.begin(), result.end(),
                    [&](const std::wstring& item) { return EqualNoCase(item, name); }))
                result.emplace_back(name);
            if (end == std::wstring_view::npos) break;
            names.remove_prefix(end + 1);
        }
    }
    return result;
}

bool MayUseService(std::wstring_view executable, std::wstring_view service) {
    if (!executable.empty() && ExcludedFromGeneration(executable)) return false;
    return std::any_of(std::begin(Data::presets), std::end(Data::presets),
        [&](const Data::Preset& preset) {
            const bool serviceHost = preset.host == Data::Host::Service ||
                preset.host == Data::Host::AppService || preset.host == Data::Host::SystemServiceGroup;
            return serviceHost && (executable.empty() || Listed(preset.executables, executable)) &&
                !ListedService(preset.services, service).empty();
        });
}

std::vector<Rule> Generate(const std::wstring& path, const std::vector<ServiceEntry>& services) {
    std::vector<Rule> result;
    if (path.empty() || ExcludedFromGeneration(path)) return result;
    const std::wstring_view executable = FileName(path);
    AskRequest request;
    request.appPath = path;
    request.appName = std::wstring(executable);
    for (const Data::Preset& preset : Data::presets) {
        if (!Listed(preset.executables, executable)) continue;
        // Без привязки к службе резервная заготовка разрешила бы трафик
        // любых служб в svchost, в том числе не прошедших проверку.
        if (preset.host == Data::Host::SvchostFallback ||
            preset.host == Data::Host::PostAppPidZero) continue;
        if (preset.host == Data::Host::System && !EqualNoCase(path, KernelImagePath())) continue;
        if ((preset.host == Data::Host::Service || preset.host == Data::Host::SystemServiceGroup) &&
            !EqualNoCase(path, SystemDirFile(std::wstring(executable).c_str()))) continue;

        std::vector<ServiceItem> matched;
        if (preset.host == Data::Host::Service || preset.host == Data::Host::AppService ||
            preset.host == Data::Host::SystemServiceGroup) {
            for (const ServiceEntry& service : services) {
                if (!ListedService(preset.services, service.name).empty())
                    matched.push_back({service.name, service.display});
            }
            if (matched.empty()) continue;
        }
        if (preset.host == Data::Host::Service || preset.host == Data::Host::AppService) {
            // Только проверенный ключ SCM, а не маска для ещё не проверенных служб.
            for (const ServiceItem& service : matched)
                AppendRules(result, request, preset, &service, {});
        } else {
            AppendRules(result, request, preset, nullptr, matched);
        }
    }
    return result;
}

std::vector<Rule> GenerateIgmp() {
    std::vector<Rule> result;
    const AskRequest request;
    for (const Data::Preset& preset : Data::presets) {
        if (preset.host != Data::Host::PostAppPidZero ||
            (preset.titleId != IDS_PRESET_IGMP && preset.titleId != IDS_PRESET_IGMP_IN)) continue;
        AppendRules(result, request, preset, nullptr, {});
    }
    return result;
}

size_t ApplyGenerated(RuleStore& store, std::vector<Rule> rules) {
    return store.AddMissingRules(std::move(rules), SameRule);
}

size_t ApplySelected(RuleStore& store, const AskRequest& request, std::vector<Rule> rules) {
    // Пользователь выбрал показанный набор условий. Пока окно было открыто,
    // источник наследования мог измениться: применяем набор к актуальной группе,
    // не меняя выбранные сетевые и сервисные ограничения.
    for (Rule& rule : rules) {
        if (rule.scope != RuleScope::App) continue;
        rule.appPath = request.appPath;
        rule.appName = request.appName;
    }
    return Apply(store, request, rules);
}

} // namespace RulePresets
