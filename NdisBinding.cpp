#include "NdisBinding.h"

#include <algorithm>
#include <new>
#include <utility>

namespace ndis_binding::detail {
namespace {

void CheckStopped(const System& system) {
    if (system.Stopped()) throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
}

bool IsTarget(const Targets& targets, const GUID& guid) {
    return std::any_of(targets.begin(), targets.end(), [&](const Adapter& target) { return target.guid == guid; });
}

// Несколько путей одного адаптера допустимы; каждый целевой адаптер должен иметь путь.
bool ValidateBindings(const std::vector<Binding>& bindings, const Targets& targets,
                      bool allDisabled = false, bool requireEnabled = false) {
    bool ready = true;
    for (const auto& binding : bindings) {
        if (binding.adapter == GUID_NULL || (binding.enabled && allDisabled)) throw Error{ E_UNEXPECTED };
        // Набор путей мог измениться после перечисления; не меняем неизвестный путь.
        if (!IsTarget(targets, binding.adapter)) throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
    }
    for (const auto& target : targets) {
        bool found = false;
        for (const auto& binding : bindings) {
            if (binding.adapter != target.guid) continue;
            found = true;
            ready = ready && (binding.enabled != target.excluded);
        }
        if (!found) throw Error{ HRESULT_FROM_WIN32(ERROR_NOT_READY) };
    }
    if (requireEnabled && !ready) throw Error{ HRESULT_FROM_WIN32(ERROR_NOT_READY) };
    return ready;
}

void Revalidate(System& system, const Targets& targets, const Configuration& expected) {
    CheckStopped(system);
    const auto current = system.ResolveTargets();
    ValidateTargets(current);
    const auto config = system.ReadConfiguration();
    if (!SameTargets(targets, current) || expected.allowed != config.allowed ||
        expected.recovery != config.recovery) throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
}

void RequireRecovery(const Configuration& config, bool resumeLegacy) {
    if (config.recovery == RecoveryPermission::InstallerControlled ||
        (!config.allowed && config.recovery == RecoveryPermission::Legacy && !resumeLegacy)) {
        throw Error{ HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED) };
    }
}

} // namespace

GUID ParseGuid(std::wstring_view text) {
    const std::wstring braced = text.size() == 36 ? L"{" + std::wstring(text) + L"}" : std::wstring(text);
    GUID guid{};
    if (braced.size() != 38 || braced.front() != L'{' || braced.back() != L'}' ||
        FAILED(CLSIDFromString(braced.c_str(), &guid)) || guid == GUID_NULL) throw Error{ E_UNEXPECTED };
    return guid;
}

bool SameTarget(const Adapter& first, const Adapter& second) noexcept {
    return first.guid == second.guid && first.luid == second.luid;
}

bool SameTargets(const Targets& first, const Targets& second) noexcept {
    return first.size() == second.size() && std::is_permutation(first.begin(), first.end(), second.begin(),
        [](const Adapter& a, const Adapter& b) {
            return SameTarget(a, b) && a.expectRunning == b.expectRunning && a.excluded == b.excluded &&
                   a.name == b.name;
        });
}

void ValidateTargets(const Targets& targets) {
    for (size_t i = 0; i < targets.size(); ++i) {
        if (targets[i].guid == GUID_NULL || !targets[i].luid) throw Error{ E_UNEXPECTED };
        for (size_t j = 0; j < i; ++j) {
            if (targets[i].guid == targets[j].guid || targets[i].luid == targets[j].luid) throw Error{ E_UNEXPECTED };
        }
    }
}

Targets SelectBindingTargets(std::span<const Binding> bindings, std::span<const Adapter> adapters) {
    Targets targets;
    for (const auto& binding : bindings) {
        if (binding.adapter == GUID_NULL) throw Error{ E_UNEXPECTED };
        if (IsTarget(targets, binding.adapter)) continue;
        const Adapter* match = nullptr;
        for (const auto& adapter : adapters) {
            if (adapter.guid != binding.adapter) continue;
            if (match) throw Error{ E_UNEXPECTED };
            match = &adapter;
        }
        if (!match) throw Error{ HRESULT_FROM_WIN32(ERROR_RETRY) };
        targets.push_back(*match);
    }
    ValidateTargets(targets);
    return targets;
}

void MarkExcludedByName(Targets& targets, std::span<const std::wstring> excluded) noexcept {
    for (auto& target : targets)
        target.excluded = std::find(excluded.begin(), excluded.end(), target.name) != excluded.end();
}

bool AllTargetsRunning(const Targets& targets, std::span<const AttachedAdapter> attached) noexcept {
    for (const auto& target : targets) {
        if (!target.expectRunning || target.excluded) continue;
        if (std::count_if(attached.begin(), attached.end(), [&](const AttachedAdapter& module) {
                return module.running && SameTarget(target, module.identity);
            }) != 1) return false;
    }
    return true;
}

Inspection Inspect(System& system, std::span<const AttachedAdapter> attached) {
    CheckStopped(system);
    system.OpenNetwork();
    CheckStopped(system);
    system.RequireInstalled();
    const auto config = system.ReadConfiguration();
    RequireRecovery(config, false);
    auto targets = system.ResolveTargets();
    ValidateTargets(targets);
    const auto bindings = system.ReadBindings();
    const bool ready = ValidateBindings(bindings, targets);
    Revalidate(system, targets, config);
    const bool needsRebind = !config.allowed || !ready || !AllTargetsRunning(targets, attached);
    return {std::move(targets), needsRebind};
}

Targets FindMissing(System& system, std::span<const AttachedAdapter> attached) {
    CheckStopped(system);
    system.OpenNetwork();
    CheckStopped(system);
    system.RequireInstalled();
    const auto config = system.ReadConfiguration();
    if (!config.allowed || config.recovery != RecoveryPermission::Allowed) {
        throw Error{ HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED) };
    }
    const auto targets = system.ResolveTargets();
    ValidateTargets(targets);
    const auto bindings = system.ReadBindings();
    ValidateBindings(bindings, targets);
    Targets missing;
    for (const auto& target : targets) {
        const bool wrongBinding = std::any_of(bindings.begin(), bindings.end(), [&](const Binding& binding) {
            return binding.adapter == target.guid && binding.enabled == target.excluded;
        });
        const bool running = target.excluded || !target.expectRunning || std::count_if(attached.begin(), attached.end(),
            [&](const AttachedAdapter& module) { return module.running && SameTarget(module.identity, target); }) == 1;
        if (wrongBinding || !running) missing.push_back(target);
    }
    Revalidate(system, targets, config);
    return missing;
}

HRESULT Ensure(const std::atomic<bool>& stopped, std::span<const AttachedAdapter> attached,
               Targets& targets, Inspector inspect, Repair repair, bool* rebound) noexcept {
    try {
        if (!inspect || !repair) return E_INVALIDARG;
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        auto state = inspect(stopped, attached);
        ValidateTargets(state.targets);
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        // Ошибка проверки не является доказательством необходимости запуска worker.
        if (state.needsRebind) Check(repair(stopped));
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        targets = std::move(state.targets);
        if (rebound) *rebound = state.needsRebind;
        return S_OK;
    } catch (const Error& error) { return error.status; }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

HRESULT Prepare(System& system, bool forceReattach, bool resumeLegacy) noexcept {
    bool changing = false;
    HRESULT failure = E_UNEXPECTED;
    Targets targets;
    try {
        CheckStopped(system);
        system.LockNetwork();
        CheckStopped(system);
        system.RequireInstalled();
        auto config = system.ReadConfiguration();
        RequireRecovery(config, resumeLegacy);
        if (resumeLegacy && config.allowed) return HRESULT_FROM_WIN32(ERROR_ALREADY_INITIALIZED);
        targets = system.ResolveTargets();
        ValidateTargets(targets);
        const auto bindings = system.ReadBindings();
        const bool ready = ValidateBindings(bindings, targets);
        if (resumeLegacy && config.recovery == RecoveryPermission::Legacy) {
            ValidateBindings(bindings, targets, true);
        }
        if (!forceReattach && config.allowed && ready) {
            Revalidate(system, targets, config);
            return S_OK;
        }
        Revalidate(system, targets, config);
        changing = true;
        if (config.recovery == RecoveryPermission::Legacy) {
            system.SetRecoveryAllowed(true);
            config.recovery = RecoveryPermission::Allowed;
        }
        system.Disarm();
        config.allowed = false;
        // Полный цикл только для путей установленного фильтра.
        for (const auto& target : targets) {
            CheckStopped(system);
            system.SetBinding(target, false);
        }
        ValidateBindings(system.ReadBindings(), targets, true);
        Revalidate(system, targets, config);
        system.Arm();
        config.allowed = true;
        for (const auto& target : targets) {
            CheckStopped(system);
            if (!target.excluded) system.SetBinding(target, true);
        }
        ValidateBindings(system.ReadBindings(), targets, false, true);
        Revalidate(system, targets, config);
        return S_OK;
    } catch (const Error& error) { failure = error.status; }
    catch (const std::bad_alloc&) { failure = E_OUTOFMEMORY; }
    catch (...) { failure = E_UNEXPECTED; }
    if (changing) {
        if (failure == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) {
            try { system.SetRecoveryAllowed(false); } catch (...) {}
        }
        try { system.Disarm(); } catch (...) {}
        // После NETCFG_S_REBOOT больше не вызываем Apply, в том числе при rollback.
        if (failure != HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) {
            for (const auto& target : targets) {
                try { system.SetBinding(target, false); }
                catch (const Error& error) {
                    if (error.status == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) {
                        failure = error.status;
                        try { system.SetRecoveryAllowed(false); } catch (...) {}
                        break;
                    }
                } catch (...) {}
            }
        }
    }
    return failure;
}

} // namespace ndis_binding::detail
