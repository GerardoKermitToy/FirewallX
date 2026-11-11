#include "NdisBinding.h"

#include <algorithm>
#include <new>

namespace ndis_binding::detail {
namespace {
void CheckStopped(const System& system) {
    if (system.Stopped()) throw Error{HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)};
}
void RequireAdditionAllowed(const Configuration& config) {
    if (!config.allowed || config.recovery != RecoveryPermission::Allowed) {
        throw Error{HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED)};
    }
}
std::optional<Adapter> FindTarget(System& system, uint64_t luid) {
    CheckStopped(system);
    const auto targets = system.ResolveTargets();
    ValidateTargets(targets);
    for (const auto& target : targets) if (target.luid == luid) return target;
    return std::nullopt;
}
bool MatchesBinding(System& system, const Adapter& target, bool enabled) {
    bool found = false, matches = true;
    for (const auto& binding : system.ReadBindings()) {
        if (binding.adapter != target.guid) continue;
        found = true;
        matches = matches && (binding.enabled == enabled);
    }
    if (!found) throw Error{HRESULT_FROM_WIN32(ERROR_NOT_READY)};
    return matches;
}
void RevalidateConfiguration(System& system, const Configuration& expected) {
    CheckStopped(system);
    const auto config = system.ReadConfiguration();
    RequireAdditionAllowed(config);
    if (config.allowed != expected.allowed || config.recovery != expected.recovery) {
        throw Error{HRESULT_FROM_WIN32(ERROR_RETRY)};
    }
}
void RevalidateTarget(System& system, const Adapter& target, const Configuration& expected) {
    const auto current = FindTarget(system, target.luid);
    if (!current || !SameTarget(*current, target) || current->expectRunning != target.expectRunning ||
        current->excluded != target.excluded || current->name != target.name) {
        throw Error{HRESULT_FROM_WIN32(ERROR_RETRY)};
    }
    RevalidateConfiguration(system, expected);
}
} // namespace

std::optional<Adapter> InspectAddition(System& system, uint64_t luid, std::span<const AttachedAdapter> attached) {
    if (!luid) throw Error{E_INVALIDARG};
    CheckStopped(system);
    system.OpenNetwork();
    CheckStopped(system);
    system.RequireInstalled();
    const auto config = system.ReadConfiguration();
    RequireAdditionAllowed(config);
    const auto target = FindTarget(system, luid);
    if (!target) return std::nullopt;
    const bool ready = MatchesBinding(system, *target, !target->excluded);
    const bool running = target->excluded || !target->expectRunning || std::count_if(attached.begin(), attached.end(),
        [&](const AttachedAdapter& module) { return module.running && SameTarget(module.identity, *target); }) == 1;
    RevalidateTarget(system, *target, config);
    if (ready && running) return std::nullopt;
    return target;
}

HRESULT EnsureAddition(const std::atomic<bool>& stopped, uint64_t luid, std::span<const AttachedAdapter> attached,
                       Adapter& added, AdditionInspector inspect, AdditionalWorker apply) noexcept {
    try {
        if (!luid || !inspect || !apply) return E_INVALIDARG;
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        const auto target = inspect(stopped, luid, attached);
        if (!target) return S_FALSE;
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        const auto status = apply(stopped, luid);
        Check(status);
        if (status != S_OK) return status;
        added = *target;
        return S_OK;
    } catch (const Error& error) { return error.status; }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

namespace {
HRESULT ApplyTarget(System& system, uint64_t luid, std::wstring_view name, bool matchName) noexcept {
    bool changing = false;
    Adapter target;
    HRESULT failure = E_UNEXPECTED;
    try {
        if ((!matchName && !luid) || (matchName && name.empty())) return E_INVALIDARG;
        CheckStopped(system);
        system.LockNetwork();
        CheckStopped(system);
        system.RequireInstalled();
        const auto config = system.ReadConfiguration();
        RequireAdditionAllowed(config);
        std::optional<Adapter> selected;
        if (matchName) {
            const auto targets = system.ResolveTargets();
            ValidateTargets(targets);
            for (const auto& candidate : targets) {
                if (candidate.name != name) continue;
                if (selected) throw Error{HRESULT_FROM_WIN32(ERROR_DUP_NAME)};
                selected = candidate;
            }
        } else {
            selected = FindTarget(system, luid);
        }
        if (!selected) return S_FALSE;
        target = *selected;
        MatchesBinding(system, target, !target.excluded);
        RevalidateTarget(system, target, config);
        changing = true;
        // Исключение отключает только выбранный адаптер, не прерывая остальные.
        system.SetBinding(target, false);
        if (!MatchesBinding(system, target, false)) throw Error{E_UNEXPECTED};
        RevalidateTarget(system, target, config);
        if (!target.excluded) {
            // Переподключаем только новый путь, не прерывая работающие адаптеры.
            system.SetBinding(target, true);
            if (!MatchesBinding(system, target, true)) throw Error{HRESULT_FROM_WIN32(ERROR_NOT_READY)};
        }
        RevalidateTarget(system, target, config);
        return S_OK;
    } catch (const Error& error) { failure = error.status; }
    catch (const std::bad_alloc&) { failure = E_OUTOFMEMORY; }
    catch (...) { failure = E_UNEXPECTED; }
    if (changing) {
        if (failure != HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) {
            try { system.SetBinding(target, false); }
            catch (const Error& error) {
                if (error.status == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) failure = error.status;
            } catch (...) {}
        }
        if (failure == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) {
            // Не разоружаем действующие модули, но запрещаем новые Apply до явного resume.
            try { system.SetRecoveryAllowed(false); } catch (...) {}
        }
    }
    return failure;
}
} // namespace

HRESULT AddTarget(System& system, uint64_t luid) noexcept {
    return ApplyTarget(system, luid, {}, false);
}

HRESULT ApplyNamedTarget(System& system, std::wstring_view name) noexcept {
    return ApplyTarget(system, 0, name, true);
}

} // namespace ndis_binding::detail
