// Только поддельная сеть и конфигурация: драйвер, реестр и NetCfg не вызываются.
#include "ndis_binding_component_tests.h"
#include "ndis_binding_media_tests.h"
#include "ndis_binding_async_tests.h"
#include "NdisBinding.h"
#include <algorithm>
#include <cstdio>
#include <functional>
#include <new>
#include <stdexcept>
#include <string_view>

using namespace ndis_binding::detail;
namespace {
void CheckTest(bool value, const char* message = "assertion failed") {
    if (!value) throw std::runtime_error(message);
}
GUID Guid(const wchar_t* text) { return ParseGuid(text); }
const GUID currentId = Guid(L"{1B7BCE26-738C-4848-8134-E417EFFE730D}");
const GUID secondId = Guid(L"{DE4BD21D-8A6E-4652-A812-874EE8330AB1}");
const GUID previousId = Guid(L"{C4C9FAD3-6A7B-4754-86C8-D3F9055880F5}");
const GUID foreignId = Guid(L"{00000001-0002-0003-0405-060708090A0B}");
Adapter Target(GUID id = currentId, uint64_t luid = 11, bool running = true) { return {id, luid, running}; }
Targets Pair() { return {Target(), Target(secondId, 22)}; }
std::vector<AttachedAdapter> Attached(const Targets& targets) {
    std::vector<AttachedAdapter> result;
    for (const auto& target : targets) result.push_back({target, true});
    return result;
}

class FakeSystem final : public System {
public:
    Targets targets = Pair();
    Configuration configuration{true, RecoveryPermission::Allowed};
    std::vector<Binding> bindings{{currentId, true}, {secondId, true}};
    std::vector<std::string> calls;
    std::vector<Binding> bindingChanges;
    std::function<void(const char*)> onStep;
    bool stopped = false, installed = true, locked = false, opened = false;
    bool enableEffect = true, disableEffect = true;
    std::string fail;
    unsigned failOccurrence = 1;
    HRESULT failure = E_ACCESSDENIED;
    bool rebootEnable = false, rebootDisable = false;
    bool adding = false;
    GUID additionGuid = previousId;

    void Step(const char* name) {
        calls.emplace_back(name);
        if (onStep) onStep(name);
        if (fail == name && std::count(calls.begin(), calls.end(), name) == failOccurrence) throw Error{failure};
    }
    bool Stopped() const override { return stopped; }
    void OpenNetwork() override { Step("open"); opened = true; }
    void LockNetwork() override { Step("lock"); locked = true; }
    void RequireInstalled() override {
        CheckTest(locked || opened);
        Step("installed");
        if (!installed) throw Error{HRESULT_FROM_WIN32(ERROR_SERVICE_DOES_NOT_EXIST)};
    }
    Targets ResolveTargets(std::vector<Binding>* snapshot = nullptr) override {
        Step("resolve");
        if (snapshot) *snapshot = ReadBindings();
        return targets;
    }
    Configuration ReadConfiguration() override { Step("config"); return configuration; }
    std::vector<Binding> ReadBindings() override { Step("bindings"); return bindings; }
    void SetRecoveryAllowed(bool allowed) override {
        CheckTest(locked);
        configuration.recovery = allowed ? RecoveryPermission::Allowed : RecoveryPermission::InstallerControlled;
        Step("recovery");
    }
    void Disarm() override { CheckTest(locked && !adding); configuration.allowed = false; Step("disarm"); }
    void Arm() override { CheckTest(locked && !adding); configuration.allowed = true; Step("arm"); }
    void SetBinding(const Adapter& adapter, bool enabled) override {
        CheckTest(locked && std::any_of(bindings.begin(), bindings.end(),
            [&](const Binding& binding) { return binding.adapter == adapter.guid; }), "unknown binding touched");
        if (adding) CheckTest(configuration.allowed && adapter.guid == additionGuid, "existing binding touched");
        else CheckTest(configuration.allowed == enabled);
        CheckTest(!enabled || ShouldEnable(adapter), "unsupported or excluded adapter enabled");
        bindingChanges.push_back({adapter.guid, enabled});
        Step(enabled ? "enable" : "disable");
        if (enabled ? enableEffect : disableEffect) {
            for (auto& binding : bindings) if (binding.adapter == adapter.guid) binding.enabled = enabled;
        }
        if (enabled ? rebootEnable : rebootDisable) throw Error{HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)};
    }
    bool Called(const char* name) const { return std::find(calls.begin(), calls.end(), name) != calls.end(); }
    size_t At(const char* name) const {
        const auto it = std::find(calls.begin(), calls.end(), name);
        CheckTest(it != calls.end(), "missing operation");
        return static_cast<size_t>(it - calls.begin());
    }
    void NoMutation() const {
        for (const auto name : {"recovery", "disarm", "arm", "enable", "disable"}) {
            CheckTest(!Called(name), "unexpected mutation");
        }
    }
    void Healthy() {
        configuration = {true, RecoveryPermission::Allowed};
        for (auto& binding : bindings) binding.enabled = true;
    }
    void Complete() const {
        CheckTest(configuration.allowed);
        for (const auto& binding : bindings) CheckTest(binding.enabled);
    }
};

FakeSystem* preflightSystem = nullptr;
unsigned repairs = 0;
bool lastRebound = false;
Inspection FakeInspect(const std::atomic<bool>&, std::span<const AttachedAdapter> attached) {
    return Inspect(*preflightSystem, attached);
}
HRESULT FakeRepair(const std::atomic<bool>&) { ++repairs; return Prepare(*preflightSystem, true); }
HRESULT EnsureFake(FakeSystem& system, const std::vector<AttachedAdapter>& attached, Targets& output) {
    preflightSystem = &system;
    repairs = 0;
    lastRebound = false;
    const std::atomic<bool> stopped{system.stopped};
    return Ensure(stopped, attached, output, FakeInspect, FakeRepair, &lastRebound);
}

template<class Function> HRESULT Rejected(Function action) {
    try { action(); }
    catch (const Error& error) { return error.status; }
    throw std::runtime_error("invalid state accepted");
}
struct Case { const char* name; std::function<void()> run; };
} // namespace

#include "ndis_binding_config_tests.h"
#include "ndis_binding_addition_tests.h"
#include "ndis_binding_preferences_tests.h"

int main() {
    std::vector<Case> cases{
        {"renamed driver configuration and component identity", [] {
            CheckTest(std::wstring_view(kConfigKey) == L"SOFTWARE\\FirewallXNdisFilter\\Lwf");
            CheckTest(std::wstring_view(kComponentId) == L"firewallx_ndis_filter");
            CheckTest(kConfigVersion == 4 && kFilterId == Guid(L"{6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}"));
        }},
        {"native non-PnP component identity", [] { CheckTest(ndis_binding_tests::ComponentIdentityTests()); }},
        {"NETIO identity and Ethernet or Wi-Fi media", [] { CheckTest(ndis_binding_tests::AdapterMediaTests()); }},
        {"asynchronous topology success and failure", [] { ndis_binding_tests::AsyncSuccessAndFailureTest(); }},
        {"asynchronous cancellation cannot multiply workers", [] { ndis_binding_tests::AsyncCancellationTest(); }},
        {"asynchronous deadline owns its storage", [] { ndis_binding_tests::AsyncTimeoutAndLifetimeTest(); }},
        {"asynchronous deadline keeps the captured snapshot alive", [] { ndis_binding_tests::AsyncOwnedSnapshotTest(); }},
        {"schema-4 flags and fake registry", [] { BindingConfigTests(); }},
        {"excluded interface names persist in the shared settings database", [] { PreferencePersistenceTests(); }},
        {"all filter paths remain available for safe disable", [] {
            // VMware, Wi-Fi и IP-туннели определяются средой, а не именами или происхождением.
            const Targets inventory{Target(), Target(secondId, 22), Target(previousId, 33), Target(foreignId, 44)};
            const std::vector<Binding> paths{{currentId, true}, {secondId, false}, {previousId, true}, {currentId, false}};
            const Targets expected{inventory[0], inventory[1], inventory[2]};
            CheckTest(SameTargets(SelectBindingTargets(paths, inventory), expected));
            CheckTest(SelectBindingTargets({}, inventory).empty());
        }},
        {"ambiguous or missing binding identity is rejected", [] {
            Rejected([] { SelectBindingTargets(std::vector<Binding>{{GUID_NULL, false}}, Pair()); });
            Rejected([] { SelectBindingTargets(std::vector<Binding>{{foreignId, false}}, Pair()); });
            auto inventory = Pair(); inventory.push_back(inventory.front());
            Rejected([&] { SelectBindingTargets(std::vector<Binding>{{currentId, false}}, inventory); });
            inventory = Pair(); inventory[1].luid = inventory[0].luid;
            Rejected([&] { SelectBindingTargets(std::vector<Binding>{{currentId, false}, {secondId, false}}, inventory); });
        }},
        {"healthy preflight never launches a repair process", [] {
            FakeSystem s; Targets result;
            CheckTest(EnsureFake(s, Attached(s.targets), result) == S_OK && repairs == 0 && !lastRebound);
            CheckTest(SameTargets(result, s.targets) && !s.Called("lock")); s.NoMutation();
        }},
        {"IP-only path stays disabled while VMware Ethernet is healthy", [] {
            FakeSystem s; Targets result;
            s.targets[0].name = L"VMnet1";
            s.targets[1].name = L"VMnet8";
            auto tunnel = Target(previousId, 33);
            tunnel.name = L"IP tunnel";
            tunnel.compatible = false;
            s.targets.push_back(tunnel);
            s.bindings.push_back({tunnel.guid, false});
            const auto attached = Attached(Pair());
            CheckTest(EnsureFake(s, attached, result) == S_OK && repairs == 0 && !lastRebound);
            CheckTest(SameTargets(result, s.targets) && FindMissing(s, attached).empty());
            s.NoMutation();
        }},
        {"enabled unsupported path is disabled without being re-enabled", [] {
            FakeSystem s; Targets result;
            s.targets[1].compatible = false;
            auto attached = Attached(s.targets); attached.pop_back();
            CheckTest(EnsureFake(s, attached, result) == S_OK && repairs == 1);
            CheckTest(s.bindings[0].enabled && !s.bindings[1].enabled);
            for (const auto& change : s.bindingChanges)
                CheckTest(change.adapter != secondId || !change.enabled, "IP path re-enabled");
        }},
        {"media change during full recovery prevents re-arming", [] {
            FakeSystem s;
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "disable") s.targets[1].compatible = false;
            };
            CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_RETRY));
            CheckTest(!s.configuration.allowed && !s.Called("arm"));
        }},
        {"interface exclusions follow the name when adapter identity changes", [] {
            const std::vector<std::wstring> excluded{L"Ethernet café 网络"};
            Targets targets{Target()}; targets[0].name = excluded[0];
            MarkExcludedByName(targets, excluded);
            CheckTest(targets[0].excluded);
            targets[0].guid = secondId; targets[0].luid = 22; targets[0].excluded = false;
            MarkExcludedByName(targets, excluded);
            CheckTest(targets[0].excluded);
            targets[0].name = L"Another interface";
            MarkExcludedByName(targets, excluded);
            CheckTest(!targets[0].excluded);
        }},
        {"excluded adapters remain detached during startup and full recovery", [] {
            FakeSystem s; s.targets[1].excluded = true; s.bindings[1].enabled = false;
            auto attached = Attached(s.targets); attached.pop_back(); Targets result;
            CheckTest(EnsureFake(s, attached, result) == S_OK && repairs == 0);
            CheckTest(AllTargetsRunning(s.targets, attached)); s.NoMutation();
            s.bindings[1].enabled = true;
            s.bindings.push_back({secondId, false});
            CheckTest(EnsureFake(s, attached, result) == S_OK && repairs == 1);
            CheckTest(s.bindings[0].enabled && !s.bindings[1].enabled && !s.bindings[2].enabled);
            for (const auto& change : s.bindingChanges)
                CheckTest(change.adapter != secondId || !change.enabled, "excluded path re-enabled");
        }},
        {"reconciliation detects either direction of an exclusion change", [] {
            FakeSystem s; s.targets[1].excluded = true;
            CheckTest(SameTargets(FindMissing(s, Attached(s.targets)), Targets{s.targets[1]}));
            s.bindings[1].enabled = false;
            CheckTest(FindMissing(s, Attached(s.targets)).empty());
            s.targets[1].excluded = false;
            CheckTest(SameTargets(FindMissing(s, Attached(s.targets)), Targets{s.targets[1]}));
            s.NoMutation();
        }},
        {"changing exclusions during full recovery prevents arming", [] {
            FakeSystem s; s.onStep = [&](const char* name) {
                if (std::string_view(name) == "disable") s.targets[1].excluded = true;
            };
            CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_RETRY));
            CheckTest(!s.configuration.allowed && !s.Called("arm"));
        }},
        {"no eligible paths is a healthy empty configuration", [] {
            FakeSystem s; s.targets.clear(); s.bindings.clear(); Targets result;
            CheckTest(EnsureFake(s, {}, result) == S_OK && result.empty() && repairs == 0); s.NoMutation();
        }},
        {"administratively disabled adapter need not have a running module", [] {
            FakeSystem s; s.targets[1].expectRunning = false; Targets result;
            auto attached = Attached(s.targets); attached.pop_back();
            CheckTest(EnsureFake(s, attached, result) == S_OK && repairs == 0);
            attached.push_back({s.targets[1], false});
            CheckTest(AllTargetsRunning(s.targets, attached));
        }},
        {"one missing active module forces a full rebind", [] {
            FakeSystem s; Targets result; auto attached = Attached(s.targets); attached.pop_back();
            CheckTest(EnsureFake(s, attached, result) == S_OK && repairs == 1 && lastRebound);
            CheckTest(s.bindingChanges.size() == 4 && s.At("disarm") < s.At("disable") &&
                s.At("disable") < s.At("arm") && s.At("arm") < s.At("enable")); s.Complete();
        }},
        {"paused wrong-GUID or stale-LUID module requires repair", [] {
            for (unsigned mode = 0; mode < 3; ++mode) {
                FakeSystem s; auto attached = Attached(s.targets);
                if (mode == 0) attached[1].running = false;
                if (mode == 1) attached[1].identity.guid = foreignId;
                if (mode == 2) ++attached[1].identity.luid;
                CheckTest(Inspect(s, attached).needsRebind); s.NoMutation();
            }
        }},
        {"reconciliation selects only missing or disabled paths", [] {
            FakeSystem s;
            s.targets.push_back(Target(previousId, 33, false));
            s.bindings.push_back({previousId, true});
            auto attached = Attached(s.targets); attached.pop_back(); attached.pop_back();
            CheckTest(SameTargets(FindMissing(s, attached), Targets{Target(secondId, 22)}));
            s.bindings[2].enabled = false;
            CheckTest(SameTargets(FindMissing(s, attached), Targets{Target(secondId, 22), Target(previousId, 33, false)}));
            s.NoMutation();
        }},
        {"reconciliation respects installer and disarm state", [] {
            for (unsigned mode = 0; mode < 3; ++mode) {
                FakeSystem s;
                if (mode == 0) s.configuration.allowed = false;
                if (mode == 1) s.configuration.recovery = RecoveryPermission::InstallerControlled;
                if (mode == 2) s.configuration.recovery = RecoveryPermission::Legacy;
                CheckTest(Rejected([&] { FindMissing(s, {}); }) == HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED));
                s.NoMutation();
            }
        }},
        {"reconciliation rejects topology changes before publication", [] {
            FakeSystem s; unsigned resolves = 0;
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "resolve" && ++resolves == 2) s.targets[1].guid = foreignId;
            };
            CheckTest(Rejected([&] { FindMissing(s, {}); }) == HRESULT_FROM_WIN32(ERROR_RETRY));
            s.NoMutation();
        }},
        {"reconciliation rejects binding changes before publication", [] {
            FakeSystem s; unsigned resolves = 0;
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "resolve" && ++resolves == 2) s.bindings[1].enabled = false;
            };
            CheckTest(Rejected([&] { FindMissing(s, Attached(s.targets)); }) == HRESULT_FROM_WIN32(ERROR_RETRY));
            CheckTest(resolves == 2 && std::count(s.calls.begin(), s.calls.end(), "bindings") == 2);
            s.NoMutation();
        }},
        {"reordered unchanged paths do not require a repair", [] {
            FakeSystem s; unsigned resolves = 0; Targets result;
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "resolve" && ++resolves == 2) std::reverse(s.bindings.begin(), s.bindings.end());
            };
            CheckTest(EnsureFake(s, Attached(s.targets), result) == S_OK && repairs == 0);
            s.NoMutation();
        }},
        {"inspection failure is not permission to launch a helper", [] {
            FakeSystem s; s.fail = "resolve"; Targets result{Target(previousId)};
            CheckTest(EnsureFake(s, Attached(s.targets), result) == E_ACCESSDENIED && repairs == 0);
            CheckTest(result.front().guid == previousId); s.NoMutation();
        }},
        {"stopped preflight cannot launch a helper", [] {
            FakeSystem s; s.stopped = true; Targets result;
            CheckTest(EnsureFake(s, {}, result) == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) && repairs == 0);
            CheckTest(s.calls.empty());
        }},
        {"healthy repair stays read-only unless forced", [] {
            FakeSystem s; CheckTest(Prepare(s) == S_OK); s.NoMutation();
            s.calls.clear(); CheckTest(Prepare(s, true) == S_OK && s.bindingChanges.size() == 4); s.Complete();
        }},
        {"disabled binding forces full rebind", [] {
            FakeSystem s; s.bindings[1].enabled = false; Targets result;
            CheckTest(EnsureFake(s, Attached(s.targets), result) == S_OK && repairs == 1); s.Complete();
        }},
        {"runtime failure remains retryable", [] {
            FakeSystem s; s.fail = "enable";
            CheckTest(Prepare(s, true) == E_ACCESSDENIED && !s.configuration.allowed);
            CheckTest(s.configuration.recovery == RecoveryPermission::Allowed);
            s.fail.clear(); CheckTest(Prepare(s) == S_OK); s.Complete();
        }},
        {"installer-controlled state cannot be resumed", [] {
            FakeSystem s; s.configuration.recovery = RecoveryPermission::InstallerControlled;
            CheckTest(Prepare(s) == HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED));
            CheckTest(Prepare(s, false, true) == HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED)); s.NoMutation();
        }},
        {"disarmed legacy state requires explicit resume", [] {
            FakeSystem s; s.configuration = {false, RecoveryPermission::Legacy};
            for (auto& binding : s.bindings) binding.enabled = false;
            CheckTest(Prepare(s) == HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED)); s.NoMutation();
            CheckTest(Prepare(s, false, true) == S_OK); s.Complete();
            CheckTest(Prepare(s, false, true) == HRESULT_FROM_WIN32(ERROR_ALREADY_INITIALIZED));
        }},
        {"legacy resume rejects enabled paths", [] {
            FakeSystem s; s.configuration = {false, RecoveryPermission::Legacy};
            CheckTest(Prepare(s, false, true) == E_UNEXPECTED); s.NoMutation();
        }},
        {"runtime-disarmed configuration can recover", [] {
            FakeSystem s; s.configuration = {false, RecoveryPermission::Allowed};
            for (auto& binding : s.bindings) binding.enabled = false;
            CheckTest(Prepare(s) == S_OK && !s.Called("recovery")); s.Complete();
        }},
        {"ineffective disable prevents arming", [] {
            FakeSystem s; s.disableEffect = false;
            CheckTest(Prepare(s, true) == E_UNEXPECTED && !s.Called("arm") && !s.configuration.allowed);
        }},
        {"all paths of one adapter are enabled", [] {
            FakeSystem s; s.bindings.push_back({currentId, false});
            CheckTest(Prepare(s) == S_OK && s.bindings.back().enabled); s.Complete();
        }},
        {"missing changed or malformed path is read-only", [] {
            FakeSystem s; s.bindings.erase(s.bindings.begin());
            CheckTest(Prepare(s) == HRESULT_FROM_WIN32(ERROR_NOT_READY)); s.NoMutation();
            FakeSystem extra; extra.bindings.push_back({foreignId, false});
            CheckTest(Prepare(extra) == HRESULT_FROM_WIN32(ERROR_RETRY)); extra.NoMutation();
            FakeSystem bad; bad.bindings.push_back({GUID_NULL, false});
            CheckTest(Prepare(bad) == E_UNEXPECTED); bad.NoMutation();
        }},
        {"missing component and failed write lock do not mutate", [] {
            FakeSystem s; s.installed = false;
            CheckTest(Prepare(s) == HRESULT_FROM_WIN32(ERROR_SERVICE_DOES_NOT_EXIST)); s.NoMutation();
            FakeSystem locked; locked.fail = "lock";
            CheckTest(Prepare(locked) == E_ACCESSDENIED); locked.NoMutation();
        }},
        {"topology change before mutation is read-only", [] {
            FakeSystem s; unsigned resolves = 0;
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "resolve" && ++resolves == 2) s.targets[1].guid = foreignId;
            };
            CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_RETRY)); s.NoMutation();
        }},
        {"topology or configuration change prevents arming", [] {
            for (const bool topology : {false, true}) {
                FakeSystem s; s.onStep = [&](const char* name) {
                    if (std::string_view(name) != "disable") return;
                    if (topology) s.targets[1].guid = foreignId;
                    else s.configuration.recovery = RecoveryPermission::InstallerControlled;
                };
                CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_RETRY));
                CheckTest(!s.configuration.allowed && !s.Called("arm"));
            }
        }},
        {"cancellation after disable leaves targets disarmed", [] {
            FakeSystem s; s.onStep = [&](const char* name) { if (std::string_view(name) == "disable") s.stopped = true; };
            CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED));
            CheckTest(!s.configuration.allowed && !s.Called("arm"));
        }},
        {"ineffective enable rolls back every target", [] {
            FakeSystem s; s.enableEffect = false;
            CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_NOT_READY) && !s.configuration.allowed);
            for (const auto& binding : s.bindings) CheckTest(!binding.enabled);
        }},
        {"partial arm and allocation failures roll back", [] {
            FakeSystem arm; arm.fail = "arm";
            CheckTest(Prepare(arm, true) == E_ACCESSDENIED && !arm.configuration.allowed);
            FakeSystem oom; oom.onStep = [](const char* name) {
                if (std::string_view(name) == "disable") throw std::bad_alloc();
            };
            CheckTest(Prepare(oom, true) == E_OUTOFMEMORY && !oom.configuration.allowed && !oom.Called("arm"));
        }},
        {"rollback reboot is not hidden by the original error", [] {
            FakeSystem s; s.fail = "enable";
            s.onStep = [&](const char* name) { if (std::string_view(name) == "enable") s.rebootDisable = true; };
            CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED));
            CheckTest(s.configuration.recovery == RecoveryPermission::InstallerControlled && !s.configuration.allowed);
        }},
        {"disable and enable reboot stop further Apply calls", [] {
            for (const bool enable : {false, true}) {
                FakeSystem s; if (enable) s.rebootEnable = true; else s.rebootDisable = true;
                CheckTest(Prepare(s, true) == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED));
                CheckTest(!s.configuration.allowed && s.configuration.recovery == RecoveryPermission::InstallerControlled);
                CheckTest(s.bindingChanges.size() == (enable ? 3u : 1u));
            }
        }},
        {"more than 4096 filter adapters are accepted", [] {
            Targets inventory; std::vector<Binding> bindings;
            for (unsigned i = 1; i <= 4097; ++i) {
                GUID id = currentId; id.Data1 = i;
                inventory.push_back(Target(id, i)); bindings.push_back({id, false});
            }
            CheckTest(SameTargets(SelectBindingTargets(bindings, inventory), inventory));
        }},
        {"many filter paths have no pair limit", [] {
            Targets inventory; std::vector<Binding> bindings;
            for (unsigned i = 1; i <= 129; ++i) {
                GUID id = currentId; id.Data1 = i;
                inventory.push_back(Target(id, i)); bindings.push_back({id, false});
            }
            CheckTest(SameTargets(SelectBindingTargets(bindings, inventory), inventory));
            FakeSystem s; s.targets = inventory; s.bindings = bindings;
            CheckTest(Prepare(s) == S_OK && s.bindingChanges.size() == 258); s.Complete();
        }}
    };
    auto additions = AdditionCases();
    cases.insert(cases.end(), additions.begin(), additions.end());
    for (const auto& test : cases) {
        try { test.run(); }
        catch (const std::exception& error) {
            std::fprintf(stderr, "FAIL: %s: %s\n", test.name, error.what()); return 1;
        } catch (const Error& error) {
            std::fprintf(stderr, "FAIL: %s: HRESULT 0x%08lx\n", test.name, static_cast<unsigned long>(error.status)); return 1;
        } catch (...) { std::fprintf(stderr, "FAIL: %s: unexpected exception\n", test.name); return 1; }
    }
    std::printf("PASS: %zu offline binding cases; no driver, registry or NetCfg access.\n", cases.size());
    return 0;
}
