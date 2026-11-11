#pragma once

namespace {
const Adapter arriving = Target(previousId, 33);
void NewArrival(FakeSystem& s, bool enabled = false) {
    s.Healthy();
    s.adding = true;
    s.additionGuid = arriving.guid;
    s.targets.push_back(arriving);
    s.bindings.push_back({arriving.guid, enabled});
}
void OldBindingsUnchanged(const FakeSystem& s) {
    CheckTest(s.configuration.allowed && s.bindings[0].enabled && s.bindings[1].enabled);
    CheckTest(!s.Called("disarm") && !s.Called("arm"));
    for (const auto& change : s.bindingChanges) CheckTest(change.adapter == arriving.guid);
}
unsigned additionalWorkers = 0;
std::optional<Adapter> FakeInspectAddition(const std::atomic<bool>&, uint64_t luid,
                                         std::span<const AttachedAdapter> attached) {
    return InspectAddition(*preflightSystem, luid, attached);
}
HRESULT FakeAdditionalWorker(const std::atomic<bool>&, uint64_t luid) {
    ++additionalWorkers;
    return AddTarget(*preflightSystem, luid);
}
HRESULT EnsureFakeAddition(FakeSystem& s, uint64_t luid, const std::vector<AttachedAdapter>& attached, Adapter& output) {
    preflightSystem = &s;
    additionalWorkers = 0;
    const std::atomic<bool> stopped{s.stopped};
    return EnsureAddition(stopped, luid, attached, output, FakeInspectAddition, FakeAdditionalWorker);
}
std::vector<Case> AdditionCases() {
    return {
        {"arrival repairs only its own path", [] {
            FakeSystem s; NewArrival(s); Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_OK);
            CheckTest(additionalWorkers == 1 && SameTarget(output, arriving));
            CheckTest(s.bindings.back().enabled && s.bindingChanges.size() == 2 && s.At("disable") < s.At("enable"));
            OldBindingsUnchanged(s);
        }},
        {"unsupported arrival stays disabled without starting a worker", [] {
            FakeSystem s; NewArrival(s); s.targets.back().compatible = false;
            Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_FALSE);
            CheckTest(additionalWorkers == 0); s.NoMutation();
        }},
        {"enabled unsupported arrival is only disabled", [] {
            FakeSystem s; NewArrival(s, true); s.targets.back().compatible = false;
            Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_OK);
            CheckTest(!output.compatible && !s.bindings.back().enabled && s.bindingChanges.size() == 1 &&
                      !s.bindingChanges.front().enabled);
            OldBindingsUnchanged(s);
            s.calls.clear(); s.bindingChanges.clear();
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_FALSE);
            CheckTest(additionalWorkers == 0); s.NoMutation();
        }},
        {"media change during addition prevents enabling a stale target", [] {
            FakeSystem s; NewArrival(s);
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "disable") s.targets.back().compatible = false;
            };
            CheckTest(AddTarget(s, arriving.luid) == HRESULT_FROM_WIN32(ERROR_RETRY));
            CheckTest(!s.bindings.back().enabled && !s.Called("enable")); OldBindingsUnchanged(s);
        }},
        {"excluded arrival detaches only its own paths and stays detached", [] {
            FakeSystem s; NewArrival(s, true); s.targets.back().excluded = true;
            s.bindings.push_back({arriving.guid, false});
            Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_OK);
            CheckTest(output.excluded && !s.bindings[2].enabled && !s.bindings[3].enabled);
            CheckTest(s.bindingChanges.size() == 1 && !s.bindingChanges.front().enabled);
            OldBindingsUnchanged(s);
            s.calls.clear(); s.bindingChanges.clear();
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_FALSE);
            CheckTest(additionalWorkers == 0); s.NoMutation();
            s.targets.back().excluded = false;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_OK);
            CheckTest(s.bindings[2].enabled && s.bindings[3].enabled);
            OldBindingsUnchanged(s);
        }},
        {"exclusion changed during addition never enables the stale target", [] {
            FakeSystem s; NewArrival(s);
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "disable") s.targets.back().excluded = true;
            };
            CheckTest(AddTarget(s, arriving.luid) == HRESULT_FROM_WIN32(ERROR_RETRY));
            CheckTest(!s.bindings.back().enabled && !s.Called("enable")); OldBindingsUnchanged(s);
        }},
        {"named update resolves the current identity and rejects ambiguity", [] {
            FakeSystem s; NewArrival(s, true); s.targets.back().name = L"Ethernet café";
            s.targets.back().excluded = true;
            CheckTest(ApplyNamedTarget(s, L"Ethernet café") == S_OK && !s.bindings.back().enabled);
            OldBindingsUnchanged(s);
            s.calls.clear(); s.bindingChanges.clear();
            s.targets.back().guid = foreignId;
            s.targets.back().luid = 44;
            s.additionGuid = foreignId;
            s.bindings.back() = {foreignId, true};
            CheckTest(ApplyNamedTarget(s, L"Ethernet café") == S_OK && !s.bindings.back().enabled);
            CheckTest(s.bindingChanges.size() == 1 && s.bindingChanges[0].adapter == foreignId);
            s.calls.clear(); s.bindingChanges.clear();
            s.targets[0].name = s.targets.back().name;
            CheckTest(ApplyNamedTarget(s, L"Ethernet café") == HRESULT_FROM_WIN32(ERROR_DUP_NAME));
            s.NoMutation();
        }},
        {"replacement using the same LUID still respects its excluded name", [] {
            FakeSystem s; NewArrival(s, true);
            s.targets.back().guid = foreignId;
            s.targets.back().name = L"Ethernet";
            s.targets.back().excluded = true;
            s.bindings.back().adapter = foreignId;
            s.additionGuid = foreignId;
            auto attached = Attached(Pair());
            attached.push_back({arriving, true});
            Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, attached, output) == S_OK);
            CheckTest(output.guid == foreignId && output.excluded && !s.bindings.back().enabled);
            CheckTest(s.bindingChanges.size() == 1 && s.bindingChanges[0].adapter == foreignId &&
                      !s.bindingChanges[0].enabled);
        }},
        {"automatically enabled but unattached path is retried", [] {
            FakeSystem s; NewArrival(s, true);
            CheckTest(AddTarget(s, arriving.luid) == S_OK && s.bindings.back().enabled);
            OldBindingsUnchanged(s);
        }},
        {"only event target is changed when several new paths exist", [] {
            FakeSystem s; NewArrival(s);
            s.targets.push_back(Target(foreignId, 44)); s.bindings.push_back({foreignId, false});
            CheckTest(AddTarget(s, arriving.luid) == S_OK && !s.bindings.back().enabled);
            OldBindingsUnchanged(s);
        }},
        {"interface without a filter path does not start a worker", [] {
            FakeSystem s; NewArrival(s); Adapter output = Target();
            CheckTest(EnsureFakeAddition(s, 99, Attached(Pair()), output) == S_FALSE && additionalWorkers == 0);
            CheckTest(SameTarget(output, Target()) && !s.Called("lock")); s.NoMutation();
        }},
        {"duplicate arrival is read-only after successful attachment", [] {
            FakeSystem s; NewArrival(s); Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_OK);
            s.calls.clear(); s.bindingChanges.clear();
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(s.targets), output) == S_FALSE && additionalWorkers == 0);
            s.NoMutation();
        }},
        {"disabled adapter with enabled path need not be running", [] {
            FakeSystem s; NewArrival(s, true); s.targets.back().expectRunning = false; Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) == S_FALSE);
            CheckTest(additionalWorkers == 0); s.NoMutation();
        }},
        {"healthy arrival does not repair unrelated disabled binding", [] {
            FakeSystem s; NewArrival(s, true); s.bindings[0].enabled = false; Adapter output;
            CheckTest(EnsureFakeAddition(s, arriving.luid, {{arriving, true}}, output) == S_FALSE && additionalWorkers == 0);
            CheckTest(!s.bindings[0].enabled); s.NoMutation();
        }},
        {"enable failure rolls back only new adapter", [] {
            FakeSystem s; NewArrival(s); s.fail = "enable";
            CheckTest(AddTarget(s, arriving.luid) == E_ACCESSDENIED && !s.bindings.back().enabled);
            OldBindingsUnchanged(s);
        }},
        {"disarmed or installer-controlled configuration prohibits addition", [] {
            for (const unsigned mode : {0u, 1u, 2u}) {
                FakeSystem s; NewArrival(s);
                if (mode == 0) s.configuration.allowed = false;
                if (mode == 1) s.configuration.recovery = RecoveryPermission::InstallerControlled;
                if (mode == 2) s.configuration.recovery = RecoveryPermission::Legacy;
                Adapter output;
                CheckTest(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output) ==
                    HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED) && additionalWorkers == 0);
                s.NoMutation();
            }
        }},
        {"topology change before enable disables only arriving path", [] {
            FakeSystem s; NewArrival(s);
            s.onStep = [&](const char* name) {
                if (std::string_view(name) == "disable") s.targets.pop_back();
            };
            CheckTest(AddTarget(s, arriving.luid) == HRESULT_FROM_WIN32(ERROR_RETRY));
            CheckTest(!s.bindings.back().enabled && !s.Called("enable")); OldBindingsUnchanged(s);
        }},
        {"cancel or OOM during addition preserves previous paths", [] {
            for (const bool oom : {false, true}) {
                FakeSystem s; NewArrival(s);
                s.onStep = [&](const char* name) {
                    if (std::string_view(name) != "disable") return;
                    if (oom) throw std::bad_alloc();
                    s.stopped = true;
                };
                CheckTest(AddTarget(s, arriving.luid) ==
                    (oom ? E_OUTOFMEMORY : HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)));
                CheckTest(!s.bindings.back().enabled); OldBindingsUnchanged(s);
            }
        }},
        {"arrival reboot stops Apply without globally disarming filter", [] {
            for (const bool enable : {false, true}) {
                FakeSystem s; NewArrival(s, true);
                if (enable) s.rebootEnable = true; else s.rebootDisable = true;
                CheckTest(AddTarget(s, arriving.luid) == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED));
                CheckTest(s.configuration.recovery == RecoveryPermission::InstallerControlled);
                CheckTest(s.bindingChanges.size() == (enable ? 2u : 1u)); OldBindingsUnchanged(s);
            }
        }},
        {"arrival inspection failure and missing path never start worker", [] {
            for (const bool missing : {false, true}) {
                FakeSystem s; NewArrival(s);
                if (missing) s.bindings.pop_back(); else s.fail = "resolve";
                Adapter output;
                CheckTest(FAILED(EnsureFakeAddition(s, arriving.luid, Attached(Pair()), output)) && additionalWorkers == 0);
                s.NoMutation();
            }
        }}
    };
}
} // namespace
