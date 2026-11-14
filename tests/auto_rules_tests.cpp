// Проверяет очередь автоправил вместе с настоящими Ingest и RuleStore без драйвера.
#include "../main.cpp"
#include "package_test_path.h"

#include <cstdlib>
#include <iostream>
#include <thread>

namespace {
DriverVerdictSession testSession;
std::vector<std::pair<uint64_t, pmkext::Verdict>> verdicts;

void CheckAuto(bool value, const char* message) {
    if (!value) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}
}

DriverVerdictRequest test_register_driver_verdict_request(uint64_t id) {
    return testSession.Receive(id);
}

bool test_process_verdict(DriverVerdictRequest request, pmkext::Verdict verdict) {
    uint64_t id = 0;
    if (!testSession.Consume(request, id)) return false;
    verdicts.emplace_back(id, verdict);
    return true;
}

DWORD test_clear_driver_cache() { return ERROR_SUCCESS; }
DriverVerdictRequest test_firewallxndisfilter_register_request(uint64_t) { return {}; }
bool test_firewallxndisfilter_process_verdict(DriverVerdictRequest,
                                             firewallxndisfilter::Client::Verdict) { return false; }

struct IngestTestAccess {
    static AskRequestId ParkIgmp(Ingest& ingest, uint64_t id, const wchar_t* remote,
                                 DWORD pid = 0, Proto proto = ProtoFromNumber(2),
                                 Dir dir = Dir::Out, bool ambiguous = false,
                                 const wchar_t* localAddress = L"127.0.0.1") {
        Ingest::PendingGroup group;
        group.flow.pid = pid;
        group.flow.dir = dir;
        group.flow.ownerAmbiguous = ambiguous;
        IpAddr local, destination;
        CheckAuto(ParseIpAddr(localAddress, local) && ParseIpAddr(remote, destination),
                  "invalid test address");
        group.flow.key = MakeFlowKey(proto, local, destination, 0, 0);
        group.flow.app = std::make_shared<const ProcessPathInfo>(L"", nullptr);
        group.keyHash = AskHash(L"", pid, group.flow.key, dir, -1, -1, ambiguous);
        group.driverSession = testSession.active();
        group.requests.emplace_back(testSession.Receive(id));
        group.requests.back().payloadLayer = 3;
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ++ingest.calls_;
        ++ingest.waiting_;
        const auto inserted = ingest.AddPendingLocked(std::move(group));
        return { testSession.active(), inserted->first };
    }

    static AskRequestId Park(Ingest& ingest, const std::wstring& path, uint64_t id,
                             uint16_t localPort, DWORD pid = 0, uint16_t remotePort = 443,
                             Proto proto = Proto::Tcp, const wchar_t* localAddress = L"192.0.2.1",
                             const wchar_t* remoteAddress = L"198.51.100.1") {
        Ingest::PendingGroup group;
        group.flow.pid = pid ? pid : GetCurrentProcessId();
        group.flow.dir = Dir::Out;
        IpAddr local, remote;
        CheckAuto(ParseIpAddr(localAddress, local) && ParseIpAddr(remoteAddress, remote),
                  "invalid test address");
        group.flow.key = MakeFlowKey(proto, local, remote, localPort, remotePort);
        group.flow.app = std::make_shared<const ProcessPathInfo>(path,
            ProcessImagePathRef(group.flow.pid)->process);
        group.keyHash = AskHash(path, group.flow.pid, group.flow.key, group.flow.dir);
        group.driverSession = testSession.active();
        group.requests.emplace_back(testSession.Receive(id));
        group.requests.back().payloadLayer = 3;
        group.requests.back().tcpFlags = 0x010;
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ++ingest.calls_;
        ++ingest.waiting_;
        const auto inserted = ingest.AddPendingLocked(std::move(group));
        return { testSession.active(), inserted->first };
    }
};

namespace {

struct TempDirectory {
    std::wstring path;
    TempDirectory() {
        wchar_t directory[MAX_PATH]{}, name[MAX_PATH]{};
        CheckAuto(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxa", 0, name),
                  "cannot create temporary directory");
        CheckAuto(DeleteFileW(name) && CreateDirectoryW(name, nullptr), "cannot create temporary directory");
        path = name;
    }
    ~TempDirectory() {
        for (const wchar_t* name : { L"chrome.exe", L"msedge.exe", L"curl.exe", L"unknown.exe",
                                     L"devenv.exe", L"winget.exe", L"wget.exe", L"pwsh.exe",
                                     L"powershell.exe", L"python.exe", L"python3.exe", L"perl.exe",
                                     L"FeedbackHub.exe", L"MSPUB.EXE", L"POWERPNT.EXE", L"WINWORD.EXE",
                                     L"BackgroundDownload.exe", L"Blend.exe", L"PerfWatson2.exe",
                                     L"iTunes.exe", L"Wireshark.exe", L"SIHClient.exe", L"taskhostw.exe",
                                     L"CopilotApp.exe", L"explorer.exe", L"MpCmdRun.exe",
                                     L"Discord.exe", L"obs64.exe", L"OneDrive.exe",
                                     L"OneDrive.Sync.Service.exe", L"OneDriveUpdaterService.exe",
                                     L"msiexec.exe", L"YandexDisk4.exe",
                                     L"AnyDesk.exe", L"RustDesk.exe", L"TeamViewer.exe", L"TeamViewer_Service.exe",
                                     L"AppHostRegistrationVerifier.exe", L"backgroundTaskHost.exe",
                                     L"HxOutlook.exe", L"WWAHost.exe", L"Photos.exe", L"wslservice.exe", L"settings.db",
                                     L"settings.db-wal", L"settings.db-shm", L"generation.db",
                                     L"generation.db-wal", L"generation.db-shm" })
            DeleteFileW((path + L"\\" + name).c_str());
        RemoveDirectoryW(path.c_str());
    }
    std::wstring File(const wchar_t* name) const { return path + L"\\" + name; }
};

struct AppStorageTestAccess {
    struct Fixture {
        App app;
        Fixture() {
            verdicts.clear();
            Ingest::Instance().Attach(&app.rules_, nullptr);
            Ingest::Instance().BeginDriverSession(testSession.Begin());
        }
        ~Fixture() {
            Ingest::Instance().EndDriverSession(testSession.End());
            Ingest::Instance().Detach();
        }
    };

    struct BlockedCheck {
        HANDLE gate;
        std::shared_ptr<AutoSignatureCheck> check;
    };

    static DWORD WINAPI RunBlocked(void* raw) {
        std::unique_ptr<BlockedCheck> context(static_cast<BlockedCheck*>(raw));
        if (WaitForSingleObject(context->gate, 30000) != WAIT_OBJECT_0) return 1;
        return AutoSignatureCheck::Run(new std::shared_ptr<AutoSignatureCheck>(context->check));
    }

    static void StartBlocked(App& app, const std::wstring& path, HANDLE gate) {
        app.autoSignature_ = std::make_shared<AutoSignatureCheck>();
        app.autoSignature_->path = path;
        app.autoSignature_->rulePath = path;
        auto* context = new BlockedCheck{gate, app.autoSignature_};
        app.autoSignatureThread_ = CreateThread(nullptr, 0, &RunBlocked, context, 0, nullptr);
        if (!app.autoSignatureThread_) delete context;
        CheckAuto(app.autoSignatureThread_ != nullptr, "cannot start blocked signature check");
    }

    static void Complete(App& app) {
        while (!app.autoRequests_.empty()) {
            if (app.autoSignatureThread_)
                CheckAuto(WaitForSingleObject(app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                          "signature check timed out");
            app.ProcessAutoRules();
        }
    }

    static void IgmpAutomatic() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto first = IngestTestAccess::ParkIgmp(Ingest::Instance(), 31, L"224.0.0.22");
        const auto second = IngestTestAccess::ParkIgmp(Ingest::Instance(), 32, L"239.255.255.250");
        const auto otherPid = IngestTestAccess::ParkIgmp(Ingest::Instance(), 33, L"224.0.0.22", 4);
        const auto incoming = IngestTestAccess::ParkIgmp(Ingest::Instance(), 34, L"224.0.0.22", 0,
                                                        ProtoFromNumber(2), Dir::In);
        const auto unicast = IngestTestAccess::ParkIgmp(Ingest::Instance(), 35, L"192.0.2.10");
        const auto otherProto = IngestTestAccess::ParkIgmp(Ingest::Instance(), 36, L"224.0.0.22", 0,
                                                          Proto::Udp);
        f.app.DrainIngest();
        CheckAuto(!Ingest::Instance().IsPending(first) && !Ingest::Instance().IsPending(second) &&
                  Ingest::Instance().IsPending(otherPid) && Ingest::Instance().IsPending(incoming) &&
                  Ingest::Instance().IsPending(unicast) && Ingest::Instance().IsPending(otherProto) &&
                  verdicts.size() == 2 &&
                  std::all_of(verdicts.begin(), verdicts.end(), [](const auto& verdict) {
                      return verdict.second == pmkext::Verdict::PermanentAccept;
                  }), "IGMP automatic rule answered an unrelated request or missed multicast");
        const auto rules = f.app.rules_.PostApps();
        CheckAuto(rules.size() == 1 && rules.front().action == RuleAction::Allow &&
                  rules.front().proto == ProtoFromNumber(2) && rules.front().dir == Dir::Out &&
                  rules.front().conds == (CondProto | CondDirection | CondRemoteAddr | CondPidZero) &&
                  rules.front().remoteAddrs.size() == 1 && rules.front().remoteAddrs.front().prefix == 4 &&
                  f.app.queue_.size() == 4 && !f.app.autoSignature_ && f.app.autoRequests_.empty(),
                  "IGMP automatic rule was not restricted or started signature verification");
    }

    static void IgmpInboundAutomatic() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto outgoing = IngestTestAccess::ParkIgmp(Ingest::Instance(), 81, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(!Ingest::Instance().IsPending(outgoing) && f.app.rules_.PostApps().size() == 1,
                  "existing outgoing IGMP preset was not created");
        const auto first = IngestTestAccess::ParkIgmp(Ingest::Instance(), 82, L"192.168.0.1", 0,
            ProtoFromNumber(2), Dir::In, false, L"224.0.0.1");
        const auto second = IngestTestAccess::ParkIgmp(Ingest::Instance(), 83, L"203.0.113.12", 0,
            ProtoFromNumber(2), Dir::In, false, L"239.255.255.255");
        const auto otherPid = IngestTestAccess::ParkIgmp(Ingest::Instance(), 84, L"192.168.0.1", 4,
            ProtoFromNumber(2), Dir::In, false, L"224.0.0.1");
        const auto unicast = IngestTestAccess::ParkIgmp(Ingest::Instance(), 85, L"224.0.0.22", 0,
            ProtoFromNumber(2), Dir::In, false, L"192.0.2.1");
        const auto otherProto = IngestTestAccess::ParkIgmp(Ingest::Instance(), 86, L"192.168.0.1", 0,
            Proto::Udp, Dir::In, false, L"224.0.0.1");
        f.app.DrainIngest();
        CheckAuto(!Ingest::Instance().IsPending(first) && !Ingest::Instance().IsPending(second) &&
                  Ingest::Instance().IsPending(otherPid) && Ingest::Instance().IsPending(unicast) &&
                  Ingest::Instance().IsPending(otherProto) && verdicts.size() == 3 &&
                  std::all_of(verdicts.begin(), verdicts.end(), [](const auto& verdict) {
                      return verdict.second == pmkext::Verdict::PermanentAccept;
                  }), "incoming IGMP automatic rule answered an unrelated request or missed multicast");
        const auto rules = f.app.rules_.PostApps();
        CheckAuto(rules.size() == 2 && rules.front().dir == Dir::Out &&
                  rules.front().conds == (CondProto | CondDirection | CondRemoteAddr | CondPidZero) &&
                  rules.back().action == RuleAction::Allow &&
                  rules.back().proto == ProtoFromNumber(2) && rules.back().dir == Dir::In &&
                  rules.back().conds == (CondProto | CondDirection | CondLocalAddr | CondPidZero) &&
                  rules.back().localAddrs.size() == 1 && rules.back().localAddrs.front().prefix == 4 &&
                  rules.back().remoteAddrs.empty() && f.app.queue_.size() == 3 &&
                  !f.app.autoSignature_ && f.app.autoRequests_.empty(),
                  "incoming IGMP automatic rule changed the outgoing rule or lost restrictions");
    }

    static void IgmpUnknownDirection() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 87, L"192.168.0.1", 0,
            ProtoFromNumber(2), Dir::Unknown, false, L"224.0.0.1");
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(id) && f.app.queue_.contains(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "unknown IGMP direction created an automatic rule");
    }

    static void IgmpInboundSetting() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 88, L"192.168.0.1", 0,
            ProtoFromNumber(2), Dir::In, false, L"224.0.0.1");
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.contains(id) && Ingest::Instance().IsPending(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "disabled automatic rules created incoming IGMP rule");
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        Ingest::Instance().Republish();
        f.app.DrainIngest();
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.queue_.empty() &&
                  f.app.rules_.PostApps().size() == 1 &&
                  f.app.rules_.PostApps().front().dir == Dir::In && verdicts.size() == 1,
                  "enabling automatic rules did not resolve incoming IGMP request");
    }

    static void IgmpInboundDisabledWhileQueued() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        f.app.askBusy_ = true;
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 89, L"192.168.0.1", 0,
            ProtoFromNumber(2), Dir::In, false, L"224.0.0.1");
        f.app.DrainIngest();
        CheckAuto(f.app.autoRequests_.size() == 1 && Ingest::Instance().IsPending(id),
                  "incoming IGMP request was not queued while UI was busy");
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        f.app.askBusy_ = false;
        f.app.ProcessAutoRules();
        CheckAuto(Ingest::Instance().IsPending(id) && f.app.queue_.contains(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "disabled automatic rules still created incoming IGMP rule");
    }

    static void IgmpInboundManualIsolation() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        f.app.askBusy_ = true;
        const auto first = IngestTestAccess::ParkIgmp(Ingest::Instance(), 90, L"192.168.0.1", 0,
            ProtoFromNumber(2), Dir::In, false, L"224.0.0.1");
        f.app.DrainIngest();
        CheckAuto(f.app.autoRequests_.size() == 1, "incoming IGMP request was not queued");
        f.app.autoRequests_.front().deadline = GetTickCount64() - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(first), "expired incoming IGMP request was not returned to user");
        f.app.askBusy_ = false;
        const auto second = IngestTestAccess::ParkIgmp(Ingest::Instance(), 91, L"203.0.113.12", 0,
            ProtoFromNumber(2), Dir::In, false, L"224.0.0.251");
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(first) && Ingest::Instance().IsPending(second) &&
                  f.app.queue_.contains(first) && f.app.queue_.contains(second) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "incoming IGMP automatic rule answered a manual request");
    }

    static void IgmpAmbiguousOwner() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 37, L"224.0.0.22", 0,
                                                   ProtoFromNumber(2), Dir::Out, true);
        const auto incoming = IngestTestAccess::ParkIgmp(Ingest::Instance(), 92, L"192.168.0.1", 0,
            ProtoFromNumber(2), Dir::In, true, L"224.0.0.1");
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(id) && f.app.queue_.contains(id) &&
                  Ingest::Instance().IsPending(incoming) && f.app.queue_.contains(incoming) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "ambiguous IGMP request created an automatic rule");
    }

    static void IgmpSetting() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 38, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.contains(id) && Ingest::Instance().IsPending(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(), "disabled IGMP created a rule");
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        Ingest::Instance().Republish();
        f.app.DrainIngest();
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.queue_.empty() &&
                  f.app.rules_.PostApps().size() == 1 && verdicts.size() == 1,
                  "enabling automatic rules did not resolve the existing IGMP request");
    }

    static void IgmpDisabledWhileQueued() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        f.app.askBusy_ = true;
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 41, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(f.app.autoRequests_.size() == 1 && Ingest::Instance().IsPending(id),
                  "IGMP request was not queued while the UI was busy");
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        f.app.askBusy_ = false;
        f.app.ProcessAutoRules();
        CheckAuto(Ingest::Instance().IsPending(id) && f.app.queue_.contains(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "disabled automatic rules still created an IGMP rule");
    }

    static void IgmpOldSession() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        f.app.askBusy_ = true;
        const auto id = IngestTestAccess::ParkIgmp(Ingest::Instance(), 42, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(f.app.autoRequests_.size() == 1, "IGMP request was not queued");
        Ingest::Instance().EndDriverSession(testSession.End());
        Ingest::Instance().BeginDriverSession(testSession.Begin());
        f.app.askBusy_ = false;
        f.app.ProcessAutoRules();
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.autoRequests_.empty() &&
                  f.app.queue_.empty() && f.app.rules_.Count() == 0 && verdicts.empty(),
                  "stale IGMP request created an automatic rule");
    }

    static void IgmpManualIsolation() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        f.app.askBusy_ = true;
        const auto first = IngestTestAccess::ParkIgmp(Ingest::Instance(), 43, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(f.app.autoRequests_.size() == 1, "IGMP request was not queued");
        f.app.autoRequests_.front().deadline = GetTickCount64() - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(first), "expired IGMP request was not returned for manual handling");
        f.app.askBusy_ = false;
        const auto second = IngestTestAccess::ParkIgmp(Ingest::Instance(), 44, L"224.0.0.251");
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(first) && Ingest::Instance().IsPending(second) &&
                  f.app.queue_.contains(first) && f.app.queue_.contains(second) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "automatic IGMP rule answered a request returned for manual handling");
    }

    static void IgmpUnrelatedManualRequest() {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        f.app.askBusy_ = true;
        const auto manual = IngestTestAccess::ParkIgmp(Ingest::Instance(), 45, L"192.0.2.10");
        f.app.DrainIngest();
        CheckAuto(f.app.autoRequests_.size() == 1, "pathless request was not queued");
        f.app.autoRequests_.front().deadline = GetTickCount64() - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(manual), "expired request was not returned for manual handling");
        f.app.askBusy_ = false;
        const auto igmp = IngestTestAccess::ParkIgmp(Ingest::Instance(), 46, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(manual) && f.app.queue_.contains(manual) &&
                  !Ingest::Instance().IsPending(igmp) && f.app.rules_.PostApps().size() == 1 &&
                  verdicts.size() == 1 && verdicts.front().first == 46,
                  "unrelated manual request prevented automatic IGMP rule");
    }

    static void IgmpDuringSignatureCheck(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const HANDLE gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CheckAuto(gate != nullptr, "cannot create signature gate");
        StartBlocked(f.app, signedPath, gate);
        const auto first = IngestTestAccess::Park(Ingest::Instance(), signedPath, 39, 40039);
        const auto igmp = IngestTestAccess::ParkIgmp(Ingest::Instance(), 40, L"224.0.0.22");
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(igmp) && Ingest::Instance().IsPending(first) &&
                  f.app.rules_.PostApps().empty() && verdicts.empty(),
                  "IGMP request bypassed an active signature check");
        SetEvent(gate);
        CheckAuto(WaitForSingleObject(f.app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                  "blocked signature check did not finish");
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(first) && !Ingest::Instance().IsPending(igmp) &&
                  f.app.rules_.PostApps().size() == 1 && verdicts.size() == 2,
                  "IGMP automatic rule did not resume after signature verification");
        CloseHandle(gate);
    }

    static void UserPushService() {
        const std::wstring path = SystemDirFile(L"svchost.exe");
        ServiceInfo::Version(true);
        DWORD pid = 0;
        for (const ServiceEntry& service : ServiceInfo::All(true)) {
            if (!service.running() || !service.pid ||
                !ServiceNameMatches(L"WpnUserService_*", service.name)) continue;
            const auto processPath = ProcessImagePathRef(service.pid);
            const auto hosted = ServiceInfo::ServicesOfPid(service.pid, true);
            if (processPath && processPath->process && processPath->process->alive() &&
                EqualNoCase(processPath->text, path) && hosted && hosted->size() == 1 &&
                EqualNoCase(hosted->front().name, service.name)) {
                pid = service.pid;
                break;
            }
        }
        if (!pid) {
            std::cout << "user push automatic rules test skipped: eligible service not running\n";
            return;
        }

        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), path, 47, 40047, pid);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_), "user push signature check did not start");
        Complete(f.app);
        const auto rules = f.app.rules_.ForApp(path);
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.queue_.empty() &&
                  rules.size() == 1 && rules[0].services.size() == 1 &&
                  rules[0].services[0].name == L"WpnUserService_*" && verdicts.size() == 1 &&
                  verdicts[0].second == pmkext::Verdict::Accept,
                  "user push service request was not resolved by the wildcard preset");
        std::cout << "user push automatic rules test passed\n";
    }

    static void Disabled(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 1, 40001);
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.size() == 1 && f.app.autoRequests_.empty() &&
                  !f.app.autoSignature_ && Ingest::Instance().IsPending(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(), "disabled setting created a rule");
    }

    static void EnableForExisting(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 7, 40007);
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.size() == 1, "existing request was not queued");
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        Ingest::Instance().Republish();
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.empty() && f.app.autoSignature_,
                  "existing request was not moved to automatic verification");
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.queue_.empty() &&
                  f.app.rules_.Count() == 4 && verdicts.size() == 1,
                  "enabling automatic rules did not resolve the existing request");
    }

    static void Signed(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto first = IngestTestAccess::Park(Ingest::Instance(), signedPath, 2, 40002);
        const auto second = IngestTestAccess::Park(Ingest::Instance(), signedPath, 3, 40003);
        f.app.DrainIngest();
        CheckAuto(f.app.autoSignature_ && f.app.queue_.empty(), "signature check did not start");
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(first) && !Ingest::Instance().IsPending(second) &&
                  verdicts.size() == 2 && f.app.queue_.empty(), "signed requests were not resolved together");
        CheckAuto(f.app.rules_.Count() == 4, "automatic mode did not choose the first matching browser template");
    }

    static void SignedCapturedPreset(const std::wstring& path, uint64_t id, size_t expectedRules,
                                     uint16_t localPort, uint16_t remotePort, Proto proto,
                                     const wchar_t* localAddress, const wchar_t* remoteAddress) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto request = IngestTestAccess::Park(Ingest::Instance(), path, id, localPort, 0,
                                                    remotePort, proto, localAddress, remoteAddress);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_), "captured preset signature check did not start");
        Complete(f.app);
        const auto rules = f.app.rules_.ForApp(path);
        CheckAuto(!Ingest::Instance().IsPending(request) && f.app.queue_.empty() &&
                  rules.size() == expectedRules && verdicts.size() == 1 &&
                  (verdicts[0].second == pmkext::Verdict::Accept ||
                   verdicts[0].second == pmkext::Verdict::PermanentAccept),
                  "signed captured preset did not resolve its request automatically");
    }

    static void UnattributedService(const std::wstring& path, uint64_t id, uint16_t remotePort,
                                    Proto proto = Proto::Tcp, uint16_t localPort = 41000,
                                    const wchar_t* localAddress = L"192.0.2.1",
                                    const wchar_t* remoteAddress = L"198.51.100.1") {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto request = IngestTestAccess::Park(Ingest::Instance(), path, id, localPort, 0, remotePort,
                                                    proto, localAddress, remoteAddress);
        f.app.DrainIngest();
        CheckAuto(Ingest::Instance().IsPending(request) && f.app.queue_.size() == 1 &&
                  !f.app.autoSignature_ && f.app.rules_.Count() == 0 && verdicts.empty(),
                  "service-only preset automatically allowed a process without the required service");
    }

    static void SignedPackage(const std::wstring& path) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), path, 8, 40008);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_), "package signature check did not start");
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.queue_.empty() &&
                  f.app.rules_.Count() == 3 && verdicts.size() == 1,
                  "signed package request was not resolved automatically");
    }

    static void ManualFallback(const std::wstring& path, bool hasTemplate) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), path, 4, 40004);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_) == hasTemplate, "unexpected signature check");
        Complete(f.app);
        CheckAuto(Ingest::Instance().IsPending(id) && f.app.queue_.size() == 1 &&
                  f.app.rules_.Count() == 0 && verdicts.empty(), "fallback lost or answered a request");
    }

    static void DisabledDuringCheck(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 5, 40005);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_), "signature check did not start");
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, false), "setting write failed");
        Complete(f.app);
        CheckAuto(Ingest::Instance().IsPending(id) && f.app.queue_.size() == 1 &&
                  f.app.rules_.Count() == 0 && verdicts.empty(), "disabled check created a rule");
    }

    static void TimedOutRequests(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const HANDLE gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CheckAuto(gate != nullptr, "cannot create signature gate");
        StartBlocked(f.app, signedPath, gate);
        const auto first = IngestTestAccess::Park(Ingest::Instance(), signedPath, 10, 40010);
        const auto second = IngestTestAccess::Park(Ingest::Instance(), signedPath, 11, 40011);
        const ULONGLONG before = GetTickCount64();
        f.app.DrainIngest();
        const ULONGLONG after = GetTickCount64();
        CheckAuto(f.app.autoRequests_.size() == 2 && f.app.queue_.empty(), "blocked checks were not queued");
        for (const auto& request : f.app.autoRequests_)
            CheckAuto(request.deadline >= before + 5000 && request.deadline <= after + 5000,
                      "automatic request did not receive a five-second deadline");
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.empty(), "request returned before its deadline");

        f.app.askBusy_ = true;
        f.app.autoRequests_.front().deadline = GetTickCount64() - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(first) && !f.app.queue_.contains(second) &&
                  f.app.autoRequests_.size() == 1 && f.app.autoSignatureAbandoned_ &&
                  Ingest::Instance().IsPending(first) && verdicts.empty(),
                  "expired request was not returned while the UI was busy");
        Ingest::Instance().Republish();
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.size() == 1 && f.app.queue_.contains(first) &&
                  f.app.autoRequests_.size() == 1 && !f.app.autoRequestIds_.contains(first),
                  "republishing restarted or duplicated an expired request");

        f.app.autoRequests_.front().deadline = GetTickCount64() - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.autoRequests_.empty() && f.app.queue_.contains(first) &&
                  f.app.queue_.contains(second) && Ingest::Instance().IsPending(second) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "blocked worker prevented a later request from timing out");
        SetEvent(gate);
        CheckAuto(WaitForSingleObject(f.app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                  "blocked signature check did not finish");
        f.app.ProcessAutoRules();
        CheckAuto(!f.app.autoSignature_ && f.app.queue_.size() == 2 &&
                  Ingest::Instance().IsPending(first) && Ingest::Instance().IsPending(second) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "late trusted result changed an expired request");
        CheckAuto(Ingest::Instance().AnswerOnce(first, RuleAction::Block) &&
                  Ingest::Instance().AnswerOnce(second, RuleAction::Block),
                  "could not answer expired requests manually");
        f.app.queue_.Prune();
        f.app.askBusy_ = false;
        const auto next = IngestTestAccess::Park(Ingest::Instance(), signedPath, 12, 40012);
        f.app.DrainIngest();
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(next) && f.app.rules_.Count() == 4 &&
                  verdicts.size() == 3, "automatic verification did not resume after a timeout");
        CloseHandle(gate);
    }

    static void ManualRequestIsolation(const std::wstring& signedPath,
                                       const std::wstring& otherSignedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const HANDLE gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CheckAuto(gate != nullptr, "cannot create signature gate");
        StartBlocked(f.app, signedPath, gate);
        const auto first = IngestTestAccess::Park(Ingest::Instance(), signedPath, 16, 40016);
        const auto second = IngestTestAccess::Park(Ingest::Instance(), signedPath, 17, 40017);
        f.app.DrainIngest();
        f.app.autoRequests_.front().deadline = GetTickCount64() - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(first) && f.app.autoRequests_.size() == 1,
                  "first request did not expire independently");
        SetEvent(gate);
        CheckAuto(WaitForSingleObject(f.app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                  "blocked signature check did not finish");
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(first) && f.app.queue_.contains(second) &&
                  f.app.autoRequests_.empty() && !f.app.autoSignature_ &&
                  Ingest::Instance().IsPending(first) && Ingest::Instance().IsPending(second) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(),
                  "automatic rule could close an expired request for the same application");
        Ingest::Instance().Republish();
        f.app.DrainIngest();
        CheckAuto(f.app.queue_.size() == 2 && f.app.autoRequests_.empty(),
                  "related manual request was retried automatically");

        const auto other = IngestTestAccess::Park(Ingest::Instance(), otherSignedPath, 18, 40018);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_),
                  "manual request prevented verification of another application");
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(other) && Ingest::Instance().IsPending(first) &&
                  Ingest::Instance().IsPending(second) && f.app.queue_.size() == 2 && verdicts.size() == 1,
                  "another application's automatic rule changed manual requests");
        CloseHandle(gate);
    }

    static void FinishedBeforeDeadline(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 13, 40013);
        f.app.DrainIngest();
        CheckAuto(f.app.autoSignature_ &&
                  WaitForSingleObject(f.app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                  "signature check did not finish");
        const ULONGLONG now = GetTickCount64();
        f.app.autoSignature_->finishedAt = now - 2;
        f.app.autoRequests_.front().deadline = now - 1;
        f.app.askBusy_ = true;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.empty() && f.app.autoRequests_.size() == 1 &&
                  Ingest::Instance().IsPending(id) && verdicts.empty(),
                  "a timely verification expired while the UI was busy");
        f.app.askBusy_ = false;
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.rules_.Count() == 4 &&
                  verdicts.size() == 1, "timely verification did not resume after the UI became available");
    }

    static void FinishedAfterDeadline(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 14, 40014);
        f.app.DrainIngest();
        CheckAuto(f.app.autoSignature_ &&
                  WaitForSingleObject(f.app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                  "signature check did not finish");
        const ULONGLONG now = GetTickCount64();
        f.app.autoSignature_->finishedAt = now;
        f.app.autoRequests_.front().deadline = now - 1;
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.contains(id) && !f.app.autoSignature_ &&
                  Ingest::Instance().IsPending(id) && f.app.rules_.Count() == 0 && verdicts.empty(),
                  "late verification created an automatic rule");
    }

    static void TimeoutTimer(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const HANDLE gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CheckAuto(gate != nullptr, "cannot create signature gate");
        StartBlocked(f.app, signedPath, gate);
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 15, 40015);
        f.app.DrainIngest();
        const HWND window = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                                             HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
        CheckAuto(window != nullptr, "cannot create timer window");
        f.app.hwnd_ = window;
        const HWND otherWindow = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                                                 HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
        CheckAuto(otherWindow != nullptr, "cannot create unrelated timer window");
        // Таймер другого окна не должен прерывать ожидание этого окна.
        constexpr UINT_PTR kOtherTimerId = 4;
        CheckAuto(SetTimer(otherWindow, kOtherTimerId, 10, nullptr) != 0,
                  "cannot start unrelated timer");
        constexpr UINT_PTR kWatchdogTimerId = kAutoRulesTimerId + 1;
        CheckAuto(SetTimer(window, kWatchdogTimerId, 8000, nullptr) != 0,
                  "cannot start watchdog timer");
        // Раннее сообщение не должно возвращать запрос раньше срока.
        f.app.autoRequests_.front().deadline = GetTickCount64() + 10000;
        f.app.ScheduleAutoRulesTimer();
        CheckAuto(PostMessageW(window, WM_TIMER, kAutoRulesTimerId, 0) != FALSE,
                  "cannot post early timer message");
        MSG message{};
        CheckAuto(GetMessageW(&message, window, WM_TIMER, WM_TIMER) > 0 &&
                  message.wParam == kAutoRulesTimerId, "early timer message was not received");
        KillTimer(window, kAutoRulesTimerId);
        f.app.ProcessAutoRules();
        CheckAuto(f.app.queue_.empty() && Ingest::Instance().IsPending(id) &&
                  f.app.autoRequests_.size() == 1 && f.app.rules_.Count() == 0 && verdicts.empty(),
                  "early timer changed the pending request");

        // Пятисекундный срок отдельно проверяется в TimedOutRequests.
        const ULONGLONG deadline = GetTickCount64() + 250;
        f.app.autoRequests_.front().deadline = deadline;
        f.app.ScheduleAutoRulesTimer();
        do {
            CheckAuto(GetMessageW(&message, window, WM_TIMER, WM_TIMER) > 0,
                      "cannot retrieve automatic request timer message");
            CheckAuto(message.wParam != kWatchdogTimerId, "automatic request timer did not return the request");
            CheckAuto(message.wParam == kAutoRulesTimerId, "automatic request timer used the wrong ID");
            KillTimer(window, kAutoRulesTimerId);
            f.app.ProcessAutoRules();
            if (!f.app.queue_.contains(id))
                CheckAuto(Ingest::Instance().IsPending(id) && f.app.autoRequests_.size() == 1 &&
                          f.app.rules_.Count() == 0 && verdicts.empty(),
                          "early timer changed the pending request");
        } while (!f.app.queue_.contains(id));
        CheckAuto(GetTickCount64() >= deadline && Ingest::Instance().IsPending(id) &&
                  f.app.rules_.Count() == 0 && verdicts.empty(), "timer did not return the request on time");
        MSG otherMessage{};
        CheckAuto(PeekMessageW(&otherMessage, otherWindow, WM_TIMER, WM_TIMER, PM_REMOVE) &&
                  otherMessage.wParam == kOtherTimerId, "unrelated timer did not fire");
        SetEvent(gate);
        CheckAuto(WaitForSingleObject(f.app.autoSignatureThread_, 30000) == WAIT_OBJECT_0,
                  "blocked signature check did not finish");
        f.app.ProcessAutoRules();
        KillTimer(otherWindow, kOtherTimerId);
        KillTimer(window, kWatchdogTimerId);
        DestroyWindow(otherWindow);
        f.app.hwnd_ = nullptr;
        DestroyWindow(window);
        CloseHandle(gate);
    }

    static void ShutdownDuringCheck(const std::wstring& signedPath) {
        const HANDLE gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const HANDLE destroyed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CheckAuto(gate && destroyed, "cannot create shutdown events");
        auto app = std::make_unique<App>();
        StartBlocked(*app, signedPath, gate);
        std::weak_ptr<AutoSignatureCheck> check = app->autoSignature_;
        HANDLE worker = nullptr;
        CheckAuto(DuplicateHandle(GetCurrentProcess(), app->autoSignatureThread_, GetCurrentProcess(),
                                  &worker, 0, FALSE, DUPLICATE_SAME_ACCESS),
                  "cannot retain worker handle");
        std::thread shutdown([owned = std::move(app), destroyed]() mutable {
            owned.reset();
            SetEvent(destroyed);
        });
        const DWORD result = WaitForSingleObject(destroyed, 3000);
        const bool workerOwnsCheck = !check.expired();
        SetEvent(gate);
        shutdown.join();
        const DWORD finished = WaitForSingleObject(worker, 30000);
        CloseHandle(worker);
        CloseHandle(destroyed);
        CloseHandle(gate);
        CheckAuto(result == WAIT_OBJECT_0 && workerOwnsCheck && finished == WAIT_OBJECT_0 && check.expired(),
                  "application shutdown waited for or invalidated a blocked signature check");
    }

    static void OldSession(const std::wstring& signedPath) {
        Fixture f;
        CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
        const auto id = IngestTestAccess::Park(Ingest::Instance(), signedPath, 6, 40006);
        f.app.DrainIngest();
        CheckAuto(static_cast<bool>(f.app.autoSignature_), "signature check did not start");
        Ingest::Instance().EndDriverSession(testSession.End());
        Ingest::Instance().BeginDriverSession(testSession.Begin());
        Complete(f.app);
        CheckAuto(!Ingest::Instance().IsPending(id) && f.app.queue_.empty() &&
                  f.app.rules_.Count() == 0 && verdicts.empty(), "stale session created a rule");
    }
};

void GeneratedIgmp(const std::wstring& dbPath) {
    std::atomic_bool cancel{false};
    size_t progressCalls = 0;
    const auto result = RuleGenerator::VerifyCandidates({}, {}, cancel,
        [&](size_t completed, size_t total) {
            CheckAuto(completed == 0 && total == 0, "empty generation reported invalid progress");
            ++progressCalls;
        });
    CheckAuto(!result.cancelled && result.files.empty() && result.rules.size() == 2 && progressCalls == 1,
              "generation without files did not create both IGMP rules");
    IpAddr multicast;
    CheckAuto(ParseIpAddr(L"224.0.0.0", multicast), "invalid IGMP test address");
    for (Dir direction : {Dir::Out, Dir::In}) {
        const auto rule = std::find_if(result.rules.begin(), result.rules.end(),
            [&](const Rule& item) { return item.dir == direction; });
        CheckAuto(rule != result.rules.end() && rule->scope == RuleScope::PostApp &&
                  rule->appPath.empty() && rule->enabled && rule->action == RuleAction::Allow &&
                  rule->proto == ProtoFromNumber(2) &&
                  rule->conds == (CondProto | CondDirection | CondPidZero |
                                  (direction == Dir::Out ? CondRemoteAddr : CondLocalAddr)) &&
                  rule->remotePorts.empty() && rule->localPorts.empty(),
                  "generated IGMP rule lost its scope or restrictions");
        const auto& addresses = direction == Dir::Out ? rule->remoteAddrs : rule->localAddrs;
        const auto& otherAddresses = direction == Dir::Out ? rule->localAddrs : rule->remoteAddrs;
        CheckAuto(addresses.size() == 1 && addresses.front().addr == multicast &&
                  addresses.front().prefix == 4 && otherAddresses.empty(),
                  "generated IGMP rule lost its multicast range");

        AskRequest request;
        request.dir = direction;
        IpAddr local, remote;
        CheckAuto(ParseIpAddr(direction == Dir::Out ? L"192.0.2.1" : L"224.0.0.1", local) &&
                  ParseIpAddr(direction == Dir::Out ? L"224.0.0.22" : L"192.0.2.2", remote),
                  "invalid IGMP test flow");
        request.key = MakeFlowKey(ProtoFromNumber(2), local, remote, 0, 0);
        CheckAuto(RuleStore::MatchesRule(*rule, request.ToQuery()),
                  "generated IGMP rule did not match multicast traffic");
        request.pid = 4;
        CheckAuto(!RuleStore::MatchesRule(*rule, request.ToQuery()),
                  "generated IGMP rule matched a different PID");
        request.pid = 0;
        request.key.proto = Proto::Udp;
        CheckAuto(!RuleStore::MatchesRule(*rule, request.ToQuery()),
                  "generated IGMP rule matched a different protocol");
        request.key.proto = ProtoFromNumber(2);
        request.key.source = TrafficSource::Ndis;
        CheckAuto(!RuleStore::MatchesRule(*rule, request.ToQuery()),
                  "generated IGMP rule matched NDIS traffic");
        request.key.source = TrafficSource::Host;
        request.dir = direction == Dir::Out ? Dir::In : Dir::Out;
        CheckAuto(!RuleStore::MatchesRule(*rule, request.ToQuery()),
                  "generated IGMP rule matched the wrong direction");
        request.dir = direction;
        IpAddr unicast;
        CheckAuto(ParseIpAddr(L"192.0.2.3", unicast), "invalid unicast test address");
        if (direction == Dir::Out) request.key.remote = unicast;
        else request.key.local = unicast;
        CheckAuto(!RuleStore::MatchesRule(*rule, request.ToQuery()),
                  "generated IGMP rule matched a unicast address");
    }
    RuleStore store;
    std::wstring error;
    CheckAuto(store.AttachDatabase(dbPath, error) &&
              RulePresets::ApplyGenerated(store, result.rules) == 2 && store.dbError().empty(),
              "generated IGMP rules were not saved");
    store.DetachDatabase();
    RuleStore loaded;
    CheckAuto(loaded.LoadOnce(dbPath, error) && loaded.PostApps().size() == 2 &&
              RulePresets::ApplyGenerated(loaded, result.rules) == 0,
              "reloaded IGMP rules were lost or duplicated");
    for (Dir direction : {Dir::Out, Dir::In}) {
        AskRequest request;
        request.dir = direction;
        IpAddr local, remote;
        CheckAuto(ParseIpAddr(direction == Dir::Out ? L"192.0.2.1" : L"224.0.0.1", local) &&
                  ParseIpAddr(direction == Dir::Out ? L"224.0.0.22" : L"192.0.2.2", remote),
                  "invalid persisted IGMP test flow");
        request.key = MakeFlowKey(ProtoFromNumber(2), local, remote, 0, 0);
        Rule matched;
        CheckAuto(loaded.Match(request.ToQuery(), matched) && matched.dir == direction &&
                  matched.scope == RuleScope::PostApp,
                  "reloaded IGMP rule did not match in the rule store");
    }
    const auto cancelled = RuleGenerator::VerifyCandidates({}, {}, cancel,
        [&](size_t, size_t) { cancel.store(true); });
    CheckAuto(cancelled.cancelled && cancelled.rules.empty() && cancelled.files.empty(),
              "cancelled empty generation retained IGMP rules");
}

void GeneratedRules(const std::wstring& signedPath, const std::wstring& unsignedPath,
                    const std::wstring& servicePath) {
    const auto browser = RulePresets::Generate(signedPath, {});
    CheckAuto(browser.size() > 2, "generation did not include complete browser templates");
    CheckAuto(std::any_of(browser.begin(), browser.end(), [](const Rule& rule) {
        return rule.proto == Proto::Tcp && std::any_of(rule.remotePorts.begin(), rule.remotePorts.end(),
            [](const PortItem& port) { return port.from <= 80 && port.to >= 80; });
    }), "generation omitted HTTP not associated with a current connection");
    CheckAuto(std::any_of(browser.begin(), browser.end(), [](const Rule& rule) {
        return rule.proto == Proto::Tcp && std::any_of(rule.remotePorts.begin(), rule.remotePorts.end(),
            [](const PortItem& port) { return port.from <= 443 && port.to >= 443; });
    }), "generation omitted HTTPS");

    RuleStore store;
    Rule disabled = browser.front();
    disabled.enabled = false;
    const uint64_t disabledId = store.Add(disabled);
    Rule manual = browser.front();
    manual.action = manual.action == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow;
    const uint64_t manualId = store.Add(manual);
    const auto igmp = RulePresets::GenerateIgmp();
    CheckAuto(igmp.size() == 2, "missing IGMP presets");
    const auto outgoing = std::find_if(igmp.begin(), igmp.end(),
        [](const Rule& rule) { return rule.dir == Dir::Out; });
    const auto incoming = std::find_if(igmp.begin(), igmp.end(),
        [](const Rule& rule) { return rule.dir == Dir::In; });
    CheckAuto(outgoing != igmp.end() && incoming != igmp.end(), "missing IGMP preset direction");
    Rule disabledIgmp = *outgoing;
    disabledIgmp.enabled = false;
    const uint64_t disabledIgmpId = store.Add(disabledIgmp);
    Rule manualIgmp = *outgoing;
    manualIgmp.action = RuleAction::Block;
    const uint64_t manualIgmpId = store.Add(manualIgmp);
    Rule global = *incoming;
    global.scope = RuleScope::Global;
    const uint64_t globalId = store.Add(global);
    auto generated = browser;
    generated.insert(generated.end(), igmp.begin(), igmp.end());
    const uint64_t before = store.version();
    const size_t added = RulePresets::ApplyGenerated(store, generated);
    CheckAuto(added > 0 && store.version() == before + 1,
              "generated rules were not saved as one batch");
    Rule existing;
    CheckAuto(store.Get(disabledId, existing) && !existing.enabled && existing.priority == 0,
              "generation enabled or moved a disabled rule");
    CheckAuto(store.Get(manualId, existing) && existing.priority == 1,
              "generation moved a manual rule");
    CheckAuto(store.Get(disabledIgmpId, existing) && !existing.enabled && existing.priority == 0,
              "generation enabled or moved a disabled IGMP rule");
    CheckAuto(store.Get(manualIgmpId, existing) && existing.priority == 1 &&
              existing.action == RuleAction::Block,
              "generation changed a manual post-app rule");
    CheckAuto(store.Get(globalId, existing) && existing.scope == RuleScope::Global &&
              store.PostApps().size() == 3 && store.PostApps().back().dir == Dir::In &&
              store.PostApps().back().enabled && store.PostApps().back().priority == 2,
              "generation mixed rule groups or omitted the incoming IGMP rule");
    const uint64_t after = store.version();
    CheckAuto(RulePresets::ApplyGenerated(store, generated) == 0 && store.version() == after,
              "repeat generation duplicated rules or rebuilt the store");

    const std::wstring svchost = SystemDirFile(L"svchost.exe");
    CheckAuto(RulePresets::Generate(svchost, {}).empty(),
              "generation created an unrestricted svchost fallback");
    ServiceEntry dns;
    dns.name = L"Dnscache";
    auto serviceRules = RulePresets::Generate(svchost, {dns});
    CheckAuto(!serviceRules.empty(), "generation missed the DNS service");
    for (const Rule& rule : serviceRules)
        CheckAuto((rule.conds & CondService) && rule.services.size() == 1 &&
                  EqualNoCase(rule.services.front().name, dns.name),
                  "generated svchost rule was not restricted to the verified service");
    ServiceEntry userPush;
    userPush.name = L"WpnUserService_test";
    serviceRules = RulePresets::Generate(svchost, {userPush});
    CheckAuto(!serviceRules.empty() &&
              std::all_of(serviceRules.begin(), serviceRules.end(), [&](const Rule& rule) {
                  return (rule.conds & CondService) && rule.services.size() == 1 &&
                         rule.services.front().name == userPush.name;
              }), "generation allowed unverified future services through a wildcard");
    CheckAuto(RulePresets::Generate(L"C:\\Temp\\svchost.exe", {dns}).empty(),
              "generation accepted a non-system host for a system service");

    std::atomic_bool cancel{false};
    size_t last = 0, total = 0;
    auto result = RuleGenerator::VerifyCandidates({signedPath, unsignedPath}, {}, cancel,
        [&](size_t completed, size_t count) {
            CheckAuto(completed >= last && completed <= count, "invalid generation progress");
            last = completed;
            total = count;
        });
    CheckAuto(!result.cancelled && total == 2 && last == 2 && result.rules.size() > 2 &&
              std::count_if(result.rules.begin(), result.rules.end(), [](const Rule& rule) {
                  return rule.scope == RuleScope::PostApp;
              }) == 2 &&
              std::all_of(result.rules.begin(), result.rules.end(), [&](const Rule& rule) {
                  return rule.scope == RuleScope::PostApp || EqualNoCase(rule.appPath, signedPath);
              }), "generation accepted an unsigned file or rejected a signed file");
    HANDLE write = CreateFileW(signedPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (write != INVALID_HANDLE_VALUE) CloseHandle(write);
    CheckAuto(write == INVALID_HANDLE_VALUE, "verified file was not locked until application");
    result = {};

    cancel.store(false);
    result = RuleGenerator::VerifyCandidates({signedPath, unsignedPath}, {}, cancel,
        [&](size_t completed, size_t) { if (completed == 1) cancel.store(true); });
    CheckAuto(result.cancelled && result.rules.empty() && result.files.empty(),
              "cancelled generation retained partial results");

    ServiceEntry teamViewer;
    teamViewer.name = L"TeamViewer";
    RuleGenerator::ServiceCandidate service{teamViewer, servicePath, unsignedPath};
    cancel.store(false);
    result = RuleGenerator::VerifyCandidates({servicePath}, {service}, cancel, {});
    CheckAuto(result.rules.size() == 2 && std::all_of(result.rules.begin(), result.rules.end(),
        [](const Rule& rule) { return rule.scope == RuleScope::PostApp; }),
        "service with unsigned DLL received rules");
    result = {};
    service.dll = signedPath;
    result = RuleGenerator::VerifyCandidates({servicePath}, {service}, cancel, {});
    CheckAuto(result.rules.size() > 2 && std::all_of(result.rules.begin(), result.rules.end(),
        [](const Rule& rule) {
            return rule.scope == RuleScope::PostApp ||
                ((rule.conds & CondService) && rule.services.size() == 1 &&
                 EqualNoCase(rule.services.front().name, L"TeamViewer"));
        }), "verified service did not receive service-restricted rules");
    result = {};
    service.image = unsignedPath;
    result = RuleGenerator::VerifyCandidates({unsignedPath}, {service}, cancel, {});
    CheckAuto(result.rules.size() == 2 && result.files.empty() &&
              std::all_of(result.rules.begin(), result.rules.end(),
                  [](const Rule& rule) { return rule.scope == RuleScope::PostApp; }),
              "generation unnecessarily verified a DLL of an untrusted host");
}

void GeneratedExecutableSelection(const std::wstring& systemExe) {
    TempDirectory dir;
    const wchar_t* excluded[] = {
        L"CURL.EXE", L"wget.exe", L"PWSH.exe", L"powershell.exe",
        L"PYTHON.exe", L"python3.exe", L"Perl.exe"
    };
    std::vector<std::wstring> candidates;
    const auto executables = RulePresets::Executables();
    for (const wchar_t* name : excluded) {
        const std::wstring path = dir.File(name);
        CheckAuto(CopyFileW(systemExe.c_str(), path.c_str(), FALSE), "cannot copy excluded executable");
        candidates.push_back(path);
        CheckAuto(RulePresets::ExcludedFromGeneration(path) && RulePresets::Generate(path, {}).empty() &&
                  std::none_of(executables.begin(), executables.end(),
                      [&](const std::wstring& item) { return EqualNoCase(item, name); }),
                  "excluded executable was retained in generation");
    }
    CheckAuto(!RulePresets::ExcludedFromGeneration(L"C:\\curl.exe\\winget.exe") &&
              !RulePresets::ExcludedFromGeneration(L"C:\\Apps\\mycurl.exe") &&
              !RulePresets::ExcludedFromGeneration(L"C:\\Apps\\python3.exe.backup"),
              "generation excluded a different executable");
    for (const wchar_t* name : {L"curl.exe", L"wget.exe"}) {
        AskRequest request;
        request.appPath = dir.File(name);
        request.key.proto = Proto::Tcp;
        request.key.rport = 443;
        request.dir = Dir::Out;
        CheckAuto(!RulePresets::Suggest(request).empty(),
                  "generation exclusion removed a manual preset");
    }

    const std::wstring visualStudio = dir.File(L"devenv.exe");
    const std::wstring winget = dir.File(L"winget.exe");
    CheckAuto(CopyFileW(systemExe.c_str(), visualStudio.c_str(), FALSE) &&
              CopyFileW(systemExe.c_str(), winget.c_str(), FALSE), "cannot copy allowed executables");
    candidates.push_back(visualStudio);
    candidates.push_back(winget);
    CheckAuto(std::any_of(executables.begin(), executables.end(), [](const std::wstring& item) {
                  return EqualNoCase(item, L"devenv.exe");
              }) && std::any_of(executables.begin(), executables.end(), [](const std::wstring& item) {
                  return EqualNoCase(item, L"winget.exe");
              }), "generation omitted an allowed executable");

    ServiceEntry excludedService;
    excludedService.name = L"ExcludedService";
    const RuleGenerator::ServiceCandidate service{excludedService, candidates.front(), systemExe};
    std::atomic_bool cancel{false};
    size_t total = 0, completed = 0;
    const auto result = RuleGenerator::VerifyCandidates(candidates, {service}, cancel,
        [&](size_t done, size_t count) { completed = done; total = count; });
    CheckAuto(!result.cancelled && total == 2 && completed == 2 && result.files.size() == 2 &&
              std::any_of(result.rules.begin(), result.rules.end(), [&](const Rule& rule) {
                  return EqualNoCase(rule.appPath, winget);
              }) && std::none_of(result.rules.begin(), result.rules.end(), [](const Rule& rule) {
                  return RulePresets::ExcludedFromGeneration(rule.appPath);
              }), "generation verified excluded files or omitted an allowed executable");

    RuleStore retained;
    Rule existing;
    existing.scope = RuleScope::App;
    existing.appPath = candidates.front();
    existing.action = RuleAction::Block;
    existing.enabled = false;
    const uint64_t existingId = retained.Add(existing);
    CheckAuto(RulePresets::ApplyGenerated(retained, result.rules) > 0 &&
              retained.Get(existingId, existing) && !existing.enabled &&
              existing.action == RuleAction::Block && existing.priority == 0 &&
              retained.ForApp(candidates.front()).size() == 1,
              "generation changed an existing rule for an excluded executable");

    std::vector<Rule> visualRules;
    for (const Rule& rule : result.rules)
        if (EqualNoCase(rule.appPath, visualStudio)) visualRules.push_back(rule);
    CheckAuto(visualRules.size() == 2 && std::all_of(visualRules.begin(), visualRules.end(),
        [](const Rule& rule) {
            return rule.scope == RuleScope::App && rule.action == RuleAction::Allow &&
                rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
                rule.conds == (CondProto | CondDirection | CondRemotePort);
        }), "generation omitted Visual Studio templates or changed their restrictions");
    RuleStore store;
    CheckAuto(RulePresets::ApplyGenerated(store, visualRules) == 2 &&
              RulePresets::ApplyGenerated(store, visualRules) == 0 && store.Count() == 2,
              "Visual Studio generation did not retain both profiles or deduplicate repeats");
    for (uint16_t port : {uint16_t{80}, uint16_t{443}})
        CheckAuto(std::any_of(visualRules.begin(), visualRules.end(), [&](const Rule& rule) {
            return std::any_of(rule.remotePorts.begin(), rule.remotePorts.end(), [&](const PortItem& item) {
                return item.from == port && item.to == port;
            });
        }), "Visual Studio generation omitted a template port");
}

void GeneratedDoSvc(const std::wstring& signedDll, const std::wstring& unsignedDll) {
    ServiceEntry entry;
    entry.name = L"DoSvc";
    const std::wstring host = SystemDirFile(L"svchost.exe");
    RuleGenerator::ServiceCandidate service{entry, host, signedDll};
    std::atomic_bool cancel{false};
    auto result = RuleGenerator::VerifyCandidates({host}, {service}, cancel, {});
    CheckAuto(!result.cancelled && result.files.size() == 2,
              "DoSvc host or DLL did not pass signature verification");
    std::vector<Rule> serviceRules;
    for (const Rule& rule : result.rules) {
        if (rule.scope != RuleScope::App) continue;
        CheckAuto(EqualNoCase(rule.appPath, host) && (rule.conds & CondService) &&
                  rule.services.size() == 1 && EqualNoCase(rule.services.front().name, L"DoSvc"),
                  "generated svchost rule was not limited to DoSvc");
        serviceRules.push_back(rule);
    }
    RuleStore store;
    CheckAuto(serviceRules.size() == 10 && RulePresets::ApplyGenerated(store, serviceRules) == 5 &&
              RulePresets::ApplyGenerated(store, serviceRules) == 0,
              "DoSvc templates were incomplete or generated duplicate rules");
    for (Dir direction : {Dir::Out, Dir::In}) {
        CheckAuto(std::any_of(serviceRules.begin(), serviceRules.end(), [&](const Rule& rule) {
            const auto& ports = direction == Dir::Out ? rule.remotePorts : rule.localPorts;
            return rule.dir == direction && rule.proto == Proto::Tcp &&
                   std::any_of(ports.begin(), ports.end(), [](const PortItem& port) {
                       return port.from == 7680 && port.to == 7680;
                   });
        }), "DoSvc template omitted a local peer direction");
    }
    result = {};
    service.dll = unsignedDll;
    result = RuleGenerator::VerifyCandidates({host}, {service}, cancel, {});
    CheckAuto(!result.cancelled && std::none_of(result.rules.begin(), result.rules.end(),
        [](const Rule& rule) { return rule.scope == RuleScope::App; }),
        "unsigned DoSvc DLL received rules");
}

void ServiceDllRegistry() {
    const std::wstring keyPath = L"Software\\FirewallX-ServiceDllTest-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    HKEY key = nullptr;
    DWORD disposition = 0;
    CheckAuto(RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, nullptr, REG_OPTION_VOLATILE,
                              KEY_ALL_ACCESS, nullptr, &key, &disposition) == ERROR_SUCCESS &&
              disposition == REG_CREATED_NEW_KEY, "cannot create test service key");
    struct Cleanup {
        HKEY key;
        std::wstring path;
        ~Cleanup() {
            RegCloseKey(key);
            RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
        }
    } cleanup{key, keyPath};
    const auto write = [](HKEY target, DWORD type, const std::wstring& value) {
        return RegSetValueExW(target, L"ServiceDll", 0, type,
            reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    };
    CheckAuto(RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath).empty(),
              "missing service DLL was not empty");
    CheckAuto(write(key, REG_EXPAND_SZ, L"%SystemRoot%\\System32\\dosvc.dll") &&
              EqualNoCase(RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath),
                          SystemDirFile(L"dosvc.dll")),
              "service DLL in the root key was not read and expanded");
    HKEY parameters = nullptr;
    CheckAuto(RegCreateKeyExW(key, L"Parameters", 0, nullptr, REG_OPTION_VOLATILE,
                              KEY_ALL_ACCESS, nullptr, &parameters, nullptr) == ERROR_SUCCESS,
              "cannot create test service parameters");
    const std::wstring configured = SystemDirFile(L"different.dll");
    CheckAuto(write(parameters, REG_SZ, configured) &&
              EqualNoCase(RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath), configured),
              "service parameters lost their existing priority");
    const DWORD invalid = 1;
    CheckAuto(RegSetValueExW(parameters, L"ServiceDll", 0, REG_DWORD,
                             reinterpret_cast<const BYTE*>(&invalid), sizeof(invalid)) == ERROR_SUCCESS &&
              RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath).empty() &&
              write(parameters, REG_SZ, L"") &&
              RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath).empty(),
              "invalid service parameters were replaced with a different DLL");
    CheckAuto(RegDeleteValueW(parameters, L"ServiceDll") == ERROR_SUCCESS &&
              EqualNoCase(RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath),
                          SystemDirFile(L"dosvc.dll")),
              "service DLL did not fall back to the root key");
    CheckAuto(RegDeleteValueW(key, L"ServiceDll") == ERROR_SUCCESS &&
              write(parameters, REG_SZ, configured) &&
              EqualNoCase(RuleGenerator::ReadServiceDll(HKEY_CURRENT_USER, keyPath), configured),
              "service DLL in parameters was not read");
    RegCloseKey(parameters);
}

void GeneratedOfficeAndFeedback(const std::wstring& systemExe, const wchar_t* unsignedExe) {
    TempDirectory dir;
    std::vector<std::wstring> paths;
    for (const wchar_t* name : {L"FeedbackHub.exe", L"MSPUB.EXE", L"POWERPNT.EXE", L"WINWORD.EXE"}) {
        const std::wstring path = dir.File(name);
        CheckAuto(CopyFileW(systemExe.c_str(), path.c_str(), FALSE), "cannot copy signed test executable");
        paths.push_back(path);
    }
    std::atomic_bool cancel{false};
    const auto result = RuleGenerator::VerifyCandidates(paths, {}, cancel, {});
    CheckAuto(!result.cancelled && result.files.size() == paths.size(),
              "generation did not verify the requested applications");
    for (const std::wstring& path : paths) {
        std::vector<const Rule*> rules;
        for (const Rule& rule : result.rules)
            if (EqualNoCase(rule.appPath, path)) rules.push_back(&rule);
        CheckAuto(rules.size() == 1 && rules.front()->scope == RuleScope::App &&
                  rules.front()->action == RuleAction::Allow && rules.front()->proto == Proto::Tcp &&
                  rules.front()->dir == Dir::Out &&
                  rules.front()->conds == (CondProto | CondDirection | CondRemotePort) &&
                  rules.front()->remotePorts.size() == 2 &&
                  std::any_of(rules.front()->remotePorts.begin(), rules.front()->remotePorts.end(),
                      [](const PortItem& port) { return port.from == 80 && port.to == 80; }) &&
                  std::any_of(rules.front()->remotePorts.begin(), rules.front()->remotePorts.end(),
                      [](const PortItem& port) { return port.from == 443 && port.to == 443; }),
                  "requested application did not receive its complete HTTP/HTTPS template");
    }
    RuleStore store;
    CheckAuto(RulePresets::ApplyGenerated(store, result.rules) == paths.size() + 2 &&
              RulePresets::ApplyGenerated(store, result.rules) == 0,
              "requested applications were not added without duplicates");

    TempDirectory unsignedDir;
    const std::wstring unsignedPath = unsignedDir.File(L"FeedbackHub.exe");
    CheckAuto(CopyFileW(unsignedExe, unsignedPath.c_str(), FALSE), "cannot copy unsigned test executable");
    const auto unsignedResult = RuleGenerator::VerifyCandidates({unsignedPath}, {}, cancel, {});
    CheckAuto(unsignedResult.files.empty() &&
              std::none_of(unsignedResult.rules.begin(), unsignedResult.rules.end(),
                  [&](const Rule& rule) { return EqualNoCase(rule.appPath, unsignedPath); }),
              "unsigned requested application received rules");
}

void GeneratedNewPrograms(const std::wstring& systemExe, const wchar_t* unsignedExe) {
    struct Program {
        const wchar_t* name;
        size_t ruleCount;
    };
    const Program programs[] = {
        {L"BackgroundDownload.exe", 1}, {L"Blend.exe", 1}, {L"PerfWatson2.exe", 1},
        {L"iTunes.exe", 4}, {L"Wireshark.exe", 1}, {L"SIHClient.exe", 1}, {L"taskhostw.exe", 2},
        {L"git-remote-https.exe", 4}
    };
    TempDirectory signedDir, unsignedDir, excludedDir;
    std::vector<std::wstring> candidates;
    const auto executables = RulePresets::Executables();
    size_t expectedRules = 2; // Два независимых от приложений правила IGMP.
    for (const Program& program : programs) {
        CheckAuto(std::count_if(executables.begin(), executables.end(), [&](const std::wstring& name) {
            return EqualNoCase(name, program.name);
        }) == 1, "new program is absent from the executable list or duplicated");
        const std::wstring signedPath = signedDir.File(program.name);
        const std::wstring unsignedPath = unsignedDir.File(program.name);
        CheckAuto(CopyFileW(systemExe.c_str(), signedPath.c_str(), FALSE) &&
                  CopyFileW(unsignedExe, unsignedPath.c_str(), FALSE),
                  "cannot copy new program test executables");
        candidates.push_back(signedPath);
        candidates.push_back(unsignedPath);
        expectedRules += program.ruleCount;
    }
    for (const wchar_t* name : {L"curl.exe", L"wget.exe", L"pwsh.exe", L"powershell.exe",
                                L"python.exe", L"python3.exe", L"perl.exe"}) {
        const std::wstring path = excludedDir.File(name);
        CheckAuto(CopyFileW(systemExe.c_str(), path.c_str(), FALSE),
                  "cannot copy excluded test executable");
        candidates.push_back(path);
    }

    std::atomic_bool cancel{false};
    size_t completed = 0, total = 0;
    const auto result = RuleGenerator::VerifyCandidates(candidates, {}, cancel,
        [&](size_t done, size_t count) { completed = done; total = count; });
    CheckAuto(!result.cancelled && total == std::size(programs) * 2 && completed == total &&
              result.files.size() == std::size(programs) && result.rules.size() == expectedRules,
              "generation verified excluded programs or accepted an unsigned program");
    for (const Program& program : programs) {
        const std::wstring signedPath = signedDir.File(program.name);
        const std::wstring unsignedPath = unsignedDir.File(program.name);
        std::vector<const Rule*> rules;
        for (const Rule& rule : result.rules) {
            CheckAuto(!EqualNoCase(rule.appPath, unsignedPath) &&
                      !RulePresets::ExcludedFromGeneration(rule.appPath),
                      "unsigned or excluded program received a rule");
            if (EqualNoCase(rule.appPath, signedPath)) rules.push_back(&rule);
        }
        CheckAuto(rules.size() == program.ruleCount &&
                  std::all_of(rules.begin(), rules.end(), [](const Rule* rule) {
                      return rule->scope == RuleScope::App && rule->action == RuleAction::Allow;
                  }), "new program did not receive its complete template");
        for (uint16_t port : {uint16_t{80}, uint16_t{443}}) {
            CheckAuto(std::any_of(rules.begin(), rules.end(), [&](const Rule* rule) {
                return rule->proto == Proto::Tcp && rule->dir == Dir::Out &&
                    rule->conds == (CondProto | CondDirection | CondRemotePort) &&
                    std::any_of(rule->remotePorts.begin(), rule->remotePorts.end(), [&](const PortItem& item) {
                        return item.from == port && item.to == port;
                    });
            }), "new program template omitted HTTP or HTTPS");
        }
        if (EqualNoCase(program.name, L"git-remote-https.exe")) {
            IpAddr loopback;
            CheckAuto(ParseIpAddr(L"127.0.0.1", loopback), "cannot parse Git loopback address");
            CheckAuto(std::count_if(rules.begin(), rules.end(), [&](const Rule* rule) {
                return rule->proto == Proto::Tcp && rule->dir == Dir::Unknown &&
                    rule->conds == (CondProto | CondRemoteAddr | CondLocalAddr) &&
                    rule->remoteAddrs.size() == 1 && rule->remoteAddrs[0].addr == loopback &&
                    rule->remoteAddrs[0].prefix == -1 && rule->localAddrs.size() == 1 &&
                    rule->localAddrs[0].addr == loopback && rule->localAddrs[0].prefix == -1 &&
                    rule->remotePorts.empty() && rule->localPorts.empty();
            }) == 1, "Git HTTPS generation omitted or duplicated the exact loopback rule");
        }
        if (EqualNoCase(program.name, L"iTunes.exe")) {
            IpAddr loopback;
            CheckAuto(ParseIpAddr(L"127.0.0.1", loopback), "cannot parse loopback address");
            for (Proto proto : {Proto::Tcp, Proto::Udp}) {
                CheckAuto(std::any_of(rules.begin(), rules.end(), [&](const Rule* rule) {
                    return rule->proto == proto && rule->dir == Dir::Unknown &&
                        rule->conds == (CondProto | CondRemoteAddr | CondLocalAddr) &&
                        rule->remoteAddrs.size() == 1 && rule->remoteAddrs[0].addr == loopback &&
                        rule->localAddrs.size() == 1 && rule->localAddrs[0].addr == loopback;
                }), "iTunes generation omitted a restricted loopback rule");
            }
            CheckAuto(std::any_of(rules.begin(), rules.end(), [](const Rule* rule) {
                return rule->proto == Proto::Udp && rule->dir == Dir::Unknown &&
                    rule->conds == (CondProto | CondRemotePort | CondLocalPort) &&
                    rule->remotePorts.size() == 1 && rule->remotePorts[0].from == 5353 &&
                    rule->remotePorts[0].to == 5353 && rule->localPorts.size() == 1 &&
                    rule->localPorts[0].from == 5353 && rule->localPorts[0].to == 5353;
            }), "iTunes generation omitted the mDNS rule");
        }
    }
    RuleStore store;
    CheckAuto(RulePresets::ApplyGenerated(store, result.rules) == expectedRules &&
              RulePresets::ApplyGenerated(store, result.rules) == 0 && store.Count() == expectedRules,
              "new program rules were duplicated on repeated generation");
}

void GenerationDiscovery() {
    std::atomic_bool cancel{false};
    size_t discovered = 0;
    const auto result = RuleGenerator::Scan(cancel, [&](size_t completed, size_t total) {
        CheckAuto(completed == 0, "discovery did not report the initial progress");
        discovered = total;
        cancel.store(true);
    });
    CheckAuto(discovered > 0 && result.cancelled && result.rules.empty() && result.files.empty(),
              "system-path discovery or early cancellation failed");
}

RuleGenerator::Result CompleteImmediately(const std::atomic_bool&,
                                           const RuleGenerator::Progress& progress) {
    progress(1, 1);
    return {};
}

RuleGenerator::Result FailGeneration(const std::atomic_bool&, const RuleGenerator::Progress&) {
    throw 1;
}

struct GenerationDialogProbe {
    unsigned visibleButtons = 0;
    bool sawCancel = false;
    bool inspected = false;
    bool stayedOpen = false;
    bool cancelDisabled = false;
    HWND cancelButton = nullptr;
};

enum class GenerationCancel { Button, TitleBar, CloseMessage };
GenerationDialogProbe generationDialogProbe;
HANDLE generationDialogRelease = nullptr;
DWORD generationDialogWait = WAIT_FAILED;
GenerationCancel generationCancel = GenerationCancel::Button;
constexpr WPARAM kInspectGenerationDialog = 0x4658;

RuleGenerator::Result AwaitCancel(const std::atomic_bool& cancel,
                                 const RuleGenerator::Progress&) {
    generationDialogWait = WaitForSingleObject(generationDialogRelease, 5000);
    RuleGenerator::Result result;
    result.cancelled = cancel.load(std::memory_order_relaxed);
    return result;
}

BOOL CALLBACK CountGenerationButtons(HWND control, LPARAM data) {
    auto& probe = *reinterpret_cast<GenerationDialogProbe*>(data);
    wchar_t name[32]{};
    if (GetClassNameW(control, name, static_cast<int>(std::size(name))) &&
        lstrcmpiW(name, L"Button") == 0 && IsWindowVisible(control)) {
        wchar_t text[256]{};
        GetWindowTextW(control, text, static_cast<int>(std::size(text)));
        ++probe.visibleButtons;
        if (LoadStringRes(IDS_BTN_CANCEL) == text) {
            probe.sawCancel = true;
            probe.cancelButton = control;
        }
    }
    return TRUE;
}

LRESULT CALLBACK CancelGenerationOnShow(int code, WPARAM wp, LPARAM lp) {
    if (code >= 0) {
        const auto* message = reinterpret_cast<const CWPSTRUCT*>(lp);
        if (message->message == WM_SHOWWINDOW && message->wParam) {
            wchar_t title[256]{};
            GetWindowTextW(message->hwnd, title, static_cast<int>(std::size(title)));
            if (LoadStringRes(IDS_RULE_GENERATE) == title)
                PostMessageW(message->hwnd, WM_NULL, kInspectGenerationDialog, 0);
        }
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

LRESULT CALLBACK InspectGenerationDialog(int code, WPARAM wp, LPARAM lp) {
    if (code >= 0 && wp == PM_REMOVE) {
        const auto* message = reinterpret_cast<const MSG*>(lp);
        if (message->message == WM_NULL && message->wParam == kInspectGenerationDialog &&
            !generationDialogProbe.inspected) {
            auto& probe = generationDialogProbe;
            probe.inspected = true;
            EnumChildWindows(message->hwnd, CountGenerationButtons, reinterpret_cast<LPARAM>(&probe));
            if (generationCancel == GenerationCancel::TitleBar)
                SendMessageW(message->hwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
            else if (generationCancel == GenerationCancel::CloseMessage)
                SendMessageW(message->hwnd, WM_CLOSE, 0, 0);
            else
                SendMessageW(message->hwnd, TDM_CLICK_BUTTON, IDCANCEL, 0);
            probe.stayedOpen = IsWindow(message->hwnd) != FALSE;
            probe.cancelDisabled = probe.cancelButton && !IsWindowEnabled(probe.cancelButton);
            SetEvent(generationDialogRelease);
        }
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

void GenerationDialog() {
    RuleGenerationProgress complete;
    complete.scan = CompleteImmediately;
    complete.Show(nullptr, GetModuleHandleW(nullptr));
    CheckAuto(!complete.failed && !complete.cancel.load(), "completed progress dialog failed");

    RuleGenerationProgress failure;
    failure.scan = FailGeneration;
    failure.Show(nullptr, GetModuleHandleW(nullptr));
    CheckAuto(failure.failed && !failure.cancel.load(), "failed progress dialog did not close");

    for (GenerationCancel action : {GenerationCancel::Button, GenerationCancel::TitleBar,
                                    GenerationCancel::CloseMessage}) {
        generationDialogProbe = {};
        generationDialogWait = WAIT_FAILED;
        generationCancel = action;
        generationDialogRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CheckAuto(generationDialogRelease != nullptr, "cannot create progress dialog event");
        HHOOK inspect = SetWindowsHookExW(WH_GETMESSAGE, InspectGenerationDialog, nullptr,
                                          GetCurrentThreadId());
        HHOOK hook = SetWindowsHookExW(WH_CALLWNDPROC, CancelGenerationOnShow, nullptr,
                                       GetCurrentThreadId());
        CheckAuto(inspect != nullptr && hook != nullptr, "cannot hook progress dialog");
        RuleGenerationProgress cancelled;
        cancelled.scan = AwaitCancel;
        cancelled.Show(nullptr, GetModuleHandleW(nullptr));
        UnhookWindowsHookEx(hook);
        UnhookWindowsHookEx(inspect);
        CloseHandle(generationDialogRelease);
        generationDialogRelease = nullptr;
        CheckAuto(generationDialogProbe.inspected, "progress dialog was not inspected");
        if (generationDialogProbe.visibleButtons != 1 || !generationDialogProbe.sawCancel)
            std::cerr << "visible buttons=" << generationDialogProbe.visibleButtons
                      << ", cancel=" << generationDialogProbe.sawCancel << '\n';
        CheckAuto(generationDialogProbe.visibleButtons == 1 && generationDialogProbe.sawCancel,
                  "progress dialog did not show exactly one Cancel button");
        if (!generationDialogProbe.stayedOpen || !generationDialogProbe.cancelDisabled)
            std::cerr << "action=" << static_cast<int>(action) << ", stayed=" << generationDialogProbe.stayedOpen
                      << ", disabled=" << generationDialogProbe.cancelDisabled
                      << ", cancelled=" << cancelled.cancel.load() << '\n';
        CheckAuto(generationDialogProbe.stayedOpen, "progress dialog closed before the worker finished");
        CheckAuto(generationDialogProbe.cancelDisabled, "Cancel button stayed enabled after cancellation");
        CheckAuto(generationDialogWait == WAIT_OBJECT_0 && !cancelled.failed &&
                  cancelled.cancel.load() && cancelled.result.cancelled,
                  "progress dialog did not cancel the worker");
    }
}

} // анонимное пространство имён

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--generation-scan") {
        std::atomic_bool cancel{false};
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        size_t scanned = 0, total = 0;
        const auto result = RuleGenerator::Scan(cancel, [&](size_t done, size_t count) {
            scanned = done;
            total = count;
        });
        CheckAuto(!result.cancelled && total > 0 && scanned == total && !result.rules.empty() &&
                  std::count_if(result.rules.begin(), result.rules.end(), [](const Rule& rule) {
                      return rule.scope == RuleScope::PostApp && rule.proto == ProtoFromNumber(2);
                  }) == 2 && std::none_of(result.rules.begin(), result.rules.end(), [](const Rule& rule) {
                      return RulePresets::ExcludedFromGeneration(rule.appPath);
                  }), "real system generation scan failed, omitted IGMP, or included excluded files");
        const auto visualRules = std::count_if(result.rules.begin(), result.rules.end(), [](const Rule& rule) {
            return EqualNoCase(rule.appName, L"devenv.exe");
        });
        const auto doSvcRules = std::count_if(result.rules.begin(), result.rules.end(), [](const Rule& rule) {
            return (rule.conds & CondService) && std::any_of(rule.services.begin(), rule.services.end(),
                [](const ServiceItem& service) { return EqualNoCase(service.name, L"DoSvc"); });
        });
        std::cout << "Candidates checked: " << total << ", trusted files: " << result.files.size()
                  << ", generated rules: " << result.rules.size()
                  << ", Visual Studio rules: " << visualRules << ", DoSvc rules: " << doSvcRules << '\n';
        for (const auto& [name, label] : {
                std::pair{L"FeedbackHub.exe", "FeedbackHub.exe"},
                std::pair{L"MSPUB.EXE", "MSPUB.EXE"},
                std::pair{L"POWERPNT.EXE", "POWERPNT.EXE"},
                std::pair{L"WINWORD.EXE", "WINWORD.EXE"},
                std::pair{L"BackgroundDownload.exe", "BackgroundDownload.exe"},
                std::pair{L"Blend.exe", "Blend.exe"},
                std::pair{L"PerfWatson2.exe", "PerfWatson2.exe"},
                std::pair{L"iTunes.exe", "iTunes.exe"},
                std::pair{L"Wireshark.exe", "Wireshark.exe"},
                std::pair{L"SIHClient.exe", "SIHClient.exe"},
                std::pair{L"taskhostw.exe", "taskhostw.exe"}}) {
            const auto count = std::count_if(result.rules.begin(), result.rules.end(), [&](const Rule& rule) {
                return EqualNoCase(rule.appName, name);
            });
            std::cout << label << " rules: " << count << '\n';
        }
        return 0;
    }
    TempDirectory dir;
    wchar_t system[MAX_PATH]{}, self[MAX_PATH]{};
    CheckAuto(GetSystemDirectoryW(system, MAX_PATH) && GetModuleFileNameW(nullptr, self, MAX_PATH),
              "cannot find test executables");
    const std::wstring systemExe = std::wstring(system) + L"\\cmd.exe";
    const std::wstring signedPath = dir.File(L"chrome.exe");
    const std::wstring otherSignedPath = dir.File(L"msedge.exe");
    const std::wstring unsignedPath = dir.File(L"curl.exe");
    const std::wstring unsignedGeneratedPath = dir.File(L"winget.exe");
    const std::wstring unknownPath = dir.File(L"unknown.exe");
    CheckAuto(CopyFileW(systemExe.c_str(), signedPath.c_str(), FALSE) &&
              CopyFileW(systemExe.c_str(), otherSignedPath.c_str(), FALSE) &&
              CopyFileW(systemExe.c_str(), unknownPath.c_str(), FALSE) &&
              CopyFileW(self, unsignedPath.c_str(), FALSE) &&
              CopyFileW(self, unsignedGeneratedPath.c_str(), FALSE), "cannot copy test executables");
    for (const wchar_t* name : {L"CopilotApp.exe", L"explorer.exe", L"MpCmdRun.exe",
                                L"Discord.exe", L"obs64.exe", L"OneDrive.exe",
                                L"OneDrive.Sync.Service.exe", L"OneDriveUpdaterService.exe", L"msiexec.exe",
                                L"YandexDisk4.exe", L"AnyDesk.exe", L"RustDesk.exe", L"TeamViewer.exe",
                                L"TeamViewer_Service.exe", L"AppHostRegistrationVerifier.exe",
                                L"backgroundTaskHost.exe", L"HxOutlook.exe", L"WWAHost.exe",
                                L"Photos.exe", L"wslservice.exe", L"git-remote-https.exe"})
        CheckAuto(CopyFileW(systemExe.c_str(), dir.File(name).c_str(), FALSE),
                  "cannot copy captured-preset test executable");
    GeneratedIgmp(dir.File(L"generation.db"));
    GeneratedRules(signedPath, unsignedGeneratedPath, dir.File(L"TeamViewer_Service.exe"));
    GeneratedExecutableSelection(systemExe);
    GeneratedOfficeAndFeedback(systemExe, self);
    GeneratedNewPrograms(systemExe, self);
    ServiceDllRegistry();
    GeneratedDoSvc(systemExe, unsignedGeneratedPath);
    GenerationDiscovery();
    GenerationDialog();
    std::wstring error;
    CheckAuto(Settings::Open(dir.File(L"settings.db"), error), "cannot open test settings");
    CheckAuto(!Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false),
              "automatic rules are enabled by default");
    CheckAuto(Settings::SetBool(Settings::Key::kAutoCreatePresetRules, true), "setting write failed");
    Settings::Close();
    CheckAuto(Settings::Open(dir.File(L"settings.db"), error) &&
              Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false),
              "automatic rule setting did not survive reopening");
    AppStorageTestAccess::IgmpAutomatic();
    AppStorageTestAccess::IgmpInboundAutomatic();
    AppStorageTestAccess::IgmpUnknownDirection();
    AppStorageTestAccess::IgmpInboundSetting();
    AppStorageTestAccess::IgmpInboundDisabledWhileQueued();
    AppStorageTestAccess::IgmpInboundManualIsolation();
    AppStorageTestAccess::IgmpAmbiguousOwner();
    AppStorageTestAccess::IgmpSetting();
    AppStorageTestAccess::IgmpDisabledWhileQueued();
    AppStorageTestAccess::IgmpOldSession();
    AppStorageTestAccess::IgmpManualIsolation();
    AppStorageTestAccess::IgmpUnrelatedManualRequest();
    AppStorageTestAccess::IgmpDuringSignatureCheck(signedPath);
    AppStorageTestAccess::UserPushService();
    AppStorageTestAccess::Disabled(signedPath);
    AppStorageTestAccess::EnableForExisting(signedPath);
    AppStorageTestAccess::Signed(signedPath);
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"CopilotApp.exe"), 48, 6, 5353, 5353,
                                              Proto::Udp, L"192.0.2.1", L"224.0.0.251");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"git-remote-https.exe"), 76, 1, 28907, 28906,
                                              Proto::Tcp, L"127.0.0.1", L"127.0.0.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"explorer.exe"), 49, 1, 40049, 80,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"MpCmdRun.exe"), 50, 1, 40050, 443,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"Discord.exe"), 51, 1, 40051, 80,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"obs64.exe"), 52, 2, 61822, 61821,
                                              Proto::Tcp, L"127.0.0.1", L"127.0.0.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"OneDrive.exe"), 53, 1, 64153, 80,
                                              Proto::Tcp, L"192.0.2.1", L"23.12.158.97");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"OneDrive.Sync.Service.exe"), 54, 1, 64156, 443,
                                              Proto::Tcp, L"192.0.2.1", L"23.103.242.129");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"YandexDisk4.exe"), 55, 2, 53002, 53001,
                                              Proto::Tcp, L"127.0.0.1", L"127.0.0.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"AppHostRegistrationVerifier.exe"), 56, 1, 64233, 80,
                                              Proto::Tcp, L"192.0.2.1", L"104.18.21.226");
    AppStorageTestAccess::UnattributedService(dir.File(L"msiexec.exe"), 57, 80);
    AppStorageTestAccess::UnattributedService(dir.File(L"OneDriveUpdaterService.exe"), 58, 80);
    AppStorageTestAccess::UnattributedService(dir.File(L"OneDriveUpdaterService.exe"), 59, 443);
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"AnyDesk.exe"), 60, 2, 41060, 53,
                                              Proto::Udp, L"192.0.2.1", L"1.1.1.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"TeamViewer.exe"), 61, 2, 5939, 52480,
                                              Proto::Tcp, L"127.0.0.1", L"127.0.0.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"RustDesk.exe"), 67, 2, 41067, 21116,
                                              Proto::Udp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"RustDesk.exe"), 68, 2, 41068, 21115,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"backgroundTaskHost.exe"), 69, 1, 41069, 80,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"HxOutlook.exe"), 70, 1, 41070, 80,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"WWAHost.exe"), 73, 1, 41073, 80,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"WWAHost.exe"), 74, 1, 41074, 443,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::SignedCapturedPreset(dir.File(L"Photos.exe"), 71, 1, 41071, 443,
                                              Proto::Tcp, L"192.0.2.1", L"198.51.100.1");
    AppStorageTestAccess::UnattributedService(dir.File(L"wslservice.exe"), 72, 80);
    AppStorageTestAccess::UnattributedService(dir.File(L"TeamViewer_Service.exe"), 62, 80);
    AppStorageTestAccess::UnattributedService(dir.File(L"TeamViewer_Service.exe"), 63, 443);
    AppStorageTestAccess::UnattributedService(dir.File(L"TeamViewer_Service.exe"), 64, 5938);
    AppStorageTestAccess::UnattributedService(dir.File(L"TeamViewer_Service.exe"), 65, 5353,
                                             Proto::Udp, 5353, L"224.0.0.251", L"192.0.2.1");
    AppStorageTestAccess::UnattributedService(dir.File(L"TeamViewer_Service.exe"), 66, 5353,
                                             Proto::Udp, 5353, L"::1", L"ff02::fb");
    AppStorageTestAccess::UnattributedService(dir.File(L"TeamViewer_Service.exe"), 75, 5353,
                                             Proto::Udp, 5353, L"192.168.219.24", L"224.0.0.251");
    const std::wstring package = TestWindowsStorePath();
    if (!package.empty()) AppStorageTestAccess::SignedPackage(package);
    else std::cout << "package automatic rules test skipped: Microsoft Store not found\n";
    AppStorageTestAccess::ManualFallback(unsignedPath, true);
    AppStorageTestAccess::ManualFallback(unknownPath, false);
    AppStorageTestAccess::DisabledDuringCheck(signedPath);
    AppStorageTestAccess::TimedOutRequests(signedPath);
    AppStorageTestAccess::ManualRequestIsolation(signedPath, otherSignedPath);
    AppStorageTestAccess::FinishedBeforeDeadline(signedPath);
    AppStorageTestAccess::FinishedAfterDeadline(signedPath);
    AppStorageTestAccess::TimeoutTimer(signedPath);
    AppStorageTestAccess::OldSession(signedPath);
    AppStorageTestAccess::ShutdownDuringCheck(signedPath);
    Settings::Close();
    std::cout << "automatic rule tests passed\n";
    return 0;
}
