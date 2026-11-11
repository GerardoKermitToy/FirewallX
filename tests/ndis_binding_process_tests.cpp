// Настоящие дочерние процессы, но операция NetCfg целиком подменена.
#include "NdisBindingProcess.h"
#include <chrono>
#include <cstdio>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
using namespace ndis_binding::detail;
unsigned calls = 0;
bool lastForce = false, lastResume = false;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

HRESULT FakeWorker(const std::atomic<bool>& stopped, bool force, bool resume) noexcept {
    ++calls;
    lastForce = force;
    lastResume = resume;
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &policy, sizeof(policy))) return E_FAIL;
    if (policy.MicrosoftSignedOnly || policy.StoreSignedOnly || policy.MitigationOptIn) return E_ACCESSDENIED;
    if (resume) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (force) return HRESULT_FROM_WIN32(ERROR_BUSY);
    wchar_t unrelated[32]{};
    if (GetEnvironmentVariableW(L"FIREWALLX_TEST_UNRELATED_HANDLE", unrelated, 32)) {
        // При правильном HANDLE_LIST это не дескриптор события родителя.
        SetEvent(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(_wcstoui64(unrelated, nullptr, 10))));
    }
    for (unsigned index = 0; index != 100; ++index) {
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        Sleep(2);
    }
    return S_OK;
}

constexpr uint64_t additionLuid = 0x0102030405060708ull;
HRESULT FakeAdditionalWorker(const std::atomic<bool>& stopped, uint64_t luid) noexcept {
    if (luid == 33) return S_FALSE;
    if (luid == 44) return HRESULT_FROM_WIN32(ERROR_BUSY);
    if (luid != additionLuid) return E_INVALIDARG;
    return FakeWorker(stopped, false, false);
}

constexpr std::wstring_view namedAdapter = L"Ethernet café \"тест\" \\ 网络";
HRESULT FakeNamedWorker(const std::atomic<bool>& stopped, std::wstring_view name) noexcept {
    if (name == L"missing") return S_FALSE;
    if (name != namedAdapter) return E_INVALIDARG;
    return FakeWorker(stopped, false, false);
}

bool Dispatch(std::vector<std::wstring> args, HRESULT& result) {
    std::vector<wchar_t*> pointers;
    for (auto& arg : args) pointers.push_back(arg.data());
    return DispatchHelper(static_cast<int>(pointers.size()), pointers.data(), FakeWorker, result,
                          FakeAdditionalWorker, FakeNamedWorker);
}
}

int wmain(int argc, wchar_t** argv) {
    HRESULT workerResult = E_INVALIDARG;
    if (DispatchHelper(argc, argv, FakeWorker, workerResult, FakeAdditionalWorker, FakeNamedWorker))
        return static_cast<int>(workerResult);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    try {
        HRESULT result = S_FALSE;
        Check(!Dispatch({L"test", L"--service"}, result) && result == S_FALSE, "normal startup was intercepted");
        const unsigned before = calls;
        const std::vector<std::vector<std::wstring>> invalid{
            {L"test", kWorkerArgument},
            {L"test", L"extra", kWorkerArgument},
            {L"test", kWorkerArgument, L"2", L"4", L"8"},
            {L"test", kWorkerArgument, L"0", L"0", L"8"},
            {L"test", kWorkerArgument, L"0", L"-1", L"8"},
            {L"test", kWorkerArgument, L"0", L"184467440737095516160", L"8"},
            {L"test", kWorkerArgument, L"0", L"7", L"7"},
            {L"test", kAddWorkerArgument},
            {L"test", kAddWorkerArgument, L"0", L"4", L"8"},
            {L"test", kAddWorkerArgument, L"-1", L"4", L"8"},
            {L"test", kAddWorkerArgument, L"18446744073709551616", L"4", L"8"},
            {L"test", kAddWorkerArgument, L"33", L"0", L"8"},
            {L"test", kAddWorkerArgument, L"33", L"7", L"7"},
            {L"test", kNamedWorkerArgument},
            {L"test", kNamedWorkerArgument, L"123", L"4", L"8"},
            {L"test", kNamedWorkerArgument, L"00ZZ", L"4", L"8"},
            {L"test", kNamedWorkerArgument, L"0000", L"4", L"8"},
            {L"test", kNamedWorkerArgument, L"0041", L"7", L"7"},
            {L"test", kResumeArgument},
            {L"test", kResumeArgument, L"--no"},
            {L"test", L"extra", kResumeArgument, L"--yes"},
        };
        for (const auto& args : invalid) {
            Check(Dispatch(args, result) && FAILED(result), "malformed helper command accepted");
            Check(calls == before, "malformed command invoked an operation");
        }
        Check(Dispatch({L"test", kResumeArgument, L"--yes"}, result) &&
            result == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) && lastResume && !lastForce,
            "explicit resume was not isolated from normal preparation");
        const std::atomic<bool> active{false};
        const std::atomic<bool> alreadyStopped{true};
        Check(RunIsolated(alreadyStopped, false) == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED), "pre-cancel did not stop startup");
        Check(RunIsolated(active, false) == S_OK, "normal child failed");
        Check(RunIsolated(active, true) == HRESULT_FROM_WIN32(ERROR_BUSY), "child HRESULT/force mode was lost");
        Check(RunIsolatedAddition(active, additionLuid) == S_OK, "addition child lost the 64-bit LUID");
        Check(RunIsolatedAddition(active, 33) == S_FALSE, "disappeared arrival was not a successful no-op");
        Check(RunIsolatedAddition(active, 44) == HRESULT_FROM_WIN32(ERROR_BUSY), "addition child lost its error");
        Check(RunIsolatedAddition(active, 0) == E_INVALIDARG, "zero addition LUID was accepted");
        Check(ndis_binding::ApplyInterfaceBinding(namedAdapter) == S_OK,
            "named child lost Unicode, quotes or backslashes");
        Check(ndis_binding::ApplyInterfaceBinding(L"missing") == S_FALSE,
            "missing named interface was not a no-op");
        Check(ndis_binding::ApplyInterfaceBinding(L"") == E_INVALIDARG,
            "empty named interface was accepted");
        Check(RunIsolatedAddition(alreadyStopped, additionLuid) == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED),
            "pre-cancel did not stop addition child");
        {
            std::atomic<bool> stopped{false};
            const auto started = std::chrono::steady_clock::now();
            auto operation = std::async(std::launch::async, [&] { return RunIsolated(stopped, false); });
            Sleep(75);
            stopped.store(true);
            Check(operation.wait_for(std::chrono::seconds(5)) == std::future_status::ready, "cancel did not drain child");
            Check(operation.get() == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED), "cancel was reported as success");
            Check(std::chrono::steady_clock::now() - started < std::chrono::seconds(5), "cancel exceeded test bound");
        }
        {
            SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
            const HANDLE unrelated = CreateEventW(&security, TRUE, FALSE, nullptr);
            Check(unrelated != nullptr, "test event creation failed");
            const auto text = std::to_wstring(reinterpret_cast<uintptr_t>(unrelated));
            Check(SetEnvironmentVariableW(L"FIREWALLX_TEST_UNRELATED_HANDLE", text.c_str()) != FALSE, "test environment failed");
            const HRESULT status = RunIsolated(active, false);
            SetEnvironmentVariableW(L"FIREWALLX_TEST_UNRELATED_HANDLE", nullptr);
            const DWORD signalled = WaitForSingleObject(unrelated, 0);
            CloseHandle(unrelated);
            Check(status == S_OK && signalled == WAIT_TIMEOUT, "an unrelated inheritable handle leaked into child");
        }
        wchar_t image[32768]{};
        Check(GetModuleFileNameW(nullptr, image, 32768) != 0 && std::wstring(image).find(L' ') != std::wstring::npos,
            "CMake must place this test in a path containing spaces");
        // Политики меняются только в этом тестовом процессе, без записи настроек ОС.
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
        signature.MicrosoftSignedOnly = 1;
        Check(SetProcessMitigationPolicy(ProcessSignaturePolicy, &signature, sizeof(signature)) != FALSE, "could not enable test CIG");
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode{};
        dynamicCode.ProhibitDynamicCode = 1;
        Check(SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCode, sizeof(dynamicCode)) != FALSE, "could not enable test ACG");
        Check(RunIsolated(active, false) == S_OK, "CIG parent could not run the clean child");
        Check(RunIsolatedAddition(active, additionLuid) == S_OK, "CIG parent could not run the addition-only child");
        Check(ndis_binding::ApplyInterfaceBinding(namedAdapter) == S_OK, "CIG parent could not run the named child");
        Check(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &signature, sizeof(signature)) &&
            signature.MicrosoftSignedOnly, "parent CIG was weakened");
        Check(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &dynamicCode, sizeof(dynamicCode)) &&
            dynamicCode.ProhibitDynamicCode, "parent ACG was weakened");
        Check(Dispatch({L"test", kResumeArgument, L"--yes"}, result) &&
            result == HRESULT_FROM_WIN32(ERROR_INVALID_IMAGE_HASH), "restricted process was allowed to run NetCfg directly");
        std::puts("PASS: self-hosted CIG-safe child, unchanged parent CIG/ACG, HRESULTs, cancellation, strict CLI, quoted path and handle allowlist; no driver/registry/NetCfg access.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
