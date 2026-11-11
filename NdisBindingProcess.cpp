#include "NdisBindingProcess.h"
#include <shellapi.h>
#include <iterator>
#include <cwchar>
#include <limits>
#include <new>
#include <thread>

namespace ndis_binding {
namespace {
using namespace detail;

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

std::wstring ImagePath(HANDLE process = nullptr) {
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (process) CheckWin32(QueryFullProcessImageNameW(process, 0, path.data(), &size) ? ERROR_SUCCESS : GetLastError());
    else {
        size = GetModuleFileNameW(nullptr, path.data(), size);
        if (!size || size == path.size()) throw Error{ HRESULT_FROM_WIN32(size ? ERROR_INSUFFICIENT_BUFFER : GetLastError()) };
    }
    path.resize(size);
    return path;
}

bool RestrictedSignaturePolicy() {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy{};
    CheckWin32(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy,
        &policy, sizeof(policy)) ? ERROR_SUCCESS : GetLastError());
    return policy.MicrosoftSignedOnly || policy.StoreSignedOnly || policy.MitigationOptIn;
}

bool SameImage(HANDLE parent) {
    const auto parentPath = ImagePath(parent);
    const auto ownPath = ImagePath();
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    Handle first(CreateFileW(parentPath.c_str(), FILE_READ_ATTRIBUTES, share, nullptr, OPEN_EXISTING, 0, nullptr));
    Handle second(CreateFileW(ownPath.c_str(), FILE_READ_ATTRIBUTES, share, nullptr, OPEN_EXISTING, 0, nullptr));
    if (first.value == INVALID_HANDLE_VALUE || second.value == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION a{}, b{};
    return GetFileInformationByHandle(first.value, &a) && GetFileInformationByHandle(second.value, &b) &&
        a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow;
}

uint64_t ParseNumber(const wchar_t* text) {
    if (!text || !*text) throw Error{E_INVALIDARG};
    uint64_t value = 0;
    for (; *text; ++text) {
        if (*text < L'0' || *text > L'9') throw Error{E_INVALIDARG};
        const auto digit = static_cast<uint64_t>(*text - L'0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) throw Error{E_INVALIDARG};
        value = value * 10 + digit;
    }
    if (!value) throw Error{E_INVALIDARG};
    return value;
}
HANDLE ParseHandle(const wchar_t* text) {
    const auto value = ParseNumber(text);
    if (value >= std::numeric_limits<uintptr_t>::max()) throw Error{E_INVALIDARG};
    return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
}

// Кодируем UTF-16 в безопасный аргумент без кавычек и разделителей командной строки.
std::wstring EncodeName(std::wstring_view name) {
    if (name.empty() || name.size() > 256) throw Error{E_INVALIDARG};
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring encoded;
    encoded.reserve(name.size() * 4);
    for (const wchar_t ch : name) {
        if (!ch) throw Error{E_INVALIDARG};
        const auto value = static_cast<uint16_t>(ch);
        for (int shift = 12; shift >= 0; shift -= 4) encoded.push_back(digits[(value >> shift) & 15]);
    }
    return encoded;
}

std::wstring DecodeName(const wchar_t* text) {
    if (!text) throw Error{E_INVALIDARG};
    const std::wstring_view encoded(text);
    if (encoded.empty() || encoded.size() > 1024 || encoded.size() % 4) throw Error{E_INVALIDARG};
    std::wstring name;
    name.reserve(encoded.size() / 4);
    for (size_t i = 0; i < encoded.size(); i += 4) {
        uint16_t value = 0;
        for (size_t j = 0; j < 4; ++j) {
            const wchar_t ch = encoded[i + j];
            const int digit = ch >= L'0' && ch <= L'9' ? ch - L'0' :
                              ch >= L'A' && ch <= L'F' ? ch - L'A' + 10 : -1;
            if (digit < 0) throw Error{E_INVALIDARG};
            value = static_cast<uint16_t>((value << 4) | digit);
        }
        if (!value) throw Error{E_INVALIDARG};
        name.push_back(static_cast<wchar_t>(value));
    }
    return name;
}

template<class Operation>
HRESULT InvokeOperation(Operation operation, const std::atomic<bool>& stopped) {
    if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
    // Политики ОС и родителя не ослабляются. Навязанная извне CIG остаётся отказом.
    if (RestrictedSignaturePolicy()) return HRESULT_FROM_WIN32(ERROR_INVALID_IMAGE_HASH);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    CheckWin32(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
        ? ERROR_SUCCESS : GetLastError());
    return operation(stopped);
}
HRESULT Invoke(Worker worker, const std::atomic<bool>& stopped, bool force, bool resume) {
    return InvokeOperation([=](const std::atomic<bool>& cancel) { return worker(cancel, force, resume); }, stopped);
}

template<class Operation>
HRESULT RunInherited(Operation operation, HANDLE cancelValue, HANDLE parentValue) {
    if (cancelValue == parentValue) return E_INVALIDARG;
    DWORD flags = 0;
    if (!GetHandleInformation(cancelValue, &flags) || !(flags & HANDLE_FLAG_INHERIT) ||
        !GetHandleInformation(parentValue, &flags) || !(flags & HANDLE_FLAG_INHERIT)) return E_INVALIDARG;
    Handle cancel(cancelValue), parent(parentValue);
    const DWORD parentId = GetProcessId(parent.value);
    if (!parentId || parentId == GetCurrentProcessId() || !SameImage(parent.value)) return E_INVALIDARG;
    const HANDLE requests[]{cancel.value, parent.value};
    const DWORD initial = WaitForMultipleObjects(2, requests, FALSE, 0);
    if (initial == WAIT_OBJECT_0 || initial == WAIT_OBJECT_0 + 1) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
    if (initial != WAIT_TIMEOUT) return HRESULT_FROM_WIN32(GetLastError());
    Handle finished(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!finished.value) return HRESULT_FROM_WIN32(GetLastError());
    std::atomic<bool> stopped{false};
    std::thread watcher([&]() noexcept {
        const HANDLE waits[]{finished.value, cancel.value, parent.value};
        if (WaitForMultipleObjects(3, waits, FALSE, INFINITE) != WAIT_OBJECT_0) stopped.store(true);
    });
    HRESULT result = E_UNEXPECTED;
    try { result = InvokeOperation(operation, stopped); }
    catch (const Error& error) { result = error.status; }
    catch (const std::bad_alloc&) { result = E_OUTOFMEMORY; }
    catch (...) { result = E_UNEXPECTED; }
    SetEvent(finished.value);
    watcher.join();
    return stopped.load() ? HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) : result;
}

struct Attributes {
    std::vector<unsigned char> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
    explicit Attributes(HANDLE* handles, size_t count) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        if (!size) throw Error{ HRESULT_FROM_WIN32(GetLastError()) };
        storage.resize(size);
        value = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(value, 1, 0, &size)) {
            value = nullptr;
            throw Error{ HRESULT_FROM_WIN32(GetLastError()) };
        }
        if (!UpdateProcThreadAttribute(value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles, count * sizeof(HANDLE), nullptr, nullptr)) {
            const auto error = GetLastError();
            DeleteProcThreadAttributeList(value);
            value = nullptr;
            throw Error{ HRESULT_FROM_WIN32(error) };
        }
    }
    ~Attributes() { if (value) DeleteProcThreadAttributeList(value); }
};
} // namespace

namespace detail {
static HRESULT RunChild(const std::atomic<bool>& stopped, const wchar_t* operation, const std::wstring& argument,
                        bool allowNoChange = false) noexcept {
    try {
        if (stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
        Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr)), inheritedCancel, inheritedParent;
        if (!cancel.value) return HRESULT_FROM_WIN32(GetLastError());
        CheckWin32(DuplicateHandle(GetCurrentProcess(), cancel.value, GetCurrentProcess(),
            &inheritedCancel.value, SYNCHRONIZE, TRUE, 0) ? ERROR_SUCCESS : GetLastError());
        CheckWin32(DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
            &inheritedParent.value, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0)
            ? ERROR_SUCCESS : GetLastError());
        HANDLE handles[]{inheritedCancel.value, inheritedParent.value};
        Attributes attributes(handles, std::size(handles));
        const auto image = ImagePath();
        std::wstring command = L"\"" + image + L"\" " + operation + L" " + argument + L" " +
            std::to_wstring(reinterpret_cast<uintptr_t>(inheritedCancel.value)) + L" " +
            std::to_wstring(reinterpret_cast<uintptr_t>(inheritedParent.value));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = attributes.value;
        PROCESS_INFORMATION process{};
        CheckWin32(CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
            &startup.StartupInfo, &process) ? ERROR_SUCCESS : GetLastError());
        Handle child(process.hProcess), thread(process.hThread);
        // Отмена кооперативная: не убиваем процесс посреди Apply/rollback NetCfg.
        bool cancelling = false;
        for (;;) {
            if (stopped.load() && !cancelling) {
                CheckWin32(SetEvent(cancel.value) ? ERROR_SUCCESS : GetLastError());
                cancelling = true;
            }
            // После сигнала отмены ждём завершения без периодических пробуждений.
            const DWORD wait = WaitForSingleObject(child.value, cancelling ? INFINITE : 250);
            if (wait == WAIT_TIMEOUT) continue;
            if (wait != WAIT_OBJECT_0) {
                const auto error = GetLastError();
                SetEvent(cancel.value);
                return HRESULT_FROM_WIN32(error);
            }
            DWORD code = 0;
            CheckWin32(GetExitCodeProcess(child.value, &code) ? ERROR_SUCCESS : GetLastError());
            if (cancelling || stopped.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
            const auto result = static_cast<HRESULT>(code);
            return code == 0 || (allowNoChange && code == S_FALSE) || FAILED(result) ? result : E_UNEXPECTED;
        }
    } catch (const Error& error) { return error.status; }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

HRESULT RunIsolated(const std::atomic<bool>& stopped, bool forceReattach) noexcept {
    try { return RunChild(stopped, kWorkerArgument, forceReattach ? L"1" : L"0"); }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}
HRESULT RunIsolatedAddition(const std::atomic<bool>& stopped, uint64_t luid) noexcept {
    if (!luid) return E_INVALIDARG;
    try { return RunChild(stopped, kAddWorkerArgument, std::to_wstring(luid), true); }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

bool DispatchHelper(int argc, wchar_t* const* argv, Worker worker, HRESULT& result,
                    AdditionalWorker additional, NamedWorker named) noexcept {
    bool recognized = false;
    for (int index = 1; argv && index < argc; ++index) {
        if (argv[index] && (std::wcscmp(argv[index], kWorkerArgument) == 0 ||
                std::wcscmp(argv[index], kResumeArgument) == 0 ||
                std::wcscmp(argv[index], kAddWorkerArgument) == 0 ||
                std::wcscmp(argv[index], kNamedWorkerArgument) == 0)) recognized = true;
    }
    if (!recognized) return false;
    result = E_INVALIDARG;
    try {
        if (!worker || !argv || !argv[1]) return true;
        if (argc == 3 && std::wcscmp(argv[1], kResumeArgument) == 0 && argv[2] &&
                std::wcscmp(argv[2], L"--yes") == 0) {
            const std::atomic<bool> stopped{false};
            result = Invoke(worker, stopped, false, true);
        } else if (argc == 5 && std::wcscmp(argv[1], kWorkerArgument) == 0 && argv[2] &&
                (std::wcscmp(argv[2], L"0") == 0 || std::wcscmp(argv[2], L"1") == 0)) {
            const bool force = *argv[2] == L'1';
            result = RunInherited([=](const std::atomic<bool>& cancel) { return worker(cancel, force, false); },
                ParseHandle(argv[3]), ParseHandle(argv[4]));
        } else if (argc == 5 && std::wcscmp(argv[1], kAddWorkerArgument) == 0 && additional) {
            const auto luid = ParseNumber(argv[2]);
            result = RunInherited([=](const std::atomic<bool>& cancel) { return additional(cancel, luid); },
                ParseHandle(argv[3]), ParseHandle(argv[4]));
        } else if (argc == 5 && std::wcscmp(argv[1], kNamedWorkerArgument) == 0 && named) {
            const auto name = DecodeName(argv[2]);
            result = RunInherited([&](const std::atomic<bool>& cancel) { return named(cancel, name); },
                ParseHandle(argv[3]), ParseHandle(argv[4]));
        }
    } catch (const Error& error) { result = error.status; }
    catch (const std::bad_alloc&) { result = E_OUTOFMEMORY; }
    catch (...) { result = E_UNEXPECTED; }
    return true;
}
} // namespace detail

HRESULT EnsureBindings(const std::atomic<bool>& stopped, std::span<const detail::AttachedAdapter> attached,
                          detail::Targets& targets, bool* rebound) noexcept {
    return detail::Ensure(stopped, attached, targets, detail::InspectWindows,
        [](const std::atomic<bool>& cancel) -> HRESULT {
            // CIG-процесс не загружает notify DLL. Worker нужен только после положительного preflight.
            if (RestrictedSignaturePolicy()) return detail::RunIsolated(cancel, true);
            return detail::PrepareWindows(cancel, true, false);
        }, rebound);
}

HRESULT EnsureAdditionalBinding(const std::atomic<bool>& stopped, uint64_t luid,
                                std::span<const detail::AttachedAdapter> attached, detail::Adapter& added) noexcept {
    return detail::EnsureAddition(stopped, luid, attached, added, detail::InspectWindowsAddition,
        [](const std::atomic<bool>& cancel, uint64_t targetLuid) -> HRESULT {
            if (RestrictedSignaturePolicy()) return detail::RunIsolatedAddition(cancel, targetLuid);
            return detail::AddTargetWindows(cancel, targetLuid);
        });
}

HRESULT ApplyInterfaceBinding(std::wstring_view name) noexcept {
    try {
        const std::atomic<bool> stopped{false};
        // UI может работать под CIG или в STA, поэтому NetCfg выполняется отдельно.
        return detail::RunChild(stopped, detail::kNamedWorkerArgument, EncodeName(name), true);
    } catch (const detail::Error& error) { return error.status; }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

bool TryRunHelper(int& exitCode) noexcept {
    int argc = 0;
    auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) { exitCode = static_cast<int>(E_OUTOFMEMORY); return true; }
    HRESULT result = E_INVALIDARG;
    const bool handled = detail::DispatchHelper(argc, argv, detail::PrepareWindows, result,
                                               detail::AddTargetWindows, detail::ApplyNamedTargetWindows);
    LocalFree(argv);
    if (handled) exitCode = static_cast<int>(result);
    return handled;
}
} // namespace ndis_binding
