#include "ServiceInfo.h"
#include "StringRes.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <malloc.h>
#include <new>
#include <stdexcept>
#include <thread>

namespace {
std::atomic<size_t> liveBytes{0};
std::atomic<size_t> allocations{0};
}

void* operator new(size_t size) {
    void* pointer = std::malloc(size ? size : 1);
    if (!pointer) throw std::bad_alloc();
    liveBytes += _msize(pointer);
    ++allocations;
    return pointer;
}

void operator delete(void* pointer) noexcept {
    if (!pointer) return;
    liveBytes -= _msize(pointer);
    std::free(pointer);
}

void* operator new[](size_t size) { return ::operator new(size); }
void operator delete[](void* pointer) noexcept { ::operator delete(pointer); }
void operator delete(void* pointer, size_t) noexcept { ::operator delete(pointer); }
void operator delete[](void* pointer, size_t) noexcept { ::operator delete(pointer); }

namespace {
struct ServiceFixture {
    DWORD count = 1;
    size_t nameLength = 8;
    wchar_t displayFill = L'd';
    DWORD servicesPerPid = 1;
    DWORD pageSize = 0;
    bool fail = false;
    size_t opened = 0;
    size_t closed = 0;
    std::vector<DWORD> sizes;
} scmFixture;

SC_HANDLE WINAPI TestOpenSCManagerW(LPCWSTR, LPCWSTR, DWORD) {
    ++scmFixture.opened;
    return reinterpret_cast<SC_HANDLE>(1);
}

BOOL WINAPI TestCloseServiceHandle(SC_HANDLE) {
    ++scmFixture.closed;
    return TRUE;
}

BOOL WINAPI TestEnumServicesStatusExW(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD,
                                     LPBYTE buffer, DWORD bytes, LPDWORD needed,
                                     LPDWORD returned, LPDWORD resume, LPCWSTR) {
    scmFixture.sizes.push_back(bytes);
    *needed = *returned = 0;
    if (scmFixture.fail) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    const DWORD start = *resume;
    const DWORD count = scmFixture.pageSize
        ? std::min(scmFixture.pageSize, scmFixture.count - start)
        : scmFixture.count - start;
    const size_t stringBytes = count * 2 * (scmFixture.nameLength + 1) * sizeof(wchar_t);
    const size_t required = count * sizeof(ENUM_SERVICE_STATUS_PROCESSW) + stringBytes;
    if (bytes < required) {
        *needed = static_cast<DWORD>(required);
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }

    auto* rows = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer);
    // Как у SCM: строки лежат у конца выделения, а не сразу после записей.
    auto* text = reinterpret_cast<wchar_t*>(buffer + bytes - stringBytes);
    for (DWORD i = 0; i < count; ++i) {
        auto& row = rows[i];
        row = {};
        row.lpServiceName = text;
        std::fill_n(text, scmFixture.nameLength, L'n');
        text[scmFixture.nameLength] = L'\0';
        text += scmFixture.nameLength + 1;
        row.lpDisplayName = text;
        std::fill_n(text, scmFixture.nameLength, scmFixture.displayFill);
        text[scmFixture.nameLength] = L'\0';
        text += scmFixture.nameLength + 1;
        row.ServiceStatusProcess.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        row.ServiceStatusProcess.dwCurrentState = start + i ? SERVICE_RUNNING : SERVICE_STOPPED;
        row.ServiceStatusProcess.dwProcessId = 1000 + (start + i) / scmFixture.servicesPerPid;
    }
    *returned = count;
    if (start + count < scmFixture.count) {
        *resume = start + count;
        *needed = static_cast<DWORD>(required);
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    *resume = 0;
    return TRUE;
}
} // namespace

// Проверяется настоящий Enumerator; заменены только вызовы SCM. Ни службы,
// ни системные настройки тест не открывает и не изменяет.
#define OpenSCManagerW TestOpenSCManagerW
#define CloseServiceHandle TestCloseServiceHandle
#define EnumServicesStatusExW TestEnumServicesStatusExW
#include "../ServiceInfo.cpp"
#undef EnumServicesStatusExW
#undef CloseServiceHandle
#undef OpenSCManagerW

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void TestServiceBuffer() {
    scmFixture.sizes.reserve(256);
    Enumerator enumerator;
    std::vector<ServiceEntry> rows;
    scmFixture.count = 3000;
    scmFixture.nameLength = 96;
    Check(enumerator.Run(SERVICE_STATE_ALL, rows) && rows.size() == scmFixture.count,
          "SCM buffer growth lost services");
    const size_t peak = scmFixture.sizes.back();
    Check(peak > 4 * kStartBytes && rows[0].pid == 0 && rows[1].pid == 1001 &&
          rows[0].name == std::wstring(96, L'n') &&
          rows[0].display == std::wstring(96, L'd'),
          "SCM buffer growth changed service fields");

    scmFixture.count = 1;
    scmFixture.nameLength = 8;
    Check(enumerator.Run(SERVICE_STATE_ALL, rows) && rows.size() == 1 &&
          scmFixture.sizes.back() == peak, "SCM buffer could not reuse its previous allocation");
    Check(enumerator.Run(SERVICE_STATE_ALL, rows) && scmFixture.sizes.back() == kStartBytes,
          "SCM buffer retained its peak or used tail pointers as the live size");

    scmFixture.count = 9;
    scmFixture.pageSize = 3;
    Check(enumerator.Run(SERVICE_STATE_ALL, rows) && rows.size() == 9 && rows[8].pid == 1008,
          "SCM pagination lost service rows");
    scmFixture.pageSize = 0;
    scmFixture.count = 0;
    Check(enumerator.Run(SERVICE_STATE_ALL, rows) && rows.empty(), "empty SCM result failed");
    const size_t stableAllocations = allocations.load();
    for (int pass = 0; pass < 100; ++pass)
        Check(enumerator.Run(SERVICE_STATE_ALL, rows) && rows.empty(), "stable SCM poll failed");
    Check(allocations == stableAllocations && scmFixture.opened == 1,
          "stable empty SCM polling reallocated the buffer or reopened SCM");

    scmFixture.count = 3000;
    scmFixture.nameLength = 96;
    Check(enumerator.Run(SERVICE_STATE_ALL, rows), "SCM buffer could not grow again");
    const size_t regrown = scmFixture.sizes.back();
    scmFixture.fail = true;
    Check(!enumerator.Run(SERVICE_STATE_ALL, rows) && scmFixture.closed == 1,
          "SCM failure did not close the old handle");
    scmFixture.fail = false;
    scmFixture.count = 1;
    scmFixture.nameLength = 8;
    Check(enumerator.Run(SERVICE_STATE_ALL, rows) && scmFixture.sizes.back() == kStartBytes &&
          scmFixture.opened == 2 && regrown > 4 * kStartBytes,
          "SCM error retained the old buffer or prevented recovery");
    const size_t beforeClose = liveBytes.load();
    enumerator.Close();
    Check(scmFixture.closed == 2 && liveBytes.load() + kStartBytes <= beforeClose,
          "closing SCM retained the raw buffer");
    enumerator.Close();
    Check(scmFixture.closed == 2, "SCM close was not idempotent");
    std::cout << "SCM raw buffer: peak=" << peak << ", stable=" << kStartBytes << '\n';
}

void TestHostedServicesStorage() {
    scmFixture.count = 3001;
    scmFixture.nameLength = 96;
    scmFixture.servicesPerPid = 2;
    EmptyServices();
    const size_t baseline = liveBytes.load();
    ServiceInfo::HostedServices held;
    std::weak_ptr<const std::vector<ServiceEntry>> heldLifetime;
    {
        RuntimeManager manager;
        const size_t beforePoll = scmFixture.sizes.size();
        Check(manager.ServicesOfPid(0, true)->empty() &&
              scmFixture.sizes.size() == beforePoll, "zero PID queried SCM");
        Check(manager.Refresh(true), "runtime service fixture could not be published");
        const uint64_t version = manager.Version(false);
        auto snapshot = manager.Snapshot();
        Check(snapshot->byPid.size() == 1501 && !snapshot->byPid.count(0),
              "runtime service grouping lost PIDs or retained a stopped service");
        std::weak_ptr<const RuntimeSnapshot> oldSnapshot = snapshot;
        snapshot.reset();
        std::weak_ptr<const std::vector<ServiceEntry>> otherServices =
            manager.ServicesOfPid(1002, false);
        held = manager.ServicesOfPid(1001, false);
        heldLifetime = held;
        Check(held && held->size() == 2 && (*held)[0].pid == 1001 &&
              (*held)[1].pid == 1001 && (*held)[0].state == SERVICE_RUNNING &&
              (*held)[0].name == std::wstring(96, L'n') &&
              (*held)[0].display == std::wstring(96, L'd'),
              "hosted service list changed its process or fields");
        const auto* address = held.get();
        const size_t beforeLookup = allocations.load();
        const size_t beforeCalls = scmFixture.sizes.size();
        for (int pass = 0; pass < 1000; ++pass) {
            Check(manager.ServicesOfPid(1001, false).get() == address &&
                  manager.ServicesOfPid(MAXDWORD, false)->empty(),
                  "runtime service lookup copied the list or lost an empty result");
        }
        Check(allocations == beforeLookup && scmFixture.sizes.size() == beforeCalls,
              "runtime service lookup allocated storage or queried SCM");

        // Старый список остаётся у соединения. После обновления он не должен
        // удерживать ни сам снимок, ни списки остальных полутора тысяч PID.
        scmFixture.displayFill = L'e';
        Check(manager.Refresh(true) && manager.Version(false) == version,
              "display-only service update changed the runtime mapping version");
        Check(oldSnapshot.expired(), "hosted service list retained the whole runtime snapshot");
        Check(otherServices.expired(), "hosted service list retained unrelated process services");
        auto current = manager.ServicesOfPid(1001, false);
        Check(current->size() == 2 && current.get() != address &&
              (*current)[0].display == std::wstring(96, L'e') &&
              (*held)[0].display == std::wstring(96, L'd'),
              "runtime refresh mutated an already published service list");

        scmFixture.fail = true;
        Check(!manager.Refresh(true) && manager.Version(false) == version &&
              manager.ServicesOfPid(1001, false) == current,
              "failed SCM poll replaced the last complete service list");
        scmFixture.fail = false;
        oldSnapshot = manager.Snapshot();
        otherServices = manager.ServicesOfPid(1002, false);
        current.reset();
        scmFixture.count = 1;
        Check(manager.Refresh(true) && manager.Version(false) > version &&
              manager.ServicesOfPid(1001, false)->empty() &&
              oldSnapshot.expired() && otherServices.expired(),
              "removing runtime services retained their old snapshot or mapping");
    }
    Check(held.get() && held->size() == 2 && (*held)[0].name == std::wstring(96, L'n') &&
          (*held)[1].display == std::wstring(96, L'd'),
          "destroying the runtime manager invalidated a hosted service list");
    const size_t retained = liveBytes.load() - baseline;
    Check(retained < 4096, "one hosted service list retained storage for unrelated PIDs");
    held.reset();
    Check(heldLifetime.expired(), "releasing the last hosted service reference retained its list");
    heldLifetime.reset();
    Check(liveBytes == baseline, "runtime service lookup retained its nested allocations");
    scmFixture.servicesPerPid = 1;
    scmFixture.displayFill = L'd';
    std::cout << "hosted services: retained bytes for one PID=" << retained
              << ", released unrelated PIDs=1500\n";
}

void TestStringCacheStorage() {
    SetUiLang(UiLang::English);
    const auto& mainText = StringResRef(IDS_MENU_VIEW_TITLE);
    const std::wstring mainValue = mainText;
    size_t sparseBytes = 0;
    size_t sparseAllocations = 0;

    // Два потока начинают с пустого кеша: один с малого ID, другой с большого.
    // Проверяются оба порядка, рост прямого индекса и освобождение при выходе.
    for (const UINT firstId : { UINT(IDS_APPNAME), UINT(IDS_PRESET_SYSTEM_TCP_LOOPBACK) }) {
        std::exception_ptr failure;
        const size_t baseline = liveBytes.load();
        std::thread worker([&] {
            try {
                const size_t before = liveBytes.load();
                const size_t beforeAllocations = allocations.load();
                const auto& first = StringResRef(firstId);
                const size_t bytes = liveBytes.load() - before;
                const size_t count = allocations.load() - beforeAllocations;
                Check(!first.empty(), "sparse cache could not load its first resource");
                Check(count < 32, "sparse cache constructed strings for unrequested IDs");
                Check(bytes < (static_cast<size_t>(firstId) + 1) * sizeof(void*) + 8192,
                      "sparse cache retained string objects between requested IDs");
                if (firstId == IDS_PRESET_SYSTEM_TCP_LOOPBACK) {
                    sparseBytes = bytes;
                    sparseAllocations = count;
                }
                const auto* firstAddress = &first;
                const std::wstring firstValue = first;
                Check(&StringResRef(IDS_MENU_VIEW_TITLE) != &mainText && mainText == mainValue,
                      "resource cache is shared between threads");

                for (UINT id = IDS_PRESET_OTHER; id <= IDS_PRESET_RULE_LOOPBACK_HTTPS_UDP; ++id) {
                    Check(!StringResRef(id).empty(), "cache growth lost a resource");
                    Check(first == firstValue && &StringResRef(firstId) == firstAddress,
                          "cache growth invalidated a resource reference");
                }
                for (UINT id = IDS_PRESET_CLIPCHAMP; id <= IDS_PRESET_SYSTEM_TCP_LOOPBACK; ++id) {
                    Check(!StringResRef(id).empty(), "cache growth lost a new preset resource");
                    Check(first == firstValue && &StringResRef(firstId) == firstAddress,
                          "new preset resources invalidated a cached reference");
                }

                const size_t warmedAllocations = allocations.load();
                for (int pass = 0; pass < 10000; ++pass) {
                    Check(&StringResRef(firstId) == firstAddress && first == firstValue &&
                          !StringResRef(IDS_PRESET_OTHER).empty(),
                          "warm resource lookup changed its cached value");
                }
                Check(allocations == warmedAllocations, "warm resource lookup allocated storage");

                SetUiLang(UiLang::Russian);
                const auto& russian = StringResRef(IDS_MENU_VIEW_TITLE);
                Check(!russian.empty() && russian != mainValue,
                      "language switch reused stale cached text");
                size_t languageCount = 0;
                const UiLangInfo* languages = UiLangs(languageCount);
                for (size_t i = 0; i < languageCount; ++i) {
                    SetUiLang(languages[i].lang);
                    Check(!StringResRef(firstId).empty() &&
                          !StringResRef(IDS_MENU_VIEW_TITLE).empty() &&
                          !LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, L"one", L"two").empty(),
                          "language switch lost a cached resource or format");
                }
                SetUiLang(UiLang::English);
                Check(&StringResRef(firstId) == firstAddress && first == firstValue &&
                      StringResRef(IDS_MENU_VIEW_TITLE) == mainValue,
                      "language round trip lost the original resource");
            } catch (...) {
                failure = std::current_exception();
            }
        });
        worker.join();
        if (failure) std::rethrow_exception(failure);
        Check(liveBytes == baseline, "thread exit retained its resource cache");
    }
    Check(mainText == mainValue && &StringResRef(IDS_MENU_VIEW_TITLE) == &mainText,
          "worker language changes invalidated another thread's cache");
    std::cout << "sparse resource cache: first ID=" << IDS_PRESET_SYSTEM_TCP_LOOPBACK
              << ", allocations=" << sparseAllocations << ", bytes=" << sparseBytes << '\n';
}

void TestFormattingStorage() {
    SetUiLang(UiLang::English);
    Check(LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, L"one", L"two") == L"one — two",
          "direct formatting changed Unicode output");
    Check(!LoadStringResFmt(IDS_STATUS_PROCS_FMT, 12u, 34u).empty(),
          "direct formatting lost numeric arguments");
    Check(!LoadStringResFmt(IDS_RULEN_ADDR_LIST_FMT, L"x").empty(),
          "cannot load formatting fixture");

    const std::wstring input(1024 * 1024, L'Ж');
    const size_t baseline = liveBytes.load();
    {
        const auto result = LoadStringResFmt(IDS_RULEN_ADDR_LIST_FMT, input.c_str());
        Check(result.find(input) != std::wstring::npos, "long formatted string was truncated");
    }
    Check(liveBytes == baseline, "formatting retained the longest thread-local buffer");
    for (int pass = 0; pass < 1000; ++pass)
        Check(!LoadStringResFmt(IDS_RULEN_ADDR_LIST_FMT, L"short").empty(),
              "short formatting after a long result failed");
    Check(liveBytes == baseline, "repeated formatting retained temporary allocations");
    Check(LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, L"", L"") == L" — ",
          "direct formatting changed empty arguments");
    std::cout << "formatting retained bytes after long result: " << liveBytes.load() - baseline << '\n';
}
} // namespace

int main() {
    try {
        TestServiceBuffer();
        TestHostedServicesStorage();
        TestStringCacheStorage();
        TestFormattingStorage();
        std::cout << "runtime buffer tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
