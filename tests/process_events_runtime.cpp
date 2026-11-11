// Ограниченная ручная проверка настоящего драйвера, не входит в CTest.
// KextClient сам управляет службой; сетевые запросы получают PermanentAccept.
#include "PortmasterKextClient.hpp"

#include <atomic>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace FirewallX { Mode g_runMode = Mode::Desktop; }
namespace TrafficAttributionOptions {
DWORD ApplySaved() { return ERROR_SUCCESS; }
}

namespace {
pmkext::KextClient* client = nullptr;
std::atomic<unsigned> ownSnapshots{0};
std::atomic<unsigned> processRecords{0};
std::atomic<unsigned> verdictErrors{0};
std::atomic<bool> forwarding{false};
std::atomic<unsigned> forwardedProcessRecords{0};
std::atomic<uint64_t> forwardedChildPid{0};
std::atomic<bool> forwardedChildExited{false};

bool ForwardProcessRecord(void*, const uint8_t* record, uint32_t size) noexcept {
    if (!forwarding.load() || size < 5 || (record[0] != 9 && record[0] != 10)) return false;
    ++forwardedProcessRecords;
    if (record[0] == 10) {
        for (size_t offset = 5; offset + 8 <= size; offset += 8)
            if (pmkext::detail::load<uint64_t>(record + offset) == forwardedChildPid.load())
                forwardedChildExited.store(true);
    }
    // Эмуляция получателя process events; сетевые записи остаются локальными
    // и по-прежнему получают PermanentAccept, а не теряются в тестовом relay.
    return true;
}

void Created(const pmkext::ProcessCreated* values, uint32_t count) noexcept {
    ++processRecords;
    for (uint32_t i = 0; i < count; ++i)
        if (values[i].pid == GetCurrentProcessId()) ++ownSnapshots;
}
void Terminated(const pmkext::ProcessTerminated*, uint32_t) noexcept { ++processRecords; }
void ConnectionV4(const pmkext::ConnectionFixedV4* value, const uint8_t*, uint32_t) noexcept {
    if (!client->sendVerdict(value->external_connection_id, pmkext::Verdict::PermanentAccept))
        ++verdictErrors;
}
void ConnectionV6(const pmkext::ConnectionFixedV6* value, const uint8_t*, uint32_t) noexcept {
    if (!client->sendVerdict(value->external_connection_id, pmkext::Verdict::PermanentAccept))
        ++verdictErrors;
}
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <class Predicate>
void Await(ULONGLONG deadline, Predicate predicate, const char* message) {
    while (!predicate()) {
        Check(GetTickCount64() < deadline, message);
        Sleep(10);
    }
}

struct Child {
    PROCESS_INFORMATION info{};
    ~Child() {
        // Ребёнок сам завершится через две секунды, принудительного убийства нет.
        if (info.hProcess) {
            WaitForSingleObject(info.hProcess, 3000);
            CloseHandle(info.hProcess);
        }
        if (info.hThread) CloseHandle(info.hThread);
    }
};

void LaunchChild(const std::filesystem::path& exe, Child& child) {
    std::wstring command = L"\"" + exe.wstring() + L"\" --child --duration 2";
    STARTUPINFOW startup{sizeof(startup)};
    Check(CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child.info) != FALSE,
          "cannot launch bounded child");
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wcscmp(argv[1], L"--child") == 0 &&
        std::wcscmp(argv[2], L"--duration") == 0 && std::wcscmp(argv[3], L"2") == 0) {
        Sleep(2000);
        return 0;
    }
    if (argc != 4 || std::wcscmp(argv[1], L"--duration") != 0 ||
        std::wcscmp(argv[2], L"8") != 0) {
        std::cerr << "Usage: kext_process_runtime.exe --duration 8 absolute-driver.sys\n";
        return 2;
    }
    try {
        const ULONGLONG deadline = GetTickCount64() + 8000;
        std::vector<wchar_t> module(32768);
        const DWORD length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
        Check(length && length < module.size(), "cannot determine probe path");
        const std::filesystem::path exe(std::wstring(module.data(), length));
        const auto relativeDriver = std::filesystem::relative(
            std::filesystem::path(argv[3]), exe.parent_path()).wstring();

        pmkext::KextClient driver;
        client = &driver;
        driver.driverFile = relativeDriver.c_str();
        driver.onConnectionV4 = ConnectionV4;
        driver.onConnectionV6 = ConnectionV6;
        driver.onProcessCreated = Created;
        driver.onProcessTerminated = Terminated;
        driver.onRawRecord = ForwardProcessRecord;
        Check(driver.open(), "driver open failed");
        Check(driver.startReadLoop(), "reader start failed");
        Sleep(250);
        Check(processRecords.load() == 0 && driver.processes().size() == 0,
              "process collection started before explicit request");
        Check(driver.ioctlStartProcessMonitoring(), "initial process IOCTL failed");
        Await(deadline, [] { return ownSnapshots.load() >= 1; }, "initial snapshot timed out");
        pmkext::ProcessInfo own;
        Check(driver.processes().find(GetCurrentProcessId(), own) && own.path &&
              own.path_error == ERROR_SUCCESS, "own image path missing");

        // Подключение получателя очищает уже существующую локальную таблицу.
        const auto previousPath = own.path;
        forwarding.store(true);
        driver.setProcessEventsEnabled(false);
        Check(driver.processes().size() == 0 && driver.processes().pathCount() == 0,
              "client connect did not clear the local table and paths");
        Child forwardedChild;
        LaunchChild(exe, forwardedChild);
        forwardedChildPid.store(forwardedChild.info.dwProcessId);
        Check(driver.ioctlStartProcessMonitoring(), "forwarded client's snapshot request failed");
        Check(WaitForSingleObject(forwardedChild.info.hProcess, 3000) == WAIT_OBJECT_0,
              "forwarded child did not exit");
        Await(deadline, [] { return forwardedChildExited.load(); }, "forwarded exit timed out");
        Check(forwardedProcessRecords.load() != 0 && driver.processes().size() == 0 &&
              driver.processes().pathCount() == 0 && ownSnapshots.load() == 1,
              "service kept local process data while forwarding");

        // Отключение получателя начинает новый локальный снимок с нуля.
        driver.setProcessEventsEnabled(true);
        forwarding.store(false);
        Check(driver.ioctlStartProcessMonitoring(), "local snapshot resume failed");
        Await(deadline, [] { return ownSnapshots.load() >= 2; }, "fresh local snapshot timed out");
        Check(driver.processes().find(GetCurrentProcessId(), own) && own.path &&
              own.path != previousPath && *own.path == *previousPath,
              "resume reused the old process/path inventory");
        pmkext::ProcessInfo oldChild;
        Check(!driver.processes().find(forwardedChild.info.dwProcessId, oldChild),
              "fresh snapshot retained a process that exited while forwarding");

        Child child;
        LaunchChild(exe, child);
        pmkext::ProcessInfo childInfo;
        Await(deadline, [&] { return driver.processes().find(child.info.dwProcessId, childInfo); },
              "live child creation timed out");
        Check(childInfo.parent_pid == GetCurrentProcessId() && !childInfo.terminated &&
              childInfo.path == own.path, "parent link or path deduplication failed");
        Check(driver.sendStartProcessMonitoring(), "WriteFile restart failed");
        Check(driver.ioctlStartProcessMonitoring(), "IOCTL restart failed");
        Await(deadline, [] { return ownSnapshots.load() >= 4; }, "repeat snapshots timed out");
        pmkext::ProcessInfo repeated;
        Check(driver.processes().find(GetCurrentProcessId(), repeated) && repeated.path == own.path,
              "restart replaced the interned path");
        Check(WaitForSingleObject(child.info.hProcess, 3000) == WAIT_OBJECT_0,
              "bounded child did not exit");
        Await(deadline, [&] {
            pmkext::ProcessInfo value;
            return !driver.processes().find(child.info.dwProcessId, value);
        }, "exited child retained without descendants");
        Check(driver.processes().find(GetCurrentProcessId(), repeated) && !repeated.terminated,
              "live parent removed with child");
        Check(verdictErrors.load() == 0, "automatic accept verdict failed");
        const size_t processes = driver.processes().size();
        const size_t paths = driver.processes().pathCount();
        driver.close();
        Check(driver.processes().size() == 0 && driver.processes().pathCount() == 0,
              "close retained process state");
        client = nullptr;
        std::cout << "PASS: connect clears local state; no local collection while forwarding; "
                     "disconnect rebuilds snapshot; IOCTL/WriteFile restart; live child create/exit; "
                     "shared paths; close cleanup. snapshots=" << ownSnapshots.load()
                  << " processes=" << processes << " unique_paths=" << paths << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
