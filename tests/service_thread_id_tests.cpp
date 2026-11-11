#include "ServiceThreadId.h"

#include <array>
#include <atomic>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace {

constexpr uint64_t kBlockedId = 0xFEDCBA9876543210;
constexpr uint64_t kErrorId = UINT64_MAX;
constexpr uint64_t kMask = 0x123456789ABCDEF0;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void Wait(HANDLE event) {
    Check(WaitForSingleObject(event, 5000) == WAIT_OBJECT_0, "ожидание события завершилось ошибкой");
}

uint64_t Expected(uint64_t id) { return id ? id ^ kMask : 0; }

std::wstring ChannelName() {
    static std::atomic<unsigned> sequence{ 0 };
    return L"Local\\FirewallX.ServiceThreadIdTests." + std::to_wstring(GetCurrentProcessId()) +
        L"." + std::to_wstring(GetTickCount64()) + L"." + std::to_wstring(++sequence);
}

class Event {
public:
    explicit Event(const wchar_t* name = nullptr) {
        handle_ = CreateEventW(nullptr, TRUE, FALSE, name);
        Check(handle_ != nullptr, "не удалось создать событие");
    }
    ~Event() { CloseHandle(handle_); }
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_ = nullptr;
};

class Child {
public:
    explicit Child(const std::wstring& arguments) {
        std::array<wchar_t, 32768> path{};
        const DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        Check(size && size < path.size(), "не удалось получить путь теста");
        std::wstring command = L"\"" + std::wstring(path.data(), size) + L"\" " + arguments;
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        Check(CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info_) != FALSE,
            "не удалось создать дочерний процесс");
        CloseHandle(info_.hThread);
        info_.hThread = nullptr;
    }
    ~Child() {
        TerminateProcess(info_.hProcess, 1);
        WaitForSingleObject(info_.hProcess, 5000);
        CloseHandle(info_.hProcess);
    }
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;

    void Kill() {
        Check(TerminateProcess(info_.hProcess, 0) != FALSE, "не удалось завершить дочерний процесс");
        Wait(info_.hProcess);
    }
    void RequireSuccess() {
        Wait(info_.hProcess);
        DWORD exitCode = 1;
        Check(GetExitCodeProcess(info_.hProcess, &exitCode) && exitCode == 0,
              "дочерний процесс сообщил об ошибке");
    }
private:
    PROCESS_INFORMATION info_{};
};

// Служебный callback заменяет только IOCTL драйвера. Сам канал и его
// последовательный worker настоящие; SCM, драйвер и pipe не запускаются.
class ServiceLoop {
public:
    ServiceLoop() : name(ChannelName()) {
        Check(server.Start(Query, this, name.c_str()) == ERROR_SUCCESS,
              "не удалось запустить TID-канал");
    }
    ~ServiceLoop() {
        SetEvent(release.get());
        server.Stop();
    }

    static DWORD Query(void* context, uint64_t id, uint64_t& threadId) noexcept {
        auto& service = *static_cast<ServiceLoop*>(context);
        const unsigned active = service.active_.fetch_add(1) + 1;
        if (active > 1) service.parallel.store(true);
        ++service.calls;
        if (id == kBlockedId) {
            SetEvent(service.entered.get());
            WaitForSingleObject(service.release.get(), INFINITE);
        }
        threadId = Expected(id);
        --service.active_;
        return id == kErrorId ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    }

    std::wstring name;
    ServiceThreadId::Server server;
    Event entered;
    Event release;
    std::atomic<unsigned> calls{ 0 };
    std::atomic<bool> parallel{ false };
private:
    std::atomic<unsigned> active_{ 0 };
};

// Освобождается раньше деструкторов jthread, в том числе при исключении теста.
struct Unblock {
    HANDLE event;
    ~Unblock() { SetEvent(event); }
};

void TestValuesAndErrors() {
    ServiceLoop service;
    ServiceThreadId::Client client;
    Check(client.Connect(service.name.c_str()) == ERROR_SUCCESS, "клиент не подключён");
    for (const uint64_t id : { uint64_t{ 0 }, uint64_t{ 42 }, uint64_t{ 0xFFFFFFFF00000001 } }) {
        uint64_t threadId = UINT64_MAX;
        Check(client.GetThreadId(id, threadId), "синхронный запрос завершился ошибкой");
        Check(threadId == Expected(id), "потеряны биты connectionId или threadId");
    }
    uint64_t threadId = UINT64_MAX;
    Check(!client.GetThreadId(kErrorId, threadId), "ошибка службы не передана клиенту");
    Check(threadId == 0 && GetLastError() == ERROR_ACCESS_DENIED, "ошибка или выходной TID неверны");
    Check(service.calls == 4, "число запросов драйверу не равно числу вызовов клиента");
    client.Disconnect();
    Check(!client.GetThreadId(42, threadId) && GetLastError() == ERROR_INVALID_HANDLE,
          "отключённый клиент отправил запрос");
}

void TestCrossProcessExchange() {
    ServiceLoop service;
    const uint64_t id = 0xFFFFFFFF00000001;
    Child child(L"--query \"" + service.name + L"\" " + std::to_wstring(id) +
                L" " + std::to_wstring(Expected(id)));
    child.RequireSuccess();
    Check(service.calls == 1, "один межпроцессный запрос дал несколько вызовов драйвера");
}

void TestRepeatedRequests() {
    ServiceLoop service;
    ServiceThreadId::Client client;
    Check(client.Connect(service.name.c_str()) == ERROR_SUCCESS, "клиент серии не подключён");
    for (uint64_t id = 1; id <= 1000; ++id) {
        uint64_t threadId = 0;
        Check(client.GetThreadId(id, threadId) && threadId == Expected(id),
              "потерян или перепутан ответ в серии запросов");
    }
    Check(service.calls == 1000, "повторный сигнал создал лишний запрос драйверу");
}

void TestSecondRequestWaitsForFirstAnswer() {
    ServiceLoop service;
    ServiceThreadId::Client first;
    ServiceThreadId::Client second;
    Check(first.Connect(service.name.c_str()) == ERROR_SUCCESS, "первый клиент не подключён");
    Check(second.Connect(service.name.c_str()) == ERROR_SUCCESS, "второй клиент не подключён");
    Event secondStarted;
    Event secondFinished;
    uint64_t firstTid = 0, secondTid = 0;
    bool firstOk = false, secondOk = false;
    std::jthread firstRequest([&] { firstOk = first.GetThreadId(kBlockedId, firstTid); });
    Unblock firstGuard{ service.release.get() };
    Wait(service.entered.get());
    std::jthread secondRequest([&] {
        SetEvent(secondStarted.get());
        secondOk = second.GetThreadId(73, secondTid);
        SetEvent(secondFinished.get());
    });
    Unblock secondGuard{ service.release.get() };
    Wait(secondStarted.get());
    Check(WaitForSingleObject(secondFinished.get(), 100) == WAIT_TIMEOUT,
          "второй запрос завершился до ответа первому");
    Check(service.calls == 1, "второй запрос дошёл до службы до первого ответа");
    SetEvent(service.release.get());
    firstRequest.join();
    secondRequest.join();
    Check(firstOk && secondOk && firstTid == Expected(kBlockedId) && secondTid == Expected(73),
          "конкурентные запросы перепутали ответы");
    Check(service.calls == 2 && !service.parallel, "запросы выполнялись параллельно");
}

void TestAbandonedClientDoesNotReuseBusySlot() {
    ServiceLoop service;
    ServiceThreadId::Client next;
    Check(next.Connect(service.name.c_str()) == ERROR_SUCCESS, "следующий клиент не подключён");
    Child child(L"--query \"" + service.name + L"\" " + std::to_wstring(kBlockedId) +
                L" " + std::to_wstring(Expected(kBlockedId)));
    Unblock childGuard{ service.release.get() };
    Wait(service.entered.get());
    child.Kill();

    Event finished;
    uint64_t threadId = 0;
    bool ok = false;
    std::jthread request([&] {
        ok = next.GetThreadId(81, threadId);
        SetEvent(finished.get());
    });
    Unblock requestGuard{ service.release.get() };
    Check(WaitForSingleObject(finished.get(), 100) == WAIT_TIMEOUT,
          "занятый слот переиспользован после смерти первого клиента");
    Check(service.calls == 1, "GetThreadId первого клиента ещё выполняется");
    SetEvent(service.release.get());
    request.join();
    Check(ok && threadId == Expected(81), "старый ответ принят за ответ новому клиенту");
    Check(service.calls == 2 && !service.parallel, "потерян или повторён запрос после abandoned mutex");
}

void TestStopAndRestartInvalidateOldClient() {
    const std::wstring name = ChannelName();
    struct Pending {
        Event entered;
        Event release;
    } pending;
    const auto query = [](void* context, uint64_t id, uint64_t& tid) noexcept -> DWORD {
        if (context) {
            auto& pending = *static_cast<Pending*>(context);
            SetEvent(pending.entered.get());
            WaitForSingleObject(pending.release.get(), INFINITE);
        }
        tid = Expected(id);
        return ERROR_SUCCESS;
    };
    ServiceThreadId::Server server;
    ServiceThreadId::Client oldClient;
    Check(server.Start(query, &pending, name.c_str()) == ERROR_SUCCESS, "канал не запущен");
    Check(oldClient.Connect(name.c_str()) == ERROR_SUCCESS, "старый клиент не подключён");
    Event finished;
    uint64_t threadId = 1;
    DWORD error = 0;
    bool ok = true;
    std::jthread request([&] {
        ok = oldClient.GetThreadId(10, threadId);
        error = GetLastError();
        SetEvent(finished.get());
    });
    Unblock requestGuard{ pending.release.get() };
    Wait(pending.entered.get());
    std::jthread stopper([&] { server.Stop(); });
    Unblock stopGuard{ pending.release.get() };
    Wait(finished.get());
    request.join();
    ServiceThreadId::Server replacement;
    Check(replacement.Start(query, nullptr, name.c_str()) == ERROR_ALREADY_EXISTS,
          "новый Server запущен параллельно с завершающимся IOCTL");
    // Клиент уже разбужен, но Stop не закрывает Channel и драйвер до конца IOCTL.
    SetEvent(pending.release.get());
    stopper.join();
    Check(!ok && threadId == 0 && error == ERROR_OPERATION_ABORTED,
          "остановка службы не прервала ожидание");
    Check(server.Start(query, nullptr, name.c_str()) == ERROR_SUCCESS, "канал не перезапущен");
    Check(!oldClient.GetThreadId(10, threadId) && GetLastError() == ERROR_INVALID_HANDLE,
          "старый клиент отправил запрос в новое поколение службы");
    ServiceThreadId::Client newClient;
    Check(newClient.Connect(name.c_str()) == ERROR_SUCCESS, "новый клиент не подключён");
    Check(newClient.GetThreadId(10, threadId) && threadId == Expected(10),
          "новое поколение не отвечает");
}

void TestServiceCrashWakesClient() {
    const std::wstring name = ChannelName();
    const std::wstring readyName = name + L".TestReady";
    Event ready(readyName.c_str());
    Child child(L"--crash-server \"" + name + L"\" \"" + readyName + L"\"");
    Wait(ready.get());
    ServiceThreadId::Client client;
    Check(client.Connect(name.c_str()) == ERROR_SUCCESS, "клиент аварийной службы не подключён");
    uint64_t threadId = 1;
    Check(!client.GetThreadId(11, threadId), "аварийно завершившаяся служба дала ответ");
    Check(threadId == 0 && GetLastError() == ERROR_PROCESS_ABORTED,
          "аварийное завершение службы не обнаружено");
    child.RequireSuccess();
}

int RunChildQuery(const wchar_t* name, uint64_t id, uint64_t expected) {
    ServiceThreadId::Client client;
    if (client.Connect(name) != ERROR_SUCCESS) return 1;
    uint64_t threadId = 0;
    return client.GetThreadId(id, threadId) && threadId == expected ? 0 : 1;
}

int RunCrashingServer(const wchar_t* name, const wchar_t* readyName) {
    ServiceThreadId::Server server;
    const auto query = [](void*, uint64_t, uint64_t&) noexcept -> DWORD {
        // Намеренно без Stop и деструкторов: клиент ждёт и дескриптор процесса.
        ExitProcess(0);
    };
    if (server.Start(query, nullptr, name) != ERROR_SUCCESS) return 1;
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyName);
    if (!ready) return 1;
    SetEvent(ready);
    CloseHandle(ready);
    Sleep(INFINITE);
    return 1;
}

} // анонимное пространство имён

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 5 && std::wstring_view(argv[1]) == L"--query")
        return RunChildQuery(argv[2], std::wcstoull(argv[3], nullptr, 10),
                             std::wcstoull(argv[4], nullptr, 10));
    if (argc == 4 && std::wstring_view(argv[1]) == L"--crash-server")
        return RunCrashingServer(argv[2], argv[3]);
    try {
        TestValuesAndErrors();
        TestCrossProcessExchange();
        TestRepeatedRequests();
        TestSecondRequestWaitsForFirstAnswer();
        TestAbandonedClientDoesNotReuseBusySlot();
        TestStopAndRestartInvalidateOldClient();
        TestServiceCrashWakesClient();
        std::cout << "service_thread_id_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "service_thread_id_tests: " << error.what() << '\n';
        return 1;
    }
}
