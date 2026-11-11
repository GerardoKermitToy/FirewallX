#include "ThreadSuspend.h"

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
// Внутреннюю таблицу проверяем в том же модуле, без тестового API в приложении.
#include "../ThreadSuspend.cpp"

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct SharedState {
    volatile LONG secondaryTid = 0;
};

DWORD WINAPI IdleThread(void*) {
    Sleep(INFINITE);
    return 0;
}

int RunChild(const wchar_t* mappingName) {
    HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName);
    if (!mapping) return 1;
    auto* shared = static_cast<SharedState*>(
        MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
    if (!shared) {
        CloseHandle(mapping);
        return 1;
    }
    DWORD tid = 0;
    HANDLE secondary = CreateThread(nullptr, 0, IdleThread, nullptr, 0, &tid);
    if (!secondary) {
        UnmapViewOfFile(shared);
        CloseHandle(mapping);
        return 1;
    }
    InterlockedExchange(&shared->secondaryTid, static_cast<LONG>(tid));
    WaitForSingleObject(secondary, INFINITE);
    CloseHandle(secondary);
    UnmapViewOfFile(shared);
    CloseHandle(mapping);
    return 0;
}

// Два настоящих потока отдельного тестового процесса. Завершение дочернего
// процесса в деструкторе не оставляет приостановленных потоков при ошибке теста.
class ChildProcess {
public:
    ChildProcess() {
        try {
            std::array<wchar_t, 32768> path{};
            const DWORD size = GetModuleFileNameW(
                nullptr, path.data(), static_cast<DWORD>(path.size()));
            Check(size && size < path.size(), "не удалось получить путь теста");
            imagePath_.assign(path.data(), size);
            const std::wstring mappingName = L"Local\\FirewallX_thread_suspend_test_" +
                std::to_wstring(GetCurrentProcessId()) + L"_" +
                std::to_wstring(GetTickCount64());
            mapping_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                PAGE_READWRITE, 0, sizeof(SharedState), mappingName.c_str());
            Check(mapping_ != nullptr, "не удалось создать общую память");
            shared_ = static_cast<SharedState*>(
                MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
            Check(shared_ != nullptr, "не удалось отобразить общую память");
            InterlockedExchange(&shared_->secondaryTid, 0);

            std::wstring command = L"\"" + imagePath_ + L"\" --child \"" + mappingName + L"\"";
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            Check(CreateProcessW(imagePath_.c_str(), command.data(), nullptr, nullptr,
                FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info_) != FALSE,
                "не удалось создать дочерний процесс");

            const ULONGLONG deadline = GetTickCount64() + 5000;
            DWORD secondaryTid = 0;
            while (!(secondaryTid = static_cast<DWORD>(
                InterlockedCompareExchange(&shared_->secondaryTid, 0, 0)))) {
                Check(WaitForSingleObject(info_.hProcess, 0) == WAIT_TIMEOUT,
                      "дочерний процесс завершился до создания потока");
                Check(GetTickCount64() < deadline, "дочерний поток не создан вовремя");
                Sleep(5);
            }
            secondary_ = OpenThread(THREAD_SUSPEND_RESUME, FALSE, secondaryTid);
            Check(secondary_ != nullptr, "не удалось открыть дочерний поток");
            secondaryTid_ = secondaryTid;
        } catch (...) {
            Cleanup();
            throw;
        }
    }

    ~ChildProcess() { Cleanup(); }
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    DWORD pid() const { return info_.dwProcessId; }
    DWORD primaryTid() const { return info_.dwThreadId; }
    DWORD secondaryTid() const { return secondaryTid_; }
    HANDLE primary() const { return info_.hThread; }
    HANDLE secondary() const { return secondary_; }

    void Stop() {
        Check(TerminateProcess(info_.hProcess, 0) != FALSE,
              "не удалось завершить дочерний процесс");
        Check(WaitForSingleObject(info_.hProcess, 5000) == WAIT_OBJECT_0,
              "дочерний процесс не завершился");
    }

private:
    void Cleanup() noexcept {
        if (info_.hProcess) {
            TerminateProcess(info_.hProcess, 0);
            WaitForSingleObject(info_.hProcess, 5000);
            CloseHandle(info_.hProcess);
        }
        if (info_.hThread) CloseHandle(info_.hThread);
        if (secondary_) CloseHandle(secondary_);
        if (shared_) UnmapViewOfFile(shared_);
        if (mapping_) CloseHandle(mapping_);
        info_ = {};
        secondary_ = nullptr;
        shared_ = nullptr;
        mapping_ = nullptr;
    }

    PROCESS_INFORMATION info_{};
    HANDLE mapping_ = nullptr;
    HANDLE secondary_ = nullptr;
    SharedState* shared_ = nullptr;
    DWORD secondaryTid_ = 0;
    std::wstring imagePath_;
};

class Suspension {
public:
    explicit Suspension(uint64_t token) : token_(token) {
        Check(token != 0, "поток не приостановлен");
    }
    ~Suspension() { Release(); }
    Suspension(const Suspension&) = delete;
    Suspension& operator=(const Suspension&) = delete;

    uint64_t token() const { return token_; }
    void Release() { ThreadSuspend::Release(std::exchange(token_, 0)); }

private:
    uint64_t token_ = 0;
};

// Возвращает исходный счётчик, не меняя его: пробная пара suspend/resume
// позволяет проверить удержания без зависимости от планировщика и таймеров.
DWORD SuspendCount(HANDLE thread) {
    const DWORD count = SuspendThread(thread);
    Check(count != static_cast<DWORD>(-1), "не удалось проверить счётчик потока");
    Check(ResumeThread(thread) == count + 1, "не удалось снять пробную приостановку");
    return count;
}

void TestOnlyRequestedThreadIsSuspended(ChildProcess& child) {
    Check(SuspendCount(child.primary()) == 0, "исходный поток уже приостановлен");
    Check(SuspendCount(child.secondary()) == 0, "второй поток уже приостановлен");
    Suspension first(ThreadSuspend::Acquire(child.pid(), child.primaryTid()));
    const uint64_t firstToken = first.token();
    Check(SuspendCount(child.primary()) == 1, "исходный поток не удерживается");
    Check(SuspendCount(child.secondary()) == 0, "приостановлен посторонний поток процесса");

    Suspension second(ThreadSuspend::Acquire(child.pid(), child.primaryTid()));
    Check(second.token() != firstToken, "обязательства получили одинаковый токен");
    Check(SuspendCount(child.primary()) == 2, "повторный запрос не удерживает поток");
    first.Release();
    Check(SuspendCount(child.primary()) == 1, "поток возобновлён до последнего ответа");
    ThreadSuspend::Release(firstToken);
    ThreadSuspend::Release(0);
    ThreadSuspend::Release(UINT64_MAX);
    Check(SuspendCount(child.primary()) == 1, "повторное освобождение сняло чужое удержание");
    second.Release();
    Check(SuspendCount(child.primary()) == 0, "поток не возобновлён после последнего ответа");
}

void TestThreadsHaveIndependentTokens(ChildProcess& child) {
    Suspension primary(ThreadSuspend::Acquire(child.pid(), child.primaryTid()));
    Suspension secondary(ThreadSuspend::Acquire(child.pid(), child.secondaryTid()));
    Check(SuspendCount(child.primary()) == 1 && SuspendCount(child.secondary()) == 1,
          "потоки не удерживаются независимо");
    primary.Release();
    Check(SuspendCount(child.primary()) == 0 && SuspendCount(child.secondary()) == 1,
          "освобождение одного потока затронуло другой");
    secondary.Release();
    Check(SuspendCount(child.secondary()) == 0, "второй поток не возобновлён");
}

void TestExternalSuspendIsPreserved(ChildProcess& child) {
    Check(SuspendThread(child.primary()) == 0, "не удалось приостановить поток извне");
    Suspension token(ThreadSuspend::Acquire(child.pid(), child.primaryTid()));
    Check(SuspendCount(child.primary()) == 2, "внешнее удержание потеряно");
    token.Release();
    Check(SuspendCount(child.primary()) == 1, "снята внешняя приостановка потока");
    Check(ResumeThread(child.primary()) == 1, "не удалось снять внешнее удержание");
}

void TestInvalidOwnersAndIdsAreRejected(ChildProcess& child) {
    Check(ThreadSuspend::Acquire(child.pid(), 0) == 0,
          "нулевой TID принят");
    Check(ThreadSuspend::Acquire(child.pid(), UINT64_MAX) == 0,
          "TID обрезан до DWORD");
    Check(ThreadSuspend::Acquire(child.pid(), GetCurrentThreadId()) == 0,
          "приостановлен поток другого процесса");
    Check(ThreadSuspend::Acquire(GetCurrentProcessId(), GetCurrentThreadId()) == 0,
          "приостановлен текущий процесс");
    Check(ThreadSuspend::Acquire(0, child.primaryTid()) == 0,
          "нулевой PID принят");
    Check(ThreadSuspend::Acquire(4, child.primaryTid()) == 0,
          "системный PID принят");
    Check(SuspendCount(child.primary()) == 0, "невалидный запрос оставил удержание");
}

void TestWindowsImageCanBeSuspended() {
    struct Child {
        PROCESS_INFORMATION info{};
        ~Child() {
            if (info.hProcess) {
                TerminateProcess(info.hProcess, 0);
                WaitForSingleObject(info.hProcess, 5000);
                CloseHandle(info.hProcess);
            }
            if (info.hThread) CloseHandle(info.hThread);
        }
    } child;
    std::array<wchar_t, MAX_PATH> root{};
    const UINT size = GetSystemWindowsDirectoryW(root.data(), static_cast<UINT>(root.size()));
    Check(size && size < root.size(), "не удалось получить системный каталог");
    const std::wstring imagePath = std::wstring(root.data(), size) + L"\\System32\\cmd.exe";
    std::wstring command = L"\"" + imagePath + L"\" /c exit";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    Check(CreateProcessW(imagePath.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child.info) != FALSE,
        "не удалось создать процесс из папки Windows");
    Suspension token(ThreadSuspend::Acquire(child.info.dwProcessId, child.info.dwThreadId));
    Check(SuspendCount(child.info.hThread) == 2, "поток процесса из Windows не приостановлен");
    token.Release();
    Check(SuspendCount(child.info.hThread) == 1, "исходная приостановка процесса из Windows снята");
}

void TestTokenStorageRetention(ChildProcess& child) {
    auto& state = ThreadSuspend::GetState();
    for (unsigned pass = 0; pass < 3; ++pass) {
        struct Tokens {
            std::array<uint64_t, 64> values{};
            ~Tokens() { for (uint64_t token : values) ThreadSuspend::Release(token); }
        } tokens;
        {
            std::lock_guard lock(state.mutex);
            // Большой прежний пик не требует приостанавливать тысячи потоков.
            state.tokens.reserve(20000);
        }
        for (uint64_t& token : tokens.values) {
            token = ThreadSuspend::Acquire(child.pid(), child.primaryTid());
            Check(token != 0, "не удалось создать набор токенов для проверки памяти");
        }
        size_t peak = 0;
        {
            std::lock_guard lock(state.mutex);
            peak = state.tokens.bucket_count();
        }
        for (size_t i = 32; i < tokens.values.size(); ++i)
            ThreadSuspend::Release(std::exchange(tokens.values[i], 0));
        {
            std::lock_guard lock(state.mutex);
            Check(state.tokens.size() == 32 && state.tokens.bucket_count() < peak / 8,
                  "таблица токенов сохранила пиковую ёмкость после удаления");
        }
        Check(SuspendCount(child.primary()) == 32,
              "сжатие таблицы нарушило действующие удержания потока");
        for (uint64_t& token : tokens.values) ThreadSuspend::Release(std::exchange(token, 0));
        {
            std::lock_guard lock(state.mutex);
            Check(state.tokens.empty() && state.tokens.bucket_count() <= 8,
                  "пустая таблица токенов не освободила пиковую ёмкость");
        }
        Check(SuspendCount(child.primary()) == 0,
              "освобождение всех токенов оставило поток приостановленным");
    }
}

void TestReleaseAfterProcessExit(ChildProcess& child) {
    Suspension token(ThreadSuspend::Acquire(child.pid(), child.primaryTid()));
    child.Stop();
    token.Release();
}

} // анонимное пространство имён

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 3 && std::wstring_view(argv[1]) == L"--child") return RunChild(argv[2]);
    try {
        ChildProcess child;
        TestOnlyRequestedThreadIsSuspended(child);
        TestThreadsHaveIndependentTokens(child);
        TestExternalSuspendIsPreserved(child);
        TestInvalidOwnersAndIdsAreRejected(child);
        TestWindowsImageCanBeSuspended();
        TestTokenStorageRetention(child);
        TestReleaseAfterProcessExit(child);
        std::cout << "thread_suspend_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "thread_suspend_tests: " << error.what() << '\n';
        return 1;
    }
}
