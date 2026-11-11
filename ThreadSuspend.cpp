#include "ThreadSuspend.h"
#include "StorageMaintenance.h"

#include <mutex>
#include <unordered_map>

namespace ThreadSuspend {
namespace {

struct State {
    std::mutex mutex;
    // Каждый токен удерживает открытый дескриптор исходного потока и одну
    // пару SuspendThread/ResumeThread. Числовой TID может быть переиспользован,
    // но Release никогда не открывает поток заново по этому идентификатору.
    std::unordered_map<uint64_t, HANDLE> tokens;
    uint64_t nextToken = 0;

    ~State() noexcept {
        for (const auto& item : tokens) {
            ResumeThread(item.second);
            CloseHandle(item.second);
        }
    }
};

State& GetState() noexcept {
    static State state;
    return state;
}

} // namespace

uint64_t Acquire(DWORD pid, uint64_t threadId) noexcept {
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId() ||
        threadId == 0 || threadId > MAXDWORD) return 0;

    HANDLE thread = OpenThread(
        THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME,
        FALSE, static_cast<DWORD>(threadId));
    if (!thread) return 0;
    // TID от драйвера мог устареть до OpenThread. Не останавливаем поток,
    // если открытый дескриптор принадлежит другому процессу.
    if (GetProcessIdOfThread(thread) != pid) {
        CloseHandle(thread);
        return 0;
    }

    State& state = GetState();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
        CloseHandle(thread);
        return 0;
    }

    uint64_t token = 0;
    do {
        token = ++state.nextToken;
    } while (token == 0 || state.tokens.count(token));
    try {
        if (state.tokens.emplace(token, thread).second) return token;
    } catch (...) {
    }
    ResumeThread(thread);
    CloseHandle(thread);
    return 0;
}

void Release(uint64_t token) noexcept {
    if (!token) return;

    State& state = GetState();
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto it = state.tokens.find(token);
    if (it == state.tokens.end()) return;

    ResumeThread(it->second);
    CloseHandle(it->second);
    state.tokens.erase(it);
    // Освобождение токена noexcept: нехватка памяти при сжатии не должна
    // помешать возобновлению потока и закрытию уже снятого дескриптора.
    try {
        TrimHashTable(state.tokens);
    } catch (...) {
    }
}

} // namespace ThreadSuspend
