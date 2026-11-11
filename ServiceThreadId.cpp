#include "ServiceThreadId.h"
#include "AppInfo.h"

#include <new>
#include <sddl.h>
#include <string>
#include <utility>

namespace ServiceThreadId {
namespace {

constexpr DWORD kMagic = 0x44495446;
constexpr DWORD kConnectTimeoutMs = 5000;

struct alignas(8) Shared {
    DWORD magic = 0;
    DWORD size = 0;
    DWORD serverPid = 0;
    DWORD status = ERROR_IO_PENDING;
    uint64_t serverCreated = 0;
    uint64_t generation = 0;
    volatile LONG64 requestSequence = 0;
    volatile LONG64 responseSequence = 0;
    uint64_t connectionId = 0;
    uint64_t threadId = 0;
    volatile LONG running = 0;
    DWORD reserved = 0;
};
static_assert(sizeof(Shared) == 72);

LONG64 LoadSequence(volatile LONG64& value) noexcept {
    return InterlockedCompareExchange64(&value, 0, 0);
}

bool ProcessCreated(HANDLE process, uint64_t& created) noexcept {
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return false;
    created = (uint64_t{ creation.dwHighDateTime } << 32) | creation.dwLowDateTime;
    return true;
}

struct ExclusiveLock {
    explicit ExclusiveLock(SRWLOCK& lock) noexcept : lock_(lock) {
        AcquireSRWLockExclusive(&lock_);
    }
    ~ExclusiveLock() { ReleaseSRWLockExclusive(&lock_); }
    SRWLOCK& lock_;
};

struct MutexRelease {
    explicit MutexRelease(HANDLE mutex) noexcept : mutex_(mutex) {}
    ~MutexRelease() { ReleaseMutex(mutex_); }
    HANDLE mutex_;
};

DWORD LockMutex(HANDLE mutex) noexcept {
    const DWORD wait = WaitForSingleObject(mutex, kConnectTimeoutMs);
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) return ERROR_SUCCESS;
    return wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
}

} // namespace

namespace detail {

struct Channel {
    HANDLE mutex = nullptr;
    HANDLE request = nullptr;
    HANDLE response = nullptr;
    HANDLE stopped = nullptr;
    HANDLE mapping = nullptr;
    HANDLE serverProcess = nullptr;
    Shared* shared = nullptr;
    DWORD serverPid = 0;
    uint64_t serverCreated = 0;
    uint64_t generation = 0;

    ~Channel() {
        if (shared) UnmapViewOfFile(shared);
        if (serverProcess) CloseHandle(serverProcess);
        if (mapping) CloseHandle(mapping);
        if (stopped) CloseHandle(stopped);
        if (response) CloseHandle(response);
        if (request) CloseHandle(request);
        if (mutex) CloseHandle(mutex);
    }

    DWORD Open(const wchar_t* name, SECURITY_ATTRIBUTES* security, bool create) noexcept {
        try {
            const std::wstring base = name ? name : AppInfo::kServiceThreadIdChannel;
            const std::wstring mutexName = base + L".Mutex";
            const std::wstring requestName = base + L".Request";
            const std::wstring responseName = base + L".Response";
            const std::wstring stoppedName = base + L".Stopped";
            const std::wstring mappingName = base + L".Memory";
            mutex = create ? CreateMutexW(security, FALSE, mutexName.c_str())
                : OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, mutexName.c_str());
            if (!mutex) return GetLastError();
            request = create ? CreateEventW(security, FALSE, FALSE, requestName.c_str())
                : OpenEventW(EVENT_MODIFY_STATE, FALSE, requestName.c_str());
            if (!request) return GetLastError();
            response = create ? CreateEventW(security, FALSE, FALSE, responseName.c_str())
                : OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, responseName.c_str());
            if (!response) return GetLastError();
            stopped = create ? CreateEventW(security, TRUE, TRUE, stoppedName.c_str())
                : OpenEventW(SYNCHRONIZE, FALSE, stoppedName.c_str());
            if (!stopped) return GetLastError();
            mapping = create ? CreateFileMappingW(INVALID_HANDLE_VALUE, security,
                PAGE_READWRITE, 0, sizeof(Shared), mappingName.c_str())
                : OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, mappingName.c_str());
            if (!mapping) return GetLastError();
            shared = static_cast<Shared*>(MapViewOfFile(mapping,
                FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(Shared)));
            return shared ? ERROR_SUCCESS : GetLastError();
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    bool Current() const noexcept {
        return shared->serverPid == serverPid && shared->serverCreated == serverCreated &&
            shared->generation == generation;
    }

    DWORD WaitResponse(LONG64 sequence) noexcept {
        // Таймаута после публикации запроса нет: слот нельзя переиспользовать,
        // пока служба ещё выполняет предыдущий GetThreadId. Завершение службы
        // обнаруживается и при аварии, когда событие Stopped не выставлено.
        HANDLE waits[] = { stopped, serverProcess, response };
        while (LoadSequence(shared->responseSequence) != sequence) {
            const DWORD wait = WaitForMultipleObjects(3, waits, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) return ERROR_OPERATION_ABORTED;
            if (wait == WAIT_OBJECT_0 + 1) return ERROR_PROCESS_ABORTED;
            if (wait != WAIT_OBJECT_0 + 2) return GetLastError();
        }
        if (WaitForSingleObject(stopped, 0) == WAIT_OBJECT_0) return ERROR_OPERATION_ABORTED;
        if (WaitForSingleObject(serverProcess, 0) == WAIT_OBJECT_0) return ERROR_PROCESS_ABORTED;
        return ERROR_SUCCESS;
    }
};

} // namespace detail

Server::Server() noexcept = default;
Server::~Server() { Stop(); }

DWORD Server::Start(Query query, void* context, const wchar_t* channelName) noexcept {
    if (channel_) return ERROR_ALREADY_INITIALIZED;
    if (!query) return ERROR_INVALID_PARAMETER;
    auto channel = std::unique_ptr<detail::Channel>(new (std::nothrow) detail::Channel);
    if (!channel) return ERROR_NOT_ENOUGH_MEMORY;

    // Как и у остальных служебных событий: доступ только SYSTEM и администраторам.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        return GetLastError();
    SECURITY_ATTRIBUTES security{ sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE };
    const DWORD opened = channel->Open(channelName, &security, true);
    LocalFree(descriptor);
    if (opened != ERROR_SUCCESS) return opened;
    const DWORD locked = LockMutex(channel->mutex);
    if (locked != ERROR_SUCCESS) return locked;
    MutexRelease unlock(channel->mutex);

    Shared& shared = *channel->shared;
    // Stopped будит клиента до завершения IOCTL, но новый Server ещё нельзя
    // запускать параллельно со старым worker-ом. running снимается только после join.
    if (shared.magic == kMagic && InterlockedCompareExchange(&shared.running, 0, 0)) {
        HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, shared.serverPid);
        uint64_t created = 0;
        const bool alive = process && ProcessCreated(process, created) &&
            created == shared.serverCreated && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        if (process) CloseHandle(process);
        if (alive) return ERROR_ALREADY_EXISTS;
    }

    uint64_t created = 0;
    if (!ProcessCreated(GetCurrentProcess(), created)) return GetLastError();
    uint64_t generation = shared.magic == kMagic ? shared.generation + 1 : 1;
    if (!generation) ++generation;
    shared = Shared{};
    shared.magic = kMagic;
    shared.size = sizeof(Shared);
    shared.serverPid = GetCurrentProcessId();
    shared.serverCreated = created;
    shared.generation = generation;
    InterlockedExchange(&shared.running, 1);
    ResetEvent(channel->request);
    ResetEvent(channel->response);
    ResetEvent(channel->stopped);
    query_ = query;
    context_ = context;
    channel_ = std::move(channel);
    worker_ = CreateThread(nullptr, 0, WorkerThread, this, 0, nullptr);
    if (!worker_) {
        const DWORD error = GetLastError();
        // unlock ещё использует mutex: оставляем Channel живым до выхода.
        channel = std::move(channel_);
        SetEvent(channel->stopped);
        InterlockedExchange(&channel->shared->running, 0);
        query_ = nullptr;
        context_ = nullptr;
        return error;
    }
    return ERROR_SUCCESS;
}

void Server::Stop() noexcept {
    if (!channel_) return;
    SetEvent(channel_->stopped);
    WaitForSingleObject(worker_, INFINITE);
    CloseHandle(worker_);
    worker_ = nullptr;
    InterlockedExchange(&channel_->shared->running, 0);
    channel_.reset();
    query_ = nullptr;
    context_ = nullptr;
}

DWORD WINAPI Server::WorkerThread(void* context) noexcept {
    auto& server = *static_cast<Server*>(context);
    HANDLE waits[] = { server.channel_->stopped, server.channel_->request };
    while (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
        server.Reply();
    SetEvent(server.channel_->stopped);
    return 0;
}

void Server::Reply() noexcept {
    if (!channel_) return;
    Shared& shared = *channel_->shared;
    const LONG64 sequence = LoadSequence(shared.requestSequence);
    // Повторный сигнал после смерти клиента не создаёт второй запрос драйверу.
    if (sequence == LoadSequence(shared.responseSequence)) return;
    uint64_t threadId = 0;
    shared.status = query_(context_, shared.connectionId, threadId);
    shared.threadId = shared.status == ERROR_SUCCESS ? threadId : 0;
    InterlockedExchange64(&shared.responseSequence, sequence);
    SetEvent(channel_->response);
}

Client::Client() noexcept = default;
Client::~Client() { Disconnect(); }

DWORD Client::Connect(const wchar_t* channelName) noexcept {
    ExclusiveLock lock(lock_);
    channel_.reset();
    auto channel = std::unique_ptr<detail::Channel>(new (std::nothrow) detail::Channel);
    if (!channel) return ERROR_NOT_ENOUGH_MEMORY;
    const DWORD opened = channel->Open(channelName, nullptr, false);
    if (opened != ERROR_SUCCESS) return opened;
    const DWORD locked = LockMutex(channel->mutex);
    if (locked != ERROR_SUCCESS) return locked;
    MutexRelease unlock(channel->mutex);

    const Shared& shared = *channel->shared;
    if (shared.magic != kMagic || shared.size != sizeof(Shared)) return ERROR_INVALID_DATA;
    if (WaitForSingleObject(channel->stopped, 0) != WAIT_TIMEOUT) return ERROR_SERVICE_NOT_ACTIVE;
    channel->serverProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE, shared.serverPid);
    if (!channel->serverProcess) return GetLastError();
    uint64_t created = 0;
    if (!ProcessCreated(channel->serverProcess, created)) return GetLastError();
    if (created != shared.serverCreated ||
        WaitForSingleObject(channel->serverProcess, 0) != WAIT_TIMEOUT) return ERROR_PROCESS_ABORTED;
    channel->serverPid = shared.serverPid;
    channel->serverCreated = created;
    channel->generation = shared.generation;
    channel_ = std::move(channel);
    return ERROR_SUCCESS;
}

void Client::Disconnect() noexcept {
    ExclusiveLock lock(lock_);
    channel_.reset();
}

bool Client::GetThreadId(uint64_t external_connection_id, uint64_t& threadIdOut) noexcept {
    threadIdOut = 0;
    ExclusiveLock lock(lock_);
    if (!channel_) { SetLastError(ERROR_INVALID_HANDLE); return false; }
    auto& channel = *channel_;
    HANDLE waits[] = { channel.stopped, channel.serverProcess, channel.mutex };
    const DWORD wait = WaitForMultipleObjects(3, waits, FALSE, INFINITE);
    if (wait != WAIT_OBJECT_0 + 2 && wait != WAIT_ABANDONED_0 + 2) {
        SetLastError(wait == WAIT_OBJECT_0 ? ERROR_OPERATION_ABORTED :
            wait == WAIT_OBJECT_0 + 1 ? ERROR_PROCESS_ABORTED : GetLastError());
        return false;
    }
    MutexRelease unlock(channel.mutex);
    if (!channel.Current()) { SetLastError(ERROR_INVALID_HANDLE); return false; }

    Shared& shared = *channel.shared;
    LONG64 sequence = LoadSequence(shared.requestSequence);
    if (sequence != LoadSequence(shared.responseSequence)) {
        // Предыдущий клиент мог завершиться, удерживая mutex. Сначала дожидаемся
        // его ответа; SetEvent также восстанавливает запрос, оборванный до сигнала.
        if (!SetEvent(channel.request)) return false;
        const DWORD status = channel.WaitResponse(sequence);
        if (status != ERROR_SUCCESS) { SetLastError(status); return false; }
    }

    ResetEvent(channel.response);
    shared.connectionId = external_connection_id;
    shared.threadId = 0;
    shared.status = ERROR_IO_PENDING;
    const uint64_t next = static_cast<uint64_t>(sequence) + 1;
    sequence = static_cast<LONG64>(next ? next : 1);
    InterlockedExchange64(&shared.requestSequence, sequence);
    if (!SetEvent(channel.request)) return false;
    DWORD status = channel.WaitResponse(sequence);
    if (status == ERROR_SUCCESS) status = shared.status;
    if (status == ERROR_SUCCESS) threadIdOut = shared.threadId;
    SetLastError(status);
    return status == ERROR_SUCCESS;
}

} // namespace ServiceThreadId
