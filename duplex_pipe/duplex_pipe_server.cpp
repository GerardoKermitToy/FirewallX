#include "duplex_pipe/duplex_pipe_server.h"

#include <atomic>
#include <new>
#include <string>
#include <utility>

#include <Windows.h>
#include <sddl.h>

#include "duplex_pipe/pipe_transport.h"
#include "pipe_support.h"

namespace
{
class PipeSecurity final
{
public:
    PipeSecurity() noexcept
    {
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
                SDDL_REVISION_1,
                &descriptor_,
                nullptr) == FALSE)
        {
            status_ = GetLastError();
            return;
        }

        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = descriptor_;
        attributes_.bInheritHandle = FALSE;
    }

    ~PipeSecurity() noexcept
    {
        if (descriptor_ != nullptr)
        {
            LocalFree(descriptor_);
        }
    }

    [[nodiscard]] bool IsValid() const noexcept
    {
        return descriptor_ != nullptr;
    }

    [[nodiscard]] DWORD Status() const noexcept
    {
        return status_ == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : status_;
    }

    [[nodiscard]] SECURITY_ATTRIBUTES* Attributes() noexcept
    {
        return &attributes_;
    }

private:
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    SECURITY_ATTRIBUTES attributes_{};
    DWORD status_ = ERROR_SUCCESS;
};
} // namespace

namespace duplex_pipe
{
class Server::Impl final
{
public:
    explicit Impl(Channel channel) noexcept
        : pipeName_(PipeName(channel)), stopEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
          startupEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
    {
    }

    ~Impl() noexcept
    {
        Stop();
    }

    RPC_STATUS Start(const std::wstring_view trustedClientPath) noexcept
    {
        AcquireSRWLockExclusive(&lifecycleLock_);
        if (!stopEvent_.IsValid() || !startupEvent_.IsValid())
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        if (workerThread_.IsValid())
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_ALREADY_INITIALIZED;
        }

        std::wstring normalizedTrustedPath;
        const bool pathReady = trustedClientPath.empty()
            ? pipe_support::CurrentExecutablePath(normalizedTrustedPath)
            : pipe_support::NormalizePath(
                  trustedClientPath,
                  normalizedTrustedPath);
        if (!pathReady)
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_INVALID_NAME;
        }

        trustedClientPath_ = std::move(normalizedTrustedPath);
        startupStatus_.store(ERROR_IO_PENDING, std::memory_order_relaxed);
        running_.store(true, std::memory_order_release);
        ResetEvent(stopEvent_.Get());
        ResetEvent(startupEvent_.Get());

        DWORD threadId = 0;
        const HANDLE thread = CreateThread(
            nullptr,
            0,
            WorkerThread,
            this,
            0,
            &threadId);
        if (thread == nullptr)
        {
            const DWORD status = GetLastError();
            running_.store(false, std::memory_order_release);
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }

        workerThread_.Reset(thread);
        workerThreadId_ = threadId;

        const DWORD waitStatus = WaitForSingleObject(
            startupEvent_.Get(),
            pipe_transport::kHandshakeTimeoutMilliseconds);
        if (waitStatus != WAIT_OBJECT_0)
        {
            const DWORD status = waitStatus == WAIT_TIMEOUT
                ? ERROR_TIMEOUT
                : GetLastError();
            RequestStop();
            WaitForSingleObject(workerThread_.Get(), INFINITE);
            workerThread_.Reset();
            workerThreadId_ = 0;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }

        const DWORD startupStatus =
            startupStatus_.load(std::memory_order_acquire);
        if (startupStatus != ERROR_SUCCESS)
        {
            RequestStop();
            WaitForSingleObject(workerThread_.Get(), INFINITE);
            workerThread_.Reset();
            workerThreadId_ = 0;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return startupStatus;
        }

        ReleaseSRWLockExclusive(&lifecycleLock_);
        return ERROR_SUCCESS;
    }

    void Stop() noexcept
    {
        AcquireSRWLockExclusive(&lifecycleLock_);
        RequestStop();
        if (workerThread_.IsValid() &&
            workerThreadId_ != GetCurrentThreadId())
        {
            WaitForSingleObject(workerThread_.Get(), INFINITE);
        }
        workerThread_.Reset();
        workerThreadId_ = 0;
        ReleaseSRWLockExclusive(&lifecycleLock_);
    }

    RPC_STATUS SendRaw(
        const byte* const data,
        const unsigned long dataSize) noexcept
    {
        AcquireSRWLockShared(&activeLock_);
        pipe_transport::Connection* const connection = activeConnection_;
        RPC_STATUS status = RPC_S_SERVER_UNAVAILABLE;
        if (connection != nullptr &&
            running_.load(std::memory_order_acquire) &&
            connection->IsActive())
        {
            status = pipe_transport::WriteRaw(
                *connection,
                data,
                dataSize,
                pipe_transport::kDataTransferTimeoutMilliseconds);
        }
        ReleaseSRWLockShared(&activeLock_);
        return status;
    }

    void SetReceiveCallback(
        const ReceiveCallback callback,
        void* const context) noexcept
    {
        receiveCallback_ = callback;
        receiveContext_ = context;
    }

    void SetConnectionCallback(
        const ConnectionCallback callback,
        void* const context) noexcept
    {
        connectionCallback_ = callback;
        connectionContext_ = context;
    }

private:
    static DWORD WINAPI WorkerThread(void* const parameter) noexcept
    {
        static_cast<Impl*>(parameter)->Run();
        return 0;
    }

    void SignalStartup(
        const DWORD status,
        bool& signalled) noexcept
    {
        if (signalled)
        {
            return;
        }
        startupStatus_.store(status, std::memory_order_release);
        SetEvent(startupEvent_.Get());
        signalled = true;
    }

    void RequestStop() noexcept
    {
        running_.store(false, std::memory_order_release);
        if (stopEvent_.IsValid())
        {
            SetEvent(stopEvent_.Get());
        }

        AcquireSRWLockShared(&activeLock_);
        if (activeConnection_ != nullptr)
        {
            activeConnection_->Cancel(ERROR_OPERATION_ABORTED);
        }
        ReleaseSRWLockShared(&activeLock_);
    }

    bool SetActiveConnection(
        pipe_transport::Connection* const connection) noexcept
    {
        AcquireSRWLockExclusive(&activeLock_);
        const bool accepted = running_.load(std::memory_order_acquire) &&
            activeConnection_ == nullptr;
        if (accepted)
        {
            activeConnection_ = connection;
        }
        ReleaseSRWLockExclusive(&activeLock_);
        return accepted;
    }

    void EndSession(
        pipe_transport::Connection* const connection,
        DWORD status) noexcept
    {
        if (status == ERROR_SUCCESS || status == ERROR_PIPE_NOT_CONNECTED)
        {
            status = ERROR_BROKEN_PIPE;
        }
        connection->Cancel(status);

        bool notify = false;
        AcquireSRWLockExclusive(&activeLock_);
        if (activeConnection_ == connection)
        {
            activeConnection_ = nullptr;
            notify = true;
        }
        ReleaseSRWLockExclusive(&activeLock_);

        if (notify && connectionCallback_ != nullptr)
        {
            connectionCallback_(
                connectionContext_,
                ClientConnectionEvent::Disconnected);
        }
    }

    void ReadClientMessages(pipe_transport::Connection& connection) noexcept
    {
        pipe_transport::RawMessage message;
        while (running_.load(std::memory_order_acquire) &&
               connection.IsActive())
        {
            const DWORD status = pipe_transport::ReadRaw(connection, message);
            if (status != ERROR_SUCCESS) [[unlikely]]
            {
                break;
            }
            if (receiveCallback_ == nullptr)
            {
                connection.Cancel(ERROR_INVALID_DATA);
                break;
            }

            const RPC_STATUS callbackStatus = receiveCallback_(
                receiveContext_,
                message.Data(),
                message.Size());
            if (callbackStatus != ERROR_SUCCESS) [[unlikely]]
            {
                connection.Cancel(callbackStatus);
                break;
            }
        }
    }

    void Run() noexcept
    {
        bool startupSignalled = false;
        PipeSecurity security;
        if (!security.IsValid())
        {
            SignalStartup(security.Status(), startupSignalled);
            running_.store(false, std::memory_order_release);
            return;
        }

        bool firstInstance = true;
        while (running_.load(std::memory_order_acquire))
        {
            const DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
            // Граница записи named pipe сохраняет целую raw-запись драйвера;
            // дополнительный пользовательский заголовок для data path не нужен.
            pipe_transport::UniqueHandle pipe(CreateNamedPipeW(
                pipeName_,
                openMode,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                    PIPE_REJECT_REMOTE_CLIENTS,
                1,
                pipe_transport::kPipeBufferSize,
                pipe_transport::kPipeBufferSize,
                0,
                security.Attributes()));
            if (!pipe.IsValid())
            {
                const DWORD status = GetLastError();
                if (firstInstance)
                {
                    SignalStartup(status, startupSignalled);
                    break;
                }
                if (WaitForSingleObject(stopEvent_.Get(), 100) == WAIT_OBJECT_0)
                {
                    break;
                }
                continue;
            }
            firstInstance = false;
            SignalStartup(ERROR_SUCCESS, startupSignalled);

            DWORD status = pipe_transport::ConnectNamedPipeCancelable(
                pipe.Get(),
                stopEvent_.Get());
            if (!running_.load(std::memory_order_acquire))
            {
                break;
            }
            if (status != ERROR_SUCCESS)
            {
                continue;
            }

            ULONG clientProcessId = 0;
            if (GetNamedPipeClientProcessId(
                    pipe.Get(),
                    &clientProcessId) == FALSE)
            {
                status = GetLastError();
            }
            else
            {
                status = pipe_support::AuthorizeProcessPath(
                    static_cast<DWORD>(clientProcessId),
                    trustedClientPath_);
            }

            pipe_transport::Connection connection(std::move(pipe));
            if (!connection.IsValid())
            {
                continue;
            }
            if (status != ERROR_SUCCESS)
            {
                pipe_transport::WriteHandshake(
                    connection,
                    pipe_transport::HandshakeType::Rejected,
                    pipe_transport::kHandshakeTimeoutMilliseconds);
                connection.Cancel(ERROR_ACCESS_DENIED);
                DisconnectNamedPipe(connection.Pipe());
                continue;
            }

            status = pipe_transport::WriteHandshake(
                connection,
                pipe_transport::HandshakeType::Ready,
                pipe_transport::kHandshakeTimeoutMilliseconds);
            if (status != ERROR_SUCCESS)
            {
                DisconnectNamedPipe(connection.Pipe());
                continue;
            }

            pipe_transport::HandshakeType acknowledgement =
                pipe_transport::HandshakeType::Ready;
            status = pipe_transport::ReadHandshake(
                connection,
                acknowledgement,
                pipe_transport::kHandshakeTimeoutMilliseconds);
            if (status != ERROR_SUCCESS ||
                acknowledgement != pipe_transport::HandshakeType::Accepted)
            {
                if (status == ERROR_SUCCESS)
                {
                    connection.Cancel(ERROR_INVALID_DATA);
                }
                DisconnectNamedPipe(connection.Pipe());
                continue;
            }

            if (!SetActiveConnection(&connection))
            {
                connection.Cancel(ERROR_OPERATION_ABORTED);
                DisconnectNamedPipe(connection.Pipe());
                continue;
            }

            if (connectionCallback_ != nullptr)
            {
                connectionCallback_(
                    connectionContext_,
                    ClientConnectionEvent::Connected);
            }
            ReadClientMessages(connection);
            EndSession(&connection, connection.Status());
            DisconnectNamedPipe(connection.Pipe());
        }

        if (!startupSignalled)
        {
            SignalStartup(ERROR_GEN_FAILURE, startupSignalled);
        }

        AcquireSRWLockShared(&activeLock_);
        pipe_transport::Connection* const active = activeConnection_;
        if (active != nullptr)
        {
            active->Cancel(ERROR_OPERATION_ABORTED);
        }
        ReleaseSRWLockShared(&activeLock_);
        running_.store(false, std::memory_order_release);
    }

    const wchar_t* pipeName_;
    SRWLOCK lifecycleLock_ = SRWLOCK_INIT;
    SRWLOCK activeLock_ = SRWLOCK_INIT;
    pipe_transport::UniqueHandle stopEvent_;
    pipe_transport::UniqueHandle startupEvent_;
    pipe_transport::UniqueHandle workerThread_;
    DWORD workerThreadId_ = 0;
    std::atomic<bool> running_ = false;
    std::atomic<DWORD> startupStatus_ = ERROR_IO_PENDING;
    pipe_transport::Connection* activeConnection_ = nullptr;
    std::wstring trustedClientPath_;
    ReceiveCallback receiveCallback_ = nullptr;
    void* receiveContext_ = nullptr;
    ConnectionCallback connectionCallback_ = nullptr;
    void* connectionContext_ = nullptr;
};

Server::Server(Channel channel) noexcept
    : impl_(new (std::nothrow) Impl(channel))
{
}

Server::~Server() noexcept
{
    delete impl_;
}

RPC_STATUS Server::Start(
    const std::wstring_view trustedClientPath) noexcept
{
    return impl_ != nullptr
        ? impl_->Start(trustedClientPath)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Server::Stop() noexcept
{
    if (impl_ != nullptr)
    {
        impl_->Stop();
    }
}

RPC_STATUS Server::SendRaw(
    const byte* const data,
    const unsigned long dataSize) noexcept
{
    return impl_ != nullptr
        ? impl_->SendRaw(data, dataSize)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Server::SetReceiveCallback(
    const ReceiveCallback callback,
    void* const context) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetReceiveCallback(callback, context);
    }
}

void Server::SetConnectionCallback(
    const ConnectionCallback callback,
    void* const context) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetConnectionCallback(callback, context);
    }
}
} // namespace duplex_pipe
