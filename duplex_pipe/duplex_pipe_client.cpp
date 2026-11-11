#include "duplex_pipe/duplex_pipe_client.h"

#include <atomic>
#include <new>
#include <string>
#include <utility>

#include <Windows.h>

#include "duplex_pipe/pipe_transport.h"
#include "pipe_support.h"

namespace
{
DWORD OpenServerPipe(pipe_transport::UniqueHandle& pipe, const wchar_t* pipeName) noexcept
{
    pipe.Reset();

    for (int attempt = 0; attempt < 2; ++attempt)
    {
        const HANDLE handle = CreateFileW(
            pipeName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
                SECURITY_IDENTIFICATION,
            nullptr);
        if (handle != INVALID_HANDLE_VALUE)
        {
            // Читаем те же границы raw-сообщений, которые создаёт служба.
            DWORD readMode = PIPE_READMODE_MESSAGE;
            if (SetNamedPipeHandleState(
                    handle, &readMode, nullptr, nullptr) == FALSE)
            {
                const DWORD status = GetLastError();
                CloseHandle(handle);
                return status;
            }
            pipe.Reset(handle);
            return ERROR_SUCCESS;
        }

        const DWORD status = GetLastError();
        if (status != ERROR_PIPE_BUSY)
        {
            return status;
        }
        if (WaitNamedPipeW(
                pipeName,
                pipe_transport::kHandshakeTimeoutMilliseconds) == FALSE)
        {
            return GetLastError();
        }
    }

    return ERROR_PIPE_BUSY;
}
} // namespace

namespace duplex_pipe
{
class Client::Impl final
{
public:
    explicit Impl(Channel channel) noexcept : pipeName_(PipeName(channel)) {}
#ifdef FIREWALLX_PIPE_TESTS
    explicit Impl(const wchar_t* pipeName) noexcept : pipeName_(pipeName) {}
#endif

    ~Impl() noexcept
    {
        Stop();
    }

    RPC_STATUS Start(const std::wstring_view trustedServerPath) noexcept
    {
        AcquireSRWLockExclusive(&lifecycleLock_);
        if (readerThread_.IsValid() || connection_ != nullptr)
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_ALREADY_INITIALIZED;
        }
        if (!drainRequest_.IsValid())
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        std::wstring normalizedTrustedPath;
        const bool pathReady = trustedServerPath.empty()
            ? pipe_support::CurrentExecutablePath(normalizedTrustedPath)
            : pipe_support::NormalizePath(
                  trustedServerPath,
                  normalizedTrustedPath);
        if (!pathReady)
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_INVALID_NAME;
        }

        pipe_transport::UniqueHandle pipe;
        DWORD status = OpenServerPipe(pipe, pipeName_);
        if (status != ERROR_SUCCESS)
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }

        ULONG serverProcessId = 0;
        if (GetNamedPipeServerProcessId(pipe.Get(), &serverProcessId) == FALSE)
        {
            status = GetLastError();
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }
        status = pipe_support::AuthorizeProcessPath(
            static_cast<DWORD>(serverProcessId),
            normalizedTrustedPath);
        if (status != ERROR_SUCCESS)
        {
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }

        auto* const connection = new (std::nothrow)
            pipe_transport::Connection(std::move(pipe));
        if (connection == nullptr || !connection->IsValid())
        {
            delete connection;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        pipe_transport::HandshakeType handshake =
            pipe_transport::HandshakeType::Ready;
        status = pipe_transport::ReadHandshake(
            *connection,
            handshake,
            pipe_transport::kHandshakeTimeoutMilliseconds);
        if (status != ERROR_SUCCESS)
        {
            delete connection;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }
        if (handshake == pipe_transport::HandshakeType::Rejected)
        {
            connection->Cancel(ERROR_ACCESS_DENIED);
            delete connection;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_ACCESS_DENIED;
        }
        if (handshake != pipe_transport::HandshakeType::Ready)
        {
            connection->Cancel(ERROR_INVALID_DATA);
            delete connection;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return ERROR_INVALID_DATA;
        }

        status = pipe_transport::WriteHandshake(
            *connection,
            pipe_transport::HandshakeType::Accepted,
            pipe_transport::kHandshakeTimeoutMilliseconds);
        if (status != ERROR_SUCCESS)
        {
            delete connection;
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }

        AcquireSRWLockExclusive(&connectionLock_);
        connection_ = connection;
        ReleaseSRWLockExclusive(&connectionLock_);
        NotifyConnected();

        DWORD threadId = 0;
        const HANDLE thread = CreateThread(
            nullptr,
            0,
            ReaderThread,
            this,
            0,
            &threadId);
        if (thread == nullptr)
        {
            status = GetLastError();
            AcquireSRWLockExclusive(&connectionLock_);
            connection_ = nullptr;
            ReleaseSRWLockExclusive(&connectionLock_);
            connection->Cancel(status);
            delete connection;
            NotifyDisconnected();
            ReleaseSRWLockExclusive(&lifecycleLock_);
            return status;
        }

        readerThread_.Reset(thread);
        readerThreadId_ = threadId;
        ReleaseSRWLockExclusive(&lifecycleLock_);
        return ERROR_SUCCESS;
    }

    void Stop() noexcept
    {
        AcquireSRWLockExclusive(&lifecycleLock_);

        AcquireSRWLockShared(&connectionLock_);
        pipe_transport::Connection* const connection = connection_;
        if (connection != nullptr)
        {
            connection->Cancel(ERROR_OPERATION_ABORTED);
        }
        ReleaseSRWLockShared(&connectionLock_);

        if (readerThread_.IsValid() &&
            readerThreadId_ != GetCurrentThreadId())
        {
            WaitForSingleObject(readerThread_.Get(), INFINITE);
        }
        readerThread_.Reset();
        readerThreadId_ = 0;

        AcquireSRWLockExclusive(&connectionLock_);
        pipe_transport::Connection* const dead = connection_;
        connection_ = nullptr;
        ReleaseSRWLockExclusive(&connectionLock_);
        delete dead;

        NotifyDisconnected();
        ReleaseSRWLockExclusive(&lifecycleLock_);
    }

    RPC_STATUS SendRaw(
        const byte* const data,
        const unsigned long dataSize) noexcept
    {
        AcquireSRWLockShared(&connectionLock_);
        pipe_transport::Connection* const connection = connection_;
        const RPC_STATUS status = connection != nullptr
            ? pipe_transport::WriteRaw(
                  *connection,
                  data,
                  dataSize,
                  pipe_transport::kDataTransferTimeoutMilliseconds)
            : static_cast<RPC_STATUS>(RPC_S_INVALID_BINDING);
        ReleaseSRWLockShared(&connectionLock_);
        return status;
    }

    bool FlushSent() noexcept
    {
        AcquireSRWLockShared(&connectionLock_);
        const bool flushed = connection_ != nullptr && connection_->IsActive() &&
            FlushFileBuffers(connection_->Pipe()) != FALSE;
        ReleaseSRWLockShared(&connectionLock_);
        return flushed;
    }

    bool BeginDrain(const HANDLE completed, const HANDLE failed) noexcept
    {
        HANDLE completedCopy = nullptr;
        HANDLE failedCopy = nullptr;
        const HANDLE process = GetCurrentProcess();
        if (!DuplicateHandle(process, completed, process, &completedCopy,
                             EVENT_MODIFY_STATE, FALSE, 0)) return false;
        if (!DuplicateHandle(process, failed, process, &failedCopy,
                             EVENT_MODIFY_STATE, FALSE, 0))
        {
            CloseHandle(completedCopy);
            return false;
        }

        AcquireSRWLockExclusive(&drainLock_);
        const bool ready = connected_.load(std::memory_order_acquire) &&
            !drainPending_.load(std::memory_order_relaxed) && drainRequest_.IsValid();
        if (ready)
        {
            drainCompleted_.Reset(completedCopy);
            drainFailed_.Reset(failedCopy);
            drainPending_.store(true, std::memory_order_release);
            if (!SetEvent(drainRequest_.Get()))
            {
                drainPending_.store(false, std::memory_order_release);
                drainCompleted_.Reset();
                drainFailed_.Reset();
                ReleaseSRWLockExclusive(&drainLock_);
                return false;
            }
        }
        ReleaseSRWLockExclusive(&drainLock_);
        if (!ready)
        {
            CloseHandle(completedCopy);
            CloseHandle(failedCopy);
        }
        return ready;
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
    static DWORD WINAPI ReaderThread(void* const parameter) noexcept
    {
        static_cast<Impl*>(parameter)->ReadLoop();
        return 0;
    }

    void ReadLoop() noexcept
    {
        pipe_transport::Connection* const connection = connection_;
        if (connection == nullptr)
        {
            NotifyDisconnected();
            return;
        }

        pipe_transport::RawMessage message;
        while (connection->IsActive())
        {
            const bool draining = drainPending_.load(std::memory_order_acquire);
            if (draining) [[unlikely]]
            {
                DWORD available = 0;
                if (!PeekNamedPipe(connection->Pipe(), nullptr, 0, nullptr,
                                   &available, nullptr))
                {
                    connection->Cancel(GetLastError());
                    break;
                }
                if (available == 0)
                {
                    FinishDrain(true);
                    continue;
                }
            }
            const DWORD status = pipe_transport::ReadRaw(
                *connection, message, INFINITE, draining ? nullptr : drainRequest_.Get());
            if (status == ERROR_RETRY) [[unlikely]] continue;
            if (status != ERROR_SUCCESS) [[unlikely]]
            {
                break;
            }
            if (receiveCallback_ == nullptr)
            {
                connection->Cancel(ERROR_INVALID_DATA);
                break;
            }

            const RPC_STATUS callbackStatus = receiveCallback_(
                receiveContext_,
                message.Data(),
                message.Size());
            if (callbackStatus != ERROR_SUCCESS) [[unlikely]]
            {
                connection->Cancel(callbackStatus);
                break;
            }
        }
        NotifyDisconnected();
    }

    void FinishDrain(const bool success) noexcept
    {
        AcquireSRWLockExclusive(&drainLock_);
        if (drainPending_.load(std::memory_order_relaxed))
        {
            ResetEvent(drainRequest_.Get());
            drainPending_.store(false, std::memory_order_release);
            SetEvent(success ? drainCompleted_.Get() : drainFailed_.Get());
            drainCompleted_.Reset();
            drainFailed_.Reset();
        }
        ReleaseSRWLockExclusive(&drainLock_);
    }

    void NotifyConnected() noexcept
    {
        bool expected = false;
        if (connected_.compare_exchange_strong(
                expected,
                true,
                std::memory_order_acq_rel,
                std::memory_order_acquire) &&
            connectionCallback_ != nullptr)
        {
            connectionCallback_(
                connectionContext_,
                ClientConnectionEvent::Connected);
        }
    }

    void NotifyDisconnected() noexcept
    {
        bool expected = true;
        if (connected_.compare_exchange_strong(
                expected,
                false,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
        {
            FinishDrain(false);
            if (connectionCallback_ != nullptr)
                connectionCallback_(
                    connectionContext_,
                    ClientConnectionEvent::Disconnected);
        }
    }

    const wchar_t* pipeName_;
    SRWLOCK lifecycleLock_ = SRWLOCK_INIT;
    SRWLOCK connectionLock_ = SRWLOCK_INIT;
    pipe_transport::Connection* connection_ = nullptr;
    pipe_transport::UniqueHandle readerThread_;
    DWORD readerThreadId_ = 0;
    ReceiveCallback receiveCallback_ = nullptr;
    void* receiveContext_ = nullptr;
    ConnectionCallback connectionCallback_ = nullptr;
    void* connectionContext_ = nullptr;
    std::atomic<bool> connected_ = false;
    SRWLOCK drainLock_ = SRWLOCK_INIT;
    pipe_transport::UniqueHandle drainRequest_{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    pipe_transport::UniqueHandle drainCompleted_;
    pipe_transport::UniqueHandle drainFailed_;
    std::atomic<bool> drainPending_ = false;
};

Client::Client(Channel channel) noexcept
    : impl_(new (std::nothrow) Impl(channel))
{
}

#ifdef FIREWALLX_PIPE_TESTS
Client::Client(const wchar_t* pipeName) noexcept
    : impl_(new (std::nothrow) Impl(pipeName))
{
}
#endif

Client::~Client() noexcept
{
    delete impl_;
}

RPC_STATUS Client::Start(
    const std::wstring_view trustedServerPath) noexcept
{
    return impl_ != nullptr
        ? impl_->Start(trustedServerPath)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Client::Stop() noexcept
{
    if (impl_ != nullptr)
    {
        impl_->Stop();
    }
}

RPC_STATUS Client::SendRaw(
    const byte* const data,
    const unsigned long dataSize) noexcept
{
    return impl_ != nullptr
        ? impl_->SendRaw(data, dataSize)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

bool Client::FlushSent() noexcept
{
    return impl_ != nullptr && impl_->FlushSent();
}

bool Client::BeginDrain(const HANDLE completed, const HANDLE failed) noexcept
{
    return impl_ != nullptr && impl_->BeginDrain(completed, failed);
}

DrainWait::DrainWait() noexcept
    : completed_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      failed_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
}

DrainWait::~DrainWait() noexcept
{
    if (completed_) CloseHandle(completed_);
    if (failed_) CloseHandle(failed_);
}

bool DrainWait::Start(Client& client) noexcept
{
    if (!completed_ || !failed_) return false;
    ResetEvent(completed_);
    ResetEvent(failed_);
    return client.BeginDrain(completed_, failed_);
}

bool DrainWait::Wait() const noexcept
{
    if (!completed_ || !failed_) return false;
    const HANDLE events[] = {completed_, failed_};
    return WaitForMultipleObjects(2, events, FALSE, INFINITE) == WAIT_OBJECT_0;
}

void Client::SetReceiveCallback(
    const ReceiveCallback callback,
    void* const context) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetReceiveCallback(callback, context);
    }
}

void Client::SetConnectionCallback(
    const ConnectionCallback callback,
    void* const context) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetConnectionCallback(callback, context);
    }
}
} // namespace duplex_pipe
