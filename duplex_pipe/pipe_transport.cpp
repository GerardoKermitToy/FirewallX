#include "duplex_pipe/pipe_transport.h"

#include <array>
#include <cstring>
#include <utility>

namespace pipe_transport
{
namespace
{
constexpr std::uint32_t kHandshakeMagic = 0x45504950U;
// Версия 3 означает raw-передачу wire-API драйвера >= 3.0.0.0 без оболочки.
constexpr std::uint16_t kHandshakeVersion = 3;

class Deadline final
{
public:
    explicit Deadline(const DWORD timeoutMilliseconds) noexcept
        : timeoutMilliseconds_(timeoutMilliseconds),
          startedAt_(timeoutMilliseconds == INFINITE ? 0 : GetTickCount64())
    {
    }

    [[nodiscard]] DWORD Remaining() const noexcept
    {
        if (timeoutMilliseconds_ == INFINITE)
        {
            return INFINITE;
        }

        const ULONGLONG elapsed = GetTickCount64() - startedAt_;
        if (elapsed >= timeoutMilliseconds_)
        {
            return 0;
        }
        return timeoutMilliseconds_ - static_cast<DWORD>(elapsed);
    }

    [[nodiscard]] bool IsFinite() const noexcept
    {
        return timeoutMilliseconds_ != INFINITE;
    }

private:
    DWORD timeoutMilliseconds_ = INFINITE;
    ULONGLONG startedAt_ = 0;
};

void StoreUint16(byte* const destination, const std::uint16_t value) noexcept
{
    destination[0] = static_cast<byte>(value & 0xFFU);
    destination[1] = static_cast<byte>((value >> 8U) & 0xFFU);
}

void StoreUint32(byte* const destination, const std::uint32_t value) noexcept
{
    destination[0] = static_cast<byte>(value & 0xFFU);
    destination[1] = static_cast<byte>((value >> 8U) & 0xFFU);
    destination[2] = static_cast<byte>((value >> 16U) & 0xFFU);
    destination[3] = static_cast<byte>((value >> 24U) & 0xFFU);
}

std::uint16_t LoadUint16(const byte* const source) noexcept
{
    return static_cast<std::uint16_t>(source[0]) |
        static_cast<std::uint16_t>(source[1] << 8U);
}

std::uint32_t LoadUint32(const byte* const source) noexcept
{
    return static_cast<std::uint32_t>(source[0]) |
        (static_cast<std::uint32_t>(source[1]) << 8U) |
        (static_cast<std::uint32_t>(source[2]) << 16U) |
        (static_cast<std::uint32_t>(source[3]) << 24U);
}

void BuildHeader(
    byte* const header,
    const HandshakeType type,
    const unsigned long payloadSize) noexcept
{
    StoreUint32(header, kHandshakeMagic);
    StoreUint16(header + 4, kHandshakeVersion);
    StoreUint16(header + 6, static_cast<std::uint16_t>(type));
    StoreUint32(header + 8, payloadSize);
}

DWORD DrainCancelledOperation(
    const HANDLE pipe,
    OVERLAPPED& overlapped,
    const DWORD result) noexcept
{
    CancelIoEx(pipe, &overlapped);
    DWORD transferred = 0;
    GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
    return result;
}

DWORD TransferOnce(
    Connection& connection,
    byte* const buffer,
    const DWORD size,
    const bool writing,
    const DWORD timeoutMilliseconds,
    DWORD& transferred,
    bool& moreData,
    const HANDLE interruptEvent = nullptr) noexcept
{
    transferred = 0;
    moreData = false;
    if (size == 0)
    {
        return ERROR_SUCCESS;
    }
    if (!connection.IsActive()) [[unlikely]]
    {
        return connection.Status();
    }

    const HANDLE operationEvent = writing
        ? connection.WriteEvent()
        : connection.ReadEvent();
    if (operationEvent == nullptr) [[unlikely]]
    {
        return ERROR_NO_SYSTEM_RESOURCES;
    }
    ResetEvent(operationEvent);

    OVERLAPPED overlapped{};
    overlapped.hEvent = operationEvent;
    const BOOL started = writing
        ? WriteFile(
              connection.Pipe(),
              buffer,
              size,
              &transferred,
              &overlapped)
        : ReadFile(
              connection.Pipe(),
              buffer,
              size,
              &transferred,
              &overlapped);

    if (started == FALSE)
    {
        const DWORD startStatus = GetLastError();
        if (startStatus != ERROR_IO_PENDING &&
            (writing || startStatus != ERROR_MORE_DATA))
        {
            return startStatus;
        }
        if (!writing && startStatus == ERROR_MORE_DATA)
        {
            moreData = true;
        }

        const HANDLE waitHandles[] = {
            operationEvent,
            connection.CancelEvent(),
            interruptEvent,
        };
        const DWORD waitStatus = WaitForMultipleObjects(
            interruptEvent ? 3 : 2,
            waitHandles,
            FALSE,
            timeoutMilliseconds);
        if (waitStatus == WAIT_OBJECT_0 + 2 && interruptEvent) [[unlikely]]
        {
            // Отмена может проиграть уже завершившемуся чтению. В этом случае
            // обязательно возвращаем прочитанное сообщение, а не теряем его.
            CancelIoEx(connection.Pipe(), &overlapped);
            if (GetOverlappedResult(
                    connection.Pipe(), &overlapped, &transferred, TRUE) == FALSE)
            {
                const DWORD status = GetLastError();
                if (status == ERROR_OPERATION_ABORTED) return ERROR_RETRY;
                if (!writing && status == ERROR_MORE_DATA) moreData = true;
                else return status;
            }
            return transferred == 0 ? ERROR_BROKEN_PIPE : ERROR_SUCCESS;
        }
        if (waitStatus == WAIT_OBJECT_0 + 1) [[unlikely]]
        {
            const DWORD status = connection.Status();
            return DrainCancelledOperation(
                connection.Pipe(),
                overlapped,
                status == ERROR_SUCCESS ? ERROR_OPERATION_ABORTED : status);
        }
        if (waitStatus == WAIT_TIMEOUT) [[unlikely]]
        {
            return DrainCancelledOperation(
                connection.Pipe(),
                overlapped,
                ERROR_TIMEOUT);
        }
        if (waitStatus != WAIT_OBJECT_0) [[unlikely]]
        {
            return DrainCancelledOperation(
                connection.Pipe(),
                overlapped,
                GetLastError());
        }

        if (GetOverlappedResult(
                connection.Pipe(),
                &overlapped,
                &transferred,
                FALSE) == FALSE)
        {
            const DWORD status = GetLastError();
            if (!writing && status == ERROR_MORE_DATA)
            {
                moreData = true;
            }
            else
            {
                return status;
            }
        }
    }

    return transferred == 0 ? ERROR_BROKEN_PIPE : ERROR_SUCCESS;
}

} // namespace

UniqueHandle::UniqueHandle(const HANDLE handle) noexcept
    : handle_(handle)
{
}

UniqueHandle::~UniqueHandle() noexcept
{
    Reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept
    : handle_(other.Release())
{
}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept
{
    if (this != &other)
    {
        Reset(other.Release());
    }
    return *this;
}

HANDLE UniqueHandle::Get() const noexcept
{
    return handle_;
}

bool UniqueHandle::IsValid() const noexcept
{
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
}

HANDLE UniqueHandle::Release() noexcept
{
    const HANDLE handle = handle_;
    handle_ = INVALID_HANDLE_VALUE;
    return handle;
}

void UniqueHandle::Reset(const HANDLE handle) noexcept
{
    if (IsValid())
    {
        CloseHandle(handle_);
    }
    handle_ = handle;
}

RawMessage::~RawMessage() noexcept = default;

const byte* RawMessage::Data() const noexcept
{
    return payloadSize_ == 0 ? nullptr : buffer_.Data();
}

unsigned long RawMessage::Size() const noexcept
{
    return payloadSize_;
}

bool RawMessage::Empty() const noexcept
{
    return payloadSize_ == 0;
}

void RawMessage::Clear() noexcept
{
    payloadSize_ = 0;
    buffer_.Trim();
}

Connection::Connection(UniqueHandle pipe) noexcept
    : pipe_(std::move(pipe)),
      cancelEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      readEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      writeEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
    if (pipe_.IsValid())
    {
        SetFileCompletionNotificationModes(
            pipe_.Get(),
            FILE_SKIP_SET_EVENT_ON_HANDLE);
    }
}

Connection::~Connection() noexcept
{
    Cancel(ERROR_OPERATION_ABORTED);
}

bool Connection::IsValid() const noexcept
{
    return pipe_.IsValid() && cancelEvent_.IsValid() &&
        readEvent_.IsValid() && writeEvent_.IsValid();
}

bool Connection::IsActive() const noexcept
{
    return IsValid() &&
        status_.load(std::memory_order_acquire) == ERROR_SUCCESS;
}

DWORD Connection::Status() const noexcept
{
    const DWORD status = status_.load(std::memory_order_acquire);
    return status == ERROR_SUCCESS ? ERROR_PIPE_NOT_CONNECTED : status;
}

HANDLE Connection::Pipe() const noexcept
{
    return pipe_.Get();
}

HANDLE Connection::CancelEvent() const noexcept
{
    return cancelEvent_.Get();
}

HANDLE Connection::ReadEvent() const noexcept
{
    return readEvent_.Get();
}

HANDLE Connection::WriteEvent() const noexcept
{
    return writeEvent_.Get();
}

void Connection::Cancel(DWORD status) noexcept
{
    if (status == ERROR_SUCCESS)
    {
        status = ERROR_OPERATION_ABORTED;
    }

    DWORD expected = ERROR_SUCCESS;
    if (status_.compare_exchange_strong(
            expected,
            status,
            std::memory_order_acq_rel,
            std::memory_order_acquire))
    {
        if (cancelEvent_.IsValid())
        {
            SetEvent(cancelEvent_.Get());
        }
        if (pipe_.IsValid())
        {
            CancelIoEx(pipe_.Get(), nullptr);
        }
    }
}

void Connection::LockWrites() noexcept
{
    AcquireSRWLockExclusive(&writeLock_);
}

void Connection::UnlockWrites() noexcept
{
    ReleaseSRWLockExclusive(&writeLock_);
}

DWORD ConnectNamedPipeCancelable(
    const HANDLE pipe,
    const HANDLE stopEvent) noexcept
{
    UniqueHandle operationEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!operationEvent.IsValid())
    {
        return GetLastError();
    }

    OVERLAPPED overlapped{};
    overlapped.hEvent = operationEvent.Get();
    if (ConnectNamedPipe(pipe, &overlapped) != FALSE)
    {
        return ERROR_SUCCESS;
    }

    const DWORD startStatus = GetLastError();
    if (startStatus == ERROR_PIPE_CONNECTED)
    {
        return ERROR_SUCCESS;
    }
    if (startStatus != ERROR_IO_PENDING)
    {
        return startStatus;
    }

    const HANDLE waitHandles[] = {operationEvent.Get(), stopEvent};
    const DWORD waitStatus = WaitForMultipleObjects(
        2,
        waitHandles,
        FALSE,
        INFINITE);
    if (waitStatus == WAIT_OBJECT_0 + 1)
    {
        return DrainCancelledOperation(
            pipe,
            overlapped,
            ERROR_OPERATION_ABORTED);
    }
    if (waitStatus != WAIT_OBJECT_0)
    {
        return DrainCancelledOperation(pipe, overlapped, GetLastError());
    }

    DWORD transferred = 0;
    if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) == FALSE)
    {
        const DWORD status = GetLastError();
        return status == ERROR_PIPE_CONNECTED ? ERROR_SUCCESS : status;
    }
    return ERROR_SUCCESS;
}

DWORD ReadRaw(
    Connection& connection,
    RawMessage& message,
    const DWORD timeoutMilliseconds,
    const HANDLE interruptEvent) noexcept
{
    message.Clear();
    if (!message.buffer_.Reserve(kRawReadChunkSize)) [[unlikely]]
    {
        connection.Cancel(ERROR_NOT_ENOUGH_MEMORY);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    Deadline deadline(timeoutMilliseconds);

    for (;;)
    {
        const size_t available = message.buffer_.Capacity() - message.payloadSize_;
        const DWORD want = available > MAXDWORD ? MAXDWORD : static_cast<DWORD>(available);
        DWORD transferred = 0;
        bool moreData = false;
        DWORD status = TransferOnce(
            connection,
            message.buffer_.Data() + message.payloadSize_,
            want,
            false,
            deadline.Remaining(),
            transferred,
            moreData,
            message.payloadSize_ == 0 ? interruptEvent : nullptr);
        if (status == ERROR_RETRY && interruptEvent) return status;
        if (status != ERROR_SUCCESS) [[unlikely]]
        {
            message.Clear();
            message.buffer_.ReleaseLarge();
            connection.Cancel(status);
            return status;
        }
        if (transferred > MAXDWORD - message.payloadSize_) [[unlikely]]
        {
            message.Clear();
            message.buffer_.ReleaseLarge();
            connection.Cancel(ERROR_ARITHMETIC_OVERFLOW);
            return ERROR_ARITHMETIC_OVERFLOW;
        }
        message.payloadSize_ += transferred;
        if (!moreData)
        {
            message.buffer_.RecordCompleted(message.payloadSize_);
            return ERROR_SUCCESS;
        }

        // Peek нужен только при росте: уже выделенный крупный буфер принимает
        // следующую запись сразу, без копирования первоначального фрагмента.
        DWORD remaining = 0;
        if (!PeekNamedPipe(connection.Pipe(), nullptr, 0, nullptr, nullptr, &remaining)) [[unlikely]]
        {
            status = GetLastError();
            message.Clear();
            message.buffer_.ReleaseLarge();
            connection.Cancel(status);
            return status;
        }
        const size_t additional = remaining ? remaining : kRawReadChunkSize;
        if (additional > MAXDWORD - message.payloadSize_) [[unlikely]]
        {
            message.Clear();
            message.buffer_.ReleaseLarge();
            connection.Cancel(ERROR_ARITHMETIC_OVERFLOW);
            return ERROR_ARITHMETIC_OVERFLOW;
        }
        if (!message.buffer_.Reserve(size_t(message.payloadSize_) + additional,
                                     message.payloadSize_)) [[unlikely]]
        {
            message.Clear();
            message.buffer_.ReleaseLarge();
            connection.Cancel(ERROR_NOT_ENOUGH_MEMORY);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
}

DWORD ReadHandshake(
    Connection& connection,
    HandshakeType& type,
    const DWORD timeoutMilliseconds) noexcept
{
    std::array<byte, kHandshakeHeaderSize> storage;
    DWORD transferred = 0;
    bool moreData = false;
    const DWORD status = TransferOnce(connection, storage.data(),
        static_cast<DWORD>(storage.size()), false, timeoutMilliseconds, transferred, moreData);
    if (status != ERROR_SUCCESS)
    {
        connection.Cancel(status);
        return status;
    }
    if (moreData || transferred != storage.size())
    {
        connection.Cancel(ERROR_INVALID_DATA);
        return ERROR_INVALID_DATA;
    }

    const byte* const header = storage.data();
    const std::uint32_t magic = LoadUint32(header);
    const std::uint16_t version = LoadUint16(header + 4);
    const auto receivedType =
        static_cast<HandshakeType>(LoadUint16(header + 6));
    const std::uint32_t payloadSize = LoadUint32(header + 8);
    if (magic != kHandshakeMagic ||
        (receivedType != HandshakeType::Ready &&
         receivedType != HandshakeType::Rejected &&
         receivedType != HandshakeType::Accepted) ||
        payloadSize != 0)
    {
        connection.Cancel(ERROR_INVALID_DATA);
        return ERROR_INVALID_DATA;
    }
    if (version != kHandshakeVersion)
    {
        connection.Cancel(ERROR_REVISION_MISMATCH);
        return ERROR_REVISION_MISMATCH;
    }
    type = receivedType;
    return ERROR_SUCCESS;
}

DWORD WriteRaw(
    Connection& connection,
    const byte* const data,
    const unsigned long dataSize,
    const DWORD timeoutMilliseconds) noexcept
{
    if (data == nullptr && dataSize != 0) [[unlikely]]
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (dataSize == 0) [[unlikely]]
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (!connection.IsActive()) [[unlikely]]
    {
        return connection.Status();
    }

    connection.LockWrites();
    DWORD transferred = 0;
    bool moreData = false;
    const DWORD status = TransferOnce(
        connection,
        const_cast<byte*>(data),
        dataSize,
        true,
        timeoutMilliseconds,
        transferred,
        moreData);
    connection.UnlockWrites();

    DWORD result = status;
    if (result == ERROR_SUCCESS &&
        (moreData || transferred != dataSize)) [[unlikely]]
    {
        result = ERROR_WRITE_FAULT;
    }
    if (result != ERROR_SUCCESS) [[unlikely]]
    {
        connection.Cancel(result);
    }
    return result;
}

DWORD WriteHandshake(
    Connection& connection,
    const HandshakeType type,
    const DWORD timeoutMilliseconds) noexcept
{
    if (type != HandshakeType::Ready &&
        type != HandshakeType::Rejected &&
        type != HandshakeType::Accepted)
    {
        return ERROR_INVALID_PARAMETER;
    }

    std::array<byte, kHandshakeHeaderSize> header{};
    BuildHeader(header.data(), type, 0);
    return WriteRaw(
        connection,
        header.data(),
        static_cast<unsigned long>(header.size()),
        timeoutMilliseconds);
}
} // namespace pipe_transport
