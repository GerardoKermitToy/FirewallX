#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_common.h"
#include "ReadBuffer.h"

namespace pipe_transport
{
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\WinNamedPipeDuplex.Service";
constexpr DWORD kHandshakeTimeoutMilliseconds = 5000;
// Размер и скорость чтения не ограничивают доставку. Stop/Cancel прерывает I/O.
constexpr DWORD kDataTransferTimeoutMilliseconds = INFINITE;
// Это квота рабочего буфера ядра, а не максимальный размер сообщения.
constexpr DWORD kPipeBufferSize = 512U * 1024U;
constexpr size_t kHandshakeHeaderSize = 12;
constexpr size_t kRawReadChunkSize = 512U * 1024U;

class UniqueHandle final
{
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept;
    ~UniqueHandle() noexcept;

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept;
    UniqueHandle& operator=(UniqueHandle&& other) noexcept;

    [[nodiscard]] HANDLE Get() const noexcept;
    [[nodiscard]] bool IsValid() const noexcept;
    HANDLE Release() noexcept;
    void Reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

// Типы используются только в 12-байтовом рукопожатии. После него данные
// передаются отдельными raw-сообщениями named pipe без этого заголовка.
enum class HandshakeType : std::uint16_t
{
    Ready = 1,
    Rejected = 2,
    Accepted = 3,
};

class RawMessage final
{
public:
    RawMessage() noexcept = default;
    ~RawMessage() noexcept;

    RawMessage(const RawMessage&) = delete;
    RawMessage& operator=(const RawMessage&) = delete;

    [[nodiscard]] const byte* Data() const noexcept;
    [[nodiscard]] unsigned long Size() const noexcept;
    [[nodiscard]] bool Empty() const noexcept;

private:
    friend DWORD ReadRaw(
        class Connection& connection,
        RawMessage& message,
        DWORD timeoutMilliseconds,
        HANDLE interruptEvent) noexcept;

    friend struct RawMessageTestAccess;
    void Clear() noexcept;

    read_buffer::Buffer<kRawReadChunkSize> buffer_;
    unsigned long payloadSize_ = 0;
};

class Connection final
{
public:
    explicit Connection(UniqueHandle pipe) noexcept;
    ~Connection() noexcept;

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] bool IsActive() const noexcept;
    [[nodiscard]] DWORD Status() const noexcept;
    [[nodiscard]] HANDLE Pipe() const noexcept;
    [[nodiscard]] HANDLE CancelEvent() const noexcept;
    [[nodiscard]] HANDLE ReadEvent() const noexcept;
    [[nodiscard]] HANDLE WriteEvent() const noexcept;

    void Cancel(DWORD status) noexcept;
    void LockWrites() noexcept;
    void UnlockWrites() noexcept;

private:
    friend DWORD ReadRaw(
        Connection& connection,
        RawMessage& message,
        DWORD timeoutMilliseconds,
        HANDLE interruptEvent) noexcept;
    friend DWORD WriteRaw(
        Connection& connection,
        const byte* data,
        unsigned long dataSize,
        DWORD timeoutMilliseconds) noexcept;

    UniqueHandle pipe_;
    UniqueHandle cancelEvent_;
    UniqueHandle readEvent_;
    UniqueHandle writeEvent_;
    std::atomic<DWORD> status_ = ERROR_SUCCESS;
    SRWLOCK writeLock_ = SRWLOCK_INIT;
};

DWORD ConnectNamedPipeCancelable(HANDLE pipe, HANDLE stopEvent) noexcept;
// Заголовок используется только для трёх сообщений рукопожатия.
DWORD ReadHandshake(
    Connection& connection,
    HandshakeType& type,
    DWORD timeoutMilliseconds = INFINITE) noexcept;
DWORD WriteHandshake(
    Connection& connection,
    HandshakeType type,
    DWORD timeoutMilliseconds = INFINITE) noexcept;

// После рукопожатия named pipe работает в message mode: один вызов записи
// переносит одно целое raw-сообщение драйвера без пользовательского заголовка.
// Если interruptEvent сработал до начала сообщения, возвращается ERROR_RETRY;
// частично прочитанное сообщение всегда дочитывается без прерывания.
DWORD ReadRaw(
    Connection& connection,
    RawMessage& message,
    DWORD timeoutMilliseconds = INFINITE,
    HANDLE interruptEvent = nullptr) noexcept;
DWORD WriteRaw(
    Connection& connection,
    const byte* data,
    unsigned long dataSize,
    DWORD timeoutMilliseconds = INFINITE) noexcept;
} // namespace pipe_transport
