#pragma once

#include <string_view>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_common.h"

namespace duplex_pipe
{
class DrainWait;

class Client final
{
public:
    explicit Client(Channel channel = Channel::Portmaster) noexcept;
#ifdef FIREWALLX_PIPE_TESTS
    explicit Client(const wchar_t* pipeName) noexcept;
#endif
    ~Client() noexcept;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    RPC_STATUS Start(std::wstring_view trustedServerPath = {}) noexcept;
    void Stop() noexcept;

    // После рукопожатия передаёт одну сырую команду без pipe-заголовка.
    RPC_STATUS SendRaw(const byte* data, unsigned long dataSize) noexcept;
    // Перед закрытием дождаться, пока служба прочитает отправленные команды.
    bool FlushSent() noexcept;
    void SetReceiveCallback(ReceiveCallback callback, void* context) noexcept;
    void SetConnectionCallback(ConnectionCallback callback, void* context) noexcept;

private:
    friend class DrainWait;
    bool BeginDrain(HANDLE completed, HANDLE failed) noexcept;

    class Impl;
    Impl* impl_ = nullptr;
};

// Ожидание выполняется отдельно от Start, чтобы вызывающий код мог заранее
// отпустить замок маршрута, необходимый обработчикам принятых сообщений.
class DrainWait final
{
public:
    DrainWait() noexcept;
    ~DrainWait() noexcept;
    DrainWait(const DrainWait&) = delete;
    DrainWait& operator=(const DrainWait&) = delete;

    bool Start(Client& client) noexcept;
    bool Wait() const noexcept;

private:
    HANDLE completed_ = nullptr;
    HANDLE failed_ = nullptr;
};
} // namespace duplex_pipe
