#pragma once

#include <string_view>

#include "duplex_pipe/duplex_pipe_common.h"

namespace duplex_pipe
{
class Server final
{
public:
    explicit Server(Channel channel = Channel::Portmaster) noexcept;
    ~Server() noexcept;

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = delete;
    Server& operator=(Server&&) = delete;

    RPC_STATUS Start(std::wstring_view trustedClientPath = {}) noexcept;
    void Stop() noexcept;

    // После рукопожатия передаёт одну сырую запись драйвера без pipe-заголовка.
    RPC_STATUS SendRaw(const byte* data, unsigned long dataSize) noexcept;
    void SetReceiveCallback(ReceiveCallback callback, void* context) noexcept;
    void SetConnectionCallback(ConnectionCallback callback, void* context) noexcept;

private:
    class Impl;
    Impl* impl_ = nullptr;
};
} // namespace duplex_pipe
