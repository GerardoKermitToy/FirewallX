#pragma once

#include <rpc.h>
#include <rpcndr.h>

namespace duplex_pipe
{
// После рукопожатия callback получает одно целое raw-сообщение драйвера
// (запись или команду); пользовательский заголовок к нему не добавляется.
// Прикладного лимита размера нет; длина одного Win32-сообщения имеет тип DWORD.

// Каналы используют разные имена pipe, сохраняя общий защищённый raw-транспорт.
enum class Channel { Portmaster, FirewallXNdisFilter };
inline constexpr const wchar_t* PipeName(Channel channel) noexcept {
    return channel == Channel::FirewallXNdisFilter
        ? LR"(\\.\pipe\FirewallX.FirewallXNdisFilter.Service)"
        : LR"(\\.\pipe\WinNamedPipeDuplex.Service)";
}

enum class ClientConnectionEvent
{
    Connected,
    Disconnected,
};

using ReceiveCallback = RPC_STATUS (*)(
    void* context,
    const byte* data,
    unsigned long dataSize) noexcept;
using ConnectionCallback = void (*)(
    void* context,
    ClientConnectionEvent event) noexcept;
} // namespace duplex_pipe
