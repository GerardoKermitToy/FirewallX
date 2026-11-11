#pragma once

#include <cstdint>
#include <string>

namespace quic_sni {

// Непрозрачное состояние, которым владеет ExtractQuicInitialSni. Вызывающая
// сторона не должна ни обращаться к его полям, ни удалять его самостоятельно.
struct QuicSniState;

enum class QuicSniStatus : std::uint8_t {
    NeedMorePackets,
    SniFound,
    InvalidPacket,
    SniNotPresent,
};

struct QuicSniResult {
    QuicSniStatus status = QuicSniStatus::InvalidPacket;
    std::string sni;
};

// Удаляет состояние, созданное ExtractQuicInitialSni, и записывает nullptr в
// указатель вызывающей стороны. Разрешено передавать nullptr либо указатель,
// который уже содержит nullptr.
void FreeQuicSniState(QuicSniState** state) noexcept;

// Извлекает SNI из TLS ClientHello, перенесённого клиентскими пакетами Initial
// QUIC v1/v2 внутри полного UDP-пакета IPv4 или IPv6.
//
// Изначально *state должен содержать nullptr. Если нужны дополнительные пакеты,
// функция создаёт состояние. При любом терминальном результате — SniFound,
// InvalidPacket или SniNotPresent — она удаляет состояние и записывает nullptr.
// Пустой либо нулевой payload также удаляет состояние и возвращает InvalidPacket.
[[nodiscard]] QuicSniResult ExtractQuicInitialSni(
    QuicSniState** state,
    const std::uint8_t* payload,
    std::uint32_t payloadSize) noexcept;

}  // пространство имён quic_sni
