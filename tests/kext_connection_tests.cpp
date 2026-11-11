#include "PortmasterKextClient.hpp"

#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

// Тест разбирает записи без open(), запуска службы и загрузки драйвера.
namespace FirewallX {
Mode g_runMode = Mode::Desktop;
}

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

constexpr uint64_t kId = 0x0102030405060708ull;
constexpr uint64_t kPid = 0x1112131415161718ull;
constexpr uint64_t kTid = 0xFEDCBA9876543210ull;
constexpr uint32_t kCompartment = 0x21324354u;
constexpr uint32_t kConditionFlags = 0x81828384u;
constexpr uint32_t kInterface = 0x65768798u;
constexpr uint32_t kSubInterface = 0xA9BACBDCu;
constexpr std::array<uint8_t, 4> kPayload{0xDE, 0xAD, 0xBE, 0xEF};

template <class Fixed>
struct Observed {
    static inline Fixed connection{};
    static inline unsigned calls = 0;
    static inline uint32_t payloadSize = 0;
    static inline std::array<uint8_t, 4> payload{};

    static void Reset() {
        connection = {};
        calls = 0;
        payloadSize = 0;
        payload = {};
    }

    static void Receive(const Fixed* event, const uint8_t* data, uint32_t size) noexcept {
        ++calls;
        std::memcpy(&connection, event, sizeof(connection));
        payloadSize = size;
        if (size <= payload.size()) std::memcpy(payload.data(), data, size);
    }
};

// Wire-буфер строится независимо от упакованных структур клиента.
void Append(std::vector<uint8_t>& data, uint64_t value, unsigned size) {
    for (unsigned i = 0; i < size; ++i) {
        data.push_back(static_cast<uint8_t>(value));
        value >>= 8;
    }
}

template <size_t AddressSize>
std::vector<uint8_t> MakeRecord(uint8_t layer = 3, bool withPayload = true,
                                bool zeroMetadata = false) {
    std::vector<uint8_t> data;
    Append(data, kId, 8);
    Append(data, kPid, 8);
    Append(data, zeroMetadata ? 0 : kTid, 8);
    Append(data, zeroMetadata ? 0 : kCompartment, 4);
    Append(data, zeroMetadata ? 0 : kConditionFlags, 4);
    Append(data, zeroMetadata ? 0 : kInterface, 4);
    Append(data, zeroMetadata ? 0 : kSubInterface, 4);
    Append(data, 1, 1);
    Append(data, 17, 1);
    for (size_t i = 0; i < AddressSize; ++i)
        data.push_back(static_cast<uint8_t>(0x20 + i));
    for (size_t i = 0; i < AddressSize; ++i)
        data.push_back(static_cast<uint8_t>(0x80 + i));
    Append(data, 0x1234, 2);
    Append(data, 0x5678, 2);
    Append(data, layer, 1);
    Append(data, withPayload ? kPayload.size() : 0, 4);
    if (withPayload) data.insert(data.end(), kPayload.begin(), kPayload.end());
    return data;
}

template <class Fixed, size_t AddressSize>
void TestConnection(pmkext::KextClient& client, pmkext::InfoType type,
                    uint8_t legacyType) {
    using State = Observed<Fixed>;
    auto data = MakeRecord<AddressSize>();
    State::Reset();
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size()));
    Check(State::calls == 1, "событие соединения не доставлено");
    const auto& event = State::connection;
    Check(event.external_connection_id == kId && event.process_id == kPid,
          "ошибка разбора id/PID");
    Check(event.tid == kTid, "TID обрезан или прочитан по старому смещению");
    Check(event.condition_flags == kConditionFlags, "неверное смещение condition_flags");
    Check(event.compartment_id == kCompartment && event.interface_index == kInterface &&
          event.sub_interface_index == kSubInterface, "ошибка разбора метаданных WFP");
    Check(event.direction == 1 && event.protocol == 17, "смещение direction/protocol неверно");
    for (size_t i = 0; i < AddressSize; ++i) {
        Check(event.local_ip[i] == 0x20 + i, "смещение local_ip неверно");
        Check(event.remote_ip[i] == 0x80 + i, "смещение remote_ip неверно");
    }
    Check(event.local_port == 0x1234 && event.remote_port == 0x5678,
          "ошибка разбора портов");
    Check(event.payload_layer == 3 && State::payloadSize == kPayload.size() &&
          State::payload == kPayload, "ошибка разбора payload");

    // Короткая фиксированная часть, неполная длина и усечённый payload не доходят до callback.
    for (uint32_t size = 0; size < sizeof(Fixed) + 4; ++size) {
        State::Reset();
        client.dispatchOne(type, data.data(), size);
        Check(State::calls == 0, "принята короткая запись");
    }
    State::Reset();
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size() - 1));
    Check(State::calls == 0, "принят усечённый payload");

    for (size_t i = sizeof(Fixed); i < sizeof(Fixed) + 4; ++i) data[i] = 0xFF;
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size()));
    Check(State::calls == 0, "принята переполненная длина payload");

    data = MakeRecord<AddressSize>(3, false, true);
    Check(data.size() == sizeof(Fixed) + 4, "неверный размер фиксированной части API v3");
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size()));
    Check(State::calls == 1 && State::payloadSize == 0, "не принято событие без payload");
    Check(State::connection.tid == 0 && State::connection.compartment_id == 0 &&
          State::connection.condition_flags == 0 &&
          State::connection.interface_index == 0 && State::connection.sub_interface_index == 0,
          "неверно разобраны нулевые метаданные");

    data = MakeRecord<AddressSize>(4);
    State::Reset();
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size()));
    Check(State::calls == 1 && State::payloadSize == 0,
          "изменилось прежнее поведение payload_layer != 3");

    // Максимальные значения не должны менять соседние поля или обрезаться.
    data = MakeRecord<AddressSize>();
    for (size_t i = 16; i < 40; ++i) data[i] = 0xFF;
    State::Reset();
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size()));
    Check(State::calls == 1 && State::connection.tid == std::numeric_limits<uint64_t>::max() &&
          State::connection.compartment_id == std::numeric_limits<uint32_t>::max() &&
          State::connection.condition_flags == std::numeric_limits<uint32_t>::max() &&
          State::connection.interface_index == std::numeric_limits<uint32_t>::max() &&
          State::connection.sub_interface_index == std::numeric_limits<uint32_t>::max(),
          "максимальные метаданные разобраны неверно");

    State::Reset();
    client.dispatchOne(static_cast<pmkext::InfoType>(legacyType), data.data(),
                       static_cast<uint32_t>(data.size()));
    Check(State::calls == 0, "старый тип события ошибочно принят как API v3");
    client.dispatchOne(type, data.data(), static_cast<uint32_t>(data.size()));
    Check(State::calls == 1, "после ошибочной записи клиент не восстановился");
}

} // namespace

int main() {
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionIpv4) == 7);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionIpv6) == 8);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionEndEventV4) == 3);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionEndEventV6) == 4);
    static_assert(sizeof(pmkext::ConnectionFixedV4) + 4 == 59);
    static_assert(sizeof(pmkext::ConnectionFixedV6) + 4 == 83);
    try {
        pmkext::KextClient client;
        client.onConnectionV4 = Observed<pmkext::ConnectionFixedV4>::Receive;
        client.onConnectionV6 = Observed<pmkext::ConnectionFixedV6>::Receive;
        TestConnection<pmkext::ConnectionFixedV4, 4>(client, pmkext::InfoType::ConnectionIpv4, 1);
        TestConnection<pmkext::ConnectionFixedV6, 16>(client, pmkext::InfoType::ConnectionIpv6, 2);
        std::cout << "Portmaster API v3: IPv4/IPv6 metadata and malformed records passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
