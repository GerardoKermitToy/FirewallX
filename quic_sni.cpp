#include "quic_sni.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace quic_sni {

namespace detail {

void DestroyCngKey(BCRYPT_KEY_HANDLE handle) noexcept {
    const NTSTATUS status = BCryptDestroyKey(handle);
    static_cast<void>(status);
}

template <typename Handle, void (*Close)(Handle)>
class CngHandle {
public:
    CngHandle() = default;
    CngHandle(const CngHandle&) = delete;
    CngHandle& operator=(const CngHandle&) = delete;

    CngHandle(CngHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}

    CngHandle& operator=(CngHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~CngHandle() {
        Reset();
    }

    [[nodiscard]] Handle Get() const noexcept {
        return handle_;
    }

    [[nodiscard]] Handle* Put() noexcept {
        Reset();
        return &handle_;
    }

private:
    void Reset() noexcept {
        if (handle_ != nullptr) {
            Close(handle_);
            handle_ = nullptr;
        }
    }

    Handle handle_ = nullptr;
};

using CngKeyHandle = CngHandle<BCRYPT_KEY_HANDLE, DestroyCngKey>;

struct InitialCryptoContext {
    std::array<std::uint8_t, 12> iv{};
    CngKeyHandle packetKey;
    CngKeyHandle headerProtectionKey;
    // Сохранённое состояние повторно использует оба ключа и ёмкость буферов.
    std::vector<std::uint8_t> associatedData;
    std::vector<std::uint8_t> plaintext;
};

}  // пространство имён detail

struct QuicSniState {
    std::uint8_t ipVersion = 0;
    std::array<std::uint8_t, 16> sourceAddress{};
    std::array<std::uint8_t, 16> destinationAddress{};
    std::size_t addressLength = 0;
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::uint32_t quicVersion = 0;
    std::array<std::uint8_t, 20> destinationConnectionId{};
    std::size_t destinationConnectionIdLength = 0;
    detail::InitialCryptoContext initialCrypto;
    std::optional<std::uint64_t> largestPacketNumber;
    std::vector<std::uint8_t> cryptoData;
    std::vector<std::uint8_t> cryptoDataPresent;
    std::size_t contiguousCryptoDataSize = 0;
};

void FreeQuicSniState(QuicSniState** state) noexcept {
    if (state != nullptr) {
        delete *state;
        *state = nullptr;
    }
}

namespace {

constexpr std::uint32_t kQuicV1 = 0x00000001U;
constexpr std::uint32_t kQuicV2 = 0x6b3343cfU;
constexpr std::size_t kAeadTagLength = 16;
constexpr std::size_t kHeaderProtectionSampleLength = 16;
constexpr std::size_t kMaximumCryptoStreamSize = 1024U * 1024U;
constexpr std::size_t kMaximumHkdfLabelLength = 255;
constexpr std::size_t kMaximumHkdfInfoLength = 2U + 1U + kMaximumHkdfLabelLength + 1U;
constexpr std::uint64_t kMaxPacketNumber = (std::uint64_t{1} << 62U) - 1U;

constexpr std::array<std::uint8_t, 20> kQuicV1InitialSalt = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

constexpr std::array<std::uint8_t, 20> kQuicV2InitialSalt = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

struct Bytes {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
};

struct UdpDatagram {
    Bytes payload;
    std::uint8_t ipVersion = 0;
    std::array<std::uint8_t, 16> sourceAddress{};
    std::array<std::uint8_t, 16> destinationAddress{};
    std::size_t addressLength = 0;
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
};

[[nodiscard]] bool HasRange(Bytes bytes, std::size_t offset, std::size_t length) {
    return offset <= bytes.size && length <= bytes.size - offset;
}

[[nodiscard]] std::optional<Bytes> SubBytes(
    Bytes bytes,
    std::size_t offset,
    std::size_t length) {
    if (!HasRange(bytes, offset, length)) {
        return std::nullopt;
    }
    return Bytes{bytes.data + offset, length};
}

[[nodiscard]] bool IsZeroFilled(Bytes bytes) noexcept {
    std::size_t offset = 0;
    for (; bytes.size - offset >= sizeof(std::uint64_t);
         offset += sizeof(std::uint64_t)) {
        std::uint64_t word;
        std::memcpy(&word, bytes.data + offset, sizeof(word));
        if (word != 0) {
            return false;
        }
    }
    for (; offset < bytes.size; ++offset) {
        if (bytes.data[offset] != 0) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::uint16_t ReadBe16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8U) |
        static_cast<std::uint16_t>(data[1]));
}

[[nodiscard]] std::uint32_t ReadBe24(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 16U) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           static_cast<std::uint32_t>(data[2]);
}

[[nodiscard]] std::uint32_t ReadBe32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24U) |
           (static_cast<std::uint32_t>(data[1]) << 16U) |
           (static_cast<std::uint32_t>(data[2]) << 8U) |
           static_cast<std::uint32_t>(data[3]);
}

class Cursor {
public:
    explicit Cursor(Bytes bytes, std::size_t offset = 0)
        : bytes_(bytes), offset_(offset) {}

    [[nodiscard]] std::size_t offset() const { return offset_; }
    [[nodiscard]] std::size_t remaining() const {
        return offset_ <= bytes_.size ? bytes_.size - offset_ : 0;
    }

    bool ReadU8(std::uint8_t& value) {
        if (!HasRange(bytes_, offset_, 1)) {
            return false;
        }
        value = bytes_.data[offset_++];
        return true;
    }

    bool ReadU16(std::uint16_t& value) {
        if (!HasRange(bytes_, offset_, 2)) {
            return false;
        }
        value = ReadBe16(bytes_.data + offset_);
        offset_ += 2;
        return true;
    }

    bool ReadVarInt(std::uint64_t& value) {
        if (!HasRange(bytes_, offset_, 1)) {
            return false;
        }

        const std::uint8_t first = bytes_.data[offset_];
        const std::size_t length = std::size_t{1} << (first >> 6U);
        if (!HasRange(bytes_, offset_, length)) {
            return false;
        }

        value = first & 0x3fU;
        for (std::size_t i = 1; i < length; ++i) {
            value = (value << 8U) | bytes_.data[offset_ + i];
        }
        offset_ += length;
        return true;
    }

    bool Skip(std::uint64_t length) {
        if (length > std::numeric_limits<std::size_t>::max()) {
            return false;
        }
        const auto nativeLength = static_cast<std::size_t>(length);
        if (!HasRange(bytes_, offset_, nativeLength)) {
            return false;
        }
        offset_ += nativeLength;
        return true;
    }

    bool Take(std::uint64_t length, Bytes& value) {
        if (length > std::numeric_limits<std::size_t>::max()) {
            return false;
        }
        const auto nativeLength = static_cast<std::size_t>(length);
        const auto result = SubBytes(bytes_, offset_, nativeLength);
        if (!result) {
            return false;
        }
        value = *result;
        offset_ += nativeLength;
        return true;
    }

private:
    Bytes bytes_;
    std::size_t offset_;
};

[[nodiscard]] std::optional<UdpDatagram> ExtractUdpPayloadFromIpv4(Bytes packet) {
    if (!HasRange(packet, 0, 20)) {
        return std::nullopt;
    }

    const std::size_t headerLength = (packet.data[0] & 0x0fU) * 4U;
    if (headerLength < 20 || !HasRange(packet, 0, headerLength)) {
        return std::nullopt;
    }

    const std::size_t totalLength = ReadBe16(packet.data + 2);
    if (totalLength < headerLength || totalLength > packet.size) {
        return std::nullopt;
    }

    const std::uint16_t fragment = ReadBe16(packet.data + 6);
    if ((fragment & 0xbfffU) != 0 || packet.data[9] != 17) {
        return std::nullopt;
    }

    constexpr std::size_t kUdpHeaderLength = 8;
    if (totalLength - headerLength < kUdpHeaderLength) {
        return std::nullopt;
    }

    const std::size_t udpOffset = headerLength;
    const std::size_t udpLength = ReadBe16(packet.data + udpOffset + 4);
    if (udpLength < kUdpHeaderLength || udpLength > totalLength - udpOffset) {
        return std::nullopt;
    }

    const auto udpPayload =
        SubBytes(packet, udpOffset + kUdpHeaderLength, udpLength - kUdpHeaderLength);
    if (!udpPayload) {
        return std::nullopt;
    }

    UdpDatagram result;
    result.payload = *udpPayload;
    result.ipVersion = 4;
    result.addressLength = 4;
    std::copy_n(packet.data + 12, result.addressLength, result.sourceAddress.begin());
    std::copy_n(packet.data + 16, result.addressLength, result.destinationAddress.begin());
    result.sourcePort = ReadBe16(packet.data + udpOffset);
    result.destinationPort = ReadBe16(packet.data + udpOffset + 2);
    return result;
}

[[nodiscard]] std::optional<UdpDatagram> ExtractUdpPayloadFromIpv6(Bytes packet) {
    constexpr std::size_t kIpv6HeaderLength = 40;
    constexpr std::size_t kUdpHeaderLength = 8;
    if (!HasRange(packet, 0, kIpv6HeaderLength)) {
        return std::nullopt;
    }

    const std::size_t payloadLength = ReadBe16(packet.data + 4);
    if (payloadLength == 0 || payloadLength > packet.size - kIpv6HeaderLength) {
        return std::nullopt;
    }

    const std::size_t packetEnd = kIpv6HeaderLength + payloadLength;
    std::uint8_t nextHeader = packet.data[6];
    std::size_t offset = kIpv6HeaderLength;

    for (unsigned extensionCount = 0; nextHeader != 17; ++extensionCount) {
        if (extensionCount >= 16 || offset >= packetEnd) {
            return std::nullopt;
        }

        std::size_t extensionLength = 0;
        switch (nextHeader) {
            case 0:   // параметры Hop-by-Hop
            case 43:  // маршрутизация
            case 60:  // параметры назначения
                if (packetEnd - offset < 2) {
                    return std::nullopt;
                }
                extensionLength = (static_cast<std::size_t>(packet.data[offset + 1]) + 1U) * 8U;
                break;
            case 51:  // заголовок аутентификации
                if (packetEnd - offset < 2) {
                    return std::nullopt;
                }
                extensionLength = (static_cast<std::size_t>(packet.data[offset + 1]) + 2U) * 4U;
                break;
            case 44:  // Фрагментированную дейтаграмму этот API собрать не может.
            case 50:  // защищённая полезная нагрузка ESP
            case 59:  // следующего заголовка нет
            default:
                return std::nullopt;
        }

        if (extensionLength == 0 || extensionLength > packetEnd - offset) {
            return std::nullopt;
        }
        nextHeader = packet.data[offset];
        offset += extensionLength;
    }

    if (packetEnd - offset < kUdpHeaderLength) {
        return std::nullopt;
    }

    const std::size_t udpLength = ReadBe16(packet.data + offset + 4);
    if (udpLength < kUdpHeaderLength || udpLength > packetEnd - offset) {
        return std::nullopt;
    }

    const auto udpPayload =
        SubBytes(packet, offset + kUdpHeaderLength, udpLength - kUdpHeaderLength);
    if (!udpPayload) {
        return std::nullopt;
    }

    UdpDatagram result;
    result.payload = *udpPayload;
    result.ipVersion = 6;
    result.addressLength = 16;
    std::copy_n(packet.data + 8, result.addressLength, result.sourceAddress.begin());
    std::copy_n(packet.data + 24, result.addressLength, result.destinationAddress.begin());
    result.sourcePort = ReadBe16(packet.data + offset);
    result.destinationPort = ReadBe16(packet.data + offset + 2);
    return result;
}

[[nodiscard]] std::optional<UdpDatagram> ExtractUdpPayload(Bytes packet) {
    if (packet.size == 0) {
        return std::nullopt;
    }

    switch (packet.data[0] >> 4U) {
        case 4:
            return ExtractUdpPayloadFromIpv4(packet);
        case 6:
            return ExtractUdpPayloadFromIpv6(packet);
        default:
            return std::nullopt;
    }
}

struct VersionParameters {
    Bytes salt;
    std::string_view keyLabel;
    std::string_view ivLabel;
    std::string_view hpLabel;
    std::uint8_t initialType;
    std::uint8_t retryType;
};

[[nodiscard]] std::optional<VersionParameters> GetVersionParameters(std::uint32_t version) {
    if (version == kQuicV1) {
        return VersionParameters{
            {kQuicV1InitialSalt.data(), kQuicV1InitialSalt.size()},
            "quic key",
            "quic iv",
            "quic hp",
            0,
            3,
        };
    }
    if (version == kQuicV2) {
        return VersionParameters{
            {kQuicV2InitialSalt.data(), kQuicV2InitialSalt.size()},
            "quicv2 key",
            "quicv2 iv",
            "quicv2 hp",
            1,
            0,
        };
    }
    return std::nullopt;
}

struct LongPacket {
    std::size_t start = 0;
    std::size_t packetNumberOffset = 0;
    std::size_t end = 0;
    std::uint32_t version = 0;
    Bytes destinationConnectionId;
    bool isInitial = false;
    bool consumesRestOfDatagram = false;
};

[[nodiscard]] std::optional<LongPacket> ParseLongPacket(Bytes datagram, std::size_t start) {
    if (!HasRange(datagram, start, 7)) {
        return std::nullopt;
    }

    const std::uint8_t first = datagram.data[start];
    if ((first & 0xc0U) != 0xc0U) {
        return std::nullopt;
    }

    const std::uint32_t version = ReadBe32(datagram.data + start + 1);
    const auto parameters = GetVersionParameters(version);
    if (!parameters) {
        return std::nullopt;
    }

    Cursor cursor(datagram, start + 5);
    std::uint8_t connectionIdLength = 0;
    Bytes destinationConnectionId;
    if (!cursor.ReadU8(connectionIdLength) || connectionIdLength > 20 ||
        !cursor.Take(connectionIdLength, destinationConnectionId)) {
        return std::nullopt;
    }

    if (!cursor.ReadU8(connectionIdLength) || connectionIdLength > 20 ||
        !cursor.Skip(connectionIdLength)) {
        return std::nullopt;
    }

    const std::uint8_t packetType = static_cast<std::uint8_t>((first >> 4U) & 0x03U);
    const bool isInitial = packetType == parameters->initialType;
    if (packetType == parameters->retryType) {
        return LongPacket{
            start,
            cursor.offset(),
            datagram.size,
            version,
            destinationConnectionId,
            false,
            true,
        };
    }

    if (isInitial) {
        std::uint64_t tokenLength = 0;
        if (!cursor.ReadVarInt(tokenLength) || !cursor.Skip(tokenLength)) {
            return std::nullopt;
        }
    }

    std::uint64_t protectedLength = 0;
    if (!cursor.ReadVarInt(protectedLength) ||
        protectedLength > datagram.size - cursor.offset()) {
        return std::nullopt;
    }

    return LongPacket{
        start,
        cursor.offset(),
        cursor.offset() + static_cast<std::size_t>(protectedLength),
        version,
        destinationConnectionId,
        isInitial,
        false,
    };
}

using detail::CngKeyHandle;
using detail::InitialCryptoContext;

[[nodiscard]] bool CngSucceeded(NTSTATUS status) noexcept {
    return BCRYPT_SUCCESS(status);
}

[[nodiscard]] bool FitsCngBuffer(std::size_t size) noexcept {
    return size <= static_cast<std::size_t>(std::numeric_limits<ULONG>::max());
}

[[nodiscard]] PUCHAR MutableBytes(const std::uint8_t* data) noexcept {
    return reinterpret_cast<PUCHAR>(const_cast<std::uint8_t*>(data));
}

[[nodiscard]] bool HmacSha256(
    Bytes key,
    Bytes input,
    std::array<std::uint8_t, 32>& output) {
    if (!FitsCngBuffer(key.size) || !FitsCngBuffer(input.size)) {
        return false;
    }

    std::uint8_t emptyInput = 0;
    // Псевдодескрипторы Windows 11 позволяют не открывать дескриптор
    // поставщика алгоритма на каждом шаге HKDF.
    return CngSucceeded(BCryptHash(
        BCRYPT_HMAC_SHA256_ALG_HANDLE,
        key.size == 0 ? nullptr : MutableBytes(key.data),
        static_cast<ULONG>(key.size),
        input.size == 0 ? &emptyInput : MutableBytes(input.data),
        static_cast<ULONG>(input.size),
        output.data(),
        static_cast<ULONG>(output.size())));
}

[[nodiscard]] bool HkdfExpandSha256(
    const std::array<std::uint8_t, 32>& secret,
    Bytes info,
    std::uint8_t* output,
    std::size_t outputLength) {
    constexpr std::size_t kHashLength = 32;
    if (outputLength > 255U * kHashLength || info.size > kMaximumHkdfInfoLength) {
        return false;
    }

    std::array<std::uint8_t, kHashLength> previous{};
    std::array<std::uint8_t, kHashLength + kMaximumHkdfInfoLength + 1U> input;
    std::size_t previousLength = 0;
    std::size_t written = 0;
    std::uint8_t counter = 1;

    while (written < outputLength) {
        std::size_t inputLength = 0;
        if (previousLength != 0) {
            std::memcpy(input.data(), previous.data(), previousLength);
            inputLength += previousLength;
        }
        if (info.size != 0) {
            std::memcpy(input.data() + inputLength, info.data, info.size);
            inputLength += info.size;
        }
        input[inputLength++] = counter;

        if (!HmacSha256(
                {secret.data(), secret.size()},
                {input.data(), inputLength},
                previous)) {
            return false;
        }

        previousLength = previous.size();
        const std::size_t toCopy = std::min(previousLength, outputLength - written);
        std::memcpy(output + written, previous.data(), toCopy);
        written += toCopy;
        ++counter;
    }

    return true;
}

template <std::size_t OutputLength>
[[nodiscard]] bool HkdfExpandLabel(
    const std::array<std::uint8_t, 32>& secret,
    std::string_view label,
    std::array<std::uint8_t, OutputLength>& output) {
    constexpr std::string_view kPrefix = "tls13 ";
    if (OutputLength > std::numeric_limits<std::uint16_t>::max() ||
        kPrefix.size() + label.size() > std::numeric_limits<std::uint8_t>::max()) {
        return false;
    }

    const std::size_t fullLabelLength = kPrefix.size() + label.size();
    std::array<std::uint8_t, kMaximumHkdfInfoLength> hkdfLabel;
    std::size_t hkdfLabelLength = 0;
    hkdfLabel[hkdfLabelLength++] = static_cast<std::uint8_t>(OutputLength >> 8U);
    hkdfLabel[hkdfLabelLength++] = static_cast<std::uint8_t>(OutputLength);
    hkdfLabel[hkdfLabelLength++] = static_cast<std::uint8_t>(fullLabelLength);
    std::memcpy(hkdfLabel.data() + hkdfLabelLength, kPrefix.data(), kPrefix.size());
    hkdfLabelLength += kPrefix.size();
    std::memcpy(hkdfLabel.data() + hkdfLabelLength, label.data(), label.size());
    hkdfLabelLength += label.size();
    hkdfLabel[hkdfLabelLength++] = 0;  // Пустой контекст.

    return HkdfExpandSha256(
        secret,
        {hkdfLabel.data(), hkdfLabelLength},
        output.data(),
        output.size());
}

struct InitialKeys {
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> iv{};
    std::array<std::uint8_t, 16> headerProtection{};
};

[[nodiscard]] std::optional<InitialKeys> DeriveClientInitialKeys(
    const VersionParameters& parameters,
    Bytes destinationConnectionId) {
    std::array<std::uint8_t, 32> initialSecret{};
    if (!HmacSha256(parameters.salt, destinationConnectionId, initialSecret)) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 32> clientSecret{};
    if (!HkdfExpandLabel(initialSecret, "client in", clientSecret)) {
        return std::nullopt;
    }

    InitialKeys keys;
    if (!HkdfExpandLabel(clientSecret, parameters.keyLabel, keys.key) ||
        !HkdfExpandLabel(clientSecret, parameters.ivLabel, keys.iv) ||
        !HkdfExpandLabel(clientSecret, parameters.hpLabel, keys.headerProtection)) {
        return std::nullopt;
    }
    return keys;
}

[[nodiscard]] bool GenerateAesKey(
    BCRYPT_ALG_HANDLE algorithm,
    Bytes keyMaterial,
    CngKeyHandle& key) {
    if (keyMaterial.size != 16 || !FitsCngBuffer(keyMaterial.size)) {
        return false;
    }

    return CngSucceeded(BCryptGenerateSymmetricKey(
        algorithm,
        key.Put(),
        nullptr,
        0,
        MutableBytes(keyMaterial.data),
        static_cast<ULONG>(keyMaterial.size),
        0));
}

[[nodiscard]] std::optional<InitialCryptoContext> CreateInitialCryptoContext(
    const VersionParameters& parameters,
    Bytes destinationConnectionId) {
    const auto keys = DeriveClientInitialKeys(parameters, destinationConnectionId);
    if (!keys) {
        return std::nullopt;
    }

    InitialCryptoContext context;
    context.iv = keys->iv;
    if (!GenerateAesKey(
            BCRYPT_AES_GCM_ALG_HANDLE,
            {keys->key.data(), keys->key.size()},
            context.packetKey) ||
        !GenerateAesKey(
            BCRYPT_AES_ECB_ALG_HANDLE,
            {keys->headerProtection.data(), keys->headerProtection.size()},
            context.headerProtectionKey)) {
        return std::nullopt;
    }
    return context;
}

[[nodiscard]] std::optional<std::array<std::uint8_t, 5>> CreateHeaderProtectionMask(
    BCRYPT_KEY_HANDLE key,
    const std::uint8_t* sample) {
    std::array<std::uint8_t, 16> block{};
    ULONG outputLength = 0;
    if (!CngSucceeded(BCryptEncrypt(
            key,
            MutableBytes(sample),
            static_cast<ULONG>(kHeaderProtectionSampleLength),
            nullptr,
            nullptr,
            0,
            block.data(),
            static_cast<ULONG>(block.size()),
            &outputLength,
            0)) ||
        outputLength != static_cast<ULONG>(block.size())) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 5> mask{};
    std::copy_n(block.begin(), mask.size(), mask.begin());
    return mask;
}

[[nodiscard]] std::uint64_t DecodePacketNumber(
    std::uint64_t truncated,
    std::size_t encodedLength,
    std::uint64_t expected) {
    const unsigned bitCount = static_cast<unsigned>(encodedLength * 8U);
    const std::uint64_t window = std::uint64_t{1} << bitCount;
    const std::uint64_t halfWindow = window / 2U;
    const std::uint64_t mask = window - 1U;
    std::uint64_t candidate = (expected & ~mask) | truncated;

    if (candidate < kMaxPacketNumber - window + 1U &&
        candidate <= expected && expected - candidate >= halfWindow) {
        candidate += window;
    } else if (candidate >= window && candidate > expected &&
               candidate - expected > halfWindow) {
        candidate -= window;
    }
    return candidate;
}

[[nodiscard]] bool DecryptAes128Gcm(
    InitialCryptoContext& context,
    std::uint64_t packetNumber,
    Bytes associatedData,
    Bytes ciphertextAndTag) {
    if (!FitsCngBuffer(associatedData.size) ||
        ciphertextAndTag.size < kAeadTagLength) {
        return false;
    }

    const std::size_t ciphertextLength = ciphertextAndTag.size - kAeadTagLength;
    if (!FitsCngBuffer(ciphertextLength)) {
        return false;
    }

    std::array<std::uint8_t, 12> nonce = context.iv;
    for (std::size_t i = 0; i < sizeof(packetNumber); ++i) {
        nonce[nonce.size() - 1U - i] ^=
            static_cast<std::uint8_t>(packetNumber >> (i * 8U));
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authenticationInfo{};
    authenticationInfo.cbSize = sizeof(authenticationInfo);
    authenticationInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    authenticationInfo.pbNonce = nonce.data();
    authenticationInfo.cbNonce = static_cast<ULONG>(nonce.size());
    authenticationInfo.pbAuthData = associatedData.size == 0
        ? nullptr
        : MutableBytes(associatedData.data);
    authenticationInfo.cbAuthData = static_cast<ULONG>(associatedData.size);
    authenticationInfo.pbTag =
        MutableBytes(ciphertextAndTag.data + ciphertextLength);
    authenticationInfo.cbTag = static_cast<ULONG>(kAeadTagLength);

    // Ненулевой выходной буфер заставляет CNG выполнить проверку подлинности,
    // даже если открытый текст имеет нулевую длину.
    context.plaintext.resize(std::max<std::size_t>(ciphertextLength, 1U));
    ULONG plaintextLength = 0;
    if (!CngSucceeded(BCryptDecrypt(
            context.packetKey.Get(),
            ciphertextLength == 0 ? nullptr : MutableBytes(ciphertextAndTag.data),
            static_cast<ULONG>(ciphertextLength),
            &authenticationInfo,
            nullptr,
            0,
            context.plaintext.data(),
            static_cast<ULONG>(context.plaintext.size()),
            &plaintextLength,
            0)) ||
        plaintextLength != static_cast<ULONG>(ciphertextLength)) {
        return false;
    }

    context.plaintext.resize(plaintextLength);
    return true;
}

struct DecryptedInitial {
    std::uint64_t packetNumber = 0;
};

[[nodiscard]] std::optional<DecryptedInitial> DecryptInitialPacket(
    Bytes datagram,
    const LongPacket& packet,
    std::uint64_t expectedPacketNumber,
    InitialCryptoContext& context) {
    if (packet.packetNumberOffset < packet.start || packet.end < packet.packetNumberOffset ||
        !HasRange(datagram, packet.start, packet.end - packet.start) ||
        packet.packetNumberOffset + 4U > packet.end ||
        kHeaderProtectionSampleLength > packet.end - (packet.packetNumberOffset + 4U)) {
        return std::nullopt;
    }

    const auto mask = CreateHeaderProtectionMask(
        context.headerProtectionKey.Get(),
        datagram.data + packet.packetNumberOffset + 4U);
    if (!mask) {
        return std::nullopt;
    }

    const std::uint8_t unprotectedFirst =
        datagram.data[packet.start] ^ ((*mask)[0] & 0x0fU);
    if ((unprotectedFirst & 0x0cU) != 0) {
        return std::nullopt;
    }

    const std::size_t packetNumberLength = (unprotectedFirst & 0x03U) + 1U;
    if (!HasRange(datagram, packet.packetNumberOffset, packetNumberLength) ||
        packet.packetNumberOffset + packetNumberLength > packet.end) {
        return std::nullopt;
    }

    std::uint64_t truncatedPacketNumber = 0;
    std::array<std::uint8_t, 4> packetNumberBytes{};
    for (std::size_t i = 0; i < packetNumberLength; ++i) {
        packetNumberBytes[i] =
            datagram.data[packet.packetNumberOffset + i] ^ (*mask)[i + 1U];
        truncatedPacketNumber =
            (truncatedPacketNumber << 8U) | packetNumberBytes[i];
    }

    const std::uint64_t packetNumber = DecodePacketNumber(
        truncatedPacketNumber, packetNumberLength, expectedPacketNumber);
    if (packetNumber > kMaxPacketNumber) {
        return std::nullopt;
    }

    const std::size_t associatedDataLength =
        packet.packetNumberOffset + packetNumberLength - packet.start;
    context.associatedData.assign(
        datagram.data + packet.start,
        datagram.data + packet.start + associatedDataLength);
    context.associatedData[0] = unprotectedFirst;
    const std::size_t relativePacketNumberOffset = packet.packetNumberOffset - packet.start;
    std::copy_n(
        packetNumberBytes.begin(),
        packetNumberLength,
        context.associatedData.begin() +
            static_cast<std::ptrdiff_t>(relativePacketNumberOffset));

    const std::size_t ciphertextOffset = packet.packetNumberOffset + packetNumberLength;
    if (!DecryptAes128Gcm(
            context,
            packetNumber,
            {context.associatedData.data(), context.associatedData.size()},
            {datagram.data + ciphertextOffset, packet.end - ciphertextOffset})) {
        return std::nullopt;
    }

    return DecryptedInitial{packetNumber};
}

class CryptoReassembler {
public:
    explicit CryptoReassembler(QuicSniState& state) : state_(state) {}

    bool Add(std::uint64_t offset, Bytes data) {
        if (offset > kMaximumCryptoStreamSize) {
            return false;
        }
        if (data.size == 0) {
            return true;
        }

        const std::size_t nativeOffset = static_cast<std::size_t>(offset);
        if (data.size > kMaximumCryptoStreamSize - nativeOffset) {
            return false;
        }

        const std::size_t requiredSize = nativeOffset + data.size;
        const std::size_t previousSize = state_.cryptoData.size();
        if (requiredSize > previousSize) {
            state_.cryptoData.resize(requiredSize);
            state_.cryptoDataPresent.resize(requiredSize);
        }

        if (nativeOffset >= previousSize) {
            std::copy_n(
                data.data,
                data.size,
                state_.cryptoData.begin() + static_cast<std::ptrdiff_t>(nativeOffset));
            std::fill(
                state_.cryptoDataPresent.begin() +
                    static_cast<std::ptrdiff_t>(nativeOffset),
                state_.cryptoDataPresent.begin() +
                    static_cast<std::ptrdiff_t>(requiredSize),
                std::uint8_t{1});

            if (nativeOffset == state_.contiguousCryptoDataSize) {
                state_.contiguousCryptoDataSize = requiredSize;
            }
        } else {
            for (std::size_t i = 0; i < data.size; ++i) {
                const std::size_t index = nativeOffset + i;
                if (state_.cryptoDataPresent[index] != 0 &&
                    state_.cryptoData[index] != data.data[i]) {
                    return false;
                }
                state_.cryptoData[index] = data.data[i];
                state_.cryptoDataPresent[index] = 1;
            }
        }

        while (state_.contiguousCryptoDataSize < state_.cryptoDataPresent.size() &&
               state_.cryptoDataPresent[state_.contiguousCryptoDataSize] != 0) {
            ++state_.contiguousCryptoDataSize;
        }
        return true;
    }

    [[nodiscard]] Bytes contiguous() const {
        return {state_.cryptoData.data(), state_.contiguousCryptoDataSize};
    }

private:
    QuicSniState& state_;
};

bool SkipAckFrame(Cursor& cursor, bool hasEcnCounts) {
    std::uint64_t ignored = 0;
    std::uint64_t rangeCount = 0;
    if (!cursor.ReadVarInt(ignored) || !cursor.ReadVarInt(ignored) ||
        !cursor.ReadVarInt(rangeCount) || !cursor.ReadVarInt(ignored)) {
        return false;
    }

    if (rangeCount > cursor.remaining() / 2U) {
        return false;
    }
    for (std::uint64_t i = 0; i < rangeCount; ++i) {
        if (!cursor.ReadVarInt(ignored) || !cursor.ReadVarInt(ignored)) {
            return false;
        }
    }

    if (hasEcnCounts) {
        return cursor.ReadVarInt(ignored) && cursor.ReadVarInt(ignored) &&
               cursor.ReadVarInt(ignored);
    }
    return true;
}

bool AddCryptoFrames(Bytes plaintext, CryptoReassembler& reassembler) {
    Cursor cursor(plaintext);
    while (cursor.remaining() != 0) {
        std::uint64_t frameType = 0;
        if (!cursor.ReadVarInt(frameType)) {
            return false;
        }

        switch (frameType) {
            case 0x00:  // PADDING, заполнение
            case 0x01:  // PING, проверка доступности
                break;
            case 0x02:  // ACK, подтверждение
            case 0x03:  // ACK_ECN, подтверждение с ECN
                if (!SkipAckFrame(cursor, frameType == 0x03)) {
                    return false;
                }
                break;
            case 0x06: {  // CRYPTO, криптографические данные
                std::uint64_t offset = 0;
                std::uint64_t length = 0;
                Bytes data;
                if (!cursor.ReadVarInt(offset) || !cursor.ReadVarInt(length) ||
                    !cursor.Take(length, data) || !reassembler.Add(offset, data)) {
                    return false;
                }
                break;
            }
            case 0x1c: {  // CONNECTION_CLOSE, закрытие транспорта
                std::uint64_t ignored = 0;
                std::uint64_t reasonLength = 0;
                if (!cursor.ReadVarInt(ignored) || !cursor.ReadVarInt(ignored) ||
                    !cursor.ReadVarInt(reasonLength) || !cursor.Skip(reasonLength)) {
                    return false;
                }
                break;
            }
            default:
                // Другие типы фреймов в пакете Initial недопустимы.
                return false;
        }
    }
    return true;
}

enum class ClientHelloStatus {
    NeedMoreData,
    FoundSni,
    NoSni,
    Invalid,
};

struct ClientHelloResult {
    ClientHelloStatus status;
    std::string sni;
};

[[nodiscard]] bool IsValidSniByte(std::uint8_t value) {
    return value > 0x20U && value < 0x7fU;
}

[[nodiscard]] ClientHelloResult ParseClientHello(Bytes cryptoData) {
    constexpr std::size_t kHandshakeHeaderLength = 4;
    if (cryptoData.size < kHandshakeHeaderLength) {
        return {ClientHelloStatus::NeedMoreData, {}};
    }
    if (cryptoData.data[0] != 0x01) {
        return {ClientHelloStatus::Invalid, {}};
    }

    const std::size_t bodyLength = ReadBe24(cryptoData.data + 1);
    if (bodyLength > kMaximumCryptoStreamSize - kHandshakeHeaderLength) {
        return {ClientHelloStatus::Invalid, {}};
    }
    if (bodyLength > cryptoData.size - kHandshakeHeaderLength) {
        return {ClientHelloStatus::NeedMoreData, {}};
    }

    const Bytes body{cryptoData.data + kHandshakeHeaderLength, bodyLength};
    Cursor cursor(body);
    if (!cursor.Skip(2 + 32)) {  // legacy_version и random
        return {ClientHelloStatus::Invalid, {}};
    }

    std::uint8_t vectorLength8 = 0;
    if (!cursor.ReadU8(vectorLength8) || !cursor.Skip(vectorLength8)) {
        return {ClientHelloStatus::Invalid, {}};
    }

    std::uint16_t vectorLength16 = 0;
    if (!cursor.ReadU16(vectorLength16) || vectorLength16 == 0 ||
        (vectorLength16 & 1U) != 0 || !cursor.Skip(vectorLength16)) {
        return {ClientHelloStatus::Invalid, {}};
    }

    if (!cursor.ReadU8(vectorLength8) || vectorLength8 == 0 || !cursor.Skip(vectorLength8)) {
        return {ClientHelloStatus::Invalid, {}};
    }

    if (cursor.remaining() == 0) {
        return {ClientHelloStatus::NoSni, {}};
    }

    std::uint16_t extensionsLength = 0;
    if (!cursor.ReadU16(extensionsLength) || extensionsLength != cursor.remaining()) {
        return {ClientHelloStatus::Invalid, {}};
    }

    Bytes extensions;
    if (!cursor.Take(extensionsLength, extensions)) {
        return {ClientHelloStatus::Invalid, {}};
    }

    Cursor extensionCursor(extensions);
    while (extensionCursor.remaining() != 0) {
        std::uint16_t extensionType = 0;
        std::uint16_t extensionLength = 0;
        Bytes extensionData;
        if (!extensionCursor.ReadU16(extensionType) ||
            !extensionCursor.ReadU16(extensionLength) ||
            !extensionCursor.Take(extensionLength, extensionData)) {
            return {ClientHelloStatus::Invalid, {}};
        }

        if (extensionType != 0x0000) {
            continue;
        }

        Cursor serverNameCursor(extensionData);
        std::uint16_t serverNameListLength = 0;
        if (!serverNameCursor.ReadU16(serverNameListLength) ||
            serverNameListLength != serverNameCursor.remaining()) {
            return {ClientHelloStatus::Invalid, {}};
        }

        while (serverNameCursor.remaining() != 0) {
            std::uint8_t nameType = 0;
            std::uint16_t nameLength = 0;
            Bytes name;
            if (!serverNameCursor.ReadU8(nameType) ||
                !serverNameCursor.ReadU16(nameLength) || nameLength == 0 ||
                !serverNameCursor.Take(nameLength, name)) {
                return {ClientHelloStatus::Invalid, {}};
            }

            if (nameType == 0) {
                if (!std::all_of(name.data, name.data + name.size, IsValidSniByte)) {
                    return {ClientHelloStatus::Invalid, {}};
                }
                return {
                    ClientHelloStatus::FoundSni,
                    std::string(
                        reinterpret_cast<const char*>(name.data),
                        name.size),
                };
            }
        }
        return {ClientHelloStatus::NoSni, {}};
    }

    return {ClientHelloStatus::NoSni, {}};
}

[[nodiscard]] bool MatchesState(
    const QuicSniState& state,
    const UdpDatagram& datagram,
    const LongPacket& packet) {
    if (state.ipVersion != datagram.ipVersion ||
        state.addressLength != datagram.addressLength ||
        state.sourcePort != datagram.sourcePort ||
        state.destinationPort != datagram.destinationPort ||
        state.quicVersion != packet.version ||
        state.destinationConnectionIdLength != packet.destinationConnectionId.size) {
        return false;
    }

    return std::equal(
               state.sourceAddress.begin(),
               state.sourceAddress.begin() + static_cast<std::ptrdiff_t>(state.addressLength),
               datagram.sourceAddress.begin()) &&
           std::equal(
               state.destinationAddress.begin(),
               state.destinationAddress.begin() +
                   static_cast<std::ptrdiff_t>(state.addressLength),
               datagram.destinationAddress.begin()) &&
           std::equal(
               state.destinationConnectionId.begin(),
               state.destinationConnectionId.begin() +
                   static_cast<std::ptrdiff_t>(state.destinationConnectionIdLength),
               packet.destinationConnectionId.data);
}

void InitializeState(
    QuicSniState& state,
    const UdpDatagram& datagram,
    const LongPacket& packet,
    InitialCryptoContext&& initialCrypto) {
    state.ipVersion = datagram.ipVersion;
    state.sourceAddress = datagram.sourceAddress;
    state.destinationAddress = datagram.destinationAddress;
    state.addressLength = datagram.addressLength;
    state.sourcePort = datagram.sourcePort;
    state.destinationPort = datagram.destinationPort;
    state.quicVersion = packet.version;
    state.destinationConnectionIdLength = packet.destinationConnectionId.size;
    std::copy_n(
        packet.destinationConnectionId.data,
        state.destinationConnectionIdLength,
        state.destinationConnectionId.begin());
    state.initialCrypto = std::move(initialCrypto);
}

[[nodiscard]] QuicSniResult MakeTerminalResult(
    QuicSniState** state,
    QuicSniStatus status,
    std::string sni = {}) {
    FreeQuicSniState(state);
    return {status, std::move(sni)};
}

[[nodiscard]] QuicSniResult ExtractFromUdpDatagram(
    const UdpDatagram& udpDatagram,
    QuicSniState** stateHandle) {
    const Bytes datagram = udpDatagram.payload;
    // Состояние нового соединения остаётся на стеке, пока не нужен следующий пакет.
    std::optional<QuicSniState> pendingState;
    QuicSniState* state = *stateHandle;
    bool sawInitialPacket = false;
    std::size_t offset = 0;

    while (offset < datagram.size) {
        // После аутентифицированного Initial допускаем только нулевое
        // заполнение UDP-дейтаграммы за пределами QUIC Length.
        if (sawInitialPacket && datagram.data[offset] == 0 &&
            IsZeroFilled({datagram.data + offset, datagram.size - offset})) {
            break;
        }

        const auto packet = ParseLongPacket(datagram, offset);
        if (!packet || packet->end <= offset) {
            return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
        }

        if (packet->isInitial) {
            sawInitialPacket = true;
            if (state != nullptr && !MatchesState(*state, udpDatagram, *packet)) {
                return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
            }

            if (state == nullptr) {
                const auto parameters = GetVersionParameters(packet->version);
                if (!parameters) {
                    return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
                }

                auto initialCrypto =
                    CreateInitialCryptoContext(*parameters, packet->destinationConnectionId);
                if (!initialCrypto) {
                    return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
                }

                pendingState.emplace();
                InitializeState(
                    *pendingState,
                    udpDatagram,
                    *packet,
                    std::move(*initialCrypto));
                state = &*pendingState;
            }

            const std::uint64_t expectedPacketNumber = state->largestPacketNumber
                ? std::min(*state->largestPacketNumber + 1U, kMaxPacketNumber)
                : 0;
            const auto decrypted = DecryptInitialPacket(
                datagram,
                *packet,
                expectedPacketNumber,
                state->initialCrypto);
            if (!decrypted) {
                return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
            }

            if (!state->largestPacketNumber ||
                decrypted->packetNumber > *state->largestPacketNumber) {
                state->largestPacketNumber = decrypted->packetNumber;
            }

            CryptoReassembler reassembler(*state);
            if (!AddCryptoFrames(
                    {state->initialCrypto.plaintext.data(),
                     state->initialCrypto.plaintext.size()},
                    reassembler)) {
                return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
            }

            auto result = ParseClientHello(reassembler.contiguous());
            if (result.status == ClientHelloStatus::FoundSni) {
                return MakeTerminalResult(
                    stateHandle,
                    QuicSniStatus::SniFound,
                    std::move(result.sni));
            }
            if (result.status == ClientHelloStatus::NoSni) {
                return MakeTerminalResult(stateHandle, QuicSniStatus::SniNotPresent);
            }
            if (result.status == ClientHelloStatus::Invalid) {
                return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
            }
        }

        if (packet->consumesRestOfDatagram) {
            break;
        }
        offset = packet->end;
    }

    if (!sawInitialPacket) {
        return MakeTerminalResult(stateHandle, QuicSniStatus::InvalidPacket);
    }
    if (pendingState) {
        auto retainedState = std::make_unique<QuicSniState>(std::move(*pendingState));
        *stateHandle = retainedState.release();
    }
    return {QuicSniStatus::NeedMorePackets, {}};
}

}  // безымянное пространство имён

QuicSniResult ExtractQuicInitialSni(
    QuicSniState** state,
    const std::uint8_t* payload,
    std::uint32_t payloadSize) noexcept {
    if (state == nullptr) {
        return {QuicSniStatus::InvalidPacket, {}};
    }
    if (payload == nullptr || payloadSize == 0) {
        return MakeTerminalResult(state, QuicSniStatus::InvalidPacket);
    }

    try {
        const auto udpDatagram = ExtractUdpPayload({payload, payloadSize});
        if (!udpDatagram) {
            return MakeTerminalResult(state, QuicSniStatus::InvalidPacket);
        }
        return ExtractFromUdpDatagram(*udpDatagram, state);
    } catch (...) {
        return MakeTerminalResult(state, QuicSniStatus::InvalidPacket);
    }
}

}  // пространство имён quic_sni
