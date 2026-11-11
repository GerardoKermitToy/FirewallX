#include "TlsReassembly.h"

#include <algorithm>
#include <utility>

namespace {

size_t Be16(const uint8_t* data) {
    return (static_cast<size_t>(data[0]) << 8) |
            static_cast<size_t>(data[1]);
}

size_t Be24(const uint8_t* data) {
    return (static_cast<size_t>(data[0]) << 16) |
           (static_cast<size_t>(data[1]) << 8) |
            static_cast<size_t>(data[2]);
}

} // namespace

void TlsClientHelloInspector::ConsumeHandshake(
    const uint8_t* data, size_t size) {
    constexpr size_t kHandshakeHeaderBytes = 4;
    constexpr uint8_t kClientHello = 1;

    if (handshakeHeaderBytes_ < kHandshakeHeaderBytes) {
        const size_t part = std::min(
            kHandshakeHeaderBytes - handshakeHeaderBytes_, size);
        std::copy_n(data, part, handshakeHeader_ + handshakeHeaderBytes_);
        handshakeHeaderBytes_ += part;
        handshakeBytes_ += part;
        data += part;
        size -= part;

        if (handshakeHeaderBytes_ >= 1 && handshakeHeader_[0] != kClientHello) {
            progress_ = TlsClientHelloProgress::NotClientHello;
            return;
        }
        if (handshakeHeaderBytes_ == kHandshakeHeaderBytes) {
            const size_t bodySize = Be24(handshakeHeader_ + 1);
            if (bodySize > kMaxTlsClientHelloBytes) {
                progress_ = TlsClientHelloProgress::NotClientHello;
                return;
            }
            handshakeSize_ = kHandshakeHeaderBytes + bodySize;
        }
    }

    if (handshakeSize_ && handshakeBytes_ < handshakeSize_) {
        const size_t part = std::min(
            handshakeSize_ - handshakeBytes_, size);
        handshakeBytes_ += part;
    }
}

void TlsClientHelloInspector::Append(const uint8_t* data, size_t size) {
    constexpr size_t kRecordHeaderBytes = 5;
    constexpr uint8_t kHandshakeRecord = 22;

    if (!data || size == 0 ||
        progress_ != TlsClientHelloProgress::Incomplete)
        return;

    while (size && progress_ == TlsClientHelloProgress::Incomplete) {
        if (phase_ == Phase::RecordHeader) {
            const size_t part = std::min(
                kRecordHeaderBytes - recordHeaderBytes_, size);
            std::copy_n(data, part, recordHeader_ + recordHeaderBytes_);
            data += part;
            size -= part;
            processedBytes_ += part;
            recordHeaderBytes_ += part;

            if (recordHeaderBytes_ >= 1 &&
                recordHeader_[0] != kHandshakeRecord) {
                progress_ = TlsClientHelloProgress::NotClientHello;
                return;
            }
            if (recordHeaderBytes_ >= 2 && recordHeader_[1] != 3) {
                progress_ = TlsClientHelloProgress::NotClientHello;
                return;
            }
            if (recordHeaderBytes_ < kRecordHeaderBytes) return;

            recordPayloadLeft_ = Be16(recordHeader_ + 3);
            recordHeaderBytes_ = 0;
            phase_ = Phase::RecordPayload;
        }

        if (phase_ == Phase::RecordPayload) {
            const size_t part = std::min(recordPayloadLeft_, size);
            ConsumeHandshake(data, part);
            if (progress_ == TlsClientHelloProgress::NotClientHello) return;
            data += part;
            size -= part;
            processedBytes_ += part;
            recordPayloadLeft_ -= part;

            if (recordPayloadLeft_ != 0) return;

            phase_ = Phase::RecordHeader;
            if (handshakeSize_ && handshakeBytes_ >= handshakeSize_) {
                progress_ = TlsClientHelloProgress::Complete;
                return;
            }
            // Нулевой record не потребляет данные после заголовка. Цикл
            // продолжает разбор со следующего заголовка, который уже в data.
        }
    }
}

TlsClientHelloProgress InspectTlsClientHelloRecords(
    const uint8_t* data, size_t size) {
    if (!data || size == 0)
        return TlsClientHelloProgress::NotClientHello;

    TlsClientHelloInspector inspector;
    inspector.Append(data, size);
    return inspector.progress();
}

TlsClientHelloBuffer::TlsClientHelloBuffer(
    uint32_t sequence, const uint8_t* data, size_t size)
    : firstSequence_(sequence) {
    if (!data || size == 0) return;
    data_.assign(data, data + size);
    inspector_.Append(data_.data(), data_.size());
}

TlsClientHelloBuffer::TlsClientHelloBuffer(
    uint32_t sequence, const uint8_t* data, size_t size,
    TlsClientHelloInspector inspector)
    : firstSequence_(sequence), inspector_(std::move(inspector)) {
    if (data && size) data_.assign(data, data + size);
}

bool TlsClientHelloBuffer::Append(
    uint32_t sequence, const uint8_t* data, size_t size) {
    if (!data || size == 0) return true;

    // Беззнаковое вычитание намеренно: оно корректно переживает переход TCP
    // sequence через UINT32_MAX. Размер ClientHello намного меньше 2^31.
    const uint32_t relative32 = sequence - firstSequence_;
    if (relative32 > data_.size()) return false;
    const size_t offset = static_cast<size_t>(relative32);

    const size_t overlap = std::min(size, data_.size() - offset);
    if (!std::equal(data, data + overlap, data_.data() + offset))
        return false;

    if (overlap < size) {
        const size_t oldSize = data_.size();
        data_.insert(data_.end(), data + overlap, data + size);
        inspector_.Append(data_.data() + oldSize, data_.size() - oldSize);
    }
    return true;
}

std::vector<uint8_t> TlsClientHelloBuffer::Take() {
    return std::move(data_);
}
