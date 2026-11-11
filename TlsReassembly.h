#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Тот же предел использует разборщик ClientHello: вложенные 16-битные векторы
// оставляют достаточно места для корректного сообщения, а повреждённая
// 24-битная длина не должна заставлять накапливать мегабайты данных.
inline constexpr size_t kMaxTlsClientHelloBytes = 132 * 1024;

enum class TlsClientHelloProgress : uint8_t {
    NotClientHello,
    Incomplete,
    Complete,
};

// Инкрементально проверяет границы TLS records и первого Handshake ClientHello.
// Каждый переданный байт рассматривается ровно один раз; уже обработанный префикс
// при поступлении следующего TCP-сегмента не обходится заново.
class TlsClientHelloInspector {
public:
    void Append(const uint8_t* data, size_t size);

    TlsClientHelloProgress progress() const { return progress_; }
    size_t processedBytes() const { return processedBytes_; }

private:
    enum class Phase : uint8_t {
        RecordHeader,
        RecordPayload,
    };

    void ConsumeHandshake(const uint8_t* data, size_t size);

    TlsClientHelloProgress progress_ = TlsClientHelloProgress::Incomplete;
    Phase phase_ = Phase::RecordHeader;
    uint8_t recordHeader_[5]{};
    size_t recordHeaderBytes_ = 0;
    size_t recordPayloadLeft_ = 0;
    uint8_t handshakeHeader_[4]{};
    size_t handshakeHeaderBytes_ = 0;
    size_t handshakeBytes_ = 0;
    size_t handshakeSize_ = 0;
    size_t processedBytes_ = 0;
};

// Одноразовая обёртка над тем же инкрементальным автоматом.
TlsClientHelloProgress InspectTlsClientHelloRecords(
    const uint8_t* data, size_t size);

// Непрерывный участок TCP payload одного соединения. TCP sequence защищает от
// повторной вставки ретрансмита и от склеивания частей, между которыми есть
// пропуск. Сложение sequence выполняется по модулю 2^32, как в самом TCP.
class TlsClientHelloBuffer {
public:
    TlsClientHelloBuffer(uint32_t sequence,
                         const uint8_t* data, size_t size);
    // Состояние уже обработало data: используется при первом неполном сегменте,
    // чтобы не проходить его второй раз после помещения в карту сборок.
    TlsClientHelloBuffer(uint32_t sequence, const uint8_t* data, size_t size,
                         TlsClientHelloInspector inspector);

    // true — нет пропуска и конфликта перекрытия; новый хвост добавлен, если он
    // есть. Полный повтор и пустые данные тоже допустимы. false — пропуск либо
    // несовпадение с уже сохранёнными байтами.
    bool Append(uint32_t sequence, const uint8_t* data, size_t size);

    TlsClientHelloProgress progress() const { return inspector_.progress(); }
    size_t processedBytes() const { return inspector_.processedBytes(); }
    std::vector<uint8_t> Take();

private:
    uint32_t firstSequence_ = 0;
    std::vector<uint8_t> data_;
    TlsClientHelloInspector inspector_;
};
