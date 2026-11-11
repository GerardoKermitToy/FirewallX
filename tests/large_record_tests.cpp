#include "PortmasterKextClient.hpp"
#include "duplex_pipe/pipe_transport.h"

#include <algorithm>
#include <atomic>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace FirewallX { Mode g_runMode = Mode::Desktop; }

namespace pmkext {
struct KextClientTestAccess {
    static void Feed(KextClient& client, const uint8_t* bytes, size_t size, size_t fragment = 65536) {
        while (size) {
            if (!client.ensureWritable(1)) throw std::runtime_error("driver buffer allocation failed");
            const size_t take = (std::min)({size, fragment, client.buffer_.Capacity() - client.tail_});
            std::memcpy(client.buffer_.Data() + client.tail_, bytes, take);
            client.tail_ += take;
            client.dispatchAvailable();
            bytes += take;
            size -= take;
        }
    }
    static size_t Capacity(const KextClient& client) { return client.buffer_.Capacity(); }
    static size_t Pending(const KextClient& client) { return client.tail_ - client.head_; }
    static const void* Data(const KextClient& client) { return client.buffer_.Data(); }
};
}

namespace pipe_transport {
struct RawMessageTestAccess {
    static size_t Capacity(const RawMessage& message) { return message.buffer_.Capacity(); }
    static const void* Storage(const RawMessage& message) { return message.buffer_.Data(); }
    static void Clear(RawMessage& message) { message.Clear(); }
};
}

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

bool Released(const void* pointer) {
    MEMORY_BASIC_INFORMATION info{};
    return VirtualQuery(pointer, &info, sizeof(info)) == sizeof(info) && info.State == MEM_FREE;
}

void Store(uint8_t*& destination, uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) {
        *destination++ = static_cast<uint8_t>(value);
        value >>= 8;
    }
}

uint8_t Address(uint32_t tuple, size_t byte, bool remote) {
    return static_cast<uint8_t>((tuple >> (8 * (byte % 4))) ^ byte ^ (remote ? 0xa0 : 0x20));
}

std::vector<uint8_t> Record(bool ipv6, uint8_t protocol, uint32_t count) {
    const size_t addr = ipv6 ? 16 : 4;
    const size_t payload = 5 + size_t(count) * (addr * 2 + 20);
    Check(payload <= MAXDWORD, "test payload does not fit driver wire format");
    std::vector<uint8_t> wire(5 + payload);
    auto* out = wire.data();
    Store(out, ipv6 ? 6 : 5, 1);
    Store(out, payload, 4);
    Store(out, protocol, 1);
    Store(out, count, 4);
    for (uint32_t i = 0; i < count; ++i) {
        for (size_t byte = 0; byte < addr; ++byte) *out++ = Address(i, byte, false);
        Store(out, static_cast<uint16_t>(1000 + i), 2);
        for (size_t byte = 0; byte < addr; ++byte) *out++ = Address(i, byte, true);
        Store(out, static_cast<uint16_t>(60000 - i), 2);
        Store(out, 0x1234567800000000ULL + i, 8);
        Store(out, 0xabcdef0100000000ULL + 7ULL * i, 8);
    }
    Check(out == wire.data() + wire.size(), "test encoder length");
    return wire;
}

struct Observation {
    uint32_t count;
    uint8_t protocol;
    std::atomic<unsigned> calls{0};
    std::atomic<bool> valid{true};
} *observed = nullptr;

template <class Value>
void Observe(uint8_t protocol, const Value* values, uint32_t count) noexcept {
    bool valid = protocol == observed->protocol && count == observed->count;
    const size_t addr = sizeof(values[0].local_ip);
    for (uint32_t i = 0; i < count; ++i) {
        const auto& entry = values[i];
        for (size_t byte = 0; byte < addr; ++byte) {
            valid &= entry.local_ip[byte] == Address(i, byte, false);
            valid &= entry.remote_ip[byte] == Address(i, byte, true);
        }
        valid &= entry.local_port == static_cast<uint16_t>(1000 + i);
        valid &= entry.remote_port == static_cast<uint16_t>(60000 - i);
        valid &= entry.transmitted_bytes == 0x1234567800000000ULL + i;
        valid &= entry.received_bytes == 0xabcdef0100000000ULL + 7ULL * i;
    }
    if (!valid) observed->valid.store(false);
    observed->calls.fetch_add(1);
}

void Callbacks(pmkext::KextClient& client) {
    client.onBandwidthStatsV4 = Observe<pmkext::BandwidthValueV4>;
    client.onBandwidthStatsV6 = Observe<pmkext::BandwidthValueV6>;
}

pipe_transport::UniqueHandle Server(const std::wstring& name) {
    pipe_transport::UniqueHandle pipe(CreateNamedPipeW(name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, pipe_transport::kPipeBufferSize, pipe_transport::kPipeBufferSize, 0, nullptr));
    Check(pipe.IsValid(), "create test pipe");
    return pipe;
}

pipe_transport::UniqueHandle Client(const std::wstring& name) {
    pipe_transport::UniqueHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    Check(pipe.IsValid(), "open test pipe");
    DWORD mode = PIPE_READMODE_MESSAGE;
    Check(SetNamedPipeHandleState(pipe.Get(), &mode, nullptr, nullptr) != FALSE, "pipe message mode");
    return pipe;
}

struct PipePair {
    static inline unsigned sequence = 0;
    std::wstring name = L"\\\\.\\pipe\\FirewallX.LargeRecordTest." +
        std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(++sequence);
    pipe_transport::Connection server{Server(name)};
    pipe_transport::Connection client{Client(name)};
    PipePair() {
        Check(pipe_transport::ConnectNamedPipeCancelable(server.Pipe(), server.CancelEvent()) == ERROR_SUCCESS,
              "connect test pipe");
    }
};

void SendAndRead(PipePair& pipes, const uint8_t* data, size_t size, pipe_transport::RawMessage& message) {
    DWORD sent = ERROR_IO_PENDING;
    std::thread writer([&] {
        sent = pipe_transport::WriteRaw(pipes.server, data, static_cast<unsigned long>(size), 15000);
    });
    const DWORD read = pipe_transport::ReadRaw(pipes.client, message, 15000);
    if (read != ERROR_SUCCESS) pipes.server.Cancel(read);
    writer.join();
    Check(sent == ERROR_SUCCESS && read == ERROR_SUCCESS, "large pipe transfer failed");
}

void TestRecord(bool ipv6, uint8_t protocol, uint32_t count) {
    const auto wire = Record(ipv6, protocol, count);
    Observation observation{count, protocol};
    observed = &observation;
    pmkext::KextClient driver;
    Callbacks(driver);
    // И заголовок, и payload приходят фрагментами; последний байт удерживаем.
    pmkext::KextClientTestAccess::Feed(driver, wire.data(), 1);
    pmkext::KextClientTestAccess::Feed(driver, wire.data() + 1, 2);
    pmkext::KextClientTestAccess::Feed(driver, wire.data() + 3, wire.size() - 4);
    Check(observation.calls == 0 && pmkext::KextClientTestAccess::Pending(driver) == wire.size() - 1,
          "partial driver record was lost or dispatched");
    const void* large = pmkext::KextClientTestAccess::Data(driver);
    const bool grew = wire.size() > 512 * 1024;
    if (grew) Check(pmkext::KextClientTestAccess::Capacity(driver) >= wire.size(), "driver capacity is too small");
    pmkext::KextClientTestAccess::Feed(driver, wire.data() + wire.size() - 1, 1);
    Check(observation.calls == 1 && observation.valid, "driver tuple or counter loss");
    Check(pmkext::KextClientTestAccess::Pending(driver) == 0 &&
          pmkext::KextClientTestAccess::Data(driver) == large, "driver discarded a reusable buffer");
    driver.close();
    if (grew) Check(Released(large), "closed driver retained large pages");

    PipePair pipes;
    pipe_transport::RawMessage message;
    SendAndRead(pipes, wire.data(), wire.size(), message);
    Check(message.Size() == wire.size() && std::memcmp(message.Data(), wire.data(), wire.size()) == 0,
          "raw pipe changed, truncated or framed the driver record");
    driver.dispatchOne(static_cast<pmkext::InfoType>(message.Data()[0]),
        message.Data() + 5, static_cast<uint32_t>(message.Size() - 5));
    Check(observation.calls == 2 && observation.valid, "pipe tuple or counter loss");
    const void* pipeLarge = message.Data();
    if (grew)
        Check(pipe_transport::RawMessageTestAccess::Capacity(message) >= wire.size(), "pipe capacity is too small");
    // Одно малое сообщение не освобождает крупный переиспользуемый буфер.
    // Граница следующего сообщения сохраняется независимо от размера буфера.
    const uint8_t following[] = {0, 3, 0, 0, 0, 3, 'o', 'k'};
    SendAndRead(pipes, following, sizeof(following), message);
    Check(message.Size() == sizeof(following) &&
          std::memcmp(message.Data(), following, sizeof(following)) == 0, "following message boundary");
    if (grew) {
        Check(message.Data() == pipeLarge, "one small pipe message discarded reusable storage");
        for (unsigned i = 1; i <= read_buffer::Buffer<512 * 1024>::kUnderusedRecordCount; ++i)
            SendAndRead(pipes, following, sizeof(following), message);
        Check(pipe_transport::RawMessageTestAccess::Capacity(message) == pipe_transport::kRawReadChunkSize,
              "sustained small pipe traffic retained peak capacity");
        Check(Released(pipeLarge), "pipe large pages were not returned to OS");
    }
    std::cout << "PASS IPv" << (ipv6 ? 6 : 4) << " protocol=" << unsigned(protocol)
              << " tuples=" << count << " bytes=" << wire.size() << '\n';
}

void TestBufferLifetime() {
    constexpr size_t baselineSize = 512 * 1024;
    static_assert(pipe_transport::kRawReadChunkSize == baselineSize);
    static_assert(pipe_transport::kPipeBufferSize == baselineSize);
    read_buffer::Buffer<baselineSize> buffer;
    Check(buffer.Reserve(baselineSize), "baseline allocation");
    auto* baseline = buffer.Data();
    baseline[0] = 42;
    for (const size_t size : {size_t{1024 * 1024}, size_t{33 * 1024 * 1024}, size_t{129 * 1024 * 1024}}) {
        Check(buffer.Reserve(size, 1) && buffer.Data()[0] == 42 && buffer.Capacity() >= size,
              "large buffer preservation");
        const void* large = buffer.Data();
        Check(buffer.Compact(1) && buffer.Data() == baseline && buffer.Data()[0] == 42 &&
              buffer.Capacity() == baselineSize && Released(large), "large buffer shrink and page release");
    }
    buffer.Reset();
    Check(buffer.Data() == nullptr && buffer.Capacity() == 0, "buffer reset");
    static_assert(size_t{MAXDWORD} + 5 > MAXDWORD, "64-bit record-length arithmetic is required");
}

void TestAdaptiveBuffer() {
    using Buffer = read_buffer::Buffer<512 * 1024>;
    Buffer buffer;
    Check(buffer.Reserve(512 * 1024), "adaptive baseline allocation");
    auto* const baseline = buffer.Data();
    constexpr size_t largeSize = 8 * 1024 * 1024;
    constexpr size_t mediumSize = 1024 * 1024;
    Check(buffer.Reserve(largeSize), "adaptive large allocation");
    auto* const large = buffer.Data();
    const size_t largeCapacity = buffer.Capacity();
    Check(largeCapacity > largeSize && largeCapacity <= largeSize + largeSize / 4 + 65536,
          "growth headroom is missing or excessive");
    large[0] = 42;
    for (unsigned i = 0; i < 32; ++i) {
        const size_t size = largeSize + (i % 16) * 4096;
        Check(buffer.Reserve(size, 1) && buffer.Data() == large, "nearby large sizes reallocated");
        buffer.RecordCompleted(size);
        buffer.RecordCompleted(1);
        Check(buffer.Trim(1) && buffer.Data() == large && buffer.Capacity() == largeCapacity,
              "alternating small and large records released storage");
    }
    buffer.RecordCompleted(largeSize);
    for (unsigned i = 1; i < Buffer::kUnderusedRecordCount; ++i) {
        buffer.RecordCompleted(mediumSize);
        Check(!buffer.NeedsTrim(), "buffer trimmed before hysteresis threshold");
    }
    buffer.RecordCompleted(mediumSize);
    Check(buffer.NeedsTrim(), "sustained underuse did not request trimming");
    Check(buffer.Trim(1, largeSize) && buffer.Capacity() == largeCapacity,
          "incomplete large record was not protected");
    Check(buffer.Trim(1) && buffer.Data() == large && buffer.Data()[0] == 42 &&
          buffer.Capacity() >= mediumSize && buffer.Capacity() < largeCapacity,
          "medium demand did not decommit unused tail in place");
    MEMORY_BASIC_INFORMATION info{};
    Check(VirtualQuery(buffer.Data() + buffer.Capacity(), &info, sizeof(info)) == sizeof(info) &&
          info.State == MEM_RESERVE, "trimmed large pages remain committed");
    Check(buffer.Reserve(largeSize, 1) && buffer.Data() == large && buffer.Data()[0] == 42,
          "recommitting reserved pages reallocated or corrupted data");
    for (unsigned i = 0; i < Buffer::kUnderusedRecordCount; ++i) buffer.RecordCompleted(1);
    Check(buffer.Trim(1) && buffer.Data() == baseline && baseline[0] == 42 &&
          buffer.Capacity() == 512 * 1024 && Released(large), "small demand retained large pages");
    Check(buffer.Reserve(largeSize), "adaptive regrowth");
    const void* const regrown = buffer.Data();
    buffer.Reset();
    Check(Released(regrown) && buffer.Data() == nullptr && buffer.Capacity() == 0,
          "reset retained adaptive storage");
}

void TestDriverReuse() {
    constexpr uint32_t count = (4 * 1024 * 1024) / 28;
    const auto large = Record(false, 6, count);
    const auto smallRecord = Record(false, 6, 1);
    Observation observation{count, 6};
    observed = &observation;
    pmkext::KextClient driver;
    Callbacks(driver);
    auto feed = [&](const std::vector<uint8_t>& wire, uint32_t tuples) {
        observation.count = tuples;
        const unsigned before = observation.calls.load();
        pmkext::KextClientTestAccess::Feed(driver, wire.data(), wire.size());
        Check(observation.calls == before + 1 && observation.valid, "reused driver record corruption");
    };
    feed(large, count);
    const void* const storage = pmkext::KextClientTestAccess::Data(driver);
    const size_t capacity = pmkext::KextClientTestAccess::Capacity(driver);
    for (unsigned i = 0; i < 8; ++i) {
        feed(smallRecord, 1);
        feed(large, count);
        Check(pmkext::KextClientTestAccess::Data(driver) == storage &&
              pmkext::KextClientTestAccess::Capacity(driver) == capacity, "driver did not reuse large storage");
    }
    for (unsigned i = 1; i < read_buffer::Buffer<512 * 1024>::kUnderusedRecordCount; ++i) feed(smallRecord, 1);
    auto partial = smallRecord;
    partial.insert(partial.end(), large.begin(), large.begin() + 13);
    observation.count = 1;
    const unsigned beforePartial = observation.calls.load();
    pmkext::KextClientTestAccess::Feed(driver, partial.data(), partial.size(), partial.size());
    Check(observation.calls == beforePartial + 1 && observation.valid &&
          pmkext::KextClientTestAccess::Pending(driver) == 13 &&
          pmkext::KextClientTestAccess::Data(driver) == storage &&
          pmkext::KextClientTestAccess::Capacity(driver) == capacity,
          "partial large record was trimmed or counted as small fragments");
    observation.count = count;
    pmkext::KextClientTestAccess::Feed(driver, large.data() + 13, large.size() - 13, 777);
    Check(observation.calls == beforePartial + 2 && observation.valid &&
          pmkext::KextClientTestAccess::Data(driver) == storage, "fragmented reused driver record failed");
    for (unsigned i = 0; i < read_buffer::Buffer<512 * 1024>::kUnderusedRecordCount; ++i) feed(smallRecord, 1);
    Check(pmkext::KextClientTestAccess::Capacity(driver) == 512 * 1024 && Released(storage),
          "sustained small driver traffic retained peak capacity");

    feed(large, count);
    const void* const nextStorage = pmkext::KextClientTestAccess::Data(driver);
    for (unsigned i = 1; i < read_buffer::Buffer<512 * 1024>::kUnderusedRecordCount; ++i) feed(smallRecord, 1);
    partial = smallRecord;
    partial.insert(partial.end(), smallRecord.begin(), smallRecord.begin() + 3);
    observation.count = 1;
    const unsigned beforeHeader = observation.calls.load();
    pmkext::KextClientTestAccess::Feed(driver, partial.data(), partial.size(), partial.size());
    Check(observation.calls == beforeHeader + 1 && observation.valid &&
          pmkext::KextClientTestAccess::Pending(driver) == 3 &&
          pmkext::KextClientTestAccess::Capacity(driver) == 512 * 1024 && Released(nextStorage),
          "trim lost partial next header");
    pmkext::KextClientTestAccess::Feed(driver, smallRecord.data() + 3, smallRecord.size() - 3);
    Check(observation.calls == beforeHeader + 2 && observation.valid &&
          pmkext::KextClientTestAccess::Pending(driver) == 0, "trimmed partial header corrupted next record");
}

void TestPipeReuse() {
    PipePair pipes;
    pipe_transport::RawMessage message;
    constexpr size_t size = 4 * 1024 * 1024;
    const std::vector<uint8_t> payload(size + 65536, 0xad);
    SendAndRead(pipes, payload.data(), size, message);
    const void* const storage = message.Data();
    const size_t capacity = pipe_transport::RawMessageTestAccess::Capacity(message);
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t smallRecord = 7;
        SendAndRead(pipes, &smallRecord, 1, message);
        Check(message.Data() == storage && message.Size() == 1 && message.Data()[0] == smallRecord,
              "one small pipe message released storage");
        const size_t nextSize = size + i * 4096;
        SendAndRead(pipes, payload.data(), nextSize, message);
        Check(message.Data() == storage && message.Size() == nextSize &&
              pipe_transport::RawMessageTestAccess::Capacity(message) == capacity &&
              std::memcmp(message.Data(), payload.data(), nextSize) == 0,
              "nearby large pipe sizes reallocated or corrupted payload");
    }
    const uint8_t smallRecord = 7;
    for (unsigned i = 0; i < read_buffer::Buffer<512 * 1024>::kUnderusedRecordCount; ++i)
        SendAndRead(pipes, &smallRecord, 1, message);
    Check(message.Data() == storage, "pipe freed payload before its callback boundary");
    SendAndRead(pipes, &smallRecord, 1, message);
    Check(pipe_transport::RawMessageTestAccess::Capacity(message) == 512 * 1024 && Released(storage),
          "quiet pipe traffic did not release storage");
}

void TestStreamBoundaries() {
    pmkext::KextClient client;
    const uint8_t extreme[] = {5, 0xff, 0xff, 0xff, 0xff};
    pmkext::KextClientTestAccess::Feed(client, extreme, sizeof(extreme));
    Check(pmkext::KextClientTestAccess::Pending(client) == sizeof(extreme),
          "maximum wire length wrapped or was discarded");

    pmkext::KextClient batched;
    Observation observation{1, 6};
    observed = &observation;
    Callbacks(batched);
    auto first = Record(false, 6, 1);
    const auto second = Record(true, 6, 1);
    first.insert(first.end(), second.begin(), second.end());
    first.insert(first.end(), second.begin(), second.begin() + 3);
    pmkext::KextClientTestAccess::Feed(batched, first.data(), first.size(), first.size());
    Check(observation.calls == 2 && observation.valid &&
          pmkext::KextClientTestAccess::Pending(batched) == 3, "coalesced driver records");
    pmkext::KextClientTestAccess::Feed(batched, second.data() + 3, second.size() - 3, 1);
    Check(observation.calls == 3 && observation.valid &&
          pmkext::KextClientTestAccess::Pending(batched) == 0, "partial next header");
}

void TestCancelledWrites() {
    const std::vector<uint8_t> data(4 * 1024 * 1024, 0xab);
    {
        PipePair pipes;
        std::atomic<DWORD> sent{ERROR_IO_PENDING};
        std::thread writer([&] { sent = pipe_transport::WriteRaw(pipes.server, data.data(),
            static_cast<unsigned long>(data.size()), INFINITE); });
        Sleep(30);
        const bool pending = sent == ERROR_IO_PENDING;
        pipes.server.Cancel(ERROR_OPERATION_ABORTED);
        writer.join();
        Check(pending && sent == ERROR_OPERATION_ABORTED, "pending write cancellation was not reaped");
    }
    {
        PipePair pipes;
        Check(pipe_transport::WriteRaw(pipes.server, data.data(),
            static_cast<unsigned long>(data.size()), 30) == ERROR_TIMEOUT,
            "pending write timeout was not reaped");
        Check(!pipes.server.IsActive(), "timed-out connection remains active");
    }
}

struct ForwardContext { pipe_transport::Connection* pipe; unsigned calls = 0; DWORD status = ERROR_SUCCESS; };
bool Forward(void* context, const uint8_t* data, uint32_t size) noexcept {
    auto& state = *static_cast<ForwardContext*>(context);
    ++state.calls;
    state.status = pipe_transport::WriteRaw(*state.pipe, data, size, 15000);
    return state.status == ERROR_SUCCESS;
}

void TestForwarding() {
    const auto wire = Record(true, 17, (65 * 1024 * 1024) / 52);
    Observation observation{(65 * 1024 * 1024) / 52, 17};
    observed = &observation;
    PipePair pipes;
    pmkext::KextClient driver;
    Callbacks(driver);
    ForwardContext context{&pipes.server};
    driver.onRawRecord = Forward;
    driver.onRawRecordContext = &context;
    std::exception_ptr failure;
    std::thread writer([&] {
        try { pmkext::KextClientTestAccess::Feed(driver, wire.data(), wire.size()); }
        catch (...) { failure = std::current_exception(); pipes.client.Cancel(ERROR_OPERATION_ABORTED); }
    });
    pipe_transport::RawMessage message;
    const DWORD status = pipe_transport::ReadRaw(pipes.client, message, 15000);
    if (status != ERROR_SUCCESS) pipes.server.Cancel(status);
    writer.join();
    if (failure) std::rethrow_exception(failure);
    Check(status == ERROR_SUCCESS && context.status == ERROR_SUCCESS && context.calls == 1,
          "driver-to-pipe forwarding failed");
    Check(observation.calls == 0 && message.Size() == wire.size(), "forwarded record also dispatched locally");
    driver.dispatchOne(pmkext::InfoType::BandwidthStatsV6, message.Data() + 5,
                       static_cast<uint32_t>(message.Size() - 5));
    Check(observation.calls == 1 && observation.valid, "forwarded snapshot detail loss");
    const void* const forwardedBuffer = message.Data();
    pipe_transport::RawMessageTestAccess::Clear(message);
    Check(message.Empty() && pipe_transport::RawMessageTestAccess::Storage(message) == forwardedBuffer,
          "clearing one forwarded record discarded reusable storage");

    // Неуспешная отправка возвращает весь снимок локальному callback без потерь.
    pipes.server.Cancel(ERROR_OPERATION_ABORTED);
    pmkext::KextClientTestAccess::Feed(driver, wire.data(), wire.size());
    Check(observation.calls == 2 && observation.valid && context.calls == 2,
          "failed forwarding lost local fallback");
}
}

int main() {
    try {
        TestBufferLifetime();
        TestAdaptiveBuffer();
        TestDriverReuse();
        TestPipeReuse();
        TestStreamBoundaries();
        TestCancelledWrites();
        for (const bool ipv6 : {false, true}) {
            const size_t entry = ipv6 ? 52 : 28;
            for (const uint8_t protocol : {uint8_t{6}, uint8_t{17}}) {
                for (const uint32_t count : {0u, 1u, 13u}) TestRecord(ipv6, protocol, count);
                const auto lastBaseline = static_cast<uint32_t>((512 * 1024 - 10) / entry);
                TestRecord(ipv6, protocol, lastBaseline);
                TestRecord(ipv6, protocol, lastBaseline + 1);
                const auto firstTen = static_cast<uint32_t>((10 * 1024 * 1024 - 5) / entry + 1);
                TestRecord(ipv6, protocol, firstTen - 1);
                TestRecord(ipv6, protocol, firstTen);
                for (const size_t size : {size_t{16 * 1024 * 1024}, size_t{64 * 1024 * 1024}, size_t{128 * 1024 * 1024}})
                    TestRecord(ipv6, protocol, static_cast<uint32_t>((size - 10) / entry + 1));
            }
        }
        TestForwarding();
        std::cout << "PASS: unbounded records, all tuples, raw pipe, cancellation and released memory\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
