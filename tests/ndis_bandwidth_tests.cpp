// Только wire-кодек и память: устройство, служба и привязки не используются.
#include "FirewallXNdisFilter.hpp"
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace {
using Client = firewallxndisfilter::Client;
using Bytes = std::vector<uint8_t>;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

template <class T>
void Put(Bytes& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

Bytes BandwidthRecord(bool ipv6, uint32_t index, uint32_t count) {
    const size_t address = ipv6 ? 16 : 4, entry = 2 * address + 20;
    Bytes record(14 + entry * count);
    record[0] = ipv6 ? 6 : 5;
    Put(record, 1, static_cast<uint32_t>(record.size() - 5));
    record[5] = 17;
    Put(record, 6, index);
    Put(record, 10, count);
    for (uint32_t i = 0; i < count; ++i) {
        const size_t offset = 14 + entry * i;
        record[offset] = 10;
        Put(record, offset + address, static_cast<uint16_t>(30000 + i));
        record[offset + address + 2] = 198;
        Put(record, offset + 2 * address + 2, uint16_t{53});
        Put(record, offset + 2 * address + 4, uint64_t{0x100000000ull + i});
        Put(record, offset + 2 * address + 12, uint64_t{0x200000000ull + i});
    }
    return record;
}

struct Capture {
    bool ipv6 = false;
    uint32_t count = 0;
    const void* expectedEntries = nullptr;
    std::vector<uint32_t> indices;
};

template <class Entry>
void CaptureBandwidth(void* context, uint8_t protocol, uint32_t index,
                      const Entry* entries, uint32_t count) {
    auto& capture = *static_cast<Capture*>(context);
    Check(protocol == 17 && count == capture.count &&
              (sizeof(entries->local_ip) == 16) == capture.ipv6,
          "wrong grouped bandwidth header");
    Check(!capture.expectedEntries || capture.expectedEntries == entries,
          "bandwidth callback did not borrow the packed array");
    for (uint32_t i = 0; i < count; ++i) {
        const auto& entry = entries[i];
        Check(entry.local_ip[0] == 10 && entry.remote_ip[0] == 198 &&
                  entry.local_port == static_cast<uint16_t>(30000 + i) && entry.remote_port == 53 &&
                  entry.transmitted_bytes == 0x100000000ull + i &&
                  entry.received_bytes == 0x200000000ull + i,
              "bandwidth entries or 64-bit counters were corrupted");
    }
    capture.indices.push_back(index);
}

void Feed(Client::Stream& stream, const Bytes& record, size_t chunk, const Client::Callbacks& callbacks) {
    for (size_t offset = 0; offset < record.size();) {
        auto buffer = stream.Buffer();
        Check(!buffer.empty(), "bandwidth stream ran out of writable storage");
        const size_t count = (std::min)({chunk, buffer.size(), record.size() - offset});
        std::memcpy(buffer.data(), record.data() + offset, count);
        Check(stream.Commit(count, callbacks) == ERROR_SUCCESS, "bandwidth stream rejected a group");
        offset += count;
    }
}

void TestBandwidthRecords() {
    for (const bool ipv6 : {false, true}) {
        Capture capture;
        capture.ipv6 = ipv6;
        Client::Callbacks callbacks;
        callbacks.context = &capture;
        callbacks.on_bandwidth_v4 = CaptureBandwidth<Client::BandwidthV4>;
        callbacks.on_bandwidth_v6 = CaptureBandwidth<Client::BandwidthV6>;
        for (const uint32_t count : {2u, 40000u}) {
            capture.count = count;
            const auto first = BandwidthRecord(ipv6, 101, count);
            const auto second = BandwidthRecord(ipv6, 0x87654321u, count);
            Check(count != 40000 || first.size() > Client::MaxRecordSize,
                  "large bandwidth fixture does not exceed the connection bound");
            capture.indices.clear();
            capture.expectedEntries = first.data() + 14;
            Check(Client::DispatchRecord(first, callbacks) == ERROR_SUCCESS,
                  "grouped bandwidth record was rejected");
            Check(capture.indices == std::vector<uint32_t>{101}, "group index was decoded at the wrong offset");
            capture.expectedEntries = nullptr;
            Bytes combined = first;
            combined.insert(combined.end(), second.begin(), second.end());
            combined.insert(combined.end(), first.begin(), first.end());
            for (const size_t chunk : {size_t{16}, size_t{4093}, size_t{65536}}) {
                capture.indices.clear();
                Client::Stream stream;
                Feed(stream, combined, chunk, callbacks);
                Check(stream.PendingBytes() == 0 &&
                          capture.indices == std::vector<uint32_t>{101, 0x87654321u, 101},
                      "fragmented or coalesced bandwidth groups lost their index or entries");
            }
        }
        const auto valid = BandwidthRecord(ipv6, 101, 2);
        auto invalid = valid;
        Put(invalid, 10, UINT32_MAX);
        Check(Client::DispatchRecord(invalid, callbacks) == ERROR_INVALID_DATA, "invalid group count accepted");
        invalid = valid;
        invalid.erase(invalid.begin() + 6, invalid.begin() + 10);
        Put(invalid, 1, static_cast<uint32_t>(invalid.size() - 5));
        Check(Client::DispatchRecord(invalid, callbacks) == ERROR_INVALID_DATA, "old bandwidth layout accepted");
        invalid = valid;
        invalid.pop_back();
        Put(invalid, 1, static_cast<uint32_t>(invalid.size() - 5));
        Check(Client::DispatchRecord(invalid, callbacks) == ERROR_INVALID_DATA, "partial bandwidth entry accepted");
        const size_t calls = capture.indices.size();
        Check(Client::DispatchRecord(BandwidthRecord(ipv6, 101, 0), callbacks) == ERROR_SUCCESS &&
                  capture.indices.size() == calls, "empty bandwidth group called the callback");
    }
}

void TestRecordBounds() {
    for (const bool ipv6 : {false, true}) {
        const size_t prefix = ipv6 ? 60 : 36;
        Bytes record(prefix + Client::MaxPayloadSize + 1);
        record[0] = ipv6 ? 2 : 1;
        Put(record, 1, static_cast<uint32_t>(record.size() - 5));
        record[prefix - 5] = 3;
        Put(record, prefix - 4, static_cast<uint32_t>(Client::MaxPayloadSize + 1));
        Check(Client::DispatchRecord(record, {}) == ERROR_INVALID_DATA, "connection payload bound changed");
        Client::Stream stream;
        std::memcpy(stream.Buffer().data(), record.data(), 5);
        Check(stream.Commit(5, {}) == ERROR_INVALID_DATA && stream.Buffer().empty(),
              "oversized connection header did not invalidate the stream");
        stream.Reset();
        Check(!stream.Buffer().empty(), "stream did not reset after an invalid header");
    }
    Bytes log(513);
    Put(log, 1, uint32_t{508});
    log[5] = 3;
    Check(Client::DispatchRecord(log, {}) == ERROR_INVALID_DATA, "log size bound changed");
}
} // namespace

int main() {
    try {
        TestBandwidthRecords();
        TestRecordBounds();
        std::puts("PASS: interface-grouped IPv4/IPv6 bandwidth, borrowed arrays, u64 counters, complete groups above 1 MiB, fragmented/coalesced reads, malformed/old records and preserved connection/log bounds; no driver.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
