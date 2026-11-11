#include "Common.h"
#include "TlsReassembly.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

namespace {

[[noreturn]] void Fail(const char* text) {
    std::cerr << text << '\n';
    std::exit(1);
}

void Check(bool value, const char* text) {
    if (!value) Fail(text);
}

void Add16(std::vector<uint8_t>& out, size_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void Add24(std::vector<uint8_t>& out, size_t value) {
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

std::vector<uint8_t> TlsRecord(const uint8_t* data, size_t size) {
    std::vector<uint8_t> record{ 22, 3, 1 };
    Add16(record, size);
    record.insert(record.end(), data, data + size);
    return record;
}

std::vector<uint8_t> ClientHello(const std::string& domain) {
    std::vector<uint8_t> serverName;
    Add16(serverName, 1 + 2 + domain.size());
    serverName.push_back(0);
    Add16(serverName, domain.size());
    serverName.insert(serverName.end(), domain.begin(), domain.end());

    std::vector<uint8_t> extensions;
    Add16(extensions, 0);
    Add16(extensions, serverName.size());
    extensions.insert(extensions.end(), serverName.begin(), serverName.end());

    std::vector<uint8_t> body{ 3, 3 };
    body.insert(body.end(), 32, 0x5a);
    body.push_back(0);                  // пустой session_id
    Add16(body, 2);
    body.push_back(0x13);
    body.push_back(0x01);
    body.push_back(1);                  // один метод сжатия
    body.push_back(0);
    Add16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake{ 1 };
    Add24(handshake, body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());

    return TlsRecord(handshake.data(), handshake.size());
}

void TestCompleteClientHelloDomain() {
    const std::vector<uint8_t> hello = ClientHello("split.example");
    Check(InspectTlsClientHelloRecords(hello.data(), hello.size()) ==
              TlsClientHelloProgress::Complete,
          "complete ClientHello was not recognized");
    Check(GetTlsClientHelloDomain(hello.data(), hello.size()) ==
              "split.example",
          "SNI was not parsed from complete ClientHello");
}

void TestIncrementalInspectionVisitsEachByteOnce() {
    const std::vector<uint8_t> hello = ClientHello("bytewise.example");
    TlsClientHelloInspector inspector;

    for (size_t i = 0; i < hello.size(); ++i) {
        inspector.Append(hello.data() + i, 1);
        Check(inspector.processedBytes() == i + 1,
              "incremental inspector revisited prior bytes");
        if (i + 1 < hello.size()) {
            Check(inspector.progress() == TlsClientHelloProgress::Incomplete,
                  "incremental inspector completed before record boundary");
        }
    }

    Check(inspector.progress() == TlsClientHelloProgress::Complete,
          "bytewise ClientHello was not completed");
}

void TestHandshakeAcrossTlsRecords() {
    const std::vector<uint8_t> single = ClientHello("records.example");
    const uint8_t* const handshake = single.data() + 5;
    const size_t handshakeSize = single.size() - 5;
    const size_t parts[] = { 2, 7, handshakeSize - 9 };

    std::vector<uint8_t> fragmented;
    size_t offset = 0;
    for (const size_t part : parts) {
        std::vector<uint8_t> record = TlsRecord(handshake + offset, part);
        fragmented.insert(fragmented.end(), record.begin(), record.end());
        offset += part;
    }

    TlsClientHelloInspector inspector;
    for (size_t i = 0; i < fragmented.size(); ++i)
        inspector.Append(fragmented.data() + i, 1);
    Check(inspector.progress() == TlsClientHelloProgress::Complete,
          "ClientHello split across TLS records was not completed");
    Check(inspector.processedBytes() == fragmented.size(),
          "fragmented TLS records were not inspected exactly once");
    Check(GetTlsClientHelloDomain(fragmented.data(), fragmented.size()) ==
              "records.example",
          "SNI was not parsed across TLS record boundaries");
}

void TestTwoTcpSegmentsAreReassembled() {
    const std::vector<uint8_t> hello = ClientHello("split.example");
    const size_t split = 37;
    const uint32_t sequence = 0xfffffff0u;

    TlsClientHelloBuffer buffer(sequence, hello.data(), split);
    const size_t processedAfterFirst = buffer.processedBytes();
    Check(processedAfterFirst == split,
          "first TCP segment was not inspected exactly once");
    Check(buffer.progress() == TlsClientHelloProgress::Incomplete,
          "first TCP segment was not marked incomplete");
    Check(GetTlsClientHelloDomain(hello.data(), split).empty(),
          "incomplete ClientHello unexpectedly returned SNI");
    Check(buffer.Append(sequence + static_cast<uint32_t>(split),
                        hello.data() + split, hello.size() - split),
          "contiguous second TCP segment was rejected");
    Check(buffer.progress() == TlsClientHelloProgress::Complete,
          "reassembled ClientHello was not marked complete");
    Check(buffer.processedBytes() == hello.size(),
          "reassembly inspector revisited the first TCP segment");

    const std::vector<uint8_t> assembled = buffer.Take();
    Check(assembled == hello, "reassembled TLS bytes differ from source");
    Check(GetTlsClientHelloDomain(assembled.data(), assembled.size()) ==
              "split.example",
          "SNI was not parsed after TCP reassembly");
}

void TestProblemPacketFramingNeeds463Bytes() {
    std::vector<uint8_t> hello(1831, 0);
    const uint8_t headers[] = {
        0x16, 0x03, 0x01, 0x07, 0x22,
        0x01, 0x00, 0x07, 0x1e,
    };
    std::copy(std::begin(headers), std::end(headers), hello.begin());

    constexpr size_t firstPart = 1368;
    constexpr uint32_t sequence = 0x79c67ee9u;
    TlsClientHelloBuffer buffer(sequence, hello.data(), firstPart);
    Check(buffer.progress() == TlsClientHelloProgress::Incomplete,
          "problem packet framing was not marked incomplete");
    Check(buffer.Append(sequence + static_cast<uint32_t>(firstPart),
                        hello.data() + firstPart,
                        hello.size() - firstPart),
          "463-byte continuation was rejected");
    Check(buffer.progress() == TlsClientHelloProgress::Complete,
          "problem packet framing did not complete after 463 bytes");
}

void TestRetransmitIsNotDuplicated() {
    const std::vector<uint8_t> hello = ClientHello("retry.example");
    const size_t split = 31;
    constexpr uint32_t sequence = 5000;

    TlsClientHelloBuffer buffer(sequence, hello.data(), split);
    const size_t processed = buffer.processedBytes();
    Check(buffer.Append(sequence, hello.data(), split),
          "identical retransmit was rejected");
    Check(buffer.processedBytes() == processed,
          "identical retransmit was inspected twice");
    Check(buffer.Append(sequence + static_cast<uint32_t>(split),
                        hello.data() + split, hello.size() - split),
          "tail after retransmit was rejected");
    Check(buffer.Take() == hello, "retransmit duplicated TLS bytes");
}

void TestSequenceGapIsRejected() {
    const std::vector<uint8_t> hello = ClientHello("gap.example");
    constexpr size_t split = 29;
    constexpr uint32_t sequence = 7000;

    TlsClientHelloBuffer buffer(sequence, hello.data(), split);
    Check(!buffer.Append(sequence + static_cast<uint32_t>(split) + 1,
                         hello.data() + split, hello.size() - split),
          "TCP sequence gap was accepted");
}

} // namespace

int main() {
    TestCompleteClientHelloDomain();
    TestIncrementalInspectionVisitsEachByteOnce();
    TestHandshakeAcrossTlsRecords();
    TestTwoTcpSegmentsAreReassembled();
    TestProblemPacketFramingNeeds463Bytes();
    TestRetransmitIsNotDuplicated();
    TestSequenceGapIsRejected();
    return 0;
}
