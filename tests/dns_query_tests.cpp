#include "Common.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

void Check(bool value, const char* text) {
    if (!value) {
        std::cerr << text << '\n';
        std::exit(1);
    }
}

std::vector<uint8_t> FromHex(std::string_view hex) {
    auto digit = [](char value) -> uint8_t {
        return static_cast<uint8_t>(value <= '9' ? value - '0' : value - 'a' + 10);
    };
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<uint8_t>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    return bytes;
}

void Set16(std::vector<uint8_t>& bytes, size_t offset, size_t value) {
    bytes[offset] = static_cast<uint8_t>(value >> 8);
    bytes[offset + 1] = static_cast<uint8_t>(value);
}

std::vector<uint8_t> Question(std::string_view name, uint16_t type = 1,
                              uint16_t dnsClass = 1) {
    std::vector<uint8_t> message(12, 0);
    message[2] = 1;
    message[5] = 1;
    for (size_t begin = 0; begin < name.size();) {
        const size_t dot = name.find('.', begin);
        const size_t end = dot == std::string_view::npos ? name.size() : dot;
        message.push_back(static_cast<uint8_t>(end - begin));
        message.insert(message.end(), name.begin() + begin, name.begin() + end);
        begin = end + 1;
    }
    message.insert(message.end(), {0, static_cast<uint8_t>(type >> 8),
                                  static_cast<uint8_t>(type),
                                  static_cast<uint8_t>(dnsClass >> 8),
                                  static_cast<uint8_t>(dnsClass)});
    return message;
}

std::vector<uint8_t> UdpPacket(const std::vector<uint8_t>& message, bool ipv6 = false,
                               size_t optionsSize = 0, uint16_t remotePort = 53) {
    const size_t ipSize = (ipv6 ? 40 : 20) + optionsSize;
    std::vector<uint8_t> packet(ipSize + 8 + message.size(), 0);
    if (ipv6) {
        packet[0] = 0x60;
        Set16(packet, 4, packet.size() - 40);
        packet[6] = optionsSize ? 0 : 17;
        if (optionsSize) {
            packet[40] = 17;
            packet[41] = static_cast<uint8_t>(optionsSize / 8 - 1);
        }
    } else {
        packet[0] = static_cast<uint8_t>(0x40 | (ipSize / 4));
        Set16(packet, 2, packet.size());
        packet[9] = 17;
    }
    Set16(packet, ipSize, 41000);
    Set16(packet, ipSize + 2, remotePort);
    Set16(packet, ipSize + 4, 8 + message.size());
    std::copy(message.begin(), message.end(), packet.begin() + ipSize + 8);
    return packet;
}

std::string Domain(const std::vector<uint8_t>& packet) {
    return GetDnsQueryDomain(packet.data(), static_cast<uint32_t>(packet.size()));
}

void TestProvidedPackets() {
    const auto domain = FromHex(
        "4500004f62ef0000801168bc0add540608080808c49f0035003b9b8f"
        "aec60120000100000000000106676f6f676c6503636f6d0000010001"
        "000029100000000000000c000a00086dba8f4efd3e75de");
    Check(Domain(domain) == "google.com", "provided DNS A query was not decoded");

    const auto reverse = FromHex(
        "4500005962f00000801168b10add540608080808e7e1003500453959"
        "ad3501200001000000000001013101310131013107696e2d61646472"
        "046172706100000c0001000029100000000000000c000a0008baf4560baff7c869");
    Check(Domain(reverse) == "1.1.1.1", "provided DNS PTR query was not decoded as an IP");
}

void TestIpHeaders() {
    const auto message = Question("www.example.com", 28);
    Check(Domain(UdpPacket(message)) == "www.example.com", "IPv4 DNS query was not decoded");
    Check(Domain(UdpPacket(message, false, 4)) == "www.example.com",
          "IPv4 DNS query with IP options was not decoded");
    Check(Domain(UdpPacket(message, true)) == "www.example.com",
          "IPv6 DNS query was not decoded");
    Check(Domain(UdpPacket(message, true, 8)) == "www.example.com",
          "IPv6 DNS query with an extension header was not decoded");
}

void TestAdditionalDnsQueries() {
    auto message = Question("workstation");
    message[2] = 0;
    for (uint16_t remotePort : {uint16_t{5353}, uint16_t{5355}})
    for (bool ipv6 : {false, true})
    for (size_t optionsSize : {size_t{0}, size_t{8}}) {
        const auto packet = UdpPacket(message, ipv6, optionsSize, remotePort);
        Check(Domain(packet) == "workstation", "additional DNS query was not decoded");
    }

    for (uint16_t remotePort : {uint16_t{5353}, uint16_t{5355}}) {
        message[2] = 0x80;
        Check(Domain(UdpPacket(message, false, 0, remotePort)).empty(),
              "additional DNS response was accepted as a query");
        message[2] = 0;
    }
}

void TestReverseQueries() {
    Check(Domain(UdpPacket(Question("7.2.0.192.in-addr.arpa", 12))) == "192.0.2.7",
          "IPv4 reverse DNS octets were not reversed");
    Check(Domain(UdpPacket(Question("7.2.0.192.IN-ADDR.ARPA", 12))) == "192.0.2.7",
          "uppercase reverse DNS suffix was not recognized");
    Check(Domain(UdpPacket(Question(
              "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", 12), true)) ==
              "2001:db8::1",
          "IPv6 reverse DNS nibbles were not decoded");
    Check(Domain(UdpPacket(Question("7.2.0.192.in-addr.arpa"))) == "7.2.0.192.in-addr.arpa",
          "non-PTR query was incorrectly converted to an IP");
    Check(Domain(UdpPacket(Question("999.2.0.192.in-addr.arpa", 12))) ==
              "999.2.0.192.in-addr.arpa",
          "invalid reverse DNS address was converted to an IP");
    Check(Domain(UdpPacket(Question("_service._udp.example.com"))) == "_service._udp.example.com",
          "DNS service labels were not decoded");
}

void TestMdnsReverseQueries() {
    struct ReverseQuery {
        std::string_view name;
        std::string_view address;
    };
    constexpr ReverseQuery queries[] = {
        {"7.2.0.192.in-addr.arpa", "192.0.2.7"},
        {"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1"},
    };
    for (const ReverseQuery& query : queries) {
        for (uint16_t dnsClass : {uint16_t{1}, uint16_t{255}, uint16_t{0x8001}, uint16_t{0x80ff}}) {
            auto message = Question(query.name, 12, dnsClass);
            message[2] = 0;
            for (bool ipv6 : {false, true})
            for (size_t optionsSize : {size_t{0}, size_t{8}})
                Check(Domain(UdpPacket(message, ipv6, optionsSize, 5353)) == query.address,
                      "mDNS PTR query with or without QU was not decoded as an IP");

            // QU относится только к mDNS, не меняя классы обычного DNS и LLMNR.
            if (dnsClass & 0x8000u) {
                for (uint16_t remotePort : {uint16_t{53}, uint16_t{5355}})
                    Check(Domain(UdpPacket(message, false, 0, remotePort)) == query.name,
                          "mDNS QU handling changed a non-mDNS question class");
            }
        }

        auto message = Question(query.name, 12, 0x8003);
        message[2] = 0;
        Check(Domain(UdpPacket(message, false, 0, 5353)) == query.name,
              "QU caused an unsupported mDNS class to be treated as IN");
        message = Question(query.name, 1, 0x8001);
        message[2] = 0;
        Check(Domain(UdpPacket(message, false, 0, 5353)) == query.name,
              "QU caused a non-PTR mDNS query to be converted to an IP");
    }
}

void TestMdnsQuestionClasses() {
    for (uint16_t dnsClass : {uint16_t{0}, uint16_t{0x8000}}) {
        auto message = Question("example.local", 1, dnsClass);
        message[2] = 0;
        Check(Domain(UdpPacket(message, false, 0, 5353)).empty(),
              "mDNS question with a zero class was accepted");
    }

    auto message = Question("example.local", 1, 0x8001);
    message[2] = 0;
    Check(Domain(UdpPacket(message, false, 0, 5353)) == "example.local",
          "mDNS A query with QU was not decoded");
    message[5] = 2;
    message.insert(message.end(), {0xc0, 12, 0, 1, 0x80, 0});
    Check(Domain(UdpPacket(message, false, 0, 5353)).empty(),
          "a later mDNS question with a zero class and QU was accepted");
}

void TestNameBoundsAndEscaping() {
    const std::string label(63, 'a');
    const std::string maximum = label + "." + label + "." + label + "." + std::string(61, 'b');
    Check(Domain(UdpPacket(Question(maximum))) == maximum,
          "maximum-length DNS name was rejected");
    Check(Domain(UdpPacket(Question(label + "." + label + "." + label + "." + label))).empty(),
          "oversized DNS name was accepted");
    Check(Domain(UdpPacket(Question("", 2))) == ".", "DNS root question was not decoded");

    auto message = Question("example.com");
    message[13] = 0;
    Check(Domain(UdpPacket(message)) == "\\000xample.com",
          "control character in DNS label was not escaped");
    message[13] = '.';
    Check(Domain(UdpPacket(message)) == "\\046xample.com",
          "dot inside a DNS label was confused with a label separator");
}

void TestNonQueries() {
    auto message = Question("example.com");
    message[2] |= 0x80;
    Check(Domain(UdpPacket(message)).empty(), "DNS response was accepted as a query");
    message[2] = 0x29;
    Check(Domain(UdpPacket(message)).empty(), "DNS update was accepted as a query");
    message[2] = 1;
    message[5] = 0;
    Check(Domain(UdpPacket(message)).empty(), "DNS message without questions returned a domain");

    auto packet = UdpPacket(Question("example.com"));
    packet[9] = 6;
    Check(Domain(packet).empty(), "TCP packet was accepted as UDP DNS");
    packet[9] = 17;
    Set16(packet, 22, 5354);
    Check(Domain(packet).empty(), "non-DNS UDP destination was accepted as DNS");
}

void TestCompressedQuestions() {
    auto message = Question("example.com");
    message[5] = 2;
    message.insert(message.end(), {0xc0, 12, 0, 28, 0, 1});
    Check(Domain(UdpPacket(message)) == "example.com",
          "DNS query with a compressed second question was not decoded");
    message.pop_back();
    Check(Domain(UdpPacket(message)).empty(),
          "truncated compressed DNS question was accepted");

    message = Question("example.com");
    message[5] = 2;
    const size_t pointer = message.size();
    message.insert(message.end(), {0xc0, static_cast<uint8_t>(pointer), 0, 28, 0, 1});
    Check(Domain(UdpPacket(message)).empty(),
          "cyclic compression in a later DNS question was accepted");
}

void TestMalformedPackets() {
    const auto packet = UdpPacket(Question("example.com"));
    Check(GetDnsQueryDomain(nullptr, 0).empty(), "null packet returned a domain");
    for (size_t size = 0; size < packet.size(); ++size)
        Check(GetDnsQueryDomain(packet.data(), static_cast<uint32_t>(size)).empty(),
              "truncated IP packet returned a domain");

    auto malformed = packet;
    Set16(malformed, 24, 7);
    Check(Domain(malformed).empty(), "short UDP length returned a domain");
    Set16(malformed, 24, malformed.size());
    Check(Domain(malformed).empty(), "oversized UDP length returned a domain");
    malformed = packet;
    malformed[6] = 0x20;
    Check(Domain(malformed).empty(), "fragmented IPv4 datagram returned a domain");
    malformed[6] = 0;
    malformed[7] = 1;
    Check(Domain(malformed).empty(), "non-first IPv4 fragment returned a domain");

    auto message = Question("example.com");
    message[12] = 64;
    Check(Domain(UdpPacket(message)).empty(), "invalid DNS label length returned a domain");
    message[12] = 0xc0;
    message[13] = 12;
    Check(Domain(UdpPacket(message)).empty(), "cyclic DNS compression returned a domain");
    message[13] = 0xff;
    Check(Domain(UdpPacket(message)).empty(), "out-of-bounds DNS compression returned a domain");
    message = Question("example.com");
    message.resize(message.size() - 1);
    Check(Domain(UdpPacket(message)).empty(), "truncated DNS question returned a domain");
}

} // анонимное пространство имён

int main() {
    TestProvidedPackets();
    TestIpHeaders();
    TestAdditionalDnsQueries();
    TestReverseQueries();
    TestMdnsReverseQueries();
    TestMdnsQuestionClasses();
    TestNameBoundsAndEscaping();
    TestNonQueries();
    TestCompressedQuestions();
    TestMalformedPackets();
    return 0;
}
