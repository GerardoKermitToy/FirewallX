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

std::vector<uint8_t> HttpPacket(std::string_view request, bool ipv6 = false) {
    const size_t ipHeaderSize = ipv6 ? 40 : 20;
    std::vector<uint8_t> packet(ipHeaderSize + 20 + request.size(), 0);
    if (ipv6) {
        packet[0] = 0x60;
        const size_t payloadSize = packet.size() - ipHeaderSize;
        packet[4] = static_cast<uint8_t>(payloadSize >> 8);
        packet[5] = static_cast<uint8_t>(payloadSize);
        packet[6] = 6;
    } else {
        packet[0] = 0x45;
        packet[2] = static_cast<uint8_t>(packet.size() >> 8);
        packet[3] = static_cast<uint8_t>(packet.size());
        packet[9] = 6;
    }
    packet[ipHeaderSize + 12] = 0x50;
    packet[ipHeaderSize + 13] = 0x18;
    std::copy(request.begin(), request.end(), packet.begin() + ipHeaderSize + 20);
    return packet;
}

void TestIpv4Host() {
    const auto packet = HttpPacket(
        "GET / HTTP/1.1\r\nHost: www.example.com:80\r\n\r\n");
    Check(getHttpHost(packet.data(), static_cast<uint32_t>(packet.size())) ==
              "www.example.com",
          "IPv4 HTTP Host was not extracted without port");
}

void TestIpv6Host() {
    const auto packet = HttpPacket(
        "GET / HTTP/1.1\r\nhost: [::1]:80\r\n\r\n", true);
    Check(getHttpHost(packet.data(), static_cast<uint32_t>(packet.size())) ==
              "[::1]",
          "IPv6 HTTP Host was not extracted");
}

void TestMissingAndIncompleteHost() {
    const auto missing = HttpPacket("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n");
    Check(getHttpHost(missing.data(), static_cast<uint32_t>(missing.size())).empty(),
          "HTTP request without Host returned a domain");

    const auto incomplete = HttpPacket("GET / HTTP/1.1\r\nHost: example.com");
    Check(getHttpHost(incomplete.data(),
                      static_cast<uint32_t>(incomplete.size())).empty(),
          "incomplete HTTP Host returned a domain");
}

} // namespace

int main() {
    TestIpv4Host();
    TestIpv6Host();
    TestMissingAndIncompleteHost();
    return 0;
}
