#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <cstdio>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

const char* StateToString(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED:     return "CLOSED";
    case MIB_TCP_STATE_LISTEN:     return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:    return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default:                       return "UNKNOWN";
    }
}

DWORD ReadTable(TCP_TABLE_CLASS tableClass, std::vector<BYTE>& buffer) {
    DWORD size = 0;
    DWORD status = GetExtendedTcpTable(
        nullptr, &size, FALSE, AF_INET, tableClass, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER) return status;

    for (int attempt = 0; attempt < 4; ++attempt) {
        buffer.resize(size);
        status = GetExtendedTcpTable(
            buffer.data(), &size, FALSE, AF_INET, tableClass, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) return status;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

void DumpTable(const char* name, TCP_TABLE_CLASS tableClass) {
    std::vector<BYTE> buffer;
    const DWORD status = ReadTable(tableClass, buffer);
    if (status != NO_ERROR) {
        std::printf("%s: GetExtendedTcpTable failed: %lu\n\n", name, status);
        return;
    }

    const auto* table =
        reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    std::printf("=== %s ===\n", name);
    std::printf("Total entries: %lu\n\n", table->dwNumEntries);

    // Для сравнения классов достаточно состояний, в которых владелец чаще
    // всего уже исчез из сокращённой таблицы.
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_TIME_WAIT &&
            row.dwState != MIB_TCP_STATE_SYN_SENT) {
            continue;
        }

        const auto* local = reinterpret_cast<const BYTE*>(&row.dwLocalAddr);
        const auto* remote = reinterpret_cast<const BYTE*>(&row.dwRemoteAddr);
        std::printf(
            "%u.%u.%u.%u:%-5u -> %u.%u.%u.%u:%-5u  %-12s  PID=%-6lu\n",
            local[0], local[1], local[2], local[3],
            ntohs(static_cast<u_short>(row.dwLocalPort)),
            remote[0], remote[1], remote[2], remote[3],
            ntohs(static_cast<u_short>(row.dwRemotePort)),
            StateToString(row.dwState), row.dwOwningPid);
    }
    std::printf("\n");
}

} // namespace

int main() {
    DumpTable("TCP_TABLE_OWNER_PID_ALL", TCP_TABLE_OWNER_PID_ALL);
    DumpTable("TCP_TABLE_OWNER_PID_CONNECTIONS",
              TCP_TABLE_OWNER_PID_CONNECTIONS);
    return 0;
}
