#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

int main() {
    std::vector<BYTE> buf(64 * 1024);
    DWORD size = static_cast<DWORD>(buf.size());

    // Читаем полную таблицу TCP IPv4
    DWORD err = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                     TCP_TABLE_OWNER_PID_ALL, 0);
    if (err != NO_ERROR) {
        printf("GetExtendedTcpTable failed: %lu\n", err);
        return 1;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    printf("Total entries: %lu\n\n", table->dwNumEntries);

    // Ищем TIME_WAIT соединения (state == 11)
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState == MIB_TCP_STATE_TIME_WAIT) {
            BYTE* la = (BYTE*)&row.dwLocalAddr;
            BYTE* ra = (BYTE*)&row.dwRemoteAddr;
            printf("TIME_WAIT: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d  PID=%lu\n",
                   la[0], la[1], la[2], la[3], ntohs((u_short)row.dwLocalPort),
                   ra[0], ra[1], ra[2], ra[3], ntohs((u_short)row.dwRemotePort),
                   row.dwOwningPid);
        }
    }

    return 0;
}
