// Все обращения к устройству и именованному событию подменены; драйвер не используется.
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <cwchar>
#include <stdexcept>
#include <vector>

namespace testio {
HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
HANDLE CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
BOOL DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
DWORD WaitForMultipleObjects(DWORD, const HANDLE*, BOOL, DWORD);
}

#define CreateFileW testio::CreateFileW
#define CreateEventW testio::CreateEventW
#define DeviceIoControl testio::DeviceIoControl
#define WriteFile testio::WriteFile
#define GetOverlappedResult testio::GetOverlappedResult
#define WaitForMultipleObjects testio::WaitForMultipleObjects
#include "FirewallXNdisFilter.hpp"
#undef CreateFileW
#undef CreateEventW
#undef DeviceIoControl
#undef WriteFile
#undef GetOverlappedResult
#undef WaitForMultipleObjects

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct State {
    bool available = false, cancel = false;
    unsigned opens = 0, notifications = 0, waits = 0, versions = 0, countQueries = 0;
    std::array<uint8_t, 4> version = firewallxndisfilter::Client::RequiredVersion;
    uint32_t filteredCount = 0;
    DWORD countError = ERROR_SUCCESS, countSize = 4, actualSize = 4;
    HANDLE ready = nullptr;
    std::vector<DWORD> openErrors;
    unsigned waitLimit = 1, adapterQueries = 0;
    DWORD adapterError = ERROR_SUCCESS;
    std::vector<uint8_t> adapters;
    std::vector<uint8_t> commands;
    unsigned adapterGrowths = 0;
} state;

template <class Connection>
void CaptureIndex(void* context, const Connection* connection, const uint8_t*, uint32_t) {
    static_cast<std::vector<uint32_t>*>(context)->push_back(connection->interface_index);
}

void CheckConnectionIndices() {
    using Client = firewallxndisfilter::Client;
    const std::vector<uint32_t> expected{101, 0x12345678, 101, 0x87654321};
    for (const bool ipv6 : {false, true}) {
        const size_t prefix = ipv6 ? 60 : 36;
        std::vector<uint8_t> records;
        for (const uint32_t index : expected) {
            std::vector<uint8_t> record(prefix + 1);
            record[0] = ipv6 ? 2 : 1;
            const uint32_t body = static_cast<uint32_t>(record.size() - 5);
            std::memcpy(record.data() + 1, &body, 4);
            std::memcpy(record.data() + 13, &index, 4);
            record[17] = ipv6 ? 1 : 0;
            record[18] = 17;
            record[prefix - 5] = 3;
            record[prefix - 4] = 1;
            record[prefix] = ipv6 ? 0x60 : 0x45;
            records.insert(records.end(), record.begin(), record.end());
        }
        for (const size_t chunk : {size_t{1}, size_t{16}, size_t{65536}}) {
            std::vector<uint32_t> observed;
            Client::Callbacks callbacks;
            callbacks.context = &observed;
            callbacks.on_connection_v4 = CaptureIndex<Client::ConnectionV4>;
            callbacks.on_connection_v6 = CaptureIndex<Client::ConnectionV6>;
            Client::Stream stream;
            for (size_t offset = 0; offset < records.size();) {
                auto buffer = stream.Buffer();
                const size_t count = (std::min)({chunk, buffer.size(), records.size() - offset});
                std::memcpy(buffer.data(), records.data() + offset, count);
                Check(stream.Commit(count, callbacks) == ERROR_SUCCESS, "adapter index stream was rejected");
                offset += count;
            }
            Check(observed == expected && stream.PendingBytes() == 0,
                  "adapter indices were lost or mixed between records");
        }
    }
}

}

namespace testio {
HANDLE CreateFileW(LPCWSTR name, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES,
                   DWORD mode, DWORD flags, HANDLE) {
    ++state.opens;
    Check(std::wcscmp(name, LR"(\\.\FirewallXNdisFilter)") == 0, "wrong driver device name");
    Check(access == (GENERIC_READ | GENERIC_WRITE) && sharing == 0 &&
              mode == OPEN_EXISTING && flags == FILE_FLAG_OVERLAPPED,
          "wrong driver open flags");
    const DWORD error = state.opens <= state.openErrors.size()
        ? state.openErrors[state.opens - 1] : state.available ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
    if (!error) return ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetLastError(error);
    return INVALID_HANDLE_VALUE;
}

HANDLE CreateEventW(LPSECURITY_ATTRIBUTES security, BOOL manual, BOOL initial, LPCWSTR name) {
    if (!name) return ::CreateEventW(security, manual, initial, nullptr);
    ++state.notifications;
    Check(std::wcscmp(name, L"Global\\FirewallXNdisFilter.DriverReady") == 0,
          "wrong driver readiness event name");
    Check(security && security->lpSecurityDescriptor && !security->bInheritHandle &&
              manual && !initial, "wrong driver readiness event attributes");
    // Частное событие изначально сигнализируется: клиент обязан сбросить старый сигнал.
    state.ready = ::CreateEventW(nullptr, TRUE, TRUE, nullptr);
    return state.ready;
}

DWORD WaitForMultipleObjects(DWORD count, const HANDLE* events, BOOL all, DWORD timeout) {
    ++state.waits;
    Check(state.waits <= state.waitLimit, "busy exclusive device must not wait for DriverReady");
    Check(count == 2 && !all && timeout == INFINITE && events[1] == state.ready,
          "startup must wait indefinitely on stop/readiness, without polling");
    Check(::WaitForSingleObject(state.ready, 0) == WAIT_TIMEOUT,
          "stale readiness signal was not reset before retrying");
    if (state.cancel) {
        SetEvent(events[0]);
        return WAIT_OBJECT_0;
    }
    state.available = true;
    return WAIT_OBJECT_0 + 1;
}

BOOL DeviceIoControl(HANDLE, DWORD code, LPVOID input, DWORD inputSize,
                     LPVOID output, DWORD size, LPDWORD actual, LPOVERLAPPED) {
    Check(!input && inputSize == 0 && output, "wrong control request layout");
    if (code == 0x9C40E00C) {
        ++state.adapterQueries;
        if (state.adapterError) { SetLastError(state.adapterError); return FALSE; }
        if (state.adapterGrowths) {
            --state.adapterGrowths;
            const uint32_t count = (size - 16) / 1760 + 1;
            state.adapters.assign(16, 0);
            const uint32_t schema = 1, entry = 1760;
            std::memcpy(state.adapters.data(), &schema, 4);
            std::memcpy(state.adapters.data() + 4, &entry, 4);
            std::memcpy(state.adapters.data() + 8, &count, 4);
        }
        Check(size >= 16 && state.adapters.size() >= 16, "bad adapter snapshot request");
        uint32_t count = 0;
        std::memcpy(&count, state.adapters.data() + 8, 4);
        const bool grow = 16ull + count * 1760ull > size;
        state.actualSize = grow ? 16 : static_cast<DWORD>(state.adapters.size());
        std::memcpy(output, state.adapters.data(), state.actualSize);
        *actual = state.actualSize;
        if (grow) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        return TRUE;
    }
    Check(size == 4, "wrong scalar control request size");
    if (code == 0x9C40E000) {
        ++state.versions;
        std::memcpy(output, state.version.data(), 4);
        state.actualSize = 4;
    } else {
        Check(code == 0x9C40E008, "wrong filtered-device-count request");
        ++state.countQueries;
        if (state.countError) { SetLastError(state.countError); return FALSE; }
        std::memcpy(output, &state.filteredCount, 4);
        state.actualSize = state.countSize;
    }
    *actual = state.actualSize;
    return TRUE;
}

BOOL WriteFile(HANDLE, LPCVOID buffer, DWORD size, LPDWORD actual, LPOVERLAPPED) {
    Check(buffer && size == 1, "wrong command request layout");
    state.commands.push_back(*static_cast<const uint8_t*>(buffer));
    state.actualSize = size;
    *actual = size;
    return TRUE;
}

BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD actual, BOOL wait) {
    Check(wait != FALSE, "version request was not reaped");
    *actual = state.actualSize;
    return TRUE;
}
}

namespace {
std::vector<uint8_t> Snapshot(uint32_t count, uint32_t running) {
    std::vector<uint8_t> bytes(16 + static_cast<size_t>(count) * 1760);
    const uint32_t schema = 1, entrySize = 1760;
    std::memcpy(bytes.data(), &schema, 4);
    std::memcpy(bytes.data() + 4, &entrySize, 4);
    std::memcpy(bytes.data() + 8, &count, 4);
    std::memcpy(bytes.data() + 12, &running, 4);
    for (uint32_t i = 0; i < count; ++i) {
        auto* entry = bytes.data() + 16 + static_cast<size_t>(i) * 1760;
        const uint32_t index = i + 1, flags = i < running ? 1 : 0;
        const uint64_t luid = 1000ull + i;
        const GUID guid{index, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
        std::memcpy(entry + 8, &index, 4);
        std::memcpy(entry + 20, &flags, 4);
        std::memcpy(entry + 24, &luid, 8);
        std::memcpy(entry + 48, &guid, 16);
    }
    return bytes;
}
void CheckCommands() {
    using Client = firewallxndisfilter::Client;
    state = {};
    state.available = true;
    Client client;
    Check(client.Open() == ERROR_SUCCESS, "command client did not open");
    for (const auto command : {Client::Command::ClearCache, Client::Command::GetLogs,
                               Client::Command::GetBandwidthStats, Client::Command::PrintMemoryStats}) {
        Check(client.Send(command) == ERROR_SUCCESS, "supported command was rejected");
    }
    Check(state.commands == std::vector<uint8_t>{4, 5, 6, 7}, "supported command bytes changed");
    for (const uint8_t value : {uint8_t{0}, uint8_t{3}, uint8_t{8}, uint8_t{255}}) {
        Check(client.Send(static_cast<Client::Command>(value)) == ERROR_INVALID_PARAMETER,
              "unsupported command was accepted");
    }
    Check(state.commands == std::vector<uint8_t>{4, 5, 6, 7}, "unsupported command reached the device");
}

void CheckAdapterSnapshots() {
    using Client = firewallxndisfilter::Client;
    for (const uint32_t count : {0u, 2u, 33u, 129u}) {
        state = {}; state.available = true; state.adapters = Snapshot(count, count ? count - 1 : 0);
        Client client;
        Check(client.Open() == ERROR_SUCCESS, "snapshot client did not open");
        std::vector<Client::AdapterState> adapters;
        Check(client.GetAdapterStates(adapters) == ERROR_SUCCESS && adapters.size() == count,
            "adapter snapshot failed or was capped");
        Check(state.adapterQueries == (count > 32 ? 2u : 1u), "snapshot growth was not bounded by returned sizing header");
        if (count) Check(adapters[0].guid.Data1 == 1 && adapters[0].luid == 1000 &&
            adapters.back().interface_index == count && !adapters.back().running, "snapshot lost identities or paused modules");
    }
    for (unsigned mutation = 0; mutation < 8; ++mutation) {
        auto bytes = Snapshot(2, 2);
        if (mutation == 0) bytes[0] = 2;
        if (mutation == 1) bytes[4] = 0;
        if (mutation == 2) std::memset(bytes.data() + 8, 0xff, 4);
        if (mutation == 3) bytes[12] = 1;
        if (mutation == 4) bytes.pop_back();
        if (mutation == 5) std::memset(bytes.data() + 16 + 48, 0, 16);
        if (mutation == 6) std::memcpy(bytes.data() + 16 + 1760 + 24, bytes.data() + 16 + 24, 8);
        if (mutation == 7) std::memcpy(bytes.data() + 16 + 1760 + 8, bytes.data() + 16 + 8, 4);
        std::vector<Client::AdapterState> result(1); result[0].luid = 42;
        Check(Client::DecodeAdapterStates(bytes, result) == ERROR_INVALID_DATA && result.size() == 1 && result[0].luid == 42,
            "malformed adapter snapshot was accepted or changed output");
    }
    {
        state = {}; state.available = true; state.adapterError = ERROR_INVALID_FUNCTION;
        Client client; Check(client.Open() == ERROR_SUCCESS, "unsupported snapshot client did not open");
        std::vector<Client::AdapterState> result(1); result[0].luid = 42;
        Check(client.GetAdapterStates(result) == ERROR_INVALID_FUNCTION && result[0].luid == 42,
            "unsupported snapshot invented attachment data");
    }
    {
        state = {}; state.available = true; state.adapterGrowths = 8;
        Client client; Check(client.Open() == ERROR_SUCCESS, "growing snapshot client did not open");
        std::vector<Client::AdapterState> result(1); result[0].luid = 42;
        Check(client.GetAdapterStates(result) == ERROR_RETRY && state.adapterQueries == 8 && result[0].luid == 42,
            "topology churn was not bounded or changed output");
    }
}
} // namespace

int main() {
    try {
        using Client = firewallxndisfilter::Client;
        static_assert(Client::RequiredVersion == std::array<uint8_t, 4>{0, 3, 3, 0});
        CheckConnectionIndices();
        CheckAdapterSnapshots();
        CheckCommands();
        for (const auto version : {std::array<uint8_t, 4>{0, 3, 2, 0}, {0, 3, 1, 0}}) {
            state = {};
            state.available = true;
            state.version = version;
            Client oldDriver;
            Check(oldDriver.Open() == ERROR_REVISION_MISMATCH && state.opens == 1 && state.waits == 0,
                  "old driver layout must be rejected before reading events");
        }
        for (const bool available : {true, false}) {
            state = {};
            state.available = available;
            Client client;
            Check(client.Open() == ERROR_SUCCESS, "renamed client did not open");
            Check(state.opens == (available ? 1u : 3u) && state.versions == 1 &&
                      state.notifications == (available ? 0u : 1u) &&
                      state.waits == (available ? 0u : 1u), "unexpected startup sequence");
            Check(client.Close() == ERROR_SUCCESS, "client did not close");
        }
        for (const auto& errors : std::vector<std::vector<DWORD>>{
                {ERROR_SHARING_VIOLATION},
                {ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION},
                {ERROR_FILE_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION}}) {
            state = {};
            state.openErrors = errors;
            state.waitLimit = errors.size() == 3 ? 1u : 0u;
            Client busy;
            Check(busy.Open() == ERROR_SHARING_VIOLATION, "exclusive ownership must return a busy error");
            Check(state.opens == errors.size() && state.waits == state.waitLimit && state.versions == 0 &&
                state.notifications == (errors.size() == 1 ? 0u : 1u), "busy device incorrectly used startup readiness");
            state.openErrors.clear();
            state.available = true;
            Check(busy.Open() == ERROR_SUCCESS && state.versions == 1,
                "same client did not reopen after the other owner released the device");
            Check(busy.Close() == ERROR_SUCCESS, "reopened busy client did not close");
        }
        for (const uint32_t count : {0u, 1u, 3u}) {
            state = {};
            state.available = true;
            state.filteredCount = count;
            Client client;
            Check(client.Open() == ERROR_SUCCESS, "count client did not open");
            uint32_t actual = 17;
            Check(client.GetFilteredDeviceCount(actual) == ERROR_SUCCESS && actual == count && state.countQueries == 1,
                  "filtered device count was not read from the driver reply");
        }
        for (const DWORD error : {ERROR_INVALID_FUNCTION, ERROR_ACCESS_DENIED}) {
            state = {};
            state.available = true;
            state.countError = error;
            Client client;
            Check(client.Open() == ERROR_SUCCESS, "failing count client did not open");
            uint32_t actual = 17;
            Check(client.GetFilteredDeviceCount(actual) == error && actual == 17,
                  "count failure was hidden or invented a zero count");
        }
        {
            state = {};
            state.available = true;
            state.countSize = 3;
            Client client;
            Check(client.Open() == ERROR_SUCCESS, "short count client did not open");
            uint32_t actual = 17;
            Check(client.GetFilteredDeviceCount(actual) == ERROR_BAD_LENGTH && actual == 17,
                  "short count reply was accepted");
        }
        state = {};
        state.cancel = true;
        Client client;
        Check(client.Open() == ERROR_OPERATION_ABORTED && state.opens == 2 &&
                  state.notifications == 1 && state.waits == 1 && state.versions == 0,
              "startup cancellation did not stop before opening the device");
        std::puts("PASS: renamed device/readiness names, immediate/delayed startup, busy-device fail-fast/reopen, cancellation, filtered-device-count replies/errors, adapter-index streams and old-version rejection; fake device only.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
