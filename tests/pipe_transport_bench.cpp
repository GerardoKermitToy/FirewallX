#include "duplex_pipe/pipe_transport.h"

#include <psapi.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

pipe_transport::UniqueHandle Server(const std::wstring& name) {
    pipe_transport::UniqueHandle pipe(CreateNamedPipeW(name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, pipe_transport::kPipeBufferSize, pipe_transport::kPipeBufferSize, 0, nullptr));
    Check(pipe.IsValid(), "create benchmark pipe");
    return pipe;
}
pipe_transport::UniqueHandle Client(const std::wstring& name) {
    pipe_transport::UniqueHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    Check(pipe.IsValid(), "open benchmark pipe");
    DWORD mode = PIPE_READMODE_MESSAGE;
    Check(SetNamedPipeHandleState(pipe.Get(), &mode, nullptr, nullptr) != FALSE, "message mode");
    return pipe;
}
struct PipePair {
    static inline unsigned sequence = 0;
    std::wstring name = L"\\\\.\\pipe\\FirewallX.PipeBench." +
        std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(++sequence);
    pipe_transport::Connection server{Server(name)};
    pipe_transport::Connection client{Client(name)};
    PipePair() {
        Check(pipe_transport::ConnectNamedPipeCancelable(server.Pipe(), server.CancelEvent()) == ERROR_SUCCESS,
              "connect benchmark pipe");
    }
};

double CpuMs() {
    FILETIME creation{}, exit{}, kernel{}, user{};
    Check(GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) != FALSE, "CPU time");
    ULARGE_INTEGER k{}, u{};
    k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
    return double(k.QuadPart + u.QuadPart) / 10000.0;
}
size_t PrivateBytes() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    Check(GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
        sizeof(counters)) != FALSE, "private memory");
    return counters.PrivateUsage;
}

size_t MessageSize(const char* kind, size_t size, unsigned index) {
    if (std::strcmp(kind, "mixed") == 0 && (index & 1)) return 64;
    if (std::strcmp(kind, "varying") == 0) return size + (index % 16) * 4096;
    return size;
}

void SmallMessage(PipePair& pipes, pipe_transport::RawMessage& message) {
    const byte next = 7;
    Check(pipe_transport::WriteRaw(pipes.server, &next, 1, 1000) == ERROR_SUCCESS &&
        pipe_transport::ReadRaw(pipes.client, message, 1000) == ERROR_SUCCESS &&
        message.Size() == 1 && message.Data()[0] == next, "small benchmark message");
}

void Run(unsigned run, const char* kind, size_t size, unsigned messages) {
    PipePair pipes;
    std::vector<byte> payload(size + 15 * 4096, 0xa5);
    pipe_transport::RawMessage message;
    SmallMessage(pipes, message);
    const size_t before = PrivateBytes();
    DWORD sent = ERROR_SUCCESS;
    DWORD read = ERROR_SUCCESS;
    // Один и тот же барьер у обоих вариантов исключает влияние разной глубины
    // очереди. Малые сообщения идут без дополнительного барьера.
    pipe_transport::UniqueHandle consumed(size > 65536 ? CreateEventW(nullptr, FALSE, FALSE, nullptr) : nullptr);
    Check(size <= 65536 || consumed.IsValid(), "benchmark pacing event");
    const double cpuStart = CpuMs();
    const auto start = std::chrono::steady_clock::now();
    std::thread writer([&] {
        for (unsigned i = 0; i < messages; ++i) {
            sent = pipe_transport::WriteRaw(pipes.server, payload.data(),
                static_cast<unsigned long>(MessageSize(kind, size, i)), INFINITE);
            if (sent != ERROR_SUCCESS) { pipes.client.Cancel(sent); break; }
            if (consumed.IsValid() && WaitForSingleObject(consumed.Get(), 30000) != WAIT_OBJECT_0) {
                sent = ERROR_TIMEOUT;
                pipes.client.Cancel(sent);
                break;
            }
        }
    });
    for (unsigned i = 0; i < messages; ++i) {
        read = pipe_transport::ReadRaw(pipes.client, message, 30000);
        const size_t expected = MessageSize(kind, size, i);
        if (read != ERROR_SUCCESS || message.Size() != expected || message.Data()[0] != 0xa5 ||
            message.Data()[expected - 1] != 0xa5) {
            pipes.server.Cancel(read == ERROR_SUCCESS ? ERROR_INVALID_DATA : read);
            if (read == ERROR_SUCCESS) read = ERROR_INVALID_DATA;
            if (consumed.IsValid()) SetEvent(consumed.Get());
            break;
        }
        if (consumed.IsValid()) SetEvent(consumed.Get());
    }
    writer.join();
    const double wall = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    const double cpu = CpuMs() - cpuStart;
    Check(sent == ERROR_SUCCESS && read == ERROR_SUCCESS, "benchmark transfer failed");
    const size_t peak = PrivateBytes();
    SmallMessage(pipes, message);
    const size_t afterOne = PrivateBytes();
    // 129 малых сообщений: решение после 128-го, освобождение в начале
    // следующего чтения, когда callback больше не использует предыдущий payload.
    for (unsigned i = 1; i < 129; ++i) SmallMessage(pipes, message);
    const size_t afterQuiet = PrivateBytes();
    std::printf("%s,%u,%u,%zu,%.3f,%.3f,%zu,%zu,%zu,%zu\n", kind, run, messages, size,
                wall, cpu, before, peak, afterOne, afterQuiet);
    std::fflush(stdout);
}
}

int main() {
    try {
        std::puts("kind,run,messages,bytes,wall_ms,cpu_ms,private_before,private_last,private_after_one_small,private_after_quiet");
        for (unsigned run = 1; run <= 7; ++run) {
            Run(run, "small", 64, 100000);
            Run(run, "large", 12 * 1024 * 1024, 128);
            Run(run, "mixed", 12 * 1024 * 1024, 256);
            Run(run, "varying", 12 * 1024 * 1024, 128);
        }
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
