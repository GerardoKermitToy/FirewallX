#include "duplex_pipe/duplex_pipe_client.h"
#include "duplex_pipe/pipe_transport.h"

#include <atomic>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

using Handle = pipe_transport::UniqueHandle;

struct Observation {
    Handle entered{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle release{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::atomic<bool> blockFirst{false};
    std::atomic<unsigned> calls{0};
    duplex_pipe::Client* reply = nullptr;
    std::mutex mutex;
    std::vector<std::vector<byte>> records;
};

RPC_STATUS Receive(void* context, const byte* data, unsigned long size) noexcept {
    auto& observation = *static_cast<Observation*>(context);
    const unsigned call = observation.calls.fetch_add(1);
    if (call == 0 && observation.blockFirst.load()) {
        SetEvent(observation.entered.Get());
        WaitForSingleObject(observation.release.Get(), INFINITE);
    }
    try {
        {
            std::lock_guard lock(observation.mutex);
            observation.records.emplace_back(data, data + size);
        }
        return observation.reply ? observation.reply->SendRaw(data, size) : ERROR_SUCCESS;
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

struct Fixture {
    static inline unsigned sequence = 0;
    std::wstring name = L"\\\\.\\pipe\\FirewallX.DrainTest." +
        std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(++sequence);
    pipe_transport::Connection server{Handle{CreateNamedPipeW(name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, pipe_transport::kPipeBufferSize, pipe_transport::kPipeBufferSize, 0, nullptr)}};
    Observation observed;
    duplex_pipe::Client client{name.c_str()};

    explicit Fixture(bool blockFirst = false, bool reply = false) {
        Check(server.IsValid() && observed.entered.IsValid() && observed.release.IsValid(),
              "cannot create test handles");
        observed.blockFirst.store(blockFirst);
        if (reply) observed.reply = &client;
        client.SetReceiveCallback(Receive, &observed);
        DWORD serverStatus = ERROR_IO_PENDING;
        std::thread handshake([&] {
            serverStatus = pipe_transport::ConnectNamedPipeCancelable(server.Pipe(), server.CancelEvent());
            if (serverStatus != ERROR_SUCCESS) return;
            serverStatus = pipe_transport::WriteHandshake(server, pipe_transport::HandshakeType::Ready, 5000);
            if (serverStatus != ERROR_SUCCESS) return;
            pipe_transport::HandshakeType response{};
            serverStatus = pipe_transport::ReadHandshake(server, response, 5000);
            if (serverStatus == ERROR_SUCCESS && response != pipe_transport::HandshakeType::Accepted)
                serverStatus = ERROR_INVALID_DATA;
        });
        const DWORD clientStatus = client.Start();
        handshake.join();
        Check(clientStatus == ERROR_SUCCESS && serverStatus == ERROR_SUCCESS,
              "test handshake failed");
    }

    ~Fixture() {
        SetEvent(observed.release.Get());
        client.Stop();
    }

    void Send(const std::vector<byte>& message) {
        Check(pipe_transport::WriteRaw(server, message.data(),
            static_cast<unsigned long>(message.size()), 10000) == ERROR_SUCCESS,
            "test write failed");
    }
};

bool WaitDrain(duplex_pipe::DrainWait& drain, duplex_pipe::Client& client) {
    Handle finished{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Check(finished.IsValid(), "cannot create wait event");
    bool result = false;
    std::thread waiter([&] { result = drain.Wait(); SetEvent(finished.Get()); });
    const bool finishedInTime = WaitForSingleObject(finished.Get(), 10000) == WAIT_OBJECT_0;
    if (!finishedInTime) client.Stop();
    waiter.join();
    Check(finishedInTime, "drain did not complete");
    return result;
}

void TestIdleAndRepeatedHandoffs() {
    Fixture fixture;
    {
        duplex_pipe::DrainWait drain;
        Check(drain.Start(fixture.client) && WaitDrain(drain, fixture.client),
              "idle reader was not interrupted");
    }
    for (unsigned i = 0; i < 200; ++i) {
        fixture.Send({static_cast<byte>(i), static_cast<byte>(i >> 8)});
        duplex_pipe::DrainWait drain;
        Check(drain.Start(fixture.client) && WaitDrain(drain, fixture.client),
              "drain lost a record while cancelling an overlapped read");
        std::lock_guard lock(fixture.observed.mutex);
        Check(fixture.observed.records.size() == i + 1 &&
              fixture.observed.records.back() == std::vector<byte>{static_cast<byte>(i), static_cast<byte>(i >> 8)},
              "drain completed before the record callback");
    }
}

void TestCallbacksAndBufferedRecords() {
    Fixture fixture(true);
    fixture.Send({1});
    Check(WaitForSingleObject(fixture.observed.entered.Get(), 5000) == WAIT_OBJECT_0,
          "first callback did not start");
    fixture.Send({2});
    fixture.Send({3});

    duplex_pipe::DrainWait drain;
    Check(drain.Start(fixture.client), "cannot start drain");
    Handle finished{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Check(finished.IsValid(), "cannot create wait event");
    bool result = false;
    std::thread waiter([&] { result = drain.Wait(); SetEvent(finished.Get()); });
    const bool waitedForCallback = WaitForSingleObject(finished.Get(), 100) == WAIT_TIMEOUT;
    SetEvent(fixture.observed.release.Get());
    const bool finishedInTime = WaitForSingleObject(finished.Get(), 10000) == WAIT_OBJECT_0;
    if (!finishedInTime) fixture.client.Stop();
    waiter.join();

    Check(waitedForCallback && finishedInTime && result, "drain did not wait for the callback");
    std::lock_guard lock(fixture.observed.mutex);
    Check(fixture.observed.records == std::vector<std::vector<byte>>{{1}, {2}, {3}},
          "buffered records were not delivered in order");
}

void TestLargeRecords() {
    Fixture fixture;
    for (unsigned i = 0; i < 10; ++i) {
        std::vector<byte> message(2 * 1024 * 1024 + i, static_cast<byte>(i + 1));
        fixture.Send(message);
        duplex_pipe::DrainWait drain;
        Check(drain.Start(fixture.client) && WaitDrain(drain, fixture.client),
              "large-message drain failed");
        std::lock_guard lock(fixture.observed.mutex);
        Check(fixture.observed.records.size() == i + 1 && fixture.observed.records.back() == message,
              "large message was lost or truncated during drain");
    }
}

void TestFlushSent() {
    Fixture fixture;
    const byte command[] = {4, 3, 2, 1};
    Check(fixture.client.SendRaw(command, sizeof(command)) == ERROR_SUCCESS,
          "cannot send command to service");
    Handle finished{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Check(finished.IsValid(), "cannot create flush event");
    bool result = false;
    std::thread flusher([&] { result = fixture.client.FlushSent(); SetEvent(finished.Get()); });
    const bool waitedForServer = WaitForSingleObject(finished.Get(), 100) == WAIT_TIMEOUT;
    pipe_transport::RawMessage message;
    const DWORD readStatus = pipe_transport::ReadRaw(fixture.server, message, 5000);
    const bool finishedInTime = WaitForSingleObject(finished.Get(), 10000) == WAIT_OBJECT_0;
    if (!finishedInTime) DisconnectNamedPipe(fixture.server.Pipe());
    flusher.join();
    Check(waitedForServer && finishedInTime && result && readStatus == ERROR_SUCCESS,
          "flush did not wait for the service to read the command");
    Check(message.Size() == sizeof(command) && std::memcmp(message.Data(), command, sizeof(command)) == 0,
          "flushed command was corrupted");
}

void TestExitWithInFlightRequests() {
    Fixture fixture(true, true);
    fixture.Send({11});
    Check(WaitForSingleObject(fixture.observed.entered.Get(), 5000) == WAIT_OBJECT_0,
          "request callback did not start");
    fixture.Send({12});
    duplex_pipe::DrainWait drain;
    Check(drain.Start(fixture.client), "cannot start exit drain");
    SetEvent(fixture.observed.release.Get());
    Check(WaitDrain(drain, fixture.client), "exit did not drain the received requests");

    Handle finished{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Check(finished.IsValid(), "cannot create exit flush event");
    bool flushed = false;
    std::thread flusher([&] { flushed = fixture.client.FlushSent(); SetEvent(finished.Get()); });
    const bool waitedForServer = WaitForSingleObject(finished.Get(), 100) == WAIT_TIMEOUT;
    pipe_transport::RawMessage first;
    pipe_transport::RawMessage second;
    const DWORD firstStatus = pipe_transport::ReadRaw(fixture.server, first, 5000);
    const DWORD secondStatus = pipe_transport::ReadRaw(fixture.server, second, 5000);
    const bool finishedInTime = WaitForSingleObject(finished.Get(), 10000) == WAIT_OBJECT_0;
    if (!finishedInTime) DisconnectNamedPipe(fixture.server.Pipe());
    flusher.join();
    Check(waitedForServer && finishedInTime && flushed && firstStatus == ERROR_SUCCESS &&
          secondStatus == ERROR_SUCCESS, "exit did not wait for both replies");
    Check(first.Size() == 1 && first.Data()[0] == 11 && second.Size() == 1 && second.Data()[0] == 12,
          "exit lost or reordered a reply");
}

void TestDisconnectDuringCallback() {
    Fixture fixture(true);
    fixture.Send({42});
    Check(WaitForSingleObject(fixture.observed.entered.Get(), 5000) == WAIT_OBJECT_0,
          "callback did not start before disconnect");
    duplex_pipe::DrainWait drain;
    Check(drain.Start(fixture.client), "cannot start drain before disconnect");
    const bool disconnected = DisconnectNamedPipe(fixture.server.Pipe()) != FALSE;
    SetEvent(fixture.observed.release.Get());
    Check(disconnected, "cannot disconnect test pipe");
    Check(!WaitDrain(drain, fixture.client), "disconnect was reported as a successful drain");
}

} // namespace

int main() {
    try {
        TestIdleAndRepeatedHandoffs();
        TestCallbacksAndBufferedRecords();
        TestLargeRecords();
        TestFlushSent();
        TestExitWithInFlightRequests();
        TestDisconnectDuringCallback();
        std::cout << "pipe drain tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "pipe drain test failed: " << error.what() << '\n';
        return 1;
    }
}
