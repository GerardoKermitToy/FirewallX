#pragma once
#include "NdisBindingAsync.h"
#include <memory>
#include <stdexcept>
#include <thread>

namespace ndis_binding_tests {

struct QueryGate {
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE exited = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<unsigned> calls{0};
    ~QueryGate() {
        if (entered) CloseHandle(entered);
        if (release) CloseHandle(release);
        if (exited) CloseHandle(exited);
    }
};
inline std::atomic<std::shared_ptr<QueryGate>> queryGate;

inline ndis_binding::detail::Targets BlockingQuery(const std::atomic<bool>&) {
    const auto gate = queryGate.load();
    ++gate->calls;
    SetEvent(gate->entered);
    // Намеренно игнорируем stop, как зависший синхронный вызов NetCfg.
    WaitForSingleObject(gate->release, INFINITE);
    ndis_binding::detail::Adapter target;
    target.luid = 123;
    SetEvent(gate->exited);
    return {target};
}
inline ndis_binding::detail::Targets ImmediateQuery(const std::atomic<bool>&) {
    ndis_binding::detail::Adapter target;
    target.luid = 456;
    return {target};
}
inline ndis_binding::detail::Targets FailedQuery(const std::atomic<bool>&) {
    throw ndis_binding::detail::Error{ E_ACCESSDENIED };
}

inline void AsyncRequire(bool value) {
    if (!value) throw std::runtime_error("asynchronous topology query assertion failed");
}
inline void AsyncCancellationTest() {
    using namespace ndis_binding::detail;
    auto gate = std::make_shared<QueryGate>();
    AsyncRequire(gate->entered && gate->release && gate->exited);
    queryGate.store(gate);
    TargetResolver resolver;
    std::atomic<bool> stopped{false};
    HRESULT status = E_PENDING;
    const HANDLE returned = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    AsyncRequire(returned != nullptr);
    std::thread caller([&] {
        try { resolver.Resolve(stopped, BlockingQuery, 10000); status = S_OK; }
        catch (const Error& error) { status = error.status; }
        SetEvent(returned);
    });
    const bool entered = WaitForSingleObject(gate->entered, 5000) == WAIT_OBJECT_0;
    stopped.store(true);
    const bool bounded = WaitForSingleObject(returned, 1500) == WAIT_OBJECT_0;
    // Даже неудачный тест выпускает поддельный провайдер перед join.
    if (!bounded) SetEvent(gate->release);
    caller.join();
    CloseHandle(returned);
    bool busy = false;
    if (bounded && entered) {
        std::atomic<bool> retryStop{false};
        try { resolver.Resolve(retryStop, ImmediateQuery); }
        catch (const Error& error) { busy = error.status == HRESULT_FROM_WIN32(ERROR_BUSY); }
    }
    SetEvent(gate->release);
    const bool exited = WaitForSingleObject(gate->exited, 5000) == WAIT_OBJECT_0;
    AsyncRequire(entered && bounded && exited && busy && gate->calls == 1 &&
        status == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED));
}
inline void AsyncTimeoutAndLifetimeTest() {
    using namespace ndis_binding::detail;
    auto gate = std::make_shared<QueryGate>();
    AsyncRequire(gate->entered && gate->release && gate->exited);
    queryGate.store(gate);
    std::atomic<bool> stopped{false};
    HRESULT status = E_PENDING;
    const auto started = GetTickCount64();
    {
        TargetResolver resolver;
        try { resolver.Resolve(stopped, BlockingQuery, 500); }
        catch (const Error& error) { status = error.status; }
    }
    const bool bounded = GetTickCount64() - started < 2000;
    // Сам resolver и вызывающий System уже могут быть уничтожены.
    SetEvent(gate->release);
    const bool exited = WaitForSingleObject(gate->exited, 5000) == WAIT_OBJECT_0;
    AsyncRequire(bounded && exited && gate->calls == 1 && status == HRESULT_FROM_WIN32(ERROR_TIMEOUT));
}
inline void AsyncOwnedSnapshotTest() {
    using namespace ndis_binding::detail;
    auto gate = std::make_shared<QueryGate>();
    auto snapshot = std::make_shared<std::vector<uint64_t>>(std::initializer_list<uint64_t>{123, 456});
    std::weak_ptr<std::vector<uint64_t>> retained = snapshot;
    std::atomic<bool> stopped{false};
    HRESULT status = E_PENDING;
    {
        TargetResolver resolver;
        try {
            resolver.Resolve(stopped, [gate, owned = std::move(snapshot)](const std::atomic<bool>&) {
                ++gate->calls;
                SetEvent(gate->entered);
                WaitForSingleObject(gate->release, INFINITE);
                Targets result;
                for (const auto luid : *owned) { Adapter target; target.luid = luid; result.push_back(target); }
                SetEvent(gate->exited);
                return result;
            }, 500);
        } catch (const Error& error) { status = error.status; }
    }
    const bool held = !retained.expired();
    SetEvent(gate->release);
    const bool exited = WaitForSingleObject(gate->exited, 5000) == WAIT_OBJECT_0;
    const auto deadline = GetTickCount64() + 5000;
    while (!retained.expired() && GetTickCount64() < deadline) Sleep(1);
    AsyncRequire(status == HRESULT_FROM_WIN32(ERROR_TIMEOUT) && held && exited && retained.expired());
}

inline void AsyncSuccessAndFailureTest() {
    using namespace ndis_binding::detail;
    std::atomic<bool> stopped{false};
    TargetResolver resolver;
    AsyncRequire(resolver.Resolve(stopped, ImmediateQuery).front().luid == 456);
    const auto captured = resolver.Resolve(stopped, [identities = std::vector<uint64_t>{42, 84}](const std::atomic<bool>&) {
        Targets result;
        for (const auto luid : identities) { Adapter target; target.luid = luid; result.push_back(target); }
        return result;
    });
    AsyncRequire(captured.size() == 2 && captured[0].luid == 42 && captured[1].luid == 84);
    HRESULT status = S_OK;
    try { resolver.Resolve(stopped, FailedQuery); }
    catch (const Error& error) { status = error.status; }
    AsyncRequire(status == E_ACCESSDENIED);
    stopped.store(true);
    try { resolver.Resolve(stopped, ImmediateQuery); status = S_OK; }
    catch (const Error& error) { status = error.status; }
    AsyncRequire(status == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED));
}

} // namespace ndis_binding_tests
