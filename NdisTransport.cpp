#include "NdisTransport.h"
#include "NdisBinding.h"
#include "network_interface_watcher.h"
#include "AppInfo.h"
#include "FlowStore.h"
#include "Ingest.h"
#include "ServiceControl.h"
#include "duplex_pipe/duplex_pipe_client.h"
#include "duplex_pipe/duplex_pipe_server.h"
#include "duplex_pipe/pipe_transport.h"

#include <atomic>
#include <cstring>
#include <sddl.h>
#include <optional>
#include <utility>
#include <vector>

#ifdef FIREWALLX_TEST_VERDICTS
DriverVerdictRequest test_firewallxndisfilter_register_request(uint64_t id);
bool test_firewallxndisfilter_process_verdict(DriverVerdictRequest request,
                                     firewallxndisfilter::Client::Verdict verdict);
#endif

namespace {

using Client = firewallxndisfilter::Client;
constexpr wchar_t kLocalRequest[] = L"Global\\FirewallX.FirewallXNdisFilter.LocalRequest";
constexpr wchar_t kLocalReady[] = L"Global\\FirewallX.FirewallXNdisFilter.LocalReady";
constexpr wchar_t kProxyReady[] = L"Global\\FirewallX.FirewallXNdisFilter.ProxyReady";

SRWLOCK g_lock = SRWLOCK_INIT;
Client* g_client = nullptr;
duplex_pipe::Client* g_pipe = nullptr;
DriverVerdictSession g_session;
HANDLE g_thread = nullptr;
HANDLE g_wake = nullptr;
std::atomic<bool> g_stop{ false };
std::atomic<bool> g_ready{ false };

using Event = pipe_transport::UniqueHandle;

Ingest& Events() { return Ingest::ForSource(TrafficSource::Ndis); }
DWORD SendControlCommand(Client::Command commandType);

bool ServiceExpected() {
    FirewallX::ServiceState state;
    std::wstring error;
    return FirewallX::ServiceQuery(state, error) && state.installed &&
           state.state != 0 && state.state != SERVICE_STOPPED;
}

uint64_t FailSessionLocked() {
    const uint64_t ended = g_session.End();
    g_ready.store(false, std::memory_order_release);
    if (g_client) g_client->Stop();
    if (g_wake) SetEvent(g_wake);
    return ended;
}

void EndSession(uint64_t expected = 0) {
    AcquireSRWLockExclusive(&g_lock);
    const uint64_t ended = g_session.End(expected);
    if (ended) g_ready.store(false, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lock);
    if (ended) Events().EndDriverSession(ended);
}

// Формат raw pipe совпадает с FirewallXNdisFilter. Команды Portmaster сюда не попадают.
RPC_STATUS ForwardCommand(void* context, const byte* data, unsigned long size) noexcept {
    auto& client = *static_cast<Client*>(context);
    if (!data || !size) return ERROR_INVALID_DATA;
    if (data[0] == 1 && size == 10) {
        uint64_t id = 0;
        std::memcpy(&id, data + 1, sizeof(id));
        return client.SendVerdict(id, static_cast<Client::Verdict>(data[9]));
    }
    if (size == 1) return client.Send(static_cast<Client::Command>(data[0]));
    return ERROR_INVALID_DATA;
}

struct ServiceRoute {
    duplex_pipe::Server server{ duplex_pipe::Channel::FirewallXNdisFilter };
    SRWLOCK lock = SRWLOCK_INIT;
    bool local = true;
    HANDLE proxyReady = nullptr;
    std::wstring rulesPath = ModuleDirFile(AppInfo::kRulesDb);
    // Единственный Run-поток повторно использует буфер пересылки.
    std::vector<uint8_t> record;
};

void SwitchLocal(ServiceRoute& route, bool reload) {
    AcquireSRWLockExclusive(&route.lock);
    if (!route.local || reload) Events().ReloadServiceRules(route.rulesPath);
    route.local = true;
    ReleaseSRWLockExclusive(&route.lock);
}

void ServiceConnectionChanged(void* context, duplex_pipe::ClientConnectionEvent event) noexcept {
    auto& route = *static_cast<ServiceRoute*>(context);
    if (event == duplex_pipe::ClientConnectionEvent::Disconnected) {
        SwitchLocal(route, false);
        return;
    }
    AcquireSRWLockExclusive(&route.lock);
    route.local = false;
    if (route.proxyReady) SetEvent(route.proxyReady);
    ReleaseSRWLockExclusive(&route.lock);
}

bool ForwardRecord(ServiceRoute* route) {
    if (!route) return false;
    AcquireSRWLockExclusive(&route->lock);
    bool sent = false;
    if (!route->local) {
        sent = route->server.SendRaw(route->record.data(),
            static_cast<unsigned long>(route->record.size())) == ERROR_SUCCESS;
        if (!sent) {
            // Эта же запись обрабатывается локально уже по свежей политике.
            Events().ReloadServiceRules(route->rulesPath);
            route->local = true;
        }
    }
    ReleaseSRWLockExclusive(&route->lock);
    return sent;
}

void RecordHeader(std::vector<uint8_t>& record, uint8_t type, size_t body) {
    record.resize(5 + body);
    record[0] = type;
    const auto size = static_cast<uint32_t>(body);
    std::memcpy(record.data() + 1, &size, sizeof(size));
}

template <class Connection>
void ConnectionEvent(void* context, const Connection* connection,
                     const uint8_t* payload, uint32_t size) noexcept {
    auto* route = static_cast<ServiceRoute*>(context);
    if (route) {
        constexpr uint8_t type = sizeof(Connection) == sizeof(Client::ConnectionV4) ? 1 : 2;
        RecordHeader(route->record, type, sizeof(Connection) + sizeof(size) + size);
        uint8_t* body = route->record.data() + 5;
        std::memcpy(body, connection, sizeof(Connection));
        std::memcpy(body + sizeof(Connection), &size, sizeof(size));
        if (size) std::memcpy(body + sizeof(Connection) + sizeof(size), payload, size);
        if (ForwardRecord(route)) return;
    }
    Events().HandleNdis(*connection, payload, size);
}

template <class Bandwidth>
void BandwidthEvent(void* context, uint8_t protocol, uint32_t interface_index,
                    const Bandwidth* entries, uint32_t count) noexcept {
    auto* route = static_cast<ServiceRoute*>(context);
    if (route) {
        constexpr uint8_t type = sizeof(Bandwidth) == sizeof(Client::BandwidthV4) ? 5 : 6;
        RecordHeader(route->record, type, 9 + sizeof(Bandwidth) * count);
        uint8_t* body = route->record.data() + 5;
        body[0] = protocol;
        // Индекс передаётся без изменения, включая прозрачную пересылку.
        std::memcpy(body + 1, &interface_index, sizeof(interface_index));
        std::memcpy(body + 5, &count, sizeof(count));
        std::memcpy(body + 9, entries, sizeof(Bandwidth) * count);
        if (ForwardRecord(route)) return;
    }
    FlowStore::Instance().AddNdisBandwidthBatch(protocol, entries, count, interface_index);
}

Client::Callbacks Callbacks(ServiceRoute* route = nullptr) {
    Client::Callbacks callbacks;
    callbacks.context = route;
    callbacks.on_connection_v4 = ConnectionEvent<Client::ConnectionV4>;
    callbacks.on_connection_v6 = ConnectionEvent<Client::ConnectionV6>;
    callbacks.on_bandwidth_v4 = BandwidthEvent<Client::BandwidthV4>;
    callbacks.on_bandwidth_v6 = BandwidthEvent<Client::BandwidthV6>;
    return callbacks;
}

RPC_STATUS ReceiveRecord(void*, const byte* data, unsigned long size) noexcept {
    if (!data) return ERROR_INVALID_DATA;
    return Client::DispatchRecord({ data, size }, Callbacks());
}

struct ProxySession {
    duplex_pipe::Client pipe{ duplex_pipe::Channel::FirewallXNdisFilter };
    uint64_t session = 0;
};

void ProxyConnectionChanged(void* context, duplex_pipe::ClientConnectionEvent event) noexcept {
    auto& proxy = *static_cast<ProxySession*>(context);
    uint64_t started = 0, ended = 0;
    AcquireSRWLockExclusive(&g_lock);
    if (event == duplex_pipe::ClientConnectionEvent::Connected && !g_stop.load()) {
        g_pipe = &proxy.pipe;
        started = g_session.Begin();
        proxy.session = started;
    } else {
        const uint64_t expected = std::exchange(proxy.session, 0);
        if (expected) ended = g_session.End(expected);
        if (g_pipe == &proxy.pipe) g_pipe = nullptr;
        g_ready.store(false, std::memory_order_release);
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (started) Events().BeginDriverSession(started);
    if (ended) Events().EndDriverSession(ended);
    if (!started && g_wake) SetEvent(g_wake);
}

void RunProxy() {
    Event ready{ OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, kProxyReady) };
    if (!ready.IsValid()) return;
    ResetEvent(ready.Get());
    ProxySession proxy;
    proxy.pipe.SetConnectionCallback(ProxyConnectionChanged, &proxy);
    proxy.pipe.SetReceiveCallback(ReceiveRecord, nullptr);
    ResetEvent(g_wake);
    if (g_stop.load() || proxy.pipe.Start() != ERROR_SUCCESS) return;

    HANDLE waits[]{ g_wake, ready.Get() };
    const DWORD result = WaitForMultipleObjects(2, waits, FALSE, 30000);
    if (result == WAIT_OBJECT_0 + 1 && !g_stop.load() &&
        firewallxndisfilter_clear_cache() == ERROR_SUCCESS) {
        AcquireSRWLockShared(&g_lock);
        const bool connected = g_pipe == &proxy.pipe && g_session.active();
        g_ready.store(connected, std::memory_order_release);
        ReleaseSRWLockShared(&g_lock);
        if (connected) {
            while (!g_stop.load()) {
                if (WaitForSingleObject(g_wake, 1000) != WAIT_TIMEOUT) break;
                FlowStore::Instance().BeginNdisBandwidthPoll(GetTickCount64());
                if (SendControlCommand(Client::Command::GetBandwidthStats) != ERROR_SUCCESS) {
                    FlowStore::Instance().CancelNdisBandwidthPoll();
                    break;
                }
            }
        }
    }
    AcquireSRWLockExclusive(&g_lock);
    const uint64_t session = std::exchange(proxy.session, 0);
    if (g_pipe == &proxy.pipe) g_pipe = nullptr;
    const uint64_t ended = session ? g_session.End(session) : 0;
    g_ready.store(false, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lock);
    if (ended) Events().EndDriverSession(ended);
    proxy.pipe.Stop();
}

struct ReaderContext {
    Client* client;
    Client::Callbacks callbacks;
};

DWORD WINAPI ReadEvents(void* context) noexcept {
    auto& reader = *static_cast<ReaderContext*>(context);
    return reader.client->Run(reader.callbacks);
}

bool CreateRouteEvents(Event& request, Event& ready, Event& proxy) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
            &descriptor, nullptr)) return false;
    SECURITY_ATTRIBUTES security{ sizeof(security), descriptor, FALSE };
    request.Reset(CreateEventW(&security, FALSE, FALSE, kLocalRequest));
    ready.Reset(CreateEventW(&security, FALSE, FALSE, kLocalReady));
    proxy.Reset(CreateEventW(&security, FALSE, FALSE, kProxyReady));
    LocalFree(descriptor);
    return request.IsValid() && ready.IsValid() && proxy.IsValid();
}

using AttachedAdapters = std::vector<ndis_binding::detail::AttachedAdapter>;

HRESULT ReadAttachedAdapters(Client& client, AttachedAdapters& output) noexcept {
    try {
        std::vector<Client::AdapterState> states;
        const auto status = client.GetAdapterStates(states);
        if (status) return HRESULT_FROM_WIN32(status);
        AttachedAdapters result;
        result.reserve(states.size());
        for (const auto& state : states) {
            result.push_back({{state.guid, state.luid}, state.running});
        }
        output.swap(result);
        return S_OK;
    } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

HRESULT CheckAdapterCoverage(Client& client, const ndis_binding::detail::Targets& targets) noexcept {
    AttachedAdapters attached;
    const auto status = ReadAttachedAdapters(client, attached);
    if (FAILED(status)) return status;
    return ndis_binding::detail::AllTargetsRunning(targets, attached) ? S_OK : HRESULT_FROM_WIN32(ERROR_NOT_READY);
}

HRESULT ProcessArrivals(Client& client, std::span<const net::NetworkInterfaceWatcher::AddedInterface> pending) noexcept {
    try {
        HRESULT result = S_OK;
        for (const auto& arrival : pending) {
            if (g_stop.load()) return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
            // Один LUID может снова появиться у другого адаптера; сначала проверяем текущую привязку.
            AttachedAdapters attached;
            auto status = ReadAttachedAdapters(client, attached);
            ndis_binding::detail::Adapter added;
            if (SUCCEEDED(status)) status = ndis_binding::EnsureAdditionalBinding(
                g_stop, arrival.interface_luid, attached, added);
            if (status == S_OK) {
                status = ReadAttachedAdapters(client, attached);
                if (SUCCEEDED(status) && !added.excluded && added.expectRunning &&
                    std::count_if(attached.begin(), attached.end(), [&](const auto& module) {
                        return module.running && ndis_binding::detail::SameTarget(module.identity, added);
                    }) != 1) status = HRESULT_FROM_WIN32(ERROR_NOT_READY);
            }
            if (status == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) return status;
            if (FAILED(status)) result = status;
        }
        return result;
    } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

HRESULT ReconcileBindings(Client& client) noexcept {
    try {
        AttachedAdapters attached;
        const auto status = ReadAttachedAdapters(client, attached);
        if (FAILED(status)) return status;
        const auto missing = ndis_binding::detail::FindWindowsMissing(g_stop, attached);
        std::vector<net::NetworkInterfaceWatcher::AddedInterface> pending;
        pending.reserve(missing.size());
        for (const auto& target : missing) pending.push_back({0, target.luid});
        return ProcessArrivals(client, pending);
    } catch (const ndis_binding::detail::Error& error) { return error.status; }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

// Владеет только подпиской существующего общего watcher, не самим watcher.
struct WatcherSubscription {
    net::NetworkInterfaceWatcher& watcher;
    uint64_t id = 0;
    void Reset() { if (id) watcher.Unsubscribe(std::exchange(id, 0)); }
    ~WatcherSubscription() { Reset(); }
};

void RunDirect(bool service) {
    Client client;
    auto& interfaces = net::SharedNetworkInterfaces();
    Event adapterAdded;
    WatcherSubscription subscription{interfaces};
    bool additionsBlocked = false;
    AcquireSRWLockExclusive(&g_lock);
    g_client = &client;
    ReleaseSRWLockExclusive(&g_lock);

    ndis_binding::detail::Targets targets;
    HRESULT activated = HRESULT_FROM_WIN32(g_stop.load() ? ERROR_OPERATION_ABORTED : client.Open());
    if (SUCCEEDED(activated) && !g_stop.load()) {
        // Подписываемся до перечисления путей, чтобы не потерять появление адаптера.
        adapterAdded.Reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!adapterAdded.IsValid()) activated = HRESULT_FROM_WIN32(GetLastError());
        else {
            try {
                subscription.id = interfaces.SubscribeAdded(adapterAdded.Get());
                if (!subscription.id || !interfaces.Start()) {
                    const auto error = interfaces.LastError();
                    activated = HRESULT_FROM_WIN32(error ? error : ERROR_NOT_READY);
                }
            } catch (const std::bad_alloc&) { activated = E_OUTOFMEMORY; }
            catch (...) { activated = E_UNEXPECTED; }
        }
        AttachedAdapters attached;
        if (SUCCEEDED(activated)) activated = ReadAttachedAdapters(client, attached);
        // Preflight выполняется всегда, worker — только при доказанной неполной/ошибочной привязке.
        bool rebound = false;
        if (SUCCEEDED(activated)) activated = ndis_binding::EnsureBindings(g_stop, attached, targets, &rebound);
        if (SUCCEEDED(activated) && rebound) activated = CheckAdapterCoverage(client, targets);
    }
    if (SUCCEEDED(activated) && !g_stop.load()) {
        std::optional<ServiceRoute> route;
        Event localRequest, localReady, proxyReady;
        if (!service || CreateRouteEvents(localRequest, localReady, proxyReady)) {
            if (service) {
                route.emplace();
                route->proxyReady = proxyReady.Get();
                route->server.SetReceiveCallback(ForwardCommand, &client);
                route->server.SetConnectionCallback(ServiceConnectionChanged, &*route);
                // Драйвер мог появиться после ухода окна, когда его маршрут
                // ещё не участвовал в переключении службы на локальную обработку.
                // Читаем актуальную политику до начала сессии и первого события.
                Events().ReloadServicePolicy();
            }
            AcquireSRWLockExclusive(&g_lock);
            const uint64_t session = g_session.Begin();
            ReleaseSRWLockExclusive(&g_lock);
            Events().BeginDriverSession(session);
            bool started = client.Send(Client::Command::ClearCache) == ERROR_SUCCESS;
            if (started && route) started = route->server.Start() == ERROR_SUCCESS;
            if (started) {
                ReaderContext reader{ &client, Callbacks(route ? &*route : nullptr) };
                const HANDLE thread = CreateThread(nullptr, 0, ReadEvents, &reader, 0, nullptr);
                if (thread) {
                    g_ready.store(true, std::memory_order_release);
                    // Запрос статистики независим от таблиц Windows и основного драйвера.
                    HANDLE waits[]{ g_wake, thread, adapterAdded.Get(), localRequest.Get() };
                    constexpr ULONGLONG kReconcileIntervalMs = 30000;
                    auto nextReconcile = GetTickCount64() + kReconcileIntervalMs;
                    while (!g_stop.load()) {
                        const DWORD result = WaitForMultipleObjects(service ? 4 : 3, waits, FALSE, 1000);
                        if (result == WAIT_OBJECT_0 + 2) {
                            // Только MibAddInstance. Сессия, reader и прежние привязки остаются активными.
                            const auto pending = interfaces.TakeAdded(subscription.id);
                            if (!additionsBlocked) additionsBlocked = ProcessArrivals(client, pending) ==
                                HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED);
                        } else if (result == WAIT_OBJECT_0 + 3 && service) {
                            SwitchLocal(*route, true);
                            SetEvent(localReady.Get());
                        } else if (result == WAIT_TIMEOUT) {
                            bool poll = !service;
                            if (service) {
                                AcquireSRWLockShared(&route->lock);
                                poll = route->local;
                                ReleaseSRWLockShared(&route->lock);
                            }
                            if (poll) {
                                if (!service)
                                    FlowStore::Instance().BeginNdisBandwidthPoll(GetTickCount64());
                                if (client.Send(Client::Command::GetBandwidthStats) != ERROR_SUCCESS) break;
                            }
                        } else {
                            break;
                        }
                        // IP-уведомления не охватывают все Ethernet-адаптеры и могут прийти до появления пути.
                        const auto now = GetTickCount64();
                        if (!additionsBlocked && now >= nextReconcile && !g_stop.load()) {
                            nextReconcile = now + kReconcileIntervalMs;
                            additionsBlocked = ReconcileBindings(client) ==
                                HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED);
                        }
                    }
                    EndSession(session);
                    client.Stop();
                    WaitForSingleObject(thread, INFINITE);
                    CloseHandle(thread);
                }
            }
            // Сначала прекращаем callbacks, затем освобождаем route и сервер команд.
            EndSession(session);
            if (route) route->server.Stop();
        }
    }
    AcquireSRWLockExclusive(&g_lock);
    g_client = nullptr;
    ReleaseSRWLockExclusive(&g_lock);
    subscription.Reset();
    client.Close();
    if (FAILED(activated) && !g_stop.load()) WaitForSingleObject(g_wake, 5000);
}

DWORD WINAPI Worker(void*) noexcept {
    while (!g_stop.load()) {
        ResetEvent(g_wake);
        if (!FirewallX::IsService() && ServiceExpected()) RunProxy();
        else RunDirect(FirewallX::IsService());
        if (g_stop.load()) break;
        // После обрыва восстанавливаем только собственный маршрут.
        Sleep(100);
    }
    return 0;
}

} // namespace

DriverVerdictRequest firewallxndisfilter_register_request(uint64_t id) noexcept {
#ifdef FIREWALLX_TEST_VERDICTS
    return test_firewallxndisfilter_register_request(id);
#else
    AcquireSRWLockShared(&g_lock);
    DriverVerdictRequest request = (g_client || g_pipe)
        ? g_session.Receive(id) : DriverVerdictRequest();
    ReleaseSRWLockShared(&g_lock);
    return request;
#endif
}

bool firewallxndisfilter_process_verdict(DriverVerdictRequest request, Client::Verdict verdict) {
#ifdef FIREWALLX_TEST_VERDICTS
    return test_firewallxndisfilter_process_verdict(std::move(request), verdict);
#else
    uint64_t id = 0, ended = 0;
    bool sent = false;
    AcquireSRWLockExclusive(&g_lock);
    if (g_session.Consume(request, id)) {
        if (g_pipe) {
            uint8_t command[10]{ 1 };
            std::memcpy(command + 1, &id, sizeof(id));
            command[9] = static_cast<uint8_t>(verdict);
            sent = g_pipe->SendRaw(command, sizeof(command)) == ERROR_SUCCESS;
        } else if (g_client) {
            // Только FirewallXNdisFilter: совпавший id Portmaster не имеет здесь значения.
            sent = g_client->SendVerdict(id, verdict) == ERROR_SUCCESS;
        }
        if (!sent) {
            ended = FailSessionLocked();
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (ended) Events().EndDriverSession(ended);
    return sent;
#endif
}

namespace {

DWORD SendControlCommand(Client::Command commandType) {
    DWORD status = ERROR_SUCCESS;
    uint64_t ended = 0;
    AcquireSRWLockExclusive(&g_lock);
    if (g_session.active()) {
        if (g_pipe) {
            const byte command = static_cast<byte>(commandType);
            status = g_pipe->SendRaw(&command, sizeof(command));
        } else if (g_client) {
            status = g_client->Send(commandType);
        }
        if (status != ERROR_SUCCESS) {
            ended = FailSessionLocked();
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (ended) Events().EndDriverSession(ended);
    return status;
}

} // namespace

DWORD firewallxndisfilter_clear_cache() {
    return SendControlCommand(Client::Command::ClearCache);
}

bool firewallxndisfilter_running() { return g_ready.load(std::memory_order_acquire); }

bool firewallxndisfilter_service_connected() {
    AcquireSRWLockShared(&g_lock);
    const bool connected = g_pipe != nullptr;
    ReleaseSRWLockShared(&g_lock);
    return connected;
}

bool firewallxndisfilter_service_process_locally() {
    AcquireSRWLockShared(&g_lock);
    const uint64_t expected = g_pipe ? g_session.active() : 0;
    ReleaseSRWLockShared(&g_lock);
    if (!expected) return true;
    Event request{ OpenEventW(EVENT_MODIFY_STATE, FALSE, kLocalRequest) };
    Event ready{ OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, kLocalReady) };
    if (!request.IsValid() || !ready.IsValid()) return false;
    ResetEvent(ready.Get());
    if (!SetEvent(request.Get()) || WaitForSingleObject(ready.Get(), INFINITE) != WAIT_OBJECT_0)
        return false;

    duplex_pipe::DrainWait drain;
    AcquireSRWLockShared(&g_lock);
    const bool started = g_pipe && g_session.active() == expected && drain.Start(*g_pipe);
    ReleaseSRWLockShared(&g_lock);
    const bool drained = started && drain.Wait();
    AcquireSRWLockShared(&g_lock);
    const bool connected = g_pipe && g_session.active() == expected;
    ReleaseSRWLockShared(&g_lock);
    return drained && connected;
}

bool firewallxndisfilter_service_flush_verdicts() {
    AcquireSRWLockShared(&g_lock);
    const bool flushed = !g_pipe || g_pipe->FlushSent();
    ReleaseSRWLockShared(&g_lock);
    return flushed;
}

void firewallxndisfilter_start() {
    AcquireSRWLockExclusive(&g_lock);
    if (!g_thread) {
        g_stop.store(false);
        g_wake = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_wake) g_thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (!g_thread && g_wake) {
            CloseHandle(g_wake);
            g_wake = nullptr;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void firewallxndisfilter_stop() {
    g_stop.store(true);
    AcquireSRWLockShared(&g_lock);
    const HANDLE thread = g_thread;
    ReleaseSRWLockShared(&g_lock);
    if (!thread) return;
    // Stop может опередить вход Worker в Open, который сбрасывает свой stop-флаг.
    // Повторная отмена во время join закрывает это окно без тайм-аута у Open.
    for (;;) {
        AcquireSRWLockShared(&g_lock);
        if (g_wake) SetEvent(g_wake);
        if (g_client) g_client->Stop();
        ReleaseSRWLockShared(&g_lock);
        if (WaitForSingleObject(thread, 50) == WAIT_OBJECT_0) break;
    }
    EndSession();
    AcquireSRWLockExclusive(&g_lock);
    CloseHandle(g_thread);
    g_thread = nullptr;
    CloseHandle(g_wake);
    g_wake = nullptr;
    g_pipe = nullptr;
    ReleaseSRWLockExclusive(&g_lock);
}
