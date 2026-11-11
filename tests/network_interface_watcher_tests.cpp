#include "network_interface_watcher.h"
#include "MacroAddr.h"
#include "Rules.h"
#include "StringRes.h"
#include "Settings.h"
#include <netioapi.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace {
using Watcher = net::NetworkInterfaceWatcher;
using Interface = Watcher::InterfaceInfo;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Predicate>
void WaitUntil(Predicate predicate) {
    const auto deadline = GetTickCount64() + 3000;
    while (!predicate()) {
        Check(GetTickCount64() < deadline, "timed out waiting for watcher");
        Sleep(1);
    }
}

struct RegistryKey {
    std::wstring path;
    HANDLE event = nullptr;
};

std::mutex fixtureMutex;
std::vector<Interface> adapters;
std::vector<RegistryKey*> registryKeys;
PIPINTERFACE_CHANGE_CALLBACK interfaceCallback = nullptr;
PUNICAST_IPADDRESS_CHANGE_CALLBACK addressCallback = nullptr;
PIPFORWARD_CHANGE_CALLBACK routeCallback = nullptr;
void* notificationContext = nullptr;
ULONG enumerationError = ERROR_SUCCESS;
ULONG notificationError = ERROR_SUCCESS;
LSTATUS registryError = ERROR_SUCCESS;
std::function<void()> enumerationHook;
std::atomic<unsigned> enumerationCalls{0};
std::atomic<unsigned> enumerations{0};
std::atomic<unsigned> registrations{0};
std::atomic<ULONGLONG> macroTick{100000};

void ResetFixture() {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    Check(registryKeys.empty() && registrations == 0, "watcher leaked registrations");
    adapters.clear();
    enumerationError = notificationError = ERROR_SUCCESS;
    registryError = ERROR_SUCCESS;
    enumerationHook = {};
    enumerationCalls = enumerations = 0;
    macroTick = 100000;
}

IpAddr Ip4(BYTE a, BYTE b, BYTE c, BYTE d) {
    const BYTE bytes[]{a, b, c, d};
    return IpAddr::Raw4(bytes);
}

IpAddr Ip6(BYTE last) {
    IpAddr ip;
    ip.family = AF_INET6;
    ip.b[0] = 0x20;
    ip.b[1] = 0x01;
    ip.b[2] = 0x0d;
    ip.b[3] = 0xb8;
    ip.b[15] = last;
    return ip;
}

std::vector<Interface> SampleAdapters() {
    Interface ethernet;
    ethernet.number = 7;
    ethernet.ipv6_number = 17;
    ethernet.luid = 1007;
    ethernet.name = L"Ethernet";
    ethernet.up = true;
    ethernet.unicast = {{Ip4(10, 23, 4, 5), 24}, {Ip6(5), 64}};
    ethernet.dns_servers = {Ip4(1, 1, 1, 1), Ip6(53), Ip4(1, 1, 1, 1)};
    ethernet.gateways = {Ip4(10, 23, 4, 1), Ip6(1)};
    ethernet.wins_servers = {Ip4(10, 23, 4, 2)};

    Interface loopback;
    loopback.number = loopback.ipv6_number = 1;
    loopback.name = L"Loopback";
    loopback.up = loopback.loopback = true;
    IpAddr lo6;
    lo6.family = AF_INET6;
    lo6.b[15] = 1;
    loopback.unicast = {{Ip4(127, 0, 0, 1), 8}, {lo6, 128}};

    Interface down;
    down.number = 11;
    down.name = L"Disconnected";
    down.unicast = {{Ip4(172, 16, 0, 2), 16}};
    down.dns_servers = {Ip4(9, 9, 9, 9)};

    Interface ipv6;
    ipv6.ipv6_number = 21;
    ipv6.up = true;
    ipv6.unicast = {{Ip6(21), 128}};
    return {ethernet, loopback, down, ipv6};
}

void SetAdapters(std::vector<Interface> value) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    adapters = std::move(value);
}

// Все указатели IP Helper указывают внутрь предоставленного ему буфера.
class WireBuffer {
public:
    explicit WireBuffer(void* data) : next_(static_cast<BYTE*>(data)) {}

    template<class T>
    T* Make(size_t count = 1) {
        const auto aligned = (reinterpret_cast<uintptr_t>(next_) + alignof(T) - 1) &
                             ~(static_cast<uintptr_t>(alignof(T)) - 1);
        auto* result = reinterpret_cast<T*>(aligned);
        for (size_t i = 0; i < count; ++i) std::construct_at(result + i);
        next_ = reinterpret_cast<BYTE*>(result + count);
        return result;
    }

    SOCKET_ADDRESS Socket(const IpAddr& ip) {
        if (ip.family == AF_INET) {
            auto* value = Make<sockaddr_in>();
            value->sin_family = AF_INET;
            std::memcpy(&value->sin_addr, ip.b, 4);
            return {reinterpret_cast<sockaddr*>(value), sizeof(*value)};
        }
        auto* value = Make<sockaddr_in6>();
        value->sin6_family = ip.family;
        std::memcpy(&value->sin6_addr, ip.b, 16);
        return {reinterpret_cast<sockaddr*>(value), sizeof(*value)};
    }

    template<class T>
    T* Addresses(const std::vector<IpAddr>& source) {
        T* head = nullptr;
        T** tail = &head;
        for (const auto& ip : source) {
            auto* item = Make<T>();
            item->Address = Socket(ip);
            *tail = item;
            tail = &item->Next;
        }
        return head;
    }

private:
    BYTE* next_;
};

ULONG WINAPI TestGetAdaptersAddresses(ULONG family, ULONG flags, PVOID,
                                      PIP_ADAPTER_ADDRESSES output, PULONG size) {
    ++enumerationCalls;
    Check(family == AF_UNSPEC && (flags & GAA_FLAG_INCLUDE_GATEWAYS) &&
          (flags & GAA_FLAG_INCLUDE_WINS_INFO) && !(flags & GAA_FLAG_SKIP_DNS_SERVER) &&
          !(flags & GAA_FLAG_SKIP_UNICAST) && !(flags & GAA_FLAG_SKIP_FRIENDLY_NAME),
          "incomplete adapter enumeration flags");
    std::vector<Interface> source;
    std::function<void()> hook;
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        if (enumerationError != ERROR_SUCCESS) return enumerationError;
        if (*size < 64 * 1024) {
            *size = 64 * 1024;
            return ERROR_BUFFER_OVERFLOW;
        }
        source = adapters;
        hook = std::exchange(enumerationHook, {});
    }
    ++enumerations;
    if (hook) hook();
    if (source.empty()) return ERROR_NO_DATA;

    WireBuffer buffer(output);
    IP_ADAPTER_ADDRESSES** tail = &output;
    for (const auto& adapter : source) {
        auto* item = buffer.Make<IP_ADAPTER_ADDRESSES>();
        item->Length = sizeof(*item);
        item->IfIndex = adapter.number;
        item->Ipv6IfIndex = adapter.ipv6_number;
        item->Luid.Value = adapter.luid;
        item->IfType = adapter.loopback ? IF_TYPE_SOFTWARE_LOOPBACK : IF_TYPE_ETHERNET_CSMACD;
        item->OperStatus = adapter.up ? IfOperStatusUp : IfOperStatusDown;
        item->FriendlyName = buffer.Make<wchar_t>(adapter.name.size() + 1);
        std::copy(adapter.name.begin(), adapter.name.end(), item->FriendlyName);
        IP_ADAPTER_UNICAST_ADDRESS** unicastTail = &item->FirstUnicastAddress;
        for (const auto& address : adapter.unicast) {
            auto* unicast = buffer.Make<IP_ADAPTER_UNICAST_ADDRESS>();
            unicast->Address = buffer.Socket(address.address);
            unicast->OnLinkPrefixLength = address.prefix_length;
            *unicastTail = unicast;
            unicastTail = &unicast->Next;
        }
        item->FirstDnsServerAddress = buffer.Addresses<IP_ADAPTER_DNS_SERVER_ADDRESS>(adapter.dns_servers);
        item->FirstWinsServerAddress = buffer.Addresses<IP_ADAPTER_WINS_SERVER_ADDRESS>(adapter.wins_servers);
        item->FirstGatewayAddress = buffer.Addresses<IP_ADAPTER_GATEWAY_ADDRESS>(adapter.gateways);
        *tail = item;
        tail = &item->Next;
    }
    return NO_ERROR;
}

ULONG NETIOAPI_API_ TestNotifyIpInterfaceChange(ADDRESS_FAMILY, PIPINTERFACE_CHANGE_CALLBACK callback,
                                               PVOID context, BOOLEAN, HANDLE* handle) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    interfaceCallback = callback;
    notificationContext = context;
    *handle = reinterpret_cast<HANDLE>(1);
    ++registrations;
    return NO_ERROR;
}
ULONG NETIOAPI_API_ TestNotifyUnicastIpAddressChange(ADDRESS_FAMILY, PUNICAST_IPADDRESS_CHANGE_CALLBACK callback,
                                                   PVOID context, BOOLEAN, HANDLE* handle) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    if (notificationError != ERROR_SUCCESS) return notificationError;
    addressCallback = callback;
    notificationContext = context;
    *handle = reinterpret_cast<HANDLE>(2);
    ++registrations;
    return NO_ERROR;
}
ULONG NETIOAPI_API_ TestNotifyRouteChange2(ADDRESS_FAMILY, PIPFORWARD_CHANGE_CALLBACK callback,
                                        PVOID context, BOOLEAN, HANDLE* handle) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    routeCallback = callback;
    notificationContext = context;
    *handle = reinterpret_cast<HANDLE>(3);
    ++registrations;
    return NO_ERROR;
}
ULONG NETIOAPI_API_ TestCancelMibChangeNotify2(HANDLE handle) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    if (handle == reinterpret_cast<HANDLE>(1)) interfaceCallback = nullptr;
    if (handle == reinterpret_cast<HANDLE>(2)) addressCallback = nullptr;
    if (handle == reinterpret_cast<HANDLE>(3)) routeCallback = nullptr;
    --registrations;
    return NO_ERROR;
}

LSTATUS WINAPI TestRegOpenKeyExW(HKEY, LPCWSTR path, DWORD, REGSAM, PHKEY result) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    // Проверяем также наблюдение за отсутствующим необязательным ключом.
    if (std::wstring_view(path).ends_with(L"DNSClient")) return ERROR_FILE_NOT_FOUND;
    auto* key = new RegistryKey{path};
    registryKeys.push_back(key);
    *result = reinterpret_cast<HKEY>(key);
    return ERROR_SUCCESS;
}
LSTATUS WINAPI TestRegNotifyChangeKeyValue(HKEY handle, BOOL subtree, DWORD filter, HANDLE event, BOOL async) {
    Check(subtree && async && (filter & REG_NOTIFY_THREAD_AGNOSTIC), "invalid registry watch flags");
    std::lock_guard<std::mutex> lock(fixtureMutex);
    if (registryError != ERROR_SUCCESS) return std::exchange(registryError, ERROR_SUCCESS);
    reinterpret_cast<RegistryKey*>(handle)->event = event;
    return ERROR_SUCCESS;
}
LSTATUS WINAPI TestRegCloseKey(HKEY handle) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    auto* key = reinterpret_cast<RegistryKey*>(handle);
    std::erase(registryKeys, key);
    delete key;
    return ERROR_SUCCESS;
}

void NotifyInterface(MIB_NOTIFICATION_TYPE type = MibParameterNotification,
                     ADDRESS_FAMILY family = AF_INET, ULONG index = 7, uint64_t luid = 77) {
    PIPINTERFACE_CHANGE_CALLBACK callback;
    void* context;
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        callback = interfaceCallback;
        context = notificationContext;
    }
    Check(callback != nullptr, "missing interface notification registration");
    MIB_IPINTERFACE_ROW row{};
    row.Family = family;
    row.InterfaceIndex = index;
    row.InterfaceLuid.Value = luid;
    callback(context, &row, type);
}

void NotifyAddress() {
    PUNICAST_IPADDRESS_CHANGE_CALLBACK callback;
    void* context;
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        callback = addressCallback;
        context = notificationContext;
    }
    Check(callback != nullptr, "missing address notification registration");
    MIB_UNICASTIPADDRESS_ROW row{};
    row.Address.si_family = AF_INET6;
    row.InterfaceIndex = 17;
    callback(context, &row, MibParameterNotification);
}

void NotifyRoute() {
    PIPFORWARD_CHANGE_CALLBACK callback;
    void* context;
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        callback = routeCallback;
        context = notificationContext;
    }
    Check(callback != nullptr, "missing route notification registration");
    MIB_IPFORWARD_ROW2 row{};
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.InterfaceIndex = 7;
    callback(context, &row, MibParameterNotification);
}

void NotifyRegistry(std::wstring_view path) {
    std::lock_guard<std::mutex> lock(fixtureMutex);
    for (const auto* key : registryKeys) {
        if (key->path.find(path) != std::wstring::npos) {
            Check(SetEvent(key->event) != FALSE, "failed to signal registry fixture");
            return;
        }
    }
    Check(false, "missing registry notification registration");
}

ULONGLONG TestMacroTick() { return macroTick.load(); }
} // namespace

#define GetAdaptersAddresses TestGetAdaptersAddresses
#define NotifyIpInterfaceChange TestNotifyIpInterfaceChange
#define NotifyUnicastIpAddressChange TestNotifyUnicastIpAddressChange
#define NotifyRouteChange2 TestNotifyRouteChange2
#define CancelMibChangeNotify2 TestCancelMibChangeNotify2
#define RegOpenKeyExW TestRegOpenKeyExW
#define RegNotifyChangeKeyValue TestRegNotifyChangeKeyValue
#define RegCloseKey TestRegCloseKey
#include "../network_interface_watcher.cpp"
#undef GetAdaptersAddresses
#undef NotifyIpInterfaceChange
#undef NotifyUnicastIpAddressChange
#undef NotifyRouteChange2
#undef CancelMibChangeNotify2
#undef RegOpenKeyExW
#undef RegNotifyChangeKeyValue
#undef RegCloseKey

#define GetTickCount64 TestMacroTick
#include "../MacroAddr.cpp"
#undef GetTickCount64

namespace {
void TestAddedNotifications() {
    ResetFixture();
    SetAdapters(SampleAdapters());
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE addedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(entered && release && addedEvent, "arrival events could not be created");
    std::atomic<unsigned> callbacks{0};
    Watcher watcher([&](const Watcher::ChangeEvent&) {
        if (++callbacks == 1) {
            SetEvent(entered);
            WaitForSingleObject(release, 3000);
        }
    });
    Check(watcher.Start(), "shared watcher did not start");
    const auto initialRegistrations = registrations.load();
    const auto initialEnumerations = enumerationCalls.load();
    const auto token = watcher.SubscribeAdded(addedEvent);
    Check(token && registrations == initialRegistrations && enumerationCalls == initialEnumerations,
        "arrival subscription duplicated native registrations or enumerated adapters");
    Check(WaitForSingleObject(addedEvent, 0) == WAIT_TIMEOUT, "initial interfaces were replayed as new");
    watcher.RequestRefresh();
    Check(WaitForSingleObject(entered, 3000) == WAIT_OBJECT_0, "generic callback did not block");
    NotifyInterface(MibParameterNotification);
    NotifyInterface(MibDeleteInstance);
    NotifyInterface(MibInitialNotification);
    NotifyAddress(); NotifyRoute(); NotifyRegistry(L"Dnscache");
    Check(WaitForSingleObject(addedEvent, 0) == WAIT_TIMEOUT && watcher.TakeAdded(token).empty(),
        "a route/address/change/removal was reported as adapter arrival");
    NotifyInterface(MibAddInstance, AF_INET, 23, 2300);
    NotifyAddress(); NotifyRoute();
    NotifyInterface(MibDeleteInstance, AF_INET, 23, 2300);
    NotifyInterface(MibAddInstance, AF_INET6, 23, 2300);
    NotifyInterface(MibAddInstance, AF_INET, 24, 2400);
    Check(WaitForSingleObject(addedEvent, 0) == WAIT_OBJECT_0,
        "separate arrival delivery waited for the blocked generic subscriber");
    const auto added = watcher.TakeAdded(token);
    Check(added.size() == 2 && added[0].interface_luid == 2300 && added[0].interface_index == 23 &&
        added[1].interface_luid == 2400 && added[1].interface_index == 24,
        "mixed notifications lost Added or IPv4/IPv6 duplicated the same queued arrival");
    Check(WaitForSingleObject(addedEvent, 0) == WAIT_TIMEOUT && watcher.TakeAdded(token).empty(),
        "draining arrivals did not reset the event and queue together");
    watcher.Unsubscribe(token);
    NotifyInterface(MibAddInstance, AF_INET, 25, 2500);
    Check(WaitForSingleObject(addedEvent, 0) == WAIT_TIMEOUT, "unsubscribed event was signaled");
    SetEvent(release);
    watcher.Stop();
    Check(registrations == 0, "arrival subscription leaked a native registration");
    CloseHandle(addedEvent); CloseHandle(release); CloseHandle(entered);
}

void TestSnapshots() {
    ResetFixture();
    SetAdapters(SampleAdapters());
    Watcher watcher;
    Check(!watcher.GetSnapshot() && watcher.GetInterfaceCount() == 0, "unexpected initial snapshot");
    Check(watcher.Start() && watcher.Start(), "watcher did not start");
    const auto original = watcher.GetSnapshot();
    Check(original && original->version && original->interfaces.size() == 4, "incomplete initial snapshot");
    Check(watcher.GetInterfaceName(7) == L"Ethernet" && watcher.GetInterfaceNameByIndex(17) == L"Ethernet" &&
          watcher.GetInterfaceNumberByName(L"Ethernet") == 7u && !watcher.GetInterfaceName(0),
          "interface lookup failed");
    Check(original->interfaces[3].number == 21 && original->interfaces[3].name.empty(),
          "IPv6-only unnamed interface was lost");
    const auto& ethernet = original->interfaces.front();
    Check(ethernet.up && !ethernet.loopback && ethernet.unicast.size() == 2 &&
          ethernet.unicast[1].address == Ip6(5) && ethernet.unicast[1].prefix_length == 64 &&
          ethernet.dns_servers.size() == 3 && ethernet.gateways.size() == 2 && ethernet.wins_servers.size() == 1,
          "interface address lists were not copied");
    Check(!original->interfaces[2].up && original->interfaces[1].loopback, "interface state was lost");
    auto copy = watcher.GetInterfaces();
    copy.front().name.clear();
    Check(watcher.GetInterfaceName(7) == L"Ethernet", "caller changed immutable snapshot");
    const auto reads = enumerationCalls.load();
    for (int i = 0; i < 100; ++i) watcher.GetSnapshot();
    Sleep(20);
    Check(enumerationCalls == reads, "watcher polled without a notification");

    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        enumerationError = ERROR_GEN_FAILURE;
    }
    Check(!watcher.Refresh() && watcher.LastError() == ERROR_GEN_FAILURE && watcher.GetSnapshot() == original,
          "failed enumeration replaced the last full snapshot");
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        enumerationError = ERROR_SUCCESS;
    }
    SetAdapters({});
    Check(watcher.Refresh() && watcher.GetInterfaceCount() == 0 &&
          watcher.GetSnapshot()->version > original->version && original->interfaces.size() == 4,
          "empty snapshot or retained reader was corrupted");
    Check(watcher.GetInterfaceNumberByName(L"Ethernet", original) == 7u &&
              !watcher.GetInterfaceNumberByName(L"Ethernet"),
          "snapshot-bound lookup changed beneath its reader");
    watcher.Stop();
    watcher.Stop();
    Check(!watcher.IsRunning() && registrations == 0, "watcher did not stop");
}

void TestNotificationsAndRaces() {
    ResetFixture();
    SetAdapters(SampleAdapters());
    std::atomic<unsigned> callbacks{0};
    std::atomic<unsigned> discarded{0};
    std::atomic<std::uint32_t> flags{0};
    Watcher watcher([&](const Watcher::ChangeEvent& event) {
        flags = static_cast<std::uint32_t>(event.changes);
        if (!event.snapshot_updated) ++discarded;
        ++callbacks;
    });
    Check(watcher.Start() && callbacks == 0, "unexpected initial callback");
    auto source = SampleAdapters();
    source[0].dns_servers = {Ip4(8, 8, 8, 8)};
    SetAdapters(source);
    NotifyRegistry(L"Dnscache");
    WaitUntil([&] { return callbacks.load() == 1; });
    Check(watcher.GetSnapshot()->interfaces[0].dns_servers[0] == Ip4(8, 8, 8, 8) &&
          Watcher::HasChange(static_cast<Watcher::ChangeFlags>(flags.load()), Watcher::ChangeFlags::DnsServers),
          "DNS registry change did not refresh the shared snapshot");
    source[0].unicast[1].address = Ip6(8);
    SetAdapters(source);
    NotifyAddress();
    WaitUntil([&] { return callbacks.load() == 2; });
    Check(watcher.GetSnapshot()->interfaces[0].unicast[1].address == Ip6(8), "address change was lost");
    source[0].gateways = {Ip4(10, 23, 4, 254)};
    SetAdapters(source);
    NotifyRoute();
    WaitUntil([&] { return callbacks.load() == 3; });
    Check(watcher.GetSnapshot()->interfaces[0].gateways[0] == Ip4(10, 23, 4, 254), "route change was lost");

    const auto stable = watcher.GetSnapshot();
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        enumerationHook = [] {
            SetAdapters({});
            NotifyInterface(MibDeleteInstance);
        };
    }
    watcher.RequestRefresh();
    WaitUntil([&] { return watcher.GetSnapshot()->interfaces.empty(); });
    Check(watcher.GetSnapshot()->version == stable->version + 1 && discarded >= 1,
          "enumeration raced with deletion and published an obsolete snapshot");

    // Реестр может удалить ключ между уведомлением и повторной регистрацией.
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        registryError = ERROR_KEY_DELETED;
    }
    const auto version = watcher.GetSnapshot()->version;
    NotifyRegistry(L"Dnscache");
    WaitUntil([&] { return watcher.GetSnapshot()->version > version; });
    Check(watcher.IsRunning(), "deleted registry key stopped monitoring");
    watcher.Stop();
}

void TestLifecycleAndCoalescing() {
    ResetFixture();
    SetAdapters(SampleAdapters());
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        notificationError = ERROR_ACCESS_DENIED;
    }
    Watcher failed;
    Check(!failed.Start() && !failed.IsRunning() && registrations == 0 && failed.Refresh(),
          "registration failure leaked resources or prevented standalone refresh");
    failed.Stop();
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        notificationError = ERROR_SUCCESS;
    }

    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(entered && release, "failed to create callback fixture events");
    std::atomic<unsigned> callbacks{0};
    {
        Watcher watcher([&](const Watcher::ChangeEvent&) {
            if (++callbacks == 1) {
                SetEvent(entered);
                WaitForSingleObject(release, 3000);
                throw std::runtime_error("intentional callback failure");
            }
        });
        Check(watcher.Start(), "coalescing watcher did not start");
        const auto before = enumerations.load();
        watcher.RequestRefresh();
        Check(WaitForSingleObject(entered, 3000) == WAIT_OBJECT_0, "callback did not run");
        for (int i = 0; i < 1000; ++i) watcher.RequestRefresh();
        SetEvent(release);
        WaitUntil([&] { return callbacks.load() == 2; });
        Check(enumerations == before + 2 && watcher.IsRunning(), "notifications were not coalesced");
        watcher.Stop();
        Check(watcher.Start(), "watcher did not restart after stop");
    }
    CloseHandle(entered);
    CloseHandle(release);

    std::atomic<bool> stopped{false};
    Watcher* pointer = nullptr;
    Watcher fromCallback([&](const Watcher::ChangeEvent&) {
        pointer->Stop();
        stopped = !pointer->Start() && pointer->LastError() == ERROR_BUSY;
    });
    pointer = &fromCallback;
    Check(fromCallback.Start(), "callback-stop watcher did not start");
    fromCallback.RequestRefresh();
    WaitUntil([&] { return stopped.load(); });
    fromCallback.Stop();
    Check(fromCallback.Start(), "watcher could not restart outside its callback");
    fromCallback.Stop();
}

void TestMacros() {
    ResetFixture();
    auto source = SampleAdapters();
    SetAdapters(source);
    const auto version = AddrMacros::Version(true);
    Check(version != 0 && AddrMacros::Resolve(AddrMacro::DnsServers).size() == 2 &&
          AddrMacros::Matches(AddrMacro::DnsServers, Ip4(1, 1, 1, 1)) &&
          !AddrMacros::Matches(AddrMacro::DnsServers, Ip4(9, 9, 9, 9)) &&
          AddrMacros::Matches(AddrMacro::LocalNetwork, Ip4(10, 23, 4, 199)) &&
          AddrMacros::Matches(AddrMacro::LocalNetwork, Ip6(200)) &&
          AddrMacros::Matches(AddrMacro::WinsServers, Ip4(10, 23, 4, 2)) &&
          AddrMacros::Matches(AddrMacro::Gateways, Ip6(1)) &&
          AddrMacros::Matches(AddrMacro::MyComputer, Ip4(127, 2, 3, 4)) &&
          !AddrMacros::Matches(AddrMacro::AllMyAddresses, Ip4(127, 0, 0, 1)) &&
          !AddrMacros::Matches(AddrMacro::AllMyAddresses, Ip4(172, 16, 0, 2)) &&
          AddrMacros::Matches(AddrMacro::AllMyAddresses, Ip6(21)) &&
          AddrMacros::Matches(AddrMacro::BroadcastAddresses, Ip4(10, 23, 4, 255)) &&
          AddrMacros::Matches(AddrMacro::BroadcastAddresses, Ip4(255, 255, 255, 255)) &&
          AddrMacros::Matches(AddrMacro::MulticastAddresses, Ip4(239, 1, 2, 3)),
          "macro semantics changed after switching to the watcher");
    const auto reads = enumerationCalls.load();
    macroTick += AddrMacros::kCacheTtlMs * 2;
    for (int i = 0; i < 100; ++i) AddrMacros::Version(false);
    Check(enumerationCalls == reads, "normal macro reads still polled IP Helper");

    source[0].name = L"Renamed";
    std::reverse(source.begin(), source.end());
    SetAdapters(source);
    Check(AddrMacros::Version(true) == version, "rename or adapter order changed macro version");
    source.back().dns_servers = {Ip4(8, 8, 4, 4)};
    SetAdapters(source);
    NotifyRegistry(L"Dnscache");
    WaitUntil([] { return AddrMacros::Matches(AddrMacro::DnsServers, Ip4(8, 8, 4, 4)); });
    Check(AddrMacros::Version(false) == version + 1, "DNS change did not update macro version once");
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        enumerationError = ERROR_GEN_FAILURE;
    }
    Check(AddrMacros::Version(true) == version + 1 &&
          AddrMacros::Matches(AddrMacro::DnsServers, Ip4(8, 8, 4, 4)), "failed refresh lost macro values");
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        enumerationError = ERROR_SUCCESS;
    }
    source.back().dns_servers = {Ip4(4, 4, 4, 4)};
    SetAdapters(source);
    AddrMacros::Invalidate();
    WaitUntil([] { return AddrMacros::Matches(AddrMacro::DnsServers, Ip4(4, 4, 4, 4)); });
    AddrMacros::Shutdown();

    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        notificationError = ERROR_ACCESS_DENIED;
    }
    source.back().dns_servers = {Ip4(2, 2, 2, 2)};
    SetAdapters(source);
    AddrMacros::Version(true);
    Check(AddrMacros::Matches(AddrMacro::DnsServers, Ip4(2, 2, 2, 2)), "fallback did not obtain macro values");
    const auto fallbackReads = enumerationCalls.load();
    source.back().dns_servers = {Ip4(3, 3, 3, 3)};
    SetAdapters(source);
    for (int i = 0; i < 100; ++i) AddrMacros::Version(false);
    Check(enumerationCalls == fallbackReads, "fallback ignored its retry TTL");
    macroTick += AddrMacros::kCacheTtlMs;
    Check(AddrMacros::Matches(AddrMacro::DnsServers, Ip4(3, 3, 3, 3)), "fallback did not retry after TTL");
    {
        std::lock_guard<std::mutex> lock(fixtureMutex);
        notificationError = ERROR_SUCCESS;
    }
    macroTick += AddrMacros::kCacheTtlMs;
    AddrMacros::Version(false);
    Check(registrations == 3, "watcher did not recover from fallback");
    AddrMacros::Shutdown();
}
} // namespace

namespace {
void TestInterfaceRuleGroups() {
    ResetFixture();
    SetAdapters(SampleAdapters());
    auto& watcher = net::SharedNetworkInterfaces();
    {
        RuleStore store;
        auto groups = store.Interfaces();
        Check(groups.size() == 2, "empty groups must exist only for active named interfaces");
        Rule global;
        global.scope = RuleScope::Global;
        global.conds = CondNone;
        global.action = RuleAction::Block;
        store.Add(global);
        Rule ethernet = global;
        ethernet.id = 0;
        ethernet.scope = RuleScope::Interface;
        ethernet.appPath = L"Ethernet";
        ethernet.action = RuleAction::Allow;
        store.Add(ethernet);
        Rule offline = ethernet;
        offline.id = 0;
        offline.appPath = L"Saved offline interface";
        store.Add(offline);
        MatchQuery query;
        query.interfaceIndex = 7;
        Rule found;
        const unsigned reads = enumerationCalls;
        for (int i = 0; i < 1000; ++i)
            Check(store.Match(query, found) && found.id == ethernet.id, "interface did not precede Global");
        Check(enumerationCalls == reads, "rule matching polled network interfaces");
        query.interfaceIndex = 17;
        Check(store.Match(query, found) && found.id == ethernet.id, "IPv6 alias has no interface rules");

        std::atomic<unsigned> first{0}, second{0};
        const auto token1 = watcher.Subscribe([&](const auto&) { ++first; });
        const auto token2 = watcher.Subscribe([&](const auto&) { ++second; });
        auto nextAdapters = SampleAdapters();
        nextAdapters[0].up = false;
        Interface wifi;
        wifi.name = L"Wi-Fi";
        wifi.number = wifi.ipv6_number = 7;
        wifi.up = true;
        nextAdapters.push_back(wifi);
        uint64_t version = store.interfaceVersion();
        SetAdapters(nextAdapters);
        NotifyInterface();
        WaitUntil([&] { return store.interfaceVersion() != version && first && second; });
        Check(!watcher.GetInterfaceNumberByName(L"Ethernet"), "inactive interface still resolves an index");
        query.interfaceIndex = 7;
        Check(store.Match(query, found) && found.id == global.id, "reused index selected inactive interface rules");
        groups = store.Interfaces();
        Check(std::any_of(groups.begin(), groups.end(), [](const auto& entry) {
            return entry.name == L"Ethernet" && !entry.active && entry.rules == 1;
        }), "inactive interface rules disappeared");
        Check(std::any_of(groups.begin(), groups.end(), [](const auto& entry) {
            return entry.name == L"Wi-Fi" && entry.active && entry.rules == 0;
        }), "new interface has no empty group");
        watcher.Unsubscribe(token1);
        const auto firstCount = first.load();
        const auto secondCount = second.load();
        version = store.interfaceVersion();
        nextAdapters[0].up = true;
        nextAdapters[0].number = 29;
        nextAdapters[0].ipv6_number = 39;
        nextAdapters.pop_back();
        SetAdapters(nextAdapters);
        NotifyInterface();
        WaitUntil([&] { return store.interfaceVersion() != version && second > secondCount; });
        Check(first == firstCount, "unsubscribed callback was invoked");
        groups = store.Interfaces();
        Check(std::none_of(groups.begin(), groups.end(), [](const auto& entry) { return entry.name == L"Wi-Fi"; }),
              "empty inactive interface group was retained");
        for (uint32_t index : {29u, 39u}) {
            query.interfaceIndex = index;
            for (auto source : {TrafficSource::Host, TrafficSource::Ndis}) {
                query.source = source;
                Check(store.Match(query, found) && found.id == ethernet.id, "renumbered interface lost its rules");
            }
        }
        const auto unchanged = store.version();
        const auto callbacks = second.load();
        NotifyRoute();
        WaitUntil([&] { return second > callbacks; });
        Check(store.version() == unchanged, "unchanged interfaces invalidated rule caches");
        Check(store.Remove(offline.id), "cannot remove last offline rule");
        groups = store.Interfaces();
        Check(std::none_of(groups.begin(), groups.end(), [](const auto& entry) {
            return entry.name == L"Saved offline interface";
        }), "last rule deletion retained an inactive group");
        watcher.Unsubscribe(token2);
    }
    watcher.Stop();
}
} // namespace

namespace {
void TestFrozenInterfaceQueries() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    const std::wstring original = adapter.name;
    SetAdapters({adapter});
    auto& watcher = net::SharedNetworkInterfaces();
    {
        RuleStore store;
        MatchQuery pending;
        pending.source = TrafficSource::Ndis;
        pending.interfaceIndex = adapter.number;
        Rule found;
        RuleAction action;
        uint64_t matchedVersion = 0;
        std::shared_ptr<const std::wstring> captured;
        Check(!store.MatchVerdict(pending, action, matchedVersion, nullptr, &captured) &&
                  captured && *captured == original,
              "matcher miss did not retain the original interface name");
        pending.interfaceName = captured.get();
        adapter.name = L"Wi-Fi";
        SetAdapters({adapter});
        const auto version = store.interfaceVersion();
        NotifyInterface();
        WaitUntil([&] { return store.interfaceVersion() != version; });
        Rule replacement;
        replacement.scope = RuleScope::Interface;
        replacement.appPath = adapter.name;
        replacement.conds = CondNone;
        replacement.action = RuleAction::Allow;
        store.Add(replacement);
        MatchQuery current = pending;
        current.interfaceName = nullptr;
        Check(store.Match(current, found) && found.id == replacement.id,
              "current event lost its interface rules");
        std::shared_ptr<const std::wstring> matchedName;
        Check(store.MatchVerdict(current, action, matchedVersion, nullptr, &matchedName) && !matchedName,
              "successful matcher copied an interface name on the hot path");
        Check(!store.Match(pending, found) && !RuleStore::MatchesRule(replacement, pending),
              "old pending adopted the replacement interface rules");
        const std::wstring unknown;
        current.interfaceName = &unknown;
        Check(!store.Match(current, found) && !RuleStore::MatchesRule(replacement, current),
              "previously unknown index adopted a known interface");
        Rule saved = replacement;
        saved.id = 0;
        saved.appPath = original;
        saved.action = RuleAction::Block;
        store.Add(saved);
        Check(store.Match(pending, found) && found.id == saved.id &&
                  RuleStore::MatchesRule(saved, pending),
              "offline interface rule cannot settle its original pending");
        const auto reads = enumerationCalls.load();
        for (int i = 0; i < 1000; ++i) store.Match(pending, found);
        Check(enumerationCalls == reads, "pending matching polled interfaces");
    }
    watcher.Stop();
}

void TestReverseNdisInterfaces() {
    ResetFixture();
    auto adapter = SampleAdapters().front();
    SetAdapters({adapter});
    const std::wstring key = Settings::Key::kNdisReverseTrafficPrefix + adapter.name;
    Check(Settings::SetBool(key.c_str(), true), "cannot set Ndis direction preference");
    Watcher watcher;
    Check(watcher.Refresh(), "cannot load Ndis direction preference");
    Check(watcher.ReverseNdisTraffic(7) && watcher.ReverseNdisTraffic(17) &&
              !watcher.ReverseNdisTraffic(0) && !watcher.ReverseNdisTraffic(11),
          "Ndis preference matched the wrong interface index");
    const auto reads = enumerationCalls.load();
    const auto before = watcher.GetSnapshot();
    Check(Settings::SetBool(key.c_str(), false) && watcher.SetReverseNdisTraffic(adapter.name, false) &&
              !watcher.ReverseNdisTraffic(7) && !watcher.ReverseNdisTraffic(17) &&
              before->interfaces.front().reverse_ndis_traffic &&
              watcher.SnapshotVersion() > before->version,
          "Ndis preference did not update the immutable snapshot immediately");
    Check(Settings::SetBool(key.c_str(), true) && watcher.SetReverseNdisTraffic(adapter.name, true),
          "cannot restore Ndis preference");
    for (int i = 0; i < 10000; ++i) Check(watcher.ReverseNdisTraffic(7), "cached preference changed");
    Check(enumerationCalls == reads, "Ndis preference lookup enumerated adapters");
    auto other = SampleAdapters()[1];
    const std::wstring otherKey = Settings::Key::kNdisReverseTrafficPrefix + other.name;
    Check(Settings::SetBool(otherKey.c_str(), true), "cannot set second Ndis preference");
    SetAdapters({adapter, other});
    Check(watcher.Refresh() && watcher.ReverseNdisTraffic(7) && watcher.ReverseNdisTraffic(17) &&
              watcher.ReverseNdisTraffic(1) && !watcher.ReverseNdisTraffic(11),
          "Ndis preferences failed with more than two indices");
    Check(Settings::Remove(otherKey.c_str()), "cannot remove second Ndis preference");
    adapter.number = 29;
    adapter.ipv6_number = 39;
    SetAdapters({adapter});
    Check(watcher.Refresh() && !watcher.ReverseNdisTraffic(7) &&
              watcher.ReverseNdisTraffic(29) && watcher.ReverseNdisTraffic(39),
          "renumbered Ndis interface retained its old index");
    adapter.up = false;
    SetAdapters({adapter});
    Check(watcher.Refresh() && watcher.ReverseNdisTraffic(29),
          "Ndis preference ignored a known inactive interface index");
    adapter.name = L"Renamed";
    SetAdapters({adapter});
    Check(watcher.Refresh() && !watcher.ReverseNdisTraffic(29),
          "Ndis preference followed a renamed interface");
    Check(Settings::Remove(key.c_str()), "cannot remove Ndis test preference");
}

void TestSynchronousRuleRecovery() {
    for (bool running : {true, false}) {
        ResetFixture();
        auto adapter = SampleAdapters().front();
        SetAdapters({adapter});
        if (!running) {
            std::lock_guard lock(fixtureMutex);
            notificationError = ERROR_ACCESS_DENIED;
        }
        auto& watcher = net::SharedNetworkInterfaces();
        {
            RuleStore store;
            Rule rule;
            rule.scope = RuleScope::Interface;
            rule.appPath = adapter.name;
            rule.conds = CondNone;
            rule.action = RuleAction::Allow;
            store.Add(rule);
            const auto oldVersion = store.version();
            const auto oldSnapshot = watcher.SnapshotVersion();
            std::atomic<unsigned> callbacks{0};
            const auto token = watcher.Subscribe([&](const auto&) { ++callbacks; });
            adapter.number = 29;
            adapter.ipv6_number = 39;
            SetAdapters({adapter});
            if (running) {
                {
                    std::lock_guard lock(fixtureMutex);
                    enumerationError = ERROR_GEN_FAILURE;
                }
                NotifyInterface();
                WaitUntil([&] { return callbacks.load() != 0; });
                Check(watcher.SnapshotVersion() == oldSnapshot, "failed refresh published a version");
                std::lock_guard lock(fixtureMutex);
                enumerationError = ERROR_SUCCESS;
            }
            AddrMacros::Version(true);
            Check(watcher.SnapshotVersion() > oldSnapshot &&
                      watcher.GetInterfaceNumberByName(adapter.name) == 29u,
                  "synchronous refresh did not recover the snapshot");
            // Проверяем и прямой matcher, и версию внешних кешей до callback.
            MatchQuery query;
            query.source = TrafficSource::Ndis;
            Rule found;
            for (uint32_t index : {29u, 39u}) {
                query.interfaceIndex = index;
                Check(store.Match(query, found) && found.id == rule.id,
                      "synchronous refresh left a stale interface index");
            }
            for (uint32_t index : {7u, 17u}) {
                query.interfaceIndex = index;
                Check(!store.Match(query, found), "obsolete interface index still matched");
            }
            Check(store.version() != oldVersion, "shape caches cannot see a renumbered interface");
            const auto stable = store.version();
            Check(watcher.Refresh() && store.version() == stable,
                  "identical snapshot invalidated rule caches");
            const auto reads = enumerationCalls.load();
            query.interfaceIndex = 29;
            for (int i = 0; i < 1000; ++i) {
                Check(store.version() == stable && store.Match(query, found), "stable lookup failed");
            }
            Check(enumerationCalls == reads, "version checks polled network adapters");
            watcher.Unsubscribe(token);
        }
        AddrMacros::Shutdown();
    }
}
} // namespace

#include "interface_filter_tests.h"
#include "app_interface_preference_tests.h"

int main() {
    try {
        std::wstring error;
        Check(Settings::Open(L":memory:", error), "cannot open test settings");
        TestSnapshots();
        TestAddedNotifications();
        TestNotificationsAndRaces();
        TestLifecycleAndCoalescing();
        TestMacros();
        TestInterfaceRuleGroups();
        TestFrozenInterfaceQueries();
        TestReverseNdisInterfaces();
        TestSynchronousRuleRecovery();
        TestInterfaceFilterScopes();
        TestInterfaceFilterUpdates();
        TestInterfaceFilterPersistence();
        TestAppInterfacePreferences();
        TestBlockOtherInterfaces();
        TestBlockOtherInterfacesDatabase();
        TestAppInterfaceRemovalResets();
        TestAppInterfacePreferenceDatabase();
        TestAppInterfacePreferenceInheritance();
        ResetFixture();
        std::cout << "network interface watcher tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        AddrMacros::Shutdown();
        std::cerr << error.what() << '\n';
        return 1;
    }
}
