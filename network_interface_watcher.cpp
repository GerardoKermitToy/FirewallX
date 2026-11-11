#include "network_interface_watcher.h"
#include "Settings.h"

#include <netioapi.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <utility>

namespace net {

class NetworkInterfaceWatcher::Impl final {
public:
    explicit Impl(ChangeCallback callback) : callback_(std::move(callback)) {}
    ~Impl() { Stop(); }

    std::uint64_t Subscribe(ChangeCallback callback) {
        std::lock_guard lock(callback_mutex_);
        const auto id = next_subscription_.fetch_add(1, std::memory_order_relaxed) + 1;
        subscribers_.emplace_back(id, std::move(callback));
        return id;
    }

    std::uint64_t SubscribeAdded(HANDLE event) {
        if (!event || event == INVALID_HANDLE_VALUE) {
            last_error_.store(ERROR_INVALID_HANDLE, std::memory_order_relaxed);
            return 0;
        }
        std::lock_guard added(added_mutex_);
        const auto id = next_subscription_.fetch_add(1, std::memory_order_relaxed) + 1;
        added_subscribers_.push_back({id, event, {}});
        return id;
    }

    std::vector<AddedInterface> TakeAdded(std::uint64_t subscription) {
        std::lock_guard lock(added_mutex_);
        for (auto& entry : added_subscribers_) {
            if (entry.id != subscription) continue;
            std::vector<AddedInterface> result;
            result.swap(entry.pending);
            ResetEvent(entry.event);
            return result;
        }
        return {};
    }

    void Unsubscribe(std::uint64_t subscription) {
        {
            std::lock_guard added(added_mutex_);
            if (std::erase_if(added_subscribers_, [=](const auto& entry) { return entry.id == subscription; })) return;
        }
        std::lock_guard callbacks(callback_mutex_);
        std::erase_if(subscribers_, [=](const auto& entry) { return entry.first == subscription; });
    }

    bool Start() {
        if (current_callback_owner_ == this) {
            if (IsRunning()) return true;
            last_error_.store(ERROR_BUSY, std::memory_order_relaxed);
            return false;
        }

        std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
        if (IsRunning()) return true;
        if (worker_.joinable()) worker_.join();

        last_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
        try {
            if (!PrepareResources()) {
                CloseResources();
                return false;
            }
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                pending_ = {};
                running_ = true;
            }

            ULONG status = NotifyIpInterfaceChange(
                AF_UNSPEC, &Impl::OnIpInterfaceChange, this, FALSE,
                &notification_handles_[0]);
            if (status == NO_ERROR) {
                status = NotifyUnicastIpAddressChange(
                    AF_UNSPEC, &Impl::OnUnicastAddressChange, this, FALSE,
                    &notification_handles_[1]);
            }
            if (status == NO_ERROR) {
                status = NotifyRouteChange2(
                    AF_UNSPEC, &Impl::OnRouteChange, this, FALSE,
                    &notification_handles_[2]);
            }
            if (status != NO_ERROR) {
                last_error_.store(status, std::memory_order_relaxed);
                CloseResources();
                return false;
            }

            // Регистрация предшествует перечислению: изменения во время первого
            // опроса остаются в очереди. При гонке полный снимок получит worker.
            if (!RefreshSnapshot(true) && LastError() != ERROR_RETRY) {
                CloseResources();
                return false;
            }
            worker_ = std::thread([this] { Run(); });
            return true;
        } catch (...) {
            last_error_.store(ERROR_NOT_ENOUGH_MEMORY, std::memory_order_relaxed);
            CloseResources();
            return false;
        }
    }

    void Stop() noexcept {
        // NetIO callbacks только накапливают флаги. Отменять регистрацию внутри
        // самого NetIO callback нельзя: CancelMibChangeNotify2 ждёт его завершения.
        if (current_callback_owner_ == this) {
            RequestStop();
            return;
        }
        std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
        RequestStop();
        if (worker_.joinable()) worker_.join();
    }

    bool IsRunning() const noexcept {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return running_;
    }

    SnapshotPtr GetSnapshot() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return snapshot_;
    }

    std::uint64_t SnapshotVersion() const noexcept {
        return snapshot_version_.load(std::memory_order_acquire);
    }

    bool Refresh() { return RefreshSnapshot(false); }

    void RequestRefresh() noexcept {
        QueueChange(MakeEvent(ChangeFlags::All));
    }

    std::optional<std::wstring> GetInterfaceName(std::uint32_t number) const {
        const auto snapshot = GetSnapshot();
        if (snapshot && number) {
            for (const auto& entry : snapshot->interfaces) {
                if (entry.number == number || entry.ipv6_number == number)
                    return entry.name;
            }
        }
        return std::nullopt;
    }

    std::optional<std::uint32_t> GetInterfaceNumberByName(
        std::wstring_view name, const SnapshotPtr& snapshot) const {
        if (snapshot) {
            for (const auto& entry : snapshot->interfaces)
                if (entry.up && entry.number && entry.name == name) return entry.number;
        }
        return std::nullopt;
    }

    bool ReverseNdisTraffic(std::uint32_t index) const {
        if (!index) return false;
        const std::uint64_t indices = reverse_ndis_indices_.load(std::memory_order_acquire);
        if (indices != UINT64_MAX)
            return index == static_cast<std::uint32_t>(indices) ||
                   index == static_cast<std::uint32_t>(indices >> 32);
        const auto snapshot = GetSnapshot();
        if (!snapshot) return false;
        for (const auto& entry : snapshot->interfaces)
            if (entry.reverse_ndis_traffic &&
                (entry.number == index || entry.ipv6_number == index)) return true;
        return false;
    }

    bool SetReverseNdisTraffic(std::wstring_view name, bool reverse) {
        std::lock_guard refresh(refresh_mutex_);
        std::lock_guard lock(state_mutex_);
        if (!snapshot_) return false;
        auto next = std::make_shared<Snapshot>(*snapshot_);
        bool changed = false;
        for (auto& entry : next->interfaces) {
            if (entry.name == name && entry.reverse_ndis_traffic != reverse) {
                entry.reverse_ndis_traffic = reverse;
                changed = true;
            }
        }
        if (changed) {
            const std::uint64_t indices = ReverseNdisIndices(*next);
            next->version = snapshot_->version + 1;
            snapshot_ = std::move(next);
            reverse_ndis_indices_.store(indices, std::memory_order_release);
            snapshot_version_.store(snapshot_->version, std::memory_order_release);
        }
        return true;
    }

    std::size_t GetInterfaceCount() const noexcept {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return snapshot_ ? snapshot_->interfaces.size() : 0;
    }

    std::uint32_t LastError() const noexcept {
        return last_error_.load(std::memory_order_relaxed);
    }

private:
    // Два индекса помещаются в атомарное значение; при большем числе используется снимок.
    static std::uint64_t ReverseNdisIndices(const Snapshot& snapshot) noexcept {
        std::uint32_t first = 0, second = 0;
        for (const auto& entry : snapshot.interfaces) {
            if (!entry.reverse_ndis_traffic) continue;
            for (const auto index : {entry.number, entry.ipv6_number}) {
                if (!index || index == first || index == second) continue;
                if (!first) first = index;
                else if (!second) second = index;
                else return UINT64_MAX;
            }
        }
        return static_cast<std::uint64_t>(first) | (static_cast<std::uint64_t>(second) << 32);
    }

    struct RegistryWatch {
        HKEY key = nullptr;
        HANDLE event = nullptr;
        ChangeFlags changes = ChangeFlags::None;
    };

    struct RegistrySpec {
        const wchar_t* path;
        ChangeFlags changes;
    };

    static constexpr ChangeFlags kAddressChanges =
        ChangeFlags::Interfaces | ChangeFlags::LocalNetwork |
        ChangeFlags::MyComputer | ChangeFlags::AllMyAddresses |
        ChangeFlags::BroadcastAddresses;

    static constexpr std::array<RegistrySpec, 6> kRegistrySpecs{{
        {L"SYSTEM\\CurrentControlSet\\Services\\Tcpip",
         ChangeFlags::DnsServers | ChangeFlags::LocalNetwork |
             ChangeFlags::Gateways | ChangeFlags::MyComputer |
             ChangeFlags::AllMyAddresses | ChangeFlags::BroadcastAddresses},
        {L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6",
         ChangeFlags::DnsServers | ChangeFlags::LocalNetwork |
             ChangeFlags::Gateways | ChangeFlags::MyComputer |
             ChangeFlags::AllMyAddresses | ChangeFlags::BroadcastAddresses},
        {L"SYSTEM\\CurrentControlSet\\Services\\NetBT", ChangeFlags::WinsServers},
        {L"SYSTEM\\CurrentControlSet\\Services\\Dnscache", ChangeFlags::DnsServers},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", ChangeFlags::DnsServers},
        {L"SYSTEM\\CurrentControlSet\\Control\\Network", ChangeFlags::Interfaces},
    }};

    static bool FromSockaddr(const SOCKET_ADDRESS& address, IpAddr& out) {
        if (!address.lpSockaddr) return false;
        if (address.lpSockaddr->sa_family == AF_INET &&
            address.iSockaddrLength >= static_cast<int>(sizeof(sockaddr_in))) {
            const auto* in4 = reinterpret_cast<const sockaddr_in*>(address.lpSockaddr);
            out = IpAddr::Raw4(&in4->sin_addr);
            return true;
        }
        if (address.lpSockaddr->sa_family == AF_INET6 &&
            address.iSockaddrLength >= static_cast<int>(sizeof(sockaddr_in6))) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(address.lpSockaddr);
            out = IpAddr::Raw6(&in6->sin6_addr);
            return true;
        }
        return false;
    }

    template<class Address>
    static void CopyAddresses(const Address* first, std::vector<IpAddr>& out) {
        for (const auto* entry = first; entry; entry = entry->Next) {
            IpAddr ip;
            if (FromSockaddr(entry->Address, ip)) out.push_back(ip);
        }
    }

    static bool BuildSnapshot(std::vector<InterfaceInfo>& snapshot, ULONG& error) {
        constexpr ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_WINS_INFO |
                                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        std::vector<BYTE> buffer(16 * 1024);
        for (int attempt = 0; attempt < 4; ++attempt) {
            ULONG size = static_cast<ULONG>(buffer.size());
            auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            const ULONG status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &size);
            if (status == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(size);
                continue;
            }
            if (status == ERROR_NO_DATA) {
                error = ERROR_SUCCESS;
                return true;
            }
            if (status != NO_ERROR) {
                error = status;
                return false;
            }

            for (const auto* adapter = addresses; adapter; adapter = adapter->Next) {
                const ULONG number = adapter->IfIndex ? adapter->IfIndex : adapter->Ipv6IfIndex;
                if (!number) continue;
                InterfaceInfo entry;
                entry.number = number;
                entry.ipv6_number = adapter->Ipv6IfIndex;
                entry.luid = adapter->Luid.Value;
                if (adapter->FriendlyName) entry.name = adapter->FriendlyName;
                entry.up = adapter->OperStatus == IfOperStatusUp;
                entry.loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
                if (!entry.name.empty()) {
                    const std::wstring key = Settings::Key::kNdisReverseTrafficPrefix + entry.name;
                    entry.reverse_ndis_traffic = Settings::GetBool(key.c_str(), false);
                }
                for (const auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                    IpAddr ip;
                    if (FromSockaddr(unicast->Address, ip))
                        entry.unicast.push_back({ip, unicast->OnLinkPrefixLength});
                }
                CopyAddresses(adapter->FirstDnsServerAddress, entry.dns_servers);
                CopyAddresses(adapter->FirstWinsServerAddress, entry.wins_servers);
                CopyAddresses(adapter->FirstGatewayAddress, entry.gateways);
                snapshot.push_back(std::move(entry));
            }
            error = ERROR_SUCCESS;
            return true;
        }
        error = ERROR_BUFFER_OVERFLOW;
        return false;
    }

    bool RefreshSnapshot(bool require_running) noexcept {
        // Явный refresh и фоновое обновление не должны перечислять адаптеры
        // параллельно или публиковать снимки в обратном порядке.
        std::lock_guard<std::mutex> refresh_lock(refresh_mutex_);
        try {
            std::uint64_t generation;
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                if (require_running && !running_) return false;
                generation = snapshot_generation_;
            }
            auto next = std::make_shared<Snapshot>();
            ULONG error = ERROR_SUCCESS;
            if (!BuildSnapshot(next->interfaces, error)) {
                last_error_.store(error, std::memory_order_relaxed);
                return false;
            }
            std::lock_guard<std::mutex> lock(state_mutex_);
            if (require_running && !running_) return false;
            if (generation != snapshot_generation_) {
                // Пришедшее во время опроса удаление не должно воскресить
                // интерфейс. Новое уведомление уже поставило повторный опрос.
                last_error_.store(ERROR_RETRY, std::memory_order_relaxed);
                return false;
            }
            next->version = snapshot_version_.load(std::memory_order_relaxed) + 1;
            const std::uint64_t indices = ReverseNdisIndices(*next);
            snapshot_ = std::move(next);
            reverse_ndis_indices_.store(indices, std::memory_order_release);
            snapshot_version_.store(snapshot_->version, std::memory_order_release);
            last_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
            return true;
        } catch (...) {
            last_error_.store(ERROR_NOT_ENOUGH_MEMORY, std::memory_order_relaxed);
            return false;
        }
    }

    static ChangeEvent MakeEvent(ChangeFlags changes, std::uint16_t family = 0,
                                 std::uint32_t index = 0) noexcept {
        ChangeEvent event;
        event.address_family = family;
        event.interface_index = index;
        event.changes = changes;
        return event;
    }

    static void MergePending(ChangeEvent& pending, const ChangeEvent& event) noexcept {
        if (pending.changes == ChangeFlags::None) {
            pending = event;
        } else {
            pending.changes = pending.changes | event.changes;
            if (pending.type != event.type || pending.address_family != event.address_family ||
                pending.interface_index != event.interface_index) {
                pending.type = ChangeType::Changed;
                pending.address_family = 0;
                pending.interface_index = 0;
            }
        }
    }

    static ChangeType ToChangeType(MIB_NOTIFICATION_TYPE type) noexcept {
        switch (type) {
        case MibAddInstance: return ChangeType::Added;
        case MibDeleteInstance: return ChangeType::Removed;
        case MibInitialNotification: return ChangeType::Initial;
        default: return ChangeType::Changed;
        }
    }

    static VOID CALLBACK OnIpInterfaceChange(PVOID context, PMIB_IPINTERFACE_ROW row,
                                            MIB_NOTIFICATION_TYPE type) noexcept {
        auto event = MakeEvent(ChangeFlags::All, row ? row->Family : 0,
                               row ? row->InterfaceIndex : 0);
        event.type = ToChangeType(type);
        auto& self = *static_cast<Impl*>(context);
        self.QueueChange(event);
        if (type == MibAddInstance && row) self.QueueAdded({row->InterfaceIndex, row->InterfaceLuid.Value});
    }

    static VOID CALLBACK OnUnicastAddressChange(PVOID context, PMIB_UNICASTIPADDRESS_ROW row,
                                               MIB_NOTIFICATION_TYPE /*type*/) noexcept {
        static_cast<Impl*>(context)->QueueChange(MakeEvent(
            kAddressChanges, row ? row->Address.si_family : 0, row ? row->InterfaceIndex : 0));
    }

    static VOID CALLBACK OnRouteChange(PVOID context, PMIB_IPFORWARD_ROW2 row,
                                      MIB_NOTIFICATION_TYPE /*type*/) noexcept {
        static_cast<Impl*>(context)->QueueChange(MakeEvent(
            ChangeFlags::LocalNetwork | ChangeFlags::Gateways,
            row ? row->DestinationPrefix.Prefix.si_family : 0, row ? row->InterfaceIndex : 0));
    }

    void QueueChange(const ChangeEvent& event) noexcept {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!running_) return;
        ++snapshot_generation_;
        MergePending(pending_, event);
        SetEvent(wake_event_);
    }

    void QueueAdded(const AddedInterface& arrival) noexcept {
        if (!arrival.interface_index || !arrival.interface_luid) return;
        std::lock_guard lock(added_mutex_);
        for (auto& entry : added_subscribers_) {
            try {
                if (std::none_of(entry.pending.begin(), entry.pending.end(), [&](const auto& previous) {
                        return previous.interface_luid == arrival.interface_luid &&
                            previous.interface_index == arrival.interface_index;
                    })) entry.pending.push_back(arrival);
                SetEvent(entry.event);
            } catch (...) { last_error_.store(ERROR_NOT_ENOUGH_MEMORY, std::memory_order_relaxed); }
        }
    }

    static LSTATUS ArmRegistryWatch(RegistryWatch& watch) noexcept {
        // Start может выполняться в короткоживущем потоке. Регистрация должна
        // пережить его завершение, не порождая ложного изменения реестра.
        return RegNotifyChangeKeyValue(watch.key, TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
            watch.event, TRUE);
    }

    static LSTATUS OpenRegistryKey(const RegistrySpec& spec, HKEY& key) {
        std::wstring path(spec.path);
        for (;;) {
            const LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                                                 KEY_NOTIFY | KEY_WOW64_64KEY, &key);
            if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) return status;
            // Необязательный ключ политики может ещё не существовать. Родитель
            // сообщит и о его создании без периодического опроса реестра.
            const auto separator = path.rfind(L'\\');
            if (separator == std::wstring::npos) return status;
            path.resize(separator);
        }
    }

    bool PrepareResources() {
        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event_) {
            last_error_.store(GetLastError(), std::memory_order_relaxed);
            return false;
        }
        wake_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!wake_event_) {
            last_error_.store(GetLastError(), std::memory_order_relaxed);
            return false;
        }
        for (std::size_t i = 0; i < registry_watches_.size(); ++i) {
            auto& watch = registry_watches_[i];
            watch.changes = kRegistrySpecs[i].changes;
            LSTATUS status = OpenRegistryKey(kRegistrySpecs[i], watch.key);
            if (status != ERROR_SUCCESS) {
                last_error_.store(status, std::memory_order_relaxed);
                return false;
            }
            watch.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!watch.event) {
                last_error_.store(GetLastError(), std::memory_order_relaxed);
                return false;
            }
            status = ArmRegistryWatch(watch);
            if (status != ERROR_SUCCESS) {
                last_error_.store(status, std::memory_order_relaxed);
                return false;
            }
        }
        return true;
    }

    void Run() noexcept {
        try {
            std::array<HANDLE, 2 + kRegistrySpecs.size()> events{};
            events[0] = stop_event_;
            events[1] = wake_event_;
            for (std::size_t i = 0; i < registry_watches_.size(); ++i)
                events[2 + i] = registry_watches_[i].event;

            for (;;) {
                const DWORD result = WaitForMultipleObjects(
                    static_cast<DWORD>(events.size()), events.data(), FALSE, INFINITE);
                if (result == WAIT_OBJECT_0) break;
                if (result == WAIT_FAILED) {
                    last_error_.store(GetLastError(), std::memory_order_relaxed);
                    break;
                }
                ChangeEvent pending;
                {
                    std::lock_guard<std::mutex> lock(state_mutex_);
                    if (!running_) break;
                    pending = pending_;
                    pending_ = {};
                    ResetEvent(wake_event_);
                }

                bool registry_ok = true;
                for (std::size_t i = 0; i < registry_watches_.size(); ++i) {
                    auto& watch = registry_watches_[i];
                    if (WaitForSingleObject(watch.event, 0) != WAIT_OBJECT_0) continue;
                    ResetEvent(watch.event);
                    LSTATUS status = ArmRegistryWatch(watch);
                    if (status == ERROR_KEY_DELETED) {
                        RegCloseKey(watch.key);
                        watch.key = nullptr;
                        ResetEvent(watch.event);
                        status = OpenRegistryKey(kRegistrySpecs[i], watch.key);
                        if (status == ERROR_SUCCESS) status = ArmRegistryWatch(watch);
                    }
                    if (status != ERROR_SUCCESS) {
                        last_error_.store(status, std::memory_order_relaxed);
                        registry_ok = false;
                        break;
                    }
                    // Перевооружаем до опроса и callback: очередное изменение
                    // останется сигнальным, пока worker занят текущим снимком.
                    {
                        std::lock_guard<std::mutex> lock(state_mutex_);
                        ++snapshot_generation_;
                    }
                    MergePending(pending, MakeEvent(watch.changes));
                }
                if (!registry_ok) break;
                if (pending.changes == ChangeFlags::None) continue;

                pending.snapshot_updated = RefreshSnapshot(true);
                if (!IsRunning()) break;
                current_callback_owner_ = this;
                {
                    std::lock_guard lock(callback_mutex_);
                    const auto invoke = [&](const ChangeCallback& callback) {
                        try { if (callback) callback(pending); }
                        catch (...) { /* Ошибка потребителя не останавливает наблюдение. */ }
                    };
                    invoke(callback_);
                    for (const auto& entry : subscribers_) invoke(entry.second);
                }
                current_callback_owner_ = nullptr;
            }
        } catch (...) {
            last_error_.store(ERROR_NOT_ENOUGH_MEMORY, std::memory_order_relaxed);
        }
        CloseResources();
    }

    void RequestStop() noexcept {
        std::lock_guard<std::mutex> lock(state_mutex_);
        running_ = false;
        if (stop_event_) SetEvent(stop_event_);
    }

    void CloseResources() noexcept {
        RequestStop();
        // state_mutex здесь не удерживается: отмена ждёт NetIO callbacks,
        // которым этот mutex нужен для постановки изменения в очередь.
        for (auto& handle : notification_handles_) {
            if (handle) {
                const ULONG status = CancelMibChangeNotify2(handle);
                if (status != NO_ERROR) last_error_.store(status, std::memory_order_relaxed);
                handle = nullptr;
            }
        }
        for (auto& watch : registry_watches_) {
            if (watch.key) { RegCloseKey(watch.key); watch.key = nullptr; }
            if (watch.event) { CloseHandle(watch.event); watch.event = nullptr; }
        }
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (wake_event_) { CloseHandle(wake_event_); wake_event_ = nullptr; }
        if (stop_event_) { CloseHandle(stop_event_); stop_event_ = nullptr; }
        pending_ = {};
        std::lock_guard added(added_mutex_);
        for (auto& entry : added_subscribers_) {
            entry.pending.clear();
            ResetEvent(entry.event);
        }
    }

    mutable std::mutex state_mutex_;
    std::mutex lifecycle_mutex_;
    std::mutex refresh_mutex_;
    SnapshotPtr snapshot_;
    ChangeCallback callback_;
    std::mutex callback_mutex_;
    std::vector<std::pair<std::uint64_t, ChangeCallback>> subscribers_;
    struct AddedSubscriber {
        std::uint64_t id;
        HANDLE event;
        std::vector<AddedInterface> pending;
    };
    std::mutex added_mutex_;
    std::vector<AddedSubscriber> added_subscribers_;
    std::atomic<std::uint64_t> next_subscription_{0};
    ChangeEvent pending_;
    std::array<RegistryWatch, kRegistrySpecs.size()> registry_watches_{};
    std::array<HANDLE, 3> notification_handles_{};
    HANDLE stop_event_ = nullptr;
    HANDLE wake_event_ = nullptr;
    std::thread worker_;
    std::uint64_t snapshot_generation_ = 0;
    std::atomic<std::uint64_t> snapshot_version_{0};
    std::atomic<std::uint64_t> reverse_ndis_indices_{0};
    bool running_ = false;
    std::atomic<std::uint32_t> last_error_{ERROR_SUCCESS};
    static thread_local Impl* current_callback_owner_;
};

thread_local NetworkInterfaceWatcher::Impl*
    NetworkInterfaceWatcher::Impl::current_callback_owner_ = nullptr;

NetworkInterfaceWatcher::NetworkInterfaceWatcher(ChangeCallback callback)
    : impl_(std::make_unique<Impl>(std::move(callback))) {}
NetworkInterfaceWatcher::~NetworkInterfaceWatcher() = default;

NetworkInterfaceWatcher& SharedNetworkInterfaces() {
    static NetworkInterfaceWatcher watcher;
    return watcher;
}

std::uint64_t NetworkInterfaceWatcher::Subscribe(ChangeCallback callback) {
    return impl_->Subscribe(std::move(callback));
}
std::uint64_t NetworkInterfaceWatcher::SubscribeAdded(HANDLE event) {
    return impl_->SubscribeAdded(event);
}
std::vector<NetworkInterfaceWatcher::AddedInterface> NetworkInterfaceWatcher::TakeAdded(std::uint64_t subscription) {
    return impl_->TakeAdded(subscription);
}
void NetworkInterfaceWatcher::Unsubscribe(std::uint64_t subscription) {
    impl_->Unsubscribe(subscription);
}

bool NetworkInterfaceWatcher::Start() { return impl_->Start(); }
void NetworkInterfaceWatcher::Stop() noexcept { impl_->Stop(); }
bool NetworkInterfaceWatcher::IsRunning() const noexcept { return impl_->IsRunning(); }
NetworkInterfaceWatcher::SnapshotPtr NetworkInterfaceWatcher::GetSnapshot() const {
    return impl_->GetSnapshot();
}
std::uint64_t NetworkInterfaceWatcher::SnapshotVersion() const noexcept {
    return impl_->SnapshotVersion();
}
bool NetworkInterfaceWatcher::Refresh() { return impl_->Refresh(); }
void NetworkInterfaceWatcher::RequestRefresh() noexcept { impl_->RequestRefresh(); }

std::optional<std::wstring> NetworkInterfaceWatcher::GetInterfaceName(std::uint32_t number) const {
    return impl_->GetInterfaceName(number);
}
std::optional<std::uint32_t> NetworkInterfaceWatcher::GetInterfaceNumberByName(
    std::wstring_view name, const SnapshotPtr& snapshot) const {
    return impl_->GetInterfaceNumberByName(name, snapshot ? snapshot : impl_->GetSnapshot());
}
std::optional<std::wstring> NetworkInterfaceWatcher::GetInterfaceNameByIndex(std::uint32_t index) const {
    return impl_->GetInterfaceName(index);
}
bool NetworkInterfaceWatcher::ReverseNdisTraffic(std::uint32_t index) const {
    return impl_->ReverseNdisTraffic(index);
}
bool NetworkInterfaceWatcher::SetReverseNdisTraffic(std::wstring_view name, bool reverse) {
    return impl_->SetReverseNdisTraffic(name, reverse);
}
std::vector<NetworkInterfaceWatcher::InterfaceInfo> NetworkInterfaceWatcher::GetInterfaces() const {
    const auto snapshot = GetSnapshot();
    return snapshot ? snapshot->interfaces : std::vector<InterfaceInfo>{};
}
std::size_t NetworkInterfaceWatcher::GetInterfaceCount() const noexcept { return impl_->GetInterfaceCount(); }
std::uint32_t NetworkInterfaceWatcher::LastError() const noexcept { return impl_->LastError(); }

} // namespace net
