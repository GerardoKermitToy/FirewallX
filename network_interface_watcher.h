#pragma once
#include "Common.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace net {

// Общий снимок IP-интерфейсов. Уведомления Windows объединяются спящим потоком;
// обычное чтение снимка не опрашивает систему и не копирует списки адресов.
class NetworkInterfaceWatcher final {
public:
    enum class ChangeType : std::uint8_t {
        Added,
        Removed,
        Changed,
        Initial,
    };

    // Это признаки возможных изменений, а не результат сравнения снимков.
    // Например, уведомление реестра может прийти без смены значения.
    enum class ChangeFlags : std::uint32_t {
        None               = 0,
        Interfaces         = 1u << 0,
        DnsServers         = 1u << 1,
        LocalNetwork       = 1u << 2,
        WinsServers        = 1u << 3,
        Gateways           = 1u << 4,
        MyComputer         = 1u << 5,
        AllMyAddresses     = 1u << 6,
        BroadcastAddresses = 1u << 7,
        MulticastAddresses = 1u << 8,
        All                = (1u << 9) - 1,
    };

    struct ChangeEvent {
        // Объединённые уведомления и изменения адресов/маршрутов — Changed.
        ChangeType type = ChangeType::Changed;
        std::uint16_t address_family = 0;
        std::uint32_t interface_index = 0; // 0 для общего изменения.
        bool snapshot_updated = false;
        ChangeFlags changes = ChangeFlags::None;
    };

    // Отдельное уведомление MibAddInstance, не общий Changed и не новый IP-адрес.
    struct AddedInterface {
        std::uint32_t interface_index = 0;
        std::uint64_t interface_luid = 0;
    };

    struct UnicastAddress {
        IpAddr address;
        std::uint8_t prefix_length = 0;
    };

    struct InterfaceInfo {
        std::uint32_t number = 0;      // IfIndex, а при его отсутствии — Ipv6IfIndex.
        std::uint32_t ipv6_number = 0;
        std::uint64_t luid = 0;        // NET_LUID::Value, не числовой индекс.
        std::wstring name;             // Имя подключения из панели управления.
        bool up = false;
        bool loopback = false;
        bool reverse_ndis_traffic = false;
        std::vector<UnicastAddress> unicast;
        std::vector<IpAddr> dns_servers;
        std::vector<IpAddr> wins_servers;
        std::vector<IpAddr> gateways;
    };

    struct Snapshot {
        // Поколение успешного полного перечисления, а не версия значений макросов.
        std::uint64_t version = 0;
        std::vector<InterfaceInfo> interfaces;

        struct NameLookup {
            const InterfaceInfo* first = nullptr;
            const InterfaceInfo* active = nullptr;
        };

        // Указатели действуют, пока жив и не изменён сам снимок.
        const InterfaceInfo* FindByIndex(std::uint32_t index) const noexcept;
        NameLookup FindByName(std::wstring_view name) const noexcept;
        const InterfaceInfo* FindActiveByName(std::wstring_view name) const noexcept;
        bool ReversesNdisTraffic(std::uint32_t index) const noexcept;

        // Вызывается после изменения интерфейсов и до публикации снимка.
        void RebuildLookup();

    private:
        struct IndexEntry {
            std::size_t position;
            bool reverse_ndis_traffic;
        };
        static constexpr std::size_t kMissingPosition = static_cast<std::size_t>(-1);
        struct NameEntry {
            std::size_t first;
            std::size_t active = kMissingPosition;
        };
        struct NameHash {
            using is_transparent = void;
            std::size_t operator()(std::wstring_view name) const noexcept {
                return std::hash<std::wstring_view>{}(name);
            }
        };
        struct NameEqual {
            using is_transparent = void;
            bool operator()(std::wstring_view left, std::wstring_view right) const noexcept {
                return left == right;
            }
        };
        std::unordered_map<std::uint32_t, IndexEntry> indices_;
        std::unordered_map<std::wstring, NameEntry, NameHash, NameEqual> names_;
    };
    using SnapshotPtr = std::shared_ptr<const Snapshot>;

    // Вызывается последовательно в рабочем потоке, без блокировки снимка.
    // Исключения обработчика не останавливают наблюдение.
    using ChangeCallback = std::function<void(const ChangeEvent&)>;

    explicit NetworkInterfaceWatcher(ChangeCallback callback = {});
    ~NetworkInterfaceWatcher();

    NetworkInterfaceWatcher(const NetworkInterfaceWatcher&) = delete;
    NetworkInterfaceWatcher& operator=(const NetworkInterfaceWatcher&) = delete;
    NetworkInterfaceWatcher(NetworkInterfaceWatcher&&) = delete;
    NetworkInterfaceWatcher& operator=(NetworkInterfaceWatcher&&) = delete;

    // Отписка дожидается выполняющегося обработчика. Подписывать/отписывать
    // обработчики внутри ChangeCallback нельзя.
    std::uint64_t Subscribe(ChangeCallback callback);
    // Только MibAddInstance. Очередь принадлежит этому watcher; новый поток не создаётся.
    // Владелец сохраняет manual-reset event до Unsubscribe; TakeAdded атомарно сбрасывает его.
    std::uint64_t SubscribeAdded(HANDLE event);
    std::vector<AddedInterface> TakeAdded(std::uint64_t subscription);
    void Unsubscribe(std::uint64_t subscription);

    // Сначала регистрирует уведомления, затем получает начальный снимок.
    // Повторный запуск безвреден; начальный callback не вызывается.
    bool Start();

    // Дожидается завершения уведомлений и рабочего потока. Внутри callback
    // только запрашивает остановку; разрушать watcher из callback нельзя.
    void Stop() noexcept;
    bool IsRunning() const noexcept;

    // Неизменяемый полный снимок; nullptr до первого успешного перечисления.
    // Ошибка обновления сохраняет последний полный снимок и его поколение.
    SnapshotPtr GetSnapshot() const;
    // Дешёвая проверка публикации, включая синхронный Refresh без callback.
    std::uint64_t SnapshotVersion() const noexcept;

    // Синхронное обновление для подготовки правил до запуска транспорта и
    // явного запроса свежих данных. Работает также без запущенного наблюдения.
    // Callback не вызывается. Обычный matcher использует только GetSnapshot().
    bool Refresh();

    // Только будит рабочий поток; повторные запросы объединяются.
    void RequestRefresh() noexcept;

    std::optional<std::wstring> GetInterfaceName(
        std::uint32_t interface_number) const;
    // Только активный интерфейс с ненулевым индексом.
    std::optional<std::uint32_t> GetInterfaceNumberByName(
        std::wstring_view name, const SnapshotPtr& snapshot = {}) const;
    std::optional<std::wstring> GetInterfaceNameByIndex(
        std::uint32_t interface_index) const;
    bool ReverseNdisTraffic(std::uint32_t interface_index) const;
    bool SetReverseNdisTraffic(std::wstring_view name, bool reverse);

    // Копирование предусмотрено только для редких потребителей списка.
    std::vector<InterfaceInfo> GetInterfaces() const;
    std::size_t GetInterfaceCount() const noexcept;

    // Последняя ошибка перечисления, регистрации или ожидания.
    std::uint32_t LastError() const noexcept;

    static constexpr bool HasChange(ChangeFlags value, ChangeFlags flags) noexcept {
        return (static_cast<std::uint32_t>(value) &
                static_cast<std::uint32_t>(flags)) != 0;
    }

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

NetworkInterfaceWatcher& SharedNetworkInterfaces();

constexpr NetworkInterfaceWatcher::ChangeFlags operator|(
    NetworkInterfaceWatcher::ChangeFlags left,
    NetworkInterfaceWatcher::ChangeFlags right) noexcept {
    return static_cast<NetworkInterfaceWatcher::ChangeFlags>(
        static_cast<std::uint32_t>(left) | static_cast<std::uint32_t>(right));
}

} // namespace net
