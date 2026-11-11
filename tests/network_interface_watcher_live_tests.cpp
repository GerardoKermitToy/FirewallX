#include "network_interface_watcher.h"

#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>

int main() {
    try {
        std::mutex mutex;
        std::condition_variable ready;
        net::NetworkInterfaceWatcher watcher([&](const auto&) {
            std::lock_guard<std::mutex> lock(mutex);
            ready.notify_all();
        });
        if (!watcher.Start())
            throw std::runtime_error("Start failed: " + std::to_string(watcher.LastError()));
        const auto initial = watcher.GetSnapshot();
        if (!initial || !initial->version)
            throw std::runtime_error("initial adapter snapshot is not ready");
        size_t compared = 0;
        for (const auto& entry : initial->interfaces) {
            if (!entry.luid || entry.name.empty()) continue;
            MIB_IF_ROW2 row{};
            row.InterfaceLuid.Value = entry.luid;
            if (GetIfEntry2(&row) != NO_ERROR) continue;
            if (entry.name != row.Alias)
                throw std::runtime_error("interface display name does not match NetCfg adapter alias");
            ++compared;
        }
        if (!initial->interfaces.empty() && !compared)
            throw std::runtime_error("no current interface name could be checked");

        // Только чтение настоящей конфигурации Windows. Сигнал обновления
        // создаём сами, не меняя адреса, маршруты, реестр или состояние адаптеров.
        watcher.RequestRefresh();
        bool updated;
        {
            std::unique_lock<std::mutex> lock(mutex);
            updated = ready.wait_for(lock, std::chrono::seconds(5), [&] {
                return watcher.GetSnapshot()->version > initial->version;
            });
        }
        watcher.Stop();
        if (!updated || watcher.IsRunning())
            throw std::runtime_error("background refresh or shutdown failed");
        std::cout << "live network snapshot passed (" << initial->interfaces.size()
                  << " interfaces)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
