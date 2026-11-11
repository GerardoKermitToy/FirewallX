#pragma once

#include <cstdint>
#include <memory>
#include <windows.h>

// Отдельный синхронный канал TID: один слот общей памяти, mutex и события.
// Дескриптор драйвера остаётся в службе; pipe в этом канале не используется.
namespace ServiceThreadId {

namespace detail { struct Channel; }

using Query = DWORD (*)(void* context, uint64_t connectionId, uint64_t& threadId) noexcept;

// Один ожидающий поток обрабатывает запросы строго последовательно. Он не
// зависит от reader-а драйвера, пересылки записей и переключения маршрута.
// Start/Stop вызываются одним служебным потоком, не из callback query.
class Server final {
public:
    Server() noexcept;
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // nullptr выбирает штатное глобальное имя; отдельное имя нужно тестам.
    DWORD Start(Query query, void* context, const wchar_t* channelName = nullptr) noexcept;
    void Stop() noexcept;

private:
    static DWORD WINAPI WorkerThread(void* context) noexcept;
    void Reply() noexcept;

    std::unique_ptr<detail::Channel> channel_;
    HANDLE worker_ = nullptr;
    Query query_ = nullptr;
    void* context_ = nullptr;
};

class Client final {
public:
    Client() noexcept;
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Канал открывается один раз при подключении desktop к службе.
    DWORD Connect(const wchar_t* channelName = nullptr) noexcept;
    void Disconnect() noexcept;
    // Сигнатура повторяет KextClient::GetThreadId. Mutex удерживается до ответа:
    // другой запрос, даже из другого процесса, не может начаться параллельно.
    // Ожидание прерывается при остановке/завершении службы; ошибка — GetLastError.
    bool GetThreadId(uint64_t external_connection_id, uint64_t& threadIdOut) noexcept;

private:
    SRWLOCK lock_ = SRWLOCK_INIT;
    std::unique_ptr<detail::Channel> channel_;
};

} // namespace ServiceThreadId
