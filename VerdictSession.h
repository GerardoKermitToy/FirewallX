#pragma once

#include <cstdint>
#include <utility>

class DriverVerdictSession;

// Одно событие on_connection_* даёт ровно одно перемещаемое обязательство.
// Сырой external_connection_id сам по себе не позволяет отправить вердикт:
// отправителю нужен этот объект, полученный при разборе записи драйвера. Сам id
// снаружи не доступен: gate проверяет поколение перед приостановкой потока
// и извлекает id через Consume в process_verdict.
class DriverVerdictRequest final {
public:
    DriverVerdictRequest() noexcept = default;

    DriverVerdictRequest(DriverVerdictRequest&& other) noexcept
        : owner_(std::exchange(other.owner_, nullptr)),
          session_(std::exchange(other.session_, 0)),
          externalConnectionId_(std::exchange(other.externalConnectionId_, 0)) {}

    DriverVerdictRequest& operator=(DriverVerdictRequest&&) = delete;
    DriverVerdictRequest(const DriverVerdictRequest&) = delete;
    DriverVerdictRequest& operator=(const DriverVerdictRequest&) = delete;

    explicit operator bool() const noexcept {
        return owner_ != nullptr && session_ != 0;
    }

    uint64_t session() const noexcept { return session_; }
private:
    friend class DriverVerdictSession;

    DriverVerdictRequest(const DriverVerdictSession* owner,
                         uint64_t session,
                         uint64_t externalConnectionId) noexcept
        : owner_(owner), session_(session),
          externalConnectionId_(externalConnectionId) {}

    void Invalidate() noexcept {
        owner_ = nullptr;
        session_ = 0;
        externalConnectionId_ = 0;
    }

    const DriverVerdictSession* owner_ = nullptr;
    uint64_t session_ = 0;
    uint64_t externalConnectionId_ = 0;
};

// Состояние не синхронизируется внутри класса: владелец защищает его тем же
// замком, что активный дескриптор драйвера. Поэтому проверка поколения и запись
// команды образуют одну критическую секцию без окна TOCTOU.
class DriverVerdictSession final {
public:
    DriverVerdictSession() noexcept = default;
    DriverVerdictSession(const DriverVerdictSession&) = delete;
    DriverVerdictSession& operator=(const DriverVerdictSession&) = delete;
    DriverVerdictSession(DriverVerdictSession&&) = delete;
    DriverVerdictSession& operator=(DriverVerdictSession&&) = delete;

    uint64_t Begin() noexcept {
        do {
            ++next_;
        } while (next_ == 0);
        active_ = next_;
        return active_;
    }

    // expected защищает новую сессию от запоздавшего callback отключения старой.
    uint64_t End(uint64_t expected = 0) noexcept {
        if (active_ == 0 || (expected != 0 && active_ != expected)) return 0;
        const uint64_t ended = active_;
        active_ = 0;
        return ended;
    }

    DriverVerdictRequest Receive(uint64_t externalConnectionId) const noexcept {
        return active_ != 0
            ? DriverVerdictRequest(this, active_, externalConnectionId)
            : DriverVerdictRequest();
    }

    // Проверка поколения под замком транспорта не позволяет приостановить
    // поток из старого события после смены сессии драйвера.
    // Само обязательство не поглощается.
    bool Inspect(const DriverVerdictRequest& request,
                 uint64_t& externalConnectionId) const noexcept {
        if (request.owner_ != this || request.session_ != active_ || active_ == 0) [[unlikely]]
            return false;
        externalConnectionId = request.externalConnectionId_;
        return true;
    }

    // Объект поглощается при любой попытке. Повторно отправить ответ по тому же
    // событию невозможно, а объект от прежней сессии никогда не пройдёт проверку.
    bool Consume(DriverVerdictRequest& request,
                 uint64_t& externalConnectionId) const noexcept {
        if (!request) [[unlikely]] return false;
        const bool current = request.owner_ == this &&
            request.session_ == active_ && active_ != 0;
        externalConnectionId = request.externalConnectionId_;
        request.Invalidate();
        return current;
    }

    uint64_t active() const noexcept { return active_; }

private:
    uint64_t next_ = 0;
    uint64_t active_ = 0;
};
