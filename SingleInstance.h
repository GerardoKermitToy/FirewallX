#pragma once
#include "Common.h"

namespace FirewallX {

// ---------------------------------------------------------------------------
// Единственная копия программы.
//
// Владение подтверждается именованным мьютексом в пространстве имён сеанса
// (Local\...). Копия, запущенная диспетчером служб, этот объект не создаёт
// вообще — см. wWinMain: до Acquire() дело доходит только в оконном режиме,
// поэтому служба и оконная программа сосуществуют без конфликта.
//
// При повторном ручном запуске работающая копия получает право на передний план
// и показывается; автоматический запуск может не активировать её окно.
// ---------------------------------------------------------------------------
class SingleInstance {
public:
    SingleInstance() = default;
    ~SingleInstance() { Release(); }
    SingleInstance(const SingleInstance&) = delete;
    SingleInstance& operator=(const SingleInstance&) = delete;

    // true — мьютекс получен либо его не удалось создать: запуск продолжается;
    // false — мьютекс уже существует, новый процесс должен выйти; при
    // activateExisting также предпринимается попытка показать старую копию.
    bool Acquire(bool activateExisting = true);
    void Release();
    bool owned() const { return owned_; }

    // Сообщение «покажи главное окно», общее для всех копий
    static UINT ActivateMessage();

    // Найти работающую копию и передать ей фокус
    static bool ActivateRunning(DWORD timeoutMs = 5000);

private:
    HANDLE mutex_ = nullptr;
    bool   owned_ = false;
};

} // namespace FirewallX