#include "SingleInstance.h"
#include "AppInfo.h"

namespace FirewallX {

namespace {

constexpr DWORD kPollStepMs = 100;

} // namespace

UINT SingleInstance::ActivateMessage() {
    // инициализация статика потокобезопасна; идентификатор одинаков во всех копиях
    static const UINT msg = RegisterWindowMessageW(AppInfo::kActivateMessage);
    return msg;
}

bool SingleInstance::ActivateRunning(DWORD timeoutMs) {
    const UINT msg = ActivateMessage();

    // Окно могло ещё не появиться: первая копия успела создать мьютекс, но
    // до CreateWindow не дошла. Ждём с опросом, а не выходим сразу.
    for (DWORD spent = 0; ; spent += kPollStepMs) {
        HWND h = FindWindowW(AppInfo::kMainWindowClass, nullptr);
        if (h) {
            DWORD pid = 0;
            GetWindowThreadProcessId(h, &pid);
            // Право на передний план принадлежит нам (нас только что запустил
            // пользователь) — передаём его работающей копии, иначе её
            // SetForegroundWindow будет проигнорирован системой.
            if (pid) AllowSetForegroundWindow(pid);

            DWORD_PTR res = 0;
            // Send, а не Post: сообщение должно быть обработано, пока наш
            // процесс жив и право на передний план ещё действует.
            SendMessageTimeoutW(h, msg, 0, 0, SMTO_ABORTIFHUNG | SMTO_NORMAL,
                                2000, &res);
            return true;
        }
        if (spent >= timeoutMs) return false;
        Sleep(kPollStepMs);
    }
}

bool SingleInstance::Acquire(bool activateExisting) {
    mutex_ = CreateMutexW(nullptr, TRUE, AppInfo::kInstanceMutex);
    if (!mutex_) return true;              // не смогли проверить — не мешаем работе

    if (GetLastError() != ERROR_ALREADY_EXISTS) {
        owned_ = true;
        return true;
    }

    // Владение НЕ получено: ReleaseMutex вызывать нельзя, только закрыть дескриптор
    CloseHandle(mutex_);
    mutex_ = nullptr;
    owned_ = false;

    if (activateExisting) ActivateRunning();
    return false;
}

void SingleInstance::Release() {
    if (!mutex_) return;
    if (owned_) ReleaseMutex(mutex_);
    CloseHandle(mutex_);
    mutex_ = nullptr;
    owned_ = false;
}

} // namespace FirewallX