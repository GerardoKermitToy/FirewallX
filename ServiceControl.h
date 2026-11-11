#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// Режим запуска и управление службой.
//
// Программа определяет режим сама, без внешних подсказок:
//   1) ключ командной строки --service (с ним служба и регистрируется);
//   2) наличие в маркере доступа SID «Служба» (S-1-5-6) — он есть только
//      у процессов, запущенных диспетчером служб;
//   3) сессия 0 без SID «Интерактивные» — процесс запущен не с рабочего стола;
//   4) окончательная проверка — StartServiceCtrlDispatcherW: если он вернул
//      ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, значит SCM нас не запускал,
//      и программа продолжает работу как обычное приложение.
// ---------------------------------------------------------------------------
namespace FirewallX {

enum class Mode : uint8_t { Desktop = 0, Service = 1 };

// Режим задаётся в начале wWinMain; при отказе SCM возможен ForceDesktopMode.
// После выбора маршрута запуска значение только читается.
extern Mode g_runMode;

Mode DetectRunMode(const wchar_t* cmdLine);
void ForceDesktopMode();                    // откат, если SCM недоступен

inline Mode RunMode()     { return g_runMode; }
inline bool IsService()   { return g_runMode == Mode::Service; }
// По значению: текст читается из STRINGTABLE при каждом вызове
std::wstring RunModeText();

// Точка входа службы. false — SCM нас не запускал, допустим оконный режим.
// true — служебный запуск завершён либо закончился другой ошибкой dispatcher-а;
// exitCode содержит код возврата, переходить к UI не нужно.
bool RunAsService(int& exitCode);

// ---- управление службой из оконного режима (требует прав администратора) ----
struct ServiceState {
    bool  installed = false;
    bool  running   = false;
    bool  pending   = false;      // переходное состояние: START/STOP_PENDING
    bool  autoStart = false;
    DWORD state     = 0;          // SERVICE_* или 0, если не установлена
    std::wstring Text() const;
    std::wstring FullText() const;
};

bool ServiceQuery(ServiceState& out, std::wstring& error);
bool ServiceInstall(std::wstring& error);
bool ServiceRemove(std::wstring& error);
bool ServiceStart(std::wstring& error);
bool ServiceStop(std::wstring& error);

} // namespace FirewallX