#pragma once
#include <windows.h>

namespace ProcessProtectionOptions {

// Общая настройка оконной копии и службы; по умолчанию защита выключена.
bool Load();
bool Save(bool enabled);

// Включает CIG и ACG при запуске. Выключение требует нового процесса;
// при ошибке одной из политик запуск нельзя продолжать с частичной защитой.
DWORD ApplySaved();

} // namespace ProcessProtectionOptions
