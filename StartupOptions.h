#pragma once
#include <windows.h>

namespace StartupOptions {

inline constexpr wchar_t kStartInTrayArgument[] = L"--start-in-tray";

// COM должен быть инициализирован в вызывающем потоке. Состояние хранится
// в Планировщике заданий Windows, отдельно для текущего пользователя.
HRESULT GetEnabled(bool& enabled);
HRESULT SetEnabled(bool enabled);

} // namespace StartupOptions
