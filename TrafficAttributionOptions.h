#pragma once
#include <windows.h>

namespace TrafficAttributionOptions {

// Источник настройки — общая settings.db, а не текущее состояние драйвера.
// По умолчанию точная атрибуция включена.
bool Load();
bool Save(bool enabled);

// Записывает DWORD драйвера. Сам драйвер перечитывает его только при запуске.
DWORD Apply(bool enabled);
// Вызывается после создания службы драйвера, но до её запуска в обоих режимах.
DWORD ApplySaved();

} // namespace TrafficAttributionOptions
