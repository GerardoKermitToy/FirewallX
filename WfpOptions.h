#pragma once

#include <windows.h>

namespace WfpOptions {

// Читает состояние сбора сетевых событий WFP.
// Возвращает ERROR_SUCCESS или код ошибки Windows.
DWORD GetNetEvents(bool& enabled);

// Включает или отключает сбор сетевых событий WFP.
// Возвращает ERROR_SUCCESS или код ошибки Windows.
DWORD SetNetEvents(bool enabled);

// Флажок установлен, если хотя бы одна доступная подкатегория аудита WFP
// включает аудит успешных или неуспешных событий.
DWORD GetAudit(bool& enabled);

// Включает или отключает оба вида событий во всех доступных подкатегориях
// аудита WFP. Другие подкатегории системной политики не затрагиваются.
DWORD SetAudit(bool enabled);

} // namespace WfpOptions
