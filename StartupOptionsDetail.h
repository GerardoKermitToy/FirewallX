#pragma once
#include <windows.h>
#include <taskschd.h>
#include <string>

namespace StartupOptions::Detail {

bool IsTaskMissing(HRESULT status);
std::wstring TaskName(const std::wstring& userSid);

// Создание определения не регистрирует задание и не меняет автозапуск Windows.
HRESULT CreateTaskDefinition(ITaskService* service, const std::wstring& userSid,
                             const std::wstring& executable,
                             const std::wstring& description,
                             ITaskDefinition** definition);

} // namespace StartupOptions::Detail
