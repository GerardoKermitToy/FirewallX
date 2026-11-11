#pragma once
#include "Rules.h"

// Модальный редактор правил приложения, интерфейса, глобальной группы или PostApp.
// Порядок строк списка задаёт приоритет: самое важное
// правило — вверху.
class AppRulesEditor {
public:
    static bool Run(HWND owner, HINSTANCE inst, RuleStore& store,
                    const std::wstring& appPath, const std::wstring& appName,
                    bool global = false, bool postapp = false, bool interfaceGroup = false,
                    DWORD pid = MAXDWORD);
#ifdef FIREWALLX_TEST_VERDICTS
    static void SetInterfaceBindingTestHandler(void (*handler)(const std::wstring&));
#endif
};