#pragma once
#include "Rules.h"

#include <functional>

enum class ListSkin : uint8_t;

// Окно общих настроек программы и общего списка правил.
class SettingsWindow {
public:
    // Возвращает true, если настройки или набор правил изменились.
    // Обработчики применяют изменения правил и шрифта, пока окно открыто.
    // Настройка шрифта относится только к переданному текущему оформлению.
    static bool Run(HWND owner, HINSTANCE inst, RuleStore& store, ListSkin skin,
                    const std::function<void()>& onRulesChanged,
                    const std::function<void()>& onFontChanged);
};
