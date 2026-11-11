#pragma once
#include "Rules.h"
#include <span>

// Конструктор одного правила: условия, расшифровка со ссылками, имя
class RuleEditor {
public:
    // Payload передаётся только из Ask и остаётся подсказкой, не частью Rule.
    // Наследование также возвращается отдельно от Rule и только после «ОК».
    // topmost включается при создании правила из окна запроса вердикта.
    static bool Run(HWND owner, HINSTANCE inst, Rule& rule, bool editing,
                    std::span<const uint8_t> payload = {},
                    RuleInheritance* inheritance = nullptr, bool topmost = false);
};