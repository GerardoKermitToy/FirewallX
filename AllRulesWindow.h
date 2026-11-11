#pragma once
#include "Rules.h"

#include <functional>

// Редактор всех правил: список приложений с иконками, переход к правилам
class AllRulesWindow {
public:
    // onChanged вызывается сразу после каждой записи во вложенном редакторе,
    // пока внешнее окно ещё открыто.
    static bool Run(HWND owner, HINSTANCE inst, RuleStore& store,
                    const std::function<void()>& onChanged);
};