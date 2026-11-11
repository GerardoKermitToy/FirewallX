#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

// uint64_t: не более 20 цифр и 6 неразрывных пробелов. Общий формат для
// отображения и фильтра; завершающий ноль позволяет искать без временной строки.
inline std::wstring_view FormatNumberView(uint64_t value, wchar_t (&buffer)[32]) {
    wchar_t* const end = buffer + 31;
    *end = L'\0';
    wchar_t* out = end;
    unsigned group = 0;
    do {
        if (group == 3) {
            *--out = L' ';
            group = 0;
        }
        *--out = static_cast<wchar_t>(L'0' + value % 10);
        value /= 10;
        ++group;
    } while (value != 0);
    return {out, static_cast<size_t>(end - out)};
}
