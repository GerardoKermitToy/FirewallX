#pragma once

#include <windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

// Неизменяемые пути сворачиваются один раз; индекс и запрос используют один ключ.
inline constexpr uint64_t kFoldedTextHashBasis = 1469598103934665603ull;
inline constexpr uint64_t kFoldedTextHashPrime = 1099511628211ull;

inline const std::array<wchar_t, 65536>& FoldCaseTable() {
    // Все элементы UTF-16 сворачиваются по таблице Windows без CRT locale
    // и лингвистических замен. Один вызов WinAPI на процесс вместо вызова
    // на каждый символ; неизменяемая таблица занимает 128 КиБ.
    static const auto table = [] {
        std::array<wchar_t, 65536> values;
        for (size_t i = 0; i < values.size(); ++i)
            values[i] = static_cast<wchar_t>(i);
        CharUpperBuffW(values.data(), static_cast<DWORD>(values.size()));
        return values;
    }();
    return table;
}

inline wchar_t FoldCaseChar(wchar_t c) {
    return FoldCaseTable()[static_cast<uint16_t>(c)];
}

inline void MixFoldedChar(uint64_t& hash, wchar_t c) {
    const uint16_t value = static_cast<uint16_t>(c);
    hash ^= static_cast<uint8_t>(value & 0xFF);
    hash *= kFoldedTextHashPrime;
    hash ^= static_cast<uint8_t>((value >> 8) & 0xFF);
    hash *= kFoldedTextHashPrime;
}

inline uint64_t HashFoldedText(std::wstring_view folded) {
    uint64_t hash = kFoldedTextHashBasis;
    for (wchar_t c : folded) MixFoldedChar(hash, c);
    return hash;
}

inline uint64_t HashTextNoCase(std::wstring_view text) {
    uint64_t hash = kFoldedTextHashBasis;
    if (text.empty()) return hash;
    const auto& table = FoldCaseTable();
    for (wchar_t c : text) MixFoldedChar(hash, table[static_cast<uint16_t>(c)]);
    return hash;
}

inline std::wstring FoldCaseCopy(std::wstring_view text) {
    std::wstring folded(text);
    if (folded.empty()) return folded;
    const auto& table = FoldCaseTable();
    for (wchar_t& c : folded) c = table[static_cast<uint16_t>(c)];
    return folded;
}
