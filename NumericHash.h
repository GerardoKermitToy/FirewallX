#pragma once

#include <cstddef>
#include <cstdint>

// Ключ уже содержит полноценный хеш: повторный FNV по его байтам не нужен.
struct PreparedHash64 {
    size_t operator()(uint64_t value) const noexcept {
        if constexpr (sizeof(size_t) < sizeof(uint64_t)) value ^= value >> 32;
        return static_cast<size_t>(value);
    }
};

// Числовые ID ещё не перемешаны. Финализатор распределяет также PID,
// кратные четырём, и различает старшие биты без побайтового хеширования.
struct NumericIdHash {
    size_t operator()(uint64_t value) const noexcept {
        value ^= value >> 33;
        value *= 0xff51afd7ed558ccdull;
        value ^= value >> 33;
        value *= 0xc4ceb9fe1a85ec53ull;
        value ^= value >> 33;
        return PreparedHash64{}(value);
    }
};
