#pragma once

#include <cstdint>
#include <windows.h>

// Управление временной приостановкой одного потока для обязательства verdict.
// Нулевой токен означает, что поток не удалось приостановить, он не принадлежит
// pid либо PID системный/текущий. Каталог образа процесса значения не имеет.
// Каждый ненулевой токен нужно передать Release ровно один раз.
namespace ThreadSuspend {

uint64_t Acquire(DWORD pid, uint64_t threadId) noexcept;
void     Release(uint64_t token) noexcept;

} // namespace ThreadSuspend
