#pragma once

#include <string>
#include <string_view>

#include <Windows.h>

namespace pipe_support
{
bool CurrentExecutablePath(std::wstring& path) noexcept;
bool NormalizePath(std::wstring_view input, std::wstring& path) noexcept;
bool QueryProcessPath(DWORD processId, std::wstring& path) noexcept;
bool PathsEqual(std::wstring_view left, std::wstring_view right) noexcept;
DWORD AuthorizeProcessPath(
    DWORD processId,
    const std::wstring& trustedPath) noexcept;
} // namespace pipe_support
