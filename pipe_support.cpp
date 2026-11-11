#include "pipe_support.h"

#include <array>
#include <limits>

namespace pipe_support
{
namespace
{
constexpr size_t kMaxPathChars = 32768;

void RemoveExtendedPathPrefix(std::wstring& path) noexcept
{
    constexpr std::wstring_view uncPrefix = L"\\\\?\\UNC\\";
    constexpr std::wstring_view pathPrefix = L"\\\\?\\";

    if (path.starts_with(uncPrefix))
    {
        path.replace(0, uncPrefix.size(), L"\\\\");
    }
    else if (path.starts_with(pathPrefix))
    {
        path.erase(0, pathPrefix.size());
    }
}

bool QueryPathFromProcess(const HANDLE process, std::wstring& path) noexcept
{
    std::array<wchar_t, kMaxPathChars> buffer{};
    DWORD size = static_cast<DWORD>(buffer.size());
    if (QueryFullProcessImageNameW(
            process,
            0,
            buffer.data(),
            &size) == FALSE)
    {
        path.clear();
        return false;
    }

    path.assign(buffer.data(), size);
    return true;
}
} // namespace

bool NormalizePath(
    const std::wstring_view input,
    std::wstring& path) noexcept
{
    path.clear();
    if (input.empty() || input.size() >= kMaxPathChars)
    {
        return false;
    }

    std::array<wchar_t, kMaxPathChars> source{};
    for (size_t i = 0; i < input.size(); ++i)
    {
        source[i] = input[i] == L'/' ? L'\\' : input[i];
    }

    std::array<wchar_t, kMaxPathChars> full{};
    const DWORD written = GetFullPathNameW(
        source.data(),
        static_cast<DWORD>(full.size()),
        full.data(),
        nullptr);
    if (written == 0 || written >= full.size())
    {
        return false;
    }

    path.assign(full.data(), written);
    RemoveExtendedPathPrefix(path);
    while (path.size() > 3 && path.back() == L'\\')
    {
        path.pop_back();
    }
    return !path.empty();
}

bool CurrentExecutablePath(std::wstring& path) noexcept
{
    std::array<wchar_t, kMaxPathChars> buffer{};
    const DWORD size = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (size == 0 || size >= buffer.size())
    {
        path.clear();
        return false;
    }
    return NormalizePath(std::wstring_view(buffer.data(), size), path);
}

bool QueryProcessPath(
    const DWORD processId,
    std::wstring& path) noexcept
{
    path.clear();
    const HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        processId);
    if (process == nullptr)
    {
        return false;
    }

    std::wstring rawPath;
    const bool queried = QueryPathFromProcess(process, rawPath);
    CloseHandle(process);
    return queried && NormalizePath(rawPath, path);
}

bool PathsEqual(
    const std::wstring_view left,
    const std::wstring_view right) noexcept
{
    if (left.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        right.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }

    return CompareStringOrdinal(
               left.data(),
               static_cast<int>(left.size()),
               right.data(),
               static_cast<int>(right.size()),
               TRUE) == CSTR_EQUAL;
}

DWORD AuthorizeProcessPath(
    const DWORD processId,
    const std::wstring& trustedPath) noexcept
{
    std::wstring actualPath;
    if (processId == 0 || !QueryProcessPath(processId, actualPath))
    {
        return ERROR_ACCESS_DENIED;
    }
    if (!PathsEqual(actualPath, trustedPath))
    {
        return ERROR_ACCESS_DENIED;
    }
    return ERROR_SUCCESS;
}
} // namespace pipe_support
