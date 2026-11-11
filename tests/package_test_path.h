#pragma once

#include <windows.h>
#include <appmodel.h>

#include <string>
#include <vector>

inline std::wstring TestWindowsStorePath() {
    UINT32 count = 0, length = 0;
    if (GetPackagesByPackageFamily(L"Microsoft.WindowsStore_8wekyb3d8bbwe", &count, nullptr,
                                   &length, nullptr) != ERROR_INSUFFICIENT_BUFFER ||
        !count || !length) return {};
    std::vector<PWSTR> names(count);
    std::vector<wchar_t> buffer(length);
    if (GetPackagesByPackageFamily(L"Microsoft.WindowsStore_8wekyb3d8bbwe", &count, names.data(),
                                   &length, buffer.data()) != ERROR_SUCCESS) return {};
    names.resize(count);
    for (PWSTR name : names) {
        UINT32 pathLength = 0;
        if (GetPackagePathByFullName(name, &pathLength, nullptr) != ERROR_INSUFFICIENT_BUFFER ||
            !pathLength) continue;
        std::wstring root(pathLength, L'\0');
        if (GetPackagePathByFullName(name, &pathLength, root.data()) != ERROR_SUCCESS) continue;
        root.resize(wcslen(root.c_str()));
        const std::wstring path = root + L"\\WinStore.App.exe";
        const std::wstring catalog = root + L"\\AppxMetadata\\CodeIntegrity.cat";
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesW(catalog.c_str()) != INVALID_FILE_ATTRIBUTES) return path;
    }
    return {};
}
