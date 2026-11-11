#include "FileSignature.h"
#include "package_test_path.h"

#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void Check(bool value, const char* message) {
    if (!value) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

struct TempFile {
    std::wstring path;
    ~TempFile() { if (!path.empty()) DeleteFileW(path.c_str()); }
};

void Corrupt(const std::wstring& path) {
    HANDLE write = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    Check(write != INVALID_HANDLE_VALUE, "verified file was not released");
    LARGE_INTEGER offset{};
    offset.QuadPart = 512;
    Check(SetFilePointerEx(write, offset, nullptr, FILE_BEGIN) != FALSE,
          "cannot seek in test executable");
    BYTE changed = 0;
    DWORD count = 0;
    Check(ReadFile(write, &changed, sizeof(changed), &count, nullptr) && count == 1,
          "cannot read test executable");
    changed ^= 0xff;
    Check(SetFilePointerEx(write, offset, nullptr, FILE_BEGIN) != FALSE,
          "cannot seek in test executable");
    count = 0;
    const bool ok = WriteFile(write, &changed, sizeof(changed), &count, nullptr) && count == 1;
    CloseHandle(write);
    Check(ok, "cannot modify test executable");
}

void TestCatalogSignature() {
    wchar_t system[MAX_PATH]{};
    Check(GetSystemDirectoryW(system, MAX_PATH) != 0, "system directory not found");
    const std::wstring source = std::wstring(system) + L"\\cmd.exe";
    Check(static_cast<bool>(FileSignature::TrustedFile(source)),
          "Windows system file was not trusted");

    wchar_t directory[MAX_PATH]{};
    wchar_t name[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) != 0 && GetTempFileNameW(directory, L"fxs", 0, name),
          "cannot create test file");
    TempFile copy{ name };
    Check(CopyFileW(source.c_str(), copy.path.c_str(), FALSE) != FALSE,
          "cannot copy system executable");
    {
        FileSignature::TrustedFile trusted(copy.path);
        Check(static_cast<bool>(trusted), "catalog signature not trusted on copied file");
        HANDLE write = CreateFileW(copy.path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (write != INVALID_HANDLE_VALUE) CloseHandle(write);
        Check(write == INVALID_HANDLE_VALUE, "verified file can be modified while held");
    }
    Corrupt(copy.path);
    Check(!static_cast<bool>(FileSignature::TrustedFile(copy.path)),
          "modified executable was trusted");
}

void TestEmbedded(const std::wstring& path) {
    Check(static_cast<bool>(FileSignature::TrustedFile(path)), "embedded signature was not trusted");
    wchar_t directory[MAX_PATH]{}, name[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxe", 0, name),
          "cannot create test file");
    TempFile copy{ name };
    Check(CopyFileW(path.c_str(), copy.path.c_str(), FALSE) != FALSE,
          "cannot copy signed executable");
    Corrupt(copy.path);
    Check(!static_cast<bool>(FileSignature::TrustedFile(copy.path)),
          "executable with damaged embedded signature was trusted");
}

void TestPackageCatalog(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    Check(slash != std::wstring::npos, "package executable has no directory");
    const std::wstring catalog = path.substr(0, slash) + L"\\AppxMetadata\\CodeIntegrity.cat";
    Check(static_cast<bool>(FileSignature::TrustedFile(path)), "package executable was not trusted");

    wchar_t directory[MAX_PATH]{}, name[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxp", 0, name),
          "cannot create temporary package");
    Check(DeleteFileW(name) && CreateDirectoryW(name, nullptr), "cannot create temporary package");
    struct TempPackage {
        std::wstring root;
        ~TempPackage() {
            DeleteFileW((root + L"\\nested\\package.exe").c_str());
            DeleteFileW((root + L"\\AppxMetadata\\CodeIntegrity.cat").c_str());
            RemoveDirectoryW((root + L"\\nested").c_str());
            RemoveDirectoryW((root + L"\\AppxMetadata").c_str());
            RemoveDirectoryW(root.c_str());
        }
    } temp{ name };
    const std::wstring nested = temp.root + L"\\nested";
    const std::wstring metadata = temp.root + L"\\AppxMetadata";
    const std::wstring executable = nested + L"\\package.exe";
    const std::wstring copiedCatalog = metadata + L"\\CodeIntegrity.cat";
    Check(CreateDirectoryW(nested.c_str(), nullptr) && CreateDirectoryW(metadata.c_str(), nullptr) &&
          CopyFileW(path.c_str(), executable.c_str(), FALSE), "cannot copy package executable");
    if (static_cast<bool>(FileSignature::TrustedFile(executable))) {
        std::cout << "package catalog-only test skipped: file is already trusted\n";
        return;
    }
    Check(CopyFileW(catalog.c_str(), copiedCatalog.c_str(), FALSE), "cannot copy package catalog");
    Check(static_cast<bool>(FileSignature::TrustedFile(executable)),
          "package executable was not trusted using its catalog");
    Corrupt(executable);
    Check(!static_cast<bool>(FileSignature::TrustedFile(executable)),
          "modified package executable was trusted");
    Check(CopyFileW(path.c_str(), executable.c_str(), FALSE), "cannot restore package executable");
    Corrupt(copiedCatalog);
    Check(!static_cast<bool>(FileSignature::TrustedFile(executable)),
          "damaged package catalog was trusted");
    Check(CopyFileW(catalog.c_str(), copiedCatalog.c_str(), FALSE), "cannot restore package catalog");

    wchar_t self[MAX_PATH]{};
    Check(GetModuleFileNameW(nullptr, self, MAX_PATH) &&
          CopyFileW(self, executable.c_str(), FALSE), "cannot copy unsigned executable");
    Check(!static_cast<bool>(FileSignature::TrustedFile(executable)),
          "package catalog trusted an unrelated executable");
}

void TestUnsignedAndMissing() {
    wchar_t self[MAX_PATH]{};
    Check(GetModuleFileNameW(nullptr, self, MAX_PATH) != 0, "test executable not found");
    Check(!static_cast<bool>(FileSignature::TrustedFile(self)), "unsigned executable was trusted");
    Check(!static_cast<bool>(FileSignature::TrustedFile(L"")), "empty path was trusted");
    Check(!static_cast<bool>(FileSignature::TrustedFile(L"?:\\no-such-file.exe")),
          "missing file was trusted");
}

} // анонимное пространство имён

int wmain(int argc, wchar_t** argv) {
    TestCatalogSignature();
    TestUnsignedAndMissing();
    if (argc > 1) TestEmbedded(argv[1]);
    const std::wstring package = argc > 2 ? argv[2] : TestWindowsStorePath();
    if (!package.empty()) TestPackageCatalog(package);
    else std::cout << "package catalog test skipped: Microsoft Store not found\n";
    std::cout << "file signature tests passed\n";
    return 0;
}
