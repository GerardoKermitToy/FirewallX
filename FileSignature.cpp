#include "FileSignature.h"

#include <bcrypt.h>
#include <wincrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wintrust.h>

#include <array>
#include <utility>

namespace FileSignature {
namespace {

LONG Verify(WINTRUST_DATA& data) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // Проверка не должна создавать сетевых запросов во время обработки соединения.
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;
    const LONG result = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return result;
}

LONG VerifyEmbedded(const std::wstring& path, HANDLE file) {
    WINTRUST_FILE_INFO info{};
    info.cbStruct = sizeof(info);
    info.pcwszFilePath = path.c_str();
    info.hFile = file;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info;
    return Verify(data);
}

bool VerifyCatalogFile(const std::wstring& catalogPath, const std::wstring& path, HANDLE file,
                       HCATADMIN admin, BYTE* hash, DWORD hashSize) {
    static constexpr wchar_t hex[] = L"0123456789ABCDEF";
    std::array<wchar_t, 513> tag{};
    for (DWORD i = 0; i < hashSize; ++i) {
        tag[i * 2] = hex[hash[i] >> 4];
        tag[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    WINTRUST_CATALOG_INFO info{};
    info.cbStruct = sizeof(info);
    info.pcwszCatalogFilePath = catalogPath.c_str();
    info.pcwszMemberTag = tag.data();
    info.pcwszMemberFilePath = path.c_str();
    info.hMemberFile = file;
    info.pbCalculatedFileHash = hash;
    info.cbCalculatedFileHash = hashSize;
    info.hCatAdmin = admin;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &info;
    return Verify(data) == 0;
}

bool VerifyPackageCatalog(const std::wstring& path, HANDLE file, HCATADMIN admin,
                          BYTE* hash, DWORD hashSize) {
    // Каталог MSIX не обязательно зарегистрирован в системном хранилище.
    size_t end = path.find_last_of(L"\\/");
    while (end != std::wstring::npos && end > 2) {
        const std::wstring catalogPath = path.substr(0, end) + L"\\AppxMetadata\\CodeIntegrity.cat";
        const DWORD attributes = GetFileAttributesW(catalogPath.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY) &&
            VerifyCatalogFile(catalogPath, path, file, admin, hash, hashSize)) return true;
        end = path.find_last_of(L"\\/", end - 1);
    }
    return false;
}

bool VerifyCatalog(const std::wstring& path, HANDLE file, PCWSTR algorithm) {
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, nullptr, algorithm, nullptr, 0)) return false;

    std::array<BYTE, 256> hash{};
    DWORD hashSize = static_cast<DWORD>(hash.size());
    LARGE_INTEGER start{};
    bool trusted = false;
    if (SetFilePointerEx(file, start, nullptr, FILE_BEGIN) &&
        CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashSize, hash.data(), 0) &&
        hashSize > 0 && hashSize <= hash.size()) {
        HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(
            admin, hash.data(), hashSize, 0, nullptr);
        if (catalog) {
            CATALOG_INFO catalogInfo{};
            catalogInfo.cbStruct = sizeof(catalogInfo);
            if (CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0))
                trusted = VerifyCatalogFile(catalogInfo.wszCatalogFile, path, file, admin,
                                            hash.data(), hashSize);
            CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        }
        if (!trusted) trusted = VerifyPackageCatalog(path, file, admin, hash.data(), hashSize);
    }
    CryptCATAdminReleaseContext(admin, 0);
    return trusted;
}

} // анонимное пространство имён

TrustedFile::TrustedFile(const std::wstring& path) {
    if (path.empty()) return;
    file_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) return;
    if (GetFileType(file_) != FILE_TYPE_DISK) return;

    const LONG embedded = VerifyEmbedded(path, file_);
    if (embedded == 0) {
        trusted_ = true;
    } else if (static_cast<unsigned long>(embedded) == TRUST_E_NOSIGNATURE) {
        // Windows может подписывать файл через каталог, а не внутри самого файла.
        trusted_ = VerifyCatalog(path, file_, BCRYPT_SHA256_ALGORITHM) ||
                   VerifyCatalog(path, file_, nullptr);
    }
}

TrustedFile::~TrustedFile() {
    if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
}

TrustedFile::TrustedFile(TrustedFile&& other) noexcept
    : file_(std::exchange(other.file_, INVALID_HANDLE_VALUE)),
      trusted_(std::exchange(other.trusted_, false)) {}

TrustedFile& TrustedFile::operator=(TrustedFile&& other) noexcept {
    if (this != &other) {
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
        file_ = std::exchange(other.file_, INVALID_HANDLE_VALUE);
        trusted_ = std::exchange(other.trusted_, false);
    }
    return *this;
}

} // namespace FileSignature
