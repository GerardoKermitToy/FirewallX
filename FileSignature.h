#pragma once

#include <windows.h>
#include <string>

namespace FileSignature {

// Дескриптор удерживает проверенный файл от изменения и замены до применения правил.
class TrustedFile {
public:
    explicit TrustedFile(const std::wstring& path);
    ~TrustedFile();

    TrustedFile(const TrustedFile&) = delete;
    TrustedFile& operator=(const TrustedFile&) = delete;
    TrustedFile(TrustedFile&& other) noexcept;
    TrustedFile& operator=(TrustedFile&& other) noexcept;

    explicit operator bool() const noexcept { return trusted_; }

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    bool trusted_ = false;
};

} // namespace FileSignature
