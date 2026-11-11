#pragma once
#include "Common.h"
#include <memory>
#include <utility>

// Значок не зависит от позиции в общем списке. Последняя ссылка из кеша,
// снимка или окна освобождает HICON; перестраивать остальные значки не нужно.
class ProcessIcon {
public:
    // Принимает собственный HICON, полученный без LR_SHARED.
    ProcessIcon(HICON handle, int size) noexcept : handle_(handle), size_(size) {}
    ProcessIcon(ProcessIcon&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)), size_(other.size_) {}
    ProcessIcon(const ProcessIcon&) = delete;
    ProcessIcon& operator=(const ProcessIcon&) = delete;
    ~ProcessIcon() { if (handle_) DestroyIcon(handle_); }

    HICON handle() const noexcept { return handle_; }
    int size() const noexcept { return size_; }

private:
    HICON handle_ = nullptr;
    int size_ = 0;
};

using ProcessIconRef = std::shared_ptr<const ProcessIcon>;

// Требуют инициализированного COM. Пакетный логотип читается напрямую через
// XmlLite/WIC, без Shell и проверки схем AppX. Результат — собственный HICON
// для DestroyIcon; nullptr оставляет выбор запасного значка вызывающему.
HICON ExtractPackagedAppIcon(const std::wstring& appUserModelId, int size);
HICON ExtractApplicationIcon(const std::wstring& path, int size,
                             HANDLE process = nullptr);
