#pragma once
#include "ProcessIcon.h"

#include <appmodel.h>
#include <algorithm>
#include <stdexcept>
#include <type_traits>

namespace IconTest {

// Версия Store не зашита в тест: нужен установленный пакет, но не его запуск.
inline std::wstring StoreExecutable() {
    constexpr const wchar_t* family = L"Microsoft.WindowsStore_8wekyb3d8bbwe";
    UINT32 count = 0, length = 0;
    if (GetPackagesByPackageFamily(family, &count, nullptr, &length, nullptr) !=
        ERROR_INSUFFICIENT_BUFFER || count == 0)
        return {};
    std::vector<PWSTR> names(count);
    std::wstring buffer(length, L'\0');
    if (GetPackagesByPackageFamily(family, &count, names.data(), &length,
                                   buffer.data()) != ERROR_SUCCESS)
        return {};
    for (UINT32 i = 0; i < count; ++i) {
        length = 0;
        if (GetPackagePathByFullName(names[i], &length, nullptr) !=
            ERROR_INSUFFICIENT_BUFFER || length <= 1)
            continue;
        std::wstring path(length, L'\0');
        if (GetPackagePathByFullName(names[i], &length, path.data()) != ERROR_SUCCESS)
            continue;
        path.resize(length - 1);
        path += L"\\WinStore.App.exe";
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
            return path;
    }
    return {};
}

// Сравниваем изображение, а не только наличие HICON: стандартная заглушка
// тоже имеет правильный размер, но не должна проходить проверку логотипа.
inline std::vector<DWORD> Pixels(HICON icon) {
    ICONINFO info{};
    if (!icon || !GetIconInfo(icon, &info))
        throw std::runtime_error("cannot read icon pixels");
    using Bitmap = std::unique_ptr<std::remove_pointer_t<HBITMAP>, decltype(&DeleteObject)>;
    const Bitmap color(info.hbmColor, DeleteObject);
    const Bitmap mask(info.hbmMask, DeleteObject);
    BITMAP bitmap{};
    if (!color || !GetObjectW(color.get(), sizeof(bitmap), &bitmap) ||
        bitmap.bmWidth <= 0 || bitmap.bmHeight <= 0)
        throw std::runtime_error("invalid icon bitmap");
    const std::unique_ptr<std::remove_pointer_t<HDC>, decltype(&DeleteDC)>
        dc(CreateCompatibleDC(nullptr), DeleteDC);
    BITMAPINFO format{};
    format.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    format.bmiHeader.biWidth = bitmap.bmWidth;
    format.bmiHeader.biHeight = -bitmap.bmHeight;
    format.bmiHeader.biPlanes = 1;
    format.bmiHeader.biBitCount = 32;
    format.bmiHeader.biCompression = BI_RGB;
    std::vector<DWORD> pixels(static_cast<size_t>(bitmap.bmWidth) * bitmap.bmHeight);
    if (!dc || GetDIBits(dc.get(), color.get(), 0, static_cast<UINT>(bitmap.bmHeight),
                         pixels.data(), &format, DIB_RGB_COLORS) != bitmap.bmHeight)
        throw std::runtime_error("cannot copy icon pixels");
    return pixels;
}

// ListView рисует через ImageList, который может менять внутреннее
// представление альфы. Сравниваем видимый результат на непрозрачном фоне.
template<class Painter>
std::vector<DWORD> RenderedPixels(int size, Painter paint) {
    using Bitmap = std::unique_ptr<std::remove_pointer_t<HBITMAP>, decltype(&DeleteObject)>;
    const std::unique_ptr<std::remove_pointer_t<HDC>, decltype(&DeleteDC)>
        dc(CreateCompatibleDC(nullptr), DeleteDC);
    BITMAPINFO format{};
    format.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    format.bmiHeader.biWidth = size;
    format.bmiHeader.biHeight = -size;
    format.bmiHeader.biPlanes = 1;
    format.bmiHeader.biBitCount = 32;
    format.bmiHeader.biCompression = BI_RGB;
    void* memory = nullptr;
    const Bitmap canvas(CreateDIBSection(nullptr, &format, DIB_RGB_COLORS,
                                         &memory, nullptr, 0), DeleteObject);
    if (!dc || !canvas || !memory)
        throw std::runtime_error("cannot create icon rendering surface");
    struct Selection {
        HDC dc;
        HGDIOBJ previous;
        ~Selection() { SelectObject(dc, previous); }
    } selection{dc.get(), SelectObject(dc.get(), canvas.get())};
    const size_t count = static_cast<size_t>(size) * size;
    auto* pixels = static_cast<DWORD*>(memory);
    std::fill_n(pixels, count, 0xFFFFFFFF);
    if (!paint(dc.get())) throw std::runtime_error("cannot draw test icon");
    GdiFlush();
    std::vector<DWORD> result(pixels, pixels + count);
    for (DWORD& pixel : result) pixel &= 0xFFFFFF;
    return result;
}

} // namespace IconTest
