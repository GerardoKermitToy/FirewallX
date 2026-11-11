#include "ProcessIcon.h"

#include <appmodel.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wincodec.h>
#include <xmllite.h>
#include <wrl/client.h>
#include <algorithm>
#include <limits>
#include <type_traits>

namespace {

using Bitmap = std::unique_ptr<std::remove_pointer_t<HBITMAP>, decltype(&DeleteObject)>;
using Microsoft::WRL::ComPtr;

struct PackageLogo {
    std::wstring directory, resource;
    int logicalSize = 44;
};

std::wstring Attribute(IXmlReader* reader, const wchar_t* name) {
    if (reader->MoveToAttributeByName(name, nullptr) != S_OK) return {};
    const wchar_t* value = nullptr;
    UINT length = 0;
    std::wstring result;
    if (SUCCEEDED(reader->GetValue(&value, &length))) result.assign(value, length);
    reader->MoveToElement();
    return result;
}

PackageLogo ManifestLogo(const std::wstring& directory,
                         const std::wstring& relativeExecutable,
                         const std::wstring& applicationId = {}) {
    ComPtr<IStream> stream;
    const std::wstring manifest = directory + L"\\AppxManifest.xml";
    if (FAILED(SHCreateStreamOnFileEx(manifest.c_str(), STGM_READ | STGM_SHARE_DENY_NONE,
                                     0, FALSE, nullptr, &stream)))
        return {};
    // XmlLite читает только нужные атрибуты, без дорогой проверки всех схем AppX.
    ComPtr<IXmlReader> reader;
    if (FAILED(CreateXmlReader(IID_PPV_ARGS(&reader), nullptr)) ||
        FAILED(reader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
        FAILED(reader->SetInput(stream.Get())))
        return {};
    bool matching = false;
    UINT applicationDepth = 0;
    XmlNodeType type{};
    while (reader->Read(&type) == S_OK) {
        UINT depth = 0;
        reader->GetDepth(&depth);
        if (type == XmlNodeType_EndElement && matching && depth == applicationDepth) {
            matching = false;
            continue;
        }
        if (type != XmlNodeType_Element) continue;
        const wchar_t* name = nullptr;
        UINT length = 0;
        if (FAILED(reader->GetLocalName(&name, &length))) continue;
        const std::wstring_view local(name, length);
        if (local == L"Application") {
            applicationDepth = depth;
            if (!applicationId.empty()) {
                matching = Attribute(reader.Get(), L"Id") == applicationId;
            } else {
                std::wstring executable = Attribute(reader.Get(), L"Executable");
                std::replace(executable.begin(), executable.end(), L'/', L'\\');
                matching = !executable.empty() && EqualNoCase(executable, relativeExecutable);
            }
        } else if (matching && local == L"VisualElements") {
            for (const auto& [attribute, size] : {
                    std::pair{L"Square44x44Logo", 44}, {L"SmallLogo", 30},
                    {L"Logo", 150}, {L"Square150x150Logo", 150}}) {
                std::wstring resource = Attribute(reader.Get(), attribute);
                if (!resource.empty()) return { directory, std::move(resource), size };
            }
        }
    }
    return {};
}

std::wstring PackageDirectory(const wchar_t* fullName) {
    UINT32 length = 0;
    if (GetPackagePathByFullName(fullName, &length, nullptr) != ERROR_INSUFFICIENT_BUFFER ||
        length <= 1)
        return {};
    std::wstring directory(length, L'\0');
    if (GetPackagePathByFullName(fullName, &length, directory.data()) != ERROR_SUCCESS)
        return {};
    directory.resize(length - 1);
    return directory;
}

std::wstring FolderPackageFamily(const std::wstring& folder) {
    UINT32 length = 0;
    if (PackageFamilyNameFromFullName(folder.c_str(), &length, nullptr) ==
        ERROR_INSUFFICIENT_BUFFER && length > 1) {
        std::wstring family(length, L'\0');
        if (PackageFamilyNameFromFullName(folder.c_str(), &length, family.data()) ==
            ERROR_SUCCESS) {
            family.resize(length - 1);
            return family;
        }
    }
    // SystemApps обычно использует имя семейства, а WindowsApps — полное имя.
    // PublisherId занимает 13 символов; окончательно имя проверит реестр пакетов.
    const size_t separator = folder.find_last_of(L'_');
    return separator != std::wstring::npos && separator > 0 &&
        folder.size() - separator == 14 ? folder : L"";
}

PackageLogo RegisteredLogo(const std::wstring& family,
                           const std::wstring& relativeExecutable,
                           const std::wstring& applicationId = {}) {
    UINT32 count = 0, length = 0;
    if (GetPackagesByPackageFamily(family.c_str(), &count, nullptr, &length, nullptr) !=
        ERROR_INSUFFICIENT_BUFFER || count == 0)
        return {};
    std::vector<PWSTR> names(count);
    std::wstring buffer(length, L'\0');
    if (GetPackagesByPackageFamily(family.c_str(), &count, names.data(),
                                   &length, buffer.data()) != ERROR_SUCCESS)
        return {};
    for (UINT32 i = 0; i < count; ++i) {
        const std::wstring directory = PackageDirectory(names[i]);
        if (directory.empty()) continue;
        PackageLogo logo = ManifestLogo(directory, relativeExecutable, applicationId);
        if (!logo.resource.empty()) return logo;
    }
    return {};
}

PackageLogo PathLogo(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    for (size_t slash = path.find_last_of(L'\\'); slash != std::wstring::npos && slash > 0;
         slash = path.find_last_of(L'\\', slash - 1)) {
        if (slash == 2 && path[1] == L':') break;
        const std::wstring directory = path.substr(0, slash);
        const std::wstring relativeExecutable = path.substr(slash + 1);
        const std::wstring manifest = directory + L"\\AppxManifest.xml";
        const DWORD attributes = GetFileAttributesW(manifest.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
            return ManifestLogo(directory, relativeExecutable);
        const size_t parent = directory.find_last_of(L'\\');
        const std::wstring folder = directory.substr(
            parent == std::wstring::npos ? 0 : parent + 1);
        const std::wstring family = FolderPackageFamily(folder);
        if (!family.empty()) {
            // Правило может хранить удалённую версию пакета. Меняем только
            // источник картинки, но не путь и не условия самого правила.
            PackageLogo logo = RegisteredLogo(family, relativeExecutable);
            if (!logo.resource.empty()) return logo;
        }
    }
    return {};
}

PackageLogo ProcessLogo(HANDLE process) {
    if (!process) return {};
    UINT32 length = 0;
    if (GetApplicationUserModelId(process, &length, nullptr) != ERROR_INSUFFICIENT_BUFFER ||
        length <= 1)
        return {};
    std::wstring id(length, L'\0');
    if (GetApplicationUserModelId(process, &length, id.data()) != ERROR_SUCCESS || length <= 1)
        return {};
    id.resize(length - 1);
    const size_t separator = id.find(L'!');
    if (separator == std::wstring::npos) return {};
    length = 0;
    if (GetPackageFullName(process, &length, nullptr) != ERROR_INSUFFICIENT_BUFFER || length <= 1)
        return {};
    std::wstring fullName(length, L'\0');
    if (GetPackageFullName(process, &length, fullName.data()) != ERROR_SUCCESS) return {};
    const std::wstring directory = PackageDirectory(fullName.c_str());
    return directory.empty() ? PackageLogo{} :
        ManifestLogo(directory, {}, id.substr(separator + 1));
}

int QualifierNumber(std::wstring_view qualifiers, std::wstring_view name) {
    size_t start = qualifiers.find(name);
    if (start == std::wstring_view::npos) return 0;
    start += name.size();
    int number = 0;
    for (; start < qualifiers.size() && qualifiers[start] >= L'0' &&
           qualifiers[start] <= L'9'; ++start) {
        if (number > 10000) return 0;
        number = number * 10 + qualifiers[start] - L'0';
    }
    return number;
}

std::wstring LogoAsset(const PackageLogo& logo, int size) {
    std::wstring resource = logo.resource;
    std::replace(resource.begin(), resource.end(), L'/', L'\\');
    // Манифест задаёт относительное имя внутри пакета, а не Shell URI.
    if (resource.empty() || resource.front() == L'\\' || resource.find(L':') != std::wstring::npos)
        return {};
    const size_t slash = resource.find_last_of(L'\\');
    const std::wstring directory = logo.directory + L"\\" +
        (slash == std::wstring::npos ? L"" : resource.substr(0, slash + 1));
    const std::wstring filename = resource.substr(slash == std::wstring::npos ? 0 : slash + 1);
    const size_t dot = filename.find_last_of(L'.');
    const std::wstring stem = filename.substr(0, dot);
    const std::wstring extension = dot == std::wstring::npos ? L"" : filename.substr(dot);
    const std::wstring pattern = directory + stem + L"*" + extension;
    WIN32_FIND_DATAW entry{};
    HANDLE find = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &entry,
                                  FindExSearchNameMatch, nullptr, 0);
    if (find == INVALID_HANDLE_VALUE) return {};
    const std::unique_ptr<void, decltype(&FindClose)> search(find, FindClose);
    std::wstring best;
    int bestScore = std::numeric_limits<int>::max();
    do {
        const std::wstring_view name(entry.cFileName);
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            name.size() < stem.size() + extension.size())
            continue;
        const std::wstring qualifiers = FoldCaseCopy(
            name.substr(stem.size(), name.size() - stem.size() - extension.size()));
        if ((!qualifiers.empty() && qualifiers.front() != L'.' && qualifiers.front() != L'_') ||
            qualifiers.find(L"CONTRAST-") != std::wstring::npos ||
            qualifiers.find(L"ALTFORM-LIGHTUNPLATED") != std::wstring::npos)
            continue;
        int pixels = QualifierNumber(qualifiers, L"TARGETSIZE-");
        const bool targetSize = pixels > 0;
        if (!pixels) {
            const int scale = QualifierNumber(qualifiers, L"SCALE-");
            pixels = scale > 0 ? MulDiv(logo.logicalSize, scale, 100) : logo.logicalSize;
        }
        // Готовый targetsize без цветной подложки предпочтительнее плитки.
        // Среди размеров берём ближайший не меньший, иначе наибольший меньший.
        const int distance = pixels >= size ? pixels - size : 1000 + size - pixels;
        const int score = (targetSize ? 0 : 1000000) +
            (qualifiers.find(L"ALTFORM-UNPLATED") != std::wstring::npos ? 0 : 100000) + distance;
        if (score < bestScore) {
            bestScore = score;
            best = directory + entry.cFileName;
        }
    } while (FindNextFileW(find, &entry));
    return best;
}

HICON DecodeLogo(const std::wstring& path, int size) {
    if (path.empty()) return nullptr;
    ComPtr<IWICImagingFactory> factory;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&factory))))
        return nullptr;
    ComPtr<IWICBitmapDecoder> decoder;
    if (FAILED(factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
        WICDecodeMetadataCacheOnDemand, &decoder)))
        return nullptr;
    ComPtr<IWICBitmapFrameDecode> frame;
    UINT width = 0, height = 0;
    if (FAILED(decoder->GetFrame(0, &frame)) || FAILED(frame->GetSize(&width, &height)) ||
        width == 0 || height == 0)
        return nullptr;
    ComPtr<IWICBitmapSource> source = frame;
    ComPtr<IWICBitmapScaler> scaler;
    const UINT side = static_cast<UINT>(size);
    if (width != side || height != side) {
        const UINT longest = std::max(width, height);
        width = std::max(1u, static_cast<UINT>(static_cast<uint64_t>(width) * side / longest));
        height = std::max(1u, static_cast<UINT>(static_cast<uint64_t>(height) * side / longest));
        if (FAILED(factory->CreateBitmapScaler(&scaler)) ||
            FAILED(scaler->Initialize(frame.Get(), width, height, WICBitmapInterpolationModeFant)))
            return nullptr;
        source = scaler;
    }
    ComPtr<IWICFormatConverter> converter;
    if (FAILED(factory->CreateFormatConverter(&converter)) || FAILED(converter->Initialize(
        source.Get(), GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone,
        nullptr, 0, WICBitmapPaletteTypeCustom)))
        return nullptr;
    BITMAPINFO bitmap{};
    bitmap.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bitmap.bmiHeader.biWidth = size;
    bitmap.bmiHeader.biHeight = -size;
    bitmap.bmiHeader.biPlanes = 1;
    bitmap.bmiHeader.biBitCount = 32;
    void* pixels = nullptr;
    Bitmap color(CreateDIBSection(nullptr, &bitmap, DIB_RGB_COLORS, &pixels, nullptr, 0), DeleteObject);
    if (!color || !pixels) return nullptr;
    const UINT stride = side * 4;
    std::memset(pixels, 0, static_cast<size_t>(stride) * side);
    auto* start = static_cast<BYTE*>(pixels) + (side - height) / 2 * stride + (side - width) / 2 * 4;
    if (FAILED(converter->CopyPixels(nullptr, stride, stride * (height - 1) + width * 4, start)))
        return nullptr;
    const size_t maskStride = (static_cast<size_t>(size) + 15) / 16 * 2;
    const std::vector<BYTE> bits(maskStride * size, 0);
    Bitmap mask(CreateBitmap(size, size, 1, 1, bits.data()), DeleteObject);
    if (!mask) return nullptr;
    ICONINFO info{};
    info.fIcon = TRUE;
    info.hbmColor = color.get();
    info.hbmMask = mask.get();
    return CreateIconIndirect(&info);
}

HICON LoadPackageLogo(const PackageLogo& logo, int size) {
    return DecodeLogo(LogoAsset(logo, size), size);
}

} // namespace

HICON ExtractPackagedAppIcon(const std::wstring& appUserModelId, int size) {
    if (size <= 0) return nullptr;
    const size_t separator = appUserModelId.find(L'!');
    if (separator == std::wstring::npos) return nullptr;
    return LoadPackageLogo(RegisteredLogo(appUserModelId.substr(0, separator), {},
                                         appUserModelId.substr(separator + 1)), size);
}

HICON ExtractApplicationIcon(const std::wstring& path, int size, HANDLE process) {
    if (size <= 0) return nullptr;
    // Дескриптор принадлежит исходному процессу; по голому PID здесь не ищем.
    if (process) {
        if (HICON icon = LoadPackageLogo(ProcessLogo(process), size)) return icon;
    }
    // Для сохранённых правил достаточно точного Executable из манифеста.
    // Ни проверка схем AppX, ни привязка к shell:AppsFolder здесь не нужны.
    if (HICON icon = LoadPackageLogo(PathLogo(path), size)) return icon;
    HICON icon = nullptr;
    if (!path.empty())
        SHDefExtractIconW(path.c_str(), 0, 0, &icon, nullptr,
                          static_cast<UINT>(MAKELONG(size, size)));
    return icon;
}
