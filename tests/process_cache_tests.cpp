#include "ProcessCache.h"
#include "Monitor.h"
#include "SystemInfo.h"
#include "TreeList.h"
#include "icon_test_support.h"

#include <appmodel.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <objbase.h>
#include <shlobj.h>
#include <stdexcept>
#include <tlhelp32.h>
#include <wincodec.h>
#include <wrl/client.h>

struct ProcessCacheTestAccess {
    static ProcessIconRef Generic(ProcessCache& cache) { return cache.GenericIcon(); }
    static size_t Paths(const ProcessCache& cache) { return cache.iconByPath_.size(); }
    static size_t Processes(const ProcessCache& cache) { return cache.byPid_.size(); }
    static size_t ProcessBuckets(const ProcessCache& cache) { return cache.byPid_.bucket_count(); }
    static size_t PathBuckets(const ProcessCache& cache) { return cache.iconByPath_.bucket_count(); }
    static void Reserve(ProcessCache& cache) {
        cache.byPid_.reserve(100000);
        cache.iconByPath_.reserve(100000);
    }
    static size_t Users(const ProcessCache& cache, const std::wstring& path) {
        const auto it = cache.iconByPath_.find(FoldCaseCopy(path));
        return it == cache.iconByPath_.end() ? 0 : it->second.users;
    }
};

namespace {

constexpr DWORD kFirstPid = 0x70000000;
constexpr ULONGLONG kExpired = kProcessGraceMs + 1000;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

bool IconAlive(HICON icon) {
    ICONINFO info{};
    if (!GetIconInfo(icon, &info)) return false;
    if (info.hbmColor) DeleteObject(info.hbmColor);
    if (info.hbmMask) DeleteObject(info.hbmMask);
    return true;
}

void CheckIconSize(HICON icon, int size) {
    ICONINFO info{};
    Check(icon && GetIconInfo(icon, &info), "icon is invalid");
    BITMAP bitmap{};
    const bool valid = info.hbmColor &&
        GetObjectW(info.hbmColor, sizeof(bitmap), &bitmap) &&
        bitmap.bmWidth == size && bitmap.bmHeight == size;
    if (info.hbmColor) DeleteObject(info.hbmColor);
    if (info.hbmMask) DeleteObject(info.hbmMask);
    Check(valid, "icon has unexpected dimensions");
}

ProcessPathRef Path(std::wstring text) {
    return std::make_shared<const ProcessPathInfo>(std::move(text));
}

void Sweep(ProcessCache& cache,
           const std::vector<std::pair<DWORD, ULONGLONG>>& states) {
    // Меняем только кеш текущего тестового процесса. Реальные процессы,
    // системные часы и девятисекундное окно ожидания не затрагиваются.
    auto& alive = detail::aliveCache();
    {
        std::lock_guard<std::mutex> lock(alive.mtx);
        const ULONGLONG now = GetTickCount64();
        alive.swept = now;
        for (const auto& [pid, age] : states) {
            auto& entry = alive.map[pid];
            entry.alive = age == 0;
            entry.probed = entry.touched = now;
            entry.deadSince = age ? now - age : 0;
        }
    }
    cache.Sweep();
}

void TestOwnedIcon() {
    HICON handle = static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
                                                IMAGE_ICON, 16, 16, LR_COPYFROMRESOURCE));
    Check(handle != nullptr, "cannot create owned icon");
    {
        ProcessIcon first(handle, 16);
        ProcessIcon second(std::move(first));
        Check(!first.handle() && second.handle() == handle && IconAlive(handle),
              "moving icon lost ownership");
    }
    Check(!IconAlive(handle), "owned HICON was not destroyed");
}

void TestGenericIcon() {
    ProcessCache cache;
    ProcessIconRef icon = ProcessCacheTestAccess::Generic(cache);
    Check(icon && icon->size() == 16 && IconAlive(icon->handle()) &&
          ProcessCacheTestAccess::Generic(cache) == icon,
          "generic icon was not loaded or reused");
    const HICON previous = icon->handle();
    cache.SetIconSize(32);
    const ProcessIconRef next = ProcessCacheTestAccess::Generic(cache);
    Check(next && next != icon && next->size() == 32 && IconAlive(previous),
          "generic icon DPI change invalidated retained icon");
    icon.reset();
    Check(!IconAlive(previous), "generic icon DPI change leaked HICON");
}

void TestSharingAndLastProcess() {
    ProcessCache cache;
    const auto path = Path(L"C:\\FirewallXTests\\one.exe");
    const auto upper = Path(L"c:\\firewallxtests\\ONE.EXE");
    ProcessIconRef icon = cache.Get(kFirstPid, path).icon;
    Check(icon && IconAlive(icon->handle()), "process icon was not loaded");
    Check(cache.Get(kFirstPid + 1, upper).icon == icon,
          "same executable path did not share icon");
    Check(cache.Get(kFirstPid, path).icon == icon &&
          ProcessCacheTestAccess::Users(cache, path->text) == 2,
          "repeated Get incremented path users");

    ProcItem snapshot;
    TreeList::Row row;
    snapshot.icon = row.icon = icon;
    const HICON handle = icon->handle();
    std::weak_ptr<const ProcessIcon> weak = icon;
    icon.reset();

    Sweep(cache, {{kFirstPid, kExpired}, {kFirstPid + 1, 0}});
    Check(ProcessCacheTestAccess::Paths(cache) == 1 &&
          ProcessCacheTestAccess::Users(cache, path->text) == 1 &&
          cache.Get(kFirstPid + 1, upper).icon == row.icon,
          "removing one PID removed or reloaded a shared icon");
    Sweep(cache, {{kFirstPid + 1, kExpired}});
    Check(ProcessCacheTestAccess::Paths(cache) == 0 &&
          ProcessCacheTestAccess::Processes(cache) == 0 && IconAlive(handle),
          "last PID did not remove cache entry or invalidated UI icon");
    snapshot.icon.reset();
    Check(!weak.expired(), "snapshot release invalidated row icon");
    row.icon.reset();
    Check(weak.expired() && !IconAlive(handle),
          "last UI reference did not release HICON");
}

void TestPidReuse() {
    ProcessCache cache;
    const auto oldPath = Path(L"C:\\FirewallXTests\\old.exe");
    const auto newPath = Path(L"C:\\FirewallXTests\\new.exe");
    ProcessIconRef oldIcon = cache.Get(kFirstPid, oldPath).icon;
    ProcessIconRef other = cache.Get(kFirstPid + 1, newPath).icon;
    const HICON oldHandle = oldIcon->handle();
    Check(cache.Get(kFirstPid, newPath).icon == other &&
          ProcessCacheTestAccess::Paths(cache) == 1 &&
          ProcessCacheTestAccess::Users(cache, newPath->text) == 2 &&
          IconAlive(oldHandle),
          "PID reuse retained old path or changed another process icon");
    oldIcon.reset();
    Check(!IconAlive(oldHandle), "PID reuse leaked previous icon");
    Sweep(cache, {{kFirstPid, kExpired}, {kFirstPid + 1, kExpired}});
    Check(ProcessCacheTestAccess::Paths(cache) == 0,
          "reused PID left stale path");
}

void TestGraceAndSystemProcesses() {
    ProcessCache cache;
    const auto path = Path(L"C:\\FirewallXTests\\grace.exe");
    cache.Get(kFirstPid, path);
    cache.Get(0, {});
    cache.Get(4, {});
    Sweep(cache, {{kFirstPid, 1}});
    Check(ProcessCacheTestAccess::Processes(cache) == 3 &&
          ProcessCacheTestAccess::Users(cache, path->text) == 1,
          "process grace period was bypassed");
    Sweep(cache, {{kFirstPid, kExpired}});
    Check(ProcessCacheTestAccess::Processes(cache) == 2 &&
          ProcessCacheTestAccess::Paths(cache) == 1 &&
          ProcessCacheTestAccess::Users(cache, L"") == 2,
          "expired process remained or system PID was removed");
}

void TestIconSize() {
    ProcessCache cache;
    const auto path = Path(L"C:\\FirewallXTests\\dpi.exe");
    ProcessIconRef smallIcon = cache.Get(kFirstPid, path).icon;
    const HICON smallIconHandle = smallIcon->handle();
    cache.SetIconSize(16);
    Check(cache.Get(kFirstPid, path).icon == smallIcon &&
          ProcessCacheTestAccess::Users(cache, path->text) == 1,
          "unchanged DPI reloaded icon");

    ProcessCacheTestAccess::Reserve(cache);
    cache.SetIconSize(32);
    Check(ProcessCacheTestAccess::Paths(cache) == 0 &&
          ProcessCacheTestAccess::PathBuckets(cache) <= 8 && IconAlive(smallIconHandle),
          "DPI change invalidated an existing UI reference");
    ProcessIconRef largeIcon = cache.Get(kFirstPid, path).icon;
    Check(largeIcon && largeIcon != smallIcon && largeIcon->size() == 32 && smallIcon->size() == 16 &&
          ProcessCacheTestAccess::Users(cache, path->text) == 1,
          "DPI change did not replace cached icon");
    smallIcon.reset();
    Check(!IconAlive(smallIconHandle), "DPI change retained old HICON");
    const HICON largeIconHandle = largeIcon->handle();
    cache.SetIconSize(0);
    largeIcon.reset();
    Check(!IconAlive(largeIconHandle) && cache.Get(kFirstPid, path).icon->size() == 16,
          "default icon size did not release old generation");
}

void TestSystemCacheStorage() {
    detail::AliveCache cache;
    const ULONGLONG now = kProcessForgetMs + kProcessSweepMs + 10000;
    const auto path = Path(L"C:\\FirewallXTests\\retained.exe");
    for (DWORD i = 0; i < 20000; ++i) {
        auto& entry = cache.map[i];
        entry.touched = i < 32 ? now : 1;
        entry.path = path;
    }
    const size_t peak = cache.map.bucket_count();
    const auto* retained = &cache.map.at(0);
    detail::SweepAliveLocked(cache, now);
    Check(cache.map.size() == 32 && cache.map.bucket_count() < peak / 8 &&
          &cache.map.at(0) == retained && retained->path == path,
          "system process cache retained peak buckets or changed a surviving entry");
    const size_t stable = cache.map.bucket_count();
    detail::SweepAliveLocked(cache, now + kProcessSweepMs);
    Check(cache.map.bucket_count() == stable, "stable system cache changed bucket storage");
    for (auto& item : cache.map) item.second.touched = 1;
    cache.swept = 0;
    detail::SweepAliveLocked(cache, now);
    Check(cache.map.empty() && cache.map.bucket_count() <= 8,
          "empty system process cache retained peak buckets");
}

void TestRehashAndRepeatedCleanup() {
    TestSystemCacheStorage();
    ProcessCache cache;
    ProcessCacheTestAccess::Reserve(cache);
    const size_t processBuckets = ProcessCacheTestAccess::ProcessBuckets(cache);
    const size_t pathBuckets = ProcessCacheTestAccess::PathBuckets(cache);
    const auto firstPath = Path(L"C:\\FirewallXTests\\stable.exe");
    const auto* retained = &cache.Get(kFirstPid, firstPath);
    ProcessIconRef first = retained->icon;
    std::vector<std::pair<DWORD, ULONGLONG>> states{{kFirstPid, 0}};
    for (DWORD i = 1; i <= 48; ++i) {
        cache.Get(kFirstPid + i,
                  Path(L"C:\\FirewallXTests\\item" + std::to_wstring(i) + L".exe"));
        states.emplace_back(kFirstPid + i, kExpired);
    }
    Sweep(cache, states);
    Check(ProcessCacheTestAccess::Paths(cache) == 1 &&
          ProcessCacheTestAccess::Processes(cache) == 1 &&
          cache.Get(kFirstPid, firstPath).icon == first &&
          &cache.Get(kFirstPid, firstPath) == retained &&
          ProcessCacheTestAccess::ProcessBuckets(cache) < processBuckets / 8 &&
          ProcessCacheTestAccess::PathBuckets(cache) < pathBuckets / 8,
          "trimming retained peak buckets, invalidated references or reloaded an icon");
    Sweep(cache, {{kFirstPid, kExpired}});
    Check(ProcessCacheTestAccess::Paths(cache) == 0 &&
          ProcessCacheTestAccess::ProcessBuckets(cache) <= 8 &&
          ProcessCacheTestAccess::PathBuckets(cache) <= 8,
          "empty process cache retained peak buckets");

    for (DWORD i = 0; i < 32; ++i) {
        cache.Get(kFirstPid + i, Path(L""));
        Sweep(cache, {{kFirstPid + i, kExpired}});
        Check(ProcessCacheTestAccess::Paths(cache) == 0 &&
              ProcessCacheTestAccess::Processes(cache) == 0,
              "repeated process exits accumulated cache entries");
    }
}

void TestApplicationIconFallback() {
    Check(!ExtractApplicationIcon(L"", 16, GetCurrentProcess()) &&
          !ExtractApplicationIcon(L"C:\\FirewallXTests\\missing.exe", 16) &&
          !ExtractApplicationIcon(SystemDirFile(L"shell32.dll"), 0) &&
          !ExtractPackagedAppIcon(L"", 16),
          "missing icon did not leave fallback to caller");
    ProcessIcon icon(ExtractApplicationIcon(SystemDirFile(L"shell32.dll"), 32,
                                            GetCurrentProcess()), 32);
    CheckIconSize(icon.handle(), 32);
}

void WritePng(const std::wstring& path, UINT size, DWORD color) {
    using Microsoft::WRL::ComPtr;
    ComPtr<IWICImagingFactory> factory;
    Check(SUCCEEDED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_PPV_ARGS(&factory))), "cannot create PNG writer");
    ComPtr<IWICStream> stream;
    ComPtr<IWICBitmapEncoder> encoder;
    ComPtr<IWICBitmapFrameEncode> frame;
    Check(SUCCEEDED(factory->CreateStream(&stream)) &&
          SUCCEEDED(stream->InitializeFromFilename(path.c_str(), GENERIC_WRITE)) &&
          SUCCEEDED(factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder)) &&
          SUCCEEDED(encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache)) &&
          SUCCEEDED(encoder->CreateNewFrame(&frame, nullptr)) &&
          SUCCEEDED(frame->Initialize(nullptr)) && SUCCEEDED(frame->SetSize(size, size)),
          "cannot initialize PNG fixture");
    WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
    std::vector<DWORD> pixels(static_cast<size_t>(size) * size, color);
    Check(SUCCEEDED(frame->SetPixelFormat(&format)) && format == GUID_WICPixelFormat32bppBGRA &&
          SUCCEEDED(frame->WritePixels(size, size * 4, size * size * 4,
              reinterpret_cast<BYTE*>(pixels.data()))) &&
          SUCCEEDED(frame->Commit()) && SUCCEEDED(encoder->Commit()),
          "cannot write PNG fixture");
}

void TestManifestAssets() {
    struct Fixture {
        std::filesystem::path directory;
        Fixture() {
            wchar_t temp[MAX_PATH]{}, suffix[40]{};
            GUID guid{};
            Check(GetTempPathW(MAX_PATH, temp) && SUCCEEDED(CoCreateGuid(&guid)) &&
                  StringFromGUID2(guid, suffix, static_cast<int>(std::size(suffix))),
                  "cannot name package fixture");
            directory = std::filesystem::path(temp) / (std::wstring(L"FirewallXIcons-") + suffix);
            Check(std::filesystem::create_directory(directory), "cannot create package fixture");
        }
        ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
    } fixture;
    const auto file = [&](const wchar_t* name) { return (fixture.directory / name).wstring(); };
    {
        std::ofstream manifest(fixture.directory / L"AppxManifest.xml", std::ios::binary);
        manifest << R"(<Package xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
<Applications><Application Id="Other" Executable="other.exe">
<uap:VisualElements Square44x44Logo="Wrong.png"/></Application>
<Application Id="App" Executable="bin/fixture.exe">
<uap:VisualElements Square44x44Logo="Logo.png"/></Application>
<Application Id="Scale" Executable="scale.exe">
<uap:VisualElements Square44x44Logo="ScaleLogo.png"/></Application>
<Application Id="Alpha" Executable="alpha.exe">
<uap:VisualElements Square44x44Logo="Alpha.png"/></Application>
</Applications></Package>)";
        Check(manifest.good(), "cannot write package manifest fixture");
    }
    WritePng(file(L"Wrong.png"), 16, 0xFFFF0000);
    WritePng(file(L"Logo.targetsize-16.png"), 16, 0xFFFF0000);
    WritePng(file(L"Logo.targetsize-16_altform-unplated.png"), 16, 0xFF0000FF);
    WritePng(file(L"Logo.targetsize-32_altform-unplated.png"), 32, 0xFF00FF00);
    WritePng(file(L"Logo.scale-100.png"), 44, 0xFFFFFF00);
    WritePng(file(L"LogoOther.targetsize-16_altform-unplated.png"), 16, 0xFFFF0000);
    WritePng(file(L"ScaleLogo.scale-200.png"), 88, 0xFF00FFFF);
    WritePng(file(L"Alpha.png"), 16, 0x800000FF);
    const std::wstring path = file(L"bin\\fixture.exe");
    for (const int size : {16, 20, 32, 64}) {
        ProcessIcon icon(ExtractApplicationIcon(path, size), size);
        CheckIconSize(icon.handle(), size);
        const auto pixels = IconTest::Pixels(icon.handle());
        const DWORD expected = size == 16 ? 0xFF0000FF : 0xFF00FF00;
        Check(std::all_of(pixels.begin(), pixels.end(), [&](DWORD pixel) { return pixel == expected; }),
              "package chose another application, wrong targetsize or plated logo");
    }
    ProcessIcon scaled(ExtractApplicationIcon(file(L"scale.exe"), 20), 20);
    const auto pixels = IconTest::Pixels(scaled.handle());
    Check(pixels.size() == 400 && std::all_of(pixels.begin(), pixels.end(),
              [](DWORD pixel) { return pixel == 0xFF00FFFF; }),
          "package scale variant was not decoded and resized");
    ProcessIcon alpha(ExtractApplicationIcon(file(L"alpha.exe"), 16), 16);
    const auto alphaPixels = IconTest::Pixels(alpha.handle());
    Check(std::all_of(alphaPixels.begin(), alphaPixels.end(),
              [](DWORD pixel) { return pixel == 0x80000080; }),
          "package PNG alpha was lost or not premultiplied");
    Check(!ExtractApplicationIcon(file(L"missing.exe"), 16),
          "unknown executable inherited another application's logo");
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; ++i) {
        ProcessIcon icon(ExtractApplicationIcon(path, 16), 16);
        Check(icon.handle() != nullptr, "repeated PNG extraction failed");
    }
    std::cout << "100 uncached package PNG loads: " <<
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count()
        << " ms\n";
}

void TestPackagedIcons() {
    const std::wstring id = L"Microsoft.WindowsStore_8wekyb3d8bbwe!App";
    const std::wstring name = L"shell:AppsFolder\\" + id;
    Microsoft::WRL::ComPtr<IShellItem> item;
    if (FAILED(SHCreateItemFromParsingName(name.c_str(), nullptr,
                                          IID_PPV_ARGS(&item)))) {
        std::cout << "Microsoft Store icon test skipped: package not registered\n";
        return;
    }
    for (const int size : {16, 20, 24, 32, 48, 64}) {
        HICON handle = nullptr;
        {
            ProcessIcon icon(ExtractPackagedAppIcon(id, size), size);
            handle = icon.handle();
            CheckIconSize(handle, size);
        }
        Check(!IconAlive(handle), "packaged app HICON was not destroyed");
    }
    // Прогреваем Shell до измерения: его собственные кеши не принадлежат нам.
    const DWORD before = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    for (int i = 0; i < 32; ++i) {
        ProcessIcon icon(ExtractPackagedAppIcon(id, 32), 32);
        CheckIconSize(icon.handle(), 32);
    }
    Check(GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) == before,
          "packaged icon extraction leaked GDI bitmaps");
    std::cout << "Microsoft Store icons tested at 16, 20, 24, 32, 48, 64 px\n";
}

void TestPackagedIconPaths() {
    const std::wstring path = IconTest::StoreExecutable();
    if (path.empty()) {
        std::cout << "Packaged icon path test skipped: Microsoft Store not installed\n";
        return;
    }
    const size_t file = path.find_last_of(L'\\');
    const size_t package = path.find_last_of(L'\\', file - 1);
    const std::wstring stale = path.substr(0, package + 1) +
        L"Microsoft.WindowsStore_0.0.0.1_x64__8wekyb3d8bbwe\\WinStore.App.exe";
    Check(GetFileAttributesW(stale.c_str()) == INVALID_FILE_ATTRIBUTES,
          "stale package fixture unexpectedly exists");
    for (const int size : {16, 24, 32, 48}) {
        ProcessIcon expected(ExtractPackagedAppIcon(
            L"Microsoft.WindowsStore_8wekyb3d8bbwe!App", size), size);
        const auto pixels = IconTest::Pixels(expected.handle());
        for (const std::wstring& candidate : {path, FoldCaseCopy(path), stale, FoldCaseCopy(stale)}) {
            ProcessIcon icon(ExtractApplicationIcon(candidate, size), size);
            CheckIconSize(icon.handle(), size);
            Check(IconTest::Pixels(icon.handle()) == pixels,
                  "path-only packaged icon differs from registered application");
        }
    }
    const std::wstring wrong = path.substr(0, file + 1) + L"NotAnApplication.exe";
    Check(!ExtractApplicationIcon(wrong, 16),
          "unrelated executable inherited another packaged application icon");
    std::cout << "Packaged icons tested by current/stale paths without PID\n";
}

void TestRunningPackagedProcess() {
    HANDLE raw = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Check(raw != INVALID_HANDLE_VALUE, "cannot enumerate processes");
    const std::unique_ptr<void, decltype(&CloseHandle)> snapshot(raw, CloseHandle);
    PROCESSENTRY32W entry{ sizeof(entry) };
    if (!Process32FirstW(snapshot.get(), &entry))
        throw std::runtime_error("cannot read process snapshot");
    do {
        HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, entry.th32ProcessID);
        if (!handle) continue;
        auto process = std::make_shared<ProcessHandleInfo>(handle,
                                                          entry.th32ProcessID, false);
        UINT32 length = 0;
        if (GetApplicationUserModelId(handle, &length, nullptr) != ERROR_INSUFFICIENT_BUFFER)
            continue;
        // Не запускаем Store или другие приложения: используем уже работающий
        // пакетный процесс. Пустой путь не даёт незаметно уйти в EXE-fallback.
        ProcessIcon icon(ExtractApplicationIcon(L"", 32, handle), 32);
        if (!icon.handle()) continue;
        CheckIconSize(icon.handle(), 32);
        wchar_t buffer[32768]{};
        DWORD count = static_cast<DWORD>(std::size(buffer));
        Check(QueryFullProcessImageNameW(handle, 0, buffer, &count),
              "cannot query packaged process path");
        const auto path = std::make_shared<const ProcessPathInfo>(
            std::wstring(buffer, count), std::move(process));
        ProcessCache cache;
        ProcessIconRef cached = cache.Get(entry.th32ProcessID, path).icon;
        Check(cached && cache.Get(entry.th32ProcessID, path).icon == cached,
              "packaged process icon was not cached");
        CheckIconSize(cached->handle(), 16);
        cache.SetIconSize(32);
        CheckIconSize(cache.Get(entry.th32ProcessID, path).icon->handle(), 32);
        std::wcout << L"Packaged process tested: " << entry.szExeFile << L'\n';
        return;
    } while (Process32NextW(snapshot.get(), &entry));
    std::cout << "Packaged process test skipped: no accessible running app\n";
}

void TestInterfaceIcon() {
    ProcessCache cache;
    const ProcessIconRef smallIcon = cache.InterfaceIcon();
    Check(smallIcon && cache.InterfaceIcon() == smallIcon &&
              ProcessCacheTestAccess::Processes(cache) == 0 && ProcessCacheTestAccess::Paths(cache) == 0,
          "interface icons created entries in the process cache");
    cache.SetIconSize(32);
    const ProcessIconRef largeIcon = cache.InterfaceIcon();
    Check(largeIcon && largeIcon != smallIcon && largeIcon->size() == 32 && smallIcon->size() == 16 &&
              cache.InterfaceIcon() == largeIcon && ProcessCacheTestAccess::Processes(cache) == 0,
          "interface icon did not refresh after a DPI change");
}

void TestCacheLifetime() {
    ProcessIconRef retained;
    {
        ProcessCache cache;
        retained = cache.Get(kFirstPid, Path(L"C:\\FirewallXTests\\retained.exe")).icon;
    }
    const HICON handle = retained->handle();
    Check(IconAlive(handle), "cache destruction invalidated retained UI icon");
    retained.reset();
    Check(!IconAlive(handle), "icon outliving cache leaked HICON");
}

} // namespace

int main() {
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return 1;
    int result = 0;
    try {
        TestOwnedIcon();
        TestGenericIcon();
        TestSharingAndLastProcess();
        TestPidReuse();
        TestGraceAndSystemProcesses();
        TestIconSize();
        TestRehashAndRepeatedCleanup();
        TestApplicationIconFallback();
        TestManifestAssets();
        TestPackagedIcons();
        TestPackagedIconPaths();
        TestRunningPackagedProcess();
        TestCacheLifetime();
        TestInterfaceIcon();
        std::cout << "Process cache tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        result = 1;
    }
    CoUninitialize();
    return result;
}
