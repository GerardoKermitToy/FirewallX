#include "RuleGenerator.h"
#include "RulePresets.h"
#include "ServiceInfo.h"
#include "SystemInfo.h"

#include <shlobj.h>
#include <shlwapi.h>
#include <winsvc.h>

#include <algorithm>
#include <memory>
#include <unordered_map>
#include <unordered_set>

namespace RuleGenerator {
namespace {

std::wstring Expand(const std::wstring& value) {
    if (value.empty()) return {};
    const DWORD size = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (!size || size > 32768) return {};
    std::wstring result(size, L'\0');
    if (!ExpandEnvironmentStringsW(value.c_str(), result.data(), size)) return {};
    result.resize(size - 1);
    return result;
}

std::wstring FullPath(std::wstring path) {
    if (path.empty() || PathIsRelativeW(path.c_str())) return {};
    const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!size || size > 32768) return {};
    std::wstring full(size, L'\0');
    const DWORD length = GetFullPathNameW(path.c_str(), size, full.data(), nullptr);
    if (!length || length >= size) return {};
    full.resize(length);
    const DWORD longSize = GetLongPathNameW(full.c_str(), nullptr, 0);
    if (longSize && longSize <= 32768) {
        std::wstring longPath(longSize, L'\0');
        const DWORD n = GetLongPathNameW(full.c_str(), longPath.data(), longSize);
        if (n && n < longSize) {
            longPath.resize(n);
            full = std::move(longPath);
        }
    }
    return full;
}

std::wstring FileName(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

bool IsFile(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring RegistryString(HKEY root, const std::wstring& key, const wchar_t* name, REGSAM view = 0) {
    HKEY handle = nullptr;
    if (RegOpenKeyExW(root, key.c_str(), 0, KEY_QUERY_VALUE | view, &handle) != ERROR_SUCCESS) return {};
    DWORD type = 0, bytes = 0;
    LONG status = RegQueryValueExW(handle, name, nullptr, &type, nullptr, &bytes);
    std::wstring value;
    if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) &&
        bytes >= sizeof(wchar_t) && bytes <= 65536 && bytes % sizeof(wchar_t) == 0) {
        value.resize(bytes / sizeof(wchar_t) + 1, L'\0');
        status = RegQueryValueExW(handle, name, nullptr, &type,
                                  reinterpret_cast<BYTE*>(value.data()), &bytes);
        if (status == ERROR_SUCCESS) value.resize(wcsnlen_s(value.c_str(), value.size()));
        else value.clear();
    }
    RegCloseKey(handle);
    return Expand(value);
}

// Для SCM не угадываем путь с незакавыченными пробелами: CreateProcess может
// выбрать другой исполняемый файл, и правило было бы привязано не к службе.
std::wstring ServiceImage(std::wstring command) {
    command = Expand(command);
    const size_t start = command.find_first_not_of(L" \t");
    if (start == std::wstring::npos) return {};
    if (command[start] == L'"') {
        const size_t end = command.find(L'"', start + 1);
        if (end == std::wstring::npos) return {};
        return FullPath(command.substr(start + 1, end - start - 1));
    }
    const size_t end = command.find_first_of(L" \t", start);
    return FullPath(command.substr(start, end - start));
}

std::wstring KnownFolder(REFKNOWNFOLDERID id) {
    PWSTR value = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &value))) return {};
    std::wstring result(value);
    CoTaskMemFree(value);
    return result;
}

// Разворачивает только явно заданные компоненты с масками, не рекурсивно
// обходит произвольные каталоги и никогда не следует вглубь дерева диска.
void ExpandPattern(const std::wstring& pattern, const std::atomic_bool& cancel,
                   const std::function<bool(const std::wstring&)>& safeDirectory,
                   const std::function<void(const std::wstring&)>& found) {
    if (cancel.load(std::memory_order_relaxed)) return;
    const size_t wildcard = pattern.find_first_of(L"*?");
    const size_t parent = pattern.find_last_of(L"\\/", wildcard);
    if (parent == std::wstring::npos || !safeDirectory(pattern.substr(0, parent))) return;
    if (wildcard == std::wstring::npos) {
        const DWORD attributes = GetFileAttributesW(pattern.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) found(pattern);
        return;
    }
    const size_t slash = pattern.find_first_of(L"\\/", wildcard);
    const std::wstring part = pattern.substr(0, slash);
    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(part.c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) return;
    const size_t base = part.find_last_of(L"\\/");
    const std::wstring prefix = base == std::wstring::npos ? L"" : part.substr(0, base + 1);
    do {
        if (cancel.load(std::memory_order_relaxed)) break;
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        const std::wstring next = prefix + data.cFileName;
        if (slash == std::wstring::npos) {
            if (!(data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                found(next);
        } else if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ExpandPattern(next + pattern.substr(slash), cancel, safeDirectory, found);
        }
    } while (FindNextFileW(search, &data));
    FindClose(search);
}

void DiscoverServices(std::vector<ServiceCandidate>& out, const std::atomic_bool& cancel) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return;
    for (const ServiceEntry& entry : ServiceInfo::All(true)) {
        if (cancel.load(std::memory_order_relaxed)) break;
        if (!RulePresets::MayUseService({}, entry.name)) continue;
        SC_HANDLE service = OpenServiceW(manager, entry.name.c_str(), SERVICE_QUERY_CONFIG);
        if (!service) continue;
        DWORD bytes = 0;
        QueryServiceConfigW(service, nullptr, 0, &bytes);
        std::vector<BYTE> buffer(bytes);
        const bool ok = bytes && QueryServiceConfigW(service,
            reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()), bytes, &bytes);
        CloseServiceHandle(service);
        if (!ok) continue;
        const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
        const std::wstring image = ServiceImage(config->lpBinaryPathName ? config->lpBinaryPathName : L"");
        if (image.empty() || !RulePresets::MayUseService(FileName(image), entry.name)) continue;
        const std::wstring key = L"SYSTEM\\CurrentControlSet\\Services\\" + entry.name + L"\\Parameters";
        std::wstring dll = RegistryString(HKEY_LOCAL_MACHINE, key, L"ServiceDll");
        const bool hasDll = !dll.empty();
        if (dll.size() >= 2 && dll.front() == L'"' && dll.back() == L'"')
            dll = dll.substr(1, dll.size() - 2);
        dll = FullPath(dll);
        // Для разделяемого процесса без доступной DLL нельзя подтвердить
        // подпись самой службы по одной только подписи её хост-процесса.
        if (((config->dwServiceType & SERVICE_WIN32_SHARE_PROCESS) ||
             EqualNoCase(FileName(image), L"svchost.exe") || hasDll) && dll.empty()) continue;
        out.push_back({entry, image, dll});
    }
    CloseServiceHandle(manager);
}

} // анонимное пространство имён

Result Scan(const std::atomic_bool& cancel, const Progress& progress) {
    std::vector<std::wstring> paths;
    std::unordered_set<std::wstring> pathKeys;
    const auto add = [&](const std::wstring& raw) {
        if (RulePresets::ExcludedFromGeneration(raw)) return;
        std::wstring path = FullPath(raw);
        if (path.empty() || !IsFile(path)) return;
        if (pathKeys.insert(FoldCaseCopy(path)).second) paths.push_back(std::move(path));
    };
    const std::vector<std::wstring> executables = RulePresets::Executables();
    const std::wstring system = SystemDirectory();
    wchar_t windowsBuffer[MAX_PATH]{};
    const UINT windowsSize = GetWindowsDirectoryW(windowsBuffer, MAX_PATH);
    const std::wstring windows = windowsSize && windowsSize < MAX_PATH ? windowsBuffer : L"";
    // Типовые каталоги проверяются только на диске Windows и без перехода
    // через точки повторной обработки, способные вести на другой носитель.
    const auto onWindowsDrive = [&](const std::wstring& path) {
        return windows.size() >= 2 && path.size() >= 2 && windows[1] == L':' && path[1] == L':' &&
            CompareStringOrdinal(windows.data(), 1, path.data(), 1, TRUE) == CSTR_EQUAL;
    };
    std::unordered_map<std::wstring, bool> checkedDirectories;
    std::function<bool(const std::wstring&)> safeDirectory = [&](const std::wstring& input) {
        std::wstring dir = input;
        if (dir.size() == 2 && dir[1] == L':') dir.push_back(L'\\');
        if (!onWindowsDrive(dir)) return false;
        const std::wstring key = FoldCaseCopy(dir);
        const auto cached = checkedDirectories.find(key);
        if (cached != checkedDirectories.end()) return cached->second;
        bool safe = true;
        if (dir.size() > 3) {
            const size_t slash = dir.find_last_of(L"\\/");
            safe = slash != std::wstring::npos && safeDirectory(dir.substr(0, slash));
        }
        if (safe) {
            const DWORD attributes = GetFileAttributesW(dir.c_str());
            safe = attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
                   !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
        }
        checkedDirectories.emplace(key, safe);
        return safe;
    };
    for (const std::wstring& name : executables) {
        if (cancel.load(std::memory_order_relaxed)) break;
        if (!system.empty()) ExpandPattern(system + name, cancel, safeDirectory, add);
        if (!windows.empty()) {
            ExpandPattern(windows + L"\\" + name, cancel, safeDirectory, add);
            ExpandPattern(windows + L"\\SysWOW64\\" + name, cancel, safeDirectory, add);
        }
        const std::wstring key = L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + name;
        for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
            for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
                std::wstring value = RegistryString(root, key, nullptr, view);
                if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
                    value = value.substr(1, value.size() - 2);
                if (EqualNoCase(FileName(value), name)) add(value);
            }
        }
    }

    const std::wstring programFiles = KnownFolder(FOLDERID_ProgramFiles);
    const std::wstring programFilesX86 = KnownFolder(FOLDERID_ProgramFilesX86);
    const std::wstring local = KnownFolder(FOLDERID_LocalAppData);
    const std::wstring roaming = KnownFolder(FOLDERID_RoamingAppData);
    const std::wstring programData = KnownFolder(FOLDERID_ProgramData);
    static constexpr const wchar_t* common[] = {
        L"Google\\Chrome\\Application\\chrome.exe", L"Microsoft\\Edge\\Application\\msedge.exe",
        L"Mozilla Firefox\\firefox.exe", L"Mozilla Firefox\\pingsender.exe",
        L"Mozilla Thunderbird\\thunderbird.exe", L"BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        L"Vivaldi\\Application\\vivaldi.exe", L"Opera\\*\\opera.exe", L"Opera\\opera.exe",
        L"Opera GX\\*\\opera.exe", L"Microsoft\\EdgeWebView\\Application\\*\\msedgewebview2.exe",
        L"Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", L"Windows Defender\\MpCmdRun.exe",
        L"Steam\\steam.exe", L"Steam\\bin\\cef\\cef.win7x64\\steamwebhelper.exe",
        L"Steam\\bin\\steamerrorreporter64.exe", L"obs-studio\\bin\\64bit\\obs64.exe",
        L"TeamViewer\\TeamViewer.exe", L"TeamViewer\\TeamViewer_Service.exe",
        L"AnyDesk\\AnyDesk.exe", L"RustDesk\\rustdesk.exe", L"qBittorrent\\qbittorrent.exe",
        L"BitTorrent\\BitTorrent.exe", L"uTorrent\\uTorrent.exe", L"Transmission\\transmission-qt.exe",
        L"Dropbox\\Client\\Dropbox.exe", L"Google\\Drive File Stream\\*\\GoogleDriveFS.exe",
        L"PuTTY\\putty.exe", L"WinSCP\\WinSCP.exe", L"Microsoft OneDrive\\OneDrive.exe",
        L"Microsoft OneDrive\\*\\OneDrive.Sync.Service.exe",
        L"Microsoft VS Code\\Code.exe", L"Microsoft Visual Studio\\*\\*\\Common7\\IDE\\devenv.exe",
        L"Microsoft Visual Studio *\\Common7\\IDE\\devenv.exe",
        L"Git\\cmd\\git.exe", L"Git\\mingw64\\libexec\\git-core\\git-remote-https.exe",
        L"Microsoft Office\\root\\Office16\\EXCEL.EXE", L"Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        L"Microsoft Office\\root\\Office16\\ONENOTE.EXE", L"Microsoft Office\\root\\Office16\\MSACCESS.EXE",
        L"NVIDIA Corporation\\NvContainer\\nvcontainer.exe", L"NVIDIA Corporation\\Display.NvContainer\\nvdisplay.container.exe"
    };
    static constexpr const wchar_t* user[] = {
        L"Google\\Chrome\\Application\\chrome.exe", L"Microsoft\\Edge\\Application\\msedge.exe",
        L"BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"Vivaldi\\Application\\vivaldi.exe",
        L"Programs\\Opera\\opera.exe", L"Programs\\Opera\\*\\opera.exe",
        L"Programs\\Microsoft VS Code\\Code.exe", L"Discord\\app-*\\Discord.exe",
        L"DiscordCanary\\app-*\\DiscordCanary.exe", L"DiscordPTB\\app-*\\DiscordPTB.exe",
        L"Microsoft\\OneDrive\\OneDrive.exe", L"Microsoft\\OneDrive\\*\\OneDrive.Sync.Service.exe",
        L"Zoom\\bin\\Zoom.exe", L"slack\\app-*\\slack.exe", L"Telegram Desktop\\Telegram.exe",
        L"Programs\\Opera GX\\*\\opera.exe",
        L"Dropbox\\Client\\Dropbox.exe", L"Google\\Drive File Stream\\*\\GoogleDriveFS.exe",
        L"Yandex\\YandexDisk4\\YandexDisk4.exe", L"Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"
    };
    for (const std::wstring* root : {&programFiles, &programFilesX86})
        if (onWindowsDrive(*root)) for (const wchar_t* pattern : common)
            ExpandPattern(*root + L"\\" + pattern, cancel, safeDirectory, add);
    for (const std::wstring* root : {&local, &roaming})
        if (onWindowsDrive(*root)) for (const wchar_t* pattern : user)
            ExpandPattern(*root + L"\\" + pattern, cancel, safeDirectory, add);
    if (onWindowsDrive(programData))
        ExpandPattern(programData + L"\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe",
                      cancel, safeDirectory, add);

    // Системные приложения и MSIX проверяются только в известных семействах.
    static constexpr const wchar_t* packages[] = {
        L"Microsoft.WindowsStore_*\\WinStore.App.exe", L"Microsoft.Windows.Photos_*\\Photos.exe",
        L"Microsoft.WindowsAlarms_*\\HxCalendarAppImm.exe", L"microsoft.windowscommunicationsapps_*\\HxOutlook.exe",
        L"microsoft.windowscommunicationsapps_*\\HxCalendarAppImm.exe",
        L"Microsoft.MicrosoftOfficeHub_*\\M365Copilot.exe", L"Microsoft.Copilot_*\\CopilotApp.exe",
        L"Microsoft.MicrosoftSolitaireCollection_*\\Solitaire.exe", L"Microsoft.XboxApp_*\\XboxPcApp.exe",
        L"Microsoft.DesktopAppInstaller_*\\winget.exe",
        L"Microsoft.YourPhone_*\\PhoneExperienceHost.exe", L"MicrosoftWindows.Client.WebExperience_*\\WebExperienceHostApp.exe",
        L"Microsoft.MicrosoftStickyNotes_*\\Microsoft.Notes.exe", L"Microsoft.Todos_*\\Todo.exe",
        L"Microsoft.BingNews_*\\Microsoft.Msn.News.exe", L"Microsoft.BingWeather_*\\Microsoft.Msn.Weather.exe",
        L"Clipchamp.Clipchamp_*\\Clipchamp.exe", L"Microsoft.XboxGamingOverlay_*\\GameBar.exe"
    };
    if (onWindowsDrive(programFiles)) for (const wchar_t* pattern : packages)
        ExpandPattern(programFiles + L"\\WindowsApps\\" + pattern, cancel, safeDirectory, add);
    static constexpr const wchar_t* systemApps[] = {
        L"Microsoft.Windows.StartMenuExperienceHost_*\\StartMenuExperienceHost.exe",
        L"Microsoft.Windows.Search_*\\SearchHost.exe", L"MicrosoftWindows.Client.CBS_*\\SearchHost.exe",
        L"Microsoft.Windows.AppResolverUX_*\\AppHostRegistrationVerifier.exe"
    };
    if (!windows.empty()) for (const wchar_t* pattern : systemApps)
        ExpandPattern(windows + L"\\SystemApps\\" + pattern, cancel, safeDirectory, add);
    if (!windows.empty()) ExpandPattern(windows + L"\\ImmersiveControlPanel\\SystemSettings.exe",
                                        cancel, safeDirectory, add);

    std::vector<ServiceCandidate> services;
    if (!cancel.load(std::memory_order_relaxed)) DiscoverServices(services, cancel);
    for (const auto& service : services) add(service.image);
    return VerifyCandidates(paths, services, cancel, progress);
}

Result VerifyCandidates(const std::vector<std::wstring>& paths,
                        const std::vector<ServiceCandidate>& services,
                        const std::atomic_bool& cancel, const Progress& progress) {
    Result result;
    std::vector<std::wstring> files;
    std::unordered_set<std::wstring> fileKeys;
    for (const auto& path : paths)
        if (!RulePresets::ExcludedFromGeneration(path) &&
            fileKeys.insert(FoldCaseCopy(path)).second) files.push_back(path);
    const size_t imageCount = files.size();
    for (const auto& service : services)
        if (!RulePresets::ExcludedFromGeneration(service.image) && !service.dll.empty() &&
            fileKeys.insert(FoldCaseCopy(service.dll)).second)
            files.push_back(service.dll);
    std::unordered_map<std::wstring, bool> trusted;
    if (progress) progress(0, files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        if (cancel.load(std::memory_order_relaxed)) break;
        const std::wstring key = FoldCaseCopy(files[i]);
        // DLL не нужна, если все использующие её образы уже не прошли проверку.
        const bool needed = i < imageCount || std::any_of(services.begin(), services.end(),
            [&](const ServiceCandidate& service) {
                if (!EqualNoCase(service.dll, files[i])) return false;
                const auto host = trusted.find(FoldCaseCopy(service.image));
                return host != trusted.end() && host->second;
            });
        bool valid = false;
        if (needed) {
            FileSignature::TrustedFile file(files[i]);
            valid = static_cast<bool>(file);
            if (valid) result.files.push_back(std::move(file));
        }
        trusted.emplace(key, valid);
        if (progress) progress(i + 1, files.size());
    }
    if (cancel.load(std::memory_order_relaxed)) {
        result.cancelled = true;
        result.files.clear();
        return result;
    }
    for (const std::wstring& path : paths) {
        if (cancel.load(std::memory_order_relaxed)) {
            result.cancelled = true;
            result.rules.clear();
            result.files.clear();
            return result;
        }
        if (RulePresets::ExcludedFromGeneration(path) || !trusted[FoldCaseCopy(path)]) continue;
        std::vector<ServiceEntry> verified;
        for (const auto& service : services)
            if (EqualNoCase(service.image, path) &&
                (service.dll.empty() || trusted[FoldCaseCopy(service.dll)]))
                verified.push_back(service.entry);
        auto rules = RulePresets::Generate(path, verified);
        result.rules.insert(result.rules.end(), std::make_move_iterator(rules.begin()),
                            std::make_move_iterator(rules.end()));
    }
    if (cancel.load(std::memory_order_relaxed)) {
        result.cancelled = true;
        result.rules.clear();
        result.files.clear();
        return result;
    }
    // IGMP с PID 0 не связан с исполняемым файлом и не требует подписи.
    auto igmp = RulePresets::GenerateIgmp();
    result.rules.insert(result.rules.end(), std::make_move_iterator(igmp.begin()),
                        std::make_move_iterator(igmp.end()));
    return result;
}

} // namespace RuleGenerator
