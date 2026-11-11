#pragma once
#include <windows.h>
#include <objbase.h>
#include <atomic>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ndis_binding {
namespace detail {

inline constexpr wchar_t kConfigKey[] = L"SOFTWARE\\FirewallXNdisFilter\\Lwf";
inline constexpr wchar_t kComponentId[] = L"firewallx_ndis_filter";
inline constexpr GUID kFilterId = {0x6e76ead1, 0x7bcb, 0x49c4,
    {0x95, 0x47, 0xd3, 0xe6, 0xb3, 0x48, 0x8f, 0x71}};
inline constexpr DWORD kConfigVersion = 4;

struct Error { HRESULT status; };
inline void Check(HRESULT status) { if (FAILED(status)) throw Error{ status }; }
inline void CheckWin32(LSTATUS status) {
    if (status != ERROR_SUCCESS) throw Error{ HRESULT_FROM_WIN32(status) };
}

// SCM нужен только до подключения; открытый Client уже доказывает наличие драйвера.
inline HRESULT RequireDriverService() noexcept {
    const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return HRESULT_FROM_WIN32(GetLastError());
    const SC_HANDLE service = OpenServiceW(manager, L"FirewallXNdisFilter", SERVICE_QUERY_STATUS);
    const HRESULT status = service ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return status;
}

GUID ParseGuid(std::wstring_view text);

struct Adapter {
    GUID guid{};
    uint64_t luid = 0;
    // Административно выключенный адаптер не обязан иметь работающий модуль.
    bool expectRunning = true;
    // Исключённый адаптер должен иметь отключённые пути фильтра.
    bool excluded = false;
    std::wstring name;
    // Неподдерживаемые пути сохраняются для отключения, но не включаются.
    bool compatible = true;
};
using Targets = std::vector<Adapter>;

inline bool ShouldEnable(const Adapter& adapter) noexcept {
    return adapter.compatible && !adapter.excluded;
}

struct AttachedAdapter {
    Adapter identity;
    bool running = false;
};

enum class RecoveryPermission { Legacy, Allowed, InstallerControlled };
struct Configuration {
    bool allowed = false;
    RecoveryPermission recovery = RecoveryPermission::Legacy;
};
struct Binding {
    GUID adapter{};
    bool enabled = false;
};

bool SameTarget(const Adapter& first, const Adapter& second) noexcept;
bool SameTargets(const Targets& first, const Targets& second) noexcept;
void ValidateTargets(const Targets& targets);
bool AllTargetsRunning(const Targets& targets, std::span<const AttachedAdapter> attached) noexcept;
Targets SelectBindingTargets(std::span<const Binding> bindings, std::span<const Adapter> adapters);
void MarkExcludedByName(Targets& targets, std::span<const std::wstring> excluded) noexcept;

using ConfigurationReader = LSTATUS (*)(void*, const wchar_t*, DWORD, void*, DWORD*);
Configuration ReadConfiguration(ConfigurationReader read, void* context);

// Контракт отдельно от Windows API: тесты не меняют сеть, реестр и драйвер.
class System {
public:
    virtual ~System() = default;
    virtual bool Stopped() const = 0;
    virtual void OpenNetwork() = 0;
    virtual void LockNetwork() = 0;
    virtual void RequireInstalled() = 0;
    virtual Targets ResolveTargets(std::vector<Binding>* bindings = nullptr) = 0;
    virtual Configuration ReadConfiguration() = 0;
    virtual std::vector<Binding> ReadBindings() = 0;
    virtual void SetRecoveryAllowed(bool allowed) = 0;
    virtual void Disarm() = 0;
    virtual void Arm() = 0;
    virtual void SetBinding(const Adapter& adapter, bool enabled) = 0;
};

struct Inspection {
    Targets targets;
    bool needsRebind = false;
};
Inspection Inspect(System& system, std::span<const AttachedAdapter> attached);
Inspection InspectWindows(const std::atomic<bool>& stopped, std::span<const AttachedAdapter> attached);
Targets FindMissing(System& system, std::span<const AttachedAdapter> attached);
Targets FindWindowsMissing(const std::atomic<bool>& stopped, std::span<const AttachedAdapter> attached);
using Inspector = Inspection (*)(const std::atomic<bool>&, std::span<const AttachedAdapter>);
using Repair = HRESULT (*)(const std::atomic<bool>&);
HRESULT Ensure(const std::atomic<bool>& stopped, std::span<const AttachedAdapter> attached,
               Targets& targets, Inspector inspect, Repair repair, bool* rebound = nullptr) noexcept;
HRESULT Prepare(System& system, bool forceReattach = false, bool resumeLegacy = false) noexcept;

// Добавление не разоружает фильтр и не меняет привязки прежних целей.
std::optional<Adapter> InspectAddition(System& system, uint64_t luid, std::span<const AttachedAdapter> attached);
std::optional<Adapter> InspectWindowsAddition(const std::atomic<bool>& stopped, uint64_t luid,
                                             std::span<const AttachedAdapter> attached);
using AdditionInspector = std::optional<Adapter> (*)(const std::atomic<bool>&, uint64_t,
                                                    std::span<const AttachedAdapter>);
using AdditionalWorker = HRESULT (*)(const std::atomic<bool>&, uint64_t);
HRESULT EnsureAddition(const std::atomic<bool>& stopped, uint64_t luid, std::span<const AttachedAdapter> attached,
                       Adapter& added, AdditionInspector inspect, AdditionalWorker apply) noexcept;
HRESULT AddTarget(System& system, uint64_t luid) noexcept;
HRESULT ApplyNamedTarget(System& system, std::wstring_view name) noexcept;

} // namespace detail

// Проверка только читает состояние; отдельный worker допускается лишь при необходимости ремонта.
HRESULT EnsureBindings(const std::atomic<bool>& stopped, std::span<const detail::AttachedAdapter> attached,
                          detail::Targets& targets, bool* rebound = nullptr) noexcept;

HRESULT EnsureAdditionalBinding(const std::atomic<bool>& stopped, uint64_t luid,
                                std::span<const detail::AttachedAdapter> attached, detail::Adapter& added) noexcept;

// Настройки общие для desktop, службы и изолированного процесса NetCfg.
std::wstring InterfacePreferenceKey(std::wstring_view name);
HRESULT ReadExcludedInterfaces(std::vector<std::wstring>& excluded, const wchar_t* database = nullptr) noexcept;
HRESULT ApplyInterfaceBinding(std::wstring_view name) noexcept;

} // namespace ndis_binding
