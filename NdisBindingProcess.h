#pragma once
#include "NdisBinding.h"

namespace ndis_binding {

// Вызывается в самом начале wWinMain, до GUI, SCM, настроек и CIG.
bool TryRunHelper(int& exitCode) noexcept;

namespace detail {
inline constexpr wchar_t kWorkerArgument[] = L"--ndis-binding-worker";
inline constexpr wchar_t kAddWorkerArgument[] = L"--ndis-binding-add-worker";
inline constexpr wchar_t kNamedWorkerArgument[] = L"--ndis-binding-name-worker";
inline constexpr wchar_t kResumeArgument[] = L"--ndis-binding-resume";
using Worker = HRESULT (*)(const std::atomic<bool>& stopped, bool forceReattach, bool resumeLegacy);
using NamedWorker = HRESULT (*)(const std::atomic<bool>& stopped, std::wstring_view name);

HRESULT PrepareWindows(const std::atomic<bool>& stopped, bool forceReattach, bool resumeLegacy);
HRESULT AddTargetWindows(const std::atomic<bool>& stopped, uint64_t luid);
HRESULT ApplyNamedTargetWindows(const std::atomic<bool>& stopped, std::wstring_view name);
HRESULT RunIsolatedAddition(const std::atomic<bool>& stopped, uint64_t luid) noexcept;
HRESULT RunIsolated(const std::atomic<bool>& stopped, bool forceReattach) noexcept;
// Подменяемая операция позволяет проверить настоящий дочерний процесс без NetCfg.
bool DispatchHelper(int argc, wchar_t* const* argv, Worker worker, HRESULT& result,
                    AdditionalWorker additional = nullptr, NamedWorker named = nullptr) noexcept;
}
}
