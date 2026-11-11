#pragma once
#include "NdisBinding.h"
#include <functional>
#include <memory>
#include <mutex>

namespace ndis_binding::detail {

// Только чтение топологии. Поток владеет данными и COM-объектами, поэтому
// отмена ожидания не оставляет ссылок на System, NetCfg или стек вызывающего.
class TargetResolver {
    struct Work;
    std::mutex lock_;
    std::shared_ptr<Work> active_;
    static DWORD WINAPI Worker(void* context) noexcept;
public:
    using Query = std::function<Targets(const std::atomic<bool>& stopped)>;
    Targets Resolve(const std::atomic<bool>& stopped, Query query, DWORD timeoutMs = 15000);
};

} // namespace ndis_binding::detail
