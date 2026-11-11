#pragma once
#include "Rules.h"
#include <commctrl.h>
#include <unordered_map>

// Временные правила редактора не входят в RuleStore. Доступность их фильтров
// считаем один раз на имя при правке списка и после уведомления watcher.
class RuleInterfaceUi {
public:
    RuleInterfaceUi() = default;
    RuleInterfaceUi(const RuleInterfaceUi&) = delete;
    RuleInterfaceUi& operator=(const RuleInterfaceUi&) = delete;
    ~RuleInterfaceUi() { Stop(); }

    void Watch(HWND window, std::function<void()> changed) {
        Stop();
        changed_ = std::move(changed);
        if (!SetWindowSubclass(window, Events, reinterpret_cast<UINT_PTR>(this),
                               reinterpret_cast<DWORD_PTR>(this))) return;
        window_ = window;
        subscription_ = net::SharedNetworkInterfaces().Subscribe([window](const auto& event) {
            if (event.snapshot_updated)
                PostMessageW(window, RuleStore::kInterfacesChanged, 0, 0);
        });
    }

    void Refresh(std::span<const Rule> rules) {
        available_.clear();
        auto& watcher = net::SharedNetworkInterfaces();
        const auto snapshot = watcher.GetSnapshot();
        for (const auto& rule : rules) {
            if (rule.isInterface() || !(rule.conds & CondInterface)) continue;
            const auto [it, inserted] = available_.try_emplace(rule.interfaceName, false);
            if (inserted && !rule.interfaceName.empty())
                it->second = watcher.GetInterfaceNumberByName(rule.interfaceName, snapshot).has_value();
        }
    }

    bool Unavailable(const Rule& rule) const {
        if (rule.isInterface() || !(rule.conds & CondInterface)) return false;
        const auto found = available_.find(rule.interfaceName);
        return found == available_.end() || !found->second;
    }

private:
    void Stop() {
        if (subscription_) net::SharedNetworkInterfaces().Unsubscribe(subscription_);
        subscription_ = 0;
        if (window_)
            RemoveWindowSubclass(window_, Events, reinterpret_cast<UINT_PTR>(this));
        window_ = nullptr;
    }

    static LRESULT CALLBACK Events(HWND window, UINT message, WPARAM wp,
                                   LPARAM lp, UINT_PTR, DWORD_PTR data) {
        auto* self = reinterpret_cast<RuleInterfaceUi*>(data);
        if (message == RuleStore::kInterfacesChanged) {
            self->changed_();
            return 0;
        }
        if (message == WM_NCDESTROY) self->Stop();
        return DefSubclassProc(window, message, wp, lp);
    }

    HWND window_ = nullptr;
    uint64_t subscription_ = 0;
    std::function<void()> changed_;
    std::unordered_map<std::wstring, bool> available_;
};
