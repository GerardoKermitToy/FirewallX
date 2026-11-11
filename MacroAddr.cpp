#include "MacroAddr.h"
#include "StringRes.h"
#include "network_interface_watcher.h"

#include <mutex>
#include <utility>
#include <vector>

namespace {

// Смысл макросов задан здесь и нигде больше:
//   LOCAL_NETWORK      — подсети, к которым подключён компьютер (адрес + префикс
//                        интерфейса), то есть любой сосед по этим сетям;
//   MY_COMPUTER        — адреса самого компьютера, включая петлевые;
//   ALL_MY_ADDRESSES   — то же, но без петлевых: только адреса на интерфейсах;
//   BROADCAST_ADDRESSES— 255.255.255.255 и направленные широковещательные
//                        адреса каждой подсети IPv4;
//   MULTICAST_ADDRESSES— 224.0.0.0/4 и ff00::/8.
const AddrMacros::Def kDefs[] = {
    { AddrMacro::DnsServers,         L"DNS_SERVERS",         IDS_MACRO_DNS       },
    { AddrMacro::LocalNetwork,       L"LOCAL_NETWORK",       IDS_MACRO_SUBNETS   },
    { AddrMacro::WinsServers,        L"WINS_SERVERS",        IDS_MACRO_WINS      },
    { AddrMacro::Gateways,           L"GATEWAYS",            IDS_MACRO_GATEWAYS  },
    { AddrMacro::MyComputer,         L"MY_COMPUTER",         IDS_MACRO_LOCALHOST },
    { AddrMacro::AllMyAddresses,     L"ALL_MY_ADDRESSES",    IDS_MACRO_ALL_LOCAL },
    { AddrMacro::BroadcastAddresses, L"BROADCAST_ADDRESSES", IDS_MACRO_BROADCAST },
    { AddrMacro::MulticastAddresses, L"MULTICAST_ADDRESSES", IDS_MACRO_MULTICAST },
};

// Только производные наборы для matcher. Системный опрос, сведения об интерфейсах
// и уведомления принадлежат watcher; отдельного опроса IP Helper здесь нет.
struct Snapshot {
    std::vector<MacroEntry> byMacro[9];
    uint64_t interfaceVersion = 0;
    uint64_t version = 0;
};

struct State {
    std::mutex mutex;
    Snapshot snapshot;
    ULONGLONG attemptTick = 0;
    bool attempted = false;
    net::NetworkInterfaceWatcher& watcher = net::SharedNetworkInterfaces();
};

State& Cache() {
    // Общий watcher обслуживает также группы правил интерфейсов.
    static State state;
    return state;
}

size_t Slot(AddrMacro m) { return static_cast<size_t>(m); }

void Add(std::vector<MacroEntry>& v, const IpAddr& a, int prefix) {
    if (a.family != AF_INET && a.family != AF_INET6) return;
    for (const MacroEntry& e : v)
        if (e.prefix == prefix && e.addr == a) return;      // без дубликатов
    v.push_back(MacroEntry{ a, prefix });
}

bool SameValues(const Snapshot& a, const Snapshot& b) {
    for (size_t slot = 0; slot < std::size(a.byMacro); ++slot) {
        const auto& left = a.byMacro[slot];
        const auto& right = b.byMacro[slot];
        if (left.size() != right.size()) return false;

        // IP Helper не обещает стабильный порядок адаптеров. Сравниваем наборы,
        // иначе одна перестановка вызвала бы ложную смену версии и FlushVerdicts.
        for (const MacroEntry& x : left) {
            bool found = false;
            for (const MacroEntry& y : right) {
                if (x.prefix == y.prefix && x.addr == y.addr) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
    }
    return true;
}

void BuildConstants(Snapshot& s) {
    // 255.255.255.255 — всегда широковещательный
    Add(s.byMacro[Slot(AddrMacro::BroadcastAddresses)],
        IpAddr::V4(0xFFFFFFFFu), -1);

    IpAddr mc4{};                    // 224.0.0.0/4
    mc4.family = AF_INET;
    mc4.b[0] = 224;
    Add(s.byMacro[Slot(AddrMacro::MulticastAddresses)], mc4, 4);

    IpAddr mc6{};                    // ff00::/8
    mc6.family = AF_INET6;
    mc6.b[0] = 0xFF;
    Add(s.byMacro[Slot(AddrMacro::MulticastAddresses)], mc6, 8);

    IpAddr lo4{};                    // 127.0.0.0/8 — вся петлевая сеть IPv4
    lo4.family = AF_INET;
    lo4.b[0] = 127;
    Add(s.byMacro[Slot(AddrMacro::MyComputer)], lo4, 8);

    IpAddr lo6{};                    // ::1
    lo6.family = AF_INET6;
    lo6.b[15] = 1;
    Add(s.byMacro[Slot(AddrMacro::MyComputer)], lo6, -1);
}

void BuildFromInterfaces(Snapshot& s, const net::NetworkInterfaceWatcher::Snapshot& source) {
    for (const auto& adapter : source.interfaces) {
        if (!adapter.up) continue;
        for (const auto& unicast : adapter.unicast) {
            const IpAddr& ip = unicast.address;
            Add(s.byMacro[Slot(AddrMacro::MyComputer)], ip, -1);
            if (!adapter.loopback)
                Add(s.byMacro[Slot(AddrMacro::AllMyAddresses)], ip, -1);

            const int prefix = unicast.prefix_length;
            const int total = static_cast<int>(ip.len()) * 8;
            if (adapter.loopback || prefix <= 0 || prefix > total) continue;

            IpAddr net = ip;
            ApplyPrefix(net, prefix, false);
            Add(s.byMacro[Slot(AddrMacro::LocalNetwork)], net, prefix);

            if (ip.family == AF_INET && prefix < 31) {
                IpAddr bcast = ip;
                ApplyPrefix(bcast, prefix, true);      // сеть, заполненная единицами
                Add(s.byMacro[Slot(AddrMacro::BroadcastAddresses)], bcast, -1);
            }
        }
        for (const IpAddr& ip : adapter.dns_servers)
            Add(s.byMacro[Slot(AddrMacro::DnsServers)], ip, -1);
        for (const IpAddr& ip : adapter.gateways)
            Add(s.byMacro[Slot(AddrMacro::Gateways)], ip, -1);
        for (const IpAddr& ip : adapter.wins_servers)
            Add(s.byMacro[Slot(AddrMacro::WinsServers)], ip, -1);
    }
}

const Snapshot& Current(State& state, bool refresh) { // вызывается под state.mutex
    const ULONGLONG now = GetTickCount64();
    // На горячем пути читается только снимок. Проверка здоровья watcher тоже
    // ограничена TTL, но при исправном наблюдении не вызывает системного опроса.
    if (!state.attempted || refresh || now - state.attemptTick >= AddrMacros::kCacheTtlMs) {
        const bool running = state.watcher.IsRunning();
        if (!state.attempted || refresh || !running || state.watcher.LastError() != ERROR_SUCCESS) {
            if (running) {
                state.watcher.Refresh();
            } else if (!state.watcher.Start()) {
                // Недоступность уведомлений не должна лишать правила сетевых
                // адресов. Только в аварийном режиме остаётся прежний TTL-опрос.
                state.watcher.Refresh();
            }
        }
        state.attempted = true;
        state.attemptTick = now;
    }

    const auto source = state.watcher.GetSnapshot();
    if (state.snapshot.version &&
        (!source || state.snapshot.interfaceVersion == source->version)) [[likely]]
        return state.snapshot;

    Snapshot next;
    BuildConstants(next);
    if (source) {
        BuildFromInterfaces(next, *source);
        next.interfaceVersion = source->version;
    }
    next.version = (!state.snapshot.version || !SameValues(state.snapshot, next))
        ? state.snapshot.version + 1 : state.snapshot.version;
    state.snapshot = std::move(next);
    return state.snapshot;
}

} // namespace

namespace AddrMacros {

const Def* All(size_t& count) {
    count = std::size(kDefs);
    return kDefs;
}

const Def* Find(AddrMacro m) {
    for (const Def& d : kDefs) if (d.id == m) return &d;
    return nullptr;
}

const wchar_t* Name(AddrMacro m) {
    const Def* d = Find(m);
    return d ? d->name : L"";
}

std::wstring Description(AddrMacro m) {
    const Def* d = Find(m);
    return d ? LoadStringRes(d->descId) : std::wstring();
}

AddrMacro Parse(const std::wstring& token) {
    if (token.empty()) return AddrMacro::None;
    const wchar_t* p = token.c_str();
    if (*p == L'@') ++p;
    for (const Def& d : kDefs)
        if (_wcsicmp(p, d.name) == 0) return d.id;
    return AddrMacro::None;
}

std::vector<MacroEntry> Resolve(AddrMacro m) {
    if (m == AddrMacro::None) return {};
    State& state = Cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    return Current(state, false).byMacro[Slot(m)];
}

bool Matches(AddrMacro m, const IpAddr& a) {
    if (m == AddrMacro::None) return false;
    State& state = Cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    const Snapshot& s = Current(state, false);
    for (const MacroEntry& e : s.byMacro[Slot(m)])
        if (IpMatchesPrefix(a, e.addr, e.prefix)) return true;
    return false;
}

std::wstring ValuesText(AddrMacro m, size_t maxItems) {
    const std::vector<MacroEntry> v = Resolve(m);
    if (v.empty()) return LoadStringRes(IDS_MACRO_NO_DATA);

    std::wstring s;
    size_t shown = 0;
    for (const MacroEntry& e : v) {
        if (shown >= maxItems) {
            s += LoadStringRes(IDS_MACRO_MORE_PREFIX) +
                 std::to_wstring(v.size() - shown);
            break;
        }
        if (!s.empty()) s += L"; ";
        s += IpToPlainString(e.addr);
        if (e.prefix >= 0) s += L"/" + std::to_wstring(e.prefix);
        ++shown;
    }
    return s;
}

uint64_t Version(bool refresh) {
    State& state = Cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    return Current(state, refresh).version;
}

void Invalidate() {
    State& state = Cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.watcher.IsRunning()) state.watcher.RequestRefresh();
    else state.attempted = false;
}

void Shutdown() {
    State& state = Cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.watcher.Stop();
    state.attempted = false;
}

} // namespace AddrMacros
