#include "AskQueue.h"
#include "Ingest.h"          // очередь — индекс над припаркованными группами
#include "ServiceInfo.h"
#include "StringRes.h"
#include "SystemInfo.h"
#include "StorageMaintenance.h"
#include <algorithm>
#include <cwctype>
#include "Rules.h"
#include "network_interface_watcher.h"

namespace {



// Автоматическое правило без пути всегда идёт в «правила после приложений».
// Глобальную группу можно выбрать только явно в редакторе.
void SetScope(Rule& out, const FlowRuleSeed& seed) {
    if (seed.key.source == TrafficSource::Ndis) {
        out.scope = RuleScope::Interface;
        out.appPath = seed.interfaceName ? *seed.interfaceName :
            net::SharedNetworkInterfaces().GetInterfaceName(seed.key.interfaceIndex).value_or(std::wstring());
        out.appName = out.appPath.empty() ? seed.appName : out.appPath;
    } else if (seed.appPath.empty()) {
        out.scope   = RuleScope::PostApp;
        out.appPath.clear();
        out.appName = LoadStringRes(IDS_RULE_POSTAPP_APP);
        if (seed.pid == 0) out.conds |= CondPidZero;
    } else {
        out.scope   = RuleScope::App;
        out.appPath = seed.appPath;
        out.appName = seed.appName.empty() ? PathBaseUpper(seed.appPath) : seed.appName;
    }
}

// Подстановка не включает условие. Зафиксированное имя, в том числе пустое,
// важнее текущего владельца индекса: старый запрос не должен менять адаптер.
std::wstring SuggestedInterface(const FlowRuleSeed& seed) {
    if (seed.interfaceName) return *seed.interfaceName;
    auto& watcher = net::SharedNetworkInterfaces();
    const uint32_t index = seed.interfaceIndex ? seed.interfaceIndex : seed.key.interfaceIndex;
    if (index) return watcher.GetInterfaceNameByIndex(index).value_or(std::wstring());
    if (seed.key.local.isAny()) return {};

    // У строки из таблиц ОС индекса нет. Локальный адрес годится лишь тогда,
    // когда он однозначно принадлежит одному активному интерфейсу.
    const auto snapshot = watcher.GetSnapshot();
    const net::NetworkInterfaceWatcher::InterfaceInfo* found = nullptr;
    if (snapshot) {
        for (const auto& entry : snapshot->interfaces) {
            if (!entry.up || !entry.number || entry.name.empty()) continue;
            if (!std::any_of(entry.unicast.begin(), entry.unicast.end(),
                [&](const auto& address) { return address.address == seed.key.local; })) continue;
            if (found) return {};
            found = &entry;
        }
    }
    return found ? found->name : std::wstring();
}

// Условия «именно эта активность». Удалённый адрес включается, локальный —
// только подставляется. Из портов включается сервисный: локальный для входящего
// события, удалённый для исходящего; второй порт остаётся заготовкой.
//
// Набор условий зависит от протокола: порты есть лишь у TCP/UDP/SCTP/DCCP/
// UDP-Lite, тип — только у ICMP и ICMPv6. Для прочих номеров остаются
// направление и адреса — этого достаточно, потому что протокол сам по себе
// уже является условием.
void FillNarrow(Rule& out, const FlowRuleSeed& seed) {
    out.SetProto(seed.key.proto, true);   // выставляет CondProto и чистит лишнее
    out.dir   = (seed.dir == Dir::In) ? Dir::In : Dir::Out;
    out.conds |= CondDirection;
    if (!out.isInterface()) out.interfaceName = SuggestedInterface(seed);
    // Только заготовка: автоматическое правило не сужается до флагов одного события.
    if (seed.key.source == TrafficSource::Host && seed.conditionFlags)
        out.conditionFlags = *seed.conditionFlags & kSelectableWfpConditionFlags;

    // Сервисы процесса — ЗАГОТОВКА условия «сервис». Флаг намеренно не
    // ставится: иначе правило молча сузилось бы до текущего состава
    // svchost.exe и после перезапуска службы перестало бы срабатывать.
    // Это редкий пользовательский путь создания заготовки, а не matcher.
    // Если фоновой монитор не нужен правилам и спит, здесь допустимо синхронно
    // подготовить просроченную runtime-карту для подсказки сервисов процесса.
    const ServiceInfo::HostedServices hosted = ServiceInfo::ServicesOfPid(
        seed.key.source == TrafficSource::Ndis ? 0 : seed.pid,
        seed.key.source != TrafficSource::Ndis);
    for (const ServiceEntry& entry : *hosted) {
        ServiceItem s;
        s.name    = entry.name;
        s.display = entry.display;
        out.services.push_back(std::move(s));
    }

    if (!seed.key.remote.isAny()) {
        AddrItem a;
        a.addr   = seed.key.remote;
        a.prefix = -1;
        out.remoteAddrs.push_back(a);
        out.conds |= CondRemoteAddr;
    }
    if (!seed.key.local.isAny()) {
        AddrItem a;
        a.addr   = seed.key.local;
        a.prefix = -1;
        out.localAddrs.push_back(a);          // заготовка, условие не включаем
    }

    if (ProtoIsIcmp(seed.key.proto)) {
        // Тип ICMP известен только из payload события транспорта: у строки,
        // собранной по таблицам ОС, он равен -1, и условие не ставится.
        if (seed.icmpType >= 0) {
            IcmpTypeItem t;
            t.type = static_cast<uint8_t>(seed.icmpType);
            t.code = -1;                      // код оставляем «любой»
            out.icmpTypes.push_back(t);
            out.conds |= CondIcmpType;
        }
        return;
    }
    if (!ProtoHasPorts(seed.key.proto)) return;   // портов у протокола нет

    if (out.dir == Dir::In) {
        if (seed.key.lport) {
            out.localPorts.push_back(PortItem{ seed.key.lport, seed.key.lport });
            out.conds |= CondLocalPort;        // сервисный порт — он стабилен
        }
        if (seed.key.rport)
            out.remotePorts.push_back(PortItem{ seed.key.rport, seed.key.rport });
    } else {
        if (seed.key.rport) {
            out.remotePorts.push_back(PortItem{ seed.key.rport, seed.key.rport });
            out.conds |= CondRemotePort;
        }
        if (seed.key.lport)
            out.localPorts.push_back(PortItem{ seed.key.lport, seed.key.lport });
    }
}

FlowRuleSeed SeedOf(const AskRequest& r) {
    FlowRuleSeed s;
    s.key      = r.key;
    s.interfaceIndex = r.interfaceIndex;
    s.interfaceName = r.interfaceName;
    s.dir      = r.dir;
    s.icmpType = r.icmpType;
    s.icmpCode = r.icmpCode;
    s.conditionFlags = r.conditionFlags;
    s.pid      = r.pid;
    s.appPath  = r.appPath;
    s.appName  = r.appName;
    return s;
}

} // namespace

uint64_t AskHash(std::wstring_view appPath, DWORD pid, const FlowKey& k, Dir dir,
                 int icmpType, int icmpCode, bool ownerAmbiguous, uint32_t interfaceIndex,
                 const std::wstring* interfaceName,
                 std::optional<uint32_t> conditionFlags) {
    return AskHashPrepared(
        HashTextNoCase(appPath), pid, k, dir, icmpType, icmpCode,
        ownerAmbiguous, interfaceIndex, interfaceName, conditionFlags);
}

uint64_t AskHashPrepared(uint64_t foldedAppPathHash, DWORD pid,
                         const FlowKey& k, Dir dir,
                         int icmpType, int icmpCode, bool ownerAmbiguous, uint32_t interfaceIndex,
                         const std::wstring* interfaceName,
                         std::optional<uint32_t> conditionFlags) {
    // Хэш подготовленного пути является состоянием того же FNV-прохода сразу
    // после строки. Остальные поля можно дописать без повторной свёртки пути.
    uint64_t h = foldedAppPathHash;
    const auto mix = [&h](const void* p, size_t n) {
        const uint8_t* q = static_cast<const uint8_t*>(p);
        for (size_t i = 0; i < n; ++i) { h ^= q[i]; h *= 1099511628211ull; }
    };

    // Pending-группа может быть закрыта правилом с любым условием, поэтому
    // ключ должен включать ВСЕ исходные условия matcher-а. Иначе, например,
    // запросы на разные локальные порты получили бы решение по первому из них.
    mix(&pid, sizeof(pid));
    if (!interfaceIndex) interfaceIndex = k.interfaceIndex;
    mix(&interfaceIndex, sizeof(interfaceIndex));
    const bool captured = interfaceName != nullptr;
    mix(&captured, sizeof(captured));
    if (interfaceName) mix(interfaceName->data(), interfaceName->size() * sizeof(wchar_t));
    const uint8_t pr = ProtoNumber(k.proto);
    const uint8_t dr = static_cast<uint8_t>(dir);
    mix(&pr, 1);
    mix(&dr, 1);
    mix(&k.local.family, 2);
    mix(k.local.b, k.local.len());
    mix(&k.remote.family, 2);
    mix(k.remote.b, k.remote.len());
    mix(&k.lport, sizeof(k.lport));
    mix(&k.rport, sizeof(k.rport));
    const int16_t t = static_cast<int16_t>(icmpType);
    const int16_t c = static_cast<int16_t>(icmpCode);
    const uint8_t ambiguous = ownerAmbiguous ? 1 : 0;
    mix(&t, sizeof(t));
    mix(&c, sizeof(c));
    mix(&ambiguous, sizeof(ambiguous));
    const bool flagsKnown = conditionFlags.has_value();
    mix(&flagsKnown, sizeof(flagsKnown));
    if (conditionFlags) mix(&*conditionFlags, sizeof(*conditionFlags));
    return h;
}

std::wstring AskRequest::RemoteText() const {
    // «TCP (6)», «ICMPv6 (58)», «144» — номер виден всегда: для протокола без
    // известного имени это единственное, чем он опознаётся.
    const std::wstring proto = ProtoLabel(key.proto);

    if (isIcmp()) {
        std::wstring s = key.remote.isAny() ? LoadStringRes(IDS_ASKQ_ANY_HOST)
                                            : IpToPlainString(key.remote);
        s += L" (" + proto;
        if (icmpType >= 0) {
            s += LoadStringRes(IDS_ASKQ_TYPE_PREFIX);
            if (const wchar_t* n = IcmpTypeNameOf(static_cast<uint8_t>(icmpType),
                                                  isIcmpV6()))
                s += n;
            else
                s += std::to_wstring(icmpType);
            if (icmpCode > 0) s += L":" + std::to_wstring(icmpCode);
        } else {
            s += LoadStringRes(IDS_ASKQ_TYPE_UNKNOWN);
        }
        s += L")";
        return s;
    }

    std::wstring s = key.remote.isAny() ? LoadStringRes(IDS_ASKQ_ANY_ADDRESS)
                                        : IpToPlainString(key.remote);
    if (!hasPorts() || !key.rport) return s + L" (" + proto + L")";

    s += L", ";
    if (const wchar_t* svc = WellKnownPortName(key.rport)) {
        s += svc;
        s += L" ";
    }
    s += L"(" + proto + LoadStringRes(IDS_ASKQ_PORT_PREFIX) +
         std::to_wstring(key.rport) + L")";
    return s;
}

std::wstring AskRequest::LocalText() const {
    if (!hasPorts()) return IpToString(key.local);   // порта нет, адрес есть
    return EndpointToString(key.local, key.lport);
}

std::wstring AskRequest::DirPhrase() const {
    return LoadStringRes(dir == Dir::In ? IDS_ASKQ_INBOUND : IDS_ASKQ_OUTBOUND);
}

MatchQuery AskRequest::ToQuery() const {
    // Обычно путь уже подготовлен Ingest::RequestOf. Для вручную собранного
    // запроса оставляем RuleStore совместимый редкий путь.
    MatchQuery q = MakeMatchQuery(
        appPath, pid, key, dir, icmpType, icmpCode, process.get(), conditionFlags);
    q.lineage = lineage.get();
    if (interfaceIndex) q.interfaceIndex = interfaceIndex;
    q.interfaceName = interfaceName.get();
    if (appPath.empty() || !foldedAppPath.empty()) [[likely]]
        PrepareMatchAppPath(q, foldedAppPath, appPathHash);
    return q;
}

AskRequest RequestForRuleCreation(const AskRequest& request, const RuleStore& rules) {
    AskRequest result = request;
    const auto source = rules.InheritedSource(request.ToQuery());
    if (!source) return result;
    result.pid = static_cast<DWORD>(source.pid);
    result.appPath = *source.path->text;
    result.appName = PathBaseUpper(result.appPath);
    result.foldedAppPath = source.path->folded;
    result.appPathHash = source.path->hash;
    result.lineage.reset();
    const auto parent = ProcessImagePathRef(result.pid);
    result.process = parent && EqualNoCase(parent->text, result.appPath) ? parent->process : nullptr;
    return result;
}

// --------------------------------------------------------- построение правил

Rule MakeNarrowRule(const FlowRuleSeed& seed, RuleAction action) {
    Rule out;
    SetScope(out, seed);
    FillNarrow(out, seed);
    out.action   = action;
    out.enabled  = true;
    out.autoName = true;
    NormalizeRuleConds(out);
    out.SyncName();
    return out;
}

Rule MakeAllowRule(const AskRequest& r) {
    return MakeNarrowRule(SeedOf(r), RuleAction::Allow);
}

Rule MakeBlockRule(const AskRequest& r) {
    return MakeNarrowRule(SeedOf(r), RuleAction::Block);
}

Rule MakeEditorTemplate(const AskRequest& r) {
    return MakeNarrowRule(SeedOf(r), RuleAction::Allow);
}

// «Завершить»: приложение блокируется целиком — ОДНИМ правилом без условий,
// включая условие «протокол». Условие «сервис» здесь не ставится намеренно:
// обещание «приложение заблокировано» не должно зависеть от состава служб
// внутри процесса.
//
// Если путь неизвестен, блокируется только эта активность узким правилом
// в группе «правила после приложений», а не весь оставшийся трафик.
std::vector<Rule> MakeBlockAllRules(const AskRequest& r) {
    std::vector<Rule> out;

    const FlowRuleSeed seed = SeedOf(r);
    if (seed.key.source != TrafficSource::Ndis && seed.appPath.empty()) {
        out.push_back(MakeNarrowRule(seed, RuleAction::Block));
        return out;
    }

    Rule x;
    SetScope(x, seed);
    x.proto    = seed.key.proto;     // сохраняем для наглядности, но не проверяем
    x.dir      = Dir::Out;
    x.conds    = CondNone;           // любой протокол, направление, адрес, порт
    x.action   = RuleAction::Block;
    x.enabled  = true;
    x.autoName = true;
    NormalizeRuleConds(x);
    x.SyncName();
    out.push_back(std::move(x));
    return out;
}

// ----------------------------------------------------------------- AskQueue

// Барьер требования «таблицы ОС правил не создают»: запрос принимается только
// с действующим AskRequestId. Такой ID выдаёт исключительно Ingest для
// обязательства, созданного событием транспорта текущей driver-сессии.
bool AskQueue::Push(const AskRequest& r) {
    if (!r.id) return false;

    // Обязательство уже закрыто правилом или принадлежит прежней сессии.
    if (!Ingest::Instance().IsPending(r.id)) return false;

    if (!in_.insert(r.id).second) return false;   // такой запрос уже стоит
    q_.push_back(Item{ r.id, 0 });
    return true;
}

bool AskQueue::Pop(AskRequest& out) {
    const ULONGLONG now = GetTickCount64();

    for (auto it = q_.begin(); it != q_.end();) {
        if (it->holdUntil > now) { ++it; continue; }   // пауза ещё не истекла

        const AskRequestId id = it->id;
        // Запрос берётся у владельца обязательства: очередь копии не держит.
        const bool alive = Ingest::Instance().GetPending(id, out);

        in_.erase(id);
        it = q_.erase(it);

        // Группы больше нет либо сменилась driver-сессия.
        if (!alive) [[unlikely]] continue;
        TrimHashTable(in_);
        return true;
    }
    TrimHashTable(in_);
    return false;
}

// Пользователь закрыл окно, не решив. Обязательство остаётся, поэтому запрос
// возвращается в очередь — но с паузой: иначе PumpAsk открыл бы то же окно
// сразу после его закрытия, и запрос было бы невозможно отложить.
void AskQueue::Postpone(const AskRequest& r) {
    if (!r.id || !Ingest::Instance().IsPending(r.id)) return;

    const ULONGLONG until = GetTickCount64() + kPostponeMs;

    if (!in_.insert(r.id).second) {
        // Такой же запрос уже в очереди: продлеваем его паузу.
        for (Item& it : q_)
            if (it.id == r.id && it.holdUntil < until) it.holdUntil = until;
        return;
    }
    q_.push_back(Item{ r.id, until });
}

void AskQueue::MakeAllReady() {
    for (Item& item : q_) item.holdUntil = 0;
}

void AskQueue::Discard(AskRequestId id) {
    q_.erase_if([&](const Item& x) { return x.id == id; });
    in_.erase(id);
    TrimHashTable(in_);
}

// Сопоставление с правилами выполняет Ingest::FlushVerdicts: он же и снимает
// закрытые группы. Поэтому здесь достаточно убрать записи, за которыми уже
// нет припаркованного обязательства. Запросы, решения по которым нет,
// остаются в очереди неограниченно долго — этого и требует контракт.
void AskQueue::Prune() {
    Ingest& ing = Ingest::Instance();
    q_.erase_if([&](const Item& item) {
        if (ing.IsPending(item.id)) [[likely]] return false;
        in_.erase(item.id);
        return true;
    });
    TrimHashTable(in_);
}

size_t AskQueue::ready() const {
    const ULONGLONG now = GetTickCount64();
    size_t n = 0;
    for (const Item& it : q_) if (it.holdUntil <= now) ++n;
    return n;
}