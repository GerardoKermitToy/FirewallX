#include "Rules.h"
#include "RuleDb.h"
#include "ServiceInfo.h"
#include "StringRes.h"
#include "SystemInfo.h"
#include "StorageMaintenance.h"
#include <algorithm>
#include <cwctype>
#include <optional>
#include <unordered_set>

// ---------------------------------------------------------------------------
// Точка расширения: сюда попадает каждая правка набора правил.
// Сейчас обработчик пуст: сетевые вердикты выдаёт Ingest, а не это уведомление.
// ---------------------------------------------------------------------------
void notify_rule_changed(RuleChange change, uint64_t ruleId, const Rule& rule)
{
    (void)change;
    (void)ruleId;
    (void)rule;
}

namespace {

bool AppFileMissing(const std::wstring& path) {
    if (path.empty()) return false;

    // Отсутствующий съёмный носитель не должен вызывать системное окно ошибки.
    DWORD oldMode = 0;
    const bool restoreMode = SetThreadErrorMode(
        GetThreadErrorMode() | SEM_FAILCRITICALERRORS, &oldMode) != FALSE;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    const DWORD error = attributes == INVALID_FILE_ATTRIBUTES
        ? GetLastError() : ERROR_SUCCESS;
    if (restoreMode) SetThreadErrorMode(oldMode, nullptr);

    if (attributes != INVALID_FILE_ATTRIBUTES)
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    // Ошибка доступа и прочие неопределённые ошибки не доказывают отсутствие файла.
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
    case ERROR_NOT_READY:
    case ERROR_NO_MEDIA_IN_DRIVE:
    case ERROR_DEVICE_NOT_CONNECTED:
        return true;
    default:
        return false;
    }
}

bool ListHasMacro(const std::vector<AddrItem>& v) {
    for (const AddrItem& a : v) if (a.isMacro()) return true;
    return false;
}

const KnownPort kPorts[] = {
    { L"AUTH",        113,   L"Authentication Service" },
    { L"BGP",         179,   L"Border Gateway Protocol" },
    { L"BOOTPC",      68,    L"Bootstrap Protocol Client" },
    { L"BOOTPS",      67,    L"Bootstrap Protocol Server" },
    { L"Chargen",     19,    L"Character Generator" },
    { L"DCOM",        135,   L"Microsoft RPC end point mapper" },
    { L"DHCPv6c",     546,   L"DHCPv6 Client" },
    { L"DHCPv6s",     547,   L"DHCPv6 Server" },
    { L"DNS",         53,    L"Domain Name System" },
    { L"Daytime",     13,    L"Daytime Protocol" },
    { L"Discard",     9,     L"Discard Protocol" },
    { L"Echo",        7,     L"Echo Protocol" },
    { L"FTP",         21,    L"File Transfer Protocol (control)" },
    { L"FTP-DATA",    20,    L"File Transfer Protocol (data)" },
    { L"HTTP",        80,    L"World Wide Web" },
    { L"HTTPS",       443,   L"HTTP over TLS/SSL" },
    { L"IMAP",        143,   L"Internet Message Access Protocol" },
    { L"IMAPS",       993,   L"IMAP over TLS/SSL" },
    { L"IPP",         631,   L"Internet Printing Protocol" },
    { L"IRC",         194,   L"Internet Relay Chat" },
    { L"ISAKMP",      500,   L"IPsec / IKE" },
    { L"KERBEROS",    88,    L"Kerberos" },
    { L"L2TP",        1701,  L"Layer 2 Tunneling Protocol" },
    { L"LDAP",        389,   L"Lightweight Directory Access Protocol" },
    { L"LDAPS",       636,   L"LDAP over TLS/SSL" },
    { L"LLMNR",       5355,  L"Link-Local Multicast Name Resolution" },
    { L"MDNS",        5353,  L"Multicast DNS" },
    { L"MSSQL",       1433,  L"Microsoft SQL Server" },
    { L"NETBIOS-DGM", 138,   L"NetBIOS Datagram Service" },
    { L"NETBIOS-NS",  137,   L"NetBIOS Name Service" },
    { L"NETBIOS-SSN", 139,   L"NetBIOS Session Service" },
    { L"NNTP",        119,   L"Network News Transfer Protocol" },
    { L"NTP",         123,   L"Network Time Protocol" },
    { L"OPENVPN",     1194,  L"OpenVPN" },
    { L"POP3",        110,   L"Post Office Protocol v3" },
    { L"POP3S",       995,   L"POP3 over TLS/SSL" },
    { L"PPTP",        1723,  L"Point-to-Point Tunneling Protocol" },
    { L"RDP",         3389,  L"Remote Desktop Protocol" },
    { L"RSYNC",       873,   L"rsync" },
    { L"SIP",         5060,  L"Session Initiation Protocol" },
    { L"SMB",         445,   L"Microsoft SMB / CIFS" },
    { L"SMTP",        25,    L"Simple Mail Transfer Protocol" },
    { L"SMTPS",       465,   L"SMTP over TLS/SSL" },
    { L"SNMP",        161,   L"Simple Network Management Protocol" },
    { L"SOCKS",       1080,  L"SOCKS proxy" },
    { L"SSDP",        1900,  L"Simple Service Discovery Protocol" },
    { L"SSH",         22,    L"Secure Shell" },
    { L"SUBMISSION",  587,   L"Mail Submission" },
    { L"SYSLOG",      514,   L"Syslog" },
    { L"TELNET",      23,    L"Telnet" },
    { L"TFTP",        69,    L"Trivial File Transfer Protocol" },
    { L"TOR-SOCKS",   9150,  L"Tor SOCKS proxy" },
    { L"WINRM",       5985,  L"Windows Remote Management" },
	{ L"WIREGUARD",	  51820, L"WireGuard" },
    { L"WSD",         3702,  L"Web Services Discovery" },
    { L"XMPP",        5222,  L"XMPP client" },
};

// ICMPv4 (RFC 792, 950, 1256, 8335)
const KnownIcmpType kIcmp4[] = {
    { 0,   L"Echo Reply" },
    { 3,   L"Destination Unreachable" },
    { 4,   L"Source Quench" },
    { 5,   L"Redirect" },
    { 8,   L"Echo Request" },
    { 9,   L"Router Advertisement" },
    { 10,  L"Router Solicitation" },
    { 11,  L"Time Exceeded" },
    { 12,  L"Parameter Problem" },
    { 13,  L"Timestamp" },
    { 14,  L"Timestamp Reply" },
    { 15,  L"Information Request" },
    { 16,  L"Information Reply" },
    { 17,  L"Address Mask Request" },
    { 18,  L"Address Mask Reply" },
    { 30,  L"Traceroute" },
    { 42,  L"Extended Echo Request" },
    { 43,  L"Extended Echo Reply" },
};

// ICMPv6 (RFC 4443, 4861, 3810, 6275)
const KnownIcmpType kIcmp6[] = {
    { 1,   L"Destination Unreachable" },
    { 2,   L"Packet Too Big" },
    { 3,   L"Time Exceeded" },
    { 4,   L"Parameter Problem" },
    { 128, L"Echo Request" },
    { 129, L"Echo Reply" },
    { 130, L"Multicast Listener Query" },
    { 131, L"Multicast Listener Report" },
    { 132, L"Multicast Listener Done" },
    { 133, L"Router Solicitation" },
    { 134, L"Router Advertisement" },
    { 135, L"Neighbor Solicitation" },
    { 136, L"Neighbor Advertisement" },
    { 137, L"Redirect Message" },
    { 138, L"Router Renumbering" },
    { 139, L"Node Information Query" },
    { 140, L"Node Information Response" },
    { 141, L"Inverse Neighbor Discovery Solicitation" },
    { 142, L"Inverse Neighbor Discovery Advertisement" },
    { 143, L"Multicast Listener Report v2" },
    { 144, L"Home Agent Address Discovery Request" },
    { 145, L"Home Agent Address Discovery Reply" },
    { 146, L"Mobile Prefix Solicitation" },
    { 147, L"Mobile Prefix Advertisement" },
    { 148, L"Certification Path Solicitation" },
    { 149, L"Certification Path Advertisement" },
    { 151, L"Multicast Router Advertisement" },
    { 152, L"Multicast Router Solicitation" },
    { 153, L"Multicast Router Termination" },
    { 157, L"Duplicate Address Request" },
    { 158, L"Duplicate Address Confirmation" },
    { 160, L"Extended Echo Request" },
    { 161, L"Extended Echo Reply" },
};

std::mutex g_clipMtx;
Rule       g_clip;
bool       g_clipValid = false;

// SysLink разбирает <a>…</a>; любые «<» и «>» внутри текста ломают разметку
std::wstring EscapeMarkup(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        if (c == L'<')      out += L'\u2039';
        else if (c == L'>') out += L'\u203A';
        else                out.push_back(c);
    }
    return out;
}

std::wstring Anchor(const wchar_t* id, const std::wstring& text) {
    return std::wstring(L"<a id=\"") + id + L"\">" + EscapeMarkup(text) + L"</a>";
}

const wchar_t* kPad    = L"  ";
const wchar_t* kPadSub = L"      ";

// Локализованные фразы автоимени берутся из ресурсов.


// Название протокола для автоимени правила: «TCP», «протокол 144»,
// «любой протокол».
std::wstring ProtoPhrase(const Rule& r) {
    if (!r.protoFixed()) return LoadStringRes(IDS_RULE_ANY_PROTO);
    const uint8_t n = ProtoNumber(r.proto);
    if (const wchar_t* a = ProtoAlias(n)) return a;
    return LoadStringRes(IDS_RULE_PROTO_NUM) + std::to_wstring(n);
}

// «сервиса Dnscache», «сервисов Dnscache, W32Time», «любого сервиса»
std::wstring ServicePhrase(const Rule& r) {
    if (r.services.empty())      return LoadStringRes(IDS_RULE_ANY_SERVICE);
    if (r.services.size() == 1)  return LoadStringRes(IDS_RULE_SERVICE_ONE) + r.ServicesText();
    return LoadStringRes(IDS_RULE_SERVICE_MANY) + r.ServicesText();
}

// Только включённые условия стороны: «адрес:порт», адрес либо порт.
std::wstring EndpointPhrase(const Rule& r, bool remote) {
    const auto& addresses = remote ? r.remoteAddrs : r.localAddrs;
    const auto& ports = remote ? r.remotePorts : r.localPorts;
    const bool hasAddress = (r.conds & (remote ? CondRemoteAddr : CondLocalAddr)) &&
                            !addresses.empty();
    const bool hasPort = r.hasPorts() &&
                         (r.conds & (remote ? CondRemotePort : CondLocalPort)) && !ports.empty();
    std::wstring address;
    if (hasAddress) {
        address = addresses.front().Text();
        if (addresses.size() > 1)
            address = LoadStringResFmt(IDS_RULEN_ADDR_LIST_FMT, address.c_str());
        else if (hasPort && !addresses.front().isMacro() && addresses.front().addr.family == AF_INET6)
            address = L"[" + address + L"]";
    }
    if (!hasPort) return address;
    std::wstring port = r.PortsText(remote);
    if (ports.size() > 1) port = L"(" + port + L")";
    if (!hasAddress) return port;
    return address + L":" + port;
}

} // namespace

const KnownPort* KnownPorts(size_t& count) {
    count = std::size(kPorts);
    return kPorts;
}

const wchar_t* WellKnownPortName(uint16_t port) {
    for (const KnownPort& p : kPorts) if (p.port == port) return p.name;
    return nullptr;
}

const KnownIcmpType* KnownIcmpTypes(bool v6, size_t& count) {
    if (v6) { count = std::size(kIcmp6); return kIcmp6; }
    count = std::size(kIcmp4);
    return kIcmp4;
}

const wchar_t* IcmpTypeNameOf(uint8_t type, bool v6) {
    size_t n = 0;
    const KnownIcmpType* t = KnownIcmpTypes(v6, n);
    for (size_t i = 0; i < n; ++i) if (t[i].type == type) return t[i].name;
    return nullptr;
}

// ------------------------------------------------------------ AddrItem

bool AddrItem::operator==(const AddrItem& other) const {
    if (isMacro() || other.isMacro()) return macro == other.macro;
    if (addr.family != other.addr.family) return false;
    const int bits = static_cast<int>(addr.len() * 8);
    const int left = prefix < 0 ? bits : std::min(prefix, bits);
    const int right = other.prefix < 0 ? bits : std::min(other.prefix, bits);
    // Точный IP равен /32 или /128; у подсети сравниваются только сетевые биты.
    return left == right && IpMatchesPrefix(addr, other.addr, left);
}

void DeduplicateAddresses(std::vector<AddrItem>& items) {
    auto end = items.begin();
    for (auto it = items.begin(); it != items.end(); ++it) {
        if (std::find(items.begin(), end, *it) != end) continue;
        if (end != it) *end = *it;
        ++end;
    }
    items.erase(end, items.end());
}

bool AddrItem::Matches(const IpAddr& a) const {
    // Макрос разрешается в набор адресов текущей конфигурации сети
    if (isMacro()) return AddrMacros::Matches(macro, a);

    return IpMatchesPrefix(a, addr, prefix);
}

std::wstring AddrItem::Text() const {
    if (isMacro()) return AddrMacros::Name(macro);
    std::wstring s = IpToPlainString(addr);
    if (prefix >= 0) s += L"/" + std::to_wstring(prefix);
    return s;
}

std::wstring AddrItem::Token() const {
    // «@» не встречается в записи IP-адреса, поэтому разбор однозначен
    if (isMacro()) return std::wstring(L"@") + AddrMacros::Name(macro);
    return Text();
}

std::wstring PortItem::Text() const {
    if (from == to) {
        if (const wchar_t* n = WellKnownPortName(from)) return n;
        return std::to_wstring(from);
    }
    return std::to_wstring(from) + L"-" + std::to_wstring(to);
}

std::wstring IcmpTypeItem::Text(bool v6) const {
    std::wstring s;
    if (const wchar_t* n = IcmpTypeNameOf(type, v6)) s = n;
    else                                             s = std::to_wstring(type);
    if (code >= 0) s += L":" + std::to_wstring(code);
    return s;
}

// --------------------------------------------------------- ServiceItem

bool ServiceNameMatches(std::wstring_view pattern, std::wstring_view name) {
    if (EqualNoCase(pattern, name)) return true;
    const size_t firstStar = pattern.find(L'*');
    if (firstStar == std::wstring_view::npos) return false;

    // Частая маска с одним завершающим «*» сводится к сравнению префикса.
    if (firstStar + 1 == pattern.size())
        return name.size() >= firstStar && EqualNoCase(pattern.substr(0, firstStar),
                                                       name.substr(0, firstStar));

    // Остальные маски обрабатываем без выделений памяти и без рекурсии.
    size_t p = 0, n = 0, star = std::wstring_view::npos, retry = 0;
    while (n < name.size()) {
        if (p < pattern.size() && pattern[p] != L'*' &&
            (pattern[p] == name[n] || FoldCaseChar(pattern[p]) == FoldCaseChar(name[n]))) {
            ++p;
            ++n;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            star = p++;
            retry = n;
        } else if (star != std::wstring_view::npos) {
            p = star + 1;
            n = ++retry;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == L'*') ++p;
    return p == pattern.size();
}

bool ServiceItem::Matches(const std::wstring& svc) const {
    return ServiceNameMatches(name, svc);
}

// В расшифровке правила и в автоимени показывается КЛЮЧ: он короткий,
// однозначный и не зависит от языка системы.
std::wstring ServiceItem::Text() const { return name; }

std::wstring ServiceItem::FullText() const {
    if (display.empty()) return name;
    return name + LoadStringRes(IDS_RULEN_DASH) + display;
}

// ---------------------------------------------------------------- Rule

bool Rule::hasVolatileConds() const {
    if (conds & CondService) return true;
    if ((conds & CondRemoteAddr) && ListHasMacro(remoteAddrs)) return true;
    if ((conds & CondLocalAddr)  && ListHasMacro(localAddrs))  return true;
    return false;
}

void NormalizeRuleConds(Rule& r) {
    DeduplicateAddresses(r.remoteAddrs);
    DeduplicateAddresses(r.localAddrs);
    if (!r.hasPorts()) r.conds &= ~(CondRemotePort | CondLocalPort);
    if (!r.isIcmp())   r.conds &= ~CondIcmpType;
    if (!r.isPostApp()) r.conds &= ~CondPidZero;
    if (r.isInterface()) {
        r.conds &= ~CondInterface;
        r.interfaceName.clear();
    }
    // CondService не нормализуется: состав сервисов процесса не зависит
    // ни от протокола, ни от направления.
}

void Rule::SetProto(Proto p, bool fixed) {
    const Proto oldProto = proto;
    const bool oldFixed = protoFixed();
    proto = p;
    if (fixed) conds |= CondProto;
    else       conds &= ~CondProto;
    NormalizeRuleConds(*this);

    // В отличие от снятия галочки, явный выбор протокола очищает
    // несовместимые значения. Типы ICMP разных версий не взаимозаменяемы.
    if (!hasPorts()) { remotePorts.clear(); localPorts.clear(); }
    if (!isIcmp()) {
        icmpTypes.clear();
    } else if (!oldFixed || !ProtoIsIcmp(oldProto) ||
               ProtoIsIcmpV6(oldProto) != ProtoIsIcmpV6(p)) {
        conds &= ~CondIcmpType;
        icmpTypes.clear();
    }
}

std::wstring Rule::ProtoText() const {
    const uint8_t n = ProtoNumber(proto);
    if (const wchar_t* a = ProtoAlias(n)) return a;
    return std::to_wstring(n);          // номер без известного имени
}

std::wstring Rule::ProtoCondText() const {
    return protoFixed() ? ProtoText() : std::wstring(LoadStringRes(IDS_RULE_ANY));
}

std::wstring Rule::DirTextRu() const {
    return dir == Dir::In ? LoadStringRes(IDS_RULE_DIR_IN) : LoadStringRes(IDS_RULE_DIR_OUT);
}

std::wstring Rule::ActionTextRu() const {
    return (action == RuleAction::Allow) ? LoadStringRes(IDS_RULE_ACT_ALLOW) : LoadStringRes(IDS_RULE_ACT_BLOCK);
}

std::wstring Rule::ScopeTextRu() const {
    if (isGlobal()) return LoadStringRes(IDS_RULE_GLOBAL_SCOPE);
    if (isPostApp()) return LoadStringRes(IDS_RULE_POSTAPP_SCOPE);
    if (isInterface()) return appPath;
    return appName.empty() ? PathBaseUpper(appPath) : appName;
}

std::wstring Rule::AddrsText(bool remote) const {
    const auto& v = remote ? remoteAddrs : localAddrs;
    if (v.empty()) return LoadStringRes(IDS_RULE_ANY_QUOTED);
    std::wstring s;
    for (const AddrItem& a : v) {
        if (!s.empty()) s += L", ";
        s += a.Text();
    }
    return s;
}

std::wstring Rule::PortsText(bool remote) const {
    const auto& v = remote ? remotePorts : localPorts;
    if (v.empty()) return LoadStringRes(IDS_RULE_ANY_QUOTED);
    std::wstring s;
    for (const PortItem& p : v) {
        if (!s.empty()) s += L", ";
        s += p.Text();
    }
    return s;
}

std::wstring Rule::IcmpTypesText() const {
    if (icmpTypes.empty()) return LoadStringRes(IDS_RULE_ANY_QUOTED);
    std::wstring s;
    for (const IcmpTypeItem& t : icmpTypes) {
        if (!s.empty()) s += L", ";
        s += t.Text(isIcmpV6());
    }
    return s;
}

// Пустой список означает «любой сервис»: правило подойдёт любому процессу,
// который обслуживает хотя бы один сервис (см. RuleStore::MatchServices).
std::wstring Rule::ServicesText() const {
    if (services.empty()) return LoadStringRes(IDS_RULE_ANY_QUOTED);
    std::wstring s;
    for (const ServiceItem& x : services) {
        if (!s.empty()) s += L", ";
        s += x.Text();
    }
    return s;
}

std::wstring Rule::PidText() const {
    return LoadStringRes(isPostApp() && (conds & CondPidZero)
        ? IDS_RULE_PID_ZERO : IDS_RULE_ANY);
}

std::wstring WfpConditionFlagText(unsigned bit) {
    static constexpr UINT names[] = {
        IDS_WFP_FLAG_IS_LOOPBACK,
        IDS_WFP_FLAG_IS_IPSEC_SECURED,
        0,
        IDS_WFP_FLAG_IS_WILDCARD_BIND,
        IDS_WFP_FLAG_IS_RAW_ENDPOINT,
        IDS_WFP_FLAG_IS_FRAGMENT,
        IDS_WFP_FLAG_IS_FRAGMENT_GROUP,
        IDS_WFP_FLAG_IS_IPSEC_NATT_RECLASSIFY,
        IDS_WFP_FLAG_REQUIRES_ALE_CLASSIFY,
        IDS_WFP_FLAG_IS_IMPLICIT_BIND,
        IDS_WFP_FLAG_IS_REASSEMBLED,
        0,
        0,
        0,
        IDS_WFP_FLAG_IS_NAME_APP_SPECIFIED,
        IDS_WFP_FLAG_IS_PROMISCUOUS,
        IDS_WFP_FLAG_IS_AUTH_FW,
        IDS_WFP_FLAG_IS_RECLASSIFY,
        IDS_WFP_FLAG_IS_OUTBOUND_PASS_THRU,
        IDS_WFP_FLAG_IS_INBOUND_PASS_THRU,
        IDS_WFP_FLAG_IS_CONNECTION_REDIRECTED,
        IDS_WFP_FLAG_IS_PROXY_CONNECTION,
        IDS_WFP_FLAG_IS_APPCONTAINER_LOOPBACK,
        IDS_WFP_FLAG_IS_NON_APPCONTAINER_LOOPBACK,
        IDS_WFP_FLAG_IS_RESERVED,
        IDS_WFP_FLAG_IS_HONORING_POLICY_AUTHORIZE,
        0,
        0,
        0,
        0,
        0,
        0,
    };
    if (bit >= std::size(names) || !(kSelectableWfpConditionFlags & (uint32_t{1} << bit))) return {};
    return names[bit] ? LoadStringRes(names[bit])
        : LoadStringResFmt(IDS_WFP_FLAG_UNKNOWN_FMT, uint32_t{1} << bit);
}

std::wstring Rule::ConditionFlagsText() const {
    const uint32_t flags = conditionFlags & kSelectableWfpConditionFlags;
    if (!flags) return LoadStringRes(IDS_WFP_FLAGS_NONE);
    std::wstring text;
    for (unsigned bit = 0; bit < 32; ++bit) {
        if (!(flags & (uint32_t{1} << bit))) continue;
        if (!text.empty()) text += L", ";
        text += WfpConditionFlagText(bit);
    }
    return text;
}

std::wstring Rule::BuildAutoName() const {
    std::wstring s = ActionTextRu();
    s += L" ";
    if ((conds & CondDirection) && dir != Dir::Unknown) { s += DirTextRu(); s += L" "; }
    s += ProtoPhrase(*this);

    if (isPostApp() && (conds & CondPidZero)) s += LoadStringRes(IDS_RULEN_PID_ZERO);
    if (conds & CondService) s += L" " + ServicePhrase(*this);
    if (!isInterface() && (conds & CondInterface))
        s += LoadStringResFmt(IDS_RULEN_INTERFACE_FMT, interfaceName.c_str());
    if (conds & CondWfpFlags)
        s += LoadStringResFmt(IDS_RULEN_WFP_FLAGS_FMT, ConditionFlagsText().c_str());

    if (isIcmp() && (conds & CondIcmpType) && !icmpTypes.empty())
        s += LoadStringRes(IDS_RULEN_TYPE) + IcmpTypesText();

    const std::wstring local = EndpointPhrase(*this, false);
    const std::wstring remote = EndpointPhrase(*this, true);
    if ((conds & CondDirection) && dir != Dir::Unknown) {
        const std::wstring& from = dir == Dir::In ? remote : local;
        const std::wstring& to = dir == Dir::In ? local : remote;
        if (!from.empty()) s += LoadStringRes(IDS_RULEN_FROM) + from;
        if (!to.empty()) s += LoadStringRes(IDS_RULEN_TO) + to;
    } else if (!local.empty() || !remote.empty()) {
        // Без условия направления нельзя объявлять одну сторону источником.
        s += LoadStringResFmt(IDS_RULEN_BETWEEN_FMT,
            local.empty() ? L"*" : local.c_str(), remote.empty() ? L"*" : remote.c_str());
    }

    // У PostApp пометка не нужна: имя группы уже лежит в appName, и общая
    // ветка допишет его через IDS_RULEN_FOR.
    if (isGlobal())             s += LoadStringRes(IDS_RULEN_FOR_ALL);
    else if (!appName.empty())  s += LoadStringRes(IDS_RULEN_FOR) + appName;
    return s;
}

void Rule::SyncName() {
    if (autoName || name.empty()) {
        name = BuildAutoName();
        autoName = true;
    }
}

std::wstring RuleExplainMarkup(const Rule& r) {
    std::wstring s;
    s += kPad;
    s += LoadStringRes(IDS_EXPL_WHERE_PROTO) + Anchor(RuleLink::kProto, r.ProtoCondText());
    if (!r.protoFixed()) s += LoadStringRes(IDS_HINT_PICK_PROTO);
    s += L"\r\n";

    // Направление, как и действие, имеет всего два значения: щелчок по ссылке
    // сразу меняет его на противоположное.
    if (r.conds & CondDirection) {
        s += kPadSub;
        s += LoadStringRes(IDS_EXPL_AND_DIR) + Anchor(RuleLink::kDir, r.DirTextRu());
        s += (r.dir == Dir::In) ? LoadStringRes(IDS_HINT_CLICK_OUT)
                                : LoadStringRes(IDS_HINT_CLICK_IN);
        s += L"\r\n";
    }
    if (r.isPostApp()) {
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_PID) +
                        Anchor(RuleLink::kPid, r.PidText()));
        s += LoadStringRes((r.conds & CondPidZero)
            ? IDS_HINT_CLICK_PID_ANY : IDS_HINT_CLICK_PID_ZERO);
        s += L"\r\n";
    }
    if (!r.isInterface() && (r.conds & CondInterface))
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_INTERFACE) +
                        Anchor(RuleLink::kInterface, r.interfaceName.empty()
                            ? LoadStringRes(IDS_RED_DASH) : r.interfaceName)) + L"\r\n";
    if (r.conds & CondWfpFlags)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_WFP_FLAGS) +
                        Anchor(RuleLink::kWfpFlags, r.ConditionFlagsText())) + L"\r\n";
    if (r.conds & CondService)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_SERVICE) +
                        Anchor(RuleLink::kService, r.ServicesText())) + L"\r\n";
    if (r.conds & CondIcmpType)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_ICMP) +
                        Anchor(RuleLink::kIcmpType, r.IcmpTypesText())) + L"\r\n";
    if (r.conds & CondRemoteAddr)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_REMOTE_ADDR) +
                        Anchor(RuleLink::kRAddr, r.AddrsText(true))) + L"\r\n";
    if (r.conds & CondRemotePort)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_REMOTE_PORT) +
                        Anchor(RuleLink::kRPort, r.PortsText(true))) + L"\r\n";
    if (r.conds & CondLocalAddr)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_LOCAL_ADDR) +
                        Anchor(RuleLink::kLAddr, r.AddrsText(false))) + L"\r\n";
    if (r.conds & CondLocalPort)
        s += kPadSub + (LoadStringRes(IDS_EXPL_AND_LOCAL_PORT) +
                        Anchor(RuleLink::kLPort, r.PortsText(false))) + L"\r\n";

    s += kPad;
    s += Anchor(RuleLink::kAction, r.ActionTextRu());
    s += (r.action == RuleAction::Allow)
            ? LoadStringRes(IDS_HINT_CLICK_BLOCK)
            : LoadStringRes(IDS_HINT_CLICK_ALLOW);
    return s;
}

std::wstring RuleScopeLine(const Rule& r) {
    std::wstring s = LoadStringRes(IDS_EXPL_PRIORITY) + std::to_wstring(r.priority + 1);
    UINT scopeId;
    if (r.isGlobal())       scopeId = IDS_EXPL_SCOPE_GLOBAL;
    else if (r.isPostApp()) scopeId = IDS_EXPL_SCOPE_POSTAPP;
    else if (r.isInterface())  return s + L" — " + r.appPath;
    else                    scopeId = IDS_EXPL_SCOPE_APP;
    s += LoadStringRes(scopeId);
    return s;
}

// ----------------------------------------------------------- RuleStore

std::wstring InterfaceDisplayName(uint32_t index) {
    const auto name = net::SharedNetworkInterfaces().GetInterfaceName(index);
    return name && !name->empty() ? *name : LoadStringResFmt(IDS_INTERFACE_UNKNOWN, index);
}

RuleStore::RuleStore(const pmkext::ProcessTable& processes) : processes_(processes) {
    unavailableInterfaceRule_.conds = CondNone;
    unavailableInterfaceRule_.action = RuleAction::Block;
    unavailableInterfaceRule_.name = LoadStringRes(IDS_APP_INTERFACE_UNAVAILABLE);
    unavailableInterfaceRuleName_ = std::make_shared<const std::wstring>(unavailableInterfaceRule_.name);
    otherInterfaceRule_.conds = CondNone;
    otherInterfaceRule_.action = RuleAction::Block;
    otherInterfaceRule_.name = LoadStringRes(IDS_APP_INTERFACE_OTHER_BLOCKED);
    otherInterfaceRuleName_ = std::make_shared<const std::wstring>(otherInterfaceRule_.name);
    auto& watcher = net::SharedNetworkInterfaces();
    interfaceSubscription_ = watcher.Subscribe([this](const auto& event) {
        if (event.snapshot_updated) RefreshInterfaces();
    });
    if (!watcher.Start()) watcher.Refresh();
    RefreshInterfaces();
}
RuleStore::~RuleStore() {
    net::SharedNetworkInterfaces().Unsubscribe(interfaceSubscription_);
}

void RuleStore::WatchInterfaces(HWND window, bool enable) {
    std::lock_guard lock(mtx_);
    std::erase(interfaceWindows_, window);
    if (enable) interfaceWindows_.push_back(window);
}

void RuleStore::RefreshInterfaces() const {
    std::lock_guard lock(mtx_);
    SyncInterfacesLocked();
}

void RuleStore::SyncInterfacesLocked() const {
    auto& watcher = net::SharedNetworkInterfaces();
    if (interfaceSnapshotVersion_.load(std::memory_order_relaxed) == watcher.SnapshotVersion()) return;
    const auto snapshot = watcher.GetSnapshot();
    if (!snapshot) return;
    bool changed = SyncAppInterfacesLocked(snapshot);
    for (auto& group : interfaces_) {
        const auto match = snapshot->FindByName(group.name);
        const uint32_t index = match.active ? match.active->number : 0;
        const uint32_t ipv6 = match.active ? match.first->ipv6_number : 0;
        changed |= group.index != index || group.ipv6Index != ipv6;
        group.index = index;
        group.ipv6Index = ipv6;
    }
    // Один поиск на уникальное имя, независимо от числа правил и групп.
    for (auto& filter : interfaceFilters_) {
        const auto resolved = ResolveInterfaceFilter(filter.name, snapshot);
        changed |= filter.index != resolved.index || filter.ipv6Index != resolved.ipv6Index;
        filter.index = resolved.index;
        filter.ipv6Index = resolved.ipv6Index;
    }
    const auto removed = std::erase_if(interfaces_, [](const auto& group) {
        return !group.index && !group.rules;
    });
    changed |= removed != 0;
    for (const auto& entry : snapshot->interfaces) {
        if (!entry.up || entry.name.empty()) continue;
        const auto found = std::find_if(interfaces_.begin(), interfaces_.end(), [&](const auto& group) {
            return group.name == entry.name;
        });
        if (found != interfaces_.end()) continue;
        const auto* active = snapshot->FindActiveByName(entry.name);
        if (!active) continue;
        InterfaceGroup group;
        group.name = entry.name;
        group.index = active->number;
        group.ipv6Index = entry.ipv6_number;
        interfaces_.push_back(std::move(group));
        changed = true;
    }
    if (!changed) {
        interfaceSnapshotVersion_.store(snapshot->version, std::memory_order_release);
        return;
    }
    RebuildInterfaceIndexLocked();
    ++version_;
    ++interfaceVersion_;
    interfaceSnapshotVersion_.store(snapshot->version, std::memory_order_release);
    for (HWND window : interfaceWindows_) PostMessageW(window, kInterfacesChanged, 0, 0);
}

bool RuleStore::InterfaceFilter::Matches(const MatchQuery& query) const {
    if (!index || !query.interfaceIndex) return false;
    if (query.interfaceIndex != index && query.interfaceIndex != ipv6Index) return false;
    // Числовой индекс мог перейти другому адаптеру, пока запрос ждал ответа.
    return !query.interfaceName || *query.interfaceName == name;
}

RuleStore::InterfaceFilter RuleStore::ResolveInterfaceFilter(
    const std::wstring& name, const net::NetworkInterfaceWatcher::SnapshotPtr& snapshot) {
    InterfaceFilter filter;
    filter.name = name;
    if (name.empty()) return filter;
    if (snapshot) {
        const auto match = snapshot->FindByName(name);
        if (match.active) {
            filter.index = match.active->number;
            filter.ipv6Index = match.first->ipv6_number;
        }
    } else {
        filter.index = net::SharedNetworkInterfaces().GetInterfaceNumberByName(name).value_or(0);
    }
    return filter;
}

void RuleStore::RebuildInterfaceIndexLocked() const {
    idxInterface_.clear();
    for (const auto& group : interfaces_) {
        if (!group.index || group.items.empty()) continue;
        idxInterface_[group.index] = group.items;
        if (group.ipv6Index) idxInterface_[group.ipv6Index] = group.items;
    }
    TrimHashTable(idxInterface_);
}

const std::vector<ServiceEntry>& RuleStore::Hosted::Get() {
    if (!resolved) {
        // Числовой PID недостаточен: pending-запрос принадлежит исходному
        // процессу, даже если кеш его метаданных уже очищен.
        ProcessPathRef parent;
        if (!inheritedPath.empty()) {
            // Дескриптор предка нужен только сервисному условию. Сетевые события
            // без него не открывают процессы и не копируют пути.
            parent = ProcessImagePathRef(pid);
            if (parent && EqualNoCase(parent->text, inheritedPath))
                process = parent->process.get();
        }
        if (process && process->pid == pid && process->alive())
            list = ServiceInfo::ServicesOfPid(pid);
        resolved = true;
    }
    static const std::vector<ServiceEntry> empty;
    return list ? *list : empty;
}

bool RuleStore::CanSetInheritance(std::wstring_view appPath, DWORD pid) {
    return pid != 0 && pid != 4 && !appPath.empty() &&
           !EqualNoCase(appPath, KernelImagePath());
}

RuleInheritance RuleStore::InheritanceLocked(std::wstring_view path, uint64_t hash) const {
    const auto found = inheritance_.find(hash);
    if (found != inheritance_.end()) {
        for (const auto& setting : found->second)
            if (EqualNoCase(setting.appPath, path)) return setting.mode;
    }
    return RuleInheritance::Default;
}

RuleInheritance RuleStore::GetInheritance(std::wstring_view appPath) const {
    const uint64_t hash = HashTextNoCase(appPath);
    std::lock_guard<std::mutex> lock(mtx_);
    return InheritanceLocked(appPath, hash);
}

std::vector<AppInheritanceSetting> RuleStore::InheritanceSettingsLocked() const {
    std::vector<AppInheritanceSetting> result;
    for (const auto& [hash, bucket] : inheritance_) {
        (void)hash;
        result.insert(result.end(), bucket.begin(), bucket.end());
    }
    return result;
}

void RuleStore::InheritanceChangedLocked() {
    // Поколение глобально уникально: новый RuleStore по тому же адресу не
    // вправе принять кеш уничтоженного хранилища с другими настройками.
    static std::atomic<uint64_t> generation{0};
    inheritanceGeneration_ = ++generation;
    bool used = false;
    for (const auto& [hash, bucket] : inheritance_) {
        (void)hash;
        for (const auto& setting : bucket)
            used |= RuleInheritanceEnabled(setting.mode);
    }
    inheritanceUsed_.store(used, std::memory_order_relaxed);
    processVersion_.store(processes_.version(), std::memory_order_relaxed);
}

void RuleStore::LoadInheritanceLocked(std::vector<AppInheritanceSetting> settings) {
    inheritance_.clear();
    for (auto& setting : settings) {
        if (!CanSetInheritance(setting.appPath) ||
            (setting.mode == RuleInheritance::Default || static_cast<uint8_t>(setting.mode) > 3))
            continue;
        const uint64_t hash = HashTextNoCase(setting.appPath);
        auto& bucket = inheritance_[hash];
        const auto same = std::find_if(bucket.begin(), bucket.end(), [&](const auto& value) {
            return EqualNoCase(value.appPath, setting.appPath);
        });
        if (same == bucket.end()) bucket.push_back(std::move(setting));
        else *same = std::move(setting);
    }
    InheritanceChangedLocked();
}

bool RuleStore::SetInheritance(const std::wstring& appPath, RuleInheritance mode) {
    if (!CanSetInheritance(appPath) ||
        static_cast<uint8_t>(mode) > 3) return false;
    const uint64_t hash = HashTextNoCase(appPath);
    std::lock_guard<std::mutex> lock(mtx_);
    if (InheritanceLocked(appPath, hash) == mode) return true;
    auto& bucket = inheritance_[hash];
    const auto same = std::find_if(bucket.begin(), bucket.end(), [&](const auto& value) {
        return EqualNoCase(value.appPath, appPath);
    });
    if (mode == RuleInheritance::Default) {
        if (same != bucket.end()) bucket.erase(same);
        if (bucket.empty()) inheritance_.erase(hash);
    } else if (same == bucket.end()) {
        bucket.push_back({appPath, mode});
    } else {
        same->mode = mode;
    }
    InheritanceChangedLocked();
    SaveLocked();
    return true;
}

std::wstring RuleStore::GetPreferredInterface(std::wstring_view appPath) const {
    const uint64_t hash = HashTextNoCase(appPath);
    std::lock_guard lock(mtx_);
    const auto found = appInterfaces_.find(hash);
    if (found != appInterfaces_.end())
        for (const auto& value : found->second)
            if (EqualNoCase(value.setting.appPath, appPath)) return value.setting.interfaceName;
    return {};
}

bool RuleStore::GetBlockOtherInterfaces(std::wstring_view appPath) const {
    std::lock_guard lock(mtx_);
    const auto found = appInterfaces_.find(HashTextNoCase(appPath));
    if (found != appInterfaces_.end())
        for (const auto& value : found->second)
            if (EqualNoCase(value.setting.appPath, appPath)) return value.setting.blockOtherInterfaces;
    return false;
}

std::vector<AppInterfaceSetting> RuleStore::AppInterfaceSettingsLocked() const {
    std::vector<AppInterfaceSetting> result;
    for (const auto& [hash, bucket] : appInterfaces_) {
        (void)hash;
        for (const auto& value : bucket) result.push_back(value.setting);
    }
    return result;
}

void RuleStore::UpdateAppInterfacesUsedLocked() {
    const bool used = std::any_of(appInterfaces_.begin(), appInterfaces_.end(), [](const auto& entry) {
        return std::any_of(entry.second.begin(), entry.second.end(), [](const auto& value) {
            return !value.setting.interfaceName.empty();
        });
    });
    appInterfacesUsed_.store(used, std::memory_order_relaxed);
}

void RuleStore::ApplyAppInterfacesLocked() const {
    if (!appInterfacesActive_ || !appInterfaceHandler_) return;
    std::erase_if(appInterfaceResets_, [&](const auto& path) {
        return appInterfaceHandler_(path, 0);
    });
    for (auto& [hash, bucket] : appInterfaces_) {
        (void)hash;
        for (auto& value : bucket) {
            if (value.setting.interfaceName.empty()) continue;
            if (!routePoliciesAttempted_) {
                routePoliciesAttempted_ = true;
                routePoliciesReady_ = !enableRoutePolicies_ || enableRoutePolicies_();
            }
            if (value.applied && value.appliedLuid == value.luid) continue;
            // Здесь только явные предпочтения. При недоступном интерфейсе снимаем
            // его политику LUID 0; выбранное имя и блокировка matcher-а сохраняются.
            value.applied = false;
            if (appInterfaceHandler_(value.setting.appPath, value.luid)) {
                value.appliedLuid = value.luid;
                value.applied = true;
                ++version_;
            }
        }
    }
}

bool RuleStore::SyncAppInterfacesLocked(
    const net::NetworkInterfaceWatcher::SnapshotPtr& snapshot) const {
    if (appInterfaces_.empty()) {
        ApplyAppInterfacesLocked();
        return false;
    }
    // Один индекс активных имён на обновление снимка, не на сетевое событие.
    std::unordered_map<std::wstring_view, const net::NetworkInterfaceWatcher::InterfaceInfo*> active;
    if (snapshot) {
        active.reserve(snapshot->interfaces.size());
        for (const auto& entry : snapshot->interfaces)
            if (entry.up && entry.luid && !entry.name.empty()) active.emplace(entry.name, &entry);
    }
    bool changed = false;
    for (auto& [hash, bucket] : appInterfaces_) {
        (void)hash;
        for (auto& value : bucket) {
            const auto found = active.find(value.setting.interfaceName);
            const auto* entry = found == active.end() ? nullptr : found->second;
            const bool available = entry != nullptr;
            const uint64_t luid = entry ? entry->luid : 0;
            const uint32_t index = entry ? entry->number : 0;
            const uint32_t ipv6Index = entry ? entry->ipv6_number : 0;
            changed |= value.available != available || value.luid != luid ||
                       (value.setting.blockOtherInterfaces &&
                        (value.index != index || value.ipv6Index != ipv6Index));
            value.available = available;
            value.luid = luid;
            value.index = index;
            value.ipv6Index = ipv6Index;
        }
    }
    ApplyAppInterfacesLocked();
    return changed;
}

void RuleStore::ResetAppInterfaceLocked(const std::wstring& appPath) {
    if (std::none_of(appInterfaceResets_.begin(), appInterfaceResets_.end(), [&](const auto& path) {
            return EqualNoCase(path, appPath);
        })) appInterfaceResets_.push_back(appPath);
}

bool RuleStore::RemoveAppInterfaceLocked(std::wstring_view appPath) {
    const auto found = appInterfaces_.find(HashTextNoCase(appPath));
    if (found == appInterfaces_.end()) return false;
    auto& bucket = found->second;
    const auto same = std::find_if(bucket.begin(), bucket.end(), [&](const auto& value) {
        return EqualNoCase(value.setting.appPath, appPath);
    });
    if (same == bucket.end()) return false;
    if (!same->setting.interfaceName.empty()) ResetAppInterfaceLocked(same->setting.appPath);
    bucket.erase(same);
    if (bucket.empty()) appInterfaces_.erase(found);
    return true;
}

void RuleStore::LoadAppInterfacesLocked(std::vector<AppInterfaceSetting> settings) {
    for (const auto& [hash, bucket] : appInterfaces_) {
        (void)hash;
        for (const auto& value : bucket) {
            if (value.setting.interfaceName.empty()) continue;
            const bool retained = std::any_of(settings.begin(), settings.end(), [&](const auto& setting) {
                return EqualNoCase(value.setting.appPath, setting.appPath) &&
                       !setting.interfaceName.empty();
            });
            if (!retained) ResetAppInterfaceLocked(value.setting.appPath);
        }
    }
    appInterfaces_.clear();
    for (auto& setting : settings) {
        if (setting.appPath.empty() || (setting.interfaceName.empty() && !setting.blockOtherInterfaces)) continue;
        auto& bucket = appInterfaces_[HashTextNoCase(setting.appPath)];
        const auto same = std::find_if(bucket.begin(), bucket.end(), [&](const auto& value) {
            return EqualNoCase(value.setting.appPath, setting.appPath);
        });
        if (same == bucket.end()) {
            AppInterfacePreference value;
            value.foldedPath = FoldCaseCopy(setting.appPath);
            value.setting = std::move(setting);
            bucket.push_back(std::move(value));
        } else {
            // Имя и флажок могут приходить отдельными строками двух таблиц.
            if (!setting.interfaceName.empty()) same->setting.interfaceName = std::move(setting.interfaceName);
            same->setting.blockOtherInterfaces |= setting.blockOtherInterfaces;
        }
    }
    UpdateAppInterfacesUsedLocked();
    SyncAppInterfacesLocked(net::SharedNetworkInterfaces().GetSnapshot());
}

bool RuleStore::SetPreferredInterface(const std::wstring& appPath, const std::wstring& name,
                                      std::optional<bool> blockOtherInterfaces) {
    if (appPath.empty()) return false;
    std::lock_guard lock(mtx_);
    const uint64_t hash = HashTextNoCase(appPath);
    auto found = appInterfaces_.find(hash);
    AppInterfacePreference* existing = nullptr;
    if (found != appInterfaces_.end()) {
        const auto same = std::find_if(found->second.begin(), found->second.end(), [&](const auto& value) {
            return EqualNoCase(value.setting.appPath, appPath);
        });
        if (same != found->second.end()) existing = &*same;
    }
    const std::wstring oldName = existing ? existing->setting.interfaceName : std::wstring();
    const bool oldBlock = existing && existing->setting.blockOtherInterfaces;
    const bool block = blockOtherInterfaces.value_or(oldBlock);
    if (oldName == name && oldBlock == block) return true;

    if (!oldName.empty() && name.empty()) ResetAppInterfaceLocked(existing->setting.appPath);
    if (name.empty() && !block) {
        auto& bucket = found->second;
        std::erase_if(bucket, [&](const auto& value) { return EqualNoCase(value.setting.appPath, appPath); });
        if (bucket.empty()) appInterfaces_.erase(found);
    } else {
        if (!existing) {
            AppInterfacePreference value;
            value.setting.appPath = appPath;
            value.foldedPath = FoldCaseCopy(appPath);
            auto& bucket = appInterfaces_[hash];
            bucket.push_back(std::move(value));
            existing = &bucket.back();
        }
        existing->setting.interfaceName = name;
        existing->setting.blockOtherInterfaces = block;
        if (oldName != name) existing->applied = false;
    }
    if (oldName != name) {
        if (!name.empty())
            std::erase_if(appInterfaceResets_, [&](const auto& path) { return EqualNoCase(path, appPath); });
        SyncAppInterfacesLocked(net::SharedNetworkInterfaces().GetSnapshot());
    }
    SaveLocked(false);
    return true;
}

void RuleStore::SetAppInterfaceHandler(AppInterfaceHandler handler,
                                      std::function<bool()> enableRoutePolicies) {
    std::lock_guard lock(mtx_);
    appInterfaceHandler_ = std::move(handler);
    enableRoutePolicies_ = std::move(enableRoutePolicies);
}

void RuleStore::SetAppInterfacesActive(bool active) {
    std::lock_guard lock(mtx_);
    if (appInterfacesActive_ == active) return;
    appInterfacesActive_ = active;
    if (!active && !routePoliciesReady_) routePoliciesAttempted_ = false;
    if (!appInterfaces_.empty()) ++version_;
    for (auto& [hash, bucket] : appInterfaces_) {
        (void)hash;
        for (auto& value : bucket) value.applied = false;
    }
    if (active) SyncAppInterfacesLocked(net::SharedNetworkInterfaces().GetSnapshot());
}

RuleStore::AppInterfaceBlock RuleStore::PreferredInterfaceBlockedLocked(const MatchQuery& query) const {
    if (query.source != TrafficSource::Host || !appInterfacesUsed_.load(std::memory_order_relaxed))
        return AppInterfaceBlock::None;
    // Только исходный EXE: выбранный источник наследуемых правил здесь не участвует.
    const auto known = query.appPath.empty() ? processes_.rulePath(query.pid, query.lineage) : nullptr;
    const auto path = known ? std::wstring_view(*known->text) : query.appPath;
    const uint64_t hash = known ? known->hash :
        (query.preparedAppPath ? query.appPathHash : HashTextNoCase(path));
    const auto found = appInterfaces_.find(hash);
    if (found != appInterfaces_.end()) {
        const auto folded = known ? std::wstring_view(known->folded) : query.foldedAppPath;
        for (const auto& value : found->second) {
            const bool same = known || query.preparedAppPath ? value.foldedPath == folded :
                EqualNoCase(value.setting.appPath, path);
            if (!same) continue;
            if (value.setting.interfaceName.empty()) return AppInterfaceBlock::None;
            // Индекс 1 обрабатывается обычными правилами даже при недоступном адаптере.
            if (value.setting.blockOtherInterfaces && query.interfaceIndex == 1)
                return AppInterfaceBlock::None;
            if (!value.available || (appInterfacesActive_ &&
                (!routePoliciesReady_ || !value.applied || value.appliedLuid != value.luid)))
                return AppInterfaceBlock::Unavailable;
            // У ожидающего запроса сохранённое имя защищает от повторного использования индекса.
            if (value.setting.blockOtherInterfaces &&
                ((!(value.index && query.interfaceIndex == value.index) &&
                  !(value.ipv6Index && query.interfaceIndex == value.ipv6Index)) ||
                 (query.interfaceName && *query.interfaceName != value.setting.interfaceName)))
                return AppInterfaceBlock::OtherInterface;
            return AppInterfaceBlock::None;
        }
    }
    return AppInterfaceBlock::None;
}

bool RuleStore::PreferredInterfaceBlocked(const MatchQuery& query, uint64_t& matchedVersion) const {
    matchedVersion = version_.load(std::memory_order_acquire);
    if (query.source != TrafficSource::Host || !appInterfacesUsed_.load(std::memory_order_relaxed))
        return false;
    std::lock_guard lock(mtx_);
    SyncInterfacesLocked();
    matchedVersion = version_.load(std::memory_order_relaxed);
    return PreferredInterfaceBlockedLocked(query) != AppInterfaceBlock::None;
}

void RuleStore::SyncProcessVersionLocked() const {
    const uint64_t current = processes_.version();
    if (processVersion_.load(std::memory_order_relaxed) == current) return;
    ++version_;
    processVersion_.store(current, std::memory_order_release);
}

uint64_t RuleStore::version() const {
    const bool interfacesChanged = interfaceSnapshotVersion_.load(std::memory_order_acquire) !=
        net::SharedNetworkInterfaces().SnapshotVersion();
    if (interfacesChanged || (inheritanceUsed_.load(std::memory_order_relaxed) &&
        processVersion_.load(std::memory_order_relaxed) != processes_.version())) {
        std::lock_guard<std::mutex> lock(mtx_);
        SyncInterfacesLocked();
        if (inheritanceUsed_.load(std::memory_order_relaxed)) SyncProcessVersionLocked();
    }
    return version_.load();
}

uint64_t RuleStore::interfaceVersion() const {
    if (interfaceSnapshotVersion_.load(std::memory_order_acquire) !=
        net::SharedNetworkInterfaces().SnapshotVersion()) RefreshInterfaces();
    return interfaceVersion_.load(std::memory_order_relaxed);
}

pmkext::ProcessRuleSource RuleStore::InheritedSourceLocked(const MatchQuery& query) const {
    if (!inheritanceUsed_.load(std::memory_order_relaxed) ||
        query.source != TrafficSource::Host || query.pid == 0 || query.pid == 4) return {};
    const auto knownPath = query.appPath.empty() ? processes_.rulePath(query.pid, query.lineage) : nullptr;
    const std::wstring_view appPath = knownPath ? *knownPath->text : query.appPath;
    const uint64_t hash = knownPath ? knownPath->hash :
        (query.preparedAppPath ? query.appPathHash : HashTextNoCase(appPath));
    if (RuleInheritanceBlocked(InheritanceLocked(appPath, hash))) return {};
    return processes_.oldestRuleAncestor(query.pid, this, inheritanceGeneration_,
        [&](const pmkext::ProcessRulePath& path) {
            return RuleInheritanceEnabled(InheritanceLocked(*path.text, path.hash));
        }, query.lineage);
}

pmkext::ProcessRuleSource RuleStore::InheritedSource(const MatchQuery& query) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return InheritedSourceLocked(query);
}

void RuleStore::Fire(const Changes& list) {
    // Вне мьютекса: обработчик вправе обратиться к хранилищу
    for (const Change& c : list)
        notify_rule_changed(c.kind, c.rule.id, c.rule);
}

bool RuleStore::SameGroup(const Rule& a, const Rule& b) {
    if (a.scope != b.scope) return false;
    if (a.isInterface()) return a.appPath == b.appPath;
    if (a.scope != RuleScope::App) return true;
    return EqualNoCase(a.appPath, b.appPath);
}

void RuleStore::NormalizeLocked() {
    std::stable_sort(rules_.begin(), rules_.end(), [](const Rule& a, const Rule& b) {
        // Интерфейс проверяется раньше цепочки Global → App → PostApp.
        if (a.scope != b.scope) {
            const auto order = [](RuleScope scope) {
                if (scope == RuleScope::Interface) return -1;
                if (scope == RuleScope::Global) return 0;
                if (scope == RuleScope::App) return 1;
                if (scope == RuleScope::PostApp) return 2;
                return 3;
            };
            return order(a.scope) < order(b.scope);
        }
        if (a.scope == RuleScope::App || a.isInterface()) {
            const int c = a.isInterface() ? a.appPath.compare(b.appPath)
                                          : CompareNoCase(a.appPath, b.appPath);
            if (c != 0) return c < 0;
        }
        if (a.priority != b.priority) return a.priority < b.priority;
        return a.id < b.id;
    });

    int idx = 0;
    for (size_t i = 0; i < rules_.size(); ++i) {
        if (i && !SameGroup(rules_[i - 1], rules_[i])) idx = 0;
        rules_[i].priority = idx++;
        if (rules_[i].isGlobal()) {
            rules_[i].appPath.clear();
            rules_[i].appName = LoadStringRes(IDS_RULE_GLOBAL_APP);
        } else if (rules_[i].isPostApp()) {
            rules_[i].appPath.clear();
            rules_[i].appName = LoadStringRes(IDS_RULE_POSTAPP_APP);
        } else if (rules_[i].isInterface()) {
            rules_[i].appName = rules_[i].appPath;
        } else if (rules_[i].appName.empty()) {
            rules_[i].appName = PathBaseUpper(rules_[i].appPath);
        }
        // условия, не относящиеся к протоколу, не должны влиять на сопоставление
        NormalizeRuleConds(rules_[i]);
        rules_[i].SyncName();
        Rule& rule = rules_[i];
        TrimCapacity(rule.name);
        TrimCapacity(rule.appPath);
        TrimCapacity(rule.appName);
        TrimCapacity(rule.interfaceName);
        TrimCapacity(rule.remoteAddrs);
        TrimCapacity(rule.localAddrs);
        TrimCapacity(rule.remotePorts);
        TrimCapacity(rule.localPorts);
        TrimCapacity(rule.icmpTypes);
        TrimCapacity(rule.services);
        for (ServiceItem& service : rule.services) {
            TrimCapacity(service.name);
            TrimCapacity(service.display);
        }
    }
}

// ---------------------------------------------------------------------------
// Перестройка индексов правил.
//
// Выполняется только при правке набора правил, то есть по действию
// пользователя. Всё, что раньше считалось на КАЖДОЕ событие сети, посчитано
// здесь один раз: раскладка по приложениям, флаг «используются сервисы»,
// флаг «есть условия с изменчивым значением».
//
// В индекс сопоставления попадают только ВКЛЮЧЁННЫЕ правила, поэтому проверка
// признака «включено» из горячего пути ушла совсем. Индекс чтения по ID
// содержит все правила и сохраняет первое совпадение, как линейный поиск.
// ---------------------------------------------------------------------------
void RuleStore::RebuildIndexLocked() {
    TrimCapacity(rules_);
    // Старый ID-индекс относится к прежнему массиву имён. Сохраняем готовые
    // строки после сортировки и изменения размера, если имя не поменялось.
    SnapshotArray<RuleNameRef> names;
    names.reset(rules_.size());
    for (size_t i = 0; i < rules_.size(); ++i) {
        const Rule& rule = rules_[i];
        if (!rule.enabled) continue;
        const auto previous = idxId_.find(rule.id);
        if (previous != idxId_.end() && previous->second < idxRuleNames_.size()) {
            const auto& name = idxRuleNames_[previous->second];
            if (name && *name == rule.name) names[i] = name;
        }
        if (!names[i]) names[i] = std::make_shared<const std::wstring>(rule.name);
    }
    idxRuleNames_ = std::move(names);
    idxId_.clear();
    idxGlobal_ = {};
    idxApp_.clear();
    idxPostApp_ = {};
    interfaceFilters_.clear();
    const auto interfaceSnapshot = net::SharedNetworkInterfaces().GetSnapshot();
    std::unordered_map<std::wstring_view, uint32_t> interfaceFilterIndices;
    for (auto& group : interfaces_) { group.items = {}; group.rules = group.enabled = 0; }
    servicesUsed_ = false;
    macrosUsed_ = false;
    volatileConds_ = false;

    idxId_.reserve(rules_.size());
    const size_t enabled = static_cast<size_t>(std::count_if(
        rules_.begin(), rules_.end(), [](const Rule& rule) { return rule.enabled; }));
    idxCandidates_.reset(enabled);

    size_t candidate = 0;
    for (size_t first = 0; first < rules_.size();) {
        size_t last = first + 1;
        while (last < rules_.size() && SameGroup(rules_[first], rules_[last])) ++last;
        const size_t begin = candidate;
        InterfaceGroup* interface = nullptr;
        if (rules_[first].isInterface()) {
            const auto& name = rules_[first].appPath;
            auto found = std::find_if(interfaces_.begin(), interfaces_.end(), [&](const auto& group) {
                return group.name == name;
            });
            if (found == interfaces_.end()) {
                InterfaceGroup group;
                group.name = name;
                auto& watcher = net::SharedNetworkInterfaces();
                const auto snapshot = watcher.GetSnapshot();
                if (snapshot) {
                    const auto match = snapshot->FindByName(name);
                    if (match.active) {
                        group.index = match.active->number;
                        group.ipv6Index = match.first->ipv6_number;
                    }
                } else {
                    group.index = watcher.GetInterfaceNumberByName(name).value_or(0);
                }
                interfaces_.push_back(std::move(group));
                found = std::prev(interfaces_.end());
            }
            interface = &*found;
            interface->rules = last - first;
        }
        for (size_t i = first; i < last; ++i) {
            const Rule& r = rules_[i];
            idxId_.try_emplace(r.id, i);
            if (!r.enabled) continue;

            if (r.conds & CondService) servicesUsed_ = true;
            if (((r.conds & CondRemoteAddr) && ListHasMacro(r.remoteAddrs)) ||
                ((r.conds & CondLocalAddr) && ListHasMacro(r.localAddrs)))
                macrosUsed_ = true;
            if (r.hasVolatileConds()) volatileConds_ = true;

            Cand& c = idxCandidates_[candidate++];
            c = {};
            c.idx   = static_cast<uint32_t>(i);
            c.conds = static_cast<uint16_t>(EffectiveRuleConds(r));
            c.proto = ProtoNumber(r.proto);
            c.dir   = static_cast<uint8_t>(r.dir);
            if (c.conds & CondInterface) {
                const auto [it, inserted] = interfaceFilterIndices.try_emplace(
                    r.interfaceName, static_cast<uint32_t>(interfaceFilters_.size()) + 1);
                if (inserted)
                    interfaceFilters_.push_back(ResolveInterfaceFilter(r.interfaceName, interfaceSnapshot));
                c.interfaceFilter = it->second;
            }
            if ((r.conds & CondRemotePort) && !r.remotePorts.empty()) {
                c.remotePortFirst = UINT16_MAX;
                c.remotePortLast = 0;
                for (const PortItem& port : r.remotePorts) {
                    c.remotePortFirst = (std::min)(c.remotePortFirst, port.from);
                    c.remotePortLast = (std::max)(c.remotePortLast, port.to);
                }
                // Нулевой порт не совпадает с непустым списком, даже с 0-65535.
                c.remotePortFirst = (std::max)(c.remotePortFirst, uint16_t{1});
            }
        }
        if (candidate != begin) {
            const auto items = idxCandidates_.span().subspan(begin, candidate - begin);
            const Rule& group = rules_[first];
            if (group.isGlobal()) idxGlobal_ = items;
            else if (group.isPostApp()) idxPostApp_ = items;
            else if (interface) { interface->items = items; interface->enabled = candidate - begin; }
            else {
                // rules_ уже отсортирован по группам. Свёртка пути нужна один
                // раз на приложение, а не для каждого правила этой группы.
                std::wstring foldedPath = FoldCaseCopy(group.appPath);
                const uint64_t hash = HashFoldedText(foldedPath);
                idxApp_[hash].push_back(AppBucket{ std::move(foldedPath), items });
            }
        }
        first = last;
    }
    TrimHashTable(idxId_);
    TrimHashTable(idxApp_);
    TrimCapacity(interfaceFilters_);
    std::erase_if(interfaces_, [](const auto& group) { return !group.index && !group.rules; });
    RebuildInterfaceIndexLocked();
}

uint32_t EffectiveRuleConds(const Rule& r) {
    uint32_t conds = r.conds;
    if (!r.isPostApp()) conds &= ~CondPidZero;
    if (r.isInterface()) conds &= ~CondInterface;
    // Разрешающее TCP/UDP-правило с заданным IP или портом действует в обе
    // стороны. Пустой список и значения выключенного условия не считаются.
    // У блокирующих правил направление остаётся обычным условием.
    if (!r.blocks() && r.protoFixed() && ProtoInOsTables(r.proto) &&
        (((conds & CondRemoteAddr) && !r.remoteAddrs.empty()) ||
         ((conds & CondLocalAddr)  && !r.localAddrs.empty())  ||
         ((conds & CondRemotePort) && !r.remotePorts.empty()) ||
         ((conds & CondLocalPort)  && !r.localPorts.empty())))
        conds &= ~CondDirection;
    return conds;
}

int RuleStore::MaxPriorityLocked(const Rule& r) const {
    int best = -1;
    for (const Rule& x : rules_)
        if (SameGroup(x, r) && x.priority > best) best = x.priority;
    return best;
}

void RuleStore::SaveLocked(bool rebuildIndex) {
    // Индекс обязан обновиться раньше version_: по смене версии внешние
    // потребители сбрасывают свои кеши решений и сразу же начинают
    // спрашивать нас снова.
    if (rebuildIndex) RebuildIndexLocked();
    UpdateAppInterfacesUsedLocked();
    ++version_;
    if (!db_) return;
    std::wstring err;
    if (!db_->SaveAll(rules_, err, InheritanceSettingsLocked(), AppInterfaceSettingsLocked())) dbErr_ = err;
    else dbErr_.clear();
}

// Загрузка: набор правил восстанавливается, а не изменяется, поэтому
// notify_rule_changed здесь намеренно не вызывается.
bool RuleStore::AttachDatabase(const std::wstring& path, std::wstring& error) {
    std::lock_guard<std::mutex> lk(mtx_);
    db_.reset(new RuleDb());
    dbPath_ = path;
    if (!db_->Open(path, error)) {
        db_.reset();
        dbErr_ = error;
        return false;
    }
    std::vector<Rule> loaded;
    uint64_t maxId = 0;
    if (!db_->Load(loaded, maxId, error)) {
        // Непрочитанный набор нельзя перезаписывать последующими правками.
        db_.reset();
        dbErr_ = error;
        return false;
    }
    std::vector<AppInheritanceSetting> inheritance;
    if (!db_->LoadInheritance(inheritance, error)) {
        db_.reset();
        dbErr_ = error;
        return false;
    }
    std::vector<AppInterfaceSetting> appInterfaces;
    if (!db_->LoadAppInterfaces(appInterfaces, error)) {
        db_.reset();
        dbErr_ = error;
        return false;
    }
    LoadInheritanceLocked(std::move(inheritance));
    rules_ = std::move(loaded);
    LoadAppInterfacesLocked(std::move(appInterfaces));
    nextId_ = maxId + 1;
    NormalizeLocked();
    RebuildIndexLocked();
    dbErr_.clear();
    ++version_;
    return true;
}

// Однократное чтение для служебного режима: локальный RuleDb разрушается
// на выходе из функции, поэтому файл базы закрывается сразу после загрузки.
bool RuleStore::LoadOnce(const std::wstring& path, std::wstring& error) {
    std::lock_guard<std::mutex> lk(mtx_);
    db_.reset();                          // прежнее подключение, если было
    dbPath_ = path;

    // Служба не должна продолжать разрешать трафик по прежнему снимку, если
    // актуальную базу прочитать не удалось. Пустой согласованный индекс
    // исключает старые разрешения; дальнейшее решение задаёт политика.
    const auto failClosed = [&]() {
        rules_.clear();
        LoadInheritanceLocked({});
        LoadAppInterfacesLocked({});
        nextId_ = 1;
        RebuildIndexLocked();
        dbErr_ = error;
        ++version_;
        return false;
    };

    RuleDb db;
    if (!db.Open(path, error)) return failClosed();

    std::vector<Rule> loaded;
    uint64_t maxId = 0;
    if (!db.Load(loaded, maxId, error)) return failClosed();

    std::vector<AppInheritanceSetting> inheritance;
    if (!db.LoadInheritance(inheritance, error)) return failClosed();
    std::vector<AppInterfaceSetting> appInterfaces;
    if (!db.LoadAppInterfaces(appInterfaces, error)) return failClosed();
    LoadInheritanceLocked(std::move(inheritance));
    rules_  = std::move(loaded);
    LoadAppInterfacesLocked(std::move(appInterfaces));
    nextId_ = maxId + 1;
    NormalizeLocked();
    RebuildIndexLocked();
    dbErr_.clear();
    ++version_;
    return true;
}

void RuleStore::DetachDatabase() {
    std::lock_guard<std::mutex> lk(mtx_);
    db_.reset();
}

bool RuleStore::readOnly() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return !db_;
}

bool RuleStore::attached() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return db_ && db_->opened();
}

std::wstring RuleStore::dbError() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return dbErr_;
}

bool RuleStore::volatileConds() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return volatileConds_;
}

bool RuleStore::serviceConds() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return servicesUsed_;
}

bool RuleStore::macroConds() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return macrosUsed_;
}

uint64_t RuleStore::Add(Rule& r) {
    if (r.isInterface() && r.appPath.empty()) return 0;
    Changes changes;
    uint64_t id = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        r.id = nextId_++;
        // Имя группы выставляется ДО SyncName: автоимя дописывает appName,
        // и с пустым именем правило получило бы имя без пометки группы.
        if (r.isGlobal()) { r.appPath.clear(); r.appName = LoadStringRes(IDS_RULE_GLOBAL_APP); }
        else if (r.isPostApp()) { r.appPath.clear(); r.appName = LoadStringRes(IDS_RULE_POSTAPP_APP); }
        else if (r.isInterface()) { r.appName = r.appPath; }
        else if (r.appName.empty()) r.appName = PathBaseUpper(r.appPath);
        r.priority = MaxPriorityLocked(r) + 1;
        r.SyncName();
        rules_.push_back(r);
        NormalizeLocked();
        SaveLocked();
        for (const Rule& x : rules_) if (x.id == r.id) { r = x; break; }
        id = r.id;
        changes.push_back(Change{ RuleChange::Added, r });
    }
    Fire(changes);
    return id;
}

size_t RuleStore::AddMissingRules(std::vector<Rule> candidates,
                                  bool (*same)(const Rule&, const Rule&)) {
    if (!same || candidates.empty()) return 0;
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        struct Group {
            std::vector<size_t> indices;
            int priority = -1;
        };
        std::unordered_map<std::wstring, Group> groups;
        Group postApps;
        for (size_t i = 0; i < rules_.size(); ++i) {
            const Rule& rule = rules_[i];
            Group* group = nullptr;
            if (rule.scope == RuleScope::App && !rule.appPath.empty())
                group = &groups[FoldCaseCopy(rule.appPath)];
            else if (rule.scope == RuleScope::PostApp)
                group = &postApps;
            if (!group) continue;
            group->indices.push_back(i);
            group->priority = std::max(group->priority, rule.priority);
        }
        std::vector<uint64_t> added;
        for (Rule& rule : candidates) {
            Group* group = nullptr;
            if (rule.scope == RuleScope::App && !rule.appPath.empty()) {
                group = &groups[FoldCaseCopy(rule.appPath)];
            } else if (rule.scope == RuleScope::PostApp && rule.appPath.empty()) {
                group = &postApps;
            }
            if (!group) continue;
            NormalizeRuleConds(rule);
            if (std::any_of(group->indices.begin(), group->indices.end(),
                    [&](size_t index) { return same(rules_[index], rule); })) continue;
            rule.id = nextId_++;
            rule.priority = ++group->priority;
            rule.enabled = true;
            if (rule.isPostApp()) rule.appName = LoadStringRes(IDS_RULE_POSTAPP_APP);
            else if (rule.appName.empty()) rule.appName = PathBaseUpper(rule.appPath);
            rule.SyncName();
            added.push_back(rule.id);
            group->indices.push_back(rules_.size());
            rules_.push_back(std::move(rule));
        }
        if (added.empty()) return 0;
        NormalizeLocked();
        SaveLocked();
        // Сортировка могла переместить правила, поэтому ищем их по новым ID.
        std::unordered_set<uint64_t> ids(added.begin(), added.end());
        for (const Rule& rule : rules_)
            if (ids.contains(rule.id)) changes.push_back(Change{ RuleChange::Added, rule });
    }
    Fire(changes);
    return changes.size();
}

bool RuleStore::Update(const Rule& r) {
    if (r.isInterface() && r.appPath.empty()) return false;
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        bool found = false;
        for (Rule& x : rules_) {
            if (x.id != r.id) continue;
            const int keep = x.priority;
            x = r;
            x.priority = keep;
            if (x.isGlobal()) { x.appPath.clear(); x.appName = LoadStringRes(IDS_RULE_GLOBAL_APP); }
            else if (x.isPostApp()) { x.appPath.clear(); x.appName = LoadStringRes(IDS_RULE_POSTAPP_APP); }
            else if (x.isInterface()) { x.appName = x.appPath; }
            x.SyncName();
            found = true;
            break;
        }
        if (!found) return false;
        NormalizeLocked();
        SaveLocked();
        for (const Rule& x : rules_)
            if (x.id == r.id) { changes.push_back(Change{ RuleChange::Modified, x }); break; }
    }
    Fire(changes);
    return true;
}

bool RuleStore::Remove(uint64_t id) {
    if (!id) return false;
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = std::find_if(rules_.begin(), rules_.end(),
                               [id](const Rule& x) { return x.id == id; });
        if (it == rules_.end()) return false;
        changes.push_back(Change{ RuleChange::Removed, *it });
        rules_.erase(it);
        NormalizeLocked();
        SaveLocked();
    }
    Fire(changes);
    return true;
}

bool RuleStore::RemoveByName(RuleScope scope, const std::wstring& appPath,
                             const std::wstring& name) {
    if (name.empty()) return false;
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const auto match = [&](const Rule& x) {
            if (x.scope != scope) return false;
            // Путь сверяется только у правил приложения: у Global и PostApp
            // он пуст, и группу задаёт один scope.
            if (scope == RuleScope::Interface && x.appPath != appPath) return false;
            if (scope == RuleScope::App && !EqualNoCase(x.appPath, appPath))
                return false;
            return x.name == name;
        };
        for (const Rule& x : rules_)
            if (match(x)) changes.push_back(Change{ RuleChange::Removed, x });
        if (changes.empty()) return false;

        rules_.erase(std::remove_if(rules_.begin(), rules_.end(), match), rules_.end());
        NormalizeLocked();
        SaveLocked();
    }
    Fire(changes);
    return true;
}

void RuleStore::RemoveApp(const std::wstring& appPath) {
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const auto match = [&](const Rule& x) {
            return x.scope == RuleScope::App && EqualNoCase(x.appPath, appPath);
        };
        for (const Rule& x : rules_)
            if (match(x)) changes.push_back(Change{ RuleChange::Removed, x });
        bool settingsRemoved = false;
        const auto bucket = inheritance_.find(HashTextNoCase(appPath));
        if (bucket != inheritance_.end()) {
            auto& values = bucket->second;
            const auto before = values.size();
            values.erase(std::remove_if(values.begin(), values.end(), [&](const auto& value) {
                return EqualNoCase(value.appPath, appPath);
            }), values.end());
            settingsRemoved = before != values.size();
            if (values.empty()) inheritance_.erase(bucket);
        }
        const bool interfaceRemoved = RemoveAppInterfaceLocked(appPath);
        if (changes.empty() && !settingsRemoved && !interfaceRemoved) return;
        if (settingsRemoved) InheritanceChangedLocked();
        ApplyAppInterfacesLocked();
        rules_.erase(std::remove_if(rules_.begin(), rules_.end(), match), rules_.end());
        NormalizeLocked();
        SaveLocked();
    }
    Fire(changes);
}

size_t RuleStore::RemoveMissingApps() {
    // Файловый ввод-вывод выполняется без мьютекса, по одному разу на приложение.
    std::unordered_set<std::wstring> missing;
    for (const AppEntry& app : Apps()) {
        if (!app.global && !app.postapp && !app.interfaceGroup && AppFileMissing(app.path))
            missing.insert(FoldCaseCopy(app.path));
    }
    if (missing.empty()) return 0;

    Changes changes;
    size_t settingsRemoved = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const auto match = [&](const Rule& rule) {
            return rule.scope == RuleScope::App && missing.contains(FoldCaseCopy(rule.appPath));
        };
        for (const Rule& rule : rules_)
            if (match(rule)) changes.push_back(Change{ RuleChange::Removed, rule });
        for (auto it = inheritance_.begin(); it != inheritance_.end();) {
            auto& bucket = it->second;
            const auto before = bucket.size();
            bucket.erase(std::remove_if(bucket.begin(), bucket.end(), [&](const auto& value) {
                return missing.contains(FoldCaseCopy(value.appPath));
            }), bucket.end());
            settingsRemoved += before - bucket.size();
            if (bucket.empty()) it = inheritance_.erase(it);
            else ++it;
        }
        size_t interfacesRemoved = 0;
        for (const auto& path : missing) interfacesRemoved += RemoveAppInterfaceLocked(path) ? 1u : 0u;
        if (changes.empty() && !settingsRemoved && !interfacesRemoved) return 0;
        if (settingsRemoved) InheritanceChangedLocked();
        settingsRemoved += interfacesRemoved;
        ApplyAppInterfacesLocked();
        rules_.erase(std::remove_if(rules_.begin(), rules_.end(), match), rules_.end());
        NormalizeLocked();
        SaveLocked();
    }
    Fire(changes);
    return changes.size() + settingsRemoved;
}

void RuleStore::RemoveGlobals() {
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (const Rule& x : rules_)
            if (x.isGlobal()) changes.push_back(Change{ RuleChange::Removed, x });
        if (changes.empty()) return;

        rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
                        [](const Rule& x) { return x.isGlobal(); }),
                     rules_.end());
        NormalizeLocked();
        SaveLocked();
    }
    Fire(changes);
}

void RuleStore::RemovePostApps() {
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (const Rule& x : rules_)
            if (x.isPostApp()) changes.push_back(Change{ RuleChange::Removed, x });
        if (changes.empty()) return;

        rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
                        [](const Rule& x) { return x.isPostApp(); }),
                     rules_.end());
        NormalizeLocked();
        SaveLocked();
    }
    Fire(changes);
}

bool RuleStore::SetEnabled(uint64_t id, bool on) {
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        bool found = false;
        for (Rule& x : rules_) {
            if (x.id != id) continue;
            found = true;
            if (x.enabled == on) return true;      // состояние не изменилось
            x.enabled = on;
            changes.push_back(Change{ RuleChange::Modified, x });
            break;
        }
        if (!found) return false;
        // Индекс содержит только включённые правила, поэтому его перестройка
        // здесь обязательна: её выполняет SaveLocked.
        SaveLocked();
    }
    Fire(changes);
    return true;
}

bool RuleStore::MovePriority(uint64_t id, int delta) {
    if (!id || delta == 0) return false;
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);

        auto it = std::find_if(rules_.begin(), rules_.end(),
                               [id](const Rule& x) { return x.id == id; });
        if (it == rules_.end()) return false;

        std::vector<Rule>::iterator tgt;
        if (delta < 0) {
            if (it == rules_.begin()) return false;
            tgt = std::prev(it);
        } else {
            tgt = std::next(it);
            if (tgt == rules_.end()) return false;
        }
        if (!SameGroup(*it, *tgt)) return false;

        std::swap(it->priority, tgt->priority);
        NormalizeLocked();
        SaveLocked();

        // порядок проверки изменился у обоих правил
        for (const Rule& x : rules_)
            if (x.id == id) { changes.push_back(Change{ RuleChange::Reordered, x }); break; }
    }
    Fire(changes);
    return true;
}

const Rule* RuleStore::FindByIdLocked(uint64_t id) const {
    const auto it = idxId_.find(id);
    return it != idxId_.end() ? &rules_[it->second] : nullptr;
}

bool RuleStore::Get(uint64_t id, Rule& out) const {
    if (!id) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    const Rule* rule = FindByIdLocked(id);
    if (!rule) return false;
    out = *rule;
    return true;
}

bool RuleStore::GetInfo(uint64_t id, RuleMatchInfo& out) const {
    if (!id) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    const Rule* rule = FindByIdLocked(id);
    if (!rule) return false;
    out.id = rule->id;
    out.name = rule->name;
    out.scope = rule->scope;
    out.action = rule->action;
    return true;
}

bool RuleStore::Exists(uint64_t id) const {
    if (!id) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    return FindByIdLocked(id) != nullptr;
}

bool RuleStore::FindByName(const std::wstring& appPath, const std::wstring& name,
                           Rule& out) const {
    if (name.empty()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    for (const Rule& x : rules_) {
        // Ищется правило ПРИЛОЖЕНИЯ: у групп без пути appPath пуст, и по
        // пустому appPath они совпали бы с любым запросом такого вида.
        if (x.scope != RuleScope::App) continue;
        if (!EqualNoCase(x.appPath, appPath)) continue;
        if (x.name != name) continue;
        out = x;
        return true;
    }
    return false;
}

bool RuleStore::FindGlobalByName(const std::wstring& name, Rule& out) const {
    if (name.empty()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    for (const Rule& x : rules_)
        if (x.isGlobal() && x.name == name) { out = x; return true; }
    return false;
}

void RuleStore::Replace(RuleScope scope, const std::wstring& appPath,
                        const std::wstring& appName, std::vector<Rule> list) {
    if (scope == RuleScope::Interface && appPath.empty()) return;
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);

        // App и Interface различаются также именем группы в appPath;
        // Global и PostApp определяются одним scope.
        const bool global  = scope == RuleScope::Global;
        const bool postApp = scope == RuleScope::PostApp;
        const bool interfaceGroup = scope == RuleScope::Interface;
        const bool byPath  = scope == RuleScope::App || interfaceGroup;

        std::wstring name;
        if (global)       name = LoadStringRes(IDS_RULE_GLOBAL_APP);
        else if (postApp) name = LoadStringRes(IDS_RULE_POSTAPP_APP);
        else if (interfaceGroup) name = appPath;
        else              name = appName.empty() ? PathBaseUpper(appPath) : appName;

        int pr = 0;
        for (Rule& r : list) {
            r.scope    = scope;
            r.appPath  = byPath ? appPath : std::wstring();
            r.appName  = name;
            r.priority = pr++;
            if (!r.id) r.id = nextId_++;
            r.SyncName();
        }

        // что было в группе до замены: пропавшие -> Removed, оставшиеся -> Modified
        const auto inGroup = [&](const Rule& x) {
            if (global)  return x.isGlobal();
            if (postApp) return x.isPostApp();
            if (interfaceGroup) return x.isInterface() && x.appPath == appPath;
            return x.scope == RuleScope::App && EqualNoCase(x.appPath, appPath);
        };
        const auto keptId = [&](uint64_t id) {
            for (const Rule& r : list) if (r.id == id) return true;
            return false;
        };

        for (const Rule& x : rules_)
            if (inGroup(x) && !keptId(x.id))
                changes.push_back(Change{ RuleChange::Removed, x });

        std::vector<uint64_t> before;
        for (const Rule& x : rules_) if (inGroup(x)) before.push_back(x.id);

        rules_.erase(std::remove_if(rules_.begin(), rules_.end(), inGroup), rules_.end());
        rules_.insert(rules_.end(), list.begin(), list.end());
        NormalizeLocked();
        SaveLocked();

        const auto existedBefore = [&](uint64_t id) {
            return std::find(before.begin(), before.end(), id) != before.end();
        };
        for (const Rule& x : rules_) {
            if (!inGroup(x)) continue;
            changes.push_back(Change{
                existedBefore(x.id) ? RuleChange::Modified : RuleChange::Added, x });
        }
    }
    Fire(changes);
}

std::vector<Rule> RuleStore::All() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return rules_;
}

std::vector<Rule> RuleStore::ForApp(const std::wstring& appPath) const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<Rule> out;
    for (const Rule& x : rules_)
        if (x.scope == RuleScope::App && EqualNoCase(x.appPath, appPath))
            out.push_back(x);
    return out;
}

std::vector<Rule> RuleStore::Globals() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<Rule> out;
    for (const Rule& x : rules_) if (x.isGlobal()) out.push_back(x);
    return out;
}

std::vector<Rule> RuleStore::PostApps() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<Rule> out;
    for (const Rule& x : rules_) if (x.isPostApp()) out.push_back(x);
    return out;
}

std::vector<Rule> RuleStore::InterfaceRules(const std::wstring& name) const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<Rule> out;
    for (const Rule& r : rules_) if (r.isInterface() && r.appPath == name) out.push_back(r);
    return out;
}

std::vector<AppEntry> RuleStore::Apps() const {
    std::lock_guard<std::mutex> lk(mtx_);

    AppEntry g;
    g.global = true;
    g.name = LoadStringRes(IDS_APPED_GLOBAL_HEADER);
    for (const Rule& r : rules_) {
        if (!r.isGlobal()) continue;
        ++g.rules;
        if (r.enabled) ++g.enabled;
    }

    AppEntry p;
    p.postapp = true;
    p.name = LoadStringRes(IDS_RULE_POSTAPP_APP);
    for (const Rule& r : rules_) {
        if (!r.isPostApp()) continue;
        ++p.rules;
        if (r.enabled) ++p.enabled;
    }

    std::vector<AppEntry> apps;
    for (const Rule& r : rules_) {
        if (r.isGlobal() || r.isPostApp() || r.isInterface() || r.appPath.empty()) continue;
        auto it = std::find_if(apps.begin(), apps.end(), [&](const AppEntry& a) {
            return EqualNoCase(a.path, r.appPath);
        });
        if (it == apps.end()) {
            AppEntry e;
            e.path = r.appPath;
            e.name = r.appName.empty() ? PathBaseUpper(r.appPath) : r.appName;
            e.rules = 1;
            e.enabled = r.enabled ? 1u : 0u;
            apps.push_back(std::move(e));
        } else {
            ++it->rules;
            if (r.enabled) ++it->enabled;
        }
    }
    // Приложение с одной настройкой наследования доступно в списке и после
    // удаления последнего правила: настройку можно изменить либо удалить.
    for (const auto& [hash, bucket] : inheritance_) {
        (void)hash;
        for (const auto& setting : bucket) {
            const bool listed = std::any_of(apps.begin(), apps.end(), [&](const auto& app) {
                return EqualNoCase(app.path, setting.appPath);
            });
            if (!listed) {
                AppEntry app;
                app.path = setting.appPath;
                app.name = PathBaseUpper(app.path);
                apps.push_back(std::move(app));
            }
        }
    }
    for (const auto& [hash, bucket] : appInterfaces_) {
        (void)hash;
        for (const auto& value : bucket) {
            const auto& setting = value.setting;
            if (std::none_of(apps.begin(), apps.end(), [&](const auto& app) {
                    return EqualNoCase(app.path, setting.appPath);
                })) {
                AppEntry app;
                app.path = setting.appPath;
                app.name = PathBaseUpper(app.path);
                apps.push_back(std::move(app));
            }
        }
    }
    std::sort(apps.begin(), apps.end(), [](const AppEntry& a, const AppEntry& b) {
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });

    std::vector<AppEntry> out;
    out.reserve(apps.size() + 3);
    out.push_back(std::move(g));
    out.insert(out.end(), apps.begin(), apps.end());
    out.push_back(std::move(p));
    return out;
}

std::vector<AppEntry> RuleStore::Interfaces() const {
    std::lock_guard lock(mtx_);
    SyncInterfacesLocked();
    std::vector<AppEntry> out;
    out.reserve(interfaces_.size());
    for (const auto& group : interfaces_) {
        AppEntry entry;
        entry.path = entry.name = group.name;
        entry.interfaceGroup = true;
        entry.active = group.index != 0;
        entry.rules = group.rules;
        entry.enabled = group.enabled;
        out.push_back(std::move(entry));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        return CompareNoCase(a.name, b.name) < 0;
    });
    return out;
}

void RuleStore::ReadDebugCounters(DebugCounters::Snapshot& out) const {
    std::unique_lock lock(mtx_, std::try_to_lock);
    if (!lock.owns_lock()) return;
    auto& v = out.values;
    v[DebugCounters::Rules] = rules_.size();
    v[DebugCounters::RuleIds] = idxId_.size();
    v[DebugCounters::RuleCandidates] = idxCandidates_.size();
    v[DebugCounters::RuleApps] = idxApp_.size();
    v[DebugCounters::RuleInheritanceBuckets] = inheritance_.size();
    size_t inheritanceSettings = 0;
    for (const auto& [hash, bucket] : inheritance_) {
        (void)hash;
        inheritanceSettings += bucket.size();
    }
    v[DebugCounters::RuleInheritanceSettings] = inheritanceSettings;
    v[DebugCounters::RuleNameReferences] = idxRuleNames_.size();
    size_t interfaceCandidates = 0;
    for (const auto& group : interfaces_) interfaceCandidates += group.enabled;
    v[DebugCounters::RuleInterfaceCandidates] = interfaceCandidates;
}

size_t RuleStore::Count() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return rules_.size();
}

size_t RuleStore::GlobalCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    size_t n = 0;
    for (const Rule& r : rules_) if (r.isGlobal()) ++n;
    return n;
}

size_t RuleStore::PostAppCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    size_t n = 0;
    for (const Rule& r : rules_) if (r.isPostApp()) ++n;
    return n;
}

void RuleStore::Clear() {
    Changes changes;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (rules_.empty() && inheritance_.empty() && appInterfaces_.empty()) return;
        for (const Rule& x : rules_)
            changes.push_back(Change{ RuleChange::Removed, x });
        rules_.clear();
        LoadInheritanceLocked({});
        LoadAppInterfacesLocked({});
        SaveLocked();               // внутри — RebuildIndexLocked
    }
    Fire(changes);
}

bool RuleStore::MatchAddrs(const std::vector<AddrItem>& v, const IpAddr& a) {
    if (v.empty()) return true;
    for (const AddrItem& x : v) if (x.Matches(a)) return true;
    return false;
}

bool RuleStore::MatchPorts(const std::vector<PortItem>& v, uint16_t p) {
    if (v.empty()) return true;
    if (p == 0) return false;
    for (const PortItem& x : v) if (x.Contains(p)) return true;
    return false;
}

bool RuleStore::MatchIcmp(const std::vector<IcmpTypeItem>& v, int type, int code) {
    if (v.empty()) return true;
    for (const IcmpTypeItem& x : v) if (x.Matches(type, code)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Условие «сервис».
//
// Выполняется, когда ВСЕ сервисы, обслуживаемые процессом, перечислены
// в правиле. Смысл именно такой: один svchost.exe обслуживает несколько
// сервисов, и «разрешить сервису X» не должно оборачиваться разрешением
// всему содержимому этого процесса.
//
// Два краевых случая заданы здесь и больше нигде:
//   * процесс не обслуживает ни одного сервиса — условие НЕ выполняется;
//   * список правила пуст — «любой сервис»: правило подходит любому процессу,
//     обслуживающему хотя бы один сервис.
// ---------------------------------------------------------------------------
bool RuleStore::MatchServices(const std::vector<ServiceItem>& v,
                              const std::vector<ServiceEntry>& hosted) {
    if (hosted.empty()) return false;
    if (v.empty()) return true;

    for (const ServiceEntry& h : hosted) {
        bool listed = false;
        for (const ServiceItem& x : v) {
            if (x.Matches(h.name)) { listed = true; break; }
        }
        if (!listed) return false;       // сервис процесса в правиле не указан
    }
    return true;
}

// ---------------------------------------------------------------------------
// Проверка оставшихся условий кандидата.
//
// Протокол, направление и PID уже проверены по компактной записи Cand в FindLocked.
// Здесь порядок выбран по ЦЕНЕ: сначала порты, затем адреса и ICMP, и только
// в самом конце — сервисы. Несовпадение портов отсекает правило до обхода
// адресных списков и обращения к макро-адресам. Состав сервисов читается из
// опубликованной ServiceInfo runtime-карты, только когда всё остальное совпало.
//
// Условия набора уже нормализованы (NormalizeRuleConds), поэтому CondIcmpType
// встречается только у ICMP, а порты — только у протоколов с портами.
// ---------------------------------------------------------------------------
bool RuleStore::MatchRemainingConds(const Rule& r, const MatchQuery& q, Hosted& hosted) {
    if ((r.conds & CondWfpFlags) &&
        (q.source != TrafficSource::Host || !q.conditionFlags ||
         (*q.conditionFlags & r.conditionFlags) != r.conditionFlags)) return false;

    if ((r.conds & CondRemotePort) && !MatchPorts(r.remotePorts, q.remotePort)) return false;
    if ((r.conds & CondLocalPort)  && !MatchPorts(r.localPorts,  q.localPort))  return false;

    if ((r.conds & CondRemoteAddr) && !MatchAddrs(r.remoteAddrs, q.remoteAddr)) return false;
    if ((r.conds & CondLocalAddr)  && !MatchAddrs(r.localAddrs,  q.localAddr))  return false;

    if (r.conds & CondIcmpType) {
        // Неизвестный тип не совпадает с условием. Затем поиск продолжится
        // по остальным правилам; при полном промахе решение задаст политика.
        if (q.icmpType < 0) return false;
        if (!MatchIcmp(r.icmpTypes, q.icmpType, q.icmpCode)) return false;
    }

    if ((r.conds & CondService) && !MatchServices(r.services, hosted.Get())) return false;
    return true;
}

bool RuleStore::MatchesRule(const Rule& rule, const MatchQuery& q) {
    if (!rule.enabled) return false;
    if (rule.isInterface()) {
        if (q.interfaceName) {
            if (q.interfaceName->empty() || *q.interfaceName != rule.appPath) return false;
        } else {
            const auto number = net::SharedNetworkInterfaces().GetInterfaceNumberByName(rule.appPath);
            if (!number || !q.interfaceIndex) return false;
            bool matches = *number == q.interfaceIndex;
            if (!matches) {
                const auto name = net::SharedNetworkInterfaces().GetInterfaceName(q.interfaceIndex);
                matches = name && *name == rule.appPath;
            }
            if (!matches) return false;
        }
    } else if (q.source == TrafficSource::Ndis) return false;
    if (rule.scope == RuleScope::App && !EqualNoCase(rule.appPath, q.appPath))
        return false;

    return MatchesRuleConditions(rule, q);
}

bool RuleStore::MatchesRuleConditions(const Rule& rule, const MatchQuery& q) {
    if (!rule.enabled) return false;
    const uint32_t conds = EffectiveRuleConds(rule);
    if ((conds & CondPidZero) && q.pid != 0) return false;
    if ((conds & CondProto) && rule.proto != q.proto) return false;
    if ((conds & CondDirection) && q.dir != Dir::Unknown && rule.dir != q.dir)
        return false;
    if (conds & CondInterface) {
        const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
        if (!ResolveInterfaceFilter(rule.interfaceName, snapshot).Matches(q)) return false;
    }
    Hosted hosted{ q.pid, q.process };
    return MatchRemainingConds(rule, q, hosted);
}

std::span<const RuleStore::Cand>
RuleStore::FindAppLocked(const MatchQuery& q) const {
    if (idxApp_.empty() || q.appPath.empty()) return {};

    if (q.preparedAppPath) [[likely]] {
        const auto it = idxApp_.find(q.appPathHash);
        if (it == idxApp_.end()) return {};
        for (const AppBucket& b : it->second)
            if (b.foldedPath == q.foldedAppPath) return b.items;
        return {};
    }

    // Редкий совместимый путь для внешнего вызывающего, который передал только
    // исходную строку. Внутренние горячие маршруты всегда готовят ключ заранее.
    const std::wstring folded = FoldCaseCopy(q.appPath);
    const auto it = idxApp_.find(HashFoldedText(folded));
    if (it == idxApp_.end()) return {};
    for (const AppBucket& b : it->second)
        if (b.foldedPath == folded) return b.items;
    return {};
}

// ---------------------------------------------------------------------------
// Единственная точка поиска.
//
// Сначала проверяется интерфейс, затем для событий хоста Global, App и PostApp.
// У событий NDIS после группы интерфейса остаётся выбранная политика.
// Индексы сохраняют приоритет внутри группы: они строятся обходом
// уже упорядоченного rules_.
// ---------------------------------------------------------------------------
const Rule* RuleStore::FindLocked(const MatchQuery& q, Hosted& hosted) const {
    switch (PreferredInterfaceBlockedLocked(q)) {
    case AppInterfaceBlock::Unavailable: return &unavailableInterfaceRule_;
    case AppInterfaceBlock::OtherInterface: return &otherInterfaceRule_;
    case AppInterfaceBlock::None: break;
    }
    const uint8_t proto = ProtoNumber(q.proto);
    const uint8_t dir   = static_cast<uint8_t>(q.dir);
    const bool dirKnown = q.dir != Dir::Unknown;

    const auto scan = [&](std::span<const Cand> list, const MatchQuery& query,
                          Hosted& services) -> const Rule* {
        for (const Cand& c : list) {
            // Дешёвый отказ по компактной записи: большой объект Rule
            // не читается вовсе, пока не пройдены PID, протокол и направление.
            if ((c.conds & CondPidZero) && query.pid != 0) continue;
            if ((c.conds & CondProto) && c.proto != proto) continue;
            if ((c.conds & CondDirection) && dirKnown && c.dir != dir) continue;
            if (query.remotePort < c.remotePortFirst || query.remotePort > c.remotePortLast) continue;
            if ((c.conds & CondInterface) &&
                !interfaceFilters_[c.interfaceFilter - 1].Matches(query)) continue;

            const Rule& r = rules_[c.idx];
            if (!MatchRemainingConds(r, query, services)) continue;
            return &r;
        }
        return nullptr;
    };

    // Только pending использует сохранённое имя, в том числе для исчезнувшей
    // группы. Обычное событие делает один поиск по числовому индексу.
    if (q.interfaceName) {
        if (!q.interfaceName->empty()) {
            const auto group = std::find_if(interfaces_.begin(), interfaces_.end(), [&](const auto& item) {
                return item.name == *q.interfaceName;
            });
            if (group != interfaces_.end())
                if (const Rule* r = scan(group->items, q, hosted)) return r;
        }
    } else if (q.interfaceIndex) {
        const auto found = idxInterface_.find(q.interfaceIndex);
        if (found != idxInterface_.end())
            if (const Rule* r = scan(found->second, q, hosted)) return r;
    }
    if (q.source == TrafficSource::Ndis) return nullptr;

    // Порядок: Interface → Global → App → PostApp
    if (const Rule* r = scan(idxGlobal_, q, hosted)) return r;
    const auto knownPath = q.appPath.empty() && inheritanceUsed_.load(std::memory_order_relaxed)
        ? processes_.rulePath(q.pid, q.lineage) : nullptr;
    std::optional<MatchQuery> resolved;
    if (knownPath) {
        resolved = q;
        resolved->appPath = *knownPath->text;
        PrepareMatchAppPath(*resolved, knownPath->folded, knownPath->hash);
    }
    const MatchQuery& own = resolved ? *resolved : q;
    const auto inherited = InheritedSourceLocked(own);
    if (inherited) {
        MatchQuery parent = q;
        parent.appPath = *inherited.path->text;
        parent.pid = static_cast<DWORD>(inherited.pid);
        parent.process = nullptr;
        PrepareMatchAppPath(parent, inherited.path->folded, inherited.path->hash);
        Hosted services;
        services.pid = parent.pid;
        services.inheritedPath = parent.appPath;
        if (const Rule* r = scan(FindAppLocked(parent), parent, services)) return r;
        // Собственные правила потомка не являются запасным вариантом.
    } else if (!own.appPath.empty()) {
        if (const Rule* r = scan(FindAppLocked(own), own, hosted)) return r;
    }
    // Global и PostApp сохраняют исходного владельца и обычный приоритет.
    return scan(idxPostApp_, q, hosted);
}

bool RuleStore::Match(const MatchQuery& q, Rule& out) const {
    std::lock_guard<std::mutex> lk(mtx_);
    SyncInterfacesLocked();
    if (inheritanceUsed_.load(std::memory_order_relaxed)) SyncProcessVersionLocked();
    Hosted hosted;
    hosted.pid = q.pid;
    hosted.process = q.process;
    const Rule* r = FindLocked(q, hosted);
    if (!r) return false;
    out = *r;                       // копия нужна вызывающему (имя, область)
    return true;
}

bool RuleStore::MatchInfo(const MatchQuery& q, RuleMatchInfo& out,
                          bool includeName) const {
    std::lock_guard<std::mutex> lk(mtx_);
    SyncInterfacesLocked();
    if (inheritanceUsed_.load(std::memory_order_relaxed)) SyncProcessVersionLocked();
    Hosted hosted;
    hosted.pid = q.pid;
    hosted.process = q.process;
    const Rule* r = FindLocked(q, hosted);
    if (!r) return false;
    out.id = r->id;
    if (includeName) out.name = r->name;
    else             out.name.clear();
    out.scope = r->scope;
    out.action = r->action;
    return true;
}
bool RuleStore::MatchVerdict(const MatchQuery& q, RuleAction& action,
                             RuleNameRef* matchedRuleName) const {
    uint64_t matchedVersion = 0;
    return MatchVerdict(q, action, matchedVersion, matchedRuleName);
}

bool RuleStore::MatchVerdict(const MatchQuery& q, RuleAction& action,
                             uint64_t& matchedVersion,
                             RuleNameRef* matchedRuleName,
                             std::shared_ptr<const std::wstring>* unmatchedInterfaceName,
                             bool* preferredInterfaceBlocked) const {
    std::lock_guard<std::mutex> lk(mtx_);
    SyncInterfacesLocked();
    if (inheritanceUsed_.load(std::memory_order_relaxed)) SyncProcessVersionLocked();
    matchedVersion = version_.load(std::memory_order_relaxed);
    Hosted hosted;
    hosted.pid = q.pid;
    hosted.process = q.process;
    const Rule* r = FindLocked(q, hosted);
    if (preferredInterfaceBlocked)
        *preferredInterfaceBlocked = r == &unavailableInterfaceRule_ || r == &otherInterfaceRule_;
    if (!r) {
        // Имя фиксируется вместе с промахом, до освобождения mtx_. Иначе между
        // matcher и парковкой Windows могла бы передать индекс другому адаптеру.
        if (unmatchedInterfaceName && !*unmatchedInterfaceName) {
            const std::wstring* name = q.interfaceName;
            if (!name && q.interfaceIndex) {
                const auto group = std::find_if(interfaces_.begin(), interfaces_.end(), [&](const auto& item) {
                    return item.index && (item.index == q.interfaceIndex || item.ipv6Index == q.interfaceIndex);
                });
                if (group != interfaces_.end()) name = &group->name;
            }
            *unmatchedInterfaceName = std::make_shared<const std::wstring>(name ? *name : std::wstring());
        }
        return false;
    }
    action = r->action;             // действие читается без копирования Rule
    if (matchedRuleName)
        *matchedRuleName = r == &unavailableInterfaceRule_ ? unavailableInterfaceRuleName_ :
            r == &otherInterfaceRule_ ? otherInterfaceRuleName_ :
            idxRuleNames_[static_cast<size_t>(r - rules_.data())];
    return true;
}

namespace RuleClipboard {

void Set(const Rule& r) {
    std::lock_guard<std::mutex> lk(g_clipMtx);
    g_clip = r;
    g_clip.id = 0;
    g_clip.priority = 0;
    g_clipValid = true;
}

bool Get(Rule& out) {
    std::lock_guard<std::mutex> lk(g_clipMtx);
    if (!g_clipValid) return false;
    out = g_clip;
    return true;
}

bool Has() {
    std::lock_guard<std::mutex> lk(g_clipMtx);
    return g_clipValid;
}

} // namespace RuleClipboard