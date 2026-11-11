#include "Common.h"
#include "NumberText.h"
#include "StringRes.h"
#include "TlsReassembly.h"
#include "resource.h"

#include <commctrl.h>
#include <shlwapi.h>
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <iterator>

std::wstring FormatNumber(uint64_t value) {
    // uint64_t: \u043C\u0430\u043A\u0441\u0438\u043C\u0443\u043C 20 \u0446\u0438\u0444\u0440 \u0438 6 \u043D\u0435\u0440\u0430\u0437\u0440\u044B\u0432\u043D\u044B\u0445 \u043F\u0440\u043E\u0431\u0435\u043B\u043E\u0432. \u0417\u0430\u043F\u043E\u043B\u043D\u0435\u043D\u0438\u0435 \u0441 \u043A\u043E\u043D\u0446\u0430
    // \u0441\u043E\u0437\u0434\u0430\u0451\u0442 \u0438\u0442\u043E\u0433\u043E\u0432\u0443\u044E \u0441\u0442\u0440\u043E\u043A\u0443 \u043E\u0434\u043D\u0438\u043C \u0432\u044B\u0434\u0435\u043B\u0435\u043D\u0438\u0435\u043C \u0432\u043C\u0435\u0441\u0442\u043E \u0442\u0440\u0451\u0445 \u0432\u0440\u0435\u043C\u0435\u043D\u043D\u044B\u0445 \u0441\u0442\u0440\u043E\u043A.
    wchar_t buffer[32];
    return std::wstring(FormatNumberView(value, buffer));
}

std::wstring FormatBytes(uint64_t v) {
    if (v < 1024ull)
        return LoadStringResFmt(IDS_FMT_BYTES,
                                static_cast<unsigned long long>(v));
    const double d = static_cast<double>(v);
    if (v < 1024ull * 1024)        return LoadStringResFmt(IDS_FMT_KIB, d / 1024.0);
    if (v < 1024ull * 1024 * 1024) return LoadStringResFmt(IDS_FMT_MIB, d / 1048576.0);
    return LoadStringResFmt(IDS_FMT_GIB, d / 1073741824.0);
}

std::wstring FormatSpeed(double bps) {
    if (bps < 0) bps = 0;
    if (bps < 1024.0)                   return LoadStringResFmt(IDS_FMT_BPS, bps);
    if (bps < 1024.0 * 1024.0)          return LoadStringResFmt(IDS_FMT_KBPS, bps / 1024.0);
    if (bps < 1024.0 * 1024.0 * 1024.0) return LoadStringResFmt(IDS_FMT_MBPS, bps / 1048576.0);
    return LoadStringResFmt(IDS_FMT_GBPS, bps / 1073741824.0);
}

std::wstring IpToPlainString(const IpAddr& a) {
    wchar_t buf[64]{};
    if (!InetNtopW(a.family, const_cast<uint8_t*>(a.b), buf, 64)) return L"?";
    return buf;
}


const wchar_t* DirToString(Dir d) {
    switch (d) {
        case Dir::In:  return L"IN";
        case Dir::Out: return L"OUT";
        default:       return L"";
    }
}

// ------------------------------------------------------- справочник протоколов
//
// Номера и назначение по реестру IANA «Protocol Numbers». Таблица служит
// только для показа и для разбора ввода: правило можно создать для любого
// номера 0..255, даже если его здесь нет — тогда он отображается числом.

namespace {

// Таблица известных протоколов IP. У части поле `name` англоязычное из реестра
// IANA; для них descId == 0, и описание показывается как есть. У остальных
// descId ссылается на STRINGTABLE — там либо русское пояснение, либо корректный
// английский вместо отсутствующего в IANA.
const KnownProto kProtos[] = {
    {   0, L"HOPOPT",     L"IPv6 Hop-by-Hop Option",                 0 },
    {   1, L"ICMP",       L"Internet Control Message Protocol",      0 },
    {   2, L"IGMP",       L"Internet Group Management Protocol",     0 },
    {   3, L"GGP",        L"Gateway-to-Gateway Protocol",            0 },
    {   4, L"IPv4",       nullptr,                       IDS_PROTO_IPIP },
    {   5, L"ST",         L"Stream Protocol",                        0 },
    {   6, L"TCP",        L"Transmission Control Protocol",          0 },
    {   7, L"CBT",        L"Core Based Trees",                       0 },
    {   8, L"EGP",        L"Exterior Gateway Protocol",              0 },
    {   9, L"IGP",        nullptr,                        IDS_PROTO_IRP },
    {  12, L"PUP",        L"PARC Universal Packet",                  0 },
    {  17, L"UDP",        L"User Datagram Protocol",                 0 },
    {  20, L"HMP",        L"Host Monitoring Protocol",               0 },
    {  22, L"XNS-IDP",    L"Xerox NS IDP",                           0 },
    {  27, L"RDP",        L"Reliable Data Protocol",                 0 },
    {  29, L"ISO-TP4",    L"ISO Transport Protocol Class 4",         0 },
    {  33, L"DCCP",       L"Datagram Congestion Control Protocol",   0 },
    {  41, L"IPv6",       nullptr,                      IDS_PROTO_6IN4 },
    {  43, L"IPv6-Route", L"IPv6 Routing Header",                    0 },
    {  44, L"IPv6-Frag",  L"IPv6 Fragment Header",                   0 },
    {  46, L"RSVP",       L"Resource Reservation Protocol",          0 },
    {  47, L"GRE",        L"Generic Routing Encapsulation",          0 },
    {  50, L"ESP",        L"IPsec Encapsulating Security Payload",   0 },
    {  51, L"AH",         L"IPsec Authentication Header",            0 },
    {  58, L"ICMPv6",     nullptr,                    IDS_PROTO_ICMPV6 },
    {  59, L"IPv6-NoNxt", L"IPv6 No Next Header",                    0 },
    {  60, L"IPv6-Opts",  L"IPv6 Destination Options",               0 },
    {  88, L"EIGRP",      L"Enhanced Interior Gateway Routing Protocol", 0 },
    {  89, L"OSPF",       L"Open Shortest Path First",               0 },
    {  94, L"IPIP",       L"IP-in-IP encapsulation",                 0 },
    {  97, L"ETHERIP",    L"Ethernet-within-IP",                     0 },
    {  98, L"ENCAP",      L"Encapsulation Header",                   0 },
    { 103, L"PIM",        L"Protocol Independent Multicast",         0 },
    { 108, L"IPComp",     L"IP Payload Compression Protocol",        0 },
    { 112, L"VRRP",       L"Virtual Router Redundancy Protocol",     0 },
    { 113, L"PGM",        L"Pragmatic General Multicast",            0 },
    { 115, L"L2TP",       L"Layer Two Tunneling Protocol v3",        0 },
    { 124, L"ISIS",       nullptr,                       IDS_PROTO_ISIS },
    { 132, L"SCTP",       L"Stream Control Transmission Protocol",   0 },
    { 133, L"FC",         L"Fibre Channel",                          0 },
    { 135, L"MH",         L"Mobility Header (Mobile IPv6)",          0 },
    { 136, L"UDPLite",    L"Lightweight User Datagram Protocol",     0 },
    { 137, L"MPLS-in-IP", nullptr,                       IDS_PROTO_MPLS },
    { 139, L"HIP",        L"Host Identity Protocol",                 0 },
    { 140, L"Shim6",      L"Shim6 Protocol",                         0 },
    { 141, L"WESP",       L"Wrapped Encapsulating Security Payload", 0 },
    { 142, L"ROHC",       L"Robust Header Compression",              0 },
    { 143, L"Ethernet",   nullptr,                    IDS_PROTO_ETHERIP },
    { 144, L"AGGFRAG",    nullptr,                    IDS_PROTO_AGGFRAG },
    { 145, L"NSH",        L"Network Service Header",                 0 },
    { 253, L"EXP1",       nullptr,               IDS_PROTO_EXPERIMENTAL },
    { 254, L"EXP2",       nullptr,               IDS_PROTO_EXPERIMENTAL },
    { 255, L"Reserved",   nullptr,                  IDS_PROTO_RESERVED },
};

// Типы ICMP, которые петлевая эвристика относит к входящим: ответы, ошибки
// и выбранные объявления/отчёты, в том числе незапрошенные. Остальные типы
// считаются исходящими только для выбора направления при совпавших src/dst.
const uint8_t kIcmp4Replies[] = {
     0,   // Echo Reply
     3,   // Destination Unreachable
     4,   // Source Quench
     5,   // Redirect
     9,   // Router Advertisement
    11,   // Time Exceeded
    12,   // Parameter Problem
    14,   // Timestamp Reply
    16,   // Information Reply
    18,   // Address Mask Reply
    43,   // Extended Echo Reply
};

const uint8_t kIcmp6Replies[] = {
      1,  // Destination Unreachable
      2,  // Packet Too Big
      3,  // Time Exceeded
      4,  // Parameter Problem
    129,  // Echo Reply
    131,  // Multicast Listener Report
    134,  // Router Advertisement
    136,  // Neighbor Advertisement
    137,  // Redirect
    142,  // Inverse Neighbor Discovery Advertisement
    143,  // Multicast Listener Report v2
    145,  // Home Agent Address Discovery Reply
    147,  // Mobile Prefix Advertisement
    149,  // Certification Path Advertisement
    158,  // Duplicate Address Confirmation
    161,  // Extended Echo Reply
};

uint16_t Be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

// Заголовки-расширения IPv6, которые стоят между фиксированным заголовком
// и транспортным. ESP (50) и No Next Header (59) сюда не входят: за ними
// транспортного заголовка в открытом виде уже нет.
bool Ipv6IsExt(uint8_t nh) {
    switch (nh) {
    case 0:      // Hop-by-Hop Options
    case 43:     // Routing
    case 44:     // Fragment
    case 51:     // Authentication Header
    case 60:     // Destination Options
    case 135:    // Mobility
    case 139:    // HIP
    case 140:    // Shim6
        return true;
    default:
        return false;
    }
}

// Длина заголовка-расширения. Единицы измерения у AH и Fragment свои.
size_t Ipv6ExtLen(uint8_t nh, const uint8_t* p) {
    switch (nh) {
    case 44: return 8;                                    // фиксированные 8 байт
    case 51: return (static_cast<size_t>(p[1]) + 2) * 4;   // единицы по 4 байта
    default: return (static_cast<size_t>(p[1]) + 1) * 8;   // единицы по 8 байт
    }
}

} // namespace

const KnownProto* KnownProtos(size_t& count) {
    count = std::size(kProtos);
    return kProtos;
}

const wchar_t* ProtoAlias(uint8_t num) {
    for (const KnownProto& p : kProtos) if (p.num == num) return p.alias;
    return nullptr;
}

std::wstring ProtoDesc(uint8_t num) {
    for (const KnownProto& p : kProtos) {
        if (p.num != num) continue;
        return p.descId ? LoadStringRes(p.descId) : std::wstring(p.name);
    }
    return {};
}

std::wstring ProtoToString(Proto p) {
    const uint8_t n = ProtoNumber(p);
    if (const wchar_t* a = ProtoAlias(n)) return a;
    return std::to_wstring(n);
}

std::wstring ProtoLabel(Proto p) {
    const uint8_t n = ProtoNumber(p);
    if (const wchar_t* a = ProtoAlias(n))
        return std::wstring(a) + L" (" + std::to_wstring(n) + L")";
    return std::to_wstring(n);
}

bool ParseProtoToken(const std::wstring& s, uint8_t& out) {
    size_t a = 0, b = s.size();
    while (a < b && iswspace(s[a])) ++a;
    while (b > a && iswspace(s[b - 1])) --b;
    if (a >= b) return false;
    const std::wstring t = s.substr(a, b - a);

    bool digits = true;
    for (wchar_t c : t) if (!iswdigit(c)) { digits = false; break; }
    if (digits) {
        // iswdigit допускает и надстрочные цифры: требуем разбор всего токена.
        wchar_t* end = nullptr;
        const long v = std::wcstol(t.c_str(), &end, 10);
        if (end != t.c_str() + t.size() || v < 0 || v > 255) return false;
        out = static_cast<uint8_t>(v);
        return true;
    }
    for (const KnownProto& p : kProtos)
        if (_wcsicmp(t.c_str(), p.alias) == 0) { out = p.num; return true; }
    return false;
}

bool IcmpIsReply(int type, bool v6) {
    if (type < 0 || type > 255) return false;
    const uint8_t t = static_cast<uint8_t>(type);
    if (v6) {
        for (uint8_t x : kIcmp6Replies) if (x == t) return true;
        return false;
    }
    for (uint8_t x : kIcmp4Replies) if (x == t) return true;
    return false;
}

bool IsElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{}; DWORD cb = sizeof(el);
    const BOOL ok = GetTokenInformation(tok, TokenElevation, &el, cb, &cb);
    CloseHandle(tok);
    return ok && el.TokenIsElevated;
}

bool EnableDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    bool ok = false;
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(ERROR_SUCCESS);
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

bool ParseIpAddr(const std::wstring& s, IpAddr& out) {
    IN_ADDR v4{};
    if (InetPtonW(AF_INET, s.c_str(), &v4) == 1) { out = IpAddr::V4(v4.S_un.S_addr); return true; }
    IN6_ADDR v6{};
    if (InetPtonW(AF_INET6, s.c_str(), &v6) == 1) { out = IpAddr::V6(&v6); return true; }
    return false;
}

bool MaskToPrefix(const IpAddr& mask, int& prefix) {
    prefix = 0;
    bool zeros = false;
    for (size_t i = 0; i < mask.len(); ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            const bool one = (mask.b[i] >> bit) & 1;
            if (one) {
                if (zeros) return false;      // немонотонная маска
                ++prefix;
            } else {
                zeros = true;
            }
        }
    }
    return true;
}

IpAddr PrefixToMask(uint16_t family, int prefix) {
    IpAddr m;
    m.family = family;
    const int total = static_cast<int>(m.len()) * 8;
    if (prefix < 0) prefix = 0;
    if (prefix > total) prefix = total;
    for (int i = 0; i < prefix; ++i)
        m.b[i / 8] = static_cast<uint8_t>(m.b[i / 8] | (1u << (7 - (i % 8))));
    return m;
}

void ApplyPrefix(IpAddr& addr, int prefix, bool fillOnes) {
    const int total = static_cast<int>(addr.len()) * 8;
    if (prefix < 0) prefix = 0;
    if (prefix > total) prefix = total;
    for (int i = prefix; i < total; ++i) {
        const int byte = i / 8, bit = 7 - (i % 8);
        if (fillOnes) addr.b[byte] = static_cast<uint8_t>(addr.b[byte] |  (1u << bit));
        else          addr.b[byte] = static_cast<uint8_t>(addr.b[byte] & ~(1u << bit));
    }
}

std::wstring PathBaseUpper(const std::wstring& path) {
    if (path.empty()) return L"";
    return FoldCaseCopy(PathFindFileNameW(path.c_str()));
}

// ------------------------------------------------------- разбор IP-пакета

// payload события транспорта — стандартный IP-пакет.
//
// IPv4: версия и IHL в первом байте, полная длина в байтах 2–3, адреса
//       в байтах 12–15 и 16–19, номер протокола в байте 9, транспортный
//       заголовок начинается с IHL*4.
// IPv6: фиксированный заголовок 40 байт, длина полезной нагрузки в байтах 4–5,
//       next header в байте 6, адреса в байтах 8–23 и 24–39; далее проходим
//       цепочку extension headers.
//
// У обычного пакета размер берётся из поля длины, а не из len: транспорт может
// отдать усечённые данные (например, «4500003c…» задаёт 60 байт: 20 IP + 8 ICMP
// + 32 данных). При нулевом IPv6 Payload Length используется len, без разбора
// опции Jumbo Payload.
bool ParseIpPacket(const uint8_t* pkt, size_t len, IpPacketInfo& out) {
    out = IpPacketInfo{};
    if (!pkt || !len) return false;

    const uint8_t ver = static_cast<uint8_t>(pkt[0] >> 4);

    if (ver == 4) {
        if (len < 20) return false;
        const size_t ihl = static_cast<size_t>(pkt[0] & 0x0F) * 4u;
        if (ihl < 20 || ihl > len) return false;

        const size_t total = Be16(pkt + 2);
        // Полная длина не может быть меньше заголовка. Отбрасываем как
        // повреждённый IPv4, так и данные, случайно начинающиеся с версии 4.
        if (total < ihl) return false;

        out.version      = 4;
        out.proto        = pkt[9];
        out.headerBytes  = ihl;
        out.totalBytes   = total;
        out.payloadBytes = total - ihl;
        out.truncated    = total > len;
        // Смещение фрагмента: у продолжений транспортного заголовка нет.
        out.fragment     = (Be16(pkt + 6) & 0x1FFF) != 0;
        out.src          = IpAddr::Raw4(pkt + 12);
        out.dst          = IpAddr::Raw4(pkt + 16);
        out.hasAddrs     = true;

        if (!out.fragment && out.proto == DriverProto::kIcmp && ihl + 2 <= len) {
            out.icmp.type = pkt[ihl];
            out.icmp.code = pkt[ihl + 1];
            out.icmp.v6   = false;
        }
        return true;
    }

    if (ver == 6) {
        if (len < 40) return false;
        const size_t payloadLen = Be16(pkt + 4);

        out.version    = 6;
        // Нулевое поле бывает у jumbogram и пакета без полезной нагрузки.
        // Jumbo Payload option здесь не разбирается: берём доступную длину.
        out.totalBytes = payloadLen ? 40 + payloadLen : len;
        out.truncated  = out.totalBytes > len;
        out.src        = IpAddr::Raw6(pkt + 8);
        out.dst        = IpAddr::Raw6(pkt + 24);
        out.hasAddrs   = true;

        uint8_t nh  = pkt[6];
        size_t  off = 40;
        for (int hop = 0; hop < 8 && Ipv6IsExt(nh); ++hop) {
            if (off + 2 > len) { out.truncated = true; break; }
            if (nh == 44 && off + 4 <= len && (Be16(pkt + off + 2) >> 3) != 0)
                out.fragment = true;

            const uint8_t inner = pkt[off];
            const size_t  step  = Ipv6ExtLen(nh, pkt + off);
            if (!step || off + step > len) { out.truncated = true; break; }
            off += step;
            nh = inner;
        }
        out.proto        = nh;      // при обрыве цепочки — последний известный
        out.headerBytes  = off;
        out.payloadBytes = out.totalBytes > off ? out.totalBytes - off : 0;

        if (!out.fragment && out.proto == DriverProto::kIcmpV6 && off + 2 <= len) {
            out.icmp.type = pkt[off];
            out.icmp.code = pkt[off + 1];
            out.icmp.v6   = true;
        }
        return true;
    }
    return false;      // не IP-пакет
}

bool ParseIcmpFromIpPacket(const uint8_t* pkt, size_t len, IcmpInfo& out) {
    out = IcmpInfo{};
    IpPacketInfo info;
    if (!ParseIpPacket(pkt, len, info)) return false;
    if (!info.icmp.known()) return false;
    out = info.icmp;
    return true;
}

namespace {

struct TlsCursor {
    const uint8_t* data = nullptr;
    size_t left = 0;

    bool Take(size_t count, const uint8_t*& value) {
        if (count > left) return false;
        value = data;
        data += count;
        left -= count;
        return true;
    }

    bool Skip(size_t count) {
        const uint8_t* ignored = nullptr;
        return Take(count, ignored);
    }

    bool Read8(uint8_t& value) {
        const uint8_t* bytes = nullptr;
        if (!Take(1, bytes)) return false;
        value = bytes[0];
        return true;
    }

    bool Read16(size_t& value) {
        const uint8_t* bytes = nullptr;
        if (!Take(2, bytes)) return false;
        value = Be16(bytes);
        return true;
    }
};

size_t TlsBe24(const uint8_t* data) {
    return (static_cast<size_t>(data[0]) << 16) |
           (static_cast<size_t>(data[1]) << 8) |
            static_cast<size_t>(data[2]);
}

// server_name — список типизированных имён, а не одна строка. Неизвестные
// типы пропускаются; берётся запись host_name (тип 0), где и лежит SNI.
bool ParseTlsServerName(const uint8_t* data, size_t size,
                        std::string& domain) {
    TlsCursor extension{ data, size };
    size_t listSize = 0;
    if (!extension.Read16(listSize) || listSize == 0 ||
        listSize != extension.left)
        return false;

    TlsCursor names{ extension.data, listSize };
    bool hostNameSeen = false;
    while (names.left) {
        uint8_t type = 0;
        size_t nameSize = 0;
        const uint8_t* name = nullptr;
        if (!names.Read8(type) || !names.Read16(nameSize) || nameSize == 0 ||
            !names.Take(nameSize, name))
            return false;

        if (type != 0) continue;
        // RFC 6066 запрещает две записи одного типа и нулевые байты в DNS-имени.
        if (hostNameSeen || std::memchr(name, 0, nameSize) != nullptr)
            return false;
        domain.assign(reinterpret_cast<const char*>(name), nameSize);
        hostNameSeen = true;
    }
    return true;
}

bool ParseTlsExtensions(TlsCursor& hello, std::string& domain) {
    domain.clear();
    // В SSL 3.0 и раннем TLS блок extensions мог отсутствовать целиком.
    if (hello.left == 0) return true;

    size_t extensionsSize = 0;
    if (!hello.Read16(extensionsSize) || extensionsSize != hello.left)
        return false;

    TlsCursor extensions{ hello.data, extensionsSize };
    bool serverNameSeen = false;
    while (extensions.left) {
        size_t type = 0;
        size_t size = 0;
        const uint8_t* value = nullptr;
        if (!extensions.Read16(type) || !extensions.Read16(size) ||
            !extensions.Take(size, value))
            return false;

        if (type != 0) continue;
        // Одинаковые extensions в одном ClientHello запрещены.
        if (serverNameSeen || !ParseTlsServerName(value, size, domain))
            return false;
        // SNI обычно стоит среди первых extensions. После получения host_name
        // остальная часть ClientHello для результата функции уже не нужна.
        if (!domain.empty()) return true;
        serverNameSeen = true;
    }
    return true;
}

// Формат тела одинаков у ClientHello SSL 3.0, TLS 1.0–1.2 и совместимого
// ClientHello TLS 1.3. Реальную версию TLS 1.3 задаёт supported_versions,
// поэтому разбирать отдельный «тип TLS 1.3» здесь не требуется.
bool ParseTlsClientHelloBody(const uint8_t* data, size_t size,
                             std::string& domain) {
    TlsCursor hello{ data, size };
    const uint8_t* legacyVersion = nullptr;
    if (!hello.Take(2, legacyVersion) || legacyVersion[0] != 3 ||
        !hello.Skip(32))
        return false;

    uint8_t sessionIdSize = 0;
    if (!hello.Read8(sessionIdSize) || sessionIdSize > 32 ||
        !hello.Skip(sessionIdSize))
        return false;

    size_t cipherSuitesSize = 0;
    if (!hello.Read16(cipherSuitesSize) || cipherSuitesSize < 2 ||
        (cipherSuitesSize & 1) != 0 || !hello.Skip(cipherSuitesSize))
        return false;

    uint8_t compressionMethodsSize = 0;
    if (!hello.Read8(compressionMethodsSize) ||
        compressionMethodsSize == 0 || !hello.Skip(compressionMethodsSize))
        return false;

    return ParseTlsExtensions(hello, domain);
}

bool ParseTlsHandshake(const uint8_t* data, size_t size,
                       std::string& domain) {
    if (size < 4 || data[0] != 1) return false;
    const size_t bodySize = TlsBe24(data + 1);
    if (bodySize > kMaxTlsClientHelloBytes || bodySize > size - 4)
        return false;
    return ParseTlsClientHelloBody(data + 4, bodySize, domain);
}

// Источник последовательно читает содержимое Handshake records как один поток,
// не собирая их во временный буфер. Поэтому даже редкий фрагментированный
// ClientHello не создаёт дополнительных выделений памяти.
class TlsRecordReader {
public:
    TlsRecordReader(const uint8_t* data, size_t size)
        : records_(data), recordsLeft_(size) {}

    bool Read8(uint8_t& value) {
        if (!EnsureFragment()) return false;
        value = *fragment_++;
        --fragmentLeft_;
        return true;
    }

    bool Read16(size_t& value) {
        if (!EnsureFragment()) return false;
        if (fragmentLeft_ >= 2) {
            value = Be16(fragment_);
            fragment_ += 2;
            fragmentLeft_ -= 2;
            return true;
        }

        uint8_t high = 0;
        uint8_t low = 0;
        if (!Read8(high) || !Read8(low)) return false;
        value = (static_cast<size_t>(high) << 8) | low;
        return true;
    }

    bool Skip(size_t count) {
        while (count) {
            if (!EnsureFragment()) return false;
            const size_t part = std::min(count, fragmentLeft_);
            fragment_ += part;
            fragmentLeft_ -= part;
            count -= part;
        }
        return true;
    }

    bool ReadDomain(size_t count, std::string& domain) {
        domain.clear();
        if (!EnsureFragment()) return false;

        if (count <= fragmentLeft_) {
            if (std::memchr(fragment_, 0, count) != nullptr) return false;
            domain.assign(reinterpret_cast<const char*>(fragment_), count);
            fragment_ += count;
            fragmentLeft_ -= count;
            return true;
        }

        domain.reserve(count);
        while (count) {
            if (!EnsureFragment()) return false;
            const size_t part = std::min(count, fragmentLeft_);
            if (std::memchr(fragment_, 0, part) != nullptr) return false;
            domain.append(reinterpret_cast<const char*>(fragment_), part);
            fragment_ += part;
            fragmentLeft_ -= part;
            count -= part;
        }
        return true;
    }

private:
    bool EnsureFragment() {
        while (fragmentLeft_ == 0) {
            if (recordsLeft_ < 5 || records_[0] != 22 || records_[1] != 3)
                return false;
            const size_t size = Be16(records_ + 3);
            if (size > recordsLeft_ - 5) return false;

            fragment_ = records_ + 5;
            fragmentLeft_ = size;
            records_ += 5 + size;
            recordsLeft_ -= 5 + size;
        }
        return true;
    }

    const uint8_t* records_ = nullptr;
    size_t recordsLeft_ = 0;
    const uint8_t* fragment_ = nullptr;
    size_t fragmentLeft_ = 0;
};

// Ограничение не даёт длине вложенного вектора выйти за границы ClientHello,
// даже когда сам TLS record продолжается следующим handshake-сообщением.
struct TlsRecordCursor {
    TlsRecordReader* reader = nullptr;
    size_t left = 0;

    bool Read8(uint8_t& value) {
        if (left < 1 || !reader->Read8(value)) return false;
        --left;
        return true;
    }

    bool Read16(size_t& value) {
        if (left < 2 || !reader->Read16(value)) return false;
        left -= 2;
        return true;
    }

    bool Skip(size_t count) {
        if (count > left || !reader->Skip(count)) return false;
        left -= count;
        return true;
    }

    bool ReadDomain(size_t count, std::string& domain) {
        if (count > left || !reader->ReadDomain(count, domain)) return false;
        left -= count;
        return true;
    }

    bool Subcursor(size_t count, TlsRecordCursor& subcursor) {
        if (count > left) return false;
        left -= count;
        subcursor = TlsRecordCursor{ reader, count };
        return true;
    }
};

bool ParseFragmentedTlsServerName(TlsRecordCursor extension,
                                  std::string& domain) {
    size_t listSize = 0;
    if (!extension.Read16(listSize) || listSize == 0 ||
        listSize != extension.left)
        return false;

    bool hostNameSeen = false;
    while (extension.left) {
        uint8_t type = 0;
        size_t nameSize = 0;
        if (!extension.Read8(type) || !extension.Read16(nameSize) ||
            nameSize == 0 || nameSize > extension.left)
            return false;

        if (type != 0) {
            if (!extension.Skip(nameSize)) return false;
            continue;
        }
        if (hostNameSeen || !extension.ReadDomain(nameSize, domain))
            return false;
        hostNameSeen = true;
    }
    return true;
}

bool ParseFragmentedTlsExtensions(TlsRecordCursor& hello,
                                  std::string& domain) {
    domain.clear();
    if (hello.left == 0) return true;

    size_t extensionsSize = 0;
    if (!hello.Read16(extensionsSize) || extensionsSize != hello.left)
        return false;

    bool serverNameSeen = false;
    while (hello.left) {
        size_t type = 0;
        size_t size = 0;
        if (!hello.Read16(type) || !hello.Read16(size) || size > hello.left)
            return false;

        if (type != 0) {
            if (!hello.Skip(size)) return false;
            continue;
        }

        TlsRecordCursor extension;
        if (serverNameSeen || !hello.Subcursor(size, extension) ||
            !ParseFragmentedTlsServerName(extension, domain))
            return false;
        if (!domain.empty()) return true;
        serverNameSeen = true;
    }
    return true;
}

bool ParseFragmentedTlsClientHelloBody(TlsRecordReader& reader, size_t size,
                                       std::string& domain) {
    TlsRecordCursor hello{ &reader, size };
    uint8_t majorVersion = 0;
    if (!hello.Read8(majorVersion) || majorVersion != 3 || !hello.Skip(1) ||
        !hello.Skip(32))
        return false;

    uint8_t sessionIdSize = 0;
    if (!hello.Read8(sessionIdSize) || sessionIdSize > 32 ||
        !hello.Skip(sessionIdSize))
        return false;

    size_t cipherSuitesSize = 0;
    if (!hello.Read16(cipherSuitesSize) || cipherSuitesSize < 2 ||
        (cipherSuitesSize & 1) != 0 || !hello.Skip(cipherSuitesSize))
        return false;

    uint8_t compressionMethodsSize = 0;
    if (!hello.Read8(compressionMethodsSize) ||
        compressionMethodsSize == 0 || !hello.Skip(compressionMethodsSize))
        return false;

    return ParseFragmentedTlsExtensions(hello, domain);
}

// Handshake может пересекать границы TLS records, включая границу внутри его
// четырёхбайтового заголовка. Обычный случай разбирается прямо в первом record;
// для фрагментированного используется последовательный reader без копирования.
bool ParseTlsRecords(const uint8_t* data, size_t size,
                     std::string& domain) {
    if (size < 5 || data[0] != 22 || data[1] != 3) return false;
    const size_t recordSize = Be16(data + 3);
    if (recordSize > size - 5) return false;

    if (recordSize >= 4) {
        const uint8_t* const handshake = data + 5;
        if (handshake[0] != 1) return false;
        const size_t bodySize = TlsBe24(handshake + 1);
        if (bodySize > kMaxTlsClientHelloBytes) return false;
        if (bodySize <= recordSize - 4)
            return ParseTlsClientHelloBody(handshake + 4, bodySize, domain);
    }

    TlsRecordReader reader(data, size);
    uint8_t type = 0;
    uint8_t lengthHigh = 0;
    size_t lengthLow = 0;
    if (!reader.Read8(type) || type != 1 || !reader.Read8(lengthHigh) ||
        !reader.Read16(lengthLow))
        return false;

    const size_t bodySize = (static_cast<size_t>(lengthHigh) << 16) | lengthLow;
    if (bodySize > kMaxTlsClientHelloBytes) return false;
    return ParseFragmentedTlsClientHelloBody(reader, bodySize, domain);
}

// Принимаются все формы, которые может передать вызывающий: TLS records,
// Handshake ClientHello без record header и непосредственно тело ClientHello.
bool ParseTlsAt(const uint8_t* data, size_t size, std::string& domain) {
    if (!data || size == 0) return false;
    if (data[0] == 22)
        return ParseTlsRecords(data, size, domain);
    if (data[0] == 1)
        return ParseTlsHandshake(data, size, domain);
    if (data[0] == 3)
        return ParseTlsClientHelloBody(data, size, domain);
    return false;
}

bool ParseTlsFromTcp(const uint8_t* data, size_t capturedSize,
                     size_t declaredSize, std::string& domain) {
    constexpr size_t kTcpMinHeaderBytes = 20;
    if (!data || capturedSize < kTcpMinHeaderBytes ||
        declaredSize < kTcpMinHeaderBytes)
        return false;

    const size_t headerSize = static_cast<size_t>(data[12] >> 4) * 4u;
    if (headerSize < kTcpMinHeaderBytes || headerSize > capturedSize ||
        headerSize > declaredSize)
        return false;

    const size_t applicationSize = std::min(
        capturedSize - headerSize, declaredSize - headerSize);
    return ParseTlsAt(data + headerSize, applicationSize, domain);
}

} // namespace

std::string GetTlsClientHelloDomain(const uint8_t* payload,
                                    size_t payload_len) {
    if (!payload || payload_len == 0) return {};

    std::string domain;

    // Удобно также принимать уже отделённые TLS/Handshake-данные.
    if (ParseTlsAt(payload, payload_len, domain)) return domain;

    // payload драйвера обычно содержит полный пакет IPv4 либо IPv6. Для TCP
    // учитываются IPv4 IHL, цепочка IPv6 extension headers и TCP Data Offset.
    IpPacketInfo ip;
    if (ParseIpPacket(payload, payload_len, ip)) {
        if (ip.proto != DriverProto::kTcp || ip.fragment ||
            ip.headerBytes > payload_len)
            return {};

        size_t packetSize = payload_len;
        if (ip.totalBytes && packetSize > ip.totalBytes)
            packetSize = ip.totalBytes;
        if (ip.headerBytes > packetSize) return {};

        const size_t capturedTcpSize = packetSize - ip.headerBytes;
        ParseTlsFromTcp(payload + ip.headerBytes, capturedTcpSize,
                        ip.payloadBytes, domain);
        return domain;
    }

    // Последний вариант — TCP segment без IP-заголовка.
    ParseTlsFromTcp(payload, payload_len, payload_len, domain);
    return domain;
}

namespace {

bool ReadDnsName(const uint8_t* message, size_t size, size_t& offset,
                 std::string* name) {
    size_t pos = offset;
    size_t expandedSize = 1; // завершающий нулевой label входит в лимит 255 байт
    size_t jumpLimit = pos;
    unsigned jumps = 0;
    bool compressed = false;
    if (name) name->clear();

    while (pos < size) {
        const uint8_t labelSize = message[pos++];
        if (labelSize == 0) {
            if (!compressed) offset = pos;
            if (name && name->empty()) *name = ".";
            return true;
        }
        if ((labelSize & 0xc0u) == 0xc0u) {
            if (pos == size) return false;
            const size_t target = (static_cast<size_t>(labelSize & 0x3fu) << 8) |
                                  message[pos++];
            // Сжатие ссылается на предыдущее имя, не на заголовок DNS. Убывающий
            // предел и лимит переходов исключают циклы и длинные цепочки указателей.
            if (target < 12 || target >= jumpLimit || ++jumps > 128) return false;
            if (!compressed) offset = pos;
            compressed = true;
            jumpLimit = target;
            pos = target;
            continue;
        }
        if ((labelSize & 0xc0u) != 0 || labelSize > size - pos ||
            expandedSize + labelSize + 1 > 255)
            return false;
        expandedSize += labelSize + 1;
        if (name) {
            if (!name->empty()) name->push_back('.');
            for (size_t i = 0; i < labelSize; ++i) {
                const uint8_t ch = message[pos + i];
                if (ch >= 0x21 && ch <= 0x7e && ch != '.' && ch != '\\') {
                    name->push_back(static_cast<char>(ch));
                } else {
                    // DNS label допускает произвольные байты. Управляющие символы
                    // и разделители показываются в DNS-форме \\DDD, не попадают в UI.
                    name->push_back('\\');
                    name->push_back(static_cast<char>('0' + ch / 100));
                    name->push_back(static_cast<char>('0' + ch / 10 % 10));
                    name->push_back(static_cast<char>('0' + ch % 10));
                }
            }
        }
        pos += labelSize;
    }
    return false;
}

std::string DnsPtrAddress(std::string_view name) {
    const auto hasSuffix = [name](std::string_view suffix) {
        if (name.size() <= suffix.size()) return false;
        const size_t start = name.size() - suffix.size();
        for (size_t i = 0; i < suffix.size(); ++i) {
            char ch = name[start + i];
            if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
            if (ch != suffix[i]) return false;
        }
        return true;
    };

    IpAddr address;
    constexpr std::string_view v4Suffix = ".in-addr.arpa";
    constexpr std::string_view v6Suffix = ".ip6.arpa";
    if (hasSuffix(v4Suffix)) {
        name.remove_suffix(v4Suffix.size());
        size_t pos = 0;
        for (size_t i = 0; i < 4; ++i) {
            const size_t begin = pos;
            unsigned value = 0;
            while (pos < name.size() && name[pos] >= '0' && name[pos] <= '9') {
                value = value * 10 + static_cast<unsigned>(name[pos++] - '0');
                if (pos - begin > 3 || value > 255) return {};
            }
            if (pos == begin) return {};
            address.b[3 - i] = static_cast<uint8_t>(value);
            if (i == 3) {
                if (pos != name.size()) return {};
            } else if (pos == name.size() || name[pos++] != '.') {
                return {};
            }
        }
    } else if (hasSuffix(v6Suffix)) {
        name.remove_suffix(v6Suffix.size());
        if (name.size() != 63) return {};
        address.family = AF_INET6;
        for (size_t i = 0; i < 32; ++i) {
            const char ch = name[i * 2];
            unsigned value;
            if (ch >= '0' && ch <= '9') value = static_cast<unsigned>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') value = static_cast<unsigned>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') value = static_cast<unsigned>(ch - 'A' + 10);
            else return {};
            if (i < 31 && name[i * 2 + 1] != '.') return {};
            address.b[15 - i / 2] |= static_cast<uint8_t>(value << ((i % 2) * 4));
        }
    } else {
        return {};
    }

    char text[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(address.family, address.b, text, sizeof(text))) return {};
    return text;
}

} // анонимное пространство имён

std::string GetDnsQueryDomain(const uint8_t* payload, size_t payload_len) {
    constexpr size_t kUdpHeaderBytes = 8;
    constexpr size_t kDnsHeaderBytes = 12;
    IpPacketInfo ip;
    if (!ParseIpPacket(payload, payload_len, ip) || ip.truncated || ip.fragment ||
        ip.proto != DriverProto::kUdp || ip.headerBytes > ip.totalBytes ||
        ip.payloadBytes < kUdpHeaderBytes || ip.totalBytes > payload_len)
        return {};

    // ParseIpPacket допускает первый фрагмент ради учёта. DNS разбирается лишь
    // в целой датаграмме, без IPv4 MF, IPv6 Fragment и неподдерживаемых jumbograms.
    if (ip.version == 4 && (Be16(payload + 6) & 0x2000u) != 0) return {};
    if (ip.version == 6) {
        if (Be16(payload + 4) == 0) return {};
        uint8_t next = payload[6];
        for (size_t pos = 40; pos < ip.headerBytes;) {
            if (next == 44) return {};
            const size_t step = Ipv6ExtLen(next, payload + pos);
            if (step == 0 || step > ip.headerBytes - pos) return {};
            next = payload[pos];
            pos += step;
        }
    }

    const uint8_t* const udp = payload + ip.headerBytes;
    const size_t udpSize = Be16(udp + 4);
    const uint16_t remotePort = Be16(udp + 2);
    if ((remotePort != 53 && remotePort != 5353 && remotePort != 5355) ||
        udpSize < kUdpHeaderBytes + kDnsHeaderBytes ||
        udpSize > ip.payloadBytes)
        return {};

    const uint8_t* const message = udp + kUdpHeaderBytes;
    const size_t size = udpSize - kUdpHeaderBytes;
    const uint16_t flags = Be16(message + 2);
    // Только обычный полный запрос: QR/opcode/TC/Z/RCODE должны быть нулевыми.
    if ((flags & 0xfa4fu) != 0) return {};
    const size_t questionCount = Be16(message + 4);
    if (questionCount == 0 || questionCount > (size - kDnsHeaderBytes) / 5) return {};

    size_t offset = kDnsHeaderBytes;
    uint16_t firstType = 0;
    uint16_t firstClass = 0;
    std::string domain;
    for (size_t i = 0; i < questionCount; ++i) {
        if (!ReadDnsName(message, size, offset, i == 0 ? &domain : nullptr) ||
            size - offset < 4)
            return {};
        const uint16_t type = Be16(message + offset);
        uint16_t dnsClass = Be16(message + offset + 2);
        // В mDNS старший бит QCLASS задаёт QU, а не часть класса вопроса.
        if (remotePort == 5353) dnsClass &= 0x7fffu;
        if (type == 0 || dnsClass == 0) return {};
        if (i == 0) {
            firstType = type;
            firstClass = dnsClass;
        }
        offset += 4;
    }
    if (firstType == 12 && (firstClass == 1 || firstClass == 255)) {
        std::string address = DnsPtrAddress(domain);
        if (!address.empty()) return address;
    }
    return domain;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                      nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::wstring ModulePath() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buf.data(),
                                           static_cast<DWORD>(buf.size()));
        if (n == 0) return std::wstring();
        if (n < buf.size() - 1) { buf.resize(n); break; }
        if (buf.size() > 32768) return std::wstring();
        buf.resize(buf.size() * 2);
    }
    return buf;
}

std::wstring ModuleDir() {
    const std::wstring path = ModulePath();
    if (path.empty()) return std::wstring();
    const size_t p = path.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? std::wstring() : path.substr(0, p + 1);
}

std::wstring ModuleDirFile(const wchar_t* leaf) {
    std::wstring dir = ModuleDir();
    if (dir.empty()) return leaf ? std::wstring(leaf) : std::wstring();
    return dir + (leaf ? leaf : L"");
}

std::wstring FormatWinError(DWORD err) {
    LPWSTR buf = nullptr;
    const DWORD n = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);

    std::wstring text;
    if (n && buf) text.assign(buf, n);
    if (buf) LocalFree(buf);

    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' ||
                             text.back() == L' '  || text.back() == L'.'))
        text.pop_back();

    // IGNORE_INSERTS оставляет %1…%99 в тексте (например, у ошибки 317).
    // Без исходных аргументов это не описание ошибки: показываем только её код.
    for (size_t i = 0; i + 1 < text.size(); ++i) {
        if (text[i] == L'%' && text[i + 1] >= L'1' && text[i + 1] <= L'9') {
            text.clear();
            break;
        }
    }

    if (text.empty())
        return LoadStringResFmt(IDS_FMT_ERRCODE_ONLY,
                                static_cast<unsigned long>(err));
    return LoadStringResFmt(IDS_FMT_ERRCODE_WITH_TEXT, text.c_str(),
                            static_cast<unsigned long>(err));
}

HICON LoadAppIcon(HINSTANCE inst, int px) {
    if (px <= 0) px = 32;

    HICON ico = nullptr;
    // корректное уменьшение из большего кадра .ico — без «мыла» на 125/150 %
    if (SUCCEEDED(LoadIconWithScaleDown(inst, MAKEINTRESOURCEW(IDI_ICON1),
                                        px, px, &ico)) && ico)
        return ico;

    ico = static_cast<HICON>(LoadImageW(inst, MAKEINTRESOURCEW(IDI_ICON1),
                                       IMAGE_ICON, px, px, LR_DEFAULTCOLOR));
    return ico;                       // владение у вызывающего
}

std::wstring IpToString(const IpAddr& a) {
    if (a.isAny()) return L"*";
    // Протоколы без портов (ICMP, GRE, ESP…) показывают только адрес,
    // поэтому подпись здесь без «:loopback».
    if (IsLocalhostV4(a)) return kLocalhostName;
    return IpToPlainString(a);
}

// «1.2.3.4: 5678», «[2001:db8::1]: 443», «localhost:loopback: 1234», «*: *»
std::wstring EndpointToString(const IpAddr& a, uint16_t port) {
    // Петлевой эндпоинт — одна подпись: она сообщает и адрес, и то, что
    // обмен не выходит за пределы этого компьютера.
    if (IsLocalhostV4(a)) return std::wstring(kLoopbackEndpoint) + L": " + std::to_wstring(port);

    std::wstring host;
    if (a.isAny())                 host = L"*";
    else if (a.family == AF_INET6) host = L"[" + IpToPlainString(a) + L"]";
    else                           host = IpToPlainString(a);
    // Пробел ставится ПОСЛЕ двоеточия: «1.2.3.4: 5678».
    return host + L": " + (port ? std::to_wstring(port) : std::wstring(L"*"));
}

std::string_view getHttpHost( const uint8_t* payload, uint32_t payloadSize) noexcept
{
    if (!payload || payloadSize < 20)
        return {};

    uint32_t offset = 0;
    uint32_t end = 0;
    uint8_t protocol = 0;

    if ((payload[0] >> 4) == 4) {
        const uint32_t ipHeaderSize = (payload[0] & 0x0F) * 4u;
        const uint32_t totalSize =
            (uint32_t(payload[2]) << 8) | payload[3];

        if (ipHeaderSize < 20 || ipHeaderSize > payloadSize ||
            totalSize < ipHeaderSize ||
            (((uint32_t(payload[6]) << 8) | payload[7]) & 0x3FFFu))
            return {}; // Фрагментированный IPv4-пакет.

        offset = ipHeaderSize;
        end = std::min(payloadSize, totalSize);
        protocol = payload[9];
    } else if ((payload[0] >> 4) == 6) {
        if (payloadSize < 40)
            return {};

        const uint32_t ipPayloadSize =
            (uint32_t(payload[4]) << 8) | payload[5];
        if (ipPayloadSize == 0)
            return {}; // IPv6 jumbogram здесь не поддерживается.

        offset = 40;
        end = std::min(payloadSize, 40u + ipPayloadSize);
        protocol = payload[6];

        // Пропускаем распространённые IPv6 extension headers.
        for (unsigned count = 0; protocol != 6; ++count) {
            if (count == 8 || end - offset < 2)
                return {};

            if (protocol == 44)
                return {}; // Fragment: требуется сборка фрагментов.

            uint32_t headerSize;
            switch (protocol) {
                case 0:   // Hop-by-Hop
                case 43:  // Routing
                case 60:  // Destination Options
                    headerSize = 8u * (uint32_t(payload[offset + 1]) + 1u);
                    break;
                case 51:  // AH
                    headerSize = 4u * (uint32_t(payload[offset + 1]) + 2u);
                    break;
                default:
                    return {};
            }

            if (headerSize > end - offset)
                return {};

            protocol = payload[offset];
            offset += headerSize;
        }
    } else {
        return {};
    }

    if (protocol != 6 || end - offset < 20)
        return {}; // Не TCP или усечённый TCP-заголовок.

    const uint32_t tcpHeaderSize = (payload[offset + 12] >> 4) * 4u;
    if (tcpHeaderSize < 20 || tcpHeaderSize > end - offset)
        return {};

    const char* current =
        reinterpret_cast<const char*>(payload + offset + tcpHeaderSize);
    const char* const limit = reinterpret_cast<const char*>(payload + end);

    // Проверяем первую строку: METHOD target HTTP/1.0 или HTTP/1.1.
    const char* newline = static_cast<const char*>(
        std::memchr(current, '\n', limit - current));
    if (!newline || newline == current || newline[-1] != '\r')
        return {};

    const char* const lineEnd = newline - 1;
    const char* const space1 = static_cast<const char*>(
        std::memchr(current, ' ', lineEnd - current));
    if (!space1 || space1 == current)
        return {};

    const char* const space2 = static_cast<const char*>(
        std::memchr(space1 + 1, ' ', lineEnd - (space1 + 1)));
    if (!space2 || space2 == space1 + 1 ||
        lineEnd - space2 != 9 ||
        std::memcmp(space2 + 1, "HTTP/1.", 7) != 0 ||
        (space2[8] != '0' && space2[8] != '1'))
        return {};

    current = newline + 1;
    while (current < limit) {
        newline = static_cast<const char*>(
            std::memchr(current, '\n', limit - current));
        if (!newline || newline == current || newline[-1] != '\r')
            return {};

        const char* valueEnd = newline - 1;
        if (valueEnd == current)
            return {}; // Конец заголовков: Host не найден.

        if (valueEnd - current >= 5 &&
            (current[0] | 0x20) == 'h' &&
            (current[1] | 0x20) == 'o' &&
            (current[2] | 0x20) == 's' &&
            (current[3] | 0x20) == 't' &&
            current[4] == ':') {

            const char* host = current + 5;
            while (host < valueEnd && (*host == ' ' || *host == '\t'))
                ++host;
            while (valueEnd > host &&
                   (valueEnd[-1] == ' ' || valueEnd[-1] == '\t'))
                --valueEnd;

            if (host == valueEnd)
                return {};

            const char* hostEnd = valueEnd;
            const char* port = nullptr;

            if (*host == '[') { // IP-литерал IPv6: [::1]:8080
                const char* closing = static_cast<const char*>(
                    std::memchr(host, ']', valueEnd - host));
                if (!closing || closing == host + 1)
                    return {};
                hostEnd = closing + 1; // Возвращаем литерал со скобками.
                if (hostEnd != valueEnd) {
                    if (*hostEnd != ':')
                        return {};
                    port = hostEnd + 1;
                }
            } else {
                const char* colon = static_cast<const char*>(
                    std::memchr(host, ':', valueEnd - host));
                if (colon) {
                    hostEnd = colon;
                    port = colon + 1;
                }
            }

            if (hostEnd == host)
                return {};
            if (port) {
                if (port == valueEnd)
                    return {};
                for (const char* p = port; p < valueEnd; ++p)
                    if (*p < '0' || *p > '9')
                        return {};
            }

            return {host, static_cast<size_t>(hostEnd - host)};
        }

        current = newline + 1;
    }

    return {};
}
