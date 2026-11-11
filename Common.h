#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "FoldedText.h"
#include "NumericHash.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <string>
#include <string_view>
#include <vector>

// ---------------------------------------------------------------------------
// Протокол — это НОМЕР протокола IP: поле «Protocol» заголовка IPv4 либо
// «Next Header» заголовка IPv6. Значений ровно 256, и в on_connection_v4 /
// on_connection_v6 может прийти любое из них (HOPOPT, ICMP, IGMP, GRE, ESP…).
//
// Поэтому перечисление задаёт только АЛИАСЫ тех номеров, которые упоминаются
// в коде; остальные значения получаются приведением ProtoFromNumber(n): для
// enum class с фиксированным базовым типом допустим весь диапазон uint8_t.
// ---------------------------------------------------------------------------
enum class Proto : uint8_t {
    HopOpt         = 0,     // IPv6 Hop-by-Hop Option
    Icmp           = 1,
    Igmp           = 2,
    Ipv4           = 4,     // IP-in-IP
    Tcp            = 6,
    Egp            = 8,
    Udp            = 17,
    Rdp            = 27,
    Dccp           = 33,
    Ipv6           = 41,
    Ipv6Route      = 43,
    Ipv6Frag       = 44,
    Rsvp           = 46,
    Gre            = 47,
    Esp            = 50,
    Ah             = 51,
    IcmpV6         = 58,
    Ipv6NoNxt      = 59,
    Ipv6Opts       = 60,
    Eigrp          = 88,
    Ospf           = 89,
    Pim            = 103,
    Vrrp           = 112,
    Pgm            = 113,
    L2tp           = 115,
    Sctp           = 132,
    MobilityHeader = 135,
    UdpLite        = 136,
    MplsInIp       = 137,
    Hip            = 139,
    Shim6          = 140,
    Ethernet       = 143,
};

enum class Dir : uint8_t { Unknown = 0, In = 1, Out = 2 };

inline constexpr uint8_t ProtoNumber(Proto p)       { return static_cast<uint8_t>(p); }
inline constexpr Proto   ProtoFromNumber(uint8_t n) { return static_cast<Proto>(n); }

// ---------------------------------------------------------------------------
// Подготовленное безрегистровое представление пути.
//
// Пути процессов участвуют в сопоставлении каждого сетевого события. Свёртка
// одного и того же имени по сотне символов на каждом запросе
// заметно дороже поиска в хэш-таблице, поэтому неизменяемые пути сворачиваются
// один раз и дальше передаются вместе с готовым FNV-хэшем.
//
// Эти функции общие для построения индекса и запроса: иное правило свёртки
// оставило бы существующее правило в таблице, но сделало бы его недоступным.
// ---------------------------------------------------------------------------
inline int CompareNoCase(std::wstring_view a, std::wstring_view b) {
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    // Точное совпадение проверяем пакетно, без свёртки и чтения таблицы.
    if (n && a.data() != b.data() &&
        std::char_traits<wchar_t>::compare(a.data(), b.data(), n) != 0) {
        const auto& table = FoldCaseTable();
        for (size_t i = 0; i < n; ++i) {
            if (a[i] == b[i]) continue;
            const wchar_t x = table[static_cast<uint16_t>(a[i])];
            const wchar_t y = table[static_cast<uint16_t>(b[i])];
            if (x != y) return x < y ? -1 : 1;
        }
    }
    if (a.size() == b.size()) return 0;
    return a.size() < b.size() ? -1 : 1;
}

inline bool EqualNoCase(std::wstring_view a, std::wstring_view b) {
    return a.size() == b.size() && CompareNoCase(a, b) == 0;
}

// Порты предусмотрены форматом заголовка только у этих протоколов. Для всех
// остальных поля local_port / remote_port события смысла не имеют: они
// обнуляются, а условия портов в правиле недоступны.
inline constexpr bool ProtoHasPorts(Proto p) {
    switch (p) {
    case Proto::Tcp:
    case Proto::Udp:
    case Proto::Sctp:
    case Proto::Dccp:
    case Proto::UdpLite:
        return true;
    default:
        return false;
    }
}
inline constexpr bool ProtoIsIcmp(Proto p) {
    return p == Proto::Icmp || p == Proto::IcmpV6;
}
inline constexpr bool ProtoIsIcmpV6(Proto p) { return p == Proto::IcmpV6; }

// ---------------------------------------------------------------------------
// Таблицы соединений операционной системы (GetExtendedTcpTable /
// GetExtendedUdpTable) содержат ТОЛЬКО эти два протокола.
//
// Для любого другого номера — ICMP, IGMP, GRE, ESP… — таблицы нет вообще,
// поэтому единственным источником и строки списка, и счётчиков байт остаётся
// событие транспорта. Проверка вынесена сюда, чтобы это правило было записано
// один раз, а не повторялось в FlowStore, Ingest и Monitor независимо.
// ---------------------------------------------------------------------------
inline constexpr bool ProtoInOsTables(Proto p) {
    return p == Proto::Tcp || p == Proto::Udp;
}

// Номера протоколов, встречающиеся в разборе IP-заголовков и в структурах
// транспорта. Значения те же, что у алиасов Proto.
namespace DriverProto {
    constexpr uint8_t kIcmp   = ProtoNumber(Proto::Icmp);
    constexpr uint8_t kTcp    = ProtoNumber(Proto::Tcp);
    constexpr uint8_t kUdp    = ProtoNumber(Proto::Udp);
    constexpr uint8_t kIcmpV6 = ProtoNumber(Proto::IcmpV6);
}

struct IpAddr {
    uint16_t family = AF_INET;
    uint8_t  b[16]{};

    static IpAddr V4(uint32_t netOrder) {
        IpAddr a; a.family = AF_INET; std::memcpy(a.b, &netOrder, 4); return a;
    }
    static IpAddr V6(const void* p) {
        IpAddr a; a.family = AF_INET6; std::memcpy(a.b, p, 16); return a;
    }
    // байты уже в сетевом порядке — как в структурах транспорта
    static IpAddr Raw4(const void* p) {
        IpAddr a; a.family = AF_INET; std::memcpy(a.b, p, 4); return a;
    }
    static IpAddr Raw6(const void* p) {
        IpAddr a; a.family = AF_INET6; std::memcpy(a.b, p, 16); return a;
    }
    size_t len() const { return family == AF_INET6 ? 16u : 4u; }

    bool operator==(const IpAddr& o) const {
        return family == o.family && std::memcmp(b, o.b, len()) == 0;
    }
    int Cmp(const IpAddr& o) const {          // сетевой порядок => memcmp корректен
        if (family != o.family) return family < o.family ? -1 : 1;
        return std::memcmp(b, o.b, len());
    }
    bool isAny() const {
        for (size_t i = 0; i < len(); ++i) if (b[i]) return false;
        return true;
    }
    bool isLoopback() const {
        if (family == AF_INET) return b[0] == 127;
        for (int i = 0; i < 15; ++i) if (b[i]) return false;
        return b[15] == 1;
    }
};

// Сравниваем только сетевые биты, без построения границ диапазона.
// Отрицательный префикс означает точный адрес, слишком длинный — полный адрес.
inline bool IpMatchesPrefix(const IpAddr& a, const IpAddr& base, int prefix) {
    if (a.family != base.family) return false;
    if (prefix < 0) return a == base;

    const int total = static_cast<int>(base.len()) * 8;
    if (prefix > total) prefix = total;
    const size_t wholeBytes = static_cast<size_t>(prefix / 8);
    if (wholeBytes && std::memcmp(a.b, base.b, wholeBytes) != 0) return false;

    const int remainingBits = prefix % 8;
    if (!remainingBits) return true;
    const uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - remainingBits));
    return (a.b[wholeBytes] & mask) == (base.b[wholeBytes] & mask);
}

// Источник входит в tuple: одинаковые адреса двух драйверов не являются одним потоком.
enum class TrafficSource : uint8_t { Host = 0, Ndis = 1 };
// Источник разделяет пространства PID хоста и индексов Ethernet-интерфейсов NDIS.
// Числовой аргумент конструктора всегда означает PID хоста; интерфейс задаётся явно.
struct TrafficGroupKey {
    TrafficSource source = TrafficSource::Host;
    uint32_t id = 0;

    constexpr TrafficGroupKey() = default;
    constexpr TrafficGroupKey(DWORD pid) : id(pid) {}
    constexpr TrafficGroupKey(TrafficSource source_, uint32_t id_) : source(source_), id(id_) {}
    static constexpr TrafficGroupKey Host(DWORD pid) { return {TrafficSource::Host, pid}; }
    static constexpr TrafficGroupKey Ndis(uint32_t index) { return {TrafficSource::Ndis, index}; }
    constexpr bool isHost() const { return source == TrafficSource::Host; }
    constexpr bool isNdis() const { return source == TrafficSource::Ndis; }
    constexpr DWORD pid() const { return isHost() ? id : 0; }
    constexpr uint32_t interfaceIndex() const { return isNdis() ? id : 0; }
    constexpr uint64_t value() const { return (static_cast<uint64_t>(source) << 32) | id; }
    bool operator==(const TrafficGroupKey&) const = default;
};

struct TrafficGroupKeyHash {
    size_t operator()(const TrafficGroupKey& group) const noexcept {
        return NumericIdHash{}(group.value());
    }
};
inline constexpr ULONGLONG kNdisInactiveMs = 60 * 1000;

struct FlowKey {
    Proto    proto = Proto::Tcp;      // номер протокола IP
    IpAddr   local;
    IpAddr   remote;
    uint16_t lport = 0;               // 0, если у протокола нет портов
    uint16_t rport = 0;
    TrafficSource source = TrafficSource::Host;
    uint32_t interfaceIndex = 0; // Только NDIS: таблицы сокетов хоста индекса не содержат.

    bool operator==(const FlowKey& o) const {
        return source == o.source && interfaceIndex == o.interfaceIndex && proto == o.proto && lport == o.lport && rport == o.rport &&
               local == o.local && remote == o.remote;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        uint64_t h = 1469598103934665603ull;
        auto mix = [&h](const void* p, size_t n) {
            const uint8_t* q = static_cast<const uint8_t*>(p);
            for (size_t i = 0; i < n; ++i) { h ^= q[i]; h *= 1099511628211ull; }
        };
        mix(&k.source, sizeof(k.source));
        if (k.source == TrafficSource::Ndis)
            mix(&k.interfaceIndex, sizeof(k.interfaceIndex));
        uint8_t pr = ProtoNumber(k.proto);
        mix(&pr, 1);
        mix(&k.lport, 2); mix(&k.rport, 2);
        mix(&k.local.family, 2);  mix(k.local.b,  k.local.len());
        mix(&k.remote.family, 2); mix(k.remote.b, k.remote.len());
        return static_cast<size_t>(h ^ (h >> 32));
    }
};

struct FlowId {
    FlowKey  key;
    uint64_t generation = 0;       // уникальный экземпляр потока с данным FlowKey

    bool operator==(const FlowId& o) const {
        return generation == o.generation && key == o.key;
    }
};

struct FlowIdHash {
    size_t operator()(const FlowId& id) const noexcept {
        uint64_t h = static_cast<uint64_t>(FlowKeyHash{}(id.key));
        h ^= id.generation + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdull;
        h ^= h >> 33;
        return static_cast<size_t>(h ^ (h >> 32));
    }
};

// ---------------------------------------------------------------------------
// Адрес из «сырых» байт структуры транспорта.
//
// Выбор по РАЗМЕРУ массива, а не по внешнему признаку «это IPv6»: обработчики
// событий IPv4 и IPv6 отличаются ровно этим, поэтому одна перегрузка избавляет
// от второй копии каждого обработчика (Ingest::HandleFixed,
// on_connection_end_*, on_bandwidthstats_*).
// ---------------------------------------------------------------------------
inline IpAddr IpFromRaw(const uint8_t (&raw)[4])  { return IpAddr::Raw4(raw); }
inline IpAddr IpFromRaw(const uint8_t (&raw)[16]) { return IpAddr::Raw6(raw); }

// Ключ потока по данным события транспорта. Порты берутся только там, где они
// предусмотрены форматом заголовка: у ICMP, GRE, ESP… поля события смысла
// не имеют. Одно место вместо трёх копий этой проверки.
inline FlowKey MakeFlowKey(Proto proto, const IpAddr& local, const IpAddr& remote,
                           uint16_t lport, uint16_t rport) {
    const bool ports = ProtoHasPorts(proto);
    FlowKey k;
    k.proto  = proto;
    k.local  = local;
    k.remote = remote;
    k.lport  = ports ? lport : 0;
    k.rport  = ports ? rport : 0;
    return k;
}

// Поле direction структур транспорта: 1 — входящее, иначе исходящее.
inline constexpr Dir DirFromDriver(uint8_t direction) {
    return direction == 1 ? Dir::In : Dir::Out;
}

// ---------------------------------------------------------------------------
// Локальный эндпоинт сокета: семейство + порт + адрес.
//
// Нулевой адрес — это и есть привязка к 0.0.0.0 / ::.
//
// Тип общий для FlowStore (набор допущенных UDP-эндпоинтов) и OwnerLookup
// (владелец по локальному эндпоинту): обе карты описывают одно и то же, и
// держать два одинаковых типа с двумя одинаковыми хэшами не за чем.
// ---------------------------------------------------------------------------
struct IpEndpoint {
    uint16_t family = AF_INET;
    uint16_t port = 0;
    uint8_t  b[16]{};

    size_t len() const { return family == AF_INET6 ? 16u : 4u; }
    bool operator==(const IpEndpoint& o) const {
        return family == o.family && port == o.port &&
               std::memcmp(b, o.b, len()) == 0;
    }
};

struct IpEndpointHash {
    size_t operator()(const IpEndpoint& e) const noexcept {
        uint64_t h = 1469598103934665603ull;
        const auto mix = [&h](const void* p, size_t n) {
            const uint8_t* q = static_cast<const uint8_t*>(p);
            for (size_t i = 0; i < n; ++i) { h ^= q[i]; h *= 1099511628211ull; }
        };
        mix(&e.family, 2);
        mix(&e.port, 2);
        mix(e.b, e.len());
        return static_cast<size_t>(h ^ (h >> 32));
    }
};

inline IpEndpoint MakeIpEndpoint(const IpAddr& a, uint16_t port) {
    IpEndpoint e;
    e.family = a.family;
    e.port = port;
    std::memcpy(e.b, a.b, a.len());
    return e;
}

inline IpEndpoint MakeIpWildcard(uint16_t family, uint16_t port) {
    IpEndpoint e;
    e.family = family;
    e.port = port;
    return e;                            // адрес нулевой
}

// Тип и код ICMP, извлечённые из payload соединения
struct IcmpInfo {
    int  type = -1;         // -1 = не определён
    int  code = -1;
    bool v6 = false;
    bool known() const { return type >= 0; }
};

// ---------------------------------------------------------------------------
// Разобранный IP-пакет из payload события транспорта.
//
// Нужен по трём причинам сразу: из него берутся тип/код ICMP, размер пакета
// «на проводе» и НАПРАВЛЕНИЕ. Последнее — потому что поле direction события
// само по себе непроверяемо, а заголовок содержит фактические адреса
// источника и получателя (см. ResolveDir в Ingest.cpp).
//
// У обычного IP-пакета размер берётся из поля длины, даже если payload усечён.
// При нулевом IPv6 Payload Length разборщик не читает Jumbo Payload option
// и использует доступную длину переданного буфера.
// ---------------------------------------------------------------------------
struct IpPacketInfo {
    uint8_t  version = 0;        // 4 либо 6; 0 — версия не распознана или заголовок отвергнут
    uint8_t  proto = 0;          // протокол IP; у IPv6 — после разобранной части цепочки
    size_t   headerBytes = 0;    // IP-заголовок (для IPv6 — с extension headers)
    size_t   totalBytes = 0;     // размер по заголовку; при нулевой длине IPv6 — len
    size_t   payloadBytes = 0;   // max(totalBytes - headerBytes, 0)
    bool     truncated = false;  // усечён пакет либо цепочка расширений IPv6
    bool     fragment = false;   // не первый фрагмент: транспортного заголовка нет
    bool     hasAddrs = false;   // src/dst заполнены
    IpAddr   src, dst;           // фактические адреса из заголовка
    IcmpInfo icmp;               // заполнено только для протоколов 1 и 58
};

// ---------------- утилиты (Util.cpp) ----------------
std::wstring FormatNumber(uint64_t v);
std::wstring FormatBytes(uint64_t v);
std::wstring FormatSpeed(double bytesPerSec);
std::wstring IpToString(const IpAddr& a);
std::wstring IpToPlainString(const IpAddr& a);          // без спецобозначений
std::wstring EndpointToString(const IpAddr& a, uint16_t port);
const wchar_t* DirToString(Dir d);
bool IsElevated();
bool EnableDebugPrivilege();                            // SE_DEBUG_NAME

// ---------------------------------------------------------------------------
// Отображение адреса и эндпоинта в списке соединений.
//
// Два правила заданы ЗДЕСЬ и больше нигде:
//   * 127.0.0.1 показывается символически: сам адрес — «localhost»,
//     эндпоинт — «localhost:loopback: <порт>»;
//   * между адресом и портом стоит пробел: «1.2.3.4: 5678».
// ---------------------------------------------------------------------------
inline constexpr wchar_t kLocalhostName[]    = L"localhost";
inline constexpr wchar_t kLoopbackEndpoint[] = L"localhost:loopback";

// Ровно 127.0.0.1. Прочие адреса 127.0.0.0/8 и ::1 остаются числовыми:
// требование касается одного адреса, а не всей петлевой сети (для «любого
// петлевого» достаточно заменить тело на a.isLoopback()).
inline constexpr bool IsLocalhostV4(const IpAddr& a) {
    return a.family == AF_INET &&
           a.b[0] == 127 && a.b[1] == 0 && a.b[2] == 0 && a.b[3] == 1;
}

// ---------------- справочник протоколов (Util.cpp) ----------------
// Таблица нужна только для показа и разбора ввода: любой номер 0..255
// остаётся допустимым, даже если его в таблице нет.
struct KnownProto { uint8_t num; const wchar_t* alias; const wchar_t* name; UINT descId; };
const KnownProto* KnownProtos(size_t& count);
const wchar_t*    ProtoAlias(uint8_t num);   // nullptr — номер без имени
// По значению: descId может брать строку из STRINGTABLE
std::wstring      ProtoDesc(uint8_t num);
std::wstring      ProtoToString(Proto p);    // «TCP», «ICMPv6», «144»
std::wstring      ProtoLabel(Proto p);       // «TCP (6)», «144»
// «6», «tcp», «ICMPv6», «GRE» -> номер; false, если не распознано
bool              ParseProtoToken(const std::wstring& s, uint8_t& out);

bool ParseIpAddr(const std::wstring& s, IpAddr& out);
bool MaskToPrefix(const IpAddr& mask, int& prefix);
IpAddr PrefixToMask(uint16_t family, int prefix);
void   ApplyPrefix(IpAddr& addr, int prefix, bool fillOnes);   // сеть / broadcast
std::wstring PathBaseUpper(const std::wstring& path);

// Разбор payload события транспорта как IP-пакета: заголовок IPv4 с учётом
// IHL либо IPv6 с цепочкой extension headers. false — заголовок не удалось
// распознать или проверить; например, payload начинается с TCP, а не с IP.
bool ParseIpPacket(const uint8_t* pkt, size_t len, IpPacketInfo& out);

// Извлечь SNI из TLS ClientHello. Принимает полный IPv4/IPv6-пакет,
// TCP-сегмент либо уже отделённые TLS/Handshake-данные; пустая строка означает,
// что корректный ClientHello с именем сервера не найден.
std::string GetTlsClientHelloDomain(const uint8_t* payload, size_t payload_len);

// Первое имя вопроса DNS-запроса в полном IPv4/IPv6 UDP-пакете на порт 53.
// PTR для in-addr.arpa/ip6.arpa возвращает IP; некорректный пакет — пустую строку.
std::string GetDnsQueryDomain(const uint8_t* payload, size_t payload_len);

// Извлечь имя узла из Host HTTP/1.x-запроса в полном IPv4/IPv6 TCP-пакете.
// Порт отбрасывается, скобки IPv6 сохраняются; результат ссылается на исходный пакет.
std::string_view getHttpHost(const uint8_t* payload, uint32_t payloadSize) noexcept;

// Тип и код ICMP из стандартного IPv4/IPv6-пакета. Оставлено как удобная
// обёртка над ParseIpPacket: разбор выполняется одним и тем же кодом.
bool ParseIcmpFromIpPacket(const uint8_t* pkt, size_t len, IcmpInfo& out);

// ---------------------------------------------------------------------------
// Отнесён ли тип ICMP к входящим сообщениям в эвристике петлевого обмена.
//
// Таблица включает ответы, ошибки, а также некоторые объявления и отчёты.
// Последние могут быть незапрошенными: это правило выбора направления,
// а не доказательство того, что пакет отвечает на наш запрос.
//
// Применяется РОВНО в одном случае — когда источник и получатель пакета
// совпадают (петля), и направление принципиально неопределимо: пакет
// одновременно отправлен и получен этим же компьютером. См. ResolveDir.
// ---------------------------------------------------------------------------
bool IcmpIsReply(int type, bool v6);

// строки и путь к каталогу программы
std::string  WideToUtf8(const std::wstring& s);
std::wstring Utf8ToWide(const std::string& s);
std::wstring ModulePath();                              // полный путь к .exe
std::wstring ModuleDir();                               // с завершающим «\»
std::wstring ModuleDirFile(const wchar_t* leaf);

// текст системной ошибки без завершающих переводов строк
std::wstring FormatWinError(DWORD err);

// Значок программы (IDI_ICON1) нужного размера; владение у вызывающего:
// освобождать через DestroyIcon.
HICON LoadAppIcon(HINSTANCE inst, int px);