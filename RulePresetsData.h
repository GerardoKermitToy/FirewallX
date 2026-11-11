#pragma once
#include "Rules.h"
#include "RulePresetsResource.h"
#include <span>

// Каталог отделён от сопоставления и UI. Порты и адреса — условия, а не
// догадки по текущему IP сервера; динамические адреса разрешаются макросами.
namespace RulePresets::Data {

struct Address {
    AddrMacro macro = AddrMacro::None;
    const wchar_t* ip = nullptr;
    int prefix = -1;
};

struct NetworkRule {
    UINT nameId;
    Proto proto;
    Dir dir = Dir::Out;
    std::span<const PortItem> remotePorts;
    std::span<const PortItem> localPorts;
    std::span<const Address> remoteAddresses;
    std::span<const IcmpTypeItem> icmpTypes;
    RuleAction action = RuleAction::Allow;
    std::span<const Address> localAddresses;
};

enum class Host { App, Service, AppService, SystemServiceGroup, SvchostFallback, System, PostAppPidZero };

struct Preset {
    UINT titleId;
    std::wstring_view executables;       // имена через «;», регистр не важен
    std::span<const NetworkRule> rules;
    Host host = Host::App;
    std::wstring_view services;          // ключи SCM или маски с «*», не отображаемые имена
};

inline constexpr PortItem pHttps[] = { {443, 443} };
inline constexpr PortItem pHttp[] = { {80, 80} };
inline constexpr PortItem pDns[] = { {53, 53} };
inline constexpr PortItem pMail[] = { {465, 465}, {587, 587}, {993, 993}, {995, 995} };
inline constexpr PortItem pStun[] = { {3478, 3481} };
inline constexpr PortItem pZoom[] = { {8801, 8810} };
inline constexpr PortItem pDiscord[] = { {50000, 65535} };
inline constexpr PortItem pTelegram[] = { {5222, 5222} };
inline constexpr PortItem pGooglePush[] = { {5228, 5228} };
inline constexpr PortItem pSteamTcp[] = { {27015, 27050} };
inline constexpr PortItem pSteamUdp[] = { {4380, 4380}, {27000, 27200} };
inline constexpr PortItem pSsh[] = { {22, 22} };
inline constexpr PortItem pRdp[] = { {3389, 3389} };
inline constexpr PortItem pDhcp4Server[] = { {67, 67} };
inline constexpr PortItem pDhcp4Client[] = { {68, 68} };
inline constexpr PortItem pDhcp6Server[] = { {547, 547} };
inline constexpr PortItem pDhcp6Client[] = { {546, 546} };
inline constexpr PortItem pNtp[] = { {123, 123} };
inline constexpr PortItem pWinrm[] = { {5985, 5985} };
inline constexpr PortItem pDelivery[] = { {7680, 7680} };
inline constexpr PortItem pSsdp[] = { {1900, 1900} };
inline constexpr PortItem pUpnp[] = { {2869, 2869} };
inline constexpr PortItem pWsd[] = { {3702, 3702} };
inline constexpr PortItem pWsdMetadata[] = { {5357, 5358} };
inline constexpr PortItem pSmb[] = { {445, 445} };
inline constexpr PortItem pNetbiosNs[] = { {137, 137} };
inline constexpr PortItem pNetbiosDgm[] = { {138, 138} };
inline constexpr PortItem pPrint[] = { {515, 515}, {631, 631}, {9100, 9100} };
inline constexpr PortItem pMdns[] = { {5353, 5353} };
inline constexpr PortItem pLlmnr[] = { {5355, 5355} };
inline constexpr PortItem pAnyDesk[] = { {6568, 6568} };
inline constexpr PortItem pTeamViewer[] = { {5938, 5938} };
inline constexpr PortItem pRustDesk21116[] = { {21116, 21116} };
inline constexpr PortItem pRustDesk21115[] = { {21115, 21115} };

inline constexpr Address aDns[] = { {AddrMacro::DnsServers}, {AddrMacro::MyComputer} };
inline constexpr Address aDoh[] = { {AddrMacro::DnsServers} };
inline constexpr Address aLan[] = { {AddrMacro::LocalNetwork}, {AddrMacro::MyComputer} };
inline constexpr Address aLoopback[] = {
    {AddrMacro::None, L"127.0.0.0", 8}, {AddrMacro::None, L"::1"}
};
inline constexpr Address aLoopback4Host[] = { {AddrMacro::None, L"127.0.0.1"} };
inline constexpr Address aLoopback6Host[] = { {AddrMacro::None, L"::1"} };
inline constexpr Address aAnyDeskDns[] = { {AddrMacro::None, L"1.1.1.1"} };
inline constexpr Address aLimitedBroadcast[] = { {AddrMacro::None, L"255.255.255.255"} };
inline constexpr Address aDhcp4[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::BroadcastAddresses},
    {AddrMacro::None, L"255.255.255.255"}
};
inline constexpr Address aDhcp6[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::None, L"ff02::1:2"}
};
inline constexpr Address aDhcpClient4[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::MyComputer}, {AddrMacro::None, L"0.0.0.0"}
};
inline constexpr Address aDhcpClient6[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::MyComputer}, {AddrMacro::None, L"fe80::", 10}
};
inline constexpr Address aDiscovery[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::MyComputer},
    {AddrMacro::None, L"239.255.255.250"}, {AddrMacro::None, L"ff02::c"}
};
inline constexpr Address aMdns[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::MyComputer},
    {AddrMacro::None, L"224.0.0.251"}, {AddrMacro::None, L"ff02::fb"}
};
inline constexpr Address aIgmpMulticast[] = { {AddrMacro::None, L"224.0.0.0", 4} };
inline constexpr Address aMdnsMulticast4[] = { {AddrMacro::None, L"224.0.0.251"} };
inline constexpr Address aMdnsMulticast6[] = { {AddrMacro::None, L"ff02::fb"} };
inline constexpr Address aLlmnr[] = {
    {AddrMacro::LocalNetwork}, {AddrMacro::MyComputer},
    {AddrMacro::None, L"224.0.0.252"}, {AddrMacro::None, L"ff02::1:3"}
};
inline constexpr IcmpTypeItem echo4[] = { {8, -1} };
inline constexpr IcmpTypeItem echo6[] = { {128, -1} };
inline constexpr IcmpTypeItem replies4[] = { {0, -1}, {3, -1}, {11, -1} };
inline constexpr IcmpTypeItem replies6[] = { {1, -1}, {3, -1}, {129, -1} };

inline constexpr NetworkRule https = { IDS_PRESET_RULE_HTTPS, Proto::Tcp, Dir::Out, pHttps };
inline constexpr NetworkRule http = { IDS_PRESET_RULE_HTTP, Proto::Tcp, Dir::Out, pHttp };
inline constexpr NetworkRule quic = { IDS_PRESET_RULE_QUIC, Proto::Udp, Dir::Out, pHttps };
inline constexpr NetworkRule dnsUdp = {
    IDS_PRESET_RULE_DNS_UDP, Proto::Udp, Dir::Out, pDns, {}, aDns
};
inline constexpr NetworkRule dnsTcp = {
    IDS_PRESET_RULE_DNS_TCP, Proto::Tcp, Dir::Out, pDns, {}, aDns
};
inline constexpr NetworkRule dnsDoh = {
    IDS_PRESET_RULE_DOH, Proto::Tcp, Dir::Out, pHttps, {}, aDoh
};
inline constexpr NetworkRule dhcp4 = {
    IDS_PRESET_RULE_DHCP4, Proto::Udp, Dir::Out, pDhcp4Server, pDhcp4Client, aDhcp4
};
inline constexpr NetworkRule dhcp6 = {
    IDS_PRESET_RULE_DHCP6, Proto::Udp, Dir::Out, pDhcp6Server, pDhcp6Client, aDhcp6
};
inline constexpr NetworkRule dhcp4In = {
    IDS_PRESET_RULE_DHCP4_IN, Proto::Udp, Dir::In, pDhcp4Client, pDhcp4Server, aDhcpClient4
};
inline constexpr NetworkRule dhcp6In = {
    IDS_PRESET_RULE_DHCP6_IN, Proto::Udp, Dir::In, pDhcp6Client, pDhcp6Server, aDhcpClient6
};
inline constexpr NetworkRule ntp = { IDS_PRESET_RULE_NTP, Proto::Udp, Dir::Out, pNtp };

inline constexpr NetworkRule mdnsOut = {
    IDS_PRESET_RULE_MDNS_OUT, Proto::Udp, Dir::Out, pMdns, {}, aMdns
};
inline constexpr NetworkRule mdnsIn = {
    IDS_PRESET_RULE_MDNS_IN, Proto::Udp, Dir::In, {}, pMdns, aMdns
};

inline constexpr NetworkRule loopbackTcp = {
    IDS_PRESET_RULE_LOOPBACK_TCP, Proto::Tcp, Dir::Unknown, {}, {}, aLoopback
};
// Локальный обмен ограничен обоими loopback-адресами, но не временными портами.
inline constexpr NetworkRule loopbackTcpOut = {
    IDS_PRESET_RULE_LOOPBACK_TCP, Proto::Tcp, Dir::Out, {}, {}, aLoopback,
    {}, RuleAction::Allow, aLoopback
};
inline constexpr NetworkRule loopbackTcp4HostOut = {
    IDS_PRESET_RULE_LOOPBACK_TCP, Proto::Tcp, Dir::Out, {}, {}, aLoopback4Host,
    {}, RuleAction::Allow, aLoopback4Host
};
inline constexpr NetworkRule loopbackTcp4HostIn = {
    IDS_PRESET_RULE_LOOPBACK_TCP, Proto::Tcp, Dir::In, {}, {}, aLoopback4Host,
    {}, RuleAction::Allow, aLoopback4Host
};
inline constexpr NetworkRule loopbackTcpIn = {
    IDS_PRESET_RULE_LOOPBACK_TCP, Proto::Tcp, Dir::In, {}, {}, aLoopback,
    {}, RuleAction::Allow, aLoopback
};
inline constexpr NetworkRule loopbackUdpOut = {
    IDS_PRESET_RULE_LOOPBACK_UDP, Proto::Udp, Dir::Out, {}, {}, aLoopback,
    {}, RuleAction::Allow, aLoopback
};
inline constexpr NetworkRule loopbackUdpIn = {
    IDS_PRESET_RULE_LOOPBACK_UDP, Proto::Udp, Dir::In, {}, {}, aLoopback,
    {}, RuleAction::Allow, aLoopback
};
inline constexpr NetworkRule winrmLoopback = {
    IDS_PRESET_RULE_WINRM_LOOPBACK, Proto::Tcp, Dir::Out, pWinrm, {}, aLoopback,
    {}, RuleAction::Allow, aLoopback
};
inline constexpr NetworkRule ssdpOut = {
    IDS_PRESET_RULE_SSDP, Proto::Udp, Dir::Out, pSsdp, {}, aDiscovery
};
inline constexpr NetworkRule ssdpIn = {
    IDS_PRESET_RULE_SSDP, Proto::Udp, Dir::In, {}, pSsdp, aDiscovery
};
inline constexpr NetworkRule wsdOut = {
    IDS_PRESET_RULE_WSD_OUT, Proto::Udp, Dir::Out, pWsd, {}, aDiscovery
};
inline constexpr NetworkRule wsdIn = {
    IDS_PRESET_RULE_WSD_IN, Proto::Udp, Dir::In, {}, pWsd, aDiscovery
};
inline constexpr NetworkRule wsdMetadata = {
    IDS_PRESET_RULE_WSD_METADATA, Proto::Tcp, Dir::Out, pWsdMetadata, {}, aLan
};
inline constexpr NetworkRule deliveryOut = {
    IDS_PRESET_RULE_DELIVERY, Proto::Tcp, Dir::Out, pDelivery, {}, aLan
};
inline constexpr NetworkRule deliveryIn = {
    IDS_PRESET_RULE_DELIVERY, Proto::Tcp, Dir::In, {}, pDelivery, aLan
};
inline constexpr NetworkRule steamTcp = {
    IDS_PRESET_RULE_STEAM_TCP, Proto::Tcp, Dir::Out, pSteamTcp
};
inline constexpr NetworkRule steamUdp = {
    IDS_PRESET_RULE_STEAM_UDP, Proto::Udp, Dir::Out, pSteamUdp
};

inline constexpr NetworkRule igmp[] = {
    { IDS_PRESET_RULE_IGMP, ProtoFromNumber(2), Dir::Out, {}, {}, aIgmpMulticast }
};
inline constexpr NetworkRule igmpIn[] = {
    { IDS_PRESET_RULE_IGMP, ProtoFromNumber(2), Dir::In, {}, {}, {}, {},
      RuleAction::Allow, aIgmpMulticast }
};
inline constexpr NetworkRule browserHttps[] = { https, quic, dnsUdp, dnsTcp };
inline constexpr NetworkRule web[] = { https, http, quic, dnsUdp, dnsTcp };
inline constexpr NetworkRule chromeMdns[] = {
    {IDS_PRESET_RULE_MDNS, Proto::Udp, Dir::Out, pMdns, pMdns, aMdns}
};
inline constexpr NetworkRule edgeMdns[] = {
    {IDS_PRESET_RULE_MDNS, Proto::Udp, Dir::Out, pMdns, pMdns}
};
inline constexpr NetworkRule chromePush[] = {
    {IDS_PRESET_RULE_GOOGLE_PUSH, Proto::Tcp, Dir::Out, pGooglePush}
};
inline constexpr NetworkRule firefoxHttps[] = { https, quic, dnsUdp, dnsTcp, loopbackTcp };
inline constexpr NetworkRule firefoxWeb[] = { https, http, quic, dnsUdp, dnsTcp, loopbackTcp };
inline constexpr NetworkRule braveHttps[] = { https, quic, dnsUdp, dnsTcp, mdnsOut, mdnsIn };
inline constexpr NetworkRule braveWeb[] = { https, http, quic, dnsUdp, dnsTcp, mdnsOut, mdnsIn };
inline constexpr NetworkRule mail[] = {
    https, dnsUdp, dnsTcp, {IDS_PRESET_RULE_MAIL, Proto::Tcp, Dir::Out, pMail}
};
inline constexpr NetworkRule chat[] = {
    https, http, quic, dnsUdp, dnsTcp,
    {IDS_PRESET_RULE_STUN, Proto::Udp, Dir::Out, pStun},
    {IDS_PRESET_RULE_ZOOM, Proto::Udp, Dir::Out, pZoom}
};
inline constexpr NetworkRule discord[] = {
    https, quic, dnsUdp, dnsTcp,
    {IDS_PRESET_RULE_STUN, Proto::Udp, Dir::Out, pStun},
    {IDS_PRESET_RULE_DISCORD_VOICE, Proto::Udp, Dir::Out, pDiscord}
};
inline constexpr NetworkRule discordHttp[] = { http };
inline constexpr NetworkRule telegram[] = {
    https, http, dnsUdp, dnsTcp,
    {IDS_PRESET_RULE_TELEGRAM, Proto::Tcp, Dir::Out, pTelegram}
};
inline constexpr NetworkRule steam[] = {
    https, http, quic, dnsUdp, dnsTcp, steamTcp, steamUdp, loopbackTcpIn
};
inline constexpr NetworkRule steamWebHelper[] = {
    https, http, quic, dnsUdp, dnsTcp, steamTcp, steamUdp,
    ssdpOut, ssdpIn, mdnsOut, mdnsIn, loopbackTcpOut
};
inline constexpr NetworkRule steamErrorReporter[] = { https };
inline constexpr NetworkRule nvidiaContainer[] = { https, loopbackUdpOut };
inline constexpr NetworkRule nvidiaDisplay[] = { https };
inline constexpr NetworkRule nvidiaApp[] = {
    {IDS_PRESET_RULE_DNS_UDP, Proto::Udp, Dir::Out, pDns, {}, aDoh},
    loopbackUdpIn, https, ssdpOut, quic, mdnsOut, mdnsIn
};
inline constexpr NetworkRule nvidiaNgxUpdate[] = { loopbackTcpOut, https };
inline constexpr NetworkRule lsassHttp[] = { http };
inline constexpr NetworkRule httpsOnly[] = { https };
inline constexpr NetworkRule httpOnly[] = { http };
inline constexpr NetworkRule httpsAndHttp[] = { https, http };
inline constexpr NetworkRule webview2[] = {
    https, quic, {IDS_PRESET_RULE_DNS_UDP, Proto::Udp, Dir::Out, pDns, {}, aDoh}
};
// mDNS ограничен показанными multicast-адресами и портами; DNS — системными серверами.
inline constexpr NetworkRule copilotApp[] = {
    {IDS_PRESET_RULE_DNS_UDP, Proto::Udp, Dir::Out, pDns, {}, aDoh},
    {IDS_PRESET_RULE_MDNS_OUT_IPV4, Proto::Udp, Dir::Out, pMdns, pMdns, aMdnsMulticast4},
    {IDS_PRESET_RULE_MDNS_OUT_IPV6, Proto::Udp, Dir::Out, pMdns, pMdns, aMdnsMulticast6},
    https,
    {IDS_PRESET_RULE_MDNS_IN_IPV4, Proto::Udp, Dir::In, {}, pMdns, {}, {},
        RuleAction::Allow, aMdnsMulticast4},
    {IDS_PRESET_RULE_MDNS_IN_IPV6, Proto::Udp, Dir::In, pMdns, pMdns, {}, {},
        RuleAction::Allow, aMdnsMulticast6},
    quic
};
// Локальный обмен ограничен точным IPv4-адресом на обоих концах.
inline constexpr NetworkRule obsStudio[] = { loopbackTcp4HostOut, https };
inline constexpr NetworkRule yandexDisk[] = { loopbackTcp4HostOut, https, http };
inline constexpr NetworkRule anyDesk[] = {
    https, http, {IDS_PRESET_RULE_DNS_UDP, Proto::Udp, Dir::Out, pDns, {}, aAnyDeskDns},
    {IDS_PRESET_RULE_ANYDESK_TCP, Proto::Tcp, Dir::Out, pAnyDesk}
};
inline constexpr NetworkRule rustDesk[] = {
    {IDS_PRESET_RULE_RUSTDESK_TCP_21116, Proto::Tcp, Dir::Out, pRustDesk21116},
    http, https,
    {IDS_PRESET_RULE_RUSTDESK_TCP_21115, Proto::Tcp, Dir::Out, pRustDesk21115},
    {IDS_PRESET_RULE_RUSTDESK_UDP_21116, Proto::Udp, Dir::Out, pRustDesk21116}
};
inline constexpr NetworkRule teamViewer[] = { loopbackTcp4HostOut, https };
// VMware использует точные адреса loopback на обоих концах, без привязки к портам.
inline constexpr NetworkRule vmwareAuthd[] = {
    {IDS_PRESET_RULE_LOOPBACK_TCP_IPV4, Proto::Tcp, Dir::Out, {}, {}, aLoopback4Host,
        {}, RuleAction::Allow, aLoopback4Host}
};
inline constexpr NetworkRule vmware[] = {
    vmwareAuthd[0],
    {IDS_PRESET_RULE_LOOPBACK_TCP_IPV6, Proto::Tcp, Dir::Out, {}, {}, aLoopback6Host,
        {}, RuleAction::Allow, aLoopback6Host}
};
// Сохраняем показанные адреса и парные порты mDNS без привязки к интерфейсу.
inline constexpr NetworkRule teamViewerService[] = {
    http, https, loopbackTcp4HostIn,
    {IDS_PRESET_RULE_TEAMVIEWER_TCP, Proto::Tcp, Dir::Out, pTeamViewer},
    {IDS_PRESET_RULE_MDNS_IN_IPV4, Proto::Udp, Dir::In, pMdns, pMdns, {}, {},
        RuleAction::Allow, aMdnsMulticast4},
    {IDS_PRESET_RULE_MDNS_OUT_IPV6, Proto::Udp, Dir::Out, pMdns, pMdns, aMdnsMulticast6, {},
        RuleAction::Allow, aLoopback6Host},
    {IDS_PRESET_RULE_MDNS_OUT_IPV4, Proto::Udp, Dir::Out, pMdns, pMdns, aMdnsMulticast4}
};
inline constexpr NetworkRule loopbackTcpOnly[] = { loopbackTcpOut };
inline constexpr NetworkRule loopbackUdpOnly[] = { loopbackUdpOut };
inline constexpr NetworkRule sharedAccessDhcp[] = {
    {IDS_PRESET_RULE_DHCP4, Proto::Udp, Dir::Out, pDhcp4Server, pDhcp4Client, aLimitedBroadcast},
    {IDS_PRESET_RULE_DHCP4_IN, Proto::Udp, Dir::In, pDhcp4Client, pDhcp4Server}
};
inline constexpr NetworkRule httpsBlock[] = {
    {IDS_PRESET_RULE_HTTPS, Proto::Tcp, Dir::Out, pHttps, {}, {}, {}, RuleAction::Block}
};
// Пиры, DHT и трекеры используют произвольные порты. Два правила покрывают
// также DNS, веб-трекеры и локальное обнаружение без дублирующих разрешений.
inline constexpr NetworkRule torrent[] = {
    {IDS_PRESET_RULE_TORRENT_TCP, Proto::Tcp, Dir::Unknown},
    {IDS_PRESET_RULE_TORRENT_UDP, Proto::Udp, Dir::Unknown}
};
inline constexpr NetworkRule git[] = {
    https, http, dnsUdp, dnsTcp,
    {IDS_PRESET_RULE_SSH, Proto::Tcp, Dir::Out, pSsh}
};
inline constexpr NetworkRule ssh[] = {
    dnsUdp, dnsTcp, {IDS_PRESET_RULE_SSH, Proto::Tcp, Dir::Out, pSsh}
};
inline constexpr NetworkRule rdpClient[] = {
    {IDS_PRESET_RULE_RDP_TCP, Proto::Tcp, Dir::Out, pRdp},
    {IDS_PRESET_RULE_RDP_UDP, Proto::Udp, Dir::Out, pRdp}, dnsUdp, dnsTcp
};
inline constexpr NetworkRule diagnostics[] = {
    {IDS_PRESET_RULE_ECHO4, Proto::Icmp, Dir::Out, {}, {}, {}, echo4},
    {IDS_PRESET_RULE_ECHO6, Proto::IcmpV6, Dir::Out, {}, {}, {}, echo6},
    {IDS_PRESET_RULE_ICMP4_REPLIES, Proto::Icmp, Dir::In, {}, {}, {}, replies4},
    {IDS_PRESET_RULE_ICMP6_REPLIES, Proto::IcmpV6, Dir::In, {}, {}, {}, replies6}
};
inline constexpr NetworkRule dns[] = {
    dnsUdp, dnsTcp,
    {IDS_PRESET_RULE_MDNS, Proto::Udp, Dir::Out, pMdns, {}, aMdns},
    {IDS_PRESET_RULE_LLMNR, Proto::Udp, Dir::Out, pLlmnr, {}, aLlmnr}, dnsDoh
};
inline constexpr NetworkRule dnsCacheMdns[] = {
    {IDS_PRESET_RULE_MDNS_IN, Proto::Udp, Dir::In, {}, pMdns, {}, {}, RuleAction::Allow, aMdnsMulticast4}
};
inline constexpr NetworkRule dhcp[] = { dhcp4, dhcp6, dhcp4In, dhcp6In };
inline constexpr NetworkRule dhcpClientPorts[] = {
    {IDS_PRESET_RULE_DHCP_CLIENT_PORTS, Proto::Udp, Dir::Unknown, pDhcp4Server, pDhcp4Client}
};
inline constexpr NetworkRule time[] = { ntp, dnsUdp, dnsTcp };
inline constexpr NetworkRule systemWeb[] = { https, http, dnsUdp, dnsTcp };
inline constexpr NetworkRule runtimeBroker[] = { https };
inline constexpr NetworkRule capabilityAccess[] = { http };
inline constexpr NetworkRule bits[] = { https, http, dnsUdp, dnsTcp, winrmLoopback };
inline constexpr NetworkRule braveUpdate[] = { https };
// LxpSvc: только HTTPS, без HTTP, QUIC и привязки к текущему IP сервера.
inline constexpr NetworkRule languagePacks[] = { https };
inline constexpr NetworkRule deliveryLan[] = { deliveryOut, deliveryIn };
inline constexpr NetworkRule deliveryFull[] = {
    https, http, dnsUdp, dnsTcp, deliveryOut, deliveryIn
};
inline constexpr NetworkRule ssdp[] = {
    ssdpOut, ssdpIn, {IDS_PRESET_RULE_UPNP, Proto::Tcp, Dir::In, {}, pUpnp, aLan}
};
inline constexpr NetworkRule discovery[] = { wsdOut, wsdIn };
// fdPHost ищет устройства и читает их метаданные, но не получает общий
// веб-доступ или разрешение на обнаружение узлов за пределами локальной сети.
inline constexpr NetworkRule functionDiscoveryHost[] = {
    wsdOut, wsdIn, ssdpOut, ssdpIn, wsdMetadata
};
inline constexpr NetworkRule smbClient[] = {
    {IDS_PRESET_RULE_SMB_OUT, Proto::Tcp, Dir::Out, pSmb, {}, aLan}
};
inline constexpr NetworkRule smbServer[] = {
    {IDS_PRESET_RULE_SMB_IN, Proto::Tcp, Dir::In, {}, pSmb, aLan}
};
inline constexpr NetworkRule printing[] = {
    {IDS_PRESET_RULE_PRINT, Proto::Tcp, Dir::Out, pPrint, {}, aLan}
};
inline constexpr NetworkRule rdpService[] = {
    {IDS_PRESET_RULE_RDP_TCP, Proto::Tcp, Dir::In, {}, pRdp, aLan},
    {IDS_PRESET_RULE_RDP_UDP, Proto::Udp, Dir::In, {}, pRdp, aLan}
};
inline constexpr NetworkRule svchost[] = {
    dnsUdp, dnsTcp, dhcp4, dhcp6, dhcp4In, dhcp6In, ntp, https, http
};
// SMB и UDP/443 ядра допускаются только внутри loopback с обеих сторон.
inline constexpr NetworkRule systemSmbLoopback[] = {
    {IDS_PRESET_RULE_SMB_OUT, Proto::Tcp, Dir::Out, pSmb, {}, aLoopback,
        {}, RuleAction::Allow, aLoopback},
    {IDS_PRESET_RULE_SMB_IN, Proto::Tcp, Dir::In, {}, pSmb, aLoopback,
        {}, RuleAction::Allow, aLoopback}
};
inline constexpr NetworkRule systemUdpLoopback[] = {
    {IDS_PRESET_RULE_LOOPBACK_HTTPS_UDP, Proto::Udp, Dir::Out, pHttps, {}, aLoopback,
        {}, RuleAction::Allow, aLoopback}
};
// Блокируем только исходящий NetBIOS ядра с парными портами, без привязки
// к адресу подсети: смена интерфейса не должна обходить блокировку.
inline constexpr NetworkRule netbiosBlock[] = {
    {IDS_PRESET_RULE_NETBIOS_NS_BLOCK, Proto::Udp, Dir::Out,
        pNetbiosNs, pNetbiosNs, {}, {}, RuleAction::Block},
    {IDS_PRESET_RULE_NETBIOS_DGM_BLOCK, Proto::Udp, Dir::Out,
        pNetbiosDgm, pNetbiosDgm, {}, {}, RuleAction::Block}
};

inline constexpr std::wstring_view browsers =
    L"chrome.exe;msedge.exe;opera.exe;vivaldi.exe;chromium.exe";
inline constexpr std::wstring_view torrentClients =
    L"qbittorrent.exe;qbittorrent-nox.exe;utorrent.exe;utweb.exe;bittorrent.exe;btweb.exe;"
    L"transmission-qt.exe;transmission-daemon.exe;transmission-cli.exe;"
    L"deluge.exe;deluge-gtk.exe;deluged.exe;tixati.exe;bitcomet.exe;bitcomet_x64.exe;"
    L"biglybt.exe;vuze.exe;azureus.exe;picotorrent.exe;halite.exe;tribler.exe;"
    L"frostwire.exe;webtorrent.exe;aria2c.exe;bitlord.exe;bitspirit.exe";

inline constexpr Preset presets[] = {
    {IDS_PRESET_BROWSER_HTTPS, browsers, browserHttps},
    {IDS_PRESET_BROWSER_WEB, browsers, web},
    {IDS_PRESET_CHROME_MDNS, L"chrome.exe", chromeMdns},
    {IDS_PRESET_CHROME_PUSH, L"chrome.exe", chromePush},
    {IDS_PRESET_EDGE_MDNS, L"msedge.exe", edgeMdns},
    {IDS_PRESET_BROWSER_HTTPS, L"firefox.exe", firefoxHttps},
    {IDS_PRESET_BROWSER_WEB, L"firefox.exe", firefoxWeb},
    {IDS_PRESET_BROWSER_HTTPS, L"brave.exe", braveHttps},
    {IDS_PRESET_BROWSER_WEB, L"brave.exe", braveWeb},
    {IDS_PRESET_BRAVE_UPDATE, L"BraveUpdate.exe", braveUpdate, Host::AppService, L"brave"},
    {IDS_PRESET_MAIL, L"outlook.exe;olk.exe;thunderbird.exe", mail},
    {IDS_PRESET_CHAT, L"ms-teams.exe;teams.exe;zoom.exe;slack.exe;skype.exe", chat},
    {IDS_PRESET_DISCORD, L"discord.exe;discordcanary.exe;discordptb.exe", discord},
    {IDS_PRESET_DISCORD_HTTP, L"discord.exe", discordHttp},
    {IDS_PRESET_OBS_STUDIO, L"obs64.exe", obsStudio},
    {IDS_PRESET_ANYDESK, L"AnyDesk.exe", anyDesk},
    {IDS_PRESET_RUSTDESK, L"RustDesk.exe", rustDesk},
    {IDS_PRESET_TEAMVIEWER, L"TeamViewer.exe", teamViewer},
    {IDS_PRESET_TEAMVIEWER_SERVICE, L"TeamViewer_Service.exe", teamViewerService,
        Host::AppService, L"TeamViewer"},
    {IDS_PRESET_VMWARE_AUTHD, L"vmware-authd.exe", vmwareAuthd, Host::AppService, L"VMAuthdService"},
    {IDS_PRESET_VMWARE, L"vmware.exe", vmware},
    {IDS_PRESET_TELEGRAM, L"telegram.exe", telegram},
    {IDS_PRESET_STEAM, L"steam.exe", steam},
    {IDS_PRESET_STEAM, L"steamwebhelper.exe", steamWebHelper},
    {IDS_PRESET_STEAM_ERROR_REPORTER, L"steamerrorreporter64.exe", steamErrorReporter},
    {IDS_PRESET_NVIDIA_CONTAINER, L"nvcontainer.exe", nvidiaContainer},
    {IDS_PRESET_NVIDIA_DISPLAY, L"nvdisplay.container.exe", nvidiaDisplay},
    {IDS_PRESET_NVIDIA_APP, L"NVIDIA App.exe", nvidiaApp},
    {IDS_PRESET_NVIDIA_NGX_UPDATE, L"nvngx_update.exe", nvidiaNgxUpdate},
    {IDS_PRESET_LSASS_HTTP, L"lsass.exe", lsassHttp,
        Host::SystemServiceGroup, L"KeyIso;SamSs"},
    {IDS_PRESET_TORRENT, torrentClients, torrent},
    {IDS_PRESET_CLOUD, L"onedrive.exe;dropbox.exe;googledrivefs.exe", browserHttps},
    {IDS_PRESET_ONEDRIVE_HTTP, L"OneDrive.exe", httpOnly},
    {IDS_PRESET_ONEDRIVE_SYNC, L"OneDrive.Sync.Service.exe", httpsOnly},
    {IDS_PRESET_ONEDRIVE_UPDATER, L"OneDriveUpdaterService.exe", httpsAndHttp,
        Host::AppService, L"OneDrive Updater Service"},
    {IDS_PRESET_YANDEX_DISK, L"YandexDisk4.exe", yandexDisk},
    {IDS_PRESET_MSI_INSTALLER, L"msiexec.exe", httpOnly, Host::AppService, L"msiserver"},
    {IDS_PRESET_WEB_TOOLS, L"curl.exe;wget.exe;winget.exe;code.exe", web},
    {IDS_PRESET_VISUAL_STUDIO_HTTPS, L"devenv.exe", httpsOnly},
    {IDS_PRESET_VISUAL_STUDIO_WEB, L"devenv.exe", httpsAndHttp},
    {IDS_PRESET_WINDOWS_PACKAGE_MANAGER, L"windowspackagemanagerserver.exe", systemWeb},
    {IDS_PRESET_MICROSOFT_STORE, L"winstore.app.exe", systemWeb},
    {IDS_PRESET_IGMP, L"", igmp, Host::PostAppPidZero},
    {IDS_PRESET_IGMP_IN, L"", igmpIn, Host::PostAppPidZero},
    {IDS_PRESET_RUNTIME_BROKER, L"RuntimeBroker.exe", runtimeBroker},
    {IDS_PRESET_WSL_SERVICE, L"wslservice.exe", httpsAndHttp, Host::AppService, L"WSLService"},
    {IDS_PRESET_TASK_HOST, L"taskhostw.exe", httpsOnly},
    {IDS_PRESET_APPHOST_VERIFIER, L"AppHostRegistrationVerifier.exe", httpsAndHttp},
    {IDS_PRESET_BACKGROUND_TASK_HOST, L"backgroundTaskHost.exe", httpsAndHttp},
    {IDS_PRESET_WWA_HOST, L"WWAHost.exe", httpsAndHttp},
    {IDS_PRESET_BACKGROUND_TRANSFER, L"BackgroundTransferHost.exe", httpsAndHttp},
    {IDS_PRESET_EXPLORER, L"explorer.exe", httpsAndHttp},
    {IDS_PRESET_MOUSO_CORE_WORKER, L"MoUsoCoreWorker.exe", httpsOnly},
    {IDS_PRESET_PING_SENDER, L"pingsender.exe", httpsOnly},
    {IDS_PRESET_SYSTEM_SETTINGS, L"SystemSettings.exe", httpsOnly},
    {IDS_PRESET_UC_CONFIG_TASK, L"UCConfigTask.exe", httpsOnly},
    {IDS_PRESET_GAMING_SERVICES, L"GamingServices.exe", httpsOnly,
        Host::AppService, L"GamingServices"},
    {IDS_PRESET_M365_COPILOT, L"M365Copilot.exe", httpsOnly},
    {IDS_PRESET_COPILOT_APP, L"CopilotApp.exe", copilotApp},
    {IDS_PRESET_DEFENDER_COMMAND, L"MpCmdRun.exe", httpsOnly},
    {IDS_PRESET_MSN_NEWS, L"Microsoft.Msn.News.exe", httpsAndHttp},
    {IDS_PRESET_MSN_WEATHER, L"Microsoft.Msn.Weather.exe", httpsAndHttp},
    {IDS_PRESET_MICROSOFT_NOTES, L"Microsoft.Notes.exe", httpsAndHttp},
    {IDS_PRESET_PHONE_EXPERIENCE, L"PhoneExperienceHost.exe", httpsOnly},
    {IDS_PRESET_SMARTSCREEN, L"smartscreen.exe", httpsOnly},
    {IDS_PRESET_WEB_EXPERIENCE, L"WebExperienceHostApp.exe", httpsAndHttp},
    {IDS_PRESET_WINDOWS_BACKUP, L"WindowsBackupClient.exe", httpsOnly},
    {IDS_PRESET_XBOX_PC_APP, L"XboxPcApp.exe", httpsAndHttp},
    {IDS_PRESET_XBOX_PC_APP_FT, L"XboxPcAppFT.exe", httpsOnly},
    {IDS_PRESET_WUDF_HOST, L"WUDFHost.exe", loopbackTcpOnly},
    {IDS_PRESET_EXCEL, L"EXCEL.EXE", httpsOnly},
    {IDS_PRESET_MSACCESS, L"MSACCESS.EXE", httpsOnly},
    {IDS_PRESET_WHITEBOARD, L"MicrosoftWhiteboard.exe", httpsOnly},
    {IDS_PRESET_HX_OUTLOOK, L"HxOutlook.exe", httpsAndHttp},
    {IDS_PRESET_PHOTOS, L"Photos.exe", httpsOnly},
    {IDS_PRESET_HX_CALENDAR, L"HxCalendarAppImm.exe", httpsOnly},
    {IDS_PRESET_START_MENU, L"StartMenuExperienceHost.exe", httpsAndHttp},
    {IDS_PRESET_XPD_AGENT, L"xpdAgent.exe", httpsOnly},
    {IDS_PRESET_TODO, L"Todo.exe", httpsAndHttp},
    {IDS_PRESET_CLIPCHAMP, L"Clipchamp.exe", httpsOnly},
    {IDS_PRESET_GAME_BAR, L"GameBar.exe", httpsAndHttp},
    {IDS_PRESET_INTEL_GRAPHICS, L"IntelGraphicsSoftware.exe", httpsOnly},
    {IDS_PRESET_INTEL_IPF, L"ipfsvc.exe", loopbackTcpOnly, Host::AppService, L"dttui;ipfui"},
    {IDS_PRESET_EDGE_UPDATE, L"MicrosoftEdgeUpdate.exe", httpsOnly},
    {IDS_PRESET_DEFENDER_CORE, L"MpDefenderCoreService.exe", httpsAndHttp,
        Host::AppService, L"MDCoreSvc"},
    {IDS_PRESET_TEAMS_UPDATE, L"ms-teamsupdate.exe", httpsOnly},
    {IDS_PRESET_WEBVIEW2, L"msedgewebview2.exe", webview2},
    {IDS_PRESET_OFFICE_CLIENT, L"OfficeC2RClient.exe", httpsOnly},
    {IDS_PRESET_OFFICE_SERVICE, L"OfficeClickToRun.exe", httpsAndHttp,
        Host::AppService, L"ClickToRunSvc"},
    {IDS_PRESET_ONENOTE, L"ONENOTE.EXE", httpsOnly},
    {IDS_PRESET_SEARCH_HOST, L"SearchHost.exe", httpsOnly},
    {IDS_PRESET_SOLITAIRE, L"Solitaire.exe", httpsAndHttp},
    {IDS_PRESET_GIT, L"git.exe;git-remote-https.exe;git-remote-http.exe", git},
    {IDS_PRESET_SSH, L"ssh.exe;putty.exe;winscp.exe;sftp.exe;scp.exe", ssh},
    {IDS_PRESET_RDP_CLIENT, L"mstsc.exe", rdpClient},
    {IDS_PRESET_DIAGNOSTICS, L"ping.exe;tracert.exe;pathping.exe", diagnostics},
    {IDS_PRESET_DNS, L"svchost.exe", dns, Host::Service, L"Dnscache"},
    {IDS_PRESET_DNSCACHE_MDNS, L"svchost.exe", dnsCacheMdns, Host::Service, L"Dnscache"},
    {IDS_PRESET_DHCP_CLIENT_PORTS, L"svchost.exe", dhcpClientPorts, Host::Service, L"Dhcp"},
    {IDS_PRESET_DHCP, L"svchost.exe", dhcp, Host::Service, L"Dhcp"},
    {IDS_PRESET_TIME, L"svchost.exe", time, Host::Service, L"W32Time"},
    {IDS_PRESET_WINDOWS_UPDATE, L"svchost.exe", systemWeb, Host::Service, L"wuauserv;UsoSvc"},
    {IDS_PRESET_INSTALL_SERVICE, L"svchost.exe", systemWeb, Host::Service, L"InstallService"},
    {IDS_PRESET_APPX_DEPLOYMENT, L"svchost.exe", systemWeb, Host::Service, L"AppXSvc"},
    {IDS_PRESET_LANGUAGE_PACKS, L"svchost.exe", languagePacks, Host::Service, L"LxpSvc"},
    {IDS_PRESET_CAPABILITY_ACCESS, L"svchost.exe", capabilityAccess, Host::Service, L"camsvc"},
    {IDS_PRESET_PUSH_SERVICE, L"svchost.exe", httpsOnly, Host::Service, L"WpnService"},
    {IDS_PRESET_PUSH_SERVICE, L"svchost.exe", httpsOnly, Host::Service, L"WpnUserService_*"},
    {IDS_PRESET_LICENSE_MANAGER, L"svchost.exe", httpsOnly, Host::Service, L"LicenseManager"},
    {IDS_PRESET_MICROSOFT_ACCOUNT, L"svchost.exe", httpsAndHttp, Host::Service, L"wlidsvc"},
    {IDS_PRESET_WAAS_MEDIC, L"svchost.exe", httpsOnly, Host::Service, L"WaaSMedicSvc"},
    {IDS_PRESET_DIAGTRACK_BLOCK, L"svchost.exe", httpsBlock, Host::Service, L"DiagTrack"},
    {IDS_PRESET_SHARED_ACCESS_DHCP, L"svchost.exe", sharedAccessDhcp, Host::Service, L"SharedAccess"},
    {IDS_PRESET_SSDP_LOOPBACK, L"svchost.exe", loopbackUdpOnly, Host::Service, L"SSDPSRV"},
    {IDS_PRESET_BITS, L"svchost.exe", bits, Host::Service, L"BITS"},
    {IDS_PRESET_DELIVERY_WEB, L"svchost.exe", systemWeb, Host::Service, L"DoSvc"},
    {IDS_PRESET_DELIVERY_LAN, L"svchost.exe", deliveryLan, Host::Service, L"DoSvc"},
    {IDS_PRESET_DELIVERY_FULL, L"svchost.exe", deliveryFull, Host::Service, L"DoSvc"},
    {IDS_PRESET_CERTIFICATES, L"svchost.exe", systemWeb, Host::Service, L"CryptSvc"},
    {IDS_PRESET_CONNECTIVITY, L"svchost.exe", systemWeb, Host::Service, L"NlaSvc;netprofm;NcbService"},
    {IDS_PRESET_SSDP, L"svchost.exe", ssdp, Host::Service, L"SSDPSRV;upnphost"},
    {IDS_PRESET_FUNCTION_DISCOVERY_HOST, L"svchost.exe", functionDiscoveryHost, Host::Service, L"fdPHost"},
    {IDS_PRESET_DISCOVERY, L"svchost.exe", discovery, Host::Service, L"FDResPub"},
    {IDS_PRESET_SMB_CLIENT, L"svchost.exe", smbClient, Host::Service, L"LanmanWorkstation"},
    {IDS_PRESET_SMB_SERVER, L"svchost.exe", smbServer, Host::Service, L"LanmanServer"},
    {IDS_PRESET_PRINTING, L"spoolsv.exe", printing, Host::Service, L"Spooler"},
    {IDS_PRESET_RDP_SERVICE, L"svchost.exe", rdpService, Host::Service, L"TermService"},
    {IDS_PRESET_SVCHOST, L"svchost.exe", svchost, Host::SvchostFallback},
    {IDS_PRESET_SYSTEM_SMB_LOOPBACK, L"ntoskrnl.exe", systemSmbLoopback, Host::System},
    {IDS_PRESET_SYSTEM_UDP_LOOPBACK, L"ntoskrnl.exe", systemUdpLoopback, Host::System},
    {IDS_PRESET_NETBIOS_BLOCK, L"ntoskrnl.exe", netbiosBlock, Host::System}
};

} // namespace RulePresets::Data
