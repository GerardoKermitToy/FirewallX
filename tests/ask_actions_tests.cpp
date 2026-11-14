#include "AskWindow.h"
#include "FlowStore.h"
#include "Ingest.h"
#include "RuleEditor.h"
#include <commctrl.h>
#include "RulePresetsData.h"
#include "Settings.h"
#include "StringRes.h"
#include "SystemInfo.h"
#include "UiKit.h"
#include "rule_editor_ui_tests.h"
#include "ingest_work_probe.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <tuple>
#include <unordered_map>

struct StorageTestAccess {
    static size_t MarkEndedConnectionsDue(FlowStore& store) {
        const ULONGLONG now = GetTickCount64();
        if (!now) return 0;
        size_t changed = 0;
        std::lock_guard<std::mutex> lock(store.mtx_);
        for (auto& process : store.processes_) {
            for (auto& item : process.second.connections) {
                auto& connection = item.second;
                if (!connection.endReceived || !connection.removeAfter) continue;
                connection.removeAfter = now;
                ++changed;
            }
        }
        return changed;
    }
};

namespace {

std::unordered_map<DWORD, ServiceInfo::HostedServices> hostedByPid;
size_t serviceReads = 0;
uint64_t serviceRefreshRequested = 0;
uint64_t serviceRefreshCompleted = 0;
bool deferServiceRefresh = false;
DriverVerdictSession* captureSession = nullptr;
std::vector<std::pair<uint64_t, pmkext::Verdict>> sentVerdicts;
size_t driverCacheClears = 0;
DWORD driverCacheClearStatus = ERROR_SUCCESS;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

IpAddr Ip(const wchar_t* text) {
    IpAddr address;
    Check(ParseIpAddr(text, address), "invalid test address");
    return address;
}

AskRequest Request(std::wstring path, Proto proto = Proto::Tcp, uint16_t remotePort = 443,
                   const wchar_t* remote = L"198.51.100.20") {
    AskRequest request;
    request.pid = GetCurrentProcessId();
    request.process = ProcessImagePathRef(request.pid)->process;
    request.appPath = std::move(path);
    request.appName = PathBaseUpper(request.appPath);
    request.dir = Dir::Out;
    request.key = MakeFlowKey(proto, Ip(L"192.0.2.10"), Ip(remote), 41000, remotePort);
    return request;
}

void SetServices(DWORD pid, std::initializer_list<const wchar_t*> names) {
    std::vector<ServiceEntry> services;
    for (const wchar_t* name : names) {
        ServiceEntry entry;
        entry.name = name;
        entry.display = name;
        entry.pid = pid;
        entry.state = SERVICE_RUNNING;
        services.push_back(std::move(entry));
    }
    hostedByPid[pid] = std::make_shared<const std::vector<ServiceEntry>>(std::move(services));
}

const RulePresets::Choice& ChoiceOf(const std::vector<RulePresets::Choice>& choices, UINT id) {
    const auto it = std::find_if(choices.begin(), choices.end(),
        [&](const RulePresets::Choice& choice) { return choice.titleId == id; });
    Check(it != choices.end(), "expected preset was not suggested");
    return *it;
}

bool HasString(UINT id, WORD language) {
    HMODULE module = GetModuleHandleW(nullptr);
    HRSRC resource = FindResourceExW(module, RT_STRING,
        MAKEINTRESOURCEW(id / 16 + 1), language);
    if (!resource) return false;
    const auto* data = static_cast<const wchar_t*>(LockResource(LoadResource(module, resource)));
    if (!data) return false;
    const wchar_t* end = data + SizeofResource(module, resource) / sizeof(wchar_t);
    for (UINT index = 0; index < id % 16; ++index) {
        if (data >= end) return false;
        data += 1 + *data;
    }
    return data < end && *data && data + 1 + *data <= end;
}

BOOL CALLBACK CollectStringTables(HMODULE, LPCWSTR, LPWSTR name, LONG_PTR param) {
    if (!IS_INTRESOURCE(name)) return FALSE;
    auto& blocks = *reinterpret_cast<std::vector<UINT>*>(param);
    blocks.push_back(static_cast<UINT>(reinterpret_cast<ULONG_PTR>(name)));
    return TRUE;
}

BOOL CALLBACK CollectStringLanguages(HMODULE, LPCWSTR, LPCWSTR, WORD language, LONG_PTR param) {
    auto& languages = *reinterpret_cast<std::vector<WORD>*>(param);
    languages.push_back(language);
    return TRUE;
}

void TestStringTableCoverage(const UiLangInfo* languages, size_t count) {
    HMODULE module = GetModuleHandleW(nullptr);
    std::vector<UINT> blocks;
    Check(EnumResourceNamesW(module, RT_STRING, CollectStringTables,
                            reinterpret_cast<LONG_PTR>(&blocks)) != FALSE && !blocks.empty(),
          "string table enumeration failed");
    for (UINT block : blocks) {
        std::vector<WORD> available;
        Check(EnumResourceLanguagesW(module, RT_STRING, MAKEINTRESOURCEW(block),
                                     CollectStringLanguages,
                                     reinterpret_cast<LONG_PTR>(&available)) != FALSE,
              "string table language enumeration failed");
        // Проверяем реальное наличие локали, чтобы fallback Win32 не скрыл пропуск.
        for (size_t i = 0; i < count; ++i) {
            Check(std::find(available.begin(), available.end(), languages[i].winLangId) != available.end(),
                  "missing localized string table");
            for (UINT offset = 0; offset < 16; ++offset) {
                const UINT id = (block - 1) * 16 + offset;
                if (HasString(id, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)))
                    Check(HasString(id, languages[i].winLangId), "missing interface or preset translation");
            }
        }
    }
}

void TestNewResources() {
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    Check(count == 34, "unexpected language count");
    TestStringTableCoverage(languages, count);
    for (size_t i = 0; i < count; ++i) {
        for (UINT id : {IDS_ACTION_ALLOW_ONCE, IDS_ACTION_BLOCK_ONCE,
                        IDS_ACTION_USE_PRESETS, IDS_ACTION_USE_PRESETS_DESC,
                        IDS_RED_PAYLOAD, IDS_RULE_PID_ZERO, IDS_COND_PID,
                        IDS_INHERITANCE_ENABLED, IDS_INHERITANCE_NEVER,
                        IDS_INHERITANCE_NOTE, IDS_INHERITANCE_SECTION,
                        IDS_SETTINGS_AUTO_CREATE_RULES, IDS_SETTINGS_AUTO_CREATE_RULES_TIP,
                        IDS_SETTINGS_AUTO_CREATE_RULES_SAVE_ERROR,
                        IDS_RULEN_PID_ZERO, IDS_EXPL_AND_PID, IDS_HINT_CLICK_PID_ANY,
                        IDS_HINT_CLICK_PID_ZERO, IDS_RED_POSTAPP_NOTE,
                        IDS_COND_INTERFACE, IDS_EXPL_AND_INTERFACE, IDS_RULEN_INTERFACE_FMT,
                        IDS_INTERFACE_FILTER_TITLE, IDS_INTERFACE_FILTER_NOTE,
                        IDS_INTERFACE_FILTER_NAME, IDS_INTERFACE_FILTER_ACTIVE,
                        IDS_INTERFACE_FILTER_UNAVAILABLE, IDS_INTERFACE_FILTER_INDEX_FMT,
                        IDS_INTERFACE_FILTER_IP_FMT, IDS_INTERFACE_FILTER_GATEWAY_FMT,
                        IDS_INTERFACE_FILTER_DNS_FMT, IDS_INTERFACE_FILTER_EMPTY,
                        IDS_APP_INTERFACE_BLOCK_OTHERS, IDS_APP_INTERFACE_OTHER_BLOCKED})
            Check(HasString(id, languages[i].winLangId), "missing action translation");
        for (UINT id = IDS_PRESET_OTHER; id <= IDS_PRESET_BRAVE_UPDATE; ++id)
            Check(HasString(id, languages[i].winLangId), "missing preset translation");
        for (UINT id : {IDS_PRESET_STEAM_ERROR_REPORTER, IDS_PRESET_CHROME_MDNS,
                        IDS_PRESET_CHROME_PUSH, IDS_PRESET_RULE_GOOGLE_PUSH,
                        IDS_PRESET_RUNTIME_BROKER, IDS_PRESET_CAPABILITY_ACCESS,
                        IDS_PRESET_NVIDIA_CONTAINER, IDS_PRESET_NVIDIA_DISPLAY,
                        IDS_PRESET_NVIDIA_APP, IDS_PRESET_NVIDIA_NGX_UPDATE,
                        IDS_PRESET_LSASS_HTTP, IDS_PRESET_RULE_LOOPBACK_UDP,
                        IDS_PRESET_SYSTEM_SMB_LOOPBACK, IDS_PRESET_SYSTEM_UDP_LOOPBACK,
                        IDS_PRESET_RULE_LOOPBACK_HTTPS_UDP})
            Check(HasString(id, languages[i].winLangId), "missing additional preset translation");
        for (UINT id = IDS_PRESET_CLIPCHAMP; id <= IDS_PRESET_STEAM_SERVICE; ++id)
            Check(HasString(id, languages[i].winLangId), "missing captured-connection preset translation");
        for (UINT id = IDS_PRESET_RULE_NAME_FMT; id <= IDS_PRESET_RULE_WINRM_LOOPBACK; ++id)
            Check(HasString(id, languages[i].winLangId), "missing preset rule translation");
    }

    // Наличие непустой строки не гарантирует правильную кодировку: проверяем
    // точный Unicode-текст после компиляции ресурсов, а не исходный .rc.
    struct Translation {
        UiLang language;
        const wchar_t* other;
        const wchar_t* browser;
        const wchar_t* dns;
        const wchar_t* mdnsOut;
        const wchar_t* mdnsIn;
        const wchar_t* loopback;
        const wchar_t* doh;
        const wchar_t* dhcp4In;
        const wchar_t* dhcp6In;
    };
    const Translation translations[] = {
        {UiLang::Russian, L"Другие...", L"Браузер: только HTTPS",
            L"DNS, UDP 53, настроенные серверы",
            L"Запросы mDNS, UDP 5353", L"Приём mDNS, UDP 5353",
            L"Локальные соединения (loopback), TCP",
            L"DoH, TCP 443, настроенные DNS-серверы",
            L"Приём DHCPv4, UDP 68 → 67", L"Приём DHCPv6, UDP 546 → 547"},
        {UiLang::English, L"Other...", L"Browser: HTTPS only",
            L"DNS, UDP 53, configured servers",
            L"mDNS requests, UDP 5353", L"mDNS reception, UDP 5353",
            L"Local connections (loopback), TCP",
            L"DoH, TCP 443, configured DNS servers",
            L"DHCPv4 reception, UDP 68 → 67", L"DHCPv6 reception, UDP 546 → 547"},
        {UiLang::Korean, L"기타...", L"브라우저: HTTPS만 허용",
            L"DNS, UDP 53, 구성된 서버",
            L"mDNS 요청, UDP 5353", L"mDNS 수신, UDP 5353",
            L"로컬 연결(루프백), TCP",
            L"DoH, TCP 443, 구성된 DNS 서버",
            L"DHCPv4 수신, UDP 68 → 67", L"DHCPv6 수신, UDP 546 → 547"},
        {UiLang::Chinese, L"其他...", L"浏览器：仅限 HTTPS",
            L"DNS，UDP 53，已配置的服务器",
            L"mDNS 请求，UDP 5353", L"mDNS 接收，UDP 5353",
            L"本机连接（环回），TCP",
            L"DoH，TCP 443，已配置的 DNS 服务器",
            L"DHCPv4 接收，UDP 68 → 67", L"DHCPv6 接收，UDP 546 → 547"},
        {UiLang::Ukrainian, L"Інші...", L"Браузер: лише HTTPS",
            L"DNS, UDP 53, налаштовані сервери",
            L"Запити mDNS, UDP 5353", L"Приймання mDNS, UDP 5353",
            L"Локальні з’єднання (loopback), TCP",
            L"DoH, TCP 443, налаштовані DNS-сервери",
            L"Приймання DHCPv4, UDP 68 → 67", L"Приймання DHCPv6, UDP 546 → 547"},
        {UiLang::German, L"Weitere...", L"Browser: nur HTTPS",
            L"DNS, UDP 53, konfigurierte Server",
            L"mDNS-Anfragen, UDP 5353", L"mDNS-Empfang, UDP 5353",
            L"Lokale Verbindungen (Loopback), TCP",
            L"DoH, TCP 443, konfigurierte DNS-Server",
            L"DHCPv4-Empfang, UDP 68 → 67", L"DHCPv6-Empfang, UDP 546 → 547"},
        {UiLang::French, L"Autres...", L"Navigateur : HTTPS uniquement",
            L"DNS, UDP 53, serveurs configurés",
            L"Requêtes mDNS, UDP 5353", L"Réception mDNS, UDP 5353",
            L"Connexions locales (bouclage), TCP",
            L"DoH, TCP 443, serveurs DNS configurés",
            L"Réception DHCPv4, UDP 68 → 67", L"Réception DHCPv6, UDP 546 → 547"},
        {UiLang::Spanish, L"Otros...", L"Navegador: solo HTTPS",
            L"DNS, UDP 53, servidores configurados",
            L"Solicitudes de mDNS, UDP 5353", L"Recepción de mDNS, UDP 5353",
            L"Conexiones locales (bucle local), TCP",
            L"DoH, TCP 443, servidores DNS configurados",
            L"Recepción de DHCPv4, UDP 68 → 67", L"Recepción de DHCPv6, UDP 546 → 547"},
        {UiLang::Arabic, L"أخرى...", L"المتصفح: HTTPS فقط",
            L"DNS، UDP 53، الخوادم المضبوطة",
            L"طلبات mDNS، UDP 5353", L"استقبال mDNS، UDP 5353",
            L"اتصالات محلية (استرجاع)، TCP",
            L"DoH، TCP 443، خوادم DNS المضبوطة",
            L"استقبال DHCPv4، UDP 68 → 67", L"استقبال DHCPv6، UDP 546 → 547"},
        {UiLang::Hindi, L"अन्य...", L"ब्राउज़र: केवल HTTPS",
            L"DNS, UDP 53, कॉन्फ़िगर किए गए सर्वर",
            L"mDNS अनुरोध, UDP 5353", L"mDNS प्राप्ति, UDP 5353",
            L"स्थानीय कनेक्शन (लूपबैक), TCP",
            L"DoH, TCP 443, कॉन्फ़िगर किए गए DNS सर्वर",
            L"DHCPv4 प्राप्ति, UDP 68 → 67", L"DHCPv6 प्राप्ति, UDP 546 → 547"},
        {UiLang::Latvian, L"Citi...", L"Pārlūks: tikai HTTPS",
            L"DNS, UDP 53, konfigurētie serveri",
            L"mDNS pieprasījumi, UDP 5353", L"mDNS saņemšana, UDP 5353",
            L"Lokālie savienojumi (atgriezeniskā cilpa), TCP",
            L"DoH, TCP 443, konfigurētie DNS serveri",
            L"DHCPv4 saņemšana, UDP 68 → 67", L"DHCPv6 saņemšana, UDP 546 → 547"},
        {UiLang::Lithuanian, L"Kiti...", L"Naršyklė: tik HTTPS",
            L"DNS, UDP 53, sukonfigūruoti serveriai",
            L"mDNS užklausos, UDP 5353", L"mDNS gavimas, UDP 5353",
            L"Vietiniai ryšiai (grįžtamasis ryšys), TCP",
            L"DoH, TCP 443, sukonfigūruoti DNS serveriai",
            L"DHCPv4 gavimas, UDP 68 → 67", L"DHCPv6 gavimas, UDP 546 → 547"},
        {UiLang::Estonian, L"Muud...", L"Brauser: ainult HTTPS",
            L"DNS, UDP 53, seadistatud serverid",
            L"mDNS päringud, UDP 5353", L"mDNS vastuvõtt, UDP 5353",
            L"Kohalikud ühendused (tagasiside), TCP",
            L"DoH, TCP 443, seadistatud DNS-serverid",
            L"DHCPv4 vastuvõtt, UDP 68 → 67", L"DHCPv6 vastuvõtt, UDP 546 → 547"},
        {UiLang::Romanian, L"Altele...", L"Browser: numai HTTPS",
            L"DNS, UDP 53, servere configurate",
            L"Solicitări mDNS, UDP 5353", L"Recepție mDNS, UDP 5353",
            L"Conexiuni locale (buclă locală), TCP",
            L"DoH, TCP 443, servere DNS configurate",
            L"Recepție DHCPv4, UDP 68 → 67", L"Recepție DHCPv6, UDP 546 → 547"},
        {UiLang::Swedish, L"Övriga...", L"Webbläsare: endast HTTPS",
            L"DNS, UDP 53, konfigurerade servrar",
            L"mDNS-förfrågningar, UDP 5353", L"mDNS-mottagning, UDP 5353",
            L"Lokala anslutningar (loopback), TCP",
            L"DoH, TCP 443, konfigurerade DNS-servrar",
            L"DHCPv4-mottagning, UDP 68 → 67", L"DHCPv6-mottagning, UDP 546 → 547"},
        {UiLang::Polish, L"Inne...", L"Przeglądarka: tylko HTTPS",
            L"DNS, UDP 53, skonfigurowane serwery",
            L"Żądania mDNS, UDP 5353", L"Odbiór mDNS, UDP 5353",
            L"Połączenia lokalne (pętla zwrotna), TCP",
            L"DoH, TCP 443, skonfigurowane serwery DNS",
            L"Odbiór DHCPv4, UDP 68 → 67", L"Odbiór DHCPv6, UDP 546 → 547"},
        {UiLang::Vietnamese, L"Khác...", L"Trình duyệt: chỉ HTTPS",
            L"DNS, UDP 53, máy chủ đã cấu hình",
            L"Yêu cầu mDNS, UDP 5353", L"Nhận mDNS, UDP 5353",
            L"Kết nối cục bộ (vòng lặp), TCP",
            L"DoH, TCP 443, máy chủ DNS đã cấu hình",
            L"Nhận DHCPv4, UDP 68 → 67", L"Nhận DHCPv6, UDP 546 → 547"},
        {UiLang::Portuguese, L"Outras...", L"Navegador: apenas HTTPS",
            L"DNS, UDP 53, servidores configurados",
            L"Pedidos mDNS, UDP 5353", L"Receção mDNS, UDP 5353",
            L"Ligações locais (loopback), TCP",
            L"DoH, TCP 443, servidores DNS configurados",
            L"Receção DHCPv4, UDP 68 → 67", L"Receção DHCPv6, UDP 546 → 547"},
        {UiLang::Italian, L"Altre...", L"Browser: solo HTTPS",
            L"DNS, UDP 53, server configurati",
            L"Richieste mDNS, UDP 5353", L"Ricezione mDNS, UDP 5353",
            L"Connessioni locali (loopback), TCP",
            L"DoH, TCP 443, server DNS configurati",
            L"Ricezione DHCPv4, UDP 68 → 67", L"Ricezione DHCPv6, UDP 546 → 547"},
        {UiLang::Persian, L"سایر...", L"مرورگر: فقط HTTPS",
            L"DNS، UDP 53، سرورهای پیکربندی‌شده",
            L"درخواست‌های mDNS، UDP 5353", L"دریافت mDNS، UDP 5353",
            L"اتصال‌های محلی (حلقهٔ بازگشت)، TCP",
            L"DoH، TCP 443، سرورهای DNS پیکربندی‌شده",
            L"دریافت DHCPv4، UDP 68 → 67", L"دریافت DHCPv6، UDP 546 → 547"},
        {UiLang::Japanese, L"その他...",
            L"ブラウザー: HTTPS のみ",
            L"DNS、UDP 53、設定済みサーバー",
            L"mDNS 要求、UDP 5353",
            L"mDNS 受信、UDP 5353",
            L"ローカル接続（ループバック）、TCP",
            L"DoH、TCP 443、設定済み DNS サーバー",
            L"DHCPv4 受信、UDP 68 → 67",
            L"DHCPv6 受信、UDP 546 → 547"},
        {UiLang::Turkish, L"Diğer...",
            L"Tarayıcı: yalnızca HTTPS",
            L"DNS, UDP 53, yapılandırılmış sunucular",
            L"mDNS istekleri, UDP 5353",
            L"mDNS alımı, UDP 5353",
            L"Yerel bağlantılar (geri döngü), TCP",
            L"DoH, TCP 443, yapılandırılmış DNS sunucuları",
            L"DHCPv4 alımı, UDP 68 → 67",
            L"DHCPv6 alımı, UDP 546 → 547"},
        {UiLang::Indonesian, L"Lainnya...",
            L"Peramban: hanya HTTPS",
            L"DNS, UDP 53, server yang dikonfigurasi",
            L"Permintaan mDNS, UDP 5353",
            L"Penerimaan mDNS, UDP 5353",
            L"Koneksi lokal (loopback), TCP",
            L"DoH, TCP 443, server DNS yang dikonfigurasi",
            L"Penerimaan DHCPv4, UDP 68 → 67",
            L"Penerimaan DHCPv6, UDP 546 → 547"},
        {UiLang::Czech, L"Jiné...",
            L"Prohlížeč: pouze HTTPS",
            L"DNS, UDP 53, nastavené servery",
            L"Požadavky mDNS, UDP 5353",
            L"Příjem mDNS, UDP 5353",
            L"Místní spojení (loopback), TCP",
            L"DoH, TCP 443, nastavené servery DNS",
            L"Příjem DHCPv4, UDP 68 → 67",
            L"Příjem DHCPv6, UDP 546 → 547"},
        {UiLang::Thai, L"อื่น ๆ...",
            L"เบราว์เซอร์: เฉพาะ HTTPS",
            L"DNS, UDP 53, เซิร์ฟเวอร์ที่กำหนดไว้",
            L"คำขอ mDNS, UDP 5353",
            L"การรับ mDNS, UDP 5353",
            L"การเชื่อมต่อภายใน (ลูปแบ็ก), TCP",
            L"DoH, TCP 443, เซิร์ฟเวอร์ DNS ที่กำหนดไว้",
            L"การรับ DHCPv4, UDP 68 → 67",
            L"การรับ DHCPv6, UDP 546 → 547"},
        {UiLang::PortugueseBrazil, L"Outras...",
            L"Navegador: apenas HTTPS",
            L"DNS, UDP 53, servidores configurados",
            L"Solicitações mDNS, UDP 5353",
            L"Receção mDNS, UDP 5353",
            L"Conexões locais (loopback), TCP",
            L"DoH, TCP 443, servidores DNS configurados",
            L"Receção DHCPv4, UDP 68 → 67",
            L"Receção DHCPv6, UDP 546 → 547"},
        {UiLang::ChineseTraditional, L"其他...",
            L"瀏覽器：僅限 HTTPS",
            L"DNS，UDP 53，已設定的伺服器",
            L"mDNS 要求，UDP 5353",
            L"mDNS 接收，UDP 5353",
            L"本機連線（回送），TCP",
            L"DoH，TCP 443，已設定的 DNS 伺服器",
            L"DHCPv4 接收，UDP 68 → 67",
            L"DHCPv6 接收，UDP 546 → 547"},
        {UiLang::Hungarian, L"Egyéb...",
            L"Böngésző: csak HTTPS",
            L"DNS, UDP 53, beállított kiszolgálók",
            L"mDNS-kérések, UDP 5353",
            L"mDNS-fogadás, UDP 5353",
            L"Helyi kapcsolatok (visszacsatolás), TCP",
            L"DoH, TCP 443, beállított DNS-kiszolgálók",
            L"DHCPv4-fogadás, UDP 68 → 67",
            L"DHCPv6-fogadás, UDP 546 → 547"},
        {UiLang::Greek, L"Άλλο...",
            L"Περιηγητής: μόνο HTTPS",
            L"DNS, UDP 53, ρυθμισμένοι διακομιστές",
            L"Αιτήματα mDNS, UDP 5353",
            L"Λήψη mDNS, UDP 5353",
            L"Τοπικές συνδέσεις (βρόχος επιστροφής), TCP",
            L"DoH, TCP 443, ρυθμισμένοι διακομιστές DNS",
            L"Λήψη DHCPv4, UDP 68 → 67",
            L"Λήψη DHCPv6, UDP 546 → 547"},
        {UiLang::Dutch, L"Andere...",
            L"Browser: alleen HTTPS",
            L"DNS, UDP 53, ingestelde servers",
            L"mDNS-aanvragen, UDP 5353",
            L"mDNS-ontvangst, UDP 5353",
            L"Lokale verbindingen (loopback), TCP",
            L"DoH, TCP 443, ingestelde DNS-servers",
            L"DHCPv4-ontvangst, UDP 68 → 67",
            L"DHCPv6-ontvangst, UDP 546 → 547"},
        {UiLang::Bulgarian, L"Други...",
            L"Браузър: само HTTPS",
            L"DNS, UDP 53, зададени сървъри",
            L"mDNS заявки, UDP 5353",
            L"Приемане на mDNS, UDP 5353",
            L"Локални връзки (loopback), TCP",
            L"DoH, TCP 443, зададени DNS сървъри",
            L"Приемане на DHCPv4, UDP 68 → 67",
            L"Приемане на DHCPv6, UDP 546 → 547"},
        {UiLang::Danish, L"Andre...",
            L"Browser: kun HTTPS",
            L"DNS, UDP 53, konfigurerede servere",
            L"mDNS-anmodninger, UDP 5353",
            L"mDNS-modtagelse, UDP 5353",
            L"Lokale forbindelser (loopback), TCP",
            L"DoH, TCP 443, konfigurerede DNS-servere",
            L"DHCPv4-modtagelse, UDP 68 → 67",
            L"DHCPv6-modtagelse, UDP 546 → 547"},
        {UiLang::NorwegianBokmal, L"Andre...",
            L"Nettleser: bare HTTPS",
            L"DNS, UDP 53, konfigurerte tjenere",
            L"mDNS-forespørsler, UDP 5353",
            L"mDNS-mottak, UDP 5353",
            L"Lokale tilkoblinger (loopback), TCP",
            L"DoH, TCP 443, konfigurerte DNS-tjenere",
            L"DHCPv4-mottak, UDP 68 → 67",
            L"DHCPv6-mottak, UDP 546 → 547"},
        {UiLang::Finnish, L"Muut...",
            L"Selain: vain HTTPS",
            L"DNS, UDP 53, määritetyt palvelimet",
            L"mDNS-pyynnöt, UDP 5353",
            L"mDNS-vastaanotto, UDP 5353",
            L"Paikalliset yhteydet (takaisinkytkentä), TCP",
            L"DoH, TCP 443, määritetyt DNS-palvelimet",
            L"DHCPv4-vastaanotto, UDP 68 → 67",
            L"DHCPv6-vastaanotto, UDP 546 → 547"},
    };
    const UiLang previous = CurrentUiLang();
    for (const Translation& translation : translations) {
        SetUiLang(translation.language);
        const std::wstring autoTip = LoadStringRes(IDS_SETTINGS_AUTO_CREATE_RULES_TIP);
        Check(!autoTip.empty() && autoTip.find(L"IGMP") == std::wstring::npos,
              "automatic rule tooltip is empty or mentions IGMP");
        Check(LoadStringRes(IDS_RDS_EXTRA_LABEL).find(L'*') != std::wstring::npos,
              "service wildcard hint is missing from a translation");
        Check(LoadStringRes(IDS_PRESET_OTHER) == translation.other,
              "preset Other text was decoded with the wrong code page");
        Check(LoadStringRes(IDS_PRESET_BROWSER_HTTPS) == translation.browser,
              "preset title text was decoded with the wrong code page");
        Check(LoadStringRes(IDS_PRESET_RULE_DNS_UDP) == translation.dns,
              "preset rule text was decoded with the wrong code page");
        Check(LoadStringRes(IDS_PRESET_RULE_MDNS_OUT) == translation.mdnsOut &&
              LoadStringRes(IDS_PRESET_RULE_MDNS_IN) == translation.mdnsIn,
              "mDNS rule text was decoded with the wrong code page");
        std::wstring incomingIgmp = translation.mdnsIn;
        const size_t mdns = incomingIgmp.find(L"mDNS");
        Check(mdns != std::wstring::npos, "mDNS translation omitted its protocol");
        incomingIgmp.replace(mdns, 4, L"IGMP");
        const size_t separator = incomingIgmp.find_first_of(L",，、،");
        Check(separator != std::wstring::npos, "mDNS translation omitted its port separator");
        incomingIgmp.erase(separator);
        incomingIgmp += L" (PID 0)";
        Check(LoadStringRes(IDS_PRESET_IGMP_IN) == incomingIgmp,
              "incoming IGMP preset translation was decoded incorrectly");
        Check(LoadStringRes(IDS_PRESET_RULE_LOOPBACK_TCP) == translation.loopback,
              "loopback rule text was decoded with the wrong code page");
        Check(LoadStringRes(IDS_PRESET_RULE_DOH) == translation.doh &&
              LoadStringRes(IDS_PRESET_RULE_DHCP4_IN) == translation.dhcp4In &&
              LoadStringRes(IDS_PRESET_RULE_DHCP6_IN) == translation.dhcp6In,
              "DoH/DHCP rule text was decoded with the wrong code page");
        Check(LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, L"one", L"two") == L"one — two",
              "preset rule name separator was decoded with the wrong code page");
    }
    struct StoreServiceTranslation {
        UiLang language;
        const wchar_t* install;
        const wchar_t* appx;
    };
    const StoreServiceTranslation storeServices[] = {
        {UiLang::Russian, L"Служба установки Microsoft Store", L"Служба развёртывания AppX"},
        {UiLang::English, L"Microsoft Store Install Service", L"AppX Deployment Service"},
        {UiLang::Korean, L"Microsoft Store 설치 서비스", L"AppX 배포 서비스"},
        {UiLang::Chinese, L"Microsoft Store 安装服务", L"AppX 部署服务"},
        {UiLang::Ukrainian, L"Служба інсталяції Microsoft Store", L"Служба розгортання AppX"},
        {UiLang::German, L"Microsoft Store-Installationsdienst", L"AppX-Bereitstellungsdienst"},
        {UiLang::French, L"Service d’installation du Microsoft Store", L"Service de déploiement AppX"},
        {UiLang::Spanish, L"Servicio de instalación de Microsoft Store", L"Servicio de implementación de AppX"},
        {UiLang::Arabic, L"خدمة تثبيت Microsoft Store", L"خدمة نشر AppX"},
        {UiLang::Hindi, L"Microsoft Store इंस्टॉल सेवा", L"AppX परिनियोजन सेवा"},
        {UiLang::Latvian, L"Microsoft Store instalēšanas pakalpojums", L"AppX izvietošanas pakalpojums"},
        {UiLang::Lithuanian, L"Microsoft Store diegimo tarnyba", L"AppX diegimo tarnyba"},
        {UiLang::Estonian, L"Microsoft Store’i installimisteenus", L"AppX-i juurutusteenus"},
        {UiLang::Romanian, L"Serviciul de instalare Microsoft Store", L"Serviciul de implementare AppX"},
        {UiLang::Swedish, L"Installationstjänst för Microsoft Store", L"AppX-distributionstjänst"},
        {UiLang::Polish, L"Usługa instalacji Microsoft Store", L"Usługa wdrażania AppX"},
        {UiLang::Vietnamese, L"Dịch vụ cài đặt Microsoft Store", L"Dịch vụ triển khai AppX"},
        {UiLang::Portuguese, L"Serviço de Instalação do Microsoft Store", L"Serviço de Implementação de AppX"},
        {UiLang::Italian, L"Servizio di installazione di Microsoft Store", L"Servizio di distribuzione AppX"},
        {UiLang::Persian, L"سرویس نصب Microsoft Store", L"سرویس استقرار AppX"},
        {UiLang::Japanese, L"Microsoft Store インストールサービス", L"AppX 展開サービス"},
        {UiLang::Turkish, L"Microsoft Store Yükleme Hizmeti", L"AppX Dağıtım Hizmeti"},
        {UiLang::Indonesian, L"Layanan Penginstalan Microsoft Store", L"Layanan Penyebaran AppX"},
        {UiLang::Czech, L"Instalační služba Microsoft Store", L"Služba nasazování AppX"},
        {UiLang::Thai, L"บริการติดตั้ง Microsoft Store", L"บริการปรับใช้ AppX"},
        {UiLang::PortugueseBrazil, L"Serviço de Instalação do Microsoft Store", L"Serviço de Implantação de AppX"},
        {UiLang::ChineseTraditional, L"Microsoft Store 安裝服務", L"AppX 部署服務"},
        {UiLang::Hungarian, L"Microsoft Store telepítési szolgáltatás", L"AppX telepítési szolgáltatás"},
        {UiLang::Greek, L"Υπηρεσία εγκατάστασης Microsoft Store", L"Υπηρεσία ανάπτυξης AppX"},
        {UiLang::Dutch, L"Microsoft Store-installatieservice", L"AppX-implementatieservice"},
        {UiLang::Bulgarian, L"Услуга за инсталиране на Microsoft Store", L"Услуга за разполагане на AppX"},
        {UiLang::Danish, L"Microsoft Store-installationstjeneste", L"AppX-installationstjeneste"},
        {UiLang::NorwegianBokmal, L"Microsoft Store-installasjonstjeneste", L"AppX-distribusjonstjeneste"},
        {UiLang::Finnish, L"Microsoft Storen asennuspalvelu", L"AppX-käyttöönottopalvelu"},
    };
    Check(std::size(storeServices) == count, "missing Store service translation test");
    for (const auto& translation : storeServices) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_PRESET_INSTALL_SERVICE) == translation.install &&
              LoadStringRes(IDS_PRESET_APPX_DEPLOYMENT) == translation.appx,
              "Store service title was decoded with the wrong code page");
    }
    struct StoreAppTranslation {
        UiLang language;
        const wchar_t* manager;
        const wchar_t* store;
    };
    const StoreAppTranslation storeApps[] = {
        {UiLang::Russian, L"Диспетчер пакетов Windows", L"Microsoft Store: магазин и загрузки"},
        {UiLang::English, L"Windows Package Manager", L"Microsoft Store: store and downloads"},
        {UiLang::Korean, L"Windows 패키지 관리자", L"Microsoft Store: 스토어 및 다운로드"},
        {UiLang::Chinese, L"Windows 程序包管理器", L"Microsoft Store：商店和下载"},
        {UiLang::Ukrainian, L"Диспетчер пакетів Windows", L"Microsoft Store: магазин і завантаження"},
        {UiLang::German, L"Windows-Paket-Manager", L"Microsoft Store: Shop und Downloads"},
        {UiLang::French, L"Gestionnaire de paquets Windows", L"Microsoft Store : boutique et téléchargements"},
        {UiLang::Spanish, L"Administrador de paquetes de Windows", L"Microsoft Store: tienda y descargas"},
        {UiLang::Arabic, L"مدير حزم Windows", L"Microsoft Store: المتجر والتنزيلات"},
        {UiLang::Hindi, L"Windows पैकेज प्रबंधक", L"Microsoft Store: स्टोर और डाउनलोड"},
        {UiLang::Latvian, L"Windows pakotņu pārvaldnieks", L"Microsoft Store: veikals un lejupielādes"},
        {UiLang::Lithuanian, L"Windows paketų tvarkytuvė", L"Microsoft Store: parduotuvė ir atsisiuntimai"},
        {UiLang::Estonian, L"Windowsi paketihaldur", L"Microsoft Store: pood ja allalaadimised"},
        {UiLang::Romanian, L"Manager de pachete Windows", L"Microsoft Store: magazin și descărcări"},
        {UiLang::Swedish, L"Pakethanteraren för Windows", L"Microsoft Store: butik och nedladdningar"},
        {UiLang::Polish, L"Menedżer pakietów Windows", L"Microsoft Store: sklep i pobieranie"},
        {UiLang::Vietnamese, L"Trình quản lý gói Windows", L"Microsoft Store: cửa hàng và tải xuống"},
        {UiLang::Portuguese, L"Gestor de Pacotes do Windows", L"Microsoft Store: loja e transferências"},
        {UiLang::Italian, L"Gestione pacchetti di Windows", L"Microsoft Store: negozio e download"},
        {UiLang::Persian, L"مدیر بستهٔ Windows", L"Microsoft Store: فروشگاه و بارگیری‌ها"},
        {UiLang::Japanese, L"Windows パッケージマネージャー", L"Microsoft Store: ストアとダウンロード"},
        {UiLang::Turkish, L"Windows Paket Yöneticisi", L"Microsoft Store: mağaza ve indirmeler"},
        {UiLang::Indonesian, L"Manajer Paket Windows", L"Microsoft Store: toko dan unduhan"},
        {UiLang::Czech, L"Správce balíčků Windows", L"Microsoft Store: obchod a stahování"},
        {UiLang::Thai, L"ตัวจัดการแพ็กเกจ Windows", L"Microsoft Store: ร้านค้าและดาวน์โหลด"},
        {UiLang::PortugueseBrazil, L"Gerenciador de Pacotes do Windows", L"Microsoft Store: loja e downloads"},
        {UiLang::ChineseTraditional, L"Windows 套件管理器", L"Microsoft Store：商店和下載"},
        {UiLang::Hungarian, L"Windows csomagkezelő", L"Microsoft Store: áruház és letöltések"},
        {UiLang::Greek, L"Διαχείριση πακέτων Windows", L"Microsoft Store: κατάστημα και λήψεις"},
        {UiLang::Dutch, L"Windows-pakketbeheer", L"Microsoft Store: winkel en downloads"},
        {UiLang::Bulgarian, L"Диспечер на пакети на Windows", L"Microsoft Store: магазин и изтегляния"},
        {UiLang::Danish, L"Windows-pakkehåndtering", L"Microsoft Store: butik og downloads"},
        {UiLang::NorwegianBokmal, L"Windows-pakkebehandling", L"Microsoft Store: butikk og nedlastinger"},
        {UiLang::Finnish, L"Windowsin paketinhallinta", L"Microsoft Store: kauppa ja lataukset"},
    };
    Check(std::size(storeApps) == count, "missing Store application translation test");
    for (const auto& translation : storeApps) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_PRESET_WINDOWS_PACKAGE_MANAGER) == translation.manager &&
              LoadStringRes(IDS_PRESET_MICROSOFT_STORE) == translation.store,
              "Store application title was decoded with the wrong code page");
    }
    struct TorrentTranslation {
        UiLang language;
        const wchar_t* title;
        const wchar_t* tcp;
        const wchar_t* udp;
    };
    const TorrentTranslation torrents[] = {
        {UiLang::Russian, L"Торрент-клиент: TCP/UDP, все порты",
            L"BitTorrent, TCP, все порты (оба направления)",
            L"BitTorrent/DHT, UDP, все порты (оба направления)"},
        {UiLang::English, L"Torrent client: TCP/UDP, all ports",
            L"BitTorrent, TCP, all ports (both directions)",
            L"BitTorrent/DHT, UDP, all ports (both directions)"},
        {UiLang::Korean, L"토렌트 클라이언트: TCP/UDP, 모든 포트",
            L"BitTorrent, TCP, 모든 포트 (양방향)",
            L"BitTorrent/DHT, UDP, 모든 포트 (양방향)"},
        {UiLang::Chinese, L"BT 客户端：TCP/UDP，所有端口",
            L"BitTorrent，TCP，所有端口（双向）",
            L"BitTorrent/DHT，UDP，所有端口（双向）"},
        {UiLang::Ukrainian, L"Торент-клієнт: TCP/UDP, усі порти",
            L"BitTorrent, TCP, усі порти (обидва напрямки)",
            L"BitTorrent/DHT, UDP, усі порти (обидва напрямки)"},
        {UiLang::German, L"Torrent-Client: TCP/UDP, alle Ports",
            L"BitTorrent, TCP, alle Ports (beide Richtungen)",
            L"BitTorrent/DHT, UDP, alle Ports (beide Richtungen)"},
        {UiLang::French, L"Client torrent : TCP/UDP, tous les ports",
            L"BitTorrent, TCP, tous les ports (les deux sens)",
            L"BitTorrent/DHT, UDP, tous les ports (les deux sens)"},
        {UiLang::Spanish, L"Cliente torrent: TCP/UDP, todos los puertos",
            L"BitTorrent, TCP, todos los puertos (ambas direcciones)",
            L"BitTorrent/DHT, UDP, todos los puertos (ambas direcciones)"},
        {UiLang::Arabic, L"عميل تورنت: TCP/UDP، جميع المنافذ",
            L"BitTorrent، TCP، جميع المنافذ (كلا الاتجاهين)",
            L"BitTorrent/DHT، UDP، جميع المنافذ (كلا الاتجاهين)"},
        {UiLang::Hindi, L"टोरेंट क्लाइंट: TCP/UDP, सभी पोर्ट",
            L"BitTorrent, TCP, सभी पोर्ट (दोनों दिशाएँ)",
            L"BitTorrent/DHT, UDP, सभी पोर्ट (दोनों दिशाएँ)"},
        {UiLang::Latvian, L"Torrentu klients: TCP/UDP, visi porti",
            L"BitTorrent, TCP, visi porti (abi virzieni)",
            L"BitTorrent/DHT, UDP, visi porti (abi virzieni)"},
        {UiLang::Lithuanian, L"Torentų programa: TCP/UDP, visi prievadai",
            L"BitTorrent, TCP, visi prievadai (abi kryptys)",
            L"BitTorrent/DHT, UDP, visi prievadai (abi kryptys)"},
        {UiLang::Estonian, L"Torrentiklient: TCP/UDP, kõik pordid",
            L"BitTorrent, TCP, kõik pordid (mõlemad suunad)",
            L"BitTorrent/DHT, UDP, kõik pordid (mõlemad suunad)"},
        {UiLang::Romanian, L"Client torrent: TCP/UDP, toate porturile",
            L"BitTorrent, TCP, toate porturile (ambele sensuri)",
            L"BitTorrent/DHT, UDP, toate porturile (ambele sensuri)"},
        {UiLang::Swedish, L"Torrentklient: TCP/UDP, alla portar",
            L"BitTorrent, TCP, alla portar (båda riktningarna)",
            L"BitTorrent/DHT, UDP, alla portar (båda riktningarna)"},
        {UiLang::Polish, L"Klient torrent: TCP/UDP, wszystkie porty",
            L"BitTorrent, TCP, wszystkie porty (oba kierunki)",
            L"BitTorrent/DHT, UDP, wszystkie porty (oba kierunki)"},
        {UiLang::Vietnamese, L"Ứng dụng torrent: TCP/UDP, mọi cổng",
            L"BitTorrent, TCP, mọi cổng (hai chiều)",
            L"BitTorrent/DHT, UDP, mọi cổng (hai chiều)"},
        {UiLang::Portuguese, L"Cliente torrent: TCP/UDP, todas as portas",
            L"BitTorrent, TCP, todas as portas (ambas as direções)",
            L"BitTorrent/DHT, UDP, todas as portas (ambas as direções)"},
        {UiLang::Italian, L"Client torrent: TCP/UDP, tutte le porte",
            L"BitTorrent, TCP, tutte le porte (entrambe le direzioni)",
            L"BitTorrent/DHT, UDP, tutte le porte (entrambe le direzioni)"},
        {UiLang::Persian, L"کلاینت تورنت: TCP/UDP، همهٔ درگاه‌ها",
            L"BitTorrent، TCP، همهٔ درگاه‌ها (هر دو جهت)",
            L"BitTorrent/DHT، UDP، همهٔ درگاه‌ها (هر دو جهت)"},
        {UiLang::Japanese, L"Torrent クライアント: TCP/UDP、全ポート",
            L"BitTorrent、TCP、全ポート（双方向）",
            L"BitTorrent/DHT、UDP、全ポート（双方向）"},
        {UiLang::Turkish, L"Torrent istemcisi: TCP/UDP, tüm bağlantı noktaları",
            L"BitTorrent, TCP, tüm bağlantı noktaları (iki yönlü)",
            L"BitTorrent/DHT, UDP, tüm bağlantı noktaları (iki yönlü)"},
        {UiLang::Indonesian, L"Klien torrent: TCP/UDP, semua port",
            L"BitTorrent, TCP, semua port (kedua arah)",
            L"BitTorrent/DHT, UDP, semua port (kedua arah)"},
        {UiLang::Czech, L"Torrentový klient: TCP/UDP, všechny porty",
            L"BitTorrent, TCP, všechny porty (oba směry)",
            L"BitTorrent/DHT, UDP, všechny porty (oba směry)"},
        {UiLang::Thai, L"ไคลเอนต์ทอร์เรนต์: TCP/UDP, ทุกพอร์ต",
            L"BitTorrent, TCP, ทุกพอร์ต (ทั้งสองทิศทาง)",
            L"BitTorrent/DHT, UDP, ทุกพอร์ต (ทั้งสองทิศทาง)"},
        {UiLang::PortugueseBrazil, L"Cliente torrent: TCP/UDP, todas as portas",
            L"BitTorrent, TCP, todas as portas (ambas as direções)",
            L"BitTorrent/DHT, UDP, todas as portas (ambas as direções)"},
        {UiLang::ChineseTraditional, L"Torrent 用戶端：TCP/UDP，所有連接埠",
            L"BitTorrent，TCP，所有連接埠（雙向）",
            L"BitTorrent/DHT，UDP，所有連接埠（雙向）"},
        {UiLang::Hungarian, L"Torrentkliens: TCP/UDP, minden port",
            L"BitTorrent, TCP, minden port (mindkét irány)",
            L"BitTorrent/DHT, UDP, minden port (mindkét irány)"},
        {UiLang::Greek, L"Πελάτης torrent: TCP/UDP, όλες οι θύρες",
            L"BitTorrent, TCP, όλες οι θύρες (και οι δύο κατευθύνσεις)",
            L"BitTorrent/DHT, UDP, όλες οι θύρες (και οι δύο κατευθύνσεις)"},
        {UiLang::Dutch, L"Torrentclient: TCP/UDP, alle poorten",
            L"BitTorrent, TCP, alle poorten (beide richtingen)",
            L"BitTorrent/DHT, UDP, alle poorten (beide richtingen)"},
        {UiLang::Bulgarian, L"Торент клиент: TCP/UDP, всички портове",
            L"BitTorrent, TCP, всички портове (двете посоки)",
            L"BitTorrent/DHT, UDP, всички портове (двете посоки)"},
        {UiLang::Danish, L"Torrentklient: TCP/UDP, alle porte",
            L"BitTorrent, TCP, alle porte (begge retninger)",
            L"BitTorrent/DHT, UDP, alle porte (begge retninger)"},
        {UiLang::NorwegianBokmal, L"Torrentklient: TCP/UDP, alle porter",
            L"BitTorrent, TCP, alle porter (begge retninger)",
            L"BitTorrent/DHT, UDP, alle porter (begge retninger)"},
        {UiLang::Finnish, L"Torrent-asiakas: TCP/UDP, kaikki portit",
            L"BitTorrent, TCP, kaikki portit (molemmat suunnat)",
            L"BitTorrent/DHT, UDP, kaikki portit (molemmat suunnat)"},
    };
    Check(std::size(torrents) == count, "missing torrent translation test");
    for (const auto& translation : torrents) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_PRESET_TORRENT) == translation.title &&
              LoadStringRes(IDS_PRESET_RULE_TORRENT_TCP) == translation.tcp &&
              LoadStringRes(IDS_PRESET_RULE_TORRENT_UDP) == translation.udp,
              "torrent preset text was decoded with the wrong code page");
    }
    struct ServiceNetworkTranslation {
        UiLang language;
        const wchar_t* discovery;
        const wchar_t* delivery;
        const wchar_t* metadata;
    };
    const ServiceNetworkTranslation serviceNetworks[] = {
        {UiLang::Russian, L"Хост поставщика обнаружения функций",
            L"Оптимизация доставки: загрузки и локальные узлы",
            L"Метаданные WS-Discovery, TCP 5357/5358, локальная сеть"},
        {UiLang::English, L"Function Discovery Provider Host",
            L"Delivery Optimization: downloads and local peers",
            L"WS-Discovery metadata, TCP 5357/5358, local network"},
        {UiLang::Korean, L"기능 검색 공급자 호스트",
            L"배달 최적화: 다운로드 및 로컬 피어",
            L"WS-Discovery 메타데이터, TCP 5357/5358, 로컬 네트워크"},
        {UiLang::Chinese, L"功能发现提供程序主机",
            L"传递优化：下载和本地对等设备",
            L"WS-Discovery 元数据，TCP 5357/5358，局域网"},
        {UiLang::Ukrainian, L"Хост постачальника виявлення функцій",
            L"Оптимізація доставки: завантаження та локальні вузли",
            L"Метадані WS-Discovery, TCP 5357/5358, локальна мережа"},
        {UiLang::German, L"Funktionssuchanbieter-Host",
            L"Übermittlungsoptimierung: Downloads und lokale Peers",
            L"WS-Discovery-Metadaten, TCP 5357/5358, lokales Netzwerk"},
        {UiLang::French, L"Hôte du fournisseur de découverte de fonctions",
            L"Optimisation de la distribution : téléchargements et pairs locaux",
            L"Métadonnées WS-Discovery, TCP 5357/5358, réseau local"},
        {UiLang::Spanish, L"Host de proveedor de detección de función",
            L"Optimización de distribución: descargas y pares locales",
            L"Metadatos WS-Discovery, TCP 5357/5358, red local"},
        {UiLang::Arabic, L"مضيف موفر اكتشاف الوظائف",
            L"تحسين التسليم: التنزيلات والنظراء المحليون",
            L"بيانات WS-Discovery الوصفية، TCP 5357/5358، الشبكة المحلية"},
        {UiLang::Hindi, L"फ़ंक्शन डिस्कवरी प्रदाता होस्ट",
            L"डिलीवरी ऑप्टिमाइज़ेशन: डाउनलोड और स्थानीय पीयर",
            L"WS-Discovery मेटाडेटा, TCP 5357/5358, स्थानीय नेटवर्क"},
        {UiLang::Latvian, L"Funkciju atklāšanas nodrošinātāja resursdators",
            L"Piegādes optimizācija: lejupielādes un lokālie partneri",
            L"WS-Discovery metadati, TCP 5357/5358, lokālais tīkls"},
        {UiLang::Lithuanian, L"Funkcijų aptikimo teikėjo pagrindinis kompiuteris",
            L"Pristatymo optimizavimas: atsisiuntimai ir vietiniai partneriai",
            L"WS-Discovery metaduomenys, TCP 5357/5358, vietinis tinklas"},
        {UiLang::Estonian, L"Funktsioonituvastuse pakkuja host",
            L"Edastuse optimeerimine: allalaadimised ja kohalikud partnerid",
            L"WS-Discovery metaandmed, TCP 5357/5358, kohalik võrk"},
        {UiLang::Romanian, L"Gazdă furnizor descoperire funcții",
            L"Optimizarea livrării: descărcări și parteneri locali",
            L"Metadate WS-Discovery, TCP 5357/5358, rețea locală"},
        {UiLang::Swedish, L"Värd för funktionsidentifieringsprovider",
            L"Leveransoptimering: nedladdningar och lokala peer-datorer",
            L"WS-Discovery-metadata, TCP 5357/5358, lokalt nätverk"},
        {UiLang::Polish, L"Host dostawcy odnajdywania funkcji",
            L"Optymalizacja dostarczania: pobieranie i lokalne węzły",
            L"Metadane WS-Discovery, TCP 5357/5358, sieć lokalna"},
        {UiLang::Vietnamese, L"Máy chủ nhà cung cấp khám phá chức năng",
            L"Tối ưu hóa phân phối: tải xuống và máy ngang hàng cục bộ",
            L"Siêu dữ liệu WS-Discovery, TCP 5357/5358, mạng cục bộ"},
        {UiLang::Portuguese, L"Anfitrião do fornecedor de deteção de funções",
            L"Otimização da Entrega: transferências e pares locais",
            L"Metadados WS-Discovery, TCP 5357/5358, rede local"},
        {UiLang::Italian, L"Host provider di individuazione funzioni",
            L"Ottimizzazione recapito: download e peer locali",
            L"Metadati WS-Discovery, TCP 5357/5358, rete locale"},
        {UiLang::Persian, L"میزبان ارائه‌دهندهٔ کشف قابلیت‌ها",
            L"بهینه‌سازی تحویل: بارگیری‌ها و همتایان محلی",
            L"فرادادهٔ WS-Discovery، TCP 5357/5358، شبکهٔ محلی"},
        {UiLang::Japanese, L"Function Discovery プロバイダーホスト",
            L"配信の最適化: ダウンロードとローカルピア",
            L"WS-Discovery メタデータ、TCP 5357/5358、ローカルネットワーク"},
        {UiLang::Turkish, L"İşlev Bulma Sağlayıcısı Ana Bilgisayarı",
            L"Teslim İyileştirme: indirmeler ve yerel eşler",
            L"WS-Discovery meta verileri, TCP 5357/5358, yerel ağ"},
        {UiLang::Indonesian, L"Host Penyedia Penemuan Fungsi",
            L"Pengoptimalan Pengiriman: unduhan dan rekan lokal",
            L"Metadata WS-Discovery, TCP 5357/5358, jaringan lokal"},
        {UiLang::Czech, L"Hostitel poskytovatele rozpoznávání funkcí",
            L"Optimalizace doručení: stahování a místní partneři",
            L"Metadata WS-Discovery, TCP 5357/5358, místní síť"},
        {UiLang::Thai, L"โฮสต์ผู้ให้บริการค้นหาฟังก์ชัน",
            L"การปรับการนำส่งให้เหมาะสม: ดาวน์โหลดและเพียร์ภายใน",
            L"เมทาดาทา WS-Discovery, TCP 5357/5358, เครือข่ายภายใน"},
        {UiLang::PortugueseBrazil, L"Host de Provedor de Descoberta de Função",
            L"Otimização de Entrega: downloads e pares locais",
            L"Metadados WS-Discovery, TCP 5357/5358, rede local"},
        {UiLang::ChineseTraditional, L"功能探索提供者主機",
            L"傳遞最佳化：下載和本機對等裝置",
            L"WS-Discovery 中繼資料，TCP 5357/5358，區域網路"},
        {UiLang::Hungarian, L"Funkciófelderítési szolgáltató gazdagépe",
            L"Kézbesítésoptimalizálás: letöltések és helyi társak",
            L"WS-Discovery-metaadatok, TCP 5357/5358, helyi hálózat"},
        {UiLang::Greek, L"Κεντρικός υπολογιστής υπηρεσίας παροχής εντοπισμού λειτουργιών",
            L"Βελτιστοποίηση παράδοσης: λήψεις και τοπικοί ομότιμοι",
            L"Μεταδεδομένα WS-Discovery, TCP 5357/5358, τοπικό δίκτυο"},
        {UiLang::Dutch, L"Host voor functieproviderdetectie",
            L"Delivery Optimization: downloads en lokale peers",
            L"WS-Discovery-metagegevens, TCP 5357/5358, lokaal netwerk"},
        {UiLang::Bulgarian, L"Хост на доставчик за откриване на функции",
            L"Оптимизация на доставянето: изтегляния и локални партньори",
            L"WS-Discovery метаданни, TCP 5357/5358, локална мрежа"},
        {UiLang::Danish, L"Vært for funktionsregistreringsudbyder",
            L"Leveringsoptimering: downloads og lokale peers",
            L"WS-Discovery-metadata, TCP 5357/5358, lokalnetværk"},
        {UiLang::NorwegianBokmal, L"Vert for funksjonsoppdagingsleverandør",
            L"Leveringsoptimalisering: nedlastinger og lokale noder",
            L"WS-Discovery-metadata, TCP 5357/5358, lokalnett"},
        {UiLang::Finnish, L"Toimintojen etsinnän palveluntarjoajan isäntä",
            L"Toimituksen optimointi: lataukset ja paikalliset vertaiskoneet",
            L"WS-Discovery-metatiedot, TCP 5357/5358, paikallisverkko"},
    };
    Check(std::size(serviceNetworks) == count, "missing discovery/delivery translation test");
    for (const auto& translation : serviceNetworks) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_PRESET_FUNCTION_DISCOVERY_HOST) == translation.discovery &&
              LoadStringRes(IDS_PRESET_DELIVERY_FULL) == translation.delivery &&
              LoadStringRes(IDS_PRESET_RULE_WSD_METADATA) == translation.metadata,
              "discovery/delivery preset text was decoded with the wrong code page");
    }
    struct NetbiosTranslation {
        UiLang language;
        const wchar_t* title;
        const wchar_t* ns;
        const wchar_t* dgm;
    };
    const NetbiosTranslation netbios[] = {
        {UiLang::Russian, L"SYSTEM: блокировать NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::English, L"SYSTEM: block NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Korean, L"SYSTEM: NetBIOS 차단",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Chinese, L"SYSTEM：阻止 NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Ukrainian, L"SYSTEM: блокувати NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::German, L"SYSTEM: NetBIOS blockieren",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::French, L"SYSTEM : bloquer NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Spanish, L"SYSTEM: bloquear NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Arabic, L"SYSTEM: حظر NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Hindi, L"SYSTEM: NetBIOS अवरुद्ध करें",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Latvian, L"SYSTEM: bloķēt NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Lithuanian, L"SYSTEM: blokuoti NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Estonian, L"SYSTEM: blokeeri NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Romanian, L"SYSTEM: blochează traficul NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Swedish, L"SYSTEM: blockera NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Polish, L"SYSTEM: blokuj NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Vietnamese, L"SYSTEM: chặn NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Portuguese, L"SYSTEM: bloquear NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Italian, L"SYSTEM: blocca NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Persian, L"SYSTEM: مسدود کردن NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Japanese, L"SYSTEM: NetBIOS をブロック",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Turkish, L"SYSTEM: NetBIOS'u engelle",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Indonesian, L"SYSTEM: blokir NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Czech, L"SYSTEM: blokovat NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Thai, L"SYSTEM: บล็อก NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::PortugueseBrazil, L"SYSTEM: bloquear NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::ChineseTraditional, L"SYSTEM：封鎖 NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Hungarian, L"SYSTEM: NetBIOS tiltása",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Greek, L"SYSTEM: αποκλεισμός NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Dutch, L"SYSTEM: NetBIOS blokkeren",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Bulgarian, L"SYSTEM: блокиране на NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Danish, L"SYSTEM: bloker NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::NorwegianBokmal, L"SYSTEM: blokker NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
        {UiLang::Finnish, L"SYSTEM: estä NetBIOS",
            L"NetBIOS-NS, UDP 137 → 137",
            L"NetBIOS-DGM, UDP 138 → 138"},
    };
    Check(std::size(netbios) == count, "missing NetBIOS translation test");
    for (const auto& translation : netbios) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_PRESET_NETBIOS_BLOCK) == translation.title &&
              LoadStringRes(IDS_PRESET_RULE_NETBIOS_NS_BLOCK) == translation.ns &&
              LoadStringRes(IDS_PRESET_RULE_NETBIOS_DGM_BLOCK) == translation.dgm,
              "NetBIOS preset text was decoded with the wrong code page");
    }
    struct InterfaceTranslation {
        UiLang language;
        const wchar_t* settings;
        const wchar_t* processes;
    };
    const InterfaceTranslation interfaces[] = {
        {UiLang::Latvian, L"Iestatījumi", L"Procesi: 12 · savienojumi: 34"},
        {UiLang::Lithuanian, L"Nuostatos", L"Procesai: 12 · ryšiai: 34"},
        {UiLang::Estonian, L"Seaded", L"Protsesse: 12 · ühendusi: 34"},
        {UiLang::Romanian, L"Setări", L"Procese: 12 · conexiuni: 34"},
        {UiLang::Swedish, L"Inställningar", L"Processer: 12 · anslutningar: 34"},
        {UiLang::Polish, L"Ustawienia", L"Procesy: 12 · połączenia: 34"},
        {UiLang::Vietnamese, L"Cài đặt", L"Tiến trình: 12 · kết nối: 34"},
        {UiLang::Portuguese, L"Definições", L"Processos: 12 · ligações: 34"},
        {UiLang::Italian, L"Impostazioni", L"Processi: 12 · connessioni: 34"},
        {UiLang::Persian, L"تنظیمات", L"فرایندها: 12 · اتصال‌ها: 34"},
        {UiLang::Japanese, L"設定", L"プロセス: 12 · 接続: 34"},
        {UiLang::Turkish, L"Ayarlar", L"İşlemler: 12 · bağlantılar: 34"},
        {UiLang::Indonesian, L"Pengaturan", L"Proses: 12 · koneksi: 34"},
        {UiLang::Czech, L"Nastavení", L"Procesy: 12 · spojení: 34"},
        {UiLang::Thai, L"การตั้งค่า", L"กระบวนการ: 12 · การเชื่อมต่อ: 34"},
        {UiLang::PortugueseBrazil, L"Configurações", L"Processos: 12 · conexões: 34"},
        {UiLang::ChineseTraditional, L"設定", L"處理程序: 12 · 連線: 34"},
        {UiLang::Hungarian, L"Beállítások", L"Folyamatok: 12 · kapcsolatok: 34"},
        {UiLang::Greek, L"Ρυθμίσεις", L"Διεργασίες: 12 · συνδέσεις: 34"},
        {UiLang::Dutch, L"Instellingen", L"Processen: 12 · verbindingen: 34"},
        {UiLang::Bulgarian, L"Настройки", L"Процеси: 12 · връзки: 34"},
        {UiLang::Danish, L"Indstillinger", L"Processer: 12 · forbindelser: 34"},
        {UiLang::NorwegianBokmal, L"Innstillinger", L"Prosesser: 12 · tilkoblinger: 34"},
        {UiLang::Finnish, L"Asetukset", L"Prosessit: 12 · yhteydet: 34"},
    };
    for (const auto& translation : interfaces) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_SETTINGS_TITLE) == translation.settings,
              "interface text was decoded with the wrong code page");
        Check(LoadStringResFmt(IDS_STATUS_PROCS_FMT, 12u, 34u) == translation.processes,
              "localized process count was formatted incorrectly");
    }
    SetUiLang(UiLang::Ukrainian);
    Check(std::to_wstring(5) + LoadStringRes(IDS_MON_TIME_AGO) == L"5 с тому",
          "Ukrainian inactivity time lost its seconds suffix");
    Check(LoadStringRes(IDS_RDS_ONLY_RUNNING) == L"Тільки запущені",
          "Ukrainian service filter does not describe running services");
    SetUiLang(UiLang::Lithuanian);
    Check(std::to_wstring(5) + LoadStringRes(IDS_MON_TIME_AGO) == L"5 s anksčiau",
          "Lithuanian inactivity time is not a valid suffix");
    SetUiLang(UiLang::Arabic);
    Check(LoadStringRes(IDS_MACRO_MORE_PREFIX) + L"5" == L"... المتبقي: 5",
          "Arabic remaining address count is incorrect");
    SetUiLang(UiLang::Persian);
    Check(LoadStringRes(IDS_MACRO_MORE_PREFIX) + L"5" == L"... باقی‌مانده: 5",
          "Persian remaining address count is incorrect");
    SetUiLang(UiLang::Polish);
    Check(L"1" + LoadStringRes(IDS_ALLRULES_ENABLED_SUFFIX) == L"1 wł.)",
          "Polish enabled rule count is incorrect");
    Check(LoadStringRes(IDS_MACRO_MORE_PREFIX) + L"5" == L"... i jeszcze 5",
          "Polish remaining address count is incorrect");
    SetUiLang(previous);
}

void TestAutomaticRuleNames() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::Russian);
    Rule example;
    example.appPath = SystemDirFile(L"taskhostw.exe");
    example.appName = L"TASKHOSTW.EXE";
    example.action = RuleAction::Block;
    example.conds = CondProto | CondDirection | CondRemoteAddr | CondRemotePort | CondLocalAddr;
    example.proto = Proto::Tcp;
    example.dir = Dir::Out;
    example.remoteAddrs = {{Ip(L"40.126.32.131"), -1}};
    example.localAddrs = {{Ip(L"192.168.0.196"), -1}};
    example.remotePorts = {{443, 443}};
    example.localPorts = {{2141, 2141}};
    const std::wstring expected =
        L"Блокировать Исходящее TCP с 192.168.0.196 на 40.126.32.131:HTTPS для TASKHOSTW.EXE";
    Check(example.BuildAutoName() == expected,
          "outbound rule name reversed its endpoints or included an unchecked local port");
    example.SyncName();
    Check(example.name == expected && example.autoName, "automatic rule name was not synchronized");
    Rule incoming = example;
    incoming.dir = Dir::In;
    Check(incoming.BuildAutoName() ==
              L"Блокировать Входящее TCP с 40.126.32.131:HTTPS на 192.168.0.196 для TASKHOSTW.EXE",
          "incoming rule name reversed the source and destination");

    struct Translation {
        UiLang language;
        const wchar_t* from;
        const wchar_t* to;
        const wchar_t* between;
    };
    const Translation translations[] = {
        {UiLang::Russian, L" с ", L" на ", L" между %s и %s"},
        {UiLang::English, L" from ", L" to ", L" between %s and %s"},
        {UiLang::Korean, L" <- ", L" -> ", L" %s 및 %s 사이"},
        {UiLang::Chinese, L" 从 ", L" 到 ", L" 在 %s 与 %s 之间"},
        {UiLang::Ukrainian, L" від ", L" до ", L" між %s і %s"},
        {UiLang::German, L" von ", L" an ", L" zwischen %s und %s"},
        {UiLang::French, L" de ", L" vers ", L" entre %s et %s"},
        {UiLang::Spanish, L" de ", L" a ", L" entre %s y %s"},
        {UiLang::Arabic, L" من ", L" إلى ", L" بين %s و%s"},
        {UiLang::Hindi, L" स्रोत: ", L" गंतव्य: ", L" %s और %s के बीच"},
        {UiLang::Latvian, L" no ", L" uz ", L" starp %s un %s"},
        {UiLang::Lithuanian, L" iš ", L" į ", L" tarp %s ir %s"},
        {UiLang::Estonian, L" lähtekohast ", L" sihtkohta ", L" %s ja %s vahel"},
        {UiLang::Romanian, L" de la ", L" către ", L" între %s și %s"},
        {UiLang::Swedish, L" från ", L" till ", L" mellan %s och %s"},
        {UiLang::Polish, L" z ", L" do ", L" między %s a %s"},
        {UiLang::Vietnamese, L" từ ", L" đến ", L" giữa %s và %s"},
        {UiLang::Portuguese, L" de ", L" para ", L" entre %s e %s"},
        {UiLang::Italian, L" da ", L" a ", L" tra %s e %s"},
        {UiLang::Persian, L" از ", L" به ", L" بین %s و %s"},
        {UiLang::Japanese, L" 送信元 ",
            L" 宛先 ",
            L" %s と %s の間"},
        {UiLang::Turkish, L" kaynak ",
            L" hedef ",
            L" %s ile %s arasında"},
        {UiLang::Indonesian, L" dari ",
            L" ke ",
            L" antara %s dan %s"},
        {UiLang::Czech, L" z ",
            L" do ",
            L" mezi %s a %s"},
        {UiLang::Thai, L" จาก ",
            L" ไปยัง ",
            L" ระหว่าง %s และ %s"},
        {UiLang::PortugueseBrazil, L" de ",
            L" para ",
            L" entre %s e %s"},
        {UiLang::ChineseTraditional, L" 從 ",
            L" 到 ",
            L" 在 %s 與 %s 之間"},
        {UiLang::Hungarian, L" forrás: ",
            L" cél: ",
            L" %s és %s között"},
        {UiLang::Greek, L" από ",
            L" προς ",
            L" μεταξύ %s και %s"},
        {UiLang::Dutch, L" van ",
            L" naar ",
            L" tussen %s en %s"},
        {UiLang::Bulgarian, L" от ",
            L" към ",
            L" между %s и %s"},
        {UiLang::Danish, L" fra ",
            L" til ",
            L" mellem %s og %s"},
        {UiLang::NorwegianBokmal, L" fra ",
            L" til ",
            L" mellom %s og %s"},
        {UiLang::Finnish, L" lähteestä ",
            L" kohteeseen ",
            L" välillä %s ja %s"},
    };
    size_t languageCount = 0;
    UiLangs(languageCount);
    Check(std::size(translations) == languageCount, "missing automatic rule name translation test");
    for (const auto& translation : translations) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_RULEN_FROM) == translation.from &&
              LoadStringRes(IDS_RULEN_TO) == translation.to &&
              LoadStringRes(IDS_RULEN_BETWEEN_FMT) == translation.between,
              "automatic rule name phrases were decoded incorrectly");
        Check(LoadStringResFmt(IDS_RULEN_ADDR_LIST_FMT, L"1.1.1.1") == L"(1.1.1.1, ...)" &&
              !LoadStringRes(IDS_ERR_ADDR_EXISTS).empty(),
              "missing compact address list format or duplicate-address message");
        for (RuleAction action : {RuleAction::Allow, RuleAction::Block})
        for (Dir dir : {Dir::Out, Dir::In, Dir::Unknown})
        for (Proto proto : {Proto::Tcp, Proto::Udp, Proto::Sctp, Proto::Dccp, Proto::UdpLite,
                            Proto::Icmp, Proto::IcmpV6, Proto{200}})
        for (uint32_t endpoints = 0; endpoints < 16; ++endpoints) {
            Rule rule = example;
            rule.action = action;
            rule.dir = dir;
            rule.proto = proto;
            rule.conds = CondProto | (dir == Dir::Unknown ? 0 : CondDirection);
            if (endpoints & 1) rule.conds |= CondRemoteAddr;
            if (endpoints & 2) rule.conds |= CondRemotePort;
            if (endpoints & 4) rule.conds |= CondLocalAddr;
            if (endpoints & 8) rule.conds |= CondLocalPort;
            std::wstring name = LoadStringRes(action == RuleAction::Allow
                ? IDS_RULE_ACT_ALLOW : IDS_RULE_ACT_BLOCK) + L" ";
            if (dir != Dir::Unknown)
                name += LoadStringRes(dir == Dir::In ? IDS_RULE_DIR_IN : IDS_RULE_DIR_OUT) + L" ";
            name += proto == Proto{200}
                ? LoadStringRes(IDS_RULE_PROTO_NUM) + L"200" : rule.ProtoText();
            const bool hasPorts = proto == Proto::Tcp || proto == Proto::Udp ||
                                  proto == Proto::Sctp || proto == Proto::Dccp || proto == Proto::UdpLite;
            std::wstring local, remote;
            if (endpoints & 1) remote = L"40.126.32.131";
            if ((endpoints & 2) && hasPorts) remote += remote.empty() ? L"HTTPS" : L":HTTPS";
            if (endpoints & 4) local = L"192.168.0.196";
            if ((endpoints & 8) && hasPorts) local += local.empty() ? L"2141" : L":2141";
            if (dir == Dir::Unknown) {
                if (!local.empty() || !remote.empty())
                    name += LoadStringResFmt(IDS_RULEN_BETWEEN_FMT,
                        local.empty() ? L"*" : local.c_str(), remote.empty() ? L"*" : remote.c_str());
            } else {
                const std::wstring& from = dir == Dir::In ? remote : local;
                const std::wstring& to = dir == Dir::In ? local : remote;
                if (!from.empty()) name += std::wstring(translation.from) + from;
                if (!to.empty()) name += std::wstring(translation.to) + to;
            }
            name += LoadStringRes(IDS_RULEN_FOR) + rule.appName;
            Check(rule.BuildAutoName() == name,
                  "automatic name lost an endpoint or included an unchecked/inapplicable condition");
        }
    }
    struct ScopeLabel {
        UiLang language;
        const wchar_t* prefix;
    };
    const ScopeLabel scopeLabels[] = {
        {UiLang::Hindi, L" दायरा: "},
        {UiLang::Korean, L" 범위: "},
        {UiLang::Turkish, L" kapsam: "},
        {UiLang::Estonian, L" ulatus: "},
    };
    for (const auto& translation : scopeLabels) {
        SetUiLang(translation.language);
        for (RuleScope scope : {RuleScope::App, RuleScope::PostApp, RuleScope::Interface}) {
            Rule named = example;
            named.scope = scope;
            named.appName = scope == RuleScope::App ? L"TASKHOSTW.EXE" : L"Test group";
            const std::wstring expectedSuffix = std::wstring(translation.prefix) + named.appName;
            Check(named.BuildAutoName().ends_with(expectedSuffix),
                  "localized rule name does not correctly label its application or group");
        }
    }
    struct InterfaceLabel {
        UiLang language;
        const wchar_t* prefix;
    };
    const InterfaceLabel interfaceLabels[] = {
        {UiLang::English, L"and the interface is "},
        {UiLang::German, L"und die Schnittstelle ist "},
        {UiLang::French, L"et l’interface est "},
        {UiLang::Spanish, L"y la interfaz es "},
        {UiLang::Portuguese, L"e a interface é "},
        {UiLang::Italian, L"e l’interfaccia è "},
        {UiLang::PortugueseBrazil, L"e a interface é "},
        {UiLang::Swedish, L"och gränssnittet är "},
        {UiLang::Romanian, L"și interfața este "},
    };
    Rule withInterface = example;
    withInterface.conds |= CondInterface;
    withInterface.interfaceName = L"Ethernet";
    for (const auto& translation : interfaceLabels) {
        SetUiLang(translation.language);
        const std::wstring expectedMarkup = std::wstring(translation.prefix) +
            L"<a id=\"interface\">Ethernet</a>";
        Check(RuleExplainMarkup(withInterface).find(expectedMarkup) != std::wstring::npos,
              "localized interface condition is incomplete or does not include its name");
    }
    Rule serviceRule;
    serviceRule.conds = CondProto | CondDirection | CondService;
    serviceRule.proto = Proto::Tcp;
    serviceRule.dir = Dir::Out;
    serviceRule.action = RuleAction::Allow;
    struct ServiceNames {
        UiLang language;
        const wchar_t* any;
        const wchar_t* one;
        const wchar_t* many;
    };
    const ServiceNames serviceNames[] = {
        {UiLang::Dutch, L"Toestaan Uitgaand TCP van elke service",
         L"Toestaan Uitgaand TCP van de service Dnscache",
         L"Toestaan Uitgaand TCP van de services Dnscache, W32Time"},
        {UiLang::Polish, L"Dopuść wychodzący TCP dowolnej usługi",
         L"Dopuść wychodzący TCP usługi Dnscache",
         L"Dopuść wychodzący TCP usług Dnscache, W32Time"},
    };
    for (const auto& translation : serviceNames) {
        SetUiLang(translation.language);
        serviceRule.services.clear();
        Check(serviceRule.BuildAutoName() == translation.any,
              "localized rule name does not describe any service correctly");
        serviceRule.services = {{L"Dnscache", L""}};
        Check(serviceRule.BuildAutoName() == translation.one,
              "localized rule name does not describe one service correctly");
        serviceRule.services.push_back({L"W32Time", L""});
        Check(serviceRule.BuildAutoName() == translation.many,
              "localized rule name does not describe multiple services correctly");
    }
    SetUiLang(UiLang::Polish);
    serviceRule.dir = Dir::In;
    serviceRule.conds &= ~CondProto;
    Check(serviceRule.BuildAutoName() == L"Dopuść przychodzący protokół (dowolny) usług Dnscache, W32Time",
          "Polish rule name disagrees with its direction or unspecified protocol");
    serviceRule.services.clear();
    Check(RuleExplainMarkup(serviceRule).find(
              L"i identyfikator usługi: <a id=\"service\">«dowolny»</a>") != std::wstring::npos,
          "Polish service explanation disagrees with an unspecified service");
    SetUiLang(UiLang::Russian);
    Rule rule = example;
    rule.conds = CondProto | CondDirection | CondRemotePort | CondLocalPort;
    rule.remotePorts = {{137, 137}};
    rule.localPorts = {{137, 137}};
    Check(rule.BuildAutoName() ==
              L"Блокировать Исходящее TCP с NETBIOS-NS на NETBIOS-NS для TASKHOSTW.EXE",
          "port-only endpoints were merged or omitted from the name");
    rule = example;
    rule.conds |= CondLocalPort;
    rule.remoteAddrs = {{Ip(L"2001:db8::10"), -1}};
    rule.localAddrs = {{Ip(L"2001:db8::20"), -1}};
    Check(rule.BuildAutoName() ==
              L"Блокировать Исходящее TCP с [2001:db8::20]:2141 на [2001:db8::10]:HTTPS для TASKHOSTW.EXE",
          "IPv6 rule endpoints lost the brackets separating addresses from ports");
    rule = example;
    rule.conds |= CondLocalPort;
    rule.remoteAddrs.push_back({Ip(L"198.51.100.20"), -1});
    rule.remotePorts = {{443, 443}, {5000, 5010}};
    rule.localPorts = {{2141, 2142}};
    Check(rule.BuildAutoName() ==
              L"Блокировать Исходящее TCP с 192.168.0.196:2141-2142 "
              L"на (40.126.32.131, ...):(HTTPS, 5000-5010) для TASKHOSTW.EXE",
          "automatic name did not shorten the address list or lost the port grouping");
    rule = example;
    rule.conds &= ~CondDirection;
    rule.dir = Dir::In;
    Check(rule.BuildAutoName() ==
              L"Блокировать TCP между 192.168.0.196 и 40.126.32.131:HTTPS для TASKHOSTW.EXE",
          "unchecked direction still labeled one endpoint as the source");
    rule.conds |= CondDirection;
    rule.dir = Dir::Unknown;
    Check(rule.BuildAutoName() ==
              L"Блокировать TCP между 192.168.0.196 и 40.126.32.131:HTTPS для TASKHOSTW.EXE",
          "unknown direction was displayed as outbound");
    rule = example;
    rule.SetProto(Proto::Icmp);
    rule.conds |= CondIcmpType;
    rule.icmpTypes = {{8, -1}};
    Check(rule.BuildAutoName() ==
              L"Блокировать Исходящее ICMP тип Echo Request с 192.168.0.196 на 40.126.32.131 для TASKHOSTW.EXE",
          "ICMP automatic name lost its type or retained port conditions");
    rule = example;
    rule.conds &= ~CondProto;
    Check(rule.BuildAutoName().find(LoadStringRes(IDS_RULE_ANY_PROTO)) != std::wstring::npos &&
          rule.BuildAutoName().find(L"TCP") == std::wstring::npos &&
          rule.BuildAutoName().find(L"HTTPS") == std::wstring::npos &&
          rule.BuildAutoName().find(L"2141") == std::wstring::npos,
          "any-protocol name retained the previous protocol or its ports");
    rule = example;
    rule.autoName = false;
    rule.name = L"Custom rule";
    rule.SyncName();
    Check(rule.name == L"Custom rule" && !rule.autoName, "custom rule name was overwritten");
    SetUiLang(previous);
}

void TestAddressListRuleNames() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::Russian);
    Rule rule;
    rule.appPath = L"C:\\FirefoxPortable\\App\\Firefox64\\firefox.exe";
    rule.appName = L"FIREFOX.EXE";
    rule.conds = CondProto | CondDirection | CondRemoteAddr | CondRemotePort;
    rule.remoteAddrs = {{Ip(L"1.1.1.1"), -1}, {Ip(L"1.1.1.1"), -1}, {Ip(L"1.1.1.1"), -1}};
    rule.remotePorts = {{443, 443}};
    Check(rule.BuildAutoName() ==
              L"Разрешать Исходящее TCP на (1.1.1.1, ...):HTTPS для FIREFOX.EXE",
          "legacy duplicate addresses were repeated in the automatic name");
    NormalizeRuleConds(rule);
    Check(rule.remoteAddrs.size() == 1 && rule.BuildAutoName() ==
              L"Разрешать Исходящее TCP на 1.1.1.1:HTTPS для FIREFOX.EXE",
          "duplicate-only list did not become a single address");

    for (Dir dir : {Dir::Out, Dir::In, Dir::Unknown})
    for (bool withPorts : {false, true}) {
        rule.dir = dir;
        rule.conds = CondProto | CondDirection | CondRemoteAddr | CondLocalAddr;
        if (withPorts) rule.conds |= CondRemotePort | CondLocalPort;
        rule.remoteAddrs = {{Ip(L"1.1.1.1"), -1}, {Ip(L"8.8.8.8"), -1}, {Ip(L"9.9.9.9"), -1}};
        rule.localAddrs = {{Ip(L"192.168.0.196"), -1}, {Ip(L"192.168.0.197"), -1}};
        rule.localPorts = {{2141, 2141}};
        const std::wstring remote = withPorts ? L"(1.1.1.1, ...):HTTPS" : L"(1.1.1.1, ...)";
        const std::wstring local = withPorts ? L"(192.168.0.196, ...):2141" : L"(192.168.0.196, ...)";
        std::wstring expected = L"Разрешать ";
        if (dir == Dir::Unknown) {
            expected += L"TCP между " + local + L" и " + remote;
        } else {
            expected += dir == Dir::In ? L"Входящее TCP с " : L"Исходящее TCP с ";
            expected += (dir == Dir::In ? remote : local) + L" на " + (dir == Dir::In ? local : remote);
        }
        expected += L" для FIREFOX.EXE";
        Check(rule.BuildAutoName() == expected, "address-list shortening changed endpoint direction or ports");
        Check(rule.AddrsText(true) == L"1.1.1.1, 8.8.8.8, 9.9.9.9" &&
              rule.AddrsText(false) == L"192.168.0.196, 192.168.0.197" &&
              RuleExplainMarkup(rule).find(L"1.1.1.1, 8.8.8.8, 9.9.9.9") != std::wstring::npos,
              "short automatic name truncated the actual conditions or explanation");
        Check(rule.remoteAddrs.size() == 3 && rule.localAddrs.size() == 2,
              "building an automatic name mutated the address conditions");
    }

    rule.dir = Dir::Out;
    rule.conds &= ~(CondLocalAddr | CondLocalPort);
    rule.remoteAddrs = {{Ip(L"2001:db8::1"), -1}, {Ip(L"2001:db8::2"), -1}};
    Check(rule.BuildAutoName() ==
              L"Разрешать Исходящее TCP на (2001:db8::1, ...):HTTPS для FIREFOX.EXE",
          "IPv6 list did not retain compact endpoint grouping");
    AddrItem macro;
    macro.macro = AddrMacro::DnsServers;
    rule.remoteAddrs = {macro, {Ip(L"1.1.1.1"), -1}};
    Check(rule.BuildAutoName() == L"Разрешать Исходящее TCP на (" + macro.Text() +
              L", ...):HTTPS для FIREFOX.EXE",
          "macro address list was not shortened consistently");
    SetUiLang(previous);
}

void TestApplicationSuggestions() {
    AskRequest browser = Request(L"C:\\Apps\\Chrome.EXE");
    auto choices = RulePresets::Suggest(browser);
    Check(choices.size() == 2, "browser HTTPS should offer two profiles");
    const auto& secure = ChoiceOf(choices, IDS_PRESET_BROWSER_HTTPS);
    Check(secure.rules.size() == 4, "unexpected secure browser rule count");
    for (const Rule& rule : secure.rules) {
        Check(rule.scope == RuleScope::App && rule.appPath == browser.appPath,
              "preset escaped the concrete application");
        Check(!rule.autoName && !rule.name.empty(), "preset rule has no localized fixed name");
    }
    browser.key.rport = 80;
    choices = RulePresets::Suggest(browser);
    Check(choices.size() == 1 && choices.front().titleId == IDS_PRESET_BROWSER_WEB,
          "HTTP offered HTTPS-only profile");
    browser.key.rport = 42667;
    Check(RulePresets::Suggest(browser).empty(), "nonstandard browser port got a preset");
    browser.key.rport = 443;
    browser.key.proto = ProtoFromNumber(144);
    Check(RulePresets::Suggest(browser).empty(), "unknown protocol got a web preset");
    browser.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(browser).size() == 2, "QUIC browser profiles missing");

    Check(RulePresets::Suggest(Request(L"C:\\Apps\\unknown.exe")).empty(),
          "unknown program got a preset");
    Check(RulePresets::Suggest(Request(L"")).empty(), "pathless request got app rules");
    browser.ownerAmbiguous = true;
    Check(RulePresets::Suggest(browser).empty(), "ambiguous owner got a preset");

    for (auto [file, proto, port, title] : {
        std::tuple{L"outlook.exe", Proto::Tcp, uint16_t{993}, UINT{IDS_PRESET_MAIL}},
        std::tuple{L"teams.exe", Proto::Udp, uint16_t{3478}, UINT{IDS_PRESET_CHAT}},
        std::tuple{L"discord.exe", Proto::Udp, uint16_t{50001}, UINT{IDS_PRESET_DISCORD}},
        std::tuple{L"telegram.exe", Proto::Tcp, uint16_t{5222}, UINT{IDS_PRESET_TELEGRAM}},
        std::tuple{L"steam.exe", Proto::Udp, uint16_t{27015}, UINT{IDS_PRESET_STEAM}},
        std::tuple{L"onedrive.exe", Proto::Tcp, uint16_t{443}, UINT{IDS_PRESET_CLOUD}},
        std::tuple{L"curl.exe", Proto::Tcp, uint16_t{80}, UINT{IDS_PRESET_WEB_TOOLS}},
        std::tuple{L"git.exe", Proto::Tcp, uint16_t{22}, UINT{IDS_PRESET_GIT}},
        std::tuple{L"winscp.exe", Proto::Tcp, uint16_t{22}, UINT{IDS_PRESET_SSH}},
        std::tuple{L"mstsc.exe", Proto::Udp, uint16_t{3389}, UINT{IDS_PRESET_RDP_CLIENT}}
    }) {
        choices = RulePresets::Suggest(Request(std::wstring(L"C:\\Apps\\") + file, proto, port));
        ChoiceOf(choices, title);
    }
}

void TestCombinedPresetPorts() {
    struct Example {
        const wchar_t* path;
        UINT titleId;
        const wchar_t* service;
        Proto proto;
        std::vector<std::pair<unsigned, unsigned>> ranges;
    };
    const Example examples[] = {
        {L"C:\\Apps\\outlook.exe", IDS_PRESET_MAIL, nullptr, Proto::Tcp,
            {{443, 443}, {465, 465}, {587, 587}, {993, 993}, {995, 995}}},
        {L"C:\\Apps\\teams.exe", IDS_PRESET_CHAT, nullptr, Proto::Tcp, {{443, 443}, {80, 80}}},
        {L"C:\\Apps\\teams.exe", IDS_PRESET_CHAT, nullptr, Proto::Udp,
            {{443, 443}, {3478, 3481}, {8801, 8810}}},
        {L"C:\\Apps\\discord.exe", IDS_PRESET_DISCORD, nullptr, Proto::Udp,
            {{443, 443}, {3478, 3481}, {50000, 65535}}},
        {L"C:\\Apps\\telegram.exe", IDS_PRESET_TELEGRAM, nullptr, Proto::Tcp,
            {{443, 443}, {80, 80}, {5222, 5222}}},
        {L"C:\\Apps\\steam.exe", IDS_PRESET_STEAM, nullptr, Proto::Tcp,
            {{443, 443}, {80, 80}, {27015, 27050}}},
        {L"C:\\Apps\\steam.exe", IDS_PRESET_STEAM, nullptr, Proto::Udp,
            {{443, 443}, {4380, 4380}, {27000, 27200}}},
        {L"C:\\Apps\\steamwebhelper.exe", IDS_PRESET_STEAM, nullptr, Proto::Tcp,
            {{443, 443}, {80, 80}, {27015, 27050}}},
        {L"C:\\Apps\\steamwebhelper.exe", IDS_PRESET_STEAM, nullptr, Proto::Udp,
            {{443, 443}, {4380, 4380}, {27000, 27200}}},
        {L"C:\\Apps\\AnyDesk.exe", IDS_PRESET_ANYDESK, nullptr, Proto::Tcp,
            {{443, 443}, {80, 80}, {6568, 6568}}},
        {L"C:\\Apps\\RustDesk.exe", IDS_PRESET_RUSTDESK, nullptr, Proto::Tcp,
            {{443, 443}, {80, 80}, {21115, 21116}}},
        {L"C:\\Apps\\TeamViewer_Service.exe", IDS_PRESET_TEAMVIEWER_SERVICE, L"TeamViewer", Proto::Tcp,
            {{443, 443}, {80, 80}, {5938, 5938}}},
        {L"C:\\Apps\\git.exe", IDS_PRESET_GIT, nullptr, Proto::Tcp,
            {{443, 443}, {80, 80}, {22, 22}}}
    };
    for (const Example& example : examples) {
        AskRequest request = Request(example.path, example.proto,
                                     static_cast<uint16_t>(example.ranges.front().first));
        if (example.service) SetServices(request.pid, {example.service});
        else SetServices(request.pid, {});
        const auto choices = RulePresets::Suggest(request);
        const auto& preset = ChoiceOf(choices, example.titleId);
        const uint32_t conds = CondProto | CondDirection | CondRemotePort |
                               (example.service ? CondService : 0);
        const auto found = std::find_if(preset.rules.begin(), preset.rules.end(), [&](const Rule& rule) {
            return rule.proto == example.proto && rule.conds == conds;
        });
        Check(found != preset.rules.end(), "combined preset port rule missing");
        const Rule& rule = *found;
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.dir == Dir::Out &&
              rule.remotePorts.size() == example.ranges.size() && rule.localPorts.empty() &&
              rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.interfaceName.empty() &&
              rule.conditionFlags == 0 &&
              (example.service ? rule.services.size() == 1 && rule.services[0].name == example.service
                               : rule.services.empty()),
              "combined preset port rule gained or lost a condition");
        MatchQuery query = request.ToQuery();
        for (unsigned port = 0; port <= 65535; ++port) {
            query.remotePort = static_cast<uint16_t>(port);
            const bool expected = std::any_of(example.ranges.begin(), example.ranges.end(),
                [&](const auto& range) { return range.first <= port && port <= range.second; });
            Check(RuleStore::MatchesRule(rule, query) == expected,
                  "combined preset rule changed the allowed remote port set");
        }
        query.remotePort = static_cast<uint16_t>(example.ranges.front().first);
        query.dir = Dir::In;
        Check(RuleStore::MatchesRule(rule, query), "combined rule changed allow direction semantics");
        query.proto = example.proto == Proto::Tcp ? Proto::Udp : Proto::Tcp;
        Check(!RuleStore::MatchesRule(rule, query), "combined rule accepted another protocol");
        query.proto = example.proto;
        query.appPath = L"C:\\Other\\unrelated.exe";
        Check(!RuleStore::MatchesRule(rule, query), "combined rule escaped the application path");
    }
    SetServices(GetCurrentProcessId(), {});
}

void TestFeedbackOfficeAndWebViewPresets() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    struct WebProfile {
        const wchar_t* path;
        UINT titleId;
        const wchar_t* title;
    };
    const WebProfile profiles[] = {
        {L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsFeedbackHub_2.2609.102.0_x64__8wekyb3d8bbwe\\WinUI3App\\FeedbackHub.exe",
            IDS_PRESET_FEEDBACK_HUB, L"FeedbackHub.exe: HTTPS / HTTP"},
        {L"C:\\Program Files\\Microsoft Office\\root\\Office16\\MSPUB.EXE",
            IDS_PRESET_PUBLISHER, L"MSPUB.EXE: HTTPS / HTTP"},
        {L"C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
            IDS_PRESET_POWERPOINT, L"POWERPNT.EXE: HTTPS / HTTP"},
        {L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            IDS_PRESET_WORD, L"WINWORD.EXE: HTTPS / HTTP"},
        {L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\resources\\app\\ServiceHub\\Services\\Microsoft.VisualStudio.Setup.Service\\BackgroundDownload.exe",
            IDS_PRESET_BACKGROUND_DOWNLOAD, L"BackgroundDownload.exe: HTTPS / HTTP"},
        {L"C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\Blend.exe",
            IDS_PRESET_BLEND, L"Blend.exe: HTTPS / HTTP"},
        {L"C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\PerfWatson2.exe",
            IDS_PRESET_PERFWATSON, L"PerfWatson2.exe: HTTPS / HTTP"},
        {L"C:\\Windows\\System32\\SIHClient.exe",
            IDS_PRESET_SIH_CLIENT, L"SIHClient.exe: HTTPS / HTTP"},
        {L"C:\\Program Files\\Wireshark\\Wireshark.exe",
            IDS_PRESET_WIRESHARK, L"Wireshark.exe: HTTPS / HTTP"}
    };
    for (const auto& profile : profiles) {
        AskRequest request = Request(profile.path, Proto::Tcp, 443, L"150.171.73.13");
        request.key.local = Ip(L"192.168.0.225");
        request.key.lport = 24794;
        request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
        request.conditionFlags = 1;
        const auto choices = RulePresets::Suggest(request);
        Check(choices.size() == 1, "web application did not get its exact preset");
        const auto& preset = ChoiceOf(choices, profile.titleId);
        Check(preset.title == profile.title && preset.rules.size() == 1,
              "web application preset lost its title or single rule");
        const Rule& rule = preset.rules.front();
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
              rule.conds == (CondProto | CondDirection | CondRemotePort) &&
              rule.remotePorts.size() == 2 && rule.remotePorts[0].from == 443 &&
              rule.remotePorts[0].to == 443 && rule.remotePorts[1].from == 80 &&
              rule.remotePorts[1].to == 80 && rule.localPorts.empty() &&
              rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.services.empty() &&
              rule.interfaceName.empty() && rule.conditionFlags == 0 &&
              !rule.autoName && !rule.name.empty(),
              "web application rule lost a condition or pinned a captured endpoint");
        for (uint16_t port : {uint16_t{443}, uint16_t{80}}) {
            AskRequest flow = request;
            flow.key.rport = port;
            flow.key.remote = Ip(L"203.0.113.33");
            flow.key.local = Ip(L"10.20.30.40");
            flow.key.lport = 60000;
            flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
            flow.conditionFlags.reset();
            const auto offered = RulePresets::Suggest(flow);
            Check(offered.size() == 1 && offered.front().titleId == profile.titleId &&
                  RuleStore::MatchesRule(rule, flow.ToQuery()),
                  "web preset missed a port or depended on the captured endpoint");
            flow.dir = Dir::In;
            Check(RuleStore::MatchesRule(rule, flow.ToQuery()),
                  "web rule changed the existing direction handling for port-restricted allows");
        }
        for (const auto& [proto, port] : {
                std::pair{Proto::Udp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{80}},
                std::pair{Proto::Tcp, uint16_t{8080}}}) {
            AskRequest unrelated = request;
            unrelated.key.proto = proto;
            unrelated.key.rport = port;
            Check(RulePresets::Suggest(unrelated).empty() &&
                  !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
                  "web preset accepted an unrelated protocol or port");
        }
        AskRequest unrelated = request;
        unrelated.appPath = L"D:\\Other\\" + PathBaseUpper(request.appPath);
        Check(RulePresets::Suggest(unrelated).size() == 1 &&
              !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
              "web preset lost filename matching or concrete path scope");
        unrelated.appPath = L"C:\\Apps\\not-a-preset.exe";
        Check(RulePresets::Suggest(unrelated).empty(), "web preset matched an unrelated executable");
        unrelated = request;
        unrelated.ownerAmbiguous = true;
        Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner got a web preset");

        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
              "cannot apply web application preset");
        const uint64_t version = store.version();
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            const auto localized = RulePresets::Suggest(request);
            const auto& translated = ChoiceOf(localized, profile.titleId);
            const std::wstring title = LoadStringRes(profile.titleId);
            const std::wstring name = LoadStringRes(IDS_PRESET_RULE_HTTPS_HTTP);
            Check(title == profile.title && name == L"HTTPS / HTTP, TCP 443 / 80" &&
                  translated.title == title && translated.rules.size() == 1 &&
                  translated.rules[0].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                      title.c_str(), name.c_str()) &&
                  RulePresets::Apply(store, request, translated.rules) == 0 &&
                  store.Count() == 1 && store.version() == version,
                  "localized web preset was lost or duplicated");
        }
        SetUiLang(UiLang::English);
    }

    const std::wstring path = L"C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\157.0.4341.42\\msedgewebview2.exe";
    AskRequest request = Request(path, Proto::Udp, 5353, L"224.0.0.251");
    request.key.local = Ip(L"192.168.156.1");
    request.key.lport = 5353;
    request.interfaceName = std::make_shared<const std::wstring>(L"VMware Network Adapter VMnet1");
    request.conditionFlags = 1;
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "WebView2 mDNS did not get its own preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_WEBVIEW2_MDNS);
    Check(preset.title == L"msedgewebview2.exe: mDNS" && preset.rules.size() == 1,
          "WebView2 mDNS preset lost its title or single rule");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == path && rule.action == RuleAction::Allow &&
          rule.proto == Proto::Udp && rule.dir == Dir::Unknown &&
          rule.conds == (CondProto | CondRemotePort | CondLocalPort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts[0].from == 5353 &&
          rule.remotePorts[0].to == 5353 && rule.localPorts.size() == 1 &&
          rule.localPorts[0].from == 5353 && rule.localPorts[0].to == 5353 &&
          rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.services.empty() &&
          rule.interfaceName.empty() && rule.conditionFlags == 0 &&
          !rule.autoName && !rule.name.empty(),
          "WebView2 mDNS rule lost paired ports or pinned a captured condition");
    for (const auto& [local, remote] : {
            std::pair{L"192.0.2.10", L"224.0.0.251"},
            std::pair{L"2001:db8::10", L"ff02::fb"},
            std::pair{L"192.0.2.10", L"198.51.100.20"}}) {
        for (Dir dir : {Dir::In, Dir::Out}) {
            AskRequest flow = request;
            flow.dir = dir;
            flow.key.local = Ip(local);
            flow.key.remote = Ip(remote);
            flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
            flow.conditionFlags.reset();
            const auto offered = RulePresets::Suggest(flow);
            Check(offered.size() == 1 && offered.front().titleId == IDS_PRESET_WEBVIEW2_MDNS &&
                  RuleStore::MatchesRule(rule, flow.ToQuery()),
                  "WebView2 mDNS depended on direction, endpoint, interface or flags");
        }
    }
    const auto rejectsMdns = [&](const AskRequest& other) {
        const auto offered = RulePresets::Suggest(other);
        Check(std::none_of(offered.begin(), offered.end(), [](const auto& choice) {
                  return choice.titleId == IDS_PRESET_WEBVIEW2_MDNS;
              }) && !RuleStore::MatchesRule(rule, other.ToQuery()),
              "WebView2 mDNS accepted an unrelated connection");
    };
    AskRequest unrelated = request;
    unrelated.key.proto = Proto::Tcp;
    rejectsMdns(unrelated);
    unrelated = request;
    unrelated.key.rport = 5354;
    rejectsMdns(unrelated);
    unrelated = request;
    unrelated.key.lport = 5354;
    rejectsMdns(unrelated);
    unrelated = request;
    unrelated.appPath = L"C:\\Apps\\not-a-preset.exe";
    rejectsMdns(unrelated);
    unrelated = request;
    unrelated.appPath = L"D:\\Other\\msedgewebview2.exe";
    Check(RulePresets::Suggest(unrelated).size() == 1 &&
          !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
          "WebView2 mDNS lost filename matching or concrete path scope");
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner got a WebView2 preset");

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1, "cannot apply WebView2 mDNS preset");
    AskRequest web = request;
    web.key.proto = Proto::Tcp;
    web.key.rport = 443;
    const auto webChoices = RulePresets::Suggest(web);
    const auto& existing = ChoiceOf(webChoices, IDS_PRESET_WEBVIEW2);
    Check(existing.rules.size() == 3 && RulePresets::Apply(store, web, existing.rules) == 3 &&
          store.Count() == 4, "WebView2 mDNS changed the existing web preset");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto localized = RulePresets::Suggest(request);
        const auto& translated = ChoiceOf(localized, IDS_PRESET_WEBVIEW2_MDNS);
        const std::wstring title = LoadStringRes(IDS_PRESET_WEBVIEW2_MDNS);
        const std::wstring name = LoadStringRes(IDS_PRESET_RULE_MDNS);
        Check(title == L"msedgewebview2.exe: mDNS" && !name.empty() &&
              translated.title == title && translated.rules.size() == 1 &&
              translated.rules[0].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                  title.c_str(), name.c_str()) &&
              RulePresets::Apply(store, request, translated.rules) == 0 &&
              store.Count() == 4 && store.version() == version,
              "localized WebView2 mDNS preset was lost or duplicated");
    }
    SetUiLang(previous);
}

void TestITunesPreset() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const std::wstring path = L"C:\\Program Files\\iTunes\\iTunes.exe";
    AskRequest request = Request(path, Proto::Tcp, 47001, L"127.0.0.1");
    request.key.local = Ip(L"127.0.0.1");
    request.key.lport = 52774;
    request.conditionFlags = 1;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured interface");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "iTunes did not get its preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_ITUNES);
    Check(preset.title == L"iTunes.exe: 127.0.0.1 / HTTPS / HTTP / mDNS" && preset.rules.size() == 4,
          "iTunes preset lost its title or four rules");
    for (const Rule& rule : preset.rules) {
        Check(rule.scope == RuleScope::App && rule.appPath == path &&
              rule.action == RuleAction::Allow && rule.services.empty() &&
              rule.interfaceName.empty() && rule.conditionFlags == 0 && !rule.autoName,
              "iTunes preset lost its application scope or pinned an unrelated condition");
    }
    for (size_t i = 0; i < 2; ++i) {
        const Rule& rule = preset.rules[i];
        Check(rule.proto == (i == 0 ? Proto::Tcp : Proto::Udp) && rule.dir == Dir::Unknown &&
              rule.conds == (CondProto | CondRemoteAddr | CondLocalAddr) &&
              rule.remotePorts.empty() && rule.localPorts.empty() &&
              rule.remoteAddrs.size() == 1 && rule.remoteAddrs[0].addr == Ip(L"127.0.0.1") &&
              rule.localAddrs.size() == 1 && rule.localAddrs[0].addr == Ip(L"127.0.0.1"),
              "iTunes loopback rule was widened or pinned ports/direction");
        for (Dir dir : {Dir::In, Dir::Out}) {
            AskRequest flow = request;
            flow.dir = dir;
            flow.key.proto = rule.proto;
            flow.key.lport = 1;
            flow.key.rport = 65535;
            Check(RuleStore::MatchesRule(rule, flow.ToQuery()),
                  "iTunes loopback rule did not allow arbitrary ports or directions");
            for (const wchar_t* address : {L"127.0.0.2", L"::1", L"192.0.2.10"}) {
                AskRequest wrong = flow;
                wrong.key.local = Ip(address);
                Check(!RuleStore::MatchesRule(rule, wrong.ToQuery()),
                      "iTunes loopback rule accepted another local address");
                wrong = flow;
                wrong.key.remote = Ip(address);
                Check(!RuleStore::MatchesRule(rule, wrong.ToQuery()),
                      "iTunes loopback rule accepted another remote address");
            }
        }
    }
    const Rule& web = preset.rules[2];
    Check(web.proto == Proto::Tcp && web.dir == Dir::Out &&
          web.conds == (CondProto | CondDirection | CondRemotePort) &&
          web.remotePorts.size() == 2 && web.remotePorts[0].from == 443 &&
          web.remotePorts[0].to == 443 && web.remotePorts[1].from == 80 &&
          web.remotePorts[1].to == 80 && web.localPorts.empty() &&
          web.localAddrs.empty() && web.remoteAddrs.empty(),
          "iTunes web rule lost HTTP/HTTPS or pinned an endpoint");
    const Rule& mdns = preset.rules[3];
    Check(mdns.proto == Proto::Udp && mdns.dir == Dir::Unknown &&
          mdns.conds == (CondProto | CondRemotePort | CondLocalPort) &&
          mdns.remotePorts.size() == 1 && mdns.remotePorts[0].from == 5353 &&
          mdns.remotePorts[0].to == 5353 && mdns.localPorts.size() == 1 &&
          mdns.localPorts[0].from == 5353 && mdns.localPorts[0].to == 5353 &&
          mdns.localAddrs.empty() && mdns.remoteAddrs.empty(),
          "iTunes mDNS rule lost its paired ports or pinned addresses/direction");
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 4 && store.Count() == 4,
          "cannot apply iTunes preset");
    const uint64_t version = store.version();
    for (Dir dir : {Dir::In, Dir::Out}) {
        for (uint16_t port : {uint16_t{80}, uint16_t{443}}) {
            AskRequest flow = Request(path, Proto::Tcp, port, L"203.0.113.33");
            flow.dir = dir;
            flow.key.lport = 60000;
            const auto offered = RulePresets::Suggest(flow);
            RuleAction action = RuleAction::Block;
            Check(offered.size() == 1 && offered.front().titleId == IDS_PRESET_ITUNES &&
                  RuleStore::MatchesRule(web, flow.ToQuery()) &&
                  store.MatchVerdict(flow.ToQuery(), action) && action == RuleAction::Allow,
                  "iTunes web rule lost a port or existing direction handling");
        }
        AskRequest flow = Request(path, Proto::Udp, 5353, L"224.0.0.251");
        flow.dir = dir;
        flow.key.lport = 5353;
        const auto offered = RulePresets::Suggest(flow);
        RuleAction action = RuleAction::Block;
        Check(offered.size() == 1 && offered.front().titleId == IDS_PRESET_ITUNES &&
              RuleStore::MatchesRule(mdns, flow.ToQuery()) &&
              store.MatchVerdict(flow.ToQuery(), action) && action == RuleAction::Allow,
              "iTunes mDNS rule missed matching traffic");
        flow.key.local = Ip(L"10.20.30.40");
        flow.key.remote = Ip(L"198.51.100.33");
        Check(RuleStore::MatchesRule(mdns, flow.ToQuery()), "iTunes mDNS rule pinned the captured addresses");
        flow.key.rport = 5354;
        Check(!RuleStore::MatchesRule(mdns, flow.ToQuery()), "iTunes mDNS rule accepted another remote port");
        flow.key.rport = 5353;
        flow.key.lport = 5354;
        Check(!RuleStore::MatchesRule(mdns, flow.ToQuery()), "iTunes mDNS rule accepted another local port");
    }
    AskRequest wrong = Request(path, Proto::Tcp, 8080, L"198.51.100.33");
    Check(RulePresets::Suggest(wrong).empty(), "iTunes preset accepted an unrelated connection");
    wrong = request;
    wrong.appPath = L"D:\\Other\\iTunes.exe";
    Check(RulePresets::Suggest(wrong).size() == 1 &&
          !RuleStore::MatchesRule(preset.rules[0], wrong.ToQuery()),
          "iTunes preset lost filename matching or concrete path scope");
    wrong = request;
    wrong.appPath = L"C:\\Apps\\other.exe";
    Check(RulePresets::Suggest(wrong).empty(), "iTunes preset matched another executable");
    wrong = request;
    wrong.ownerAmbiguous = true;
    Check(RulePresets::Suggest(wrong).empty(), "ambiguous owner received iTunes preset");
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto localized = RulePresets::Suggest(request);
        const auto& translated = ChoiceOf(localized, IDS_PRESET_ITUNES);
        Check(translated.title == L"iTunes.exe: 127.0.0.1 / HTTPS / HTTP / mDNS" &&
              translated.rules.size() == 4 &&
              RulePresets::Apply(store, request, translated.rules) == 0 &&
              store.Count() == 4 && store.version() == version,
              "localized iTunes preset was lost or duplicated");
    }
    SetUiLang(previous);
}

void TestTaskHostHttpPreset() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    AskRequest request = Request(SystemDirFile(L"taskhostw.exe"), Proto::Tcp, 80, L"165.204.91.91");
    request.key.local = Ip(L"192.168.0.116");
    request.key.lport = 4867;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
    request.conditionFlags = 1;
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "taskhostw HTTP did not get its preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_TASK_HOST_HTTP);
    Check(preset.title == L"taskhostw.exe: HTTP" && preset.rules.size() == 1,
          "taskhostw HTTP preset lost its title or rule");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondRemotePort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts[0].from == 80 && rule.remotePorts[0].to == 80 &&
          rule.localPorts.empty() && rule.localAddrs.empty() && rule.remoteAddrs.empty() &&
          rule.services.empty() && rule.interfaceName.empty() && rule.conditionFlags == 0,
          "taskhostw HTTP rule lost its conditions or pinned an endpoint");
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1, "cannot apply taskhostw HTTP preset");
    AskRequest https = request;
    https.key.rport = 443;
    const auto httpsChoices = RulePresets::Suggest(https);
    Check(httpsChoices.size() == 1 && httpsChoices.front().titleId == IDS_PRESET_TASK_HOST &&
          !RuleStore::MatchesRule(rule, https.ToQuery()) &&
          RulePresets::Apply(store, https, httpsChoices.front().rules) == 1 && store.Count() == 2,
          "taskhostw HTTP preset changed or duplicated the existing HTTPS preset");
    for (Dir dir : {Dir::In, Dir::Out}) {
        AskRequest flow = request;
        flow.dir = dir;
        flow.key.remote = Ip(L"203.0.113.33");
        flow.key.local = Ip(L"10.20.30.40");
        flow.key.lport = 60000;
        flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
        flow.conditionFlags.reset();
        RuleAction action = RuleAction::Block;
        Check(RuleStore::MatchesRule(rule, flow.ToQuery()) &&
              store.MatchVerdict(flow.ToQuery(), action) && action == RuleAction::Allow,
              "taskhostw HTTP pinned an endpoint or changed direction handling");
    }
    for (auto [proto, port] : {std::pair{Proto::Udp, uint16_t{80}},
                               std::pair{Proto::Tcp, uint16_t{8080}}}) {
        AskRequest wrong = request;
        wrong.key.proto = proto;
        wrong.key.rport = port;
        Check(RulePresets::Suggest(wrong).empty() && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
              "taskhostw HTTP preset accepted an unrelated protocol or port");
    }
    AskRequest wrong = request;
    wrong.ownerAmbiguous = true;
    Check(RulePresets::Suggest(wrong).empty(), "ambiguous owner received taskhostw HTTP preset");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto localized = RulePresets::Suggest(request);
        const auto& translated = ChoiceOf(localized, IDS_PRESET_TASK_HOST_HTTP);
        Check(translated.title == L"taskhostw.exe: HTTP" && translated.rules.size() == 1 &&
              RulePresets::Apply(store, request, translated.rules) == 0 &&
              store.Count() == 2 && store.version() == version,
              "localized taskhostw HTTP preset was lost or duplicated");
    }
    SetUiLang(previous);
}

void TestVisualStudioPresets() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const std::wstring path = L"C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\devenv.exe";
    AskRequest request = Request(path, Proto::Tcp, 443, L"198.51.100.25");
    request.key.lport = 52000;
    request.conditionFlags = 1;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured interface");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 2 && choices.front().titleId == IDS_PRESET_VISUAL_STUDIO_HTTPS,
          "Visual Studio HTTPS must offer the secure profile first");
    const auto& secure = ChoiceOf(choices, IDS_PRESET_VISUAL_STUDIO_HTTPS);
    const auto& web = ChoiceOf(choices, IDS_PRESET_VISUAL_STUDIO_WEB);
    Check(RulePresets::StrictlyCovers(web.rules, secure.rules) &&
          !RulePresets::StrictlyCovers(secure.rules, web.rules) &&
          !RulePresets::StrictlyCovers(web.rules, web.rules),
          "combined web preset coverage was not compared correctly");
    Rule different = web.rules.front();
    different.action = RuleAction::Block;
    Check(!RulePresets::StrictlyCovers({different}, secure.rules),
          "preset coverage compared a blocking rule with an allow rule");
    different = web.rules.front();
    different.appPath = L"C:\\Other\\devenv.exe";
    Check(!RulePresets::StrictlyCovers({different}, secure.rules),
          "preset coverage ignored the application scope");
    different = web.rules.front();
    different.conds |= CondRemoteAddr;
    different.remoteAddrs.push_back({Ip(L"203.0.113.1"), -1});
    Check(!RulePresets::StrictlyCovers({different}, secure.rules),
          "preset coverage ignored an address restriction");
    different = secure.rules.front();
    different.remotePorts.clear();
    Check(!RulePresets::StrictlyCovers(web.rules, {different}),
          "an empty port condition was mistaken for a restricted port set");
    Rule narrowRange = secure.rules.front();
    narrowRange.remotePorts = {{100, 105}, {106, 110}};
    Rule wideRange = narrowRange;
    wideRange.remotePorts = {{99, 111}};
    Check(RulePresets::StrictlyCovers({wideRange}, {narrowRange}) &&
          !RulePresets::StrictlyCovers({narrowRange}, {wideRange}),
          "preset coverage did not compare adjacent port ranges");
    Check(secure.title == L"Visual Studio: HTTPS" && web.title == L"Visual Studio: HTTPS / HTTP" &&
          secure.rules.size() == 1 && web.rules.size() == 1,
          "Visual Studio presets lost their titles or rule counts");
    for (const Rule* rule : {&secure.rules[0], &web.rules[0]}) {
        Check(rule->scope == RuleScope::App && rule->appPath == path &&
              rule->action == RuleAction::Allow && rule->proto == Proto::Tcp &&
              rule->dir == Dir::Out && rule->conds == (CondProto | CondDirection | CondRemotePort) &&
              rule->remotePorts.size() == (rule == &secure.rules[0] ? 1 : 2) &&
              rule->remotePorts[0].from == 443 && rule->remotePorts[0].to == 443 &&
              (rule == &secure.rules[0] ||
                  (rule->remotePorts[1].from == 80 && rule->remotePorts[1].to == 80)) &&
              rule->localPorts.empty() &&
              rule->remoteAddrs.empty() && rule->localAddrs.empty() && rule->services.empty() &&
              rule->interfaceName.empty() && rule->conditionFlags == 0 &&
              !rule->autoName && !rule->name.empty(),
              "Visual Studio rule lost a condition or pinned a captured endpoint");
        for (uint16_t port : {uint16_t{443}, uint16_t{80}}) {
            AskRequest flow = request;
            flow.key.rport = port;
            Check(RuleStore::MatchesRule(*rule, flow.ToQuery()) ==
                      (port == 443 || rule == &web.rules[0]),
                  "Visual Studio rule matched the wrong port");
            flow.key.remote = Ip(L"203.0.113.33");
            flow.key.local = Ip(L"10.20.30.40");
            flow.key.lport = 60000;
            flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
            flow.conditionFlags.reset();
            Check(RuleStore::MatchesRule(*rule, flow.ToQuery()) ==
                      (port == 443 || rule == &web.rules[0]),
                  "Visual Studio rule depends on a transient endpoint or interface");
        }
    }
    AskRequest changed = request;
    changed.key.rport = 80;
    const auto httpChoices = RulePresets::Suggest(changed);
    Check(httpChoices.size() == 1 && httpChoices[0].titleId == IDS_PRESET_VISUAL_STUDIO_WEB &&
          !RuleStore::MatchesRule(secure.rules[0], changed.ToQuery()),
          "Visual Studio HTTP must offer only the web preset");
    for (const auto& [proto, port] : {
            std::pair{Proto::Udp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{80}},
            std::pair{Proto::Tcp, uint16_t{8080}}, std::pair{Proto::Udp, uint16_t{53}}}) {
        changed = request;
        changed.key.proto = proto;
        changed.key.rport = port;
        Check(RulePresets::Suggest(changed).empty(), "Visual Studio preset accepted an unrelated protocol or port");
    }
    changed = request;
    changed.appPath = L"D:\\Apps\\Visual Studio\\Common7\\IDE\\DEVENV.EXE";
    Check(RulePresets::Suggest(changed).size() == 2 &&
          !RuleStore::MatchesRule(secure.rules[0], changed.ToQuery()),
          "Visual Studio filename matching or rule path scope changed");
    for (const wchar_t* filename : {L"devenv.com", L"devenv-helper.exe", L"mydevenv.exe"}) {
        changed.appPath = std::wstring(L"C:\\Apps\\") + filename;
        Check(RulePresets::Suggest(changed).empty(), "Visual Studio preset matched another executable");
    }
    changed = request;
    changed.ownerAmbiguous = true;
    Check(RulePresets::Suggest(changed).empty(), "ambiguous owner got a Visual Studio preset");

    RuleStore store;
    Check(RulePresets::Apply(store, request, secure.rules) == 1 &&
          RulePresets::Apply(store, request, web.rules) == 1 && store.Count() == 2,
          "overlapping Visual Studio presets were not applied");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_VISUAL_STUDIO_WEB);
        Check(localized.title == LoadStringRes(IDS_PRESET_VISUAL_STUDIO_WEB) &&
              localized.rules.size() == 1 &&
              RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 2 && store.version() == version,
              "localized Visual Studio preset lost its title or duplicated rules");
    }
    SetUiLang(previous);
}

void TestIgmpPreset() {
    AskRequest request = Request(L"", ProtoFromNumber(2), 0, L"224.0.0.22");
    request.pid = 0;
    request.process.reset();
    request.key.local = Ip(L"127.0.0.1");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "IGMP PID 0 preset was not suggested");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_IGMP);
    Check(preset.rules.size() == 1, "IGMP preset has an unexpected rule count");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::PostApp && rule.appPath.empty() &&
          rule.conds == (CondProto | CondDirection | CondRemoteAddr | CondPidZero) &&
          rule.proto == ProtoFromNumber(2) && rule.dir == Dir::Out &&
          rule.action == RuleAction::Allow && !rule.autoName && !rule.name.empty() &&
          rule.remoteAddrs.size() == 1 && rule.remoteAddrs[0].addr == Ip(L"224.0.0.0") &&
          rule.remoteAddrs[0].prefix == 4 && rule.localAddrs.empty() &&
          rule.remotePorts.empty() && rule.localPorts.empty(),
          "IGMP preset lost its protocol, PID, direction or multicast restrictions");
    for (const wchar_t* address : {L"224.0.0.1", L"224.0.0.2", L"224.0.0.22",
                                   L"224.0.0.251", L"232.1.2.3", L"239.255.255.255"}) {
        AskRequest other = request;
        other.key.remote = Ip(address);
        Check(RulePresets::Suggest(other).size() == 1 &&
              RuleStore::MatchesRule(rule, other.ToQuery()),
              "IGMP preset missed a multicast address");
    }
    for (const wchar_t* address : {L"223.255.255.255", L"240.0.0.0", L"8.8.8.8", L"ff02::1"}) {
        AskRequest other = request;
        other.key.remote = Ip(address);
        Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
              "IGMP preset matched a non-IPv4-multicast address");
    }
    AskRequest other = request;
    other.pid = 4;
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "IGMP PID 0 preset matched another PID");
    other = request;
    other.appPath = L"C:\\Apps\\test.exe";
    Check(RulePresets::Suggest(other).empty(), "IGMP PID 0 preset matched an application");
    other = request;
    other.key.source = TrafficSource::Ndis;
    Check(RulePresets::Suggest(other).empty(), "IGMP PID 0 preset matched NDIS");
    other = request;
    other.dir = Dir::In;
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "IGMP preset matched incoming traffic");
    other.dir = Dir::Unknown;
    Check(RulePresets::Suggest(other).empty(), "IGMP preset matched unknown direction");
    other = request;
    other.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "IGMP preset matched another protocol");
    other = request;
    other.ownerAmbiguous = true;
    Check(RulePresets::Suggest(other).empty(), "IGMP preset matched an ambiguous owner");

    RuleStore store;
    Check(RulePresets::ApplySelected(store, request, preset.rules) == 1 &&
          store.PostApps().size() == 1 && store.ForApp(request.appPath).empty(),
          "IGMP preset was not saved in the post-app group");
    const uint64_t version = store.version();
    Check(RulePresets::ApplySelected(store, request, preset.rules) == 0 &&
          store.PostApps().size() == 1 && store.version() == version,
          "IGMP preset created a duplicate");
    Rule saved = store.PostApps().front();
    Check(store.SetEnabled(saved.id, false) && RulePresets::ApplySelected(store, request, preset.rules) == 1 &&
          store.PostApps().front().enabled, "IGMP preset did not re-enable its existing rule");
    other = request;
    other.pid = 4;
    Check(RulePresets::ApplySelected(store, other, preset.rules) == 0,
          "IGMP PID 0 preset was applied to another PID");
    other = request;
    other.appPath = L"C:\\Apps\\test.exe";
    Check(RulePresets::ApplySelected(store, other, preset.rules) == 0,
          "IGMP post-app preset was applied to an application");
}

void TestIgmpInboundPreset() {
    AskRequest request = Request(L"", ProtoFromNumber(2), 0, L"192.168.0.1");
    request.pid = 0;
    request.process.reset();
    request.dir = Dir::In;
    request.key.local = Ip(L"224.0.0.1");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "incoming IGMP PID 0 preset was not suggested");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_IGMP_IN);
    Check(preset.rules.size() == 1, "incoming IGMP preset has an unexpected rule count");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::PostApp && rule.appPath.empty() &&
          rule.conds == (CondProto | CondDirection | CondLocalAddr | CondPidZero) &&
          rule.proto == ProtoFromNumber(2) && rule.dir == Dir::In &&
          rule.action == RuleAction::Allow && !rule.autoName && !rule.name.empty() &&
          rule.localAddrs.size() == 1 && rule.localAddrs[0].addr == Ip(L"224.0.0.0") &&
          rule.localAddrs[0].prefix == 4 && rule.remoteAddrs.empty() &&
          rule.remotePorts.empty() && rule.localPorts.empty(),
          "incoming IGMP preset lost its PID, direction or local multicast restrictions");
    for (const wchar_t* address : {L"224.0.0.0", L"224.0.0.1", L"224.0.0.22",
                                   L"224.0.0.251", L"232.1.2.3", L"239.255.255.255"}) {
        AskRequest other = request;
        other.key.local = Ip(address);
        Check(RulePresets::Suggest(other).size() == 1 &&
              RuleStore::MatchesRule(rule, other.ToQuery()),
              "incoming IGMP preset missed a local multicast address");
    }
    for (const wchar_t* address : {L"223.255.255.255", L"240.0.0.0", L"192.0.2.1", L"ff02::1"}) {
        AskRequest other = request;
        other.key.local = Ip(address);
        Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
              "incoming IGMP preset matched a non-IPv4-multicast local address");
    }
    AskRequest other = request;
    other.key.remote = Ip(L"203.0.113.25");
    Check(RuleStore::MatchesRule(rule, other.ToQuery()) && RulePresets::Suggest(other).size() == 1,
          "incoming IGMP preset restricted the remote address");
    other = request;
    other.pid = 4;
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "incoming IGMP preset matched another PID");
    other = request;
    other.appPath = L"C:\\Apps\\test.exe";
    Check(RulePresets::Suggest(other).empty(), "incoming IGMP preset matched an application");
    other = request;
    other.key.source = TrafficSource::Ndis;
    Check(RulePresets::Suggest(other).empty(), "incoming IGMP preset matched NDIS");
    other = request;
    other.dir = Dir::Out;
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "incoming IGMP preset matched outgoing traffic");
    other.dir = Dir::Unknown;
    Check(RulePresets::Suggest(other).empty(), "incoming IGMP preset matched unknown direction");
    other = request;
    other.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "incoming IGMP preset matched another protocol");
    other = request;
    other.ownerAmbiguous = true;
    Check(RulePresets::Suggest(other).empty(), "incoming IGMP preset matched an ambiguous owner");

    RuleStore store;
    AskRequest outgoing = request;
    outgoing.dir = Dir::Out;
    outgoing.key.local = Ip(L"192.0.2.10");
    outgoing.key.remote = Ip(L"224.0.0.22");
    const auto oldChoices = RulePresets::Suggest(outgoing);
    const auto& oldPreset = ChoiceOf(oldChoices, IDS_PRESET_IGMP);
    Check(RulePresets::ApplySelected(store, outgoing, oldPreset.rules) == 1 &&
          RulePresets::ApplySelected(store, request, preset.rules) == 1 &&
          store.PostApps().size() == 2 && store.PostApps().front().dir == Dir::Out &&
          store.PostApps().back().dir == Dir::In,
          "incoming IGMP preset replaced the existing outgoing rule");
    const uint64_t version = store.version();
    Check(RulePresets::ApplySelected(store, request, preset.rules) == 0 &&
          store.PostApps().size() == 2 && store.version() == version,
          "incoming IGMP preset created a duplicate");
    const Rule saved = store.PostApps().back();
    Check(store.SetEnabled(saved.id, false) &&
          RulePresets::ApplySelected(store, request, preset.rules) == 1 &&
          store.PostApps().back().enabled,
          "incoming IGMP preset did not re-enable its existing rule");
}

void TestStoreAppPresets(const wchar_t* path, UINT titleId, uint16_t localPort) {
    AskRequest request = Request(path, Proto::Tcp, 80, L"23.11.40.157");
    request.key.local = Ip(L"10.221.84.6");
    request.key.lport = localPort;
    const size_t reads = serviceReads;
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1 && serviceReads == reads,
          "Store application did not get exactly one profile or queried hosted services");
    const auto& preset = ChoiceOf(choices, titleId);
    Check(preset.rules.size() == 3 && preset.title == LoadStringRes(titleId),
          "Store application profile lost its web rules or localized title");
    for (const Rule& rule : preset.rules) {
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.dir == Dir::Out &&
              !(rule.conds & CondService) && rule.services.empty() &&
              !rule.autoName && rule.name.find(preset.title) != std::wstring::npos,
              "Store application rule lost its application scope or got a service condition");
        Check(!rule.remotePorts.empty() && rule.localPorts.empty() && rule.localAddrs.empty() &&
              !(rule.conds & (CondLocalPort | CondLocalAddr)),
              "Store application rule pinned the captured local endpoint");
        const uint16_t port = rule.remotePorts.front().from;
        Check(rule.remotePorts.front().to == port, "Store application rule widened the port range");
        if (port == 53) {
            Check(rule.remotePorts.size() == 1 && (rule.proto == Proto::Tcp || rule.proto == Proto::Udp) &&
                  (rule.conds & CondRemoteAddr) && rule.remoteAddrs.size() == 2 &&
                  rule.remoteAddrs[0].macro == AddrMacro::DnsServers &&
                  rule.remoteAddrs[1].macro == AddrMacro::MyComputer,
                  "Store application DNS lost its resolver restriction");
        } else {
            Check(rule.proto == Proto::Tcp && port == 443 && rule.remotePorts.size() == 2 &&
                  rule.remotePorts[1].from == 80 && rule.remotePorts[1].to == 80 &&
                  !(rule.conds & CondRemoteAddr) && rule.remoteAddrs.empty(),
                  "Store application web rule pinned a server or allowed an unrelated port");
        }
    }
    for (auto [proto, port, remote] : {
        std::tuple{Proto::Tcp, uint16_t{80}, L"23.11.40.157"},
        std::tuple{Proto::Tcp, uint16_t{443}, L"198.51.100.20"},
        std::tuple{Proto::Tcp, uint16_t{80}, L"2001:db8::20"},
        std::tuple{Proto::Tcp, uint16_t{443}, L"2001:db8::20"},
        std::tuple{Proto::Udp, uint16_t{53}, L"127.0.0.1"},
        std::tuple{Proto::Tcp, uint16_t{53}, L"127.0.0.1"}
    }) {
        AskRequest connection = Request(request.appPath, proto, port, remote);
        if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"2001:db8::10");
        const auto suggested = RulePresets::Suggest(connection);
        Check(suggested.size() == 1 && suggested.front().titleId == titleId,
              "Store application missed a supported web or DNS connection");
        const MatchQuery query = MakeMatchQuery(connection.appPath, connection.pid, connection.key,
            connection.dir, connection.icmpType, connection.icmpCode,
            connection.process.get());
        Check(std::any_of(preset.rules.begin(), preset.rules.end(),
                         [&](const Rule& rule) { return RuleStore::MatchesRule(rule, query); }),
              "Store application rules did not permit a supported connection");
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{22}},
        std::pair{Proto::Udp, uint16_t{443}},
        std::pair{Proto::Udp, uint16_t{53}},
        std::pair{Proto::Tcp, uint16_t{53}},
        std::pair{Proto::Icmp, uint16_t{0}}
    })
        Check(RulePresets::Suggest(Request(request.appPath, proto, port)).empty(),
              "Store application permitted SSH, QUIC, arbitrary DNS or an unrelated protocol");
    AskRequest unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous Store application owner got a preset");
    unrelated = request;
    unrelated.appPath += L".bak";
    Check(RulePresets::Suggest(unrelated).empty(), "Store application profile matched a name suffix");
    unrelated.appPath = L"C:\\Apps\\not-" + request.appName;
    Check(RulePresets::Suggest(unrelated).empty(), "Store application profile matched a name prefix");
    const MatchQuery otherQuery = MakeMatchQuery(unrelated.appPath, unrelated.pid, unrelated.key,
        unrelated.dir, unrelated.icmpType, unrelated.icmpCode, unrelated.process.get());
    for (const Rule& rule : preset.rules)
        Check(!RuleStore::MatchesRule(rule, otherQuery), "Store application rule permitted another path");

    RuleStore store;
    Check(RulePresets::Apply(store, request, {preset.rules.front()}) == 1 &&
          RulePresets::Apply(store, request, preset.rules) == 2 && store.Count() == 3,
          "Store application profile duplicated an existing rule");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, preset.rules) == 0 && store.version() == version,
          "repeated Store application profile changed the store");
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::Russian);
    const auto translated = RulePresets::Suggest(request);
    Check(RulePresets::Apply(store, request, ChoiceOf(translated, titleId).rules) == 0 &&
          store.version() == version, "Store application translation bypassed deduplication");
    SetUiLang(previous);
    AskRequest relocated = request;
    relocated.appPath = L"D:\\Apps\\" + request.appName;
    const auto separate = RulePresets::Suggest(relocated);
    Check(RulePresets::Apply(store, relocated, ChoiceOf(separate, titleId).rules) == 3 &&
          store.Count() == 6, "Store application profile did not keep installation paths separate");
}

void TestTorrentPresets() {
    const wchar_t* executables[] = {
        L"qBittorrent.EXE", L"qbittorrent-nox.exe", L"utorrent.exe", L"utweb.exe",
        L"bittorrent.exe", L"btweb.exe", L"transmission-qt.exe", L"transmission-daemon.exe",
        L"transmission-cli.exe", L"deluge.exe", L"deluge-gtk.exe", L"deluged.exe",
        L"tixati.exe", L"bitcomet.exe", L"bitcomet_x64.exe", L"biglybt.exe",
        L"vuze.exe", L"azureus.exe", L"picotorrent.exe", L"halite.exe", L"tribler.exe",
        L"frostwire.exe", L"webtorrent.exe", L"aria2c.exe", L"bitlord.exe", L"bitspirit.exe"
    };
    for (const wchar_t* executable : executables) {
        AskRequest request = Request(std::wstring(L"C:\\Apps\\") + executable, Proto::Udp, 45678);
        const auto choices = RulePresets::Suggest(request);
        Check(choices.size() == 1, "torrent client did not get exactly one profile");
        const auto& torrent = ChoiceOf(choices, IDS_PRESET_TORRENT);
        Check(torrent.rules.size() == 2 && torrent.rules[0].proto == Proto::Tcp &&
              torrent.rules[1].proto == Proto::Udp, "torrent profile must contain only TCP and UDP");
        for (const Rule& rule : torrent.rules) {
            Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
                  rule.action == RuleAction::Allow && rule.conds == CondProto &&
                  rule.dir == Dir::Unknown && rule.remotePorts.empty() && rule.localPorts.empty() &&
                  rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.services.empty() &&
                  !rule.autoName && !rule.name.empty(),
                  "torrent profile escaped the app or restricted peer ports, addresses or direction");
        }
    }

    AskRequest request = Request(L"C:\\Apps\\qbittorrent.exe", Proto::Udp, 45678);
    const auto choices = RulePresets::Suggest(request);
    const auto& torrent = ChoiceOf(choices, IDS_PRESET_TORRENT);
    for (Proto proto : {Proto::Tcp, Proto::Udp}) {
        for (Dir dir : {Dir::Out, Dir::In}) {
            for (auto [local, remote, port] : {
                std::tuple{L"192.0.2.10", L"198.51.100.20", uint16_t{1}},
                std::tuple{L"192.0.2.10", L"198.51.100.20", uint16_t{65535}},
                std::tuple{L"192.0.2.10", L"198.51.100.20", uint16_t{443}},
                std::tuple{L"192.0.2.10", L"198.51.100.20", uint16_t{6969}},
                std::tuple{L"2001:db8::10", L"2001:db8::20", uint16_t{6881}},
                std::tuple{L"127.0.0.1", L"127.0.0.1", uint16_t{45678}},
                std::tuple{L"::1", L"::1", uint16_t{80}},
                std::tuple{L"192.0.2.10", L"239.192.152.143", uint16_t{6771}},
                std::tuple{L"192.0.2.10", L"239.255.255.250", uint16_t{1900}},
                std::tuple{L"192.0.2.10", L"192.0.2.1", uint16_t{5351}}
            }) {
                AskRequest connection = Request(request.appPath, proto, port, remote);
                connection.dir = dir;
                connection.key.local = Ip(local);
                connection.key.lport = 51413;
                const auto suggested = RulePresets::Suggest(connection);
                Check(suggested.size() == 1, "torrent profile missed a peer, tracker or local connection");
                ChoiceOf(suggested, IDS_PRESET_TORRENT);
                const MatchQuery query = MakeMatchQuery(connection.appPath, connection.pid, connection.key,
                    connection.dir, connection.icmpType, connection.icmpCode,
                    connection.process.get());
                for (const Rule& rule : torrent.rules)
                    Check(RuleStore::MatchesRule(rule, query) == (rule.proto == proto),
                          "torrent rule ignored its protocol or rejected a supported connection");
            }
        }
    }
    for (Proto proto : {Proto::Icmp, Proto::IcmpV6, ProtoFromNumber(144)}) {
        AskRequest unrelated = request;
        unrelated.key.proto = proto;
        Check(RulePresets::Suggest(unrelated).empty(), "torrent profile permitted an unrelated protocol");
    }
    for (const wchar_t* executable : {L"not-qbittorrent.exe", L"qbittorrent.exe.bak",
                                     L"javaw.exe", L"python.exe"})
        Check(RulePresets::Suggest(Request(std::wstring(L"C:\\Apps\\") + executable)).empty(),
              "torrent profile matched a partial name or a generic runtime");
    AskRequest unrelated = Request(L"C:\\Apps\\other.exe", request.key.proto, request.key.rport);
    const MatchQuery otherQuery = MakeMatchQuery(unrelated.appPath, unrelated.pid, unrelated.key,
        unrelated.dir, unrelated.icmpType, unrelated.icmpCode, unrelated.process.get());
    for (const Rule& rule : torrent.rules)
        Check(!RuleStore::MatchesRule(rule, otherQuery), "torrent rule permitted a different application");
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous torrent owner got a preset");

    RuleStore store;
    Check(RulePresets::Apply(store, request, {torrent.rules.front()}) == 1,
          "cannot seed an existing torrent TCP rule");
    Check(RulePresets::Apply(store, request, torrent.rules) == 1 && store.Count() == 2,
          "torrent profile duplicated an existing rule");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, torrent.rules) == 0 && store.version() == version,
          "repeated torrent profile changed the store");
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::Russian);
    const auto translated = RulePresets::Suggest(request);
    Check(RulePresets::Apply(store, request, ChoiceOf(translated, IDS_PRESET_TORRENT).rules) == 0 &&
          store.version() == version, "torrent translation bypassed deduplication");
    SetUiLang(previous);
    AskRequest portable = request;
    portable.appPath = L"D:\\Portable\\qbittorrent.exe";
    const auto separate = RulePresets::Suggest(portable);
    Check(RulePresets::Apply(store, portable, ChoiceOf(separate, IDS_PRESET_TORRENT).rules) == 2 &&
          store.Count() == 4, "torrent profile did not keep application paths separate");
}

void TestAdditionalApplicationPresets() {
    const wchar_t* chrome = L"C:\\Program Files\\Google\\Chrome\\Application\\CHROME.EXE";
    AskRequest mdns = Request(chrome, Proto::Udp, 5353, L"224.0.0.251");
    mdns.key.local = Ip(L"10.94.59.2");
    mdns.key.lport = 5353;
    mdns.conditionFlags = 1;
    mdns.interfaceIndex = 15;
    mdns.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
    AskRequest push = Request(chrome, Proto::Tcp, 5228, L"64.233.164.188");
    push.key.local = Ip(L"10.221.84.6");
    push.key.lport = 39488;
    AskRequest broker = Request(SystemDirFile(L"RuntimeBroker.exe"), Proto::Tcp, 443, L"150.171.109.53");
    broker.key.local = Ip(L"192.168.0.196");
    broker.key.lport = 23922;
    AskRequest capability = Request(SystemDirFile(L"svchost.exe"), Proto::Tcp, 80, L"23.11.40.157");
    capability.key.local = Ip(L"192.168.0.196");
    capability.key.lport = 6340;
    const auto browserChoices = RulePresets::Suggest(Request(chrome));
    Check(browserChoices.size() == 2 &&
          ChoiceOf(browserChoices, IDS_PRESET_BROWSER_HTTPS).rules.size() == 4 &&
          ChoiceOf(browserChoices, IDS_PRESET_BROWSER_WEB).rules.size() == 4,
          "additional Chrome profiles changed the existing browser permissions");

    struct TestCase {
        AskRequest request;
        UINT titleId;
        UINT ruleNameId;
        const wchar_t* service;
        const wchar_t* russianTitle;
        const wchar_t* englishTitle;
    };
    const TestCase cases[] = {
        {mdns, IDS_PRESET_CHROME_MDNS, IDS_PRESET_RULE_MDNS, nullptr,
            L"Chrome: mDNS в локальной сети", L"Chrome: local network mDNS"},
        {push, IDS_PRESET_CHROME_PUSH, IDS_PRESET_RULE_GOOGLE_PUSH, nullptr,
            L"Chrome: push-уведомления Google", L"Chrome: Google push notifications"},
        {broker, IDS_PRESET_RUNTIME_BROKER, IDS_PRESET_RULE_HTTPS, nullptr,
            L"Брокер среды выполнения: HTTPS", L"Runtime Broker: HTTPS"},
        {capability, IDS_PRESET_CAPABILITY_ACCESS, IDS_PRESET_RULE_HTTP, L"camsvc",
            L"Диспетчер доступа к возможностям: HTTP", L"Capability Access Manager: HTTP"}
    };
    for (const TestCase& test : cases) {
        const AskRequest& request = test.request;
        if (test.service) SetServices(request.pid, {test.service});
        else SetServices(request.pid, {});
        const bool discovery = test.titleId == IDS_PRESET_CHROME_MDNS;
        const auto choices = RulePresets::Suggest(request);
        Check(choices.size() == 1, "connection did not get its exact additional profile");
        const auto& preset = ChoiceOf(choices, test.titleId);
        Check(preset.rules.size() == 1, "additional profile included unrelated permissions");
        const Rule& rule = preset.rules.front();
        const uint32_t conds = CondProto | CondDirection | CondRemotePort |
            (discovery ? CondRemoteAddr | CondLocalPort : 0) | (test.service ? CondService : 0);
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.proto == request.key.proto &&
              rule.dir == Dir::Out && rule.conds == conds && !rule.autoName &&
              rule.remotePorts.size() == 1 && rule.remotePorts.front().from == request.key.rport &&
              rule.remotePorts.front().to == request.key.rport && rule.localAddrs.empty(),
              "additional rule lost its protocol, direction or port, or pinned captured conditions");
        if (discovery) {
            Check(rule.localPorts.size() == 1 && rule.localPorts.front().from == 5353 &&
                  rule.localPorts.front().to == 5353 && rule.remoteAddrs.size() == 4 &&
                  rule.remoteAddrs[0].macro == AddrMacro::LocalNetwork &&
                  rule.remoteAddrs[1].macro == AddrMacro::MyComputer &&
                  rule.remoteAddrs[2].addr == Ip(L"224.0.0.251") &&
                  rule.remoteAddrs[3].addr == Ip(L"ff02::fb"),
                  "Chrome mDNS lost its source port or local discovery address restrictions");
        } else {
            Check(rule.remoteAddrs.empty() && rule.localPorts.empty(),
                  "additional web rule pinned a captured IP or local port");
        }
        Check(test.service ? rule.services.size() == 1 && rule.services.front().name == test.service
                           : rule.services.empty(),
              "additional rule lost or guessed a service identity");
        const auto matches = [&](const AskRequest& connection) {
            return RuleStore::MatchesRule(rule, connection.ToQuery());
        };
        const auto offered = [&](const AskRequest& connection) {
            const auto suggested = RulePresets::Suggest(connection);
            return std::any_of(suggested.begin(), suggested.end(), [&](const auto& choice) {
                return choice.titleId == test.titleId;
            });
        };
        for (auto [local, remote] : {
            std::pair{L"192.0.2.22", discovery ? L"224.0.0.251" : L"198.51.100.20"},
            std::pair{L"2001:db8::22", discovery ? L"ff02::fb" : L"2001:db8::20"}
        }) {
            AskRequest changed = request;
            changed.key.local = Ip(local);
            changed.key.remote = Ip(remote);
            changed.key.lport = discovery ? 5353 : 55000;
            changed.interfaceIndex = 99;
            changed.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
            changed.conditionFlags.reset();
            Check(offered(changed) && matches(changed),
                  "additional profile depended on the captured endpoint, interface or WFP flags");
            changed.dir = Dir::In;
            Check(matches(changed), "additional rule changed bidirectional endpoint-restricted allow semantics");
        }
        AskRequest unrelated = request;
        unrelated.key.proto = discovery ? Proto::Tcp : Proto::Udp;
        Check(!offered(unrelated) && !matches(unrelated), "additional profile accepted another protocol");
        unrelated = request;
        ++unrelated.key.rport;
        Check(!offered(unrelated) && !matches(unrelated), "additional profile accepted another remote port");
        unrelated = request;
        unrelated.appPath = L"C:\\Other\\" + PathBaseUpper(request.appPath);
        Check(!matches(unrelated), "additional rule escaped its executable path");
        unrelated.appPath = L"C:\\Apps\\not-a-preset.exe";
        Check(!offered(unrelated), "additional profile matched an unrelated executable");
        unrelated = request;
        unrelated.ownerAmbiguous = true;
        Check(!offered(unrelated), "ambiguous owner received an additional application profile");
        if (discovery) {
            unrelated = request;
            unrelated.key.remote = Ip(L"198.51.100.20");
            Check(!offered(unrelated) && !matches(unrelated), "Chrome mDNS allowed a public peer");
            unrelated = request;
            ++unrelated.key.lport;
            Check(!offered(unrelated) && !matches(unrelated), "Chrome mDNS accepted another local port");
            for (const wchar_t* file : {L"msedge.exe", L"brave.exe", L"chromium.exe"}) {
                unrelated = request;
                unrelated.appPath = std::wstring(L"C:\\Apps\\") + file;
                Check(!offered(unrelated) && !matches(unrelated), "Chrome mDNS leaked to another browser");
            }
        }

        RuleStore store;
        const bool chromeProfile = discovery || test.titleId == IDS_PRESET_CHROME_PUSH;
        if (chromeProfile)
            Check(RulePresets::Apply(store, request,
                  ChoiceOf(browserChoices, IDS_PRESET_BROWSER_HTTPS).rules) == 4,
                  "could not seed existing Chrome permissions");
        const size_t expectedCount = chromeProfile ? 5 : 1;
        Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == expectedCount,
              "additional profile did not preserve existing application rules");
        const uint64_t version = store.version();
        const UiLang previous = CurrentUiLang();
        SetUiLang(UiLang::Russian);
        Check(LoadStringRes(test.titleId) == test.russianTitle, "additional Russian title was decoded incorrectly");
        SetUiLang(UiLang::English);
        Check(LoadStringRes(test.titleId) == test.englishTitle, "additional English title was decoded incorrectly");
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            const auto translated = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(translated, test.titleId);
            const std::wstring title = LoadStringRes(test.titleId);
            const std::wstring name = LoadStringRes(test.ruleNameId);
            Check(localized.title == (test.service
                      ? LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT, title.c_str(), test.service) : title) &&
                  localized.rules.size() == 1 && localized.rules.front().name == (test.service
                      ? LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT, title.c_str(), test.service, name.c_str())
                      : LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), name.c_str())),
                  "additional profile lost its localized title or rule name");
            Check(RulePresets::Apply(store, request, localized.rules) == 0 &&
                  store.Count() == expectedCount && store.version() == version,
                  "translated additional profile duplicated a rule");
        }
        SetUiLang(previous);
        if (test.service) {
            SetServices(request.pid, {L"BITS"});
            Check(!offered(request) && !matches(request), "camsvc HTTP rule leaked to another service");
            SetServices(request.pid, {L"camsvc", L"BITS"});
            Check(!offered(request) && !matches(request), "shared svchost guessed camsvc");
            SetServices(request.pid, {L"cAmSvC"});
            Check(offered(request) && matches(request), "camsvc matching was case-sensitive");
            unrelated = request;
            unrelated.appPath = L"C:\\Apps\\svchost.exe";
            Check(!offered(unrelated) && !matches(unrelated), "fake svchost received the camsvc profile");
            unrelated = request;
            unrelated.process.reset();
            const size_t reads = serviceReads;
            Check(!offered(unrelated) && !matches(unrelated) && serviceReads == reads,
                  "camsvc profile queried a service PID without the original process handle");
        }
        SetServices(request.pid, {});
    }
}

void TestEdgeMdnsPreset() {
    const std::wstring edge = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    AskRequest request = Request(edge, Proto::Udp, 5353, L"224.0.0.251");
    request.key.local = Ip(L"192.168.137.1");
    request.key.lport = 5353;
    request.conditionFlags = 1;
    request.interfaceIndex = 15;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured Ethernet");

    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "Edge mDNS connection did not get its own preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_EDGE_MDNS);
    Check(preset.rules.size() == 1, "Edge mDNS preset included unrelated rules");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == edge &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Udp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondRemotePort | CondLocalPort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 5353 &&
          rule.remotePorts.front().to == 5353 && rule.localPorts.size() == 1 &&
          rule.localPorts.front().from == 5353 && rule.localPorts.front().to == 5353 &&
          rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.services.empty() && !rule.autoName,
          "Edge mDNS rule lost its port conditions or pinned captured connection details");

    const auto offered = [&](const AskRequest& connection) {
        const auto suggested = RulePresets::Suggest(connection);
        return std::any_of(suggested.begin(), suggested.end(), [](const auto& choice) {
            return choice.titleId == IDS_PRESET_EDGE_MDNS;
        });
    };
    const auto matches = [&](const AskRequest& connection) {
        return RuleStore::MatchesRule(rule, connection.ToQuery());
    };
    Check(matches(request), "Edge mDNS rule did not match the captured connection");
    for (auto [local, remote] : {
        std::pair{L"192.0.2.22", L"198.51.100.20"},
        std::pair{L"2001:db8::22", L"ff02::fb"}
    }) {
        AskRequest changed = request;
        changed.key.local = Ip(local);
        changed.key.remote = Ip(remote);
        changed.interfaceIndex = 99;
        changed.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
        changed.conditionFlags.reset();
        Check(offered(changed) && matches(changed), "Edge mDNS pinned an address, interface or WFP flags");
        changed.dir = Dir::In;
        Check(offered(changed) && matches(changed), "Edge mDNS changed allow-rule direction semantics");
    }
    AskRequest changed = request;
    changed.key.proto = Proto::Tcp;
    Check(!offered(changed) && !matches(changed), "Edge mDNS accepted TCP");
    changed = request;
    ++changed.key.rport;
    Check(!offered(changed) && !matches(changed), "Edge mDNS accepted another remote port");
    changed = request;
    ++changed.key.lport;
    Check(!offered(changed) && !matches(changed), "Edge mDNS accepted another local port");
    changed = request;
    changed.appPath = L"D:\\Portable\\MSEDGE.EXE";
    Check(offered(changed) && !matches(changed), "Edge mDNS lost installation independence or path scope");
    changed.appPath = L"C:\\Apps\\chrome.exe";
    Check(!offered(changed) && !matches(changed), "Edge mDNS leaked to another browser");
    changed = request;
    changed.ownerAmbiguous = true;
    Check(!offered(changed), "ambiguous owner received the Edge mDNS preset");

    const auto browserChoices = RulePresets::Suggest(Request(edge));
    RuleStore store;
    Check(RulePresets::Apply(store, request, ChoiceOf(browserChoices, IDS_PRESET_BROWSER_HTTPS).rules) == 4,
          "could not seed existing Edge browser permissions");
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 5,
          "Edge mDNS preset did not preserve existing browser permissions");
    RuleAction verdict = RuleAction::Block;
    Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == RuleAction::Allow,
          "applied Edge mDNS rule did not allow the connection");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_EDGE_MDNS);
        const std::wstring title = LoadStringRes(IDS_PRESET_EDGE_MDNS);
        const std::wstring name = LoadStringRes(IDS_PRESET_RULE_MDNS);
        Check(title == L"Microsoft Edge: mDNS" && localized.title == title &&
              localized.rules.size() == 1 && localized.rules.front().name ==
                  LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), name.c_str()),
              "Edge mDNS preset lost its localized title or rule name");
        Check(RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 5 && store.version() == version,
              "translated Edge mDNS preset duplicated a rule");
    }
    SetUiLang(previous);
}

void TestCopilotAppPreset() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const std::wstring path = L"C:\\Program Files\\WindowsApps\\Microsoft.Copilot_1.2.3.0_x64__8wekyb3d8bbwe\\CopilotApp.exe";
    AskRequest request = Request(path);
    const auto choices = RulePresets::Suggest(request);
    const auto& preset = ChoiceOf(choices, IDS_PRESET_COPILOT_APP);
    Check(preset.rules.size() == 6, "Copilot preset lost its combined or captured rules");
    for (const Rule& rule : preset.rules) {
        Check(rule.scope == RuleScope::App && rule.appPath == path && rule.action == RuleAction::Allow &&
              rule.services.empty() && !rule.autoName,
              "Copilot rule lost its application scope or action");
    }
    const auto portIs = [](const std::vector<PortItem>& ports, uint16_t port) {
        return ports.size() == 1 && ports.front().from == port && ports.front().to == port;
    };
    const auto addressIs = [](const std::vector<AddrItem>& addresses, const wchar_t* value) {
        return addresses.size() == 1 && addresses.front().macro == AddrMacro::None &&
               addresses.front().addr == Ip(value) && addresses.front().prefix == -1;
    };
    const Rule& dns = preset.rules[0];
    Check(dns.proto == Proto::Udp && dns.dir == Dir::Out &&
          dns.conds == (CondProto | CondDirection | CondRemoteAddr | CondRemotePort) &&
          portIs(dns.remotePorts, 53) && dns.localPorts.empty() && dns.localAddrs.empty() &&
          dns.remoteAddrs.size() == 1 && dns.remoteAddrs.front().macro == AddrMacro::DnsServers,
          "Copilot DNS was not restricted to configured servers and UDP/53");
    const Rule& mdnsOut = preset.rules[1];
    Check(mdnsOut.proto == Proto::Udp && mdnsOut.dir == Dir::Out &&
          mdnsOut.conds == (CondProto | CondDirection | CondRemoteAddr | CondRemotePort | CondLocalPort) &&
          portIs(mdnsOut.remotePorts, 5353) && portIs(mdnsOut.localPorts, 5353) &&
          mdnsOut.remoteAddrs.size() == 2 && mdnsOut.remoteAddrs[0].addr == Ip(L"224.0.0.251") &&
          mdnsOut.remoteAddrs[1].addr == Ip(L"ff02::fb") && mdnsOut.localAddrs.empty(),
          "Copilot outgoing mDNS lost its address or port restrictions");
    for (size_t i : {size_t{2}, size_t{5}}) {
        const Rule& rule = preset.rules[i];
        Check(rule.proto == (i == 2 ? Proto::Tcp : Proto::Udp) && rule.dir == Dir::Out &&
              rule.conds == (CondProto | CondDirection | CondRemotePort) &&
              portIs(rule.remotePorts, 443) && rule.localPorts.empty() &&
              rule.localAddrs.empty() && rule.remoteAddrs.empty(),
              "Copilot HTTPS or QUIC pinned an address or allowed another port");
    }
    for (size_t i : {size_t{3}, size_t{4}}) {
        const Rule& rule = preset.rules[i];
        Check(rule.proto == Proto::Udp && rule.dir == Dir::In &&
              rule.conds == (CondProto | CondDirection | CondLocalAddr | CondLocalPort |
                             (i == 4 ? CondRemotePort : 0)) &&
              portIs(rule.localPorts, 5353) &&
              (i == 4 ? portIs(rule.remotePorts, 5353) : rule.remotePorts.empty()) &&
              addressIs(rule.localAddrs, i == 3 ? L"224.0.0.251" : L"ff02::fb") &&
              rule.remoteAddrs.empty(), "Copilot incoming mDNS lost its address or port restrictions");
    }

    const auto offered = [](const AskRequest& connection) {
        const auto suggested = RulePresets::Suggest(connection);
        return std::any_of(suggested.begin(), suggested.end(), [](const auto& choice) {
            return choice.titleId == IDS_PRESET_COPILOT_APP;
        });
    };
    const auto matches = [&](size_t index, const AskRequest& connection) {
        return RuleStore::MatchesRule(preset.rules[index], connection.ToQuery());
    };
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 6 && store.Count() == 6,
          "Copilot preset was not applied");
    for (size_t i : {size_t{1}, size_t{2}, size_t{4}, size_t{5}}) {
        const size_t ruleIndex = i <= 2 ? 1 : i - 1;
        const bool ipv6 = i == 2 || i == 5;
        const bool inbound = i >= 4;
        AskRequest flow = Request(path, Proto::Udp, i == 4 ? 42000 : 5353,
                                  inbound ? (ipv6 ? L"fe80::2" : L"192.0.2.20") :
                                            (ipv6 ? L"ff02::fb" : L"224.0.0.251"));
        flow.dir = inbound ? Dir::In : Dir::Out;
        flow.key.local = Ip(inbound ? (ipv6 ? L"ff02::fb" : L"224.0.0.251") :
                                      (ipv6 ? L"fe80::1" : L"192.0.2.10"));
        flow.key.lport = 5353;
        RuleAction verdict = RuleAction::Block;
        Check(offered(flow) && matches(ruleIndex, flow) && store.MatchVerdict(flow.ToQuery(), verdict) &&
              verdict == RuleAction::Allow, "Copilot mDNS did not match the captured flow");
        AskRequest changed = flow;
        changed.key.proto = Proto::Tcp;
        Check(!offered(changed) && !matches(ruleIndex, changed), "Copilot mDNS accepted TCP");
        changed = flow;
        ++changed.key.lport;
        Check(!offered(changed) && !matches(ruleIndex, changed), "Copilot mDNS accepted another local port");
        changed = flow;
        if (inbound) changed.key.local = Ip(ipv6 ? L"ff02::fc" : L"224.0.0.250");
        else changed.key.remote = Ip(ipv6 ? L"ff02::fc" : L"224.0.0.250");
        Check(!offered(changed) && !matches(ruleIndex, changed), "Copilot mDNS accepted another multicast address");
        changed = flow;
        ++changed.key.rport;
        Check(matches(ruleIndex, changed) == (i == 4) && offered(changed) == (i == 4),
              "Copilot mDNS changed the captured remote port restriction");
    }
    for (const auto& server : AddrMacros::Resolve(AddrMacro::DnsServers)) {
        AskRequest flow = Request(path, Proto::Udp, 53);
        flow.key.remote = server.addr;
        Check(matches(0, flow) && offered(flow), "Copilot DNS rejected a configured DNS server");
    }
    for (const wchar_t* address : {L"198.51.100.123", L"2001:db8::53"}) {
        AskRequest flow = Request(path, Proto::Udp, 53, address);
        const bool configured = AddrMacros::Matches(AddrMacro::DnsServers, flow.key.remote);
        Check(matches(0, flow) == configured && offered(flow) == configured,
              "Copilot DNS ignored the configured-server boundary");
    }
    Check(matches(2, request) && offered(request), "Copilot HTTPS was not offered");
    AskRequest changed = request;
    changed.key.proto = Proto::Udp;
    Check(matches(5, changed) && offered(changed), "Copilot QUIC was not offered");
    changed.key.rport = 80;
    Check(!offered(changed), "Copilot preset allowed an unrelated UDP port");
    changed = request;
    changed.key.rport = 80;
    Check(!offered(changed), "Copilot preset allowed HTTP");
    changed = request;
    changed.appPath = L"C:\\Program Files\\WindowsApps\\Microsoft.Copilot_2.0.0.0_x64__8wekyb3d8bbwe\\COPILOTAPP.EXE";
    Check(offered(changed) && !matches(2, changed), "Copilot preset lost version independence or exact rule path");
    changed.appPath = L"C:\\Apps\\M365Copilot.exe";
    Check(!offered(changed), "CopilotApp preset matched a different executable");
    changed = request;
    changed.ownerAmbiguous = true;
    Check(!offered(changed), "ambiguous owner received the Copilot preset");

    const UINT names[] = {IDS_PRESET_RULE_DNS_UDP, IDS_PRESET_RULE_MDNS, IDS_PRESET_RULE_HTTPS,
                          IDS_PRESET_RULE_MDNS_IN_IPV4, IDS_PRESET_RULE_MDNS_IN_IPV6,
                          IDS_PRESET_RULE_QUIC};
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_COPILOT_APP);
        const std::wstring title = LoadStringRes(IDS_PRESET_COPILOT_APP);
        Check(title == L"CopilotApp.exe: DNS / mDNS / HTTPS / QUIC" && localized.title == title &&
              localized.rules.size() == 6, "Copilot localized title or rule count changed");
        for (size_t j = 0; j < localized.rules.size(); ++j) {
            const std::wstring name = LoadStringRes(names[j]);
            Check(localized.rules[j].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), name.c_str()),
                  "Copilot lost a localized rule name");
        }
        Check(RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 6 && store.version() == version,
              "localized Copilot preset duplicated a rule");
    }
    SetUiLang(previous);
}

void TestDiscordAndObsPresets() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const std::wstring discordPath = L"C:\\Users\\Admin\\AppData\\Local\\Discord\\app-1.0.9267\\Discord.exe";
    AskRequest discord = Request(discordPath, Proto::Tcp, 80, L"23.11.40.157");
    const auto choices = RulePresets::Suggest(discord);
    const auto& preset = ChoiceOf(choices, IDS_PRESET_DISCORD_HTTP);
    Check(preset.rules.size() == 1, "Discord HTTP preset included unrelated rules");
    const Rule& http = preset.rules.front();
    Check(http.scope == RuleScope::App && http.appPath == discordPath &&
          http.proto == Proto::Tcp && http.dir == Dir::Out && http.action == RuleAction::Allow &&
          http.conds == (CondProto | CondDirection | CondRemotePort) &&
          http.remotePorts.size() == 1 && http.remotePorts[0].from == 80 && http.remotePorts[0].to == 80 &&
          http.remoteAddrs.empty() && http.localAddrs.empty() && http.localPorts.empty() &&
          RuleStore::MatchesRule(http, discord.ToQuery()), "Discord HTTP rule lost a captured restriction");
    AskRequest changed = discord;
    changed.key.remote = Ip(L"203.0.113.9");
    changed.key.local = Ip(L"192.0.2.8");
    changed.key.lport = 51000;
    Check(RuleStore::MatchesRule(http, changed.ToQuery()), "Discord HTTP pinned a temporary endpoint");
    changed.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(http, changed.ToQuery()),
          "Discord HTTP accepted UDP");
    changed = discord;
    changed.key.rport = 8080;
    Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(http, changed.ToQuery()),
          "Discord HTTP accepted another port");
    changed = discord;
    changed.appPath = L"C:\\Apps\\Discord.exe";
    Check(!RuleStore::MatchesRule(http, changed.ToQuery()) &&
          ChoiceOf(RulePresets::Suggest(changed), IDS_PRESET_DISCORD_HTTP).rules.size() == 1,
          "Discord lost installation independence or exact application scope");
    for (const wchar_t* file : {L"discordcanary.exe", L"discordptb.exe"}) {
        changed = discord;
        changed.appPath = std::wstring(L"C:\\Apps\\") + file;
        Check(RulePresets::Suggest(changed).empty(), "Discord HTTP leaked to another edition");
        const auto originalChoices = RulePresets::Suggest(Request(changed.appPath));
        Check(ChoiceOf(originalChoices, IDS_PRESET_DISCORD).rules.size() == 4,
              "Discord HTTP changed another edition's original preset");
    }
    const auto originalChoices = RulePresets::Suggest(Request(discordPath));
    const auto& original = ChoiceOf(originalChoices, IDS_PRESET_DISCORD);
    RuleStore discordStore;
    Check(original.rules.size() == 4 && RulePresets::Apply(discordStore, discord, original.rules) == 4 &&
          RulePresets::Apply(discordStore, discord, preset.rules) == 1 && discordStore.Count() == 5,
          "Discord HTTP preset did not preserve existing rules");
    RuleAction verdict = RuleAction::Block;
    Check(discordStore.MatchVerdict(discord.ToQuery(), verdict) && verdict == RuleAction::Allow,
          "applied Discord preset did not allow HTTP");

    const std::wstring obsPath = L"C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe";
    AskRequest obs = Request(obsPath, Proto::Tcp, 61821, L"127.0.0.1");
    obs.key.local = Ip(L"127.0.0.1");
    obs.key.lport = 61822;
    const auto obsChoices = RulePresets::Suggest(obs);
    const auto& obsPreset = ChoiceOf(obsChoices, IDS_PRESET_OBS_STUDIO);
    Check(obsPreset.rules.size() == 2, "OBS preset must contain only loopback TCP and HTTPS");
    const Rule& loopback = obsPreset.rules[0];
    const Rule& https = obsPreset.rules[1];
    const auto loopbackAddress = [](const std::vector<AddrItem>& addresses) {
        return addresses.size() == 1 && addresses[0].macro == AddrMacro::None &&
               addresses[0].addr == Ip(L"127.0.0.1") && addresses[0].prefix == -1;
    };
    Check(loopback.scope == RuleScope::App && loopback.appPath == obsPath &&
          loopback.proto == Proto::Tcp && loopback.dir == Dir::Out && loopback.action == RuleAction::Allow &&
          loopback.conds == (CondProto | CondDirection | CondRemoteAddr | CondLocalAddr) &&
          loopbackAddress(loopback.remoteAddrs) && loopbackAddress(loopback.localAddrs) &&
          loopback.remotePorts.empty() && loopback.localPorts.empty() &&
          RuleStore::MatchesRule(loopback, obs.ToQuery()), "OBS loopback did not retain both exact addresses");
    Check(https.proto == Proto::Tcp && https.dir == Dir::Out && https.action == RuleAction::Allow &&
          https.conds == (CondProto | CondDirection | CondRemotePort) &&
          https.remotePorts.size() == 1 && https.remotePorts[0].from == 443 && https.remotePorts[0].to == 443 &&
          https.remoteAddrs.empty() && https.localAddrs.empty() && https.localPorts.empty(),
          "OBS HTTPS pinned an address or lost its port");
    changed = obs;
    changed.key.rport = 12345;
    changed.key.lport = 54321;
    Check(RuleStore::MatchesRule(loopback, changed.ToQuery()), "OBS loopback pinned temporary ports");
    for (const wchar_t* address : {L"127.0.0.2", L"::1", L"192.0.2.1"}) {
        changed = obs;
        changed.key.local = Ip(address);
        Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(loopback, changed.ToQuery()),
              "OBS loopback accepted another local address");
        changed = obs;
        changed.key.remote = Ip(address);
        Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(loopback, changed.ToQuery()),
              "OBS loopback accepted another remote address");
    }
    changed = obs;
    changed.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(loopback, changed.ToQuery()),
          "OBS loopback accepted UDP");
    changed = Request(obsPath, Proto::Tcp, 443, L"37.59.185.111");
    Check(RuleStore::MatchesRule(https, changed.ToQuery()) &&
          ChoiceOf(RulePresets::Suggest(changed), IDS_PRESET_OBS_STUDIO).rules.size() == 2,
          "OBS HTTPS request was not offered");
    RuleStore obsStore;
    Check(RulePresets::Apply(obsStore, obs, obsPreset.rules) == 2, "OBS preset was not applied");
    verdict = RuleAction::Block;
    Check(obsStore.MatchVerdict(obs.ToQuery(), verdict) && verdict == RuleAction::Allow &&
          obsStore.MatchVerdict(changed.ToQuery(), verdict) && verdict == RuleAction::Allow,
          "applied OBS preset did not allow loopback and HTTPS");
    changed.ownerAmbiguous = true;
    Check(RulePresets::Suggest(changed).empty(), "ambiguous owner received the OBS preset");

    const uint64_t discordVersion = discordStore.version();
    const uint64_t obsVersion = obsStore.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translatedDiscord = RulePresets::Suggest(discord);
        const auto& discordChoice = ChoiceOf(translatedDiscord, IDS_PRESET_DISCORD_HTTP);
        const auto translatedObs = RulePresets::Suggest(obs);
        const auto& obsChoice = ChoiceOf(translatedObs, IDS_PRESET_OBS_STUDIO);
        const std::wstring title = LoadStringRes(IDS_PRESET_OBS_STUDIO);
        const std::wstring loopName = LoadStringRes(IDS_PRESET_RULE_LOOPBACK_TCP);
        const std::wstring httpsName = LoadStringRes(IDS_PRESET_RULE_HTTPS);
        const std::wstring discordTitle = LoadStringRes(IDS_PRESET_DISCORD_HTTP);
        const std::wstring httpName = LoadStringRes(IDS_PRESET_RULE_HTTP);
        Check(discordTitle == L"Discord: HTTP" && discordChoice.title == discordTitle &&
              discordChoice.rules.size() == 1 && discordChoice.rules.front().name ==
                  LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, discordTitle.c_str(), httpName.c_str()),
              "Discord HTTP lost its localized title or rule name");
        Check(title == L"OBS Studio: HTTPS / TCP 127.0.0.1" && obsChoice.title == title &&
              obsChoice.rules[0].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), loopName.c_str()) &&
              obsChoice.rules[1].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), httpsName.c_str()),
              "OBS preset lost its localized title or rule names");
        Check(RulePresets::Apply(discordStore, discord, discordChoice.rules) == 0 &&
              RulePresets::Apply(obsStore, obs, obsChoice.rules) == 0 &&
              discordStore.version() == discordVersion && obsStore.version() == obsVersion,
              "localized Discord or OBS preset duplicated rules");
    }
    SetUiLang(previous);
}

void TestOneDriveAndYandexDiskPresets() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const std::wstring oneDrivePath = L"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe";
    AskRequest oneDrive = Request(oneDrivePath, Proto::Tcp, 80, L"23.12.158.97");
    const auto oneDriveChoices = RulePresets::Suggest(oneDrive);
    const auto& oneDrivePreset = ChoiceOf(oneDriveChoices, IDS_PRESET_ONEDRIVE_HTTP);
    Check(oneDrivePreset.rules.size() == 1, "OneDrive HTTP preset included unrelated rules");
    const Rule& oneDriveHttp = oneDrivePreset.rules.front();
    Check(oneDriveHttp.scope == RuleScope::App && oneDriveHttp.appPath == oneDrivePath &&
          oneDriveHttp.action == RuleAction::Allow && oneDriveHttp.proto == Proto::Tcp &&
          oneDriveHttp.dir == Dir::Out && oneDriveHttp.conds == (CondProto | CondDirection | CondRemotePort) &&
          oneDriveHttp.remotePorts.size() == 1 && oneDriveHttp.remotePorts[0].from == 80 &&
          oneDriveHttp.remotePorts[0].to == 80 && oneDriveHttp.remoteAddrs.empty() &&
          oneDriveHttp.localAddrs.empty() && oneDriveHttp.localPorts.empty() && oneDriveHttp.services.empty() &&
          RuleStore::MatchesRule(oneDriveHttp, oneDrive.ToQuery()), "OneDrive HTTP conditions changed");
    const auto cloudChoices = RulePresets::Suggest(Request(oneDrivePath));
    const auto& cloud = ChoiceOf(cloudChoices, IDS_PRESET_CLOUD);
    Check(cloud.rules.size() == 4, "OneDrive original cloud preset was modified");
    RuleStore oneDriveStore;
    Check(RulePresets::Apply(oneDriveStore, oneDrive, cloud.rules) == 4 &&
          RulePresets::Apply(oneDriveStore, oneDrive, oneDrivePreset.rules) == 1 &&
          oneDriveStore.Count() == 5, "OneDrive HTTP did not preserve the original rules");
    AskRequest changed = oneDrive;
    changed.key.local = Ip(L"192.0.2.8");
    changed.key.remote = Ip(L"203.0.113.9");
    changed.key.lport = 50000;
    Check(RuleStore::MatchesRule(oneDriveHttp, changed.ToQuery()), "OneDrive HTTP pinned an endpoint");
    for (const wchar_t* file : {L"dropbox.exe", L"googledrivefs.exe"}) {
        changed.appPath = std::wstring(L"C:\\Apps\\") + file;
        Check(RulePresets::Suggest(changed).empty(), "OneDrive HTTP leaked to another cloud client");
        const auto original = RulePresets::Suggest(Request(changed.appPath));
        Check(ChoiceOf(original, IDS_PRESET_CLOUD).rules.size() == 4,
              "OneDrive HTTP changed another cloud client's preset");
    }
    changed = oneDrive;
    changed.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(changed).empty(), "OneDrive HTTP accepted UDP");
    changed = oneDrive;
    changed.key.rport = 8080;
    Check(RulePresets::Suggest(changed).empty(), "OneDrive HTTP accepted another port");
    changed = oneDrive;
    changed.appPath = L"C:\\Another\\OneDrive.exe";
    Check(!RuleStore::MatchesRule(oneDriveHttp, changed.ToQuery()) &&
          ChoiceOf(RulePresets::Suggest(changed), IDS_PRESET_ONEDRIVE_HTTP).rules.size() == 1,
          "OneDrive HTTP lost installation independence or exact path scope");

    const std::wstring diskPath = L"C:\\Apps\\YandexDisk4.exe";
    AskRequest disk = Request(diskPath, Proto::Tcp, 53001, L"127.0.0.1");
    disk.key.local = Ip(L"127.0.0.1");
    disk.key.lport = 53002;
    const auto diskChoices = RulePresets::Suggest(disk);
    const auto& diskPreset = ChoiceOf(diskChoices, IDS_PRESET_YANDEX_DISK);
    Check(diskPreset.rules.size() == 2, "Yandex Disk preset must contain loopback and combined web rules");
    const Rule& loop = diskPreset.rules[0];
    const auto exactLoopback = [](const std::vector<AddrItem>& addresses) {
        return addresses.size() == 1 && addresses[0].macro == AddrMacro::None &&
               addresses[0].addr == Ip(L"127.0.0.1") && addresses[0].prefix == -1;
    };
    Check(loop.scope == RuleScope::App && loop.appPath == diskPath && loop.action == RuleAction::Allow &&
          loop.proto == Proto::Tcp && loop.dir == Dir::Out &&
          loop.conds == (CondProto | CondDirection | CondRemoteAddr | CondLocalAddr) &&
          exactLoopback(loop.remoteAddrs) && exactLoopback(loop.localAddrs) &&
          loop.remotePorts.empty() && loop.localPorts.empty() && RuleStore::MatchesRule(loop, disk.ToQuery()),
          "Yandex Disk loopback lost an exact endpoint restriction");
    changed = disk;
    changed.key.lport = 12000;
    changed.key.rport = 13000;
    Check(RuleStore::MatchesRule(loop, changed.ToQuery()), "Yandex Disk loopback pinned transient ports");
    for (const wchar_t* address : {L"127.0.0.2", L"::1", L"192.0.2.1"}) {
        changed = disk;
        changed.key.local = Ip(address);
        Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(loop, changed.ToQuery()),
              "Yandex Disk loopback accepted another local address");
        changed = disk;
        changed.key.remote = Ip(address);
        Check(RulePresets::Suggest(changed).empty() && !RuleStore::MatchesRule(loop, changed.ToQuery()),
              "Yandex Disk loopback accepted another remote address");
    }
    changed = disk;
    changed.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(changed).empty(), "Yandex Disk preset accepted UDP");
    RuleStore diskStore;
    Check(RulePresets::Apply(diskStore, disk, diskPreset.rules) == 2, "Yandex Disk preset was not applied");
    for (uint16_t port : {uint16_t{443}, uint16_t{80}}) {
        const Rule& web = diskPreset.rules[1];
        changed = Request(diskPath, Proto::Tcp, port, L"203.0.113.9");
        Check(web.conds == (CondProto | CondDirection | CondRemotePort) && web.proto == Proto::Tcp &&
              web.dir == Dir::Out && web.remotePorts.size() == 2 &&
              web.remotePorts[0].from == 443 && web.remotePorts[0].to == 443 &&
              web.remotePorts[1].from == 80 && web.remotePorts[1].to == 80 &&
              web.remoteAddrs.empty() && web.localAddrs.empty() &&
              web.localPorts.empty() && RuleStore::MatchesRule(web, changed.ToQuery()) &&
              ChoiceOf(RulePresets::Suggest(changed), IDS_PRESET_YANDEX_DISK).rules.size() == 2,
              "Yandex Disk web rule pinned an endpoint or lost its port");
        RuleAction verdict = RuleAction::Block;
        Check(diskStore.MatchVerdict(changed.ToQuery(), verdict) && verdict == RuleAction::Allow,
              "applied Yandex Disk web rule did not allow the request");
    }
    changed = disk;
    changed.appPath = L"C:\\Other\\YANDEXDISK4.EXE";
    Check(!RuleStore::MatchesRule(loop, changed.ToQuery()) &&
          ChoiceOf(RulePresets::Suggest(changed), IDS_PRESET_YANDEX_DISK).rules.size() == 2,
          "Yandex Disk lost installation independence or exact application scope");
    changed.ownerAmbiguous = true;
    Check(RulePresets::Suggest(changed).empty(), "ambiguous owner received the Yandex Disk preset");

    const uint64_t oneDriveVersion = oneDriveStore.version();
    const uint64_t diskVersion = diskStore.version();
    size_t languageCount = 0;
    const UiLangInfo* languages = UiLangs(languageCount);
    for (size_t i = 0; i < languageCount; ++i) {
        SetUiLang(languages[i].lang);
        const auto oneDriveTranslated = RulePresets::Suggest(oneDrive);
        const auto diskTranslated = RulePresets::Suggest(disk);
        const auto& oneDriveChoice = ChoiceOf(oneDriveTranslated, IDS_PRESET_ONEDRIVE_HTTP);
        const auto& diskChoice = ChoiceOf(diskTranslated, IDS_PRESET_YANDEX_DISK);
        const std::wstring oneDriveTitle = LoadStringRes(IDS_PRESET_ONEDRIVE_HTTP);
        const std::wstring diskTitle = LoadStringRes(IDS_PRESET_YANDEX_DISK);
        Check(oneDriveChoice.title == oneDriveTitle && diskChoice.title == diskTitle &&
              oneDriveChoice.rules.size() == 1 && diskChoice.rules.size() == 2,
              "localized OneDrive or Yandex Disk title or count changed");
        const UINT names[] = {IDS_PRESET_RULE_LOOPBACK_TCP, IDS_PRESET_RULE_HTTPS_HTTP};
        for (size_t j = 0; j < diskChoice.rules.size(); ++j) {
            const std::wstring name = LoadStringRes(names[j]);
            Check(diskChoice.rules[j].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                  diskTitle.c_str(), name.c_str()), "Yandex Disk lost a localized rule name");
        }
        Check(RulePresets::Apply(oneDriveStore, oneDrive, oneDriveChoice.rules) == 0 &&
              RulePresets::Apply(diskStore, disk, diskChoice.rules) == 0 &&
              oneDriveStore.version() == oneDriveVersion && diskStore.version() == diskVersion,
              "localized OneDrive or Yandex Disk preset duplicated rules");
    }
    SetUiLang(previous);
}

void TestRemoteAccessPresets() {
    struct Expected {
        Proto proto;
        Dir dir;
        uint16_t remotePort;
        uint16_t localPort;
        const wchar_t* remoteAddress;
        const wchar_t* localAddress;
        std::vector<PortItem> extraRemotePorts;
    };
    struct Flow {
        Proto proto;
        Dir dir;
        uint16_t remotePort;
        uint16_t localPort;
        const wchar_t* remoteAddress;
        const wchar_t* localAddress;
    };
    const Expected anyDeskRules[] = {
        {Proto::Tcp, Dir::Out, 443, 0, nullptr, nullptr, {{80, 80}, {6568, 6568}}},
        {Proto::Udp, Dir::Out, 53, 0, L"1.1.1.1", nullptr}
    };
    const Flow anyDeskFlows[] = {
        {Proto::Tcp, Dir::Out, 443, 41000, L"198.51.100.20", L"192.0.2.10"},
        {Proto::Tcp, Dir::Out, 80, 41001, L"198.51.100.21", L"192.0.2.10"},
        {Proto::Udp, Dir::Out, 53, 41002, L"1.1.1.1", L"192.0.2.10"},
        {Proto::Tcp, Dir::Out, 6568, 41003, L"198.51.100.22", L"192.0.2.10"}
    };
    const UINT anyDeskNames[] = {IDS_PRESET_RULE_WEB_ANYDESK_TCP, IDS_PRESET_RULE_DNS_UDP};
    const Expected rustDeskRules[] = {
        {Proto::Tcp, Dir::Out, 443, 0, nullptr, nullptr, {{80, 80}, {21115, 21116}}},
        {Proto::Udp, Dir::Out, 21116, 0, nullptr, nullptr}
    };
    const Flow rustDeskFlows[] = {
        {Proto::Tcp, Dir::Out, 21116, 41004, L"198.51.100.20", L"192.0.2.10"},
        {Proto::Tcp, Dir::Out, 80, 41005, L"198.51.100.21", L"192.0.2.10"},
        {Proto::Tcp, Dir::Out, 443, 41006, L"198.51.100.22", L"192.0.2.10"},
        {Proto::Tcp, Dir::Out, 21115, 41007, L"198.51.100.23", L"192.0.2.10"},
        {Proto::Udp, Dir::Out, 21116, 41008, L"198.51.100.24", L"192.0.2.10"}
    };
    const UINT rustDeskNames[] = {IDS_PRESET_RULE_WEB_RUSTDESK_TCP, IDS_PRESET_RULE_RUSTDESK_UDP_21116};
    const Expected clientRules[] = {
        {Proto::Tcp, Dir::Out, 0, 0, L"127.0.0.1", L"127.0.0.1"},
        {Proto::Tcp, Dir::Out, 443, 0, nullptr, nullptr}
    };
    const Flow clientFlows[] = {
        {Proto::Tcp, Dir::Out, 52480, 5939, L"127.0.0.1", L"127.0.0.1"},
        {Proto::Tcp, Dir::Out, 443, 52481, L"198.51.100.20", L"192.0.2.10"}
    };
    const UINT clientNames[] = {IDS_PRESET_RULE_LOOPBACK_TCP, IDS_PRESET_RULE_HTTPS};
    const Expected serviceRules[] = {
        {Proto::Tcp, Dir::Out, 443, 0, nullptr, nullptr, {{80, 80}, {5938, 5938}}},
        {Proto::Tcp, Dir::In, 0, 0, L"127.0.0.1", L"127.0.0.1"},
        {Proto::Udp, Dir::In, 5353, 5353, nullptr, L"224.0.0.251"},
        {Proto::Udp, Dir::Out, 5353, 5353, L"ff02::fb", L"::1"},
        {Proto::Udp, Dir::Out, 5353, 5353, L"224.0.0.251", nullptr}
    };
    const Flow serviceFlows[] = {
        {Proto::Tcp, Dir::Out, 80, 52479, L"23.11.40.157", L"192.0.2.10"},
        {Proto::Tcp, Dir::Out, 443, 52481, L"104.17.23.111", L"192.0.2.10"},
        {Proto::Tcp, Dir::In, 52480, 5939, L"127.0.0.1", L"127.0.0.1"},
        {Proto::Tcp, Dir::Out, 5938, 52484, L"217.146.8.69", L"192.0.2.10"},
        {Proto::Udp, Dir::In, 5353, 5353, L"192.0.2.10", L"224.0.0.251"},
        {Proto::Udp, Dir::Out, 5353, 5353, L"ff02::fb", L"::1"},
        {Proto::Udp, Dir::Out, 5353, 5353, L"224.0.0.251", L"192.168.219.24"}
    };
    const UINT serviceNames[] = {IDS_PRESET_RULE_WEB_TEAMVIEWER_TCP, IDS_PRESET_RULE_LOOPBACK_TCP,
                                 IDS_PRESET_RULE_MDNS_IN_IPV4, IDS_PRESET_RULE_MDNS_OUT_IPV6,
                                 IDS_PRESET_RULE_MDNS_OUT_IPV4};
    const Expected vmwareAuthdRules[] = {
        {Proto::Tcp, Dir::Out, 0, 0, L"127.0.0.1", L"127.0.0.1"}
    };
    const Flow vmwareAuthdFlows[] = {
        {Proto::Tcp, Dir::Out, 52693, 52694, L"127.0.0.1", L"127.0.0.1"}
    };
    const UINT vmwareAuthdNames[] = {IDS_PRESET_RULE_LOOPBACK_TCP_IPV4};
    const Expected vmwareRules[] = {
        {Proto::Tcp, Dir::Out, 0, 0, L"127.0.0.1", L"127.0.0.1"},
        {Proto::Tcp, Dir::Out, 0, 0, L"::1", L"::1"}
    };
    const Flow vmwareFlows[] = {
        {Proto::Tcp, Dir::Out, 52693, 52694, L"127.0.0.1", L"127.0.0.1"},
        {Proto::Tcp, Dir::Out, 52695, 52696, L"::1", L"::1"}
    };
    const UINT vmwareNames[] = {IDS_PRESET_RULE_LOOPBACK_TCP_IPV4, IDS_PRESET_RULE_LOOPBACK_TCP_IPV6};
    const std::wstring vmwareAuthdPath = L"C:\\Program Files\\VMware\\VMware Workstation\\vmware-authd.exe";
    const std::wstring vmwarePath = L"C:\\Program Files\\VMware\\VMware Workstation\\vmware.exe";
    const std::wstring anyDeskPath = L"C:\\Program Files\\AnyDesk\\AnyDesk.exe";
    const std::wstring rustDeskPath = L"C:\\Program Files\\RustDesk\\RUSTDESK.EXE";
    const std::wstring clientPath = L"C:\\Program Files\\TeamViewer\\TeamViewer.exe";
    const std::wstring servicePath = L"C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe";
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const auto makeFlow = [](const std::wstring& path, const Flow& flow) {
        AskRequest request = Request(path, flow.proto, flow.remotePort, flow.remoteAddress);
        request.dir = flow.dir;
        request.key.local = Ip(flow.localAddress);
        request.key.lport = flow.localPort;
        return request;
    };
    const auto offered = [](const AskRequest& request, UINT id) {
        const auto choices = RulePresets::Suggest(request);
        return std::any_of(choices.begin(), choices.end(), [id](const auto& choice) {
            return choice.titleId == id;
        });
    };
    const auto verify = [&](const std::wstring& path, UINT id, const wchar_t* service,
                            std::span<const Expected> expected, std::span<const Flow> flows,
                            std::span<const UINT> names) {
        Check(!flows.empty() && expected.size() == names.size(), "invalid remote-access test");
        AskRequest request = makeFlow(path, flows.front());
        if (service) SetServices(request.pid, {service});
        else SetServices(request.pid, {});
        const auto choices = RulePresets::Suggest(request);
        const auto& preset = ChoiceOf(choices, id);
        Check(preset.rules.size() == expected.size(), "remote-access preset rule count changed");
        const auto portIs = [](const std::vector<PortItem>& ports, uint16_t port) {
            return port ? ports.size() == 1 && ports[0].from == port && ports[0].to == port : ports.empty();
        };
        const auto addressIs = [](const std::vector<AddrItem>& addresses, const wchar_t* address) {
            return address ? addresses.size() == 1 && addresses[0].macro == AddrMacro::None &&
                             addresses[0].addr == Ip(address) && addresses[0].prefix == -1 : addresses.empty();
        };
        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == expected.size(),
              "remote-access preset was not applied");
        RuleStore existing;
        Rule oldRule = preset.rules.front();
        oldRule.name = L"Existing remote-access rule";
        Check(RulePresets::Apply(existing, request, {oldRule}) == 1 &&
              RulePresets::Apply(existing, request, preset.rules) == expected.size() - 1 &&
              existing.Count() == expected.size(),
              "remote-access preset duplicated an existing rule or missed a new one");
        for (size_t i = 0; i < expected.size(); ++i) {
            const Expected& spec = expected[i];
            const Rule& rule = preset.rules[i];
            const uint32_t conds = CondProto | CondDirection | (service ? CondService : 0) |
                (spec.remotePort ? CondRemotePort : 0) | (spec.localPort ? CondLocalPort : 0) |
                (spec.remoteAddress ? CondRemoteAddr : 0) | (spec.localAddress ? CondLocalAddr : 0);
            const auto remotePortsMatch = [&] {
                if (!portIs(rule.remotePorts, spec.remotePort) && spec.extraRemotePorts.empty()) return false;
                if (spec.extraRemotePorts.empty()) return true;
                if (!spec.remotePort || rule.remotePorts.size() != 1 + spec.extraRemotePorts.size() ||
                    rule.remotePorts[0].from != spec.remotePort || rule.remotePorts[0].to != spec.remotePort)
                    return false;
                for (size_t j = 0; j < spec.extraRemotePorts.size(); ++j)
                    if (rule.remotePorts[j + 1].from != spec.extraRemotePorts[j].from ||
                        rule.remotePorts[j + 1].to != spec.extraRemotePorts[j].to) return false;
                return true;
            };
            Check(rule.scope == RuleScope::App && rule.appPath == path && rule.action == RuleAction::Allow &&
                  rule.proto == spec.proto && rule.dir == spec.dir && rule.conds == conds && !rule.autoName &&
                  remotePortsMatch() && portIs(rule.localPorts, spec.localPort) &&
                  addressIs(rule.remoteAddrs, spec.remoteAddress) && addressIs(rule.localAddrs, spec.localAddress) &&
                  (service ? rule.services.size() == 1 && rule.services[0].name == service : rule.services.empty()),
                  "remote-access rule lost or gained a condition");
        }
        for (const Flow& sample : flows) {
            AskRequest flow = makeFlow(path, sample);
            RuleAction verdict = RuleAction::Block;
            const auto matched = std::find_if(preset.rules.begin(), preset.rules.end(), [&](const Rule& rule) {
                return RuleStore::MatchesRule(rule, flow.ToQuery());
            });
            Check(offered(flow, id) && matched != preset.rules.end() &&
                  store.MatchVerdict(flow.ToQuery(), verdict) && verdict == RuleAction::Allow,
                  "remote-access rule did not cover its captured connection");
            flow.dir = flow.dir == Dir::In ? Dir::Out : Dir::In;
            Check(RuleStore::MatchesRule(*matched, flow.ToQuery()),
                  "remote-access rule changed existing effective direction semantics");
        }
        AskRequest changed = request;
        changed.appPath = L"D:\\Portable\\" + PathBaseUpper(path);
        Check(offered(changed, id) && !RuleStore::MatchesRule(preset.rules.front(), changed.ToQuery()),
              "remote-access preset lost filename matching or exact path scope");
        changed = request;
        changed.ownerAmbiguous = true;
        Check(!offered(changed, id), "ambiguous process received a remote-access preset");
        if (service) {
            for (auto services : {std::initializer_list<const wchar_t*>{}, {L"AnotherService"},
                                  {service, L"AnotherService"}}) {
                SetServices(request.pid, services);
                Check(!offered(request, id) && !RuleStore::MatchesRule(preset.rules.front(), request.ToQuery()),
                      "service preset accepted missing, wrong or ambiguous service attribution");
            }
            const std::wstring foldedService = FoldCaseCopy(service);
            SetServices(request.pid, {foldedService.c_str()});
            Check(offered(request, id) && RuleStore::MatchesRule(preset.rules.front(), request.ToQuery()),
                  "service matching was case-sensitive");
            SetServices(request.pid, {service});
            changed = request;
            changed.process.reset();
            Check(!offered(changed, id) && !RuleStore::MatchesRule(preset.rules.front(), changed.ToQuery()),
                  "service preset accepted a request without its process handle");
        }
        const uint64_t version = store.version();
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            const auto localizedChoices = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(localizedChoices, id);
            const std::wstring title = LoadStringRes(id);
            Check(localized.title == (service ? LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT,
                  title.c_str(), service) : title) && localized.rules.size() == expected.size(),
                  "remote-access preset lost its localized title");
            for (size_t j = 0; j < names.size(); ++j) {
                const std::wstring name = LoadStringRes(names[j]);
                const std::wstring fullName = service ? LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT,
                    title.c_str(), service, name.c_str()) : LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                    title.c_str(), name.c_str());
                Check(localized.rules[j].name == fullName, "remote-access rule lost its localized name");
            }
            Check(RulePresets::Apply(store, request, localized.rules) == 0 && store.version() == version &&
                  store.Count() == expected.size(), "localized remote-access preset duplicated rules");
        }
        SetServices(request.pid, {});
        SetUiLang(UiLang::English);
    };
    verify(anyDeskPath, IDS_PRESET_ANYDESK, nullptr, anyDeskRules, anyDeskFlows, anyDeskNames);
    verify(rustDeskPath, IDS_PRESET_RUSTDESK, nullptr, rustDeskRules, rustDeskFlows, rustDeskNames);
    verify(clientPath, IDS_PRESET_TEAMVIEWER, nullptr, clientRules, clientFlows, clientNames);
    verify(servicePath, IDS_PRESET_TEAMVIEWER_SERVICE, L"TeamViewer", serviceRules, serviceFlows, serviceNames);
    verify(vmwareAuthdPath, IDS_PRESET_VMWARE_AUTHD, L"VMAuthdService",
           vmwareAuthdRules, vmwareAuthdFlows, vmwareAuthdNames);
    verify(vmwarePath, IDS_PRESET_VMWARE, nullptr, vmwareRules, vmwareFlows, vmwareNames);

    AskRequest dns = makeFlow(anyDeskPath, anyDeskFlows[2]);
    const auto dnsChoices = RulePresets::Suggest(dns);
    const Rule& dnsRule = ChoiceOf(dnsChoices, IDS_PRESET_ANYDESK).rules[1];
    AskRequest changed = dns;
    changed.key.local = Ip(L"192.0.2.55");
    changed.key.lport = 60000;
    Check(RuleStore::MatchesRule(dnsRule, changed.ToQuery()), "AnyDesk DNS pinned a local endpoint");
    changed.key.remote = Ip(L"1.0.0.1");
    Check(!offered(changed, IDS_PRESET_ANYDESK) && !RuleStore::MatchesRule(dnsRule, changed.ToQuery()),
          "AnyDesk DNS accepted another server");
    changed = dns;
    changed.key.rport = 54;
    Check(!offered(changed, IDS_PRESET_ANYDESK), "AnyDesk DNS accepted another port");
    changed = dns;
    changed.key.proto = Proto::Tcp;
    Check(!offered(changed, IDS_PRESET_ANYDESK), "AnyDesk DNS accepted TCP");
    changed = makeFlow(anyDeskPath, anyDeskFlows[3]);
    changed.key.rport = 6569;
    Check(!offered(changed, IDS_PRESET_ANYDESK), "AnyDesk accepted another TCP port");

    AskRequest rustDesk = makeFlow(rustDeskPath, rustDeskFlows[0]);
    const auto rustDeskChoices = RulePresets::Suggest(rustDesk);
    const Rule& rustDeskTcp = ChoiceOf(rustDeskChoices, IDS_PRESET_RUSTDESK).rules[0];
    changed = rustDesk;
    changed.key.local = Ip(L"192.0.2.55");
    changed.key.remote = Ip(L"203.0.113.77");
    changed.key.lport = 60000;
    Check(RuleStore::MatchesRule(rustDeskTcp, changed.ToQuery()),
          "RustDesk pinned a dynamic endpoint");
    changed = rustDesk;
    changed.key.rport = 21117;
    Check(!offered(changed, IDS_PRESET_RUSTDESK), "RustDesk accepted another TCP port");
    changed = makeFlow(rustDeskPath, rustDeskFlows[3]);
    changed.key.proto = Proto::Udp;
    Check(!offered(changed, IDS_PRESET_RUSTDESK), "RustDesk accepted UDP 21115");
    changed = makeFlow(rustDeskPath, rustDeskFlows[4]);
    changed.key.rport = 21117;
    Check(!offered(changed, IDS_PRESET_RUSTDESK), "RustDesk accepted another UDP port");
    changed.key.rport = 443;
    Check(!offered(changed, IDS_PRESET_RUSTDESK), "RustDesk accepted UDP 443");

    AskRequest client = makeFlow(clientPath, clientFlows[0]);
    const auto clientChoices = RulePresets::Suggest(client);
    const Rule& clientLoop = ChoiceOf(clientChoices, IDS_PRESET_TEAMVIEWER).rules[0];
    changed = client;
    changed.key.lport = 10000;
    changed.key.rport = 10001;
    Check(RuleStore::MatchesRule(clientLoop, changed.ToQuery()), "TeamViewer client loopback pinned ports");
    for (const wchar_t* address : {L"127.0.0.2", L"::1", L"192.0.2.10"}) {
        changed = client;
        changed.key.local = Ip(address);
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER), "TeamViewer client accepted another local address");
        changed = client;
        changed.key.remote = Ip(address);
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER), "TeamViewer client accepted another remote address");
    }

    AskRequest service = makeFlow(servicePath, serviceFlows[2]);
    SetServices(service.pid, {L"TeamViewer"});
    const auto serviceChoices = RulePresets::Suggest(service);
    const auto& servicePreset = ChoiceOf(serviceChoices, IDS_PRESET_TEAMVIEWER_SERVICE);
    changed = service;
    changed.key.lport = 10000;
    changed.key.rport = 10001;
    Check(RuleStore::MatchesRule(servicePreset.rules[1], changed.ToQuery()),
          "TeamViewer service loopback pinned ports");
    for (const wchar_t* address : {L"127.0.0.2", L"::1", L"192.0.2.10"}) {
        changed = service;
        changed.key.local = Ip(address);
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE), "service loopback accepted another local address");
        changed = service;
        changed.key.remote = Ip(address);
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE), "service loopback accepted another remote address");
    }
    RuleStore oldServiceStore;
    const std::vector<Rule> oldServiceRules(servicePreset.rules.begin(), servicePreset.rules.end() - 1);
    Check(RulePresets::Apply(oldServiceStore, service, oldServiceRules) == oldServiceRules.size() &&
          RulePresets::Apply(oldServiceStore, service, servicePreset.rules) == 1 &&
          oldServiceStore.Count() == servicePreset.rules.size(),
          "updated TeamViewer service preset duplicated existing rules or missed IPv4 mDNS");
    for (size_t i : {size_t{4}, size_t{5}, size_t{6}}) {
        AskRequest mdns = makeFlow(servicePath, serviceFlows[i]);
        Check(RuleStore::MatchesRule(servicePreset.rules[i - 2], mdns.ToQuery()), "service mDNS flow did not match");
        changed = mdns;
        ++changed.key.lport;
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE), "service mDNS accepted another local port");
        changed = mdns;
        ++changed.key.rport;
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE), "service mDNS accepted another remote port");
        changed = mdns;
        changed.key.local = Ip(i == 4 ? L"224.0.0.250" : i == 5 ? L"::2" : L"192.0.2.55");
        Check(offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE) == (i == 6),
              "service mDNS lost its captured local-address boundary");
        changed = mdns;
        changed.key.remote = Ip(i == 4 ? L"198.51.100.77" : i == 5 ? L"ff02::fc" : L"224.0.0.252");
        Check(offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE) == (i == 4),
              "service mDNS lost its captured remote-address boundary");
        changed = mdns;
        changed.key.proto = Proto::Tcp;
        Check(!offered(changed, IDS_PRESET_TEAMVIEWER_SERVICE), "service mDNS accepted TCP");
    }
    SetServices(service.pid, {});

    for (size_t i = 0; i < 3; ++i) {
        const bool authd = i == 0;
        AskRequest loop = authd ? makeFlow(vmwareAuthdPath, vmwareAuthdFlows[0])
                                : makeFlow(vmwarePath, vmwareFlows[i - 1]);
        const UINT titleId = authd ? IDS_PRESET_VMWARE_AUTHD : IDS_PRESET_VMWARE;
        SetServices(loop.pid, authd ? std::initializer_list<const wchar_t*>{L"VMAuthdService"}
                                    : std::initializer_list<const wchar_t*>{});
        loop.conditionFlags = 1;
        loop.interfaceName = std::make_shared<const std::wstring>(L"Loopback Pseudo-Interface 1");
        const auto loopChoices = RulePresets::Suggest(loop);
        const auto& preset = ChoiceOf(loopChoices, titleId);
        const Rule& rule = preset.rules[authd ? 0 : i - 1];
        Check(!(rule.conds & (CondInterface | CondWfpFlags | CondRemotePort | CondLocalPort)) &&
              rule.interfaceName.empty() && rule.conditionFlags == 0 &&
              rule.remotePorts.empty() && rule.localPorts.empty(),
              "VMware loopback rule pinned captured interface, flags or ports");
        changed = loop;
        changed.key.lport = 10000;
        changed.key.rport = 60000;
        changed.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
        changed.conditionFlags.reset();
        Check(offered(changed, titleId) && RuleStore::MatchesRule(rule, changed.ToQuery()),
              "VMware loopback rule depended on captured interface, flags or ports");
        for (const wchar_t* address : {L"127.0.0.2", L"192.0.2.10", L"::2",
                                      i == 2 ? L"127.0.0.1" : L"::1"}) {
            changed = loop;
            changed.key.local = Ip(address);
            Check(!offered(changed, titleId) && !RuleStore::MatchesRule(rule, changed.ToQuery()),
                  "VMware loopback rule accepted another local address");
            changed = loop;
            changed.key.remote = Ip(address);
            Check(!offered(changed, titleId) && !RuleStore::MatchesRule(rule, changed.ToQuery()),
                  "VMware loopback rule accepted another remote address");
        }
        changed = loop;
        changed.key.proto = Proto::Udp;
        Check(!offered(changed, titleId) && !RuleStore::MatchesRule(rule, changed.ToQuery()),
              "VMware loopback rule accepted UDP");
        changed = loop;
        changed.appPath = authd ? vmwarePath : vmwareAuthdPath;
        Check(!offered(changed, titleId) && !RuleStore::MatchesRule(rule, changed.ToQuery()),
              "VMware preset accepted the other executable");
    }
    SetServices(service.pid, {});
    SetUiLang(previous);
}

void TestCapturedConnectionPresets() {
    struct Profile {
        std::wstring path;
        UINT titleId;
        const wchar_t* service;
        size_t count;
        bool combinedWeb;
        RuleAction action;
    };
    const std::wstring svchost = SystemDirFile(L"svchost.exe");
    const Profile profiles[] = {
        {L"C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe",
            IDS_PRESET_STEAM_SERVICE, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WSL\\wslservice.exe", IDS_PRESET_WSL_SERVICE, L"WSLService", 1, true, RuleAction::Allow},
        {SystemDirFile(L"taskhostw.exe"), IDS_PRESET_TASK_HOST, nullptr, 1, false, RuleAction::Allow},
        {SystemDirFile(L"AppHostRegistrationVerifier.exe"), IDS_PRESET_APPHOST_VERIFIER, nullptr, 1, true, RuleAction::Allow},
        {SystemDirFile(L"msiexec.exe"), IDS_PRESET_MSI_INSTALLER, L"msiserver", 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\Microsoft OneDrive\\26.189.0928.0009\\OneDrive.Sync.Service.exe",
            IDS_PRESET_ONEDRIVE_SYNC, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\Microsoft OneDrive\\26.189.0928.0009\\OneDriveUpdaterService.exe",
            IDS_PRESET_ONEDRIVE_UPDATER, L"OneDrive Updater Service", 1, true, RuleAction::Allow},
        {SystemDirFile(L"backgroundTaskHost.exe"), IDS_PRESET_BACKGROUND_TASK_HOST, nullptr, 1, true, RuleAction::Allow},
        {SystemDirFile(L"WWAHost.exe"), IDS_PRESET_WWA_HOST, nullptr, 1, true, RuleAction::Allow},
        {SystemDirFile(L"BackgroundTransferHost.exe"), IDS_PRESET_BACKGROUND_TRANSFER, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Windows\\explorer.exe", IDS_PRESET_EXPLORER, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26100.4-0\\MpCmdRun.exe",
            IDS_PRESET_DEFENDER_COMMAND, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe", IDS_PRESET_MOUSO_CORE_WORKER, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\Mozilla Firefox\\pingsender.exe", IDS_PRESET_PING_SENDER, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe", IDS_PRESET_SYSTEM_SETTINGS, nullptr, 1, false, RuleAction::Allow},
        {SystemDirFile(L"UCConfigTask.exe"), IDS_PRESET_UC_CONFIG_TASK, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.GamingServices_38.117.27001.0_x64__8wekyb3d8bbwe\\gamingservices.exe",
            IDS_PRESET_GAMING_SERVICES, L"GamingServices", 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftOfficeHub_19.2611.32041.0_x64__8wekyb3d8bbwe\\M365Copilot.exe",
            IDS_PRESET_M365_COPILOT, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.BingNews_4.56.21872.0_x64__8wekyb3d8bbwe\\Microsoft.Msn.News.exe",
            IDS_PRESET_MSN_NEWS, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.BingWeather_4.54.63045.0_x64__8wekyb3d8bbwe\\Microsoft.Msn.Weather.exe",
            IDS_PRESET_MSN_WEATHER, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftStickyNotes_6.1.4.0_x64__8wekyb3d8bbwe\\Microsoft.Notes.exe",
            IDS_PRESET_MICROSOFT_NOTES, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.YourPhone_1.26092.119.0_x64__8wekyb3d8bbwe\\PhoneExperienceHost.exe",
            IDS_PRESET_PHONE_EXPERIENCE, nullptr, 1, false, RuleAction::Allow},
        {SystemDirFile(L"smartscreen.exe"), IDS_PRESET_SMARTSCREEN, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\WebExperienceHostApp.exe",
            IDS_PRESET_WEB_EXPERIENCE, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\WindowsBackupClient.exe",
            IDS_PRESET_WINDOWS_BACKUP, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.GamingApp_2611.1001.10.0_x64__8wekyb3d8bbwe\\XboxPcApp.exe",
            IDS_PRESET_XBOX_PC_APP, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.GamingApp_2611.1001.10.0_x64__8wekyb3d8bbwe\\XboxPcAppFT.exe",
            IDS_PRESET_XBOX_PC_APP_FT, nullptr, 1, false, RuleAction::Allow},
        {svchost, IDS_PRESET_WAAS_MEDIC, L"WaaSMedicSvc", 1, false, RuleAction::Allow},
        {SystemDirFile(L"WUDFHost.exe"), IDS_PRESET_WUDF_HOST, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", IDS_PRESET_EXCEL, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\Microsoft Office\\root\\Office16\\MSACCESS.EXE", IDS_PRESET_MSACCESS, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftWhiteboard_55.20811.580.0_x64__8wekyb3d8bbwe\\MicrosoftWhiteboard\\MicrosoftWhiteboard.exe",
            IDS_PRESET_WHITEBOARD, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_16005.14326.22342.0_x64__8wekyb3d8bbwe\\HxOutlook.exe",
            IDS_PRESET_HX_OUTLOOK, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_2025.11100.29001.0_x64__8wekyb3d8bbwe\\Photos.exe",
            IDS_PRESET_PHOTOS, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_16005.14326.22342.0_x64__8wekyb3d8bbwe\\HxCalendarAppImm.exe",
            IDS_PRESET_HX_CALENDAR, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
            IDS_PRESET_START_MENU, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.OutlookForWindows_1.2025.1027.200_x64__8wekyb3d8bbwe\\xpdAgent.exe",
            IDS_PRESET_XPD_AGENT, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Program Files\\WindowsApps\\Microsoft.Todos_2.178.8571.0_x64__8wekyb3d8bbwe\\Todo.exe",
            IDS_PRESET_TODO, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Apps\\Clipchamp.exe", IDS_PRESET_CLIPCHAMP, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\GameBar.exe", IDS_PRESET_GAME_BAR, nullptr, 1, true, RuleAction::Allow},
        {L"C:\\Apps\\IntelGraphicsSoftware.exe", IDS_PRESET_INTEL_GRAPHICS, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\ipfsvc.exe", IDS_PRESET_INTEL_IPF, L"dttui", 1, false, RuleAction::Allow},
        {L"C:\\Apps\\ipfsvc.exe", IDS_PRESET_INTEL_IPF, L"ipfui", 1, false, RuleAction::Allow},
        {L"C:\\Apps\\MicrosoftEdgeUpdate.exe", IDS_PRESET_EDGE_UPDATE, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\MpDefenderCoreService.exe", IDS_PRESET_DEFENDER_CORE, L"MDCoreSvc", 1, true, RuleAction::Allow},
        {L"C:\\Apps\\ms-teamsupdate.exe", IDS_PRESET_TEAMS_UPDATE, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\msedgewebview2.exe", IDS_PRESET_WEBVIEW2, nullptr, 3, false, RuleAction::Allow},
        {L"C:\\Apps\\OfficeC2RClient.exe", IDS_PRESET_OFFICE_CLIENT, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\OfficeClickToRun.exe", IDS_PRESET_OFFICE_SERVICE, L"ClickToRunSvc", 1, true, RuleAction::Allow},
        {L"C:\\Apps\\ONENOTE.EXE", IDS_PRESET_ONENOTE, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\SearchHost.exe", IDS_PRESET_SEARCH_HOST, nullptr, 1, false, RuleAction::Allow},
        {L"C:\\Apps\\Solitaire.exe", IDS_PRESET_SOLITAIRE, nullptr, 1, true, RuleAction::Allow},
        {svchost, IDS_PRESET_PUSH_SERVICE, L"WpnService", 1, false, RuleAction::Allow},
        {svchost, IDS_PRESET_LICENSE_MANAGER, L"LicenseManager", 1, false, RuleAction::Allow},
        {svchost, IDS_PRESET_MICROSOFT_ACCOUNT, L"wlidsvc", 1, true, RuleAction::Allow},
        {svchost, IDS_PRESET_DIAGTRACK_BLOCK, L"DiagTrack", 1, false, RuleAction::Block}
    };
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    for (const Profile& profile : profiles) {
        const bool loopback = profile.titleId == IDS_PRESET_INTEL_IPF ||
                              profile.titleId == IDS_PRESET_WUDF_HOST;
        const bool webview = profile.titleId == IDS_PRESET_WEBVIEW2;
        const bool httpOnly = profile.titleId == IDS_PRESET_MSI_INSTALLER;
        AskRequest request = Request(profile.path, Proto::Tcp,
                                     profile.titleId == IDS_PRESET_WUDF_HOST ? 49717 :
                                         (loopback ? 51716 : (httpOnly ? 80 : 443)),
                                     loopback ? L"127.0.0.1" : L"198.51.100.20");
        if (loopback) request.key.local = Ip(L"127.0.0.1");
        if (profile.titleId == IDS_PRESET_STEAM_SERVICE) {
            request.key.local = Ip(L"192.168.0.196");
            request.key.remote = Ip(L"23.11.40.157");
        }
        request.key.lport = profile.titleId == IDS_PRESET_WUDF_HOST ? 49718 :
                            profile.titleId == IDS_PRESET_STEAM_SERVICE ? 9191 : 41001;
        request.conditionFlags = 1;
        request.interfaceIndex = 15;
        request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
        if (profile.service) SetServices(request.pid, {profile.service});
        else SetServices(request.pid, {});
        const auto offered = [&](const AskRequest& connection) {
            const auto choices = RulePresets::Suggest(connection);
            return std::any_of(choices.begin(), choices.end(), [&](const auto& choice) {
                return choice.titleId == profile.titleId;
            });
        };
        const auto choices = RulePresets::Suggest(request);
        const auto& preset = ChoiceOf(choices, profile.titleId);
        Check(preset.rules.size() == profile.count, "captured preset included unrelated rules");
        for (size_t i = 0; i < profile.count; ++i) {
            const Rule& rule = preset.rules[i];
            const bool dns = webview && i == 2;
            const Proto proto = webview && i > 0 ? Proto::Udp : Proto::Tcp;
            const uint16_t port = dns ? 53 : (httpOnly || (!webview && i == 1) ? 80 : 443);
            const uint32_t conditions = CondProto | CondDirection |
                (loopback ? CondRemoteAddr | CondLocalAddr : CondRemotePort) |
                (dns ? CondRemoteAddr : 0) | (profile.service ? CondService : 0);
            Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
                  rule.action == profile.action && rule.proto == proto && rule.dir == Dir::Out &&
                  rule.conds == conditions && rule.localPorts.empty() && !rule.autoName,
                  "captured preset lost its action, scope, protocol or conditions");
            Check(profile.service ? rule.services.size() == 1 && rule.services.front().name == profile.service
                                  : rule.services.empty(),
                  "captured preset lost or guessed its service identity");
            if (loopback) {
                Check(rule.remotePorts.empty() && rule.remoteAddrs.size() == 2 && rule.localAddrs.size() == 2,
                      "loopback preset pinned a port or lost an endpoint restriction");
                for (const auto* addresses : {&rule.remoteAddrs, &rule.localAddrs})
                    Check((*addresses)[0].addr == Ip(L"127.0.0.0") && (*addresses)[0].prefix == 8 &&
                          (*addresses)[1].addr == Ip(L"::1"), "loopback preset addresses were widened");
            } else {
                Check(rule.remotePorts.size() == (profile.combinedWeb ? 2 : 1) &&
                      rule.remotePorts[0].from == port && rule.remotePorts[0].to == port &&
                      (!profile.combinedWeb || (rule.remotePorts[1].from == 80 &&
                                                rule.remotePorts[1].to == 80)) &&
                      rule.localAddrs.empty(),
                      "captured web rule pinned an endpoint or lost its port");
                Check(dns ? rule.remoteAddrs.size() == 1 &&
                            rule.remoteAddrs.front().macro == AddrMacro::DnsServers
                          : rule.remoteAddrs.empty(),
                      "captured web rule lost its DNS boundary or pinned a remote address");
            }
        }
        const Rule& first = preset.rules.front();
        const auto matches = [&](const AskRequest& connection) {
            return RuleStore::MatchesRule(first, connection.ToQuery());
        };
        Check(matches(request), "captured preset did not match its request");
        AskRequest changed = request;
        changed.key.lport = 55000;
        changed.conditionFlags.reset();
        changed.interfaceIndex = 99;
        changed.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
        if (!loopback) {
            changed.key.local = Ip(L"192.0.2.55");
            changed.key.remote = Ip(L"203.0.113.8");
        }
        Check(offered(changed) && matches(changed), "captured preset pinned a temporary condition");
        changed.dir = Dir::In;
        Check(matches(changed) == (profile.action == RuleAction::Allow),
              "captured preset changed the established allow/block direction semantics");
        changed = request;
        changed.key.proto = Proto::Udp;
        Check(!matches(changed) && (!loopback || !offered(changed)),
              "captured TCP loopback rule accepted UDP");
        changed = request;
        changed.appPath = L"C:\\Other\\" + PathBaseUpper(request.appPath);
        Check(!matches(changed), "captured rule escaped its executable path");
        if (profile.path == svchost)
            Check(!offered(changed), "fake svchost received a system service profile");
        else if (!profile.service || profile.titleId == IDS_PRESET_WSL_SERVICE ||
                 profile.titleId == IDS_PRESET_GAMING_SERVICES)
            Check(offered(changed), "application preset depended on the installation directory");
        if (profile.titleId == IDS_PRESET_ONEDRIVE_SYNC || profile.titleId == IDS_PRESET_ONEDRIVE_UPDATER) {
            changed = request;
            changed.appPath = std::wstring(L"C:\\Program Files\\Microsoft OneDrive\\26.198.1011.0006\\") +
                              PathBaseUpper(request.appPath);
            Check(offered(changed) && !matches(changed),
                  "OneDrive version change lost suggestion or exact application scope");
        }
        changed = request;
        changed.appPath = L"C:\\Apps\\not-a-preset.exe";
        Check(!offered(changed) && !matches(changed), "captured preset matched another executable");
        if (profile.titleId == IDS_PRESET_XBOX_PC_APP || profile.titleId == IDS_PRESET_XBOX_PC_APP_FT) {
            changed = request;
            changed.appPath = profile.titleId == IDS_PRESET_XBOX_PC_APP
                ? L"C:\\Apps\\XboxPcAppFT.exe" : L"C:\\Apps\\XboxPcApp.exe";
            Check(!offered(changed) && !matches(changed), "Xbox presets matched the other executable");
        }
        changed = request;
        changed.ownerAmbiguous = true;
        Check(!offered(changed), "ambiguous owner received a captured preset");

        if (loopback) {
            for (const wchar_t* address : {L"127.0.0.1", L"127.42.0.2", L"::1"}) {
                changed = request;
                changed.key.local = Ip(address);
                changed.key.remote = Ip(address);
                changed.key.lport = 12345;
                changed.key.rport = 54321;
                Check(offered(changed) && matches(changed), "loopback preset rejected loopback or another port");
            }
            for (const wchar_t* address : {L"192.0.2.10", L"2001:db8::10"}) {
                changed = request;
                changed.key.local = Ip(address);
                Check(!offered(changed) && !matches(changed), "loopback preset accepted a non-loopback local address");
                changed = request;
                changed.key.remote = Ip(address);
                Check(!offered(changed) && !matches(changed), "loopback preset accepted a non-loopback peer");
            }
        } else {
            changed = request;
            changed.key.rport = 8443;
            Check(!offered(changed) && !matches(changed), "captured web preset accepted another port");
        }
        if (profile.titleId == IDS_PRESET_TASK_HOST ||
            profile.titleId == IDS_PRESET_ONEDRIVE_SYNC || profile.titleId == IDS_PRESET_PHOTOS ||
            profile.titleId == IDS_PRESET_DEFENDER_COMMAND || profile.titleId == IDS_PRESET_MOUSO_CORE_WORKER ||
            profile.titleId == IDS_PRESET_PING_SENDER || profile.titleId == IDS_PRESET_WAAS_MEDIC ||
            profile.titleId == IDS_PRESET_SYSTEM_SETTINGS || profile.titleId == IDS_PRESET_UC_CONFIG_TASK ||
            profile.titleId == IDS_PRESET_GAMING_SERVICES || profile.titleId == IDS_PRESET_M365_COPILOT ||
            profile.titleId == IDS_PRESET_PHONE_EXPERIENCE || profile.titleId == IDS_PRESET_SMARTSCREEN ||
            profile.titleId == IDS_PRESET_WINDOWS_BACKUP || profile.titleId == IDS_PRESET_XBOX_PC_APP_FT ||
            profile.titleId == IDS_PRESET_EXCEL || profile.titleId == IDS_PRESET_MSACCESS ||
            profile.titleId == IDS_PRESET_WHITEBOARD || profile.titleId == IDS_PRESET_HX_CALENDAR ||
            profile.titleId == IDS_PRESET_XPD_AGENT) {
            for (auto [proto, port] : {
                std::pair{Proto::Tcp, uint16_t{80}}, std::pair{Proto::Tcp, uint16_t{465}},
                std::pair{Proto::Udp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{53}}
            }) {
                changed = request;
                changed.key.proto = proto;
                changed.key.rport = port;
                Check(!offered(changed) && !matches(changed),
                      "HTTPS-only application preset accepted another protocol or port");
            }
        }
        if (httpOnly) {
            for (auto [proto, port] : {
                std::pair{Proto::Tcp, uint16_t{443}}, std::pair{Proto::Tcp, uint16_t{8080}},
                std::pair{Proto::Udp, uint16_t{80}}
            }) {
                changed = request;
                changed.key.proto = proto;
                changed.key.rport = port;
                Check(!offered(changed) && !matches(changed),
                      "HTTP-only installer preset accepted another protocol or port");
            }
        }
        if (profile.combinedWeb) {
            changed = request;
            changed.key.rport = 80;
            Check(offered(changed) && RuleStore::MatchesRule(preset.rules[0], changed.ToQuery()),
                  "captured web preset did not cover HTTP");
            for (auto [proto, port] : {
                std::pair{Proto::Tcp, uint16_t{465}}, std::pair{Proto::Udp, uint16_t{80}},
                std::pair{Proto::Udp, uint16_t{443}}
            }) {
                changed.key.proto = proto;
                changed.key.rport = port;
                Check(!offered(changed), "captured web preset accepted another protocol or port");
            }
        }
        if (profile.titleId == IDS_PRESET_WUDF_HOST || profile.titleId == IDS_PRESET_TASK_HOST ||
            profile.titleId == IDS_PRESET_STEAM_SERVICE) {
            SetServices(request.pid, {L"ServiceA", L"ServiceB"});
            changed = request;
            changed.process.reset();
            const size_t reads = serviceReads;
            Check(offered(changed) && matches(changed) && serviceReads == reads,
                  "service-independent preset depended on service identity or a process handle");
            SetServices(request.pid, {});
        }
        if (webview) {
            const Rule& quic = preset.rules[1];
            const Rule& dns = preset.rules[2];
            changed = request;
            changed.key.proto = Proto::Udp;
            Check(offered(changed) && RuleStore::MatchesRule(quic, changed.ToQuery()),
                  "WebView2 did not cover QUIC");
            changed.key.rport = 53;
            std::vector<IpAddr> destinations = {Ip(L"198.51.100.123"), Ip(L"2001:db8::53"),
                                                Ip(L"127.0.0.1"), Ip(L"::1")};
            for (const MacroEntry& server : AddrMacros::Resolve(AddrMacro::DnsServers))
                destinations.push_back(server.addr);
            for (const IpAddr& destination : destinations) {
                changed.key.remote = destination;
                changed.key.local = Ip(destination.family == AF_INET6 ? L"2001:db8::10" : L"192.0.2.10");
                const bool configured = AddrMacros::Matches(AddrMacro::DnsServers, destination);
                Check(offered(changed) == configured &&
                      RuleStore::MatchesRule(dns, changed.ToQuery()) == configured,
                      "WebView2 DNS did not respect configured servers");
            }
        }

        if (profile.titleId == IDS_PRESET_START_MENU || profile.titleId == IDS_PRESET_DEFENDER_CORE ||
            profile.titleId == IDS_PRESET_EXPLORER || profile.titleId == IDS_PRESET_APPHOST_VERIFIER ||
            profile.titleId == IDS_PRESET_WSL_SERVICE || profile.titleId == IDS_PRESET_BACKGROUND_TASK_HOST ||
            profile.titleId == IDS_PRESET_HX_OUTLOOK || profile.titleId == IDS_PRESET_MICROSOFT_ACCOUNT) {
            RuleStore existingStore;
            Rule oldHttps = preset.rules.front();
            oldHttps.remotePorts.resize(1);
            oldHttps.name = L"Previous HTTPS-only preset";
            Check(RulePresets::Apply(existingStore, request, {oldHttps}) == 1,
                  "could not seed the previous HTTPS preset");
            changed = request;
            changed.key.rport = 80;
            const auto httpChoices = RulePresets::Suggest(changed);
            const auto& httpPreset = ChoiceOf(httpChoices, profile.titleId);
            Check(RulePresets::Apply(existingStore, changed, httpPreset.rules) == 1 &&
                  existingStore.Count() == 2,
                  "extended web preset duplicated the previous HTTPS rule");
            RuleAction existingVerdict = RuleAction::Block;
            Check(existingStore.MatchVerdict(request.ToQuery(), existingVerdict) &&
                  existingVerdict == RuleAction::Allow &&
                  existingStore.MatchVerdict(changed.ToQuery(), existingVerdict) &&
                  existingVerdict == RuleAction::Allow,
                  "extended web preset lost HTTP or HTTPS access");
        }

        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == profile.count &&
              store.Count() == profile.count, "captured preset was not applied");
        RuleAction verdict = profile.action == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow;
        Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == profile.action,
              "captured preset produced the wrong verdict");
        if (profile.combinedWeb) {
            changed = request;
            changed.key.rport = 80;
            verdict = RuleAction::Block;
            Check(store.MatchVerdict(changed.ToQuery(), verdict) && verdict == RuleAction::Allow,
                  "applied web preset did not allow HTTP");
            const auto httpChoices = RulePresets::Suggest(changed);
            Check(RulePresets::Apply(store, changed, ChoiceOf(httpChoices, profile.titleId).rules) == 0 &&
                  store.Count() == profile.count, "HTTP request duplicated an applied web preset");
        }
        const uint64_t version = store.version();
        size_t languageCount = 0;
        const UiLangInfo* languages = UiLangs(languageCount);
        for (size_t i = 0; i < languageCount; ++i) {
            SetUiLang(languages[i].lang);
            const auto translated = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(translated, profile.titleId);
            const std::wstring title = LoadStringRes(profile.titleId);
            if (profile.titleId == IDS_PRESET_WSL_SERVICE || profile.titleId == IDS_PRESET_BACKGROUND_TASK_HOST ||
                profile.titleId == IDS_PRESET_HX_OUTLOOK || profile.titleId == IDS_PRESET_MICROSOFT_ACCOUNT ||
                profile.titleId == IDS_PRESET_WWA_HOST)
                Check(title.find(L"HTTPS / HTTP") != std::wstring::npos,
                      "extended captured preset title omitted HTTP or HTTPS");
            if (profile.titleId == IDS_PRESET_WWA_HOST)
                Check(title == L"WWAHost.exe: HTTPS / HTTP", "WWAHost preset title was decoded incorrectly");
            if (profile.titleId == IDS_PRESET_STEAM_SERVICE)
                Check(title == L"steamservice.exe: HTTPS / HTTP", "Steam service preset title was decoded incorrectly");
            Check(localized.title == (profile.service
                      ? LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT, title.c_str(), profile.service)
                      : title) && localized.rules.size() == profile.count &&
                  RulePresets::Apply(store, request, localized.rules) == 0 &&
                  store.Count() == profile.count && store.version() == version,
                  "localized captured preset lost its title or duplicated a rule");
            for (size_t j = 0; j < profile.count; ++j) {
                const UINT nameId = loopback ? IDS_PRESET_RULE_LOOPBACK_TCP :
                    webview && j == 1 ? IDS_PRESET_RULE_QUIC :
                    webview && j == 2 ? IDS_PRESET_RULE_DNS_UDP :
                    profile.combinedWeb ? IDS_PRESET_RULE_HTTPS_HTTP :
                    (httpOnly || j == 1) ? IDS_PRESET_RULE_HTTP : IDS_PRESET_RULE_HTTPS;
                const std::wstring name = LoadStringRes(nameId);
                const std::wstring expected = profile.service
                    ? LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT, title.c_str(), profile.service, name.c_str())
                    : LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, title.c_str(), name.c_str());
                Check(localized.rules[j].name == expected, "captured preset lost a localized rule name");
            }
        }
        SetUiLang(UiLang::English);
        if (profile.service) {
            SetServices(request.pid, {L"AnotherService"});
            Check(!offered(request) && !matches(request), "captured rule leaked to another service");
            SetServices(request.pid, {profile.service, L"AnotherService"});
            Check(!offered(request) && !matches(request), "captured preset guessed a service in a shared process");
            SetServices(request.pid, {});
            Check(!offered(request) && !matches(request), "captured service preset accepted a process without services");
            std::wstring lowerService = profile.service;
            CharLowerBuffW(lowerService.data(), static_cast<DWORD>(lowerService.size()));
            SetServices(request.pid, {lowerService.c_str()});
            Check(offered(request) && matches(request), "captured service matching was case-sensitive");
            SetServices(request.pid, {profile.service});
            changed = request;
            changed.process.reset();
            size_t reads = serviceReads;
            Check(!offered(changed) && !matches(changed) && serviceReads == reads,
                  "captured service preset queried SCM without the original process handle");
            changed = request;
            ++changed.pid;
            reads = serviceReads;
            Check(!offered(changed) && serviceReads == reads,
                  "captured service preset queried SCM with a mismatched process handle");
            if (profile.combinedWeb) {
                AskRequest http = request;
                http.key.rport = 80;
                const Rule& httpRule = preset.rules[0];
                Check(offered(http) && RuleStore::MatchesRule(httpRule, http.ToQuery()),
                      "service HTTP rule rejected its own service");
                for (auto services : {std::initializer_list<const wchar_t*>{},
                                      {L"AnotherService"}, {profile.service, L"AnotherService"}}) {
                    SetServices(request.pid, services);
                    Check(!offered(http) && !RuleStore::MatchesRule(httpRule, http.ToQuery()),
                          "service HTTP rule accepted missing, wrong or shared attribution");
                }
                SetServices(request.pid, {profile.service});
                http.process.reset();
                Check(!offered(http) && !RuleStore::MatchesRule(httpRule, http.ToQuery()),
                      "service HTTP rule accepted a request without a process handle");
            }
        }
        SetServices(request.pid, {});
    }
    AskRequest intel = Request(L"C:\\Apps\\ipfsvc.exe", Proto::Tcp, 51716, L"127.0.0.1");
    intel.key.local = Ip(L"127.0.0.1");
    RuleStore intelStore;
    for (const wchar_t* service : {L"dttui", L"ipfui"}) {
        SetServices(intel.pid, {service});
        const auto choices = RulePresets::Suggest(intel);
        const auto& rules = ChoiceOf(choices, IDS_PRESET_INTEL_IPF).rules;
        Check(RulePresets::Apply(intelStore, intel, rules) == 1,
              "Intel IPF incorrectly deduplicated different service rules");
        RuleAction verdict = RuleAction::Block;
        Check(intelStore.MatchVerdict(intel.ToQuery(), verdict) && verdict == RuleAction::Allow,
              "Intel IPF did not allow the selected service");
    }
    Check(intelStore.Count() == 2, "Intel IPF services did not retain independent rules");
    SetServices(intel.pid, {L"AnotherService"});
    RuleAction verdict = RuleAction::Allow;
    Check(!intelStore.MatchVerdict(intel.ToQuery(), verdict), "Intel IPF allowed another service");
    SetServices(intel.pid, {});
    SetUiLang(UiLang::Russian);
    Check(LoadStringRes(IDS_PRESET_DEFENDER_CORE) == L"Microsoft Defender Core: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_DIAGTRACK_BLOCK) == L"DiagTrack: блокировать исходящий HTTPS" &&
          LoadStringRes(IDS_PRESET_EDGE_UPDATE) == L"Обновление Microsoft Edge: HTTPS" &&
          LoadStringRes(IDS_PRESET_OFFICE_CLIENT) == L"Office Click-to-Run — клиент: HTTPS" &&
          LoadStringRes(IDS_PRESET_SEARCH_HOST) == L"Поиск Windows: HTTPS" &&
          LoadStringRes(IDS_PRESET_PUSH_SERVICE) == L"Push-уведомления Windows: HTTPS" &&
          LoadStringRes(IDS_PRESET_WUDF_HOST) == L"WUDFHost: Локальные соединения (loopback), TCP",
          "captured preset Russian titles do not match the compiled translations");
    SetUiLang(UiLang::English);
    Check(LoadStringRes(IDS_PRESET_DEFENDER_CORE) == L"Microsoft Defender Core: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_DIAGTRACK_BLOCK) == L"DiagTrack: block outbound HTTPS" &&
          LoadStringRes(IDS_PRESET_PUSH_SERVICE) == L"Windows push notifications: HTTPS" &&
          LoadStringRes(IDS_PRESET_WUDF_HOST) == L"WUDFHost: Local connections (loopback), TCP" &&
          LoadStringRes(IDS_PRESET_TODO) == L"Microsoft To Do: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_WSL_SERVICE) == L"WSLService: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_HX_OUTLOOK) == L"HxOutlook: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_MICROSOFT_ACCOUNT) == L"Microsoft account: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_PHOTOS) == L"Photos.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_TASK_HOST) == L"taskhostw.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_APPHOST_VERIFIER) == L"AppHostRegistrationVerifier.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_BACKGROUND_TASK_HOST) == L"backgroundTaskHost.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_BACKGROUND_TRANSFER) == L"BackgroundTransferHost.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_EXPLORER) == L"explorer.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_DEFENDER_COMMAND) == L"MpCmdRun.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_MOUSO_CORE_WORKER) == L"MoUsoCoreWorker.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_PING_SENDER) == L"pingsender.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_WAAS_MEDIC) == L"WaaSMedicSvc: HTTPS" &&
          LoadStringRes(IDS_PRESET_SYSTEM_SETTINGS) == L"SystemSettings.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_UC_CONFIG_TASK) == L"UCConfigTask.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_GAMING_SERVICES) == L"GamingServices: HTTPS" &&
          LoadStringRes(IDS_PRESET_M365_COPILOT) == L"M365Copilot.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_MSN_NEWS) == L"Microsoft.Msn.News.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_MSN_WEATHER) == L"Microsoft.Msn.Weather.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_MICROSOFT_NOTES) == L"Microsoft.Notes.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_PHONE_EXPERIENCE) == L"PhoneExperienceHost.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_SMARTSCREEN) == L"smartscreen.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_WEB_EXPERIENCE) == L"WebExperienceHostApp.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_WINDOWS_BACKUP) == L"WindowsBackupClient.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_XBOX_PC_APP) == L"XboxPcApp.exe: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_XBOX_PC_APP_FT) == L"XboxPcAppFT.exe: HTTPS" &&
          LoadStringRes(IDS_PRESET_START_MENU) == L"StartMenuExperienceHost: HTTPS / HTTP" &&
          LoadStringRes(IDS_PRESET_SHARED_ACCESS_DHCP) == L"SharedAccess: DHCPv4" &&
          LoadStringRes(IDS_PRESET_SSDP_LOOPBACK) == L"SSDPSRV: Local connections (loopback), UDP",
          "captured preset English titles do not match the compiled translations");
    SetUiLang(previous);
}

void TestDnscacheMdnsPreset() {
    const std::wstring svchost = SystemDirFile(L"svchost.exe");
    AskRequest request = Request(svchost, Proto::Udp, 38940, L"192.168.0.1");
    request.dir = Dir::In;
    request.key.local = Ip(L"224.0.0.251");
    request.key.lport = 5353;
    request.conditionFlags = 1;
    request.interfaceIndex = 15;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
    SetServices(request.pid, {L"Dnscache"});

    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    const auto choices = RulePresets::Suggest(request);
    const auto& preset = ChoiceOf(choices, IDS_PRESET_DNSCACHE_MDNS);
    Check(preset.rules.size() == 1, "Dnscache mDNS preset included unrelated rules");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == svchost &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Udp && rule.dir == Dir::In &&
          rule.conds == (CondProto | CondDirection | CondService | CondLocalAddr | CondLocalPort) &&
          rule.services.size() == 1 && rule.services.front().name == L"Dnscache" &&
          rule.localPorts.size() == 1 && rule.localPorts.front().from == 5353 &&
          rule.localPorts.front().to == 5353 && rule.localAddrs.size() == 1 &&
          rule.localAddrs.front().macro == AddrMacro::None &&
          rule.localAddrs.front().addr == Ip(L"224.0.0.251") &&
          rule.localAddrs.front().prefix == -1 && rule.remotePorts.empty() &&
          rule.remoteAddrs.empty() && !rule.autoName,
          "Dnscache mDNS rule lost its local multicast, port or service restriction");
    const auto offered = [&](const AskRequest& connection) {
        const auto suggested = RulePresets::Suggest(connection);
        return std::any_of(suggested.begin(), suggested.end(), [](const auto& choice) {
            return choice.titleId == IDS_PRESET_DNSCACHE_MDNS;
        });
    };
    const auto matches = [&](const AskRequest& connection) {
        return RuleStore::MatchesRule(rule, connection.ToQuery());
    };
    Check(offered(request) && matches(request), "Dnscache mDNS did not match its captured connection");
    AskRequest changed = request;
    changed.key.remote = Ip(L"198.51.100.20");
    changed.key.rport = 12345;
    changed.interfaceIndex = 99;
    changed.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
    changed.conditionFlags.reset();
    Check(offered(changed) && matches(changed), "Dnscache mDNS pinned a peer, interface or WFP flag");
    changed.dir = Dir::Out;
    Check(offered(changed) && matches(changed), "Dnscache mDNS changed allow-rule direction semantics");
    for (const wchar_t* address : {L"224.0.0.250", L"192.168.0.1", L"ff02::fb"}) {
        changed = request;
        changed.key.local = Ip(address);
        Check(!offered(changed) && !matches(changed), "Dnscache mDNS accepted another local address");
    }
    changed = request;
    ++changed.key.lport;
    Check(!offered(changed) && !matches(changed), "Dnscache mDNS accepted another local port");
    changed = request;
    changed.key.proto = Proto::Tcp;
    Check(!offered(changed) && !matches(changed), "Dnscache mDNS accepted TCP");
    changed = request;
    changed.appPath = L"C:\\Apps\\svchost.exe";
    Check(!offered(changed) && !matches(changed), "Dnscache mDNS accepted a fake svchost");
    changed = request;
    changed.ownerAmbiguous = true;
    Check(!offered(changed), "ambiguous owner received Dnscache mDNS");

    const auto dnsChoices = RulePresets::Suggest(Request(svchost, Proto::Udp, 53, L"127.0.0.1"));
    const auto& dns = ChoiceOf(dnsChoices, IDS_PRESET_DNS);
    Check(dns.rules.size() == 5, "Dnscache mDNS changed the existing DNS preset");
    RuleStore store;
    Check(RulePresets::Apply(store, request, dns.rules) == 5 &&
          RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 6,
          "Dnscache mDNS did not preserve existing DNS rules");
    RuleAction verdict = RuleAction::Block;
    Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == RuleAction::Allow,
          "applied Dnscache mDNS rule did not allow the captured connection");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_DNSCACHE_MDNS);
        const std::wstring title = LoadStringRes(IDS_PRESET_DNSCACHE_MDNS);
        const std::wstring name = LoadStringRes(IDS_PRESET_RULE_MDNS_IN);
        Check(title == L"Dnscache: mDNS" && localized.title ==
                  LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT, title.c_str(), L"Dnscache") &&
              localized.rules.size() == 1 && localized.rules.front().name ==
                  LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT, title.c_str(), L"Dnscache", name.c_str()),
              "Dnscache mDNS lost its localized title or rule name");
        Check(RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 6 && store.version() == version,
              "translated Dnscache mDNS preset duplicated a rule");
    }
    SetUiLang(UiLang::English);
    SetServices(request.pid, {L"AnotherService"});
    Check(!offered(request) && !matches(request), "Dnscache mDNS leaked to another service");
    SetServices(request.pid, {L"Dnscache", L"AnotherService"});
    Check(!offered(request) && !matches(request), "Dnscache mDNS guessed a shared service");
    SetServices(request.pid, {});
    Check(!offered(request) && !matches(request), "Dnscache mDNS accepted a process without services");
    SetServices(request.pid, {L"dNsCaChE"});
    Check(offered(request) && matches(request), "Dnscache mDNS service matching was case-sensitive");
    SetServices(request.pid, {L"Dnscache"});
    changed = request;
    changed.process.reset();
    size_t reads = serviceReads;
    Check(!offered(changed) && !matches(changed) && serviceReads == reads,
          "Dnscache mDNS queried SCM without the original process handle");
    changed = request;
    ++changed.pid;
    reads = serviceReads;
    Check(!offered(changed) && serviceReads == reads,
          "Dnscache mDNS queried SCM with a mismatched process handle");
    SetServices(request.pid, {});
    SetUiLang(previous);
}

void TestCapturedServicePresets() {
    struct Profile {
        UINT titleId;
        const wchar_t* service;
        bool dhcp;
    };
    const Profile profiles[] = {
        {IDS_PRESET_SHARED_ACCESS_DHCP, L"SharedAccess", true},
        {IDS_PRESET_SSDP_LOOPBACK, L"SSDPSRV", false}
    };
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    for (const Profile& profile : profiles) {
        AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Udp,
                                     profile.dhcp ? 67 : 64983,
                                     profile.dhcp ? L"255.255.255.255" : L"::1");
        request.key.local = Ip(profile.dhcp ? L"192.168.137.1" : L"::1");
        request.key.lport = profile.dhcp ? 68 : 64983;
        request.conditionFlags = 1;
        request.interfaceIndex = 15;
        request.interfaceName = std::make_shared<const std::wstring>(L"Captured interface");
        SetServices(request.pid, {profile.service});
        const auto offered = [&](const AskRequest& connection) {
            const auto choices = RulePresets::Suggest(connection);
            return std::any_of(choices.begin(), choices.end(), [&](const auto& choice) {
                return choice.titleId == profile.titleId;
            });
        };
        const auto choices = RulePresets::Suggest(request);
        const auto& preset = ChoiceOf(choices, profile.titleId);
        Check(preset.rules.size() == (profile.dhcp ? 2u : 1u),
              "captured service preset included unrelated rules");
        for (const Rule& rule : preset.rules) {
            Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
                  rule.action == RuleAction::Allow && rule.proto == Proto::Udp &&
                  rule.services.size() == 1 && rule.services.front().name == profile.service &&
                  !rule.autoName,
                  "captured service rule lost its scope, action, protocol or service");
        }
        const Rule& first = preset.rules.front();
        const auto matches = [&](const AskRequest& connection) {
            return RuleStore::MatchesRule(first, connection.ToQuery());
        };
        Check(offered(request) && matches(request), "captured service preset did not match its request");
        if (profile.dhcp) {
            const Rule& in = preset.rules[1];
            Check(first.dir == Dir::Out &&
                  first.conds == (CondProto | CondDirection | CondService | CondRemoteAddr |
                                  CondRemotePort | CondLocalPort) &&
                  first.remotePorts.size() == 1 && first.remotePorts[0].from == 67 && first.remotePorts[0].to == 67 &&
                  first.localPorts.size() == 1 && first.localPorts[0].from == 68 && first.localPorts[0].to == 68 &&
                  first.remoteAddrs.size() == 1 && first.remoteAddrs[0].macro == AddrMacro::None &&
                  first.remoteAddrs[0].addr == Ip(L"255.255.255.255") && first.localAddrs.empty(),
                  "SharedAccess broadcast lost its exact address or DHCP ports");
            Check(in.dir == Dir::In &&
                  in.conds == (CondProto | CondDirection | CondService | CondRemotePort | CondLocalPort) &&
                  in.remotePorts.size() == 1 && in.remotePorts[0].from == 68 && in.remotePorts[0].to == 68 &&
                  in.localPorts.size() == 1 && in.localPorts[0].from == 67 && in.localPorts[0].to == 67 &&
                  in.remoteAddrs.empty() && in.localAddrs.empty(),
                  "SharedAccess incoming DHCP pinned an address or lost its ports");
            AskRequest changed = request;
            changed.key.remote = Ip(L"255.255.255.254");
            Check(!offered(changed) && !matches(changed), "SharedAccess broadcast accepted another destination");
            changed = request;
            changed.key.lport = 69;
            Check(!offered(changed) && !matches(changed), "SharedAccess broadcast accepted another local port");
            AskRequest incoming = request;
            incoming.dir = Dir::In;
            incoming.key = MakeFlowKey(Proto::Udp, Ip(L"255.255.255.255"), Ip(L"192.168.137.1"), 67, 68);
            Check(offered(incoming) && RuleStore::MatchesRule(in, incoming.ToQuery()) && !matches(incoming),
                  "SharedAccess incoming DHCP did not match its request");
            incoming.key.local = Ip(L"192.0.2.50");
            incoming.key.remote = Ip(L"198.51.100.50");
            Check(offered(incoming) && RuleStore::MatchesRule(in, incoming.ToQuery()),
                  "SharedAccess incoming DHCP pinned a captured address");
            incoming.key.rport = 69;
            Check(!offered(incoming) && !RuleStore::MatchesRule(in, incoming.ToQuery()),
                  "SharedAccess incoming DHCP accepted another remote port");
        } else {
            Check(first.dir == Dir::Out &&
                  first.conds == (CondProto | CondDirection | CondService | CondRemoteAddr | CondLocalAddr) &&
                  first.remotePorts.empty() && first.localPorts.empty() &&
                  first.remoteAddrs.size() == 2 && first.localAddrs.size() == 2,
                  "SSDP loopback pinned a port or lost an endpoint restriction");
            for (const auto* addresses : {&first.remoteAddrs, &first.localAddrs})
                Check((*addresses)[0].addr == Ip(L"127.0.0.0") && (*addresses)[0].prefix == 8 &&
                      (*addresses)[1].addr == Ip(L"::1"), "SSDP loopback addresses were widened");
            for (const wchar_t* address : {L"127.0.0.1", L"127.42.0.2", L"::1"}) {
                AskRequest changed = request;
                changed.key.local = Ip(address);
                changed.key.remote = Ip(address);
                changed.key.lport = 12345;
                changed.key.rport = 54321;
                Check(offered(changed) && matches(changed), "SSDP loopback rejected an address or port");
            }
            AskRequest changed = request;
            changed.key.local = Ip(L"2001:db8::10");
            Check(!offered(changed) && !matches(changed), "SSDP loopback accepted a non-loopback local address");
            changed = request;
            changed.key.remote = Ip(L"2001:db8::20");
            Check(!offered(changed) && !matches(changed), "SSDP loopback accepted a non-loopback peer");
        }
        AskRequest changed = request;
        changed.key.proto = Proto::Tcp;
        Check(!offered(changed) && !matches(changed), "captured service UDP preset accepted TCP");
        changed = request;
        changed.interfaceIndex = 99;
        changed.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
        changed.conditionFlags.reset();
        Check(offered(changed) && matches(changed), "captured service rule pinned an interface or WFP flag");
        changed = request;
        changed.appPath = L"C:\\Apps\\svchost.exe";
        Check(!offered(changed) && !matches(changed), "captured service preset accepted a fake svchost");
        changed = request;
        changed.ownerAmbiguous = true;
        Check(!offered(changed), "ambiguous owner received a service preset");

        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == preset.rules.size(),
              "captured service preset was not applied");
        RuleAction verdict = RuleAction::Block;
        Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == RuleAction::Allow,
              "captured service preset did not produce an allow verdict");
        const uint64_t version = store.version();
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            const auto translated = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(translated, profile.titleId);
            const std::wstring title = LoadStringRes(profile.titleId);
            Check(localized.title == LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT, title.c_str(), profile.service) &&
                  localized.rules.size() == preset.rules.size() &&
                  RulePresets::Apply(store, request, localized.rules) == 0 && store.version() == version,
                  "localized service preset lost its title or duplicated rules");
            for (size_t j = 0; j < localized.rules.size(); ++j) {
                const UINT nameId = profile.dhcp ? (j ? IDS_PRESET_RULE_DHCP4_IN : IDS_PRESET_RULE_DHCP4)
                                                 : IDS_PRESET_RULE_LOOPBACK_UDP;
                const std::wstring name = LoadStringRes(nameId);
                Check(localized.rules[j].name == LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT,
                      title.c_str(), profile.service, name.c_str()), "service preset lost a localized rule name");
            }
        }
        SetUiLang(UiLang::English);
        SetServices(request.pid, {L"AnotherService"});
        Check(!offered(request) && !matches(request), "captured service preset leaked to another service");
        SetServices(request.pid, {profile.service, L"AnotherService"});
        Check(!offered(request) && !matches(request), "captured service preset guessed a shared service");
        SetServices(request.pid, {});
        Check(!offered(request) && !matches(request), "captured service preset accepted a process without services");
        std::wstring lowerService = profile.service;
        CharLowerBuffW(lowerService.data(), static_cast<DWORD>(lowerService.size()));
        SetServices(request.pid, {lowerService.c_str()});
        Check(offered(request) && matches(request), "captured service matching was case-sensitive");
        SetServices(request.pid, {profile.service});
        changed = request;
        changed.process.reset();
        size_t reads = serviceReads;
        Check(!offered(changed) && !matches(changed) && serviceReads == reads,
              "captured service preset queried SCM without the original process handle");
        changed = request;
        ++changed.pid;
        reads = serviceReads;
        Check(!offered(changed) && serviceReads == reads,
              "captured service preset queried SCM with a mismatched process handle");
        SetServices(request.pid, {});
    }
    SetUiLang(previous);
}

void TestGeolocationPreset() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Tcp, 443, L"4.208.231.73");
    request.key.local = Ip(L"192.168.0.196");
    request.key.lport = 1570;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
    request.conditionFlags = 1;
    SetServices(request.pid, {L"lfsvc"});

    const auto offered = [](const AskRequest& connection) {
        const auto choices = RulePresets::Suggest(connection);
        return std::any_of(choices.begin(), choices.end(), [](const auto& choice) {
            return choice.titleId == IDS_PRESET_GEOLOCATION;
        });
    };
    const auto choices = RulePresets::Suggest(request);
    const auto& preset = ChoiceOf(choices, IDS_PRESET_GEOLOCATION);
    Check(preset.title == L"Geolocation: HTTPS / HTTP (lfsvc)" && preset.rules.size() == 1,
          "geolocation preset lost its title or single rule");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondService | CondRemotePort) &&
          rule.services.size() == 1 && rule.services[0].name == L"lfsvc" &&
          rule.remotePorts.size() == 2 && rule.remotePorts[0].from == 443 &&
          rule.remotePorts[0].to == 443 && rule.remotePorts[1].from == 80 &&
          rule.remotePorts[1].to == 80 && rule.localPorts.empty() &&
          rule.remoteAddrs.empty() && rule.localAddrs.empty() &&
          rule.interfaceName.empty() && rule.conditionFlags == 0 && !rule.autoName,
          "geolocation rule lost a condition or pinned a captured endpoint");
    const auto matches = [&](const AskRequest& flow) {
        return RuleStore::MatchesRule(rule, flow.ToQuery());
    };
    for (uint16_t port : {uint16_t{443}, uint16_t{80}}) {
        for (const auto& [local, remote] : {
                std::pair{L"192.0.2.10", L"198.51.100.20"},
                std::pair{L"2001:db8::10", L"2001:db8::20"}}) {
            AskRequest flow = request;
            flow.key.rport = port;
            flow.key.local = Ip(local);
            flow.key.remote = Ip(remote);
            flow.key.lport = 60000;
            flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
            flow.conditionFlags.reset();
            Check(offered(flow) && matches(flow),
                  "geolocation preset missed a port or depended on captured conditions");
            flow.dir = Dir::In;
            Check(matches(flow), "geolocation rule changed direction handling for port-restricted allows");
        }
    }
    for (const auto& [proto, port] : {
            std::pair{Proto::Udp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{80}},
            std::pair{Proto::Tcp, uint16_t{8080}}}) {
        AskRequest flow = request;
        flow.key.proto = proto;
        flow.key.rport = port;
        Check(!offered(flow) && !matches(flow), "geolocation preset accepted another protocol or port");
    }
    AskRequest other = request;
    other.appPath = L"C:\\Apps\\svchost.exe";
    Check(!offered(other) && !matches(other), "geolocation preset accepted a fake svchost");
    other = request;
    other.ownerAmbiguous = true;
    Check(!offered(other), "ambiguous owner received a geolocation preset");

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "geolocation preset was not applied");
    RuleAction verdict = RuleAction::Block;
    Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == RuleAction::Allow,
          "geolocation preset did not produce an allow verdict");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_GEOLOCATION);
        const std::wstring title = LoadStringRes(IDS_PRESET_GEOLOCATION);
        const std::wstring name = LoadStringRes(IDS_PRESET_RULE_HTTPS_HTTP);
        Check(!title.empty() && localized.title == LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT,
                  title.c_str(), L"lfsvc") && localized.rules.size() == 1 &&
              localized.rules[0].name == LoadStringResFmt(IDS_PRESET_SERVICE_RULE_NAME_FMT,
                  title.c_str(), L"lfsvc", name.c_str()) &&
              RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "localized geolocation preset was lost or duplicated");
    }
    SetUiLang(UiLang::Russian);
    Check(LoadStringRes(IDS_PRESET_GEOLOCATION) == L"Геолокация: HTTPS / HTTP",
          "geolocation Russian title was decoded incorrectly");
    SetUiLang(UiLang::English);
    SetServices(request.pid, {L"AnotherService"});
    Check(!offered(request) && !matches(request), "geolocation preset leaked to another service");
    SetServices(request.pid, {L"lfsvc", L"AnotherService"});
    Check(!offered(request) && !matches(request), "geolocation preset guessed a shared service");
    SetServices(request.pid, {});
    Check(!offered(request) && !matches(request), "geolocation preset accepted an unknown service");
    SetServices(request.pid, {L"LfSvC"});
    Check(offered(request) && matches(request), "geolocation service matching was case-sensitive");
    SetServices(request.pid, {L"lfsvc"});
    other = request;
    other.process.reset();
    const size_t reads = serviceReads;
    Check(!offered(other) && !matches(other) && serviceReads == reads,
          "geolocation preset queried SCM without the original process handle");
    other = request;
    ++other.pid;
    Check(!offered(other) && serviceReads == reads,
          "geolocation preset queried SCM with a mismatched process handle");
    SetServices(request.pid, {});
    SetUiLang(previous);
}

void TestNvidiaPresets() {
    struct Profile {
        const wchar_t* path;
        UINT titleId;
        size_t count;
    };
    const Profile profiles[] = {
        {L"C:\\Program Files\\NVIDIA Corporation\\NVContainer\\NVCONTAINER.EXE",
            IDS_PRESET_NVIDIA_CONTAINER, 2},
        {L"C:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDISPLAY.CONTAINER.EXE",
            IDS_PRESET_NVIDIA_DISPLAY, 1},
        {L"C:\\Program Files\\NVIDIA Corporation\\NVIDIA App\\NVIDIA APP.EXE",
            IDS_PRESET_NVIDIA_APP, 7},
        {L"C:\\Program Files\\NVIDIA Corporation\\NVNGX_UPDATE.EXE",
            IDS_PRESET_NVIDIA_NGX_UPDATE, 2}
    };
    const UiLang previous = CurrentUiLang();
    for (const Profile& profile : profiles) {
        AskRequest request = Request(profile.path);
        request.key.local = Ip(L"192.168.0.196");
        request.key.lport = 43844;
        request.conditionFlags = 1;
        request.interfaceIndex = 15;
        request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
        const auto choices = RulePresets::Suggest(request);
        Check(choices.size() == 1, "NVIDIA HTTPS request received the wrong profile");
        const auto& preset = ChoiceOf(choices, profile.titleId);
        Check(preset.rules.size() == profile.count, "NVIDIA profile has the wrong rule count");
        for (const Rule& rule : preset.rules) {
            Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
                  rule.action == RuleAction::Allow && rule.protoFixed() && !rule.autoName &&
                  !(rule.conds & (CondService | CondInterface | CondWfpFlags)) &&
                  rule.services.empty(), "NVIDIA rule pinned an unrelated condition");
            AskRequest other = request;
            other.appPath = L"C:\\Other\\" + PathBaseUpper(request.appPath);
            Check(!RuleStore::MatchesRule(rule, other.ToQuery()),
                  "NVIDIA rule escaped its executable path");
        }
        const auto https = std::find_if(preset.rules.begin(), preset.rules.end(), [](const Rule& rule) {
            return rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
                rule.conds == (CondProto | CondDirection | CondRemotePort) &&
                rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 443 &&
                rule.remotePorts.front().to == 443 && rule.remoteAddrs.empty() &&
                rule.localAddrs.empty() && rule.localPorts.empty();
        });
        Check(https != preset.rules.end(), "NVIDIA profile lost its unrestricted HTTPS destination");
        for (const wchar_t* address : {L"198.51.100.20", L"2001:db8::20"}) {
            AskRequest connection = Request(profile.path, Proto::Tcp, 443, address);
            connection.key.lport = 55000;
            Check(RuleStore::MatchesRule(*https, connection.ToQuery()) &&
                  RulePresets::Suggest(connection).size() == 1,
                  "NVIDIA HTTPS rule pinned the captured address or local port");
        }
        for (auto [proto, port] : {
            std::pair{Proto::Tcp, uint16_t{80}}, std::pair{Proto::Udp, uint16_t{444}}
        }) {
            Check(RulePresets::Suggest(Request(profile.path, proto, port)).empty(),
                  "NVIDIA profile allowed unrelated external traffic");
        }
        AskRequest ambiguous = request;
        ambiguous.ownerAmbiguous = true;
        Check(RulePresets::Suggest(ambiguous).empty(), "ambiguous owner received an NVIDIA profile");
        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == profile.count &&
              store.Count() == profile.count, "NVIDIA profile was not applied");
        const uint64_t version = store.version();
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            const auto translated = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(translated, profile.titleId);
            Check(localized.title == LoadStringRes(profile.titleId) &&
                  RulePresets::Apply(store, request, localized.rules) == 0 &&
                  store.Count() == profile.count && store.version() == version,
                  "translated NVIDIA profile duplicated existing rules");
        }
    }
    SetUiLang(previous);

    for (auto [index, ruleIndex, proto, direction] : {
        std::tuple{size_t{0}, size_t{1}, Proto::Udp, Dir::Out},
        std::tuple{size_t{2}, size_t{1}, Proto::Udp, Dir::In},
        std::tuple{size_t{3}, size_t{0}, Proto::Tcp, Dir::Out}
    }) {
        AskRequest web = Request(profiles[index].path);
        const auto choices = RulePresets::Suggest(web);
        const Rule& local = ChoiceOf(choices, profiles[index].titleId).rules[ruleIndex];
        Check(local.proto == proto && local.dir == direction &&
              local.conds == (CondProto | CondDirection | CondRemoteAddr | CondLocalAddr) &&
              local.remotePorts.empty() && local.localPorts.empty() &&
              local.remoteAddrs.size() == 2 && local.localAddrs.size() == 2,
              "NVIDIA loopback lost a protocol, direction or endpoint restriction");
        for (const auto* addresses : {&local.remoteAddrs, &local.localAddrs}) {
            Check((*addresses)[0].addr == Ip(L"127.0.0.0") && (*addresses)[0].prefix == 8 &&
                  (*addresses)[1].addr == Ip(L"::1"), "NVIDIA loopback escaped localhost");
        }
        for (const wchar_t* address : {L"127.0.0.1", L"127.0.0.2", L"::1"}) {
            AskRequest connection = Request(profiles[index].path, proto, 47000, address);
            connection.dir = direction;
            connection.key.local = Ip(address);
            connection.key.lport = 50000;
            Check(RuleStore::MatchesRule(local, connection.ToQuery()) &&
                  RulePresets::Suggest(connection).size() == 1,
                  "NVIDIA loopback depended on specific ports or address family");
            connection.key.local = Ip(connection.key.remote.family == AF_INET6
                ? L"2001:db8::1" : L"198.51.100.1");
            Check(!RuleStore::MatchesRule(local, connection.ToQuery()) &&
                  RulePresets::Suggest(connection).empty(),
                  "NVIDIA loopback accepted a nonlocal source");
            connection.key.local = Ip(address);
            connection.key.remote = Ip(connection.key.local.family == AF_INET6
                ? L"2001:db8::2" : L"198.51.100.2");
            Check(!RuleStore::MatchesRule(local, connection.ToQuery()) &&
                  RulePresets::Suggest(connection).empty(),
                  "NVIDIA loopback accepted a nonlocal peer");
        }
    }

    AskRequest app = Request(profiles[2].path);
    const auto choices = RulePresets::Suggest(app);
    const auto& rules = ChoiceOf(choices, IDS_PRESET_NVIDIA_APP).rules;
    const Rule& dns = rules[0];
    Check(dns.proto == Proto::Udp && dns.dir == Dir::Out &&
          dns.conds == (CondProto | CondDirection | CondRemotePort | CondRemoteAddr) &&
          dns.remotePorts.size() == 1 && dns.remotePorts[0].from == 53 &&
          dns.remotePorts[0].to == 53 && dns.remoteAddrs.size() == 1 &&
          dns.remoteAddrs[0].macro == AddrMacro::DnsServers,
          "NVIDIA App DNS did not restrict destinations to configured DNS servers");
    std::vector<IpAddr> servers = {Ip(L"198.51.100.123"), Ip(L"2001:db8::53")};
    for (const MacroEntry& server : AddrMacros::Resolve(AddrMacro::DnsServers))
        servers.push_back(server.addr);
    for (const IpAddr& server : servers) {
        AskRequest connection = Request(app.appPath, Proto::Udp, 53);
        connection.key.remote = server;
        connection.key.local = Ip(server.family == AF_INET6 ? L"2001:db8::1" : L"192.0.2.1");
        const bool configured = AddrMacros::Matches(AddrMacro::DnsServers, server);
        Check(RuleStore::MatchesRule(dns, connection.ToQuery()) == configured &&
              (RulePresets::Suggest(connection).size() == 1) == configured,
              "NVIDIA App DNS ignored configured servers");
    }
    Check(rules[4].proto == Proto::Udp && rules[4].dir == Dir::Out &&
          rules[4].remotePorts.size() == 1 && rules[4].remotePorts[0].from == 443 &&
          rules[4].remotePorts[0].to == 443, "NVIDIA App lost QUIC");
    for (auto [ruleIndex, port, remote] : {
        std::tuple{size_t{3}, uint16_t{1900}, L"239.255.255.250"},
        std::tuple{size_t{5}, uint16_t{5353}, L"224.0.0.251"},
        std::tuple{size_t{3}, uint16_t{1900}, L"ff02::c"},
        std::tuple{size_t{5}, uint16_t{5353}, L"ff02::fb"}
    }) {
        AskRequest connection = Request(app.appPath, Proto::Udp, port, remote);
        Check(RuleStore::MatchesRule(rules[ruleIndex], connection.ToQuery()) &&
              RulePresets::Suggest(connection).size() == 1,
              "NVIDIA App local discovery request was not covered");
        connection.key.remote = Ip(L"198.51.100.20");
        Check(!RuleStore::MatchesRule(rules[ruleIndex], connection.ToQuery()) &&
              RulePresets::Suggest(connection).empty(),
              "NVIDIA App discovery allowed a public destination");
    }
    const Rule& incomingMdns = rules[6];
    Check(incomingMdns.proto == Proto::Udp && incomingMdns.dir == Dir::In &&
          incomingMdns.localPorts.size() == 1 && incomingMdns.localPorts[0].from == 5353 &&
          incomingMdns.localPorts[0].to == 5353 && incomingMdns.remotePorts.empty(),
          "NVIDIA App incoming mDNS did not cover both pictured rules");
    for (uint16_t sourcePort : {uint16_t{5353}, uint16_t{47000}}) {
        AskRequest connection = Request(app.appPath, Proto::Udp, sourcePort, L"127.0.0.1");
        connection.dir = Dir::In;
        connection.key.lport = 5353;
        Check(RuleStore::MatchesRule(incomingMdns, connection.ToQuery()) &&
              RulePresets::Suggest(connection).size() == 1,
              "NVIDIA App incoming mDNS rejected a valid source port");
        connection.key.remote = Ip(L"198.51.100.20");
        Check(!RuleStore::MatchesRule(incomingMdns, connection.ToQuery()),
              "NVIDIA App incoming mDNS accepted a public peer");
    }
}

void TestLsassServiceGroupPreset() {
    AskRequest request = Request(SystemDirFile(L"lsass.exe"), Proto::Tcp, 80, L"23.11.41.157");
    request.key.local = Ip(L"192.168.0.196");
    request.key.lport = 43844;
    request.conditionFlags = 1;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
    SetServices(request.pid, {L"KeyIso", L"SamSs"});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "LSASS HTTP did not receive its service group profile");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_LSASS_HTTP);
    Check(preset.rules.size() == 1, "LSASS profile included unrelated rules");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondService | CondRemotePort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts[0].from == 80 &&
          rule.remotePorts[0].to == 80 && rule.remoteAddrs.empty() &&
          rule.localAddrs.empty() && rule.localPorts.empty() && rule.services.size() == 2 &&
          rule.services[0].name == L"KeyIso" && rule.services[1].name == L"SamSs",
          "LSASS HTTP lost its exact service group or pinned captured conditions");
    for (const wchar_t* address : {L"198.51.100.20", L"2001:db8::20"}) {
        AskRequest connection = Request(request.appPath, Proto::Tcp, 80, address);
        connection.key.lport = 55000;
        Check(RuleStore::MatchesRule(rule, connection.ToQuery()) &&
              RulePresets::Suggest(connection).size() == 1,
              "LSASS HTTP pinned an address or local port");
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{80}}
    }) {
        AskRequest connection = Request(request.appPath, proto, port);
        Check(!RuleStore::MatchesRule(rule, connection.ToQuery()) &&
              RulePresets::Suggest(connection).empty(), "LSASS profile allowed unrelated traffic");
    }
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "LSASS service group profile was not applied");
    const uint64_t version = store.version();
    const UiLang previous = CurrentUiLang();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_LSASS_HTTP);
        Check(localized.title == LoadStringRes(IDS_PRESET_LSASS_HTTP) &&
              RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "translated LSASS profile duplicated the service group rule");
    }
    SetUiLang(previous);
    for (auto [first, second] : {
        std::pair{L"keyiso", L"SAMSS"}, std::pair{L"SamSs", static_cast<const wchar_t*>(nullptr)},
        std::pair{L"KeyIso", static_cast<const wchar_t*>(nullptr)}
    }) {
        if (second) SetServices(request.pid, {first, second});
        else SetServices(request.pid, {first});
        const auto subset = RulePresets::Suggest(request);
        Check(subset.size() == 1 && RuleStore::MatchesRule(rule, request.ToQuery()) &&
              ChoiceOf(subset, IDS_PRESET_LSASS_HTTP).rules[0].services.size() == 2,
              "LSASS group was case-sensitive or lost an allowed service");
    }
    for (auto [first, second] : {
        std::pair{L"KeyIso", L"OtherService"}, std::pair{L"SamSs", L"OtherService"}
    }) {
        SetServices(request.pid, {first, second});
        Check(RulePresets::Suggest(request).empty() &&
              !RuleStore::MatchesRule(rule, request.ToQuery()),
              "LSASS profile allowed an unlisted service in the shared process");
    }
    SetServices(request.pid, {});
    Check(RulePresets::Suggest(request).empty() && !RuleStore::MatchesRule(rule, request.ToQuery()),
          "LSASS profile allowed a process without services");
    SetServices(request.pid, {L"KeyIso", L"SamSs"});
    AskRequest unrelated = request;
    unrelated.appPath = L"C:\\Apps\\lsass.exe";
    Check(RulePresets::Suggest(unrelated).empty() && !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
          "fake LSASS received a system service group profile");
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner received an LSASS profile");
    unrelated = request;
    unrelated.process.reset();
    size_t reads = serviceReads;
    Check(RulePresets::Suggest(unrelated).empty() && serviceReads == reads &&
          !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
          "LSASS queried services without the original process handle");
    unrelated = request;
    ++unrelated.pid;
    reads = serviceReads;
    Check(RulePresets::Suggest(unrelated).empty() && serviceReads == reads,
          "LSASS queried a PID not belonging to the original process");
    unrelated = request;
    HANDLE ended = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    Check(ended != nullptr, "cannot create a signaled process lifetime fixture");
    unrelated.process = std::make_shared<ProcessHandleInfo>(ended, request.pid, true);
    reads = serviceReads;
    Check(RulePresets::Suggest(unrelated).empty() && serviceReads == reads &&
          !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
          "LSASS queried services after the original process exited");
    auto wrongPid = std::make_shared<std::vector<ServiceEntry>>(*hostedByPid[request.pid]);
    ++wrongPid->back().pid;
    hostedByPid[request.pid] = wrongPid;
    Check(RulePresets::Suggest(request).empty(), "LSASS accepted a service from another PID");
    SetServices(request.pid, {});
}

void TestBraveMdnsPresets() {
    AskRequest request = Request(L"C:\\Apps\\BRAVE.exe");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 2, "Brave got duplicate browser profiles");
    const auto& secure = ChoiceOf(choices, IDS_PRESET_BROWSER_HTTPS);
    const auto& web = ChoiceOf(choices, IDS_PRESET_BROWSER_WEB);
    Check(secure.rules.size() == 6 && web.rules.size() == 6,
          "Brave profiles must include both mDNS rules");
    for (const auto& choice : choices) {
        const Rule& outgoing = choice.rules[choice.rules.size() - 2];
        const Rule& incoming = choice.rules.back();
        for (const Rule* rule : {&outgoing, &incoming})
            Check(rule->scope == RuleScope::App && rule->appPath == request.appPath &&
                  rule->action == RuleAction::Allow && rule->proto == Proto::Udp &&
                  (rule->conds & CondRemoteAddr) && !rule->remoteAddrs.empty(),
                  "Brave mDNS rule lost its application, protocol or address restriction");
        Check(outgoing.dir == Dir::Out && outgoing.remotePorts.size() == 1 &&
              outgoing.remotePorts.front().from == 5353 &&
              outgoing.remotePorts.front().to == 5353 && outgoing.localPorts.empty(),
              "outgoing mDNS rule must use remote UDP port 5353");
        Check(incoming.dir == Dir::In && incoming.localPorts.size() == 1 &&
              incoming.localPorts.front().from == 5353 &&
              incoming.localPorts.front().to == 5353 && incoming.remotePorts.empty(),
              "incoming mDNS rule must use local UDP port 5353");
    }

    const auto expectMdns = [](const AskRequest& mdns) {
        const auto suggested = RulePresets::Suggest(mdns);
        Check(suggested.size() == 2, "Brave mDNS request did not offer both browser profiles");
        const MatchQuery query = MakeMatchQuery(mdns.appPath, mdns.pid, mdns.key,
            mdns.dir, mdns.icmpType, mdns.icmpCode, mdns.process.get());
        for (const auto& choice : suggested) {
            const Rule& rule = mdns.dir == Dir::In ? choice.rules.back()
                : choice.rules[choice.rules.size() - 2];
            Check(RuleStore::MatchesRule(rule, query), "Brave mDNS rule did not match its request");
        }
    };
    for (auto [local, multicast] : {
        std::pair{L"192.0.2.10", L"224.0.0.251"}, std::pair{L"fe80::10", L"ff02::fb"}
    }) {
        AskRequest mdns = Request(request.appPath, Proto::Udp, 5353, multicast);
        mdns.key.local = Ip(local);
        expectMdns(mdns);
    }
    for (const wchar_t* peer : {L"127.0.0.1", L"::1"}) {
        AskRequest mdns = Request(request.appPath, Proto::Udp, 41000, peer);
        mdns.dir = Dir::In;
        mdns.key.local = Ip(peer);
        mdns.key.lport = 5353;
        expectMdns(mdns);
    }
    AskRequest unrelated = Request(request.appPath, Proto::Udp, 5353);
    Check(RulePresets::Suggest(unrelated).empty(), "Brave mDNS allowed a public address");
    unrelated.dir = Dir::In;
    unrelated.key.lport = 5353;
    unrelated.key.rport = 41000;
    Check(RulePresets::Suggest(unrelated).empty(), "incoming mDNS allowed a public peer");
    unrelated = Request(request.appPath, Proto::Tcp, 5353, L"224.0.0.251");
    Check(RulePresets::Suggest(unrelated).empty(), "Brave mDNS accepted TCP");
    unrelated.key.proto = Proto::Udp;
    unrelated.key.rport = 5354;
    Check(RulePresets::Suggest(unrelated).empty(), "Brave mDNS accepted a different port");
    for (const wchar_t* file : {L"chrome.exe", L"onedrive.exe", L"curl.exe"})
        Check(RulePresets::Suggest(Request(std::wstring(L"C:\\Apps\\") + file,
              Proto::Udp, 5353, L"224.0.0.251")).empty(), "Brave mDNS leaked into another application");

    RuleStore store;
    std::vector<Rule> existing(web.rules.begin(), web.rules.end() - 2);
    Check(RulePresets::Apply(store, request, existing) == 4, "cannot seed existing Brave web rules");
    Check(RulePresets::Apply(store, request, secure.rules) == 3 && store.Count() == 7,
          "Brave preset did not add its HTTPS and mDNS rules");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, secure.rules) == 0 &&
          RulePresets::Apply(store, request, web.rules) == 0 && store.Count() == 7 &&
          store.version() == version, "repeated Brave profiles duplicated mDNS rules");
}

void TestSteamWebHelperDiscoveryPresets() {
    AskRequest request = Request(L"C:\\Apps\\SteamWebHelper.EXE");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "Steam web helper got duplicate profiles");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_STEAM);
    Check(preset.rules.size() == 9, "Steam web helper lost its base, discovery or loopback rules");
    for (size_t i = 4; i + 1 < preset.rules.size(); ++i) {
        const Rule& rule = preset.rules[i];
        const bool outgoing = i % 2 == 0;
        const uint16_t port = i < 6 ? 1900 : 5353;
        const auto& ports = outgoing ? rule.remotePorts : rule.localPorts;
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.proto == Proto::Udp &&
              rule.dir == (outgoing ? Dir::Out : Dir::In) &&
              (rule.conds & CondRemoteAddr) && rule.remoteAddrs.size() == 4 &&
              rule.remoteAddrs[0].macro == AddrMacro::LocalNetwork &&
              rule.remoteAddrs[1].macro == AddrMacro::MyComputer && ports.size() == 1 &&
              ports.front().from == port && ports.front().to == port,
              "Steam web helper discovery rule lost its app, port or address restriction");
    }
    const auto expectConnection = [&](const AskRequest& connection) {
        const auto suggested = RulePresets::Suggest(connection);
        Check(suggested.size() == 1, "Steam web helper discovery request lost its profile");
        ChoiceOf(suggested, IDS_PRESET_STEAM);
        const MatchQuery query = MakeMatchQuery(connection.appPath, connection.pid, connection.key,
            connection.dir, connection.icmpType, connection.icmpCode,
            connection.process.get());
        Check(std::any_of(preset.rules.begin() + 4, preset.rules.end() - 1, [&](const Rule& rule) {
                  return RuleStore::MatchesRule(rule, query);
              }), "Steam web helper discovery rules did not match their connection");
    };
    for (auto [port, multicast4, multicast6] : {
        std::tuple{uint16_t{1900}, L"239.255.255.250", L"ff02::c"},
        std::tuple{uint16_t{5353}, L"224.0.0.251", L"ff02::fb"}
    }) {
        for (const wchar_t* remote : {multicast4, multicast6}) {
            AskRequest connection = Request(request.appPath, Proto::Udp, port, remote);
            if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"fe80::10");
            expectConnection(connection);
        }
        for (const wchar_t* peer : {L"127.0.0.1", L"::1"}) {
            AskRequest connection = Request(request.appPath, Proto::Udp, 41000, peer);
            connection.dir = Dir::In;
            connection.key.local = Ip(peer);
            connection.key.lport = port;
            expectConnection(connection);
        }
        AskRequest unrelated = Request(request.appPath, Proto::Udp, port);
        Check(RulePresets::Suggest(unrelated).empty(), "Steam discovery allowed a public destination");
        unrelated.dir = Dir::In;
        unrelated.key.rport = 41000;
        unrelated.key.lport = port;
        Check(RulePresets::Suggest(unrelated).empty(), "Steam discovery allowed a public peer");
        Check(RulePresets::Suggest(Request(request.appPath, Proto::Tcp, port, multicast4)).empty(),
              "Steam UDP discovery accepted TCP");
        Check(RulePresets::Suggest(Request(request.appPath, Proto::Udp, port + 1, multicast4)).empty(),
              "Steam discovery accepted an unrelated port");
        for (const wchar_t* file : {L"steam.exe", L"chrome.exe", L"not-steamwebhelper.exe"})
            Check(RulePresets::Suggest(Request(std::wstring(L"C:\\Apps\\") + file,
                  Proto::Udp, port, multicast4)).empty(), "Steam web helper discovery leaked to another app");
    }
    const auto steamChoices = RulePresets::Suggest(Request(L"C:\\Apps\\steam.exe"));
    Check(ChoiceOf(steamChoices, IDS_PRESET_STEAM).rules.size() == 5,
          "main Steam profile lost its base or incoming loopback rules");
    RuleStore store;
    const std::vector<Rule> existing(preset.rules.begin(), preset.rules.begin() + 4);
    Check(RulePresets::Apply(store, request, existing) == 4 &&
          RulePresets::Apply(store, request, preset.rules) == 5 && store.Count() == 9,
          "Steam web helper duplicated existing rules instead of adding discovery and loopback");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, preset.rules) == 0 && store.version() == version,
          "repeated Steam web helper profile duplicated discovery rules");
}

void TestSteamErrorReporterPresets() {
    AskRequest request = Request(L"C:\\Program Files (x86)\\Steam\\SteamErrorReporter64.EXE",
                                 Proto::Tcp, 443, L"208.64.203.140");
    request.key.local = Ip(L"192.168.0.196");
    request.key.lport = 46601;
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "Steam error reporter did not get its exact HTTPS profile");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_STEAM_ERROR_REPORTER);
    Check(preset.rules.size() == 1, "Steam error reporter received unrelated Steam rules");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondRemotePort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 443 &&
          rule.remotePorts.front().to == 443 && rule.remoteAddrs.empty() &&
          rule.localAddrs.empty() && rule.localPorts.empty() && rule.services.empty() && !rule.autoName,
          "Steam error reporter lost its HTTPS restriction or pinned a captured endpoint");
    for (const wchar_t* remote : {L"208.64.203.140", L"198.51.100.20", L"2001:db8::20"}) {
        AskRequest connection = Request(request.appPath, Proto::Tcp, 443, remote);
        if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"2001:db8::10");
        for (uint16_t port : {uint16_t{46601}, uint16_t{55000}}) {
            connection.key.lport = port;
            Check(RulePresets::Suggest(connection).size() == 1 &&
                  RuleStore::MatchesRule(rule, connection.ToQuery()),
                  "Steam error reporter depended on the captured IP or local port");
        }
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{80}}, std::pair{Proto::Tcp, uint16_t{53}},
        std::pair{Proto::Tcp, uint16_t{27015}}, std::pair{Proto::Udp, uint16_t{443}},
        std::pair{Proto::Udp, uint16_t{27000}}
    }) {
        const AskRequest unrelated = Request(request.appPath, proto, port);
        Check(RulePresets::Suggest(unrelated).empty() &&
              !RuleStore::MatchesRule(rule, unrelated.ToQuery()),
              "Steam error reporter permitted HTTP, DNS, QUIC or game traffic");
    }
    AskRequest unrelated = request;
    unrelated.appPath = L"C:\\Other\\steamerrorreporter64.exe";
    Check(!RuleStore::MatchesRule(rule, unrelated.ToQuery()),
          "Steam error reporter rule escaped its executable path");
    unrelated.appPath = L"C:\\Apps\\not-steamerrorreporter64.exe";
    Check(RulePresets::Suggest(unrelated).empty(), "Steam error reporter matched an unrelated filename");
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner received a Steam error reporter profile");

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "Steam error reporter profile was not applied");
    const uint64_t version = store.version();
    const UiLang previous = CurrentUiLang();
    for (auto [language, title] : {
        std::pair{UiLang::Russian, L"Steam: отправка отчётов об ошибках по HTTPS"},
        std::pair{UiLang::English, L"Steam: error reporting over HTTPS"}
    }) {
        SetUiLang(language);
        Check(LoadStringRes(IDS_PRESET_STEAM_ERROR_REPORTER) == title,
              "Steam error reporter title was decoded incorrectly");
    }
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_STEAM_ERROR_REPORTER);
        Check(localized.title == LoadStringRes(IDS_PRESET_STEAM_ERROR_REPORTER) &&
              localized.rules.size() == 1 && localized.rules.front().name ==
                  LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT, localized.title.c_str(),
                                   LoadStringRes(IDS_PRESET_RULE_HTTPS).c_str()),
              "Steam error reporter lost its localized title or rule name");
        Check(RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "translated Steam error reporter profile duplicated its HTTPS rule");
    }
    SetUiLang(previous);
}

void TestSteamLoopbackPresets() {
    for (auto [path, direction, ruleCount] : {
        std::tuple{L"C:\\Program Files (x86)\\Steam\\bin\\cef\\cef.win64\\steamwebhelper.exe",
                   Dir::Out, size_t{9}},
        std::tuple{L"C:\\Program Files (x86)\\Steam\\steam.exe", Dir::In, size_t{5}}
    }) {
        AskRequest request = Request(path, Proto::Tcp, 59941, L"::1");
        request.dir = direction;
        request.key.local = Ip(L"::1");
        request.key.lport = 59943;
        const auto choices = RulePresets::Suggest(request);
        Check(choices.size() == 1, "Steam loopback connection lost its profile");
        const auto& preset = ChoiceOf(choices, IDS_PRESET_STEAM);
        Check(preset.rules.size() == ruleCount, "Steam loopback duplicated or removed existing rules");
        const Rule& rule = preset.rules.back();
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == direction &&
              rule.conds == (CondProto | CondDirection | CondRemoteAddr | CondLocalAddr) &&
              rule.remoteAddrs.size() == 2 && rule.localAddrs == rule.remoteAddrs &&
              rule.remoteAddrs[0].addr == Ip(L"127.0.0.0") && rule.remoteAddrs[0].prefix == 8 &&
              rule.remoteAddrs[1].addr == Ip(L"::1") && rule.remotePorts.empty() &&
              rule.localPorts.empty() && rule.services.empty(),
              "Steam loopback lost an endpoint or direction restriction, or pinned a temporary port");
        const auto matches = [&](const AskRequest& connection) {
            return RuleStore::MatchesRule(rule, connection.ToQuery());
        };
        for (const wchar_t* address : {L"127.0.0.1", L"127.42.0.2", L"::1"}) {
            for (uint16_t port : {uint16_t{1}, uint16_t{59941}, uint16_t{65535}}) {
                AskRequest connection = Request(request.appPath, Proto::Tcp, port, address);
                connection.dir = direction;
                connection.key.local = Ip(address);
                connection.key.lport = port == 59941 ? 59942 : 59943;
                Check(matches(connection), "Steam loopback depended on a captured address or port");
                const auto suggested = RulePresets::Suggest(connection);
                Check(suggested.size() == 1, "Steam loopback failed to suggest its profile");
                ChoiceOf(suggested, IDS_PRESET_STEAM);
            }
        }
        for (const wchar_t* address : {L"126.255.255.255", L"128.0.0.1", L"192.168.0.196",
                                      L"198.51.100.20", L"fe80::1", L"2001:db8::1"}) {
            AskRequest connection = request;
            connection.key.remote = Ip(address);
            Check(!matches(connection) && RulePresets::Suggest(connection).empty(),
                  "Steam loopback allowed a non-loopback peer");
            connection = request;
            connection.key.local = Ip(address);
            Check(!matches(connection) && RulePresets::Suggest(connection).empty(),
                  "Steam loopback allowed a non-loopback local endpoint");
        }
        AskRequest unrelated = request;
        unrelated.dir = direction == Dir::Out ? Dir::In : Dir::Out;
        Check(matches(unrelated) && RulePresets::Suggest(unrelated).size() == 1,
              "Steam loopback changed the bidirectional semantics of address-restricted allow rules");
        for (Proto proto : {Proto::Udp, Proto::IcmpV6}) {
            unrelated = request;
            unrelated.key.proto = proto;
            Check(!matches(unrelated) && RulePresets::Suggest(unrelated).empty(),
                  "Steam TCP loopback allowed another protocol");
        }
        unrelated = request;
        unrelated.appPath = L"C:\\Apps\\not-steamwebhelper.exe";
        Check(!matches(unrelated) && RulePresets::Suggest(unrelated).empty(),
              "Steam loopback escaped its executable path");
        unrelated = request;
        unrelated.ownerAmbiguous = true;
        Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner received Steam loopback rules");

        RuleStore store;
        const std::vector<Rule> existing(preset.rules.begin(), preset.rules.end() - 1);
        Check(RulePresets::Apply(store, request, existing) == ruleCount - 1 &&
              RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == ruleCount,
              "Steam profile did not add only the missing loopback rule");
        const uint64_t version = store.version();
        const UiLang previous = CurrentUiLang();
        size_t languageCount = 0;
        const UiLangInfo* languages = UiLangs(languageCount);
        for (size_t i = 0; i < languageCount; ++i) {
            SetUiLang(languages[i].lang);
            const auto translated = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(translated, IDS_PRESET_STEAM);
            Check(localized.rules.back().name.find(LoadStringRes(IDS_PRESET_RULE_LOOPBACK_TCP)) !=
                      std::wstring::npos &&
                  RulePresets::Apply(store, request, localized.rules) == 0 &&
                  store.Count() == ruleCount && store.version() == version,
                  "translated Steam profile lost its loopback name or duplicated rules");
        }
        SetUiLang(previous);
    }
}

void TestBitsLoopbackPresets() {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Tcp, 5985, L"::1");
    request.key.local = Ip(L"::1");
    request.key.lport = 1241;
    SetServices(request.pid, {L"BITS"});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "BITS WinRM loopback connection lost its exact service profile");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_BITS);
    Check(preset.rules.size() == 4, "BITS lost its web rules or WinRM loopback rule");
    for (const Rule& item : preset.rules)
        Check((item.conds & CondService) && item.services.size() == 1 &&
              item.services.front().name == L"BITS", "BITS rules escaped the exact service");
    const Rule& rule = preset.rules.back();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondService | CondRemoteAddr |
                         CondRemotePort | CondLocalAddr) &&
          rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 5985 &&
          rule.remotePorts.front().to == 5985 && rule.localPorts.empty() &&
          rule.remoteAddrs.size() == 2 && rule.localAddrs == rule.remoteAddrs &&
          rule.remoteAddrs[0].addr == Ip(L"127.0.0.0") && rule.remoteAddrs[0].prefix == 8 &&
          rule.remoteAddrs[1].addr == Ip(L"::1"),
          "BITS WinRM rule lost a loopback endpoint, direction or port restriction");
    const auto matches = [&](const AskRequest& connection) {
        return RuleStore::MatchesRule(rule, connection.ToQuery());
    };
    for (const wchar_t* address : {L"127.0.0.1", L"127.42.0.2", L"::1"}) {
        AskRequest connection = Request(request.appPath, Proto::Tcp, 5985, address);
        connection.key.local = Ip(address);
        for (uint16_t port : {uint16_t{1241}, uint16_t{1242}, uint16_t{52000}}) {
            connection.key.lport = port;
            const auto suggested = RulePresets::Suggest(connection);
            Check(suggested.size() == 1 && matches(connection),
                  "BITS WinRM loopback depended on a captured address or local port");
            ChoiceOf(suggested, IDS_PRESET_BITS);
        }
    }
    for (const wchar_t* address : {L"126.255.255.255", L"128.0.0.1", L"192.168.0.196",
                                  L"198.51.100.20", L"fe80::1", L"2001:db8::1"}) {
        AskRequest connection = request;
        connection.key.remote = Ip(address);
        Check(!matches(connection) && RulePresets::Suggest(connection).empty(),
              "BITS WinRM loopback allowed a non-loopback peer");
        connection = request;
        connection.key.local = Ip(address);
        Check(!matches(connection) && RulePresets::Suggest(connection).empty(),
              "BITS WinRM loopback allowed a non-loopback local endpoint");
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{5984}}, std::pair{Proto::Tcp, uint16_t{5986}},
        std::pair{Proto::Udp, uint16_t{5985}}, std::pair{Proto::IcmpV6, uint16_t{0}}
    }) {
        AskRequest connection = request;
        connection.key.proto = proto;
        connection.key.rport = port;
        Check(!matches(connection) && RulePresets::Suggest(connection).empty(),
              "BITS WinRM loopback permitted an unrelated port or protocol");
    }
    AskRequest unrelated = request;
    unrelated.dir = Dir::In;
    Check(matches(unrelated) && RulePresets::Suggest(unrelated).size() == 1,
          "BITS WinRM changed the bidirectional semantics of port-restricted allow rules");
    unrelated = request;
    unrelated.appPath = L"C:\\Downloads\\svchost.exe";
    Check(!matches(unrelated) && RulePresets::Suggest(unrelated).empty(),
          "fake svchost received BITS WinRM loopback permissions");

    RuleStore store;
    const std::vector<Rule> existing(preset.rules.begin(), preset.rules.end() - 1);
    Check(RulePresets::Apply(store, request, existing) == 3 &&
          RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 4,
          "BITS profile did not add only the missing WinRM loopback rule");
    const uint64_t version = store.version();
    const UiLang previous = CurrentUiLang();
    size_t languageCount = 0;
    const UiLangInfo* languages = UiLangs(languageCount);
    for (size_t i = 0; i < languageCount; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_BITS);
        Check(localized.rules.back().name.find(LoadStringRes(IDS_PRESET_RULE_WINRM_LOOPBACK)) !=
                  std::wstring::npos && RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 4 && store.version() == version,
              "translated BITS profile lost its WinRM name or duplicated rules");
    }
    SetUiLang(previous);
    SetServices(request.pid, {L"W32Time"});
    Check(!matches(request) && RulePresets::Suggest(request).empty(),
          "BITS WinRM loopback permissions leaked to another service");
    SetServices(request.pid, {L"BITS", L"LxpSvc"});
    Check(!matches(request) && RulePresets::Suggest(request).empty(),
          "shared svchost guessed BITS from a WinRM loopback connection");
    SetServices(request.pid, {L"bItS"});
    Check(matches(request) && RulePresets::Suggest(request).size() == 1,
          "BITS WinRM loopback service matching was case-sensitive");
    unrelated = request;
    unrelated.process.reset();
    const size_t reads = serviceReads;
    Check(RulePresets::Suggest(unrelated).empty() && serviceReads == reads && !matches(unrelated),
          "BITS WinRM loopback used a service PID without the original process handle");
}

void TestBraveUpdatePresets() {
    AskRequest request = Request(L"C:\\Program Files (x86)\\BraveSoftware\\Update\\BraveUpdate.exe",
                                 Proto::Tcp, 443, L"3.164.240.15");
    request.key.local = Ip(L"192.168.0.196");
    request.key.lport = 1239;
    SetServices(request.pid, {L"brave"});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "Brave updater service did not receive its HTTPS profile");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_BRAVE_UPDATE);
    Check(preset.rules.size() == 1 && preset.title.find(L"brave") != std::wstring::npos,
          "Brave updater profile lost its HTTPS rule or service key");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondService | CondRemotePort) &&
          rule.services.size() == 1 && rule.services.front().name == L"brave" &&
          rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 443 &&
          rule.remotePorts.front().to == 443 && rule.remoteAddrs.empty() &&
          rule.localAddrs.empty() && rule.localPorts.empty(),
          "Brave updater rule lost its path, service or HTTPS restrictions, or pinned an endpoint");
    const auto matches = [&](const AskRequest& connection) {
        return RuleStore::MatchesRule(rule, connection.ToQuery());
    };
    for (const wchar_t* address : {L"3.164.240.15", L"198.51.100.20", L"2001:db8::20"}) {
        AskRequest connection = Request(request.appPath, Proto::Tcp, 443, address);
        if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"2001:db8::10");
        for (uint16_t port : {uint16_t{1239}, uint16_t{52000}}) {
            connection.key.lport = port;
            Check(matches(connection) && RulePresets::Suggest(connection).size() == 1,
                  "Brave updater HTTPS depended on the captured IP or local port");
        }
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{80}}, std::pair{Proto::Tcp, uint16_t{53}},
        std::pair{Proto::Tcp, uint16_t{8443}}, std::pair{Proto::Udp, uint16_t{443}},
        std::pair{Proto::Icmp, uint16_t{0}}
    }) {
        AskRequest connection = Request(request.appPath, proto, port);
        Check(!matches(connection) && RulePresets::Suggest(connection).empty(),
              "Brave updater profile permitted HTTP, QUIC, DNS or another protocol");
    }
    AskRequest unrelated = request;
    unrelated.dir = Dir::In;
    Check(matches(unrelated) && RulePresets::Suggest(unrelated).size() == 1,
          "Brave updater changed the bidirectional semantics of port-restricted allow rules");

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "Brave updater profile was not applied");
    const uint64_t version = store.version();
    const UiLang previous = CurrentUiLang();
    size_t languageCount = 0;
    const UiLangInfo* languages = UiLangs(languageCount);
    for (size_t i = 0; i < languageCount; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_BRAVE_UPDATE);
        Check(localized.title == LoadStringResFmt(IDS_PRESET_SERVICE_TITLE_FMT,
                  LoadStringRes(IDS_PRESET_BRAVE_UPDATE).c_str(), L"brave") &&
              RulePresets::Apply(store, request, localized.rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "translated Brave updater profile lost its service title or duplicated rules");
    }
    SetUiLang(previous);
    for (const wchar_t* service : {L"bravem", L"BITS", L"AnotherService"}) {
        SetServices(request.pid, {service});
        Check(!matches(request) && RulePresets::Suggest(request).empty(),
              "Brave updater HTTPS permissions leaked to another service");
    }
    SetServices(request.pid, {L"brave", L"bravem"});
    Check(!matches(request) && RulePresets::Suggest(request).empty(),
          "shared Brave updater process guessed the service from an HTTPS connection");
    SetServices(request.pid, {});
    Check(!matches(request) && RulePresets::Suggest(request).empty(),
          "standalone BraveUpdate.exe received service-specific HTTPS permissions");
    SetServices(request.pid, {L"BrAvE"});
    unrelated = request;
    unrelated.appPath = L"C:\\Apps\\BRAVEUPDATE.EXE";
    Check(RulePresets::Suggest(unrelated).size() == 1 && matches(request),
          "Brave updater profile depended on executable or service name casing or install directory");
    SetServices(request.pid, {L"brave"});
    unrelated = request;
    unrelated.appPath = L"C:\\Apps\\not-BraveUpdate.exe";
    Check(!matches(unrelated) && RulePresets::Suggest(unrelated).empty(),
          "Brave updater service profile ignored the executable name");
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner received a Brave updater profile");
    unrelated = request;
    unrelated.process.reset();
    size_t reads = serviceReads;
    Check(RulePresets::Suggest(unrelated).empty() && serviceReads == reads && !matches(unrelated),
          "Brave updater profile used a service PID without the original process handle");
    unrelated = request;
    ++unrelated.pid;
    reads = serviceReads;
    Check(RulePresets::Suggest(unrelated).empty() && serviceReads == reads,
          "Brave updater profile read SCM for a mismatched process handle");
}

void TestFirefoxLoopbackPresets() {
    AskRequest request = Request(L"C:\\FirefoxPortable\\App\\Firefox64\\firefox.EXE",
                                 Proto::Tcp, 56975, L"127.0.0.1");
    request.key.local = Ip(L"127.0.0.1");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 2, "Firefox loopback did not offer both browser profiles");
    const auto& secure = ChoiceOf(choices, IDS_PRESET_BROWSER_HTTPS);
    const auto& web = ChoiceOf(choices, IDS_PRESET_BROWSER_WEB);
    Check(secure.rules.size() == 5 && web.rules.size() == 5,
          "Firefox profiles must include one loopback rule");
    for (const auto& choice : choices) {
        const Rule& rule = choice.rules.back();
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.proto == Proto::Tcp &&
              (rule.conds & CondRemoteAddr) && rule.remoteAddrs.size() == 2 &&
              !(rule.conds & (CondDirection | CondRemotePort | CondLocalPort)) &&
              rule.remotePorts.empty() && rule.localPorts.empty(),
              "Firefox loopback rule lost its scope or restricted ports or direction");
    }
    for (Dir dir : {Dir::Out, Dir::In}) {
        for (const wchar_t* address : {L"127.0.0.1", L"127.42.0.2", L"::1"}) {
            for (uint16_t port : {uint16_t{1}, uint16_t{56975}, uint16_t{65535}}) {
                AskRequest local = Request(request.appPath, Proto::Tcp, port, address);
                local.dir = dir;
                local.key.local = Ip(address);
                const auto suggested = RulePresets::Suggest(local);
                Check(suggested.size() == 2, "Firefox loopback address or port lost a profile");
                const MatchQuery query = MakeMatchQuery(local.appPath, local.pid, local.key,
                    local.dir, local.icmpType, local.icmpCode, local.process.get());
                for (const auto& choice : suggested)
                    Check(RuleStore::MatchesRule(choice.rules.back(), query),
                          "Firefox loopback rule did not match its request");
            }
        }
    }
    for (const wchar_t* remote : {L"126.255.255.255", L"128.0.0.1", L"192.168.1.20",
                                L"198.51.100.20", L"fe80::1", L"2001:db8::1"})
        Check(RulePresets::Suggest(Request(request.appPath, Proto::Tcp, 56975, remote)).empty(),
              "Firefox loopback permitted a non-loopback address");
    for (const wchar_t* remote : {L"127.0.0.1", L"::1"})
        Check(RulePresets::Suggest(Request(request.appPath, Proto::Udp, 56975, remote)).empty(),
              "Firefox TCP loopback rule permitted UDP");
    for (const wchar_t* file : {L"chrome.exe", L"brave.exe", L"onedrive.exe", L"curl.exe"})
        Check(RulePresets::Suggest(Request(std::wstring(L"C:\\Apps\\") + file,
              Proto::Tcp, 56975, L"127.0.0.1")).empty(), "Firefox loopback leaked into another profile");

    RuleStore store;
    std::vector<Rule> existing(web.rules.begin(), web.rules.end() - 1);
    Check(RulePresets::Apply(store, request, existing) == 4, "cannot seed existing Firefox web rules");
    Check(RulePresets::Apply(store, request, secure.rules) == 2 && store.Count() == 6,
          "Firefox preset did not add the HTTPS and loopback rules");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, secure.rules) == 0 &&
          RulePresets::Apply(store, request, web.rules) == 0 && store.Count() == 6 &&
          store.version() == version, "repeated Firefox profiles duplicated the loopback rule");
}

void TestDnscacheDohPresets() {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Udp, 53, L"127.0.0.1");
    SetServices(request.pid, {L"Dnscache"});
    const auto choices = RulePresets::Suggest(request);
    const auto& dns = ChoiceOf(choices, IDS_PRESET_DNS);
    Check(dns.rules.size() == 5, "Dnscache profile must include DoH");
    const Rule& doh = dns.rules.back();
    Check(doh.scope == RuleScope::App && doh.appPath == request.appPath &&
          doh.action == RuleAction::Allow && doh.proto == Proto::Tcp &&
          doh.dir == Dir::Out && doh.remotePorts.size() == 1 &&
          doh.remotePorts.front().from == 443 && doh.remotePorts.front().to == 443 &&
          doh.localPorts.empty() && (doh.conds & CondRemoteAddr) &&
          doh.remoteAddrs.size() == 1 && doh.remoteAddrs.front().macro == AddrMacro::DnsServers &&
          (doh.conds & CondService) && doh.services.size() == 1 &&
          doh.services.front().name == L"Dnscache", "DoH lost its server, port or service restriction");

    // Проверяем текущий набор DNS, не меняя сетевые настройки тестовой машины.
    std::vector<IpAddr> destinations = {
        Ip(L"198.51.100.123"), Ip(L"2001:db8::53"), Ip(L"127.0.0.1"), Ip(L"::1")
    };
    for (const MacroEntry& server : AddrMacros::Resolve(AddrMacro::DnsServers))
        destinations.push_back(server.addr);
    AskRequest https = request;
    https.key.proto = Proto::Tcp;
    https.key.rport = 443;
    for (const IpAddr& destination : destinations) {
        https.key.remote = destination;
        https.key.local = Ip(destination.family == AF_INET6 ? L"2001:db8::10" : L"192.0.2.10");
        const bool configured = AddrMacros::Matches(AddrMacro::DnsServers, destination);
        const auto suggested = RulePresets::Suggest(https);
        Check(suggested.size() == (configured ? 1u : 0u), "DoH ignored configured DNS servers");
        if (configured) ChoiceOf(suggested, IDS_PRESET_DNS);
        const MatchQuery query = MakeMatchQuery(https.appPath, https.pid, https.key,
            https.dir, https.icmpType, https.icmpCode, https.process.get());
        Check(RuleStore::MatchesRule(doh, query) == configured,
              "DoH rule did not match the configured DNS boundary");
    }
    for (uint16_t port : {uint16_t{80}, uint16_t{853}}) {
        https.key.rport = port;
        Check(RulePresets::Suggest(https).empty(), "DoH profile permitted HTTP or DNS-over-TLS");
    }
    https.key.rport = 443;
    https.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(https).empty(), "Dnscache DoH profile permitted arbitrary UDP 443");
    https.key.proto = Proto::Tcp;
    SetServices(request.pid, {L"W32Time"});
    Check(RulePresets::Suggest(https).empty(), "DoH leaked into another service");
    SetServices(request.pid, {L"Dnscache", L"W32Time"});
    const auto shared = RulePresets::Suggest(https);
    Check(shared.size() == 1 && shared.front().titleId == IDS_PRESET_SVCHOST,
          "shared svchost guessed Dnscache from HTTPS traffic");

    RuleStore store;
    std::vector<Rule> existing(dns.rules.begin(), dns.rules.end() - 1);
    Check(RulePresets::Apply(store, request, existing) == 4, "cannot seed existing DNS rules");
    Check(RulePresets::Apply(store, request, dns.rules) == 1 && store.Count() == 5,
          "Dnscache preset did not add only the missing DoH rule");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, dns.rules) == 0 && store.version() == version,
          "repeated Dnscache preset duplicated DoH");
}

void TestIncomingDhcpPresets() {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Udp, 68, L"0.0.0.0");
    request.dir = Dir::In;
    request.key.local = Ip(L"255.255.255.255");
    request.key.lport = 67;
    SetServices(request.pid, {L"Dhcp"});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "incoming BOOTPS did not offer the DHCP profile");
    const auto& dhcp = ChoiceOf(choices, IDS_PRESET_DHCP);
    Check(dhcp.rules.size() == 4, "DHCP profile must include both incoming rules");
    for (auto [local, remote, localPort, remotePort, ruleIndex] : {
        std::tuple{L"255.255.255.255", L"0.0.0.0", uint16_t{67}, uint16_t{68}, size_t{2}},
        std::tuple{L"127.0.0.1", L"127.0.0.1", uint16_t{67}, uint16_t{68}, size_t{2}},
        std::tuple{L"ff02::1:2", L"fe80::20", uint16_t{547}, uint16_t{546}, size_t{3}}
    }) {
        AskRequest incoming = Request(request.appPath, Proto::Udp, remotePort, remote);
        incoming.dir = Dir::In;
        incoming.key.local = Ip(local);
        incoming.key.lport = localPort;
        const auto suggested = RulePresets::Suggest(incoming);
        Check(suggested.size() == 1, "incoming DHCP request lost its service profile");
        const Rule& rule = ChoiceOf(suggested, IDS_PRESET_DHCP).rules[ruleIndex];
        Check(rule.scope == RuleScope::App && rule.appPath == incoming.appPath &&
              rule.proto == Proto::Udp && rule.dir == Dir::In &&
              rule.localPorts.size() == 1 && rule.localPorts.front().from == localPort &&
              rule.localPorts.front().to == localPort && rule.remotePorts.size() == 1 &&
              rule.remotePorts.front().from == remotePort && rule.remotePorts.front().to == remotePort &&
              (rule.conds & CondRemoteAddr) && !rule.remoteAddrs.empty() &&
              (rule.conds & CondService) && rule.services.size() == 1 &&
              rule.services.front().name == L"Dhcp", "incoming DHCP lost its exact ports or service");
        const MatchQuery query = MakeMatchQuery(incoming.appPath, incoming.pid, incoming.key,
            incoming.dir, incoming.icmpType, incoming.icmpCode, incoming.process.get());
        Check(RuleStore::MatchesRule(rule, query), "incoming DHCP rule did not match its request");
    }
    AskRequest unrelated = request;
    unrelated.key.remote = Ip(L"198.51.100.123");
    Check(RulePresets::Suggest(unrelated).empty(), "incoming DHCP permitted a public client");
    unrelated = request;
    unrelated.key.rport = 69;
    Check(RulePresets::Suggest(unrelated).empty(), "incoming DHCP permitted another source port");
    unrelated = request;
    unrelated.key.lport = 66;
    Check(RulePresets::Suggest(unrelated).empty(), "incoming DHCP permitted another local port");
    unrelated = request;
    unrelated.key.proto = Proto::Tcp;
    Check(RulePresets::Suggest(unrelated).empty(), "incoming DHCP permitted TCP");
    SetServices(request.pid, {L"Dnscache"});
    Check(RulePresets::Suggest(request).empty(), "BOOTPS port guessed the DHCP service");
    SetServices(request.pid, {L"Dhcp", L"Dnscache"});
    const auto shared = RulePresets::Suggest(request);
    Check(shared.size() == 1 && shared.front().titleId == IDS_PRESET_SVCHOST,
          "shared svchost lost its general incoming DHCP profile");

    RuleStore store;
    std::vector<Rule> existing(dhcp.rules.begin(), dhcp.rules.begin() + 2);
    Check(RulePresets::Apply(store, request, existing) == 2, "cannot seed outgoing DHCP rules");
    Check(RulePresets::Apply(store, request, dhcp.rules) == 2 && store.Count() == 4,
          "DHCP preset did not add only the missing incoming rules");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, dhcp.rules) == 0 && store.version() == version,
          "repeated DHCP preset duplicated incoming rules");
}

void TestDhcpClientPortsPreset(const wchar_t* service) {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Udp, 67,
                                 EqualNoCase(service, L"SharedAccess") ? L"172.30.32.1" : L"192.168.69.254");
    request.dir = Dir::In;
    request.key.local = Ip(L"255.255.255.255");
    request.key.lport = 68;
    request.conditionFlags = 1;
    request.interfaceName = std::make_shared<const std::wstring>(EqualNoCase(service, L"SharedAccess")
        ? L"vEthernet (Default Switch)" : L"VMware Network Adapter VMnet8");
    SetServices(request.pid, {service});

    const auto choices = RulePresets::Suggest(request);
    const auto& preset = ChoiceOf(choices, IDS_PRESET_DHCP_CLIENT_PORTS);
    Check(preset.rules.size() == 1 && preset.title.find(L"DHCPv4: UDP 68 / 67") != std::wstring::npos,
          "DHCP client port preset lost its rule or title");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Udp && rule.dir == Dir::Unknown &&
          rule.conds == (CondProto | CondService | CondRemotePort | CondLocalPort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 67 &&
          rule.remotePorts.front().to == 67 && rule.localPorts.size() == 1 &&
          rule.localPorts.front().from == 68 && rule.localPorts.front().to == 68 &&
          rule.services.size() == 1 && rule.services.front().name == service &&
          rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.interfaceName.empty() &&
          rule.conditionFlags == 0 && !rule.autoName && !rule.name.empty(),
          "DHCP client rule did not preserve the selected conditions");

    auto hasPreset = [](const AskRequest& candidate) {
        const auto suggested = RulePresets::Suggest(candidate);
        return std::any_of(suggested.begin(), suggested.end(), [](const auto& choice) {
            return choice.titleId == IDS_PRESET_DHCP_CLIENT_PORTS;
        });
    };
    for (Dir dir : {Dir::In, Dir::Out}) {
        AskRequest other = request;
        other.dir = dir;
        other.key.remote = Ip(L"198.51.100.123");
        other.key.local = Ip(L"10.2.3.4");
        other.interfaceName = std::make_shared<const std::wstring>(L"Another adapter");
        other.conditionFlags.reset();
        Check(hasPreset(other) && RuleStore::MatchesRule(rule, other.ToQuery()),
              "DHCP client rule pinned an address, interface, flag or direction");
    }
    AskRequest other = request;
    other.key.rport = 68;
    Check(!hasPreset(other) && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "DHCP client rule accepted another remote port");
    other = request;
    other.key.lport = 67;
    Check(!hasPreset(other) && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "DHCP client rule accepted another local port");
    other = request;
    other.key.proto = Proto::Tcp;
    Check(!hasPreset(other) && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "DHCP client rule accepted TCP");
    other = request;
    other.appPath = L"C:\\Downloads\\svchost.exe";
    Check(!hasPreset(other) && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "DHCP client preset accepted a non-system executable");
    other = request;
    other.ownerAmbiguous = true;
    Check(!hasPreset(other), "DHCP client preset guessed an ambiguous owner");
    SetServices(request.pid, {L"Dnscache"});
    Check(!hasPreset(request) && !RuleStore::MatchesRule(rule, request.ToQuery()),
          "DHCP client rule accepted another service");
    SetServices(request.pid, {service, L"Dnscache"});
    Check(!hasPreset(request) && !RuleStore::MatchesRule(rule, request.ToQuery()),
          "DHCP client preset guessed a service in a shared process");
    const wchar_t* otherService = EqualNoCase(service, L"Dhcp") ? L"SharedAccess" : L"Dhcp";
    SetServices(request.pid, {otherService});
    Check(!RuleStore::MatchesRule(rule, request.ToQuery()),
          "DHCP client rule matched the other DHCP service");
    const auto otherChoices = RulePresets::Suggest(request);
    const auto& otherRules = ChoiceOf(otherChoices, IDS_PRESET_DHCP_CLIENT_PORTS).rules;
    SetServices(request.pid, {service});

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "DHCP client port rule was not applied");
    const uint64_t version = store.version();
    SetUiLang(UiLang::Russian);
    const auto translated = RulePresets::Suggest(request);
    Check(RulePresets::Apply(store, request,
          ChoiceOf(translated, IDS_PRESET_DHCP_CLIENT_PORTS).rules) == 0 &&
          store.Count() == 1 && store.version() == version,
          "DHCP client rule was duplicated after a language change");
    Check(RulePresets::Apply(store, request, otherRules) == 1 && store.Count() == 2,
          "different DHCP services were deduplicated into one rule");
    SetServices(request.pid, {});
    SetUiLang(previous);
}

void TestStoreServicePresets(const wchar_t* service, UINT titleId, const wchar_t* remoteAddress,
                             const wchar_t* localAddress, uint16_t localPort) {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Tcp, 443, remoteAddress);
    request.key.local = Ip(localAddress);
    request.key.lport = localPort;
    SetServices(request.pid, {service});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "Store service HTTPS request did not get its service profile");
    const auto& preset = ChoiceOf(choices, titleId);
    Check(preset.rules.size() == 3 && preset.title.find(service) != std::wstring::npos,
          "Store service profile lost its web rules or service key");
    for (const Rule& rule : preset.rules) {
        Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
              rule.action == RuleAction::Allow && rule.dir == Dir::Out &&
              (rule.conds & CondService) && rule.services.size() == 1 &&
              rule.services.front().name == service && !rule.autoName &&
              rule.name.find(service) != std::wstring::npos,
              "Store service rule lost its application, service or localized name");
        Check(!rule.remotePorts.empty() && rule.localPorts.empty() && rule.localAddrs.empty(),
              "Store service rule pinned the captured local endpoint");
        const uint16_t port = rule.remotePorts.front().from;
        Check(rule.remotePorts.front().to == port, "Store service rule widened the port range");
        if (port == 53) {
            Check(rule.remotePorts.size() == 1 && (rule.proto == Proto::Tcp || rule.proto == Proto::Udp) &&
                  (rule.conds & CondRemoteAddr) && rule.remoteAddrs.size() == 2 &&
                  rule.remoteAddrs[0].macro == AddrMacro::DnsServers &&
                  rule.remoteAddrs[1].macro == AddrMacro::MyComputer,
                  "Store service DNS lost its resolver restriction");
        } else {
            Check(rule.proto == Proto::Tcp && port == 443 && rule.remotePorts.size() == 2 &&
                  rule.remotePorts[1].from == 80 && rule.remotePorts[1].to == 80 &&
                  !(rule.conds & CondRemoteAddr) && rule.remoteAddrs.empty(),
                  "Store service web rules pinned a server or allowed an unrelated port");
        }
    }
    for (auto [proto, port, remote] : {
        std::tuple{Proto::Tcp, uint16_t{443}, remoteAddress},
        std::tuple{Proto::Tcp, uint16_t{443}, L"2001:db8::20"},
        std::tuple{Proto::Tcp, uint16_t{80}, L"198.51.100.20"},
        std::tuple{Proto::Udp, uint16_t{53}, L"127.0.0.1"},
        std::tuple{Proto::Tcp, uint16_t{53}, L"127.0.0.1"}
    }) {
        AskRequest connection = Request(request.appPath, proto, port, remote);
        if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"2001:db8::10");
        const auto suggested = RulePresets::Suggest(connection);
        Check(suggested.size() == 1, "Store service lost a supported web or DNS connection");
        ChoiceOf(suggested, titleId);
    }
    AskRequest unrelated = request;
    unrelated.key.rport = 22;
    Check(RulePresets::Suggest(unrelated).empty(), "Store service permitted SSH");
    unrelated = request;
    unrelated.key.proto = Proto::Udp;
    Check(RulePresets::Suggest(unrelated).empty(), "Store service permitted QUIC");
    unrelated.key.rport = 53;
    unrelated.key.remote = Ip(L"198.51.100.123");
    Check(RulePresets::Suggest(unrelated).empty(), "Store service permitted an arbitrary DNS server");

    RuleStore store;
    Check(RulePresets::Apply(store, request, {preset.rules.front()}) == 1,
          "cannot seed an existing Store service rule");
    Check(RulePresets::Apply(store, request, preset.rules) == 2 && store.Count() == 3,
          "Store service preset duplicated an existing rule");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, preset.rules) == 0 && store.version() == version,
          "repeated Store service preset changed the store");

    SetServices(request.pid, {L"W32Time"});
    Check(RulePresets::Suggest(request).empty(), "Store service web access leaked to another service");
    SetServices(request.pid, {service, L"BITS"});
    const auto shared = RulePresets::Suggest(request);
    Check(shared.size() == 1 && shared.front().titleId == IDS_PRESET_SVCHOST,
          "shared svchost guessed a Store service from HTTPS traffic");
    SetServices(request.pid, {service});
    request.appPath = L"C:\\Downloads\\svchost.exe";
    Check(RulePresets::Suggest(request).empty(), "fake svchost got a Store service preset");
}

void TestUserPushServicePreset() {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Tcp, 443, L"23.73.2.69");
    SetServices(request.pid, {L"WpnUserService_4f11e"});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "user push service did not get its HTTPS preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_PUSH_SERVICE);
    Check(preset.rules.size() == 1 && preset.title.find(L"WpnUserService_*") != std::wstring::npos,
          "user push service preset lost its wildcard");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondService | CondRemotePort) &&
          rule.services.size() == 1 && rule.services[0].name == L"WpnUserService_*" &&
          rule.name.find(L"WpnUserService_*") != std::wstring::npos &&
          rule.remotePorts.size() == 1 && rule.remotePorts[0].from == 443 &&
          rule.remotePorts[0].to == 443 && rule.remoteAddrs.empty() &&
          rule.localAddrs.empty() && rule.localPorts.empty(),
          "user push service rule lost its application, wildcard or HTTPS restriction");

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "user push service preset was not applied");
    RuleAction verdict = RuleAction::Block;
    Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == RuleAction::Allow,
          "user push service rule did not produce an allow verdict");
    const uint64_t version = store.version();
    for (const wchar_t* name : {L"WpnUserService_new", L"WPNUSERSERVICE_A12"}) {
        SetServices(request.pid, {name});
        const auto next = RulePresets::Suggest(request);
        const auto& repeated = ChoiceOf(next, IDS_PRESET_PUSH_SERVICE);
        Check(RuleStore::MatchesRule(rule, request.ToQuery()) &&
                  RulePresets::Apply(store, request, repeated.rules) == 0 &&
                  store.Count() == 1 && store.version() == version,
              "changed user service suffix did not match or duplicated the preset");
    }
    SetServices(request.pid, {L"WpnUserService_4f11e"});
    for (const auto& [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{80}}, std::pair{Proto::Tcp, uint16_t{8443}},
        std::pair{Proto::Udp, uint16_t{443}}}) {
        AskRequest other = request;
        other.key.proto = proto;
        other.key.rport = port;
        Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
              "user push service preset allowed a different protocol or port");
    }
    AskRequest ipv6 = request;
    ipv6.key.remote = Ip(L"2001:db8::20");
    ipv6.key.local = Ip(L"2001:db8::10");
    Check(RuleStore::MatchesRule(rule, ipv6.ToQuery()),
          "user push service preset was pinned to the original IPv4 address");
    AskRequest other = request;
    other.appPath = L"C:\\Downloads\\svchost.exe";
    Check(RulePresets::Suggest(other).empty() && !RuleStore::MatchesRule(rule, other.ToQuery()),
          "user push service preset accepted a non-system svchost");
    other = request;
    other.ownerAmbiguous = true;
    Check(RulePresets::Suggest(other).empty(), "ambiguous user push owner got a preset");
    SetServices(request.pid, {L"OtherService_4f11e"});
    Check(RulePresets::Suggest(request).empty() && !RuleStore::MatchesRule(rule, request.ToQuery()),
          "user push service rule accepted an unrelated service");
    SetServices(request.pid, {L"WpnUserService_4f11e", L"OtherService"});
    const auto shared = RulePresets::Suggest(request);
    Check(shared.size() == 1 && shared[0].titleId == IDS_PRESET_SVCHOST &&
              !RuleStore::MatchesRule(rule, request.ToQuery()),
          "user push service rule accepted a process with an unrelated service");
    SetServices(request.pid, {});
    Check(!RuleStore::MatchesRule(rule, request.ToQuery()),
          "user push service rule accepted a process without services");
}

void TestLanguagePackPresets() {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Tcp, 443, L"150.171.109.53");
    request.key.local = Ip(L"192.168.0.196");
    request.key.lport = 17066;
    SetServices(request.pid, {L"LxpSvc"});
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "LxpSvc HTTPS request did not get its exact service profile");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_LANGUAGE_PACKS);
    Check(preset.rules.size() == 1 && preset.title.find(L"LxpSvc") != std::wstring::npos,
          "language pack profile lost its HTTPS rule or service key");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondService | CondRemotePort) &&
          rule.services.size() == 1 && rule.services.front().name == L"LxpSvc" &&
          !rule.autoName && rule.name.find(L"LxpSvc") != std::wstring::npos,
          "language pack rule escaped its application, service or HTTPS conditions");
    Check(rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 443 &&
          rule.remotePorts.front().to == 443 && rule.remoteAddrs.empty() &&
          rule.localAddrs.empty() && rule.localPorts.empty(),
          "language pack rule pinned a captured endpoint or widened its port range");
    const auto matches = [&](const AskRequest& connection) {
        return RuleStore::MatchesRule(rule, MakeMatchQuery(connection.appPath, connection.pid,
            connection.key, connection.dir, connection.icmpType, connection.icmpCode,
            connection.process.get()));
    };
    for (const wchar_t* remote : {L"150.171.109.53", L"198.51.100.20", L"2001:db8::20"}) {
        AskRequest connection = Request(request.appPath, Proto::Tcp, 443, remote);
        if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"2001:db8::10");
        for (uint16_t localPort : {uint16_t{17066}, uint16_t{52000}}) {
            connection.key.lport = localPort;
            const auto suggested = RulePresets::Suggest(connection);
            Check(suggested.size() == 1 && matches(connection),
                  "language pack HTTPS rule depended on the captured IP or local port");
            ChoiceOf(suggested, IDS_PRESET_LANGUAGE_PACKS);
        }
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{80}}, std::pair{Proto::Tcp, uint16_t{53}},
        std::pair{Proto::Tcp, uint16_t{8443}}, std::pair{Proto::Udp, uint16_t{443}},
        std::pair{Proto::Udp, uint16_t{53}}, std::pair{Proto::Icmp, uint16_t{0}}
    }) {
        AskRequest connection = Request(request.appPath, proto, port);
        Check(RulePresets::Suggest(connection).empty() && !matches(connection),
              "language pack profile permitted HTTP, QUIC, DNS or an unrelated protocol");
    }

    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "language pack profile was not applied");
    const uint64_t version = store.version();
    const UiLang previous = CurrentUiLang();
    struct Translation { UiLang language; const wchar_t* title; };
    const Translation translations[] = {
        {UiLang::Russian, L"Языковые пакеты Windows: HTTPS"},
        {UiLang::English, L"Windows language packs: HTTPS"},
        {UiLang::Korean, L"Windows 언어 팩: HTTPS"},
        {UiLang::Chinese, L"Windows 语言包：HTTPS"},
        {UiLang::Ukrainian, L"Мовні пакети Windows: HTTPS"},
        {UiLang::German, L"Windows-Sprachpakete: HTTPS"},
        {UiLang::French, L"Packs linguistiques Windows : HTTPS"},
        {UiLang::Spanish, L"Paquetes de idioma de Windows: HTTPS"},
        {UiLang::Arabic, L"حزم لغات Windows: HTTPS"},
        {UiLang::Hindi, L"Windows भाषा पैक: HTTPS"},
        {UiLang::Latvian, L"Windows valodu pakotnes: HTTPS"},
        {UiLang::Lithuanian, L"Windows kalbos paketai: HTTPS"},
        {UiLang::Estonian, L"Windowsi keelepaketid: HTTPS"},
        {UiLang::Romanian, L"Pachete lingvistice Windows: HTTPS"},
        {UiLang::Swedish, L"Språkpaket för Windows: HTTPS"},
        {UiLang::Polish, L"Pakiety językowe systemu Windows: HTTPS"},
        {UiLang::Vietnamese, L"Gói ngôn ngữ Windows: HTTPS"},
        {UiLang::Portuguese, L"Pacotes de idiomas do Windows: HTTPS"},
        {UiLang::Italian, L"Pacchetti di lingua di Windows: HTTPS"},
        {UiLang::Persian, L"بسته‌های زبان Windows: HTTPS"},
        {UiLang::Japanese, L"Windows 言語パック: HTTPS"},
        {UiLang::Turkish, L"Windows dil paketleri: HTTPS"},
        {UiLang::Indonesian, L"Paket bahasa Windows: HTTPS"},
        {UiLang::Czech, L"Jazykové sady Windows: HTTPS"},
        {UiLang::Thai, L"ชุดภาษา Windows: HTTPS"},
        {UiLang::PortugueseBrazil, L"Pacotes de idiomas do Windows: HTTPS"},
        {UiLang::ChineseTraditional, L"Windows 語言套件：HTTPS"},
        {UiLang::Hungarian, L"Windows nyelvi csomagok: HTTPS"},
        {UiLang::Greek, L"Πακέτα γλωσσών Windows: HTTPS"},
        {UiLang::Dutch, L"Windows-taalpakketten: HTTPS"},
        {UiLang::Bulgarian, L"Езикови пакети на Windows: HTTPS"},
        {UiLang::Danish, L"Windows-sprogpakker: HTTPS"},
        {UiLang::NorwegianBokmal, L"Windows-språkpakker: HTTPS"},
        {UiLang::Finnish, L"Windowsin kielipaketit: HTTPS"},
    };
    size_t languageCount = 0;
    UiLangs(languageCount);
    Check(std::size(translations) == languageCount, "missing language pack translation test");
    for (const auto& translation : translations) {
        SetUiLang(translation.language);
        Check(LoadStringRes(IDS_PRESET_LANGUAGE_PACKS) == translation.title,
              "language pack profile title was decoded incorrectly");
        const auto translated = RulePresets::Suggest(request);
        Check(RulePresets::Apply(store, request, ChoiceOf(translated, IDS_PRESET_LANGUAGE_PACKS).rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "language pack translation bypassed semantic deduplication");
    }
    SetUiLang(previous);

    SetServices(request.pid, {L"W32Time"});
    Check(RulePresets::Suggest(request).empty() && !matches(request),
          "language pack HTTPS permission leaked to another service");
    SetServices(request.pid, {L"LxpSvc", L"BITS"});
    const auto shared = RulePresets::Suggest(request);
    Check(shared.size() == 1 && shared.front().titleId == IDS_PRESET_SVCHOST && !matches(request),
          "shared svchost guessed LxpSvc from an HTTPS connection");
    SetServices(request.pid, {L"lXpSvC"});
    const auto mixedCase = RulePresets::Suggest(request);
    ChoiceOf(mixedCase, IDS_PRESET_LANGUAGE_PACKS);
    Check(matches(request), "language pack service matching was case-sensitive");
    SetServices(request.pid, {L"LxpSvc"});
    AskRequest unrelated = request;
    unrelated.appPath = L"C:\\Downloads\\svchost.exe";
    Check(RulePresets::Suggest(unrelated).empty() && !matches(unrelated),
          "fake svchost received language pack HTTPS permissions");
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner received a language pack profile");
    unrelated = request;
    unrelated.process.reset();
    const size_t reads = serviceReads;
    const auto withoutProcess = RulePresets::Suggest(unrelated);
    Check(withoutProcess.size() == 1 && withoutProcess.front().titleId == IDS_PRESET_SVCHOST &&
          serviceReads == reads && !matches(unrelated),
          "language pack profile used a service PID without the original process handle");
}

void TestDiscoveryDeliveryPresets() {
    const auto checkBoundary = [](const AskRequest& request, const RulePresets::Choice& preset,
                                  const wchar_t* service, size_t ruleCount) {
        Check(preset.rules.size() == ruleCount && preset.title.find(service) != std::wstring::npos,
              "discovery/delivery profile lost its rules or service key");
        for (const Rule& rule : preset.rules)
            Check(rule.scope == RuleScope::App && rule.appPath == request.appPath &&
                  rule.action == RuleAction::Allow && (rule.conds & CondService) &&
                  rule.services.size() == 1 && rule.services.front().name == service &&
                  !rule.autoName && rule.name.find(service) != std::wstring::npos,
                  "discovery/delivery rule escaped its application or exact service");
        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == ruleCount,
              "discovery/delivery profile was not applied");
        const uint64_t version = store.version();
        Check(RulePresets::Apply(store, request, preset.rules) == 0 && store.version() == version,
              "repeated discovery/delivery profile duplicated rules");
        const UiLang previous = CurrentUiLang();
        SetUiLang(UiLang::Russian);
        const auto translated = RulePresets::Suggest(request);
        Check(RulePresets::Apply(store, request, ChoiceOf(translated, preset.titleId).rules) == 0,
              "discovery/delivery translation bypassed deduplication");
        SetUiLang(previous);
        SetServices(request.pid, {L"W32Time"});
        const MatchQuery query = MakeMatchQuery(request.appPath, request.pid, request.key,
            request.dir, request.icmpType, request.icmpCode, request.process.get());
        for (const Rule& rule : preset.rules)
            Check(!RuleStore::MatchesRule(rule, query), "discovery/delivery rule permitted another service");
        SetServices(request.pid, {service, L"BITS"});
        const auto shared = RulePresets::Suggest(request);
        Check(std::none_of(shared.begin(), shared.end(), [](const auto& choice) {
                  return choice.titleId != IDS_PRESET_SVCHOST;
              }), "shared svchost guessed a discovery/delivery service");
        SetServices(request.pid, {service});
        AskRequest unrelated = request;
        unrelated.ownerAmbiguous = true;
        Check(RulePresets::Suggest(unrelated).empty(), "ambiguous discovery/delivery owner got a preset");
        unrelated = request;
        unrelated.appPath = L"C:\\Downloads\\svchost.exe";
        Check(RulePresets::Suggest(unrelated).empty(), "fake svchost got a discovery/delivery preset");
    };
    const auto expectConnection = [](const AskRequest& request, UINT titleId) {
        const auto suggested = RulePresets::Suggest(request);
        const auto& preset = ChoiceOf(suggested, titleId);
        const MatchQuery query = MakeMatchQuery(request.appPath, request.pid, request.key,
            request.dir, request.icmpType, request.icmpCode, request.process.get());
        Check(std::any_of(preset.rules.begin(), preset.rules.end(), [&](const Rule& rule) {
                  return RuleStore::MatchesRule(rule, query);
              }), "discovery/delivery profile did not match its connection");
    };

    AskRequest discovery = Request(SystemDirFile(L"svchost.exe"), Proto::Udp, 3702, L"239.255.255.250");
    SetServices(discovery.pid, {L"fdPHost"});
    const auto discoveryChoices = RulePresets::Suggest(discovery);
    Check(discoveryChoices.size() == 1, "fdPHost got duplicate or unrelated profiles");
    const auto& host = ChoiceOf(discoveryChoices, IDS_PRESET_FUNCTION_DISCOVERY_HOST);
    checkBoundary(discovery, host, L"fdPHost", 3);
    for (const Rule& rule : host.rules) {
        Check((rule.conds & CondRemoteAddr) && rule.remoteAddrs.size() >= 2 &&
              rule.remoteAddrs[0].macro == AddrMacro::LocalNetwork &&
              rule.remoteAddrs[1].macro == AddrMacro::MyComputer,
              "fdPHost lost its local network restriction");
        if (rule.proto == Proto::Tcp)
            Check(rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 5357 &&
                  rule.remotePorts.front().to == 5358 && rule.localPorts.empty() &&
                  rule.remoteAddrs.size() == 2, "fdPHost metadata allowed unrelated ports or multicast");
        else {
            const auto& ports = rule.dir == Dir::Out ? rule.remotePorts : rule.localPorts;
            Check(rule.proto == Proto::Udp && ports.size() == 2 &&
                  ports[0].from == 1900 && ports[0].to == 1900 &&
                  ports[1].from == 3702 && ports[1].to == 3702 && rule.remoteAddrs.size() == 4,
                  "fdPHost discovery allowed unrelated protocols, ports or addresses");
        }
    }
    for (uint16_t port : {uint16_t{1900}, uint16_t{3702}}) {
        for (const wchar_t* remote : {L"239.255.255.250", L"ff02::c"}) {
            AskRequest connection = Request(discovery.appPath, Proto::Udp, port, remote);
            if (connection.key.remote.family == AF_INET6) connection.key.local = Ip(L"fe80::10");
            expectConnection(connection, IDS_PRESET_FUNCTION_DISCOVERY_HOST);
        }
        for (const wchar_t* peer : {L"127.0.0.1", L"::1"}) {
            AskRequest connection = Request(discovery.appPath, Proto::Udp, 41000, peer);
            connection.dir = Dir::In;
            connection.key.local = Ip(peer);
            connection.key.lport = port;
            expectConnection(connection, IDS_PRESET_FUNCTION_DISCOVERY_HOST);
        }
    }
    for (uint16_t port : {uint16_t{1899}, uint16_t{1901}, uint16_t{3701}, uint16_t{3703}}) {
        AskRequest unrelated = Request(discovery.appPath, Proto::Udp, port, L"239.255.255.250");
        Check(RulePresets::Suggest(unrelated).empty(), "fdPHost accepted another remote discovery port");
        unrelated.dir = Dir::In;
        unrelated.key.rport = 41000;
        unrelated.key.lport = port;
        Check(RulePresets::Suggest(unrelated).empty(), "fdPHost accepted another local discovery port");
    }
    for (uint16_t port : {uint16_t{5357}, uint16_t{5358}})
        expectConnection(Request(discovery.appPath, Proto::Tcp, port, L"127.0.0.1"),
                         IDS_PRESET_FUNCTION_DISCOVERY_HOST);
    for (auto [proto, port] : {
        std::pair{Proto::Udp, uint16_t{1900}}, std::pair{Proto::Udp, uint16_t{3702}},
        std::pair{Proto::Tcp, uint16_t{5357}}, std::pair{Proto::Tcp, uint16_t{80}},
        std::pair{Proto::Tcp, uint16_t{443}}
    })
        Check(RulePresets::Suggest(Request(discovery.appPath, proto, port)).empty(),
              "fdPHost received public discovery or generic web access");
    SetServices(discovery.pid, {L"FDResPub"});
    const auto publication = RulePresets::Suggest(discovery);
    Check(publication.size() == 1 && ChoiceOf(publication, IDS_PRESET_DISCOVERY).rules.size() == 2,
          "fdPHost extension changed the FDResPub profile");

    AskRequest delivery = Request(discovery.appPath);
    SetServices(delivery.pid, {L"DoSvc"});
    const auto deliveryChoices = RulePresets::Suggest(delivery);
    Check(deliveryChoices.size() == 2, "DoSvc web connection did not offer basic and full profiles");
    const auto& web = ChoiceOf(deliveryChoices, IDS_PRESET_DELIVERY_WEB);
    const auto& full = ChoiceOf(deliveryChoices, IDS_PRESET_DELIVERY_FULL);
    checkBoundary(delivery, full, L"DoSvc", 5);
    for (size_t i = 3; i < full.rules.size(); ++i) {
        const Rule& rule = full.rules[i];
        const auto& ports = i == 3 ? rule.remotePorts : rule.localPorts;
        Check(rule.proto == Proto::Tcp && rule.dir == (i == 3 ? Dir::Out : Dir::In) &&
              ports.size() == 1 && ports.front().from == 7680 && ports.front().to == 7680 &&
              (rule.conds & CondRemoteAddr) && rule.remoteAddrs.size() == 2 &&
              rule.remoteAddrs[0].macro == AddrMacro::LocalNetwork &&
              rule.remoteAddrs[1].macro == AddrMacro::MyComputer,
              "DoSvc peer rule lost its port, direction or local network restriction");
    }
    for (auto [proto, port, remote] : {
        std::tuple{Proto::Tcp, uint16_t{80}, L"198.51.100.20"},
        std::tuple{Proto::Tcp, uint16_t{443}, L"2001:db8::20"},
        std::tuple{Proto::Udp, uint16_t{53}, L"127.0.0.1"},
        std::tuple{Proto::Tcp, uint16_t{53}, L"127.0.0.1"}
    })
        expectConnection(Request(delivery.appPath, proto, port, remote), IDS_PRESET_DELIVERY_FULL);
    for (const wchar_t* peer : {L"127.0.0.1", L"::1"}) {
        for (Dir dir : {Dir::Out, Dir::In}) {
            AskRequest connection = Request(delivery.appPath, Proto::Tcp,
                                           dir == Dir::Out ? 7680 : 41000, peer);
            connection.dir = dir;
            connection.key.local = Ip(peer);
            connection.key.lport = dir == Dir::Out ? 41000 : 7680;
            expectConnection(connection, IDS_PRESET_DELIVERY_FULL);
            const auto peerChoices = RulePresets::Suggest(connection);
            Check(peerChoices.size() == 2 && ChoiceOf(peerChoices, IDS_PRESET_DELIVERY_LAN).rules.size() == 2,
                  "DoSvc peer connection lost its LAN-only profile");
        }
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{7680}}, std::pair{Proto::Udp, uint16_t{7680}},
        std::pair{Proto::Udp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{53}},
        std::pair{Proto::Tcp, uint16_t{22}}
    })
        Check(RulePresets::Suggest(Request(delivery.appPath, proto, port)).empty(),
              "DoSvc permitted public peers, arbitrary DNS or unrelated traffic");
    RuleStore store;
    Check(RulePresets::Apply(store, delivery, web.rules) == 3 &&
          RulePresets::Apply(store, delivery, full.rules) == 2 && store.Count() == 5,
          "full DoSvc profile duplicated existing web/DNS rules");
}

void TestGitHttpsLoopbackPreset() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    AskRequest request = Request(L"C:\\Program Files\\Git\\mingw64\\libexec\\git-core\\git-remote-https.exe",
                                 Proto::Tcp, 28906, L"127.0.0.1");
    request.key.local = Ip(L"127.0.0.1");
    request.key.lport = 28907;
    request.interfaceName = std::make_shared<const std::wstring>(L"Loopback Pseudo-Interface 1");
    request.conditionFlags = 1;
    const auto offered = [](const AskRequest& flow) {
        const auto choices = RulePresets::Suggest(flow);
        return std::any_of(choices.begin(), choices.end(), [](const auto& choice) {
            return choice.titleId == IDS_PRESET_GIT_HTTPS_LOOPBACK;
        });
    };
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "Git HTTPS loopback request did not receive its own preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_GIT_HTTPS_LOOPBACK);
    Check(preset.title == L"git-remote-https.exe: Local connections (loopback), TCP" &&
          preset.rules.size() == 1, "Git HTTPS loopback preset lost its title or rule");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && EqualNoCase(rule.appPath, request.appPath) &&
          rule.action == RuleAction::Allow && rule.proto == Proto::Tcp && rule.dir == Dir::Unknown &&
          rule.conds == (CondProto | CondRemoteAddr | CondLocalAddr) &&
          rule.remoteAddrs.size() == 1 && rule.localAddrs.size() == 1 &&
          rule.remoteAddrs[0].addr == Ip(L"127.0.0.1") && rule.remoteAddrs[0].prefix == -1 &&
          rule.localAddrs[0].addr == Ip(L"127.0.0.1") && rule.localAddrs[0].prefix == -1 &&
          rule.remotePorts.empty() && rule.localPorts.empty() && rule.services.empty() &&
          rule.interfaceName.empty() && rule.conditionFlags == 0 && !rule.autoName,
          "Git HTTPS loopback rule lost its exact endpoints or pinned a captured condition");
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "Git HTTPS loopback preset was not applied");
    for (Dir direction : {Dir::Out, Dir::In}) {
        for (uint16_t port : {uint16_t{1}, uint16_t{80}, uint16_t{443},
                              uint16_t{28906}, uint16_t{65535}}) {
            AskRequest flow = request;
            flow.dir = direction;
            flow.key = MakeFlowKey(Proto::Tcp, Ip(L"127.0.0.1"), Ip(L"127.0.0.1"), 12345, port);
            flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
            flow.conditionFlags.reset();
            RuleAction action = RuleAction::Block;
            Check(offered(flow) && RuleStore::MatchesRule(rule, flow.ToQuery()) &&
                  store.MatchVerdict(flow.ToQuery(), action) && action == RuleAction::Allow,
                  "Git HTTPS loopback rule depended on ports, interface, flags or direction");
        }
    }
    for (bool local : {false, true}) {
        for (const wchar_t* address : {L"127.0.0.2", L"192.0.2.1", L"::1"}) {
            AskRequest wrong = request;
            if (local) wrong.key.local = Ip(address);
            else wrong.key.remote = Ip(address);
            Check(!offered(wrong) && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
                  "Git HTTPS loopback rule accepted another local or remote address");
        }
    }
    AskRequest wrong = request;
    wrong.key.proto = Proto::Udp;
    Check(!offered(wrong) && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
          "Git HTTPS loopback rule accepted UDP");
    for (const wchar_t* path : {L"C:\\Apps\\git.exe", L"C:\\Apps\\git-remote-http.exe",
                                L"C:\\Apps\\other.exe"}) {
        wrong = request;
        wrong.appPath = path;
        Check(!offered(wrong) && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
              "Git HTTPS loopback preset accepted another executable");
    }
    wrong = request;
    wrong.appPath = L"D:\\Other\\git-remote-https.exe";
    Check(offered(wrong) && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
          "Git HTTPS loopback rule lost its concrete executable path scope");
    wrong = request;
    wrong.ownerAmbiguous = true;
    Check(!offered(wrong), "ambiguous owner received a Git HTTPS loopback preset");
    const uint64_t version = store.version();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto localized = RulePresets::Suggest(request);
        const auto& translated = ChoiceOf(localized, IDS_PRESET_GIT_HTTPS_LOOPBACK);
        const std::wstring title = LoadStringRes(IDS_PRESET_GIT_HTTPS_LOOPBACK);
        Check(title.find(L"git-remote-https.exe") != std::wstring::npos &&
              translated.title == title && translated.rules.size() == 1 &&
              translated.rules[0].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                  title.c_str(), LoadStringRes(IDS_PRESET_RULE_LOOPBACK_TCP_IPV4).c_str()) &&
              RulePresets::Apply(store, request, translated.rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "localized Git HTTPS loopback preset was lost or duplicated");
    }
    SetUiLang(previous);
}

void TestExactTcpLoopbackPresets() {
    struct Profile {
        std::wstring path;
        UINT titleId;
        bool system;
    };
    const Profile profiles[] = {
        {L"C:\\Program Files\\PowerShell\\7\\pwsh.exe", IDS_PRESET_PWSH_TCP_LOOPBACK, false},
        {KernelImagePath(), IDS_PRESET_SYSTEM_TCP_LOOPBACK, true}
    };
    const UiLang previous = CurrentUiLang();
    for (const Profile& profile : profiles) {
        SetUiLang(UiLang::English);
        AskRequest request = Request(profile.path, Proto::Tcp, 47001, L"127.0.0.1");
        request.key.local = Ip(L"127.0.0.1");
        request.key.lport = 52774;
        request.dir = profile.system ? Dir::In : Dir::Out;
        request.interfaceName = std::make_shared<const std::wstring>(L"Loopback Pseudo-Interface 1");
        request.conditionFlags = 1;
        if (profile.system) {
            request.pid = 4;
            request.process.reset();
            request.appName = L"SYSTEM";
        }
        const auto offered = [&](const AskRequest& flow) {
            const auto choices = RulePresets::Suggest(flow);
            return std::any_of(choices.begin(), choices.end(), [&](const auto& choice) {
                return choice.titleId == profile.titleId;
            });
        };
        const auto choices = RulePresets::Suggest(request);
        const auto& preset = ChoiceOf(choices, profile.titleId);
        Check(preset.rules.size() == 2 && preset.title == (profile.system
                  ? L"SYSTEM: Local connections (loopback), TCP"
                  : L"pwsh.exe: Local connections (loopback), TCP"),
              "exact TCP loopback preset lost its title or rules");
        for (size_t i = 0; i < preset.rules.size(); ++i) {
            const Rule& rule = preset.rules[i];
            const wchar_t* address = i == 0 ? L"127.0.0.1" : L"::1";
            const bool outbound = !profile.system && i == 1;
            Check(rule.scope == RuleScope::App && EqualNoCase(rule.appPath, request.appPath) &&
                  rule.action == RuleAction::Allow && rule.proto == Proto::Tcp &&
                  rule.dir == (outbound ? Dir::Out : Dir::Unknown) &&
                  rule.conds == (CondProto | CondRemoteAddr | CondLocalAddr |
                                 (outbound ? CondDirection : 0)) &&
                  rule.remoteAddrs.size() == 1 && rule.localAddrs.size() == 1 &&
                  rule.remoteAddrs[0].addr == Ip(address) && rule.remoteAddrs[0].prefix == -1 &&
                  rule.localAddrs[0].addr == Ip(address) && rule.localAddrs[0].prefix == -1 &&
                  rule.remotePorts.empty() && rule.localPorts.empty() && rule.services.empty() &&
                  rule.interfaceName.empty() && rule.conditionFlags == 0 && !rule.autoName,
                  "exact TCP loopback rule lost its scope or pinned a captured condition");
            for (Dir direction : {Dir::In, Dir::Out}) {
                for (uint16_t port : {uint16_t{1}, uint16_t{47001}, uint16_t{65535}}) {
                    AskRequest flow = request;
                    flow.dir = direction;
                    flow.key = MakeFlowKey(Proto::Tcp, Ip(address), Ip(address), port, 12345);
                    flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
                    flow.conditionFlags.reset();
                    Check(offered(flow) && RuleStore::MatchesRule(rule, flow.ToQuery()),
                          "exact TCP loopback rule depended on ports, interface, flags or direction");
                }
            }
            for (bool changeLocal : {false, true}) {
                AskRequest flow = request;
                flow.key = MakeFlowKey(Proto::Tcp, Ip(address), Ip(address), 52774, 47001);
                const wchar_t* other = i == 0 ? L"127.0.0.2" : L"::2";
                if (changeLocal) flow.key.local = Ip(other);
                else flow.key.remote = Ip(other);
                Check(!offered(flow) && !RuleStore::MatchesRule(rule, flow.ToQuery()),
                      "exact TCP loopback rule accepted another local or remote address");
            }
        }
        AskRequest wrong = request;
        wrong.key.proto = Proto::Udp;
        Check(!offered(wrong) && std::none_of(preset.rules.begin(), preset.rules.end(), [&](const Rule& rule) {
                  return RuleStore::MatchesRule(rule, wrong.ToQuery());
              }), "exact TCP loopback rule accepted UDP");
        wrong = request;
        wrong.key.local = Ip(L"::1");
        Check(!offered(wrong), "exact TCP loopback preset accepted different address families");
        wrong = request;
        wrong.appPath = profile.system ? L"C:\\Apps\\ntoskrnl.exe" : L"D:\\Other\\pwsh.exe";
        Check(offered(wrong) == !profile.system &&
              !RuleStore::MatchesRule(preset.rules[0], wrong.ToQuery()),
              "exact TCP loopback preset lost its executable or concrete path scope");
        wrong = request;
        wrong.ownerAmbiguous = true;
        Check(!offered(wrong), "ambiguous owner received an exact TCP loopback preset");

        RuleStore store;
        Check(RulePresets::Apply(store, request, preset.rules) == 2 && store.Count() == 2,
              "exact TCP loopback preset was not applied");
        RuleAction verdict = RuleAction::Block;
        Check(store.MatchVerdict(request.ToQuery(), verdict) && verdict == RuleAction::Allow,
              "exact TCP loopback preset did not produce an allow verdict");
        const uint64_t version = store.version();
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            const auto translated = RulePresets::Suggest(request);
            const auto& localized = ChoiceOf(translated, profile.titleId);
            const std::wstring title = LoadStringRes(profile.titleId);
            Check(!title.empty() && localized.title == title && localized.rules.size() == 2 &&
                  RulePresets::Apply(store, request, localized.rules) == 0 &&
                  store.Count() == 2 && store.version() == version,
                  "localized exact TCP loopback preset was lost or duplicated");
            for (size_t j = 0; j < localized.rules.size(); ++j) {
                const std::wstring name = LoadStringRes(j == 0 ? IDS_PRESET_RULE_LOOPBACK_TCP_IPV4
                                                               : IDS_PRESET_RULE_LOOPBACK_TCP_IPV6);
                Check(localized.rules[j].name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                          title.c_str(), name.c_str()), "exact TCP loopback rule name was not localized");
            }
        }
    }
    SetUiLang(previous);
}

void TestSystemLoopbackPresets() {
    AskRequest smb = Request(KernelImagePath(), Proto::Tcp, 445, L"::1");
    smb.pid = 4;
    smb.process.reset();
    smb.appName = L"SYSTEM";
    smb.key.local = Ip(L"::1");
    smb.key.lport = 50947;
    smb.conditionFlags = 1;
    smb.interfaceName = std::make_shared<const std::wstring>(L"Loopback Pseudo-Interface 1");
    AskRequest udp = smb;
    udp.key.proto = Proto::Udp;
    udp.key.rport = 443;
    udp.key.lport = 39373;
    const size_t reads = serviceReads;
    const auto smbChoices = RulePresets::Suggest(smb);
    const auto udpChoices = RulePresets::Suggest(udp);
    Check(smbChoices.size() == 2 && udpChoices.size() == 1 && serviceReads == reads,
          "System loopback profiles queried SCM or suggested unrelated permissions");
    const auto& smbRules = ChoiceOf(smbChoices, IDS_PRESET_SYSTEM_SMB_LOOPBACK).rules;
    const auto& udpRules = ChoiceOf(udpChoices, IDS_PRESET_SYSTEM_UDP_LOOPBACK).rules;
    Check(smbRules.size() == 2 && udpRules.size() == 1 &&
          smbRules[0].name != smbRules[1].name,
          "System loopback profiles lost SMB or UDP rules or their distinct names");
    for (auto [rule, proto, remotePort, localPort] : {
        std::tuple{&smbRules[0], Proto::Tcp, uint16_t{445}, uint16_t{0}},
        std::tuple{&smbRules[1], Proto::Tcp, uint16_t{0}, uint16_t{445}},
        std::tuple{&udpRules[0], Proto::Udp, uint16_t{443}, uint16_t{0}}
    }) {
        const uint32_t portCond = remotePort ? CondRemotePort : CondLocalPort;
        const auto& ports = remotePort ? rule->remotePorts : rule->localPorts;
        Check(rule->scope == RuleScope::App && EqualNoCase(rule->appPath, smb.appPath) &&
              rule->action == RuleAction::Allow && rule->proto == proto && rule->dir == Dir::Unknown &&
              rule->conds == (CondProto | CondRemoteAddr | CondLocalAddr | portCond) &&
              ports.size() == 1 && ports[0].from == (remotePort ? remotePort : localPort) &&
              ports[0].to == ports[0].from && rule->services.empty() &&
              (remotePort ? rule->localPorts.empty() : rule->remotePorts.empty()) &&
              rule->interfaceName.empty() && rule->conditionFlags == 0 &&
              rule->remoteAddrs.size() == 2 && rule->localAddrs.size() == 2,
              "System loopback rule lost its application, port or endpoint conditions");
        for (const auto* addresses : {&rule->remoteAddrs, &rule->localAddrs}) {
            Check((*addresses)[0].addr == Ip(L"127.0.0.0") && (*addresses)[0].prefix == 8 &&
                  (*addresses)[1].addr == Ip(L"::1"), "System loopback address was widened");
        }
        for (const wchar_t* address : {L"127.0.0.2", L"::1"}) {
            for (Dir direction : {Dir::Out, Dir::In}) {
                AskRequest flow = smb;
                flow.dir = direction;
                flow.key = MakeFlowKey(proto, Ip(address), Ip(address),
                    localPort ? localPort : 50000, remotePort ? remotePort : 50000);
                Check(RuleStore::MatchesRule(*rule, flow.ToQuery()),
                      "System loopback rule should accept its port on either direction");
                if (remotePort) flow.key.rport = 50001;
                else flow.key.lport = 50001;
                Check(!RuleStore::MatchesRule(*rule, flow.ToQuery()),
                      "System loopback rule accepted a different port on its restricted side");
            }
        }
    }
    RuleStore legacyStore;
    std::vector<Rule> legacySmb = smbRules;
    std::vector<Rule> legacyUdp = udpRules;
    legacySmb[0].dir = Dir::Out;
    legacySmb[1].dir = Dir::In;
    legacyUdp[0].dir = Dir::Out;
    for (Rule& rule : legacySmb) rule.conds |= CondDirection;
    legacyUdp[0].conds |= CondDirection;
    Check(RulePresets::Apply(legacyStore, smb, legacySmb) == 2 &&
          RulePresets::Apply(legacyStore, udp, legacyUdp) == 1 &&
          RulePresets::Apply(legacyStore, smb, smbRules) == 0 &&
          RulePresets::Apply(legacyStore, udp, udpRules) == 0 && legacyStore.Count() == 3,
          "direction-free System presets duplicated equivalent existing rules");
    RuleStore store;
    Check(RulePresets::Apply(store, smb, smbRules) == 2 &&
          RulePresets::Apply(store, udp, udpRules) == 1 && store.Count() == 3,
          "System loopback profiles were not applied independently");
    const uint64_t version = store.version();
    for (const wchar_t* address : {L"127.0.0.1", L"::1"}) {
        for (auto [proto, direction, remotePort, localPort, titleId] : {
            std::tuple{Proto::Tcp, Dir::Out, uint16_t{445}, uint16_t{50948}, UINT{IDS_PRESET_SYSTEM_SMB_LOOPBACK}},
            std::tuple{Proto::Tcp, Dir::In, uint16_t{50948}, uint16_t{445}, UINT{IDS_PRESET_SYSTEM_SMB_LOOPBACK}},
            std::tuple{Proto::Udp, Dir::Out, uint16_t{443}, uint16_t{39374}, UINT{IDS_PRESET_SYSTEM_UDP_LOOPBACK}}
        }) {
            AskRequest connection = smb;
            connection.dir = direction;
            connection.key = MakeFlowKey(proto, Ip(address), Ip(address), localPort, remotePort);
            const auto choices = RulePresets::Suggest(connection);
            Check(choices.size() == (proto == Proto::Tcp ? 2u : 1u) &&
                  ChoiceOf(choices, titleId).titleId == titleId,
                  "System loopback profile did not cover a pictured IPv4 or IPv6 connection");
            RuleAction action = RuleAction::Block;
            Check(store.MatchVerdict(connection.ToQuery(), action) && action == RuleAction::Allow,
                  "System loopback rule failed to allow a pictured connection");
            AskRequest wrong = connection;
            wrong.key.local = Ip(wrong.key.local.family == AF_INET6 ? L"2001:db8::10" : L"192.0.2.10");
            Check(RulePresets::Suggest(wrong).empty() && !store.MatchVerdict(wrong.ToQuery(), action),
                  "System loopback allowed a nonlocal source");
            wrong = connection;
            wrong.key.remote = Ip(wrong.key.remote.family == AF_INET6 ? L"2001:db8::20" : L"198.51.100.20");
            Check(RulePresets::Suggest(wrong).empty() && !store.MatchVerdict(wrong.ToQuery(), action),
                  "System loopback allowed a nonlocal peer");
        }
    }
    for (auto [proto, port] : {
        std::pair{Proto::Tcp, uint16_t{443}}, std::pair{Proto::Udp, uint16_t{445}},
        std::pair{Proto::Tcp, uint16_t{444}}, std::pair{Proto::Udp, uint16_t{444}}
    }) {
        AskRequest wrong = smb;
        wrong.key.proto = proto;
        wrong.key.rport = port;
        RuleAction action = RuleAction::Block;
        const auto choices = RulePresets::Suggest(wrong);
        Check((proto == Proto::Tcp
                  ? choices.size() == 1 && choices.front().titleId == IDS_PRESET_SYSTEM_TCP_LOOPBACK
                  : choices.empty()) && !store.MatchVerdict(wrong.ToQuery(), action),
              "System SMB or UDP loopback profile allowed an unrelated protocol or port");
    }
    for (const wchar_t* path : {L"C:\\Apps\\ntoskrnl.exe", L"C:\\Apps\\other.exe", L""}) {
        AskRequest wrong = smb;
        wrong.appPath = path;
        RuleAction action = RuleAction::Block;
        Check(RulePresets::Suggest(wrong).empty() && !store.MatchVerdict(wrong.ToQuery(), action),
              "System loopback profile escaped the real kernel path");
    }
    AskRequest ambiguous = smb;
    ambiguous.ownerAmbiguous = true;
    Check(RulePresets::Suggest(ambiguous).empty(), "ambiguous owner received a System profile");
    const UiLang previous = CurrentUiLang();
    for (UiLang language : {UiLang::Russian, UiLang::English}) {
        SetUiLang(language);
        const auto translatedSmb = RulePresets::Suggest(smb);
        const auto translatedUdp = RulePresets::Suggest(udp);
        Check(RulePresets::Apply(store, smb,
              ChoiceOf(translatedSmb, IDS_PRESET_SYSTEM_SMB_LOOPBACK).rules) == 0 &&
              RulePresets::Apply(store, udp,
              ChoiceOf(translatedUdp, IDS_PRESET_SYSTEM_UDP_LOOPBACK).rules) == 0 &&
              store.Count() == 3 && store.version() == version,
              "translated System loopback profile duplicated rules");
    }
    SetUiLang(previous);
}

void TestSppExtComObjPreset() {
    const UiLang previous = CurrentUiLang();
    SetUiLang(UiLang::English);
    AskRequest request = Request(SystemDirFile(L"SppExtComObj.exe"), Proto::Tcp, 1688, L"10.3.0.20");
    request.dir = Dir::Out;
    request.key.local = Ip(L"192.168.0.116");
    request.key.lport = 15162;
    request.conditionFlags = 1;
    request.interfaceName = std::make_shared<const std::wstring>(L"Captured Wi-Fi");
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "SppExtComObj did not get its exact preset");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_SPP_EXT_COM_OBJ);
    Check(preset.title == L"SppExtComObj.exe: TCP 1688" && preset.rules.size() == 1,
          "SppExtComObj preset lost its title or single rule");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && EqualNoCase(rule.appPath, request.appPath) &&
          rule.appName == request.appName && rule.action == RuleAction::Allow &&
          rule.proto == Proto::Tcp && rule.dir == Dir::Out &&
          rule.conds == (CondProto | CondDirection | CondRemotePort) &&
          rule.remotePorts.size() == 1 && rule.remotePorts.front().from == 1688 &&
          rule.remotePorts.front().to == 1688 && rule.localPorts.empty() &&
          rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.services.empty() &&
          rule.interfaceName.empty() && rule.conditionFlags == 0 && !rule.autoName,
          "SppExtComObj rule lost a condition or pinned a captured endpoint");
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "cannot apply SppExtComObj preset");
    const uint64_t version = store.version();
    for (Dir dir : {Dir::Out, Dir::In}) {
        AskRequest flow = request;
        flow.dir = dir;
        flow.key.remote = Ip(L"203.0.113.33");
        flow.key.local = Ip(L"10.20.30.40");
        flow.key.lport = 60000;
        flow.interfaceName = std::make_shared<const std::wstring>(L"Another interface");
        flow.conditionFlags.reset();
        const auto offered = RulePresets::Suggest(flow);
        RuleAction action = RuleAction::Block;
        Check(offered.size() == 1 && offered.front().titleId == IDS_PRESET_SPP_EXT_COM_OBJ &&
              RuleStore::MatchesRule(rule, flow.ToQuery()) &&
              store.MatchVerdict(flow.ToQuery(), action) && action == RuleAction::Allow,
              "SppExtComObj preset pinned an endpoint or changed direction handling");
    }
    for (const auto& [proto, port] : {
            std::pair{Proto::Udp, uint16_t{1688}}, std::pair{Proto::Tcp, uint16_t{1687}},
            std::pair{Proto::Tcp, uint16_t{1689}}}) {
        AskRequest wrong = request;
        wrong.key.proto = proto;
        wrong.key.rport = port;
        Check(RulePresets::Suggest(wrong).empty() && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
              "SppExtComObj preset accepted another protocol or port");
    }
    AskRequest wrong = request;
    wrong.appPath = L"C:\\Apps\\other.exe";
    Check(RulePresets::Suggest(wrong).empty() && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
          "SppExtComObj preset accepted another executable");
    wrong.appPath = L"D:\\Other\\SppExtComObj.exe";
    Check(RulePresets::Suggest(wrong).size() == 1 && !RuleStore::MatchesRule(rule, wrong.ToQuery()),
          "SppExtComObj preset lost filename matching or concrete path scope");
    wrong = request;
    wrong.ownerAmbiguous = true;
    Check(RulePresets::Suggest(wrong).empty(), "ambiguous owner got SppExtComObj preset");
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto localized = RulePresets::Suggest(request);
        const auto& translated = ChoiceOf(localized, IDS_PRESET_SPP_EXT_COM_OBJ);
        const std::wstring title = LoadStringRes(IDS_PRESET_SPP_EXT_COM_OBJ);
        const std::wstring name = LoadStringRes(IDS_PRESET_RULE_KMS_TCP);
        Check(title == L"SppExtComObj.exe: TCP 1688" && name == L"TCP 1688" &&
              translated.title == title && translated.rules.size() == 1 &&
              translated.rules.front().name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                  title.c_str(), name.c_str()) &&
              RulePresets::Apply(store, request, translated.rules) == 0 &&
              store.Count() == 1 && store.version() == version,
              "localized SppExtComObj preset was lost or duplicated");
    }
    SetUiLang(previous);
}

void TestNetbiosBlockPresets() {
    AskRequest request = Request(KernelImagePath(), Proto::Udp, 46560, L"192.168.0.1");
    request.pid = 4;
    request.process.reset();
    request.appName = L"SYSTEM";
    request.dir = Dir::In;
    request.key.local = Ip(L"192.168.0.116");
    request.key.lport = 137;
    request.conditionFlags = 1;
    request.interfaceName = std::make_shared<const std::wstring>(L"Беспроводная сеть 6");
    const size_t reads = serviceReads;
    const auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1 && serviceReads == reads,
          "System NetBIOS should offer one profile without a process handle or SCM lookup");
    const auto& preset = ChoiceOf(choices, IDS_PRESET_NETBIOS_BLOCK);
    Check(preset.rules.size() == 1, "NetBIOS block profile must contain one combined rule");
    const Rule& rule = preset.rules.front();
    Check(rule.scope == RuleScope::App && EqualNoCase(rule.appPath, request.appPath) &&
          rule.appName == request.appName && !rule.autoName &&
          rule.action == RuleAction::Block && rule.proto == Proto::Udp && rule.dir == Dir::Unknown &&
          rule.conds == (CondProto | CondLocalPort) && rule.remotePorts.empty() &&
          rule.localPorts.size() == 2 && rule.localPorts[0].from == 137 && rule.localPorts[0].to == 137 &&
          rule.localPorts[1].from == 138 && rule.localPorts[1].to == 138 &&
          rule.remoteAddrs.empty() && rule.localAddrs.empty() && rule.services.empty() &&
          rule.interfaceName.empty() && rule.conditionFlags == 0 &&
          rule.name.find(preset.title) != std::wstring::npos,
          "NetBIOS block rule lost its action, exact application or combined local ports");
    RuleStore store;
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "cannot apply NetBIOS block profile");
    const uint64_t version = store.version();
    for (auto [local, remote] : {
        std::pair{L"192.168.219.144", L"192.168.219.255"},
        std::pair{L"10.180.0.4", L"10.180.0.255"},
        std::pair{L"192.0.2.10", L"255.255.255.255"},
        std::pair{L"192.0.2.20", L"198.51.100.20"}
    }) {
        for (uint16_t localPort : {uint16_t{137}, uint16_t{138}}) {
            for (uint16_t remotePort : {uint16_t{1}, uint16_t{137}, uint16_t{138},
                                        uint16_t{46560}, uint16_t{65535}}) {
                for (Dir direction : {Dir::In, Dir::Out}) {
                    AskRequest connection = request;
                    connection.key = MakeFlowKey(Proto::Udp, Ip(local), Ip(remote), localPort, remotePort);
                    connection.dir = direction;
                    const auto suggested = RulePresets::Suggest(connection);
                    Check(suggested.size() == 1, "NetBIOS block profile pinned a captured endpoint");
                    ChoiceOf(suggested, IDS_PRESET_NETBIOS_BLOCK);
                    RuleAction action = RuleAction::Allow;
                    Check(store.MatchVerdict(connection.ToQuery(), action) && action == RuleAction::Block,
                          "applied NetBIOS preset did not block the matching connection");
                }
            }
        }
    }
    const auto reject = [&](const AskRequest& unrelated) {
        Check(RulePresets::Suggest(unrelated).empty(), "unrelated connection got a NetBIOS block profile");
        RuleAction action = RuleAction::Allow;
        Check(!store.MatchVerdict(MakeMatchQuery(unrelated.appPath, unrelated.pid,
                  unrelated.key, unrelated.dir), action), "NetBIOS rule blocked unrelated traffic");
    };
    for (uint16_t port : {uint16_t{137}, uint16_t{138}}) {
        AskRequest unrelated = request;
        unrelated.key.rport = 46560;
        unrelated.key.lport = port;
        unrelated.key.proto = Proto::Tcp;
        reject(unrelated);
        unrelated.key.proto = Proto::Udp;
        unrelated.key.lport = 41000;
        reject(unrelated);
    }
    for (uint16_t port : {uint16_t{53}, uint16_t{136}, uint16_t{139}, uint16_t{445}, uint16_t{5353}}) {
        AskRequest unrelated = request;
        unrelated.key.rport = unrelated.key.lport = port;
        reject(unrelated);
    }
    for (const wchar_t* path : {L"C:\\Apps\\ntoskrnl.exe", L"C:\\Apps\\not-ntoskrnl.exe",
                               L"C:\\Apps\\ntoskrnl.exe.bak", L""}) {
        AskRequest unrelated = request;
        unrelated.appPath = path;
        reject(unrelated);
    }
    AskRequest unrelated = request;
    unrelated.appPath = SystemDirFile(L"svchost.exe");
    SetServices(unrelated.pid, {});
    reject(unrelated);
    unrelated = request;
    unrelated.ownerAmbiguous = true;
    Check(RulePresets::Suggest(unrelated).empty(), "ambiguous owner got a NetBIOS block profile");
    unrelated = request;
    unrelated.appPath = FoldCaseCopy(request.appPath);
    Check(RulePresets::Suggest(unrelated).size() == 1, "System image matching became case-sensitive");
    Check(RulePresets::Apply(store, request, preset.rules) == 0 && store.version() == version,
          "repeated NetBIOS block preset created duplicates");
    const UiLang previous = CurrentUiLang();
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        const auto translated = RulePresets::Suggest(request);
        const auto& localized = ChoiceOf(translated, IDS_PRESET_NETBIOS_BLOCK);
        const std::wstring title = LoadStringRes(IDS_PRESET_NETBIOS_BLOCK);
        const std::wstring name = LoadStringRes(IDS_PRESET_RULE_NETBIOS_LOCAL_BLOCK);
        Check(name == L"NetBIOS-NS / NetBIOS-DGM, UDP 137, 138" &&
              localized.rules.size() == 1 &&
              localized.rules.front().name == LoadStringResFmt(IDS_PRESET_RULE_NAME_FMT,
                  title.c_str(), name.c_str()) &&
              RulePresets::Apply(store, request, localized.rules) == 0 && store.version() == version,
              "language change lost or duplicated the NetBIOS block rule");
    }
    SetUiLang(previous);
    Rule disabled = store.ForApp(request.appPath).front();
    disabled.enabled = false;
    disabled.name = L"Custom NetBIOS block";
    Check(store.Update(disabled), "cannot disable NetBIOS rule");
    Check(RulePresets::Apply(store, request, preset.rules) == 1 && store.Count() == 1,
          "disabled NetBIOS block rule was duplicated instead of re-enabled");
    Rule restored;
    Check(store.Get(disabled.id, restored) && restored.enabled &&
          restored.action == RuleAction::Block && restored.name == disabled.name,
          "NetBIOS reactivation changed the existing rule identity or action");
    RuleStore opposite;
    Rule allow = preset.rules.front();
    allow.action = RuleAction::Allow;
    const uint64_t allowId = opposite.Add(allow);
    Check(RulePresets::Apply(opposite, request, preset.rules) == 1 && opposite.Count() == 2 &&
          opposite.Get(allowId, restored) && restored.action == RuleAction::Allow,
          "blocking preset deduplication confused opposite actions");
}

void TestServiceSuggestions() {
    AskRequest request = Request(SystemDirFile(L"svchost.exe"), Proto::Udp, 123);
    SetServices(request.pid, {L"W32Time"});
    auto choices = RulePresets::Suggest(request);
    Check(choices.size() == 1, "time service got unrelated profiles");
    const auto& time = ChoiceOf(choices, IDS_PRESET_TIME);
    Check(time.title.find(L"W32Time") != std::wstring::npos, "service key missing from choice");
    for (const Rule& rule : time.rules)
        Check((rule.conds & CondService) && rule.services.size() == 1 &&
              rule.services.front().name == L"W32Time", "service rule lost its exact service");
    request.key.proto = Proto::Tcp;
    request.key.rport = 443;
    Check(RulePresets::Suggest(request).empty(), "identified time service got web access");

    SetServices(request.pid, {L"Dnscache"});
    request.key.proto = Proto::Udp;
    request.key.rport = 53;
    request.key.remote = Ip(L"127.0.0.1");
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_DNS);
    request.key.remote = Ip(L"198.51.100.123");
    Check(RulePresets::Suggest(request).empty(), "DNS allowed an unconfigured public resolver");
    request.key.rport = 5353;
    request.key.remote = Ip(L"224.0.0.251");
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_DNS);

    SetServices(request.pid, {L"Dhcp"});
    request.key = MakeFlowKey(Proto::Udp, Ip(L"0.0.0.0"), Ip(L"255.255.255.255"), 68, 67);
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_DHCP);
    ChoiceOf(choices, IDS_PRESET_DHCP_CLIENT_PORTS);
    Check(choices.front().titleId == IDS_PRESET_DHCP_CLIENT_PORTS,
          "DHCP client port preset was not selected for automatic application");
    request.key = MakeFlowKey(Proto::Udp, Ip(L"fe80::10"), Ip(L"ff02::1:2"), 546, 547);
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_DHCP);
    request.key.lport = 41000;
    Check(RulePresets::Suggest(request).empty(), "DHCP profile ignored the client port");

    request.key = MakeFlowKey(Proto::Udp, Ip(L"192.0.2.10"), Ip(L"198.51.100.20"), 41000, 123);
    SetServices(request.pid, {L"W32Time", L"Dnscache"});
    choices = RulePresets::Suggest(request);
    Check(choices.size() == 1 && choices.front().titleId == IDS_PRESET_SVCHOST,
          "shared svchost guessed a specific service");
    for (const Rule& rule : choices.front().rules)
        Check(!(rule.conds & CondService), "fallback depends on an ambiguous service list");

    SetServices(request.pid, {});
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_SVCHOST);
    SetServices(request.pid, {L"W32Time"});
    request.process.reset();
    const size_t reads = serviceReads;
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_SVCHOST);
    Check(serviceReads == reads, "service lookup without the original process handle");
    request.appPath = L"C:\\Downloads\\svchost.exe";
    Check(RulePresets::Suggest(request).empty(), "fake svchost path got a system preset");

    request = Request(SystemDirFile(L"svchost.exe"));
    SetServices(request.pid, {L"wuauserv"});
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_WINDOWS_UPDATE);
    SetServices(request.pid, {L"BITS"});
    choices = RulePresets::Suggest(request);
    ChoiceOf(choices, IDS_PRESET_BITS);
}

void TestDuplicatesAndPersistence() {
    AskRequest request = Request(L"C:\\Apps\\chrome.exe");
    const auto choices = RulePresets::Suggest(request);
    const auto& secure = ChoiceOf(choices, IDS_PRESET_BROWSER_HTTPS);
    const auto& web = ChoiceOf(choices, IDS_PRESET_BROWSER_WEB);
    RuleStore store;
    Check(RulePresets::Apply(store, request, secure.rules) == 4, "initial preset not inserted");
    const uint64_t version = store.version();
    Check(RulePresets::Apply(store, request, secure.rules) == 0 && store.version() == version,
          "repeat preset duplicated or rewrote rules");
    Check(RulePresets::Apply(store, request, web.rules) == 1 && store.Count() == 5,
          "overlapping preset duplicated shared rules");
    SetUiLang(UiLang::Ukrainian);
    const auto translated = RulePresets::Suggest(request);
    Check(RulePresets::Apply(store, request, ChoiceOf(translated, IDS_PRESET_BROWSER_WEB).rules) == 0,
          "language change bypassed deduplication");
    SetUiLang(UiLang::English);

    Rule existing = store.ForApp(request.appPath).front();
    const uint64_t id = existing.id;
    existing.enabled = false;
    existing.name = L"User-defined name";
    existing.dir = Dir::In;
    existing.localPorts = {{42, 42}};       // выключенное условие не влияет на дубликат
    Check(store.Update(existing), "cannot disable existing rule");
    Check(RulePresets::Apply(store, request, secure.rules) == 1 && store.Count() == 5,
          "disabled equivalent rule was duplicated instead of enabled");
    Check(store.Get(id, existing) && existing.enabled && existing.name == L"User-defined name",
          "existing rule identity or custom name was overwritten");

    AskRequest mailRequest = Request(L"C:\\Apps\\thunderbird.exe", Proto::Tcp, 993);
    const auto mailChoices = RulePresets::Suggest(mailRequest);
    const auto& mail = ChoiceOf(mailChoices, IDS_PRESET_MAIL);
    Rule modified = mail.rules.front();
    std::reverse(modified.remotePorts.begin(), modified.remotePorts.end());
    modified.remotePorts.push_back({993, 993});
    store.Add(modified);
    const size_t count = store.Count();
    Check(RulePresets::Apply(store, mailRequest, mail.rules) == mail.rules.size() - 1 &&
          store.Count() == count + mail.rules.size() - 1, "port order or repetition created duplicates");

    wchar_t directory[MAX_PATH]{}, path[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) != 0 && GetTempFileNameW(directory, L"fxp", 0, path),
          "cannot create isolated rules database");
    {
        RuleStore database;
        std::wstring error;
        Check(database.AttachDatabase(path, error), "cannot open temporary rules database");
        Check(RulePresets::Apply(database, request, secure.rules) == 4 && database.dbError().empty(),
              "preset database save failed");
        database.DetachDatabase();
        RuleStore loaded;
        Check(loaded.LoadOnce(path, error) && loaded.Count() == 4, "preset rules did not survive reload");
        Check(loaded.ForApp(request.appPath).front().name == secure.rules.front().name,
              "localized preset rule name did not survive reload");
        Check(RulePresets::Apply(loaded, request, secure.rules) == 0, "reload bypassed deduplication");
    }
    DeleteFileW(path);
}

void TestAskIconLifetime() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    Check(InitCommonControlsEx(&controls) != FALSE, "common controls initialization failed");
    AskWindow window;
    AskRequest request = Request(L"");
    const auto makeIcon = []() -> ProcessIconRef {
        ProcessIcon icon(static_cast<HICON>(CopyImage(LoadIconW(nullptr, IDI_APPLICATION),
                                                      IMAGE_ICON, 16, 16, LR_COPYFROMRESOURCE)), 16);
        Check(icon.handle() != nullptr, "cannot create ask icon");
        return std::make_shared<ProcessIcon>(std::move(icon));
    };
    ProcessIconRef icon = makeIcon();
    std::weak_ptr<const ProcessIcon> weak = icon;
    Check(window.Show(nullptr, GetModuleHandleW(nullptr), std::move(icon), request, 0),
          "ask window with owned icon creation failed");
    Check(!weak.expired(), "ask window did not retain process icon");
    window.Close();
    Check(weak.expired(), "closing ask window retained process icon");

    icon = makeIcon();
    weak = icon;
    Check(!window.Show(nullptr, GetModuleHandleW(nullptr), std::move(icon), request, 0,
                       [] { return false; }) && weak.expired(),
          "cancelled ask window retained process icon");
}

void TestAskWindowRtl() {
    const UiLang previous = CurrentUiLang();
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    Check(InitCommonControlsEx(&controls) != FALSE, "common controls initialization failed");
    AskWindow window;
    AskRequest request = Request(L"C:\\Apps\\chrome.exe");
    for (UiLang language : {UiLang::Arabic, UiLang::English, UiLang::Persian}) {
        SetUiLang(language);
        const bool rtl = language == UiLang::Arabic || language == UiLang::Persian;
        Check(window.Show(nullptr, GetModuleHandleW(nullptr), nullptr, request, 0),
              "RTL ask window creation failed");
        Check(!!(GetWindowLongPtrW(window.hwnd(), GWL_EXSTYLE) & WS_EX_LAYOUTRTL) == rtl,
              "ask window has the wrong layout");
        for (int id : {700, 701, 702, 703, 704, 705, 706}) {
            HWND control = GetDlgItem(window.hwnd(), id);
            Check(control &&
                  !!(GetWindowLongPtrW(control, GWL_EXSTYLE) &
                     (WS_EX_LAYOUTRTL | WS_EX_RTLREADING)) == rtl,
                  "ask action or preset control has the wrong reading order");
        }
        RECT allow{}, block{};
        GetWindowRect(GetDlgItem(window.hwnd(), 705), &allow);
        GetWindowRect(GetDlgItem(window.hwnd(), 706), &block);
        Check((allow.left > block.left) == rtl, "ask once buttons were not mirrored");
        window.Close();
    }
    SetUiLang(previous);
}

void TestAskWindowHeader() {
    const UiLang previous = CurrentUiLang();
    const DPI_AWARENESS_CONTEXT previousDpi = GetThreadDpiAwarenessContext();
    const Ui::DialogColors colors = Ui::DialogPalette();
    AskWindow window;
    const AskRequest request = Request(L"C:\\Apps\\chrome.exe");
    for (DPI_AWARENESS_CONTEXT context : {DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
                                          DPI_AWARENESS_CONTEXT_UNAWARE}) {
        SetThreadDpiAwarenessContext(context);
        for (UiLang language : {UiLang::English, UiLang::Russian, UiLang::Arabic, UiLang::Persian}) {
            SetUiLang(language);
            const bool rtl = language == UiLang::Arabic || language == UiLang::Persian;
            Check(window.Show(nullptr, GetModuleHandleW(nullptr), nullptr, request, 0),
                  "ask header window creation failed");
            Ui::Metrics m;
            m.dpi = GetDpiForWindow(window.hwnd());
            RECT client{}, action{};
            GetClientRect(window.hwnd(), &client);
            GetWindowRect(GetDlgItem(window.hwnd(), 700), &action);
            MapWindowPoints(nullptr, window.hwnd(), reinterpret_cast<POINT*>(&action), 2);
            const int actionY = m.Sc(72) + m.Sc(16) + m.Sc(19) + m.Sc(14) + 2 * m.Sc(23) + m.Sc(18);
            const int height = actionY + 4 * (m.Sc(44) + m.Sc(6)) + m.Sc(30) + m.Sc(6) +
                               m.Sc(18) + m.Sc(16) + m.Sc(52);
            Check(client.right == m.Sc(520) && client.bottom == height && action.top == actionY,
                  "ask header styling changed window size or action positions");

            HDC dc = GetDC(window.hwnd());
            Check(dc != nullptr, "cannot read ask header colors");
            const int saved = SaveDC(dc);
            // Читаем экранные координаты независимо от зеркальной раскладки окна.
            SetLayout(dc, 0);
            const COLORREF warningBackground = GetPixel(dc, rtl ? client.right - m.Sc(18) - 1 : m.Sc(18), m.Sc(36));
            const COLORREF iconTop = GetPixel(dc, rtl ? client.right - m.Sc(38) - 1 : m.Sc(38), m.Sc(18));
            const COLORREF background = GetPixel(dc, m.Sc(8), m.Sc(36));
            const int textX = m.Sc(16) + m.Sc(44) + m.Sc(12);
            const int left = rtl ? client.right - textX - m.Sc(32) : textX;
            bool aligned = false;
            for (int y = m.Sc(16); y < m.Sc(56) && !aligned; y += 2)
                for (int x = left; x < left + m.Sc(32) && !aligned; x += 2) {
                    const COLORREF pixel = GetPixel(dc, x, y);
                    aligned = pixel != CLR_INVALID && pixel != colors.surface;
                }
            if (saved) RestoreDC(dc, saved);
            ReleaseDC(window.hwnd(), dc);
            window.Close();
            Check(warningBackground == colors.surface && background == colors.surface,
                  "ask warning icon has a colored background");
            Check(iconTop != CLR_INVALID && iconTop != colors.surface,
                  "ask warning icon was not enlarged");
            if (!aligned)
                std::cerr << "Ask header language=" << static_cast<int>(language) << ", DPI=" << m.dpi << '\n';
            Check(aligned, "ask title is detached from the warning icon");
        }
    }
    SetThreadDpiAwarenessContext(previousDpi);
    SetUiLang(previous);
}

void TestAskWindowActions() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    Check(InitCommonControlsEx(&controls) != FALSE, "common controls initialization failed");
    AskWindow window;
    AskRequest request = Request(L"C:\\Apps\\chrome.exe");
    request.id = {1, 1};
    AskDecision decision;
    unsigned calls = 0;
    window.onDecision = [&](const AskRequest& shown, const AskDecision& selected) {
        Check(shown.id == request.id && !window.visible(), "callback ran before window destruction");
        decision = selected;
        ++calls;
    };
    const auto show = [&]() {
        Check(window.Show(nullptr, GetModuleHandleW(nullptr), nullptr, request, 0),
              "ask window creation failed");
        RECT client{}, button{};
        GetClientRect(window.hwnd(), &client);
        for (int id : {705, 706}) {
            HWND control = GetDlgItem(window.hwnd(), id);
            Check(control != nullptr, "once button missing");
            GetWindowRect(control, &button);
            MapWindowPoints(nullptr, window.hwnd(), reinterpret_cast<POINT*>(&button), 2);
            Check(button.left >= 0 && button.right <= client.right && button.bottom <= client.bottom,
                  "once button outside client area");
        }
    };
    show();
    Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCOUNT, 0, 0) == 3,
          "preset combo must include matching choices and Other");
    Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == 1 && calls == 0,
          "fuller browser preset must be selected without applying a decision");
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(705, BN_CLICKED), 0);
    Check(calls == 1 && decision.action == AskAction::AllowOnce && decision.presetRules.empty(),
          "Allow once created a rule decision");
    show();
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(706, BN_CLICKED), 0);
    Check(calls == 2 && decision.action == AskAction::BlockOnce && decision.presetRules.empty(),
          "Block once created a rule decision");
    show();
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(calls == 3 && decision.action == AskAction::Preset && decision.presetRules.size() == 4 &&
          decision.presetRules[0].remotePorts.size() == 2 &&
          decision.presetRules[0].remotePorts[0].from == 443 &&
          decision.presetRules[0].remotePorts[1].from == 80,
          "Use presets did not apply the fuller default selection");
    show();
    SendDlgItemMessageW(window.hwnd(), 704, CB_SETCURSEL, 2, 0);
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(704, CBN_SELENDOK), 0);
    Check(calls == 4 && decision.action == AskAction::Custom && decision.presetRules.empty(),
          "Other did not select the ordinary rule editor");
    request.appPath = L"C:\\Apps\\unknown.exe";
    show();
    Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCOUNT, 0, 0) == 1 &&
          SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == 0,
          "unknown application should select only Other");
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(calls == 5 && decision.action == AskAction::Custom, "fallback did not open the editor");
    for (auto [file, proto, port, remote, selected, ruleCount] : {
        std::tuple{L"devenv.exe", Proto::Tcp, uint16_t{443}, L"198.51.100.20", 1, size_t{1}},
        std::tuple{L"firefox.exe", Proto::Tcp, uint16_t{24493}, L"127.0.0.1", 1, size_t{5}},
        std::tuple{L"brave.exe", Proto::Udp, uint16_t{5353}, L"224.0.0.251", 1, size_t{6}},
        std::tuple{L"chrome.exe", Proto::Tcp, uint16_t{80}, L"198.51.100.20", 0, size_t{4}},
        std::tuple{L"steamwebhelper.exe", Proto::Udp, uint16_t{1900}, L"239.255.255.250", 0, size_t{9}},
        std::tuple{L"steamwebhelper.exe", Proto::Udp, uint16_t{5353}, L"224.0.0.251", 0, size_t{9}}
    }) {
        request = Request(std::wstring(L"C:\\Apps\\") + file, proto, port, remote);
        request.id = {1, 1};
        const unsigned before = calls;
        show();
        Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == selected &&
              calls == before, "matching fuller profile was not selected without a decision");
        SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
        Check(calls == before + 1 && decision.action == AskAction::Preset &&
              decision.presetRules.size() == ruleCount, "fuller default profile was not applied");
    }
    for (auto [service, proto, port, remote, selected, ruleCount] : {
        std::tuple{L"fdPHost", Proto::Udp, uint16_t{1900}, L"239.255.255.250", 0, size_t{3}},
        std::tuple{L"DoSvc", Proto::Tcp, uint16_t{443}, L"198.51.100.20", 1, size_t{5}},
        std::tuple{L"DoSvc", Proto::Tcp, uint16_t{7680}, L"127.0.0.1", 1, size_t{5}}
    }) {
        request = Request(SystemDirFile(L"svchost.exe"), proto, port, remote);
        request.id = {1, 1};
        SetServices(request.pid, {service});
        const unsigned before = calls;
        show();
        Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == selected &&
              calls == before, "discovery/delivery default profile was not selected");
        SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
        Check(calls == before + 1 && decision.action == AskAction::Preset &&
              decision.presetRules.size() == ruleCount, "discovery/delivery default profile was not applied");
    }
    request = Request(KernelImagePath(), Proto::Udp, 443, L"127.0.0.1");
    request.pid = 4;
    request.process.reset();
    request.appName = L"SYSTEM";
    request.id = {1, 1};
    request.key.local = Ip(L"127.0.0.1");
    request.key.lport = 137;
    const unsigned beforeOverlap = calls;
    show();
    Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCOUNT, 0, 0) == 3 &&
          SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == 0 && calls == beforeOverlap,
          "unrelated block preset replaced the default allow preset");
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(calls == beforeOverlap + 1 && decision.action == AskAction::Preset &&
          decision.presetRules.size() == 1 && decision.presetRules[0].action == RuleAction::Allow,
          "overlapping allow and block presets changed the default action");
    for (uint16_t port : {uint16_t{137}, uint16_t{138}}) {
        request = Request(KernelImagePath(), Proto::Udp, port,
            port == 137 ? L"192.168.219.255" : L"10.180.0.255");
        request.pid = 4;
        request.process.reset();
        request.appName = L"SYSTEM";
        request.id = {1, 1};
        request.key.lport = port;
        const unsigned before = calls;
        show();
        Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCOUNT, 0, 0) == 2 &&
              SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == 0 && calls == before,
              "NetBIOS block preset was not selected without applying a decision");
        SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
        Check(calls == before + 1 && decision.action == AskAction::Preset &&
              decision.presetRules.size() == 1 &&
              std::all_of(decision.presetRules.begin(), decision.presetRules.end(),
                  [](const Rule& rule) { return rule.action == RuleAction::Block; }),
              "NetBIOS default preset lost its blocking action in the ask window");
    }
    request = Request(L"", ProtoFromNumber(2), 0, L"224.0.0.22");
    request.pid = 0;
    request.process.reset();
    request.id = {1, 1};
    const unsigned before = calls;
    show();
    Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCOUNT, 0, 0) == 2 &&
          SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == 0,
          "IGMP PID 0 preset was not selected in the ask window");
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(calls == before + 1 && decision.action == AskAction::Preset &&
          decision.presetRules.size() == 1 && decision.presetRules.front().isPostApp() &&
          (decision.presetRules.front().conds & CondPidZero),
          "IGMP PID 0 preset lost its post-app scope in the ask window");
    request.dir = Dir::In;
    request.key.local = Ip(L"224.0.0.1");
    request.key.remote = Ip(L"192.168.0.1");
    const unsigned inboundBefore = calls;
    show();
    Check(SendDlgItemMessageW(window.hwnd(), 704, CB_GETCOUNT, 0, 0) == 2 &&
          SendDlgItemMessageW(window.hwnd(), 704, CB_GETCURSEL, 0, 0) == 0,
          "incoming IGMP preset was not selected in the ask window");
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(calls == inboundBefore + 1 && decision.action == AskAction::Preset &&
          decision.presetRules.size() == 1 && decision.presetRules.front().isPostApp() &&
          decision.presetRules.front().dir == Dir::In &&
          (decision.presetRules.front().conds & CondPidZero) &&
          (decision.presetRules.front().conds & CondLocalAddr),
          "incoming IGMP preset lost its direction or restrictions in the ask window");
    Ui::ReleaseFonts();
}

struct WindowOwner {
    HWND hwnd = nullptr;
    explicit WindowOwner(HWND owner = nullptr) {
        hwnd = CreateWindowExW(0, L"STATIC", LoadStringRes(IDS_RULES_TITLE).c_str(),
            (owner ? WS_POPUP | WS_CAPTION | WS_SYSMENU : WS_OVERLAPPEDWINDOW) | WS_CLIPCHILDREN,
            40, 40, 800, 600, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
        Check(hwnd != nullptr, "test owner creation failed");
    }
    ~WindowOwner() { if (IsWindow(hwnd)) DestroyWindow(hwnd); }
};

bool PopupOnScreen(HWND window) {
    RECT rect{};
    MONITORINFO info{sizeof(info)};
    HMONITOR monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONULL);
    return monitor && GetMonitorInfoW(monitor, &info) && GetWindowRect(window, &rect) &&
        rect.left >= info.rcWork.left && rect.top >= info.rcWork.top &&
        rect.right <= info.rcWork.right && rect.bottom <= info.rcWork.bottom;
}

class VisibilityModal : public Ui::Modal {
public:
    std::function<void(VisibilityModal&)> inspect;
    bool guardedInit = false;
    bool inspected = false;
    HWND window() const { return hwnd(); }

protected:
    void OnInit() override {
        guardedInit = Ui::ModalActive();
        // Проверяем уже показанное окно внутри настоящего модального цикла.
        if (!PostMessageW(hwnd(), WM_COMMAND, 1900, 0)) EndCancel();
    }
    bool OnCommand(int id, int) override {
        if (id != 1900) return false;
        inspected = true;
        if (inspect) inspect(*this);
        EndCancel();
        return true;
    }
};

void TestModalVisibility() {
    WindowOwner owner;
    ShowWindow(owner.hwnd, SW_SHOWMINNOACTIVE);
    VisibilityModal modal;
    bool placed = false, tracked = false, hiddenRestored = false, movedRestored = false;
    modal.inspect = [&](VisibilityModal& shown) {
        HWND window = shown.window();
        placed = PopupOnScreen(window) && !IsWindowEnabled(owner.hwnd);
        tracked = Ui::ModalWindow(owner.hwnd) == window && Ui::ModalDepth() == 1;
        ShowWindow(window, SW_HIDE);
        hiddenRestored = !IsWindowVisible(window) && Ui::RestorePopup(window) &&
            IsWindowVisible(window) && !IsWindowEnabled(owner.hwnd) &&
            Ui::ModalWindow(owner.hwnd) == window;
        SetWindowPos(window, nullptr, -32000, -32000, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        movedRestored = Ui::RestorePopup(window) && PopupOnScreen(window) &&
            !IsWindowEnabled(owner.hwnd);
    };
    Check(!modal.Run(owner.hwnd, GetModuleHandleW(nullptr),
                     LoadStringRes(IDS_RED_TITLE_CREATE), 320, 200), "probe modal was accepted");
    Check(modal.guardedInit && modal.inspected, "modal initialization was not guarded");
    Check(placed, "modal with minimized owner was placed outside the screen");
    Check(tracked, "active modal window was not tracked");
    Check(hiddenRestored, "hidden modal recovery lost owner modality");
    Check(movedRestored, "off-screen modal was not recovered");
    Check(IsWindowEnabled(owner.hwnd) && !Ui::ModalActive() && !Ui::ModalWindow(owner.hwnd),
          "modal close did not restore its owner and tracking");
}

void TestNestedModalVisibility() {
    WindowOwner owner;
    ShowWindow(owner.hwnd, SW_SHOWNOACTIVATE);
    VisibilityModal outer;
    bool nestedTracked = false, nestedReturned = false, disabledOwnerPreserved = false;
    bool nativeTracked = false, nativeHiddenTracked = false;
    outer.inspect = [&](VisibilityModal& parent) {
        VisibilityModal inner;
        inner.inspect = [&](VisibilityModal& child) {
            nestedTracked = Ui::ModalDepth() == 2 && Ui::ModalWindow(owner.hwnd) == child.window() &&
                !IsWindowEnabled(parent.window()) && !IsWindowEnabled(owner.hwnd);
        };
        inner.Run(parent.window(), GetModuleHandleW(nullptr),
                  LoadStringRes(IDS_RED_TITLE_CREATE), 300, 180);
        nestedReturned = inner.inspected && Ui::ModalDepth() == 1 &&
            Ui::ModalWindow(owner.hwnd) == parent.window() &&
            IsWindowEnabled(parent.window()) && !IsWindowEnabled(owner.hwnd);

        // Команда из трея может открыть второй диалог с уже отключённым главным окном.
        VisibilityModal sibling;
        sibling.Run(owner.hwnd, GetModuleHandleW(nullptr),
                    LoadStringRes(IDS_RED_TITLE_CREATE), 300, 180);
        disabledOwnerPreserved = sibling.inspected && !IsWindowEnabled(owner.hwnd) &&
            Ui::ModalWindow(owner.hwnd) == parent.window();

        // Системный диалог не входит в ModalDepth, но отключает свой Modal-владелец.
        WindowOwner native(parent.window());
        ShowWindow(native.hwnd, SW_SHOWNOACTIVATE);
        EnableWindow(parent.window(), FALSE);
        nativeTracked = Ui::ModalDepth() == 1 && Ui::ModalWindow(owner.hwnd) == native.hwnd;
        ShowWindow(native.hwnd, SW_HIDE);
        nativeHiddenTracked = Ui::ModalWindow(owner.hwnd) == native.hwnd &&
            Ui::RestorePopup(native.hwnd) && IsWindowVisible(native.hwnd) &&
            !IsWindowEnabled(parent.window()) && !IsWindowEnabled(owner.hwnd);
        EnableWindow(parent.window(), TRUE);
    };
    outer.Run(owner.hwnd, GetModuleHandleW(nullptr),
              LoadStringRes(IDS_RED_TITLE_CREATE), 320, 200);
    Check(outer.inspected && nestedTracked, "nested modal was not tracked");
    Check(nestedReturned, "nested modal did not return to its parent");
    Check(disabledOwnerPreserved, "modal enabled an owner disabled by another dialog");
    Check(nativeTracked, "nested native modal was not found");
    Check(nativeHiddenTracked, "hidden nested native modal was not found and restored");
    Check(IsWindowEnabled(owner.hwnd) && !Ui::ModalActive(), "outer modal did not release its owner");
}

void TestAskWindowRecovery() {
    WindowOwner owner;
    ShowWindow(owner.hwnd, SW_SHOWNOACTIVATE);
    AskWindow window;
    AskRequest request = Request(L"C:\\Apps\\unknown.exe");
    request.id = {1, 1};
    unsigned calls = 0;
    window.onDecision = [&](const AskRequest&, const AskDecision&) { ++calls; };
    bool checkedHidden = false;
    Check(!window.Show(owner.hwnd, GetModuleHandleW(nullptr), nullptr, request, 0, [&]() {
        checkedHidden = window.visible() && !IsWindowVisible(window.hwnd());
        return false;
    }) && checkedHidden && !window.visible() && calls == 0,
          "resolved request was shown before the final validation or produced a decision");
    Check(!window.Show(owner.hwnd, GetModuleHandleW(nullptr), nullptr, request, 0, [&]() {
        window.Close();
        return true;
    }) && !window.visible() && calls == 0,
          "ask window closed during validation was shown again");
    Check(window.Show(owner.hwnd, GetModuleHandleW(nullptr), nullptr, request, 0),
          "owned ask window creation failed");
    HWND original = window.hwnd();
    ShowWindow(owner.hwnd, SW_SHOWMINNOACTIVE);
    Check(window.visible() && !IsWindowVisible(original), "owner minimize did not hide the ask popup");
    window.Restore();
    Check(IsWindowVisible(original) && PopupOnScreen(original) && window.hwnd() == original &&
          window.requestId() == request.id && calls == 0 && IsIconic(owner.hwnd),
          "ask recovery recreated or decided the request, or restored its owner");
    window.Close();
    Check(calls == 0, "silent ask close produced a decision");
    Ui::ReleaseFonts();
}

void TestAskToModalVisibility() {
    WindowOwner owner;
    ShowWindow(owner.hwnd, SW_SHOWMINNOACTIVE);
    AskWindow window;
    AskRequest request = Request(L"C:\\Apps\\unknown.exe");
    request.id = {1, 1};
    bool custom = false, editorVisible = false, cancelled = false;
    window.onDecision = [&](const AskRequest& shown, const AskDecision& decision) {
        custom = decision.action == AskAction::Custom && shown.id == request.id && !window.visible();
        VisibilityModal editor;
        editor.inspect = [&](VisibilityModal& modal) {
            editorVisible = IsWindowVisible(modal.window()) && PopupOnScreen(modal.window()) &&
                !IsWindowEnabled(owner.hwnd) && Ui::ModalWindow(owner.hwnd) == modal.window();
        };
        cancelled = !editor.Run(owner.hwnd, GetModuleHandleW(nullptr),
                                LoadStringRes(IDS_RED_TITLE_CREATE), 320, 200) && editor.inspected;
    };
    Check(window.Show(owner.hwnd, GetModuleHandleW(nullptr), nullptr, request, 0),
          "ask window with minimized owner creation failed");
    SendMessageW(window.hwnd(), WM_COMMAND, MAKEWPARAM(703, BN_CLICKED), 0);
    Check(custom && editorVisible && cancelled, "Ask -> Custom modal disappeared with minimized owner");
    Check(IsWindowEnabled(owner.hwnd) && !Ui::ModalActive() && !window.visible(),
          "Ask -> Custom cancellation left a blocked owner");
    Ui::ReleaseFonts();
}

struct RulePidProbe {
    static inline RulePidProbe* active = nullptr;
    int operation = 0, rows = 0;
    bool observed = false, found = false, checked = false;
    std::wstring value;

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.observed = true;
        HWND conditions = GetDlgItem(dialog, 300);
        probe.rows = ListView_GetItemCount(conditions);
        for (int row = 0; row < probe.rows; ++row) {
            wchar_t label[128]{};
            ListView_GetItemText(conditions, row, 0, label, static_cast<int>(std::size(label)));
            if (LoadStringRes(IDS_COND_PID) != label) continue;
            probe.found = true;
            if (probe.operation == 1)
                ListView_SetCheckState(conditions, row, !ListView_GetCheckState(conditions, row));
            probe.checked = ListView_GetCheckState(conditions, row) != FALSE;
            wchar_t value[128]{};
            ListView_GetItemText(conditions, row, 1, value, static_cast<int>(std::size(value)));
            probe.value = value;
        }
        if (probe.operation == 2) {
            NMLINK link{};
            link.hdr.hwndFrom = GetDlgItem(dialog, 304);
            link.hdr.idFrom = 304;
            link.hdr.code = NM_CLICK;
            wcscpy_s(link.item.szID, RuleLink::kPid);
            SendMessageW(dialog, WM_NOTIFY, 304, reinterpret_cast<LPARAM>(&link));
        }
        if (probe.operation == 3)
            SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(308, BN_CLICKED), 0);
        PostMessageW(dialog, WM_COMMAND, IDOK, 0);
    }
};

void TestRuleEditorPidFilter() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS};
    Check(InitCommonControlsEx(&controls) != FALSE, "PID editor controls initialization failed");
    const UiLang original = CurrentUiLang();
    for (UiLang language : { UiLang::Russian, UiLang::English, UiLang::Arabic }) {
        SetUiLang(language);
        for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp })
        for (bool editing : { false, true })
        for (bool zero : { false, true })
        for (int operation : { 0, 1, 2, 3 }) {
            Rule clipboard;
            clipboard.scope = RuleScope::PostApp;
            clipboard.conds = CondPidZero;
            RuleClipboard::Set(clipboard);
            Rule rule;
            rule.scope = scope;
            if (scope == RuleScope::App) rule.appPath = L"C:\\Apps\\pid-editor.exe";
            rule.conds = CondProto | (zero ? CondPidZero : 0u);
            RulePidProbe probe;
            probe.operation = operation;
            RulePidProbe::active = &probe;
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, RulePidProbe::Inspect);
            Check(timer != 0, "cannot create PID editor probe timer");
            const bool saved = RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, editing);
            KillTimer(nullptr, timer);
            RulePidProbe::active = nullptr;
            const bool postApp = scope == RuleScope::PostApp;
            const bool expectedZero = postApp &&
                (operation == 3 || (zero != (operation == 1 || operation == 2)));
            Check(probe.observed && saved && probe.found == postApp,
                  "PID selection is missing in PostApp or appears in another editor");
            if (postApp) {
                const bool checked = zero != (operation == 1);
                Check(probe.checked == checked && probe.value == LoadStringRes(
                          checked ? IDS_RULE_PID_ZERO : IDS_RULE_ANY),
                      "PID checkbox does not show any or zero");
            }
            Check(rule.scope == scope && ((rule.conds & CondPidZero) != 0) == expectedZero,
                  "PID selection or clipboard paste saved an incorrect scope-specific filter");
        }
    }
    SetUiLang(original);
    Ui::ReleaseFonts();
}

struct RulePayloadProbe {
    static inline RulePayloadProbe* active = nullptr;
    bool observed = false, present = false, readOnly = false, ltr = false;
    bool accept = true, topmost = false;
    bool created = false, createdTopmost = false;
    std::wstring text;
    DWORD selectionStart = 0, selectionEnd = 0;

    static LRESULT CALLBACK Creating(int code, WPARAM wp, LPARAM lp) {
        if (code == HCBT_CREATEWND && active) {
            wchar_t name[64]{};
            GetClassNameW(reinterpret_cast<HWND>(wp), name, static_cast<int>(std::size(name)));
            if (!lstrcmpW(name, L"FirewallXUiModal")) {
                const auto* creation = reinterpret_cast<const CBT_CREATEWNDW*>(lp);
                active->created = true;
                active->createdTopmost = (creation->lpcs->dwExStyle & WS_EX_TOPMOST) != 0;
            }
        }
        return CallNextHookEx(nullptr, code, wp, lp);
    }

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.observed = true;
        probe.topmost = (GetWindowLongPtrW(dialog, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
        for (HWND child = GetWindow(dialog, GW_CHILD); child;
             child = GetWindow(child, GW_HWNDNEXT)) {
            wchar_t className[32]{};
            GetClassNameW(child, className, static_cast<int>(std::size(className)));
            const LONG_PTR style = GetWindowLongPtrW(child, GWL_STYLE);
            if (lstrcmpiW(className, L"EDIT") || !(style & ES_MULTILINE)) continue;
            probe.present = true;
            probe.readOnly = (style & ES_READONLY) != 0;
            probe.ltr = (GetWindowLongPtrW(child, GWL_EXSTYLE) &
                         (WS_EX_LAYOUTRTL | WS_EX_RTLREADING)) == 0;
            const int length = GetWindowTextLengthW(child);
            probe.text.resize(static_cast<size_t>(length) + 1);
            GetWindowTextW(child, probe.text.data(), length + 1);
            probe.text.resize(length);
            SendMessageW(child, WM_CHAR, 1, 0);
            SendMessageW(child, EM_GETSEL, reinterpret_cast<WPARAM>(&probe.selectionStart),
                         reinterpret_cast<LPARAM>(&probe.selectionEnd));
        }
        PostMessageW(dialog, WM_COMMAND, probe.accept ? IDOK : IDCANCEL, 0);
    }
};

void TestRuleEditorPayload() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS};
    Check(InitCommonControlsEx(&controls) != FALSE, "rule editor controls initialization failed");
    const auto run = [](std::span<const uint8_t> payload, const std::wstring& expected,
                        bool editing = false, bool accept = true, bool topmost = false) {
        Rule rule = MakeEditorTemplate(Request(L"C:\\Apps\\payload.exe"));
        rule.autoName = false;
        rule.name = L"Rule without payload";
        const Rule before = rule;
        RulePayloadProbe probe;
        probe.accept = accept;
        RulePayloadProbe::active = &probe;
        const HHOOK creationHook = SetWindowsHookExW(WH_CBT, RulePayloadProbe::Creating,
                                                      nullptr, GetCurrentThreadId());
        Check(creationHook != nullptr, "cannot create rule editor creation hook");
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, RulePayloadProbe::Inspect);
        Check(timer != 0, "cannot create rule editor probe timer");
        const bool saved = RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, editing,
                                           payload, nullptr, topmost);
        UnhookWindowsHookEx(creationHook);
        KillTimer(nullptr, timer);
        RulePayloadProbe::active = nullptr;
        Check(probe.observed && saved == accept, "rule editor probe did not close normally");
        Check(probe.created && probe.createdTopmost == topmost,
              "rule editor was not created with its requested topmost mode");
        if (probe.topmost != topmost)
            std::cerr << "topmost mismatch: expected=" << topmost << " observed=" << probe.topmost
                      << " payload=" << payload.size() << " editing=" << editing << " accept=" << accept << '\n';
        Check(probe.topmost == topmost, "rule editor ignored its topmost mode");
        Check(probe.present == (!editing && !payload.empty()), "payload hint shown in the wrong context");
        if (probe.present) {
            Check(probe.text == expected, "payload Base64 was changed, truncated or incorrectly padded");
            Check(probe.readOnly && probe.ltr, "payload field is writable or inherited RTL");
            Check(probe.selectionStart == 0 && probe.selectionEnd == expected.size(),
                  "Ctrl+A did not select the entire payload for copying");
        }
        Check(rule.name == before.name && rule.appPath == before.appPath &&
              rule.conds == before.conds && rule.action == before.action &&
              rule.BuildAutoName() == before.BuildAutoName(), "payload hint changed the rule");
    };
    const struct { const char* bytes; const wchar_t* base64; } samples[] = {
        {"", L""}, {"f", L"Zg=="}, {"fo", L"Zm8="}, {"foo", L"Zm9v"},
        {"foob", L"Zm9vYg=="}, {"fooba", L"Zm9vYmE="}, {"foobar", L"Zm9vYmFy"}
    };
    for (const auto& sample : samples) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(sample.bytes);
        run({bytes, std::strlen(sample.bytes)}, sample.base64);
    }
    const std::vector<uint8_t> binary{0x00, 0x80, 0xff, 0x01};
    for (UiLang language : {UiLang::Arabic, UiLang::Persian, UiLang::English}) {
        SetUiLang(language);
        run(binary, L"AID/AQ==");
    }
    std::vector<uint8_t> large(65536, 0);
    std::wstring expected(((large.size() + 2) / 3) * 4, L'A');
    expected.replace(expected.size() - 2, 2, L"==");
    run(large, expected);
    run(binary, L"", true);
    run(binary, L"AID/AQ==", false, false);
    run({}, L"", false, true, true);
    run(binary, L"AID/AQ==", false, true, true);
    run(binary, L"AID/AQ==", false, false, true);
    run({}, L"", false, true, false);
    run(binary, L"AID/AQ==", false, false, false);
    Ui::ReleaseFonts();
}

} // анонимное пространство имён

// Только тестовая цель получает доступ к парковке и перехватывает transport.
struct IngestTestAccess {
    static void ResetSessionState(Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ingest.ClearDriverSessionLocked();
        ingest.driverSession_ = 0;
        ingest.newestDriverSession_ = 0;
    }
    static std::unique_ptr<Ingest> Create() { return std::unique_ptr<Ingest>(new Ingest); }

    static void ReservePending(Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ingest.pending_.reserve(100000);
        ingest.pendingIndex_.reserve(100000);
    }

    static bool PendingBucketsFit(const Ingest& ingest, size_t limit) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.pending_.bucket_count() <= limit &&
               ingest.pendingIndex_.bucket_count() <= limit;
    }

    static void TestPreparedShapeKey() {
        DriverVerdictSession session;
        auto ingest = Create();
        RuleStore rules;
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondNone;
        rules.Add(rule);
        ingest->Attach(&rules, nullptr);
        const auto active = session.Begin();
        ingest->BeginDriverSession(active);
        const AskRequest request = Request(L"C:\\Apps\\prepared-shape.exe", Proto::Udp);
        Ingest::Flow flow;
        flow.key = request.key;
        flow.pid = request.pid;
        flow.dir = request.dir;
        flow.app = std::make_shared<const ProcessPathInfo>(request.appPath, request.process);
        const auto key = Ingest::ShapeKeyOf(flow);
        Ingest::PreparedShapeKey prepared{key, rules.version()};

        IngestWorkProbe::counts = {};
        ingest->CacheMatchedShape(flow, RuleAction::Allow, &rules, rules.version(), active, &prepared);
        Check(IngestWorkProbe::counts.shapeHashes == 0 && ingest->verdicts_.contains(key),
              "shape insertion recalculated a key prepared for the current rules");

        const auto oldVersion = rules.version();
        rule.action = RuleAction::Block;
        Check(rules.Update(rule), "cannot change rules for prepared-key test");
        {
            std::lock_guard<std::mutex> lock(ingest->mtx_);
            ingest->SyncRulesLocked();
        }
        prepared.value ^= 1;
        IngestWorkProbe::counts = {};
        ingest->CacheMatchedShape(flow, RuleAction::Block, &rules, rules.version(), active, &prepared);
        Check(IngestWorkProbe::counts.shapeHashes == 1 && ingest->verdicts_.size() == 1 &&
                  ingest->verdicts_.contains(key) && ingest->verdicts_.at(key).action == RuleAction::Block,
              "shape insertion reused a key from another rules version");

        IngestWorkProbe::counts = {};
        ingest->CacheMatchedShape(flow, RuleAction::Allow, &rules, oldVersion, active, &prepared);
        Check(IngestWorkProbe::counts.shapeHashes == 0 &&
                  ingest->verdicts_.at(key).action == RuleAction::Block,
              "stale verdict performed hashing or replaced the current cached action");
        ingest->EndDriverSession(session.End());
    }

    static size_t VerdictExpirySize(const Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.verdictExpiry_.size();
    }

    static void CheckLastVerdictExpiry(Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        Check(ingest.verdicts_.size() == 1, "expiry test requires one shape");
        const auto tick = ingest.verdicts_.begin()->second.tick;
        ingest.ExpireVerdicts(tick + Ingest::kVerdictTtlMs);
        Check(ingest.verdicts_.size() == 1, "coalesced touches shortened the verdict TTL");
        ingest.ExpireVerdicts(tick + Ingest::kVerdictTtlMs + 1);
        Check(ingest.verdicts_.empty() && ingest.verdictExpiry_.empty(),
              "coalesced touches retained an expired verdict");
    }

    static void TestHashStorage() {
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        auto ingest = Create();
        RuleStore rules;
        ingest->Attach(&rules, nullptr);
        const uint64_t active = session.Begin();
        ingest->BeginDriverSession(active);
        AskRequest request = Request(L"C:\\Apps\\storage.exe");
        ReservePending(*ingest);
        for (uint64_t i = 0; i < 64; ++i) {
            request.key.lport = static_cast<uint16_t>(40000 + i);
            Park(*ingest, session, request, {i + 1});
        }
        const auto* pending = &ingest->pending_.begin()->second;
        const uint64_t pendingId = ingest->pending_.begin()->first;

        constexpr size_t count = 10000;
        const ULONGLONG now = GetTickCount64();
        const ULONGLONG old = now - Ingest::kVerdictTtlMs - 10000;
        const uint8_t payload[] = {0x16, 0x03, 0x03, 0x00, 0x20, 0x01};
        for (size_t i = 0; i < count; ++i) {
            const ULONGLONG tick = i < count - 32 ? old : now;
            ingest->verdicts_[i].tick = tick;
            ingest->verdictExpiry_.push_back({i, tick});
            FlowKey key = request.key;
            key.lport = static_cast<uint16_t>(i);
            TlsClientHelloInspector inspector;
            inspector.Append(payload, sizeof(payload));
            ingest->tlsAssemblies_.try_emplace(
                key, 0, payload, sizeof(payload), std::move(inspector), tick);
            ingest->tlsAssemblyExpiry_.push_back({key, tick});
            ingest->quicSniStates_[key].tick = tick;
        }
        const size_t verdictPeak = ingest->verdicts_.bucket_count();
        const size_t tlsPeak = ingest->tlsAssemblies_.bucket_count();
        const size_t quicPeak = ingest->quicSniStates_.bucket_count();
        const auto* shape = &ingest->verdicts_.at(count - 1);
        FlowKey retainedKey = request.key;
        retainedKey.lport = static_cast<uint16_t>(count - 1);
        const auto* tls = &ingest->tlsAssemblies_.at(retainedKey);
        const auto* quic = &ingest->quicSniStates_.at(retainedKey);
        ingest->Maintain();
        Check(ingest->verdicts_.size() == 32 && ingest->tlsAssemblies_.size() == 32 &&
              ingest->quicSniStates_.size() == 32 &&
              ingest->verdicts_.bucket_count() < verdictPeak / 8 &&
              ingest->tlsAssemblies_.bucket_count() < tlsPeak / 8 &&
              ingest->quicSniStates_.bucket_count() < quicPeak / 8 &&
              &ingest->verdicts_.at(count - 1) == shape &&
              &ingest->tlsAssemblies_.at(retainedKey) == tls &&
              &ingest->quicSniStates_.at(retainedKey) == quic,
              "Ingest maintenance retained peak buckets or moved live cache records");
        Check(ingest->waiting() == 64 && ingest->calls() == 64 &&
              ingest->pending_.size() == 64 && pending->requests.size() == 1,
              "cache maintenance changed pending obligations");
        Check(ingest->FlushVerdicts() == 0 && PendingBucketsFit(*ingest, 256) &&
              &ingest->pending_.at(pendingId) == pending && pending->requests.size() == 1 &&
              !pending->requests.front().tlsPayload.empty() && ingest->waiting() == 64,
              "pending compaction lost obligations, payload or node addresses");
        Check(ingest->SetPolicy(FirewallPolicy::AllowAll) == ERROR_SUCCESS &&
              ingest->verdicts_.empty() && ingest->verdicts_.bucket_count() <= 8,
              "policy reset retained verdict storage");
        Check(ingest->FlushVerdicts() == 64 && PendingBucketsFit(*ingest, 8) &&
              ingest->waiting() == 0 && ingest->calls() == ingest->answered() &&
              sentVerdicts.size() == 64,
              "pending batch cleanup retained buckets or lost verdicts");

        ingest->pending_.reserve(count);
        ingest->pendingIndex_.reserve(count);
        ingest->verdicts_.reserve(count);
        ingest->tlsAssemblies_.reserve(count);
        ingest->quicSniStates_.reserve(count);
        ingest->EndDriverSession(session.End());
        Check(PendingBucketsFit(*ingest, 8) && ingest->verdicts_.bucket_count() <= 8 &&
              ingest->tlsAssemblies_.bucket_count() <= 8 &&
              ingest->quicSniStates_.bucket_count() <= 8 &&
              ingest->verdicts_.empty() && ingest->tlsAssemblies_.empty() &&
              ingest->quicSniStates_.empty(), "session reset retained Ingest storage");
        captureSession = nullptr;
    }

    static bool DistinctWfpFlagIdentity() {
        Ingest::Flow a, b;
        a.key = b.key = MakeFlowKey(Proto::Udp, Ip(L"192.0.2.10"), Ip(L"198.51.100.20"), 41000, 5555);
        for (std::optional<uint32_t> flags : {std::optional<uint32_t>{},
                 std::optional<uint32_t>{0}, std::optional<uint32_t>{1},
                 std::optional<uint32_t>{2}, std::optional<uint32_t>{0x80000000u}}) {
            a.conditionFlags = flags;
            for (std::optional<uint32_t> other : {std::optional<uint32_t>{},
                     std::optional<uint32_t>{0}, std::optional<uint32_t>{1},
                     std::optional<uint32_t>{2}, std::optional<uint32_t>{0x80000000u}}) {
                b.conditionFlags = other;
                if (Ingest::SamePendingFlow(a, b) != (flags == other) ||
                    (Ingest::ShapeKeyOf(a) == Ingest::ShapeKeyOf(b)) != (flags == other)) return false;
            }
        }
        return true;
    }

    static void ReceivePacket(Ingest& ingest, DriverVerdictSession& session,
                              const AskRequest& request, uint64_t id,
                              const std::vector<uint8_t>& packet, uint8_t layer = 3,
                              int icmpType = -1, int icmpCode = -1, bool omitApp = false) {
        std::shared_lock policyLock(ingest.policyMtx_);
        Ingest::Incoming incoming{session.Receive(id), layer, 0, false, 0,
                                  nullptr, 0, packet.data(), packet.size()};
        incoming.flow.key = request.key;
        incoming.flow.interfaceIndex = request.interfaceIndex;
        incoming.flow.interfaceName = request.interfaceName;
        incoming.flow.pid = request.pid;
        incoming.flow.driverPid = request.pid;
        incoming.flow.dir = request.dir;
        incoming.flow.icmpType = icmpType;
        incoming.flow.icmpCode = icmpCode;
        incoming.flow.conditionFlags = request.conditionFlags;
        if (!omitApp) incoming.flow.app = std::make_shared<const ProcessPathInfo>(request.appPath, request.process);
        ingest.Ingress(std::move(incoming), packet.size());
    }

    static bool HasDnsLabelOnly(const Ingest& ingest, AskRequestId id,
                               const wchar_t* label) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        const auto group = ingest.pending_.find(id.groupId);
        if (group == ingest.pending_.end() || group->second.requests.size() != 1) return false;
        const auto& pending = group->second.requests.front();
        return pending.dnsDomainLabel && *pending.dnsDomainLabel == label &&
               pending.tlsPayload.empty() && pending.httpPayload.empty() &&
               pending.quicPayload.empty();
    }

    static AskRequestId Park(Ingest& ingest, DriverVerdictSession& session,
                             const AskRequest& request, std::initializer_list<uint64_t> ids) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        Ingest::PendingGroup group;
        group.flow.key = request.key;
        group.flow.interfaceIndex = request.interfaceIndex;
        group.flow.interfaceName = request.interfaceName;
        group.flow.pid = request.pid;
        group.flow.dir = request.dir;
        group.flow.app = std::make_shared<const ProcessPathInfo>(request.appPath, request.process);
        group.keyHash = AskHash(request.appPath, request.pid, request.key, request.dir);
        group.driverSession = session.active();
        group.accepted = true;
        for (uint64_t id : ids) {
            Ingest::PendingRequest pending{session.Receive(id)};
            pending.payloadLayer = 3;
            pending.tcpFlags = 0x010;
            pending.hasTcpPayload = true;
            pending.tlsPayload = {0x16, 0x03, 0x03, 0x00, 0x20, 0x01};
            pending.quicPayload.resize(1200, 0);
            group.requests.push_back(std::move(pending));
        }
        ingest.calls_ += ids.size();
        ingest.waiting_ += ids.size();
        const auto it = ingest.AddPendingLocked(std::move(group));
        return {session.active(), it->first};
    }

    static bool NoDecisionState(const Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.verdicts_.empty() && ingest.tlsAssemblies_.empty() &&
               ingest.quicSniStates_.empty();
    }

    static void CacheVerdict(Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        const ULONGLONG now = GetTickCount64();
        ingest.verdicts_[1].tick = now;
        ingest.verdictExpiry_.push_back({1, now});
    }

    static bool HasCurrentShapeCache(const Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.rules_ && ingest.rulesVersion_ == ingest.rules_->version() &&
               ingest.shapeCacheOn_ && !ingest.verdicts_.empty();
    }

    static bool NoCachedVerdicts(const Ingest& ingest) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.verdicts_.empty() && ingest.verdictExpiry_.empty() &&
               ingest.verdicts_.bucket_count() <= 8;
    }

    static void TouchExpiryQueues(Ingest& ingest, uint64_t shape, const FlowKey& key,
                                  ULONGLONG tick) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ingest.verdicts_[shape].tick = tick;
        ingest.verdictExpiry_.push_back({shape, tick});
        const uint8_t payload[] = {0x16, 0x03, 0x03, 0x00, 0x20, 0x01};
        auto assembly = ingest.tlsAssemblies_.find(key);
        if (assembly == ingest.tlsAssemblies_.end()) {
            TlsClientHelloInspector inspector;
            inspector.Append(payload, sizeof(payload));
            ingest.tlsAssemblies_.try_emplace(key, 0, payload, sizeof(payload),
                                            std::move(inspector), tick);
        } else {
            assembly->second.tick = tick;
        }
        ingest.tlsAssemblyExpiry_.push_back({key, tick});
    }

    static void ExpireQueues(Ingest& ingest, ULONGLONG verdictNow, ULONGLONG tlsNow) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ingest.ExpireVerdicts(verdictNow);
        ingest.ExpireTlsAssembliesLocked(tlsNow);
    }

    static bool CheckExpiryQueues(const Ingest& ingest, size_t records, size_t values) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.verdictExpiry_.size() == records &&
               ingest.tlsAssemblyExpiry_.size() == records &&
               ingest.verdicts_.size() == values && ingest.tlsAssemblies_.size() == values;
    }

    static void AddQuicState(Ingest& ingest, const FlowKey& key, ULONGLONG tick) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ingest.quicSniStates_[key].tick = tick;
    }

    static bool HasQuicState(const Ingest& ingest, const FlowKey& key) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        return ingest.quicSniStates_.count(key) != 0;
    }

    static void ExpireQuicStates(Ingest& ingest, ULONGLONG now) {
        std::lock_guard<std::mutex> lock(ingest.mtx_);
        ingest.ExpireQuicSniStatesLocked(now);
    }

    static void Maintain(Ingest& ingest) { ingest.Maintain(); }
};

#include "ask_queue_storage_tests.h"

DriverVerdictRequest test_register_driver_verdict_request(uint64_t externalConnectionId) {
    return captureSession ? captureSession->Receive(externalConnectionId) : DriverVerdictRequest();
}

bool test_process_verdict(DriverVerdictRequest request, pmkext::Verdict verdict) {
    uint64_t id = 0;
    if (!captureSession || !captureSession->Consume(request, id)) return false;
    sentVerdicts.emplace_back(id, verdict);
    return true;
}

DWORD test_clear_driver_cache() {
    ++driverCacheClears;
    return driverCacheClearStatus;
}

namespace {

void TestPolicyChangeKeepsDriverCache() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    auto ingest = IngestTestAccess::Create();
    RuleStore rules;
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    const AskRequest request = Request(L"C:\\Apps\\policy.exe", Proto::Udp);
    const AskRequestId pending = IngestTestAccess::Park(*ingest, session, request, {600});
    IngestTestAccess::CacheVerdict(*ingest);
    IngestTestAccess::AddQuicState(*ingest, request.key, GetTickCount64());

    // Ошибка перехватчика гарантирует, что SetPolicy не маскирует вызов ClearCache.
    driverCacheClears = 0;
    driverCacheClearStatus = ERROR_GEN_FAILURE;
    Check(ingest->SetPolicy(FirewallPolicy::AllowAll) == ERROR_SUCCESS &&
          ingest->policy() == FirewallPolicy::AllowAll && driverCacheClears == 0,
          "policy change cleared the driver cache");
    Check(IngestTestAccess::NoCachedVerdicts(*ingest),
          "policy change retained the user-mode verdict cache");
    Check(ingest->IsPending(pending) && ingest->waiting() == 1 &&
          ingest->calls() == 1 && ingest->answered() == 0 && sentVerdicts.empty() &&
          IngestTestAccess::HasQuicState(*ingest, request.key),
          "policy change altered pending obligations or QUIC state");
    Check(ingest->SetPolicy(FirewallPolicy::AllowAll) == ERROR_SUCCESS &&
          ingest->SetPolicy(static_cast<FirewallPolicy>(0xff)) == ERROR_INVALID_PARAMETER &&
          ingest->policy() == FirewallPolicy::AllowAll && driverCacheClears == 0,
          "unchanged or invalid policy touched the driver cache");
    ingest->Attach(&rules, nullptr, IngestMode::Service);
    Check(ingest->SetPolicy(FirewallPolicy::BlockAll) == ERROR_NOT_SUPPORTED &&
          driverCacheClears == 0, "service policy change touched the driver cache");
    ingest->EndDriverSession(session.End());
    driverCacheClearStatus = ERROR_SUCCESS;
    captureSession = nullptr;
}

void TestExpiryQueues() {
    auto ingest = IngestTestAccess::Create();
    RuleStore rules;
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(1);
    FlowKey key = Request(L"C:\\Apps\\expiry-queues.exe").key;
    constexpr ULONGLONG tick = Ingest::kVerdictTtlMs * 4;
    IngestTestAccess::TouchExpiryQueues(*ingest, 1, key, tick);
    IngestTestAccess::TouchExpiryQueues(*ingest, 1, key, tick + 1000);
    IngestTestAccess::ExpireQueues(*ingest, tick + Ingest::kVerdictTtlMs,
                                 tick + Ingest::kTlsAssemblyTtlMs);
    Check(IngestTestAccess::CheckExpiryQueues(*ingest, 2, 1),
          "expiry removed records at the exact TTL boundary");
    IngestTestAccess::ExpireQueues(*ingest, tick + Ingest::kVerdictTtlMs + 1,
                                 tick + Ingest::kTlsAssemblyTtlMs + 1);
    Check(IngestTestAccess::CheckExpiryQueues(*ingest, 1, 1),
          "old expiry records removed refreshed cache values");
    IngestTestAccess::ExpireQueues(*ingest, tick + Ingest::kVerdictTtlMs + 1001,
                                 tick + Ingest::kTlsAssemblyTtlMs + 1001);
    Check(IngestTestAccess::CheckExpiryQueues(*ingest, 0, 0),
          "fully expired queues retained cache values or records");

    // Несколько блоков повторно наполняются после полного опустошения.
    for (uint64_t i = 0; i < 10000; ++i) {
        key.lport = static_cast<uint16_t>(i);
        IngestTestAccess::TouchExpiryQueues(*ingest, i, key, tick);
    }
    Check(IngestTestAccess::CheckExpiryQueues(*ingest, 10000, 10000),
          "refilling expiry queues lost records");
    IngestTestAccess::ExpireQueues(*ingest, tick + Ingest::kVerdictTtlMs + 1,
                                 tick + Ingest::kTlsAssemblyTtlMs + 1);
    Check(IngestTestAccess::CheckExpiryQueues(*ingest, 0, 0),
          "multi-block expiry did not drain both queues");
    IngestTestAccess::TouchExpiryQueues(*ingest, 1, key, tick);
    ingest->EndDriverSession(1);
    Check(IngestTestAccess::CheckExpiryQueues(*ingest, 0, 0),
          "driver session reset retained expiry records");
}

void TestQuicSniStateExpiry() {
    for (bool ipv6 : {false, true}) {
        DriverVerdictSession session;
        auto ingest = IngestTestAccess::Create();
        RuleStore rules;
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\quic-expiry.exe", Proto::Udp);
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        const AskRequestId pending = IngestTestAccess::Park(*ingest, session, request, {610});
        FlowKey expired = request.key;
        FlowKey boundary = request.key;
        ++boundary.lport;
        FlowKey fresh = boundary;
        ++fresh.lport;
        const ULONGLONG ttl = Ingest::kQuicSniTtlMs;
        const ULONGLONG now = ttl * 4;
        IngestTestAccess::AddQuicState(*ingest, expired, now - ttl - 1);
        IngestTestAccess::AddQuicState(*ingest, boundary, now - ttl);
        IngestTestAccess::AddQuicState(*ingest, fresh, now);
        IngestTestAccess::ExpireQuicStates(*ingest, now);
        Check(!IngestTestAccess::HasQuicState(*ingest, expired) &&
              IngestTestAccess::HasQuicState(*ingest, boundary) &&
              IngestTestAccess::HasQuicState(*ingest, fresh),
              "QUIC expiry ignored the inactivity timeout boundary");
        IngestTestAccess::ExpireQuicStates(*ingest, now + 999);
        Check(IngestTestAccess::HasQuicState(*ingest, boundary),
              "QUIC maintenance scanned states more than once per second");
        IngestTestAccess::ExpireQuicStates(*ingest, now + 1000);
        Check(!IngestTestAccess::HasQuicState(*ingest, boundary) &&
              IngestTestAccess::HasQuicState(*ingest, fresh),
              "QUIC maintenance retained an expired state or removed a fresh one");

        // Последний пакет продлевает срок только своей сборки.
        IngestTestAccess::AddQuicState(*ingest, fresh, now + ttl);
        IngestTestAccess::ExpireQuicStates(*ingest, now + ttl + 1000);
        Check(IngestTestAccess::HasQuicState(*ingest, fresh),
              "QUIC expiry used creation time instead of last activity");
        IngestTestAccess::ExpireQuicStates(*ingest, now + ttl * 2 + 1000);
        Check(!IngestTestAccess::HasQuicState(*ingest, fresh) &&
              ingest->IsPending(pending) && ingest->waiting() == 1 &&
              ingest->calls() == 1 && ingest->answered() == 0,
              "QUIC expiry retained stale state or settled a pending obligation");
        ingest->EndDriverSession(session.End());
    }

    for (bool maintenance : {false, true}) {
        auto ingest = IngestTestAccess::Create();
        RuleStore rules;
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(1);
        const FlowKey key = Request(L"C:\\Apps\\quic-idle.exe", Proto::Udp).key;
        const ULONGLONG expiredAt = GetTickCount64() - Ingest::kQuicSniTtlMs - 1000;
        IngestTestAccess::AddQuicState(*ingest, key, expiredAt);
        if (maintenance) IngestTestAccess::Maintain(*ingest);
        else ingest->ExpireSniAssemblies();
        Check(!IngestTestAccess::HasQuicState(*ingest, key),
              "periodic maintenance retained idle QUIC state without new packets");
        IngestTestAccess::AddQuicState(*ingest, key, GetTickCount64());
        ingest->EndDriverSession(1);
        Check(!IngestTestAccess::HasQuicState(*ingest, key),
              "driver session retained its QUIC state");
    }
}

void TestPendingPayload() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    auto ingest = IngestTestAccess::Create();
    RuleStore rules;
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    const AskRequest request = Request(L"C:\\Apps\\payload.exe", Proto::Udp, 50001);
    IngestTestAccess::ReceivePacket(*ingest, session, request, 700, {});
    std::vector<AskRequest> pending;
    ingest->TakePending(pending);
    Check(pending.size() == 1, "empty payload did not create a pending request");
    const AskRequestId id = pending.front().id;
    Check(ingest->GetPendingPayload(id).empty(), "empty payload created a hint");

    const std::vector<uint8_t> expected{0x00, 0x80, 0xff, 0x01};
    auto packet = expected;
    IngestTestAccess::ReceivePacket(*ingest, session, request, 701, packet);
    std::fill(packet.begin(), packet.end(), uint8_t{0});
    IngestTestAccess::ReceivePacket(*ingest, session, request, 702, packet);
    const auto payload = ingest->GetPendingPayload(id);
    Check(payload == (Ingest::kShowPayloadInRuleEditor ? expected : std::vector<uint8_t>{}),
          "pending payload was not copied, replaced its first sample or ignored the constant");
    Check(ingest->GetPendingPayload({id.driverSession + 1, id.groupId}).empty() &&
          ingest->GetPendingPayload({}).empty(), "invalid request returned a payload");
    ingest->TakePending(pending);
    Check(pending.empty() && sentVerdicts.empty() && rules.Count() == 0 && ingest->waiting() == 3,
          "payload changed pending grouping, rules or verdicts");
    ingest->EndDriverSession(session.End());
    Check(ingest->GetPendingPayload(id).empty(), "payload survived its driver session");
    Check(payload == (Ingest::kShowPayloadInRuleEditor ? expected : std::vector<uint8_t>{}),
          "closing a pending group invalidated the editor's payload");
    captureSession = nullptr;
}

void TestAutomaticRuleScopes() {
    size_t cases = 0;
    for (Proto proto : { Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::IcmpV6,
                         ProtoFromNumber(47), ProtoFromNumber(132), ProtoFromNumber(144) })
    for (Dir dir : { Dir::In, Dir::Out })
    for (DWORD pid : { DWORD{0}, DWORD{4}, GetCurrentProcessId() })
    for (bool pathKnown : { false, true })
    for (bool ambiguous : { false, true }) {
        AskRequest request = Request(pathKnown ? L"C:\\Apps\\automatic.exe" : L"", proto);
        request.pid = pid;
        request.dir = dir;
        request.ownerAmbiguous = ambiguous;
        const RuleScope expected = pathKnown ? RuleScope::App : RuleScope::PostApp;
        std::vector<Rule> rules = {
            MakeAllowRule(request), MakeBlockRule(request), MakeEditorTemplate(request)
        };
        std::vector<Rule> blockAll = MakeBlockAllRules(request);
        Check(blockAll.size() == 1, "termination did not create exactly one rule");
        Check(pathKnown ? blockAll.front().conds == CondNone : blockAll.front().conds != CondNone,
              "pathless termination blocked more than the requested activity");
        rules.push_back(std::move(blockAll.front()));
        for (const Rule& rule : rules) {
            Check(rule.scope == expected && rule.appPath == request.appPath && rule.enabled,
                  "automatic rule used Global instead of App or PostApp");
            Check(RuleStore::MatchesRule(rule, request.ToQuery()),
                  "automatic rule did not cover its source request");
            Check(((rule.conds & CondPidZero) != 0) == (!pathKnown && pid == 0),
                  "automatic rule has an incorrect PID filter");
            MatchQuery otherPid = request.ToQuery();
            otherPid.pid = pid == 0 ? DWORD{1000} : DWORD{0};
            Check(RuleStore::MatchesRule(rule, otherPid) == (pathKnown || pid != 0),
                  "automatic PID filter matches the wrong ownership state");
            ++cases;
        }
    }
    std::cout << "Automatic rule scope matrix passed: " << cases << " cases\n";
}

void TestServicePolicies() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    const std::vector<uint8_t> packet;
    uint64_t id = 1;
    size_t cases = 0;

    for (auto policy : {FirewallPolicy::BlockAll, FirewallPolicy::Block,
                        FirewallPolicy::Learning, FirewallPolicy::Allow,
                        FirewallPolicy::AllowAll})
    for (Proto proto : {Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::IcmpV6,
                        ProtoFromNumber(47), ProtoFromNumber(132)})
    for (Dir dir : {Dir::Out, Dir::In})
    for (bool ipv6 : {false, true})
    for (RuleScope scope : {RuleScope::Global, RuleScope::App, RuleScope::PostApp})
    for (int match : {-1, 0, 1})
    for (bool technicalIcmp : {false, true}) {
        if (technicalIcmp && !ProtoIsIcmp(proto)) continue;
        AskRequest request = Request(L"C:\\Apps\\service-policy.exe", proto, 50001);
        request.dir = dir;
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        RuleStore rules;
        if (match >= 0) {
            Rule rule;
            rule.scope = scope;
            if (scope == RuleScope::App) rule.appPath = request.appPath;
            rule.conds = CondNone;
            rule.action = match == 0 ? RuleAction::Allow : RuleAction::Block;
            rules.Add(rule);
        }
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, IngestMode::Service, policy);
        Check(ingest->policy() == policy, "service attach replaced the selected policy");
        ingest->BeginDriverSession(session.Begin());
        const bool matched = FirewallPolicies::UsesRules(policy) && match >= 0;
        const bool allowed = matched ? match == 0
            : policy == FirewallPolicy::Allow || policy == FirewallPolicy::AllowAll ||
              (policy == FirewallPolicy::Learning && technicalIcmp);
        const auto expected = allowed ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop;
        const int icmpType = !ProtoIsIcmp(proto) ? -1 : proto == Proto::Icmp
            ? (technicalIcmp ? 3 : 8) : (technicalIcmp ? 135 : 128);

        // Повторное событие проверяет также кеш совпавшего правила.
        for (int repeat = 0; repeat < 2; ++repeat) {
            const size_t before = sentVerdicts.size();
            const uint64_t wireId = id++;
            IngestTestAccess::ReceivePacket(
                *ingest, session, request, wireId, packet, 3, icmpType,
                ProtoIsIcmp(proto) ? 0 : -1);
            const bool correct = sentVerdicts.size() == before + 1 &&
                                 sentVerdicts.back() == std::pair{wireId, expected};
            if (!correct) {
                std::cerr << "policy=" << static_cast<int>(policy)
                          << " proto=" << static_cast<int>(proto)
                          << " dir=" << static_cast<int>(dir) << " ipv6=" << ipv6
                          << " scope=" << static_cast<int>(scope) << " match=" << match
                          << " technicalIcmp=" << technicalIcmp << " repeat=" << repeat
                          << " expected=" << static_cast<int>(expected)
                          << " actual=" << (sentVerdicts.size() > before
                              ? static_cast<int>(sentVerdicts.back().second) : -1) << '\n';
            }
            Check(correct, "service policy returned an incorrect verdict");
            Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
                  "service policy parked a driver obligation");
            ++cases;
        }
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
    std::cout << "Service policy matrix passed: " << cases << " cases\n";
}

void TestServicePolicyReload() {
    std::wstring error;
    Check(Settings::Open(L":memory:", error), "cannot open isolated service settings");
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    auto ingest = IngestTestAccess::Create();
    RuleStore rules;
    ingest->Attach(&rules, nullptr, IngestMode::Service, FirewallPolicySetting::Load());
    Check(ingest->policy() == FirewallPolicy::Learning, "missing service policy did not use Learning");
    ingest->BeginDriverSession(session.Begin());
    const AskRequest request = Request(L"C:\\Apps\\service-policy.exe", Proto::Udp, 50001);
    const std::vector<uint8_t> packet;
    uint64_t id = 1;
    const auto expectVerdict = [&](pmkext::Verdict verdict) {
        const size_t before = sentVerdicts.size();
        const uint64_t wireId = id++;
        IngestTestAccess::ReceivePacket(*ingest, session, request, wireId, packet);
        Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() ==
              std::pair{wireId, verdict}, "service reload retained a stale verdict");
        Check(ingest->waiting() == 0, "service Learning created an interactive request");
    };
    expectVerdict(pmkext::Verdict::Drop);

    for (auto policy : {FirewallPolicy::AllowAll, FirewallPolicy::BlockAll,
                        FirewallPolicy::Allow, FirewallPolicy::Block,
                        FirewallPolicy::Learning}) {
        Check(FirewallPolicySetting::Save(policy), "cannot save service policy");
        // Имитируем прежнее разрешающее правило и его закешированное решение.
        Rule rule;
        rule.scope = RuleScope::Global;
        rule.conds = CondNone;
        rule.action = RuleAction::Allow;
        rules.Add(rule);
        ingest->Attach(&rules, nullptr, IngestMode::Service, FirewallPolicy::Learning);
        expectVerdict(pmkext::Verdict::PermanentAccept);
        Check(ingest->ReloadServiceRules(L":memory:"), "cannot reload service rules and policy");
        Check(ingest->policy() == policy && rules.Count() == 0,
              "service reload did not replace the rules and policy");
        expectVerdict(policy == FirewallPolicy::Allow || policy == FirewallPolicy::AllowAll
            ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop);
    }
    Check(Settings::SetString(Settings::Key::kDesktopPolicy, L"invalid"),
          "cannot store invalid service policy");
    Check(ingest->ReloadServiceRules(L":memory:") &&
          ingest->policy() == FirewallPolicy::Learning,
          "invalid service policy did not use Learning");
    expectVerdict(pmkext::Verdict::Drop);
    Check(!ingest->ReloadServiceRules(L"?:\\unavailable\\rules.db"),
          "invalid service rules path unexpectedly loaded");
    expectVerdict(pmkext::Verdict::Drop);
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    Settings::Close();
}

void TestServiceRefreshBeforeAsk() {
    DriverVerdictSession session;
    captureSession = &session;
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    deferServiceRefresh = true;

    for (RuleScope scope : {RuleScope::Global, RuleScope::App})
    for (RuleAction action : {RuleAction::Allow, RuleAction::Block}) {
        sentVerdicts.clear();
        // Уже завершённый старый опрос не подтверждает состав нового процесса.
        serviceRefreshRequested = serviceRefreshCompleted = 7;
        const AskRequest request = Request(L"C:\\Apps\\service-refresh.exe", Proto::Udp, 50001);
        SetServices(request.pid, {L"OldService"});
        RuleStore rules;
        Rule rule;
        rule.scope = scope;
        if (scope == RuleScope::App) rule.appPath = request.appPath;
        rule.conds = CondService;
        rule.services = {{L"KnownService", L""}};
        rule.action = action;
        rules.Add(rule);
        const uint64_t rulesVersion = rules.version();
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());

        IngestTestAccess::ReceivePacket(*ingest, session, request, 100, {});
        IngestTestAccess::ReceivePacket(*ingest, session, request, 101, {});
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.empty() && sentVerdicts.empty() && ingest->waiting() == 2,
              "stale service snapshot exposed a transient verdict question");
        Check(serviceRefreshRequested == 8,
              "service pending did not request one fresh SCM snapshot per group");
        ingest->TakePending(pending);
        Check(pending.empty() && serviceRefreshRequested == 8,
              "unfinished service refresh exposed a question or restarted the refresh");

        // Ошибка/частичный опрос не подтверждает отсутствие подходящего правила.
        // Успех может не изменить semantic Version(), поэтому ждём отдельный ticket.
        serviceRefreshCompleted = serviceRefreshRequested;
        SetServices(request.pid, {L"KnownService"});
        ingest->TakePending(pending);
        const auto expected = action == RuleAction::Allow
            ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop;
        Check(pending.empty() && sentVerdicts.size() == 2 &&
                  sentVerdicts[0] == std::pair{uint64_t{100}, expected} &&
                  sentVerdicts[1] == std::pair{uint64_t{101}, expected},
              "existing service rule was not applied before publishing the question");
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered() &&
                  rules.version() == rulesVersion && rules.Count() == 1,
              "service refresh lost an obligation or changed saved rules");
        IngestTestAccess::ReceivePacket(*ingest, session, request, 102, {});
        Check(sentVerdicts.size() == 3 && sentVerdicts.back().second == expected &&
                  serviceRefreshRequested == 8,
              "matched service rule unnecessarily waited for another refresh");
        ingest->EndDriverSession(session.End());
    }

    // Полный опрос без подходящей службы должен выпустить настоящий вопрос,
    // даже если карта PID -> службы и её semantic Version() не изменились.
    sentVerdicts.clear();
    serviceRefreshRequested = serviceRefreshCompleted = 0;
    const AskRequest request = Request(L"C:\\Apps\\unknown-service.exe", Proto::Udp, 50001);
    SetServices(request.pid, {});
    RuleStore rules;
    Rule rule;
    rule.scope = RuleScope::Global;
    rule.conds = CondService;
    rule.services = {{L"KnownService", L""}};
    rules.Add(rule);
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    IngestTestAccess::ReceivePacket(*ingest, session, request, 200, {});
    std::vector<AskRequest> pending;
    ingest->TakePending(pending);
    Check(pending.empty() && serviceRefreshRequested == 1,
          "unmatched service question did not wait for SCM confirmation");
    serviceRefreshCompleted = serviceRefreshRequested;
    ingest->TakePending(pending);
    Check(pending.size() == 1 && ingest->IsPending(pending.front().id) &&
              sentVerdicts.empty(),
          "unchanged fresh service snapshot lost a genuine verdict question");
    const AskRequestId id = pending.front().id;
    ingest->TakePending(pending);
    Check(pending.empty() && serviceRefreshRequested == 1,
          "service question was published twice");
    Check(ingest->AnswerOnce(id, RuleAction::Block), "cannot answer genuine service question");

    // Смена driver-сессии не превращает скрытый запрос в ответ новой сессии.
    IngestTestAccess::ReceivePacket(*ingest, session, request, 201, {});
    ingest->TakePending(pending);
    Check(pending.empty() && serviceRefreshRequested == 2,
          "new service question did not wait for its own refresh");
    ingest->EndDriverSession(session.End());
    ingest->BeginDriverSession(session.Begin());
    serviceRefreshCompleted = serviceRefreshRequested;
    ingest->TakePending(pending);
    Check(pending.empty() && sentVerdicts.size() == 1 && ingest->waiting() == 0,
          "service refresh revived an obligation from an ended driver session");
    ingest->EndDriverSession(session.End());

    // Без включённых сервисных условий обычный запрос не ждёт SCM.
    rules.SetEnabled(rule.id, false);
    const uint64_t refreshes = serviceRefreshRequested;
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    IngestTestAccess::ReceivePacket(*ingest, session, request, 202, {});
    ingest->TakePending(pending);
    Check(pending.size() == 1 && serviceRefreshRequested == refreshes,
          "ordinary question unnecessarily waited for service refresh");
    ingest->EndDriverSession(session.End());

    deferServiceRefresh = false;
    captureSession = nullptr;
    hostedByPid.clear();
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestPostAppPidCache() {
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    DriverVerdictSession session;
    captureSession = &session;
    for (IngestMode mode : { IngestMode::Desktop, IngestMode::Service })
    for (RuleAction action : { RuleAction::Allow, RuleAction::Block })
    for (bool pathKnown : { false, true })
    for (bool zeroFirst : { false, true }) {
        sentVerdicts.clear();
        RuleStore rules;
        Rule zero;
        zero.scope = RuleScope::PostApp;
        zero.conds = CondPidZero;
        zero.action = action;
        rules.Add(zero);
        Rule any = zero;
        any.conds = CondNone;
        any.action = zero.blocks() ? RuleAction::Allow : RuleAction::Block;
        rules.Add(any);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, FirewallPolicy::Learning);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(pathKnown ? L"C:\\Apps\\pid-cache.exe" : L"", Proto::Udp);
        const DWORD knownPid = request.pid;
        const auto receive = [&](DWORD pid, uint64_t wireId, RuleAction expectedAction) {
            request.pid = pid;
            const size_t before = sentVerdicts.size();
            IngestTestAccess::ReceivePacket(*ingest, session, request, wireId, {});
            const auto expected = expectedAction == RuleAction::Allow
                ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop;
            Check(sentVerdicts.size() == before + 1 &&
                      sentVerdicts.back() == std::pair{wireId, expected},
                  "verdict cache reused a PID 0 decision for a nonzero PID or vice versa");
        };
        for (uint64_t id = 1; id <= 6; ++id) {
            const DWORD pid = ((id % 2 != 0) == zeroFirst) ? DWORD{0} : knownPid;
            receive(pid, id, pid == 0 ? zero.action : any.action);
        }
        receive(4, 7, any.action);
        zero.conds = CondNone;
        Check(rules.Update(zero), "cannot remove PID condition for cache invalidation");
        receive(knownPid, 8, zero.action);
        receive(0, 9, zero.action);
        Check(ingest->waiting() == 0, "PID cache test left a pending verdict");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Enable(wasEnabled);
}

void TestAutomaticPidRuleSettlesOnlyZero() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    AskRequest zero = Request(L"", Proto::Udp);
    AskRequest known = zero;
    known.pid = 4;
    zero.pid = 0;
    IngestTestAccess::ReceivePacket(*ingest, session, zero, 401, {});
    IngestTestAccess::ReceivePacket(*ingest, session, known, 402, {});
    Check(sentVerdicts.empty() && ingest->waiting() == 2,
          "PID filter test did not create both pending requests");
    Rule allowZero = MakeAllowRule(zero);
    Check((allowZero.conds & CondPidZero) != 0, "automatic PID 0 rule has no filter");
    rules.Add(allowZero);
    ingest->FlushVerdicts();
    Check(sentVerdicts.size() == 1 && sentVerdicts.front() ==
              std::pair{uint64_t{401}, pmkext::Verdict::PermanentAccept} && ingest->waiting() == 1,
          "automatic PID 0 rule settled a pending request with a nonzero PID");
    IngestTestAccess::ReceivePacket(*ingest, session, known, 403, {});
    Check(sentVerdicts.size() == 1 && ingest->waiting() == 2,
          "cached automatic PID 0 rule answered a nonzero PID");
    Rule blockAny = MakeBlockRule(known);
    Check((blockAny.conds & CondPidZero) == 0, "nonzero automatic rule added a PID filter");
    rules.Add(blockAny);
    ingest->FlushVerdicts();
    Check(sentVerdicts.size() == 3 && ingest->waiting() == 0 &&
              sentVerdicts[1].second == pmkext::Verdict::Drop &&
              sentVerdicts[2].second == pmkext::Verdict::Drop,
          "automatic rule with any PID did not settle remaining requests");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
}

void TestIgmpPresetSettlesOnlyZero() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    AskRequest zero = Request(L"", ProtoFromNumber(2), 0, L"224.0.0.22");
    zero.pid = 0;
    zero.process.reset();
    AskRequest other = zero;
    other.pid = 4;
    IngestTestAccess::ReceivePacket(*ingest, session, zero, 411, {});
    IngestTestAccess::ReceivePacket(*ingest, session, other, 412, {});
    Check(sentVerdicts.empty() && ingest->waiting() == 2,
          "IGMP test did not create both pending requests");
    const auto presets = RulePresets::Suggest(zero);
    Check(presets.size() == 1 && RulePresets::ApplySelected(rules, zero, presets.front().rules) == 1,
          "could not apply the IGMP preset");
    ingest->FlushVerdicts();
    Check(sentVerdicts.size() == 1 && sentVerdicts.front() ==
              std::pair{uint64_t{411}, pmkext::Verdict::PermanentAccept} && ingest->waiting() == 1,
          "IGMP preset lost the PID 0 pending verdict restriction");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
}

void TestRuleBeforeAskPublication() {
    DriverVerdictSession session;
    captureSession = &session;
    for (RuleScope scope : { RuleScope::Global, RuleScope::App, RuleScope::PostApp })
    for (RuleAction action : { RuleAction::Allow, RuleAction::Block }) {
        sentVerdicts.clear();
        RuleStore rules;
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());
        const AskRequest request = Request(L"C:\\Apps\\before-ask.exe", Proto::Udp, 50001);
        IngestTestAccess::ReceivePacket(*ingest, session, request, 300, {});
        Check(sentVerdicts.empty() && ingest->waiting() == 1,
              "unmatched event was not parked before adding a rule");
        Rule rule;
        rule.scope = scope;
        if (scope == RuleScope::App) rule.appPath = request.appPath;
        rule.conds = CondNone;
        rule.action = action;
        rules.Add(rule);
        const auto expected = action == RuleAction::Allow
            ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop;
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.empty() && sentVerdicts.size() == 1 && ingest->waiting() == 0 &&
                  sentVerdicts.back() == std::pair{uint64_t{300}, expected},
              "question was published without rechecking the current rules");
        IngestTestAccess::ReceivePacket(*ingest, session, request, 301, {});
        Check(sentVerdicts.size() == 2 && sentVerdicts.back() == std::pair{uint64_t{301}, expected},
              "matched rule cache changed the decision for a new event");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
}

void TestTlsConnectionLabels() {
    // TLS ClientHello с единственным расширением SNI для example.com.
    std::vector<uint8_t> hello{22, 3, 1, 0, 67, 1, 0, 0, 63, 3, 3};
    hello.insert(hello.end(), 32, 0);
    hello.insert(hello.end(), {
        0, 0, 2, 0x13, 1, 1, 0, 0, 20, 0, 0, 0, 16, 0, 14, 0, 0, 11,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    });

    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    for (uint16_t remotePort : {uint16_t{443}, uint16_t{8443}})
    for (bool ipv6 : {false, true})
    for (bool split : {false, true})
    for (bool ask : {false, true}) {
        flows.Reset();
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        auto ingest = IngestTestAccess::Create();
        RuleStore rules;
        AskRequest request = Request(L"C:\\Apps\\tls.exe", Proto::Tcp, remotePort);
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        const auto addAllow = [&]() {
            Rule allow;
            allow.scope = RuleScope::Global;
            allow.conds = CondNone;
            allow.action = RuleAction::Allow;
            return rules.Add(allow);
        };
        if (!ask) addAllow();
        ingest->Attach(&rules, nullptr);
        ingest->BeginDriverSession(session.Begin());

        const auto packet = [&](uint32_t sequence, uint8_t flags,
                                std::span<const uint8_t> data) {
            const size_t ipBytes = ipv6 ? 40u : 20u;
            std::vector<uint8_t> bytes(ipBytes + 20 + data.size(), 0);
            const size_t length = ipv6 ? bytes.size() - ipBytes : bytes.size();
            bytes[0] = ipv6 ? 0x60 : 0x45;
            bytes[ipv6 ? 4 : 2] = static_cast<uint8_t>(length >> 8);
            bytes[ipv6 ? 5 : 3] = static_cast<uint8_t>(length);
            bytes[ipv6 ? 6 : 9] = 6;
            bytes[ipv6 ? 7 : 8] = 64;
            std::memcpy(bytes.data() + (ipv6 ? 8 : 12),
                        request.key.local.b, request.key.local.len());
            std::memcpy(bytes.data() + (ipv6 ? 24 : 16),
                        request.key.remote.b, request.key.remote.len());
            uint8_t* tcp = bytes.data() + ipBytes;
            tcp[0] = static_cast<uint8_t>(request.key.lport >> 8);
            tcp[1] = static_cast<uint8_t>(request.key.lport);
            tcp[2] = static_cast<uint8_t>(remotePort >> 8);
            tcp[3] = static_cast<uint8_t>(remotePort);
            tcp[4] = static_cast<uint8_t>(sequence >> 24);
            tcp[5] = static_cast<uint8_t>(sequence >> 16);
            tcp[6] = static_cast<uint8_t>(sequence >> 8);
            tcp[7] = static_cast<uint8_t>(sequence);
            tcp[12] = 0x50;
            tcp[13] = flags;
            std::copy(data.begin(), data.end(), bytes.begin() + ipBytes + 20);
            return bytes;
        };
        const auto label = [&]() {
            FlowStore::DisplayView view;
            flows.TakeDisplay(view);
            for (const auto& process : view.processes) {
                if (process.group != TrafficGroupKey::Host(request.pid)) continue;
                for (const auto& connection : process.connections)
                    if (connection.key == request.key && connection.tlsDomainLabel)
                        return *connection.tlsDomainLabel;
            }
            return std::wstring();
        };
        uint64_t id = 100;
        const auto receive = [&](const std::vector<uint8_t>& bytes,
                                 pmkext::Verdict expected) {
            const size_t before = sentVerdicts.size();
            const auto handle = [&](auto entry) {
                entry.external_connection_id = id;
                entry.process_id = request.pid;
                entry.protocol = ProtoNumber(request.key.proto);
                entry.direction = request.dir == Dir::In ? 1 : 0;
                entry.payload_layer = 3;
                entry.local_port = request.key.lport;
                entry.remote_port = request.key.rport;
                std::memcpy(entry.local_ip, request.key.local.b, sizeof(entry.local_ip));
                std::memcpy(entry.remote_ip, request.key.remote.b, sizeof(entry.remote_ip));
                if constexpr (std::is_same_v<decltype(entry), pmkext::ConnectionFixedV4>)
                    ingest->HandleV4(entry, bytes.data(), bytes.size());
                else
                    ingest->HandleV6(entry, bytes.data(), bytes.size());
            };
            if (ipv6) handle(pmkext::ConnectionFixedV6{});
            else handle(pmkext::ConnectionFixedV4{});
            if (ask) {
                std::vector<AskRequest> pending;
                ingest->TakePending(pending);
                Check(pending.size() == 1 && sentVerdicts.size() == before,
                      "TLS packet was not parked for an explicit answer");
                const uint64_t ruleId = addAllow();
                ingest->FlushVerdicts();
                Check(rules.Remove(ruleId), "pending TLS rule cleanup failed");
            }
            const bool correct = sentVerdicts.size() == before + 1 &&
                sentVerdicts.back() == std::pair{id, expected};
            if (!correct) {
                std::cerr << "TLS verdict mismatch: port=" << remotePort
                          << " ipv6=" << ipv6 << " split=" << split
                          << " ask=" << ask << " id=" << id
                          << " expected=" << static_cast<int>(expected)
                          << " actual=" << (sentVerdicts.empty() ? -1 :
                              static_cast<int>(sentVerdicts.back().second)) << '\n';
            }
            Check(correct, "TLS packet received an unexpected verdict");
            ++id;
        };
        receive(packet(999, 0x02, {}), pmkext::Verdict::Accept);
        receive(packet(1000, 0x10, {}), pmkext::Verdict::Accept);
        if (split) {
            constexpr size_t firstBytes = 37;
            receive(packet(1000, 0x18, {hello.data(), firstBytes}),
                    pmkext::Verdict::Accept);
            Check(label().empty(), "incomplete ClientHello published a domain");
            receive(packet(1000 + firstBytes, 0x18,
                           {hello.data() + firstBytes, hello.size() - firstBytes}),
                    pmkext::Verdict::PermanentAccept);
        } else {
            receive(packet(1000, 0x18, hello), pmkext::Verdict::PermanentAccept);
        }
        Check(label() == L"[example.com]", "outgoing TLS connection lost its SNI domain");
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
              "TLS display violated driver obligation counters");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
    }
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestDnsConnectionLabels() {
    for (uint16_t remotePort : {uint16_t{53}, uint16_t{5353}, uint16_t{5355}}) {
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        auto ingest = IngestTestAccess::Create();
        RuleStore store;
        ingest->Attach(&store, nullptr);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\dns.exe", Proto::Udp, remotePort, L"8.8.8.8");
        const std::vector<uint8_t> packet{
            0x45, 0, 0, 56, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8,
            0xa0, 0x28, static_cast<uint8_t>(remotePort >> 8),
            static_cast<uint8_t>(remotePort), 0, 36, 0, 0,
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1
        };
        FlowStore& flows = FlowStore::Instance();
        const bool wasEnabled = flows.enabled();
        flows.Enable(true);
        flows.Reset();
        const auto displayedLabel = [&]() {
            FlowStore::DisplayView view;
            flows.TakeDisplay(view);
            for (const auto& process : view.processes) {
                if (process.group != TrafficGroupKey::Host(request.pid)) continue;
                for (const auto& connection : process.connections)
                    if (connection.key == request.key && connection.tlsDomainLabel)
                        return *connection.tlsDomainLabel;
            }
            return std::wstring();
        };

        IngestTestAccess::ReceivePacket(*ingest, session, request, 900, packet);
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1 && sentVerdicts.empty(), "DNS query did not remain pending");
        Check(displayedLabel() == L"[google.com]", "pending DNS query lost the shared domain display");
        Check(IngestTestAccess::HasDnsLabelOnly(*ingest, pending.front().id, L"[google.com]"),
              "pending DNS query retained a packet instead of its parsed domain");

        // Ответ сохраняет обязательство, но не восстанавливает удалённую строку
        // вместе с подписью домена: вердикт не является новым сетевым событием.
        flows.Reset();
        Check(ingest->AnswerOnce(pending.front().id, RuleAction::Allow), "late DNS allow failed");
        Check(displayedLabel().empty(), "late DNS allow restored a removed connection");
        Check(sentVerdicts.size() == 1 && sentVerdicts.front().first == 900,
              "DNS display changed the driver obligation");
        Check(store.Count() == 0, "DNS display created a rule");

        uint64_t id = 901;
        for (FirewallPolicy policy : {FirewallPolicy::AllowAll, FirewallPolicy::BlockAll}) {
            ingest->SetPolicy(policy);
            flows.Reset();
            IngestTestAccess::ReceivePacket(*ingest, session, request, id++, packet);
            Check(displayedLabel() == L"[google.com]", "immediate DNS verdict lost its domain");
        }
        ingest->SetPolicy(FirewallPolicy::AllowAll);
        for (auto [layer, proto, dir, port] : {
            std::tuple{uint8_t{4}, Proto::Udp, Dir::Out, remotePort},
            std::tuple{uint8_t{3}, Proto::Tcp, Dir::Out, remotePort},
            std::tuple{uint8_t{3}, Proto::Udp, Dir::In, remotePort},
            std::tuple{uint8_t{3}, Proto::Udp, Dir::Out, uint16_t{5354}}
        }) {
            flows.Reset();
            request.key.proto = proto;
            request.key.rport = port;
            request.dir = dir;
            IngestTestAccess::ReceivePacket(*ingest, session, request, id++, packet, layer);
            Check(displayedLabel().empty(), "non-candidate connection received a DNS domain");
        }
        Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
              "DNS display violated driver obligation counters");
        ingest->EndDriverSession(session.End());
        captureSession = nullptr;
        flows.Reset();
        flows.Enable(wasEnabled);
    }
}

void TestPendingConnectionEndLifecycle() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    auto ingest = IngestTestAccess::Create();
    RuleStore rules;
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    flows.Reset();

    enum class ReplyAt { BeforeRemoval, AfterRemoval, AfterHistoryExpiry, AfterReuse };
    struct Case {
        AskRequest request;
        AskRequestId id;
        uint64_t wireId;
        uint64_t generation;
        ULONGLONG deadline;
        RuleAction action;
        ReplyAt replyAt;
        uint64_t nextGeneration = 0;
    };
    std::vector<Case> cases;
    const auto connection = [](const FlowStore::View& view, uint64_t generation)
        -> const FlowStore::ConnectionRecord* {
        for (const auto& process : view.processes) {
            const auto found = process.second.connections.find(generation);
            if (found != process.second.connections.end()) return &found->second;
        }
        return nullptr;
    };
    const auto take = [&]() {
        FlowStore::View view;
        flows.Take(view);
        return view;
    };
    const auto answer = [&](const Case& item) {
        Check(ingest->IsPending(item.id), "END removed the user's pending obligation");
        const size_t before = sentVerdicts.size();
        Check(ingest->AnswerOnce(item.id, item.action), "late pending answer failed");
        Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() ==
              std::pair{item.wireId, item.action == RuleAction::Allow
                  ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::PermanentDrop},
              "END changed or duplicated the user's verdict");
    };

    for (bool ipv6 : {false, true})
    for (Proto proto : {Proto::Tcp, Proto::Udp, ipv6 ? Proto::IcmpV6 : Proto::Icmp,
                        ProtoFromNumber(47)})
    for (Dir dir : {Dir::Out, Dir::In})
    for (RuleAction action : {RuleAction::Allow, RuleAction::Block})
    for (ReplyAt replyAt : {ReplyAt::BeforeRemoval, ReplyAt::AfterRemoval,
                           ReplyAt::AfterHistoryExpiry, ReplyAt::AfterReuse}) {
        AskRequest request = Request(L"C:\\Apps\\pending-end.exe", proto, 50001);
        request.dir = dir;
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::1");
            request.key.remote = Ip(L"2001:db8::2");
        }
        request.key.remote.b[request.key.remote.len() - 1] =
            static_cast<uint8_t>(cases.size() + 1);
        const uint64_t wireId = 1000 + cases.size();
        IngestTestAccess::ReceivePacket(*ingest, session, request, wireId, {});
        std::vector<AskRequest> pending;
        ingest->TakePending(pending);
        Check(pending.size() == 1, "connection did not create one pending question");
        const auto before = take();
        const auto& records = before.processes.at(request.pid).connections;
        const auto found = std::find_if(records.begin(), records.end(),
            [&](const auto& item) { return item.second.key == request.key; });
        Check(found != records.end(), "pending connection was not displayed");
        const uint64_t generation = found->first;
        const auto end = [&](auto& entry) {
            entry.process_id = request.pid;
            entry.protocol = ProtoNumber(proto);
            entry.direction = dir == Dir::In ? 1 : 0;
            std::memcpy(entry.local_ip, request.key.local.b, sizeof(entry.local_ip));
            std::memcpy(entry.remote_ip, request.key.remote.b, sizeof(entry.remote_ip));
            entry.local_port = request.key.lport;
            entry.remote_port = request.key.rport;
        };
        const size_t verdictsBeforeEnd = sentVerdicts.size();
        const ULONGLONG beforeEnd = GetTickCount64();
        if (ipv6) {
            pmkext::ConnectionEndV6 entry{};
            end(entry);
            on_connection_end_v6(&entry);
        } else {
            pmkext::ConnectionEndV4 entry{};
            end(entry);
            on_connection_end_v4(&entry);
        }
        const ULONGLONG afterEnd = GetTickCount64();
        Check(sentVerdicts.size() == verdictsBeforeEnd && ingest->IsPending(pending.front().id),
              "END automatically answered a pending obligation");
        const auto ended = take();
        const auto* record = connection(ended, generation);
        Check(record && record->endReceived &&
              record->removeAfter >= beforeEnd + kFinishedGraceMs &&
              record->removeAfter <= afterEnd + kFinishedGraceMs,
              "END did not schedule removal after the full grace period");
        Case item{request, pending.front().id, wireId, generation,
                  record->removeAfter, action, replyAt};
        if (replyAt == ReplyAt::BeforeRemoval) {
            answer(item);
            const auto replied = take();
            record = connection(replied, generation);
            Check(record && record->endReceived && record->removeAfter == item.deadline &&
                  replied.processes.at(request.pid).connections.size() == records.size(),
                  "late verdict recreated an ended connection or changed its deadline");
        } else if (replyAt == ReplyAt::AfterReuse) {
            // Новое поколение той же формы объединяется с прежним вопросом.
            // Его отображаемое состояние должно принадлежать новому callback.
            IngestTestAccess::ReceivePacket(*ingest, session, request, wireId + 1000, {});
            ingest->TakePending(pending);
            Check(pending.empty(), "tuple reuse unexpectedly created another pending group");
            const auto reused = take();
            for (const auto& entry : reused.processes.at(request.pid).connections)
                if (entry.second.key == request.key && entry.first != generation)
                    item.nextGeneration = entry.first;
            Check(item.nextGeneration != 0, "tuple reuse did not create a fresh generation");
        }
        cases.push_back(std::move(item));
    }

    // Таблицы ОС могут ещё показывать сокеты после END; это не отменяет срок.
    FlowStore::SystemSnapshot snapshot;
    snapshot.tcpV4Valid = snapshot.tcpV6Valid = true;
    snapshot.udpV4Valid = snapshot.udpV6Valid = true;
    for (const Case& item : cases) {
        const bool ipv6 = item.request.key.local.family == AF_INET6;
        if (item.request.key.proto == Proto::Tcp) {
            FlowStore::SystemTcpConnection row;
            row.key = item.request.key;
            row.pid = item.request.pid;
            row.state = item.request.dir == Dir::In
                ? MIB_TCP_STATE_SYN_RCVD : MIB_TCP_STATE_SYN_SENT;
            (ipv6 ? snapshot.tcpV6 : snapshot.tcpV4).push_back(row);
        } else if (item.request.key.proto == Proto::Udp) {
            auto& endpoints = ipv6 ? snapshot.udpV6 : snapshot.udpV4;
            if (endpoints.empty())
                endpoints.push_back({item.request.key.local, item.request.key.lport,
                                     item.request.pid});
        }
    }
    flows.ReplaceSystemSnapshot(snapshot);
    const auto retained = take();
    for (const Case& item : cases) {
        const auto* record = connection(retained, item.generation);
        Check(record && record->endReceived && record->removeAfter == item.deadline,
              "system snapshot changed the END grace period");
    }
    // Сдвигаем только сроки завершённых строк; проверяем обычную уборку TakeDisplay.
    Check(StorageTestAccess::MarkEndedConnectionsDue(flows) == cases.size(),
          "could not expire every ended generation");
    flows.ReplaceSystemSnapshot(snapshot);
    FlowStore::DisplayView display;
    flows.TakeDisplay(display);
    const auto removed = take();
    for (const Case& item : cases) {
        Check(!connection(removed, item.generation), "pending connection survived END grace period");
        if (item.replyAt == ReplyAt::BeforeRemoval ||
            item.replyAt == ReplyAt::AfterHistoryExpiry) continue;
        answer(item);
        const auto replied = take();
        Check(!connection(replied, item.generation), "late verdict restored the ended generation");
        for (const auto& process : replied.processes)
        for (const auto& entry : process.second.connections) {
            if (!(entry.second.key == item.request.key)) continue;
            Check(item.nextGeneration && entry.first == item.nextGeneration &&
                  !entry.second.endReceived && !entry.second.blockedAt && !entry.second.removeAfter,
                  "late verdict recreated an ended tuple or changed its replacement");
        }
        if (item.replyAt == ReplyAt::AfterReuse) {
            std::vector<AskRequest> remaining;
            ingest->TakePending(remaining);
            Check(remaining.size() == 1 && remaining.front().key == item.request.key &&
                  ingest->AnswerOnce(remaining.front().id, RuleAction::Allow) &&
                  sentVerdicts.back() == std::pair{item.wireId + 1000,
                                                  pmkext::Verdict::PermanentAccept},
                  "reused tuple lost its own pending obligation or verdict");
            const auto allowed = take();
            const auto* current = connection(allowed, item.nextGeneration);
            Check(current && !current->endReceived && !current->blockedAt && !current->removeAfter,
                  "new callback did not retain its own live connection generation");
        }
    }

    // Ускоряем только срок истории владельцев: обязательства остаются в Ingest.
    snapshot.tcpV4.clear();
    snapshot.tcpV6.clear();
    snapshot.udpV4.clear();
    snapshot.udpV6.clear();
    flows.ReplaceSystemSnapshot(snapshot);
    ::Sleep(20);
    FlowStore::View expired;
    flows.Take(expired, 0);
    for (const Case& item : cases) {
        if (item.replyAt != ReplyAt::AfterHistoryExpiry) continue;
        answer(item);
        const auto replied = take();
        for (const auto& process : replied.processes)
        for (const auto& entry : process.second.connections)
            Check(!(entry.second.key == item.request.key),
                  "late verdict restored an ended tuple after owner history expired");
    }
    Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered() && rules.Count() == 0,
          "END lifecycle violated the pending verdict contract");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

void TestOneRequestOnly() {
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    auto ingest = IngestTestAccess::Create();
    RuleStore store;
    ingest->Attach(&store, nullptr);
    ingest->BeginDriverSession(session.Begin());
    AskRequest request = Request(L"C:\\Apps\\chrome.exe");
    const AskRequestId original = IngestTestAccess::Park(*ingest, session, request, {100, 101, 102});
    request.key.lport = 41001;
    const AskRequestId unrelated = IngestTestAccess::Park(*ingest, session, request, {200});
    IngestTestAccess::ReservePending(*ingest);
    Check(ingest->AnswerOnce(original, RuleAction::Allow), "once answer failed");
    Check(IngestTestAccess::PendingBucketsFit(*ingest, 8),
          "one-shot answer retained peak pending buckets");
    Check(sentVerdicts == std::vector{std::pair{uint64_t{100}, pmkext::Verdict::PermanentAccept}},
          "once allow sent a temporary verdict or answered more than one callback");
    Check(!ingest->IsPending(original) && ingest->IsPending(unrelated), "once answer settled another group");
    Check(ingest->calls() == 4 && ingest->answered() == 1 && ingest->waiting() == 3,
          "once answer violated the obligation counters");
    Check(!ingest->AnswerOnce(original, RuleAction::Block), "old UI id answered the next packet");
    Check(store.Count() == 0 && IngestTestAccess::NoDecisionState(*ingest),
          "once answer created a rule, shape cache or SNI override");

    std::vector<AskRequest> pending;
    ingest->TakePending(pending);
    Check(pending.size() == 1 && pending.front().id != original,
          "remaining identical callbacks were not republished with a new identity");
    const AskRequestId second = pending.front().id;
    Check(ingest->AnswerOnce(second, RuleAction::Block), "once block failed");
    Check(sentVerdicts.size() == 2 && sentVerdicts.back() ==
          std::pair{uint64_t{101}, pmkext::Verdict::PermanentDrop}, "once block was not PermanentDrop");
    ingest->TakePending(pending);
    Check(pending.size() == 1 && pending.front().id != second, "last callback lost its UI identity");
    Check(ingest->AnswerOnce(pending.front().id, RuleAction::Allow) &&
          ingest->AnswerOnce(unrelated, RuleAction::Block), "remaining callbacks were lost");
    Check(sentVerdicts.size() == 4 && ingest->waiting() == 0 && ingest->answered() == ingest->calls(),
          "not every callback received exactly one verdict");
    Check(IngestTestAccess::NoDecisionState(*ingest) && store.Count() == 0,
          "one-shot decisions became persistent application rules");

    request.key.proto = Proto::Udp;
    request.key.rport = 443;
    const AskRequestId quic = IngestTestAccess::Park(*ingest, session, request, {300});
    Check(ingest->AnswerOnce(quic, RuleAction::Allow) &&
          sentVerdicts.back().second == pmkext::Verdict::PermanentAccept &&
          IngestTestAccess::NoDecisionState(*ingest), "QUIC changed the explicit permanent verdict");

    const AskRequestId old = IngestTestAccess::Park(*ingest, session, request, {400});
    ingest->EndDriverSession(session.End());
    ingest->BeginDriverSession(session.Begin());
    const AskRequestId fresh = IngestTestAccess::Park(*ingest, session, request, {400});
    const size_t before = sentVerdicts.size();
    Check(!ingest->AnswerOnce(old, RuleAction::Block) && ingest->IsPending(fresh) &&
          sentVerdicts.size() == before, "old driver session answered a reused wire id");
    Check(ingest->AnswerOnce(fresh, RuleAction::Block), "fresh session lost its callback");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
}

} // анонимное пространство имён

// Снимок тестов пуст для диалога выбора службы: подписи состояний не нужны.
std::wstring ServiceEntry::StateTextRu() const { return {}; }

// Управляемый SCM-снимок не зависит от служб тестовой машины и не меняет их.
namespace ServiceInfo {
HostedServices ServicesOfPid(DWORD pid, bool) {
    ++serviceReads;
    const auto it = hostedByPid.find(pid);
    static const auto empty = std::make_shared<const std::vector<ServiceEntry>>();
    return it == hostedByPid.end() ? empty : it->second;
}
bool SameName(const std::wstring& a, const std::wstring& b) { return EqualNoCase(a, b); }
std::vector<ServiceEntry> All(bool) { return {}; }
std::wstring DisplayName(const std::wstring& name) { return name; }
bool Installed(const std::wstring&) { return true; }
void SetMonitoring(bool) {}
void SetNotification(HWND, UINT) {}
void Shutdown() {}
uint64_t Version(bool) { return 1; }
uint64_t RequestRefresh() {
    const uint64_t ticket = ++serviceRefreshRequested;
    if (!deferServiceRefresh) serviceRefreshCompleted = ticket;
    return ticket;
}
bool RefreshComplete(uint64_t ticket) { return serviceRefreshCompleted >= ticket; }
void Invalidate() {}
} // namespace ServiceInfo

#include "firewallxndisfilter_ingest_tests.h"
#include "ingest_inheritance_tests.h"
#include "interface_filter_ingest_tests.h"
#include "app_interface_ingest_tests.h"
#include "interface_binding_editor_tests.h"
#include "ingest_optimization_tests.h"
#include "tls_8443_replay_tests.h"
#include "wfp_flags_ingest_tests.h"

int main(int argc, char** argv) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    try {
        std::wstring settingsError;
        Check(Settings::Open(L":memory:", settingsError), "cannot open isolated test settings");
        SetUiLang(UiLang::English);
        if (argc == 2 && std::string(argv[1]) == "--preview-rule-dialogs") {
            PreviewRuleEditors();
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--rule-layout-only") {
            TestRuleEditorLayout();
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--inheritance-editor-only") {
            TestInheritanceEditorFlags();
            std::cout << "Inheritance editor tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--rule-pid-only") {
            TestRuleEditorPidFilter();
            std::cout << "Rule PID editor tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--interface-binding-only") {
            INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS};
            Check(InitCommonControlsEx(&controls) != FALSE, "interface binding controls initialization failed");
            TestInterfaceBindingEditor();
            std::cout << "Interface binding editor tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--preferred-interface-only") {
            INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS};
            Check(InitCommonControlsEx(&controls) != FALSE, "preferred-interface controls initialization failed");
            TestPreferredInterfaceIngest();
            TestBlockOtherInterfacesIngest();
            TestBlockOtherInterfacesWireEvents();
            TestBlockOtherInterfacesRace();
            TestBlockOtherInterfacesPending();
            TestPreferredInterfaceCacheIsolation();
            TestPreferredInterfaceEditor();
            std::cout << "Preferred interface tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--payload-only") {
            TestRuleEditorPayload();
            std::cout << "Rule payload tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--tls-labels-only") {
            TestTlsConnectionLabels();
            TestTls8443PacketSequence();
            std::cout << "TLS connection label tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--dns-labels-only") {
            TestDnsConnectionLabels();
            std::cout << "DNS connection label tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--ndis-service-policy-only") {
            TestNdisServicePolicyReload();
            std::cout << "Ndis service policy tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--ingest-optimizations-only") {
            TestIngestOptimizations();
            std::cout << "Ingest optimization tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--captured-presets-only") {
            TestNewResources();
            TestCombinedPresetPorts();
            TestFeedbackOfficeAndWebViewPresets();
            TestITunesPreset();
            TestTaskHostHttpPreset();
            TestIgmpPreset();
            TestIgmpInboundPreset();
            TestEdgeMdnsPreset();
            TestCopilotAppPreset();
            TestDiscordAndObsPresets();
            TestOneDriveAndYandexDiskPresets();
            TestRemoteAccessPresets();
            TestCapturedConnectionPresets();
            TestDnscacheMdnsPreset();
            TestCapturedServicePresets();
            TestGeolocationPreset();
            TestDhcpClientPortsPreset(L"Dhcp");
            TestDhcpClientPortsPreset(L"SharedAccess");
            TestGitHttpsLoopbackPreset();
            TestExactTcpLoopbackPresets();
            TestSystemLoopbackPresets();
            TestNetbiosBlockPresets();
            TestSppExtComObjPreset();
            std::cout << "Captured connection preset tests passed\n";
            WSACleanup();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--new-presets-only") {
            SetUiLang(UiLang::English);
            TestNvidiaPresets();
            TestLsassServiceGroupPreset();
            TestSystemLoopbackPresets();
            std::cout << "NVIDIA, LSASS and System preset tests passed\n";
            WSACleanup();
            return 0;
        }
        // CTest запускает самые долгие проверки окон отдельными процессами.
        const bool separateEditors = argc == 2 && std::string(argv[1]) == "--ctest-main";
        TestWfpFlagShapeCache();
        TestWfpFlagTemplatePrefill();
        TestWfpFlagPendingGroups();
        TestWfpFlagWireEvents();
        TestWfpFlagsNeverMatchNdis();
        TestWfpFlagPicker();
        TestNewResources();
        if (!separateEditors) {
            TestRuleEditorLayout();
            TestInheritanceEditorFlags();
        }
        TestInheritanceShapeCacheAndPending();
        TestInheritanceLatePending();
        TestInheritanceChangingPresetSource();
        TestInheritancePendingPidReuse();
        TestNdisIntegration();
        TestAutomaticRuleScopes();
        TestPostAppPidCache();
        TestInterfaceFilterShapeCache();
        TestPreferredInterfaceIngest();
        TestBlockOtherInterfacesIngest();
        TestBlockOtherInterfacesWireEvents();
        TestBlockOtherInterfacesRace();
        TestBlockOtherInterfacesPending();
        TestPreferredInterfaceCacheIsolation();
        TestInterfaceFilterPrefill();
        TestInterfaceFilterPresetDedup();
        TestAutomaticPidRuleSettlesOnlyZero();
        TestIgmpPresetSettlesOnlyZero();
        TestAutomaticRuleNames();
        TestAddressListRuleNames();
        TestApplicationSuggestions();
        TestCombinedPresetPorts();
        TestFeedbackOfficeAndWebViewPresets();
        TestITunesPreset();
        TestTaskHostHttpPreset();
        TestVisualStudioPresets();
        TestIgmpPreset();
        TestIgmpInboundPreset();
        TestStoreAppPresets(L"C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe\\WindowsPackageManagerServer.exe",
                            IDS_PRESET_WINDOWS_PACKAGE_MANAGER, 38140);
        TestStoreAppPresets(L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsStore_22608.1401.6.0_x64__8wekyb3d8bbwe\\WinStore.App.exe",
                            IDS_PRESET_MICROSOFT_STORE, 38132);
        TestTorrentPresets();
        TestAdditionalApplicationPresets();
        TestEdgeMdnsPreset();
        TestCopilotAppPreset();
        TestDiscordAndObsPresets();
        TestOneDriveAndYandexDiskPresets();
        TestRemoteAccessPresets();
        TestCapturedConnectionPresets();
        TestDnscacheMdnsPreset();
        TestCapturedServicePresets();
        TestGeolocationPreset();
        TestNvidiaPresets();
        TestLsassServiceGroupPreset();
        TestBraveMdnsPresets();
        TestBraveUpdatePresets();
        TestSteamWebHelperDiscoveryPresets();
        TestSteamErrorReporterPresets();
        TestSteamLoopbackPresets();
        TestBitsLoopbackPresets();
        TestFirefoxLoopbackPresets();
        TestDnscacheDohPresets();
        TestIncomingDhcpPresets();
        TestDhcpClientPortsPreset(L"Dhcp");
        TestDhcpClientPortsPreset(L"SharedAccess");
        TestStoreServicePresets(L"InstallService", IDS_PRESET_INSTALL_SERVICE,
                                L"150.171.109.198", L"192.168.0.116", 50171);
        TestStoreServicePresets(L"AppXSvc", IDS_PRESET_APPX_DEPLOYMENT,
                                L"20.25.227.174", L"10.221.84.6", 38106);
        TestUserPushServicePreset();
        TestLanguagePackPresets();
        TestDiscoveryDeliveryPresets();
        TestGitHttpsLoopbackPreset();
        TestExactTcpLoopbackPresets();
        TestSystemLoopbackPresets();
        TestNetbiosBlockPresets();
        TestSppExtComObjPreset();
        TestServiceSuggestions();
        TestDuplicatesAndPersistence();
        TestServicePolicies();
        TestServicePolicyReload();
        TestServiceRefreshBeforeAsk();
        TestRuleBeforeAskPublication();
        TestPolicyChangeKeepsDriverCache();
        AskQueueTestAccess::TestStorage();
        IngestTestAccess::TestHashStorage();
        TestExpiryQueues();
        TestQuicSniStateExpiry();
        TestPendingPayload();
        TestTlsConnectionLabels();
        TestTls8443PacketSequence();
        TestDnsConnectionLabels();
        TestIngestOptimizations();
        TestPendingConnectionEndLifecycle();
        TestOneRequestOnly();
        TestAskIconLifetime();
        TestAskWindowRtl();
        TestAskWindowHeader();
        TestAskWindowActions();
        TestModalVisibility();
        TestNestedModalVisibility();
        TestAskWindowRecovery();
        TestAskToModalVisibility();
        TestRuleEditorPayload();
        if (!separateEditors) TestRuleEditorPidFilter();
        TestInterfaceFilterEditor();
        TestInterfacePickerHint();
        TestInterfacePickerRefresh();
        TestPreferredInterfaceEditor();
        TestInterfaceBindingEditor();
        std::cout << "Ask actions and presets tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        WSACleanup();
        return 1;
    }
    WSACleanup();
    return 0;
}
