#pragma once
#include "resource.h"
#include "StringRes.h"
#include <array>
#include <string>
#include <string_view>

// Превращение узких макросов из resource.h в широкие литералы:
// версия и авторство задаются ровно в одном месте и одинаковы
// в ресурсах и в коде.
#define FIREWALLX_WIDEN2(x) L ## x
#define FIREWALLX_WIDEN(x)  FIREWALLX_WIDEN2(x)

namespace AppInfo {

// ---------------------------------------------------------------------------
// Два имени, и путать их нельзя.
//
// kAppName — ВИДИМОЕ название: заголовок окна, подсказка значка, окно
// «О программе». Его читает пользователь.
//
// kProductName — ТЕХНИЧЕСКОЕ имя: исполняемый файл, служба, класс окна,
// мьютекс единственности, ресурс версии. По нему программа опознаётся
// системой, поэтому оно короткое, без пробелов и не переводится.
//
// Прежде здесь было четыре имени сразу («Not Outpost Firewall», netmon,
// firewall, FirewallX), и какое из них где применяется, приходилось выяснять
// по месту. Теперь их ровно два, и роль каждого задана здесь.
// ---------------------------------------------------------------------------
inline constexpr wchar_t kAppName[]     = L"Interactive Firewall";
inline constexpr wchar_t kProductName[] = FIREWALLX_WIDEN(FIREWALLX_PRODUCT);

inline constexpr wchar_t kVersion[] = FIREWALLX_WIDEN(FIREWALLX_VERSION_STR);

// ---- авторство ----
inline constexpr wchar_t kAuthor[]          = FIREWALLX_WIDEN(FIREWALLX_AUTHOR);
inline constexpr wchar_t kRepositoryUrl[]   = FIREWALLX_WIDEN(FIREWALLX_REPOSITORY_URL);
inline constexpr wchar_t kCopyrightPrefix[] = FIREWALLX_WIDEN(FIREWALLX_COPYRIGHT_PREFIX);

// Адрес восстанавливается при первом обращении и остаётся доступен до выхода.
inline const wchar_t* AuthorUrl() noexcept {
    // Чтение через volatile не позволяет компилятору раскрыть адрес заранее.
    static const volatile unsigned char encrypted[] = FIREWALLX_AUTHOR_URL;
    static const auto decoded = []() noexcept {
        std::array<wchar_t, sizeof(encrypted) + 1> result{};
        for (size_t i = 0; i < sizeof(encrypted); ++i)
            result[i] = static_cast<wchar_t>(encrypted[i] ^ 0xA7);
        return result;
    }();
    return decoded.data();
}

// ---------------------------------------------------------------------------
// ЕДИНСТВЕННЫЙ файл данных программы, лежит рядом с исполняемым файлом.
//
// В нём и правила (таблица «rules», см. RuleDb), и все настройки программы
// (таблица «settings», см. Settings). Собственные настройки хранятся в базе,
// чтобы переезжать вместе с программой. Параметры драйвера при их применении
// записываются отдельно в системный реестр.
//
// Таблицы независимы: RuleDb пересоздаёт только свою таблицу и PRAGMA
// user_version, поэтому смена версии схемы правил настройки не затрагивает.
// ---------------------------------------------------------------------------
inline constexpr wchar_t kSettingsDb[] = L"settings.db";

// Прежнее имя той же константы. Отдельной базы правил больше нет; имя
// оставлено, чтобы точки вызова не разошлись с этим определением.
inline constexpr const wchar_t* kRulesDb = kSettingsDb;

// ---- окно и единственность копии ----
//
// Все имена ниже начинаются с kProductName и склеиваются здесь же: они должны
// меняться вместе с ним, а не по отдельности. Литералы в этих строках прежде
// повторяли «FirewallX» пять раз, и переименование продукта означало пять
// независимых правок, каждую из которых можно было забыть.
//
// Класс главного окна: по нему запущенная копия отыскивается из новой.
inline constexpr wchar_t kMainWindowClass[] =
    FIREWALLX_WIDEN(FIREWALLX_PRODUCT "MainWnd");
// Мьютекс сеансовый (Local\): копии в разных сеансах не мешают друг другу,
// а служба этот объект не создаёт вообще.
inline constexpr wchar_t kInstanceMutex[]   =
    FIREWALLX_WIDEN("Local\\" FIREWALLX_PRODUCT ".SingleInstance.v1");
inline constexpr wchar_t kActivateMessage[] =
    FIREWALLX_WIDEN(FIREWALLX_PRODUCT ".ActivateInstance");

// ---- автозапуск оконной копии ----
// SID пользователя дописывается к имени задания: настройки разных
// пользователей не включают и не отключают автозапуск друг друга.
inline constexpr wchar_t kStartupTaskPrefix[] =
    FIREWALLX_WIDEN(FIREWALLX_PRODUCT ".StartWithWindows.");

// ---- служба ----
// Внутреннее имя в SCM не переводится: по нему служба ищется и после смены
// языка интерфейса, а видимое имя и описание берутся из ресурсов.
inline constexpr wchar_t kServiceName[]    =
    FIREWALLX_WIDEN(FIREWALLX_PRODUCT "Svc");
// Ключ командной строки, с которым служба регистрируется в SCM
inline constexpr wchar_t kServiceSwitch[]  = L"--service";
// Межпроцессные события переключения обработки записей на службу.
inline constexpr wchar_t kServiceLocalRequestEvent[] =
    FIREWALLX_WIDEN("Global\\" FIREWALLX_PRODUCT ".ServiceLocalRequest.v1");
inline constexpr wchar_t kServiceLocalReadyEvent[] =
    FIREWALLX_WIDEN("Global\\" FIREWALLX_PRODUCT ".ServiceLocalReady.v1");
// Служба устанавливает событие только после фактического переключения raw
// driver records на подключённый desktop-клиент.
inline constexpr wchar_t kServiceProxyReadyEvent[] =
    FIREWALLX_WIDEN("Global\\" FIREWALLX_PRODUCT ".ServiceProxyReady.v1");
// Отдельный канал синхронного GetThreadId: общая память, mutex и события.
inline constexpr wchar_t kServiceThreadIdChannel[] =
    FIREWALLX_WIDEN("Global\\" FIREWALLX_PRODUCT ".ServiceThreadId.v1");

inline std::wstring ServiceDisplay() { return LoadStringRes(IDS_SVC_DISPLAY_NAME); }
inline std::wstring ServiceDesc()    { return LoadStringRes(IDS_SVC_DESCRIPTION); }

inline std::wstring NameWithVersion() {
    return std::wstring(kAppName) + L" " + kVersion;
}

// Протоколом больше не ограничиваемся: правила и список охватывают любой
// номер протокола IP, поэтому перечисление «TCP / UDP / ICMP» в заголовке
// вводило бы в заблуждение.
inline std::wstring WindowTitle(bool driverUnavailable = false) {
    std::wstring title = kAppName;
    if (driverUnavailable) title += LoadStringRes(IDS_TITLE_DRIVER_NOT_LOADED);
    return title;
}

inline std::wstring AboutLink(const wchar_t* url, const wchar_t* label) {
    return std::wstring(L"<a href=\"") + url + L"\">" + label + L"</a>";
}

inline bool IsAboutLink(const wchar_t* url) noexcept {
    return url && (std::wstring_view(url) == AuthorUrl() ||
                   std::wstring_view(url) == kRepositoryUrl);
}

inline std::wstring AboutText(const std::wstring& runMode,
                              const std::wstring& skin,
                              const std::wstring& serviceState) {
    return NameWithVersion() + L"\n\n" +
           LoadStringRes(IDS_ABOUT_COPYRIGHT_PREFIX) +
           AboutLink(AuthorUrl(), LoadStringRes(IDS_AUTHOR).c_str()) + L"\n" +
           LoadStringRes(IDS_ABOUT_RUNMODE) + runMode + L"\n" +
           LoadStringRes(IDS_ABOUT_SKIN) + skin +
           LoadStringRes(IDS_ABOUT_SKIN_HINT) + serviceState + L"\n\n" +
           AboutLink(kRepositoryUrl, LoadStringRes(IDS_ABOUT_REPOSITORY).c_str());
}

} // namespace AppInfo