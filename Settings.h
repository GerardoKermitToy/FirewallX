#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// Настройки программы.
//
// Хранилище одно — settings.db рядом с программой (AppInfo::kSettingsDb),
// тот же файл, в котором лежат правила. Настройки переезжают вместе с базой;
// параметры драйвера дополнительно применяются в его разделе реестра перед запуском.
//
// Формат — таблица «settings» с парой «ключ — значение»; значения хранятся
// текстом, числа и признаки приводятся к тексту здесь же. Таблица правил
// живёт в том же файле независимо: RuleDb пересоздаёт только свою таблицу
// и PRAGMA user_version, поэтому смена версии схемы правил настройки
// не затрагивает.
//
// Открытие ЛЕНИВОЕ: первое же обращение открывает файл по пути по умолчанию.
// Поэтому порядок инициализации программы значения не имеет — настройки
// доступны раньше, чем подключается база правил (например, оформление списка
// читается в WM_CREATE, до RuleStore::AttachDatabase).
//
// Все функции потокобезопасны. Ошибка чтения либо записи не является
// аварийной: функции возвращают false либо значение по умолчанию. Ошибки
// открытия и подготовки запросов, а также записи доступны через lastError().
// ---------------------------------------------------------------------------
namespace Settings {

// Явное открытие: нужно только чтобы задать НЕ стандартный путь.
bool Open(const std::wstring& path, std::wstring& error);
void Close();
bool opened();

std::wstring path();
std::wstring lastError();

// false — ключа нет, аргумент недопустим либо чтение не удалось; out не меняется
bool         GetString(const wchar_t* key, std::wstring& out);
std::wstring GetString(const wchar_t* key, const wchar_t* def = L"");
int          GetInt(const wchar_t* key, int def);
bool         GetBool(const wchar_t* key, bool def);

bool SetString(const wchar_t* key, const std::wstring& value);
bool SetInt(const wchar_t* key, int value);
bool SetBool(const wchar_t* key, bool value);
bool Remove(const wchar_t* key);

// ---------------------------------------------------------------------------
// Ключи.
//
// Имя ключа — часть формата файла, поэтому литералы по коду не разбрасываются:
// новая настройка добавляется здесь и только здесь.
// ---------------------------------------------------------------------------
namespace Key {
inline constexpr wchar_t kListSkin[] = L"ui.list.skin";   // ListSkin как число
// Гарнитура и размер строк сохраняются независимо для каждого оформления.
inline constexpr wchar_t kListFontModern[] = L"ui.list.font.modern";
inline constexpr wchar_t kListFontClassic[] = L"ui.list.font.classic";
inline constexpr wchar_t kListColumnOrder[] = L"ui.list.column_order"; // Порядок колонок, общий для оформлений
inline constexpr wchar_t kListExpanded[] = L"ui.list.expanded"; // Группы развёрнуты по умолчанию
inline constexpr wchar_t kMuteMessageBeep[] = L"ui.sound.message_beep.muted"; // Звуковые сигналы отключены
inline constexpr wchar_t kSystemDpiScaling[] = L"ui.dpi.system_scaling"; // Масштабирование Windows при 96 DPI
inline constexpr wchar_t kDllInjectionProtection[] = L"security.dll_injection_protection"; // CIG и ACG при запуске
inline constexpr wchar_t kAutoCreatePresetRules[] = L"rules.auto_create_presets"; // Правила для подписанных приложений
// Язык интерфейса: код языка Windows (0x0419, 0x0409). Не индекс в массиве —
// он поехал бы при добавлении языка, и настройка молча указала бы на другой.
inline constexpr wchar_t kUiLang[]   = L"ui.language";
// Общая политика desktop и службы: числовое значение FirewallPolicy.
// Имя ключа сохранено для уже записанных настроек.
inline constexpr wchar_t kDesktopPolicy[] = L"firewall.desktop.policy";
// Дополнительная аттрибуция входящего UDP при промахе кеша драйвера.
inline constexpr wchar_t kPreciseTrafficAttribution[] = L"driver.traffic.precise_attribution";
// Суффикс — отображаемое имя сетевого интерфейса.
inline constexpr wchar_t kNdisExcludedInterfacePrefix[] = L"driver.ndis.excluded.";
inline constexpr wchar_t kNdisReverseTrafficPrefix[] = L"driver.ndis.reverse_traffic.";
}

} // namespace Settings