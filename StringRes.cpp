#include "StringRes.h"
#include <atomic>
#include <cstdarg>
#include <mutex>
#include <deque>
#include <unordered_set>
#include <vector>

namespace {

// Языки в порядке появления в меню
const UiLangInfo kLangs[] = {
    { UiLang::Russian, L"Русский", IDI_FLAG_RU,
      MAKELANGID(LANG_RUSSIAN, SUBLANG_RUSSIAN_RUSSIA) },
    { UiLang::English, L"English", IDI_FLAG_US,
      MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) },
    // Названия языков — на самих этих языках: пункт меню должен быть узнаваем
    // тому, кто ищет свой язык, не понимая текущего.
    { UiLang::Korean,  L"한국어", IDI_FLAG_KR,
      MAKELANGID(LANG_KOREAN, SUBLANG_KOREAN) },
    { UiLang::Chinese, L"简体中文", IDI_FLAG_ZH,
      MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED) },
    { UiLang::Ukrainian, L"Українська", IDI_FLAG_UK,
      MAKELANGID(LANG_UKRAINIAN, SUBLANG_UKRAINIAN_UKRAINE) },
    { UiLang::German, L"Deutsch", IDI_FLAG_DE,
      MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN) },
    { UiLang::French, L"Français", IDI_FLAG_FR,
      MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH) },
    { UiLang::Spanish, L"Español", IDI_FLAG_ES,
      MAKELANGID(LANG_SPANISH, SUBLANG_SPANISH_MODERN) },
    { UiLang::Arabic, L"العربية", IDI_FLAG_SA,
      MAKELANGID(LANG_ARABIC, SUBLANG_ARABIC_SAUDI_ARABIA) },
    { UiLang::Hindi, L"हिन्दी", IDI_FLAG_IN,
      MAKELANGID(LANG_HINDI, SUBLANG_HINDI_INDIA) },
    { UiLang::Latvian, L"Latviešu", IDI_FLAG_LV,
      MAKELANGID(LANG_LATVIAN, SUBLANG_LATVIAN_LATVIA) },
    { UiLang::Lithuanian, L"Lietuvių", IDI_FLAG_LT,
      MAKELANGID(LANG_LITHUANIAN, SUBLANG_LITHUANIAN) },
    { UiLang::Estonian, L"Eesti", IDI_FLAG_EE,
      MAKELANGID(LANG_ESTONIAN, SUBLANG_ESTONIAN_ESTONIA) },
    { UiLang::Romanian, L"Română", IDI_FLAG_RO,
      MAKELANGID(LANG_ROMANIAN, SUBLANG_ROMANIAN_ROMANIA) },
    { UiLang::Swedish, L"Svenska", IDI_FLAG_SE,
      MAKELANGID(LANG_SWEDISH, SUBLANG_SWEDISH) },
    { UiLang::Polish, L"Polski", IDI_FLAG_PL,
      MAKELANGID(LANG_POLISH, SUBLANG_POLISH_POLAND) },
    { UiLang::Vietnamese, L"Tiếng Việt", IDI_FLAG_VN,
      MAKELANGID(LANG_VIETNAMESE, SUBLANG_VIETNAMESE_VIETNAM) },
    { UiLang::Portuguese, L"Português (Portugal)", IDI_FLAG_PT,
      MAKELANGID(LANG_PORTUGUESE, SUBLANG_PORTUGUESE) },
    { UiLang::Italian, L"Italiano", IDI_FLAG_IT,
      MAKELANGID(LANG_ITALIAN, SUBLANG_ITALIAN) },
    { UiLang::Persian, L"فارسی", IDI_FLAG_IR,
      MAKELANGID(LANG_PERSIAN, SUBLANG_PERSIAN_IRAN) },
    { UiLang::Japanese, L"日本語", IDI_FLAG_JP,
      MAKELANGID(LANG_JAPANESE, SUBLANG_JAPANESE_JAPAN) },
    { UiLang::Turkish, L"Türkçe", IDI_FLAG_TR,
      MAKELANGID(LANG_TURKISH, SUBLANG_TURKISH_TURKEY) },
    { UiLang::Indonesian, L"Bahasa Indonesia", IDI_FLAG_ID,
      MAKELANGID(LANG_INDONESIAN, SUBLANG_INDONESIAN_INDONESIA) },
    { UiLang::Czech, L"Čeština", IDI_FLAG_CZ,
      MAKELANGID(LANG_CZECH, SUBLANG_CZECH_CZECH_REPUBLIC) },
    { UiLang::Thai, L"ไทย", IDI_FLAG_TH,
      MAKELANGID(LANG_THAI, SUBLANG_THAI_THAILAND) },
    { UiLang::PortugueseBrazil, L"Português (Brasil)", IDI_FLAG_BR,
      MAKELANGID(LANG_PORTUGUESE, SUBLANG_PORTUGUESE_BRAZILIAN) },
    { UiLang::ChineseTraditional, L"繁體中文", IDI_FLAG_TW,
      MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL) },
    { UiLang::Hungarian, L"Magyar", IDI_FLAG_HU,
      MAKELANGID(LANG_HUNGARIAN, SUBLANG_HUNGARIAN_HUNGARY) },
    { UiLang::Greek, L"Ελληνικά", IDI_FLAG_GR,
      MAKELANGID(LANG_GREEK, SUBLANG_GREEK_GREECE) },
    { UiLang::Dutch, L"Nederlands", IDI_FLAG_NL,
      MAKELANGID(LANG_DUTCH, SUBLANG_DUTCH) },
    { UiLang::Bulgarian, L"Български", IDI_FLAG_BG,
      MAKELANGID(LANG_BULGARIAN, SUBLANG_BULGARIAN_BULGARIA) },
    { UiLang::Danish, L"Dansk", IDI_FLAG_DK,
      MAKELANGID(LANG_DANISH, SUBLANG_DANISH_DENMARK) },
    { UiLang::NorwegianBokmal, L"Norsk bokmål", IDI_FLAG_NO,
      MAKELANGID(LANG_NORWEGIAN, SUBLANG_NORWEGIAN_BOKMAL) },
    { UiLang::Finnish, L"Suomi", IDI_FLAG_FI,
      MAKELANGID(LANG_FINNISH, SUBLANG_FINNISH_FINLAND) },
};

// Читается из любых потоков (строки грузятся и в фоне), меняется из одного —
// обработчика меню. Атомарного значения достаточно: рассинхронизация даёт лишь
// одну подпись на прежнем языке, а не порчу данных.
std::atomic<UiLang> g_lang{ UiLang::Russian };
std::atomic<bool>   g_langChosen{ false };


// Об одном и том же идентификаторе сообщаем однократно: строки грузятся из
// рабочих потоков и на каждой перерисовке списка, иначе окно всплывало бы
// без конца и работать с программой стало бы нельзя.
std::mutex g_reportMutex;
std::unordered_set<UINT> g_reported;

// Текст сообщения намеренно зашит в код: брать его из STRINGTABLE нельзя —
// именно она в этот момент и оказалась неисправной.
void ReportMissing(UINT id) {
    {
        std::lock_guard<std::mutex> lock(g_reportMutex);
        if (!g_reported.insert(id).second) return;
    }

    wchar_t msg[512];
    swprintf_s(msg,
               L"Строка с идентификатором %u отсутствует в STRINGTABLE или пуста.\n\n"
               L"Это ошибка сборки ресурсов: проверьте firewall.rc и resource.h.\n\n"
               L"В интерфейсе на месте этой строки будет пусто.",
               id);

    MessageBoxW(nullptr, msg, L"Ошибка строковых ресурсов",
                MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_SETFOREGROUND);
}

WORD WinLangOf(UiLang lang) {
    for (const UiLangInfo& i : kLangs)
        if (i.lang == lang) return i.winLangId;
    return kLangs[0].winLangId;
}

// Строка заданного языка из RT_STRING.
//
// LoadStringW не принимает явный язык, поэтому нужный блок ищется через
// FindResourceExW. Формат RT_STRING:
// строки лежат блоками по 16, номер блока = id/16 + 1, внутри блока каждая
// строка предваряется словом длины. Пустая строка от отсутствующей
// неотличима: у обеих длина 0, что для нас одно и то же.
bool LoadFromLang(UINT id, WORD winLang, std::wstring& out) {
    HMODULE mod = GetModuleHandleW(nullptr);
    HRSRC res = FindResourceExW(mod, RT_STRING,
                                reinterpret_cast<LPCWSTR>(
                                    static_cast<ULONG_PTR>(id / 16 + 1)),
                                winLang);
    if (!res) return false;

    HGLOBAL block = LoadResource(mod, res);
    if (!block) return false;

    const wchar_t* p = static_cast<const wchar_t*>(LockResource(block));
    if (!p) return false;

    const DWORD size = SizeofResource(mod, res);
    const wchar_t* end = p + size / sizeof(wchar_t);

    for (UINT i = 0, index = id % 16; i < index; ++i) {
        if (p >= end) return false;
        p += 1 + *p;                    // слово длины плюс сами символы
    }
    if (p >= end || *p == 0) return false;
    if (p + 1 + *p > end) return false; // повреждённый ресурс

    out.assign(p + 1, *p);
    return true;
}

// Ресурсы неизменяемы, а набор используемых идентификаторов у каждого потока
// мал. Потоковый кеш убирает FindResourceEx/LoadResource из секундной сборки
// тысяч строк и не требует общего мьютекса. Прямой индекс по UINT заменяет
// миллион хэш-поисков из профиля. Между запрошенными ID хранятся лишь нулевые
// указатели: deque создаёт строки по одной и сохраняет выданные ссылки при росте.
const std::wstring& CachedString(UINT id) {
    struct Cache {
        struct Entry {
            std::wstring text;
            bool loaded = false;
        };
        UiLang lang = UiLang::Russian;
        bool initialized = false;
        std::deque<Entry> strings;
        std::vector<Entry*> byId;
    };
    thread_local Cache cache;

    const UiLang lang = CurrentUiLang();
    if (!cache.initialized || cache.lang != lang) [[unlikely]] {
        cache.lang = lang;
        cache.initialized = true;
        for (auto& entry : cache.strings) entry.loaded = false;
    }

    const size_t index = static_cast<size_t>(id);
    if (index >= cache.byId.size()) [[unlikely]] cache.byId.resize(index + 1, nullptr);
    auto* entry = cache.byId[index];
    if (!entry) [[unlikely]] {
        cache.strings.emplace_back();
        entry = &cache.strings.back();
        cache.byId[index] = entry;
    }
    if (entry->loaded) [[likely]] return entry->text;

    std::wstring value;
    bool loaded = LoadFromLang(id, WinLangOf(lang), value);
    if (!loaded) [[unlikely]] {
        // Непереведённая строка лучше пустого места в интерфейсе.
        for (const UiLangInfo& candidate : kLangs) {
            if (candidate.lang == lang) continue;
            if (LoadFromLang(id, candidate.winLangId, value)) {
                loaded = true;
                break;
            }
        }
    }

    entry->text = std::move(value);
    entry->loaded = true;
    if (!loaded) [[unlikely]] ReportMissing(id);
    return entry->text;
}

} // namespace

const UiLangInfo* UiLangs(size_t& count) {
    count = sizeof(kLangs) / sizeof(kLangs[0]);
    return kLangs;
}

UiLang DefaultUiLang() {
    // Русский только для собственно русского интерфейса; для остальных
    // английский понятнее, чем незнакомая кириллица.
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_RUSSIAN
               ? UiLang::Russian : UiLang::English;
}

UiLang CurrentUiLang() {
    if (!g_langChosen.load(std::memory_order_acquire)) [[unlikely]] {
        // Никто не задал язык явно — берём системный. Запоминаем, чтобы
        // значение не менялось между вызовами.
        UiLang def = DefaultUiLang();
        bool expected = false;
        if (g_langChosen.compare_exchange_strong(expected, true,
                                                 std::memory_order_acq_rel)) {
            g_lang.store(def, std::memory_order_release);
            return def;
        }
    }
    return g_lang.load(std::memory_order_acquire);
}

bool SetUiLang(UiLang lang) {
    const UiLang prev = CurrentUiLang();      // заодно снимает «не задан»
    if (prev == lang) return false;
    g_lang.store(lang, std::memory_order_release);
    return true;
}

const std::wstring& StringResRef(UINT id) {
    return CachedString(id);
}

std::wstring LoadStringRes(UINT id) {
    return StringResRef(id);
}

std::wstring LoadStringResFmt(UINT id, ...) {
    // О пропущенном идентификаторе уже сообщил LoadStringRes
    const std::wstring& fmt = CachedString(id);
    if (fmt.empty()) [[unlikely]] return {};

    va_list args;
    va_start(args, id);
    const int size = _vscwprintf(fmt.c_str(), args);
    va_end(args);
    if (size < 0) [[unlikely]] return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    va_start(args, id);
    vswprintf_s(result.data(), result.size() + 1, fmt.c_str(), args);
    va_end(args);

    return result;
}
