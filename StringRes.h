#ifndef FIREWALLX_STRINGRES_H
#define FIREWALLX_STRINGRES_H

#include <windows.h>
#include <string>

#include "resource.h"   /* идентификаторы IDS_* нужны всем, кто грузит строки */

// ---------------------------------------------------------------------------
// Язык интерфейса.
//
// Ресурсы содержат по одному STRINGTABLE на язык (см. firewall.rc). Выбранный
// язык хранится здесь и применяется ко всем последующим вызовам LoadStringRes,
// поэтому смена языка не требует перезапуска: достаточно задать его и заново
// собрать подписи (меню, кнопки, колонки).
//
// Значение по умолчанию берётся из языка интерфейса Windows: русский, если
// система русская, иначе английский.
// ---------------------------------------------------------------------------
enum class UiLang {
    Russian, English, Korean, Chinese, Ukrainian,
    German, French, Spanish, Arabic, Hindi,
    Latvian, Lithuanian, Estonian, Romanian, Swedish,
    Polish, Vietnamese, Portuguese, Italian, Persian,
    Japanese, Turkish, Indonesian, Czech, Thai,
    PortugueseBrazil, ChineseTraditional, Hungarian, Greek, Dutch,
    Bulgarian, Danish, NorwegianBokmal, Finnish
};

// Порядок в этом массиве задаёт порядок пунктов в меню
struct UiLangInfo {
    UiLang         lang;
    const wchar_t* nativeName;   // название на своём же языке, не переводится
    UINT           flagIconId;   // IDI_FLAG_* — ICON, не BITMAP
    WORD           winLangId;    // MAKELANGID для FindResourceEx
};

const UiLangInfo* UiLangs(size_t& count);

UiLang CurrentUiLang();
// true — язык действительно изменился (вызывающему есть смысл перерисовать)
bool   SetUiLang(UiLang lang);

// Язык по умолчанию для первого запуска: выводится из языка системы
UiLang DefaultUiLang();

// ---------------------------------------------------------------------------
// Запоминание выбора в settings.db.
//
// Вынесено в отдельные функции, а не спрятано внутрь SetUiLang: StringRes
// нужен и там, где базы нет (например, в проверочных утилитах), и тянуть за
// собой Settings ему незачем. Порядок вызова — как у ListSkinSetting: Load()
// при старте, Save() после смены.
// ---------------------------------------------------------------------------
namespace UiLangSetting {
UiLang Load();          // нет записи или значение чужое -> DefaultUiLang()
void   Save(UiLang lang);
}

// Ссылка на строку из потокового кеша. Действительна до смены языка в этом
// потоке; горячие циклы берут её один раз перед обходом строк.
const std::wstring& StringResRef(UINT id);

// Загрузка строки из ресурсов по идентификатору на текущем языке интерфейса.
//
// Если выбранный перевод отсутствует или пуст, ищется строка на других языках.
// Если её нет ни на одном, показывается MessageBox с номером идентификатора
// и возвращается пустая строка. Об одном и том же
// идентификаторе сообщается один раз за запуск.
std::wstring LoadStringRes(UINT id);

// То же плюс форматирование по правилам printf: строка из ресурса —
// формат, остальные аргументы подставляются в неё.
std::wstring LoadStringResFmt(UINT id, ...);

#endif // FIREWALLX_STRINGRES_H
