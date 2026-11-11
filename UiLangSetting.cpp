// Запоминание выбранного языка интерфейса в settings.db.
//
// Отдельная единица трансляции: сам StringRes от Settings не зависит и
// работает там, где базы нет вовсе, — связку языка с хранилищем держим здесь.
//
// Хранится код языка Windows (0x0419, 0x0409), а не индекс в массиве языков:
// индекс поехал бы при добавлении нового языка, и запись молча стала бы
// указывать на другой. При ошибке чтения выбирается язык по умолчанию;
// ошибка записи не меняет текущий язык, но выбор не сохранится для нового запуска.
#include "StringRes.h"
#include "Settings.h"

namespace UiLangSetting {

UiLang Load() {
    const int stored = Settings::GetInt(Settings::Key::kUiLang, 0);
    if (stored == 0) return DefaultUiLang();      // записи ещё нет

    size_t count = 0;
    const UiLangInfo* langs = UiLangs(count);
    for (size_t i = 0; i < count; ++i)
        if (langs[i].winLangId == stored) return langs[i].lang;

    // Код в базе нам неизвестен: язык убрали из сборки либо файл правили
    // руками. Возвращаемся к языку по умолчанию, запись не трогаем — вдруг
    // сборка с этим языком ещё вернётся.
    return DefaultUiLang();
}

void Save(UiLang lang) {
    size_t count = 0;
    const UiLangInfo* langs = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        if (langs[i].lang != lang) continue;
        Settings::SetInt(Settings::Key::kUiLang, langs[i].winLangId);
        return;
    }
}

} // namespace UiLangSetting
