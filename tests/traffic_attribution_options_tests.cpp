#include "Settings.h"
#include "TrafficAttributionOptions.h"
#include "TrafficAttributionOptionsDetail.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct MockRegistry {
    inline static MockRegistry* active = nullptr;
    LSTATUS createStatus = ERROR_SUCCESS;
    LSTATUS setStatus = ERROR_SUCCESS;
    unsigned creates = 0;
    unsigned writes = 0;
    unsigned closes = 0;
    std::vector<DWORD> values;

    MockRegistry() { active = this; }
    ~MockRegistry() { active = nullptr; }

    HKEY Handle() { return reinterpret_cast<HKEY>(this); }

    static LSTATUS WINAPI Create(HKEY root, LPCWSTR path, DWORD reserved, LPWSTR name,
                                 DWORD options, REGSAM access, LPSECURITY_ATTRIBUTES security,
                                 PHKEY output, LPDWORD disposition) {
        auto& mock = *active;
        ++mock.creates;
        Check(root == HKEY_LOCAL_MACHINE, "параметр драйвера записывается не в HKLM");
        Check(std::wstring(path) ==
              L"SYSTEM\\CurrentControlSet\\Services\\PortmasterKext\\Parameters",
              "параметр драйвера записывается по неверному пути");
        Check(reserved == 0 && name == nullptr && options == REG_OPTION_NON_VOLATILE &&
              access == KEY_SET_VALUE && security == nullptr && disposition == nullptr,
              "раздел реестра открывается с неверными параметрами");
        if (mock.createStatus != ERROR_SUCCESS) return mock.createStatus;
        *output = mock.Handle();
        return ERROR_SUCCESS;
    }

    static LSTATUS WINAPI Set(HKEY key, LPCWSTR name, DWORD reserved, DWORD type,
                              const BYTE* bytes, DWORD size) {
        auto& mock = *active;
        ++mock.writes;
        Check(key == mock.Handle(), "запись использует другой дескриптор реестра");
        Check(std::wstring(name) == L"EnableInboundUdpCacheMissPidFallback",
              "изменяется посторонний параметр драйвера");
        Check(reserved == 0 && type == REG_DWORD && bytes != nullptr && size == sizeof(DWORD),
              "значение записывается не в формате DWORD");
        DWORD value = 0;
        std::memcpy(&value, bytes, sizeof(value));
        mock.values.push_back(value);
        return mock.setStatus;
    }

    static LSTATUS WINAPI Close(HKEY key) {
        auto& mock = *active;
        ++mock.closes;
        Check(key == mock.Handle(), "закрывается другой дескриптор реестра");
        return ERROR_SUCCESS;
    }

    TrafficAttributionOptions::Detail::RegistryApi Api() const {
        return { Create, Set, Close };
    }
};

class TemporarySettings {
public:
    TemporarySettings() {
        wchar_t directory[MAX_PATH + 1]{};
        const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(directory)), directory);
        Check(length != 0 && length < std::size(directory), "нет каталога для временной базы");
        wchar_t file[MAX_PATH + 1]{};
        Check(GetTempFileNameW(directory, L"fat", 0, file) != 0, "нет файла для временной базы");
        file_ = file;
        std::wstring error;
        if (!Settings::Open(file_, error)) {
            DeleteFileW(file_.c_str());
            throw std::runtime_error("не удалось открыть временную базу настроек");
        }
    }

    ~TemporarySettings() {
        Settings::Close();
        DeleteFileW(file_.c_str());
    }

    void Reopen() const {
        Settings::Close();
        std::wstring error;
        Check(Settings::Open(file_, error), "не удалось повторно открыть базу настроек");
    }

    const std::wstring& File() const { return file_; }

private:
    std::wstring file_;
};

void TestDefault() {
    TemporarySettings settings;
    MockRegistry registry;
    Check(TrafficAttributionOptions::Load(), "настройка по умолчанию должна быть включена");
    Check(registry.creates == 0, "чтение настройки обращается к реестру");
    Check(TrafficAttributionOptions::Detail::ApplySaved(registry.Api()) == ERROR_SUCCESS,
          "не удалось применить значение по умолчанию");
    Check(registry.values == std::vector<DWORD>{ 1 }, "по умолчанию не записан DWORD 1");
    Check(registry.closes == 1, "дескриптор параметров не закрыт");
}

void TestDwordValues() {
    MockRegistry registry;
    for (const bool enabled : { true, false, true, false }) {
        Check(TrafficAttributionOptions::Detail::Apply(registry.Api(), enabled) == ERROR_SUCCESS,
              "ошибка записи параметра драйвера");
        Check(registry.values.back() == (enabled ? 1u : 0u), "неверное значение DWORD");
        Check(registry.creates == registry.writes && registry.writes == registry.closes,
              "не каждый открытый раздел реестра закрыт");
    }
}

void TestPersistenceAndStartup() {
    TemporarySettings settings;
    MockRegistry registry;
    for (const bool enabled : { true, false, true }) {
        Check(TrafficAttributionOptions::Save(enabled), "настройка не сохранена в базе");
        Check(Settings::GetString(Settings::Key::kPreciseTrafficAttribution) ==
              (enabled ? L"1" : L"0"), "сохранено неверное значение настройки");
        const unsigned creates = registry.creates;
        settings.Reopen();
        Check(TrafficAttributionOptions::Load() == enabled, "настройка потеряна после перезапуска");
        Check(registry.creates == creates, "сохранение или чтение самостоятельно меняет реестр");
        Check(TrafficAttributionOptions::Detail::ApplySaved(registry.Api()) == ERROR_SUCCESS,
              "сохранённая настройка не применяется перед запуском");
        Check(registry.values.back() == (enabled ? 1u : 0u),
              "при запуске применяется не последнее сохранённое значение");
    }
    Check(registry.creates == registry.closes, "дескрипторы при запуске не закрыты");
}

void TestRegistryErrors() {
    {
        MockRegistry registry;
        registry.createStatus = ERROR_ACCESS_DENIED;
        SetLastError(ERROR_SUCCESS);
        Check(TrafficAttributionOptions::Detail::Apply(registry.Api(), true) == ERROR_ACCESS_DENIED,
              "код ошибки открытия заменён значением GetLastError");
        Check(registry.writes == 0 && registry.closes == 0, "используется неоткрытый раздел реестра");
    }
    {
        MockRegistry registry;
        registry.setStatus = ERROR_WRITE_FAULT;
        SetLastError(ERROR_SUCCESS);
        Check(TrafficAttributionOptions::Detail::Apply(registry.Api(), false) == ERROR_WRITE_FAULT,
              "ошибка записи параметра скрыта");
        Check(registry.closes == 1, "дескриптор не закрыт после ошибки записи");
    }
}

void TestSavedValueSurvivesRegistryFailure() {
    TemporarySettings settings;
    MockRegistry registry;
    Check(TrafficAttributionOptions::Save(true), "не удалось сохранить включённую настройку");
    registry.setStatus = ERROR_ACCESS_DENIED;
    Check(TrafficAttributionOptions::Detail::ApplySaved(registry.Api()) == ERROR_ACCESS_DENIED,
          "ошибка применения сохранённой настройки скрыта");
    settings.Reopen();
    Check(TrafficAttributionOptions::Load(), "ошибка реестра потеряла сохранённую настройку");
    registry.setStatus = ERROR_SUCCESS;
    Check(TrafficAttributionOptions::Detail::ApplySaved(registry.Api()) == ERROR_SUCCESS &&
          registry.values.back() == 1, "повторный запуск не применяет сохранённую настройку");
    Check(registry.creates == registry.closes, "дескриптор потерян при повторном применении");
}

void TestSaveFailure() {
    TemporarySettings settings;
    Check(TrafficAttributionOptions::Save(false), "не удалось сохранить выключенную настройку");
    std::wstring error;
    // Родитель — обычный файл: такой путь базы не может быть открыт.
    Check(!Settings::Open(settings.File() + L"\\settings.db", error), "некорректный путь базы принят");
    Check(!TrafficAttributionOptions::Save(true), "ошибка сохранения настройки скрыта");
    Check(!Settings::lastError().empty(), "нет сообщения об ошибке сохранения");
    settings.Reopen();
    Check(!TrafficAttributionOptions::Load(), "неудачная запись изменила сохранённую настройку");
}

} // namespace

int main() {
    try {
        TestDefault();
        TestDwordValues();
        TestPersistenceAndStartup();
        TestRegistryErrors();
        TestSavedValueSurvivesRegistryFailure();
        TestSaveFailure();
        std::cout << "traffic_attribution_options_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
