#include "ProcessProtectionOptions.h"
#include "ProcessProtectionOptionsDetail.h"
#include "Settings.h"
#include "StringRes.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct MockMitigations {
    inline static MockMitigations* active = nullptr;
    PROCESS_MITIGATION_POLICY failedPolicy = MaxProcessMitigationPolicy;
    DWORD error = ERROR_ACCESS_DENIED;
    std::vector<PROCESS_MITIGATION_POLICY> calls;

    MockMitigations() { active = this; }
    ~MockMitigations() { active = nullptr; }

    static BOOL WINAPI Set(PROCESS_MITIGATION_POLICY policy, PVOID bytes, SIZE_T size) {
        auto& mock = *active;
        mock.calls.push_back(policy);
        Check(bytes != nullptr, "нет параметров политики защиты");
        if (policy == ProcessSignaturePolicy) {
            Check(size == sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY),
                  "неверный размер политики CIG");
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY value{};
            std::memcpy(&value, bytes, sizeof(value));
            Check(value.Flags == 1, "CIG должен разрешать только подпись Microsoft без аудита");
        } else {
            Check(policy == ProcessDynamicCodePolicy, "изменяется посторонняя политика процесса");
            Check(size == sizeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY),
                  "неверный размер политики ACG");
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY value{};
            std::memcpy(&value, bytes, sizeof(value));
            Check(value.Flags == 1, "ACG не должен разрешать исключения для потоков или ослабление");
        }
        if (policy == mock.failedPolicy) {
            SetLastError(mock.error);
            return FALSE;
        }
        return TRUE;
    }

    ProcessProtectionOptions::Detail::MitigationApi Api() const { return { Set }; }
};

class TemporarySettings {
public:
    TemporarySettings() {
        wchar_t directory[MAX_PATH + 1]{};
        const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(directory)), directory);
        Check(length != 0 && length < std::size(directory), "нет каталога для временной базы");
        wchar_t file[MAX_PATH + 1]{};
        Check(GetTempFileNameW(directory, L"fpp", 0, file) != 0, "нет файла для временной базы");
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

void TestDefaultAndDisabled() {
    TemporarySettings settings;
    MockMitigations api;
    Check(!ProcessProtectionOptions::Load(), "защита не должна включаться по умолчанию");
    Check(ProcessProtectionOptions::Detail::ApplySaved(api.Api()) == ERROR_SUCCESS,
          "не удалось применить значение по умолчанию");
    Check(ProcessProtectionOptions::Detail::Apply(api.Api(), false) == ERROR_SUCCESS,
          "отключённая защита должна быть пропущена");
    Check(api.calls.empty(), "отключённая настройка меняет политики процесса");
}

void TestPersistenceAndStartup() {
    TemporarySettings settings;
    MockMitigations api;
    for (const bool enabled : { true, false, true }) {
        api.calls.clear();
        Check(ProcessProtectionOptions::Save(enabled), "настройка защиты не сохранена");
        Check(Settings::GetString(Settings::Key::kDllInjectionProtection) ==
              (enabled ? L"1" : L"0"), "сохранено неверное значение настройки защиты");
        settings.Reopen();
        Check(ProcessProtectionOptions::Load() == enabled, "настройка потеряна после перезапуска");
        Check(api.calls.empty(), "сохранение или чтение самостоятельно меняет политики");
        Check(ProcessProtectionOptions::Detail::ApplySaved(api.Api()) == ERROR_SUCCESS,
              "сохранённая настройка не применяется при запуске");
        const std::vector<PROCESS_MITIGATION_POLICY> expected = enabled
            ? std::vector<PROCESS_MITIGATION_POLICY>{ ProcessSignaturePolicy, ProcessDynamicCodePolicy }
            : std::vector<PROCESS_MITIGATION_POLICY>{};
        Check(api.calls == expected, "при запуске включаются не обе политики или нарушен их порядок");
    }
}

void TestErrors() {
    TemporarySettings settings;
    Check(ProcessProtectionOptions::Save(true), "не удалось сохранить включённую защиту");
    for (const auto policy : { ProcessSignaturePolicy, ProcessDynamicCodePolicy }) {
        MockMitigations api;
        api.failedPolicy = policy;
        api.error = policy == ProcessSignaturePolicy ? ERROR_ACCESS_DENIED : ERROR_NOT_SUPPORTED;
        SetLastError(ERROR_SUCCESS);
        Check(ProcessProtectionOptions::Detail::ApplySaved(api.Api()) == api.error,
              "ошибка включения одной из политик скрыта");
        const size_t expectedCalls = policy == ProcessSignaturePolicy ? 1 : 2;
        Check(api.calls.size() == expectedCalls, "после ошибки выполнены лишние изменения политик");
        settings.Reopen();
        Check(ProcessProtectionOptions::Load(), "ошибка API сбросила сохранённую настройку");
    }
}

void TestDisableAfterFailure() {
    TemporarySettings settings;
    for (const auto policy : { ProcessSignaturePolicy, ProcessDynamicCodePolicy }) {
        Check(ProcessProtectionOptions::Save(true), "не удалось сохранить включённую защиту");
        MockMitigations api;
        api.failedPolicy = policy;
        Check(ProcessProtectionOptions::Detail::ApplySaved(api.Api()) == api.error,
              "ошибка включения защиты скрыта");
        const auto applied = api.calls;
        Check(ProcessProtectionOptions::Save(false), "не удалось сохранить отключение после ошибки");
        Check(api.calls == applied, "отключение после ошибки меняет политики текущего процесса");
        settings.Reopen();
        Check(!ProcessProtectionOptions::Load(), "отключение после ошибки потеряно при перезапуске");
        api.calls.clear();
        Check(ProcessProtectionOptions::Detail::ApplySaved(api.Api()) == ERROR_SUCCESS,
              "следующий запуск повторно включает отключённую защиту");
        Check(api.calls.empty(), "отключённая защита применяется после перезапуска");
    }
}

void TestSaveFailure() {
    TemporarySettings settings;
    for (const bool enabled : { false, true }) {
        Check(ProcessProtectionOptions::Save(enabled), "не удалось сохранить исходную настройку защиты");
        std::wstring error;
        // Родитель — обычный файл: запись по такому пути должна завершиться ошибкой.
        Check(!Settings::Open(settings.File() + L"\\settings.db", error), "принят некорректный путь базы");
        Check(!ProcessProtectionOptions::Save(!enabled), "ошибка сохранения защиты скрыта");
        Check(!Settings::lastError().empty(), "нет сообщения об ошибке сохранения");
        settings.Reopen();
        Check(ProcessProtectionOptions::Load() == enabled, "неудачная запись изменила настройку защиты");
    }
}

void CheckPolicies() {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
    Check(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy,
                                     &signature, sizeof(signature)) != FALSE,
          "не удалось прочитать реальную политику CIG");
    Check(signature.MicrosoftSignedOnly != 0, "Windows не включила CIG");
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode{};
    Check(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy,
                                     &dynamicCode, sizeof(dynamicCode)) != FALSE,
          "не удалось прочитать реальную политику ACG");
    Check(dynamicCode.ProhibitDynamicCode != 0 && dynamicCode.AllowThreadOptOut == 0 &&
          dynamicCode.AllowRemoteDowngrade == 0, "Windows не включила строгую политику ACG");
}

void TestRealPolicies() {
    // CTest запускает этот сценарий отдельным процессом, без драйвера и SCM.
    TemporarySettings settings;
    Check(ProcessProtectionOptions::Save(true), "не удалось сохранить защиту для проверки Windows");
    Check(ProcessProtectionOptions::ApplySaved() == ERROR_SUCCESS,
          "Windows не приняла политики CIG/ACG");
    CheckPolicies();

    void* executable = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (executable) VirtualFree(executable, 0, MEM_RELEASE);
    Check(executable == nullptr, "ACG разрешает создание динамической исполняемой памяти");

    Check(ProcessProtectionOptions::Save(false), "не удалось сохранить отключение защиты");
    Check(ProcessProtectionOptions::ApplySaved() == ERROR_SUCCESS, "ошибка отложенного отключения");
    CheckPolicies();
    settings.Reopen();
    Check(!ProcessProtectionOptions::Load(), "отключение защиты не сохранено для следующего запуска");
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::strcmp(argv[1], "--real-policy") == 0) {
            TestRealPolicies();
        } else {
            TestDefaultAndDisabled();
            TestPersistenceAndStartup();
            TestErrors();
            TestDisableAfterFailure();
            TestSaveFailure();
        }
        std::cout << "process_protection_options_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
