#include "Common.h"
#include "StartupOptions.h"
#include "StartupOptionsDetail.h"
#include "AppInfo.h"
#include <wrl/client.h>
#include <iostream>
#include <stdexcept>

using Microsoft::WRL::ComPtr;

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void CheckStatus(HRESULT status, const char* message) {
    if (FAILED(status))
        throw std::runtime_error(std::string(message) + ": " +
                                 std::to_string(static_cast<unsigned>(status)));
}

class Bstr {
public:
    ~Bstr() { SysFreeString(text_); }
    BSTR* Out() { return &text_; }
    std::wstring Text() const { return text_ ? text_ : L""; }
private:
    BSTR text_ = nullptr;
};

void TestMissingTaskCodes() {
    using StartupOptions::Detail::IsTaskMissing;
    Check(IsTaskMissing(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)), "задание отсутствует");
    Check(IsTaskMissing(HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)), "путь задания отсутствует");
    Check(!IsTaskMissing(S_OK), "успех не означает отсутствие задания");
    Check(!IsTaskMissing(E_ACCESSDENIED), "ошибка доступа не означает выключенный автозапуск");
    Check(!IsTaskMissing(SCHED_E_SERVICE_NOT_RUNNING), "ошибка службы не означает выключенный автозапуск");
    Check(!IsTaskMissing(CO_E_NOTINITIALIZED), "ошибка COM не означает выключенный автозапуск");
}

void TestTaskNames() {
    using StartupOptions::Detail::TaskName;
    const std::wstring firstSid = L"S-1-5-21-1-2-3-1001";
    const std::wstring secondSid = L"S-1-5-21-1-2-3-1002";
    Check(TaskName(firstSid) == std::wstring(AppInfo::kStartupTaskPrefix) + firstSid,
          "имя задания не содержит SID пользователя");
    Check(TaskName(firstSid) != TaskName(secondSid), "пользователи используют одно задание");
}

void TestInvalidArguments(ITaskService* service) {
    using StartupOptions::Detail::CreateTaskDefinition;
    const std::wstring sid = L"S-1-5-21-1-2-3-1001";
    const std::wstring executable = L"C:\\Apps\\FirewallX.exe";
    Check(CreateTaskDefinition(service, sid, executable, L"", nullptr) == E_POINTER,
          "нулевой выходной указатель принят");
    ITaskDefinition* definition = nullptr;
    Check(CreateTaskDefinition(nullptr, sid, executable, L"", &definition) == E_INVALIDARG,
          "нулевой Планировщик принят");
    Check(definition == nullptr, "ошибка вернула определение задания");
    Check(CreateTaskDefinition(service, L"", executable, L"", &definition) == E_INVALIDARG,
          "пустой SID принят");
    Check(CreateTaskDefinition(service, sid, L"", L"", &definition) == E_INVALIDARG,
          "пустой путь принят");
    Check(CreateTaskDefinition(service, sid, L"FirewallX.exe", L"", &definition) == E_INVALIDARG,
          "путь без рабочего каталога принят");
    Check(CreateTaskDefinition(service, sid, L"C:\\Apps\\", L"", &definition) == E_INVALIDARG,
          "каталог вместо исполняемого файла принят");
    Check(definition == nullptr, "ошибка оставила определение задания");
}

void TestTaskDefinition(ITaskService* service, const std::wstring& executable) {
    const std::wstring sid = L"S-1-5-21-1-2-3-1001";
    const std::wstring description = L"Описание автозапуска";
    ComPtr<ITaskDefinition> task;
    CheckStatus(StartupOptions::Detail::CreateTaskDefinition(
        service, sid, executable, description, task.GetAddressOf()), "создание задания");

    ComPtr<IRegistrationInfo> registration;
    CheckStatus(task->get_RegistrationInfo(registration.GetAddressOf()), "описание задания");
    Bstr taskDescription;
    CheckStatus(registration->get_Description(taskDescription.Out()), "чтение описания");
    Check(taskDescription.Text() == description, "описание задания изменено");

    ComPtr<IPrincipal> principal;
    CheckStatus(task->get_Principal(principal.GetAddressOf()), "пользователь задания");
    Bstr principalSid;
    CheckStatus(principal->get_UserId(principalSid.Out()), "SID пользователя");
    Check(principalSid.Text() == sid, "неверный пользователь задания");
    TASK_LOGON_TYPE logonType{};
    CheckStatus(principal->get_LogonType(&logonType), "тип входа");
    Check(logonType == TASK_LOGON_INTERACTIVE_TOKEN, "задание требует пароль или запускается без UI");
    TASK_RUNLEVEL_TYPE runLevel{};
    CheckStatus(principal->get_RunLevel(&runLevel), "уровень прав");
    Check(runLevel == TASK_RUNLEVEL_HIGHEST, "не запрошены права администратора");

    ComPtr<ITaskSettings> settings;
    CheckStatus(task->get_Settings(settings.GetAddressOf()), "настройки задания");
    VARIANT_BOOL value = VARIANT_FALSE;
    CheckStatus(settings->get_Enabled(&value), "состояние задания");
    Check(value == VARIANT_TRUE, "автозапуск выключен");
    CheckStatus(settings->get_StartWhenAvailable(&value), "запуск при доступности");
    Check(value == VARIANT_TRUE, "пропущенный вход не обработан");
    CheckStatus(settings->get_DisallowStartIfOnBatteries(&value), "запуск от батареи");
    Check(value == VARIANT_FALSE, "автозапуск запрещён на ноутбуке");
    CheckStatus(settings->get_StopIfGoingOnBatteries(&value), "остановка от батареи");
    Check(value == VARIANT_FALSE, "мониторинг останавливается при отключении питания");
    CheckStatus(settings->get_RunOnlyIfIdle(&value), "зависимость от простоя");
    Check(value == VARIANT_FALSE, "автозапуск требует простоя");
    CheckStatus(settings->get_RunOnlyIfNetworkAvailable(&value), "зависимость от сети");
    Check(value == VARIANT_FALSE, "автозапуск требует доступной сети");
    Bstr timeLimit;
    CheckStatus(settings->get_ExecutionTimeLimit(timeLimit.Out()), "ограничение времени");
    Check(timeLimit.Text() == L"PT0S", "задание принудительно завершит долгий мониторинг");
    TASK_INSTANCES_POLICY instances{};
    CheckStatus(settings->get_MultipleInstances(&instances), "политика экземпляров");
    Check(instances == TASK_INSTANCES_IGNORE_NEW, "разрешены параллельные экземпляры задания");

    ComPtr<ITriggerCollection> triggers;
    CheckStatus(task->get_Triggers(triggers.GetAddressOf()), "триггеры");
    LONG count = 0;
    CheckStatus(triggers->get_Count(&count), "число триггеров");
    Check(count == 1, "неверное число триггеров");
    ComPtr<ITrigger> trigger;
    CheckStatus(triggers->get_Item(1, trigger.GetAddressOf()), "триггер входа");
    TASK_TRIGGER_TYPE2 triggerType{};
    CheckStatus(trigger->get_Type(&triggerType), "тип триггера");
    Check(triggerType == TASK_TRIGGER_LOGON, "задание не запускается при входе");
    CheckStatus(trigger->get_Enabled(&value), "состояние триггера");
    Check(value == VARIANT_TRUE, "триггер выключен");
    ComPtr<ILogonTrigger> logon;
    CheckStatus(trigger.As(&logon), "интерфейс триггера входа");
    Bstr triggerSid;
    CheckStatus(logon->get_UserId(triggerSid.Out()), "пользователь триггера");
    Check(triggerSid.Text() == sid, "вход другого пользователя запустит программу");

    ComPtr<IActionCollection> actions;
    CheckStatus(task->get_Actions(actions.GetAddressOf()), "действия");
    CheckStatus(actions->get_Count(&count), "число действий");
    Check(count == 1, "неверное число действий");
    ComPtr<IAction> action;
    CheckStatus(actions->get_Item(1, action.GetAddressOf()), "действие запуска");
    ComPtr<IExecAction> exec;
    CheckStatus(action.As(&exec), "интерфейс запуска");
    Bstr path;
    CheckStatus(exec->get_Path(path.Out()), "путь программы");
    Check(path.Text() == executable, "путь с пробелами или Unicode изменён");
    Bstr directory;
    CheckStatus(exec->get_WorkingDirectory(directory.Out()), "рабочий каталог");
    Check(directory.Text() == executable.substr(0, executable.find_last_of(L"\\/") + 1),
          "неверный рабочий каталог");
    Bstr arguments;
    CheckStatus(exec->get_Arguments(arguments.Out()), "аргументы запуска");
    Check(arguments.Text() == StartupOptions::kStartInTrayArgument,
          "автозапуск не передаёт признак запуска в трей");
}

} // namespace

int main() {
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return 1;
    int result = 0;
    try {
        TestMissingTaskCodes();
        TestTaskNames();
        bool enabled = false;
        CheckStatus(StartupOptions::GetEnabled(enabled), "чтение текущего состояния автозапуска");
        ComPtr<ITaskService> service;
        CheckStatus(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(service.GetAddressOf())), "создание Планировщика");
        // Работаем только с определением в памяти: задания не регистрируются
        // и автозапуск пользователя во время тестов не изменяется.
        TestInvalidArguments(service.Get());
        TestTaskDefinition(service.Get(), L"C:\\Программы & tools\\FirewallX.exe");
        TestTaskDefinition(service.Get(), L"C:\\FirewallX.exe");
        TestTaskDefinition(service.Get(), L"C:\\" + std::wstring(280, L'a') + L"\\FirewallX.exe");
        std::cout << "startup_options_tests: OK\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        result = 1;
    }
    CoUninitialize();
    return result;
}
