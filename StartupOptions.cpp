#include "Common.h"
#include "StartupOptions.h"
#include "StartupOptionsDetail.h"
#include "AppInfo.h"
#include <sddl.h>

namespace StartupOptions {
namespace {

template<class T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { if (ptr_) ptr_->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    T* Get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    T** Out() { return &ptr_; }

private:
    T* ptr_ = nullptr;
};

class Bstr {
public:
    explicit Bstr(const wchar_t* text) : text_(SysAllocString(text)) {}
    ~Bstr() { SysFreeString(text_); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;

    BSTR Get() const { return text_; }

private:
    BSTR text_;
};

HRESULT CurrentUserSid(std::wstring& sid) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return HRESULT_FROM_WIN32(GetLastError());

    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    DWORD status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(token);
        return HRESULT_FROM_WIN32(status);
    }

    std::vector<BYTE> buffer(bytes);
    const BOOL read = GetTokenInformation(token, TokenUser, buffer.data(),
                                          bytes, &bytes);
    status = read ? ERROR_SUCCESS : GetLastError();
    CloseHandle(token);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    LPWSTR text = nullptr;
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    if (!ConvertSidToStringSidW(user->User.Sid, &text))
        return HRESULT_FROM_WIN32(GetLastError());
    sid = text;
    LocalFree(text);
    return S_OK;
}

HRESULT OpenScheduler(ComPtr<ITaskService>& service, ComPtr<ITaskFolder>& folder,
                       std::wstring& userSid) {
    HRESULT status = CurrentUserSid(userSid);
    if (FAILED(status)) return status;

    status = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                               IID_ITaskService,
                               reinterpret_cast<void**>(service.Out()));
    if (FAILED(status)) return status;
    const VARIANT empty{};
    status = service->Connect(empty, empty, empty, empty);
    if (FAILED(status)) return status;

    Bstr root(L"\\");
    if (!root.Get()) return E_OUTOFMEMORY;
    return service->GetFolder(root.Get(), folder.Out());
}

} // namespace

namespace Detail {

bool IsTaskMissing(HRESULT status) {
    return status == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
           status == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
}

std::wstring TaskName(const std::wstring& userSid) {
    return std::wstring(AppInfo::kStartupTaskPrefix) + userSid;
}

HRESULT CreateTaskDefinition(ITaskService* service, const std::wstring& userSid,
                             const std::wstring& executable,
                             const std::wstring& description,
                             ITaskDefinition** definition) {
    if (!definition) return E_POINTER;
    *definition = nullptr;
    const size_t slash = executable.find_last_of(L"\\/");
    if (!service || userSid.empty() || executable.empty() ||
        slash == std::wstring::npos || slash + 1 == executable.size())
        return E_INVALIDARG;

    const std::wstring directory = executable.substr(0, slash + 1);
    Bstr sid(userSid.c_str());
    Bstr path(executable.c_str());
    Bstr workingDirectory(directory.c_str());
    Bstr taskDescription(description.c_str());
    Bstr unlimited(L"PT0S");
    if (!sid.Get() || !path.Get() || !workingDirectory.Get() ||
        !taskDescription.Get() || !unlimited.Get())
        return E_OUTOFMEMORY;

    ComPtr<ITaskDefinition> task;
    HRESULT status = service->NewTask(0, task.Out());
    if (FAILED(status)) return status;

    ComPtr<IRegistrationInfo> registration;
    status = task->get_RegistrationInfo(registration.Out());
    if (FAILED(status)) return status;
    status = registration->put_Description(taskDescription.Get());
    if (FAILED(status)) return status;

    // Run-ключ реестра не запускает requireAdministrator-приложение.
    // Интерактивное задание даёт повышенные права без хранения пароля.
    ComPtr<IPrincipal> principal;
    status = task->get_Principal(principal.Out());
    if (FAILED(status)) return status;
    status = principal->put_UserId(sid.Get());
    if (FAILED(status)) return status;
    status = principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
    if (FAILED(status)) return status;
    status = principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
    if (FAILED(status)) return status;

    ComPtr<ITaskSettings> settings;
    status = task->get_Settings(settings.Out());
    if (FAILED(status)) return status;
    status = settings->put_Enabled(VARIANT_TRUE);
    if (FAILED(status)) return status;
    status = settings->put_StartWhenAvailable(VARIANT_TRUE);
    if (FAILED(status)) return status;
    status = settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
    if (FAILED(status)) return status;
    status = settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    if (FAILED(status)) return status;
    // Фоновый мониторинг нельзя принудительно завершать через стандартные 72 часа.
    status = settings->put_ExecutionTimeLimit(unlimited.Get());
    if (FAILED(status)) return status;
    status = settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW);
    if (FAILED(status)) return status;

    ComPtr<ITriggerCollection> triggers;
    status = task->get_Triggers(triggers.Out());
    if (FAILED(status)) return status;
    ComPtr<ITrigger> trigger;
    status = triggers->Create(TASK_TRIGGER_LOGON, trigger.Out());
    if (FAILED(status)) return status;
    status = trigger->put_Enabled(VARIANT_TRUE);
    if (FAILED(status)) return status;
    ComPtr<ILogonTrigger> logon;
    status = trigger->QueryInterface(IID_ILogonTrigger,
                                     reinterpret_cast<void**>(logon.Out()));
    if (FAILED(status)) return status;
    status = logon->put_UserId(sid.Get());
    if (FAILED(status)) return status;

    ComPtr<IActionCollection> actions;
    status = task->get_Actions(actions.Out());
    if (FAILED(status)) return status;
    ComPtr<IAction> action;
    status = actions->Create(TASK_ACTION_EXEC, action.Out());
    if (FAILED(status)) return status;
    ComPtr<IExecAction> exec;
    status = action->QueryInterface(IID_IExecAction,
                                    reinterpret_cast<void**>(exec.Out()));
    if (FAILED(status)) return status;
    // Путь передаётся отдельно от аргументов: пробелы не требуют ручных кавычек.
    status = exec->put_Path(path.Get());
    if (FAILED(status)) return status;
    status = exec->put_WorkingDirectory(workingDirectory.Get());
    if (FAILED(status)) return status;

    *definition = task.Get();
    (*definition)->AddRef();
    return S_OK;
}

} // namespace Detail

HRESULT GetEnabled(bool& enabled) {
    enabled = false;
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> folder;
    std::wstring userSid;
    HRESULT status = OpenScheduler(service, folder, userSid);
    if (FAILED(status)) return status;

    Bstr name(Detail::TaskName(userSid).c_str());
    if (!name.Get()) return E_OUTOFMEMORY;
    ComPtr<IRegisteredTask> task;
    status = folder->GetTask(name.Get(), task.Out());
    if (Detail::IsTaskMissing(status)) return S_OK;
    if (FAILED(status)) return status;

    VARIANT_BOOL value = VARIANT_FALSE;
    status = task->get_Enabled(&value);
    if (SUCCEEDED(status)) enabled = value != VARIANT_FALSE;
    return status;
}

HRESULT SetEnabled(bool enabled) {
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> folder;
    std::wstring userSid;
    HRESULT status = OpenScheduler(service, folder, userSid);
    if (FAILED(status)) return status;

    Bstr name(Detail::TaskName(userSid).c_str());
    if (!name.Get()) return E_OUTOFMEMORY;
    if (!enabled) {
        status = folder->DeleteTask(name.Get(), 0);
        return Detail::IsTaskMissing(status) ? S_OK : status;
    }

    const std::wstring executable = ModulePath();
    if (executable.empty()) return HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);
    ComPtr<ITaskDefinition> definition;
    status = Detail::CreateTaskDefinition(
        service.Get(), userSid, executable,
        LoadStringRes(IDS_SETTINGS_START_WITH_WINDOWS_TIP), definition.Out());
    if (FAILED(status)) return status;

    Bstr sid(userSid.c_str());
    if (!sid.Get()) return E_OUTOFMEMORY;
    VARIANT user{};
    user.vt = VT_BSTR;
    user.bstrVal = sid.Get();
    const VARIANT empty{};
    ComPtr<IRegisteredTask> registered;
    return folder->RegisterTaskDefinition(name.Get(), definition.Get(),
                                          TASK_CREATE_OR_UPDATE, user, empty,
                                          TASK_LOGON_INTERACTIVE_TOKEN, empty,
                                          registered.Out());
}

} // namespace StartupOptions
