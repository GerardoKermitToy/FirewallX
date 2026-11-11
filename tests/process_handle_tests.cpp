#include "AskQueue.h"
#include "FirewallPolicy.h"
#include "SystemInfo.h"

#include <iostream>
#include <stdexcept>
#include <unordered_map>

namespace {

std::unordered_map<DWORD, ServiceInfo::HostedServices> hostedByPid;
size_t serviceReads = 0;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

// Дочерний процесс создаётся приостановленным и не выполняет тесты повторно.
// Деструктор закрывает его и при исключении, чтобы не оставить лишний процесс.
class ChildProcess {
public:
    ChildProcess() {
        wchar_t path[32768]{};
        const DWORD size = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        Check(size && size < std::size(path), "не удалось получить путь теста");
        std::wstring command = L"\"" + std::wstring(path, size) + L"\"";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        Check(CreateProcessW(path, command.data(), nullptr, nullptr, FALSE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr,
                             &startup, &info_) != FALSE,
              "не удалось создать дочерний процесс");
        CloseHandle(info_.hThread);
        info_.hThread = nullptr;
    }

    ~ChildProcess() {
        if (info_.hProcess) {
            TerminateProcess(info_.hProcess, 0);
            WaitForSingleObject(info_.hProcess, 5000);
            CloseHandle(info_.hProcess);
        }
    }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    DWORD pid() const { return info_.dwProcessId; }

    void Stop(DWORD exitCode = 0) {
        Check(TerminateProcess(info_.hProcess, exitCode) != FALSE,
              "не удалось завершить дочерний процесс");
        Check(WaitForSingleObject(info_.hProcess, 5000) == WAIT_OBJECT_0,
              "дочерний процесс не завершился");
        CloseHandle(info_.hProcess);
        info_.hProcess = nullptr;
    }

private:
    PROCESS_INFORMATION info_{};
};

void ForgetCachedProcess(DWORD pid) {
    detail::AliveCache& cache = detail::aliveCache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    const auto it = cache.map.find(pid);
    Check(it != cache.map.end(), "процесс отсутствует в кеше");
    detail::CloseEntry(it->second);
    cache.map.erase(it);
}

void SetServices(DWORD pid, std::wstring name) {
    ServiceEntry service;
    service.name = std::move(name);
    service.pid = pid;
    service.state = SERVICE_RUNNING;
    hostedByPid[pid] = std::make_shared<const std::vector<ServiceEntry>>(
        std::vector<ServiceEntry>{ std::move(service) });
}

Rule ServiceRule() {
    Rule rule;
    rule.scope = RuleScope::Global;
    rule.conds = CondProto | CondService;
    rule.proto = Proto::Tcp;
    rule.action = RuleAction::Allow;
    rule.services = { ServiceItem{ L"AllowedSvc", L"" } };
    rule.autoName = false;
    rule.name = L"service rule";
    return rule;
}

MatchQuery Query(DWORD pid, const ProcessPathRef& path) {
    const uint8_t localBytes[4] = { 192, 0, 2, 10 };
    const uint8_t remoteBytes[4] = { 198, 51, 100, 20 };
    const FlowKey key = MakeFlowKey(
        Proto::Tcp, IpAddr::Raw4(localBytes), IpAddr::Raw4(remoteBytes),
        41000, 12345);
    MatchQuery query = MakeMatchQuery(
        path->text, pid, key, Dir::Out, -1, -1, path->process.get());
    PrepareMatchAppPath(query, path->folded, path->foldedHash);
    return query;
}

void TestLiveAndFinishedServiceOwner() {
    ChildProcess child;
    ProcessPathRef path = ProcessImagePathRef(child.pid());
    Check(path->process && path->process->alive(), "исходный дескриптор не сохранён");
    SetServices(child.pid(), L"AllowedSvc");

    RuleStore store;
    Rule rule = ServiceRule();
    store.Add(rule);
    MatchQuery query = Query(child.pid(), path);
    auto decision = FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query);
    Check(decision.matchedRule && decision.action == RuleAction::Allow,
          "сервисное правило не совпало с живым исходным процессом");
    Rule full;
    RuleMatchInfo info;
    Check(store.Match(query, full) && store.MatchInfo(query, info),
          "полное или компактное сопоставление потеряло дескриптор");

    // Уборка кеша не должна закрывать дескриптор, сохранённый pending-запросом.
    ForgetCachedProcess(child.pid());
    // Код выхода STILL_ACTIVE не должен скрывать завершение: дескриптор
    // ожидания сообщает состояние независимо от числового кода выхода.
    child.Stop(STILL_ACTIVE);
    Check(!path->process->alive(), "завершённый исходный процесс считается живым");
    const size_t readsBefore = serviceReads;
    decision = FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query);
    Check(!decision.decided && !decision.matchedRule,
          "завершённый процесс получил вердикт по текущему снимку служб");
    Check(serviceReads == readsBefore,
          "после завершения исходного процесса выполнен поиск служб по PID");
    Check(!store.Match(query, full) && !store.MatchInfo(query, info),
          "полное или компактное сопоставление применило службы завершённого процесса");

    // Завершение процесса не задаёт Drop: обычное правило по сохранённому пути
    // должно по-прежнему позволять закрыть исходное обязательство.
    Rule appRule;
    appRule.appPath = path->text;
    appRule.conds = CondProto;
    appRule.proto = Proto::Tcp;
    appRule.action = RuleAction::Allow;
    appRule.autoName = false;
    appRule.name = L"app rule";
    store.Add(appRule);
    decision = FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query);
    Check(decision.decided && decision.matchedRule && decision.action == RuleAction::Allow,
          "обычное правило не закрыло запрос завершённого процесса");
}

void TestPendingOwnerCannotAcquireNewServices() {
    ChildProcess child;
    ProcessPathRef path = ProcessImagePathRef(child.pid());
    SetServices(child.pid(), L"OtherSvc");
    RuleStore store;
    Rule rule = ServiceRule();
    store.Add(rule);
    MatchQuery query = Query(child.pid(), path);
    Check(!FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query).decided,
          "исходный запрос ошибочно получил сервисный вердикт вместо ожидания");

    ForgetCachedProcess(child.pid());
    child.Stop();
    // Моделируем новый состав служб того же числового PID. Исходный запрос
    // не должен приобретать чужие условия при повторном сопоставлении.
    SetServices(child.pid(), L"AllowedSvc");
    const size_t readsBefore = serviceReads;
    Check(!FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query).decided,
          "ожидающий запрос получил вердикт по новым службам старого PID");
    Check(serviceReads == readsBefore, "pending разрешил службы по завершённому владельцу");
}

void TestMissingAndMismatchedHandle() {
    ChildProcess child;
    ProcessPathRef path = ProcessImagePathRef(child.pid());
    SetServices(child.pid(), L"AllowedSvc");
    RuleStore store;
    Rule rule = ServiceRule();
    store.Add(rule);
    MatchQuery query = Query(child.pid(), path);
    query.process = nullptr;
    const size_t readsBefore = serviceReads;
    Check(!FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query).decided,
          "сервисное правило совпало без исходного дескриптора");
    query.process = path->process.get();
    ++query.pid;
    SetServices(query.pid, L"AllowedSvc");
    Check(!FirewallPolicies::Evaluate(FirewallPolicy::Learning, &store, query).decided,
          "дескриптор чужого PID разрешил сервисное правило");
    Check(serviceReads == readsBefore, "без правильного дескриптора выполнен поиск служб");
    ForgetCachedProcess(child.pid());
}

void TestHandleLifetime() {
    ChildProcess child;
    ProcessPathRef path = ProcessImagePathRef(child.pid());
    Check(path->process != nullptr, "исходный дескриптор не сохранён");
    const HANDLE handle = path->process->h;
    std::weak_ptr<const ProcessHandleInfo> owner = path->process;
    AskRequest request;
    request.pid = child.pid();
    request.process = path->process;
    ForgetCachedProcess(child.pid());
    child.Stop();
    path.reset();
    Check(!owner.expired() && WaitForSingleObject(handle, 0) == WAIT_OBJECT_0,
          "UI-запрос не удерживает исходный дескриптор после очистки кеша");
    request.process.reset();
    Check(owner.expired(), "последняя ссылка не освободила владельца дескриптора");
    DWORD flags = 0;
    Check(!GetHandleInformation(handle, &flags) && GetLastError() == ERROR_INVALID_HANDLE,
          "дескриптор не закрыт после освобождения последней ссылки");
}

} // анонимное пространство имён

// Управляемый снимок SCM воспроизводит запоздалые данные независимо от служб ОС.
namespace ServiceInfo {

HostedServices ServicesOfPid(DWORD pid, bool) {
    ++serviceReads;
    const auto it = hostedByPid.find(pid);
    if (it != hostedByPid.end()) return it->second;
    static const HostedServices empty = std::make_shared<const std::vector<ServiceEntry>>();
    return empty;
}

bool SameName(const std::wstring& a, const std::wstring& b) {
    return EqualNoCase(a, b);
}

std::wstring DisplayName(const std::wstring& name) {
    return name;
}

} // пространство имён ServiceInfo

int main() {
    try {
        TestLiveAndFinishedServiceOwner();
        TestPendingOwnerCannotAcquireNewServices();
        TestMissingAndMismatchedHandle();
        TestHandleLifetime();
        std::cout << "Process handle tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
