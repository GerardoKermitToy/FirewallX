#include "AllRulesWindow.h"
#include "AppInfo.h"
#include "AppRulesEditor.h"
#include "AskQueue.h"
#include "AskWindow.h"
#include "Common.h"
#include "DebugWindow.h"
#include "SystemInfo.h"
#include "FlowStore.h"
#include "GenerationCache.h"
#include "FirewallPolicy.h"
#include "FileSignature.h"
#include "Ingest.h"
#include "NdisBindingProcess.h"
#include "NdisTransport.h"
#include "MacroAddr.h"
#include "network_interface_watcher.h"
#include "Monitor.h"
#include "NumberText.h"
#include "ProcessCache.h"
#include "ProcessProtectionOptions.h"
#include "RuleEditor.h"
#include "RuleDialogs.h"
#include "RulePresets.h"
#include "RuleGenerator.h"
#include "RulePresetsResource.h"
#include "Rules.h"
#include "ServiceControl.h"
#include "SettingsWindow.h"
#include "Settings.h"
#include "SingleInstance.h"
#include "StartupOptions.h"
#include "StringRes.h"
#include "StorageMaintenance.h"
#include "ServiceInfo.h"
#include "TrayIcon.h"
#include "TreeList.h"
#include "TreeRowPlan.h"
#include "UiKit.h"
#include "ConnKill.h"

#include <commctrl.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <windowsx.h>
#include <algorithm>
#include <deque>
#include <iterator>
#include <memory>
#include <numeric>
#include <unordered_map>

// Команды меню. Порядок произволен, диапазоны разделены категориями для
// удобства, но это не требование: достаточно, чтобы новое ID не совпало с
// ранее выделенным где-то ещё.
enum : UINT {
    IDM_REFRESH = 1000, IDM_FOCUS_FILTER, IDM_EXPAND_ALL, IDM_COLLAPSE_ALL,
    IDM_SORT_DEFAULT, IDM_SHOW_PASSIVE,
    IDM_SKIN_MODERN = 1010, IDM_SKIN_CLASSIC, IDM_SKIN_TOGGLE,
    IDM_LANG_FIRST = 2000,   // отдельный диапазон команд по числу языков UiLangs
    IDM_TRAY_HIDE = 1030, IDM_TRAY_SHOW, IDM_EXIT,
    IDM_RULES_ALL = 1050, IDM_RULES_GLOBAL, IDM_RULES_APP, IDM_RULE_CREATE,
    IDM_RULE_CREATE_GLOBAL, IDM_RULE_EDIT, IDM_RULE_DELETE, IDM_RULES_CLEAR, IDM_RULES_GENERATE,
    IDM_ASK_NOW = 1070,
    IDM_SVC_STATE = 1080, IDM_SVC_INSTALL, IDM_SVC_REMOVE, IDM_SVC_START,
    IDM_SVC_STOP,
    IDM_ABOUT = 1100, IDM_SETTINGS,
    IDM_COPY_ROW = 1200, IDM_COPY_ALL, IDM_CONN_KILL, IDM_PROC_KILL,
};

#include <unordered_set>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#else
#pragma comment(lib, "comctl32.lib")
#endif

namespace {

constexpr UINT kListId   = 1001;
constexpr UINT kTimerId  = 1;
constexpr UINT kAutoRulesTimerId = 2;
constexpr UINT kInterval = 1000;
constexpr ULONGLONG kAutoRulesTimeoutMs = 5000;
constexpr int  kSortNatural = -1;
constexpr int  kStatusParts = 5;

// У PID 0 нет файла, подпись которого можно проверить. Исключение относится
// только к входящему и исходящему IGMP с PID 0; диапазон проверяется шаблоном.
bool IsAutomaticIgmp(const AskRequest& request) {
    return request.key.source == TrafficSource::Host && request.appPath.empty() &&
        !request.ownerAmbiguous && request.pid == 0 &&
        (request.dir == Dir::Out || request.dir == Dir::In) &&
        request.key.proto == ProtoFromNumber(2);
}

// Показ следующего запроса откладывается сообщением: иначе новое окно
// создавалось бы из обработчика кнопки предыдущего окна.
constexpr UINT kMsgPumpAsk           = WM_APP + 1;
constexpr UINT kMsgTray              = WM_APP + 2;
constexpr UINT kMsgContinueExit      = WM_APP + 3;
constexpr UINT kMsgServiceInfoChanged = WM_APP + 4;
constexpr UINT kMsgMonitorReady       = WM_APP + 5;
constexpr UINT kMsgDriverStartFailed = WM_APP + 6;
constexpr UINT kTrayIconId = 1;

enum {                                  // элементы панели команд
    IDC_FILTER = 1100, IDC_RESET, IDC_PASSIVE
};

enum {
    IDM_EXPAND_ALL = 40001, IDM_COLLAPSE_ALL, IDM_COPY_ROW, IDM_COPY_ALL,
    IDM_KILL_CONN, IDM_KILL, IDM_REFRESH, IDM_SORT_DEFAULT,
    IDM_SHOW_PASSIVE, IDM_ABOUT, IDM_EXIT, IDM_FOCUS_FILTER,
    IDM_RULES_ALL, IDM_RULES_APP, IDM_RULES_GLOBAL,
    IDM_RULE_CREATE, IDM_RULE_CREATE_GLOBAL, IDM_RULE_EDIT,
    IDM_RULE_DELETE, IDM_RULES_CLEAR,
    IDM_ASK_NOW,
    // Оформление списка: два явных выбора и переключатель «на другое».
    // Переключатель нужен для горячей клавиши: выбирать пункт в подменю ради
    // сравнения двух видов пришлось бы каждый раз.
    IDM_SKIN_MODERN, IDM_SKIN_CLASSIC, IDM_SKIN_TOGGLE,
    IDM_TRAY_HIDE, IDM_TRAY_SHOW,
    IDM_SVC_INSTALL, IDM_SVC_REMOVE, IDM_SVC_START, IDM_SVC_STOP, IDM_SVC_STATE,
    IDM_SETTINGS, IDM_DEBUG,
    IDM_POLICY_BLOCK_ALL, IDM_POLICY_BLOCK, IDM_POLICY_LEARNING,
    IDM_POLICY_ALLOW, IDM_POLICY_ALLOW_ALL
};

struct PolicyCommand {
    UINT command;
    FirewallPolicy policy;
};

constexpr PolicyCommand kPolicyCommands[] = {
    { IDM_POLICY_BLOCK_ALL, FirewallPolicy::BlockAll },
    { IDM_POLICY_BLOCK, FirewallPolicy::Block },
    { IDM_POLICY_LEARNING, FirewallPolicy::Learning },
    { IDM_POLICY_ALLOW, FirewallPolicy::Allow },
    { IDM_POLICY_ALLOW_ALL, FirewallPolicy::AllowAll },
};

// Диалог остаётся открытым до завершения текущей проверки подписи: рабочий
// поток не обращается к уничтоженному HWND, а отмена не записывает правила.
struct RuleGenerationProgress {
    static constexpr UINT kWorkerFinished = WM_APP + 1;
    std::atomic_bool cancel{false};
    RuleGenerator::Result result;
    HANDLE thread = nullptr;
    HWND dialog = nullptr;
    bool failed = false;
    bool finished = false; // Меняется только потоком окна после сообщения о завершении.
    using Scanner = RuleGenerator::Result (*)(const std::atomic_bool&, const RuleGenerator::Progress&);
    Scanner scan = &RuleGenerator::Scan;

    static DWORD WINAPI Run(void* context) {
        auto& self = *static_cast<RuleGenerationProgress*>(context);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        try {
            self.result = self.scan(self.cancel, [&](size_t completed, size_t total) {
                const int percent = total ? static_cast<int>(completed * 100 / total) : 100;
                PostMessageW(self.dialog, TDM_SET_PROGRESS_BAR_POS, percent, 0);
            });
        } catch (...) {
            self.failed = true;
        }
        PostMessageW(self.dialog, kWorkerFinished, 0, 0);
        return 0;
    }

    void RequestCancel(HWND window) {
        cancel.store(true, std::memory_order_relaxed);
        SendMessageW(window, TDM_ENABLE_BUTTON, IDCANCEL, FALSE);
    }

    static LRESULT CALLBACK DialogProc(HWND window, UINT message, WPARAM wp, LPARAM lp,
                                       UINT_PTR id, DWORD_PTR context) {
        auto& self = *reinterpret_cast<RuleGenerationProgress*>(context);
        if (message == kWorkerFinished) {
            self.finished = true;
            SendMessageW(window, TDM_ENABLE_BUTTON, IDCANCEL, TRUE);
            SendMessageW(window, TDM_CLICK_BUTTON, IDCANCEL, 0);
            return 0;
        }
        // Системное закрытие также отменяет поиск, не уничтожая окно потока.
        if (!self.finished && (message == WM_CLOSE ||
            (message == WM_SYSCOMMAND && (wp & 0xfff0) == SC_CLOSE))) {
            self.RequestCancel(window);
            return 0;
        }
        if (message == WM_NCDESTROY) RemoveWindowSubclass(window, DialogProc, id);
        return DefSubclassProc(window, message, wp, lp);
    }

    static HRESULT CALLBACK Callback(HWND dialog, UINT event, WPARAM button, LPARAM, LONG_PTR data) {
        auto& self = *reinterpret_cast<RuleGenerationProgress*>(data);
        if (event == TDN_CREATED) {
            self.dialog = dialog;
            if (!SetWindowSubclass(dialog, DialogProc, 0, reinterpret_cast<DWORD_PTR>(&self))) {
                self.failed = true;
                self.finished = true;
                PostMessageW(dialog, TDM_CLICK_BUTTON, IDCANCEL, 0);
                return S_OK;
            }
            self.thread = CreateThread(nullptr, 0, Run, &self, 0, nullptr);
            if (!self.thread) {
                self.failed = true;
                PostMessageW(dialog, kWorkerFinished, 0, 0);
            }
        } else if (event == TDN_BUTTON_CLICKED && button == IDCANCEL) {
            if (self.finished) return S_OK;
            self.RequestCancel(dialog);
            return S_FALSE;
        }
        return S_OK;
    }

    void Show(HWND owner, HINSTANCE instance) {
        const std::wstring title = LoadStringRes(IDS_RULE_GENERATE);
        const std::wstring text = LoadStringRes(IDS_RULE_GENERATE_PROGRESS);
        const std::wstring cancelText = LoadStringRes(IDS_BTN_CANCEL);
        const TASKDIALOG_BUTTON buttons[] = {{IDCANCEL, cancelText.c_str()}};
        TASKDIALOGCONFIG config{sizeof(config)};
        config.hwndParent = owner;
        config.hInstance = instance;
        config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SHOW_PROGRESS_BAR |
                         TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
        config.pszWindowTitle = title.c_str();
        config.pszContent = text.c_str();
        config.cButtons = static_cast<UINT>(std::size(buttons));
        config.pButtons = buttons;
        config.nDefaultButton = IDCANCEL;
        config.pfCallback = Callback;
        config.lpCallbackData = reinterpret_cast<LONG_PTR>(this);
        const HRESULT status = TaskDialogIndirect(&config, nullptr, nullptr, nullptr);
        if (FAILED(status)) cancel.store(true, std::memory_order_relaxed);
        if (thread) {
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
            thread = nullptr;
        }
        if (FAILED(status)) failed = true;
    }
};

HRESULT CALLBACK AboutDialogCallback(HWND hwnd, UINT notification, WPARAM, LPARAM link, LONG_PTR) {
    if (notification == TDN_HYPERLINK_CLICKED) {
        const auto url = reinterpret_cast<const wchar_t*>(link);
        if (AppInfo::IsAboutLink(url))
            ShellExecuteW(hwnd, L"open", url, nullptr, nullptr, SW_SHOWNORMAL);
    }
    return S_OK;
}

HMENU CreatePolicyMenu(FirewallPolicy current) {
    HMENU menu = CreatePopupMenu();
    for (const auto& item : kPolicyCommands) {
        AppendMenuW(menu, MF_STRING, item.command,
                    FirewallPolicies::Name(item.policy).c_str());
        MENUITEMINFOW state{ sizeof(state) };
        state.fMask = MIIM_FTYPE | MIIM_STATE;
        state.fType = MFT_STRING | MFT_RADIOCHECK;
        state.fState = item.policy == current ? MFS_CHECKED : MFS_UNCHECKED;
        SetMenuItemInfoW(menu, item.command, FALSE, &state);
    }
    return menu;
}

// Передача переднего плана: право на него нам выдала запускаемая копия
// через AllowSetForegroundWindow, но система может его не применить —
// тогда хотя бы мигаем кнопкой в панели задач.
void ForceForeground(HWND h) {
    if (!h || !IsWindow(h)) return;
    if (IsIconic(h)) ShowWindow(h, SW_RESTORE);
    SetForegroundWindow(h);
    BringWindowToTop(h);
    if (GetForegroundWindow() != h) {
        FLASHWINFO fi{ sizeof(fi), h, FLASHW_ALL | FLASHW_TIMERNOFG, 3, 0 };
        FlashWindowEx(&fi);
    }
}

uint64_t HashAddr(const IpAddr& a) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < a.len(); ++i) { h ^= a.b[i]; h *= 1099511628211ull; }
    h ^= a.family;
    return h;
}

uint64_t ProcIdentity(TrafficGroupKey group, bool ownerAmbiguous) {
    return (static_cast<uint64_t>(group.source) << 33) |
           (static_cast<uint64_t>(ownerAmbiguous) << 32) | group.id;
}

void FillProcessDisplay(ProcItem& process, ProcessCache& cache) {
    if (process.group.isNdis()) {
        process.name = InterfaceDisplayName(process.group.interfaceIndex());
        process.path.clear();
        process.pathInfo.reset();
        process.pathKnown = false;
        process.icon = cache.InterfaceIcon();
        return;
    }
    const auto& info = cache.Get(process.group.pid(), process.pathInfo);
    process.name = info.name;
    process.path = info.path;
    process.pathInfo = info.pathInfo;
    process.pathKnown = !process.path.empty();
    process.icon = info.icon;
}

TreeList::RowKey MakeRowKey(const ProcItem& p, const ConnItem* c) {
    TreeList::RowKey k;
    k.group = p.group;
    k.ownerAmbiguous = p.ownerAmbiguous;
    if (!c) { k.proto = -1; return k; }
    // в ключ идёт номер протокола: значений 256, и они различают строки
    k.proto = static_cast<int>(ProtoNumber(c->key.proto));
    k.generation = c->flowGeneration;
    k.lport = c->key.lport;
    k.rport = c->key.rport;
    k.remoteHash = HashAddr(c->key.remote);
    return k;
}

bool DefaultAscForColumn(int col) {
    switch (col) {
        case ColProcess: case ColPid: case ColProto:
        case ColLocal:   case ColRemote: case ColDir: case ColReason: return true;
        default: return false;
    }
}

int Cmp64(uint64_t a, uint64_t b) { return (a < b) ? -1 : (a > b) ? 1 : 0; }
int CmpDbl(double a, double b)    { return (a < b) ? -1 : (a > b) ? 1 : 0; }

std::wstring SpeedText(double bps, const std::wstring& zero) {
    return bps > 0.5 ? FormatSpeed(bps) : zero;
}

// ---------------------------------------------------------------------------
// Запросов решения по строкам списка соединений здесь НЕТ и быть не должно.
//
// Список Monitor объединяет таблицы ОС и события драйвера из FlowStore.
// Сама отображаемая строка не является обязательством process_verdict:
// ожидание ответа учитывает Ingest по исходному on_connection_*, а не UI.
// Поэтому единственный источник AskRequest — события транспорта
// on_connection_v4/v6 (Ingest -> App::DrainIngest).
//
// Прежняя функция NeedsAsk() удалена вместе с App::CollectAsk(): помимо
// самого запрета, она порождала неустранимый повтор вопроса для ICMP —
// «мягкий» запрос получал другой хэш (тип не определён), и ни одно правило
// с условием «тип ICMP» его не закрывало (matcher отклоняет icmpType < 0).
// ---------------------------------------------------------------------------

bool CompareProc(const ProcItem& a, const ProcItem& b, int col, bool asc) {
    if (col == kSortNatural) return a.order < b.order;
    int r = 0;
    switch (col) {
        case ColProcess: r = _wcsicmp(a.name.c_str(), b.name.c_str()); break;
        case ColReason:  r = Cmp64(a.conns.size(), b.conns.size());    break;
        case ColSent:    r = Cmp64(a.sent, b.sent);                    break;
        case ColRecv:    r = Cmp64(a.recv, b.recv);                    break;
        case ColPid:     r = Cmp64(a.group.pid(), b.group.pid());                     break;
        case ColSpeed:   r = CmpDbl(a.speed, b.speed);                 break;
        default:         r = 0;                                        break;
    }
    if (r == 0) return a.order < b.order;
    return asc ? (r < 0) : (r > 0);
}

bool CompareConn(const ConnItem& a, const ConnItem& b, int col, bool asc) {
    if (col == kSortNatural) return a.flowGeneration < b.flowGeneration;
    int r = 0;
    switch (col) {
        case ColSent:   r = Cmp64(a.sent, b.sent);    break;
        case ColRecv:   r = Cmp64(a.recv, b.recv);    break;
        case ColSpeed:  r = CmpDbl(a.speed, b.speed); break;
        // сортировка по номеру протокола: порядок совпадает с реестром IANA
        case ColProto:  r = static_cast<int>(ProtoNumber(a.key.proto)) -
                            static_cast<int>(ProtoNumber(b.key.proto)); break;
        case ColDir:    r = static_cast<int>(a.dir) - static_cast<int>(b.dir); break;
        case ColLocal:
            r = a.key.local.Cmp(b.key.local);
            if (r == 0) r = static_cast<int>(a.key.lport) - static_cast<int>(b.key.lport);
            break;
        case ColRemote:
            r = a.key.remote.Cmp(b.key.remote);
            if (r == 0) r = static_cast<int>(a.key.rport) - static_cast<int>(b.key.rport);
            break;
        default:        r = 0; break;
    }
    if (r == 0) return a.flowGeneration < b.flowGeneration;
    return asc ? (r < 0) : (r > 0);
}

// Дескрипторы файлов остаются открытыми до применения результата в UI-потоке.
// Фоновый поток владеет своей копией ссылки и может завершиться после App.
struct AutoSignatureCheck {
    std::wstring path;
    std::wstring rulePath;
    std::optional<FileSignature::TrustedFile> file;
    std::optional<FileSignature::TrustedFile> ruleFile;
    ULONGLONG finishedAt = 0;

    static DWORD WINAPI Run(void* context) {
        std::unique_ptr<std::shared_ptr<AutoSignatureCheck>> owner(
            static_cast<std::shared_ptr<AutoSignatureCheck>*>(context));
        const auto check = std::move(*owner);
        owner.reset();
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        check->file.emplace(check->path);
        // При наследовании нельзя создавать правила для неподписанного предка.
        if (*check->file && !EqualNoCase(check->path, check->rulePath))
            check->ruleFile.emplace(check->rulePath);
        check->finishedAt = GetTickCount64();
        return 0;
    }

    bool trusted() const {
        return file && static_cast<bool>(*file) &&
               (!ruleFile || static_cast<bool>(*ruleFile));
    }
};

DWORD ReadInstructionFile(const std::wstring& path, std::wstring& text) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    std::string bytes;
    char buffer[4096];
    DWORD count = 0;
    BOOL ok = FALSE;
    while ((ok = ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) && count)
        bytes.append(buffer, count);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (error != ERROR_SUCCESS) return error;

    std::wstring decoded = Utf8ToWide(bytes);
    if (!decoded.empty() && decoded.front() == 0xFEFF) decoded.erase(0, 1);
    text.clear();
    for (wchar_t ch : decoded) {
        if (ch == L'\n' && (text.empty() || text.back() != L'\r')) text += L'\r';
        text += ch;
    }
    return ERROR_SUCCESS;
}

class InstructionDialog : public Ui::Modal {
public:
    explicit InstructionDialog(const std::wstring& text) : text_(text) {}

private:
    void OnInit() override {
        const auto& m = M();
        const int x = m.margin();
        const int y = m.margin();
        const int w = clientW() - 2 * x;
        const int buttonY = clientH() - m.margin() - m.btnH();
        HWND edit = Add(L"EDIT", L"", WS_TABSTOP | WS_VSCROLL | ES_MULTILINE |
                        ES_AUTOVSCROLL | ES_READONLY, WS_EX_CLIENTEDGE,
                        x, y, w, buttonY - y - m.margin(), 101, Ui::MonoFont(m.dpi));
        if (edit) {
            // Инструкции всегда слева направо, даже в зеркальном интерфейсе.
            Ui::KeepLeftToRight(edit);
            SendMessageW(edit, EM_SETLIMITTEXT, 0, 0);
            SetWindowTextW(edit, text_.c_str());
        }
        Button(LoadStringRes(IDS_BTN_CLOSE), clientW() - x - m.btnW(),
               buttonY, m.btnW(), m.btnH(), IDOK, true);
    }

    int InitialFocusId() const override { return 101; }
    const std::wstring& text_;
};

class App {
public:
    ~App() {
        if (autoSignatureThread_) CloseHandle(autoSignatureThread_);
        monitor_.Stop();
        ServiceInfo::Shutdown();
        AddrMacros::Shutdown();
    }
    bool Init(HINSTANCE inst, int cmdShow, bool startInTray);
    bool PreTranslate(MSG& msg);
    static LRESULT CALLBACK WndProcThunk(HWND, UINT, WPARAM, LPARAM);

private:
    friend struct AppStorageTestAccess;

    struct Selection {
        TrafficGroupKey group;
        bool         valid = false;
        bool         isGroup = true;
        std::wstring appPath, appName;
        uint64_t     ruleId = 0;
        std::wstring ruleName;
        bool         hasConn = false;
        ConnItem     conn;
    };

    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);
    void BuildMenu();
    // force = true: обновить безусловно (открытие меню — там же читается
    // состояние службы).
    void SyncMenu(bool force = false);
    void CreateBar();
    void LayoutBar(int width);
    int  BarHeight() const;
    int  Sc(int px) const { return MulDiv(px, static_cast<int>(dpi_), 96); }
    void Layout();
    void SetStatusParts(int width);
    void Tick();
    bool ApplyMonitorSnapshot();
    void RebuildRows();
    bool IsProcessExpanded(uint64_t proc) const {
        return expandedByDefault_ != (expansionOverrides_.count(proc) != 0);
    }
    void UpdateStatus();
    void UpdateTitle(bool force = false);
    void ShowDriverInstruction();
    void ResetSort();
    void ShowMenu(int row, POINT pt);
    void CopyRows(bool onlySelected);
    void KillSelected();
    // Разрыв ОДНОГО соединения. Правило не создаётся и вердикты не
    // выносятся: это точечное действие, а не решение по трафику.
    void InterruptSelected();
    // Цель разрыва по выделенной строке; valid = false, если строки
    // соединения нет (выбрана группа процесса либо ничего).
    ConnKill::Target KillTargetOf(const Selection& sel) const;
    void OnFilterChanged();
    void FocusFilter();
    void ApplyWindowIcon();
    void RebuildIcons();

    // Оформление списка. Меняется на ходу: контрол не пересоздаётся, снимок
    // соединений не перечитывается, выделение сохраняется.
    void ApplySkin(ListSkin s);
    void ApplyUiLang(UiLang lang);   // смена языка с перерисовкой интерфейса
    void ApplyPolicy(FirewallPolicy policy);

    // Единственный источник запросов решения: обязательства, накопленные
    // рабочим потоком по событиям on_connection_v4/v6.
    void DrainIngest();
    void ProcessAutoRules();
    void ExpireAutoRequests();
    void ScheduleAutoRulesTimer();
    bool HasManualRequestForRulePath(std::wstring_view path) const;
    void RulesChanged();
    void PumpAsk();
    void QueuePump();                       // отложенный PumpAsk
    // Перед открытием модального окна уже показанный запрос возвращается в
    // очередь с паузой: отключённый Ui::Modal владелец не оставляет его
    // доступным для параллельного решения.
    void DeferVisibleAsk();
    void ApplyDecision(const AskRequest& req, const AskDecision& decision);

    // Добавить правило ПЕРВЫМ в своей группе. RuleStore::Add() ставит новое
    // правило последним, а правило-заглушка из «Завершить» обязано
    // проверяться раньше уже существующих Allow-правил: иначе обещание
    // «приложение заблокировано» не выполняется.
    void AddRuleFirst(Rule r);

    // трей и завершение работы
    void ShowAtStartup(int cmdShow, bool startInTray);
    void HideToTray();
    void RestoreFromTray();
    bool ShowPendingBeforeExit();
    void RequestExit();
    void ShowTrayMenu(POINT pt);
    void UpdateTrayTip();
    bool WindowShown() const;
    void SetMonitorDisplay(bool on);

    // служба
    void RefreshServiceState();
    void DoServiceInstall();
    void DoServiceRemove();
    void DoServiceRun(bool start);

    Selection GetSelection() const;
    bool ResolveRule(const Selection& sel, Rule& out) const;
    Rule MakeRuleTemplate(const Selection& sel, bool global) const;
    void CreateRuleForSelection(bool global);
    void EditRuleForSelection();
    void DeleteRuleForSelection();
    void OpenAppRules(bool selectMatchedRule = false);
    void OpenGlobalRules();
    void OpenAllRules();
    void OpenSettings();
    void OpenDebug();
    void ReadDebugCounters(DebugCounters::Snapshot& out);

    // ---------------------------------------------------------------------
    // Слепок всего, от чего зависит вид меню и панели команд.
    //
    // SyncMenu вызывается на каждом такте, а меняться там нечему: пока
    // слепок тот же, галочки, подписи и доступность уже верны, и обращаться
    // к user32 (десятки вызовов) незачем.
    //
    // Все величины дешёвые: version() — атомарное чтение, ключ выделенной
    // строки берётся из уже построенного списка без копирования строк.
    // ---------------------------------------------------------------------
    struct MenuSig {
        bool     displayReady = false;
        bool     passive = false;
        bool     noFilter = false;
        ListSkin skin = ListSkin::Classic;
        FirewallPolicy policy = FirewallPolicy::Learning;
        bool     askReady = false;
        bool     askOpen = false;
        uint64_t rulesVersion = 0;
        int      sel = -1;
        TrafficGroupKey selOwner;
        bool     selAmbiguous = false;
        uint64_t selRule = 0;
        bool     selGroup = false;
        bool     selNoPath = true;
        bool     svcInstalled = false, svcRunning = false;
        bool     svcPending = false, svcAuto = false;
        DWORD    svcState = 0;

        bool operator==(const MenuSig&) const = default;
    };
    MenuSig menuSig_{};
    bool    menuSigValid_ = false;
    bool    driverUnavailable_ = false;

    // Текст частей строки состояния: SB_SETTEXT перерисовывает часть, поэтому
    // неизменившиеся не переписываем.
    std::wstring statusPart_[kStatusParts];

    struct StatusSig {
        uint64_t rulesVersion = 0;
        uint64_t ruleId = 0;
        uint64_t idleSeconds = 0;
        uint64_t packetSent = 0, packetRecv = 0;
        uint64_t driverEvents = 0;
        DWORD state = 0;
        BytesSource bytesFrom = BytesNone;
        int icmpOutType = -1, icmpOutCode = -1;
        int icmpInType = -1, icmpInCode = -1;
        bool icmpOutV6 = false, icmpInV6 = false;
        bool ruleGlobal = false;
        bool byPolicy = false;
        bool autoAllowedIcmp = false;
        FirewallPolicy policy = FirewallPolicy::Learning;
        bool blocked = false;
        bool processExited = false;
        bool finished = false;

        bool operator==(const StatusSig&) const = default;
    };

    struct ConnectionText {
        std::wstring remote;
        std::wstring local;
        std::wstring proto;
        std::wstring status;
        StatusSig statusSig;
        bool statusValid = false;
        uint64_t statusCheckedBuild = 0;
    };

    // Точный массив только для раскрытых строк и фильтра. При смене состава
    // готовый текст переносится по поколению; сортировка читает его по индексу.
    GenerationCache<ConnectionText> connectionText_;
    uint64_t rowBuildSeq_ = 0;
    std::unordered_map<uint64_t, RuleMatchInfo> ruleText_;
    uint64_t ruleTextVersion_ = 0;

    HINSTANCE    inst_   = nullptr;
    HWND         hwnd_   = nullptr;
    HWND         status_ = nullptr;
    HWND         edFilter_ = nullptr, btReset_ = nullptr, cbPassive_ = nullptr;
    HWND         btSettings_  = nullptr;
    HMENU        menu_   = nullptr;
    HMENU        policyMenu_ = nullptr;
    FirewallPolicy policy_ = FirewallPolicy::Learning;
    HACCEL       accel_  = nullptr;
    HFONT        uiFont_ = nullptr;
    HBRUSH       barBr_  = nullptr, lineBr_ = nullptr, winBr_ = nullptr;
    HICON        iconBig_ = nullptr, iconSmall_ = nullptr, iconTray_ = nullptr;
    UINT         dpi_    = 96;
    UINT         ingestMsg_ = 0;
    UINT         sourceMsg_ = 0;
    UINT         taskbarMsg_ = 0;
    UINT         activateMsg_ = 0;
    TreeList     list_;
    ProcessCache cache_;
    Monitor      monitor_;
    Snapshot     snap_;
    RuleStore    rules_;
    AskQueue     queue_;
    AskWindow    ask_;
    // Проверки выполняются последовательно и только для ожидающих запросов.
    struct AutoRequest {
        AskRequest request;
        ULONGLONG deadline = 0;
    };
    std::deque<AutoRequest> autoRequests_;
    std::unordered_set<AskRequestId, AskRequestIdHash> autoRequestIds_;
    std::unordered_set<AskRequestId, AskRequestIdHash> autoManualRequestIds_;
    std::shared_ptr<AutoSignatureCheck> autoSignature_;
    HANDLE       autoSignatureThread_ = nullptr;
    bool         autoSignatureAbandoned_ = false;
    bool         processingAutoRules_ = false;
    DebugWindow  debug_;
    TrayIcon     tray_;
    bool         trayClickWasShown_ = false;
    bool         trayDoubleClick_ = false;
    bool         askBusy_    = false;
    bool         exiting_    = false;   // истинный выход, а не сворачивание
    bool         exitPending_ = false;  // выход продолжится после решений
    FirewallX::ServiceState svc_;
    // Новые группы наследуют общий режим; ручные переключения — исключения из него.
    bool expandedByDefault_ = false;
    std::unordered_set<uint64_t> expansionOverrides_;

    int   sortCol_ = kSortNatural;
    bool  sortAsc_ = true;
    int   clicks_  = 0;
    bool  connOrderDirty_ = false;

    TreeList::RowKey selKey_;
    bool             selValid_ = false;
    bool             rowsReleased_ = false;
    std::wstring     warn_;
    std::wstring     dbNote_;
    std::wstring     policyHint_;
    std::wstring     filterText_;
    uint64_t         ruleSaveErrorVersion_ = 0;
    uint64_t         serviceInfoVersion_ = 0;
    uint64_t         interfaceGroupsVersion_ = 0;
    uint64_t         addrMacrosVersion_ = 0;
    uint32_t         processSweepTick_ = 0;
    size_t           shownProcs_ = 0, shownConns_ = 0;
};

void App::OpenDebug() {
    debug_.Show(hwnd_, inst_, [this](DebugCounters::Snapshot& out) {
        ReadDebugCounters(out);
    });
}

void App::ReadDebugCounters(DebugCounters::Snapshot& out) {
    FlowStore::Instance().ReadDebugCounters(out);
    Ingest::Instance().ReadDebugCounters(out);
    rules_.ReadDebugCounters(out);
    cache_.ReadDebugCounters(out);
    pmkext::ProcessTable::Instance().ReadDebugCounters(out);
    size_t systemProcesses = 0;
    if (TryGetSystemProcessCacheSize(systemProcesses))
        out.values[DebugCounters::SystemProcesses] = systemProcesses;
    // Эти коллекции принадлежат текущему UI-потоку, замки им не нужны.
    auto& v = out.values;
    v[DebugCounters::SnapshotProcesses] = snap_.procs.size();
    v[DebugCounters::SnapshotConnections] = snap_.conns.size();
    v[DebugCounters::TreeRows] = list_.rows().size();
    v[DebugCounters::ConnectionText] = connectionText_.size();
    v[DebugCounters::RuleText] = ruleText_.size();
    v[DebugCounters::ExpansionOverrides] = expansionOverrides_.size();
    v[DebugCounters::AskQueue] = queue_.size();
}

bool App::Init(HINSTANCE inst, int cmdShow, bool startInTray) {
    inst_ = inst;

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &App::WndProcThunk;
    wc.hInstance     = inst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;                 // фон рисуем сами
    // значок класса берём разделяемым: его не нужно освобождать, а Windows
    // использует его для панели задач и Alt+Tab до первого WM_SETICON
    wc.hIcon         = LoadIconW(inst, MAKEINTRESOURCEW(IDI_ICON1));
    wc.hIconSm       = wc.hIcon;
    // по этому имени класса запущенная копия отыскивается новой (SingleInstance)
    wc.lpszClassName = AppInfo::kMainWindowClass;
    if (!RegisterClassExW(&wc)) return false;

    const UINT dpi = GetDpiForSystem() ? GetDpiForSystem() : 96;
    RECT work{ 0, 0, 1600, 900 };
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int wantW = MulDiv(1520, static_cast<int>(dpi), 96);
    const int wantH = MulDiv(840,  static_cast<int>(dpi), 96);
    const int w = std::min<int>(wantW, work.right - work.left);
    const int h = std::min<int>(wantH, work.bottom - work.top);

    // При появлении полосы прокрутки список вызывает стирание фона родителя.
    // Исключаем дочерние окна из заливки, чтобы она не затирала таблицу.
    hwnd_ = CreateWindowExW(0, AppInfo::kMainWindowClass, AppInfo::WindowTitle().c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        work.left + ((work.right - work.left) - w) / 2,
        work.top  + ((work.bottom - work.top) - h) / 2,
        w, h, nullptr, nullptr, inst, this);
    if (!hwnd_) return false;

    ACCEL acc[] = {
        { FVIRTKEY,                    VK_F5,     IDM_REFRESH },
        { FVIRTKEY,                    VK_DELETE, IDM_KILL_CONN },
        { FVIRTKEY | FCONTROL,         'F',       IDM_FOCUS_FILTER },
        { FVIRTKEY | FCONTROL,         'R',       IDM_RULES_ALL },
        { FVIRTKEY | FCONTROL | FSHIFT,'R',       IDM_RULES_APP },
        { FVIRTKEY | FCONTROL,         'G',       IDM_RULES_GLOBAL },
        { FVIRTKEY | FCONTROL,         'N',       IDM_RULE_CREATE },
        { FVIRTKEY | FCONTROL | FSHIFT,'N',       IDM_RULE_CREATE_GLOBAL },
        { FVIRTKEY | FCONTROL,         'E',       IDM_RULE_EDIT },
        { FVIRTKEY | FCONTROL,         'L',       IDM_SHOW_PASSIVE },
        { FVIRTKEY | FCONTROL,         'W',       IDM_ASK_NOW },
        { FVIRTKEY | FCONTROL,         'D',       IDM_SKIN_TOGGLE },
        { FVIRTKEY | FCONTROL,         'H',       IDM_TRAY_HIDE },
    };
    accel_ = CreateAcceleratorTableW(acc, static_cast<int>(std::size(acc)));

    ShowAtStartup(cmdShow, startInTray);
    return true;
}

void App::ShowAtStartup(int cmdShow, bool startInTray) {
    if (startInTray) {
        // Если Explorer ещё не готов, TaskbarCreated восстановит значок позже.
        SetMonitorDisplay(false);
        UpdateTrayTip();
    } else {
        ShowWindow(hwnd_, cmdShow);
        UpdateWindow(hwnd_);
    }
}

LRESULT CALLBACK App::WndProcThunk(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(l);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
    }
    auto* self = reinterpret_cast<App*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    return self ? self->WndProc(h, m, w, l) : DefWindowProcW(h, m, w, l);
}

bool App::PreTranslate(MSG& msg) {
    const HWND root = msg.hwnd ? GetAncestor(msg.hwnd, GA_ROOT) : nullptr;

    // окно запроса немодальное: ему нужна навигация Tab/Enter
    if (ask_.visible() && root == ask_.hwnd())
        return IsDialogMessageW(ask_.hwnd(), &msg) != 0;

    if (debug_.hwnd() && root == debug_.hwnd())
        return IsDialogMessageW(debug_.hwnd(), &msg) != 0;

    if (!hwnd_ || !accel_ || root != hwnd_) return false;

    if (msg.hwnd == list_.hwnd() && msg.message == WM_KEYDOWN &&
        msg.wParam == 'C' && (GetKeyState(VK_CONTROL) & 0x8000)) {
        CopyRows(true);
        return true;
    }

    if (edFilter_ && msg.hwnd == edFilter_) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            SetWindowTextW(edFilter_, L"");
            SetFocus(list_.hwnd());
            return true;
        }
        const bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool fkey = msg.wParam >= VK_F1 && msg.wParam <= VK_F12;
        if (!ctrl && !fkey) return false;      // обычный ввод — полю
    }
    return TranslateAcceleratorW(hwnd_, accel_, &msg) != 0;
}

void App::BuildMenu() {
    menu_ = CreateMenu();
    policyMenu_ = nullptr;
    menuSigValid_ = false;
    if (!menu_) {
        SetMenu(hwnd_, nullptr);
        return;
    }

    HMENU view = CreatePopupMenu();
    AppendMenuW(view, MF_STRING, IDM_REFRESH,      LoadStringRes(IDS_MENU_VIEW_REFRESH).c_str());
    AppendMenuW(view, MF_STRING, IDM_FOCUS_FILTER, LoadStringRes(IDS_MENU_VIEW_FILTER).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, IDM_EXPAND_ALL,   LoadStringRes(IDS_MENU_VIEW_EXPAND).c_str());
    AppendMenuW(view, MF_STRING, IDM_COLLAPSE_ALL, LoadStringRes(IDS_MENU_VIEW_COLLAPSE).c_str());
    AppendMenuW(view, MF_STRING, IDM_SORT_DEFAULT, LoadStringRes(IDS_MENU_VIEW_SORT_DEFAULT).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, IDM_SHOW_PASSIVE,
                LoadStringRes(IDS_MENU_VIEW_SHOW_PASSIVE).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);

    // Оформление списка. Подменю даёт явный выбор и показывает, какой вид
    // включён; отдельный пункт-переключатель нужен горячей клавише.
    HMENU skin = CreatePopupMenu();
    AppendMenuW(skin, MF_STRING, IDM_SKIN_MODERN,  LoadStringRes(IDS_MENU_VIEW_SKIN_MODERN).c_str());
    AppendMenuW(skin, MF_STRING, IDM_SKIN_CLASSIC, LoadStringRes(IDS_MENU_VIEW_SKIN_CLASSIC).c_str());
    Ui::AppendSubMenu(view, skin, LoadStringRes(IDS_MENU_VIEW_SKIN_SUB).c_str());
    AppendMenuW(view, MF_STRING, IDM_SKIN_TOGGLE,
                LoadStringRes(IDS_MENU_VIEW_SKIN_TOGGLE).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);

    // Язык интерфейса. Подменю даёт выбор и показывает галочкой текущий язык;
    // иконки — флаги стран. Пункты создаются из массива UiLangs, поэтому
    // добавление нового языка в StringRes автоматически даёт пункт меню.
    HMENU lang = CreatePopupMenu();
    {
        size_t count = 0;
        const UiLangInfo* langs = UiLangs(count);
        const UiLang cur = CurrentUiLang();
        for (size_t i = 0; i < count; ++i) {
            const UINT cmd = IDM_LANG_FIRST + static_cast<UINT>(i);
            AppendMenuW(lang, MF_STRING, cmd, langs[i].nativeName);
            if (langs[i].lang == cur)
                CheckMenuItem(lang, cmd, MF_BYCOMMAND | MF_CHECKED);
            // Иконка из ресурсов через SetMenuItemInfo с HBMMENU_CALLBACK не работает,
            // поэтому преобразуем иконку в bitmap вручную через рисование в DC
            HICON icon = static_cast<HICON>(
                LoadImageW(GetModuleHandleW(nullptr),
                           MAKEINTRESOURCEW(langs[i].flagIconId),
                           IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                           GetSystemMetrics(SM_CYSMICON), 0));
            if (icon) {
                const int cx = GetSystemMetrics(SM_CXSMICON);
                const int cy = GetSystemMetrics(SM_CYSMICON);
                HDC hdcScreen = GetDC(nullptr);
                HDC hdcMem = CreateCompatibleDC(hdcScreen);
                HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, cx, cy);
                HBITMAP hbmOld = static_cast<HBITMAP>(SelectObject(hdcMem, hbm));

                // Заливка фона цветом меню перед отрисовкой иконки
                HBRUSH hbrMenu = GetSysColorBrush(COLOR_MENU);
                RECT rc = {0, 0, cx, cy};
                FillRect(hdcMem, &rc, hbrMenu);

                DrawIconEx(hdcMem, 0, 0, icon, cx, cy, 0, nullptr, DI_NORMAL);
                SelectObject(hdcMem, hbmOld);
                DeleteDC(hdcMem);
                ReleaseDC(nullptr, hdcScreen);
                DestroyIcon(icon);

                MENUITEMINFOW mii{};
                mii.cbSize = sizeof(mii);
                mii.fMask = MIIM_BITMAP;
                mii.hbmpItem = hbm;
                if (!SetMenuItemInfoW(lang, cmd, FALSE, &mii)) DeleteObject(hbm);
            }
        }
    }
    Ui::AppendSubMenu(view, lang, LoadStringRes(IDS_MENU_VIEW_LANG_SUB).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(view, MF_STRING, IDM_TRAY_HIDE, LoadStringRes(IDS_MENU_VIEW_HIDE_TRAY).c_str());
    AppendMenuW(view, MF_STRING, IDM_EXIT,      LoadStringRes(IDS_MENU_VIEW_EXIT).c_str());
    Ui::AppendSubMenu(menu_, view, LoadStringRes(IDS_MENU_VIEW_TITLE).c_str());

    HMENU rules = CreatePopupMenu();
    AppendMenuW(rules, MF_STRING, IDM_RULES_ALL, LoadStringRes(IDS_MENU_RULES_EDITOR).c_str());
    AppendMenuW(rules, MF_STRING, IDM_RULES_GLOBAL,
                LoadStringRes(IDS_MENU_RULES_GLOBAL).c_str());
    AppendMenuW(rules, MF_STRING, IDM_RULES_APP,
                LoadStringRes(IDS_MENU_RULES_APP).c_str());
    AppendMenuW(rules, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(rules, MF_STRING, IDM_RULE_CREATE,
                LoadStringRes(IDS_MENU_RULES_CREATE).c_str());
    AppendMenuW(rules, MF_STRING, IDM_RULE_CREATE_GLOBAL,
                LoadStringRes(IDS_MENU_RULES_CREATE_GLOBAL).c_str());
    AppendMenuW(rules, MF_STRING, IDM_RULES_GENERATE,
                LoadStringRes(IDS_RULE_GENERATE).c_str());
    AppendMenuW(rules, MF_STRING, IDM_RULE_EDIT,   LoadStringRes(IDS_MENU_RULES_EDIT).c_str());
    AppendMenuW(rules, MF_STRING, IDM_RULE_DELETE, LoadStringRes(IDS_MENU_RULES_DELETE).c_str());
    AppendMenuW(rules, MF_SEPARATOR, 0, nullptr);
    // Настройки «спрашивать / не спрашивать» больше нет: в очереди лежат
    // только обязательства по событиям транспорта, и отказаться от ответа
    // нельзя — соединение осталось бы без вердикта навсегда.
    AppendMenuW(rules, MF_STRING, IDM_ASK_NOW,
                LoadStringRes(IDS_MENU_RULES_ASK_NOW).c_str());
    AppendMenuW(rules, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(rules, MF_STRING, IDM_RULES_CLEAR, LoadStringRes(IDS_MENU_RULES_CLEAR).c_str());
    Ui::AppendSubMenu(menu_, rules, LoadStringRes(IDS_MENU_RULES_TITLE).c_str());

    policyMenu_ = CreatePolicyMenu(policy_);
    if (!Ui::AppendSubMenu(menu_, policyMenu_, LoadStringRes(IDS_MENU_POLICY).c_str()))
        policyMenu_ = nullptr;

    HMENU svc = CreatePopupMenu();
    AppendMenuW(svc, MF_STRING | MF_GRAYED, IDM_SVC_STATE, LoadStringRes(IDS_MENU_SVC_STATE).c_str());
    AppendMenuW(svc, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(svc, MF_STRING, IDM_SVC_INSTALL, LoadStringRes(IDS_MENU_SVC_INSTALL).c_str());
    AppendMenuW(svc, MF_STRING, IDM_SVC_REMOVE,  LoadStringRes(IDS_MENU_SVC_REMOVE).c_str());
    AppendMenuW(svc, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(svc, MF_STRING, IDM_SVC_START, LoadStringRes(IDS_MENU_SVC_START).c_str());
    AppendMenuW(svc, MF_STRING, IDM_SVC_STOP,  LoadStringRes(IDS_MENU_SVC_STOP).c_str());
    Ui::AppendSubMenu(menu_, svc, LoadStringRes(IDS_MENU_SVC_TITLE).c_str());

    HMENU help = CreatePopupMenu();
    AppendMenuW(help, MF_STRING, IDM_DEBUG, LoadStringRes(IDS_MENU_HELP_DEBUG).c_str());
    AppendMenuW(help, MF_STRING, IDM_ABOUT, LoadStringRes(IDS_MENU_HELP_ABOUT).c_str());
    Ui::AppendSubMenu(menu_, help, LoadStringRes(IDS_MENU_HELP_TITLE).c_str());

    SetMenu(hwnd_, menu_);
}

void App::SyncMenu(bool force) {
    if (!WindowShown()) return;
	MenuSig sig;
    sig.displayReady = snap_.displayReady;
    sig.passive      = monitor_.showPassive();
    sig.noFilter     = filterText_.empty();
    sig.skin         = list_.skin();
    sig.policy       = policy_;
    sig.askReady     = queue_.ready() != 0;
    sig.askOpen      = ask_.visible();
    sig.rulesVersion = rules_.version();
    sig.sel          = list_.Selected();
    if (sig.sel >= 0 && sig.sel < static_cast<int>(list_.rows().size())) {
        const TreeList::Row& row = list_.rows()[static_cast<size_t>(sig.sel)];
        sig.selOwner  = row.key.group;
        sig.selAmbiguous = row.key.ownerAmbiguous;
        sig.selRule   = row.ruleId;
        sig.selGroup  = row.isGroup;
        sig.selNoPath = !row.pathKnown;
    }
    sig.svcInstalled = svc_.installed;
    sig.svcRunning   = svc_.running;
    sig.svcPending   = svc_.pending;
    sig.svcAuto      = svc_.autoStart;
    sig.svcState     = svc_.state;

    // Сигнатура уже собрана; если она прежняя, обновлять пункты меню не нужно.
    if (!force && menuSigValid_ && sig == menuSig_) [[likely]] return;
    menuSig_ = sig;
    menuSigValid_ = true;

    CheckMenuItem(menu_, IDM_SHOW_PASSIVE,
                  MF_BYCOMMAND | (monitor_.showPassive() ? MF_CHECKED : MF_UNCHECKED));
    EnableMenuItem(menu_, IDM_ASK_NOW, MF_BYCOMMAND |
                   ((queue_.ready() && !ask_.visible()) ? MF_ENABLED : MF_GRAYED));

    // Оформление: отметка-точка, а не галочка — выбор взаимоисключающий.
    CheckMenuRadioItem(menu_, IDM_SKIN_MODERN, IDM_SKIN_CLASSIC,
                       list_.skin() == ListSkin::Modern ? IDM_SKIN_MODERN
                                                        : IDM_SKIN_CLASSIC,
                       MF_BYCOMMAND);

    for (const auto& item : kPolicyCommands) {
        CheckMenuItem(policyMenu_, item.command, MF_BYCOMMAND |
                      (item.policy == policy_ ? MF_CHECKED : MF_UNCHECKED));
    }

    if (cbPassive_)
        SendMessageW(cbPassive_, BM_SETCHECK,
                     monitor_.showPassive() ? BST_CHECKED : BST_UNCHECKED, 0);
    if (btReset_) EnableWindow(btReset_, !filterText_.empty());

    const Selection sel = GetSelection();
    Rule dummy;
    const bool canApp  = sel.valid && (!sel.appPath.empty() || sel.group.isNdis());
    const bool hasRule = ResolveRule(sel, dummy);

    EnableMenuItem(menu_, IDM_RULES_APP,   MF_BYCOMMAND | (canApp ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu_, IDM_RULE_CREATE, MF_BYCOMMAND | (canApp ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu_, IDM_RULE_EDIT,   MF_BYCOMMAND | (hasRule ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu_, IDM_RULE_DELETE, MF_BYCOMMAND | (hasRule ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu_, IDM_RULES_CLEAR, MF_BYCOMMAND |
                   (rules_.Count() ? MF_ENABLED : MF_GRAYED));

    // служба
    const std::wstring state = LoadStringRes(IDS_SVC_STATE_PREFIX) + svc_.Text() +
        (svc_.installed && svc_.autoStart ? LoadStringRes(IDS_SVC_AUTOSTART_SUFFIX) : L"");
    MENUITEMINFOW mii{ sizeof(mii) };
    mii.fMask = MIIM_STRING;
    mii.dwTypeData = const_cast<LPWSTR>(state.c_str());
    SetMenuItemInfoW(menu_, IDM_SVC_STATE, FALSE, &mii);

    EnableMenuItem(menu_, IDM_SVC_INSTALL, MF_BYCOMMAND |
                   (svc_.installed ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(menu_, IDM_SVC_REMOVE,  MF_BYCOMMAND |
                   (svc_.installed ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu_, IDM_SVC_START,   MF_BYCOMMAND |
                   ((svc_.installed && !svc_.running && !svc_.pending) ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu_, IDM_SVC_STOP,    MF_BYCOMMAND |
                   ((svc_.installed && svc_.running) ? MF_ENABLED : MF_GRAYED));
}

int App::BarHeight() const {
    return Sc(9) * 2 + Sc(24);
}

void App::CreateBar() {
    uiFont_ = Ui::MessageFont(dpi_);
    const auto add = [&](const wchar_t* cls, const wchar_t* text, DWORD style,
                         DWORD ex, int id) {
        HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style,
                                 0, 0, 10, 10, hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<UINT_PTR>(id)),
                                 inst_, nullptr);
        if (c && uiFont_)
            SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont_), TRUE);
        return c;
    };

    edFilter_ = add(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL,
                    WS_EX_CLIENTEDGE, IDC_FILTER);
    if (edFilter_) {
        Ui::ApplyLayout(edFilter_);
        // Подсказка копируется системой внутрь элемента, временной строки хватает
        const std::wstring cue = LoadStringRes(IDS_FILTER_PLACEHOLDER);
        SendMessageW(edFilter_, EM_SETCUEBANNER, TRUE,
                     reinterpret_cast<LPARAM>(cue.c_str()));
    }
    btReset_  = add(L"BUTTON", LoadStringRes(IDS_BTN_RESET).c_str(),
                    WS_TABSTOP | BS_PUSHBUTTON, 0, IDC_RESET);
    cbPassive_= add(L"BUTTON", LoadStringRes(IDS_BTN_SHOW_PASSIVE).c_str(),
                    WS_TABSTOP | BS_AUTOCHECKBOX, 0, IDC_PASSIVE);
    btSettings_  = add(L"BUTTON", LoadStringRes(IDS_MENU_SETTINGS).c_str(),
                    WS_TABSTOP | BS_PUSHBUTTON, 0, IDM_SETTINGS);
    EnableWindow(btReset_, FALSE);
}

void App::LayoutBar(int width) {
    if (!edFilter_) return;
    const int pad = Sc(9);
    const int hCtl = Sc(24);
    const int y = pad;
    const int gap = Sc(6);

    int x = pad;
    const int filterW = std::min(Sc(330), std::max(Sc(150), width / 3));
    MoveWindow(edFilter_, x, y, filterW, hCtl, TRUE);
    x += filterW + gap;
    const int resetW = Sc(66);
    MoveWindow(btReset_, x, y, resetW, hCtl, TRUE);
    x += resetW + Sc(14);
    const int passW = Sc(186);
    MoveWindow(cbPassive_, x, y + Sc(3), passW, Sc(20), TRUE);

    const int bw1 = Sc(96);
    MoveWindow(btSettings_, width - pad - bw1, y, bw1, hCtl, TRUE);
}

LRESULT App::WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    // сообщение от Ingest: появились соединения без правила
    if (ingestMsg_ && msg == ingestMsg_) {
        DrainIngest();
        return 0;
    }
    // Рабочий поток переключил источник driver records. Tick немедленно
    // запрашивает фоновое обновление таблиц, не ожидая секундного таймера.
    if (sourceMsg_ && msg == sourceMsg_) {
        Tick();
        return 0;
    }
    // Explorer перезапустился — значок в трее нужно добавить заново
    if (taskbarMsg_ && msg == taskbarMsg_) {
        tray_.Restore();
        UpdateTrayTip();
        return 0;
    }
    // Запущена вторая копия: она передала нам право на передний план и вышла
    if (activateMsg_ && msg == activateMsg_) {
        RestoreFromTray();
        return 0;
    }
    // Тяжёлый системный проход завершён в Monitor worker. Здесь остаётся только
    // O(1)-обмен снимков и построение реально отображаемых строк.
    if (msg == kMsgMonitorReady) {
        ApplyMonitorSnapshot();
        return 0;
    }

    switch (msg) {
    case kMsgPumpAsk:
        PumpAsk();
        return 0;

    case kMsgContinueExit:
        if (exitPending_) RequestExit();
        return 0;

    case kMsgDriverStartFailed:
        if (!exiting_ && !exitPending_) ShowDriverInstruction();
        return 0;

    case kMsgServiceInfoChanged:
        // Worker уже опубликовал полный снимок. Даже при прежнем наборе служб
        // опрос мог подтвердить, что скрытый pending действительно требует Ask.
        Tick();
        DrainIngest();
        return 0;

    case kMsgTray: {
        // NOTIFYICON_VERSION_4: событие в LOWORD(lParam), координаты в wParam
        const UINT event = LOWORD(lp);
        switch (event) {
        case WM_LBUTTONDOWN:
            // Первый щелчок может открыть окно до прихода двойного щелчка.
            trayClickWasShown_ = WindowShown();
            trayDoubleClick_ = false;
            break;
        case NIN_SELECT:
            // NIN_SELECT после двойного щелчка не должен снова открыть окно.
            if (!trayDoubleClick_) RestoreFromTray();
            break;
        case NIN_KEYSELECT:
            RestoreFromTray();
            break;
        case WM_LBUTTONDBLCLK:
            trayDoubleClick_ = true;
            if (trayClickWasShown_) HideToTray();
            else RestoreFromTray();
            break;
        case WM_CONTEXTMENU:
        case WM_RBUTTONUP: {
            POINT pt{ GET_X_LPARAM(wp), GET_Y_LPARAM(wp) };
            ShowTrayMenu(pt);
            break;
        }
        default:
            break;
        }
        return 0;
    }

    case WM_CREATE: {
        hwnd_ = h;                       // до BuildMenu/Layout: иначе SetMenu(nullptr)
        ServiceInfo::SetNotification(h, kMsgServiceInfoChanged);
        dpi_ = GetDpiForWindow(h);
        if (!dpi_) dpi_ = 96;

        taskbarMsg_  = RegisterWindowMessageW(L"TaskbarCreated");
        activateMsg_ = FirewallX::SingleInstance::ActivateMessage();

        RebuildIcons();
        // Язык загружается из настроек до построения любого интерфейса: иначе
        // LoadStringRes вернул бы язык по умолчанию (от системы), а не выбранный.
        SetUiLang(UiLangSetting::Load());
        Ui::ApplyLayout(h);
        // Для оконного режима читаем общую политику до меню и запуска транспорта.
        policy_ = FirewallPolicySetting::Load();
        // Оформление выбирается ДО создания контрола: тогда первая же
        // раскладка выполняется в нужном виде, без промежуточной перерисовки.
        list_.SetSkin(ListSkinSetting::Load());
        expandedByDefault_ = Settings::GetBool(Settings::Key::kListExpanded, false);
        list_.Create(h, inst_, kListId);
        list_.SetIconSize(Sc(16));
        list_.onToggle = [this](int row) {
            const auto& rows = list_.rows();
            if (row < 0 || row >= static_cast<int>(rows.size())) return;
            const TreeList::Row& item = rows[static_cast<size_t>(row)];
            const uint64_t proc = ProcIdentity(item.key.group, item.key.ownerAmbiguous);
            if (!expansionOverrides_.erase(proc)) expansionOverrides_.insert(proc);
            RebuildRows();
        };
        list_.onColumnClick = [this](int col) {
            if (col != sortCol_) { sortCol_ = col; sortAsc_ = DefaultAscForColumn(col); clicks_ = 1; }
            else if (clicks_ == 1) { sortAsc_ = !sortAsc_; clicks_ = 2; }
            else { ResetSort(); RebuildRows(); UpdateStatus(); return; }
            list_.SetSortIndicator(sortCol_, sortAsc_);
            RebuildRows();
            UpdateStatus();
        };
        list_.onSelectionChanged = [this](int row) {
            const auto& rows = list_.rows();
            if (row >= 0 && row < static_cast<int>(rows.size())) {
                selKey_ = rows[static_cast<size_t>(row)].key;
                selValid_ = true;
            }
            SyncMenu();
        };
        // Двойной щелчок по соединению открывает группу сработавшего правила.
        // Строка выбирается принудительно: OpenAppRules читает выделение
        // списка, а не сохранённый ключ.
        list_.onActivate = [this](int row) {
            list_.Select(row);
            const auto& rows = list_.rows();
            if (row >= 0 && row < static_cast<int>(rows.size())) {
                selKey_ = rows[static_cast<size_t>(row)].key;
                selValid_ = true;
            }
            OpenAppRules(true);
        };
        ask_.onDecision = [this](const AskRequest& r, const AskDecision& decision) {
            ApplyDecision(r, decision);
        };

        status_ = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP | SBARS_TOOLTIPS,
            0, 0, 0, 0, h, nullptr, inst_, nullptr);

        CreateBar();
        BuildMenu();
        ApplyWindowIcon();

        tray_.Create(h, kMsgTray, kTrayIconId, iconTray_,
                     AppInfo::NameWithVersion());

        std::wstring dbErr;
        if (rules_.AttachDatabase(ModuleDirFile(AppInfo::kRulesDb), dbErr)) {
            dbNote_ = LoadStringRes(IDS_DB_OK);
        } else {
            dbNote_ = LoadStringRes(IDS_DB_ERROR);
            warn_ += LoadStringRes(IDS_DB_RULES_PREFIX) + dbErr + L"; ";
        }
        ruleSaveErrorVersion_ = rules_.version();

        // Службы нужны и для подписей таблицы, даже без сервисных правил.
        // Первый снимок готовится до запуска драйверного маршрута, дальнейшее
        // периодическое обновление выполняет фоновый монитор.
        ServiceInfo::Invalidate();
        serviceInfoVersion_ = ServiceInfo::Version(true);
        ServiceInfo::SetMonitoring(true);

        // Единый сетевой снимок готов до приёма соединений. Дальше его
        // обновляют уведомления Windows, а matcher только читает данные.
        addrMacrosVersion_ = AddrMacros::Version(true);

        // приём событий из чужого потока: правила уже загружены
        Ingest::Instance().Attach(&rules_, h, IngestMode::Desktop, policy_);
        ingestMsg_ = Ingest::Instance().Message();
        sourceMsg_ = Ingest::Instance().SourceMessage();

        monitor_.SetRuleStore(&rules_);
        monitor_.SetPolicy(policy_);
        monitor_.SetBandwidthRequest(portmaster_request_bandwidth_stats);
        monitor_.Start(warn_, h, kMsgMonitorReady);
        RefreshServiceState();
        SyncMenu();

        ResetSort();
        Layout();
        Tick();
        SetTimer(h, kTimerId, kInterval, nullptr);
        portmaster_start(h, kMsgDriverStartFailed);
        return 0;
    }
    case WM_ERASEBKGND: {
        HDC dc = reinterpret_cast<HDC>(wp);
        RECT rc{}; GetClientRect(h, &rc);
        if (!barBr_)  barBr_  = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
        if (!lineBr_) lineBr_ = CreateSolidBrush(RGB(0xDF, 0xDF, 0xE3));
        if (!winBr_)  winBr_  = CreateSolidBrush(GetSysColor(COLOR_WINDOW));

        RECT bar = rc;
        bar.bottom = std::min<LONG>(BarHeight(), rc.bottom);
        FillRect(dc, &bar, barBr_);
        RECT line{ rc.left, bar.bottom - 1, rc.right, bar.bottom };
        FillRect(dc, &line, lineBr_);
        RECT rest{ rc.left, bar.bottom, rc.right, rc.bottom };
        if (rest.bottom > rest.top) FillRect(dc, &rest, winBr_);
        return 1;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wp);
        if (!barBr_) barBr_ = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
        SetBkColor(dc, GetSysColor(COLOR_BTNFACE));
        SetTextColor(dc, GetSysColor(COLOR_BTNTEXT));
        return reinterpret_cast<LRESULT>(barBr_);
    }
    case WM_SHOWWINDOW:
        SetMonitorDisplay(wp != 0 && !IsIconic(h));
        break;

    case WM_SYSCOMMAND:
        // Кнопка окна передаёт координаты нажатия, панель задач — нулевой lParam.
        // Проверяем также окно под курсором: прочие команды сворачивания не меняем.
        if ((wp & 0xFFF0) == SC_MINIMIZE && lp == 0 &&
            GetForegroundWindow() != h) {
            POINT pt{};
            wchar_t className[64]{};
            if (GetCursorPos(&pt) &&
                GetClassNameW(GetAncestor(WindowFromPoint(pt), GA_ROOT),
                              className, static_cast<int>(std::size(className))) &&
                (wcscmp(className, L"Shell_TrayWnd") == 0 ||
                 wcscmp(className, L"Shell_SecondaryTrayWnd") == 0)) {
                HideToTray();
                return 0;
            }
        }
        break;

    case WM_SIZE:
        SetMonitorDisplay(WindowShown());
        SendMessageW(status_, WM_SIZE, 0, 0);
        Layout();
        return 0;

    case WM_EXITSIZEMOVE:
        Layout();
        return 0;

    case WM_INITMENUPOPUP:
        // состояние службы читается только при открытии меню: опрос SCM
        // каждую секунду был бы напрасной работой
        RefreshServiceState();
        SyncMenu(true);
        break;

    case WM_MENUSELECT: {
        // При наведении или выборе с клавиатуры показываем смысл политики
        // в строке состояния. После закрытия меню возвращаем обычные счётчики.
        const UINT flags = HIWORD(wp);
        if ((flags & MF_POPUP) == 0 && flags != 0xFFFF) {
            for (const auto& item : kPolicyCommands) {
                if (item.command != LOWORD(wp)) continue;
                policyHint_ = FirewallPolicies::Description(item.policy);
                UpdateStatus();
                return 0;
            }
        }
        policyHint_.clear();
        UpdateStatus();
        return 0;
    }

    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
        UINT dpi = hwnd_ ? GetDpiForWindow(hwnd_) : GetDpiForSystem();
        if (!dpi) dpi = 96;
        mmi->ptMinTrackSize.x = MulDiv(980, static_cast<int>(dpi), 96);
        mmi->ptMinTrackSize.y = MulDiv(400, static_cast<int>(dpi), 96);
        return 0;
    }
    case WM_DPICHANGED: {
        const RECT* sug = reinterpret_cast<const RECT*>(lp);
        dpi_ = GetDpiForWindow(h);
        if (!dpi_) dpi_ = 96;
        SetWindowPos(h, nullptr, sug->left, sug->top,
                     sug->right - sug->left, sug->bottom - sug->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        uiFont_ = Ui::MessageFont(dpi_);
        for (HWND c : { edFilter_, btReset_, cbPassive_, btSettings_, status_ })
            if (c && uiFont_)
                SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont_), TRUE);
        RebuildIcons();
        list_.OnDpiChanged();
        ApplyWindowIcon();
        Layout();
        Tick();
        return 0;
    }
    case WM_SETTINGCHANGE:
    case WM_THEMECHANGED:
        if (msg == WM_SETTINGCHANGE) AddrMacros::Invalidate();
        list_.OnDpiChanged();
        if (barBr_)  { DeleteObject(barBr_);  barBr_  = nullptr; }
        if (winBr_)  { DeleteObject(winBr_);  winBr_  = nullptr; }
        InvalidateRect(h, nullptr, TRUE);
        Layout();
        return 0;

    case WM_TIMER:
        if (wp == kTimerId || wp == kAutoRulesTimerId) {
            if (wp == kAutoRulesTimerId) KillTimer(h, kAutoRulesTimerId);
            Tick();
        }
        return 0;

    case WM_NOTIFY: {
        LRESULT res = 0;
        if (list_.OnNotify(reinterpret_cast<LPNMHDR>(lp), res)) return res;
        break;
    }
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wp) == list_.hwnd()) {
            POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            if (pt.x == -1 && pt.y == -1) {
                RECT rc; GetWindowRect(list_.hwnd(), &rc);
                pt = { Ui::IsRightToLeft() ? rc.right - 40 : rc.left + 40, rc.top + 40 };
            } else {
                POINT cl = pt;
                MapWindowPoints(nullptr, list_.hwnd(), &cl, 1);
                LVHITTESTINFO hti{};
                hti.pt = cl;
                const int idx = ListView_HitTest(list_.hwnd(), &hti);
                if (idx >= 0 && idx < static_cast<int>(list_.rows().size())) {
                    list_.Select(idx);
                    selKey_ = list_.rows()[static_cast<size_t>(idx)].key;
                    selValid_ = true;
                }
            }
            ShowMenu(list_.Selected(), pt);
            return 0;
        }
        break;

    case WM_COMMAND: {
        const int id = LOWORD(wp), code = HIWORD(wp);
        if (id == IDC_FILTER && code == EN_CHANGE) { OnFilterChanged(); return 0; }
        switch (id) {
        case IDC_RESET:
            SetWindowTextW(edFilter_, L"");
            SetFocus(list_.hwnd());
            return 0;
        case IDC_PASSIVE:
            monitor_.SetShowPassive(
                SendMessageW(cbPassive_, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SyncMenu();
            Tick();
            return 0;

        case IDM_SKIN_MODERN:  ApplySkin(ListSkin::Modern);  return 0;
        case IDM_SKIN_CLASSIC: ApplySkin(ListSkin::Classic); return 0;
        case IDM_SKIN_TOGGLE:
            ApplySkin(list_.skin() == ListSkin::Modern ? ListSkin::Classic
                                                       : ListSkin::Modern);
            return 0;
        }

        for (const auto& item : kPolicyCommands) {
            if (id == static_cast<int>(item.command)) {
                ApplyPolicy(item.policy);
                return 0;
            }
        }

        // Язык интерфейса: команды генерируются динамически в BuildMenu, поэтому
        // вместо перечисления каждой проверяем диапазон начиная с IDM_LANG_FIRST.
        if (id >= IDM_LANG_FIRST) {
            size_t count = 0;
            const UiLangInfo* langs = UiLangs(count);
            const size_t idx = static_cast<size_t>(id - IDM_LANG_FIRST);
            if (idx < count) {
                ApplyUiLang(langs[idx].lang);
                return 0;
            }
        }

        switch (id) {
        case IDM_TRAY_HIDE: HideToTray();      return 0;
        case IDM_TRAY_SHOW: RestoreFromTray(); return 0;

        case IDM_SVC_INSTALL: DoServiceInstall();   return 0;
        case IDM_SVC_REMOVE:  DoServiceRemove();    return 0;
        case IDM_SVC_START:   DoServiceRun(true);   return 0;
        case IDM_SVC_STOP:    DoServiceRun(false);  return 0;

        case IDM_ASK_NOW:
            PumpAsk();
            return 0;

        case IDM_FOCUS_FILTER: FocusFilter(); return 0;
        case IDM_EXPAND_ALL:
        case IDM_COLLAPSE_ALL:
            expandedByDefault_ = id == IDM_EXPAND_ALL;
            expansionOverrides_.clear();
            TrimHashTable(expansionOverrides_);
            Settings::SetBool(Settings::Key::kListExpanded, expandedByDefault_);
            RebuildRows();
            return 0;
        case IDM_SORT_DEFAULT: ResetSort(); RebuildRows(); UpdateStatus(); return 0;
        case IDM_COPY_ROW: CopyRows(true);  return 0;
        case IDM_COPY_ALL: CopyRows(false); return 0;
        case IDM_KILL_CONN:
            // Delete действует только в списке и только на одно доступное
            // для разрыва соединение; остальные строки молча пропускаем.
            if (code == 1 &&
                (GetFocus() != list_.hwnd() ||
                 ListView_GetSelectedCount(list_.hwnd()) != 1 ||
                 ConnKill::Check(KillTargetOf(GetSelection())) != ConnKill::Denial::None))
                return 0;
            InterruptSelected();
            return 0;
        case IDM_KILL:      KillSelected();      return 0;
        case IDM_REFRESH:  Tick();          return 0;
        case IDM_SHOW_PASSIVE:
            monitor_.SetShowPassive(!monitor_.showPassive());
            SyncMenu();
            Tick();
            return 0;
        case IDM_RULES_ALL:    OpenAllRules();    return 0;
        case IDM_RULES_APP:    OpenAppRules();    return 0;
        case IDM_RULES_GLOBAL: OpenGlobalRules(); return 0;
        case IDM_RULE_CREATE:        CreateRuleForSelection(false); return 0;
        case IDM_RULE_CREATE_GLOBAL: CreateRuleForSelection(true);  return 0;
        case IDM_RULES_GENERATE: {
            DeferVisibleAsk();
            RuleGenerationProgress progress;
            progress.Show(h, inst_);
            if (progress.failed) {
                Ui::ShowMessage(h, LoadStringRes(IDS_RULE_GENERATE_FAILED).c_str(),
                                LoadStringRes(IDS_RULE_GENERATE).c_str(), MB_ICONERROR | MB_OK);
            } else if (!progress.cancel.load(std::memory_order_relaxed) && !progress.result.cancelled) {
                const size_t count = RulePresets::ApplyGenerated(rules_, std::move(progress.result.rules));
                progress.result.files.clear();
                if (count) {
                    RulesChanged();
                    Tick();
                }
                const std::wstring summary = LoadStringResFmt(IDS_RULE_GENERATE_RESULT,
                                                               static_cast<unsigned>(count));
                Ui::ShowMessage(h, summary.c_str(), LoadStringRes(IDS_RULE_GENERATE).c_str(),
                                MB_ICONINFORMATION | MB_OK);
            }
            QueuePump();
            return 0;
        }
        case IDM_RULE_EDIT:   EditRuleForSelection();   return 0;
        case IDM_RULE_DELETE: DeleteRuleForSelection(); return 0;
        case IDM_RULES_CLEAR:
            if (rules_.Count()) {
                DeferVisibleAsk();
                if (Ui::ShowMessage(h,
                        LoadStringRes(IDS_RULES_CLEAR_CONFIRM).c_str(),
                        LoadStringRes(IDS_RULES_TITLE).c_str(),
                        MB_ICONWARNING | MB_YESNO) == IDYES) {
                    rules_.Clear();
                    RulesChanged();
                    Tick();
                }
            }
            return 0;
        case IDM_SETTINGS:
            OpenSettings();
            return 0;
        case IDM_DEBUG:
            OpenDebug();
            return 0;
        case IDM_ABOUT: {
            DeferVisibleAsk();
            RefreshServiceState();
            const std::wstring text = AppInfo::AboutText(
                FirewallX::RunModeText(), ListSkinSetting::Name(list_.skin()), svc_.FullText());
            const std::wstring title = LoadStringRes(IDS_ABOUT_TITLE);
            const std::wstring ok = LoadStringRes(IDS_BTN_OK);
            const TASKDIALOG_BUTTON button{ IDOK, ok.c_str() };
            TASKDIALOGCONFIG dialog{ sizeof(dialog) };
            dialog.hwndParent = h;
            dialog.hInstance = inst_;
            dialog.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_ALLOW_DIALOG_CANCELLATION |
                             TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
            dialog.pszWindowTitle = title.c_str();
            dialog.pszMainIcon = TD_INFORMATION_ICON;
            dialog.pszContent = text.c_str();
            dialog.cButtons = 1;
            dialog.pButtons = &button;
            dialog.nDefaultButton = IDOK;
            dialog.pfCallback = AboutDialogCallback;
            TaskDialogIndirect(&dialog, nullptr, nullptr, nullptr);
            return 0;
        }
        case IDM_EXIT:
            RequestExit();
            return 0;
        }
        break;
    }
    // Кнопка закрытия окна сворачивает программу в трей; настоящий выход —
    // только через «Выход» либо при завершении сеанса Windows.
    case WM_CLOSE:
        if (!exiting_) { HideToTray(); return 0; }
        DestroyWindow(h);
        return 0;

    case WM_QUERYENDSESSION:
        exiting_ = true;                 // не мешаем завершению сеанса
        return TRUE;

    case WM_ENDSESSION:
        // WM_QUERYENDSESSION приходит и перед отменённым завершением. Если
        // сеанс не закрывается, обычный крестик снова должен сворачивать окно.
        if (!wp) exiting_ = false;
        return 0;

    case WM_SETFOCUS:
        SetFocus(list_.hwnd());
        return 0;

    case WM_DESTROY:
        debug_.Close();
        ServiceInfo::SetNotification(nullptr, 0);
		portmaster_stop();
        KillTimer(h, kTimerId);
        KillTimer(h, kAutoRulesTimerId);
        monitor_.Stop();                   // worker больше не читает правила/SCM
        Ingest::Instance().Detach();       // вердиктов не выдаёт
        ServiceInfo::Shutdown();
        AddrMacros::Shutdown();
        tray_.Destroy();                   // иначе в трее останется «призрак»
        ask_.Close();
        list_.Destroy();
        if (accel_)  { DestroyAcceleratorTable(accel_); accel_ = nullptr; }
        if (menu_)   { Ui::CleanupMenuBitmaps(menu_); DestroyMenu(menu_); menu_ = nullptr; }
        if (barBr_)  { DeleteObject(barBr_);  barBr_  = nullptr; }
        if (lineBr_) { DeleteObject(lineBr_); lineBr_ = nullptr; }
        if (winBr_)  { DeleteObject(winBr_);  winBr_  = nullptr; }
        if (iconBig_)   { DestroyIcon(iconBig_);   iconBig_ = nullptr; }
        if (iconSmall_) { DestroyIcon(iconSmall_); iconSmall_ = nullptr; }
        if (iconTray_)  { DestroyIcon(iconTray_);  iconTray_ = nullptr; }
        hwnd_ = nullptr;
        PostQuitMessage(0);		
        return 0;

    case WM_NCDESTROY:
        Ui::ReleaseFonts();          // дочерние окна уже уничтожены
        return DefWindowProcW(h, msg, wp, lp);
    }
    return DefWindowProcW(h, msg, wp, lp);
}

// ------------------------------------------------------- оформление списка

// Смена оформления не касается данных: снимок соединений не перечитывается,
// правила не опрашиваются, состояние раскрытых групп сохраняется. Строки
// пересобираются только потому, что от оформления зависит их текст (прочерк
// скорости против «0 байт/с») — этим занимается сам TreeList в SetRows.
void App::ApplySkin(ListSkin s) {
    if (list_.skin() == s) return;
    list_.SetSkin(s);
    ListSkinSetting::Save(s);
    Layout();                            // высота заголовка могла измениться
    RebuildRows();                       // текст скорости зависит от оформления
    SyncMenu();
}

// Смена языка на лету. Интерфейс перестраивается без перезапуска: меню,
// панель команд, колонки списка, заголовок окна, строка состояния. Уже
// открытые диалоги (редактор правил, запрос решения) останутся на старом
// языке до следующего открытия — их перерисовывать не нужно.
void App::ApplyUiLang(UiLang lang) {
    if (!SetUiLang(lang)) return;        // тот же язык, менять нечего
    UiLangSetting::Save(lang);
    Ui::ApplyLayout(hwnd_);

    // Меню: перестроить целиком, галочки языка поставит BuildMenu заново
    if (menu_) {
        Ui::CleanupMenuBitmaps(menu_);
        DestroyMenu(menu_);
        menu_ = nullptr;
    }
    BuildMenu();
    DrawMenuBar(hwnd_);

    // Заголовок окна
    UpdateTitle(true);

    // Панель команд: текст кнопок и подсказка в поле фильтра
    if (btReset_)
        SetWindowTextW(btReset_, LoadStringRes(IDS_BTN_RESET).c_str());
    if (cbPassive_)
        SetWindowTextW(cbPassive_, LoadStringRes(IDS_BTN_SHOW_PASSIVE).c_str());
    if (btSettings_)
        SetWindowTextW(btSettings_, LoadStringRes(IDS_MENU_SETTINGS).c_str());
    if (edFilter_) {
        const std::wstring cue = LoadStringRes(IDS_FILTER_PLACEHOLDER);
        SendMessageW(edFilter_, EM_SETCUEBANNER, TRUE,
                     reinterpret_cast<LPARAM>(cue.c_str()));
    }

    // Переписываем подписи колонок и раскладываем список для нового языка.
    list_.ApplyColumns();
    Layout();

    // Строки списка: текст причины, протокола, состояния зависит от языка.
    // Кеш состояния помечен старым языком неявно, поэтому сбрасывается целиком.
    connectionText_.clear();
    // ProcessCache кэширует и локализованные подписи для PID без пути.
    // Сначала обновляем их, затем переносим новые имена в уже опубликованный
    // снимок; иначе строка продолжала бы держать язык прошлого интерфейса.
    cache_.RefreshNames();
    for (ProcItem& process : snap_.procs) {
        FillProcessDisplay(process, cache_);
    }
    RebuildRows();

    // Строка состояния
    UpdateStatus();

    // Подсказка трея
    UpdateTrayTip();
}

void App::ApplyPolicy(FirewallPolicy policy) {
    if (policy_ == policy || !FirewallPolicies::IsValid(policy)) return;

    // При ошибке записи не меняем поведение и отметку меню: следующий запуск
    // должен восстановить именно ту политику, которую видит пользователь.
    if (!FirewallPolicySetting::Save(policy)) {
        DeferVisibleAsk();
        const bool wasBusy = askBusy_;
        askBusy_ = true;
        Ui::ShowMessage(hwnd_,
                    LoadStringResFmt(IDS_POLICY_SAVE_FAILED_FMT,
                                     Settings::lastError().c_str()).c_str(),
                    LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
        askBusy_ = wasBusy;
        return;
    }

    const DWORD status = Ingest::Instance().SetPolicy(policy);
    policy_ = policy;
    monitor_.SetPolicy(policy);
    Ingest::Instance().FlushVerdicts();
    DrainIngest();                          // убирает уже решённые Ask, включая показанный
    monitor_.RequestRefresh();
    SyncMenu();
    UpdateTrayTip();
    if (status != ERROR_SUCCESS) {
        DeferVisibleAsk();
        const bool wasBusy = askBusy_;
        askBusy_ = true;
        Ui::ShowMessage(hwnd_,
                    LoadStringResFmt(IDS_POLICY_CACHE_FAILED_FMT,
                                     FormatWinError(status).c_str()).c_str(),
                    LoadStringRes(IDS_SETTINGS_TITLE).c_str(), MB_ICONWARNING | MB_OK);
        askBusy_ = wasBusy;
    }
    Tick();
}

// ----------------------------------------------------------- трей и выход

bool App::WindowShown() const {
    return hwnd_ && IsWindowVisible(hwnd_) && !IsIconic(hwnd_);
}

void App::SetMonitorDisplay(bool on) {
    if (!on) {
        snap_.displayReady = false;
        connectionText_.clear();
        if (!rowsReleased_) {
            // Для восстановления выделения достаточно ключа: строки с текстом,
            // путями и значками скрытому окну не нужны. Повторный такт в трее
            // не должен заменять сохранённый ключ пустым выделением.
            const int selected = list_.Selected();
            selValid_ = selected >= 0 &&
                selected < static_cast<int>(list_.rows().size());
            if (selValid_)
                selKey_ = list_.rows()[static_cast<size_t>(selected)].key;
            rowsReleased_ = true;
            list_.SetRows({});
        }
    }
    monitor_.SetDisplayEnabled(on);
}

void App::HideToTray() {
    if (!hwnd_) return;
    if (!tray_.alive() && !tray_.Create(hwnd_, kMsgTray, kTrayIconId, iconTray_,
                                        AppInfo::NameWithVersion()))
        return;                         // окно нельзя прятать без пути назад

    ShowWindow(hwnd_, SW_HIDE);
    UpdateTrayTip();     // всплывающих уведомлений нет: состояние видно в подсказке
}

void App::RestoreFromTray() {
    if (!hwnd_) return;
    ShowWindow(hwnd_, IsIconic(hwnd_) ? SW_RESTORE : SW_SHOW);
    // Отключённый владелец не может принять фокус вместо модального окна.
    if (HWND modal = Ui::ModalWindow(hwnd_)) {
        Ui::RestorePopup(modal);
        ForceForeground(modal);
    } else if (ask_.visible()) {
        ask_.Restore();
        ForceForeground(ask_.hwnd());
    } else {
        ForceForeground(hwnd_);
    }
    Layout();
    Tick();
}

bool App::ShowPendingBeforeExit() {
    if (!Ingest::Instance().waiting()) return false;

    // Запросы нельзя оставлять в скрытом окне или на паузе: пользователь
    // попросил завершить программу, поэтому сначала должен решить каждый из них.
    if (!WindowShown()) RestoreFromTray();
    DrainIngest();
    if (queue_.empty() && !ask_.visible() && !askBusy_ && autoRequestIds_.empty()) {
        Ingest::Instance().Republish();
        DrainIngest();
    }
    queue_.MakeAllReady();

    if (!Ingest::Instance().waiting()) return false;
    if (ask_.visible()) {
        ask_.Restore();
        ForceForeground(ask_.hwnd());
    } else {
        PumpAsk();
    }
    return true;
}

void App::RequestExit() {
    if (!hwnd_) return;

    exitPending_ = true;
    if (ShowPendingBeforeExit()) return;

    // Служба прекращает пересылку, а reader каждого pipe обрабатывает все
    // записи, отправленные до переключения, прежде чем проверять pending.
    if (portmaster_service_connected() || firewallxndisfilter_service_connected()) {
        if (!portmaster_service_process_locally()) {
            exitPending_ = false;
            return;
        }
        Tick();
        if (ShowPendingBeforeExit()) return;
        if (!portmaster_service_flush_verdicts()) {
            exitPending_ = false;
            return;
        }
    }

    exitPending_ = false;
    exiting_ = true;
    RefreshServiceState();
    portmaster_prepare_desktop_exit(svc_.installed);
    portmaster_stop();
    DestroyWindow(hwnd_);
}

void App::ShowTrayMenu(POINT pt) {
    RefreshServiceState();

    HMENU m = CreatePopupMenu();
    if (!m) return;
    AppendMenuW(m, MF_STRING, IDM_TRAY_SHOW, LoadStringRes(IDS_TRAY_SHOW).c_str());
    SetMenuDefaultItem(m, IDM_TRAY_SHOW, FALSE);
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_RULES_ALL, LoadStringRes(IDS_MENU_RULES_EDITOR).c_str());
    AppendMenuW(m, MF_STRING | (queue_.ready() ? 0 : MF_GRAYED), IDM_ASK_NOW,
                LoadStringRes(IDS_TRAY_ASK_NOW).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    Ui::AppendSubMenu(m, CreatePolicyMenu(policy_), LoadStringRes(IDS_MENU_POLICY).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | MF_GRAYED, IDM_SVC_STATE, svc_.FullText().c_str());
    AppendMenuW(m, MF_STRING | (svc_.installed ? MF_GRAYED : 0), IDM_SVC_INSTALL,
                LoadStringRes(IDS_MENU_SVC_INSTALL).c_str());
    AppendMenuW(m, MF_STRING | (svc_.installed ? 0 : MF_GRAYED), IDM_SVC_REMOVE,
                LoadStringRes(IDS_MENU_SVC_REMOVE).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_ABOUT, LoadStringRes(IDS_MENU_HELP_ABOUT).c_str());
    AppendMenuW(m, MF_STRING, IDM_EXIT,  LoadStringRes(IDS_MENU_VIEW_EXIT).c_str());

    // окно-владелец обязано быть активным, иначе меню не закроется по щелчку вне
    SetForegroundWindow(hwnd_);
    TrackPopupMenu(m, Ui::PopupFlags(TPM_RIGHTBUTTON | TPM_RIGHTALIGN | TPM_BOTTOMALIGN),
                   pt.x, pt.y, 0, hwnd_, nullptr);
    PostMessageW(hwnd_, WM_NULL, 0, 0);
    DestroyMenu(m);
}

void App::UpdateTrayTip() {
    if (!tray_.alive()) return;

    std::wstring tip = AppInfo::NameWithVersion();
    tip += LoadStringResFmt(IDS_TRAY_TIP_POLICY_FMT,
                            FirewallPolicies::Name(policy_).c_str());
    if (!queue_.empty()) {
        tip += LoadStringResFmt(IDS_TRAY_TIP_ASKS_FMT,
                                static_cast<unsigned>(queue_.size()));
        if (const size_t held = queue_.held())
            tip += LoadStringResFmt(IDS_TRAY_TIP_DEFERRED_FMT,
                                    static_cast<unsigned>(held));
    }
    tray_.SetTip(tip);
}

// ------------------------------------------------------------------ служба

void App::RefreshServiceState() {
    std::wstring err;
    FirewallX::ServiceState st;
    if (FirewallX::ServiceQuery(st, err)) svc_ = st;
    // ошибку опроса не показываем: меню просто останется с прежним состоянием
}

void App::DoServiceInstall() {
    DeferVisibleAsk();
    const std::wstring q = LoadStringResFmt(IDS_SVC_INSTALL_CONFIRM_FMT,
                                            AppInfo::ServiceDisplay().c_str(),
                                            AppInfo::kServiceName,
                                            ModulePath().c_str(),
                                            AppInfo::kServiceSwitch);
    if (Ui::ShowMessage(hwnd_, q.c_str(), LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONQUESTION | MB_YESNO) != IDYES)
        return;

    std::wstring err;
    if (FirewallX::ServiceInstall(err)) {
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_SVC_INSTALLED).c_str(),
                    LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONINFORMATION);
    } else {
        Ui::ShowMessage(hwnd_, LoadStringResFmt(IDS_SVC_INSTALL_FAILED, err.c_str()).c_str(),
                    LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONERROR);
    }
    RefreshServiceState();
    SyncMenu();
}

void App::DoServiceRemove() {
    DeferVisibleAsk();
    const std::wstring q = LoadStringResFmt(IDS_SVC_REMOVE_CONFIRM_FMT,
                                            AppInfo::kServiceName);
    if (Ui::ShowMessage(hwnd_, q.c_str(), LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONWARNING | MB_YESNO) != IDYES)
        return;

    std::wstring err;
    portmaster_stop();
    const bool removed = FirewallX::ServiceRemove(err);
    portmaster_start();
    // Остановка transport закрыла поколение и сбросила данные прежнего маршрута.
    // Обновление снимка запрашивается до показа результата операции, чтобы
    // Monitor мог перечитать активные соединения и во время модального сообщения.
    Tick();
    if (removed) {
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_SVC_REMOVED).c_str(),
                    LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONINFORMATION);
    } else {
        Ui::ShowMessage(hwnd_, LoadStringResFmt(IDS_SVC_REMOVE_FAILED, err.c_str()).c_str(),
                    LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONERROR);
    }
    RefreshServiceState();
    SyncMenu();
}

void App::DoServiceRun(bool start) {
    DeferVisibleAsk();
    std::wstring err;
    portmaster_stop();
    const bool ok = start ? FirewallX::ServiceStart(err) : FirewallX::ServiceStop(err);
    // Даже при ошибке SCM восстанавливаем прежний маршрут: иначе одна
    // неудачная команда меню оставляет оконный процесс без мониторинга.
    portmaster_start();
    Tick();
    if (!ok) {
        const std::wstring head = LoadStringRes(start ? IDS_SVC_START_ERROR
                                                     : IDS_SVC_STOP_ERROR);
        Ui::ShowMessage(hwnd_, (head + err).c_str(), LoadStringRes(IDS_SERVICE_TITLE).c_str(), MB_ICONERROR);
    }
    RefreshServiceState();
    SyncMenu();
}

// ----------------------------------------------------- запросы и очередь

// Забрать у Ingest группы, накопленные рабочим потоком. Это ЕДИНСТВЕННОЕ
// место получения новых групп из Ingest: за каждой группой стоит
// обязательство ответить process_verdict.
//
// Строки, собранные Monitor'ом по GetExtendedTcpTable / GetExtendedUdpTable,
// сюда не попадают и запросов не создают: обязательства за ними нет, а окно
// запроса создаёт правило.
void App::DrainIngest() {
    std::vector<AskRequest> fresh;
    Ingest::Instance().TakePending(fresh);

    std::erase_if(autoManualRequestIds_, [](AskRequestId id) {
        return !Ingest::Instance().IsPending(id);
    });
    const bool autoRules = !fresh.empty() &&
        Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false);
    for (const AskRequest& request : fresh) {
        if (autoRequestIds_.contains(request.id)) continue;
        if (autoManualRequestIds_.contains(request.id)) {
            if (!ask_.visible() || ask_.requestId() != request.id) queue_.Push(request);
            continue;
        }
        if (autoRules && request.key.source == TrafficSource::Host && !request.ownerAmbiguous &&
            (!request.appPath.empty() || IsAutomaticIgmp(request))) {
            if (queue_.contains(request.id)) queue_.Discard(request.id);
            autoRequestIds_.insert(request.id);
            autoRequests_.push_back({request, GetTickCount64() + kAutoRulesTimeoutMs});
        } else {
            queue_.Push(request);
        }
    }
    ProcessAutoRules();

    // То же сообщение приходит при смене экземпляра драйвера. Новых групп в
    // нём может не быть, но ссылки очереди и показанного окна на старую сессию
    // должны исчезнуть до обработки событий новой.
    queue_.Prune();
    if (ask_.visible() &&
        !Ingest::Instance().IsPending(ask_.requestId()))
        ask_.Close();

    UpdateStatus();
    UpdateTrayTip();
    SyncMenu();
    QueuePump();
}

// Срок отсчитывается от помещения запроса в автоматическую очередь, чтобы
// медленная проверка не задерживала следующие запросы дольше того же срока.
void App::ExpireAutoRequests() {
    const ULONGLONG now = GetTickCount64();
    const bool finishedInTime = autoSignature_ && !autoSignatureAbandoned_ &&
        !autoRequests_.empty() &&
        WaitForSingleObject(autoSignatureThread_, 0) == WAIT_OBJECT_0 &&
        autoSignature_->finishedAt <= autoRequests_.front().deadline;
    for (auto it = autoRequests_.begin(); it != autoRequests_.end();) {
        const bool active = it == autoRequests_.begin() && autoSignature_ && !autoSignatureAbandoned_;
        if (now < it->deadline || (active && finishedInTime)) {
            ++it;
            continue;
        }
        if (active) autoSignatureAbandoned_ = true;
        const AskRequestId id = it->request.id;
        autoRequestIds_.erase(id);
        AskRequest current;
        if (Ingest::Instance().GetPending(id, current)) {
            // Повторная публикация не должна заново запускать ту же проверку.
            autoManualRequestIds_.insert(id);
            queue_.Push(current);
        }
        it = autoRequests_.erase(it);
    }
}

bool App::HasManualRequestForRulePath(std::wstring_view path) const {
    for (const AskRequestId id : autoManualRequestIds_) {
        AskRequest pending;
        if (Ingest::Instance().GetPending(id, pending) &&
            EqualNoCase(RequestForRuleCreation(pending, rules_).appPath, path)) return true;
    }
    return false;
}

void App::ScheduleAutoRulesTimer() {
    if (!hwnd_) return;
    auto it = autoRequests_.begin();
    if (it != autoRequests_.end() && autoSignature_ && !autoSignatureAbandoned_ &&
        WaitForSingleObject(autoSignatureThread_, 0) == WAIT_OBJECT_0 &&
        autoSignature_->finishedAt <= it->deadline) ++it;
    if (it == autoRequests_.end()) {
        KillTimer(hwnd_, kAutoRulesTimerId);
        return;
    }
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG remaining = it->deadline > now ? it->deadline - now : 1;
    SetTimer(hwnd_, kAutoRulesTimerId, static_cast<UINT>(remaining), nullptr);
}

// Дорогое чтение файла и WinVerifyTrust не выполняются в потоке драйвера
// или интерфейса. Даже просроченная проверка остаётся единственной в фоне.
void App::ProcessAutoRules() {
    if (processingAutoRules_) return;
    processingAutoRules_ = true;
    struct ResetFlag {
        bool& value;
        App& app;
        ~ResetFlag() {
            value = false;
            app.ScheduleAutoRulesTimer();
        }
    } reset{ processingAutoRules_, *this };

    for (;;) {
        ExpireAutoRequests();
        if (autoSignatureAbandoned_) {
            if (WaitForSingleObject(autoSignatureThread_, 0) == WAIT_OBJECT_0) {
                CloseHandle(autoSignatureThread_);
                autoSignatureThread_ = nullptr;
                autoSignature_.reset();
                autoSignatureAbandoned_ = false;
            } else {
                return;
            }
        }
        if (autoRequests_.empty() || askBusy_ || Ui::ModalActive() ||
            (hwnd_ && !IsWindowEnabled(hwnd_))) return;
        if (autoSignature_) {
            if (WaitForSingleObject(autoSignatureThread_, 0) != WAIT_OBJECT_0) return;
            CloseHandle(autoSignatureThread_);
            autoSignatureThread_ = nullptr;
            auto checkedSignature = std::move(autoSignature_);
            const bool trusted = checkedSignature->trusted();
            const AskRequest checked = std::move(autoRequests_.front().request);
            autoRequests_.pop_front();
            autoRequestIds_.erase(checked.id);
            Ingest::Instance().FlushVerdicts();
            AskRequest current;
            if (!Ingest::Instance().GetPending(checked.id, current)) continue;
            if (trusted && !current.ownerAmbiguous &&
                EqualNoCase(current.appPath, checked.appPath) &&
                Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false)) {
                const AskRequest ruleRequest = RequestForRuleCreation(current, rules_);
                if (HasManualRequestForRulePath(ruleRequest.appPath)) {
                    // Автоправило не должно закрыть уже переданный пользователю запрос.
                    autoManualRequestIds_.insert(current.id);
                } else if (EqualNoCase(ruleRequest.appPath, checkedSignature->rulePath)) {
                    auto choices = RulePresets::Suggest(ruleRequest);
                    if (!choices.empty() &&
                        RulePresets::ApplySelected(rules_, ruleRequest, std::move(choices.front().rules)))
                        RulesChanged();
                }
            }
            // Если шаблон не закрыл запрос, он показывается как обычно.
            if (Ingest::Instance().IsPending(current.id)) queue_.Push(current);
            continue;
        }

        AskRequest current;
        if (!Ingest::Instance().GetPending(autoRequests_.front().request.id, current)) {
            autoRequestIds_.erase(autoRequests_.front().request.id);
            autoRequests_.pop_front();
            continue;
        }
        if (IsAutomaticIgmp(current) &&
            Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false)) {
            // Явное исключение для события без файла и подписи:
            // другие безымянные запросы не получают автоматических правил.
            auto choices = RulePresets::Suggest(current);
            const auto choice = std::find_if(choices.begin(), choices.end(), [](const auto& item) {
                return item.titleId == IDS_PRESET_IGMP || item.titleId == IDS_PRESET_IGMP_IN;
            });
            const bool manualMatch = choice != choices.end() &&
                std::any_of(autoManualRequestIds_.begin(), autoManualRequestIds_.end(),
                    [&](AskRequestId id) {
                        AskRequest pending;
                        if (!Ingest::Instance().GetPending(id, pending)) return false;
                        return std::any_of(choice->rules.begin(), choice->rules.end(),
                            [&](const Rule& rule) { return RuleStore::MatchesRule(rule, pending.ToQuery()); });
                    });
            if (GetTickCount64() >= autoRequests_.front().deadline) continue;
            autoRequestIds_.erase(current.id);
            autoRequests_.pop_front();
            if (manualMatch) {
                // Уже переданный пользователю запрос нельзя закрыть автоправилом.
                autoManualRequestIds_.insert(current.id);
            } else if (choice != choices.end() &&
                       RulePresets::ApplySelected(rules_, current, std::move(choice->rules))) {
                RulesChanged();
            }
            if (Ingest::Instance().IsPending(current.id)) queue_.Push(current);
            continue;
        }
        const AskRequest ruleRequest = RequestForRuleCreation(current, rules_);
        if (!Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false) ||
            current.ownerAmbiguous || current.appPath.empty() || ruleRequest.appPath.empty() ||
            RulePresets::Suggest(ruleRequest).empty()) {
            autoRequestIds_.erase(current.id);
            autoRequests_.pop_front();
            queue_.Push(current);
            continue;
        }
        if (HasManualRequestForRulePath(ruleRequest.appPath)) {
            autoRequestIds_.erase(current.id);
            autoRequests_.pop_front();
            autoManualRequestIds_.insert(current.id);
            queue_.Push(current);
            continue;
        }
        autoRequests_.front().request = current;
        if (GetTickCount64() >= autoRequests_.front().deadline) continue;
        autoSignature_ = std::make_shared<AutoSignatureCheck>();
        autoSignature_->path = current.appPath;
        autoSignature_->rulePath = ruleRequest.appPath;
        auto* workerRef = new std::shared_ptr<AutoSignatureCheck>(autoSignature_);
        autoSignatureThread_ = CreateThread(nullptr, 0, &AutoSignatureCheck::Run,
                                            workerRef, 0, nullptr);
        if (autoSignatureThread_) return;
        // При нехватке ресурсов оставляем запрос на ручное решение.
        delete workerRef;
        autoSignature_.reset();
        autoRequestIds_.erase(current.id);
        autoRequests_.pop_front();
        queue_.Push(current);
    }
}

// Единая точка после любой мутации правил
void App::RulesChanged() {
    Ingest::Instance().FlushVerdicts();     // вердикты ожидающим соединениям
    queue_.Prune();
    // Показанная группа уже извлечена из AskQueue. Правка правила могла закрыть
    // её напрямую, поэтому такое окно тоже нужно снять.
    if (ask_.visible() &&
        !Ingest::Instance().IsPending(ask_.requestId()))
        ask_.Close();
    monitor_.RequestRefresh();

    // Предупреждение не должно оставлять доступный Ask или открывать новый поверх себя.
    if (ruleSaveErrorVersion_ != rules_.version() && !rules_.dbError().empty())
        DeferVisibleAsk();
    const bool wasBusy = askBusy_;
    askBusy_ = true;
    const HWND dialogOwner = GetActiveWindow();
    RuleDialogs::ShowSaveError(dialogOwner ? dialogOwner : hwnd_, rules_, ruleSaveErrorVersion_);
    askBusy_ = wasBusy;
}

void App::AddRuleFirst(Rule r) {
    r.id = 0;                              // Replace выдаст новый идентификатор
    const RuleScope scope = r.scope;
    const std::wstring path = r.appPath;
    const std::wstring name = r.appName;

    std::vector<Rule> list;
    if (scope == RuleScope::Global)
        list = rules_.Globals();
    else if (scope == RuleScope::PostApp)
        list = rules_.PostApps();
    else if (scope == RuleScope::Interface)
        list = rules_.InterfaceRules(path);
    else
        list = rules_.ForApp(path);
    list.insert(list.begin(), std::move(r));

    rules_.Replace(scope, path, name, std::move(list));
}

void App::QueuePump() {
    if (hwnd_) PostMessageW(hwnd_, kMsgPumpAsk, 0, 0);
}

void App::DeferVisibleAsk() {
    if (!ask_.visible()) return;

    // AskWindow уже извлёк эту группу из AskQueue. Сначала копируем запрос,
    // затем закрываем окно без callback и возвращаем обязательство в очередь.
    const AskRequest request = ask_.request();
    ask_.Close();
    queue_.Postpone(request);
}

void App::PumpAsk() {
    if (askBusy_) return;

    // Пока открыто модальное окно, ВСЕ прочие окна программы отключены
    // (см. Ui::Modal). Показать запрос поверх них нельзя: его владельцем было
    // бы отключённое окно, которое не может стать активным, и закрытие
    // запроса увело бы активность из программы. Хуже того, «Создать правило»
    // открыло бы диалог с отключённым владельцем, а тот на выходе включил бы
    // главное окно, пока другой диалог ещё на экране, — модальность бы
    // сломалась.
    //
    // Обязательства при этом не теряются: они ждут в Ingest, а запрос
    // откроется на следующем такте таймера, когда диалог закроют.
    // MessageBox не входит в счётчик Ui::Modal, но тоже отключает владельца.
    if (Ui::ModalActive() || (hwnd_ && !IsWindowEnabled(hwnd_))) return;
    if (ask_.visible()) {
        // Сворачивание владельца скрывает popup, не разрушая его HWND.
        if (!IsWindowVisible(ask_.hwnd())) ask_.Restore();
        return;
    }

    queue_.Prune();                         // могло появиться подходящее правило
    if (queue_.empty()) return;

    AskRequest r;
    // Pop пропускает отложенные запросы: если все они на паузе, окно не
    // открывается, а попытка повторится на следующем такте таймера.
    if (!queue_.Pop(r)) return;
    // Получение значка при создании окна может прокачать вложенные сообщения.
    askBusy_ = true;
    // У интерфейса нет PID: его значок не проходит через кеш процессов.
    // Pending хоста удерживает исходный путь, поэтому чужой значок при reuse PID не подставляется.
    ProcessIconRef icon;
    if (r.key.source == TrafficSource::Ndis) icon = cache_.InterfaceIcon();
    else {
        const auto& info = cache_.Get(r.pid);
        if (EqualNoCase(info.path, r.appPath)) icon = info.icon;
    }
    const bool shown = ask_.Show(hwnd_, inst_, std::move(icon), r, queue_.size(), [&]() {
        Ingest::Instance().FlushVerdicts();
        return Ingest::Instance().IsPending(r.id);
    }, &rules_);
    askBusy_ = false;
    if (!shown) {
        // Pop уже убрал запись из очереди. При ошибке создания окна нельзя
        // терять обязательство: вернуть его с паузой, чтобы не крутить UI в
        // бесконечном цикле при временной нехватке оконных ресурсов.
        queue_.Postpone(r);
        UpdateTrayTip();
        SyncMenu();
        return;
    }
    SyncMenu();
}

void App::ApplyDecision(const AskRequest& req, const AskDecision& decision) {
    const AskAction act = decision.action;
    askBusy_ = true;                      // не показывать второй запрос поверх

    // Пока пользователь нажимал кнопку, transport мог смениться. Старое окно
    // не вправе создавать правило и тем более отвечать новой driver-сессии.
    if (!Ingest::Instance().IsPending(req.id)) {
        queue_.Discard(req.id);
        askBusy_ = false;
        Tick();
        QueuePump();
        return;
    }

    if (act == AskAction::AllowOnce || act == AskAction::BlockOnce) {
        // Это не правка RuleStore: ответ адресуется одному обязательству и не
        // должен закрывать другие группы через FlushVerdicts или кеш формы.
        queue_.Discard(req.id);
        Ingest::Instance().AnswerOnce(req.id,
            act == AskAction::AllowOnce ? RuleAction::Allow : RuleAction::Block);
        DrainIngest();
        askBusy_ = false;
        Tick();
        QueuePump();
        return;
    }

    const AskRequest ruleRequest = RequestForRuleCreation(req, rules_);
    const auto applyRule = [&](Rule& rule, bool first = false) {
        if (rule.isInterface() && rule.appPath.empty()) {
            // Без исходного имени сохранять правило некуда. Ответ относится
            // только к этому pending, а не к будущему владельцу того же индекса.
            if (RuleStore::MatchesRuleConditions(rule, req.ToQuery()))
                Ingest::Instance().AnswerOnce(req.id, rule.action);
        } else if (first) {
            AddRuleFirst(rule);
        } else {
            rules_.Add(rule);
        }
    };
    switch (act) {
    case AskAction::Preset:
        RulePresets::ApplySelected(rules_, ruleRequest, decision.presetRules);
        break;
    case AskAction::Allow: {
        Rule r = MakeAllowRule(ruleRequest);
        applyRule(r);
        break;
    }
    case AskAction::Block: {
        Rule r = MakeBlockRule(ruleRequest);
        applyRule(r);
        break;
    }
    case AskAction::Terminate: {
        // Правило без условий (в том числе без условия «протокол») ставим
        // ПЕРВЫМ в группе: добавленное последним, оно перекрывалось бы уже
        // существующими Allow-правилами, и обещание «приложение
        // заблокировано» не выполнялось бы.
        std::vector<Rule> all = MakeBlockAllRules(ruleRequest);
        for (Rule& r : all) applyRule(r, true);

        if (req.key.source == TrafficSource::Host && req.pid > 4) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, req.pid);
            const bool ok = h && TerminateProcess(h, 1);
            if (h) CloseHandle(h);
            if (!ok) {
                Ui::ShowMessage(hwnd_,
                    LoadStringRes(IDS_TERMINATE_FAILED_FULL).c_str(),
                    LoadStringRes(IDS_TERMINATE_TITLE).c_str(), MB_ICONERROR);
            }
        }
        break;
    }
    case AskAction::Custom: {
        Rule r = MakeEditorTemplate(ruleRequest);
        const auto payload = Ingest::Instance().GetPendingPayload(req.id);
        RuleInheritance inheritance = rules_.GetInheritance(r.appPath);
        RuleInheritance* setting = r.scope == RuleScope::App &&
            RuleStore::CanSetInheritance(r.appPath, req.pid) ? &inheritance : nullptr;
        const bool edited = RuleEditor::Run(hwnd_, inst_, r, false, payload, setting, true);

        // Конструктор прокачивает собственный цикл сообщений. За это время
        // transport мог переподключиться и закрыть исходную группу. В таком
        // случае результат старого запроса нельзя сохранять в RuleStore.
        if (!Ingest::Instance().IsPending(req.id)) {
            askBusy_ = false;
            Tick();
            QueuePump();
            return;
        }
        if (edited) {
            applyRule(r);
            if (setting) rules_.SetInheritance(r.appPath, inheritance);
        }
        break;
    }
    case AskAction::None:
    default:
        break;
    }

    // Обычные действия и предустановки задают решение правилами. Однократные
    // ответы ушли выше и не выполняют эту синхронизацию набора правил.
    RulesChanged();

    // За запросом стоит обязательство, поэтому «ничего не делать» нельзя:
    // либо правило его закрыло, либо запрос возвращается в очередь. Возврат
    // всегда с паузой — иначе закрытое без решения окно (Esc, крестик,
    // отмена конструктора) открывалось бы этим же обработчиком снова, и
    // отложить вопрос было бы невозможно.
    Rule hit;
    const bool covered = !Ingest::Instance().IsPending(req.id) || rules_.Match(req.ToQuery(), hit);
    if (covered) queue_.Discard(req.id);
    else         queue_.Postpone(req);

    askBusy_ = false;

    Tick();
    QueuePump();     // следующий запрос — уже вне обработчика этого окна
}

// ----------------------------------------------------------------- прочее

void App::RebuildIcons() {
    const int sz = Sc(16);
    cache_.SetIconSize(sz);
    if (list_.hwnd()) list_.SetIconSize(sz);

    for (ProcItem& process : snap_.procs)
        process.icon = process.group.isNdis() ? cache_.InterfaceIcon()
            : cache_.Get(process.group.pid(), process.pathInfo).icon;
    if (WindowShown()) RebuildRows();
}

// Значок берётся из ресурса IDI_ICON1 и масштабируется под текущий DPI:
// отдельно большой (Alt+Tab, свойства окна), малый (заголовок) и для трея.
void App::ApplyWindowIcon() {
    const int cxBig   = GetSystemMetricsForDpi(SM_CXICON,   dpi_);
    const int cxSmall = GetSystemMetricsForDpi(SM_CXSMICON, dpi_);

    if (HICON nb = LoadAppIcon(inst_, cxBig > 0 ? cxBig : 32)) {
        SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(nb));
        if (iconBig_) DestroyIcon(iconBig_);      // старый снимаем только после
        iconBig_ = nb;
    }
    if (HICON ns = LoadAppIcon(inst_, cxSmall > 0 ? cxSmall : 16)) {
        SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(ns));
        if (iconSmall_) DestroyIcon(iconSmall_);
        iconSmall_ = ns;
    }
    if (HICON nt = LoadAppIcon(inst_, cxSmall > 0 ? cxSmall : 16)) {
        if (tray_.alive()) tray_.SetIcon(nt);
        if (iconTray_) DestroyIcon(iconTray_);
        iconTray_ = nt;
    }
}

void App::FocusFilter() {
    if (!edFilter_) return;
    SetFocus(edFilter_);
    SendMessageW(edFilter_, EM_SETSEL, 0, -1);
}

void App::OnFilterChanged() {
    if (!edFilter_) return;
    const int n = GetWindowTextLengthW(edFilter_);
    std::wstring s(static_cast<size_t>(n) + 1, L'\0');
    GetWindowTextW(edFilter_, s.data(), n + 1);
    s.resize(static_cast<size_t>(n));
    filterText_ = s;
    EnableWindow(btReset_, !filterText_.empty());
    RebuildRows();
    UpdateStatus();
}

App::Selection App::GetSelection() const {
    Selection sel;
    if (!snap_.displayReady) return sel;

    const int idx = list_.Selected();
    if (idx < 0 || idx >= static_cast<int>(list_.rows().size())) return sel;
    const TreeList::Row& row = list_.rows()[static_cast<size_t>(idx)];

    sel.valid    = true;
    sel.isGroup  = row.isGroup;
    sel.group    = row.key.group;
    sel.ruleId   = row.ruleId;
    sel.ruleName = row.ruleName;

    for (const ProcItem& p : snap_.procs) {
        if (p.group != row.key.group ||
            p.ownerAmbiguous != row.key.ownerAmbiguous) continue;
        sel.appPath = p.path;
        sel.appName = p.name;
        if (!row.isGroup) {
            for (const ConnItem& c : p.conns) {
                if (static_cast<int>(ProtoNumber(c.key.proto)) != row.key.proto) continue;
                if (c.flowGeneration != row.key.generation) continue;
                if (c.key.lport != row.key.lport) continue;
                if (c.key.rport != row.key.rport) continue;
                if (HashAddr(c.key.remote) != row.key.remoteHash) continue;
                sel.conn = c;
                sel.hasConn = true;
                if (!sel.ruleId) sel.ruleId = c.ruleId;
                break;
            }
        }
        break;
    }
    return sel;
}

bool App::ResolveRule(const Selection& sel, Rule& out) const {
    if (!sel.valid || !sel.ruleId) return false;

    // Имя правила не является ключом: одинаковые имена разрешены у разных
    // приложений и в глобальной группе. Если id устарел, безопаснее отключить
    // команду до следующего снимка, чем редактировать или удалять чужое правило.
    return rules_.Get(sel.ruleId, out);
}

// Заготовка правила по выбранной строке.
//
// ЕДИНСТВЕННОЕ место, где данные списка соединений (в том числе прочитанные
// из таблиц ОС) попадают в правило. Это не автоматический маршрут: функция
// вызывается только из CreateRuleForSelection по команде пользователя, а
// результат обязательно проходит через модальный конструктор правила — без
// нажатия «ОК» в хранилище ничего не попадает.
//
// AskRequest здесь намеренно не собирается: запрос решения существует только
// для обязательств по событиям транспорта.
Rule App::MakeRuleTemplate(const Selection& sel, bool global) const {
    if (sel.hasConn) {
        FlowRuleSeed seed;
        seed.key = sel.conn.key;           // номер протокола берётся из строки
        seed.interfaceIndex = sel.conn.interfaceIndex;
        seed.interfaceName = sel.conn.interfaceName;
		seed.pid = sel.group.pid();
        seed.dir = (sel.conn.dir != Dir::Unknown) ? sel.conn.dir
                 : (sel.conn.key.rport ? Dir::Out : Dir::In);
        seed.appPath = global ? std::wstring() : sel.appPath;
        seed.appName = global ? std::wstring(LoadStringRes(IDS_RULE_GLOBAL_APP)) : sel.appName;
        // Строка из события транспорта сохраняет известный тип ICMP.
        // Без payload остаётся -1, и условие типа не включается.
        seed.icmpType = sel.conn.icmp.type;
        seed.icmpCode = sel.conn.icmp.code;
        seed.conditionFlags = sel.conn.conditionFlags;
        Rule r = MakeNarrowRule(seed, RuleAction::Allow);
        if (global) {
            // Явный выбор глобального правила не зависит от владельца потока.
            r.scope = RuleScope::Global;
            r.appPath.clear();
            r.appName = seed.appName;
            r.SyncName();
        }
        return r;
    }

    Rule r;
    r.scope   = global ? RuleScope::Global :
                sel.group.isNdis() ? RuleScope::Interface : RuleScope::App;
    r.appPath = global ? std::wstring() : sel.group.isNdis()
        ? net::SharedNetworkInterfaces().GetInterfaceName(sel.group.interfaceIndex()).value_or(std::wstring())
        : sel.appPath;
    r.appName = global ? LoadStringRes(IDS_RULE_GLOBAL_APP) :
                sel.group.isNdis() ? r.appPath : sel.appName;
    r.proto   = Proto::Tcp;
    r.dir     = Dir::Out;
    r.conds   = CondProto | CondDirection;
    r.action  = RuleAction::Allow;
    r.enabled = true;
    r.autoName = true;
    r.SyncName();
    return r;
}

void App::CreateRuleForSelection(bool global) {
    const Selection sel = GetSelection();
    DeferVisibleAsk();
    if (!global && sel.valid && sel.appPath.empty() && !sel.group.isNdis()) {
        if (Ui::ShowMessage(hwnd_,
                LoadStringRes(IDS_RULE_NO_PATH_ASK_GLOBAL).c_str(),
                LoadStringRes(IDS_RULE_CREATE_TITLE).c_str(), MB_ICONQUESTION | MB_YESNO) != IDYES) return;
        global = true;
    }
    if (!global && !sel.valid) return;

    Rule r = MakeRuleTemplate(sel, global);
    if (r.isInterface() && r.appPath.empty()) {
        Ui::ShowMessage(hwnd_, LoadStringResFmt(IDS_INTERFACE_UNKNOWN, sel.group.interfaceIndex()).c_str(),
                        LoadStringRes(IDS_RULE_CREATE_TITLE).c_str(), MB_ICONINFORMATION);
        return;
    }
    RuleInheritance inheritance = rules_.GetInheritance(r.appPath);
    RuleInheritance* setting = r.scope == RuleScope::App &&
        RuleStore::CanSetInheritance(r.appPath, sel.group.pid()) ? &inheritance : nullptr;
    if (!RuleEditor::Run(hwnd_, inst_, r, false, {}, setting)) return;
    rules_.Add(r);
    if (setting) rules_.SetInheritance(r.appPath, inheritance);
    RulesChanged();
    Tick();
}

void App::EditRuleForSelection() {
    const Selection sel = GetSelection();
    Rule r;
    if (!ResolveRule(sel, r)) {
        DeferVisibleAsk();
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_ERR_RULE_NOT_FOUND).c_str(),
                    LoadStringRes(IDS_RULES_TITLE).c_str(), MB_ICONINFORMATION);
        return;
    }
    DeferVisibleAsk();
    RuleInheritance inheritance = rules_.GetInheritance(r.appPath);
    RuleInheritance* setting = r.scope == RuleScope::App &&
        RuleStore::CanSetInheritance(r.appPath, sel.group.pid()) ? &inheritance : nullptr;
    if (RuleEditor::Run(hwnd_, inst_, r, true, {}, setting)) {
        rules_.Update(r);
        if (setting) rules_.SetInheritance(r.appPath, inheritance);
        RulesChanged();
        Tick();
    }
}

void App::DeleteRuleForSelection() {
    const Selection sel = GetSelection();
    Rule r;
    if (!ResolveRule(sel, r)) {
        DeferVisibleAsk();
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_ERR_RULE_NOT_FOUND).c_str(),
                    LoadStringRes(IDS_RULES_TITLE).c_str(), MB_ICONINFORMATION);
        return;
    }
    DeferVisibleAsk();
    const std::wstring q = LoadStringRes(IDS_RULE_DELETE_CONFIRM) + r.name;
    if (Ui::ShowMessage(hwnd_, q.c_str(), LoadStringRes(IDS_RULES_TITLE).c_str(), MB_ICONWARNING | MB_YESNO) != IDYES) return;

    // ID — единственный устойчивый идентификатор. Если правило исчезло во
    // время подтверждения, удалять другой объект с тем же именем нельзя.
    const bool removed = rules_.Remove(r.id);
    if (!removed) {
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_ERR_RULE_DELETE_FAILED).c_str(),
                    LoadStringRes(IDS_RULES_TITLE).c_str(), MB_ICONERROR);
        return;
    }
    RulesChanged();
    Tick();
}

void App::OpenAppRules(bool selectMatchedRule) {
    const Selection sel = GetSelection();
    if (!sel.valid) return;
    DeferVisibleAsk();
    Rule matched;
    const bool hasMatchedRule = selectMatchedRule && !sel.isGroup && ResolveRule(sel, matched);
    const bool global = hasMatchedRule && matched.isGlobal();
    const bool postapp = hasMatchedRule && matched.isPostApp();
    const bool interfaceGroup = hasMatchedRule ? matched.isInterface() : sel.group.isNdis();
    const auto path = hasMatchedRule ? std::optional<std::wstring>(matched.appPath)
        : interfaceGroup ? net::SharedNetworkInterfaces().GetInterfaceName(sel.group.interfaceIndex())
                         : std::optional<std::wstring>(sel.appPath);
    if (!path || (interfaceGroup && path->empty())) {
        Ui::ShowMessage(hwnd_, LoadStringResFmt(IDS_INTERFACE_UNKNOWN, sel.group.interfaceIndex()).c_str(),
                        LoadStringRes(IDS_RULES_TITLE).c_str(), MB_ICONINFORMATION);
        return;
    }
    if (AppRulesEditor::Run(hwnd_, inst_, rules_, *path,
                            hasMatchedRule ? matched.appName : sel.appName,
                            global, postapp, interfaceGroup, sel.group.pid(),
                            hasMatchedRule ? matched.id : 0)) {
        RulesChanged();
        Tick();
    }
}

void App::OpenGlobalRules() {
    DeferVisibleAsk();
    if (AppRulesEditor::Run(hwnd_, inst_, rules_, std::wstring(),
                            std::wstring(LoadStringRes(IDS_RULE_GLOBAL_APP)), true)) {
        RulesChanged();
        Tick();
    }
}

void App::OpenAllRules() {
    DeferVisibleAsk();
    if (AllRulesWindow::Run(hwnd_, inst_, rules_,
                            [this]() { RulesChanged(); })) {
        Tick();
    } else {
        SyncMenu();
    }
}

void App::OpenSettings() {
    const bool autoRulesBefore = Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false);
    DeferVisibleAsk();
    if (SettingsWindow::Run(hwnd_, inst_, rules_, list_.skin(),
                            [this]() { RulesChanged(); },
                            [this]() { list_.ReloadFont(); })) {
        // Включённый режим обрабатывает и запросы, уже ожидавшие решения.
        if (!autoRulesBefore && Settings::GetBool(Settings::Key::kAutoCreatePresetRules, false)) {
            Ingest::Instance().Republish();
            DrainIngest();
        }
        Tick();
    } else {
        SyncMenu();
    }
}

void App::ResetSort() {
    sortCol_ = kSortNatural;
    sortAsc_ = true;
    clicks_  = 0;
    list_.SetSortIndicator(-1, true);
}

void App::SetStatusParts(int width) {
    if (!status_ || width <= 0) return;
    static const int wt[kStatusParts] = { 24, 14, 26, 16, 20 };
    int total = 0;
    for (int v : wt) total += v;

    int edges[kStatusParts]{};
    int x = 0;
    for (int i = 0; i < kStatusParts; ++i) {
        x += MulDiv(width, wt[i], total);
        edges[i] = x;
    }
    edges[kStatusParts - 1] = -1;
    SendMessageW(status_, SB_SETPARTS, kStatusParts,
                 reinterpret_cast<LPARAM>(edges));
}

void App::Layout() {
    if (!hwnd_ || IsIconic(hwnd_)) return;
    RECT rc; GetClientRect(hwnd_, &rc);
    if (rc.right <= 0 || rc.bottom <= 0) return;

    RECT sb{}; GetWindowRect(status_, &sb);
    const int sh = sb.bottom - sb.top;
    const int top = BarHeight();
    const int lh = rc.bottom - sh - top;

    LayoutBar(rc.right);
    MoveWindow(list_.hwnd(), 0, top, rc.right, lh > 0 ? lh : 0, TRUE);
    list_.FitColumns();
    SetStatusParts(rc.right);
}

bool App::ApplyMonitorSnapshot() {
    if (!monitor_.TakeLatest(snap_)) return false;
    if (!WindowShown()) snap_.displayReady = false;

    if (++processSweepTick_ >= 30) [[unlikely]] {
        processSweepTick_ = 0;
        cache_.Sweep();
    }

    // Ручное раскрытие исчезнувших групп убираем и в трее: при повторном
    // использовании PID новый процесс не должен наследовать старое исключение.
    if (!expansionOverrides_.empty()) {
        std::unordered_set<uint64_t> alive;
        alive.reserve(snap_.procs.size() * 2 + 8);
        for (const ProcItem& process : snap_.procs)
            alive.insert(ProcIdentity(process.group, process.ownerAmbiguous));
        for (auto it = expansionOverrides_.begin(); it != expansionOverrides_.end();)
            it = alive.count(*it) ? std::next(it) : expansionOverrides_.erase(it);
    }
    TrimHashTable(expansionOverrides_);

    const bool displayApplied = snap_.displayReady;
    if (displayApplied) {
        // После трея ключ уже сохранён, а строки освобождены. Пустое выделение
        // не должно стереть его до перестройки по новому полному снимку.
        if (!rowsReleased_) {
            const int selected = list_.Selected();
            if (selected >= 0 &&
                selected < static_cast<int>(list_.rows().size())) {
                selKey_ = list_.rows()[static_cast<size_t>(selected)].key;
                selValid_ = true;
            } else {
                selValid_ = false;
            }
        }
        connOrderDirty_ = false;

        // Значки принадлежат UI-потоку. Worker передаёт уже найденную ссылку на
        // неизменяемый путь, поэтому здесь нет повторного системного запроса.
        for (ProcItem& process : snap_.procs) {
            FillProcessDisplay(process, cache_);
        }
        RebuildRows();
        UpdateStatus();
        SyncMenu();
    }
    UpdateTrayTip();
    return displayApplied;
}

void App::UpdateTitle(bool force) {
    // Незавершённый запуск ещё не означает ошибку загрузки драйвера.
    const bool unavailable = !portmaster_running() &&
        portmaster_last_error() != ERROR_IO_PENDING;
    if (!force && driverUnavailable_ == unavailable) [[likely]] return;
    driverUnavailable_ = unavailable;
    SetWindowTextW(hwnd_, AppInfo::WindowTitle(unavailable).c_str());
}

void App::ShowDriverInstruction() {
    const wchar_t* const file = PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_RUSSIAN
        ? L"instruction.ru.txt" : L"instruction.en.txt";
    const std::wstring directory = ModuleDir();
    const std::wstring path = directory + file;
    std::wstring text;
    const DWORD error = directory.empty() ? ERROR_PATH_NOT_FOUND : ReadInstructionFile(path, text);
    const std::wstring title = AppInfo::WindowTitle(true);
    if (!WindowShown()) ShowWindow(hwnd_, IsIconic(hwnd_) ? SW_RESTORE : SW_SHOW);
    HWND owner = Ui::ModalWindow(hwnd_);
    if (!owner) owner = ask_.visible() ? ask_.hwnd() : hwnd_;
    if (error != ERROR_SUCCESS) {
        const std::wstring message = path + L"\r\n\r\n" + FormatWinError(error);
        Ui::ShowMessage(owner, message.c_str(), title.c_str(), MB_ICONERROR | MB_OK);
        return;
    }

    // Диалог должен помещаться и на экране с крупным масштабированием.
    MONITORINFO monitor{ sizeof(monitor) };
    RECT work{};
    if (GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &monitor))
        work = monitor.rcWork;
    else
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int dpi = static_cast<int>(dpi_ ? dpi_ : 96);
    const int width = std::max(240, std::min(760, MulDiv(work.right - work.left, 96, dpi) - 40));
    const int height = std::max(160, std::min(560, MulDiv(work.bottom - work.top, 96, dpi) - 80));
    InstructionDialog dialog(text);
    dialog.Run(owner, inst_, title, width, height);
}

void App::Tick() {
    UpdateTitle();
    SetMonitorDisplay(WindowShown());
    // Главное окно нельзя оставлять отключённым за невидимым диалогом.
    // Видимое окно при обычном перемещении не трогаем и фокус не перехватываем.
    if (WindowShown()) {
        HWND modal = Ui::ModalWindow(hwnd_);
        if (modal && (!IsWindowVisible(modal) || IsIconic(modal) ||
                      !MonitorFromWindow(modal, MONITOR_DEFAULTTONULL))) [[unlikely]]
            Ui::RestorePopup(modal);
    }
    Ingest::Instance().ExpireSniAssemblies();

    // Сервисные условия и макро-адреса меняются без правки RuleStore. Их
    // версии позволяют перепроверить уже припаркованные обязательства ровно
    // после фактической смены значений. SCM опрашивается фоновым потоком;
    // UI-такт только читает опубликованную версию. Сетевой снимок обновляется
    // по уведомлениям NetworkInterfaceWatcher, без периодического IP Helper.
    bool volatileValuesChanged = false;
    const uint64_t interfacesVersion = rules_.interfaceVersion();
    if (interfacesVersion != interfaceGroupsVersion_) {
        interfaceGroupsVersion_ = interfacesVersion;
        volatileValuesChanged = true;
    }
    const uint64_t serviceVersion = ServiceInfo::Version(false);
    if (serviceVersion != serviceInfoVersion_) [[unlikely]] {
        serviceInfoVersion_ = serviceVersion;
        if (serviceVersion && rules_.serviceConds()) volatileValuesChanged = true;
    }

    if (rules_.macroConds()) {
        const uint64_t version = AddrMacros::Version(false);
        if (version != addrMacrosVersion_) [[unlikely]] {
            addrMacrosVersion_ = version;
            if (version) volatileValuesChanged = true;
        }
    } else {
        addrMacrosVersion_ = 0;
    }

    if (volatileValuesChanged) [[unlikely]] RulesChanged();

    // Готовый снимок забирается без ожидания. Новый тяжёлый проход только
    // планируется; повторные Tick во время его работы сливаются в один запрос.
    const bool snapshotApplied = ApplyMonitorSnapshot();
    monitor_.RequestRefresh();

    // Снимок объединяет таблицы ОС и FlowStore, но в очередь Ask не идёт: запросы
    // порождает только Ingest по событиям транспорта.
    //
    // Если обязательства есть, а в очереди их нет (окно закрывали, программу
    // сворачивали) — вернуть группы в выдачу. Пока окно запроса открыто,
    // этого делать нельзя: показанный запрос уже извлечён из очереди и
    // вернулся бы в неё вторым экземпляром.
    if (Ingest::Instance().waiting() && queue_.empty() &&
        !ask_.visible() && !askBusy_ && autoRequestIds_.empty())
        Ingest::Instance().Republish();

    // Между публикациями всё равно могли измениться очередь запросов, правила
    // или состояние службы — для них полный RebuildRows не нужен.
    if (!snapshotApplied && WindowShown()) {
        UpdateStatus();
        SyncMenu();
    }
    UpdateTrayTip();

    ProcessAutoRules();
    PumpAsk();      // покажет отложенный запрос, когда истечёт пауза
    if (exitPending_ && !Ingest::Instance().waiting() && hwnd_) [[unlikely]]
        PostMessageW(hwnd_, kMsgContinueExit, 0, 0);
}

void App::RebuildRows() {
    if (!WindowShown() || !snap_.displayReady) return;
    const int selectedIndex = list_.Selected();
    const int selected = selectedIndex >= 0 &&
                         selectedIndex < static_cast<int>(list_.rows().size())
        ? selectedIndex : -1;
    if (selected < 0 && !rowsReleased_) selValid_ = false;

    // Нулевое значение зарезервировано для «не отмечена в этом проходе».
    if (++rowBuildSeq_ == 0) [[unlikely]] {
        connectionText_.clear();
        ++rowBuildSeq_;
    }

    // Действие сработавшего правила приходит вместе со строкой (ConnItem::
    // ruleAction): прежде здесь копировался ВЕСЬ набор правил (RuleStore::All)
    // ради карты «id -> действие» — по десятку выделений памяти на правило,
    // и всё это на каждом такте.
    const bool filtering = !filterText_.empty();
    const auto needsText = [&](const ProcItem& process) {
        return filtering || IsProcessExpanded(
            ProcIdentity(process.group, process.ownerAmbiguous));
    };
    size_t textCount = 0;
    for (const ProcItem& process : snap_.procs)
        if (needsText(process)) textCount += process.conns.size();
    connectionText_.Update(textCount, [&](auto indexOf) {
        for (ProcItem& process : snap_.procs) {
            if (!needsText(process)) continue;
            for (ConnItem& connection : process.conns)
                connection.textIndex = indexOf(connection.flowGeneration);
        }
    });

    const auto hit = [&](const std::wstring& s) {
        return !s.empty() && StrStrIW(s.c_str(), filterText_.c_str()) != nullptr;
    };

    const uint64_t currentRuleVersion = rules_.version();
    if (ruleTextVersion_ != currentRuleVersion) [[unlikely]] {
        ruleText_.clear();
        TrimHashTable(ruleText_);
        ruleTextVersion_ = currentRuleVersion;
    }

    const auto ruleInfo = [&](uint64_t ruleId) -> const RuleMatchInfo* {
        if (!ruleId) return nullptr;
        auto found = ruleText_.find(ruleId);
        if (found == ruleText_.end()) [[unlikely]] {
            RuleMatchInfo info;
            if (!rules_.GetInfo(ruleId, info)) [[unlikely]] return nullptr;
            found = ruleText_.emplace(ruleId, std::move(info)).first;
        }
        return &found->second;
    };

    const ULONGLONG statusNow = GetTickCount64();
    const auto ensureStatus = [&](const ConnItem& connection)
        -> const std::wstring& {
        ConnectionText& cached = connectionText_[connection.textIndex];
        // Сортировка обращается к одному статусу многократно, но поля
        // соединения, версия правил и время неизменны в пределах прохода.
        if (cached.statusCheckedBuild == rowBuildSeq_) return cached.status;

        StatusSig signature;
        signature.rulesVersion = currentRuleVersion;
        signature.ruleId = connection.ruleId;
        signature.packetSent = connection.pktSent;
        signature.packetRecv = connection.pktRecv;
        signature.driverEvents = connection.driverEvents;
        signature.state = connection.state;
        signature.bytesFrom = connection.bytesFrom;
        signature.icmpOutType = connection.icmpOut.type;
        signature.icmpOutCode = connection.icmpOut.code;
        signature.icmpOutV6 = connection.icmpOut.v6;
        signature.icmpInType = connection.icmpIn.type;
        signature.icmpInCode = connection.icmpIn.code;
        signature.icmpInV6 = connection.icmpIn.v6;
        signature.ruleGlobal = connection.ruleGlobal;
        signature.byPolicy = connection.byPolicy;
        signature.autoAllowedIcmp = connection.autoAllowedIcmp;
        signature.policy = connection.policy;
        signature.blocked = connection.blockedAt != 0;
        signature.processExited = connection.processExited;
        signature.finished = connection.finished;

        const bool statusUsesIdle =
            (!connection.ruleId && connection.key.proto == Proto::Udp &&
             connection.bytesFrom == BytesDriver) ||
            !ProtoInOsTables(connection.key.proto);
        if (statusUsesIdle && connection.lastActivity) {
            signature.idleSeconds =
                (statusNow - connection.lastActivity) / 1000;
            if (signature.idleSeconds < 2) signature.idleSeconds = 0;
        }

        if (cached.statusValid && cached.statusSig == signature) {
            cached.statusCheckedBuild = rowBuildSeq_;
            return cached.status;
        }

        const RuleMatchInfo* info = ruleInfo(connection.ruleId);
        cached.status = Monitor::ConnectionStatus(
            connection, info ? std::wstring_view(info->name)
                             : std::wstring_view{},
            statusNow);
        cached.statusSig = signature;
        cached.statusValid = true;
        cached.statusCheckedBuild = rowBuildSeq_;
        return cached.status;
    };

    std::vector<size_t> order(snap_.procs.size());
    std::iota(order.begin(), order.end(), size_t{ 0 });
    // Адреса, протокол и направление сортируют только соединения. Группы
    // остаются в естественном порядке, который уже обеспечил Monitor.
    const bool naturalProcOrder = sortCol_ == kSortNatural ||
                                  sortCol_ == ColLocal || sortCol_ == ColRemote ||
                                  sortCol_ == ColProto || sortCol_ == ColDir;
    if (!naturalProcOrder) {
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return CompareProc(snap_.procs[a], snap_.procs[b], sortCol_, sortAsc_);
        });
    }

    // Имя процесса и PID сортируют только группы; внутри группы сохраняется
    // естественный порядок при любом направлении сортировки. После другой
    // колонки восстанавливаем его один раз, включая свёрнутые группы.
    const bool naturalConnOrder = sortCol_ == kSortNatural ||
                                  sortCol_ == ColProcess || sortCol_ == ColPid;
    if (naturalConnOrder && connOrderDirty_) {
        for (ProcItem& process : snap_.procs) {
            std::sort(process.conns.begin(), process.conns.end(),
                      [](const ConnItem& a, const ConnItem& b) {
                          return a.flowGeneration < b.flowGeneration;
                      });
        }
        connOrderDirty_ = false;
    }

    // Эти четыре подписи используются для каждой строки. Одна ссылка на проход
    // вместо сотен тысяч обращений к CachedString сохраняет поддержку смены
    // языка и убирает повторные обращения к потоковому кешу ресурсов.
    const std::wstring& notAvailable = StringResRef(IDS_STATUS_NA);
    const std::wstring& byRules = StringResRef(IDS_STATUS_BY_RULES);
    const std::wstring& noPath = StringResRef(IDS_STATUS_NO_PATH);
    const std::wstring& zeroSpeed = StringResRef(IDS_RED_DASH);

    const auto bytesText = [&](uint64_t value, bool known) {
        return known ? FormatNumber(value) : notAvailable;
    };
    const auto bytesHit = [&](uint64_t value, bool known) {
        if (!known) return hit(notAvailable);
        wchar_t buffer[32];
        return StrStrIW(FormatNumberView(value, buffer).data(), filterText_.c_str()) != nullptr;
    };
    const auto groupReason = [&](const ProcItem& p) {
        std::wstring reason = LoadStringResFmt(IDS_STATUS_CONNS_FMT,
                                               static_cast<unsigned>(p.conns.size()));
        if (p.ruleHits) reason += byRules + std::to_wstring(p.ruleHits);
        if (!p.pathKnown && p.group.pid() > 4 && !p.group.isNdis()) reason += noPath;
        return reason;
    };
    const auto ensureEndpoints = [&](const ConnItem& c) -> ConnectionText& {
        ConnectionText& text = connectionText_[c.textIndex];
        if (text.remote.empty()) [[unlikely]] {
            const bool ports = ProtoHasPorts(c.key.proto);
            text.remote = ports
                ? EndpointToString(c.key.remote, c.key.rport)
                : IpToString(c.key.remote);
            text.local = ports
                ? EndpointToString(c.key.local, c.key.lport)
                : IpToString(c.key.local);
            text.proto = ProtoToString(c.key.proto);
        }
        return text;
    };

    const auto sortChildren = [&](ProcItem& p) {
        if (naturalConnOrder) return;
        if (sortCol_ == ColReason) {
            std::sort(p.conns.begin(), p.conns.end(),
                      [&](const ConnItem& a, const ConnItem& b) {
                          const int result = _wcsicmp(
                              ensureStatus(a).c_str(), ensureStatus(b).c_str());
                          if (result == 0)
                              return a.flowGeneration < b.flowGeneration;
                          return sortAsc_ ? result < 0 : result > 0;
                      });
        } else {
            std::sort(p.conns.begin(), p.conns.end(),
                      [&](const ConnItem& a, const ConnItem& b) {
                          return CompareConn(a, b, sortCol_, sortAsc_);
                      });
        }
        connOrderDirty_ = true;
    };

    // Фильтр выбирает индексы, не создавая Row для отброшенных соединений.
    // Без фильтра число строк уже известно, отдельный план вообще не нужен.
    TreeRowPlan plan(true);
    if (filtering) {
        for (size_t oi : order) {
            ProcItem& p = snap_.procs[oi];
            TreeRowPlan::Source source;
            source.index = oi;
            source.childCount = p.conns.size();
            source.expanded = IsProcessExpanded(ProcIdentity(p.group, p.ownerAmbiguous));
            const std::wstring pidText = p.group.pid() ? std::to_wstring(p.group.pid()) : zeroSpeed;
            const bool childSharedHit = hit(p.name) || hit(pidText);
            source.matches = childSharedHit || hit(p.path) || hit(groupReason(p)) ||
                bytesHit(p.sent, p.bytesKnown) ||
                bytesHit(p.recv, p.bytesKnown) || hit(SpeedText(p.speed, zeroSpeed));
            // Имя службы входит только в строки соединений, а не в заголовок группы.
            source.sharedChildMatch = childSharedHit ||
                (!p.serviceName().empty() && hit(p.hostedServices->front().name));
            sortChildren(p);
            plan.AddGroup(source, [&](size_t index) {
                const ConnItem& c = p.conns[index];
                if (c.tlsDomainLabel && hit(*c.tlsDomainLabel)) return true;
                const ConnectionText& text = ensureEndpoints(c);
                // Счётчики проверяются прямо в стековом буфере: временные строки
                // для отброшенных соединений не создаются. Порядок соответствует колонкам.
                return hit(text.remote) || hit(ensureStatus(c)) ||
                    bytesHit(c.sent, c.bytesKnown()) || bytesHit(c.recv, c.bytesKnown()) ||
                    hit(SpeedText(c.speed, zeroSpeed)) || hit(text.proto) ||
                    hit(text.local) || hit(DirToString(c.dir));
            });
        }
    }

    // Резервируем только известный результат, а не все исходные соединения.
    // Создание и заполнение каждой строки идут подряд, без переноса и уплотнения.
    std::vector<TreeList::Row> rows;
    rows.reserve(filtering ? plan.rowCount() : snap_.procs.size() + textCount);
    int restore = -1;
    shownProcs_ = shownConns_ = 0;
    const auto appendProcess = [&](const ProcItem& p, bool expanded,
                                   size_t childCount, auto childIndex) {
        const int groupRow = static_cast<int>(rows.size());
        rows.emplace_back();
        TreeList::Row& g = rows.back();
        g.isGroup = true;
        g.expanded = expanded;
        g.bold = expanded;
        g.icon = p.icon;
        g.key = MakeRowKey(p, nullptr);
        g.path = p.path;               // всплывающая подсказка колонки «Процесс»
        g.pathKnown = p.pathKnown;
        g.speedActive = p.speed > 0.5;
        // Завершены все соединения процесса: группа приглушается вместе с ними.
        g.finished = p.finished;
        g.col[ColProcess] = p.name;
        g.col[ColReason] = groupReason(p);
        g.col[ColSent] = bytesText(p.sent, p.bytesKnown);
        g.col[ColRecv] = bytesText(p.recv, p.bytesKnown);
        g.col[ColPid] = p.group.pid() && !p.group.isNdis() ? std::to_wstring(p.group.pid()) : zeroSpeed;
        g.col[ColSpeed] = SpeedText(p.speed, zeroSpeed);
        if (selValid_ && g.key == selKey_) restore = groupRow;
        ++shownProcs_;
        shownConns_ += childCount;

        const std::wstring_view serviceName = p.serviceName();
        for (size_t index = 0; index < childCount; ++index) {
            const ConnItem& c = p.conns[childIndex(index)];
            rows.emplace_back();
            TreeList::Row& r = rows.back();
            // Приглушается только завершённое соединение в пределах окна показа.
            r.finished = c.finished;
            r.key = MakeRowKey(p, &c);
            // Полный путь принадлежит только соседней строке-группе.
            r.pathKnown = p.pathKnown;
            r.ruleId = c.ruleId;
            if (const RuleMatchInfo* info = ruleInfo(c.ruleId))
                r.ruleName = info->name;
            r.tlsDomainLabel = c.tlsDomainLabel;
            r.speedActive = c.speed > 0.5;
            r.ruleAction = c.ruleAction;
            const ConnectionText& text = ensureEndpoints(c);
            r.col[ColProcess] = serviceName;
            r.col[ColRemote] = text.remote;
            r.col[ColReason] = ensureStatus(c);
            r.col[ColSent] = bytesText(c.sent, c.bytesKnown());
            r.col[ColRecv] = bytesText(c.recv, c.bytesKnown());
            r.col[ColSpeed] = SpeedText(c.speed, zeroSpeed);
            r.col[ColProto] = text.proto;
            r.col[ColLocal] = text.local;
            r.col[ColDir] = DirToString(c.dir);
            r.groupRow = groupRow;
            r.lastChild = (index + 1 == childCount);
            if (selValid_ && r.key == selKey_)
                restore = static_cast<int>(rows.size()) - 1;
        }
    };
    const auto directIndex = [](size_t index) { return index; };
    if (filtering) {
        for (const TreeRowPlan::Group& group : plan.groups()) {
            const ProcItem& p = snap_.procs[group.source];
            if (group.allChildren) {
                appendProcess(p, group.expanded, group.childCount, directIndex);
            } else {
                appendProcess(p, group.expanded, group.childCount,
                    [&](size_t index) { return plan.ChildIndex(group, index); });
            }
        }
    } else {
        for (size_t oi : order) {
            ProcItem& p = snap_.procs[oi];
            const bool expanded = IsProcessExpanded(ProcIdentity(p.group, p.ownerAmbiguous));
            if (expanded) sortChildren(p);
            appendProcess(p, expanded, expanded ? p.conns.size() : 0, directIndex);
        }
    }

    // SetRows сохраняет числовой индекс выделения, если он всё ещё укладывается
    // в новый массив. Если строка по устойчивому ключу не нашлась, этот индекс
    // уже относится к другой строке — снять выделение нужно ДО SetRows.
    const bool selectionCleared = restore < 0 && selected >= 0;
    if (restore < 0) {
        selValid_ = false;
        if (selected >= 0)
            ListView_SetItemState(list_.hwnd(), selected, 0,
                                  LVIS_SELECTED | LVIS_FOCUSED);
    }

    list_.SetRows(std::move(rows));
    rowsReleased_ = false;
    if (restore >= 0) list_.Select(restore);
    else if (selectionCleared && menu_) SyncMenu();
}

void App::UpdateStatus() {
    if (!WindowShown() || !snap_.displayReady) return;
	const auto set = [&](int i, const std::wstring& s) {
        // SB_SETTEXT перерисовывает часть строки состояния, а части
        // «пассивные» и «правила» подолгу не меняются: сравнение снимает
        // и сообщения, и перерисовку.
        if (statusPart_[i] == s) return;
        statusPart_[i] = s;
        SendMessageW(status_, SB_SETTEXTW, static_cast<WPARAM>(i),
                     reinterpret_cast<LPARAM>(s.c_str()));
        SendMessageW(status_, SB_SETTIPTEXTW, static_cast<WPARAM>(i),
                     reinterpret_cast<LPARAM>(s.c_str()));
    };

    std::wstring p0 = LoadStringResFmt(IDS_STATUS_PROCS_FMT,
                                      static_cast<unsigned>(snap_.procs.size()),
                                      static_cast<unsigned>(snap_.connCount));
    if (!filterText_.empty())
        p0 += LoadStringResFmt(IDS_STATUS_FILTER_FMT,
                               static_cast<unsigned>(shownProcs_),
                               static_cast<unsigned>(shownConns_));
    set(0, p0);

    std::wstring p1 = LoadStringResFmt(IDS_STATUS_PASSIVE_FMT,
                                      static_cast<unsigned>(snap_.hiddenCount)) +
                      LoadStringRes(monitor_.showPassive() ? IDS_STATUS_SHOWN
                                                           : IDS_STATUS_HIDDEN);
    // Счётчик снятых записей FlowStore включает завершение, неактивность
    // и удаление процессов. Это не число новых END: завершённые строки ещё
    // остаются в хранилище на время окна показа.
    if (snap_.closedDropped)
        p1 += LoadStringResFmt(IDS_STATUS_FINISHED_FMT,
                               static_cast<unsigned>(snap_.closedDropped));
    set(1, p1);

    // «запросов» — только обязательства по событиям транспорта: строки
    // таблиц ОС запросов не порождают
    std::wstring p2 = LoadStringResFmt(IDS_STATUS_RULES_FMT,
                                      static_cast<unsigned>(rules_.Count()),
                                      static_cast<unsigned>(rules_.GlobalCount()),
                                      static_cast<unsigned>(rules_.PostAppCount()),
                                      static_cast<unsigned>(snap_.ruleMatches),
                                      static_cast<unsigned>(queue_.size()));
    if (const size_t held = queue_.held())
        p2 += LoadStringResFmt(IDS_TRAY_TIP_DEFERRED_FMT,
                               static_cast<unsigned>(held));
    set(2, policyHint_.empty() ? p2 : policyHint_);

    // Контроль контракта: вызовов = отвечено + ожидает
    const Ingest& ing = Ingest::Instance();
    std::wstring p3 = LoadStringResFmt(IDS_STATUS_VERDICTS_FMT,
                                      FormatNumber(ing.answered()).c_str(),
                                      FormatNumber(ing.calls()).c_str(),
                                      FormatNumber(ing.waiting()).c_str());
    set(3, p3);

    std::wstring p4 = LoadStringResFmt(IDS_STATUS_TRAFFIC_FMT,
                                      FormatBytes(snap_.totalSent).c_str(),
                                      FormatBytes(snap_.totalRecv).c_str());
    if (!warn_.empty()) p4 = LoadStringRes(IDS_STATUS_WARN_PREFIX) + p4;
    set(4, p4);
}

void App::ShowMenu(int row, POINT pt) {
    const Selection sel = GetSelection();
    Rule r;
    const bool canApp  = sel.valid && (!sel.appPath.empty() || sel.group.isNdis());
    const bool hasRule = ResolveRule(sel, r);

    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING | (canApp ? 0 : MF_GRAYED), IDM_RULE_CREATE,
                LoadStringRes(IDS_CTX_RULE_CREATE).c_str());
    AppendMenuW(m, MF_STRING, IDM_RULE_CREATE_GLOBAL,
                LoadStringRes(IDS_MENU_RULES_CREATE_GLOBAL).c_str());
    if (hasRule) {
        std::wstring edit = LoadStringResFmt(IDS_CTX_RULE_EDIT_FMT, r.name.c_str());
        std::wstring del  = LoadStringResFmt(IDS_CTX_RULE_DELETE_FMT, r.name.c_str());
        // Многоточие обрезки оставлено в коде: это типографский знак, а не
        // текст для перевода — во всех языках он одинаков
        if (edit.size() > 90) { edit.resize(87); edit += L"…"; }
        if (del.size()  > 90) { del.resize(87);  del  += L"…"; }
        AppendMenuW(m, MF_STRING, IDM_RULE_EDIT,   edit.c_str());
        AppendMenuW(m, MF_STRING, IDM_RULE_DELETE, del.c_str());
    }
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (canApp ? 0 : MF_GRAYED), IDM_RULES_APP,
                LoadStringRes(IDS_CTX_RULES_APP).c_str());
    AppendMenuW(m, MF_STRING, IDM_RULES_GLOBAL, LoadStringRes(IDS_CTX_RULES_GLOBAL).c_str());
    AppendMenuW(m, MF_STRING, IDM_RULES_ALL,    LoadStringRes(IDS_CTX_RULES_EDITOR).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (queue_.ready() ? 0 : MF_GRAYED), IDM_ASK_NOW,
                LoadStringRes(IDS_CTX_ASK_NOW).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_REFRESH, LoadStringRes(IDS_CTX_REFRESH).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_EXPAND_ALL,   LoadStringRes(IDS_CTX_EXPAND).c_str());
    AppendMenuW(m, MF_STRING, IDM_COLLAPSE_ALL, LoadStringRes(IDS_CTX_COLLAPSE).c_str());
    AppendMenuW(m, MF_STRING | (sortCol_ == kSortNatural ? MF_CHECKED : 0),
                IDM_SORT_DEFAULT, LoadStringRes(IDS_CTX_SORT_DEFAULT).c_str());
    AppendMenuW(m, MF_STRING | (monitor_.showPassive() ? MF_CHECKED : 0),
                IDM_SHOW_PASSIVE, LoadStringRes(IDS_BTN_SHOW_PASSIVE).c_str());
    // Оформление: в контекстном меню достаточно переключателя, а его подпись
    // сообщает, КУДА он переключит, — читать состояние отдельно не нужно.
    AppendMenuW(m, MF_STRING, IDM_SKIN_TOGGLE,
                list_.skin() == ListSkin::Modern
                    ? LoadStringRes(IDS_CTX_SKIN_TO_CLASSIC).c_str()
                    : LoadStringRes(IDS_CTX_SKIN_TO_MODERN).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (row < 0 ? MF_GRAYED : 0), IDM_COPY_ROW, LoadStringRes(IDS_CTX_COPY_ROW).c_str());
    AppendMenuW(m, MF_STRING, IDM_COPY_ALL, LoadStringRes(IDS_CTX_COPY_ALL).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);

    // «Прервать соединение» стоит рядом с «Завершить процесс» и перед ним:
    // порядок от точечного действия к самому грубому.
    const ConnKill::Target target = KillTargetOf(sel);
    const ConnKill::Denial denial = ConnKill::Check(target);
    if (denial == ConnKill::Denial::None) {
		AppendMenuW(m, MF_STRING ,IDM_KILL_CONN, LoadStringRes(IDS_CTX_CONN_KILL).c_str());
    }
    AppendMenuW(m, MF_STRING | ((row < 0 || sel.group.pid() <= 4 || sel.group.isNdis()) ? MF_GRAYED : 0),
                IDM_KILL, LoadStringRes(IDS_CTX_PROC_KILL).c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_TRAY_HIDE, LoadStringRes(IDS_CTX_HIDE_TRAY).c_str());
    TrackPopupMenu(m, Ui::PopupFlags(TPM_RIGHTBUTTON), pt.x, pt.y, 0, hwnd_, nullptr);
    DestroyMenu(m);
}

void App::CopyRows(bool onlySelected) {
    const auto& rows = list_.rows();
    std::wstring text;
    const auto cellText = [&](size_t index, int column) {
        const TreeList::Row& row = rows[index];
        if ((column == ColProcess || column == ColPid) && !row.isGroup &&
            row.groupRow >= 0 &&
            row.groupRow < static_cast<int>(rows.size())) {
            const TreeList::Row& process =
                rows[static_cast<size_t>(row.groupRow)];
            std::wstring value = column == ColProcess
                ? row.processName(process) : process.col[column];
            if (column == ColProcess && row.tlsDomainLabel &&
                !row.tlsDomainLabel->empty()) {
                value += L" ";
                value += *row.tlsDomainLabel;
            }
            return value;
        }
        return row.col[column];
    };
    const auto append = [&](size_t index) {
        for (int column = 0; column < ColumnCount; ++column) {
            text += cellText(index, column);
            text += (column + 1 == ColumnCount) ? L"\r\n" : L"\t";
        }
    };
    if (onlySelected) {
        const int selected = list_.Selected();
        if (selected < 0 || selected >= static_cast<int>(rows.size())) return;
        append(static_cast<size_t>(selected));
    } else {
        for (size_t index = 0; index < rows.size(); ++index) append(index);
    }
    if (text.empty() || !OpenClipboard(hwnd_)) return;
    EmptyClipboard();
    const size_t cb = (text.size() + 1) * sizeof(wchar_t);
    if (HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, cb)) {
        if (void* p = GlobalLock(h)) {
            std::memcpy(p, text.c_str(), cb);
            GlobalUnlock(h);
            if (!SetClipboardData(CF_UNICODETEXT, h)) GlobalFree(h);
        } else {
            GlobalFree(h);
        }
    }
    CloseClipboard();
}

void App::KillSelected() {
    if (!snap_.displayReady) return;
    const int sel = list_.Selected();
    if (sel < 0 || sel >= static_cast<int>(list_.rows().size())) return;
    const TrafficGroupKey group = list_.rows()[static_cast<size_t>(sel)].key.group;
    const DWORD pid = group.pid();
    DeferVisibleAsk();
    if (!group.isHost() || pid <= 4) {
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_ERR_TERMINATE_SYSTEM).c_str(),
                    LoadStringRes(IDS_ERROR_TITLE).c_str(), MB_ICONINFORMATION);
        return;
    }
    const std::wstring q = LoadStringResFmt(IDS_TERMINATE_CONFIRM_FMT,
                                            static_cast<unsigned>(pid));
    // Дескриптор берём ДО подтверждения и держим его до действия. Даже если
    // исходный процесс завершится и его PID будет переиспользован, вызов по
    // этому handle всё равно относится к исходному объекту процесса.
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (Ui::ShowMessage(hwnd_, q.c_str(), LoadStringRes(IDS_CONFIRM_TITLE).c_str(), MB_ICONWARNING | MB_YESNO) != IDYES) {
        if (h) CloseHandle(h);
        return;
    }
    const bool ok = h && TerminateProcess(h, 1);
    if (!ok)
        Ui::ShowMessage(hwnd_, LoadStringRes(IDS_ERR_TERMINATE_FAILED).c_str(),
                    LoadStringRes(IDS_ERROR_TITLE).c_str(), MB_ICONERROR);
    if (h) CloseHandle(h);
    Tick();
}

ConnKill::Target App::KillTargetOf(const Selection& sel) const {
    ConnKill::Target t;
    if (!sel.valid || sel.isGroup || !sel.hasConn ||
        sel.conn.key.source == TrafficSource::Ndis) return t;   // valid остаётся false

    const ConnItem& c = sel.conn;
    t.valid  = true;
    t.proto  = c.key.proto;
    t.local  = c.key.local;
    t.remote = c.key.remote;
    t.lport  = c.key.lport;
    t.rport  = c.key.rport;
    t.state  = c.state;
    return t;
}

void App::InterruptSelected() {
    if (!snap_.displayReady) return;
    const Selection sel = GetSelection();
    const ConnKill::Target t = KillTargetOf(sel);

    const ConnKill::Denial d = ConnKill::Check(t);
    if (d != ConnKill::Denial::None) {
        // Проверяем текущую выбранную строку независимо от способа вызова команды.
        // При построении меню для такой цели пункт также был бы неактивен.
        DeferVisibleAsk();
        Ui::ShowMessage(hwnd_, ConnKill::DenialText(d).c_str(), LoadStringRes(IDS_WND_CONN_KILL).c_str(),
                    MB_ICONINFORMATION);
        Tick();
        return;
    }

    std::wstring err;
    if (!ConnKill::Kill(t, err)) {
        DeferVisibleAsk();
        Ui::ShowMessage(hwnd_,
                    (LoadStringRes(IDS_CONN_KILL_FAILED).c_str() + err).c_str(),
                    LoadStringRes(IDS_WND_CONN_KILL).c_str(), MB_ICONERROR);
        Tick();
        return;
    }

    // Соединение помечается ЗАВЕРШЁННЫМ — тем же путём, которым его помечает
    // событие on_connection_end_*. Строка не исчезает сразу: она показывается
    // приглушённой ещё kFinishedGraceMs (FlowStore.h) вместе с итоговыми
    // счётчиками, и лишь затем снимается. Таблиц ОС при этом не ждём:
    // удалённый блок управления передачей может отображаться как TIME_WAIT
    // и после того, как соединения уже нет.
    FlowStore::Instance().CloseFlow(
        sel.conn.key, sel.group.pid(), sel.conn.dir, sel.conn.flowGeneration);
    Tick();
}

} // namespace

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR cmdLine, int cmdShow) {
    int bindingHelperCode = 0;
    if (ndis_binding::TryRunHelper(bindingHelperCode)) return bindingHelperCode;

    // Режим запуска определяется до любой работы с интерфейсом
    FirewallX::DetectRunMode(GetCommandLineW());

    if (FirewallX::IsService()) {
        int code = 0;
        if (FirewallX::RunAsService(code)) return code;   // служебный маршрут, без перехода к UI
        FirewallX::ForceDesktopMode();                    // SCM недоступен — обычный запуск
    }

    const bool startInTray = _wcsicmp(cmdLine, StartupOptions::kStartInTrayArgument) == 0;

    // Оконная копия должна быть одна. Служба сюда не попадает — её экземпляр
    // не учитывается и не затрагивается. Автозапуск не открывает уже скрытое окно.
    FirewallX::SingleInstance single;
    if (!single.Acquire(!startInTray)) return 0;

    const DWORD protectionStatus = ProcessProtectionOptions::ApplySaved();
    if (protectionStatus != ERROR_SUCCESS) {
        SetUiLang(UiLangSetting::Load());
        const std::wstring message = LoadStringResFmt(
            IDS_SETTINGS_DLL_PROTECTION_APPLY_ERROR, static_cast<unsigned>(protectionStatus));
        const std::wstring title = LoadStringRes(IDS_APPNAME);
        if (Ui::ShowMessage(nullptr, message.c_str(), title.c_str(),
                            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES) {
            // Даже при частичном включении политики действуют до завершения процесса.
            if (!ProcessProtectionOptions::Save(false)) {
                const std::wstring saveError = LoadStringResFmt(
                    IDS_SETTINGS_DLL_PROTECTION_SAVE_ERROR, Settings::lastError().c_str());
                Ui::ShowMessage(nullptr, saveError.c_str(), title.c_str(), MB_ICONERROR | MB_OK);
            }
        }
        return 1;
    }

    if (!Ui::InitializeDpiAwareness()) {
        const DWORD error = GetLastError();
        SetUiLang(UiLangSetting::Load());
        const std::wstring message = LoadStringResFmt(
            IDS_SETTINGS_SYSTEM_SCALING_APPLY_ERROR, static_cast<unsigned>(error));
        Ui::ShowMessage(nullptr, message.c_str(), LoadStringRes(IDS_APPNAME).c_str(),
                        MB_ICONERROR | MB_OK);
        return 1;
    }
    EnableDebugPrivilege();          // SE_DEBUG: доступ к чужим процессам

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    INITCOMMONCONTROLSEX icc{ sizeof(icc),
        ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES |
        ICC_TAB_CLASSES | ICC_LINK_CLASS | ICC_INTERNET_CLASSES };
    InitCommonControlsEx(&icc);

    int rc = 1;
    {
        App app;
        if (app.Init(inst, cmdShow, startInTray)) {
            MSG msg{};
            for (;;) {
                const BOOL got = GetMessageW(&msg, nullptr, 0, 0);
                if (got == 0) { rc = static_cast<int>(msg.wParam); break; }
                if (got < 0)  { rc = 1; break; }
                if (app.PreTranslate(msg)) continue;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    CoUninitialize();
    WSACleanup();
    return rc;
}