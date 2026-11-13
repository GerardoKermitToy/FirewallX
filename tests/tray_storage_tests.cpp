// Проверяется настоящий оконный код без App::Init: драйвер, служба и база
// пользователя не запускаются. Меняются только окна внутри процесса теста.
#include "../Common.h"

namespace {
HWND clipboardProbe = nullptr;
bool probeClipboard = false;
bool clipboardOpen = false;
std::wstring clipboardText;

BOOL TestOpenClipboard(HWND owner) {
    if (!probeClipboard) return OpenClipboard(owner);
    clipboardProbe = owner;
    clipboardOpen = true;
    return TRUE;
}

BOOL TestEmptyClipboard() {
    if (!probeClipboard) return EmptyClipboard();
    clipboardText.clear();
    return clipboardOpen;
}

HANDLE TestSetClipboardData(UINT format, HANDLE data) {
    if (!probeClipboard) return SetClipboardData(format, data);
    if (!clipboardOpen || format != CF_UNICODETEXT) return nullptr;
    const auto* text = static_cast<const wchar_t*>(GlobalLock(data));
    if (!text) return nullptr;
    clipboardText = text;
    GlobalUnlock(data);
    GlobalFree(data);
    return reinterpret_cast<HANDLE>(1);
}

BOOL TestCloseClipboard() {
    if (!probeClipboard) return CloseClipboard();
    clipboardOpen = false;
    return TRUE;
}
}

// Не изменяем настоящий буфер обмена пользователя при проверке сочетания.
#define OpenClipboard TestOpenClipboard
#define EmptyClipboard TestEmptyClipboard
#define SetClipboardData TestSetClipboardData
#define CloseClipboard TestCloseClipboard
#include "../main.cpp"
#undef CloseClipboard
#undef SetClipboardData
#undef EmptyClipboard
#undef OpenClipboard

#include <initializer_list>
#include <future>

void TestDebugWindow();
void TestSettingsNdis();
#include <iostream>
#include <stdexcept>

namespace {
void CheckTray(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct InstructionDialogProbe {
    std::wstring expected;
    bool checked = false;
    bool correct = false;
};

InstructionDialogProbe* instructionProbe = nullptr;

LRESULT CALLBACK CheckInstructionDialog(int code, WPARAM wp, LPARAM lp) {
    const auto* event = reinterpret_cast<const CWPSTRUCT*>(lp);
    if (code < 0 || event->message != WM_SHOWWINDOW || !event->wParam ||
        event->hwnd != Ui::ModalWindow())
        return CallNextHookEx(nullptr, code, wp, lp);
    const HWND dialog = event->hwnd;
    const HWND edit = GetDlgItem(dialog, 101);
    const HWND close = GetDlgItem(dialog, IDOK);
    const LONG_PTR style = edit ? GetWindowLongPtrW(edit, GWL_STYLE) : 0;
    const LONG_PTR exStyle = edit ? GetWindowLongPtrW(edit, GWL_EXSTYLE) : 0;
    const int length = edit ? GetWindowTextLengthW(edit) : 0;
    std::wstring actual(static_cast<size_t>(length) + 1, L'\0');
    if (edit) GetWindowTextW(edit, actual.data(), length + 1);
    actual.resize(static_cast<size_t>(length));
    instructionProbe->checked = true;
    instructionProbe->correct = edit && close &&
        (style & (ES_MULTILINE | ES_READONLY | WS_VSCROLL)) ==
            (ES_MULTILINE | ES_READONLY | WS_VSCROLL) &&
        !(exStyle & (WS_EX_LAYOUTRTL | WS_EX_RTLREADING | WS_EX_RIGHT)) &&
        actual == instructionProbe->expected;
    PostMessageW(dialog, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED),
                 reinterpret_cast<LPARAM>(close));
    return CallNextHookEx(nullptr, code, wp, lp);
}

void TestInstructionDialog(const std::wstring& text) {
    InstructionDialogProbe probe;
    probe.expected = text;
    instructionProbe = &probe;
    SetUiLang(UiLang::Arabic);
    const HHOOK hook = SetWindowsHookExW(WH_CALLWNDPROC, CheckInstructionDialog,
                                         nullptr, GetCurrentThreadId());
    CheckTray(hook != nullptr, "could not observe instruction dialog");
    InstructionDialog dialog(probe.expected);
    dialog.Run(nullptr, GetModuleHandleW(nullptr), L"test", 600, 400);
    UnhookWindowsHookEx(hook);
    instructionProbe = nullptr;
    SetUiLang(UiLang::English);
    CheckTray(probe.checked && probe.correct,
              "instruction dialog lost text, scrolling, read-only or left-to-right layout");
}
} // namespace

struct StorageTestAccess {
    template<class Read>
    static void CheckDebugBusy(std::mutex& mutex, Read read) {
        std::unique_lock hold(mutex);
        auto future = std::async(std::launch::async, [&] {
            DebugCounters::Snapshot sample;
            read(sample);
            return sample;
        });
        const bool ready = future.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
        hold.unlock();
        const auto sample = future.get();
        CheckTray(ready, "diagnostics waited for a busy collection");
        for (const auto& value : sample.values)
            CheckTray(!value, "busy collection returned a fabricated zero");
    }

    static void TestTrafficGroupRows() {
        const auto host = TrafficGroupKey::Host(1000);
        const auto guest = TrafficGroupKey::Ndis(1000);
        CheckTray(host != guest && host.pid() == 1000 && guest.pid() == 0,
                  "interface index was interpreted as a host PID");
        TreeList tree;
        tree.rows_.resize(3);
        tree.rows_[0].isGroup = true;
        tree.rows_[0].key.group = host;
        tree.rows_[1].isGroup = true;
        tree.rows_[1].key.group = guest;
        tree.rows_[2].key.group = guest;
        tree.rows_[2].groupRow = 0;
        CheckTray(tree.GroupRowOf(2) == 1 && !tree.ProcessRow(tree.rows_[2]).isGroup,
                  "interface child attached to a host with the same numeric ID");
        tree.rows_[2].groupRow = 1;
        CheckTray(&tree.ProcessRow(tree.rows_[2]) == &tree.rows_[1],
                  "interface child did not resolve its own group");
        tree.rows_[1].col[ColProcess] = L"Test interface";
        CheckTray(tree.BuildTip(2).find(L"PID:") == std::wstring::npos,
                  "interface tooltip displayed its index as a PID");
        ProcItem hostProcess, guestProcess;
        hostProcess.group = host;
        guestProcess.group = guest;
        CheckTray(MakeRowKey(hostProcess, nullptr) != MakeRowKey(guestProcess, nullptr) &&
                  ProcIdentity(host, false) != ProcIdentity(guest, false) &&
                  ProcIdentity(guest, false) != ProcIdentity(guest, true),
                  "selection or expansion identity merged different sources");
        guestProcess.group = TrafficGroupKey::Ndis(0);
        CheckTray(MakeRowKey(guestProcess, nullptr).valid(), "interface zero has an invalid row key");
        ProcessCache cache;
        FillProcessDisplay(guestProcess, cache);
        DebugCounters::Snapshot debug;
        cache.ReadDebugCounters(debug);
        CheckTray(!guestProcess.pathInfo && !guestProcess.hostedServices && guestProcess.icon &&
                  debug.values[DebugCounters::CachedProcesses] == 0 &&
                  guestProcess.name == InterfaceDisplayName(0),
                  "interface display resolved or cached a fictitious process");
    }

    static void TestDebugCounters() {
        FlowStore flows;
        flows.processes_[11].connections.try_emplace(1);
        flows.processes_[11].connections.try_emplace(2);
        flows.processes_[22].connections.try_emplace(3);
        flows.ownerIndexes_.tcpV4.try_emplace(FlowKey{});
        flows.ndisConnections_[FlowKey{}] = 1;
        DebugCounters::Snapshot sample;
        flows.ReadDebugCounters(sample);
        CheckTray(sample.values[DebugCounters::FlowProcesses] == 2 &&
                  sample.values[DebugCounters::FlowConnections] == 3 &&
                  sample.values[DebugCounters::FlowNdisConnections] == 1 &&
                  sample.values[DebugCounters::OwnerTcpV4] == 1 &&
                  sample.values[DebugCounters::OwnerTcpV6] == 0,
                  "flow diagnostics returned incorrect sizes");
        CheckDebugBusy(flows.mtx_, [&](auto& out) { flows.ReadDebugCounters(out); });

        RuleStore rules;
        Rule rule;
        rule.scope = RuleScope::Global;
        rules.Add(rule);
        rules.SetInheritance(L"C:\\debug-counter.exe", RuleInheritance::Enabled);
        rules.ReadDebugCounters(sample);
        CheckTray(sample.values[DebugCounters::Rules] == 1 &&
                  sample.values[DebugCounters::RuleIds] == 1 &&
                  sample.values[DebugCounters::RuleCandidates] == 1 &&
                  sample.values[DebugCounters::RuleApps] == 0 &&
                  sample.values[DebugCounters::RuleInheritanceBuckets] == 1 &&
                  sample.values[DebugCounters::RuleInheritanceSettings] == 1 &&
                  sample.values[DebugCounters::RuleNameReferences] == 1 &&
                  sample.values[DebugCounters::RuleInterfaceCandidates] == 0,
                  "rule diagnostics returned incorrect sizes");
        CheckDebugBusy(rules.mtx_, [&](auto& out) { rules.ReadDebugCounters(out); });
        pmkext::ProcessTable processEvents;
        processEvents.ReadDebugCounters(sample);
        CheckTray(sample.values[DebugCounters::ProcessEntries] == 0 &&
                  sample.values[DebugCounters::ProcessRetired] == 0 &&
                  sample.values[DebugCounters::ProcessLateLineages] == 0 &&
                  sample.values[DebugCounters::ProcessPaths] == 0,
                  "process event diagnostics returned incorrect sizes");
        CheckDebugBusy(detail::aliveCache().mtx, [](auto& out) {
            size_t size = 0;
            if (TryGetSystemProcessCacheSize(size))
                out.values[DebugCounters::SystemProcesses] = size;
        });
        Ingest::Instance().ReadDebugCounters(sample);
        CheckTray(sample.values[DebugCounters::PendingGroups] == 0 &&
                  sample.values[DebugCounters::WaitingRequests] == 0 &&
                  sample.values[DebugCounters::Verdicts] == 0,
                  "empty ingest diagnostics returned incorrect sizes");
        std::cout << "debug counters: collection sizes and nonblocking reads passed\n";
    }

    static void Publish(Monitor& monitor, Snapshot snapshot) {
        std::lock_guard<std::mutex> lock(monitor.publishMtx_);
        monitor.published_ = std::move(snapshot);
        monitor.publishedReady_ = true;
    }

    static void FillTextCopies(TreeList& list, int selected) {
        list.SetTipText(std::wstring(100000, L'p'));
        list.tipRow_ = list.pendRow_ = selected;
        list.tipVisible_ = true;
        SetTimer(list.hwnd_, TreeList::kTipTimer, TreeList::kTipDelayMs, nullptr);
        for (auto& text : list.displayText_) text.assign(100000, L'a');
        list.textWidths_.Get(L"cached-row-name.exe", false, [] { return 100; });
    }

    static void CheckReleased(const TreeList& list) {
        CheckTray(list.rows().empty() && list.rows().capacity() == 0 &&
                  ListView_GetItemCount(list.hwnd()) == 0 && list.Selected() < 0,
                  "hidden list retained rows, their allocation or item state");
        CheckTray(!list.tipVisible_ && list.tipRow_ < 0 && list.pendRow_ < 0 &&
                  list.tipText_.empty() && list.tipText_.capacity() < 32 &&
                  list.textWidths_.empty(),
                  "hidden list retained tooltip text, pending tooltip or width cache");
        for (const auto& text : list.displayText_)
            CheckTray(text.empty() && text.capacity() < 32,
                      "hidden list retained a display text buffer");
    }
};

namespace {
struct AppStorageTestAccess {
    static LRESULT CALLBACK HostProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
        if (message == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lp);
            SetWindowLongPtrW(window, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(create->lpCreateParams));
        }
        auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (app && app->list_.hwnd()) {
            if (message == WM_SHOWWINDOW || message == WM_SIZE)
                return app->WndProc(window, message, wp, lp);
            if (message == WM_NOTIFY) {
                LRESULT result = 0;
                if (app->list_.OnNotify(reinterpret_cast<LPNMHDR>(lp), result)) return result;
            }
        }
        return DefWindowProcW(window, message, wp, lp);
    }

    static Snapshot FullSnapshot(std::initializer_list<uint64_t> generations) {
        Snapshot snapshot;
        snapshot.displayReady = true;
        snapshot.procs.reset(1);
        snapshot.conns.reset(generations.size());
        snapshot.connCount = snapshot.flowCount = generations.size();
        ProcItem& process = snapshot.procs[0];
        process.group = TrafficGroupKey::Host(GetCurrentProcessId());
        process.conns = {snapshot.conns.data(), snapshot.conns.size()};
        size_t index = 0;
        for (uint64_t generation : generations) {
            ConnItem& connection = snapshot.conns[index++];
            connection.pid = process.group.pid();
            connection.flowGeneration = generation;
            IpAddr local, remote;
            local.family = remote.family = AF_INET;
            local.b[0] = 192;
            local.b[1] = 0;
            local.b[2] = 2;
            local.b[3] = 1;
            remote.b[0] = 198;
            remote.b[1] = 51;
            remote.b[2] = 100;
            remote.b[3] = static_cast<uint8_t>(generation);
            connection.key = MakeFlowKey(Proto::Tcp, local, remote,
                                        static_cast<uint16_t>(40000 + generation), 443);
            connection.state = MIB_TCP_STATE_ESTAB;
            connection.dir = Dir::Out;
        }
        return snapshot;
    }

    static void Apply(App& app, Snapshot snapshot) {
        StorageTestAccess::Publish(app.monitor_, std::move(snapshot));
        CheckTray(app.ApplyMonitorSnapshot(), "full snapshot was not applied");
        CheckTray(!app.rowsReleased_ && app.snap_.displayReady,
                  "full snapshot did not resume the visible list");
    }

    static void CheckSelection(const App& app, const TreeList::RowKey& key) {
        const int selected = app.list_.Selected();
        CheckTray(selected >= 0 && selected < static_cast<int>(app.list_.rows().size()) &&
                  app.list_.rows()[static_cast<size_t>(selected)].key == key &&
                  app.selValid_ && app.selKey_ == key && app.GetSelection().hasConn,
                  "restoring the window lost selection or selected another connection");
    }

    static void CheckNoSelection(const App& app) {
        CheckTray(app.list_.Selected() < 0 && !app.selValid_ && !app.GetSelection().valid,
                  "missing or deselected connection restored a stale selection");
    }

    static void TestRuleTemplates() {
        App app;
        App::Selection selection;
        selection.valid = true;
        selection.appName = L"Selected interface";
        for (uint32_t index : {0u, 7u}) {
            selection.group = TrafficGroupKey::Ndis(index);
            selection.hasConn = false;
            selection.isGroup = true;
            const Rule group = app.MakeRuleTemplate(selection, true);
            CheckTray(group.isGlobal() && group.appPath.empty(),
                      "global command created an interface group rule");
            selection.hasConn = true;
            selection.isGroup = false;
            selection.conn.key.source = TrafficSource::Ndis;
            selection.conn.key.interfaceIndex = index;
            const Rule connection = app.MakeRuleTemplate(selection, true);
            CheckTray(connection.isGlobal() && connection.appPath.empty(),
                      "global command created an interface connection rule");
        }
        selection.group = TrafficGroupKey::Host(GetCurrentProcessId());
        selection.hasConn = false;
        selection.appPath = L"C:/Apps/rule-template.exe";
        CheckTray(app.MakeRuleTemplate(selection, true).isGlobal() &&
                      app.MakeRuleTemplate(selection, false).scope == RuleScope::App,
                  "interface fix changed host rule creation");
        const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
        CheckTray(snapshot != nullptr, "no interface snapshot for rule template");
        for (const auto& entry : snapshot->interfaces) {
            if (!entry.up || !entry.number || entry.name.empty()) continue;
            selection.group = TrafficGroupKey::Ndis(entry.number);
            const Rule rule = app.MakeRuleTemplate(selection, false);
            CheckTray(rule.isInterface() && rule.appPath == entry.name,
                      "ordinary interface group command lost its scope");
            selection.hasConn = true;
            selection.conn.key.interfaceIndex = entry.number;
            const Rule flow = app.MakeRuleTemplate(selection, false);
            CheckTray(flow.isInterface() && flow.appPath == entry.name,
                      "ordinary interface connection command lost its scope");
            break;
        }
        selection.group = TrafficGroupKey::Host(GetCurrentProcessId());
        selection.hasConn = true;
        selection.conn.key.source = TrafficSource::Host;
        for (const auto& entry : snapshot->interfaces) {
            if (!entry.up || !entry.number || entry.name.empty()) continue;
            selection.conn.interfaceIndex = entry.number;
            for (const auto& name : {
                    std::make_shared<const std::wstring>(L"Former adapter Сеть 网络"),
                    std::make_shared<const std::wstring>()}) {
                selection.conn.interfaceName = name;
                for (bool global : {false, true}) {
                    const Rule rule = app.MakeRuleTemplate(selection, global);
                    CheckTray(rule.interfaceName == *name && !(rule.conds & CondInterface),
                              "stored connection template adopted the current owner of an old IfIndex");
                }
            }
            break;
        }
        selection.conn.interfaceName.reset();
        selection.group = TrafficGroupKey::Ndis(0);
        selection.hasConn = false;
        const Rule unknown = app.MakeRuleTemplate(selection, false);
        CheckTray(unknown.isInterface() && unknown.appPath.empty(),
                  "unknown interface placeholder became a group identity");
    }

    static void TestCopyShortcut(App& app) {
        struct Cleanup {
            App& app;
            BYTE keyboard[256]{};
            bool keyboardSaved = false;
            ~Cleanup() {
                if (keyboardSaved) SetKeyboardState(keyboard);
                probeClipboard = false;
                clipboardOpen = false;
                clipboardText.clear();
                app.list_.SetRows({});
                if (app.edFilter_) DestroyWindow(app.edFilter_);
                app.edFilter_ = nullptr;
                if (app.accel_) DestroyAcceleratorTable(app.accel_);
                app.accel_ = nullptr;
            }
        } cleanup{app};

        ACCEL accelerator{FVIRTKEY, VK_F5, IDM_REFRESH};
        app.accel_ = CreateAcceleratorTableW(&accelerator, 1);
        app.edFilter_ = CreateWindowExW(0, L"EDIT", L"", WS_CHILD,
                                       0, 0, 100, 24, app.hwnd_, nullptr, app.inst_, nullptr);
        CheckTray(app.accel_ && app.edFilter_, "could not create shortcut test controls");
        CheckTray(GetKeyboardState(cleanup.keyboard) != FALSE, "could not read keyboard state");
        cleanup.keyboardSaved = true;
        BYTE keyboard[256];
        std::memcpy(keyboard, cleanup.keyboard, sizeof(keyboard));
        keyboard[VK_CONTROL] |= 0x80;
        keyboard[VK_MENU] &= 0x7f;
        keyboard[VK_SHIFT] &= 0x7f;
        CheckTray(SetKeyboardState(keyboard) != FALSE, "could not set Ctrl state");

        std::vector<TreeList::Row> rows(3);
        rows[0].isGroup = true;
        rows[0].col[ColProcess] = L"тест.exe";
        rows[0].col[ColPid] = L"1234";
        rows[1].groupRow = 0;
        rows[1].col[ColRemote] = L"192.0.2.1:443";
        rows[1].col[ColProto] = L"TCP";
        rows[1].tlsDomainLabel = std::make_shared<const std::wstring>(L"пример.рф");
        rows[2].groupRow = 0;
        rows[2].col[ColRemote] = L"192.0.2.2:80";
        app.list_.SetRows(std::move(rows));
        app.list_.Select(1);
        CheckTray(app.list_.Selected() == 1, "could not select a connection for copying");

        probeClipboard = true;
        clipboardProbe = nullptr;
        MSG msg{};
        msg.hwnd = app.list_.hwnd();
        msg.message = WM_KEYDOWN;
        msg.wParam = 'C';
        CheckTray(app.PreTranslate(msg) && clipboardProbe == app.hwnd_ && !clipboardOpen &&
                  clipboardText == L"тест.exe пример.рф\t192.0.2.1:443\t\t\t\t1234\t\tTCP\t\t\r\n",
                  "Ctrl+C did not copy exactly the selected Unicode connection row");

        clipboardProbe = nullptr;
        clipboardText = L"unchanged";
        msg.hwnd = app.edFilter_;
        CheckTray(!app.PreTranslate(msg) && !clipboardProbe && clipboardText == L"unchanged",
                  "Ctrl+C in the filter was intercepted by the list");
        msg.hwnd = app.hwnd_;
        CheckTray(!app.PreTranslate(msg) && !clipboardProbe,
                  "Ctrl+C outside the list copied a connection");
        msg.hwnd = app.list_.hwnd();
        msg.wParam = 'X';
        CheckTray(!app.PreTranslate(msg) && !clipboardProbe,
                  "another Ctrl shortcut copied a connection");
        msg.wParam = 'C';
        keyboard[VK_CONTROL] &= 0x7f;
        CheckTray(SetKeyboardState(keyboard) != FALSE, "could not clear Ctrl state");
        CheckTray(!app.PreTranslate(msg) && !clipboardProbe,
                  "C without Ctrl copied a connection");

        keyboard[VK_CONTROL] |= 0x80;
        CheckTray(SetKeyboardState(keyboard) != FALSE, "could not restore Ctrl state");
        ListView_SetItemState(app.list_.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        CheckTray(app.list_.Selected() < 0 && app.PreTranslate(msg) && !clipboardProbe &&
                  clipboardText == L"unchanged",
                  "Ctrl+C without a selection changed the clipboard");
        std::cout << "copy shortcut: selected row, empty selection and focus passed\n";
    }

    static void Test() {
        App app;
        app.inst_ = GetModuleHandleW(nullptr);
        WNDCLASSW wc{};
        wc.lpfnWndProc = HostProc;
        wc.hInstance = app.inst_;
        wc.lpszClassName = L"FirewallXTrayStorageTests";
        CheckTray(RegisterClassW(&wc) != 0, "could not register tray storage host");
        app.hwnd_ = CreateWindowExW(WS_EX_TOOLWINDOW, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW,
                                   -30000, -30000, 1200, 400,
                                   nullptr, nullptr, app.inst_, &app);
        struct Cleanup {
            App& app;
            ~Cleanup() {
                app.list_.Destroy();
                if (app.hwnd_) DestroyWindow(app.hwnd_);
            }
        } cleanup{app};
        CheckTray(app.hwnd_ && app.list_.Create(app.hwnd_, app.inst_, kListId),
                  "could not create tray storage list");
        app.status_ = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE,
                                      0, 0, 0, 0, app.hwnd_, nullptr, app.inst_, nullptr);
        CheckTray(app.status_ != nullptr, "could not create tray storage status bar");
        TestCopyShortcut(app);

        // Explorer может ещё не создать значок, но автозапуск не должен показывать окно.
        app.ShowAtStartup(SW_SHOWNOACTIVATE, true);
        CheckTray(!IsWindowVisible(app.hwnd_) && app.rowsReleased_,
                  "autostart showed the window or kept the display active");
        app.ShowAtStartup(SW_SHOWNOACTIVATE, false);
        CheckTray(app.WindowShown(), "manual startup did not show the window");

        // Фильтр, сортировка и ручное раскрытие должны пережить освобождение строк.
        app.filterText_ = L"192.0.2";
        app.sortCol_ = ColRemote;
        app.sortAsc_ = false;
        const uint64_t process = ProcIdentity(GetCurrentProcessId(), false);
        app.expansionOverrides_.insert(process);
        Apply(app, FullSnapshot({11, 22, 33}));
        CheckTray(app.list_.rows().size() == 4, "initial expanded rows were not built");
        DebugCounters::Snapshot debug;
        app.ReadDebugCounters(debug);
        CheckTray(debug.values[DebugCounters::SnapshotProcesses] == 1 &&
                  debug.values[DebugCounters::SnapshotConnections] == 3 &&
                  debug.values[DebugCounters::TreeRows] == 4 &&
                  debug.values[DebugCounters::ExpansionOverrides] == 1,
                  "UI diagnostics returned incorrect collection sizes");
        const auto selectedConnection = std::find_if(app.snap_.conns.begin(), app.snap_.conns.end(),
            [](const ConnItem& connection) { return connection.flowGeneration == 33; });
        CheckTray(selectedConnection != app.snap_.conns.end(), "initial selected connection is missing");
        const TreeList::RowKey key = MakeRowKey(app.snap_.procs[0], selectedConnection);

        constexpr size_t peakRows = 20001;
        constexpr int selectedIndex = 10000;
        std::weak_ptr<const std::wstring> oldLabel;
        std::weak_ptr<const ProcessIcon> oldIcon;
        {
            std::vector<TreeList::Row> rows(peakRows);
            rows[0].isGroup = rows[0].expanded = true;
            rows[0].key.group = TrafficGroupKey::Host(GetCurrentProcessId());
            rows[0].col[ColProcess] = L"tray-memory-test.exe";
            rows[0].path.assign(100000, L'p');
            for (size_t i = 1; i < rows.size(); ++i) {
                rows[i].key.group = TrafficGroupKey::Host(GetCurrentProcessId());
                rows[i].groupRow = 0;
                rows[i].col[ColRemote] = L"192.0.2.10:" + std::to_wstring(i);
            }
            rows[selectedIndex].key = key;
            rows[selectedIndex].ruleName.assign(100000, L'r');
            auto label = std::make_shared<const std::wstring>(100000, L'd');
            auto icon = std::make_shared<const ProcessIcon>(nullptr, 16);
            rows[selectedIndex].tlsDomainLabel = label;
            rows[0].icon = icon;
            oldLabel = label;
            oldIcon = icon;
            app.list_.SetRows(std::move(rows));
        }
        app.list_.Select(selectedIndex);
        StorageTestAccess::FillTextCopies(app.list_, selectedIndex);
        ShowWindow(app.hwnd_, SW_HIDE);
        StorageTestAccess::CheckReleased(app.list_);
        CheckTray(oldLabel.expired() && oldIcon.expired(),
                  "hidden rows retained their nested text or icon owner");
        CheckTray(app.rowsReleased_ && !app.snap_.displayReady &&
                  !app.GetSelection().valid && app.connectionText_.size() == 0 &&
                  app.selValid_ && app.selKey_ == key,
                  "hiding did not save only the selection key or disable stale commands");
        for (int pass = 0; pass < 1000; ++pass) app.SetMonitorDisplay(false);
        CheckTray(app.selValid_ && app.selKey_ == key,
                  "repeated hidden ticks erased the saved selection");

        Snapshot summary;
        summary.procs.reset(1);
        summary.procs[0].group = TrafficGroupKey::Host(GetCurrentProcessId());
        summary.connCount = 3;
        StorageTestAccess::Publish(app.monitor_, std::move(summary));
        CheckTray(!app.ApplyMonitorSnapshot(), "tray summary rebuilt display rows");
        // Полный снимок мог закончить строиться одновременно со скрытием окна.
        StorageTestAccess::Publish(app.monitor_, FullSnapshot({11, 22, 33}));
        CheckTray(!app.ApplyMonitorSnapshot(), "late full snapshot rebuilt a hidden list");
        StorageTestAccess::CheckReleased(app.list_);
        CheckTray(app.selValid_ && app.selKey_ == key,
                  "hidden snapshot publication erased the saved selection");

        ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
        app.RebuildRows();
        StorageTestAccess::CheckReleased(app.list_);
        CheckTray(!app.GetSelection().valid, "stale commands were enabled before a fresh snapshot");
        Apply(app, FullSnapshot({1, 11, 22, 33, 44}));
        CheckSelection(app, key);
        CheckTray(app.list_.Selected() != selectedIndex &&
                  app.filterText_ == L"192.0.2" && app.sortCol_ == ColRemote &&
                  !app.sortAsc_ && app.IsProcessExpanded(process),
                  "restoring changed the view settings or used the old numeric index");

        // Готовый старый снимок нельзя применить после быстрого скрытия и возврата.
        StorageTestAccess::Publish(app.monitor_, FullSnapshot({1, 11, 22, 33, 44}));
        ShowWindow(app.hwnd_, SW_HIDE);
        ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
        CheckTray(!app.ApplyMonitorSnapshot(), "restoring applied a pre-hide full snapshot");
        StorageTestAccess::CheckReleased(app.list_);

        // Исчезнувшее соединение и новый экземпляр того же tuple не наследуют выделение.
        Snapshot replaced = FullSnapshot({1, 11, 22, 33, 44});
        replaced.conns[3].flowGeneration = 333;
        Apply(app, std::move(replaced));
        CheckNoSelection(app);

        // Обычное сворачивание через WM_SIZE использует тот же путь очистки.
        app.list_.Select(1);
        const TreeList::RowKey minimizedKey = app.list_.rows()[1].key;
        ShowWindow(app.hwnd_, SW_SHOWMINNOACTIVE);
        CheckTray(IsIconic(app.hwnd_) != FALSE, "test window was not minimized");
        StorageTestAccess::CheckReleased(app.list_);
        ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
        CheckTray(!IsIconic(app.hwnd_), "test window was not restored");
        Snapshot restored = FullSnapshot({1, 11, 22, 33, 44});
        restored.conns[3].flowGeneration = 333;
        Apply(app, std::move(restored));
        CheckSelection(app, minimizedKey);

        app.list_.Select(0);
        const TreeList::RowKey groupKey = app.list_.rows()[0].key;
        ShowWindow(app.hwnd_, SW_HIDE);
        ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
        Apply(app, FullSnapshot({11, 22, 33}));
        CheckTray(app.list_.Selected() == 0 && app.list_.rows()[0].key == groupKey &&
                  app.GetSelection().valid && app.GetSelection().isGroup,
                  "restoring lost the selected process group");

        ListView_SetItemState(app.list_.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ShowWindow(app.hwnd_, SW_HIDE);
        ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
        Apply(app, FullSnapshot({11, 22, 33}));
        CheckNoSelection(app);

        // Пустой первый снимок после возврата окончательно снимает старый ключ.
        app.list_.Select(1);
        ShowWindow(app.hwnd_, SW_HIDE);
        ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
        Snapshot empty;
        empty.displayReady = true;
        Apply(app, std::move(empty));
        CheckNoSelection(app);
        Apply(app, FullSnapshot({11, 22, 33}));
        CheckNoSelection(app);

        for (int pass = 0; pass < 20; ++pass) {
            app.list_.Select(1);
            const TreeList::RowKey saved = app.list_.rows()[1].key;
            ShowWindow(app.hwnd_, SW_HIDE);
            app.SetMonitorDisplay(false);
            StorageTestAccess::CheckReleased(app.list_);
            ShowWindow(app.hwnd_, SW_SHOWNOACTIVATE);
            Apply(app, FullSnapshot({11, 22, 33}));
            CheckSelection(app, saved);
        }
        std::cout << "tray row storage: peak=" << peakRows
                  << ", hidden capacity=0, selection restored by key\n";
    }
};
} // namespace

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    HRESULT com = E_FAIL;
    try {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        CheckTray(SUCCEEDED(com), "could not initialize COM");
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES | ICC_INTERNET_CLASSES};
        CheckTray(InitCommonControlsEx(&controls) != FALSE, "could not initialize common controls");
        WSADATA wsa{};
        CheckTray(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "could not initialize Winsock");
        std::wstring error;
        CheckTray(Settings::Open(L":memory:", error), "could not open isolated test settings");
        SetUiLang(UiLang::English);
        TestInstructionDialog(L"Первая строка\r\n" + std::wstring(70000, L'x') + L"\r\nEnd");
        for (int i = 1; i < argc; ++i) {
            std::wstring text;
            CheckTray(ReadInstructionFile(argv[i], text) == ERROR_SUCCESS && !text.empty(),
                      "could not read supplied instruction");
            TestInstructionDialog(text);
        }
        AppStorageTestAccess::TestRuleTemplates();
        AppStorageTestAccess::Test();
        StorageTestAccess::TestTrafficGroupRows();
    StorageTestAccess::TestDebugCounters();
        TestDebugWindow();
        TestSettingsNdis();
        Settings::Close();
        Ui::ReleaseFonts();
        WSACleanup();
        CoUninitialize();
        std::cout << "tray storage tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        Settings::Close();
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }
}
