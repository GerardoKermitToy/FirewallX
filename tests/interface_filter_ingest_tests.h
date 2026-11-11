#pragma once
#include "RuleDialogs.h"

namespace {
net::NetworkInterfaceWatcher::InterfaceInfo FilterTestInterface() {
    const auto number = RuntimeTestInterface();
    const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
    for (const auto& entry : snapshot->interfaces)
        if (entry.number == number) return entry;
    Check(false, "active interface disappeared from the test snapshot");
    return {};
}

struct InterfaceEditorProbe {
    static inline InterfaceEditorProbe* active = nullptr;
    bool observed = false, found = false, checked = false, red = false;
    std::wstring value;

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.observed = true;
        HWND conditions = GetDlgItem(dialog, 300);
        ListView_SetItemState(conditions, -1, 0, LVIS_SELECTED);
        for (int row = 0; row < ListView_GetItemCount(conditions); ++row) {
            wchar_t label[128]{};
            ListView_GetItemText(conditions, row, 0, label, static_cast<int>(std::size(label)));
            if (LoadStringRes(IDS_COND_INTERFACE) != label) continue;
            probe.found = true;
            probe.checked = ListView_GetCheckState(conditions, row) != FALSE;
            wchar_t value[256]{};
            ListView_GetItemText(conditions, row, 1, value, static_cast<int>(std::size(value)));
            probe.value = value;
            NMLVCUSTOMDRAW draw{};
            draw.nmcd.hdr = {conditions, 300, NM_CUSTOMDRAW};
            draw.nmcd.dwDrawStage = CDDS_ITEMPREPAINT | CDDS_SUBITEM;
            draw.nmcd.dwItemSpec = row;
            draw.nmcd.hdc = GetDC(conditions);
            draw.iSubItem = 1;
            SendMessageW(dialog, WM_NOTIFY, 300, reinterpret_cast<LPARAM>(&draw));
            probe.red = draw.clrText == Ui::DialogPalette().block;
            ReleaseDC(conditions, draw.nmcd.hdc);
        }
        PostMessageW(dialog, WM_COMMAND, IDOK, 0);
    }
};

struct InterfaceNameProbe {
    static inline InterfaceNameProbe* active = nullptr;
    std::wstring name;
    bool observed = false, canSave = false;
    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.observed = GetDlgItem(dialog, 200) != nullptr;
        SetDlgItemTextW(dialog, 200, probe.name.c_str());
        SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(200, CBN_EDITCHANGE), 0);
        probe.canSave = IsWindowEnabled(GetDlgItem(dialog, IDOK)) != FALSE;
        PostMessageW(dialog, WM_COMMAND, IDOK, 0);
    }
};

void TestInterfaceFilterEditor() {
    const UiLang original = CurrentUiLang();
    const auto entry = FilterTestInterface();
    for (UiLang language : {UiLang::Russian, UiLang::English, UiLang::Arabic}) {
        SetUiLang(language);
        for (RuleScope scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp,
                                RuleScope::Interface})
        for (bool available : {false, true}) {
            Rule rule;
            rule.scope = scope;
            rule.appPath = scope == RuleScope::Interface ? entry.name : L"C:\\Apps\\interface-ui.exe";
            rule.conds = CondInterface;
            rule.interfaceName = available ? entry.name : L"Отсутствующая сеть 网络 \U0001f310";
            const std::wstring name = rule.interfaceName;
            InterfaceEditorProbe probe;
            InterfaceEditorProbe::active = &probe;
            const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceEditorProbe::Inspect);
            Check(timer != 0, "cannot create interface editor probe timer");
            const bool saved = RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, true);
            KillTimer(nullptr, timer);
            InterfaceEditorProbe::active = nullptr;
            const bool applicable = scope != RuleScope::Interface;
            Check(saved && probe.observed && probe.found == applicable,
                  "interface filter is missing or offered inside an interface group");
            if (applicable) {
                Check(probe.checked && probe.value == name && probe.red == !available,
                      "interface editor lost Unicode name or unavailable red state");
                Check((rule.conds & CondInterface) && rule.interfaceName == name,
                      "interface editor did not save its name condition");
            } else {
                Check(!(rule.conds & CondInterface) && rule.interfaceName.empty(),
                      "interface editor retained a redundant scope condition");
            }
        }
        InterfaceNameProbe probe;
        probe.name = L"  Сеть café, 网络 \U0001f310  ";
        InterfaceNameProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceNameProbe::Inspect);
        Check(timer != 0, "cannot create interface picker probe timer");
        std::wstring chosen = entry.name;
        const bool saved = RuleDialogs::ChooseInterface(nullptr, GetModuleHandleW(nullptr), chosen);
        KillTimer(nullptr, timer);
        InterfaceNameProbe::active = nullptr;
        Check(saved && probe.observed && probe.canSave && chosen == probe.name,
              "interface picker changed the exact Unicode connection name");
    }
    SetUiLang(original);
    Ui::ReleaseFonts();
}

void TestInterfaceFilterPrefill() {
    const auto entry = FilterTestInterface();
    for (const std::wstring path : {std::wstring(), std::wstring(L"C:\\Apps\\interface-prefill.exe")})
    for (Proto proto : {Proto::Udp, Proto::Icmp, ProtoFromNumber(144)}) {
        AskRequest request = Request(path, proto);
        request.interfaceIndex = entry.number;
        const auto check = [&](const std::wstring& expected) {
            for (const Rule& rule : {MakeEditorTemplate(request), MakeAllowRule(request),
                                     MakeBlockRule(request)})
                Check(rule.interfaceName == expected && !(rule.conds & CondInterface),
                      "interface prefill was lost or silently enabled the filter");
        };
        check(entry.name);
        if (entry.ipv6_number) {
            request.interfaceIndex = entry.ipv6_number;
            check(entry.name);
        }
        request.interfaceName = std::make_shared<const std::wstring>(L"  Сеть café, 网络 \U0001f310  ");
        check(*request.interfaceName);
        // Даже неизвестное исходное имя не заменяется владельцем старого индекса.
        request.interfaceName = std::make_shared<const std::wstring>();
        check(L"");
        request.interfaceName.reset();
        request.interfaceIndex = 0xfedcba98u;
        check(L"");
        request.interfaceIndex = 0;
        request.key.interfaceIndex = entry.number;
        check(entry.name);
    }

    FlowRuleSeed seed;
    seed.appPath = L"C:\\Apps\\interface-flow.exe";
    seed.key = Request(seed.appPath).key;
    seed.interfaceIndex = entry.number;
    Check(MakeNarrowRule(seed, RuleAction::Allow).interfaceName == entry.name,
          "flow template did not use its driver interface index");
    seed.interfaceIndex = 0;
    const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
    for (const auto& candidate : snapshot->interfaces) {
        if (!candidate.up || !candidate.number || candidate.name.empty()) continue;
        for (const auto& address : candidate.unicast) {
            if (address.address.isAny()) continue;
            seed.key.local = address.address;
            size_t owners = 0;
            for (const auto& other : snapshot->interfaces)
                if (other.up && other.number && !other.name.empty() &&
                    std::any_of(other.unicast.begin(), other.unicast.end(),
                        [&](const auto& value) { return value.address == address.address; })) ++owners;
            const Rule rule = MakeNarrowRule(seed, RuleAction::Allow);
            Check(rule.interfaceName == (owners == 1 ? candidate.name : std::wstring()) &&
                      !(rule.conds & CondInterface),
                  "local-address prefill guessed an ambiguous interface");
        }
    }
    seed.key.local = Ip(L"0.0.0.0");
    Check(MakeNarrowRule(seed, RuleAction::Allow).interfaceName.empty(),
          "wildcard local address selected an arbitrary interface");

    AskRequest request = Request(seed.appPath);
    request.interfaceIndex = entry.number;
    Rule rule = MakeEditorTemplate(request);
    InterfaceEditorProbe probe;
    InterfaceEditorProbe::active = &probe;
    const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceEditorProbe::Inspect);
    Check(timer != 0, "cannot create interface prefill probe timer");
    const bool saved = RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, false);
    KillTimer(nullptr, timer);
    InterfaceEditorProbe::active = nullptr;
    Check(saved && probe.observed && probe.found && !probe.checked && !probe.red &&
              probe.value == entry.name && rule.interfaceName == entry.name &&
              !(rule.conds & CondInterface),
          "editor did not display the suggested interface as an unchecked condition");
}

struct InterfaceHintProbe {
    static inline InterfaceHintProbe* active = nullptr;
    bool observed = false, preselected = false, emptyDisabled = false, refreshed = false;
    std::wstring initialName, initialHint, unavailableHint, emptyHint, selectedHint;

    static std::wstring Text(HWND dialog, int id) {
        HWND control = GetDlgItem(dialog, id);
        std::wstring value(static_cast<size_t>(GetWindowTextLengthW(control)) + 1, L'\0');
        const int length = GetWindowTextW(control, value.data(), static_cast<int>(value.size()));
        value.resize(static_cast<size_t>(length));
        return value;
    }

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.observed = GetDlgItem(dialog, 200) && GetDlgItem(dialog, 201);
        probe.initialName = Text(dialog, 200);
        probe.preselected = SendDlgItemMessageW(dialog, 200, CB_GETCURSEL, 0, 0) != CB_ERR;
        probe.initialHint = Text(dialog, 201);
        SetDlgItemTextW(dialog, 200, L"Отсутствующая сеть 网络 \U0001f310");
        SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(200, CBN_EDITCHANGE), 0);
        probe.unavailableHint = Text(dialog, 201);
        SetDlgItemTextW(dialog, 200, L"");
        SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(200, CBN_EDITCHANGE), 0);
        probe.emptyHint = Text(dialog, 201);
        probe.emptyDisabled = IsWindowEnabled(GetDlgItem(dialog, IDOK)) == FALSE;
        HWND combo = GetDlgItem(dialog, 200);
        const LRESULT index = SendMessageW(combo, CB_FINDSTRINGEXACT, static_cast<WPARAM>(-1),
                                          reinterpret_cast<LPARAM>(probe.initialName.c_str()));
        SendMessageW(combo, CB_SETCURSEL, index, 0);
        SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(200, CBN_SELCHANGE), 0);
        probe.selectedHint = Text(dialog, 201);
        SetDlgItemTextW(dialog, 201, L"stale");
        SendMessageW(dialog, RuleStore::kInterfacesChanged, 0, 0);
        probe.refreshed = Text(dialog, 201) == probe.selectedHint;
        PostMessageW(dialog, WM_COMMAND, IDOK, 0);
    }
};

void TestInterfacePickerHint() {
    const UiLang original = CurrentUiLang();
    const auto entry = FilterTestInterface();
    for (UiLang language : {UiLang::Russian, UiLang::English, UiLang::Arabic}) {
        SetUiLang(language);
        InterfaceHintProbe probe;
        InterfaceHintProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceHintProbe::Inspect);
        Check(timer != 0, "cannot create interface hint probe timer");
        std::wstring chosen = entry.name;
        const bool saved = RuleDialogs::ChooseInterface(nullptr, GetModuleHandleW(nullptr), chosen);
        KillTimer(nullptr, timer);
        InterfaceHintProbe::active = nullptr;
        Check(saved && probe.observed && probe.preselected && chosen == entry.name &&
                  probe.initialName == entry.name,
              "interface picker changed its preselected connection name");
        Check(probe.initialHint.find(LoadStringRes(IDS_INTERFACE_FILTER_ACTIVE)) != std::wstring::npos &&
                  probe.initialHint.find(LoadStringResFmt(IDS_INTERFACE_FILTER_INDEX_FMT,
                      entry.number, entry.ipv6_number)) != std::wstring::npos,
              "selected interface hint lost its availability or indexes");
        for (const auto& address : entry.unicast)
            Check(probe.initialHint.find(IpToPlainString(address.address) + L"/" +
                      std::to_wstring(address.prefix_length)) != std::wstring::npos,
                  "selected interface hint lost its IP addresses");
        for (const auto* values : {&entry.gateways, &entry.dns_servers})
            for (const auto& address : *values)
                Check(probe.initialHint.find(IpToPlainString(address)) != std::wstring::npos,
                      "selected interface hint lost its gateway or DNS server");
        Check(probe.unavailableHint == LoadStringRes(IDS_INTERFACE_FILTER_UNAVAILABLE) &&
                  probe.emptyHint == LoadStringRes(IDS_INTERFACE_FILTER_EMPTY) && probe.emptyDisabled,
              "manual interface entry did not update the hint or OK state");
        Check(probe.selectedHint == probe.initialHint && probe.refreshed,
              "selection or watcher notification did not refresh the interface hint");
    }
    SetUiLang(original);
    Ui::ReleaseFonts();
}

struct InterfaceRefreshProbe {
    static inline InterfaceRefreshProbe* active = nullptr;
    std::wstring initialName;
    bool observed = false, rebuilt = false, selectionPreserved = false, inputPreserved = false;

    static void CALLBACK Inspect(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog) return;
        KillTimer(nullptr, timer);
        auto& probe = *active;
        probe.observed = true;
        HWND combo = GetDlgItem(dialog, 200);
        const auto find = [&](const std::wstring& name) {
            return SendMessageW(combo, CB_FINDSTRINGEXACT, static_cast<WPARAM>(-1),
                                reinterpret_cast<LPARAM>(name.c_str()));
        };
        // Имитируем устаревший список: текущего адаптера ещё нет, исчезнувший остался.
        SendMessageW(combo, CB_DELETESTRING, find(probe.initialName), 0);
        const std::wstring stale = L"Removed adapter Сеть 网络";
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(stale.c_str()));
        SetWindowTextW(combo, probe.initialName.c_str());
        SendMessageW(dialog, RuleStore::kInterfacesChanged, 0, 0);
        const auto snapshot = net::SharedNetworkInterfaces().GetSnapshot();
        size_t expected = 0;
        bool complete = true;
        for (const auto& entry : snapshot->interfaces) {
            if (entry.name.empty()) continue;
            ++expected;
            complete &= find(entry.name) != CB_ERR;
        }
        probe.rebuilt = complete && find(stale) == CB_ERR &&
            SendMessageW(combo, CB_GETCOUNT, 0, 0) == static_cast<LRESULT>(expected);
        probe.selectionPreserved = InterfaceHintProbe::Text(dialog, 200) == probe.initialName &&
            SendMessageW(combo, CB_GETCURSEL, 0, 0) == find(probe.initialName);

        const std::wstring typed = L"  Введённая сеть café, 网络 \U0001f310  ";
        SetWindowTextW(combo, typed.c_str());
        SendMessageW(combo, CB_SETEDITSEL, 0, MAKELPARAM(3, 7));
        SendMessageW(dialog, RuleStore::kInterfacesChanged, 0, 0);
        probe.inputPreserved = InterfaceHintProbe::Text(dialog, 200) == typed &&
            SendMessageW(combo, CB_GETEDITSEL, 0, 0) == MAKELRESULT(3, 7) &&
            SendMessageW(combo, CB_GETCURSEL, 0, 0) == CB_ERR &&
            InterfaceHintProbe::Text(dialog, 201) == LoadStringRes(IDS_INTERFACE_FILTER_UNAVAILABLE);
        PostMessageW(dialog, WM_COMMAND, IDCANCEL, 0);
    }
};

void TestInterfacePickerRefresh() {
    const UiLang original = CurrentUiLang();
    const auto entry = FilterTestInterface();
    for (UiLang language : {UiLang::Russian, UiLang::English, UiLang::Arabic}) {
        SetUiLang(language);
        InterfaceRefreshProbe probe;
        probe.initialName = entry.name;
        InterfaceRefreshProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, InterfaceRefreshProbe::Inspect);
        Check(timer != 0, "cannot create interface refresh probe timer");
        std::wstring chosen = entry.name;
        RuleDialogs::ChooseInterface(nullptr, GetModuleHandleW(nullptr), chosen);
        KillTimer(nullptr, timer);
        InterfaceRefreshProbe::active = nullptr;
        Check(probe.observed && probe.rebuilt && probe.selectionPreserved && probe.inputPreserved,
              "watcher notification did not rebuild the picker while preserving its exact input");
    }
    SetUiLang(original);
    Ui::ReleaseFonts();
}

void TestInterfaceFilterPresetDedup() {
    RuleStore store;
    const AskRequest request = Request(L"C:\\Apps\\interface-presets.exe");
    Rule first = MakeAllowRule(request);
    first.conds |= CondInterface;
    first.interfaceName = L"Сеть 1";
    Rule second = first;
    second.interfaceName = L"Сеть 2";
    Check(RulePresets::Apply(store, request, {first, second}) == 2 &&
              store.ForApp(request.appPath).size() == 2,
          "preset dedup merged different interface names");
    Check(RulePresets::Apply(store, request, {first, second}) == 0,
          "preset dedup duplicated identical interface filters");
    second.conds &= ~CondInterface;
    Check(RulePresets::Apply(store, request, {second}) == 1,
          "preset dedup treated a disabled interface condition as active");
}

void TestInterfaceFilterShapeCache() {
    const auto entry = FilterTestInterface();
    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(false);
    DriverVerdictSession session;
    captureSession = &session;
    const auto cacheClears = driverCacheClears;
    for (auto mode : {IngestMode::Desktop, IngestMode::Service})
    for (auto scope : {RuleScope::App, RuleScope::Global, RuleScope::PostApp})
    for (auto action : {RuleAction::Allow, RuleAction::Block})
    for (bool ipv6 : {false, true}) {
        sentVerdicts.clear();
        RuleStore rules;
        Rule filtered;
        filtered.scope = scope;
        if (scope == RuleScope::App) filtered.appPath = L"C:\\Apps\\interface-cache.exe";
        filtered.conds = CondInterface;
        filtered.interfaceName = entry.name;
        filtered.action = action;
        rules.Add(filtered);
        Rule fallback = filtered;
        fallback.conds = CondNone;
        fallback.action = action == RuleAction::Allow ? RuleAction::Block : RuleAction::Allow;
        rules.Add(fallback);
        auto ingest = IngestTestAccess::Create();
        ingest->Attach(&rules, nullptr, mode, FirewallPolicy::Learning);
        ingest->BeginDriverSession(session.Begin());
        AskRequest request = Request(L"C:\\Apps\\interface-cache.exe", Proto::Udp);
        if (ipv6) {
            request.key.local = Ip(L"2001:db8::10");
            request.key.remote = Ip(L"2001:db8::20");
        }
        const auto receive = [&](uint32_t index, uint64_t id, RuleAction expected) {
            request.interfaceIndex = index;
            const auto before = sentVerdicts.size();
            IngestTestAccess::ReceivePacket(*ingest, session, request, id, {});
            const auto verdict = expected == RuleAction::Allow
                ? pmkext::Verdict::PermanentAccept : pmkext::Verdict::Drop;
            Check(sentVerdicts.size() == before + 1 && sentVerdicts.back() == std::pair{id, verdict},
                  "shape cache reused a verdict across different interface filters");
        };
        const auto index = ipv6 && entry.ipv6_number ? entry.ipv6_number : entry.number;
        for (uint64_t id = 1; id <= 6; ++id)
            receive(id % 2 ? index : 0xfedcba98u, id,
                    id % 2 ? action : fallback.action);
        filtered.interfaceName = L"Недоступная сеть для теста фильтра";
        Check(rules.Update(filtered), "cannot update interface filter for cache test");
        receive(index, 7, fallback.action);
        filtered.conds = CondNone;
        Check(rules.Update(filtered), "cannot clear interface filter for cache test");
        receive(index, 8, action);
        Check(ingest->waiting() == 0 && driverCacheClears == cacheClears,
              "interface filter test left pending verdicts or reset the driver cache");
        ingest->EndDriverSession(session.End());
    }
    captureSession = nullptr;
    flows.Enable(wasEnabled);
}
} // namespace
