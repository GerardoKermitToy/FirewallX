#include "rule_editor_ui_tests.h"
#include "AppRulesEditor.h"
#include "RuleEditor.h"
#include "RuleDialogs.h"
#include "StringRes.h"
#include "UiKit.h"
#include "Settings.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

RECT Bounds(HWND window, HWND parent) {
    RECT rect{};
    GetWindowRect(window, &rect);
    MapWindowPoints(nullptr, parent, reinterpret_cast<POINT*>(&rect), 2);
    return rect;
}

bool Overlap(const RECT& a, const RECT& b) {
    RECT intersection{};
    return IntersectRect(&intersection, &a, &b) != FALSE;
}

bool SaveWindow(HWND window, const std::filesystem::path& path) {
    RECT rect{};
    GetWindowRect(window, &rect);
    const int width = rect.right - rect.left, height = rect.bottom - rect.top;
    HDC source = GetWindowDC(window);
    HDC dc = CreateCompatibleDC(source);
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    void* pixels = nullptr;
    HBITMAP bitmap = CreateDIBSection(source, &info, DIB_RGB_COLORS, &pixels, nullptr, 0);
    bool saved = false;
    if (source && dc && bitmap && pixels) {
        HGDIOBJ previous = SelectObject(dc, bitmap);
        saved = PrintWindow(window, dc, 2) != FALSE;
        GdiFlush();
        const DWORD size = static_cast<DWORD>(width * height * 4);
        BITMAPFILEHEADER file{};
        file.bfType = 0x4D42;
        file.bfOffBits = sizeof(file) + sizeof(info.bmiHeader);
        file.bfSize = file.bfOffBits + size;
        std::ofstream stream(path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(&file), sizeof(file));
        stream.write(reinterpret_cast<const char*>(&info.bmiHeader), sizeof(info.bmiHeader));
        stream.write(static_cast<const char*>(pixels), size);
        saved = saved && stream.good();
        SelectObject(dc, previous);
    }
    if (bitmap) DeleteObject(bitmap);
    if (dc) DeleteDC(dc);
    if (source) ReleaseDC(window, source);
    return saved;
}

struct Probe {
    static inline Probe* active = nullptr;
    bool list = false, preview = false, inspected = false, interactive = false;
    bool savedImage = true, inheritance = false, growExplanation = false;
    std::string error;
    std::filesystem::path image;

    void Fail(const std::string& text) {
        if (error.empty()) error = text;
    }

    void InspectArrangement(HWND dialog, const RECT& client, const RECT& table, const RECT& explanation) {
        Ui::Metrics m;
        m.dpi = GetDpiForWindow(dialog);
        if (client.right != m.Sc(list ? 640 : 560))
            Fail("original dialog width changed");
        const int margin = m.margin();
        if (list) {
            const RECT first = Bounds(GetDlgItem(dialog, 401), dialog);
            RECT previous = first;
            if (first.left <= table.right || first.top != table.top - 1)
                Fail("rule actions are not to the right of the table");
            for (int id = 402; id <= 404; ++id) {
                const RECT button = Bounds(GetDlgItem(dialog, id), dialog);
                if (button.left != first.left || button.top != previous.bottom + m.gapS())
                    Fail("rule actions are not in the original vertical column");
                previous = button;
            }
            const RECT up = Bounds(GetDlgItem(dialog, 405), dialog);
            const RECT down = Bounds(GetDlgItem(dialog, 406), dialog);
            if (up.top <= table.bottom || up.top != down.top || explanation.top <= up.bottom)
                Fail("rule navigation and explanation are not below the table");
        } else {
            const RECT app = Bounds(GetDlgItem(dialog, 302), dialog);
            const RECT name = Bounds(GetDlgItem(dialog, 305), dialog);
            const RECT automatic = Bounds(GetDlgItem(dialog, 306), dialog);
            const RECT copy = Bounds(GetDlgItem(dialog, 307), dialog);
            const RECT paste = Bounds(GetDlgItem(dialog, 308), dialog);
            const RECT ok = Bounds(GetDlgItem(dialog, IDOK), dialog);
            if (table.left != margin + 1 || table.right != client.right - margin - 1 ||
                app.left != margin || app.top <= table.bottom || explanation.top <= app.bottom ||
                name.top <= explanation.bottom || automatic.top <= name.bottom)
                Fail("rule sections are not in the original full-width vertical order");
            if (copy.top != automatic.top - m.Sc(3) || paste.top != copy.top ||
                copy.left <= automatic.right || paste.left != copy.right + m.gap() ||
                paste.right != client.right - margin || copy.bottom >= ok.top)
                Fail("copy and paste are not beside the automatic-name checkbox");
            if (HWND payload = GetDlgItem(dialog, 309)) {
                const RECT rect = Bounds(payload, dialog);
                if (rect.left != margin || rect.top <= app.bottom || rect.bottom >= explanation.top)
                    Fail("payload is not between the application and explanation");
            }
        }
        const RECT ok = Bounds(GetDlgItem(dialog, IDOK), dialog);
        const int footerY = list ? explanation.bottom + m.Sc(3) + m.gap()
                                 : Bounds(GetDlgItem(dialog, 307), dialog).bottom + m.section();
        if (client.bottom != footerY + 2 * margin + m.btnH() ||
            ok.top != footerY + margin || ok.bottom != client.bottom - margin)
            Fail("footer does not fit the content with even button padding");
        if (explanation.left != margin + m.Sc(3) ||
            explanation.right != client.right - margin - m.Sc(3))
            Fail("rule explanation no longer spans the original width");

        const HWND give = GetDlgItem(dialog, list ? 410 : 310);
        const HWND never = GetDlgItem(dialog, list ? 411 : 311);
        if ((give != nullptr) != inheritance || (never != nullptr) != inheritance)
            Fail("inheritance checkbox availability changed");
        if (!inheritance || !give || !never) return;
        const RECT a = Bounds(give, dialog), b = Bounds(never, dialog);
        if (a.left != margin || Overlap(a, b) ||
            (list && std::max(a.bottom, b.bottom) > table.top) ||
            (!list && (a.top <= Bounds(GetDlgItem(dialog, 302), dialog).bottom ||
                       std::max(a.bottom, b.bottom) >= explanation.top)))
            Fail("inheritance checkboxes overlap another section");
        // Оба флажка выровнены по строке; длинные переводы могут перейти на две.
        if (a.top == b.top) {
            if (b.left != a.right + m.gap() || a.bottom != b.bottom)
                Fail("inheritance checkboxes are not aligned in two columns");
        } else if (b.left != a.left || b.top != a.bottom + m.gapS()) {
            Fail("inheritance checkbox fallback is not aligned");
        }

        const std::wstring titleText = LoadStringRes(IDS_INHERITANCE_SECTION);
        const std::wstring noteText = LoadStringRes(IDS_INHERITANCE_NOTE);
        const std::wstring nextText = LoadStringRes(list ? IDS_APPED_SECTION_RULES :
            GetDlgItem(dialog, 309) ? IDS_RED_PAYLOAD : IDS_RED_STEP3);
        HWND title = nullptr, note = nullptr, next = nullptr;
        for (HWND child = GetWindow(dialog, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
            wchar_t text[512]{};
            GetWindowTextW(child, text, static_cast<int>(std::size(text)));
            if (titleText == text) title = child;
            if (noteText == text) note = child;
            if (nextText == text) next = child;
        }
        if (!title || !note || !next) {
            Fail("inheritance title, explanation or following section is missing");
            return;
        }
        const RECT titleRect = Bounds(title, dialog), noteRect = Bounds(note, dialog);
        const RECT nextRect = Bounds(next, dialog);
        if (titleRect.left != margin || noteRect.left != margin ||
            a.top != titleRect.bottom + m.gapS() ||
            noteRect.top != std::max(a.bottom, b.bottom) + m.gapS() ||
            nextRect.top != noteRect.bottom + m.section())
            Fail("inheritance block has a detached explanation or unused vertical space");
        LOGFONTW titleFont{};
        GetObjectW(reinterpret_cast<HFONT>(SendMessageW(title, WM_GETFONT, 0, 0)),
                   sizeof(titleFont), &titleFont);
        if (titleFont.lfWeight < FW_SEMIBOLD) Fail("inheritance heading is not distinct from its note");
    }

    void InspectExplanation(HWND dialog) {
        HWND link = GetDlgItem(dialog, list ? 409 : 304);
        RECT client{};
        GetClientRect(link, &client);
        SIZE ideal{};
        if (!SendMessageW(link, LM_GETIDEALSIZE, client.right, reinterpret_cast<LPARAM>(&ideal)) ||
            ideal.cy > client.bottom) Fail("rule explanation clips its content");
        int action = -1;
        for (int index = 0; index < 32; ++index) {
            LITEM item{};
            item.mask = LIF_ITEMINDEX | LIF_ITEMID;
            item.iLink = index;
            if (!SendMessageW(link, LM_GETITEM, 0, reinterpret_cast<LPARAM>(&item))) break;
            if (std::wstring_view(item.szID) == RuleLink::kAction) action = index;
        }
        bool visible = false;
        for (int y = 0; !visible && y < client.bottom; ++y) {
            for (int x = 0; !visible && x < client.right; x += 4) {
                LHITTESTINFO hit{};
                hit.pt = {x, y};
                visible = SendMessageW(link, LM_HITTEST, 0, reinterpret_cast<LPARAM>(&hit)) &&
                          hit.item.iLink == action;
            }
        }
        if (!visible) Fail("rule action link is outside the visible explanation");
    }

    void Inspect(HWND dialog) {
        RECT client{};
        GetClientRect(dialog, &client);
        const int minimum = MulDiv(8, static_cast<int>(GetDpiForWindow(dialog)), 96);
        const RECT ok = Bounds(GetDlgItem(dialog, IDOK), dialog);
        const RECT cancel = Bounds(GetDlgItem(dialog, IDCANCEL), dialog);
        if (Overlap(ok, cancel)) Fail("dialog action buttons overlap");
        HDC footerDc = GetDC(dialog);
        SendMessageW(dialog, WM_CTLCOLORBTN, reinterpret_cast<WPARAM>(footerDc),
                     reinterpret_cast<LPARAM>(GetDlgItem(dialog, IDOK)));
        if (GetBkColor(footerDc) != GetSysColor(COLOR_WINDOW))
            Fail("previously approved rule editor footer changed");
        ReleaseDC(dialog, footerDc);
        const std::wstring heading = LoadStringRes(list ? IDS_APPED_SECTION_RULES : IDS_RED_STEP1);
        bool foundHeading = false;
        for (HWND child = GetWindow(dialog, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
            if (!IsWindowVisible(child)) continue;
            const RECT rect = Bounds(child, dialog);
            const int id = GetDlgCtrlID(child);
            if (rect.left < 0 || rect.top < 0 || rect.right > client.right ||
                rect.bottom > client.bottom || rect.right - rect.left < minimum ||
                rect.bottom - rect.top < minimum)
                Fail("control outside dialog or too small: " + std::to_string(id));
            if (id != IDOK && id != IDCANCEL && (Overlap(rect, ok) || Overlap(rect, cancel)))
                Fail("control overlaps action buttons: " + std::to_string(id));
            wchar_t caption[256]{};
            GetWindowTextW(child, caption, static_cast<int>(std::size(caption)));
            if (heading == caption) {
                foundHeading = true;
                HDC dc = GetDC(child);
                HGDIOBJ old = SelectObject(dc, reinterpret_cast<HFONT>(SendMessageW(child, WM_GETFONT, 0, 0)));
                wchar_t face[LF_FACESIZE]{};
                GetTextFaceW(dc, LF_FACESIZE, face);
                if (std::wstring(face).find(L"Segoe UI") != 0) Fail("heading uses a substituted font");
                const auto brush = reinterpret_cast<HBRUSH>(SendMessageW(dialog, WM_CTLCOLORSTATIC,
                    reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(child)));
                if (brush == GetStockObject(NULL_BRUSH)) Fail("heading has no page background");
                SelectObject(dc, old);
                ReleaseDC(child, dc);
            }
        }
        if (!foundHeading) Fail("section heading is missing");
        LOGFONTW font{};
        HWND control = GetDlgItem(dialog, list ? 400 : 300);
        GetObjectW(reinterpret_cast<HFONT>(SendMessageW(control, WM_GETFONT, 0, 0)), sizeof(font), &font);
        if (std::wstring(font.lfFaceName) != L"Segoe UI") Fail("editor font is inconsistent");
        const HWND expectedFocus = list && !ListView_GetItemCount(control) ? GetDlgItem(dialog, 401) : control;
        if (GetFocus() != expectedFocus) Fail("initial focus is not on the rule table or new action");
        HWND explanation = GetDlgItem(dialog, list ? 409 : 304);
        const RECT explanationRect = Bounds(explanation, dialog);
        const RECT tableRect = Bounds(control, dialog);
        if (Overlap(explanationRect, tableRect)) Fail("preview overlaps table");
        InspectArrangement(dialog, client, tableRect, explanationRect);
        if (list && ListView_GetItemCount(control) &&
            ListView_GetNextItem(control, -1, LVNI_SELECTED) != 0)
            Fail("first rule is not selected");
        if (!list) {
            HWND name = GetDlgItem(dialog, 305);
            HDC dc = GetDC(name);
            const COLORREF expected = GetSysColor(COLOR_WINDOW);
            SendMessageW(dialog, WM_CTLCOLOREDIT, reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(name));
            if (GetBkColor(dc) != expected) Fail("name field has the wrong background");
            ReleaseDC(name, dc);
            const RECT nameRect = Bounds(name, dialog);
            if (Overlap(nameRect, explanationRect) || Overlap(nameRect, tableRect))
                Fail("name overlaps rule content");
            if (interactive) {
                // Находим условие по ресурсу, а не по меняющемуся номеру строки.
                int portRow = -1;
                for (int row = 0; row < ListView_GetItemCount(control); ++row) {
                    wchar_t label[256]{};
                    ListView_GetItemText(control, row, 0, label, static_cast<int>(std::size(label)));
                    if (LoadStringRes(IDS_COND_REMOTE_PORT) == label) { portRow = row; break; }
                }
                Require(portRow >= 0, "remote port condition is missing");
                ListView_SetCheckState(control, portRow, FALSE);
                SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(307, BN_CLICKED), 0);
                ListView_SetCheckState(control, portRow, TRUE);
                SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(308, BN_CLICKED), 0);
            }
        }
        if (growExplanation) {
            InspectExplanation(dialog);
            if (list) {
                ListView_SetItemState(control, 0, 0, LVIS_SELECTED);
                ListView_SetItemState(control, 1, LVIS_SELECTED | LVIS_FOCUSED,
                                      LVIS_SELECTED | LVIS_FOCUSED);
                RECT resized{};
                GetClientRect(dialog, &resized);
                InspectArrangement(dialog, resized, Bounds(control, dialog),
                                   Bounds(GetDlgItem(dialog, 409), dialog));
                InspectExplanation(dialog);
            }
        }
        if (!image.empty()) savedImage = SaveWindow(dialog, image);
    }

    static void CALLBACK Tick(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog || !active) return;
        KillTimer(nullptr, timer);
        active->inspected = true;
        active->Inspect(dialog);
        PostMessageW(dialog, WM_COMMAND, active->interactive ? IDOK : IDCANCEL, 0);
    }

    UINT_PTR Start() {
        active = this;
        const UINT_PTR timer = SetTimer(nullptr, 0, preview ? 350 : 20, Tick);
        Require(timer != 0, "could not start editor layout probe");
        return timer;
    }
    void Finish(UINT_PTR timer) {
        KillTimer(nullptr, timer);
        active = nullptr;
        Require(inspected, "editor layout probe was not called");
        Require(savedImage, "could not capture native dialog");
        if (!error.empty()) throw std::runtime_error(error);
    }
};

struct ConditionDialogProbe {
    static inline ConditionDialogProbe* active = nullptr;
    int width, height, tableId, inputId, hintId, buttonId;
    bool inputBelow;
    bool inspected = false;
    std::string error;

    void Fail(const char* text) {
        if (error.empty()) error = text;
    }

    void Inspect(HWND dialog) {
        Ui::Metrics m;
        m.dpi = GetDpiForWindow(dialog);
        RECT client{};
        GetClientRect(dialog, &client);
        if (client.right != m.Sc(width) || client.bottom != m.Sc(height))
            Fail("condition dialog size changed");
        const RECT ok = Bounds(GetDlgItem(dialog, IDOK), dialog);
        const RECT cancel = Bounds(GetDlgItem(dialog, IDCANCEL), dialog);
        if (ok.top != client.bottom - m.margin() - m.btnH() ||
            cancel.left != client.right - m.margin() - m.btnW() ||
            cancel.left != ok.right + m.gap())
            Fail("condition dialog footer buttons moved");
        HWND table = GetDlgItem(dialog, tableId);
        const RECT list = Bounds(table, dialog);
        if (list.left != m.margin() + 1 || list.bottom >= ok.top)
            Fail("condition dialog list moved");
        const RECT input = Bounds(GetDlgItem(dialog, inputId), dialog);
        if (inputBelow ? input.top <= list.bottom : input.bottom >= list.top)
            Fail("condition dialog input and list order changed");
        if (buttonId) {
            const RECT button = Bounds(GetDlgItem(dialog, buttonId), dialog);
            if (button.left != list.right + m.gap() + 1 || button.top != list.top - 1)
                Fail("condition dialog actions left the right-hand column");
        }
        for (HWND control : {table, GetDlgItem(dialog, inputId)}) {
            LOGFONTW font{};
            wchar_t cls[32]{};
            GetClassNameW(control, cls, static_cast<int>(std::size(cls)));
            HWND textControl = _wcsicmp(cls, WC_IPADDRESSW) == 0 ? GetWindow(control, GW_CHILD) : control;
            GetObjectW(reinterpret_cast<HFONT>(SendMessageW(textControl, WM_GETFONT, 0, 0)), sizeof(font), &font);
            if (std::wstring(font.lfFaceName) != L"Segoe UI" ||
                (GetWindowLongPtrW(control, GWL_EXSTYLE) & WS_EX_CLIENTEDGE)) {
                std::wcerr << L"Condition control " << GetDlgCtrlID(control) << L": font=" << font.lfFaceName
                           << L", exStyle=" << GetWindowLongPtrW(control, GWL_EXSTYLE) << L'\n';
                Fail("condition dialog has inconsistent field styling");
            }
        }
        LOGFONTW header{};
        GetObjectW(reinterpret_cast<HFONT>(SendMessageW(ListView_GetHeader(table), WM_GETFONT, 0, 0)),
                   sizeof(header), &header);
        if (header.lfWeight != FW_SEMIBOLD) Fail("condition table heading is not semibold");
        if (hintId) {
            HWND hint = GetDlgItem(dialog, hintId);
            const RECT rect = Bounds(hint, dialog);
            HDC dc = GetDC(hint);
            SendMessageW(dialog, WM_CTLCOLORSTATIC, reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(hint));
            if (GetBkColor(dc) != RGB(0xFF, 0xFF, 0xE1) || rect.top <= input.bottom ||
                rect.bottom >= ok.top || (GetWindowLongPtrW(hint, GWL_EXSTYLE) & WS_EX_CLIENTEDGE))
                Fail("condition dialog hint is not a separate white field");
            ReleaseDC(hint, dc);
        }
    }

    static void CALLBACK Tick(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!active || !dialog) return;
        KillTimer(nullptr, timer);
        active->inspected = true;
        active->Inspect(dialog);
        PostMessageW(dialog, WM_COMMAND, IDCANCEL, 0);
    }
};

void ConditionDialogs(UiLang language) {
    SetUiLang(language);
    const HINSTANCE inst = GetModuleHandleW(nullptr);
    const ConditionDialogProbe cases[] = {
        {520, 470, 101, 103, 104,   0, true},
        {556, 520, 169, 164, 173, 170, false},
        {540, 470, 201, 200,   0,   0, false},
        {560, 520, 240, 241, 242, 243, true},
        {560, 520, 240, 241, 242, 243, true},
        {660, 560, 282, 286, 287, 283, true}
    };
    for (int i = 0; i < static_cast<int>(std::size(cases)); ++i) {
        ConditionDialogProbe probe = cases[i];
        ConditionDialogProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, ConditionDialogProbe::Tick);
        Require(timer != 0, "could not start condition dialog probe");
        Proto protocol = Proto::Tcp;
        bool any = false;
        std::vector<AddrItem> addresses;
        std::vector<PortItem> ports;
        std::vector<IcmpTypeItem> types;
        std::vector<ServiceItem> services;
        switch (i) {
        case 0: RuleDialogs::ChooseProtocol(nullptr, inst, protocol, any); break;
        case 1: RuleDialogs::ChooseAddresses(nullptr, inst, nullptr, addresses); break;
        case 2: RuleDialogs::ChoosePorts(nullptr, inst, nullptr, ports); break;
        case 3: case 4: RuleDialogs::ChooseIcmpTypes(nullptr, inst, i == 4, types); break;
        case 5: RuleDialogs::ChooseServices(nullptr, inst, services); break;
        }
        KillTimer(nullptr, timer);
        ConditionDialogProbe::active = nullptr;
        Require(probe.inspected, "condition dialog probe was not called");
        if (!probe.error.empty())
            throw std::runtime_error("condition dialog " + std::to_string(i) + ": " + probe.error);
    }
}

Rule Sample(RuleScope scope = RuleScope::App) {
    Rule rule;
    rule.scope = scope;
    rule.appPath = scope == RuleScope::App ? L"C:\\Windows\\System32\\notepad.exe" : L"";
    rule.appName = L"NOTEPAD.EXE";
    rule.conds = CondProto | CondDirection | CondRemotePort;
    rule.remotePorts = {{443, 443}};
    rule.SyncName();
    return rule;
}

void Editor(UiLang language, RuleScope scope, bool preview, bool payload = false) {
    SetUiLang(language);
    Rule rule = Sample(scope);
    RuleInheritance inheritance = RuleInheritance::Default;
    Probe probe;
    probe.preview = preview;
    probe.interactive = !preview;
    probe.inheritance = scope == RuleScope::App;
    if (preview) probe.image = payload ? L"build-tests/ui-polish/rule-payload.bmp"
                                      : L"build-tests/ui-polish/rule-editor.bmp";
    const UINT_PTR timer = probe.Start();
    const uint8_t bytes[]{0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02, 0x03};
    RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), rule, !payload,
                    payload ? std::span<const uint8_t>(bytes) : std::span<const uint8_t>(),
                    &inheritance);
    probe.Finish(timer);
    if (!preview) Require(!(rule.conds & CondRemotePort), "copy and paste did not restore the condition");
}

void List(UiLang language, bool preview, bool empty = false) {
    SetUiLang(language);
    RuleStore store;
    Rule rule = Sample();
    if (!empty) {
        Rule block = rule;
        block.remotePorts = {{80, 80}};
        block.action = RuleAction::Block;
        block.SyncName();
        Rule off = rule;
        off.remotePorts = {{8443, 8443}};
        off.enabled = false;
        off.SyncName();
        store.Replace(RuleScope::App, rule.appPath, rule.appName, {rule, block, off});
    }
    Probe probe;
    probe.list = true;
    probe.preview = preview;
    probe.inheritance = true;
    if (preview) probe.image = L"build-tests/ui-polish/app-rules.bmp";
    const UINT_PTR timer = probe.Start();
    AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store, rule.appPath, rule.appName);
    probe.Finish(timer);
}

struct RuleDeletionProbe {
    static inline RuleDeletionProbe* active = nullptr;
    bool clear = false, inspected = false;
    int removed = -1;
    std::string error;

    void Check(bool condition, const char* message) {
        if (!condition && error.empty()) error = message;
    }

    void Inspect(HWND dialog) {
        HWND list = GetDlgItem(dialog, 400);
        const int initialCount = ListView_GetItemCount(list);
        if (clear) {
            while (ListView_GetItemCount(list) > 0) {
                const int previous = ListView_GetItemCount(list);
                SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(404, BN_CLICKED), 0);
                if (ListView_GetItemCount(list) != previous - 1) {
                    Check(false, "could not delete all rules");
                    break;
                }
            }
            Check(ListView_GetNextItem(list, -1, LVNI_SELECTED) == -1,
                  "empty rule list still has a selection");
            Check(!IsWindowEnabled(GetDlgItem(dialog, 404)), "delete remains enabled for an empty list");
            return;
        }

        const int page = ListView_GetCountPerPage(list);
        Check(initialCount > page * 2 && page > 2, "scroll test needs more rules");
        if (initialCount <= page * 2 || page <= 2) return;
        Check(ListView_EnsureVisible(list, initialCount / 2, FALSE) != FALSE,
              "could not scroll the rule list");
        const int top = ListView_GetTopIndex(list);
        removed = top + page / 2;
        ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(list, removed, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        Check(top > 0 && removed + 2 < initialCount, "could not select a middle rule");

        // Первая операция вызывается кнопкой, вторая — клавишей Del.
        SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(404, BN_CLICKED), 0);
        Check(ListView_GetItemCount(list) == initialCount - 1, "delete did not remove one rule");
        Check(ListView_GetTopIndex(list) == top, "rule list scrolled after deleting a visible rule");
        Check(ListView_GetNextItem(list, -1, LVNI_SELECTED) == removed,
              "delete did not select the next rule");
        wchar_t text[128]{};
        ListView_GetItemText(list, removed, 1, text, static_cast<int>(std::size(text)));
        Check(text == L"Rule " + std::to_wstring(removed + 1), "wrong rule after deletion");
        Check((ListView_GetCheckState(list, removed) != FALSE) == ((removed + 1) % 3 != 0),
              "rule enabled state changed after deletion");
        ListView_GetItemText(list, removed, 0, text, static_cast<int>(std::size(text)));
        Check(text == std::to_wstring(removed + 1), "rule number was not updated");
        GetWindowTextW(GetDlgItem(dialog, 408), text, static_cast<int>(std::size(text)));
        Rule selected = Sample();
        selected.priority = removed;
        Check(text == RuleScopeLine(selected), "selected rule priority was not updated");

        SendMessageW(list, WM_KEYDOWN, VK_DELETE, 0);
        Check(ListView_GetItemCount(list) == initialCount - 2, "Del did not remove the next rule");
        Check(ListView_GetTopIndex(list) == top, "rule list scrolled after pressing Del");
        Check(ListView_GetNextItem(list, -1, LVNI_SELECTED) == removed,
              "Del did not select the next rule");

        const int last = ListView_GetItemCount(list) - 1;
        ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(list, last, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, last, FALSE);
        const int bottomTop = ListView_GetTopIndex(list);
        SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(404, BN_CLICKED), 0);
        const int newTop = ListView_GetTopIndex(list);
        Check(newTop <= bottomTop && newTop >= bottomTop - 1,
              "rule list jumped after deleting its last rule");
        Check(ListView_GetNextItem(list, -1, LVNI_SELECTED) == last - 1,
              "deleting the last rule did not select its predecessor");
    }

    static void CALLBACK Tick(HWND, UINT, UINT_PTR timer, DWORD) {
        HWND dialog = Ui::ModalWindow();
        if (!dialog || !active) return;
        KillTimer(nullptr, timer);
        active->inspected = true;
        active->Inspect(dialog);
        PostMessageW(dialog, WM_COMMAND, active->clear ? IDCANCEL : IDOK, 0);
    }
};

void RuleDeletion() {
    SetUiLang(UiLang::English);
    RuleStore store;
    Rule rule = Sample();
    std::vector<Rule> rules;
    for (int i = 0; i < 80; ++i) {
        rule.autoName = false;
        rule.name = L"Rule " + std::to_wstring(i);
        rule.enabled = i % 3 != 0;
        rules.push_back(rule);
    }
    store.ReplaceApp(rule.appPath, rule.appName, rules);

    for (bool clear : {false, true}) {
        RuleDeletionProbe probe;
        probe.clear = clear;
        RuleDeletionProbe::active = &probe;
        const UINT_PTR timer = SetTimer(nullptr, 0, 20, RuleDeletionProbe::Tick);
        Require(timer != 0, "could not start rule deletion probe");
        AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store, rule.appPath, rule.appName);
        KillTimer(nullptr, timer);
        RuleDeletionProbe::active = nullptr;
        Require(probe.inspected, "rule deletion probe was not called");
        if (!probe.error.empty()) throw std::runtime_error(probe.error);
        if (!clear) {
            rules.erase(rules.begin() + probe.removed, rules.begin() + probe.removed + 2);
            rules.pop_back();
        }
        const auto saved = store.ForApp(rule.appPath);
        Require(saved.size() == rules.size(), "saved rule count changed unexpectedly");
        for (size_t i = 0; i < saved.size(); ++i) {
            Require(saved[i].name == rules[i].name && saved[i].enabled == rules[i].enabled &&
                    saved[i].priority == static_cast<int>(i),
                    "saved rule order, priority or enabled state changed unexpectedly");
        }
    }
}

void FullExplanation(UiLang language) {
    SetUiLang(language);
    Rule rule = Sample();
    rule.conds = CondProto | CondDirection | CondService | CondInterface | CondWfpFlags |
                 CondRemoteAddr | CondRemotePort | CondLocalAddr | CondLocalPort;
    rule.conditionFlags = 0x80000101u;
    rule.interfaceName = L"Ethernet";
    rule.services = {{L"Dnscache", L""}};
    AddrItem local, remote;
    Require(ParseIpAddr(L"10.0.0.1", local.addr) && ParseIpAddr(L"1.1.1.1", remote.addr),
            "cannot prepare full rule addresses");
    rule.localAddrs = {local};
    rule.remoteAddrs = {remote};
    rule.localPorts = {{50000, 50000}};
    rule.SyncName();
    Rule longer = rule;
    for (int i = 0; i < 8; ++i) longer.interfaceName += L" Сеть café 网络";
    longer.SyncName();
    RuleStore store;
    store.ReplaceApp(rule.appPath, rule.appName, {rule, longer});
    Probe list;
    list.list = true;
    list.inheritance = true;
    list.growExplanation = true;
    auto timer = list.Start();
    AppRulesEditor::Run(nullptr, GetModuleHandleW(nullptr), store, rule.appPath, rule.appName);
    list.Finish(timer);

    Probe editor;
    editor.growExplanation = true;
    timer = editor.Start();
    RuleEditor::Run(nullptr, GetModuleHandleW(nullptr), longer, true);
    editor.Finish(timer);
}

} // namespace

void TestRuleEditorLayout() {
    const DPI_AWARENESS_CONTEXT previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    const UiLang original = CurrentUiLang();
    std::wstring error;
    Require(Settings::Open(L":memory:", error), "could not open isolated layout settings");
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS | ICC_INTERNET_CLASSES};
    Require(InitCommonControlsEx(&controls) != FALSE, "could not initialize rule controls");
    size_t count = 0;
    const UiLangInfo* languages = UiLangs(count);
    for (size_t i = 0; i < count; ++i) {
        SetUiLang(languages[i].lang);
        Editor(languages[i].lang, RuleScope::App, false);
        Editor(languages[i].lang, RuleScope::PostApp, false, true);
        List(languages[i].lang, false);
    }
    List(UiLang::English, false, true);
    RuleDeletion();
    for (UiLang language : {UiLang::English, UiLang::Russian, UiLang::Arabic}) {
        ConditionDialogs(language);
        FullExplanation(language);
    }
    SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE);
    ConditionDialogs(UiLang::Russian);
    Editor(UiLang::Russian, RuleScope::Global, false);
    List(UiLang::Russian, false);
    SetThreadDpiAwarenessContext(previous);
    SetUiLang(original);
    std::cout << "Rule editor layouts checked in " << count << " languages and both DPI modes\n";
}

void PreviewRuleEditors() {
    SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    std::wstring error;
    Require(Settings::Open(L":memory:", error), "could not open isolated preview settings");
    std::filesystem::create_directories(L"build-tests/ui-polish");
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS | ICC_INTERNET_CLASSES};
    Require(InitCommonControlsEx(&controls) != FALSE, "could not initialize rule preview controls");
    Editor(UiLang::Russian, RuleScope::App, true);
    List(UiLang::Russian, true);
    Editor(UiLang::Russian, RuleScope::PostApp, true, true);
    Settings::Close();
}
