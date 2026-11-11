#include "Common.h"
#include "StringRes.h"

#include <iostream>
#include <stdexcept>

namespace {

DWORD tcpEntryResult = NO_ERROR;

DWORD SetTcpEntryForTest(PMIB_TCPROW) {
    return tcpEntryResult;
}

bool IsElevatedForTest() {
    return true;
}

} // namespace

// Проверяем ответ API независимо от прав тестового процесса, не разрывая соединения.
#define SetTcpEntry SetTcpEntryForTest
#define IsElevated IsElevatedForTest
#include "../ConnKill.cpp"
#undef IsElevated
#undef SetTcpEntry

namespace {

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void TestMissingDescription() {
    // Эти системные шаблоны требуют аргументов, которых у вызывающего нет.
    for (DWORD error : {DWORD(ERROR_MR_MID_NOT_FOUND), DWORD(ERROR_BAD_EXE_FORMAT),
                        DWORD(ERROR_WRONG_DISK), DWORD(0xdeadbeef)}) {
        const std::wstring expected = LoadStringResFmt(
            IDS_FMT_ERRCODE_ONLY, static_cast<unsigned long>(error));
        Check(!expected.empty(), "error code resource is empty");
        Check(FormatWinError(error) == expected,
              "unresolved system message must fall back to the original error code");
    }
}

void TestConnectionError() {
    ConnKill::Target target;
    target.valid = true;
    target.local.family = target.remote.family = AF_INET;
    target.local.b[0] = target.remote.b[0] = 127;
    target.local.b[3] = target.remote.b[3] = 1;
    target.lport = 40000;
    target.rport = 443;
    target.state = MIB_TCP_STATE_ESTAB;
    Check(ConnKill::Check(target) == ConnKill::Denial::None,
          "test connection must reach SetTcpEntry");

    std::wstring message;
    for (DWORD error : {DWORD(ERROR_ACCESS_DENIED), DWORD(ERROR_MR_MID_NOT_FOUND)}) {
        tcpEntryResult = error;
        Check(!ConnKill::Kill(target, message), "access error was treated as success");
        Check(message == LoadStringRes(IDS_KILL_ERROR_ACCESS),
              "SetTcpEntry access error must explain the administrator requirement");
    }

    tcpEntryResult = ERROR_GEN_FAILURE;
    Check(!ConnKill::Kill(target, message) && message == FormatWinError(tcpEntryResult),
          "other SetTcpEntry errors must retain their system description");
    tcpEntryResult = NO_ERROR;
    Check(ConnKill::Kill(target, message) && message.empty(),
          "successful SetTcpEntry must clear the previous error");
}

void TestSystemDescription() {
    for (DWORD error : {DWORD(ERROR_ACCESS_DENIED), DWORD(ERROR_FILE_NOT_FOUND)}) {
        wchar_t buffer[2048]{};
        const DWORD size = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buffer, static_cast<DWORD>(std::size(buffer)), nullptr);
        Check(size != 0, "could not load a regular system message");
        std::wstring text(buffer, size);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' ||
                                 text.back() == L' ' || text.back() == L'.'))
            text.pop_back();
        const std::wstring expected = LoadStringResFmt(
            IDS_FMT_ERRCODE_WITH_TEXT, text.c_str(), static_cast<unsigned long>(error));
        Check(FormatWinError(error) == expected,
              "regular system description or original error code was lost");
    }
}

} // namespace

int main() {
    try {
        size_t count = 0;
        const UiLangInfo* languages = UiLangs(count);
        Check(count != 0, "no UI languages found");
        for (size_t i = 0; i < count; ++i) {
            SetUiLang(languages[i].lang);
            TestMissingDescription();
            TestSystemDescription();
            TestConnectionError();
        }
        std::cout << "Win32 error handling tests passed for " << count << " languages\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
