#pragma once
#include <winsqlite/winsqlite3.h>

namespace {
void PreferencePersistenceTests() {
    wchar_t directory[MAX_PATH]{}, name[MAX_PATH]{};
    CheckTest(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"fxn", 0, name));
    struct TempFile {
        const wchar_t* name;
        ~TempFile() { DeleteFileW(name); }
    } cleanup{name};
    sqlite3* db = nullptr;
    CheckTest(sqlite3_open16(name, &db) == SQLITE_OK);
    struct CloseDatabase {
        sqlite3* db;
        ~CloseDatabase() { if (db) sqlite3_close(db); }
    } close{db};
    CheckTest(sqlite3_exec(db, "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
                           nullptr, nullptr, nullptr) == SQLITE_OK);
    const std::wstring firstName = L"Ethernet café 网络";
    const std::wstring secondName = L"Wi-Fi";
    const auto first = ndis_binding::InterfacePreferenceKey(firstName);
    const auto second = ndis_binding::InterfacePreferenceKey(secondName);
    auto write = [&](const std::wstring& key, const wchar_t* value) {
        sqlite3_stmt* statement = nullptr;
        CheckTest(sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO settings VALUES (?1,?2)",
                                    -1, &statement, nullptr) == SQLITE_OK);
        CheckTest(sqlite3_bind_text16(statement, 1, key.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK);
        CheckTest(sqlite3_bind_text16(statement, 2, value, -1, SQLITE_TRANSIENT) == SQLITE_OK);
        const auto status = sqlite3_step(statement);
        sqlite3_finalize(statement);
        CheckTest(status == SQLITE_DONE);
    };
    std::vector<std::wstring> excluded{L"unchanged"};
    CheckTest(ndis_binding::ReadExcludedInterfaces(excluded, name) == S_OK && excluded.empty());
    write(first, L"1"); write(second, L"0");
    CheckTest(ndis_binding::ReadExcludedInterfaces(excluded, name) == S_OK &&
              excluded.size() == 1 && excluded[0] == firstName);
    write(first, L"0"); write(second, L"1");
    CheckTest(ndis_binding::ReadExcludedInterfaces(excluded, name) == S_OK &&
              excluded.size() == 1 && excluded[0] == secondName);
    write(L"driver.ndis.excluded.", L"1");
    CheckTest(FAILED(ndis_binding::ReadExcludedInterfaces(excluded, name)) &&
              excluded.size() == 1 && excluded[0] == secondName);
}
} // namespace
