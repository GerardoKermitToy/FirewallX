#include "Settings.h"
#include "AppInfo.h"

// Системный SQLite из Windows SDK, см. пояснение в RuleDb.cpp
#include <winsqlite/winsqlite3.h>
#include <mutex>

namespace {

std::mutex   g_mtx;
sqlite3*     g_db = nullptr;
std::wstring g_path;
std::wstring g_err;

// PRAGMA user_version здесь НЕ трогается: им владеет RuleDb, и запись
// собственного значения заставила бы его удалить таблицу правил.
const char* kSchema =
    "CREATE TABLE IF NOT EXISTS settings ("
    " key TEXT PRIMARY KEY NOT NULL,"
    " value TEXT NOT NULL DEFAULT ''"
    ");";

const char* kSelect = "SELECT value FROM settings WHERE key=?1;";
// INSERT OR REPLACE, а не ON CONFLICT: работает на любой версии sqlite3.
const char* kUpsert = "INSERT OR REPLACE INTO settings (key, value) VALUES (?1,?2);";
const char* kDelete = "DELETE FROM settings WHERE key=?1;";

std::wstring SqlError() {
    if (!g_db) return LoadStringRes(IDS_DBERR_SETTINGS_CLOSED);
    const char* m = sqlite3_errmsg(g_db);
    return m ? Utf8ToWide(m) : LoadStringRes(IDS_DBERR_SQLITE_UNKNOWN);
}

bool OpenLocked(const std::wstring& file) {
    if (g_db) return true;

    const std::string utf8 = WideToUtf8(file);
    const int rc = sqlite3_open_v2(utf8.c_str(), &g_db,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                   SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        g_err = g_db ? SqlError() : Utf8ToWide(sqlite3_errstr(rc));
        if (g_db) { sqlite3_close(g_db); g_db = nullptr; }
        return false;
    }
    g_path = file;
    // Тот же файл открыт вторым подключением (RuleDb): при одновременной
    // записи ждём до трёх секунд, прежде чем вернуть ошибку занятости.
    sqlite3_busy_timeout(g_db, 3000);

    char* msg = nullptr;
    if (sqlite3_exec(g_db, kSchema, nullptr, nullptr, &msg) != SQLITE_OK) {
        g_err = msg ? Utf8ToWide(msg) : SqlError();
        if (msg) sqlite3_free(msg);
        sqlite3_close(g_db);
        g_db = nullptr;
        return false;
    }
    g_err.clear();
    return true;
}

// Ленивое открытие по пути по умолчанию: настройки читаются раньше, чем
// программа успевает что-либо инициализировать.
bool EnsureLocked() {
    if (g_db) return true;
    return OpenLocked(g_path.empty() ? ModuleDirFile(AppInfo::kSettingsDb) : g_path);
}

int BindText(sqlite3_stmt* st, int idx, const std::wstring& s) {
    const std::string u = WideToUtf8(s);
    return sqlite3_bind_text(st, idx, u.c_str(), static_cast<int>(u.size()),
                             SQLITE_TRANSIENT);
}

bool RunWrite(const char* sql, const wchar_t* key, const std::wstring* value) {
    if (!key || !*key) return false;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (!EnsureLocked()) return false;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, nullptr) != SQLITE_OK) {
        g_err = SqlError();
        return false;
    }
    BindText(st, 1, key);
    if (value) BindText(st, 2, *value);

    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    if (!ok) g_err = SqlError();
    else     g_err.clear();
    sqlite3_finalize(st);
    return ok;
}

} // namespace

namespace Settings {

bool Open(const std::wstring& file, std::wstring& error) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_db && file == g_path) return true;
    if (g_db) { sqlite3_close(g_db); g_db = nullptr; }
    g_path = file;
    if (OpenLocked(file)) return true;
    error = g_err;
    return false;
}

void Close() {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_db) { sqlite3_close(g_db); g_db = nullptr; }
}

bool opened() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_db != nullptr;
}

std::wstring path() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_path.empty() ? ModuleDirFile(AppInfo::kSettingsDb) : g_path;
}

std::wstring lastError() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_err;
}

bool GetString(const wchar_t* key, std::wstring& out) {
    if (!key || !*key) return false;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (!EnsureLocked()) return false;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(g_db, kSelect, -1, &st, nullptr) != SQLITE_OK) {
        g_err = SqlError();
        return false;
    }
    BindText(st, 1, key);

    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* p = sqlite3_column_text(st, 0);
        out = p ? Utf8ToWide(reinterpret_cast<const char*>(p)) : std::wstring();
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

std::wstring GetString(const wchar_t* key, const wchar_t* def) {
    std::wstring v;
    if (!GetString(key, v)) return def ? std::wstring(def) : std::wstring();
    return v;
}

int GetInt(const wchar_t* key, int def) {
    std::wstring v;
    if (!GetString(key, v) || v.empty()) return def;

    wchar_t* end = nullptr;
    const long n = wcstol(v.c_str(), &end, 10);
    if (!end || end == v.c_str()) return def;      // значение не число
    return static_cast<int>(n);
}

bool GetBool(const wchar_t* key, bool def) {
    return GetInt(key, def ? 1 : 0) != 0;
}

bool SetString(const wchar_t* key, const std::wstring& value) {
    return RunWrite(kUpsert, key, &value);
}

bool SetInt(const wchar_t* key, int value) {
    return SetString(key, std::to_wstring(value));
}

bool SetBool(const wchar_t* key, bool value) {
    return SetInt(key, value ? 1 : 0);
}

bool Remove(const wchar_t* key) {
    return RunWrite(kDelete, key, nullptr);
}

} // namespace Settings