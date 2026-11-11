#include "NdisBinding.h"
#include "Settings.h"
#include "AppInfo.h"
#include <winsqlite/winsqlite3.h>
#include <memory>
#include <new>

namespace ndis_binding {
namespace {
using namespace detail;

struct DatabaseCloser {
    void operator()(sqlite3* db) const noexcept { if (db) sqlite3_close(db); }
};
struct StatementCloser {
    void operator()(sqlite3_stmt* statement) const noexcept { if (statement) sqlite3_finalize(statement); }
};
using Database = std::unique_ptr<sqlite3, DatabaseCloser>;
using Statement = std::unique_ptr<sqlite3_stmt, StatementCloser>;

void CheckSql(int status) {
    if (status == SQLITE_OK || status == SQLITE_ROW || status == SQLITE_DONE) return;
    if (status == SQLITE_BUSY || status == SQLITE_LOCKED) throw Error{HRESULT_FROM_WIN32(ERROR_BUSY)};
    if (status == SQLITE_PERM || status == SQLITE_AUTH || status == SQLITE_READONLY)
        throw Error{E_ACCESSDENIED};
    if (status == SQLITE_NOMEM) throw Error{E_OUTOFMEMORY};
    throw Error{HRESULT_FROM_WIN32(ERROR_READ_FAULT)};
}

std::wstring DefaultDatabase() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length == path.size()) throw Error{HRESULT_FROM_WIN32(length ? ERROR_INSUFFICIENT_BUFFER : GetLastError())};
    path.resize(length);
    const auto slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) throw Error{E_UNEXPECTED};
    path.resize(slash + 1);
    return path + AppInfo::kSettingsDb;
}

std::string Utf8(const std::wstring& value) {
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
                                           nullptr, 0, nullptr, nullptr);
    if (!length) throw Error{HRESULT_FROM_WIN32(GetLastError())};
    std::string result(static_cast<size_t>(length), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
                             result.data(), length, nullptr, nullptr))
        throw Error{HRESULT_FROM_WIN32(GetLastError())};
    result.pop_back();
    return result;
}

Statement Prepare(sqlite3* db, const char* sql) {
    sqlite3_stmt* raw = nullptr;
    const int status = sqlite3_prepare_v2(db, sql, -1, &raw, nullptr);
    Statement statement(raw);
    CheckSql(status);
    return statement;
}
} // namespace

std::wstring InterfacePreferenceKey(std::wstring_view name) {
    if (name.empty() || name.find(L'\0') != std::wstring_view::npos) throw detail::Error{E_INVALIDARG};
    return std::wstring(Settings::Key::kNdisExcludedInterfacePrefix) + std::wstring(name);
}

HRESULT ReadExcludedInterfaces(std::vector<std::wstring>& excluded, const wchar_t* database) noexcept {
    try {
        const std::wstring path = database ? database : DefaultDatabase();
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                excluded.clear();
                return S_OK;
            }
            throw Error{HRESULT_FROM_WIN32(error)};
        }
        sqlite3* raw = nullptr;
        const auto name = Utf8(path);
        const int status = sqlite3_open_v2(name.c_str(), &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
        Database db(raw);
        CheckSql(status);
        CheckSql(sqlite3_busy_timeout(db.get(), 3000));
        auto schema = Prepare(db.get(), "SELECT 1 FROM sqlite_master WHERE type='table' AND name='settings'");
        const int exists = sqlite3_step(schema.get());
        CheckSql(exists);
        if (exists == SQLITE_DONE) { excluded.clear(); return S_OK; }
        schema.reset();
        auto query = Prepare(db.get(), "SELECT key FROM settings WHERE value='1' AND substr(key,1,?1)=?2");
        const auto prefix = std::wstring(Settings::Key::kNdisExcludedInterfacePrefix);
        CheckSql(sqlite3_bind_int(query.get(), 1, static_cast<int>(prefix.size())));
        CheckSql(sqlite3_bind_text16(query.get(), 2, prefix.c_str(), -1, SQLITE_TRANSIENT));
        std::vector<std::wstring> result;
        for (;;) {
            const int step = sqlite3_step(query.get());
            CheckSql(step);
            if (step == SQLITE_DONE) break;
            const auto* text = static_cast<const wchar_t*>(sqlite3_column_text16(query.get(), 0));
            const int bytes = sqlite3_column_bytes16(query.get(), 0);
            if (!text || bytes < 0 || bytes % sizeof(wchar_t)) throw Error{HRESULT_FROM_WIN32(ERROR_INVALID_DATA)};
            const std::wstring key(text, static_cast<size_t>(bytes) / sizeof(wchar_t));
            const auto interfaceName = std::wstring_view(key).substr(prefix.size());
            if (interfaceName.empty() || interfaceName.find(L'\0') != std::wstring_view::npos)
                throw Error{HRESULT_FROM_WIN32(ERROR_INVALID_DATA)};
            result.emplace_back(interfaceName);
        }
        excluded.swap(result);
        return S_OK;
    } catch (const detail::Error& error) { return error.status; }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}
} // namespace ndis_binding
