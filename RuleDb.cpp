#include "RuleDb.h"
#include "ServiceInfo.h"
#include "StringRes.h"
// Заголовок системного SQLite из Windows SDK. Объявляет те же функции, что и
// обычный sqlite3.h, но с __stdcall — именно так их экспортирует
// winsqlite3.dll. Свою копию sqlite3.h держать не нужно.
#include <winsqlite/winsqlite3.h>
#include <algorithm>
#include <cstdio>

namespace {

// ---------------------------------------------------------------------------
// Схема базы правил.
//
// При несовпадении версии таблица создаётся заново. Версия — PRAGMA user_version, поэтому
// опознание не зависит ни от состава колонок, ни от порядка их появления;
// молчаливое чтение чужого формата исключено.
//
// Отличия от прежнего формата:
//   * протокол хранится ОДНИМ полем ip_proto — номером 0..255. Колонок proto
//     (код 0/1/2) и icmp_v6 больше нет: номер и есть протокол, а ICMPv6 —
//     это номер 58;
//   * действие хранится как 0/1: «спрашивать» перестало быть действием;
//   * добавлена колонка services — условие «сервис».
//
// Списки хранятся строками:
//   remote_addrs / local_addrs   «@DNS_SERVERS;10.0.0.0/8»        разделитель ';'
//   remote_ports / local_ports   «80-80;5000-5010»                             ';'
//   icmp_types                   «8:-1;3:1»  (код -1 = любой)                  ';'
//   services                     «Dnscache\W32Time»                            '\'
//
// Для сервисов разделителем взят обратный слэш: он ЗАПРЕЩЁН в имени сервиса
// (см. CreateService), поэтому разбор однозначен при любом допустимом имени,
// включая имена с точкой с запятой.
// ---------------------------------------------------------------------------
constexpr int kSchemaVersion = 8;

const char* kSchema =
    "CREATE TABLE IF NOT EXISTS rules ("
    " id INTEGER PRIMARY KEY,"
    " scope INTEGER NOT NULL DEFAULT 0,"
    " priority INTEGER NOT NULL DEFAULT 0,"
    " name TEXT NOT NULL DEFAULT '',"
    " auto_name INTEGER NOT NULL DEFAULT 1,"
    " app_path TEXT NOT NULL DEFAULT '',"
    " app_name TEXT NOT NULL DEFAULT '',"
    " enabled INTEGER NOT NULL DEFAULT 1,"
    " conds INTEGER NOT NULL DEFAULT 0,"
    " ip_proto INTEGER NOT NULL DEFAULT 6,"
    " dir INTEGER NOT NULL DEFAULT 2,"
    " action INTEGER NOT NULL DEFAULT 0,"
    " remote_addrs TEXT NOT NULL DEFAULT '',"
    " local_addrs TEXT NOT NULL DEFAULT '',"
    " remote_ports TEXT NOT NULL DEFAULT '',"
    " local_ports TEXT NOT NULL DEFAULT '',"
    " icmp_types TEXT NOT NULL DEFAULT '',"
    " services TEXT NOT NULL DEFAULT '',"
    " interface_name TEXT NOT NULL DEFAULT '',"
    " condition_flags INTEGER NOT NULL DEFAULT 0"
    ");";

// Независимая таблица: удаление последнего правила не теряет настройку
// приложения. Дополнение схемы 6 не меняет формат существующих правил.
const char* kInheritanceSchema =
    "CREATE TABLE IF NOT EXISTS app_inheritance ("
    " app_path TEXT PRIMARY KEY NOT NULL,"
    " mode INTEGER NOT NULL"
    ");";

const char* kAppInterfaceSchema =
    "CREATE TABLE IF NOT EXISTS app_interfaces ("
    " app_path TEXT PRIMARY KEY NOT NULL,"
    " interface_name TEXT NOT NULL CHECK(interface_name <> '')"
    ");";

// Отдельная таблица сохраняет флажок и при выборе маршрутизации по умолчанию,
// не меняя существующую схему и не удаляя прежние правила.
const char* kAppInterfaceBlockSchema =
    "CREATE TABLE IF NOT EXISTS app_interface_blocks ("
    " app_path TEXT PRIMARY KEY NOT NULL"
    ");";

const char* kInsert =
    "INSERT INTO rules (id, scope, priority, name, auto_name, app_path, app_name,"
    " enabled, conds, ip_proto, dir, action,"
    " remote_addrs, local_addrs, remote_ports, local_ports, icmp_types, services, interface_name, condition_flags)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20);";

const char* kSelect =
    "SELECT id, scope, priority, name, auto_name, app_path, app_name, enabled,"
    " conds, ip_proto, dir, action,"
    " remote_addrs, local_addrs, remote_ports, local_ports, icmp_types, services, interface_name, condition_flags"
    " FROM rules ORDER BY scope DESC, app_path COLLATE NOCASE, priority, id;";

// Порядок колонок в kSelect. Числовые литералы в коде разбора превращали
// любую правку запроса в поиск ошибки по всему файлу.
enum Col {
    ColId = 0, ColScope, ColPriority, ColName, ColAutoName, ColAppPath,
    ColAppName, ColEnabled, ColConds, ColProtoNum, ColDir, ColAction,
    ColRemoteAddrs, ColLocalAddrs, ColRemotePorts, ColLocalPorts,
    ColIcmpTypes, ColServices, ColInterfaceName, ColConditionFlags
};

// ------------------------------------------------------------ служебное sqlite

std::wstring SqlError(sqlite3* db) {
    if (!db) return LoadStringRes(IDS_DBERR_RULES_CLOSED);
    const char* msg = sqlite3_errmsg(db);
    return msg ? Utf8ToWide(msg) : LoadStringRes(IDS_DBERR_SQLITE_UNKNOWN);
}

bool RunSql(sqlite3* db, const char* sql, std::wstring& error) {
    if (!db) { error = LoadStringRes(IDS_DBERR_RULES_CLOSED); return false; }
    char* msg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &msg) != SQLITE_OK) {
        error = msg ? Utf8ToWide(msg) : SqlError(db);
        if (msg) sqlite3_free(msg);
        return false;
    }
    return true;
}

int ScalarInt(sqlite3* db, const char* sql, int def) {
    if (!db) return def;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return def;
    int v = def;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

// Версия задаёт полный формат правил; несовместимый набор создаётся заново.
bool EnsureSchema(sqlite3* db, std::wstring& error) {
    const int version = ScalarInt(db, "PRAGMA user_version;", 0);
    const int exists  = ScalarInt(db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules';", 0);

    if (exists > 0 && version != kSchemaVersion) {
        if (!RunSql(db, "DROP TABLE rules;", error)) return false;
    }
    if (!RunSql(db, kSchema, error) || !RunSql(db, kInheritanceSchema, error) ||
        !RunSql(db, kAppInterfaceSchema, error) || !RunSql(db, kAppInterfaceBlockSchema, error)) return false;

    // PRAGMA параметров не принимает, поэтому подставляем константу.
    char pragma[64]{};
    _snprintf_s(pragma, sizeof(pragma), _TRUNCATE, "PRAGMA user_version=%d;",
                kSchemaVersion);
    std::wstring ignored;
    RunSql(db, pragma, ignored);        // не критично: схема уже верна
    return true;
}

// --------------------------------------------------------- сериализация списков

// Разбор строки-списка. Пустые элементы пропускаются, поэтому лишние
// разделители и хвостовой разделитель безопасны.
template <class F>
void ForEachToken(const std::wstring& text, wchar_t sep, F&& fn) {
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t next = text.find(sep, pos);
        std::wstring item = text.substr(pos,
            next == std::wstring::npos ? std::wstring::npos : next - pos);
        pos = (next == std::wstring::npos) ? text.size() : next + 1;
        if (!item.empty()) fn(item);
    }
}

std::wstring AddrsToText(const std::vector<AddrItem>& v) {
    std::wstring s;
    for (const AddrItem& a : v) {
        if (!s.empty()) s += L';';
        s += a.Token();          // «@DNS_SERVERS» либо «10.0.0.0/8»
    }
    return s;
}

void TextToAddrs(const std::wstring& t, std::vector<AddrItem>& out) {
    ForEachToken(t, L';', [&out](std::wstring item) {
        // «@» в записи IP-адреса не встречается, поэтому разбор однозначен
        if (item.front() == L'@') {
            const AddrMacro m = AddrMacros::Parse(item);
            if (m == AddrMacro::None) return;     // неизвестный макрос отбрасываем
            AddrItem a;
            a.macro = m;
            out.push_back(a);
            return;
        }

        int prefix = -1;
        const size_t sl = item.find(L'/');
        if (sl != std::wstring::npos) {
            prefix = _wtoi(item.c_str() + sl + 1);
            item.resize(sl);
        }
        AddrItem a;
        if (!ParseIpAddr(item, a.addr)) return;
        const int total = static_cast<int>(a.addr.len()) * 8;
        if (prefix > total) prefix = total;
        a.prefix = prefix;
        if (prefix >= 0) ApplyPrefix(a.addr, prefix, false);
        out.push_back(a);
    });
}

std::wstring PortsToText(const std::vector<PortItem>& v) {
    std::wstring s;
    for (const PortItem& p : v) {
        if (!s.empty()) s += L';';
        s += std::to_wstring(p.from) + L"-" + std::to_wstring(p.to);
    }
    return s;
}

void TextToPorts(const std::wstring& t, std::vector<PortItem>& out) {
    ForEachToken(t, L';', [&out](const std::wstring& item) {
        long lo = 0, hi = 0;
        const size_t dash = item.find(L'-');
        if (dash == std::wstring::npos) {
            lo = hi = _wtol(item.c_str());
        } else {
            lo = _wtol(item.substr(0, dash).c_str());
            hi = _wtol(item.c_str() + dash + 1);
        }
        if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535) return;
        if (lo > hi) std::swap(lo, hi);
        out.push_back(PortItem{ static_cast<uint16_t>(lo), static_cast<uint16_t>(hi) });
    });
}

// «8:-1;3:1» — код -1 означает «любой»
std::wstring IcmpToText(const std::vector<IcmpTypeItem>& v) {
    std::wstring s;
    for (const IcmpTypeItem& t : v) {
        if (!s.empty()) s += L';';
        s += std::to_wstring(t.type) + L":" + std::to_wstring(t.code);
    }
    return s;
}

void TextToIcmp(const std::wstring& t, std::vector<IcmpTypeItem>& out) {
    ForEachToken(t, L';', [&out](const std::wstring& item) {
        long type = 0, code = -1;
        const size_t colon = item.find(L':');
        if (colon == std::wstring::npos) {
            type = _wtol(item.c_str());
        } else {
            type = _wtol(item.substr(0, colon).c_str());
            code = _wtol(item.c_str() + colon + 1);
        }
        if (type < 0 || type > 255) return;
        if (code > 255) code = 255;
        if (code < 0) code = -1;
        IcmpTypeItem x;
        x.type = static_cast<uint8_t>(type);
        x.code = static_cast<int>(code);
        out.push_back(x);
    });
}

// Хранится только КЛЮЧ сервиса: отображаемое имя зависит от языка системы
// и запрашивается у диспетчера служб при показе.
std::wstring ServicesToText(const std::vector<ServiceItem>& v) {
    std::wstring s;
    for (const ServiceItem& x : v) {
        if (x.name.empty()) continue;
        if (!s.empty()) s += L'\\';
        s += x.name;
    }
    return s;
}

void TextToServices(const std::wstring& t, std::vector<ServiceItem>& out) {
    ForEachToken(t, L'\\', [&out](const std::wstring& item) {
        // Дубликаты отбрасываем: на смысл правила они не влияют, а
        // сопоставление удлиняют.
        for (const ServiceItem& x : out)
            if (ServiceInfo::SameName(x.name, item)) return;
        ServiceItem s;
        s.name = item;
        out.push_back(std::move(s));
    });
}

std::wstring ColumnText(sqlite3_stmt* st, int col) {
    const unsigned char* p = sqlite3_column_text(st, col);
    if (!p) return std::wstring();
    return Utf8ToWide(reinterpret_cast<const char*>(p));
}

int BindText(sqlite3_stmt* st, int idx, const std::wstring& s) {
    const std::string u = WideToUtf8(s);
    return sqlite3_bind_text(st, idx, u.c_str(), static_cast<int>(u.size()),
                             SQLITE_TRANSIENT);
}

} // namespace

RuleDb::~RuleDb() { Close(); }

std::wstring RuleDb::LastError() const { return SqlError(db_); }

bool RuleDb::Exec(const char* sql, std::wstring& error) {
    return RunSql(db_, sql, error);
}

bool RuleDb::Open(const std::wstring& path, std::wstring& error) {
    Close();
    const std::string utf8 = WideToUtf8(path);
    const int rc = sqlite3_open_v2(utf8.c_str(), &db_,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        error = db_ ? LastError() : Utf8ToWide(sqlite3_errstr(rc));
        Close();
        return false;
    }
    sqlite3_busy_timeout(db_, 10000);

    std::wstring ignored;
    Exec("PRAGMA foreign_keys=ON;", ignored);           // не критично
    if (!EnsureSchema(db_, error)) { Close(); return false; }
    return true;
}

void RuleDb::Close() {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

bool RuleDb::Load(std::vector<Rule>& out, uint64_t& maxId, std::wstring& error) {
    out.clear();
    maxId = 0;
    if (!db_) { error = LoadStringRes(IDS_DBERR_RULES_CLOSED); return false; }

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, kSelect, -1, &st, nullptr) != SQLITE_OK) {
        error = LastError();
        return false;
    }
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        Rule r;
        r.id       = static_cast<uint64_t>(sqlite3_column_int64(st, ColId));
        const int scope = sqlite3_column_int(st, ColScope);
        // В старой схеме PostApp сохранялся как App с пустым путём.
        if (scope == 0 && sqlite3_column_type(st, ColAppPath) == SQLITE_NULL) {
            r.scope = RuleScope::PostApp;
        } else if (scope == 0 && ColumnText(st, ColAppPath).empty()) {
            r.scope = RuleScope::PostApp;
        } else if (scope == 1) {
            r.scope = RuleScope::Global;
        } else if (scope == 3) {
            r.scope = RuleScope::Interface;
        } else if (scope == 2) {
            r.scope = RuleScope::PostApp;
        } else {
            r.scope = RuleScope::App;
        }
        r.priority = sqlite3_column_int(st, ColPriority);
        r.name     = ColumnText(st, ColName);
        r.autoName = sqlite3_column_int(st, ColAutoName) != 0;
        r.appPath  = ColumnText(st, ColAppPath);
        r.appName  = ColumnText(st, ColAppName);
        r.interfaceName = ColumnText(st, ColInterfaceName);
        r.conditionFlags = static_cast<uint32_t>(sqlite3_column_int64(st, ColConditionFlags));
        r.enabled  = sqlite3_column_int(st, ColEnabled) != 0;
        r.conds    = static_cast<uint32_t>(sqlite3_column_int64(st, ColConds));

        // Номер протокола: любой из 0..255. Значение вне диапазона означает
        // повреждённую запись — берём TCP; ниже NormalizeRuleConds согласует условия.
        const int num = sqlite3_column_int(st, ColProtoNum);
        r.proto = (num >= 0 && num <= 255)
                    ? ProtoFromNumber(static_cast<uint8_t>(num))
                    : Proto::Tcp;

        r.dir = (sqlite3_column_int(st, ColDir) == 1) ? Dir::In : Dir::Out;
        // Действий два: 0 — разрешать, всё остальное — блокировать.
        r.action = (sqlite3_column_int(st, ColAction) == 0) ? RuleAction::Allow
                                                            : RuleAction::Block;

        TextToAddrs(ColumnText(st, ColRemoteAddrs), r.remoteAddrs);
        TextToAddrs(ColumnText(st, ColLocalAddrs),  r.localAddrs);
        TextToPorts(ColumnText(st, ColRemotePorts), r.remotePorts);
        TextToPorts(ColumnText(st, ColLocalPorts),  r.localPorts);
        TextToIcmp(ColumnText(st, ColIcmpTypes),    r.icmpTypes);
        TextToServices(ColumnText(st, ColServices), r.services);

        if (r.isGlobal()) r.appPath.clear();
        if (r.priority < 0) r.priority = 0;
        if (r.id > maxId) maxId = r.id;
        NormalizeRuleConds(r);
        r.SyncName();
        out.push_back(std::move(r));
    }
    if (rc != SQLITE_DONE) {
        error = LastError();
        sqlite3_finalize(st);
        // Частичный набор не должен попасть в сопоставление или сохранение.
        out.clear();
        maxId = 0;
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

bool RuleDb::LoadInheritance(std::vector<AppInheritanceSetting>& out, std::wstring& error) {
    out.clear();
    if (!db_) { error = LoadStringRes(IDS_DBERR_RULES_CLOSED); return false; }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT app_path, mode FROM app_inheritance;", -1,
                           &st, nullptr) != SQLITE_OK) {
        error = LastError();
        return false;
    }
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const int mode = sqlite3_column_int(st, 1);
        if (mode < 1 || mode > 3) continue;
        std::wstring path = ColumnText(st, 0);
        if (!path.empty()) out.push_back({std::move(path), static_cast<RuleInheritance>(mode)});
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return true;
    error = LastError();
    out.clear();
    return false;
}

bool RuleDb::LoadAppInterfaces(std::vector<AppInterfaceSetting>& out, std::wstring& error) {
    out.clear();
    if (!db_) { error = LoadStringRes(IDS_DBERR_RULES_CLOSED); return false; }
    sqlite3_stmt* st = nullptr;
    const char* select =
        "SELECT app_path, interface_name, 0 FROM app_interfaces "
        "UNION ALL SELECT app_path, '', 1 FROM app_interface_blocks;";
    if (sqlite3_prepare_v2(db_, select, -1, &st, nullptr) != SQLITE_OK) {
        error = LastError();
        return false;
    }
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        AppInterfaceSetting setting{ColumnText(st, 0), ColumnText(st, 1), sqlite3_column_int(st, 2) != 0};
        if (!setting.appPath.empty() && (!setting.interfaceName.empty() || setting.blockOtherInterfaces))
            out.push_back(std::move(setting));
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return true;
    error = LastError();
    out.clear();
    return false;
}

bool RuleDb::SaveAll(const std::vector<Rule>& rules, std::wstring& error,
                     const std::vector<AppInheritanceSetting>& inheritance,
                     const std::vector<AppInterfaceSetting>& appInterfaces) {
    if (!db_) { error = LoadStringRes(IDS_DBERR_RULES_CLOSED); return false; }

    if (!Exec("BEGIN IMMEDIATE;", error)) return false;
    if (!Exec("DELETE FROM rules; DELETE FROM app_inheritance; DELETE FROM app_interfaces; "
              "DELETE FROM app_interface_blocks;", error)) {
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, kInsert, -1, &st, nullptr) != SQLITE_OK) {
        error = LastError();
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }

    bool ok = true;
    for (const Rule& r : rules) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);

        sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(r.id));
        sqlite3_bind_int(st, 2, static_cast<int>(r.scope));
        sqlite3_bind_int(st, 3, r.priority);
        BindText(st, 4, r.name);
        sqlite3_bind_int(st, 5, r.autoName ? 1 : 0);
        BindText(st, 6, r.appPath);
        BindText(st, 7, r.appName);
        sqlite3_bind_int(st, 8, r.enabled ? 1 : 0);
        sqlite3_bind_int64(st, 9, static_cast<sqlite3_int64>(r.conds));
        sqlite3_bind_int(st, 10, ProtoNumber(r.proto));
        sqlite3_bind_int(st, 11, static_cast<int>(r.dir));
        sqlite3_bind_int(st, 12, r.blocks() ? 1 : 0);
        BindText(st, 13, AddrsToText(r.remoteAddrs));
        BindText(st, 14, AddrsToText(r.localAddrs));
        BindText(st, 15, PortsToText(r.remotePorts));
        BindText(st, 16, PortsToText(r.localPorts));
        BindText(st, 17, IcmpToText(r.icmpTypes));
        BindText(st, 18, ServicesToText(r.services));
        BindText(st, 19, r.interfaceName);
        sqlite3_bind_int64(st, 20, static_cast<sqlite3_int64>(r.conditionFlags));

        if (sqlite3_step(st) != SQLITE_DONE) {
            error = LastError();
            ok = false;
            break;
        }
    }
    sqlite3_finalize(st);

    if (!ok) {
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    const char* insertInheritance =
        "INSERT INTO app_inheritance(app_path, mode) VALUES (?1, ?2);";
    if (sqlite3_prepare_v2(db_, insertInheritance, -1, &st, nullptr) != SQLITE_OK) {
        error = LastError();
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    for (const auto& setting : inheritance) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (BindText(st, 1, setting.appPath) != SQLITE_OK ||
            sqlite3_bind_int(st, 2, static_cast<int>(setting.mode)) != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_DONE) {
            error = LastError();
            ok = false;
            break;
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    const char* insertInterface =
        "INSERT INTO app_interfaces(app_path, interface_name) VALUES (?1, ?2);";
    if (sqlite3_prepare_v2(db_, insertInterface, -1, &st, nullptr) != SQLITE_OK) {
        error = LastError();
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    for (const auto& setting : appInterfaces) {
        if (setting.interfaceName.empty()) continue;
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (BindText(st, 1, setting.appPath) != SQLITE_OK ||
            BindText(st, 2, setting.interfaceName) != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_DONE) {
            error = LastError();
            ok = false;
            break;
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    const char* insertBlock = "INSERT INTO app_interface_blocks(app_path) VALUES (?1);";
    if (sqlite3_prepare_v2(db_, insertBlock, -1, &st, nullptr) != SQLITE_OK) {
        error = LastError();
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    for (const auto& setting : appInterfaces) {
        if (!setting.blockOtherInterfaces) continue;
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (BindText(st, 1, setting.appPath) != SQLITE_OK || sqlite3_step(st) != SQLITE_DONE) {
            error = LastError();
            ok = false;
            break;
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    if (!Exec("COMMIT;", error)) {
        // SQLITE_BUSY оставляет транзакцию открытой и мешает следующему BEGIN.
        std::wstring ignored;
        Exec("ROLLBACK;", ignored);
        return false;
    }
    return true;
}