#pragma once
#include "Rules.h"

struct sqlite3;

// Хранилище правил в sqlite3-файле рядом с программой.
// Запись — полная перезапись таблицы в одной транзакции. При ошибке SaveAll
// возвращает false: файл может сохранить прежний набор, отличный от памяти.
class RuleDb {
public:
    RuleDb() = default;
    ~RuleDb();
    RuleDb(const RuleDb&) = delete;
    RuleDb& operator=(const RuleDb&) = delete;

    bool Open(const std::wstring& path, std::wstring& error);
    void Close();
    bool opened() const { return db_ != nullptr; }

    bool Load(std::vector<Rule>& out, uint64_t& maxId, std::wstring& error);
    bool LoadInheritance(std::vector<AppInheritanceSetting>& out, std::wstring& error);
    bool LoadAppInterfaces(std::vector<AppInterfaceSetting>& out, std::wstring& error);
    bool SaveAll(const std::vector<Rule>& rules, std::wstring& error,
                 const std::vector<AppInheritanceSetting>& inheritance = {},
                 const std::vector<AppInterfaceSetting>& appInterfaces = {});

private:
    bool Exec(const char* sql, std::wstring& error);
    std::wstring LastError() const;

    sqlite3* db_ = nullptr;
};