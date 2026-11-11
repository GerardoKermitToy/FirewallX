#pragma once
#include "Common.h"
#include "StorageMaintenance.h"
#include "NumericHash.h"

#include <iterator>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

// ---------------------------------------------------------------------------
// Сведения об операционной системе и процессах, которые запрашиваются часто,
// а меняются либо никогда, либо редко.
//
// Файл header-only намеренно: статические переменные внутри inline-функций
// существуют в ЕДИНСТВЕННОМ экземпляре на всю программу (требование
// стандарта), поэтому кеш общий для всех единиц трансляции и отдельный .cpp
// не нужен.
// ---------------------------------------------------------------------------

// Каталог System32 с завершающим «\».
//
// Значение ПОСТОЯННО: каталог не может измениться за время жизни процесса.
// Система спрашивается один раз; инициализация статика потокобезопасна.
//
// Пустая строка означает, что каталог определить не удалось (крайний случай):
// вызывающий обязан считать путь неизвестным, а не подставлять относительный.
inline const std::wstring& SystemDirectory() {
    static const std::wstring dir = []() -> std::wstring {
        wchar_t buf[MAX_PATH]{};
        const UINT n = GetSystemDirectoryW(buf, static_cast<UINT>(MAX_PATH));
        if (n == 0 || n >= static_cast<UINT>(MAX_PATH)) return std::wstring();
        std::wstring s(buf, n);
        if (!s.empty() && s.back() != L'\\') s.push_back(L'\\');
        return s;
    }();
    return dir;
}

inline std::wstring SystemDirFile(const wchar_t* leaf) {
    const std::wstring& dir = SystemDirectory();
    if (dir.empty()) return std::wstring();
    return dir + (leaf ? leaf : L"");
}

// Образ ядра: «исполняемый файл» процесса System (pid 4).
inline std::wstring KernelImagePath() { return SystemDirFile(L"ntoskrnl.exe"); }

// ---------------------------------------------------------------------------
// Системные номера процессов.
//
//   pid 0 — владельца нет вовсе: так приходят события пакетного уровня WFP
//           (ICMP и прочие протоколы без сокета);
//   pid 4 — System.
//
// Оба существуют всегда, поэтому проверке на завершение не подлежат: иначе
// весь трафик ядра и ICMP пропал бы из списка.
// ---------------------------------------------------------------------------
inline constexpr bool IsSystemPid(DWORD pid) { return pid == 0 || pid == 4; }

// ---------------------------------------------------------------------------
// Отсрочка удаления сведений о завершившемся процессе (имя, путь, значок).
//
// Строго БОЛЬШЕ окна показа завершённых соединений (kFinishedGraceMs,
// FlowStore.h): строки завершившейся программы живут это окно, и всё оно
// им нужны её имя и значок. Сравняй сроки — и на последнем такте окна
// вместо «FIREFOX.EXE» со значком осталось бы «PID 1234 (путь недоступен)».
//
// Согласованность проверяется static_assert в Monitor.cpp.
// ---------------------------------------------------------------------------
inline constexpr ULONGLONG kProcessGraceMs = 9000;

// Срок доверия результату опроса. Одна секунда: список соединений обновляется
// с тем же шагом, а проверка одного pid дороже поиска в карте на три порядка.
inline constexpr ULONGLONG kProcessAliveTtlMs = 1000;

// ---------------------------------------------------------------------------
// Сколько запись живёт БЕЗ обращений к ней.
//
// Величина важна: пока запись существует, момент первого обнаружения смерти
// не теряется. Если запись забыть слишком рано, следующий же вопрос о том же
// pid дал бы «умер только что» — и отсрочка началась бы заново, а строка
// замерцала бы, появляясь и исчезая каждые несколько секунд.
// ---------------------------------------------------------------------------
inline constexpr ULONGLONG kProcessForgetMs = 60 * 1000;

inline constexpr ULONGLONG kProcessSweepMs  = 5000;

// Дескриптор принадлежит исходному экземпляру процесса. Общая ссылка позволяет
// pending-запросу удерживать его после очистки кеша и не допускать повторного
// использования PID.
struct ProcessHandleInfo {
    HANDLE h = nullptr;
    DWORD  pid = 0;
    bool   canWait = false;

    ProcessHandleInfo(HANDLE handle, DWORD processId, bool waitable)
        : h(handle), pid(processId), canWait(waitable) {}
    ~ProcessHandleInfo() { if (h) CloseHandle(h); }
    ProcessHandleInfo(const ProcessHandleInfo&) = delete;
    ProcessHandleInfo& operator=(const ProcessHandleInfo&) = delete;

    bool alive() const {
        if (!h) return false;
        if (canWait) return WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
        DWORD code = 0;
        return GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    }
};

using ProcessHandleRef = std::shared_ptr<const ProcessHandleInfo>;

// ---------------------------------------------------------------------------
// Неизменяемый путь процесса вместе с подготовленным ключом сопоставления.
//
// Один объект разделяют Ingest, ProcessCache и Monitor. Полный путь нужен для
// показа, а folded/foldedHash — для поиска App-правил без повторного towupper на
// каждом соединении. Дескриптор сохраняет связь с исходным экземпляром процесса.
// ---------------------------------------------------------------------------
struct ProcessPathInfo {
    std::wstring text;
    std::wstring folded;
    uint64_t     foldedHash = kFoldedTextHashBasis;
    ProcessHandleRef process;

    ProcessPathInfo() = default;
    explicit ProcessPathInfo(std::wstring value, ProcessHandleRef owner = {})
        : text(std::move(value)),
          folded(FoldCaseCopy(text)),
          foldedHash(HashFoldedText(folded)),
          process(std::move(owner)) {}
};

using ProcessPathRef = std::shared_ptr<const ProcessPathInfo>;

// ---------------------------------------------------------------------------
// Существует ли процесс с таким номером ПРЯМО СЕЙЧАС, без кеша и без
// сохранённого дескриптора: временный HANDLE открывается на время проверки.
// Оставлено как отдельная проверка на крайний случай: обычный
// путь — ProcessAlive, он в разы дешевле (см. ниже).
// ---------------------------------------------------------------------------
inline bool ProcessExistsNow(DWORD pid) {
    if (IsSystemPid(pid)) return true;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        // Отказ в доступе означает, что процесс ЕСТЬ: защищённые процессы не
        // открываются даже с SE_DEBUG. Всё остальное (ERROR_INVALID_PARAMETER)
        // — «номера не существует».
        return GetLastError() == ERROR_ACCESS_DENIED;
    }
    DWORD code = 0;
    const bool alive = GetExitCodeProcess(h, &code) ? (code == STILL_ACTIVE) : true;
    CloseHandle(h);
    return alive;
}

namespace detail {

// ---------------------------------------------------------------------------
// Запись о процессе.
//
// ---- почему хранится ДЕСКРИПТОР -------------------------------------------
//
// Прежде каждая проверка жизни стоила три обращения к системе: OpenProcess,
// GetExitCodeProcess, CloseHandle. Проверка выполняется на каждое соединение
// каждого такта и на каждое событие транспорта, то есть сотни раз в секунду.
//
// Открытый дескриптор решает три задачи:
//
//   * проверка жизни — один WaitForSingleObject с нулевым тайм-аутом
//     либо GetExitCodeProcess, если HANDLE не имеет права SYNCHRONIZE;
//
//   * путь исполняемого файла читается тем же дескриптором, без повторного
//     OpenProcess;
//
//   * пока дескриптор открыт, система НЕ ОТДАЁТ этот номер другому процессу.
//     Значит, сведения, привязанные к номеру (путь, имя, иконка), не могут
//     «съехать» на чужую программу.
// ---------------------------------------------------------------------------
struct ProcEntry {
    ProcessHandleRef process;
    bool      alive = true;
    ULONGLONG probed = 0;       // когда последний раз спрашивали систему
    ULONGLONG touched = 0;      // когда последний раз спрашивали НАС
    ULONGLONG deadSince = 0;    // первое обнаружение смерти; 0 — процесс жив
    // Путь. nullptr — ещё не спрашивали. Общий объект содержит исходную строку
    // и один раз подготовленные безрегистровое представление с хэшем.
    ProcessPathRef path;
};

// Снимок состояния для передачи наружу. Общий владелец дескриптора отдельно
// удерживается путём процесса и не зависит от уборки этой записи.
struct ProcState {
    bool      alive = true;
    ULONGLONG deadSince = 0;
};

struct AliveCache {
    std::mutex                           mtx;
    std::unordered_map<DWORD, ProcEntry, NumericIdHash> map;
    ULONGLONG                            swept = 0;
};

inline AliveCache& aliveCache() {
    static AliveCache c;
    return c;
}

inline void CloseEntry(ProcEntry& e) {
    // Уборка освобождает только ссылки кеша. Pending и UI могут продолжать
    // удерживать исходный дескриптор вместе с неизменяемым путём.
    e.path.reset();
    e.process.reset();
}

// Одно обращение к системе вместо трёх.
inline bool HandleAlive(const ProcEntry& e) {
    return e.process && e.process->alive();
}

// Вызывается под c.mtx.
inline void SweepAliveLocked(AliveCache& c, ULONGLONG now) {
    if (now - c.swept < kProcessSweepMs) [[likely]] return;
    c.swept = now;

    for (auto it = c.map.begin(); it != c.map.end();) {
        ProcEntry& e = it->second;
        if (now - e.touched > kProcessForgetMs) {
            CloseEntry(e);
            it = c.map.erase(it);
            continue;
        }
        // После отсрочки кеш больше не удерживает завершившийся процесс.
        // Дескриптор остаётся открытым только пока он нужен внешним владельцам.
        if (e.process && e.deadSince && now - e.deadSince > kProcessGraceMs * 2)
            CloseEntry(e);
        ++it;
    }
    TrimHashTable(c.map);
}

// Вызывается под c.mtx. Возвращает ссылку на запись — она действительна,
// пока замок держится.
inline ProcEntry& ProbeLocked(AliveCache& c, DWORD pid, ULONGLONG now) {
    SweepAliveLocked(c, now);

    ProcEntry& e = c.map[pid];
    e.touched = now;                       // запись нужна: срок забвения продлён
    if (e.probed && now - e.probed <= kProcessAliveTtlMs) [[likely]] return e;
    e.probed = now;

    // Основной путь: дескриптор уже есть — одно ожидание, и всё.
    if (e.process) [[likely]] {
        e.alive = HandleAlive(e);
        if (!e.alive && !e.deadSince) e.deadSince = now;
        return e;
    }

    // Дескриптора нет: либо первый запрос, либо процесс давно мёртв.
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, pid);
    bool canWait = h != nullptr;
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        // Путь защищённого процесса может быть недоступен, хотя дескриптор
        // ожидания позволяет безопасно проверить глобальное сервисное правило.
        h = OpenProcess(SYNCHRONIZE, FALSE, pid);
        canWait = h != nullptr;
    }

    if (h) {
        e.process = std::make_shared<const ProcessHandleInfo>(h, pid, canWait);
        e.path.reset();
        // Номер мог быть занят «зомби»: процесс завершился, но его номер ещё
        // держит чей-то дескриптор. Поэтому состояние спрашиваем всегда.
        e.alive = HandleAlive(e);
        e.deadSince = e.alive ? 0 : (e.deadSince ? e.deadSince : now);
        return e;
    }

    if (GetLastError() == ERROR_ACCESS_DENIED) {
        // Процесс ЕСТЬ, но дескриптор недоступен (защищённый процесс).
        e.alive = true;
        e.deadSince = 0;
    } else {
        e.alive = false;
        if (!e.deadSince) e.deadSince = now;
    }
    return e;
}

inline ProcState ProbeAlive(DWORD pid) {
    const ULONGLONG now = GetTickCount64();
    AliveCache& c = aliveCache();

    std::lock_guard<std::mutex> lk(c.mtx);
    const ProcEntry& e = ProbeLocked(c, pid, now);
    return ProcState{ e.alive, e.deadSince };
}

} // namespace detail

// Диагностика не ждёт кеш, используемый обработчиками сетевых событий.
inline bool TryGetSystemProcessCacheSize(size_t& out) {
    auto& cache = detail::aliveCache();
    std::unique_lock lock(cache.mtx, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    out = cache.map.size();
    return true;
}

// ---------------------------------------------------------------------------
// Существует ли процесс, с кешем на kProcessAliveTtlMs.
//
// Кешируется и отрицательный ответ, и положительный: номера процессов Windows
// переиспользует, поэтому «мёртвый» навсегда запоминать нельзя — TTL один
// на оба случая.
//
// Потокобезопасно. Собственный мьютекс — самый внутренний: обратных вызовов
// отсюда нет, поэтому порядок захвата замков не нарушается и тупика не
// образуется, даже если вызов идёт из-под мьютекса RuleStore или Ingest.
// ---------------------------------------------------------------------------
inline bool ProcessAlive(DWORD pid) {
    if (IsSystemPid(pid)) return true;
    return detail::ProbeAlive(pid).alive;
}

// Сколько времени прошло с обнаружения смерти процесса.
//
//   0            — процесс существует (или он системный);
//   > 0          — миллисекунды с ПЕРВОГО обнаружения смерти.
//
// Ноль зарезервирован под «жив», поэтому у только что умершего процесса
// возвращается минимум 1: вызывающий отличает «жив» от «умер сию секунду»
// одним сравнением с нулём.
inline ULONGLONG ProcessDeadFor(DWORD pid) {
    if (IsSystemPid(pid)) return 0;

    const detail::ProcState s = detail::ProbeAlive(pid);
    if (s.alive || !s.deadSince) return 0;

    const ULONGLONG age = GetTickCount64() - s.deadSince;
    return age ? age : 1;
}

// Процесс завершился, и отсрочка уже истекла: данные подлежат удалению.
inline bool ProcessGone(DWORD pid, ULONGLONG graceMs = kProcessGraceMs) {
    const ULONGLONG dead = ProcessDeadFor(pid);
    return dead != 0 && dead > graceMs;
}

// Процесс завершился, но отсрочка ещё идёт: его данные пока показываются.
inline bool ProcessExpiring(DWORD pid, ULONGLONG graceMs = kProcessGraceMs) {
    const ULONGLONG dead = ProcessDeadFor(pid);
    return dead != 0 && dead <= graceMs;
}

// ---------------------------------------------------------------------------
// Путь исполняемого файла процесса.
//
// Спрашивается у системы один раз для текущей записи кеша и сохраняется
// в неизменяемом ProcessPathInfo. После удаления записи или получения нового
// дескриптора путь может быть запрошен заново; удерживаемый HANDLE связывает
// сохранённые сведения с исходным экземпляром процесса.
//
// Возвращается общий объект исходного и подготовленного пути: копии и свёртка
// на каждом сетевом событии не создаются.
// Пустая строка — путь недоступен (pid 0, защищённый процесс).
// ---------------------------------------------------------------------------
inline ProcessPathRef ProcessImagePathRef(DWORD pid) {
    if (pid == 0) {
        // Пакетный уровень WFP владельца не сообщает.
        static const ProcessPathRef empty =
            std::make_shared<const ProcessPathInfo>();
        return empty;
    }
    if (pid == 4) {
        // Каталог System32 постоянен, поэтому и путь ядра считается один раз.
        static const ProcessPathRef kernel =
            std::make_shared<const ProcessPathInfo>(KernelImagePath());
        return kernel;
    }

    const ULONGLONG now = GetTickCount64();
    detail::AliveCache& c = detail::aliveCache();

    std::lock_guard<std::mutex> lk(c.mtx);
    detail::ProcEntry& e = detail::ProbeLocked(c, pid, now);
    if (e.path) [[likely]] return e.path;

    std::wstring text;
    if (e.process) {
        // wWinMain пытается включить SE_DEBUG, но доступность пути не гарантирована.
        wchar_t buf[MAX_PATH * 2]{};
        DWORD cch = static_cast<DWORD>(std::size(buf));
        if (QueryFullProcessImageNameW(e.process->h, 0, buf, &cch)) text.assign(buf, cch);
    }
    // Неудача тоже запоминается в текущем объекте пути: это может быть отказ
    // в доступе, завершение процесса или другая ошибка запроса.
    e.path = std::make_shared<const ProcessPathInfo>(std::move(text), e.process);
    return e.path;
}

inline std::wstring ProcessImagePath(DWORD pid) {
    const ProcessPathRef p = ProcessImagePathRef(pid);
    return p ? p->text : std::wstring();
}