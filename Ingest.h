#pragma once
#include "AskQueue.h"
#include "DebugCounters.h"
#include "FirewallPolicy.h"
#include "quic_sni.hpp"
#include "Rules.h"
#include "BlockQueue.h"
#include "TlsReassembly.h"
#include "VerdictSession.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>
#include "PortmasterKextClient.hpp"
#include "FirewallXNdisFilter.hpp"

struct ProcessPathInfo;

// Ответ системе по одному обязательству, созданному on_connection_*.
// Move-only объект не позволяет ответить дважды, а поколение внутри него не
// позволяет отправить старое обязательство новому экземпляру драйвера.
// external_connection_id хранится внутри обязательства только для
// отправки команды из process_verdict, не участвуя в сопоставлении.
bool process_verdict(DriverVerdictRequest request, pmkext::Verdict verdict);

// Точки входа; вызываются из отдельного потока.
// event_ и payload живут только на время вызова. В Desktop TCP payload
// незавершённого исходящего ClientHello сохраняется после разрешающего правила
// по TCP tuple до следующих вызовов, чтобы собрать TLS record и извлечь SNI через
// GetTlsClientHelloDomain. В Desktop полные UDP-пакеты QUIC сохраняются на
// время ожидания правила, а состояние сборки ClientHello — отдельно по UDP
// tuple. Части связываются по tuple; значение external_connection_id на это не
// влияет.
void on_connection_v4(const pmkext::ConnectionFixedV4* event_, const uint8_t* payload, size_t payload_len);
void on_connection_v6(const pmkext::ConnectionFixedV6* event_, const uint8_t* payload, size_t payload_len);

// ---------------------------------------------------------------------------
// Управление клиентом драйвера.
//
// Обе функции идемпотентны. Объект клиента удаляется РОВНО один раз и только
// ПОСЛЕ join() рабочего потока, поэтому process_verdict никогда не обращается
// к освобождённой памяти.
// ---------------------------------------------------------------------------
// Окно получает сообщение только при ошибке этой попытки запуска.
void portmaster_start(HWND failureWindow = nullptr, UINT failureMessage = 0);
void portmaster_stop();
// Перед завершением desktop: при установленной FirewallXSvc сохранить
// регистрацию драйвера и перевести её в SERVICE_BOOT_START.
void portmaster_prepare_desktop_exit(bool serviceInstalled);
bool portmaster_running();
pmkext::KextClient* portmaster_get_driver();
// Истина только пока оконный процесс имеет активное соединение с pipe службы.
bool portmaster_service_connected();
// Попросить службу самостоятельно обрабатывать записи драйвера и дождаться
// завершения обработки всех ранее полученных оконным процессом записей.
bool portmaster_service_process_locally();
// Перед закрытием pipe дождаться, пока служба прочитает отправленные ответы.
bool portmaster_service_flush_verdicts();
// Ожидание относится только к первоначальному выбору маршрута. Служба не
// сообщает SERVICE_RUNNING, пока и драйвер, и сервер pipe не готовы.
bool portmaster_wait_ready(DWORD timeoutMs);
DWORD portmaster_last_error();
// Сброс драйверного кеша через текущий direct/raw-pipe маршрут. Если маршрута
// ещё нет, сбрасывать нечего: новый сеанс сделает это при подключении.
DWORD portmaster_clear_cache();
// Monitor запрашивает bandwidth в том же цикле, в котором читает таблицы ОС.
// Через службу проходит штатная однобайтная команда драйвера, без обёртки.
bool portmaster_request_bandwidth_stats();
// setAppInterface либо та же штатная команда через raw pipe службы.
bool portmaster_set_app_interface(const std::wstring& path, uint64_t luid);
bool portmaster_enable_route_policies();

// Режим обработки события, для которого не нашлось правила.
//   Desktop — решение задаёт выбранная политика; Learning ждёт пользователя;
//   Service — те же политики, но Learning без правила задаёт Drop,
//             кроме технических ICMP-исключений.
enum class IngestMode : uint8_t { Desktop = 0, Service = 1 };

// ---------------------------------------------------------------------------
// Приём событий и вердикты.
//
// Общее для обоих режимов:
//   * каждый принятый on_connection_* создаёт одно обязательство: не более
//     одной попытки process_verdict; завершение driver-сессии снимает остаток;
//   * external_connection_id — непрозрачное поле обязательства. Оно может быть
//     любым и не обозначает соединение: не участвует в кешах, группировке,
//     сопоставлении правил, TLS-сборке или состоянии мониторинга;
//   * вердикт для ЛЮБОГО номера протокола задаётся правилом либо политикой.
//
// ---- два уровня на пути к вердикту ----------------------------------------
//
// Порядок выбран по цене: каждый следующий уровень дороже предыдущего
// примерно на порядок.
//
//   1. verdicts_  — та же ФОРМА соединения (путь, протокол, направление,
//                   адреса, порты, тип/код ICMP) уже сопоставлялась с правилами.
//                   Кеш хранит действие правила, а конкретный driver-verdict
//                   выбирается по payload_layer, флагам, наличию полезной
//                   нагрузки TCP и состоянию сборки TLS/QUIC ClientHello.
//   2. RuleStore::MatchVerdict — собственно сопоставление.
//
// Непринятые обязательства группируются только по полям Flow и хранят
// DriverVerdictRequest до явного решения; его external_connection_id не
// используется как ключ или условие.
//
// Кеш формы соединения корректен потому, что сбрасывается ЦЕЛИКОМ при любом
// изменении набора правил (RuleStore::version). TTL ограничивает время хранения
// записей, но не участвует в защите от устаревшего решения.
//
// Кеш ВЫКЛЮЧАЕТСЯ полностью, пока среди включённых правил есть условие,
// значение которого меняется без изменения правила: макро-адрес (конфигурация
// сети) либо сервис (состояние диспетчера служб). Признак спрашивается у
// хранилища один раз на смену версии, а не на событие.
//
// Счётчика попаданий в кеш здесь нет: он инкрементировался на каждое событие
// транспорта, но не показывался ни в строке состояния, ни в окне «О программе»,
// ни в подсказке значка — то есть занимал место и такты, ничего не сообщая.
// Проверяемый снаружи контракт задаётся другими тремя счётчиками:
// calls() == answered() + waiting().
//
// ---- цена одного события --------------------------------------------------
//
// Для подготовки условий сопоставления не требуется копировать строки:
//   * путь исполняемого файла берётся из общего кеша SystemInfo
//     (ProcessImagePathRef) вместе с подготовленным безрегистровым ключом — один
//     объект на процесс, разделяемый всеми его группами и с ProcessCache;
//   * условия сопоставления (MatchQuery) ссылаются на этот экземпляр
//     представлением, а не копией;
//   * отображаемое имя процесса выводится ТОЛЬКО при выдаче запроса в
//     интерфейс (RequestOf), а не на каждое событие.
// Диагностический флаг добавляет ссылку на имя совпавшего правила. Разбор
// SNI, HTTP и DNS и подготовка UI-запроса могут создавать отдельные строки.
//
// ---- оконный режим: обязательства неприкосновенны -------------------------
//
// В Learning технические ICMP-исключения без правила разрешаются автоматически.
// Остальные обязательства паркуются и ждут, пока пользователь создаст правило
// либо сменит политику. Программа НЕ удаляет припаркованное
// обязательство по времени, количеству или завершению процесса. Остальные
// политики задают немедленное решение и закрывают также прежние pending-группы.
// Завершение владельца не определяет сетевой вердикт: запрос сохраняет исходные
// путь и условия и остаётся доступен для явного решения пользователя.
//
// ---- служебный режим ------------------------------------------------------
//
// Правила и политика прочитаны из базы при запуске и при отключении desktop-клиента;
// CondService вычисляется локально по PID и снимку SCM служебного процесса —
// через raw pipe сведения о службах не передаются. Политики работают как в desktop,
// но Learning без правила разрешает только технические ICMP-исключения;
// остальным немедленно задаётся pmkext::Verdict::Drop без запроса пользователя.
// ---------------------------------------------------------------------------
class Ingest {
public:
    static Ingest& Instance();
    // У источников независимы сессии, pending и кеши. Instance обслуживает UI
    // обоих источников; адресный ответ выбирает экземпляр по AskRequestId::source.
    static Ingest& ForSource(TrafficSource source);

    // Перечитать правила и политику в том же объекте службы: указатель не меняется,
    // поэтому обработчики соединений не пересекаются с удалением хранилища.
    // Снимок SCM сбрасывается и при наличии CondService готовится заново до
    // подтверждения перехода к локальной обработке.
    bool ReloadServiceRules(const std::wstring& path);
    // Перечитать только политику до начала новой сессии источника службы.
    bool ReloadServicePolicy();
    void Attach(RuleStore* rules, HWND ui, IngestMode mode = IngestMode::Desktop,
                FirewallPolicy policy = FirewallPolicy::Learning);
    FirewallPolicy policy() const { return policy_.load(std::memory_order_relaxed); }
    // Дожидается отправки старых ответов, меняет политику и сбрасывает только
    // пользовательский кеш решений. Драйверный кеш не очищается.
    // UI после этого вызывает FlushVerdicts и синхронизирует очередь показа.
    DWORD SetPolicy(FirewallPolicy policy);
    void ProcessEventsChanged();
    void Detach();                          // НЕ отвечает по припаркованным
    // Транспорт создаёт поколение до приёма записей и закрывает его при остановке
    // либо ошибке маршрута, в том числе до завершения reader-а. Все pending и кеши
    // принадлежат ровно одному поколению и не переходят через смену маршрута.
    void BeginDriverSession(uint64_t session);
    void EndDriverSession(uint64_t session);
    void SetAppInterfacesActive(bool active);
    // ConnectionEnd не содержит external_connection_id, но содержит устойчивый
    // tuple. По нему удаляются незавершённые состояния SNI этого соединения.
    void ForgetTlsAssembly(const FlowKey& key);
    void ForgetQuicSniState(const FlowKey& key);
    // Desktop вызывает раз в секунду: срок сборки соблюдается даже когда после
    // неполного ClientHello больше не приходит ни одного сетевого callback.
    void ExpireSniAssemblies();

    UINT Message() const { return msg_.load(std::memory_order_relaxed); }
    UINT SourceMessage() const { return sourceMsg_.load(std::memory_order_relaxed); }
    IngestMode mode() const { return mode_.load(std::memory_order_relaxed); }

    // При смене маршрута UI сразу запрашивает у Monitor новый снимок TCP/UDP,
    // не ожидая следующего секундного таймера. Для proxy уведомление отправляется
    // только после подтверждения фактического переключения службой.
    void SourceChanged(bool notifyUi = true);
    void NotifySourceChanged();

    // Вызывается из рабочего потока; ссылка на оригинал, копий нет
    void HandleV4(const pmkext::ConnectionFixedV4& e, const uint8_t* payload, size_t len);
    void HandleV6(const pmkext::ConnectionFixedV6& e, const uint8_t* payload, size_t len);
    void HandleNdis(const firewallxndisfilter::Client::ConnectionV4& e, const uint8_t* payload, size_t len);
    void HandleNdis(const firewallxndisfilter::Client::ConnectionV6& e, const uint8_t* payload, size_t len);

    // Только подсказка редактора из окна запроса: false отключает и показ,
    // и сохранение дополнительной копии исходного payload в pending-группе.
    static constexpr bool kShowPayloadInRuleEditor = true;

    // --- UI-поток (в служебном режиме не используется) ---
    void   TakePending(std::vector<AskRequest>& out);
    void   Republish();
    size_t FlushVerdicts();
    // PermanentAccept/PermanentDrop ровно одному callback показанного запроса.
    // Правило и кеш формы не создаются; остальные обязательства получают новый UI-запрос.
    bool AnswerOnce(AskRequestId id, RuleAction action);

    // Хранилище припаркованных обязательств — единственный владелец запросов,
    // поэтому очередь показа обращается к нему по AskRequestId, а не держит копию.
    bool GetPending(AskRequestId id, AskRequest& out) const;
    // Копия берётся только при открытии редактора, а не при каждом показе Ask.
    std::vector<uint8_t> GetPendingPayload(AskRequestId id) const;
    bool IsPending(AskRequestId id) const;

    // Диагностика: calls() == answered() + waiting().
    // Все три значения показываются в строке состояния, поэтому и ведутся.
    uint64_t calls() const;
    uint64_t answered() const;
    uint64_t waiting() const;        // ожидающих решения обязательств
    void ReadDebugCounters(DebugCounters::Snapshot& out) const;

    // Незавершённый ClientHello должен получить продолжение вскоре после
    // первого сегмента. Если этого не произошло, состояние больше не помогает.
    static constexpr ULONGLONG kTlsAssemblyTtlMs = 30 * 1000;
    static constexpr ULONGLONG kQuicSniTtlMs = 30 * 1000;
    // Кеш формы соединения: срок нужен только чтобы карта не росла от
    // одноразовых соединений. Смысловое устаревание исключено сбросом
    // по версии набора правил.
    static constexpr ULONGLONG kVerdictTtlMs = 2 * 60 * 1000;

    // Количество решений по форме намеренно не ограничивается: verdicts_
    // очищается по TTL, при смене набора правил и при завершении driver-сессии.
    // Идентификатор из записи драйвера в этот кеш не входит.

private:
#ifdef FIREWALLX_TEST_VERDICTS
    friend struct IngestTestAccess;
#endif
    explicit Ingest(TrafficSource source = TrafficSource::Host) : source_(source) {}
    const TrafficSource source_;
    bool SendVerdict(DriverVerdictRequest request, pmkext::Verdict verdict);
    void TakePendingLocal(std::vector<AskRequest>& out);
    template <class Fixed>
    void HandleNdisFixed(const Fixed& e, const uint8_t* payload, size_t len);

    // -----------------------------------------------------------------------
    // Описание соединения: ровно то, что нужно и для сопоставления с
    // правилами, и для показа в окне запроса.
    //
    // Один тип на оба применения намеренно: прежде разобранное событие и
    // припаркованная группа хранили одни и те же поля по отдельности, и
    // существовало два почти одинаковых сборщика MatchQuery.
    // -----------------------------------------------------------------------
    struct Flow {
        FlowKey key;
        uint32_t interfaceIndex = 0;
        std::shared_ptr<const std::wstring> interfaceName; // только для pending
        // Общий путь процесса вместе с один раз подготовленным ключом matcher-а.
        // Пустая строка означает «путь недоступен».
        std::shared_ptr<const ProcessPathInfo> app;
        pmkext::ProcessLineageRef lineage;
        // PID из события драйвера. Может быть 0 для пакетного события WFP;
        // нужен журналу и сохранению явно указанного владельца в служебном режиме.
        uint64_t driverPid = 0;
        // PID, разрешённый OwnerLookup и используемый в MatchQuery.
        DWORD pid = 0;
        Dir   dir = Dir::Unknown;
        int   icmpType = -1;
        int   icmpCode = -1;
        std::optional<uint32_t> conditionFlags;
        bool  ownerAmbiguous = false;

        std::wstring_view appPath() const;
        std::wstring_view foldedAppPath() const;
        uint64_t appPathHash() const;
        MatchQuery ToQuery() const;
    };
	
    // Один callback внутри pending-группы. payload_layer, TCP-флаги и наличие
    // полезной нагрузки TCP относятся именно к обязательству, а не к условиям
    // правила: события разных слоёв с одинаковыми условиями объединяются в один запрос, но
    // после разрешающего правила могут получить разные вердикты.
    struct PendingRequest {
        DriverVerdictRequest request;
        uint8_t              payloadLayer = 0;
        uint16_t             tcpFlags = 0;
        bool                 hasTcpPayload = false;
        uint32_t             tlsSequence = 0;
        // Ненулевой токен означает, что исходный поток был приостановлен
        // до вынесения verdict. Он освобождается сразу после отправки ответа
        // драйверу либо при завершении driver-сессии.
        uint64_t             threadSuspendToken = 0;
        // Поколение отображаемой строки относится к callback, а не к группе:
        // повторное использование tuple может попасть в тот же вопрос UI.
        uint64_t             flowGeneration = 0;
        // Копируется только TCP application payload кандидата ClientHello, пока
        // правила ещё нет. После разрешения он либо разбирается сразу, либо
        // становится первой частью сборки этого TCP-соединения.
        std::vector<uint8_t> tlsPayload;
        // HTTP Host тоже требует полного IP/TCP-пакета после выбора правила.
        std::vector<uint8_t> httpPayload;
        // Для кандидата QUIC сохраняется полный пакет, потому что правило может
        // быть создано уже после возврата из on_connection_*.
        std::vector<uint8_t> quicPayload;
        // DNS-пакет не нужен после разбора. Подпись сохраняется до решения,
        // но не восстанавливает уже завершённую или удалённую строку FlowStore.
        std::shared_ptr<const std::wstring> dnsDomainLabel;
    };

    // -----------------------------------------------------------------------
    // Компактная запись припаркованной группы.
    //
    // Число таких записей НЕ ограничено (обязательство ждёт решения столько,
    // сколько нужно), поэтому здесь нет ни одного поля «на всякий случай».
    // Момента постановки в очередь в записи нет: он никуда не показывался —
    // ни в окно запроса, ни в строку состояния, — а хранился бы по 8 байт
    // на каждое ожидающее соединение.
    // -----------------------------------------------------------------------
    struct PendingGroup {
        Flow flow;
        // Первый непустой payload группы нужен только как подсказка редактора.
        // Он не участвует в сопоставлении и не попадает в Rule/RuleDb.
        std::vector<uint8_t> ruleEditorPayload;
        // Каждая запись — отдельный вызов on_connection_*. Объект move-only:
        // один callback физически нельзя превратить в два verdict-сообщения.
        std::vector<PendingRequest> requests;
        // Хэш полей дедупликации. Сам идентификатор группы отдельный: два
        // разных набора полей вправе дать одинаковые 64 бита, поэтому перед
        // объединением всегда выполняется структурное сравнение.
        uint64_t keyHash = 0;
        uint64_t driverSession = 0;
        // Пока SCM не подтвердил свежий снимок, промах сервисного правила
        // ещё не означает, что требуется решение пользователя.
        uint64_t serviceRefresh = 0;
        bool accepted = false;          // выдана в очередь показа
    };

    // Решение по форме соединения. В карту попадают только совпадения:
    // отрицательный результат повторно проверяется, поскольку значения макросов
    // и сервисов могут меняться независимо от версии правила. Кеш хранит действие
    // правила; конкретный driver-verdict зависит ещё и от payload_layer,
    // флагов и наличия полезной нагрузки TCP текущего события.
    struct Shape {
        RuleAction  action = RuleAction::Allow;
        bool        preferredInterfaceBlocked = false;
        ULONGLONG   tick = 0;
        RuleNameRef ruleName;
    };

    struct ExpiryRecord {
        uint64_t  key = 0;
        ULONGLONG tick = 0;
    };

    struct TlsAssembly {
        TlsAssembly(uint32_t sequence, const uint8_t* data, size_t size,
                    TlsClientHelloInspector inspector, ULONGLONG tick_)
            : buffer(sequence, data, size, std::move(inspector)), tick(tick_) {}

        TlsClientHelloBuffer buffer;
        ULONGLONG tick = 0;
    };

    struct TlsAssemblyExpiry {
        FlowKey key;
        ULONGLONG tick = 0;
    };

    struct QuicSniStateOwner {
        QuicSniStateOwner() = default;
        QuicSniStateOwner(const QuicSniStateOwner&) = delete;
        QuicSniStateOwner& operator=(const QuicSniStateOwner&) = delete;
        ~QuicSniStateOwner() {
            quic_sni::FreeQuicSniState(&state);
        }

        quic_sni::QuicSniState* state = nullptr;
        ULONGLONG tick = 0;
    };

    struct Answer {
        std::vector<PendingRequest> requests;
        RuleAction                  action = RuleAction::Allow;
        // Нужен после освобождения mtx_: мониторинг и диагностический лог
        // публикуются уже после фактической отправки verdict драйверу.
        Flow flow;
        RuleNameRef ruleName;
        bool once = false;              // явный permanent-verdict без обработки SNI
        bool preferredInterfaceBlocked = false;
    };

    // Событие, разобранное до конца. Обязательство перемещается вместе с ним и
    // может закончить жизнь только в немедленном ответе либо pending-группе.
    // Указатели payload действительны до возврата из HandleFixed; при парковке
    // кандидаты TLS, HTTP и QUIC копируются в соответствующий PendingRequest.
    struct Incoming {
        Incoming(DriverVerdictRequest request_, uint8_t payloadLayer_,
                 uint16_t tcpFlags_, bool hasTcpPayload_,
                 uint32_t tcpSequence_, const uint8_t* tcpPayload_,
                 size_t tcpPayloadLen_, const uint8_t* packetPayload_,
                 size_t packetPayloadLen_)
            : request(std::move(request_)), payloadLayer(payloadLayer_),
              tcpFlags(tcpFlags_), hasTcpPayload(hasTcpPayload_),
              tcpSequence(tcpSequence_), tcpPayload(tcpPayload_),
              tcpPayloadLen(tcpPayloadLen_), packetPayload(packetPayload_),
              packetPayloadLen(packetPayloadLen_) {}

        Flow flow;
        DriverVerdictRequest request;
        uint64_t threadId = 0;           // TID из события драйвера API v3
        uint8_t payloadLayer = 0;
        uint16_t tcpFlags = 0;
        bool hasTcpPayload = false;
        uint32_t tcpSequence = 0;
        const uint8_t* tcpPayload = nullptr;
        size_t tcpPayloadLen = 0;
        // Исходный payload нужен HTTP, DNS и QUIC целиком, вместе с
        // заголовками IP и транспортного протокола.
        const uint8_t* packetPayload = nullptr;
        size_t packetPayloadLen = 0;
    };

    struct TlsVerdictPlan {
        pmkext::Verdict verdict = pmkext::Verdict::PermanentAccept;
        // Для полного ClientHello из одного callback копирование не требуется:
        // исходный указатель ещё действителен после отправки verdict.
        bool parseCurrentPayload = false;
        // При завершении сборки данные перемещаются сюда до освобождения записи
        // карты и разбираются только после успешного process_verdict.
        std::vector<uint8_t> assembledPayload;
    };

    struct QuicVerdictPlan {
        pmkext::Verdict verdict = pmkext::Verdict::PermanentAccept;
        std::shared_ptr<const std::wstring> domainLabel;
    };

    // Единственное тело обработчика: IPv4 и IPv6 различаются только размером
    // массива адреса, а его выбирает перегрузка IpFromRaw (Common.h).
    template <class Fixed>
    void HandleFixed(const Fixed& e, const uint8_t* payload, size_t len);

    void MakeIncoming(uint64_t driverPid, DWORD pid, Dir dir,
                      const FlowKey& key, const IcmpInfo& icmp,
                      bool ownerAmbiguous, Incoming& out);

    TlsVerdictPlan PrepareAllowedTls(
        uint64_t driverSession, const FlowKey& key,
        uint32_t tcpSequence, const uint8_t* tcpPayload,
        size_t tcpPayloadLen);
    QuicVerdictPlan PrepareAllowedQuic(
        uint64_t driverSession, const FlowKey& key,
        const uint8_t* packetPayload, size_t packetPayloadLen);
    static std::shared_ptr<const std::wstring> ParseTlsDomainLabel(
        const TlsVerdictPlan& plan,
        const uint8_t* currentPayload, size_t currentPayloadLen);

    uint64_t NoteFlow(
        const Incoming& in, uint64_t packetBytes,
        const std::shared_ptr<const std::wstring>& tlsDomainLabel = {},
        bool blocked = false);
    static void PublishFlowVerdict(
        const Flow& flow, pmkext::Verdict verdict,
        const std::shared_ptr<const std::wstring>& tlsDomainLabel,
        uint64_t generation, bool preferredInterfaceBlocked = false);
    void Ingress(Incoming in, uint64_t packetBytes);

    // Сброс кеша формы, если набор правил изменился. Возвращает признак
    // «кешировать можно».
    bool SyncRulesLocked();

    // Закрыть ВСЕ обязательства группы действием правила либо политики. Базовый
    // verdict каждого callback учитывает payload_layer, флаги и TCP payload;
    // Fire дополнительно оставляет Accept до завершения сборки TLS/QUIC ClientHello.
    // Ответы собираются в out и отправляются вызывающим ВНЕ мьютекса.
    void   SettleLocked(std::vector<Answer>& out, PendingGroup& g,
                        RuleAction action,
                        const RuleNameRef* ruleName = nullptr,
                        bool preferredInterfaceBlocked = false);
    // Редкая очистка записей кешей с истёкшим TTL. Pending-обязательства она
    // не затрагивает: они живут до правила либо завершения driver-сессии.
    void Maintain();
    struct PreparedShapeKey {
        uint64_t value = 0;
        uint64_t rulesVersion = 0;
    };

    void CacheMatchedShape(const Flow& flow, RuleAction action,
                           RuleStore* matchedRules, uint64_t matchedVersion,
                           uint64_t driverSession,
                           const PreparedShapeKey* preparedKey = nullptr,
                           const RuleNameRef* ruleName = nullptr,
                           bool preferredInterfaceBlocked = false);

    void ExpireVerdicts(ULONGLONG now);
    void ExpireTlsAssembliesLocked(ULONGLONG now);
    void ExpireQuicSniStatesLocked(ULONGLONG now);
    void Notify();
    size_t Fire(std::vector<Answer>& out);

    static AskRequest RequestOf(uint64_t groupId, const PendingGroup& g);
    static uint64_t   ShapeKeyOf(const Flow& f, bool inheritance = false);

    // Pending-группы имеют отдельный непрозрачный идентификатор. Индекс по
    // хэшу только находит кандидатов; перед объединением сравниваются все поля
    // MatchQuery, поэтому коллизия хэша не смешивает чужие обязательства.
    using PendingMap = std::unordered_map<uint64_t, PendingGroup>;
    static bool SamePendingFlow(const Flow& a, const Flow& b);
    PendingMap::iterator FindPendingLocked(const Incoming& in, uint64_t askKey);
    PendingMap::iterator AddPendingLocked(const Incoming& in, uint64_t askKey);
    PendingMap::iterator AddPendingLocked(PendingGroup group);
    PendingMap::iterator ErasePendingLocked(PendingMap::iterator it);
    void ClearDriverSessionLocked();

    // Shared-захват держится от разбора события/FlushVerdicts до отправки всех
    // ответов. Exclusive-смена политики ждёт завершения прежних решений,
    // поэтому один callback не может смешать две политики.
    std::shared_mutex        policyMtx_;
    mutable std::mutex      mtx_;
    RuleStore*              rules_ = nullptr;
    // Читается после освобождения мьютекса (Notify), поэтому атомарный:
    // прежде ради одного чтения брался замок.
    std::atomic<HWND>       ui_{ nullptr };
    std::atomic<UINT>       msg_{ 0 };
    std::atomic<UINT>       sourceMsg_{ 0 };
    std::atomic<IngestMode> mode_{ IngestMode::Desktop };
    std::atomic<FirewallPolicy> policy_{ FirewallPolicy::Learning };

    PendingMap                                      pending_;
    std::unordered_multimap<uint64_t, uint64_t>     pendingIndex_;
    uint64_t                                        pendingSeq_ = 0;
    // Существует только между частями незавершённого исходящего ClientHello.
    // external_connection_id хранится в обязательстве только для
    // process_verdict; TCP tuple связывает части соединения.
    std::unordered_map<FlowKey, TlsAssembly, FlowKeyHash> tlsAssemblies_;
    // Только в Desktop состояние дешифрования и сборки CRYPTO хранится отдельно
    // для каждого исходящего UDP tuple до терминального результата, ConnectionEnd
    // либо истечения срока неактивности. Отдельной истории касаний нет.
    std::unordered_map<FlowKey, QuicSniStateOwner, FlowKeyHash> quicSniStates_;
    ULONGLONG quicSniSweptAt_ = 0;
    std::unordered_map<uint64_t, Shape>             verdicts_;
    // Очередь содержит историю касаний. Устаревшая запись удаляет элемент карты
    // только если её tick всё ещё последний; полных обходов карты нет.
    BlockQueue<ExpiryRecord>                         verdictExpiry_;
    BlockQueue<TlsAssemblyExpiry>                    tlsAssemblyExpiry_;

    uint64_t   driverSession_ = 0;
    uint64_t   newestDriverSession_ = 0;
    uint64_t   rulesVersion_ = 0;
    bool       shapeCacheOn_ = false;
    bool       inheritanceOn_ = false;
    RuleStore* shapeCacheRules_ = nullptr;

    // Ведутся только показываемые счётчики; контракт проверяется как
    // calls_ == answered_ + waiting_.
    uint64_t calls_ = 0;
    uint64_t answered_ = 0;
    uint64_t waiting_ = 0;
    uint32_t sweep_ = 0;
};