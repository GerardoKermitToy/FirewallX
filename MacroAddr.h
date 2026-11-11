#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// Макро-адреса: именованные наборы адресов, содержимое которых определяется
// текущей конфигурацией сети, а не задаётся вручную.
//
// В правиле хранится только идентификатор макроса. Разрешение выполняется
// при сопоставлении, поэтому правило продолжает работать после смены сети,
// шлюза или DNS — переписывать его не нужно.
// ---------------------------------------------------------------------------
enum class AddrMacro : uint8_t {
    None = 0,
    DnsServers,
    LocalNetwork,
    WinsServers,
    Gateways,
    MyComputer,
    AllMyAddresses,
    BroadcastAddresses,
    MulticastAddresses,
};

// Элемент разрешённого набора: одиночный адрес (prefix < 0) либо подсеть
struct MacroEntry {
    IpAddr addr;
    int    prefix = -1;
};

namespace AddrMacros {

struct Def {
    AddrMacro      id;
    const wchar_t* name;      // DNS_SERVERS — то же имя идёт в базу как @DNS_SERVERS
    UINT           descId;    // пояснение для окна выбора адреса — из ресурсов
};

const Def*     All(size_t& count);
const Def*     Find(AddrMacro m);              // nullptr для None
const wchar_t* Name(AddrMacro m);              // «DNS_SERVERS», «» для None
// По значению: пояснение читается из STRINGTABLE при каждом вызове
std::wstring Description(AddrMacro m);
AddrMacro      Parse(const std::wstring& token);   // «@DNS_SERVERS» либо «DNS_SERVERS»

// Разрешение с кэшем: сетевую конфигурацию опрашивать на каждый пакет нельзя.
std::vector<MacroEntry> Resolve(AddrMacro m);
bool                    Matches(AddrMacro m, const IpAddr& a);

// Человекочитаемый список текущих значений для подсказки в диалоге.
// maxItems ограничивает длину: у ALL_MY_ADDRESSES их бывает десятки.
std::wstring ValuesText(AddrMacro m, size_t maxItems = 12);

// Версия меняется только при изменении полного набора значений. Обычное чтение
// использует снимок NetworkInterfaceWatcher; refresh = true перечитывает его
// синхронно (подготовка правил до запуска транспорта).
uint64_t Version(bool refresh = false);
void Invalidate();            // запросить объединяемое фоновое обновление
void Shutdown();              // остановить watcher после остановки транспорта

// Резервный опрос только при ошибке наблюдения или перечисления интерфейсов.
inline constexpr ULONGLONG kCacheTtlMs = 30 * 1000;

} // namespace AddrMacros