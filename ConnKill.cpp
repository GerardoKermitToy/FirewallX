#include "ConnKill.h"
#include "StringRes.h"

namespace {

// Состояния, в которых TCB существует и может быть удалён.
//
// TIME_WAIT сюда не входит намеренно: обе стороны передачу закончили, TCB
// додерживается ядром лишь для отсева запоздавших сегментов и исчезнет сам.
// Удаление здесь ничего не даёт, а пункт меню обещал бы действие.
bool HasTcb(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_SYN_SENT:
    case MIB_TCP_STATE_SYN_RCVD:
    case MIB_TCP_STATE_ESTAB:
    case MIB_TCP_STATE_FIN_WAIT1:
    case MIB_TCP_STATE_FIN_WAIT2:
    case MIB_TCP_STATE_CLOSE_WAIT:
    case MIB_TCP_STATE_CLOSING:
    case MIB_TCP_STATE_LAST_ACK:
        return true;
    default:
        return false;
    }
}

// Уровень прав за время жизни процесса не меняется, поэтому маркер доступа
// спрашивается один раз: Check вызывается на каждое открытие меню.
bool Elevated() {
    static const bool yes = IsElevated();
    return yes;
}

} // namespace

namespace ConnKill {

// Порядок проверок — от общего к частному: пользователь должен получить
// САМУЮ существенную причину, а не первую подходящую. Протокол важнее
// состояния, семейство адресов важнее состояния, права проверяются последними:
// они относятся к нам, а не к соединению.
Denial Check(const Target& t) {
    if (!t.valid)                        return Denial::NoConnection;
    if (t.proto != Proto::Tcp)           return Denial::NoTcb;
    if (t.local.family == AF_INET6)      return Denial::Ipv6NoApi;
    if (t.state == MIB_TCP_STATE_LISTEN) return Denial::Listener;
    if (!HasTcb(t.state))                return Denial::Gone;
    if (!t.rport || t.remote.isAny())    return Denial::NoRemote;
    if (!Elevated())                     return Denial::NoRights;
    return Denial::None;
}

std::wstring DenialShort(Denial d) {
    UINT id = 0;
    switch (d) {
    case Denial::NoConnection: id = IDS_KILL_NO_CONNECTION; break;
    case Denial::NoTcb:        id = IDS_KILL_NO_TCB;        break;
    case Denial::Ipv6NoApi:    id = IDS_KILL_IPV6_NO_API;   break;
    case Denial::Listener:     id = IDS_KILL_LISTENER;      break;
    case Denial::Gone:         id = IDS_KILL_GONE;          break;
    case Denial::NoRemote:     id = IDS_KILL_NO_REMOTE;     break;
    case Denial::NoRights:     id = IDS_KILL_NO_RIGHTS;     break;
    default: break;
    }
    return id ? LoadStringRes(id) : std::wstring();
}

std::wstring DenialText(Denial d) {
    UINT id = 0;
    switch (d) {
    case Denial::NoConnection: id = IDS_KILL_EXPLAIN_NO_CONN;   break;
    case Denial::NoTcb:        id = IDS_KILL_EXPLAIN_NO_TCB;    break;
    case Denial::Ipv6NoApi:    id = IDS_KILL_EXPLAIN_IPV6;      break;
    case Denial::Listener:     id = IDS_KILL_EXPLAIN_LISTENER;  break;
    case Denial::Gone:         id = IDS_KILL_EXPLAIN_GONE;      break;
    case Denial::NoRemote:     id = IDS_KILL_EXPLAIN_NO_REMOTE; break;
    case Denial::NoRights:     id = IDS_KILL_EXPLAIN_NO_RIGHTS; break;
    default: break;
    }
    return id ? LoadStringRes(id) : std::wstring();
}

bool Kill(const Target& t, std::wstring& error) {
    error.clear();

    // Повторно проверяем переданный снимок цели, не перечитывая состояние ОС.
    // Если соединение уже изменилось или исчезло, это обнаружит SetTcpEntry ниже.
    const Denial d = Check(t);
    if (d != Denial::None) { error = DenialText(d); return false; }

    MIB_TCPROW row{};
    row.dwState = MIB_TCP_STATE_DELETE_TCB;      // единственное допустимое значение
    std::memcpy(&row.dwLocalAddr,  t.local.b,  4);
    std::memcpy(&row.dwRemoteAddr, t.remote.b, 4);
    // Порты в MIB_TCPROW — в СЕТЕВОМ порядке, старшая половина DWORD нулевая.
    // В FlowKey они хранятся в порядке узла, поэтому htons обязателен: без него
    // ядро искало бы соединение с переставленными байтами порта и не находило
    // его — с сообщением «неверный параметр».
    row.dwLocalPort  = htons(t.lport);
    row.dwRemotePort = htons(t.rport);

    const DWORD rc = SetTcpEntry(&row);
    if (rc == NO_ERROR) return true;

    switch (rc) {
    // SetTcpEntry документирует код 317 как вызов без повышения прав.
    case ERROR_MR_MID_NOT_FOUND:
    case ERROR_ACCESS_DENIED:
        error = LoadStringRes(IDS_KILL_ERROR_ACCESS);
        break;
    case ERROR_INVALID_PARAMETER:
    case ERROR_NOT_FOUND:
        // Обычный исход гонки: соединение закрылось само между построением
        // меню и выполнением команды.
        error = LoadStringRes(IDS_KILL_ERROR_NOT_FOUND);
        break;
    default:
        error = FormatWinError(rc);
        break;
    }
    return false;
}

} // namespace ConnKill