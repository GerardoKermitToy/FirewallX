#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// Совместимый фасад единого индекса владельцев FlowStore.
//
// Отдельной таблицы PID и отдельного опроса IP Helper здесь больше нет. Четыре
// индекса TCP/IPv4, TCP/IPv6, UDP/IPv4 и UDP/IPv6 принадлежат FlowStore вместе с
// соединениями и счётчиками. Это гарантирует, что исправление PID перемещает все
// связанные данные одной операцией.
// ---------------------------------------------------------------------------
namespace OwnerLookup {

DWORD ResolveEventOwner(DWORD reportedPid, const FlowKey& key, Dir dir,
                        bool* ambiguous = nullptr);
void NoteReportedOwner(const FlowKey& key, DWORD reportedPid);
DWORD ByLocalEndpoint(Proto proto, const IpAddr& local, uint16_t lport,
                      bool* ambiguous = nullptr);
void NoteConnectionEnd(const FlowKey& key, DWORD reportedPid);
void ResetSession();
void Invalidate();

} // namespace OwnerLookup
