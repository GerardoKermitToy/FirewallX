#include "OwnerLookup.h"
#include "FlowStore.h"

namespace OwnerLookup {

DWORD ResolveEventOwner(DWORD reportedPid, const FlowKey& key, Dir dir,
                        bool* ambiguous) {
    return FlowStore::Instance().ResolveEventOwner(
        reportedPid, key, nullptr, ambiguous, dir);
}

void NoteReportedOwner(const FlowKey& key, DWORD reportedPid) {
    FlowStore::Instance().AssignReportedOwner(key, reportedPid);
}

DWORD ByLocalEndpoint(Proto proto, const IpAddr& local, uint16_t lport,
                      bool* ambiguous) {
    return FlowStore::Instance().ResolveLocalEndpoint(
        proto, local, lport, ambiguous);
}

void NoteConnectionEnd(const FlowKey& key, DWORD reportedPid) {
    (void)key;
    (void)reportedPid;
    // CloseFlow одновременно помечает соединение и соответствующую запись
    // индекса. Отдельный второй вызов только начал бы срок удаления заново.
}

void ResetSession() {
    // BeginDriverSession/EndDriverSession уже сбрасывают FlowStore целиком.
}

void Invalidate() {
    // Актуальный системный снимок публикуется Monitor каждую секунду.
}

} // namespace OwnerLookup
