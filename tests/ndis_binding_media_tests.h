#pragma once
#include "NdisBindingPath.h"
#include <initializer_list>

namespace ndis_binding_tests {

inline constexpr GUID mediaAdapterId = {0x9eb6ca05, 0x3905, 0x4420, {0xa3, 0x4f, 0x4f, 0xa0, 0x9d, 0xcc, 0x6a, 0x2d}};
inline constexpr GUID otherAdapterId = {1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
struct FakeMediaAdapter {
    ULONG64 luid = 123;
    GUID roundTrip = mediaAdapterId, rowGuid = mediaAdapterId;
    ULONG64 rowLuid = 123;
    NDIS_MEDIUM media = NdisMedium802_3;
    DWORD guidError = NO_ERROR, luidError = NO_ERROR, rowError = NO_ERROR;
    unsigned rowReads = 0;
};
inline FakeMediaAdapter mediaAdapter;
inline DWORD WINAPI MediaGuidToLuid(const GUID* guid, NET_LUID* luid) {
    if (*guid != mediaAdapterId) return ERROR_NOT_FOUND;
    luid->Value = mediaAdapter.luid;
    return mediaAdapter.guidError;
}
inline DWORD WINAPI MediaLuidToGuid(const NET_LUID* luid, GUID* guid) {
    if (luid->Value != mediaAdapter.luid) return ERROR_NOT_FOUND;
    *guid = mediaAdapter.roundTrip;
    return mediaAdapter.luidError;
}
inline DWORD WINAPI MediaGetEntry(MIB_IF_ROW2* row) {
    ++mediaAdapter.rowReads;
    if (row->InterfaceLuid.Value != mediaAdapter.luid) return ERROR_NOT_FOUND;
    row->InterfaceGuid = mediaAdapter.rowGuid;
    row->InterfaceLuid.Value = mediaAdapter.rowLuid;
    row->MediaType = mediaAdapter.media;
    return mediaAdapter.rowError;
}

inline bool AdapterMediaTests() {
    using namespace ndis_binding::detail;
    const AdapterQuery api{MediaGuidToLuid, MediaLuidToGuid, MediaGetEntry};
    for (const auto media : {NdisMedium802_3, NdisMediumNative802_11}) {
        mediaAdapter = {};
        mediaAdapter.media = media;
        const auto row = QueryAdapter(mediaAdapterId, api);
        if (!CompatibleMedia(row.MediaType) || row.InterfaceGuid != mediaAdapterId ||
            row.InterfaceLuid.Value != mediaAdapter.luid || mediaAdapter.rowReads != 1) return false;
    }
    for (const auto media : {NdisMediumIP, NdisMediumWan, NdisMediumMax}) {
        mediaAdapter = {};
        mediaAdapter.media = media;
        if (CompatibleMedia(QueryAdapter(mediaAdapterId, api).MediaType)) return false;
    }
    const auto rejects = [&](const GUID& guid = mediaAdapterId) {
        try { QueryAdapter(guid, api); } catch (const Error&) { return true; }
        return false;
    };
    mediaAdapter = {};
    if (!rejects(GUID_NULL) || !rejects(otherAdapterId) || mediaAdapter.rowReads != 0) return false;
    mediaAdapter = {}; mediaAdapter.guidError = ERROR_ACCESS_DENIED;
    if (!rejects() || mediaAdapter.rowReads != 0) return false;
    mediaAdapter = {}; mediaAdapter.luid = 0;
    if (!rejects() || mediaAdapter.rowReads != 0) return false;
    mediaAdapter = {}; mediaAdapter.luidError = ERROR_NOT_FOUND;
    if (!rejects() || mediaAdapter.rowReads != 0) return false;
    mediaAdapter = {}; mediaAdapter.roundTrip = otherAdapterId;
    if (!rejects() || mediaAdapter.rowReads != 0) return false;
    mediaAdapter = {}; mediaAdapter.rowError = ERROR_ACCESS_DENIED;
    if (!rejects()) return false;
    mediaAdapter = {}; mediaAdapter.rowGuid = otherAdapterId;
    if (!rejects()) return false;
    mediaAdapter = {}; ++mediaAdapter.rowLuid;
    if (!rejects()) return false;

    // Перед Enable повторно проверяются и личность, и текущая среда.
    const auto enableRejects = [&](const Adapter& target) {
        try { VerifyEnableAdapter(target, api); } catch (const Error&) { return true; }
        return false;
    };
    mediaAdapter = {};
    Adapter target{mediaAdapterId, mediaAdapter.luid};
    VerifyEnableAdapter(target, api);
    mediaAdapter.media = NdisMediumIP;
    if (!enableRejects(target)) return false;
    mediaAdapter = {}; ++target.luid;
    if (!enableRejects(target)) return false;
    target.luid = mediaAdapter.luid;
    target.compatible = false;
    if (!enableRejects(target)) return false;
    target.compatible = true; target.excluded = true;
    return enableRejects(target);
}

} // namespace ndis_binding_tests
