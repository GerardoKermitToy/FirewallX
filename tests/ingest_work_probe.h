#pragma once

#include "VerdictSession.h"
#include <cstddef>

// Счётчики существуют только в тестовой сборке Ingest.cpp.
namespace IngestWorkProbe {
struct Counts {
    size_t shapeHashes = 0;
    size_t tcpReads = 0;
    size_t dnsParses = 0;
    size_t processPathReads = 0;
};
inline thread_local Counts counts;
inline thread_local void (*beforePolicyMatch)() = nullptr;
inline thread_local void (*afterServicePolicyLoad)() = nullptr;
}

DriverVerdictRequest test_register_driver_verdict_request(uint64_t externalConnectionId);
