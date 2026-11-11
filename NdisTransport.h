#pragma once
#include "Common.h"
#include "FirewallXNdisFilter.hpp"
#include "VerdictSession.h"

// Дополнительный драйвер имеет собственные поток, сессию обязательств и raw pipe.
// Запуск не ждёт Open(): отсутствие драйвера не задерживает основной транспорт и UI.
void firewallxndisfilter_start();
void firewallxndisfilter_stop();
bool firewallxndisfilter_running();
bool firewallxndisfilter_service_connected();
bool firewallxndisfilter_service_process_locally();
bool firewallxndisfilter_service_flush_verdicts();
DWORD firewallxndisfilter_clear_cache();
DriverVerdictRequest firewallxndisfilter_register_request(uint64_t id) noexcept;
bool firewallxndisfilter_process_verdict(DriverVerdictRequest request,
                                firewallxndisfilter::Client::Verdict verdict);
