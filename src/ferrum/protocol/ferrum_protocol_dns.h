#ifndef __FERRUM_PROTOCOL_DNS_H__
#define __FERRUM_PROTOCOL_DNS_H__
#include "../ferrum.h"
#include "ferrum_protocol.h"

int32_t ferrum_protocol_dns_new(ferrum_protocol_t **protocol, const ferrum_config_t *config,
                                const ferrum_policy_t *policy, const ferrum_syslog_t *syslog);
int32_t ferrum_protocol_dns_destroy(ferrum_protocol_t *protocol);

#endif