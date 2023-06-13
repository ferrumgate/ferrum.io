#ifndef __FERRUM_PROTOCOL_DNS_H__
#define __FERRUM_PROTOCOL_DNS_H__
#include "../ferrum.h"
#include "ferrum_protocol.h"
#include "../ferrum_dns_db.h"
#include "ferrum_dns_packet.h"

int32_t
ferrum_protocol_dns_new(ferrum_protocol_t **protocol,
                        ferrum_raw_tcpsocket_pair_t *tcp_pair,
                        ferrum_raw_udpsocket_pair_t *udp_pair,
                        const ferrum_config_t *config,
                        const ferrum_policy_t *policy,
                        const ferrum_syslog_t *syslog,
                        const ferrum_dns_db_t *dns_db);
int32_t ferrum_protocol_dns_destroy(ferrum_protocol_t *protocol);

#endif