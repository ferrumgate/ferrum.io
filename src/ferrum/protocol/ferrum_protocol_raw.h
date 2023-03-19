#ifndef __FERRUM_PROTOCOL_RAW_H__
#define __FERRUM_PROTOCOL_RAW_H__
#include "ferrum_protocol.h"

int32_t ferrum_protocol_raw_new(ferrum_protocol_t **protocol, ferrum_raw_tcpsocket_pair_t *tcp_pair,
                                ferrum_raw_udpsocket_pair_t *udp_pair, const ferrum_config_t *config,
                                const ferrum_policy_t *policy, const ferrum_syslog_t *syslog);
int32_t ferrum_protocol_raw_destroy(ferrum_protocol_t *protocol);

#endif