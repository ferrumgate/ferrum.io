#ifndef __FERRUM_PROTOCOL_DNS_H__
#define __FERRUM_PROTOCOL_DNS_H__
#include "../ferrum.h"
#include "ferrum_protocol.h"
#include "ldns/ldns.h"

#define FERRUM_DNS_MAX_FQDN_LEN 512

typedef struct ferrum_dns_query {
  base_object();
  char query[FERRUM_DNS_MAX_FQDN_LEN];
  uint16_t query_id;
  ldns_rr_class query_class;
  ldns_rr_type query_type;
  struct {
    uint16_t aa : 1;
    uint16_t tc : 1;
    uint16_t rd : 1;
    uint16_t ra : 1;
  } flags;

} ferrum_dns_query_t;

int32_t ferrum_protocol_dns_new(ferrum_protocol_t **protocol,
                                ferrum_raw_tcpsocket_pair_t *tcp_pair,
                                ferrum_raw_udpsocket_pair_t *udp_pair,
                                const ferrum_config_t *config,
                                const ferrum_policy_t *policy,
                                const ferrum_syslog_t *syslog,
                                const ferrum_lmdb_t *lmdb);
int32_t ferrum_protocol_dns_destroy(ferrum_protocol_t *protocol);

#endif