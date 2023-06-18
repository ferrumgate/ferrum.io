#ifndef __FERRUM_DNS_QUERY_H__
#define __FERRUM_DNS_QUERY_H__
#include "../ferrum.h"
#include "ldns/ldns.h"

#define FERRUM_DNS_MAX_FQDN_LEN 1024

typedef struct ferrum_dns_packet {
  base_object();
  char *query;
  uint16_t query_id;
  uint16_t query_newid;
  ldns_rr_class query_class;
  ldns_rr_type query_type;
  int32_t query_crc;
  struct {
    uint16_t aa : 1;
    uint16_t tc : 1;
    uint16_t rd : 1;
    uint16_t ra : 1;
  } flags;

  struct {
    /** EDNS0 available buffer size, see RFC2671 */
    uint16_t udp_size;
    /** EDNS0 Extended rcode */
    uint8_t extended_rcode;
    /** EDNS Version */
    uint8_t version;
    /* OPT pseudo-RR presence flag */
    uint8_t present;
    /** Reserved EDNS data bits */
    uint16_t z;
    /** Arbitrary EDNS rdata */
    // ldns_rdf *data;
    /** Structed EDNS data */
    // ldns_edns_option_list *list;

  } edns;
  rebrick_sockaddr_t source;
  rebrick_sockaddr_t destination;

  struct {
    char *authz_id;
    unsigned int is_backend_sended : 1;
    unsigned int is_backend_received : 1;

    struct ferrum_redis_dns_query *redis_query_list;
    int32_t redis_query_list_len;
    int32_t is_redis_query_error;
    int32_t is_redis_query_not_found;

  } state;

} ferrum_dns_packet_t;

typedef struct ferrum_redis_dns_query {
  const char *query;
  unsigned int is_key_sended : 1;
  unsigned int is_key_received : 1;
  unsigned int is_key_timeout : 1;
  unsigned int is_key_exists : 1;
  unsigned int is_error : 1;
  unsigned int is_lists_sended : 1;
  unsigned int is_lists_timeout : 1;
  unsigned int is_lists_received : 1;

} ferrum_redis_dns_query_t;

int32_t ferrum_dns_packet_destroy(ferrum_dns_packet_t *dns);
uint32_t ferrum_dns_packet_crc(ferrum_dns_packet_t *dns);
int32_t ferrum_dns_packet_from(const uint8_t *buffer, size_t len, ferrum_dns_packet_t *dns);

#endif