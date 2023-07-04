#ifndef __FERRUM_DNS_H__
#define __FERRUM_DNS_H__
#include "ferrum.h"
#include "ferrum_redis.h"
#include "ferrum_config.h"
#include "ferrum_lmdb.h"
#include "protocol/ferrum_dns_packet.h"

typedef struct ferrum_dns_db {
  base_object();
  private_ ferrum_lmdb_t *lmdb;
  private_ ferrum_redis_t *redis;
  private_ ferrum_config_t *config;

} ferrum_dns_db_t;

int32_t ferrum_dns_db_new(ferrum_dns_db_t **dns, ferrum_config_t *config);
int32_t ferrum_dns_db_destroy(ferrum_dns_db_t *dns);
int32_t ferrum_dns_db_find_local_a(const ferrum_dns_db_t *dns, char *fqdn, char ip[REBRICK_IP_STR_LEN]);

#endif