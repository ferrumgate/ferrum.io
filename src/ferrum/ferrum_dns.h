#ifndef __FERRUM_DNS_H__
#define __FERRUM_DNS_H__
#include "ferrum.h"
#include "ferrum_redis.h"
#include "ferrum_config.h"
#include "ferrum_lmdb.h"

#define FERRUM_DNS_MAX_FQDN_LEN 512

typedef struct ferrum_dns {
  base_object();
  private_ ferrum_lmdb_t *lmdb;
  private_ ferrum_redis_t *redis;
  private_ ferrum_config_t *config;

} ferrum_dns_t;

int32_t ferrum_dns_new(ferrum_dns_t **dns, ferrum_config_t *config);
int32_t ferrum_dns_destroy(ferrum_dns_t *dns);
int32_t ferrum_dns_find_local_a(const ferrum_dns_t *dns, char fqdn[FERRUM_DNS_MAX_FQDN_LEN], char ip[REBRICK_IP_STR_LEN]);

#endif