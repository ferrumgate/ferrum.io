#ifndef __FERRUM_CACHE_H__
#define __FERRUM_CACHE_H__

#include "../ferrum.h"
#include "ferrum_dns_cache.h"

typedef struct ferrum_cache {
  base_object();
  ferrum_dns_cache_t *dns;
  rebrick_timer_t *dns_cleaner;

} ferrum_cache_t;

int32_t ferrum_cache_new(ferrum_cache_t **cache, int32_t dns_timeout);
int32_t ferrum_cache_destroy(ferrum_cache_t *cache);

#endif