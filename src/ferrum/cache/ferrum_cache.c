#include "ferrum_cache.h"
static int32_t dns_cache_clean(void *callback) {
  unused(callback);
  ferrum_cache_t *cache = cast(callback, ferrum_cache_t *);
  ferrum_log_debug("cleaning dns cache\n");
  ferrum_dns_cache_clear_timedoutdata(cache->dns);
  return FERRUM_SUCCESS;
}

int32_t ferrum_cache_new(ferrum_cache_t **cache, int32_t create_dns_timeout) {
  ferrum_cache_t *tmp = new1(ferrum_cache_t);
  constructor(tmp, ferrum_cache_t);
  if (create_dns_timeout) { // create dns cache
    ferrum_dns_cache_t *cache;
    int32_t result = ferrum_dns_cache_new(&cache, create_dns_timeout);
    if (result) {
      ferrum_log_error("dns cache create failed with error:%d\n", result);
      ferrum_cache_destroy(tmp);
      return result;
    }
    tmp->dns = cache;

    rebrick_timer_t *cache_cleaner;
    result = rebrick_timer_new(&cache_cleaner, dns_cache_clean, tmp, create_dns_timeout + (create_dns_timeout / 3), TRUE);
    if (result) {
      ferrum_log_error("dns cache timer create failed with error:%d\n", result);
      ferrum_cache_destroy(tmp);
      return result;
    }
    tmp->dns_cleaner = cache_cleaner;
    ferrum_log_info("dns cache created\n");
  }
  *cache = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_cache_destroy(ferrum_cache_t *cache) {
  if (cache) {
    if (cache->dns_cleaner)
      rebrick_timer_destroy(cache->dns_cleaner);
    cache->dns_cleaner = NULL;
    if (cache->dns)
      ferrum_dns_cache_destroy(cache->dns);
    cache->dns = NULL;
    rebrick_free(cache);
  }
  return FERRUM_SUCCESS;
}