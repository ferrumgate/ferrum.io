#include "ferrum_dns_cache.h"

static int64_t qcache_page_count = 0;
int32_t ferrum_dns_cache_page_new(ferrum_dns_cache_page_t **page, int32_t timeoutms) {

  ferrum_dns_cache_page_t *tmp = new1(ferrum_dns_cache_page_t);
  constructor(tmp, ferrum_dns_cache_page_t);

  int64_t now = rebrick_util_micro_time();
  tmp->drop_time = now + timeoutms * 2 * 1000;
  tmp->can_last_insert_time = now + timeoutms * 1000;
  tmp->table = NULL;
  *page = tmp;
  qcache_page_count++;
  ferrum_log_debug("qcache_page_count is %" PRId64 "\n", qcache_page_count);
  return FERRUM_SUCCESS;
}
int64_t counteradd = 0;
int64_t counterdel = 0;
int32_t ferrum_dns_cache_page_destroy(ferrum_dns_cache_page_t *page) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (!page) {
    ferrum_log_fatal("page is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  ferrum_dns_cache_item_t *current_item, *tmp;

  HASH_ITER(hh, page->table, current_item, tmp) {

    ferrum_list_item_t *tmplist, *tmplist2;
    DL_FOREACH_SAFE(current_item->dnslist, tmplist, tmplist2) {
      ferrum_dns_packet_t *packet = cast(tmplist->data, ferrum_dns_packet_t *);
      /* if (packet->ref_count == 1) {//kaybolan paketleri syslog yapmak gereksiz
        ferrum_dns_set_destroy_callback(packet, NULL, NULL); //paket kaybolmus
      } */
      DL_DELETE(current_item->dnslist, tmplist);
      ferrum_dns_packet_destroy(packet);
      rebrick_free(tmplist);
      page->cache_len--;
    }

    HASH_DEL(page->table, current_item); /* delete it (users advances to next) */

    rebrick_free(current_item); /* free it */
    counterdel++;
  }

  rebrick_free(page);

  qcache_page_count--;
  ferrum_log_debug("qcache_page_count is %" PRId64 "\n", qcache_page_count);

  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_page_add_item(ferrum_dns_cache_page_t *page, int32_t hkey, ferrum_dns_packet_t *dns) {

  char current_time_str[32] = {0};
  unused(current_time_str);
  // printf("hkey %d:\n",hkey);
  if (!page || !dns) {
    ferrum_log_fatal("page key or dns is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  ferrum_dns_cache_item_t *item = NULL;

  HASH_FIND_INT(page->table, &hkey, item);
  if (!item) // not found, then create
  {

    item = new1(ferrum_dns_cache_item_t);
    constructor(item, ferrum_dns_cache_item_t);

    item->key = hkey;
    HASH_ADD_INT(page->table, key, item);
    counteradd++;
  }
  ferrum_list_item_t *newitem = new1(ferrum_list_item_t);
  constructor(newitem, ferrum_list_item_t);

  DL_APPEND(item->dnslist, newitem);

  newitem->data = dns;
  page->cache_len++;
  // printf("pagecache count %d\n",page->cache_len);
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_page_find_item(ferrum_dns_cache_page_t *page, int32_t hkey, uint16_t qid, const rebrick_sockaddr_t *addr, const char *query, ferrum_dns_cache_founded_t *founded) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (!page || !founded) {
    ferrum_log_fatal("page  or founded is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  ferrum_dns_cache_item_t *item;
  ferrum_dns_packet_t *dnspacket = NULL;
  int32_t qindex = 0;

  HASH_FIND_INT(page->table, &hkey, item);
  if (item) {
    ferrum_list_item_t *tmp;

    DL_FOREACH(item->dnslist, tmp) {

      dnspacket = cast(tmp->data, ferrum_dns_packet_t *);
      if (dnspacket->query_newid == qid &&
          dnspacket->query_crc == hkey &&
          (rebrick_util_ip_equal(addr, &dnspacket->destination)) &&
          !strcmp(dnspacket->query, query)) {
        founded->cache_item = item;
        founded->dns = dnspacket;
        founded->dns_asitem = tmp;

        break;
      }

      qindex++;
    }
  }

  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_page_remove_item(ferrum_dns_cache_page_t *page, ferrum_dns_cache_founded_t *founded) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (!page || !founded || !founded->dns || !founded->cache_item || !founded->cache_item->dnslist) {
    ferrum_log_fatal("page key or founded is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  DL_DELETE(founded->cache_item->dnslist, founded->dns_asitem);
  rebrick_free(founded->dns_asitem);
  if (!founded->cache_item->dnslist) {

    HASH_DEL(page->table, founded->cache_item);
    rebrick_free(founded->cache_item);
    founded->cache_item = NULL;
  }
  ferrum_dns_packet_destroy(founded->dns);
  founded->dns = NULL;

  page->cache_len--;

  return FERRUM_SUCCESS;
}

////////////////////// dns cache  ////////////////////////////

/**
 * @brief finds a page for current time
 *
 * @param data
 * @return ferrum_dns_cache_page_t* NULL or founded page
 */
static ferrum_dns_cache_page_t *ferrum_dns_cache_find_current_time_page(ferrum_dns_cache_t *cache) {

  ferrum_list_item_t *pages = cache->pages;
  ferrum_list_item_t *tmp;
  int64_t now = rebrick_util_micro_time();
  // int count=0;
  // DL_COUNT(pages,tmp,count);
  // printf("current time page len %d\n",count);
  DL_FOREACH(pages, tmp) {
    ferrum_dns_cache_page_t *page = cast(tmp->data, ferrum_dns_cache_page_t *);

    if (page && page->can_last_insert_time > now)
      return page;
    pages = pages->next;
  }

  return NULL;
}

static int32_t ferrum_dns_cache_add_page(ferrum_dns_cache_t *cache, ferrum_dns_cache_page_t *page) {

  if (!cache || !page) {
    ferrum_log_fatal("data or page is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  ferrum_list_item_t *item = new1(ferrum_list_item_t);
  constructor(item, ferrum_list_item_t);

  item->data = page;
  DL_APPEND(cache->pages, item);

  cache->pages_len++;
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_new(ferrum_dns_cache_t **cache, int32_t timeoutmiliseconds) {

  ferrum_dns_cache_t *tmp = new1(ferrum_dns_cache_t);
  constructor(tmp, ferrum_dns_cache_t);

  tmp->timeout_ms = timeoutmiliseconds;

  *cache = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_dns_cache_destroy(ferrum_dns_cache_t *cache) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (cache) {
    ferrum_log_debug("destroying qcache\n");

    ferrum_list_item_t *tmp, *tmp2;
    DL_FOREACH_SAFE(cache->pages, tmp, tmp2) {
      ferrum_dns_cache_page_t *page = cast(tmp->data, ferrum_dns_cache_page_t *);
      ferrum_dns_cache_page_destroy(page);
      DL_DELETE(cache->pages, tmp);
      rebrick_free(tmp);
      cache->pages_len--;
    }

    rebrick_free(cache);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_add(ferrum_dns_cache_t *cache, ferrum_dns_packet_t *dns) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  if (!cache || !dns) {
    ferrum_log_fatal("cache or dns parameter is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  ferrum_dns_cache_page_t *page = ferrum_dns_cache_find_current_time_page(cache);
  if (!page) {

    result = ferrum_dns_cache_page_new(&page, cache->timeout_ms);
    if (result < 0) {
      ferrum_log_fatal("cache page create failed %d\n", result);
      return result;
    }
    // add page to qcache
    result = ferrum_dns_cache_add_page(cache, page);
    if (result < 0) {
      ferrum_log_fatal("adding page to cache failed %d\n", result);

      ferrum_dns_cache_page_destroy(page);

      return result;
    }
  }

  result = ferrum_dns_cache_page_add_item(page, dns->query_crc, dns);
  if (result < 0) {
    ferrum_log_fatal("adding dns packet to page failed %d\n", result);
    return result;
  }
  ferrum_log_debug("dns packet putted into cache qid:%d\n", dns->query_id);
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_clear_timedoutdata(ferrum_dns_cache_t *cache) {

  ferrum_list_item_t *tmp, *tmp2;

  int64_t now = rebrick_util_micro_time();
  // ferrum_log_debug("clearing timedout cache\n");
  DL_FOREACH_SAFE(cache->pages, tmp, tmp2) {

    ferrum_dns_cache_page_t *page = cast(tmp->data, ferrum_dns_cache_page_t *);
    if (page->drop_time < now) {
      DL_DELETE(cache->pages, tmp);
      ferrum_log_debug("qcache page is timed out\n");
      ferrum_dns_cache_page_destroy(page);
      rebrick_free(tmp);
      cache->pages_len--;

    } else {
      break;
    }
  }
  /*  int count=0;
    DL_COUNT(data->pages,tmp,count);
    printf("%d pages len\n",count); */

  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_get_pageslen(ferrum_dns_cache_t *cache, size_t *len) {

  if (!cache || !len) {
    ferrum_log_fatal("cache or len is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  *len = cache->pages_len;
  return FERRUM_SUCCESS;
}
int32_t ferrum_dns_cache_get_pageslist(ferrum_dns_cache_t *cache, ferrum_list_item_t **list) {

  if (!cache || !list) {
    ferrum_log_fatal("cache or list is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  *list = cache->pages;
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_find(ferrum_dns_cache_t *cache, ferrum_dns_packet_t *refdns, ferrum_dns_cache_founded_t **founded) {

  int32_t result;
  if (!cache || !refdns || !founded) {
    ferrum_log_fatal("cache or refdns or founded is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  ferrum_list_item_t *pages = cache->pages;
  ferrum_list_item_t *tmp;
  int32_t pageindex = 0;
  int32_t key = refdns->query_crc;
  ferrum_dns_cache_founded_t *foundedtmp = new1(ferrum_dns_cache_founded_t);
  constructor(foundedtmp, ferrum_dns_cache_founded_t);

  int64_t now = rebrick_util_micro_time();
  DL_FOREACH(pages, tmp) {

    ferrum_dns_cache_page_t *page = cast(tmp->data, ferrum_dns_cache_page_t *);
    if (page->drop_time >= now) {
      result = ferrum_dns_cache_page_find_item(page, key, refdns->query_id, &refdns->source, refdns->query, foundedtmp);
      if (result < 0) {
        ferrum_log_fatal("qcache search failed %s\n", refdns->query);
        rebrick_free(foundedtmp);
        return result;
      }
      if (foundedtmp->dns) {
        foundedtmp->page = page;
        break;
      }
    }

    pageindex++;
    pages = pages->next;
  }
  *founded = foundedtmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_dns_cache_remove(ferrum_dns_cache_t *cache, ferrum_dns_cache_founded_t *founded) {

  int32_t result;
  if (!cache || !founded) {
    ferrum_log_fatal("cache or refdns or founded is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  if (founded->cache_item && founded->dns && cache) {
    ferrum_log_debug("qcache removing query: %s qid: %d\n", founded->dns->query, founded->dns->query_id);

    ferrum_dns_cache_page_t *page_current = founded->page;
    result = ferrum_dns_cache_page_remove_item(page_current, founded);
    if (result < 0) {
      ferrum_log_fatal("qcache page remove item failed %d", result);
      return result;
    }
  }
  rebrick_free(founded);

  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_cache_remove_founded(ferrum_dns_cache_t *cache, ferrum_dns_cache_founded_t *founded) {

  if (!cache || !founded) {
    ferrum_log_fatal("cache or refdns or founded is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  /* if (founded->cache_item && founded->dns && cache && cache->private_data) {
    ferrum_dns_cache_private_t *prvdata = cast(cache->private_data, ferrum_dns_cache_private_t *);
    ferrum_dns_cache_page_t *page_current = founded->page;
    result = ferrum_dns_cache_page_remove_item(page_current, founded);
    if (result < 0) {
      ferrum_log_fatal("qcache page remove item failed %d", result);
      return result;
    }

    prvdata->metrics->qcache_querylen--;
  } */
  rebrick_free(founded);

  return FERRUM_SUCCESS;
}