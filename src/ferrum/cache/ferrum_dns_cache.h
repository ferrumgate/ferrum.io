#ifndef __FERRUM_DNS_CACHE_H__
#define __FERRUM_DNS_CACHE_H__

#include "../ferrum.h"
#include "../protocol/ferrum_dns_packet.h"

typedef struct ferrum_list_item {
  base_object();
  void *data;
  struct ferrum_list_item *prev, *next;

} ferrum_list_item_t;

/**
 * @brief hashtable cache item
 *
 */
typedef struct ferrum_dns_cache_item {
  base_object();
  int32_t key;
  ferrum_list_item_t *dnslist;

  UT_hash_handle hh;

} ferrum_dns_cache_item_t;

typedef struct ferrum_dns_cache_page {
  base_object();
  /**
   * @brief last time in (microseconds ) you can drop page
   *
   */
  int64_t drop_time;
  /**
   * @brief last time (microseconds)  you can insert in
   *
   */
  int64_t can_last_insert_time;

  /**
   * @brief hash table
   *
   */
  ferrum_dns_cache_item_t *table;
  /**
   * @brief dns packets count
   *
   */
  int32_t cache_len;

} ferrum_dns_cache_page_t;

/**
 * @brief founded item after search
 *
 */
typedef struct ferrum_dns_cache_founded {
  base_object();
  ferrum_dns_packet_t *dns;
  ferrum_dns_cache_page_t *page;
  ferrum_list_item_t *dns_asitem;
  ferrum_dns_cache_item_t *cache_item;
} ferrum_dns_cache_founded_t;

/**
 * @brief creates new instance of @see ferrum_dns_cache_page_t
 *
 * @param page instance ptr
 * @param timeoutms  cache time in miliseconds
 * @return int32_t  <0 for error, otherwise success
 */
int32_t ferrum_dns_cache_page_new(ferrum_dns_cache_page_t **page, int32_t timeoutms);

/**
 * @brief destroy instance
 *
 * @param page instance
 * @return int32_t
 */
int32_t ferrum_dns_cache_page_destroy(ferrum_dns_cache_page_t *page);

/**
 * @brief adds a dns packet to cache
 *
 * @param page
 * @param key search key
 * @param dns packet
 * @return int32_t  <0 for error, otherwise success
 */
int32_t ferrum_dns_cache_page_add_item(ferrum_dns_cache_page_t *page, int32_t key, ferrum_dns_packet_t *dns);

/**
 * @brief finds an item, fills founded parameters
 *
 * @param page cache instance
 * @param key search key
 * @param qid  dns query id
 * @param addr sended address
 * @param founded founded cache record with details
 * @return int32_t
 */
int32_t ferrum_dns_cache_page_find_item(ferrum_dns_cache_page_t *page, int32_t key, uint16_t qid, const rebrick_sockaddr_t *addr, const char *query, ferrum_dns_cache_founded_t *founded);

/**
 * @brief
 *
 * @param page
 * @param dns
 * @param query_index index position
 * @return int32_t
 */
int32_t ferrum_dns_cache_page_remove_item(ferrum_dns_cache_page_t *page, ferrum_dns_cache_founded_t *founded);

/////////////////////////////////////// dns cache ////////////////////////
typedef struct ferrum_dns_cache {
  base_object();
  private_ ferrum_list_item_t *pages;
  private_ size_t pages_len;
  private_ int32_t timeout_ms;
} ferrum_dns_cache_t;

int32_t ferrum_dns_cache_new(ferrum_dns_cache_t **cache, int32_t timeoutmiliseconds);
int32_t ferrum_dns_cache_destroy(ferrum_dns_cache_t *cache);
int32_t ferrum_dns_cache_add(ferrum_dns_cache_t *cache, ferrum_dns_packet_t *dns);
int32_t ferrum_dns_cache_clear_timedoutdata(ferrum_dns_cache_t *cache);
int32_t ferrum_dns_cache_find(ferrum_dns_cache_t *cache, ferrum_dns_packet_t *refdns, ferrum_dns_cache_founded_t **founded);
// removes all founded struct and inner object
int32_t ferrum_dns_cache_remove(ferrum_dns_cache_t *cache, ferrum_dns_cache_founded_t *founded);
// removes only founded struct, not inner objects
int32_t ferrum_dns_cache_remove_founded(ferrum_dns_cache_t *cache, ferrum_dns_cache_founded_t *founded);

int32_t ferrum_dns_cache_get_pageslen(ferrum_dns_cache_t *cache, size_t *len);
int32_t ferrum_dns_cache_get_pageslist(ferrum_dns_cache_t *cache, ferrum_list_item_t **list);

#endif