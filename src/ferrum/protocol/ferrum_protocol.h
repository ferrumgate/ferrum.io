#ifndef __FERRUM_PROTOCOL_H__
#define __FERRUM_PROTOCOL_H__
#include "../ferrum.h"
#include "../ferrum_dns_db.h"
#include "../ferrum_raw_socket_pair.h"
#include "../ferrum_activity_log.h"
#include "../cache/ferrum_dns_cache.h"
#include "../ferrum_dns_db.h"
#include "../ferrum_track_db.h"
#include "../ferrum_authz_db.h"
#include "../ferrum_redis.h"
#include "ferrum_dns_packet.h"
#include "../cache/ferrum_cache.h"

struct ferrum_protocol;

/**
 * @brief after client to us, send to destinaton
 */
typedef int32_t (*process_input_udp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);
/**
 * @brief after destination read, send to client
 */
typedef int32_t (*process_output_udp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);

typedef int32_t (*process_input_tcp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);
typedef int32_t (*process_output_tcp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);

typedef int32_t (*destroy_handler)(struct ferrum_protocol *protocol);

typedef struct ferrum_protocol {
  base_object();
  process_input_udp_handler process_input_udp;
  process_input_udp_handler process_output_udp;
  process_input_tcp_handler process_input_tcp;
  process_input_tcp_handler process_output_tcp;
  destroy_handler destroy;

  private_ const ferrum_config_t *config;
  private_ const ferrum_policy_t *policy;
  private_ const ferrum_syslog_t *syslog;
  private_ const ferrum_redis_t *redis_intel;
  private_ const ferrum_dns_db_t *dns_db;
  private_ const ferrum_track_db_t *track_db;
  private_ const ferrum_authz_db_t *authz_db;
  private_ const ferrum_cache_t *cache;
  struct {
    ferrum_raw_udpsocket_pair_t *udp;
    ferrum_raw_tcpsocket_pair_t *tcp;
  } pair;

  struct {
    int64_t time;
    int32_t random;
  } log;
  struct {
    // authz calculated user id that contains ,
    char *user_id;
    // authz calculated group ids that contains ,
    char *group_ids;
    // user id from policy result
    char user_id_first[FERRUM_ID_STR_LEN];
    char tun_id[FERRUM_ID_BIG_STR_LEN];
    uint32_t client_id;
    int64_t last_check;
  } identity;

  void *data;
} ferrum_protocol_t;

#endif