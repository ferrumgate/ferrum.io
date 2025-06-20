#ifndef __FERRUM_RAW_H__
#define __FERRUM_RAW_H__
#include "ferrum.h"
#include "ferrum_config.h"
#include "ferrum_redis.h"
#include "ferrum_policy.h"
#include "ferrum_syslog.h"
#include "ferrum_dns_db.h"
#include "ferrum_raw_socket_pair.h"
#include "ferrum_activity_log.h"
#include "protocol/ferrum_protocol.h"
#include "protocol/ferrum_protocol_raw.h"
#include "protocol/ferrum_protocol_dns.h"
#include "cache/ferrum_cache.h"
#include "pool/ferrum_udpsocket_pool.h"

#define FERRUM_RAW_POLICY_CHECK_MS 5000000
typedef struct ferrum_raw_udpsocket2 {
  base_object();

  rebrick_sockaddr_t client_addr;
  struct ferrum_raw *raw;
  UT_hash_handle hh;
} ferrum_raw_udpsocket2_t;

typedef int32_t (*rebrick_conntrack_get_func_t)(const struct sockaddr *peer, const struct sockaddr *local_addr,
                                                int istcp, rebrick_conntrack_t *track);
typedef struct ferrum_raw {
  base_object();

  private_ const ferrum_config_t *config;
  private_ const ferrum_policy_t *policy;
  private_ const ferrum_syslog_t *syslog;
  private_ const ferrum_redis_t *redis_intel;
  private_ const ferrum_dns_db_t *dns_db;
  private_ const ferrum_track_db_t *track_db;
  private_ const ferrum_authz_db_t *authz_db;
  private_ const ferrum_cache_t *cache;
  private_ ferrum_udpsocket_pool_t *udpsocket_pool;
  private_ rebrick_conntrack_get_func_t conntrack_get;

  private_ int32_t socket_count;
  private_ int32_t is_destroy_started;
  private_ rebrick_timer_t *udp_tracker;
  struct {
    private_ rebrick_tcpsocket_t *tcp;
    private_ rebrick_sockaddr_t tcp_listening_addr;
    private_ rebrick_sockaddr_t tcp_destination_addr;
    private_ readonly_ char tcp_destination_ip[REBRICK_IP_STR_LEN];
    private_ readonly_ char tcp_destination_port[REBRICK_PORT_STR_LEN];

    private_ rebrick_udpsocket_t *udp;
    private_ rebrick_sockaddr_t udp_listening_addr;
    private_ rebrick_sockaddr_t udp_destination_addr;
    private_ readonly_ char udp_destination_ip[REBRICK_IP_STR_LEN];
    private_ readonly_ char udp_destination_port[REBRICK_PORT_STR_LEN];
    // for supporting tproxy, we need to a raw socket to send data
    private_ rebrick_rawsocket_t *raw_udp_socket;

  } listen;

  struct {
    public_ int32_t connected_clients;
    public_ uint64_t transfered_bytes;
    public_ uint64_t rejected_clients;
  } metrics;

  struct {
    private_ ferrum_raw_tcpsocket_pair_t *tcp;
    private_ ferrum_raw_udpsocket_pair_t *udp;
  } socket_pairs;

  struct {
    private_ ferrum_raw_udpsocket_pair_t *udp_list;
  } lfu;

} ferrum_raw_t;

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config,
                       const ferrum_policy_t *policy,
                       const ferrum_syslog_t *syslog,
                       const ferrum_redis_t *redis,
                       const ferrum_dns_db_t *dns_db,
                       const ferrum_track_db_t *track_db,
                       const ferrum_authz_db_t *authz_db,
                       const ferrum_cache_t *cache,
                       ferrum_udpsocket_pool_t *udp_pool,
                       rebrick_conntrack_get_func_t conntrack_get);
int32_t ferrum_raw_destroy(ferrum_raw_t *raw);

#endif