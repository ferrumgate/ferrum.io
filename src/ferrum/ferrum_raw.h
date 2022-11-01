#ifndef __FERRUM_RAW_H__
#define __FERRUM_RAW_H__
#include "ferrum.h"
#include "ferrum_config.h"
#include "ferrum_redis.h"
#include "ferrum_policy.h"

typedef struct ferrum_raw_udpsocket2 {
  base_object();

  rebrick_sockaddr_t client_addr;
  struct ferrum_raw *raw;
  UT_hash_handle hh;
} ferrum_raw_udpsocket2_t;

typedef struct ferrum_raw_udpsocket_pair {
  base_object();
  int32_t mark;
  int64_t last_used;
  rebrick_sockaddr_t client_addr;
  rebrick_udpsocket_t *udp_socket;
  UT_hash_handle hh;
} ferrum_raw_udpsocket_pair_t;

typedef struct ferrum_raw_tcpsocket_pair {
  base_object();
  uint64_t key;

  rebrick_tcpsocket_t *source;
  rebrick_tcpsocket_t *destination;

  UT_hash_handle hh;
} ferrum_raw_tcpsocket_pair_t;

typedef int32_t (*rebrick_conntrack_get_func_t)(const struct sockaddr *peer, const struct sockaddr *local_addr,
                                                int istcp, rebrick_conntrack_t *track);
typedef struct ferrum_raw {
  base_object();

  private_ const ferrum_config_t *config;
  private_ const ferrum_policy_t *policy;
  private_ rebrick_conntrack_get_func_t conntrack_get;

  private_ int32_t socket_count;
  private_ int32_t is_destroy_started;
  struct {
    private_ rebrick_tcpsocket_t *tcp;
    private_ rebrick_sockaddr_t tcp_listening_addr;
    private_ rebrick_sockaddr_t tcp_destination_addr;

    private_ rebrick_udpsocket_t *udp;
    private_ rebrick_sockaddr_t udp_listening_addr;
    private_ rebrick_sockaddr_t udp_destination_addr;
  } listen;

  struct {
    public_ int32_t connected_clients;
    public_ uint64_t transfered_bytes;
    public_ uint64_t rejected_clients;
  } metrics;

  ferrum_raw_tcpsocket_pair_t *tcp_socket_pairs;
  ferrum_raw_udpsocket_pair_t *udp_socket_pairs;

} ferrum_raw_t;

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config,
                       const ferrum_policy_t *policy,
                       rebrick_conntrack_get_func_t conntrack_get);
int32_t ferrum_raw_destroy(ferrum_raw_t *raw);

#endif