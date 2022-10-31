#ifndef __FERRUM_RAW_H__
#define __FERRUM_RAW_H__
#include "ferrum.h"
#include "ferrum_config.h"
#include "ferrum_redis.h"
#include "ferrum_policy.h"

typedef struct ferrum_raw_socket_pair {
  base_object();
  uint64_t key;
  union {
    rebrick_tcpsocket_t *tcp;
    rebrick_udpsocket_t *udp;
  } source;
  union {
    rebrick_tcpsocket_t *tcp;
    rebrick_udpsocket_t *udp;
  } destination;

  UT_hash_handle hh;
} ferrum_raw_socket_pair_t;
typedef struct ferrum_raw {
  base_object();

  private_ const ferrum_config_t *config;
  private_ const ferrum_policy_t *policy;

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

  ferrum_raw_socket_pair_t *socket_pairs;

} ferrum_raw_t;

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config);
int32_t ferrum_raw_destroy(ferrum_raw_t *raw);

#endif