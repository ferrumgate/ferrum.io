#ifndef __FERRUM_CONFIG_H__
#define __FERRUM_CONFIG_H__
#include "ferrum.h"

#define FERRUM_HOSTNAME_LEN 64
#define FERRUM_PATH_LEN 512

typedef struct ferrum_config {
  base_object();
  char hostname[FERRUM_HOSTNAME_LEN];

  struct {
    rebrick_sockaddr_t addr;
    char addr_str[REBRICK_IP_STR_LEN];
    char ip[REBRICK_IP_STR_LEN];
    char port[REBRICK_PORT_STR_LEN];
    char pass[REBRICK_PASS_STR_LEN];
    int32_t servfail_timeout_ms;
  } redis;

  struct {
    rebrick_sockaddr_t addr;
    char addr_str[REBRICK_IP_STR_LEN];
    char ip[REBRICK_IP_STR_LEN];
    char port[REBRICK_PORT_STR_LEN];
    char pass[REBRICK_PASS_STR_LEN];
    int32_t servfail_timeout_ms;
  } redis_local;

  struct {
    char dest_tcp_addr_str[REBRICK_IP_PORT_STR_LEN];
    rebrick_sockaddr_t dest_tcp_addr;
    char dest_udp_addr_str[REBRICK_IP_PORT_STR_LEN];
    rebrick_sockaddr_t dest_udp_addr;

    char listen_tcp_addr_str[REBRICK_IP_PORT_STR_LEN];
    rebrick_sockaddr_t listen_tcp_addr;
    char listen_udp_addr_str[REBRICK_IP_PORT_STR_LEN];
    rebrick_sockaddr_t listen_udp_addr;

  } raw;
  // service id
  char service_id[REBRICK_NAME_STR_LEN];
  // gateway id
  char gateway_id[REBRICK_NAME_STR_LEN];
  // every instance will have diffent instance id when started
  char instance_id[REBRICK_NAME_STR_LEN];

  int32_t is_policy_disabled;
  char lmdb_folder[FERRUM_PATH_LEN];

} ferrum_config_t;

int32_t ferrum_config_new(ferrum_config_t **config);
int32_t ferrum_config_destroy(ferrum_config_t *config);
#endif