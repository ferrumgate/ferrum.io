#ifndef __FERRUM_CONFIG_H__
#define __FERRUM_CONFIG_H__
#include "ferrum.h"

#define FERRUM_HOSTNAME_LEN 64

typedef struct ferrum_config {
  base_object();
  char hostname[FERRUM_HOSTNAME_LEN];
  struct {
    char host[REBRICK_HOST_STR_LEN];
    rebrick_sockaddr_t addr;
    char ip[REBRICK_IP_STR_LEN];
    int32_t port;
    int32_t servfail_timeout_ms;
  } redis;

  struct {

    char dest_host[REBRICK_HOST_STR_LEN];
    char dest_ip[REBRICK_IP_STR_LEN];
    rebrick_sockaddr_t dest_tcp_addr;
    int32_t dest_tcp_port;
    rebrick_sockaddr_t dest_udp_addr;
    int32_t dest_udp_port;

  } raw;

} ferrum_config_t;

int32_t ferrum_config_new(ferrum_config_t **config);
int32_t ferrum_config_destroy(ferrum_config_t *config);
#endif