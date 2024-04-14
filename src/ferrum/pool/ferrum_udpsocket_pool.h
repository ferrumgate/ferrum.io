#ifndef __FERRUM_UDPSOCKET_POOL_H__
#define __FERRUM_UDPSOCKET_POOL_H__

#include "../ferrum.h"
#include "../../rebrick/socket/rebrick_udpsocket.h"

typedef struct ferrum_udpsocket_pool_item {
  base_object();
  rebrick_udpsocket_t *socket;
  struct ferrum_udpsocket_pool_item *prev;
  struct ferrum_udpsocket_pool_item *next;
} ferrum_udpsocket_pool_item_t;

typedef struct ferrum_udpsocket_pool {
  base_object();
  int32_t max_count;
  int32_t in_use_count;
  rebrick_udpsocket_callbacks_t callbacks;
  ferrum_udpsocket_pool_item_t *sockets;
} ferrum_udpsocket_pool_t;

int32_t ferrum_udpsocket_pool_new(ferrum_udpsocket_pool_t **pool, uint16_t max_sockets);
int32_t ferrum_udpsocket_pool_destroy(ferrum_udpsocket_pool_t *pool);
int32_t ferrum_udpsocket_pool_get(ferrum_udpsocket_pool_t *pool, rebrick_udpsocket_t **udp_socket, const rebrick_sockaddr_t *bind_addr, const rebrick_udpsocket_callbacks_t *udp_callback, uint8_t *is_from_cache);
int32_t ferrum_udpsocket_pool_set(ferrum_udpsocket_pool_t *pool, rebrick_udpsocket_t *udp_socket);

#endif