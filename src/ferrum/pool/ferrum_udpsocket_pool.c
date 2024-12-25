#include "ferrum_udpsocket_pool.h"

static int32_t create_udp_socket(ferrum_udpsocket_pool_t *pool, rebrick_udpsocket_t **socket, const rebrick_sockaddr_t *bind_addr, const rebrick_udpsocket_callbacks_t *udp_callback) {

  rebrick_udpsocket_t *udp_socket;
  int32_t result = rebrick_udpsocket_new(&udp_socket, bind_addr, udp_callback);
  if (result) {
    rebrick_log_error("pool udp socket create failed\n");
    return result;
  }

  udp_socket->pool = pool;
  *socket = udp_socket;
  return FERRUM_SUCCESS;
}

int32_t ferrum_udpsocket_pool_new(ferrum_udpsocket_pool_t **pool, uint16_t max_udp_sockets) {
  ferrum_udpsocket_pool_t *tmp = new1(ferrum_udpsocket_pool_t);
  constructor(tmp, ferrum_udpsocket_pool_t);
  tmp->max_count = max_udp_sockets;

  *pool = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_udpsocket_pool_destroy(ferrum_udpsocket_pool_t *pool) {
  if (pool) {
    ferrum_udpsocket_pool_item_t *el, *tmp;
    DL_FOREACH_SAFE(pool->sockets, el, tmp) {
      DL_DELETE(pool->sockets, el);
      el->socket->pool = NULL;
      el->socket->is_in_pool = FALSE;
      rebrick_udpsocket_destroy(el->socket);
      rebrick_free(el);
    }
    rebrick_free(pool);
  }
  return FERRUM_SUCCESS;
}
int32_t ferrum_udpsocket_pool_get(ferrum_udpsocket_pool_t *pool, rebrick_udpsocket_t **udp_socket, const rebrick_sockaddr_t *bind_addr, const rebrick_udpsocket_callbacks_t *udp_callback, uint8_t *is_from_cache) {
  if (pool->max_count == pool->in_use_count) {
    rebrick_log_error("udp socket pool reached max\n");
    return FERRUM_ERR_POOL_REACHED_MAX;
  }
  *is_from_cache = FALSE;
  *udp_socket = NULL;
  if (pool->sockets) {
    ferrum_udpsocket_pool_item_t *item = pool->sockets;
    *udp_socket = item->socket;
    (*udp_socket)->is_in_pool = FALSE;
    DL_DELETE(pool->sockets, pool->sockets);
    pool->in_use_count++;
    rebrick_free(item);
    rebrick_log_debug("getting socket from udp socket pool count: %d\n", pool->in_use_count);
    *is_from_cache = TRUE;
    return FERRUM_SUCCESS;
  }

  int32_t result = create_udp_socket(pool, udp_socket, bind_addr, udp_callback);
  if (result) {
    return result;
  }
  (*udp_socket)->is_in_pool = FALSE;
  pool->in_use_count++;
  rebrick_log_debug("getting socket from udp socket pool\n");
  return FERRUM_SUCCESS;
}
int32_t ferrum_udpsocket_pool_set(ferrum_udpsocket_pool_t *pool, rebrick_udpsocket_t *udp_socket) {
  if (udp_socket->is_in_pool) {
    rebrick_log_debug("socket is already in udp socket pool\n");
    return FERRUM_SUCCESS;
  }

  ferrum_udpsocket_pool_item_t *item = new1(ferrum_udpsocket_pool_item_t);
  constructor(item, ferrum_udpsocket_pool_item_t);
  item->socket = udp_socket;
  DL_APPEND(pool->sockets, item);
  udp_socket->is_in_pool = TRUE;
  pool->in_use_count--;
  rebrick_log_debug("socket is back to udp socket pool count: %d\n", pool->in_use_count);
  return FERRUM_SUCCESS;
}