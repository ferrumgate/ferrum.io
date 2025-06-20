
#ifndef __REBRICK_SOCKET_H__
#define __REBRICK_SOCKET_H__

#include "../common/rebrick_common.h"
#include "../common/rebrick_log.h"
#include "../lib/utlist.h"

struct rebrick_socket;
/**
 * @brief after data received, this function is called
 * @param socket which socket used
 * @param callback_data , this parameter is setted when called rebrick_xxxsocket_new(......,callback_data,.......)
 * @param addr from which addr
 * @param buffer data
 * @param len buffer length
 */
typedef void (*rebrick_socket_on_read_callback_t)(struct rebrick_socket *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len);

/**
 * @brief after data written this function is called
 * @param socket which socket used
 * @param callback_data,  this parameter is setted when called rebrick_xxxsocket_new(......,callback_data,.......)
 * @param source,  this parameters used for source detection
 */
typedef void (*rebrick_socket_on_write_callback_t)(struct rebrick_socket *socket, void *callback_data, void *source);

/**
 * @brief after error this function is called
 * @param socket which socket used
 * @param callback_data,  this parameter is setted when called rebrick_xxxsocket_new(......,callback_data,.......)
 * @param error, error code
 */
typedef void (*rebrick_socket_on_error_callback_t)(struct rebrick_socket *socket, void *callback_data, int error);

typedef void (*rebrick_socket_on_close_callback_t)(struct rebrick_socket *socket, void *callback_data);

#define rebrick_clean_func_clone(x, y)                       \
  rebrick_clean_func_t *newptr = new1(rebrick_clean_func_t); \
  constructor(newptr, rebrick_clean_func_t);                 \
  memcpy(newptr, (x), sizeof(rebrick_clean_func_t));         \
  (y) = newptr;

////////////////////////// base socket //////////////////////////////

#define base_callbacks()                                  \
  base_object();                                          \
  protected_ void *callback_data;                         \
  protected_ rebrick_socket_on_read_callback_t on_read;   \
  protected_ rebrick_socket_on_write_callback_t on_write; \
  protected_ rebrick_socket_on_error_callback_t on_error; \
  protected_ rebrick_socket_on_close_callback_t on_close;

typedef struct base_socket_callbacks {
  base_callbacks();
} rebrick_basesocket_callbacks_t;

#define cast_to_base_socket_callbacks(x) cast(((rebrick_basesocket_callbacks_t)(x)))

#define base_socket()                                     \
  base_object();                                          \
  uint64_t id1;                                           \
  uint64_t id2;                                           \
  uint64_t id3;                                           \
  void *data1;                                            \
  void *data2;                                            \
  void *data3;                                            \
  int32_t is_reading_started;                             \
  public_ readonly_ char peer_ip[REBRICK_IP_STR_LEN];     \
  public_ readonly_ char peer_port[REBRICK_PORT_STR_LEN]; \
  public_ readonly_ char bind_ip[REBRICK_IP_STR_LEN];     \
  public_ readonly_ char bind_port[REBRICK_PORT_STR_LEN]; \
                                                          \
  protected_ uv_loop_t *loop;                             \
  protected_ union {                                      \
    uv_tcp_t tcp;                                         \
    uv_udp_t udp;                                         \
  } handle;                                               \
  public_ readonly_ rebrick_sockaddr_t bind_addr;         \
  public_ readonly_ rebrick_sockaddr_t peer_addr;         \
  protected_ rebrick_socket_on_read_callback_t on_read;   \
  protected_ rebrick_socket_on_write_callback_t on_write; \
  protected_ rebrick_socket_on_error_callback_t on_error; \
  protected_ rebrick_socket_on_close_callback_t on_close; \
  protected_ void *callback_data;                         \
  protected_ void *pool;                                  \
  protected_ int8_t is_in_pool;                           \
  protected_ int8_t is_tproxy;

public_ typedef struct rebrick_socket {
  base_socket();
} rebrick_socket_t;

#define cast_to_socket(x) cast((x), rebrick_socket_t *)

#endif