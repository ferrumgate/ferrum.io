
#ifndef __REBRICK_HTTPSOCKET_H__
#define __REBRICK_HTTPSOCKET_H__

#include "rebrick_http.h"

typedef enum {
  http2,
  websocket,
  websocket2
} rebrick_upgrade_socket_type_t;

struct rebrick_httpsocket;
/**
 * @brief after a http header parsed, executes this callback
 * @param socket, which socket
 * @param header received header
 * @param status, result of parsing, parsed successfully or error
 */
typedef void (*rebrick_httpsocket_on_http_header_read_callback_t)(struct rebrick_socket *socket, int32_t stream_id, void *callback_data, rebrick_http_header_t *header);

/**
 * @brief after header parsed finished, when body data starts to come,
 * this callback trigger,this is a synonym
 * @see rebrick_socket_on_read_callback_t
 */
typedef void (*rebrick_httpsocket_on_http_body_read_callback_t)(struct rebrick_socket *socket, int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len);

typedef void (*rebrick_httpsocket_on_socket_upgrade_read_callback_t)(struct rebrick_socket *socket, void *callback_data, rebrick_upgrade_socket_type_t type, void *extra_data);

/**
 * @brief http socket structure
 * allways executes callback when new data arrives
 *
 */
public_ typedef struct rebrick_httpsocket {
  base_ssl_socket();

  private_ rebrick_tcpsocket_on_client_connect_callback_t override_override_on_client_connect;
  private_ rebrick_tcpsocket_on_client_close_callback_t override_override_on_client_close;
  private_ rebrick_socket_on_read_callback_t override_override_on_read;
  private_ rebrick_socket_on_write_callback_t override_override_on_write;
  private_ rebrick_socket_on_error_callback_t override_override_on_error;
  private_ rebrick_httpsocket_on_http_header_read_callback_t on_http_header_read;
  private_ rebrick_httpsocket_on_http_body_read_callback_t on_http_body_read;
  private_ rebrick_httpsocket_on_socket_upgrade_read_callback_t on_socket_upgrade_read;
  private_ rebrick_tls_context_t *override_override_tls_context;
  private_ void *override_override_callback_data;

  public_ readonly_ rebrick_http_header_t *received_header;
  public_ readonly_ rebrick_http_header_t *send_header;

  private_ rebrick_buffer_t *tmp_buffer;
  private_ int32_t is_header_parsed;
  public_ size_t header_len;
  public_ readonly_ size_t content_received_length;

  struct
  {
    struct phr_header headers[REBRICK_HTTP_MAX_HEADERS];
    const char *method, *path;
    int minor_version;
    size_t method_len, path_len, num_headers;
    int32_t status;
    const char *status_msg;
    size_t status_msg_len;
    size_t pos;
  } parsing_params;

} rebrick_httpsocket_t;

#define cast_to_httpsocket(x) cast(x, rebrick_httpsocket_t *)

#define base_httpsocket_callbacks()                                      \
  base_tlssocket_callbacks();                                            \
  rebrick_httpsocket_on_http_header_read_callback_t on_http_header_read; \
  rebrick_httpsocket_on_http_body_read_callback_t on_http_body_read;     \
  rebrick_httpsocket_on_socket_upgrade_read_callback_t on_socket_upgrade_read;

typedef struct rebrick_httpsocket_callbacks {
  base_httpsocket_callbacks();
} rebrick_httpsocket_callbacks_t;

#define cast_to_httpsocket_callbacks(x) cast(x, rebrick_httpsocket_callbacks_t *)

int32_t rebrick_httpsocket_new(rebrick_httpsocket_t **socket,
                               const char *sni_pattern_or_name,
                               rebrick_tls_context_t *tls, const rebrick_sockaddr_t *bind_addr,
                               const rebrick_sockaddr_t *peer_addr,
                               int32_t backlog_or_isclient, const rebrick_httpsocket_callbacks_t *callbacks);

int32_t rebrick_httpsocket_init(rebrick_httpsocket_t *socket,
                                const char *sni_pattern_or_name,
                                rebrick_tls_context_t *tls,
                                const rebrick_sockaddr_t *bind_addr,
                                const rebrick_sockaddr_t *peer_addr,
                                int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t create_client,
                                const rebrick_httpsocket_callbacks_t *callbacks);

int32_t rebrick_httpsocket_destroy(rebrick_httpsocket_t *socket);
int32_t rebrick_httpsocket_write(rebrick_httpsocket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);
int32_t rebrick_httpsocket_reset(rebrick_httpsocket_t *socket);
int32_t rebrick_httpsocket_write_header(rebrick_httpsocket_t *socket, int32_t *stream_id, int64_t flags, rebrick_http_header_t *header);
int32_t rebrick_httpsocket_write_body(rebrick_httpsocket_t *socket, int32_t stream_id, int64_t flags, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);

#endif