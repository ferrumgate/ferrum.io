#ifndef __REBRICK_WEBSOCKET_H__
#define __REBRICK_WEBSOCKET_H__

#include "../socket/rebrick_tlssocket.h"

public_ typedef struct rebrick_websocket {

  base_ssl_socket();

} rebrick_websocket_t;

int32_t rebrick_websocket_new(rebrick_websocket_t **socket, const char *sni, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr, void *callback_data,
                              rebrick_tcpsocket_on_client_connect_callback_t on_connection_accepted,
                              rebrick_tcpsocket_on_client_close_callback_t on_connection_closed,
                              rebrick_socket_on_read_callback_t on_data_received,
                              rebrick_socket_on_write_callback_t on_data_sended,
                              rebrick_socket_on_error_callback_t on_error_occured);

int32_t rebrick_websocket_init(rebrick_websocket_t *socket, const char *sni, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr, void *callback_data,
                               rebrick_tcpsocket_on_client_connect_callback_t on_connection_accepted,
                               rebrick_tcpsocket_on_client_close_callback_t on_connection_closed,
                               rebrick_socket_on_read_callback_t on_data_received,
                               rebrick_socket_on_write_callback_t on_data_sended,
                               rebrick_socket_on_error_callback_t on_error_occured,
                               rebrick_tcpsocket_create_client_t create_client);

int32_t rebrick_websocket_destroy(rebrick_websocket_t *socket);
int32_t rebrick_websocket_send(rebrick_websocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);

#endif