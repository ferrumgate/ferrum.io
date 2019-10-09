#ifndef __REBRICK_WEBSOCKET_H__
#define __REBRICK_WEBSOCKET_H__


#include "../socket/rebrick_tlssocket.h"


public_ typedef struct rebrick_websocket
{

    base_ssl_socket();



}rebrick_websocket_t;


int32_t rebrick_websocket_new(rebrick_websocket_t **socket,const char *sni, rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured);


int32_t rebrick_websocket_init(rebrick_websocket_t *socket,const char *sni, rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured,
                                    rebrick_tcpsocket_create_client_t create_client);

int32_t rebrick_websocket_destroy(rebrick_websocket_t *socket);
int32_t rebrick_websocket_send(rebrick_websocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);

#endif