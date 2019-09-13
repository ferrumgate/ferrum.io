
#ifndef __REBRICK_ASYNC_HTTPSOCKET_H__
#define __REBRICK_ASYNC_HTTPSOCKET_H__

#include "rebrick_async_tlssocket.h"
#include "rebrick_buffer.h"



public_ typedef struct rebrick_async_httpsocket
{
    base_ssl_socket();

    private_ rebrick_after_connection_accepted_callback_t override_after_connection_accepted;
    private_ rebrick_after_connection_closed_callback_t override_after_connection_closed;
    private_ rebrick_after_data_received_callback_t override_after_data_received;
    private_ rebrick_after_data_sended_callback_t   override_after_data_sended;
    private_ void *override_callback_data;
    private_ void *private_data;




} rebrick_async_httpsocket_t;

enum rebrick_http_protocol{
    http,
    https
};

#define REBRICK_MAX_HOSTNAME_LEN 1024
#define REBRICK_MAX_URI_LEN 8192

public_ typedef struct rebrick_http_config{
    rebrick_http_protocol http_protocol;
    char host[REBRICK_MAX_HOSTNAME_LEN];
    char uri[REBRICK_MAX_URI_LEN];
}rebrick_http_config_t;

int32_t rebrick_async_httpsocket_new(rebrick_async_httpsocket_t **socket,enum rebrick_http_protocol,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient);
int32_t rebrick_async_httpsocket_destroy(rebrick_async_httpsocket_t *socket);
int32_t rebrick_async_httpsocket_send(rebrick_async_httpsocket_t *socket, char *buffer, size_t len, void *aftersend_data);




#endif