#ifndef __REBRICK_ASYNC_TCPSOCKET_H__
#define __REBRICK_ASYNC_TCPSOCKET_H__


#include "rebrick_async_socket.h"





typedef struct rebrick_async_tcpsocket
{
    base_class();
    public void *data;


}rebrick_async_tcpsocket_t;

typedef int32_t (*rebrick_after_connection_accepted_callback_t)(void *callback_data,const struct sockaddr *addr,rebrick_async_tcpsocket_t *client_handle);
typedef int32_t (*rebrick_after_connection_closed_callback_t)(void *callback_data);

/**
 * @brief
 *
 * @param socket socket pointer
 * @param bind_addr bind address and port
 * @param dst_addr destination address and port, if port is zero then only listening socket opens
 * @param callback_data, callback data parameter for every callback
 * @param after_data_received data received callback
 * @param after_data_sended
 * @return int32_t
 */
int32_t rebrick_async_tcpsocket_new(rebrick_async_tcpsocket_t **socket,rebrick_sockaddr_t addr,void *callback_data,
rebrick_after_connection_accepted_callback_t after_connection_accepted,
rebrick_after_connection_closed_callback_t after_connection_closed,
rebrick_after_data_received_callback_t after_data_received,
rebrick_after_data_sended_callback_t after_data_sended,int32_t backlog_or_isclient);

int32_t rebrick_async_tcpsocket_destroy(rebrick_async_tcpsocket_t *socket);
int32_t rebrick_async_tcpsocket_send(rebrick_async_tcpsocket_t *socket, char *buffer,size_t len,void *aftersend_data);


#endif