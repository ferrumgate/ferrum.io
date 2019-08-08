#ifndef __REBRICK_ASYNC_UDPSOCKET_H__
#define __REBRICK_ASYNC_UDPSOCKET_H__
#include "rebrick_async_socket.h"

public_ typedef struct rebrick_async_udpsocket
{
    base_socket();


} rebrick_async_udpsocket_t;

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
int32_t rebrick_async_udpsocket_new(rebrick_async_udpsocket_t **socket,
                                    rebrick_sockaddr_t bind_addr,
                                    void *callback_data,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended);
int32_t rebrick_async_udpsocket_destroy(rebrick_async_udpsocket_t *socket);
int32_t rebrick_async_udpsocket_send(rebrick_async_udpsocket_t *socket, rebrick_sockaddr_t *dst_addr, char *buffer, size_t len, void *after_senddata);

#endif