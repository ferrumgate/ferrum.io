#ifndef __REBRICK_UDPSOCKET_H__
#define __REBRICK_UDPSOCKET_H__

#include "rebrick_socket.h"

public_ typedef struct rebrick_udpsocket
{
    base_socket();

} rebrick_udpsocket_t;

#define cast_to_udpsocket(x) cast((x), rebrick_udpsocket_t *)

public_ typedef struct rebrick_udpsocket_callbacks
{
    base_callbacks();
} rebrick_udpsocket_callbacks_t;

#define cast_to_udpsocket_callbacks(x) cast(x, rebrick_udpsocket_callback_t *)

/**
 * @brief
 *
 * @param socket socket pointer
 * @param bind_addr bind address and port
 * @param dst_addr destination address and port, if port is zero then only listening socket opens
 * @param callback_data, callback data parameter for every callback
 * @param on_data_received data received callback
 * @param on_data_sended
 * @return int32_t
 */
int32_t rebrick_udpsocket_new(rebrick_udpsocket_t **socket,
                              const rebrick_sockaddr_t *bind_addr,
                              const rebrick_udpsocket_callbacks_t *callbacks);
int32_t rebrick_udpsocket_destroy(rebrick_udpsocket_t *socket);
int32_t rebrick_udpsocket_write(rebrick_udpsocket_t *socket, const rebrick_sockaddr_t *dst_addr, uint8_t *buffer, size_t len, rebrick_clean_func_t clean_func);
int32_t rebrick_udpsocket_write_buffer_size(rebrick_udpsocket_t *socket, int32_t *value);
int32_t rebrick_udpsocket_read_buffer_size(rebrick_udpsocket_t *socket, int32_t *value);

#endif