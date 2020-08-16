#ifndef __REBRICK_TCPSOCKET_H__
#define __REBRICK_TCPSOCKET_H__

#include "rebrick_socket.h"

struct rebrick_tcpsocket;

/**
 * @brief function declaration after server socket or client socket connection callback
 * @params socket which socket used
 * @params callback_data data when used with @see rebrick_tcpsocket_new(...)
 * @params addr
 * @params client_handle if client_handle is null then error occured
 */
typedef void (*rebrick_tcpsocket_on_accept_callback_t)(struct rebrick_socket *socket, void *callback_data, const struct sockaddr *addr, void *client_handle);

/**
 * @brief after socket is closed this function is called
 * @param socket which socket is used
 * @param callback_data , data when used with @see rebrick_tcpsocket_new(...);
 */
typedef void (*rebrick_tcpsocket_on_close_callback_t)(struct rebrick_socket *socket, void *callback_data);

/**
 * @brief inheritance yapan sınıflar için kullanılacak child connection create method
 *
 */
typedef struct rebrick_tcpsocket *(*rebrick_tcpsocket_create_client_t)();

#define base_tcp_socket()                                               \
    base_socket();                                                      \
    private_ rebrick_tcpsocket_on_accept_callback_t on_accept;          \
    private_ rebrick_tcpsocket_on_close_callback_t on_connection_close; \
    private_ struct rebrick_tcpsocket *clients;                         \
    private_ struct rebrick_tcpsocket *prev;                            \
    private_ struct rebrick_tcpsocket *next;                            \
    public_ readonly_ struct rebrick_tcpsocket *parent_socket;          \
    public_ readonly_ int32_t is_server;                                \
    private_ rebrick_tcpsocket_create_client_t create_client;

public_ typedef struct rebrick_tcpsocket
{
    base_tcp_socket();

} rebrick_tcpsocket_t;

#define cast_to_tcpsocket(x) cast((x), rebrick_tcpsocket_t *)

#define base_tcpsocket_callbacks()                               \
    base_callbacks();                                            \
    protected_ rebrick_tcpsocket_on_accept_callback_t on_accept; \
    protected_ rebrick_tcpsocket_on_close_callback_t on_connection_close;

public_ typedef struct rebrick_tcpsocket_callbacks
{
    base_tcpsocket_callbacks();
} rebrick_tcpsocket_callbacks_t;

#define cast_to_tcpsocket_callbacks(x) cast((x), rebrick_tcpsocket_callbacks_t *)

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
int32_t rebrick_tcpsocket_new(rebrick_tcpsocket_t **socket, rebrick_sockaddr_t addr, int32_t backlog_or_isclient, const rebrick_tcpsocket_callbacks_t *callbacks);

/**
 * @brief
 *
 * @param socket
 * @param addr
 * @param callback_data
 * @param on_connection_accepted
 * @param on_connection_closed
 * @param on_data_received
 * @param on_data_sended
 * @param on_error_occured
 * @param backlog_or_isclient
 * @param create_client, createa a client instance that must be easily destory with rebrick_free(ptr), no other function like destory(ptr)
 * @return int32_t
 */

int32_t rebrick_tcpsocket_init(rebrick_tcpsocket_t *socket, rebrick_sockaddr_t addr,
                               int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t create_client,
                               const rebrick_tcpsocket_callbacks_t *callbacks);
int32_t rebrick_tcpsocket_nodelay(rebrick_tcpsocket_t *socket, int enable);
int32_t rebrick_tcpsocket_keepalive(rebrick_tcpsocket_t *socket, int enable, int delay);
int32_t rebrick_tcpsocket_simultaneous_accepts(rebrick_tcpsocket_t *socket, int enable);

int32_t rebrick_tcpsocket_destroy(rebrick_tcpsocket_t *socket);
int32_t rebrick_tcpsocket_write(rebrick_tcpsocket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);

#endif