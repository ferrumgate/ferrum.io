#ifndef __REBRICK_ASYNC_TCPSOCKET_H__
#define __REBRICK_ASYNC_TCPSOCKET_H__

#include "rebrick_async_socket.h"

struct rebrick_async_tcpsocket;

/**
 * @brief function declaration after server socket or client socket connection callback
 * @params socket which socket used
 * @params callback_data data when used with @see rebrick_async_tcpsocket_new(...)
 * @params addr
 * @params client_handle if client_handle is null then error occured
 */
typedef int32_t (*rebrick_after_connection_accepted_callback_t)(struct rebrick_async_socket *socket, void *callback_data, const struct sockaddr *addr, void *client_handle,int status);

/**
 * @brief after socket is closed this function is called
 * @param socket which socket is used
 * @param callback_data , data when used with @see rebrick_async_tcpsocket_new(...);
 */
typedef int32_t (*rebrick_after_connection_closed_callback_t)(struct rebrick_async_socket *socket, void *callback_data);


/**
 * @brief inheritance yapan sınıflar için kullanılacak child connection create method
 *
 */
typedef struct rebrick_async_tcpsocket* (*rebrick_async_tcpsocket_create_client_t)();


#define base_tcp_socket()  \
    base_socket();\
    private_ rebrick_after_connection_accepted_callback_t after_connection_accepted;\
    private_ rebrick_after_connection_closed_callback_t after_connection_closed;\
    private_ struct rebrick_async_tcpsocket *clients; \
    private_ struct rebrick_async_tcpsocket *prev; \
    private_ struct rebrick_async_tcpsocket *next; \
    public_ readonly_ struct rebrick_async_tcpsocket *parent_socket;\
    private_ rebrick_async_tcpsocket_create_client_t create_client;



public_ typedef struct rebrick_async_tcpsocket
{
    base_tcp_socket();

} rebrick_async_tcpsocket_t;

#define cast_to_tcp_socket(x)  cast((x),rebrick_async_tcpsocket_t*)

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
int32_t rebrick_async_tcpsocket_new(rebrick_async_tcpsocket_t **socket, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient);



int32_t rebrick_async_tcpsocket_init(rebrick_async_tcpsocket_t *socket, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended,
                                    int32_t backlog_or_isclient,rebrick_async_tcpsocket_create_client_t create_client);


int32_t rebrick_async_tcpsocket_destroy(rebrick_async_tcpsocket_t *socket);
int32_t rebrick_async_tcpsocket_send(rebrick_async_tcpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);

#endif