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
typedef void (*rebrick_on_connection_accepted_callback_t)(struct rebrick_socket *socket, void *callback_data, const struct sockaddr *addr, void *client_handle,int status);

/**
 * @brief after socket is closed this function is called
 * @param socket which socket is used
 * @param callback_data , data when used with @see rebrick_tcpsocket_new(...);
 */
typedef void (*rebrick_on_connection_closed_callback_t)(struct rebrick_socket *socket, void *callback_data);


/**
 * @brief inheritance yapan sınıflar için kullanılacak child connection create method
 *
 */
typedef struct rebrick_tcpsocket* (*rebrick_tcpsocket_create_client_t)();


#define base_tcp_socket()  \
    base_socket();\
    private_ rebrick_on_connection_accepted_callback_t on_connection_accepted;\
    private_ rebrick_on_connection_closed_callback_t on_connection_closed;\
    private_ struct rebrick_tcpsocket *clients; \
    private_ struct rebrick_tcpsocket *prev; \
    private_ struct rebrick_tcpsocket *next; \
    public_ readonly_ struct rebrick_tcpsocket *parent_socket;\
    private_ rebrick_tcpsocket_create_client_t create_client;



public_ typedef struct rebrick_tcpsocket
{
    base_tcp_socket();

} rebrick_tcpsocket_t;

#define cast_to_tcp_socket(x)  cast((x),rebrick_tcpsocket_t*)

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
int32_t rebrick_tcpsocket_new(rebrick_tcpsocket_t **socket, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient);


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
 * @param create_client, createa a client instance that must be easily destory with free(ptr), no other function like destory(ptr)
 * @return int32_t
 */

int32_t rebrick_tcpsocket_init(rebrick_tcpsocket_t *socket, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured,
                                    int32_t backlog_or_isclient,rebrick_tcpsocket_create_client_t create_client);


int32_t rebrick_tcpsocket_destroy(rebrick_tcpsocket_t *socket);
int32_t rebrick_tcpsocket_send(rebrick_tcpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);

#endif