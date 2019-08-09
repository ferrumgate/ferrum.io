#ifndef __REBRICK_ASYNC_SOCKET_H__
#define __REBRICK_ASYNC_SOCKET_H__
#include "rebrick_common.h"
#include "rebrick_log.h"
#include "./lib/utlist.h"

struct rebrick_async_socket;
/**
 * @brief after data received, this function is called
 * @param socket which socket used
 * @param callback_data , this parameter is setted when called rebrick_async_xxxsocket_new(......,callback_data,.......)
 * @param addr from which addr
 * @param buffer data
 * @param len buffer lenght
 */
typedef int32_t (*rebrick_after_data_received_callback_t)(struct rebrick_async_socket *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len);


/**
 * @brief after data sended this function is called
 * @param socket which socket used
 * @param callback_data,  this parameter is setted when called rebrick_async_xxxsocket_new(......,callback_data,.......)
 * @param after_sendata,  this parameters will be sended to this function
 * @param status, result of operation, if status=0 SUCCESS otherwise ERROR
 */
typedef int32_t (*rebrick_after_data_sended_callback_t)(struct rebrick_async_socket *socket, void *callback_data, void *after_senddata, int status);

#define base_socket() \
    base_object();                    \
    public_ readonly_ char bind_ip[REBRICK_IP_STR_LEN];\
    public_ readonly_ char bind_port[REBRICK_PORT_STR_LEN];\
                                \
    protected_ uv_loop_t *loop;\
    protected_ union{\
        uv_tcp_t tcp;\
        uv_udp_t udp;\
    }handle;\
    public_ readonly_ rebrick_sockaddr_t bind_addr;\
    protected_ rebrick_after_data_received_callback_t after_data_received;\
    protected_ rebrick_after_data_sended_callback_t after_data_sended;\
    protected_ void *callback_data;

public_ typedef struct rebrick_async_socket{
    base_socket();
}rebrick_async_socket_t;

#define cast_to_base_socket(x)  cast((x),rebrick_async_socket_t*)


#endif