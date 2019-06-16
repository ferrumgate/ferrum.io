#ifndef __REBRICK_ASYNC_SOCKET_H__
#define __REBRICK_ASYNC_SOCKET_H__
#include "rebrick_common.h"
#include "rebrick_log.h"
#include "./lib/utlist.h"

typedef int32_t (*rebrick_after_data_received_callback_t)(void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len);
typedef int32_t (*rebrick_after_data_sended_callback_t)(void *callback_data, void *after_senddata, int status);

#define base_socket() \
                        \
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
    base_class();
    base_socket();
}rebrick_async_socket_t;


#endif