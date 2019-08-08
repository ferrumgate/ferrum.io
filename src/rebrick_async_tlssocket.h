#ifndef __REBRICK_ASYNC_TLSSOCKET_H__
#define __REBRICK_ASYNC_TLSSOCKET_H__

#include "rebrick_tls.h"
#include "rebrick_async_tcpsocket.h"
#include "rebrick_buffer.h"

/*
public_ typedef struct rebrick_pending_bytes{
    base_object();
    rebrick_buffer_t *buffer;
    struct rebrick_pending_bytes *prev,*next;
}rebrick_pending_bytes_t; */


public_ typedef struct rebrick_async_tlssocket
{
    base_tcp_socket();
    private_ const rebrick_tls_context_t *tls_context;
    private_ rebrick_tls_ssl_t *tls;
    private_ rebrick_after_connection_accepted_callback_t override_after_connection_accepted;
    private_ rebrick_after_connection_closed_callback_t override_after_connection_closed;
    private_ rebrick_after_data_received_callback_t override_after_data_received;
    private_ rebrick_after_data_sended_callback_t   override_after_data_sended;
    private_ void *override_callback_data;

    private_ rebrick_buffer_t *pending_write_list;
    private_ rebrick_buffer_t *pending_read_list;
    private_ int32_t called_override_after_connection_accepted;



} rebrick_async_tlssocket_t;

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
int32_t rebrick_async_tlssocket_new(rebrick_async_tlssocket_t **socket, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient);

int32_t rebrick_async_tlssocket_destroy(rebrick_async_tlssocket_t *socket);
int32_t rebrick_async_tlssocket_send(rebrick_async_tlssocket_t *socket, char *buffer, size_t len, void *aftersend_data);
#endif