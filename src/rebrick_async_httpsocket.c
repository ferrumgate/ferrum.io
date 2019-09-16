#include "rebrick_async_httpsocket.h"

#define REBRICK_HTTP_BUFFER_MALLOC 8192

static int32_t local_after_connection_accepted_callback(rebrick_async_socket_t *serversocket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{

    unused(serversocket);
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(status);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_async_httpsocket_t *httpsocket = cast(socket, rebrick_async_httpsocket_t *);
    if (httpsocket)
    {
        if (httpsocket->override_override_after_connection_accepted)
            httpsocket->override_override_after_connection_accepted(serversocket, httpsocket->override_override_callback_data, addr, client_handle, status);
    }

    return REBRICK_SUCCESS;
}

static int32_t local_after_connection_closed_callback(rebrick_async_socket_t *socket, void *callback_data)
{
    unused(socket);
    unused(callback_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_async_httpsocket_t *httpsocket = cast(socket, rebrick_async_httpsocket_t *);

    if (httpsocket)
    {

        if (httpsocket->header)
            free(httpsocket->header);

        if (httpsocket->override_override_after_connection_closed)
            httpsocket->override_after_connection_closed(socket, httpsocket->override_override_callback_data);
    }

    return REBRICK_SUCCESS;
}

static int32_t local_after_data_sended_callback(rebrick_async_socket_t *socket, void *callback_data, void *source, int status)
{
    unused(socket);
    unused(callback_data);
    unused(source);
    unused(status);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    return REBRICK_SUCCESS;
}

#define call_received_error(httpsocket,addr,buffer,len) \
    if (httpsocket->override_override_after_data_received) \
        {\
            httpsocket->override_override_after_data_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr, buffer, len);\
        }

static int32_t local_after_data_received_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(socket);
    unused(callback_data);
    unused(addr);
    unused(buffer);
    unused(len);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_async_httpsocket_t *httpsocket = cast_to_http_socket(socket);
    if (len <= 0)
    {

        call_received_error(httpsocket,addr,buffer,len);
        return len;
    }

    if (!httpsocket->is_header_parsed)
    {
        if (httpsocket->tmp_buffer)
            result=rebrick_buffer_add(httpsocket->tmp_buffer, cast(buffer, uint8_t *), len);
        else
        {
            result=rebrick_buffer_new(&httpsocket->tmp_buffer, cast(buffer, uint8_t *), len, REBRICK_HTTP_BUFFER_MALLOC);
        }

        if(result<0){

            call_received_error(httpsocket,addr,NULL,result);
            return result;
        }


        char *tmparray;
        size_t tmparray_len;
        result = rebrick_buffer_to_array(httpsocket->tmp_buffer, &tmparray, &tmparray_len);
        if (result < 0)
        {
           call_received_error(httpsocket,addr,NULL,result);
            return len;
        }


        free(tmparray);
    }

    return REBRICK_SUCCESS;
}

int32_t rebrick_async_httpsocket_init(rebrick_async_httpsocket_t *httpsocket, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                      rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                      rebrick_after_connection_closed_callback_t after_connection_closed,
                                      rebrick_after_data_received_callback_t after_data_received,
                                      rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient,
                                      rebrick_after_http_request_received_callback_t after_http_request_received,
                                      rebrick_after_http_body_received_callback_t after_http_body_received)

{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    httpsocket->override_override_tls_context = tls_context;
    if (tls_context)
    {
        result = rebrick_async_tlssocket_init(cast_to_tls_socket(socket), tls_context, addr, NULL, local_after_connection_accepted_callback, local_after_connection_closed_callback, local_after_data_received_callback, local_after_data_sended_callback, backlog_or_isclient);
    }
    else
    {
        result = rebrick_async_tcpsocket_init(cast_to_tcp_socket(socket), addr, NULL, local_after_connection_accepted_callback, local_after_connection_closed_callback, local_after_data_received_callback, local_after_data_sended_callback, backlog_or_isclient, NULL);
    }
    if (result < 0)
    {
        rebrick_log_error("http socket creation failed with eror:%d\n", result);

        return result;
    }
    httpsocket->override_override_after_connection_accepted = after_connection_accepted;
    httpsocket->override_override_after_connection_closed = after_connection_closed;
    httpsocket->override_after_data_received = after_data_received;
    httpsocket->override_after_data_sended = after_data_sended;
    httpsocket->override_override_callback_data = callback_data;
    httpsocket->after_http_header_received = after_http_request_received;
    httpsocket->after_http_body_received = after_http_body_received;

    return REBRICK_SUCCESS;
}

int32_t rebrick_async_httpsocket_new(rebrick_async_httpsocket_t **socket, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                     rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                     rebrick_after_connection_closed_callback_t after_connection_closed,
                                     rebrick_after_data_received_callback_t after_data_received,
                                     rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient,
                                     rebrick_after_http_request_received_callback_t after_http_request_received,
                                     rebrick_after_http_body_received_callback_t after_http_body_received)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    rebrick_async_httpsocket_t *httpsocket = new (rebrick_async_httpsocket_t);
    constructor(httpsocket, rebrick_async_httpsocket_t);

    result = rebrick_async_httpsocket_init(httpsocket, tls_context, addr,
                                           callback_data, after_connection_accepted, after_connection_closed, after_data_received, after_data_sended, backlog_or_isclient,
                                           after_http_request_received, after_http_body_received);
    if (result < 0)
    {
        rebrick_log_error("http socket init failed with error:%d\n", result);
        free(httpsocket);
        return result;
    }
    *socket = httpsocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_async_httpsocket_destroy(rebrick_async_httpsocket_t *socket)
{
    unused(socket);
    if (socket)
    {
        if (socket->override_override_tls_context)
        {
            rebrick_async_tlssocket_destroy(cast_to_tls_socket(socket));
        }
        else
        {
            rebrick_async_tcpsocket_destroy(cast_to_tcp_socket(socket));
        }
    }
    return REBRICK_SUCCESS;
}
int32_t rebrick_async_httpsocket_send(rebrick_async_httpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{
    unused(socket);
    unused(buffer);
    unused(len);
    unused(cleanfunc);
    if (!socket || !buffer)
        return REBRICK_ERR_BAD_ARGUMENT;

    return REBRICK_SUCCESS;
}