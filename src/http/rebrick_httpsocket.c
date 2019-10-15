#include "rebrick_httpsocket.h"

static void local_on_error_occured_callback(rebrick_socket_t *ssocket, void *callbackdata, int error)
{
    unused(ssocket);
    unused(callbackdata);
    unused(error);
    rebrick_httpsocket_t *httpsocket = cast(ssocket, rebrick_httpsocket_t *);
    if (httpsocket)
    {
        if (httpsocket->override_override_on_error_occured)
            httpsocket->override_override_on_error_occured(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, error);
    }


}

static void local_on_connection_accepted_callback(rebrick_socket_t *ssocket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{

    unused(ssocket);
    unused(callback_data);
    unused(addr);
    unused(client_handle);

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_httpsocket_t *httpsocket = cast(ssocket, rebrick_httpsocket_t *);
    if (httpsocket)
    {
        if (httpsocket->override_override_on_connection_accepted)
            httpsocket->override_override_on_connection_accepted(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr, client_handle);
    }


}

static void local_on_connection_closed_callback(rebrick_socket_t *ssocket, void *callback_data)
{
    unused(ssocket);
    unused(callback_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_httpsocket_t *httpsocket = cast(ssocket, rebrick_httpsocket_t *);

    if (httpsocket)
    {
        if (httpsocket->tmp_buffer)
            rebrick_buffer_destroy(httpsocket->tmp_buffer);

        if (httpsocket->header)
            rebrick_http_header_destroy(httpsocket->header);

        if (httpsocket->override_override_on_connection_closed)
            httpsocket->override_override_on_connection_closed(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data);
    }


}

static void local_on_data_sended_callback(rebrick_socket_t *ssocket, void *callback_data, void *source)
{
    unused(ssocket);
    unused(callback_data);
    unused(source);

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_httpsocket_t *httpsocket = cast(ssocket, rebrick_httpsocket_t *);

    if (httpsocket)
    {

        if (httpsocket->override_override_on_data_sended)
            httpsocket->override_override_on_data_sended(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, source);
    }

}

#define call_on_error(httpsocket, error)                                                                                                     \
    if (httpsocket->override_override_on_error_occured)                                                                                      \
    {                                                                                                                                        \
        httpsocket->override_override_on_error_occured(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, error); \
    }

static void local_after_data_received_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
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

    if (!socket){
        rebrick_log_fatal("socket argument is null\n");
        return ;
    }

    rebrick_httpsocket_t *httpsocket = cast_to_http_socket(socket);

    if (httpsocket->override_override_on_data_received)
        httpsocket->override_override_on_data_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr, buffer, len);

    if (httpsocket->is_header_parsed)
    {
        if (httpsocket->on_http_body_received)
        {
            httpsocket->content_received_length += len;
            httpsocket->on_http_body_received(cast_to_base_socket(httpsocket),0, httpsocket->override_override_callback_data, addr,
                                              buffer, len);
        }
    }
    else
    {

        if (httpsocket->tmp_buffer)
        {
            result = rebrick_buffer_add(httpsocket->tmp_buffer, cast(buffer, uint8_t *), len);
        }
        else
        {
            result = rebrick_buffer_new(&httpsocket->tmp_buffer, cast(buffer, uint8_t *), len, REBRICK_HTTP_BUFFER_MALLOC);
        }

        if (result < 0)
        {

            call_on_error(httpsocket, result);
            return;
        }

        httpsocket->parsing_params.num_headers = sizeof(httpsocket->parsing_params.headers) / sizeof(httpsocket->parsing_params.headers[0]);
        int32_t pret = 0;
        int32_t is_request_header = FALSE;

        //check request or response
        if (httpsocket->tmp_buffer->len < 5)
        {
            rebrick_log_fatal("httpsocket tmp buffer len is<5\n");
            return ;
        }
        //small lower buffer of started data

        if ((httpsocket->header == NULL && strncasecmp(cast(httpsocket->tmp_buffer->buf, const char *), "HTTP/", 5) == 0) || !httpsocket->header->is_request)
        {
            pret = phr_parse_response(cast(httpsocket->tmp_buffer->buf, const char *),
                                      httpsocket->tmp_buffer->len,
                                      &httpsocket->parsing_params.minor_version,
                                      &httpsocket->parsing_params.status,
                                      &httpsocket->parsing_params.status_msg,
                                      &httpsocket->parsing_params.status_msg_len,
                                      httpsocket->parsing_params.headers,
                                      &httpsocket->parsing_params.num_headers, httpsocket->parsing_params.pos);
            is_request_header = FALSE;
        }
        else
        {
            is_request_header = TRUE;
            pret = phr_parse_request(cast(httpsocket->tmp_buffer->buf, const char *),
                                     httpsocket->tmp_buffer->len,
                                     &httpsocket->parsing_params.method, &httpsocket->parsing_params.method_len,
                                     &httpsocket->parsing_params.path, &httpsocket->parsing_params.path_len,
                                     &httpsocket->parsing_params.minor_version,
                                     httpsocket->parsing_params.headers, &httpsocket->parsing_params.num_headers, httpsocket->parsing_params.pos);
        }

        if (pret == -1)
        {
            rebrick_log_error("header parse error\n");
            call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
            return ;
        }

        if (httpsocket->tmp_buffer->len >= REBRICK_HTTP_MAX_HEADER_LEN)
        {
            rebrick_log_error("http max header len exceed\n");
            call_on_error(httpsocket, REBRICK_HTTP_MAX_HEADER_LEN);
            return ;
        }
        httpsocket->parsing_params.pos = pret;
        if (pret > 0)
        {
            if (!httpsocket->header)
            {

                if (is_request_header)
                {
                    result = rebrick_http_header_new2(&httpsocket->header,
                                                      httpsocket->parsing_params.method,
                                                      httpsocket->parsing_params.method_len,
                                                      httpsocket->parsing_params.path,
                                                      httpsocket->parsing_params.path_len,
                                                      httpsocket->parsing_params.minor_version == 1 ? 1 : 2,
                                                      httpsocket->parsing_params.minor_version);
                }
                else
                {
                    result = rebrick_http_header_new4(&httpsocket->header,
                                                      httpsocket->parsing_params.status,
                                                      httpsocket->parsing_params.status_msg,
                                                      httpsocket->parsing_params.status_msg_len,
                                                      httpsocket->parsing_params.minor_version == 1 ? 1 : 2,
                                                      httpsocket->parsing_params.minor_version);
                }
                if (result < 0)
                {
                    rebrick_log_error("new header create error\n");
                    call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
                }
            }

            for (size_t i = 0; i < httpsocket->parsing_params.num_headers; ++i)
            {
                struct phr_header *header = httpsocket->parsing_params.headers + i;
                result = rebrick_http_header_add_header2(httpsocket->header, header->name, header->name_len, header->value, header->value_len);
                if (result < 0)
                {
                    rebrick_log_error("adding header to headers error\n");
                    call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
                }
            }

            httpsocket->is_header_parsed = TRUE;
            httpsocket->header_len = pret;

            //http header finished
            if (httpsocket->on_http_header_received)
                httpsocket->on_http_header_received(cast_to_base_socket(httpsocket),0, httpsocket->override_override_callback_data, httpsocket->header);
            //if there is data after header parsed in buffer
            //call on_http_body
            if (cast(httpsocket->tmp_buffer->len, ssize_t) > pret)
            {
                if (httpsocket->on_http_body_received)
                {
                    size_t length_remain = httpsocket->tmp_buffer->len - pret;
                    size_t offset = httpsocket->tmp_buffer->len - length_remain;
                    httpsocket->content_received_length += length_remain;
                    httpsocket->on_http_body_received(cast_to_base_socket(httpsocket),0, httpsocket->override_override_callback_data, addr,
                                                      httpsocket->tmp_buffer->buf + offset, length_remain);
                }
            }
        }
    }


}

static struct rebrick_tcpsocket *local_create_client()
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_httpsocket_t *client = new (rebrick_httpsocket_t);
    constructor(client, rebrick_httpsocket_t);
    return cast(client, rebrick_tcpsocket_t *);
}

int32_t rebrick_httpsocket_init(rebrick_httpsocket_t *httpsocket,const char *sni_pattern_or_name, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                rebrick_on_connection_closed_callback_t on_connection_closed,
                                rebrick_on_data_received_callback_t on_data_received,
                                rebrick_on_data_sended_callback_t on_data_sended,
                                rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                rebrick_on_http_header_received_callback_t on_http_header_received,
                                rebrick_on_http_body_received_callback_t on_http_body_received, rebrick_tcpsocket_create_client_t create_client)

{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    httpsocket->override_override_tls_context = tls_context;
    if (tls_context)
    {
        result = rebrick_tlssocket_init(cast_to_tls_socket(httpsocket),sni_pattern_or_name, tls_context, addr, NULL, local_on_connection_accepted_callback, local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback, backlog_or_isclient, create_client);
    }
    else
    {
        result = rebrick_tcpsocket_init(cast_to_tcp_socket(httpsocket), addr, NULL, local_on_connection_accepted_callback, local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback, backlog_or_isclient, create_client);
    }
    if (result < 0)
    {
        rebrick_log_error("http socket creation failed with eror:%d\n", result);
        return result;
    }
    httpsocket->override_override_on_connection_accepted = on_connection_accepted;
    httpsocket->override_override_on_connection_closed = on_connection_closed;
    httpsocket->override_override_on_data_received = on_data_received;
    httpsocket->override_override_on_data_sended = on_data_sended;
    httpsocket->override_override_on_error_occured = on_error_occured;
    httpsocket->override_override_callback_data = callback_data;
    httpsocket->on_http_header_received = on_http_header_received;
    httpsocket->on_http_body_received = on_http_body_received;

    return REBRICK_SUCCESS;
}

int32_t rebrick_httpsocket_new(rebrick_httpsocket_t **socket,const char *sni_pattern_or_name, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                               rebrick_on_connection_accepted_callback_t on_connection_accepted,
                               rebrick_on_connection_closed_callback_t on_connection_closed,
                               rebrick_on_data_received_callback_t on_data_received,
                               rebrick_on_data_sended_callback_t on_data_sended,
                               rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                               rebrick_on_http_header_received_callback_t on_http_header_received,
                               rebrick_on_http_body_received_callback_t on_http_body_received)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    rebrick_httpsocket_t *httpsocket = new (rebrick_httpsocket_t);
    constructor(httpsocket, rebrick_httpsocket_t);

    result = rebrick_httpsocket_init(httpsocket,sni_pattern_or_name, tls_context, addr,
                                     callback_data, on_connection_accepted, on_connection_closed, on_data_received, on_data_sended, on_error_occured, backlog_or_isclient,
                                     on_http_header_received, on_http_body_received, local_create_client);
    if (result < 0)
    {
        rebrick_log_error("http socket init failed with error:%d\n", result);
        free(httpsocket);
        return result;
    }
    *socket = httpsocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_httpsocket_destroy(rebrick_httpsocket_t *socket)
{
    unused(socket);
    if (socket)
    {
        if (socket->override_override_tls_context)
        {
            return rebrick_tlssocket_destroy(cast_to_tls_socket(socket));
        }
        else
        {
            return rebrick_tcpsocket_destroy(cast_to_tcp_socket(socket));
        }
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_httpsocket_reset(rebrick_httpsocket_t *socket)
{
    if (socket)
    {
        if (socket->tmp_buffer)
            rebrick_buffer_destroy(socket->tmp_buffer);
        socket->tmp_buffer = NULL;

        if (socket->header)
            rebrick_http_header_destroy(socket->header);
        socket->header = NULL;
        socket->is_header_parsed = FALSE;
        socket->content_received_length = 0;
        socket->header_len=0;
    }

    return REBRICK_SUCCESS;
}
int32_t rebrick_httpsocket_send(rebrick_httpsocket_t *socket,int32_t stream_id, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{
    unused(socket);
    unused(buffer);
    unused(len);
    unused(cleanfunc);
    //not using, with http1.1 only for http2
    unused(stream_id);
    if (!socket || !buffer | !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (socket->tls)
        return rebrick_tlssocket_send(cast_to_tls_socket(socket), buffer, len, cleanfunc);
    return rebrick_tcpsocket_send(cast_to_tcp_socket(socket), buffer, len, cleanfunc);
}

static void clean_buffer(void *buffer){
    rebrick_buffer_t *tmp=cast(buffer,rebrick_buffer_t *);
    if(tmp){
        rebrick_buffer_destroy(tmp);
    }
}

int32_t rebrick_httpsocket_send_header(rebrick_httpsocket_t *socket,int32_t stream_id,rebrick_http_header_t *header){
    unused(socket);
    int32_t result;
    char current_time_str[32] = {0};
    unused(current_time_str);
    if(!socket || !header)
    return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_buffer_t *buffer;
    result=rebrick_http_header_to_buffer(header,&buffer);
    if(result<0){
        rebrick_log_error("http sending header failed with error:%d\n",result);
        return result;
    }
    rebrick_clean_func_t cleanfunc={.func=clean_buffer,.ptr=buffer};
    return rebrick_httpsocket_send(socket,stream_id,buffer->buf,buffer->len,cleanfunc);

}
int32_t rebrick_httpsocket_send_body(rebrick_httpsocket_t *socket,int32_t stream_id, uint8_t *buffer,size_t len,rebrick_clean_func_t cleanfunc);