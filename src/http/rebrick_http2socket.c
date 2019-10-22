#include "rebrick_http2socket.h"

#define call_error(httpsocket, error)                   \
    if (httpsocket->override_override_on_error_occured) \
        httpsocket->override_override_on_error_occured(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, error);

#define check_error(httpsocket, result, msg, ret) \
    if (result < 0)                               \
    {                                             \
        rebrick_log_error(msg, result);           \
        call_error(socket, result);               \
        return ret;                               \
    }

#define check_nghttp2_result(result)                                                               \
    if (result < 0)                                                                                \
    {                                                                                              \
        const char *errstr = nghttp2_strerror(result);                                             \
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr); \
        return REBRICK_ERR_HTTP2 + result;                                                         \
    }

#define check_nghttp2_result_call_error(result, socket)                                                                                                   \
    if (result < 0)                                                                                                                                       \
    {                                                                                                                                                     \
        const char *errstr = nghttp2_strerror(result);                                                                                                    \
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);                                                        \
        if (socket->override_override_on_error_occured)                                                                                                   \
            socket->override_override_on_error_occured(cast_to_base_socket(socket), socket->override_override_callback_data, REBRICK_ERR_HTTP2 + result); \
        return;                                                                                                                                           \
    }

static int32_t rebrick_http2stream_new(rebrick_http2stream_t **stream, int32_t stream_id)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_http2stream_t *tmp = new (rebrick_http2stream_t);
    constructor(tmp, rebrick_http2stream_t);
    tmp->stream_id = stream_id;
    *stream = tmp;
    return REBRICK_SUCCESS;
}

static int32_t rebrick_http2stream_destroy(rebrick_http2stream_t *stream)
{
    if (stream)
    {
        if (stream->buffer)
            rebrick_buffer_destroy(stream->buffer);
        if (stream->received_header)
            rebrick_http_header_destroy(stream->received_header);
        if (stream->send_header)
            rebrick_http_header_destroy(stream->send_header);
        free(stream);
    }
    return REBRICK_SUCCESS;
}

static void http2_stream_error(nghttp2_session *session, int32_t stream_id, uint32_t error_code)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_error("http2 stream error with error code:%d\n", error_code);
    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, error_code);
}

static ssize_t http2_on_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(session);
    unused(data);
    unused(length);
    unused(flags);
    unused(user_data);
    int32_t result;
    unused(result);
    rebrick_http2socket_t *httpsocket = cast_to_http2_socket(user_data);
    if (httpsocket)
    {
        rebrick_clean_func_t func = {.func = NULL, .ptr = NULL};
        result = rebrick_http2socket_send(httpsocket, cast(data, uint8_t *), length, func);
        if (result < 0)
        {
            rebrick_log_error("nghttp2 send callback failed with error:%d\n", result);
            call_error(httpsocket, result);
            return -1;
        }
    }
    return length;
}

static int http2_on_before_frame_send_callback(nghttp2_session *session,
                                               const nghttp2_frame *frame, void *user_data)
{
    unused(session);
    unused(frame);
    unused(user_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_debug("before frame send called and stream id is:%d\n", frame->hd.stream_id);

    return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int http2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{

    unused(session);
    unused(stream_id);
    unused(error_code);
    unused(user_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_debug("closing stream\n");
    if (!user_data)
    {
        return 0; //burası bilerek böyle yazıldı.
    }
    rebrick_http2socket_t *socket = cast_to_http2_socket(user_data);
    rebrick_http2stream_t *stream = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, stream);
    if (stream)
    {

        HASH_DEL(socket->streams, stream);
        rebrick_http2stream_destroy(stream);
    }

    // TODO burada on stream close callback çağırsak iyi olur
    return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int http2_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                             int32_t stream_id, const uint8_t *data,
                                             size_t len, void *user_data)
{
    unused(session);
    unused(flags);
    unused(stream_id);
    unused(data);
    unused(len);
    unused(user_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_debug("data chunk received from stream %d\n", stream_id);
    if (!session || !data || !len || !user_data)
        return 0;

    rebrick_http2socket_t *socket = cast_to_http2_socket(user_data);
    if (socket->on_http_body_received)
        socket->on_http_body_received(cast_to_base_socket(socket), stream_id, socket->override_override_callback_data, &socket->bind_addr.base, data, len);

    return 0;
}

static int http2_on_begin_headers_callback(nghttp2_session *session,
                                           const nghttp2_frame *frame,
                                           void *user_data)
{

    unused(session);
    unused(frame);
    unused(user_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_debug("begined headers type:%d\n", frame->hd.type);
    if (!session || !frame || !user_data)
        return 0; //expecially returning 0;

    if (frame->hd.type == NGHTTP2_HEADERS)
    {
        printf("on headers called\n");
        rebrick_http2socket_t *socket = cast_to_http2_socket(user_data);
        //find and delete the previous received header
        rebrick_http2stream_t *stream = NULL;
        int32_t stream_id = frame->hd.stream_id;
        HASH_FIND_INT(socket->streams, &stream_id, stream);

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST)
            if (stream && stream->received_header)
            {
                printf("on headers called received_header\n");
                rebrick_http_header_destroy(stream->received_header);
                stream->received_header = NULL;
            }
    }

    return 0;
}

static int http2_on_header_callback(nghttp2_session *session,
                                    const nghttp2_frame *frame, const uint8_t *name,
                                    size_t namelen, const uint8_t *value,
                                    size_t valuelen, uint8_t flags, void *user_data)
{

    unused(session);
    unused(frame);
    unused(name);
    unused(namelen);
    unused(value);
    unused(valuelen);
    unused(flags);
    unused(user_data);

    char current_time_str[32] = {0};
    unused(current_time_str);

    if (!session || !frame || !user_data)
        return 0; //expecially returning 0;

    rebrick_http2socket_t *socket = cast_to_http2_socket(user_data);
    rebrick_http2stream_t *stream = NULL;
    int32_t result = frame->hd.stream_id;
    HASH_FIND_INT(socket->streams, &result, stream);
    if (!stream)
        return 0; //expecially returning 0;
    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            if (!stream->received_header)
            {
                result = rebrick_http_header_new5(&stream->received_header, frame->headers.cat == NGHTTP2_HCAT_REQUEST, 2, 0);
                check_error(socket, result, "http header create failed with error:%d\n", 0)
            }
            if (!strcasecmp(cast(name, const char *), ":path"))
                memcpy(stream->received_header->path, value, valuelen >= REBRICK_HTTP_MAX_PATH_LEN ? REBRICK_HTTP_MAX_PATH_LEN - 1 : valuelen);
            else if (!strcasecmp(cast(name, const char *), ":method"))
                memcpy(stream->received_header->method, value, valuelen >= REBRICK_HTTP_MAX_METHOD_LEN ? REBRICK_HTTP_MAX_METHOD_LEN - 1 : valuelen);
            else if (!strcasecmp(cast(name, const char *), ":scheme"))
                memcpy(stream->received_header->scheme, value, valuelen >= REBRICK_HTTP_MAX_SCHEME_LEN ? REBRICK_HTTP_MAX_SCHEME_LEN - 1 : valuelen);
            else if (!strcasecmp(cast(name, const char *), ":authority"))
                memcpy(stream->received_header->host, value, valuelen >= REBRICK_HTTP_MAX_HOSTNAME_LEN ? REBRICK_HTTP_MAX_HOSTNAME_LEN - 1 : valuelen);
            else if (!strcasecmp(cast(name, const char *), ":status"))
            {
                stream->received_header->status_code = atoi(cast(value, const char *));
                const char *status_str = Rebrick_HttpStatus_ReasonPhrase(stream->received_header->status_code);
                if (status_str)
                {
                    size_t tmplen = strlen(status_str);
                    memcpy(stream->received_header->status_code_str,status_str, tmplen>=REBRICK_HTTP_MAX_STATUSCODE_LEN?REBRICK_HTTP_MAX_STATUSCODE_LEN-1:tmplen);
                }
            }
            else
            {
                result = rebrick_http_header_add_header2(stream->received_header, name, namelen, value, valuelen);
                check_error(socket, result, "http header create failed with error: %d\n", 0);
            }
        }
    }
    return 0;
}

static int http2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    unused(session);
    unused(frame);
    unused(user_data);
    char current_time_str[32] = {0};
    unused(current_time_str);

    if (!session || !frame || !user_data)
        return 0; //expecially returning 0;

    rebrick_http2socket_t *socket = cast_to_http2_socket(user_data);
    rebrick_http2stream_t *stream = NULL;
    int32_t result = frame->hd.stream_id;
    HASH_FIND_INT(socket->streams, &result, stream);
    if (!stream)
        return 0; //expecially returning 0;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {

            if (socket->on_http_header_received)
                socket->on_http_header_received(cast_to_base_socket(socket), frame->hd.stream_id, socket->override_override_callback_data, stream->received_header);
        }
        break;
    }
    return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{

    nghttp2_session_callbacks_set_send_callback(callbacks, http2_on_send_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, http2_on_stream_close_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, http2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, http2_on_header_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, http2_on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, http2_on_frame_recv_callback);

    nghttp2_session_callbacks_set_before_frame_send_callback(callbacks, http2_on_before_frame_send_callback);
}

static void local_on_error_occured_callback(rebrick_socket_t *ssocket, void *callbackdata, int error)
{
    unused(ssocket);
    unused(callbackdata);
    unused(error);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_http2socket_t *httpsocket = cast_to_http2_socket(ssocket);
    if (httpsocket)
    {
        rebrick_log_error("an error occured with error:%d\n", error);
        call_error(httpsocket, error);
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

    rebrick_http2socket_t *httpsocket = cast_to_http2_socket(ssocket);
    if (!httpsocket)
    {
        rebrick_log_fatal("socket casting to http2socket is null\n");
        return;
    }
    rebrick_http2socket_t *socket = NULL;
    if (httpsocket->is_server)
        socket = cast_to_http2_socket(client_handle);
    else
        socket = httpsocket;

    //copy from server structure
    if (httpsocket->is_server)
    {
        socket->override_override_callback_data = httpsocket->override_override_callback_data;
        socket->override_override_on_connection_accepted = httpsocket->override_override_on_connection_accepted;
        socket->override_override_on_connection_closed = httpsocket->override_override_on_connection_closed;
        socket->override_override_on_data_received = httpsocket->override_override_on_data_received;
        socket->override_override_on_data_sended = httpsocket->override_override_on_data_sended;
        socket->override_override_on_error_occured = httpsocket->override_override_on_error_occured;

        memcpy(&socket->settings, &httpsocket->settings, sizeof(rebrick_http2_socket_settings_t));
    }

    //init http2 structure
    result = nghttp2_session_callbacks_new(&socket->parsing_params.session_callback);
    check_nghttp2_result_call_error(result, socket);

    setup_nghttp2_callbacks(socket->parsing_params.session_callback);

    if (socket->is_server)
        result = nghttp2_session_server_new(&socket->parsing_params.session, socket->parsing_params.session_callback, socket);
    else
        result = nghttp2_session_client_new(&socket->parsing_params.session, socket->parsing_params.session_callback, socket);

    check_nghttp2_result_call_error(result, socket);

    result = nghttp2_submit_settings(socket->parsing_params.session, NGHTTP2_FLAG_NONE, socket->settings.entries, socket->settings.settings_count);
    check_nghttp2_result_call_error(result, socket);
    result = nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result_call_error(result, socket);

    if (socket->override_override_on_connection_accepted)
        socket->override_override_on_connection_accepted(cast_to_base_socket(httpsocket), socket->override_override_callback_data, addr, socket);
}

static void local_on_connection_closed_callback(rebrick_socket_t *ssocket, void *callback_data)
{
    unused(ssocket);
    unused(callback_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_http2socket_t *httpsocket = cast_to_http2_socket(ssocket);

    if (httpsocket)
    {
        //nghtt2p destroy everythign
        if (httpsocket->parsing_params.session_callback)
            nghttp2_session_callbacks_del(httpsocket->parsing_params.session_callback);

        if (httpsocket->parsing_params.session)
            nghttp2_session_del(httpsocket->parsing_params.session);

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

    rebrick_http2socket_t *httpsocket = cast_to_http2_socket(ssocket);

    if (httpsocket)
    {

        if (httpsocket->override_override_on_data_sended)
            httpsocket->override_override_on_data_sended(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, source);
    }
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

    if (!socket)
    {
        rebrick_log_fatal("socket argument is null\n");
        return;
    }

    rebrick_http2socket_t *httpsocket = cast_to_http2_socket(socket);

    if (httpsocket->override_override_on_data_received)
        httpsocket->override_override_on_data_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr, buffer, len);

    result = nghttp2_session_mem_recv(httpsocket->parsing_params.session, cast(buffer, const uint8_t *), len);
    if (result < 0)
    {

        const char *errstr = nghttp2_strerror(result);
        rebrick_log_error("http2 parsing params failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);
        call_error(httpsocket, REBRICK_ERR_HTTP2 + result);
        return;
    }
    result = nghttp2_session_send(httpsocket->parsing_params.session);
    if (result < 0)
    {
        const char *errstr = nghttp2_strerror(result);
        rebrick_log_error("http2 parsing params failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);
        call_error(httpsocket, REBRICK_ERR_HTTP2 + result);
        return;
    }
}

static struct rebrick_tcpsocket *local_create_client()
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    rebrick_http2socket_t *client = new (rebrick_http2socket_t);
    constructor(client, rebrick_http2socket_t);
    result = rebrick_tcpsocket_nodelay(cast_to_tcp_socket(client), 1);
    if (result < 0)
    {
        rebrick_log_fatal("no delay failed\n");
    }
    return cast_to_tcp_socket(client);
}

int32_t rebrick_http2socket_init(rebrick_http2socket_t *httpsocket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr, void *callback_data,
                                 const rebrick_http2_socket_settings_t *settings,
                                 rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                 rebrick_on_connection_closed_callback_t on_connection_closed,
                                 rebrick_on_data_received_callback_t on_data_received,
                                 rebrick_on_data_sended_callback_t on_data_sended,
                                 rebrick_on_error_occured_callback_t on_error_occured,
                                 int32_t backlog_or_isclient,
                                 rebrick_on_http_header_received_callback_t on_http_header_received,
                                 rebrick_on_http_body_received_callback_t on_http_body_received,
                                 rebrick_on_socket_needs_upgrade_callback_t on_socket_needs_upgrade,
                                 rebrick_tcpsocket_create_client_t create_client)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    if (tls)
    {
        //create a new tls socket
        result = rebrick_tlssocket_init(cast_to_tls_socket(httpsocket), sni_pattern_or_name, tls, addr, NULL, local_on_connection_accepted_callback, local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback, backlog_or_isclient, create_client);
    }
    else
    {
        result = rebrick_tcpsocket_init(cast_to_tcp_socket(httpsocket), addr, NULL, local_on_connection_accepted_callback, local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback, backlog_or_isclient, create_client);
    }
    if (result < 0)
    {
        rebrick_log_error("http2 socket creation failed with error:%d\n", result);
        return result;
    }
    //set no delay for tcp socket, this is important
    rebrick_tcpsocket_nodelay(cast_to_tcp_socket(httpsocket), 1);
    memcpy(&httpsocket->settings, settings, sizeof(rebrick_http2_socket_settings_t));
    httpsocket->override_override_on_connection_accepted = on_connection_accepted;
    httpsocket->override_override_on_connection_closed = on_connection_closed;
    httpsocket->override_override_on_data_received = on_data_received;
    httpsocket->override_override_on_data_sended = on_data_sended;
    httpsocket->override_override_on_error_occured = on_error_occured;
    httpsocket->override_override_callback_data = callback_data;
    httpsocket->on_http_body_received = on_http_body_received;
    httpsocket->on_http_header_received = on_http_header_received;
    httpsocket->on_socket_needs_upgrade = on_socket_needs_upgrade;
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_new(rebrick_http2socket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr, void *callback_data,
                                const rebrick_http2_socket_settings_t *settings,
                                rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                rebrick_on_connection_closed_callback_t on_connection_closed,
                                rebrick_on_data_received_callback_t on_data_received,
                                rebrick_on_data_sended_callback_t on_data_sended,
                                rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                rebrick_on_http_header_received_callback_t on_http_header_received,
                                rebrick_on_http_body_received_callback_t on_http_body_received,
                                rebrick_on_socket_needs_upgrade_callback_t on_socket_needs_upgrade)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    rebrick_http2socket_t *httpsocket = new (rebrick_http2socket_t);
    constructor(httpsocket, rebrick_http2socket_t);

    result = rebrick_http2socket_init(httpsocket, sni_pattern_or_name, tls, addr,
                                      callback_data, settings, on_connection_accepted, on_connection_closed, on_data_received, on_data_sended, on_error_occured, backlog_or_isclient,
                                      on_http_header_received, on_http_body_received, on_socket_needs_upgrade,
                                      local_create_client);
    if (result < 0)
    {
        rebrick_log_error("http2 socket init failed with error:%d\n", result);
        free(httpsocket);
        return result;
    }
    *socket = httpsocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_destroy(rebrick_http2socket_t *socket)
{
    unused(socket);
    if (socket)
    {
        if (socket->tls_context)
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

int32_t rebrick_http2socket_send(rebrick_http2socket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{
    unused(socket);
    unused(buffer);
    unused(len);
    unused(cleanfunc);

    if (!socket || !buffer | !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (socket->tls_context)
        return rebrick_tlssocket_send(cast_to_tls_socket(socket), buffer, len, cleanfunc);
    return rebrick_tcpsocket_send(cast_to_tcp_socket(socket), buffer, len, cleanfunc);
}

/* static void clean_buffer(void *buffer)
{
    rebrick_buffer_t *tmp = cast(buffer, rebrick_buffer_t *);
    if (tmp)
    {
        rebrick_buffer_destroy(tmp);
    }
} */

int32_t rebrick_http2socket_send_header(rebrick_http2socket_t *socket, int32_t *stream_id, int32_t flags, rebrick_http_header_t *header)
{
    unused(socket);
    unused(stream_id);
    unused(header);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!socket || !stream_id | !header)
        return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_buffer_t *buffer;
    result = rebrick_http_header_to_http2_buffer(header, &buffer);
    if (result < 0)
    {
        rebrick_log_error("http2 sending header failed with error:%d\n", result);
        return result;
    }

    result = nghttp2_submit_headers(socket->parsing_params.session, flags | NGHTTP2_FLAG_END_HEADERS, *stream_id, NULL, cast(buffer->buf, nghttp2_nv *), buffer->len / sizeof(nghttp2_nv), NULL);
    if (result < 0)
    {
        const char *errstr = nghttp2_strerror(result);
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);
        rebrick_buffer_destroy(buffer);
        return REBRICK_ERR_HTTP2 + result;
    }
    //buffer burada destroy edilmeli, yoksa gözden kaçacak
    rebrick_buffer_destroy(buffer);
    if (result > 0)
    { //new stream id
        *stream_id = result;
        //create new stream object
        rebrick_http2stream_t *stream = NULL;
        HASH_FIND_INT(socket->streams, &result, stream);
        if (stream)
        {
            HASH_DEL(socket->streams, stream);
            rebrick_http2stream_destroy(stream);
        }
        result = rebrick_http2stream_new(&stream, result);
        if (result < 0)
        {
            rebrick_log_error("malloc problem\n");
            return result;
        }
        HASH_ADD_INT(socket->streams, stream_id, stream);
        stream->send_header = header;
    }

    result = nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);

    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_get_stream(rebrick_http2socket_t *socket, int32_t stream_id, rebrick_http2stream_t **stream)
{

    unused(socket);
    unused(stream_id);
    unused(stream);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_http2stream_t *tmp = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, tmp);
    *stream = tmp;
    return REBRICK_SUCCESS;
}
