#include "rebrick_http2socket.h"

#define call_error(httpsocket, error)                   \
    if (httpsocket->override_override_on_error_occured) \
        httpsocket->override_override_on_error_occured(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, error);

#define check_nghttp2_result(result)                                                               \
    if (result < 0)                                                                                \
    {                                                                                              \
        const char *errstr = nghttp2_strerror(result);                                             \
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr); \
        return REBRICK_ERR_HTTP2 + result;                                                         \
    }

#define check_nghttp2_result_call_error(result, socket)                                                          \
    if (result < 0)                                                                                              \
    {                                                                                                            \
        const char *errstr = nghttp2_strerror(result);                                                           \
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);               \
        if (socket->override_override_on_error_occured)                                                          \
            socket->override_override_on_error_occured(cast_to_base_socket(socket), socket->override_override_callback_data, REBRICK_ERR_HTTP2 + result); \
        return;                                                                                                  \
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
    rebrick_http2socket_t *httpsocket = cast(user_data, rebrick_http2socket_t *);
    if (httpsocket)
    {
        rebrick_clean_func_t func = {.func = NULL, .ptr = NULL};
        result = rebrick_http2socket_send(httpsocket,cast(data,uint8_t*), length, func);
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
    rebrick_log_debug("closing stream\n");

    return 0;
}

static int http2_on_begin_headers_callback(nghttp2_session *session,
                                           const nghttp2_frame *frame,
                                           void *user_data)
{

    unused(session);
    unused(frame);
    unused(user_data);

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }
    /* stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream_data); */
    return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{

    nghttp2_session_callbacks_set_send_callback(callbacks, http2_on_send_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, http2_on_stream_close_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, http2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, http2_on_begin_headers_callback);
    nghttp2_session_callbacks_set_before_frame_send_callback(callbacks, http2_on_before_frame_send_callback);
}

static void local_on_error_occured_callback(rebrick_socket_t *ssocket, void *callbackdata, int error)
{
    unused(ssocket);
    unused(callbackdata);
    unused(error);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_http2socket_t *httpsocket = cast(ssocket, rebrick_http2socket_t *);
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

    rebrick_http2socket_t *httpsocket = cast(ssocket, rebrick_http2socket_t *);
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

    check_nghttp2_result_call_error(result,socket);

    result = nghttp2_submit_settings(socket->parsing_params.session, NGHTTP2_FLAG_NONE, socket->settings.entries, socket->settings.settings_count);
    check_nghttp2_result_call_error(result,socket);
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result_call_error(result,socket);

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

    rebrick_http2socket_t *httpsocket = cast(ssocket, rebrick_http2socket_t *);

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

    rebrick_http2socket_t *httpsocket = cast(ssocket, rebrick_http2socket_t *);

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
    result = rebrick_tcpsocket_nodelay(cast_to_tcp_socket(client), 0);
    if (result < 0)
    {
        rebrick_log_fatal("no delay failed\n");
    }
    return cast(client, rebrick_tcpsocket_t *);
}

int32_t rebrick_http2socket_init(rebrick_http2socket_t *httpsocket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr, void *callback_data,
                                 const rebrick_http2_socket_settings_t *settings,
                                 rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                 rebrick_on_connection_closed_callback_t on_connection_closed,
                                 rebrick_on_data_received_callback_t on_data_received,
                                 rebrick_on_data_sended_callback_t on_data_sended,
                                 rebrick_on_error_occured_callback_t on_error_occured,
                                 int32_t backlog_or_isclient,
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
    rebrick_tcpsocket_nodelay(cast_to_tcp_socket(httpsocket), 0);
    memcpy(&httpsocket->settings, settings, sizeof(rebrick_http2_socket_settings_t));
    httpsocket->override_override_on_connection_accepted = on_connection_accepted;
    httpsocket->override_override_on_connection_closed = on_connection_closed;
    httpsocket->override_override_on_data_received = on_data_received;
    httpsocket->override_override_on_data_sended = on_data_sended;
    httpsocket->override_override_on_error_occured = on_error_occured;
    httpsocket->override_override_callback_data = callback_data;

    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_new(rebrick_http2socket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr, void *callback_data,
                                const rebrick_http2_socket_settings_t *settings,
                                rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                rebrick_on_connection_closed_callback_t on_connection_closed,
                                rebrick_on_data_received_callback_t on_data_received,
                                rebrick_on_data_sended_callback_t on_data_sended,
                                rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    rebrick_http2socket_t *httpsocket = new (rebrick_http2socket_t);
    constructor(httpsocket, rebrick_http2socket_t);

    result = rebrick_http2socket_init(httpsocket, sni_pattern_or_name, tls, addr,
                                      callback_data, settings, on_connection_accepted, on_connection_closed, on_data_received, on_data_sended, on_error_occured, backlog_or_isclient,
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


int32_t rebrick_http2socket_send(rebrick_http2socket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{
    unused(socket);
    unused(buffer);
    unused(len);
    unused(cleanfunc);

    if (!socket || !buffer | !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (socket->tls)
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

int32_t rebrick_http2socket_send_header(rebrick_http2socket_t *socket,int32_t *stream_id,int32_t flags, rebrick_http_header_t *header){
    unused(socket);
    unused(stream_id);
    unused(header);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if(!socket || !stream_id | !header)
    return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_buffer_t *buffer;
    result = rebrick_http_header_to_http2_buffer(header, &buffer);
    if (result < 0)
    {
        rebrick_log_error("http2 sending header failed with error:%d\n", result);
        return result;
    }

    result=nghttp2_submit_headers(socket->parsing_params.session,flags|NGHTTP2_FLAG_END_HEADERS,*stream_id,NULL,cast(buffer->buf,nghttp2_nv*),buffer->len/sizeof(nghttp2_nv),NULL);
    if(result<0){
     const char *errstr = nghttp2_strerror(result);
    rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);
    rebrick_buffer_destroy(buffer);
    return REBRICK_ERR_HTTP2 + result;

    }
    if(result>0)//new stream id
    *stream_id=result;
    rebrick_buffer_destroy(buffer);
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);

    return REBRICK_SUCCESS;
}
