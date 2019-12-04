#include "rebrick_http2socket.h"

#define call_error(httpsocket, error)                   \
    if (httpsocket->override_override_on_error_occured) \
        httpsocket->override_override_on_error_occured(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, error);

#define check_error(httpsocket, result, msg, ret) \
    if (result < 0)                               \
    {                                             \
        rebrick_log_error(msg, result);           \
        call_error(socket, result);               \
        return ret;                               \
    }

#define check_error_without_call(httpsocket, result, msg, ret) \
    if (result < 0)                                            \
    {                                                          \
        rebrick_log_error(msg, result);                        \
        return ret;                                            \
    }

#define check_nghttp2_result(result)                                                               \
    if (result < 0)                                                                                \
    {                                                                                              \
        const char *errstr = nghttp2_strerror(result);                                             \
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr); \
        return REBRICK_ERR_HTTP2 + result;                                                         \
    }

#define check_nghttp2_result_call_error(result, socket)                                                                                              \
    if (result < 0)                                                                                                                                  \
    {                                                                                                                                                \
        const char *errstr = nghttp2_strerror(result);                                                                                               \
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);                                                   \
        if (socket->override_override_on_error_occured)                                                                                              \
            socket->override_override_on_error_occured(cast_to_socket(socket), socket->override_override_callback_data, REBRICK_ERR_HTTP2 + result); \
        return;                                                                                                                                      \
    }

static int32_t rebrick_http2_stream_new(rebrick_http2_stream_t **stream, int32_t stream_id, int32_t parent_stream_id)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_http2_stream_t *tmp = new (rebrick_http2_stream_t);
    constructor(tmp, rebrick_http2_stream_t);
    tmp->stream_id = stream_id;
    tmp->parent_stream_id = parent_stream_id;
    *stream = tmp;
    return REBRICK_SUCCESS;
}

static int32_t rebrick_http2_stream_destroy(rebrick_http2_stream_t *stream)
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
static int32_t destroy_stream(rebrick_http2socket_t *socket, int32_t stream_id)
{
    rebrick_http2_stream_t *stream = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, stream);
    if (stream)
    {

        HASH_DEL(socket->streams, stream);
        rebrick_http2_stream_destroy(stream);
    }
    return REBRICK_SUCCESS;
}

static inline int32_t create_stream(rebrick_http2socket_t *socket, rebrick_http2_stream_t **destination, int32_t stream_id, int32_t parent_stream_id)
{
    //create new stream object
    int32_t result;
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_http2_stream_t *stream = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, stream);
    if (stream)
    {
        HASH_DEL(socket->streams, stream);
        rebrick_http2_stream_destroy(stream);
    }
    result = rebrick_http2_stream_new(&stream, stream_id, parent_stream_id);
    if (result < 0)
    {
        rebrick_log_error("http2 stream create error malloc problem with %d:\n", result);
        return result;
    }
    HASH_ADD_INT(socket->streams, stream_id, stream);
    *destination = stream;
    return REBRICK_SUCCESS;
}

static inline int32_t add_to_header(rebrick_http_header_t *tmp, const uint8_t *name, int32_t namelen, const uint8_t *value, int32_t valuelen)
{
    char current_time_str[32] = {0};
    if (!strcasecmp(cast(name, const char *), ":path"))
        memcpy(tmp->path, value, valuelen >= REBRICK_HTTP_MAX_PATH_LEN ? REBRICK_HTTP_MAX_PATH_LEN - 1 : valuelen);
    else if (!strcasecmp(cast(name, const char *), ":method"))
        memcpy(tmp->method, value, valuelen >= REBRICK_HTTP_MAX_METHOD_LEN ? REBRICK_HTTP_MAX_METHOD_LEN - 1 : valuelen);
    else if (!strcasecmp(cast(name, const char *), ":scheme"))
        memcpy(tmp->scheme, value, valuelen >= REBRICK_HTTP_MAX_SCHEME_LEN ? REBRICK_HTTP_MAX_SCHEME_LEN - 1 : valuelen);
    else if (!strcasecmp(cast(name, const char *), ":authority"))
        memcpy(tmp->host, value, valuelen >= REBRICK_HTTP_MAX_HOSTNAME_LEN ? REBRICK_HTTP_MAX_HOSTNAME_LEN - 1 : valuelen);
    else if (!strcasecmp(cast(name, const char *), ":status"))
    {
        tmp->status_code = atoi(cast(value, const char *));
        const char *status_str = rebrick_httpstatus_reasonphrase(tmp->status_code);
        if (status_str)
        {
            size_t tmplen = strlen(status_str);
            memcpy(tmp->status_code_str, status_str, tmplen >= REBRICK_HTTP_MAX_STATUSCODE_LEN ? REBRICK_HTTP_MAX_STATUSCODE_LEN - 1 : tmplen);
        }
    }
    else
    {

        int32_t result = rebrick_http_header_add_header2(tmp, cast_to_const_uint8ptr(name), namelen, cast_to_const_uint8ptr(value), valuelen);
        if (result < 0)
        {
            rebrick_log_error("http2 add header failed with error:%d\n", result);
            return result;
        }
    }
    return REBRICK_SUCCESS;
}

/* static inline int32_t create_header(rebrick_http2socket_t *socket, rebrick_http_header_t **header, int32_t is_request, nghttp2_nv *nv, size_t nvlen)
{
    unused(socket);
    unused(header);
    unused(nv);
    unused(nvlen);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    rebrick_http_header_t *tmp;

    result = rebrick_http_header_new5(&tmp, is_request, 2, 0);
    check_error_without_call(socket, result, "http header create failed with error:%d\n", result);

    for (size_t i = 0; i < nvlen; ++i)
    {
        const uint8_t *name = nv[i].name;
        int32_t namelen = nv[i].namelen;
        const uint8_t *value = nv[i].value;
        int32_t valuelen = nv[i].valuelen;
        result = add_to_header(tmp, name, namelen, value, valuelen);
        if (result < 0)
        {
            rebrick_http_header_destroy(tmp);
            rebrick_log_error("http header add failed with error:%d\n", result);
            return result;
        }
    }

    *header = tmp;

    return REBRICK_SUCCESS;
} */

/* static void http2_stream_error(nghttp2_session *session, int32_t stream_id, uint32_t error_code)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_error("http2 stream error with error code:%d\n", error_code);
    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, error_code);
} */

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
    rebrick_http2socket_t *httpsocket = cast_to_http2socket(user_data);
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
    rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
    if (socket->on_stream_closed)
        socket->on_stream_closed(cast_to_socket(socket), stream_id, socket->override_override_callback_data);

    destroy_stream(socket, stream_id);

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

    rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
    if (socket->on_http_body_received)
        socket->on_http_body_received(cast_to_socket(socket), stream_id, socket->override_override_callback_data, &socket->bind_addr.base, data, len);

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
    int32_t result;

    if (frame->hd.type == NGHTTP2_HEADERS)
    {

        rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
        //find and delete the previous received header
        rebrick_http2_stream_t *stream = NULL;
        int32_t stream_id = frame->hd.stream_id;
        HASH_FIND_INT(socket->streams, &stream_id, stream);
        if (!stream)
        {
            result = create_stream(socket, &stream, frame->hd.stream_id, frame->hd.stream_id);
            check_error(socket, result, "create stream from push promise failed with error %d\n", 0);
        }

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST || frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE)
            if (stream && stream->received_header)
            {
                socket->last_received_stream_id = stream_id;
                printf("on headers called received_header last stream_id %d\n", stream_id);
                rebrick_http_header_destroy(stream->received_header);
                stream->received_header = NULL;
            }
    }

    if (frame->hd.type == NGHTTP2_PUSH_PROMISE)
    {

        rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
        //find and delete the previous received header
        rebrick_http2_stream_t *stream = NULL;
        // int32_t stream_id = frame->push_promise.promised_stream_id;
        // HASH_FIND_INT(socket->streams, &stream_id, stream);

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST || frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE)
        {

            result = create_stream(socket, &stream, frame->push_promise.promised_stream_id, frame->hd.stream_id);
            check_error(socket, result, "create stream from push promise failed with error %d\n", 0);
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
    rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
    rebrick_http2_stream_t *stream = NULL;
    int32_t result;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:

        result = frame->hd.stream_id;
        HASH_FIND_INT(socket->streams, &result, stream);
        if (!stream)
            return 0; //expecially returning 0;
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST || frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE)
        {

            if (!stream->received_header)
            {
                result = rebrick_http_header_new5(&stream->received_header, frame->headers.cat == NGHTTP2_HCAT_REQUEST, 2, 0);
                check_error(socket, result, "http header create failed with error:%d\n", 0)
            }
            result = add_to_header(stream->received_header, name, namelen, value, valuelen);
            check_error(socket, result, "http header create failed with error: %d\n", 0);
        }
        break;

    case NGHTTP2_PUSH_PROMISE:

        result = frame->push_promise.promised_stream_id;
        HASH_FIND_INT(socket->streams, &result, stream);
        if (!stream)
            return 0; //expecially returning 0;
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {

            if (!stream->received_header)
            {
                result = rebrick_http_header_new5(&stream->received_header, frame->headers.cat == NGHTTP2_HCAT_REQUEST, 2, 0);
                check_error(socket, result, "http header create failed with error:%d\n", 0)
            }
            result = add_to_header(stream->received_header, name, namelen, value, valuelen);
            check_error(socket, result, "http header create failed with error: %d\n", 0);
        }
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {

            if (!stream->send_header)
            {
                result = rebrick_http_header_new5(&stream->send_header, frame->headers.cat == NGHTTP2_HCAT_REQUEST, 2, 0);
                check_error(socket, result, "http header create failed with error:%d\n", 0)
            }
            result = add_to_header(stream->send_header, name, namelen, value, valuelen);
            check_error(socket, result, "http header create failed with error: %d\n", 0);
        }
        break;
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

    rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
    rebrick_http2_stream_t *stream = NULL;
    int32_t result;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
        result = frame->hd.stream_id;
        HASH_FIND_INT(socket->streams, &result, stream);
        if (stream)
        {
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_REQUEST || frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE)
            {

                if (socket->on_http_header_received)
                    socket->on_http_header_received(cast_to_socket(socket), frame->hd.stream_id, socket->override_override_callback_data, stream->received_header);
            }
        }

        break;
    case NGHTTP2_PING:

        if (socket->on_ping_received)
            socket->on_ping_received(cast_to_socket(socket), socket->override_override_callback_data, frame->ping.opaque_data);
        break;
    case NGHTTP2_GOAWAY:
        socket->is_goaway_received = TRUE;
        if (socket->on_goaway_received)
            socket->on_goaway_received(cast_to_socket(socket), socket->override_override_callback_data, frame->goaway.error_code, frame->goaway.last_stream_id, frame->goaway.opaque_data, frame->goaway.opaque_data_len);
        break;
    case NGHTTP2_WINDOW_UPDATE:
        if (socket->on_window_update_received)
            socket->on_window_update_received(cast_to_socket(socket), socket->override_override_callback_data, frame->window_update.hd.stream_id, frame->window_update.window_size_increment);
        break;

    case NGHTTP2_SETTINGS:
        fill_zero(&socket->received_settings, sizeof(rebrick_http2_socket_settings_t));
        memcpy(socket->received_settings.entries, frame->settings.iv, sizeof(nghttp2_settings_entry) * frame->settings.niv);
        socket->received_settings.settings_count = frame->settings.niv;
        if (socket->on_settings_received)
            socket->on_settings_received(cast_to_socket(socket), socket->override_override_callback_data, &socket->received_settings);
        break;
    case NGHTTP2_PUSH_PROMISE:
        //create new stream object
        result = frame->push_promise.promised_stream_id;
        HASH_FIND_INT(socket->streams, &result, stream);
        if (stream)
            if (socket->on_push_received)
                socket->on_push_received(cast_to_socket(socket), socket->override_override_callback_data, frame->hd.stream_id, frame->push_promise.promised_stream_id, stream->send_header);

        break;
    default:
        break;
    }
    return 0;
}

int http2_on_error_callback(nghttp2_session *session, int lib_error_code, const char *msg, size_t len, void *user_data)
{
    unused(session);
    unused(lib_error_code);
    unused(msg);
    unused(len);
    unused(user_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_error("nghttp2 error %s\n", msg);
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
    nghttp2_session_callbacks_set_error_callback2(callbacks, http2_on_error_callback);
}

static void local_on_error_occured_callback(rebrick_socket_t *ssocket, void *callbackdata, int error)
{
    unused(ssocket);
    unused(callbackdata);
    unused(error);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_http2socket_t *httpsocket = cast_to_http2socket(ssocket);
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

    rebrick_http2socket_t *httpsocket = cast_to_http2socket(ssocket);
    if (!httpsocket)
    {
        rebrick_log_fatal("socket casting to http2socket is null\n");
        return;
    }
    rebrick_http2socket_t *socket = NULL;
    if (httpsocket->is_server)
        socket = cast_to_http2socket(client_handle);
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
        socket->on_http_body_received = httpsocket->on_http_body_received;
        socket->on_http_header_received = httpsocket->on_http_header_received;
        socket->on_socket_needs_upgrade = httpsocket->on_socket_needs_upgrade;
        socket->on_stream_closed = httpsocket->on_stream_closed;
        socket->on_settings_received = httpsocket->on_settings_received;
        socket->on_ping_received = httpsocket->on_ping_received;
        socket->on_push_received = httpsocket->on_push_received;
        socket->on_goaway_received = httpsocket->on_goaway_received;
        socket->on_window_update_received = httpsocket->on_window_update_received;


        memcpy(&socket->settings, &httpsocket->settings, sizeof(rebrick_http2_socket_settings_t));
    }

    //init http2 structure
    result = nghttp2_session_callbacks_new(&socket->parsing_params.session_callback);
    check_nghttp2_result_call_error(result, socket);

    setup_nghttp2_callbacks(socket->parsing_params.session_callback);

    if (socket->is_server || httpsocket->is_server)
    {
        result = nghttp2_session_server_new(&socket->parsing_params.session, socket->parsing_params.session_callback, socket);
        check_nghttp2_result_call_error(result, socket);
    }
    else
    {
        result = rebrick_tcpsocket_nodelay(cast_to_tcpsocket(socket), 1);

        if (result < 0)
        {
            rebrick_log_fatal("no delay for client failed\n");
        }
        result = nghttp2_session_client_new(&socket->parsing_params.session, socket->parsing_params.session_callback, socket);
        check_nghttp2_result_call_error(result, socket);
        /*result = nghttp2_session_send(socket->parsing_params.session);
        check_nghttp2_result_call_error(result, socket);*/


    }





    result = nghttp2_submit_settings(socket->parsing_params.session, NGHTTP2_FLAG_NONE, socket->settings.entries, socket->settings.settings_count);
    check_nghttp2_result_call_error(result, socket);
    //burasını açınca tls çalışmıyor
   /* result = nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result_call_error(result, socket);*/

    if (socket->override_override_on_connection_accepted)
        socket->override_override_on_connection_accepted(cast_to_socket(httpsocket), socket->override_override_callback_data, addr, socket);
}

static void local_on_connection_closed_callback(rebrick_socket_t *ssocket, void *callback_data)
{
    unused(ssocket);
    unused(callback_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_http2socket_t *httpsocket = cast_to_http2socket(ssocket);

    if (httpsocket)
    {
        rebrick_http2_stream_t *tmp, *stmp;
        HASH_ITER(hh, httpsocket->streams, tmp, stmp)
        {
            HASH_DEL(httpsocket->streams, tmp);
            rebrick_http2_stream_destroy(tmp);
        }

        //nghtt2p destroy everythign
        if (httpsocket->parsing_params.session_callback)
            nghttp2_session_callbacks_del(httpsocket->parsing_params.session_callback);

        if (httpsocket->parsing_params.session)
            nghttp2_session_del(httpsocket->parsing_params.session);

        if (httpsocket->override_override_on_connection_closed)
            httpsocket->override_override_on_connection_closed(cast_to_socket(httpsocket), httpsocket->override_override_callback_data);
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

    rebrick_http2socket_t *httpsocket = cast_to_http2socket(ssocket);

    if (httpsocket)
    {

        if (httpsocket->override_override_on_data_sended)
            httpsocket->override_override_on_data_sended(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, source);
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

    rebrick_http2socket_t *httpsocket = cast_to_http2socket(socket);

    if (httpsocket->override_override_on_data_received)
        httpsocket->override_override_on_data_received(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, addr, buffer, len);

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
    unused(result);
    rebrick_http2socket_t *client = new (rebrick_http2socket_t);
    constructor(client, rebrick_http2socket_t);

    return cast_to_tcpsocket(client);
}




static int rebrick_tls_alpn_select_callback(unsigned char **out,unsigned char *outlen,const unsigned char *in,unsigned int inlen){

    int rv;
    rv = nghttp2_select_next_protocol(cast(out,unsigned char**), outlen, in, inlen);

    if (rv == -1) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;

}


int32_t rebrick_http2socket_init(rebrick_http2socket_t *httpsocket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr,
                                 int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t create_client,
                                 const rebrick_http2_socket_settings_t *settings, const rebrick_http2socket_callbacks_t *callbacks)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    new2(rebrick_tlssocket_callbacks_t, local_callbacks);
    local_callbacks.on_connection_accepted = local_on_connection_accepted_callback;
    local_callbacks.on_connection_closed = local_on_connection_closed_callback;
    local_callbacks.on_data_received = local_after_data_received_callback;
    local_callbacks.on_data_sended = local_on_data_sended_callback;
    local_callbacks.on_error_occured = local_on_error_occured_callback;

    if (tls || (sni_pattern_or_name && strlen(sni_pattern_or_name)))
    {

        //create a new tls socket
        result = rebrick_tlssocket_init(cast_to_tlssocket(httpsocket), sni_pattern_or_name, tls, addr, backlog_or_isclient, create_client, &local_callbacks);

        if(!result && !tls->alpn_select_callback){
        result=rebrick_tls_context_set_alpn_protos(tls,REBRICK_HTTP2_ALPN_PROTO,REBRIKC_HTTP2_ALPN_PROTO_LEN,rebrick_tls_alpn_select_callback);
        //result|=rebrick_tls_context_set_npn_protos(tls,REBRICK_HTTP2_ALPN_PROTO,REBRIKC_HTTP2_ALPN_PROTO_LEN,rebrick_tls_alpn_select_callback);
        }


    }
    else
    {
        result = rebrick_tcpsocket_init(cast_to_tcpsocket(httpsocket), addr, backlog_or_isclient, create_client, cast_to_tcpsocket_callbacks(&local_callbacks));
    }
    if (result < 0)
    {
        rebrick_log_error("http2 socket creation failed with error:%d\n", result);
        return result;
    }
    //set no delay for tcp socket, this is important
    rebrick_tcpsocket_nodelay(cast_to_tcpsocket(httpsocket), 1);
    memcpy(&httpsocket->settings, settings, sizeof(rebrick_http2_socket_settings_t));
    httpsocket->override_override_on_connection_accepted = callbacks ? callbacks->on_connection_accepted : NULL;
    httpsocket->override_override_on_connection_closed = callbacks ? callbacks->on_connection_closed : NULL;
    httpsocket->override_override_on_data_received = callbacks ? callbacks->on_data_received : NULL;
    httpsocket->override_override_on_data_sended = callbacks ? callbacks->on_data_sended : NULL;
    httpsocket->override_override_on_error_occured = callbacks ? callbacks->on_error_occured : NULL;
    httpsocket->override_override_callback_data = callbacks ? callbacks->callback_data : NULL;
    httpsocket->on_http_body_received = callbacks ? callbacks->on_http_body_received : NULL;
    httpsocket->on_http_header_received = callbacks ? callbacks->on_http_header_received : NULL;
    httpsocket->on_socket_needs_upgrade = callbacks ? callbacks->on_socket_needs_upgrade : NULL;
    httpsocket->on_stream_closed = callbacks ? callbacks->on_stream_closed : NULL;
    httpsocket->on_settings_received = callbacks ? callbacks->on_settings_received : NULL;
    httpsocket->on_ping_received = callbacks ? callbacks->on_ping_received : NULL;
    httpsocket->on_push_received = callbacks ? callbacks->on_push_received : NULL;
    httpsocket->on_goaway_received = callbacks ? callbacks->on_goaway_received : NULL;
    httpsocket->on_window_update_received = callbacks ? callbacks->on_window_update_received : NULL;
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_new(rebrick_http2socket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr,
                                int32_t backlog_or_isclient,
                                const rebrick_http2_socket_settings_t *settings,
                                const rebrick_http2socket_callbacks_t *callbacks)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    rebrick_http2socket_t *httpsocket = new (rebrick_http2socket_t);
    constructor(httpsocket, rebrick_http2socket_t);

    result = rebrick_http2socket_init(httpsocket, sni_pattern_or_name, tls, addr,
                                      backlog_or_isclient, local_create_client, settings, callbacks);
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
        if(socket->is_server){
            rebrick_tcpsocket_t *client;
            DL_FOREACH(socket->clients,client){
                if(!cast_to_http2socket(client)->is_goaway_sended)
                rebrick_http2socket_send_goaway(cast_to_http2socket(client),NULL,0);
                nghttp2_session_send(cast_to_http2socket(client)->parsing_params.session);
            }

        }else{
            if(!socket->is_goaway_sended)
            rebrick_http2socket_send_goaway(socket,NULL,0);
            nghttp2_session_send(socket->parsing_params.session);
        }

        if (socket->tls_context)
        {
            return rebrick_tlssocket_destroy(cast_to_tlssocket(socket));
        }
        else
        {
            return rebrick_tcpsocket_destroy(cast_to_tcpsocket(socket));
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
    if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;

    if (socket->tls_context)
        return rebrick_tlssocket_send(cast_to_tlssocket(socket), buffer, len, cleanfunc);
    return rebrick_tcpsocket_send(cast_to_tcpsocket(socket), buffer, len, cleanfunc);
}

/* static void clean_buffer(void *buffer)
{
    rebrick_buffer_t *tmp = cast(buffer, rebrick_buffer_t *);
    if (tmp)
    {
        rebrick_buffer_destroy(tmp);
    }
} */

int32_t rebrick_http2socket_send_header(rebrick_http2socket_t *socket, int32_t *stream_id, int64_t flags, rebrick_http_header_t *header)
{
    unused(socket);
    unused(stream_id);
    unused(header);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!socket || !stream_id | !header)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;

    nghttp2_nv *nv;
    size_t nvlen;

#define destory_nv()                      \
    for (size_t tt = 0; tt < nvlen; ++tt) \
    {                                     \
        free(nv[tt].name);                \
        free(nv[tt].value);               \
    }                                     \
    free(nv);

    result = rebrick_http_header_to_http2_buffer(header, &nv, &nvlen);
    if (result < 0)
    {
        rebrick_log_error("http2 sending header failed with error:%d\n", result);
        return result;
    }


    result = nghttp2_submit_headers(socket->parsing_params.session, flags | NGHTTP2_FLAG_END_HEADERS, *stream_id, NULL, nv, nvlen, NULL);
    if (result < 0)
    {
        const char *errstr = nghttp2_strerror(result);
        rebrick_log_error("http2 failed with error :%d %s\n", REBRICK_ERR_HTTP2 + result, errstr);

        //destory nghttp2_vn
        destory_nv();

        return REBRICK_ERR_HTTP2 + result;
    }

    //destory nghttp2_vn
    destory_nv();
    rebrick_http2_stream_t *stream = NULL;
    if (result > 0)
    { //new stream id
        *stream_id = result;
        //create new stream object


        result = create_stream(socket, &stream, *stream_id, *stream_id);
        if (result < 0)
        {
            return result;
        }


    }
    if(!stream){
        HASH_FIND_INT(socket->streams, stream_id, stream);
        if(!stream){
            return REBRICK_ERR_HTTP2_STREAM_NOT_FOUND;
        }
        if(stream->send_header)
        rebrick_http_header_destroy(stream->send_header);



    }
    stream->send_header=header;

    result = nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);

    return REBRICK_SUCCESS;
}
static ssize_t http2_data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    unused(session);
    unused(stream_id);
    unused(source);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    rebrick_http2socket_t *socket = cast_to_http2socket(user_data);
    rebrick_http2_stream_t *stream = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, stream);
    if (!stream)
    {
        rebrick_log_error("data source callback stream not found with id:%d\n", stream_id);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (!stream->buffer->len)
    {
        if (stream->flags & 0x0000000F & NGHTTP2_DATA_FLAG_EOF)
        {
            stream->is_submitted = FALSE;
            *data_flags = NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        else
            return NGHTTP2_ERR_DEFERRED;
    }
    size_t copylen = stream->buffer->len < length ? stream->buffer->len : length;
    memcpy(buf, stream->buffer->buf, copylen);
    result = rebrick_buffer_remove(stream->buffer, 0, copylen);
    if (result < 0)
    {
        rebrick_log_error("buffer remove failed:%d\n", stream_id);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (!stream->buffer->len)
    {
        if (stream->flags & 0x0000000F & NGHTTP2_DATA_FLAG_EOF)
        {
            stream->is_submitted = FALSE;
            *data_flags = NGHTTP2_DATA_FLAG_EOF;
        }
        else
            return NGHTTP2_ERR_DEFERRED;
    }

    return copylen;
}
//TODO bunları global bir settings falan yapmak lazım
#define REBRICK_BUFFER_DEFAULT_MALLOC_SIZE 4096
int32_t rebrick_http2socket_send_body(rebrick_http2socket_t *socket, int32_t stream_id, int64_t flags, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{
    unused(socket);
    unused(stream_id);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!socket || !stream_id || !buffer || !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;

    rebrick_http2_stream_t *stream = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, stream);
    if (!stream)
    {
        rebrick_log_error("stream not found with id:%d\n", stream_id);
        return REBRICK_ERR_HTTP2_STREAM_NOT_FOUND;
    }

    if (!stream->buffer)
        result = rebrick_buffer_new(&stream->buffer, buffer, len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    else
        result = rebrick_buffer_add(stream->buffer, buffer, len);
    stream->flags |= flags;

    if (result < 0)
    {
        rebrick_log_error("buffer create or add failed with error:%d\n", result);

        return result;
    }
    //clear input  data, we allready copied to buffer
    if (cleanfunc.func)
        cleanfunc.func(cleanfunc.ptr);

    if (!stream->is_submitted)
    {
        nghttp2_data_provider dataprovider = {.source = {0}, .read_callback = http2_data_source_read_callback};
        result = nghttp2_submit_data(socket->parsing_params.session, flags >> 8, stream_id, &dataprovider);
        check_nghttp2_result(result);
        stream->is_submitted = TRUE;
    }
    else
    {
        result = nghttp2_session_resume_data(socket->parsing_params.session, stream_id);
        //check error
    }
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);

    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_get_stream(rebrick_http2socket_t *socket, int32_t stream_id, rebrick_http2_stream_t **stream)
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
    rebrick_http2_stream_t *tmp = NULL;
    HASH_FIND_INT(socket->streams, &stream_id, tmp);
    *stream = tmp;
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_send_ping(rebrick_http2socket_t *socket, int64_t flags, uint8_t opaque_data[8])
{
    unused(socket);
    unused(opaque_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;

    result = nghttp2_submit_ping(socket->parsing_params.session, flags, opaque_data);
    check_nghttp2_result(result);
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_send_goaway(rebrick_http2socket_t *socket, uint8_t *opaque_data, size_t opaque_data_len)
{
    unused(socket);
    unused(opaque_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;

    result = nghttp2_submit_goaway(socket->parsing_params.session, NGHTTP2_FLAG_NONE, socket->last_received_stream_id, 0, opaque_data, opaque_data_len);
    check_nghttp2_result(result);
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);

    socket->is_goaway_sended = TRUE;
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_send_window_update(rebrick_http2socket_t *socket, int32_t stream_id, int32_t increment)
{
    unused(socket);
    unused(stream_id);
    unused(increment);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;
     if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;

    result = nghttp2_submit_window_update(socket->parsing_params.session, NGHTTP2_FLAG_NONE, stream_id, increment);
    check_nghttp2_result(result);
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);
    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_send_push(rebrick_http2socket_t *socket, int32_t *pushstream_id, int32_t stream_id, rebrick_http_header_t *header)
{

    unused(socket);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;
     if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;
    size_t counter = 0;

    while (counter < socket->received_settings.settings_count)
    {
        //check if enabled push exits
        if (socket->received_settings.entries[counter].settings_id == NGHTTP2_SETTINGS_ENABLE_PUSH && socket->received_settings.entries[counter].value)
            break;
        counter++;
    }
    if (counter && counter >= socket->received_settings.settings_count)
        return REBRICK_ERR_HTTP2_PUSH_NOTSUPPORT;

    nghttp2_nv *nv;
    size_t nvlen;

#define destory_nv()                      \
    for (size_t tt = 0; tt < nvlen; ++tt) \
    {                                     \
        free(nv[tt].name);                \
        free(nv[tt].value);               \
    }                                     \
    free(nv);

    result = rebrick_http_header_to_http2_buffer(header, &nv, &nvlen);
    if (result < 0)
    {
        rebrick_log_error("http2 sending header failed with error:%d\n", result);
        return result;
    }

    result = nghttp2_submit_push_promise(socket->parsing_params.session, 0, stream_id, nv, nvlen, socket);
    destory_nv();
    check_nghttp2_result(result);
    *pushstream_id = result;
    rebrick_http2_stream_t *tmpstream = NULL;
    result = create_stream(socket, &tmpstream, result, stream_id);
    check_error_without_call(socket, result, "create stream failed for push response with error %d\n", result);
    tmpstream->received_header = header;
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);


    return REBRICK_SUCCESS;
}

int32_t rebrick_http2socket_send_rststream(rebrick_http2socket_t *socket,int32_t stream_id,uint32_t errorcode){
    unused(socket);
    unused(stream_id);

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;
     if (socket->is_goaway_received || socket->is_goaway_sended)
        return REBRICK_ERR_HTTP2_GOAWAY;

    result = nghttp2_submit_rst_stream(socket->parsing_params.session, NGHTTP2_FLAG_NONE, stream_id, errorcode);
    check_nghttp2_result(result);
    result=nghttp2_session_send(socket->parsing_params.session);
    check_nghttp2_result(result);
    return REBRICK_SUCCESS;
}