#include "./http/rebrick_http2socket.h"
#include "./common/rebrick_resolve.h"
#include "cmocka.h"
#include <unistd.h>

#define loop(var, a, x)                           \
    var = a;                                      \
    while (var-- && (x))                          \
    {                                             \
        usleep(100);                              \
        uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
    }

static rebrick_tls_context_t *context_verify_none = NULL;
static rebrick_tls_context_t *context_hamzakilic_com = NULL;

static int setup(void **state)
{
    int32_t result;
    unused(state);
    rebrick_tls_init();
    result = rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION, 0, NULL, NULL);
    assert_int_equal(result, REBRICK_SUCCESS);

    rebrick_tls_context_new(&context_hamzakilic_com, "hamzakilic.com", SSL_VERIFY_NONE, SSL_SESS_CACHE_OFF, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET, SSL_OP_NO_COMPRESSION, "./data/domain.crt", "./data/domain.key");

    assert_int_equal(result, REBRICK_SUCCESS);

    fprintf(stdout, "****  %s ****\n", __FILE__);
    return 0;
}

static int teardown(void **state)
{
    unused(state);
    int32_t loop_counter;
    rebrick_tls_context_destroy(context_verify_none);
    context_verify_none = NULL;
    rebrick_tls_context_destroy(context_hamzakilic_com);
    context_hamzakilic_com = NULL;
    rebrick_tls_cleanup();
    loop(loop_counter, 100, TRUE);
    uv_loop_close(uv_default_loop());
    return 0;
}

static void on_error_occured_callback(rebrick_socket_t *socket, void *callback, int error)
{
    unused(socket);
    unused(callback);
    unused(error);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_debug(__FILE__, __LINE__, "error:%d occured\n", error);
}

static int32_t is_connected = FALSE;
static rebrick_http2socket_t *last_client_handle;
static void on_connection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{
    is_connected = TRUE;

    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
    last_client_handle = cast_to_http2socket(client_handle);
}
static int32_t is_connection_closed = 0;
static void on_connection_closed_callback(rebrick_socket_t *socket, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    is_connection_closed = 1;
}
static int32_t is_datareaded = FALSE;
static int32_t totalreaded_len = 0;
static char readedbuffer[131072] = {0};
static void on_data_read_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    unused(callback_data);

    is_datareaded = TRUE;
    fill_zero(readedbuffer, sizeof(readedbuffer));

    memcpy(readedbuffer, buffer, len);

    totalreaded_len += len;
}
static int32_t sended = FALSE;
static void on_data_send(rebrick_socket_t *socket, void *callback, void *source)
{
    unused(socket);
    unused(callback);
    unused(source);

    sended = TRUE;
}
static int32_t is_header_received = FALSE;
int32_t header_counter = 0;
rebrick_http_header_t *http_header;
int32_t last_headerstream_id = 0;
static void on_http_header_received(rebrick_socket_t *socket, int32_t stream_id, void *callback_data, rebrick_http_header_t *header)
{
    unused(socket);
    unused(callback_data);
    unused(header);
    //stream id is useless, at least this is not http2
    unused(stream_id);
    header_counter++;
    is_header_received = TRUE;
    http_header = header;
    last_headerstream_id = stream_id;
}

static int32_t is_bodyreaded = FALSE;
static int32_t totalreadedbody_len = 0;
static char readedbufferbody[131072] = {0};
static int32_t body_counter = 0;
static int32_t last_bodystream_id;
static void on_body_read_callback(rebrick_socket_t *socket, int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    //this is http, stream id is allways zero
    unused(stream_id);
    unused(callback_data);

    is_bodyreaded = TRUE;
    fill_zero(readedbufferbody, sizeof(readedbufferbody));

    memcpy(readedbufferbody, buffer, len);

    totalreadedbody_len += len;
    body_counter++;
    last_bodystream_id = stream_id;
}

static void deletesendata(void *ptr)
{
    if (ptr)
    {
        rebrick_buffer_t *buffer = cast(ptr, rebrick_buffer_t *);
        rebrick_buffer_destroy(buffer);
    }
}

static void http2_socket_as_client_create_get(void **tls)
{
    unused(tls);
    int32_t result;
    int32_t counter;

    rebrick_sockaddr_t destination;
    if (!*tls)
        rebrick_util_ip_port_to_addr("127.0.0.1", "9292", &destination);
    else
        rebrick_util_ip_port_to_addr("127.0.0.1", "9393", &destination);

    rebrick_http2socket_t *socket;
    is_connected = FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
    settings.entries[0] = maxstream;
    settings.settings_count = 1;

    create2(rebrick_http2socket_callbacks_t, callbacks);
    callbacks.on_accept = on_connection_accepted_callback;
    callbacks.on_connection_close = on_connection_closed_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_write = on_data_send;
    callbacks.on_error = on_error_occured_callback;
    callbacks.on_http_header_read = on_http_header_received;
    callbacks.on_http_body_read = on_body_read_callback;

    if (!*tls)
        result = rebrick_http2socket_new(&socket, NULL, NULL, destination, 0, &settings, &callbacks);
    else
        result = rebrick_http2socket_new(&socket, "hamzakilic.com", context_verify_none, destination, 0, &settings, &callbacks);
    assert_int_equal(result, 0);

    loop(counter, 1000, !is_connected);
    assert_int_equal(is_connected, TRUE);
    loop(counter, 1000, 1);
    rebrick_http_header_t *header;
    if (!*tls)
        result = rebrick_http_header_new(&header, "http", "localhost:9292", "GET", "/", 2, 0);
    else
        result = rebrick_http_header_new(&header, "https", "hamzakilic:9393", "GET", "/", 2, 0);
    assert_int_equal(result, REBRICK_SUCCESS);
    int stream_id = -1;
    is_bodyreaded = FALSE;
    result = rebrick_http2socket_send_header(socket, &stream_id, NGHTTP2_FLAG_NONE, header);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(stream_id, 1);
    is_header_received = FALSE;
    loop(counter, 1000, !is_header_received);
    loop(counter, 1000, !is_bodyreaded);
    assert_true(strstr(readedbufferbody, "hello http2"));

    rebrick_http2_stream_t *stream;
    result = rebrick_http2socket_get_stream(socket, stream_id, &stream);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_non_null(stream);
    assert_non_null(stream->received_header);
    assert_non_null(stream->send_header);

    assert_memory_equal(stream->send_header, header, sizeof(rebrick_http_header_t));

    assert_int_equal(stream->received_header->is_request, FALSE);
    assert_string_equal(stream->received_header->host, "");
    assert_string_equal(stream->received_header->path, "");
    assert_string_equal(stream->received_header->method, "");
    assert_string_equal(stream->received_header->scheme, "");
    assert_int_equal(stream->received_header->major_version, 2);
    assert_int_equal(stream->received_header->minor_version, 0);
    assert_int_equal(stream->received_header->status_code, 200);
    assert_string_equal(stream->received_header->status_code_str, "OK");
    const char *value;
    result = rebrick_http_header_get_header(stream->received_header, "content-type", &value);
    assert_non_null(value);
    assert_string_equal(value, "text/plain");

    rebrick_http2socket_destroy(socket);
    loop(counter, 1000, TRUE);
}

static void http2_socket_as_client_create_get_tls(void **start)
{
    unused(start);
    int32_t tmp = 10;
    int *val = &tmp;
    http2_socket_as_client_create_get(cast(&val, void **));
}

static void http2_socket_as_client_create_post(void **tls)
{
    unused(tls);
    int32_t result;
    int32_t counter;

    rebrick_sockaddr_t destination;

    if (!*tls)
        rebrick_util_ip_port_to_addr("127.0.0.1", "9292", &destination);
    else
        rebrick_util_ip_port_to_addr("127.0.0.1", "9393", &destination);

    rebrick_http2socket_t *socket;
    is_connected = FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
    settings.entries[0] = maxstream;
    settings.settings_count = 1;

    create2(rebrick_http2socket_callbacks_t, callbacks);
    callbacks.on_accept = on_connection_accepted_callback;
    callbacks.on_connection_close = on_connection_closed_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_write = on_data_send;
    callbacks.on_error = on_error_occured_callback;
    callbacks.on_http_header_read = on_http_header_received;
    callbacks.on_http_body_read = on_body_read_callback;

    if (!*tls)
        result = rebrick_http2socket_new(&socket, NULL, NULL, destination, 0, &settings, &callbacks);
    else
        result = rebrick_http2socket_new(&socket, "hamzakilic.com", context_verify_none, destination, 0, &settings, &callbacks);
    assert_int_equal(result, 0);

    loop(counter, 1000, !is_connected);
    assert_int_equal(is_connected, TRUE);
    loop(counter, 1000, 1);
    rebrick_http_header_t *header;
    result = rebrick_http_header_new(&header, "http", "localhost:9292", "POST", "/", 2, 0);
    assert_int_equal(result, REBRICK_SUCCESS);
    const char *data = "hello world";
    rebrick_http_header_add_header(header, "content-type", "text/plain");
    rebrick_http_header_add_header(header, "content-length", "11");
    int stream_id = -1;
    is_bodyreaded = FALSE;
    result = rebrick_http2socket_send_header(socket, &stream_id, NGHTTP2_FLAG_NONE, header);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(stream_id, 1);
    rebrick_clean_func_t func = {.ptr = 0, .func = 0};

    result = rebrick_http2socket_send_body(socket, stream_id, (NGHTTP2_FLAG_END_STREAM << 8) | NGHTTP2_DATA_FLAG_EOF, cast(data, uint8_t *), 11, func);
    loop(counter, 1000, TRUE);
    is_header_received = FALSE;
    loop(counter, 1000, !is_header_received);
    loop(counter, 100, !is_bodyreaded);
    assert_true(strstr(readedbufferbody, "hello http2 post:hello world"));

    rebrick_http2_stream_t *stream;
    result = rebrick_http2socket_get_stream(socket, stream_id, &stream);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_null(stream);

    rebrick_http2socket_destroy(socket);
    loop(counter, 100, TRUE);
}

static void http2_socket_as_client_create_post_tls(void **start)
{
    unused(start);
    int32_t tmp = 10;
    int *val = &tmp;
    http2_socket_as_client_create_post(cast(&val, void **));
}

rebrick_sockaddr_t resolved_addr;
int32_t resolved = FALSE;
static void on_resolve(const char *domain, int32_t type, rebrick_sockaddr_t addr)
{
    unused(domain);
    unused(type);
    resolved = TRUE;
    resolved_addr = addr;
}

static int32_t is_header_received_push = FALSE;
int32_t header_counter_push = 0;
rebrick_http_header_t http_headers[12];

static void on_http_header_received_for_push(rebrick_socket_t *socket, int32_t stream_id, void *callback_data, rebrick_http_header_t *header)
{
    unused(socket);
    unused(callback_data);
    unused(header);
    //stream id is useless, at least this is not http2
    unused(stream_id);

    is_header_received_push = TRUE;
    memcpy(&http_headers[header_counter_push++], header, sizeof(rebrick_http_header_t));
    last_headerstream_id = stream_id;
}

static int32_t is_bodyreaded_push = FALSE;
static char readedbufferbody_push[12][131072] = {0};
static int32_t body_counter_push = 0;

static void on_body_read_callback_for_push(rebrick_socket_t *socket, int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    //this is http, stream id is allways zero
    unused(stream_id);
    unused(callback_data);

    is_bodyreaded_push = TRUE;
    fill_zero(&readedbufferbody_push[body_counter_push], sizeof(readedbufferbody_push[0]));

    memcpy(&readedbufferbody_push[body_counter_push++], buffer, len);
}

int32_t pushed_counter = 0;
rebrick_http_header_t *push_header;
int32_t last_pushstream_id = 0;
int32_t is_pushed_received = FALSE;
rebrick_http_header_t push_headers[12];
static void on_http2_push_stream(rebrick_socket_t *socket, void *callback_data, int32_t stream_id, int32_t push_stream_id, rebrick_http_header_t *header)
{
    unused(socket);
    unused(callback_data);
    unused(stream_id);
    unused(push_stream_id);
    unused(header);

    memcpy(&push_headers[pushed_counter++], header, sizeof(rebrick_http_header_t));
    last_pushstream_id = stream_id;
    is_pushed_received = TRUE;
}

static void http2_socket_as_client_create_get_server_push_streams(void **tls)
{
    unused(tls);
    int32_t result;
    int32_t counter;

    /*  result=rebrick_resolve("nghttp2.org",A,on_resolve,NULL);
    assert_int_equal(result,TRUE);
    loop(counter,1000,!resolved);
    assert_int_equal(resolved,TRUE); */

    rebrick_sockaddr_t destination;

    if (!*tls)
        rebrick_util_ip_port_to_addr("127.0.0.1", "9292", &destination);
    else
        rebrick_util_ip_port_to_addr("127.0.0.1", "9393", &destination);

    rebrick_http2socket_t *socket;
    is_connected = FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
    settings.entries[0] = maxstream;
    settings.settings_count = 1;

    create2(rebrick_http2socket_callbacks_t, callbacks);
    callbacks.on_accept = on_connection_accepted_callback;
    callbacks.on_connection_close = on_connection_closed_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_write = on_data_send;
    callbacks.on_error = on_error_occured_callback;
    callbacks.on_http_header_read = on_http_header_received_for_push;
    callbacks.on_http_body_read = on_body_read_callback_for_push;
    callbacks.on_push_read = on_http2_push_stream;

    if (!*tls)
        result = rebrick_http2socket_new(&socket, NULL, NULL, destination, 0, &settings, &callbacks);
    else
        result = rebrick_http2socket_new(&socket, "hamzakilic.com", context_verify_none, destination, 0, &settings, &callbacks);
    assert_int_equal(result, 0);

    loop(counter, 1000, !is_connected);
    assert_int_equal(is_connected, TRUE);
    loop(counter, 1000, 1);
    rebrick_http_header_t *header;
    result = rebrick_http_header_new(&header, "http", "localhost:9292", "GET", "/push", 2, 0);
    assert_int_equal(result, REBRICK_SUCCESS);
    int stream_id = -1;
    is_bodyreaded = FALSE;
    is_pushed_received = FALSE;
    is_header_received = FALSE;
    header_counter_push = 0;
    body_counter_push = 0;
    pushed_counter = 0;

    result = rebrick_http2socket_send_header(socket, &stream_id, NGHTTP2_FLAG_NONE, header);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(stream_id, 1);

    loop(counter, 10000, TRUE);

    assert_int_equal(header_counter_push, 3);
    assert_int_equal(body_counter_push, 3);
    assert_int_equal(pushed_counter, 2);

    assert_int_equal(http_headers[0].major_version, 2);
    assert_int_equal(http_headers[0].is_request, FALSE);
    assert_int_equal(http_headers[0].status_code, 200);
    assert_string_equal(http_headers[0].status_code_str, "OK");

    assert_int_equal(http_headers[1].major_version, 2);
    assert_int_equal(http_headers[1].is_request, FALSE);
    assert_int_equal(http_headers[1].status_code, 200);
    assert_string_equal(http_headers[1].status_code_str, "OK");

    assert_int_equal(http_headers[2].major_version, 2);
    assert_int_equal(http_headers[2].is_request, FALSE);
    assert_int_equal(http_headers[2].status_code, 200);
    assert_string_equal(http_headers[2].status_code_str, "OK");

    assert_int_equal(push_headers[0].is_request, TRUE);
    assert_true(strstr(push_headers[0].path, "/deneme"));
    assert_int_equal(push_headers[0].major_version, 2);
    assert_string_equal(push_headers[0].host, "localhost:9292");

    assert_int_equal(push_headers[1].is_request, TRUE);
    assert_true(strstr(push_headers[1].path, "/deneme"));
    assert_int_equal(push_headers[1].major_version, 2);
    assert_string_equal(push_headers[1].host, "localhost:9292");

    assert_true(strstr(readedbufferbody_push[0], "push"));
    assert_true(strstr(readedbufferbody_push[1], "push"));
    assert_true(strstr(readedbufferbody_push[2], "push"));

    // loop(counter,10000,TRUE);

    rebrick_http2socket_destroy(socket);
    loop(counter, 100, TRUE);
}

static void http2_socket_as_client_create_get_server_push_streams_tls(void **start)
{
    unused(start);
    int32_t tmp = 10;
    int *val = &tmp;
    http2_socket_as_client_create_get_server_push_streams(cast(&val, void **));
}

static void http2_socket_as_serverserver_get(void **tls)
{
    unused(tls);
    int32_t result;
    int32_t counter;
    char current_time_str[32] = {0};
    unused(current_time_str);

    /*  result=rebrick_resolve("nghttp2.org",A,on_resolve,NULL);
    assert_int_equal(result,TRUE);
    loop(counter,1000,!resolved);
    assert_int_equal(resolved,TRUE); */

    rebrick_sockaddr_t destination;
    if (!*tls)
        rebrick_util_ip_port_to_addr("127.0.0.1", "9898", &destination);
    else
        rebrick_util_ip_port_to_addr("127.0.0.1", "9899", &destination);

    rebrick_http2socket_t *socket;
    is_connected = FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
    settings.entries[0] = maxstream;
    settings.settings_count = 1;

    create2(rebrick_http2socket_callbacks_t, callbacks);
    callbacks.on_accept = on_connection_accepted_callback;
    callbacks.on_connection_close = on_connection_closed_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_write = on_data_send;
    callbacks.on_error = on_error_occured_callback;
    callbacks.on_http_header_read = on_http_header_received;
    is_connected = FALSE;
    is_header_received = FALSE;

    if (!*tls)
        result = rebrick_http2socket_new(&socket, NULL, NULL, destination, 10, &settings, &callbacks);
    else
        result = rebrick_http2socket_new(&socket, NULL, context_hamzakilic_com, destination, 10, &settings, &callbacks);

    printf("http2 server started on localhost:9898\n");
    if (!*tls)
        printf("execute nghttp -v http://localhost:9898/push\n");
    else
        printf("execute nghttp -v https://localhost:9899/push\n");

    assert_int_equal(result, 0);

    loop(counter, 100000, !is_connected);

    if (is_connected)
    {

        rebrick_http_header_t *header_response;
        rebrick_http_header_new3(&header_response, Rebrick_HttpStatus_OK, 2, 0);
        rebrick_http_header_add_header(header_response, "content-type", "text/plain");

        loop(counter, 10000, !is_header_received);

        int32_t streamid = last_headerstream_id;

        /* rebrick_http2socket_send_rststream(last_client_handle,streamid,10);
    loop(counter,10000,TRUE); */
        result = rebrick_http2socket_send_header(last_client_handle, &streamid, NGHTTP2_FLAG_NONE, header_response);
        loop(counter, 100, TRUE);
        const char *msg = "hello http2 server\n";
        create2(rebrick_clean_func_t, func);
        rebrick_http2socket_send_body(last_client_handle, streamid, NGHTTP2_FLAG_END_STREAM, cast_to_uint8ptr(msg), strlen(msg), func);
        loop(counter, 1000, TRUE);
        assert_int_equal(result, REBRICK_SUCCESS);
        uint8_t test[8] = {1, 2, 3, 4};
        rebrick_http2socket_send_ping(last_client_handle, NGHTTP2_FLAG_NONE, test);
        loop(counter, 10000, TRUE);
    }

    rebrick_http2socket_destroy(socket);
    loop(counter, 100, TRUE);
}

static void http2_socket_as_serverserver_get_tls(void **start)
{
    unused(start);
    int32_t tmp = 10;
    int *val = &tmp;
    http2_socket_as_serverserver_get(cast(&val, void **));
}

static void http2_socket_as_serverserver_create_get_server_push_streams(void **tls)
{
    unused(tls);
    int32_t result;
    int32_t counter;
    char current_time_str[32] = {0};
    unused(current_time_str);

    /*  result=rebrick_resolve("nghttp2.org",A,on_resolve,NULL);
    assert_int_equal(result,TRUE);
    loop(counter,1000,!resolved);
    assert_int_equal(resolved,TRUE); */

    rebrick_sockaddr_t destination;
    if (!*tls)
        rebrick_util_ip_port_to_addr("127.0.0.1", "9898", &destination);
    else
        rebrick_util_ip_port_to_addr("127.0.0.1", "9899", &destination);

    rebrick_http2socket_t *socket;
    is_connected = FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
    settings.entries[0] = maxstream;
    settings.settings_count = 1;

    create2(rebrick_http2socket_callbacks_t, callbacks);
    callbacks.on_accept = on_connection_accepted_callback;
    callbacks.on_connection_close = on_connection_closed_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_write = on_data_send;
    callbacks.on_error = on_error_occured_callback;
    callbacks.on_http_header_read = on_http_header_received;
    is_connected = FALSE;
    is_header_received = FALSE;
    if (!*tls)
        result = rebrick_http2socket_new(&socket, NULL, NULL, destination, 10, &settings, &callbacks);
    else
        result = rebrick_http2socket_new(&socket, NULL, context_hamzakilic_com, destination, 10, &settings, &callbacks);

    if (!*tls)
        printf("execute nghttp -v http://localhost:9898/push\n");
    else
        printf("execute nghttp -v https://localhost:9899/push\n");
    assert_int_equal(result, 0);

    loop(counter, 100000, !is_connected);

    if (is_connected)
    {

        rebrick_http_header_t *header_response;
        rebrick_http_header_new3(&header_response, Rebrick_HttpStatus_OK, 2, 0);
        rebrick_http_header_add_header(header_response, "content-type", "text/plain");

        loop(counter, 10000, !is_header_received);
        int32_t streamid = last_headerstream_id;
        result = rebrick_http2socket_send_header(last_client_handle, &streamid, NGHTTP2_FLAG_NONE, header_response);
        loop(counter, 1000, TRUE);
        const char *msg = "hello http2 server\n";
        create2(rebrick_clean_func_t, func);
        rebrick_http2socket_send_body(last_client_handle, streamid, NGHTTP2_FLAG_END_STREAM, cast_to_uint8ptr(msg), strlen(msg), func);
        loop(counter, 1000, TRUE);
        assert_int_equal(result, REBRICK_SUCCESS);

        rebrick_http_header_t *header_p1;
        rebrick_http_header_new(&header_p1, "http", "localhost:9898", "GET", "/test1.txt", 2, 0);
        rebrick_http_header_add_header(header_p1, "content-type", "text/plain");
        int32_t pushstream_id1 = 0;
        result = rebrick_http2socket_send_push(last_client_handle, &pushstream_id1, streamid, header_p1);
        assert_int_equal(result, REBRICK_SUCCESS);
        assert_true(pushstream_id1);

        rebrick_http_header_t *header_p2;
        rebrick_http_header_new(&header_p2, "http", "localhost:9898", "GET", "/test2.txt", 2, 0);
        rebrick_http_header_add_header(header_p2, "content-type", "text/plain");

        int32_t pushstream_id2 = 0;
        result = rebrick_http2socket_send_push(last_client_handle, &pushstream_id2, streamid, header_p2);
        assert_int_equal(result, REBRICK_SUCCESS);
        assert_true(pushstream_id2);

        rebrick_http_header_t *push_response1;
        rebrick_http_header_new4(&push_response1, 200, 2, 0);
        rebrick_http_header_add_header(push_response1, "content-type", "text/plain");
        rebrick_http2socket_send_header(last_client_handle, &pushstream_id1, NGHTTP2_FLAG_NONE, push_response1);
        const char *content1 = "hello content1\n";
        create2(rebrick_clean_func_t, clean);
        rebrick_http2socket_send_body(last_client_handle, pushstream_id1, NGHTTP2_FLAG_END_STREAM, cast_to_uint8ptr(content1), strlen(content1), clean);
        loop(counter, 100, TRUE);

        rebrick_http_header_t *push_response2;
        rebrick_http_header_new4(&push_response2, 200, 2, 0);
        rebrick_http_header_add_header(push_response2, "content-type", "text/plain");
        rebrick_http2socket_send_header(last_client_handle, &pushstream_id2, NGHTTP2_FLAG_NONE, push_response2);
        const char *content2 = "hello content2\n";

        rebrick_http2socket_send_body(last_client_handle, pushstream_id2, NGHTTP2_FLAG_END_STREAM, cast_to_uint8ptr(content2), strlen(content1), clean);
        loop(counter, 100, TRUE);
    }

    rebrick_http2socket_destroy(socket);
    loop(counter, 100, TRUE);
}

static void http2_socket_as_serverserver_create_get_server_push_streams_tls(void **start)
{

    unused(start);
    int32_t tmp = 10;
    int *val = &tmp;
    http2_socket_as_serverserver_create_get_server_push_streams(cast(&val, void **));
}

int test_rebrick_http2socket(void)
{
    const struct CMUnitTest tests[] = {

        //cmocka_unit_test(http2_socket_as_client_create_get),
        // cmocka_unit_test(http2_socket_as_client_create_get_tls),
        // cmocka_unit_test(http2_socket_as_client_create_post),
        // cmocka_unit_test(http2_socket_as_client_create_post_tls),
        //cmocka_unit_test(http2_socket_as_client_create_get_server_push_streams),
        //cmocka_unit_test(http2_socket_as_client_create_get_server_push_streams_tls),
        //cmocka_unit_test(http2_socket_as_serverserver_get),
        cmocka_unit_test(http2_socket_as_serverserver_get_tls),
        //cmocka_unit_test(http2_socket_as_serverserver_create_get_server_push_streams),
        // cmocka_unit_test(http2_socket_as_serverserver_create_get_server_push_streams_tls)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
