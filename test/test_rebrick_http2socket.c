#include "./http/rebrick_http2socket.h"
#include "cmocka.h"
#include <unistd.h>


#define loop(var,a,x) \
    var=a; \
 while (var-- && (x)){ usleep(100); uv_run(uv_default_loop(), UV_RUN_NOWAIT);}

static rebrick_tls_context_t *context_verify_none = NULL;
static int setup(void**state){
    unused(state);
    rebrick_tls_init();
    rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL,0, NULL, NULL);
    fprintf(stdout,"****  %s ****\n",__FILE__);
    return 0;
}

static int teardown(void **state){
    unused(state);
    int32_t loop_counter;
    rebrick_tls_context_destroy(context_verify_none);
    context_verify_none = NULL;
    rebrick_tls_cleanup();
    loop(loop_counter,100,TRUE);
    uv_loop_close(uv_default_loop());
    return 0;
}


static void on_error_occured_callback(rebrick_socket_t *socket,void *callback,int error){
    unused(socket);
    unused(callback);
    unused(error);
    rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));

}

static int32_t is_connected = FALSE;

static void on_connection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{
    is_connected = TRUE;

    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);

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
static int32_t sended=FALSE;
static void on_data_send(rebrick_socket_t *socket,void *callback,void *source){
    unused(socket);
    unused(callback);
    unused(source);

sended=TRUE;


}
static int32_t header_received=FALSE;
static void on_http_header_received(rebrick_socket_t *socket,int32_t stream_id,void *callback_data,rebrick_http_header_t *header){
    unused(socket);
    unused(callback_data);
    unused(header);
    //stream id is useless, at least this is not http2
    unused(stream_id);

    header_received=TRUE;

}


static int32_t is_bodyreaded = FALSE;
static int32_t totalreadedbody_len = 0;
static char readedbufferbody[131072] = {0};
static void on_body_read_callback(rebrick_socket_t *socket,int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
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


}

static void deletesendata(void *ptr){
    if(ptr){
        rebrick_buffer_t *buffer=cast(ptr,rebrick_buffer_t *);
        rebrick_buffer_destroy(buffer);
    }
}






static void http2_socket_as_client_create_get(void **start){
    unused(start);
    int32_t result;
    int32_t counter;

    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "9191", &destination);

    rebrick_http2socket_t *socket;
    is_connected=FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream={NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,100};
    settings.entries[0]=maxstream;
    settings.settings_count=1;

    new2(rebrick_http2socket_callbacks_t,callbacks);
    callbacks.on_connection_accepted=on_connection_accepted_callback;
    callbacks.on_connection_closed=on_connection_closed_callback;
    callbacks.on_data_received=on_data_read_callback;
    callbacks.on_data_sended=on_data_send;
    callbacks.on_error_occured=on_error_occured_callback;
    callbacks.on_http_header_received=on_http_header_received;
    callbacks.on_http_body_received=on_body_read_callback;

    result = rebrick_http2socket_new(&socket,NULL, NULL, destination,0,
                &settings,&callbacks);
    assert_int_equal(result, 0);

    loop(counter,1000,!is_connected);
    assert_int_equal(is_connected,TRUE);
    loop(counter,1000,1);
    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"http","localhost:9191","GET","/",2,0);
    assert_int_equal(result,REBRICK_SUCCESS);
    int stream_id=-1;
    is_bodyreaded=FALSE;
    result=rebrick_http2socket_send_header(socket,&stream_id,NGHTTP2_FLAG_NONE,header);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_int_equal(stream_id,1);
    header_received=FALSE;
    loop(counter,1000,!header_received);
    loop(counter,100,!is_bodyreaded);
    assert_true(strstr(readedbufferbody,"hello http2"));

    rebrick_http2stream_t *stream;
    result=rebrick_http2socket_get_stream(socket,stream_id,&stream);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_non_null(stream);
    assert_non_null(stream->received_header);
    assert_non_null(stream->send_header);

    assert_memory_equal(stream->send_header,header,sizeof(rebrick_http_header_t));


    assert_int_equal(stream->received_header->is_request,FALSE);
    assert_string_equal(stream->received_header->host,"");
    assert_string_equal(stream->received_header->path,"");
    assert_string_equal(stream->received_header->method,"");
    assert_string_equal(stream->received_header->scheme,"");
    assert_int_equal(stream->received_header->major_version,2);
    assert_int_equal(stream->received_header->minor_version,0);
    assert_int_equal(stream->received_header->status_code,200);
    assert_string_equal(stream->received_header->status_code_str,"OK");
    const char *value;
    result=rebrick_http_header_get_header(header,"content-type",&value);
    assert_non_null(value);
    assert_string_equal(value,"text/plain");


    rebrick_http2socket_destroy(socket);
    loop(counter,100,TRUE);
}




static void http2_socket_as_client_create_post(void **start){
    unused(start);
    int32_t result;
    int32_t counter;

    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "9191", &destination);

    rebrick_http2socket_t *socket;
    is_connected=FALSE;
    rebrick_http2_socket_settings_t settings;
    rebrick_http2_settings_entry maxstream={NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,100};
    settings.entries[0]=maxstream;
    settings.settings_count=1;

    new2(rebrick_http2socket_callbacks_t,callbacks);
    callbacks.on_connection_accepted=on_connection_accepted_callback;
    callbacks.on_connection_closed=on_connection_closed_callback;
    callbacks.on_data_received=on_data_read_callback;
    callbacks.on_data_sended=on_data_send;
    callbacks.on_error_occured=on_error_occured_callback;
    callbacks.on_http_header_received=on_http_header_received;
    callbacks.on_http_body_received=on_body_read_callback;

    result = rebrick_http2socket_new(&socket,NULL, NULL, destination,0,
                &settings,&callbacks);
    assert_int_equal(result, 0);

    loop(counter,1000,!is_connected);
    assert_int_equal(is_connected,TRUE);
    loop(counter,1000,1);
    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"http","localhost:9191","POST","/",2,0);
    assert_int_equal(result,REBRICK_SUCCESS);
    const char *data="hello world";
    rebrick_http_header_add_header(header,"content-type","text/plain");
    rebrick_http_header_add_header(header,"content-length","11");
    int stream_id=-1;
    is_bodyreaded=FALSE;
    result=rebrick_http2socket_send_header(socket,&stream_id,NGHTTP2_FLAG_NONE,header);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_int_equal(stream_id,1);
    rebrick_clean_func_t func={.ptr=0,.func=0};

    result=rebrick_http2socket_send_body(socket,stream_id,(NGHTTP2_FLAG_END_STREAM<<8)|NGHTTP2_DATA_FLAG_EOF,cast(data,uint8_t*),11,func);
    loop(counter,1000,TRUE);
    header_received=FALSE;
    loop(counter,1000,!header_received);
    loop(counter,100,!is_bodyreaded);
    assert_true(strstr(readedbufferbody,"hello http2 post:hello world"));

    rebrick_http2stream_t *stream;
    result=rebrick_http2socket_get_stream(socket,stream_id,&stream);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_null(stream);



    rebrick_http2socket_destroy(socket);
    loop(counter,100,TRUE);
}














int test_rebrick_http2socket(void) {
    const struct CMUnitTest tests[] = {

        //cmocka_unit_test(http2_socket_as_client_create_get),
        cmocka_unit_test(http2_socket_as_client_create_post),


    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

