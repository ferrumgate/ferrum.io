#include "./http/rebrick_httpsocket.h"
#include "cmocka.h"
#include <unistd.h>

static int setup(void**state){
    unused(state);
    rebrick_tls_init();
    fprintf(stdout,"****  %s ****\n",__FILE__);
    return 0;
}

static int teardown(void **state){
    unused(state);
    rebrick_tls_cleanup();
    int32_t counter = 100;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }
    uv_loop_close(uv_default_loop());
    return 0;
}


static int32_t on_error_occured_callback(rebrick_socket_t *socket,void *callback,int error){
    unused(socket);
    unused(callback);
    unused(error);
    rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));
    return REBRICK_SUCCESS;
}

static int32_t is_connected = FALSE;

static int32_t on_connection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    is_connected = TRUE;
    unused(status);
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
    return REBRICK_SUCCESS;
}
static int32_t is_connection_closed = 0;
static int32_t on_connection_closed_callback(rebrick_socket_t *socket, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    is_connection_closed = 1;

    return REBRICK_SUCCESS;
}
static int32_t is_datareaded = FALSE;
static int32_t totalreaded_len = 0;
static char readedbuffer[131072] = {0};
static int32_t on_data_read_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
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


    return 0;
}
static int32_t sended=FALSE;
static int32_t on_data_send(rebrick_socket_t *socket,void *callback,void *source,int status){
    unused(socket);
    unused(callback);
    unused(source);
    unused(status);
sended=TRUE;
    return REBRICK_SUCCESS;

}
static int32_t header_received=FALSE;
static int32_t on_http_header_received(rebrick_socket_t *socket,void *callback_data,rebrick_http_header_t *header,int status){
    unused(socket);
    unused(callback_data);
    unused(header);
    unused(status);
    header_received=TRUE;
    return REBRICK_SUCCESS;
}


static int32_t is_bodyreaded = FALSE;
static int32_t totalreadedbody_len = 0;
static char readedbufferbody[131072] = {0};
static int32_t on_body_read_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    unused(callback_data);

        is_bodyreaded = TRUE;
        fill_zero(readedbufferbody, sizeof(readedbufferbody));

        memcpy(readedbufferbody, buffer, len);

        totalreadedbody_len += len;


    return 0;
}

void deletesendata(void *ptr){
    if(ptr){
        rebrick_buffer_t *buffer=cast(ptr,rebrick_buffer_t *);
        rebrick_buffer_destroy(buffer);
    }
}




#define loop(a,x) \
    counter=a; \
 while (counter-- && (x)){ usleep(100); uv_run(uv_default_loop(), UV_RUN_NOWAIT);}

static void http_socket_as_client_create(void **start){
    unused(start);
    int32_t result;
    int32_t counter=0;
    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "9090", &destination);

    rebrick_httpsocket_t *socket;
    is_connected=0;

    result = rebrick_httpsocket_new(&socket, NULL, destination, NULL,
                on_connection_accepted_callback,
                on_connection_closed_callback,
                on_data_read_callback, on_data_send,on_error_occured_callback,0,on_http_header_received,on_body_read_callback);
    assert_int_equal(result, 0);

    loop(1000,!is_connected);
    assert_int_equal(is_connected,TRUE);

    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"GET", "/api/get",1,1);
    assert_int_equal(result,REBRICK_SUCCESS);
    rebrick_buffer_t *buffer;
    result=rebrick_http_header_to_buffer(header,&buffer);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_non_null(buffer);

    sended=FALSE;
    header_received=FALSE;
    is_bodyreaded=FALSE;
    rebrick_clean_func_t cleanfunc;
    cleanfunc.func=deletesendata;
    cleanfunc.ptr=buffer;
    result=rebrick_httpsocket_send(socket,cast(buffer->buf,char*),buffer->len,cleanfunc);
    assert_int_equal(result,REBRICK_SUCCESS);
    loop(1000,(!sended));
    assert_int_equal(sended,TRUE);
    loop(100,!header_received);
    assert_int_equal(header_received,TRUE);
    loop(100,!is_bodyreaded);
    assert_int_equal(is_bodyreaded,TRUE);
    assert_non_null(socket->header);
    assert_int_equal(socket->header->major_version,1);
    assert_int_equal(socket->header->minor_version,1);
    assert_int_equal(socket->header->is_request,FALSE);
    assert_string_equal(socket->header->path,"");
    assert_string_equal(socket->header->method,"");
    assert_string_equal(socket->header->status_code_str,"OK");
    assert_int_equal(socket->header->status_code,200);
    const char *value;
    rebrick_http_header_get_header(socket->header,"X-Powered-By",&value);
    assert_string_equal(value,"Express");
    rebrick_http_header_get_header(socket->header,"Content-Type",&value);
    assert_string_equal(value,"text/html; charset=utf-8");
    rebrick_http_header_get_header(socket->header,"Content-Length",&value);
    assert_string_equal(value,"25");
     /*rebrick_http_header_get_header(socket->header,"ETag",&value);
    assert_string_equal(value,"W/\"19-EE0dTSKO8nU0PWVui0tLx8f6m9I\"");
     rebrick_http_header_get_header(socket->header,"Date",&value);
    assert_string_equal(value,"Sun, 22 Sep 2019 20:14:00 GMT");*/
     rebrick_http_header_get_header(socket->header,"Connection",&value);
    assert_string_equal(value,"keep-alive");


    assert_string_equal(readedbufferbody,"get captured successfully");



    rebrick_http_header_destroy(header);




    rebrick_httpsocket_destroy(socket);
    loop(100,TRUE);
}






int test_rebrick_httpsocket(void) {
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(http_socket_as_client_create)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

