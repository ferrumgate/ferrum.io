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

static void rebrick_http_keyvalue_test(void **state){
    unused(state);
    int32_t result;
    rebrick_http_key_value_t *keyvalue;
    result=rebrick_http_key_value_new(&keyvalue,"hamza","kilic");
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_memory_equal(keyvalue->key,"hamza",6);
    assert_memory_equal(keyvalue->value,"kilic",6);
    assert_int_equal(keyvalue->keylen,6);
    assert_int_equal(keyvalue->valuelen,6);
    rebrick_http_key_value_destroy(keyvalue);


}


static void rebrick_http_keyvalue_test2(void **state){
    unused(state);
    int32_t result;
    rebrick_http_key_value_t *keyvalue;
    result=rebrick_http_key_value_new2(&keyvalue,"hamza",6,"kilic",6);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_memory_equal(keyvalue->key,"hamza",6);
    assert_memory_equal(keyvalue->value,"kilic",6);
    assert_int_equal(keyvalue->keylen,6);
    assert_int_equal(keyvalue->valuelen,6);
    rebrick_http_key_value_destroy(keyvalue);


}

static void rebrick_http_header_test(void **state){
    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"/api/metrics","POST",1);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_string_equal(header->path,"/api/metrics");
    assert_string_equal(header->method,"POST");
    assert_int_equal(header->major_version,1);
    assert_int_equal(header->minor_version,1);
    assert_null(header->headers);

    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_test2(void **state){
    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result=rebrick_http_header_new2(&header,"/api/metrics","POST",1,1);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_string_equal(header->path,"/api/metrics");
    assert_string_equal(header->method,"POST");
    assert_int_equal(header->major_version,1);
    assert_int_equal(header->minor_version,1);
    assert_null(header->headers);
    result=rebrick_http_header_add_header(header,"content-type","application/json");
    assert_int_equal(result,REBRICK_SUCCESS);
    int32_t founded;
    result=rebrick_http_header_contains_key(header,"content-type",&founded);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_int_equal(founded,TRUE);



    result=rebrick_http_header_contains_key(header,"Content-Type",&founded);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_int_equal(founded,FALSE);

    result=rebrick_http_header_remove_key(header,"content-type");
    assert_int_equal(result,REBRICK_SUCCESS);

     result=rebrick_http_header_contains_key(header,"content-type",&founded);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_int_equal(founded,FALSE);

    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_to_buffer_test(void **state){
         unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result=rebrick_http_header_new2(&header,"/api/metrics","POST",1,1);
    assert_int_equal(result,REBRICK_SUCCESS);
    result=rebrick_http_header_add_header(header,"content-type","application/json");
    assert_int_equal(result,REBRICK_SUCCESS);
    result=rebrick_http_header_add_header(header,"host","hamzakilic.com");
    assert_int_equal(result,REBRICK_SUCCESS);
    rebrick_buffer_t *buffer;
    result=rebrick_http_header_to_buffer(header,&buffer);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_string_equal(buffer->buf,"POST /api/metrics HTTP/1.1\r\ncontent-type:application/json\r\nhost:hamzakilic.com\r\n\r\n");
    rebrick_buffer_destroy(buffer);
    rebrick_http_header_destroy(header);

}


static int32_t on_error_occured_callback(rebrick_socket_t *socket,void *callback,int error){
    unused(socket);
    unused(callback);
    unused(error);
    rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));
    return REBRICK_SUCCESS;
}

static int32_t is_connected = 1;

static int32_t on_connection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    is_connected = status;
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

    rebrick_util_ip_port_to_addr("127.0.0.1", "80", &destination);

    rebrick_httpsocket_t *socket;
    is_connected=0;

    result = rebrick_httpsocket_new(&socket, NULL, destination, NULL,
                on_connection_accepted_callback,
                on_connection_closed_callback,
                on_data_read_callback, NULL,on_error_occured_callback,0,on_http_header_received,NULL);
    assert_int_equal(result, 0);

    loop(100,!is_connected);

    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header, "/api/get","GET",1);
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
    result=rebrick_httpsocket_send(socket,buffer->buf,buffer->len,cleanfunc);
    assert_int_equal(result,REBRICK_SUCCESS);
    loop(100,(!sended));
    loop(100,!header_received);
    loop(100,!is_bodyreaded);


    rebrick_http_header_destroy(header);




    rebrick_httpsocket_destroy(socket);
    loop(100,TRUE);
}




int test_rebrick_httpsocket(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_http_keyvalue_test),
        cmocka_unit_test(rebrick_http_keyvalue_test2),
        cmocka_unit_test(rebrick_http_header_test),
        cmocka_unit_test(rebrick_http_header_test2),
        cmocka_unit_test(rebrick_http_header_to_buffer_test),

        cmocka_unit_test(http_socket_as_client_create)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

