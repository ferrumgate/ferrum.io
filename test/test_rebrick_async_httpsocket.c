#include "rebrick_async_httpsocket.h"
#include "cmocka.h"

static int setup(void**state){
    unused(state);
    fprintf(stdout,"****  %s ****\n",__FILE__);
    return 0;
}

static int teardown(void **state){
    unused(state);
    return 0;
}

static int32_t on_error_occured_callback(rebrick_async_socket_t *socket,void *callback,int error){
    unused(socket);
    unused(callback);
    unused(error);
    rebrick_async_tlssocket_destroy(cast(socket, rebrick_async_tlssocket_t *));
    return REBRICK_SUCCESS;
}

static int32_t is_connected = 1;

static int32_t on_connection_accepted_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    is_connected = status;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
    return REBRICK_SUCCESS;
}
static int32_t is_connection_closed = 0;
static int32_t on_connection_closed_callback(rebrick_async_socket_t *socket, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    is_connection_closed = 1;

    return REBRICK_SUCCESS;
}
static int32_t is_datareaded = 0;
static int32_t totalreaded_len = 0;
static char readedbuffer[131072] = {0};
static int32_t on_data_read_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    unused(callback_data);

        is_datareaded = 1;
        fill_zero(readedbuffer, sizeof(readedbuffer));

        memcpy(readedbuffer, buffer, len);

        totalreaded_len += len;


    return 0;
}
static int32_t header_received=0;
static int32_t on_http_header_received(rebrick_async_socket_t *socket,void *callback_data,rebrick_http_header_t *header,int status){
    unused(socket);
    unused(callback_data);
    unused(header);
    unused(status);
    header_received=1;
    return REBRICK_SUCCESS;
}


static void http_socket_as_client_create(void **start){
    unused(start);
    int32_t result;
     rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "80", &destination);

    rebrick_async_httpsocket_t *socket;

    result = rebrick_async_httpsocket_new(&socket, NULL, destination, NULL,
                on_connection_accepted_callback,
                on_connection_closed_callback,
                on_data_read_callback, NULL,on_error_occured_callback,0,on_http_header_received,NULL);
    assert_int_equal(result, 0);


    rebrick_async_httpsocket_destroy(socket);



}




int test_rebrick_async_httpsocket(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(http_socket_as_client_create)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

