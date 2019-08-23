#include "rebrick_tls.h"
#include "rebrick_async_tlssocket.h"
#include "cmocka.h"
#include <unistd.h>

static rebrick_tls_context_t *context_verify_none;
static rebrick_tls_context_t *context_server;
static rebrick_tls_context_t *context_verify;

static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);

    rebrick_tls_init();
    rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, NULL, NULL);
    rebrick_tls_context_new(&context_server, "server", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, "./data/domain.crt", "./data/domain.key");
    rebrick_tls_context_new(&context_verify, "clientverify", SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, NULL, NULL);

    return 0;
}

static int teardown(void **state)
{
    unused(state);
    rebrick_tls_context_destroy(context_verify_none);
    rebrick_tls_context_destroy(context_server);
    rebrick_tls_context_destroy(context_verify);
    context_verify = NULL;
    context_server = NULL;
    context_verify_none = NULL;
    return 0;
}

int32_t is_connected = 1;

int32_t after_connection_accepted_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    is_connected = status;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
    return REBRICK_SUCCESS;
}
int32_t is_connection_closed = 0;
int32_t after_connection_closed_callback(rebrick_async_socket_t *socket, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    is_connection_closed = 1;


    return REBRICK_SUCCESS;
}
int32_t is_datareaded = 0;
int32_t totalreaded_len = 0;
char readedbuffer[65536 * 2];
static int32_t after_data_read_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    unused(callback_data);
    is_datareaded = 1;
    memset(readedbuffer, 0, sizeof(readedbuffer));
    memcpy(readedbuffer, buffer, len);
     totalreaded_len += len;
    printf("totalreaded len:%d\n",totalreaded_len);
    return 0;
}

static void ssl_client(void **start)
{
    unused(start);
    int32_t result;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("104.20.22.46", "443", &destination);

    rebrick_async_tlssocket_t *tlsclient;
    result = rebrick_async_tlssocket_new(&tlsclient, context_verify_none, destination, NULL, after_connection_accepted_callback, NULL, after_data_read_callback, NULL, 0);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 1;
    is_connection_closed = 0;
    while (counter && is_connected && !is_connection_closed)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    assert_int_equal(is_connected, 0);
    assert_int_equal(is_connection_closed, 0);

    char *head = "GET / HTTP/1.0\r\n\
Host: nodejs.org\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
    counter = 10000;
    is_datareaded = 0;
    do
    {
        counter--;
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        result = rebrick_async_tlssocket_send(tlsclient, head, strlen(head) + 1, NULL);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    } while (result != 0 && counter && !is_connection_closed);
    assert_int_equal(result, 0);
    counter = 100000;

    while (counter && !is_datareaded)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }

    int check_header = memcmp("HTTP/1.1 302", readedbuffer, 12);
    assert_int_equal(check_header, 0);
    if (!is_connection_closed)
        rebrick_async_tlssocket_destroy(tlsclient);
}

int32_t server_connection_status = 1;

int32_t after_serverconnection_accepted_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    server_connection_status = status;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
    if (status)
        return status;
    rebrick_async_tlssocket_t *client = cast(client_handle, rebrick_async_tlssocket_t *);
    char *msg = "HTTP/1.1 200 Ok\r\n\
content-type:text/html\r\n\
content-length:52\r\n\
\r\n\
<html><body><h1>server is working</h1></body></html>";
    int32_t counter = 10000;
    rebrick_async_tlssocket_send(client, msg, strlen(msg), NULL);
    while (counter)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }

    return REBRICK_SUCCESS;
}
int32_t after_serverconnection_closed_callback(rebrick_async_socket_t *sockethandle, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    rebrick_async_tlssocket_t *socket = cast(sockethandle, rebrick_async_tlssocket_t *);
    rebrick_async_tlssocket_destroy(socket);
    return REBRICK_SUCCESS;
}
int32_t datareadedserver = 0;
char readedbufferserver[65536*2];

static int32_t after_serverdata_read_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{
    unused(addr);
    unused(addr);
    unused(buffer);
    unused(socket);
    unused(callback_data);
    unused(len);
    datareadedserver = 1;
    memset(readedbufferserver, 0, sizeof(readedbufferserver));
    memcpy(readedbufferserver, buffer, len);
    totalreaded_len += len;
    printf("totalreaded len:%d\n",totalreaded_len);
    return 0;
}

static void ssl_server(void **start)
{
    unused(start);
    int32_t result;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t listen;

    rebrick_util_ip_port_to_addr("0.0.0.0", "9999", &listen);

    rebrick_async_tlssocket_t *tlsserver;
    result = rebrick_async_tlssocket_new(&tlsserver, context_server, listen, NULL, after_serverconnection_accepted_callback, after_serverconnection_closed_callback, after_serverdata_read_callback, NULL, 100);
    assert_int_equal(result, 0);
    int counter = 1000000000;
    server_connection_status = 1;
    while (counter && server_connection_status)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    assert_int_equal(server_connection_status, 0);

    counter = 1000000;
    while (counter && !is_datareaded)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }

    rebrick_async_tlssocket_destroy(tlsserver);
}

static void ssl_client_verify(void **start)
{
    //bu projeyi çalıştırmadan önce
    //docker_ssl   ngix_data altında 10m.ignore.txt 100m.ignore.txt 1000m.ignore.txt
    unused(start);
    int32_t result;

    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "443", &destination);

    rebrick_async_tlssocket_t *tlsclient;
    result = rebrick_async_tlssocket_new(&tlsclient, context_verify, destination, NULL, after_connection_accepted_callback, NULL, after_data_read_callback, NULL, 0);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 0;
    is_connection_closed = 0;
    while (counter && !is_connected)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    assert_int_equal(is_connected, REBRICK_ERR_TLS_ERR);
    rebrick_async_tlssocket_destroy(tlsclient);
}

static void ssl_client_download_data(void **start)
{
    //bu projeyi çalıştırmadan önce
    //docker_ssl   ngix_data altında 10m.ignore.txt 100m.ignore.txt 1000m.ignore.txt
    unused(start);
    int32_t result;

    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "443", &destination);

    rebrick_async_tlssocket_t *tlsclient;
    result = rebrick_async_tlssocket_new(&tlsclient, context_verify_none, destination, NULL, after_connection_accepted_callback, after_connection_closed_callback, after_data_read_callback, NULL, 0);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 1;
    is_connection_closed = 0;
    while (counter && is_connected && !is_connection_closed)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    assert_int_equal(is_connected, 0);
    assert_int_equal(is_connection_closed, 0);

    char *head = "GET /10m.ignore.txt HTTP/1.0\r\n\
Host: nodejs.org\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
    counter = 10000;
    is_datareaded = 0;
    do
    {
        counter--;
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        result = rebrick_async_tlssocket_send(tlsclient, head, strlen(head) + 1, NULL);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    } while (result != 0 && counter && !is_connection_closed);
    assert_int_equal(result, 0);
    assert_int_equal(is_connection_closed,0);
    counter = 100000;
    totalreaded_len = 0;
    while (counter && !is_connection_closed)
    {
        usleep(100);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        counter--;
    }

    rebrick_async_tlssocket_destroy(tlsclient);
    while(!is_connection_closed){
        usleep(100);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
    //assert_is_true_equal(totalreaded_len,10485760);

}

static void ssl_client_memory_test(void **state){
    int counter=10000;
    while(counter){
        ssl_client_download_data(state);
        counter--;
    }
}

int test_rebrick_async_tlssocket(void)
{
    getchar();
    const struct CMUnitTest tests[] = {
       /*  cmocka_unit_test(ssl_client),*/
       /* cmocka_unit_test(ssl_server),*/
       /* cmocka_unit_test(ssl_client_verify),*/
       /* cmocka_unit_test(ssl_client_download_data)*/
       cmocka_unit_test(ssl_client_memory_test)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
