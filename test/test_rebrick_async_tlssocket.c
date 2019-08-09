#include "rebrick_tls.h"
#include "rebrick_async_tlssocket.h"
#include "cmocka.h"
#include <unistd.h>

static rebrick_tls_context_t *context_verify_none;
static rebrick_tls_context_t *context_server;

static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);

    rebrick_tls_init();
    rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, NULL, NULL);
    rebrick_tls_context_new(&context_server,"server",SSL_VERIFY_NONE,SSL_SESS_CACHE_BOTH, SSL_OP_ALL,"./data/domain.crt","./data/domain.key");

    return 0;
}

static int teardown(void **state)
{
    unused(state);
    rebrick_tls_context_destroy(context_verify_none);
    rebrick_tls_context_destroy(context_server);
    return 0;
}

int32_t after_connected = 1;

int32_t after_connection_accepted_callback(void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    after_connected = status;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    return REBRICK_SUCCESS;
}
int32_t after_connection_closed_callback(void *callback_data)
{
    unused(callback_data);
    return REBRICK_SUCCESS;
}
int32_t datareaded = 0;
char readedbuffer[8192 * 4];
static int32_t after_data_read_callback(void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{
    unused(addr);

    unused(addr);
    unused(buffer);
    unused(len);
    datareaded = 1;
    memset(readedbuffer, 0, sizeof(readedbuffer));
    memcpy(readedbuffer, buffer, len);
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
    after_connected=1;
    while (counter && after_connected)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    assert_int_equal(after_connected, 0);

    char *head = "GET / HTTP/1.0\r\n\
Host: nodejs.org\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
    counter = 10000;
    datareaded = 0;
    do
    {
        counter--;
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        result = rebrick_async_tlssocket_send(tlsclient, head, strlen(head) + 1, NULL);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    } while (result != 0 && counter);
    assert_int_equal(result, 0);
    counter = 100000;

    while (counter && !datareaded)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }

    int check_header = memcmp("HTTP/1.1 302", readedbuffer, 12);
    assert_int_equal(check_header, 0);
    rebrick_async_tlssocket_destroy(tlsclient);
}





int32_t after_serverconnected = 1;
int32_t after_serverclientdisconnected=1;
int32_t after_serverconnection_accepted_callback(void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    after_serverconnected = status;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    if(status)
    return status;
    rebrick_async_tlssocket_t *client=cast(client_handle,rebrick_async_tlssocket_t*);
    const char *msg="HTTP/1.1 200 Ok\r\n\
content-type:text/html\r\n\
content-length:52\r\n\
\r\n\
<html><body><h1>server is working</h1></body></html>";
 int32_t counter=10000;
    rebrick_async_tlssocket_send(client,msg,strlen(msg),NULL);
 while(counter){
      usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
 }

    return REBRICK_SUCCESS;
}
int32_t after_serverconnection_closed_callback(void *callback_data)
{
    unused(callback_data);
    rebrick_async_tlssocket_t *socket=cast(callback_data,rebrick_async_tlssocket_t *);
    rebrick_async_tlssocket_destroy(socket);
    return REBRICK_SUCCESS;
}
int32_t datareadedserver = 0;
char readedbufferserver[8192 * 4];
static int32_t after_serverdata_read_callback(void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{
    unused(addr);
    unused(addr);
    unused(buffer);
    unused(len);
    datareadedserver = 1;
    memset(readedbufferserver, 0, sizeof(readedbufferserver));
    memcpy(readedbufferserver, buffer, len);
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
    after_serverconnected=1;
    while (counter && after_serverconnected)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    assert_int_equal(after_serverconnected, 0);


    counter=1000000;
    while (counter && !datareaded)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }


    rebrick_async_tlssocket_destroy(tlsserver);
}




int test_rebrick_async_tlssocket(void)
{
    const struct CMUnitTest tests[] = {
    //cmocka_unit_test(ssl_client)
    cmocka_unit_test(ssl_server)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
