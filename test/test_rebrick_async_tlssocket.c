#include "rebrick_tls.h"
#include "rebrick_async_tlssocket.h"
#include "cmocka.h"
#include <unistd.h>
#include <string.h>

static rebrick_tls_context_t *context_verify_none=NULL;
static rebrick_tls_context_t *context_server=NULL;
static rebrick_tls_context_t *context_verify=NULL;

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
    rebrick_tls_cleanup();
     int32_t counter=100;
    while(counter--){
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }
    uv_loop_close(uv_default_loop());
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
static char readedbuffer[131072]={0};
static int32_t after_data_read_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
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
    //printf("totalreaded len:%d\n",totalreaded_len);
    return 0;
}





static void ssl_client(void **start)
{
    unused(start);
    int32_t result;
    int32_t tempresult=0;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "443", &destination);

    rebrick_async_tlssocket_t *tlsclient;
    result = rebrick_async_tlssocket_new(&tlsclient, context_verify_none, destination, NULL, after_connection_accepted_callback, after_connection_closed_callback, after_data_read_callback, NULL, 0);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 1;
    is_connection_closed = 0;
    totalreaded_len=0;
    while (counter-- && is_connected && !is_connection_closed)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
    assert_int_equal(is_connected, 0);
    assert_int_equal(is_connection_closed, 0);

     char *head = "GET / HTTP/1.0\r\n\
Host: localhost\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
    counter = 100;

    is_datareaded = 0;


        while(counter--){
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);

        }
        result = rebrick_async_tlssocket_send(tlsclient, head, strlen(head) + 1, NULL);
        assert_int_equal(result,0);
        counter=100;
        while(counter--){
            usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        }

    assert_int_equal(result, 0);
    counter = 1000;

    while (counter-- && !is_datareaded)
    {
        memset(readedbuffer,0,sizeof(readedbuffer));
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }


    tempresult=memcmp("HTTP/1.1 200",readedbuffer,12);
    assert_int_equal(tempresult,0);


    if (!is_connection_closed)
        rebrick_async_tlssocket_destroy(tlsclient);
     counter=100;
    while(counter--){

        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }
}



int32_t server_connection_status = 1;
int32_t client_count=0;
int32_t after_serverconnection_accepted_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{
    server_connection_status = status;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
    if (status){
        printf("status problem\n");
        return status;
    }
    assert_non_null(client_handle);

    client_count++;

    rebrick_async_tlssocket_t *client = cast(client_handle, rebrick_async_tlssocket_t *);
    char *msg = "HTTP/1.1 200 Ok\r\n\
content-type:text/html\r\n\
content-length:52\r\n\
\r\n\
<html><body><h1>server is working</h1></body></html>";
    int32_t counter = 10;
    rebrick_async_tlssocket_send(client, msg, strlen(msg), NULL);
    while (counter--)
    {
        usleep(10);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }

    counter=10;
    //rebrick_async_tlssocket_destroy(client);
    while (counter--)
    {
        usleep(10);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
    return REBRICK_SUCCESS;
}
int32_t after_serverconnection_closed_callback(rebrick_async_socket_t *sockethandle, void *callback_data)
{
    unused(callback_data);

    rebrick_async_tlssocket_t *socket = cast(sockethandle, rebrick_async_tlssocket_t *);
    unused(socket);
    if(socket->parent_socket){
    client_count--;

    }
    //rebrick_async_tlssocket_destroy(socket);
    return REBRICK_SUCCESS;
}
int32_t datareadedserver = 0;
static char readedbufferserver[65536*2]={0};

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
    //printf("totalreaded len:%d\n",totalreaded_len);
    return 0;
}

/**
 * @brief  for i in {1..10}; do curl --insecure https://localhost:9797; done
 *
 * @param start
 */
static void ssl_server(void **start)
{
    unused(start);
    int32_t result;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t listen;

    rebrick_util_ip_port_to_addr("0.0.0.0", "9797", &listen);
    client_count=0;
    rebrick_async_tlssocket_t *tlsserver;
    result = rebrick_async_tlssocket_new(&tlsserver, context_server, listen, NULL, after_serverconnection_accepted_callback, after_serverconnection_closed_callback, after_serverdata_read_callback, NULL, 100);
    assert_int_equal(result, 0);
    int counter = 10000;
    server_connection_status = 1;
    while (counter--)
    {

        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }


   // assert_int_equal(server_connection_status, 0);

    counter = 10;
    while (client_count)
    {

        usleep(10);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }


    rebrick_async_tlssocket_destroy(tlsserver);
    counter = 100;
    while (counter-- && client_count)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
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
    result = rebrick_async_tlssocket_new(&tlsclient, context_verify, destination, NULL, after_connection_accepted_callback, after_connection_closed_callback, after_data_read_callback, NULL, 0);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 1;
    is_connection_closed = 0;
    while (counter && is_connected)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    counter=100;
    while(counter--){
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
    char *head = "GET / HTTP/1.0\r\n\
Host: localhost\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";

    result=rebrick_async_tlssocket_send(tlsclient,head,strlen(head)+1,NULL);

    counter=100;
    assert_int_equal(result,REBRICK_ERR_TLS_ERR);
    while (counter--)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }

    rebrick_async_tlssocket_destroy(tlsclient);
    counter=100;
    while(counter--){
         usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT), --counter;
    }
}


/**
 * @brief docker nginx /10m.ignore.txt dosyası download edilecek
 *
 * @param start
 */
static void ssl_client_download_data(void **start)
{
    //bu projeyi çalıştırmadan önce
    //docker_ssl   ngix_data altında 10m.ignore.txt 100m.ignore.txt 1000m.ignore.txt olmalı
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
    printf("%d\n",totalreaded_len);
    //assert_int_equal(totalreaded_len,10486033);

}

static void ssl_client_memory_test(void **state){
    printf("enter for continue\n");
    getchar();
    int counter=10000;
    while(counter){
        ssl_client_download_data(state);
        counter--;

        /* printf("enter for continue\n");
        getchar(); */
       // usleep(1000000);
    }



    printf("enter for exit\n");
    getchar();

}

int test_rebrick_async_tlssocket(void)
{

   const struct CMUnitTest tests[] = {
       cmocka_unit_test(ssl_client),
      // cmocka_unit_test(ssl_server),
       // cmocka_unit_test(ssl_client_verify),
       /* cmocka_unit_test(ssl_client_download_data)*/
       //cmocka_unit_test(ssl_client_memory_test)

    };
    return cmocka_run_group_tests(tests, setup, teardown);

}
