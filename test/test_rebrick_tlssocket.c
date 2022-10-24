
#include "./common/rebrick_tls.h"
#include "./socket/rebrick_tlssocket.h"
#include "cmocka.h"
#include <unistd.h>
#include <string.h>

#define loop(var, a, x)                           \
    var = a;                                      \
    while (var-- && (x))                          \
    {                                             \
        usleep(100);                              \
        uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
    }

static rebrick_tls_context_t *context_verify_none = NULL;
static rebrick_tls_context_t *context_server = NULL;
static rebrick_tls_context_t *context_servermanual = NULL;
static rebrick_tls_context_t *context_hamzakilic_com = NULL;
static rebrick_tls_context_t *context_verify = NULL;
static rebrick_tls_context_t *context_test_com = NULL;

static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);

    rebrick_tls_init();
    rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, 0, NULL, NULL);
    rebrick_tls_context_new(&context_server, "server", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, 0, "./data/domain.crt", "./data/domain.key");
    rebrick_tls_context_new(&context_verify, "clientverify", SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, 0, NULL, NULL);

    rebrick_tls_context_new(&context_servermanual, "servermanuel", SSL_VERIFY_NONE, SSL_SESS_CACHE_OFF, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET, SSL_OP_NO_COMPRESSION, "./data/domain.crt", "./data/domain.key");

    rebrick_tls_context_new(&context_hamzakilic_com, "hamzakilic.com", SSL_VERIFY_NONE, SSL_SESS_CACHE_OFF, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET, SSL_OP_NO_COMPRESSION, "./data/domain.crt", "./data/domain.key");
    rebrick_tls_context_new(&context_test_com, "test.com", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, 0, "./data/test.com.crt", "./data/test.com.key");

    return 0;
}

static int teardown(void **state)
{
    unused(state);
    rebrick_tls_context_destroy(context_verify_none);
    rebrick_tls_context_destroy(context_server);

    rebrick_tls_context_destroy(context_verify);
    rebrick_tls_context_destroy(context_servermanual);
    rebrick_tls_context_destroy(context_hamzakilic_com);
    rebrick_tls_context_destroy(context_test_com);
    context_verify = NULL;
    context_server = NULL;
    context_verify_none = NULL;
    rebrick_tls_cleanup();
    int32_t counter;
    loop(counter, 100, TRUE);
    uv_loop_close(uv_default_loop());
    return 0;
}

static void on_error_occured_callback(rebrick_socket_t *socket, void *callback, int error)
{
    unused(socket);
    unused(callback);
    unused(error);
    rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));
}

static int32_t is_connected = 1;

static void on_accept_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{
    is_connected = 0;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);
}
static int32_t is_connection_closed = 0;
static void on_client_close_callback(rebrick_socket_t *socket, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    is_connection_closed = 1;
}
static int32_t is_datareaded = 0;
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

    is_datareaded = 1;
    fill_zero(readedbuffer, sizeof(readedbuffer));

    memcpy(readedbuffer, buffer, len);

    totalreaded_len += len;
}

static void ssl_client(void **start)
{
    unused(start);
    int32_t result;
    int32_t tempresult = 0;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "443", &destination);

    create2(rebrick_tlssocket_callbacks_t, callbacks);
    callbacks.on_accept = on_accept_callback;
    callbacks.on_client_close = on_client_close_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_error = on_error_occured_callback;

    rebrick_tlssocket_t *tlsclient;
    result = rebrick_tlssocket_new(&tlsclient, NULL, context_verify_none, NULL, &destination, 0, &callbacks);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 1;
    is_connection_closed = 0;
    totalreaded_len = 0;
    loop(counter, 100000, (is_connected && !is_connection_closed));

    assert_int_equal(is_connected, 0);
    assert_int_equal(is_connection_closed, 0);

    char *head = "GET / HTTP/1.0\r\n\
Host: localhost\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
    counter = 100;

    is_datareaded = 0;
    memset(readedbuffer, 0, sizeof(readedbuffer));

    loop(counter, 100, TRUE);
    rebrick_clean_func_t clean = {};
    result = rebrick_tlssocket_write(tlsclient, cast(head, uint8_t *), strlen(head) + 1, clean);
    assert_int_equal(result, 0);
    counter = 100;
    loop(counter, 100, TRUE);

    assert_int_equal(result, 0);

    loop(counter, 1000, !is_datareaded);

    tempresult = memcmp("HTTP/1.1 200", readedbuffer, 12);
    assert_int_equal(tempresult, 0);

    if (!is_connection_closed)
        rebrick_tlssocket_destroy(tlsclient);
    counter = 100;
    loop(counter, 100, TRUE);
}

static int32_t lastError = 0;

static void on_serverconnection_error_occured_callback(rebrick_socket_t *socket, void *callbackdata, int error)
{
    unused(socket);
    unused(callbackdata);
    unused(error);
    lastError = error;
    rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));
}
static int32_t server_connection_status = 1;
static int32_t client_count = 0;
static void on_serverconnection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{
    server_connection_status = 0;
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);

    assert_non_null(client_handle);

    client_count++;

    rebrick_tlssocket_t *client = cast(client_handle, rebrick_tlssocket_t *);
    char *msg = "HTTP/1.1 200 Ok\r\n\
content-type:text/html\r\n\
content-length:52\r\n\
\r\n\
<html><body><h1>server is working</h1></body></html>";
    int32_t counter = 10;
    rebrick_clean_func_t clean = {};
    rebrick_tlssocket_write(client, cast(msg, uint8_t *), strlen(msg), clean);
    loop(counter, 10, TRUE);

    loop(counter, 10, TRUE);
}

static void on_serverconnection_closed_callback(rebrick_socket_t *sockethandle, void *callback_data)
{
    unused(callback_data);

    rebrick_tlssocket_t *socket = cast(sockethandle, rebrick_tlssocket_t *);
    unused(socket);
    if (socket->parent_socket)
    {
        client_count--;
    }
    //rebrick_tlssocket_destroy(socket);
}
static int32_t datareadedserver = 0;
static char readedbufferserver[65536 * 2] = {0};

static void on_serverdata_read_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
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
}

static void on_serverdata_read_callback2(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
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
    printf("%s\n", readedbufferserver);
    totalreaded_len += len;
    char *msg = "HTTP/1.1 200 Ok\r\n\
content-type:text/html\r\n\
content-length:52\r\n\
\r\n\
<html><body><h1>server is working</h1></body></html>";
    int32_t counter = 10;
    rebrick_clean_func_t clean = {};
    rebrick_tlssocket_write(cast_to_tlssocket(socket), cast(msg, uint8_t *), strlen(msg), clean);
    loop(counter, 10, TRUE);
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
    printf("execute command on terminal: for i in {1..10}; do curl --insecure https://localhost:9797; done\n");
    rebrick_util_ip_port_to_addr("0.0.0.0", "9797", &listen);
    client_count = 0;

    create2(rebrick_tlssocket_callbacks_t, callbacks);
    callbacks.on_accept = on_serverconnection_accepted_callback;
    callbacks.on_client_close = on_serverconnection_closed_callback;
    callbacks.on_read = on_serverdata_read_callback;
    callbacks.on_error = on_serverconnection_error_occured_callback;

    rebrick_tlssocket_t *tlsserver;
    result = rebrick_tlssocket_new(&tlsserver, NULL, context_server, &listen, NULL, 100, &callbacks);
    assert_int_equal(result, 0);
    int counter;
    server_connection_status = 1;
    loop(counter, 100000, TRUE);

    counter = 10;
    while (client_count)
    {
        loop(counter, 1, TRUE);
    }

    rebrick_tlssocket_destroy(tlsserver);

    loop(counter, 100, TRUE);
}

static void ssl_client_verify(void **start)
{
    //bu projeyi çalıştırmadan önce
    //docker_ssl   ngix_data altında 10m.ignore.txt 100m.ignore.txt 1000m.ignore.txt
    unused(start);
    int32_t result;

    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "443", &destination);

    create2(rebrick_tlssocket_callbacks_t, callbacks);
    callbacks.on_accept = on_accept_callback;
    callbacks.on_client_close = on_client_close_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_error = on_serverconnection_error_occured_callback;

    rebrick_tlssocket_t *tlsclient;
    lastError = 0;
    result = rebrick_tlssocket_new(&tlsclient, NULL, context_verify, NULL, &destination, 0, &callbacks);
    assert_int_equal(result, 0);
    int counter = 100000;
    is_connected = 1;
    is_connection_closed = 0;
    loop(counter, 10000, is_connected);

    counter = 100;
    loop(counter, 100, TRUE);
    /*  char *head = "GET / HTTP/1.0\r\n\
Host: localhost\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";

    rebrick_clean_func_t clean={};
    result = rebrick_tlssocket_write(tlsclient, head, strlen(head) + 1, clean);*/

    assert_int_equal(lastError, REBRICK_ERR_TLS_ERR);
    loop(counter, 100, TRUE);
    //rebrick_tlssocket_destroy(tlsclient);

    loop(counter, 100, TRUE);
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

    create2(rebrick_tlssocket_callbacks_t, callbacks);
    callbacks.on_accept = on_accept_callback;
    callbacks.on_client_close = on_client_close_callback;
    callbacks.on_read = on_data_read_callback;
    callbacks.on_error = on_error_occured_callback;

    rebrick_tlssocket_t *tlsclient;
    result = rebrick_tlssocket_new(&tlsclient, NULL, context_verify_none, NULL, &destination, 0, &callbacks);
    assert_int_equal(result, 0);
    int counter = 100;
    is_connected = 1;
    is_connection_closed = 0;
    loop(counter, 100, (is_connected && !is_connection_closed));

    assert_int_equal(is_connected, 0);
    assert_int_equal(is_connection_closed, 0);

    char *head = "GET /10m.ignore.txt HTTP/1.0\r\n\
Host: nodejs.org\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
    counter = 10000;
    is_datareaded = 0;
    rebrick_clean_func_t clean = {};
    do
    {
        counter--;
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        result = rebrick_tlssocket_write(tlsclient, cast(head, uint8_t *), strlen(head) + 1, clean);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    } while (result != 0 && counter && !is_connection_closed);
    assert_int_equal(result, 0);
    assert_int_equal(is_connection_closed, 0);
    counter = 1000;
    totalreaded_len = 0;
    loop(counter, 1000, !is_connection_closed);

    if (!is_connection_closed)
    {
        rebrick_tlssocket_destroy(tlsclient);
        while (!is_connection_closed)
        {
            usleep(100);
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        }
    }
    //assert_int_equal(totalreaded_len,10486033);
}

static void ssl_client_memory_test(void **state)
{

    int counter = 100;
    while (counter)
    {
        ssl_client_download_data(state);
        counter--;
    }
}

static void on_serverconnectionmanuel_closed_callback(rebrick_socket_t *sockethandle, void *callback_data)
{
    unused(callback_data);

    rebrick_tlssocket_t *socket = cast(sockethandle, rebrick_tlssocket_t *);
    unused(socket);
    if (socket->parent_socket)
    {
        client_count--;
    }
    //rebrick_tlssocket_destroy(socket);
}

static void ssl_server_for_manual(void **start)
{
    unused(start);
    int32_t result;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t listen;
    printf("started a tls server at 8443\n");
    rebrick_util_ip_port_to_addr("0.0.0.0", "8443", &listen);
    client_count = 0;

    create2(rebrick_tlssocket_callbacks_t, callbacks);
    callbacks.on_error = on_error_occured_callback;

    rebrick_tlssocket_t *tlsserver;
    result = rebrick_tlssocket_new(&tlsserver, NULL, context_servermanual, &listen, NULL, 100, &callbacks);
    assert_int_equal(result, 0);
    int counter;
    server_connection_status = 1;
    // loop(counter,100000,TRUE);

    counter = 1000;
    while (1)
    {
        loop(counter, 1, TRUE);
    }

    rebrick_tlssocket_destroy(tlsserver);

    loop(counter, 100, TRUE);
}

//for test, from a terminal openssl s_client -connect hamzakilic.com:8443
//insert into /etc/hosts  127.0.0.1 hamzakilic.com
static void ssl_server_for_manual_sni(void **start)
{
    unused(start);
    int32_t result;
    //curl -XGET https://postman-echo.com/get
    rebrick_sockaddr_t listen;
    printf("started a tls server at 8443\n");
    rebrick_util_ip_port_to_addr("0.0.0.0", "8443", &listen);
    client_count = 0;

    create2(rebrick_tlssocket_callbacks_t, callbacks);
    callbacks.on_error = on_error_occured_callback;

    rebrick_tlssocket_t *tlsserver;
    result = rebrick_tlssocket_new(&tlsserver, "hamzakilic.com", context_test_com, &listen, NULL, 10, &callbacks);
    assert_int_equal(result, 0);
    int counter;
    server_connection_status = 1;
    // loop(counter,100000,TRUE);

    counter = 1000000;
    int32_t tmp = 100;
    while (counter--)
    {
        loop(tmp, 1, TRUE);
    }

    rebrick_tlssocket_destroy(tlsserver);

    loop(counter, 100, TRUE);
}

int test_rebrick_tlssocket(void)
{

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ssl_client),
        cmocka_unit_test(ssl_server),
        cmocka_unit_test(ssl_client_verify),
        cmocka_unit_test(ssl_client_download_data),
        cmocka_unit_test(ssl_client_memory_test),
        ///   cmocka_unit_test(ssl_server_for_manual),
        //  cmocka_unit_test(ssl_server_for_manual_sni)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
