#include "rebrick_tls.h"
#include "rebrick_async_tlssocket.h"
#include "cmocka.h"
#include <unistd.h>

static rebrick_tls_context_t *context_verify_none;

static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);

    rebrick_tls_init();
    rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, NULL, NULL);

    return 0;
}

static int teardown(void **state)
{
    unused(state);
    rebrick_tls_context_destroy(context_verify_none);
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




int test_rebrick_async_tlssocket(void)
{
    const struct CMUnitTest tests[] = {
    cmocka_unit_test(ssl_client)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
