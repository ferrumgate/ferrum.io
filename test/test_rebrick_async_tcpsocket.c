#include "./rebrick_async_tcpsocket.h"
#include "./server_client/tcpecho.h"
#include "cmocka.h"
#include "unistd.h"

#define TCPSERVER_PORT "9999"
static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);
    return 0;
}

static int teardown(void **state)
{
    unused(state);

    return 0;
}
struct callbackdata
{
    rebrick_async_tcpsocket_t *client;
    struct sockaddr *addr;
    char buffer[1024];
};

int client_connected = 0;
static int32_t on_newclient_connection(rebrick_async_socket_t *socket, void *callbackdata, const struct sockaddr *addr, void *client_handle, int32_t status)
{
    unused(status);
    unused(socket);
    unused(callbackdata);
    unused(addr);
    unused(client_handle);
    struct callbackdata *data = cast(callbackdata, struct callbackdata *);

    data->client = client_handle;
    data->addr = cast(addr, struct sockaddr *);
    client_connected = 1;
    return 0;
}

static int32_t on_read(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{
    unused(addr);
    unused(socket);
    unused(callback_data);

    struct callbackdata *data = cast(callback_data, struct callbackdata *);
    memset(data->buffer, 0, 1024);
    memcpy(data->buffer, buffer, len);
    return 0;
}

static void rebrick_async_tcpsocket_asserver_communication(void **start)
{
    unused(start);
    const char *port = "9999";
    rebrick_async_tcpsocket_t *server;
    rebrick_sockaddr_t addr;
    struct callbackdata data;
    int32_t result = rebrick_util_ip_port_to_addr("0.0.0.0", port, &addr);
    assert_int_equal(result, 0);

    result = rebrick_async_tcpsocket_new(&server, addr, &data, on_newclient_connection, NULL, on_read, NULL, 10);
    assert_int_equal(result, 0);

    client_connected = 0;

    result = tcp_echo_start(atoi(port), 0);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    assert_int_equal(result, 0);
    usleep(100);
    assert_int_equal(client_connected, 1);
    //struct sockaddr_in *s = data.addr;
    //assert_int_equal(s->sin_addr.s_addr,INADDR_LOOPBACK);

    char *hello = "hello";
    tcp_echo_send(hello);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100);
    assert_string_equal(data.buffer, hello);

    char *world = "world";
    result = rebrick_async_tcpsocket_send(data.client, world, strlen(world), NULL);
    assert_int_equal(result, 0);

    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100);
    char readed[1024] = {'\0'};
    result = tcp_echo_recv(readed);
    assert_int_equal(result, 5);

    assert_string_equal(readed, world);
    rebrick_async_tcpsocket_destroy(data.client);

    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100);
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100);
}

int connected_toserver = 0;
static int32_t on_connection_accepted(rebrick_async_socket_t *socket, void *callbackdata, const struct sockaddr *addr, void *client_handle, int32_t status)
{
    unused(callbackdata);
    unused(addr);
    unused(status);
    unused(client_handle);
    unused(socket);
    struct callbackdata *data = cast(callbackdata, struct callbackdata *);
    unused(data);
    connected_toserver = 1;
    return 0;
}

static int32_t on_connection_closed(rebrick_async_socket_t *socket, void *callbackdata)
{
    unused(socket);
    unused(callbackdata);
    struct callbackdata *data = cast(callbackdata, struct callbackdata *);
    unused(data);
    return 0;
}
static int datareceived_ok = 0;
static int32_t on_datarecevied(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{
    unused(callback_data);
    unused(addr);

    unused(socket);

    struct callbackdata *data = cast(callback_data, struct callbackdata *);
    memset(data->buffer, 0, 1024);
    memcpy(data->buffer, buffer, len);
    datareceived_ok = 1;
    return 0;
}

static int32_t on_datasend(rebrick_async_socket_t *socket, void *callback_data, void *after_senddata, int status)
{
    unused(callback_data);
    unused(after_senddata);
    unused(socket);
    return status - status;
}

static void rebrick_async_tcpsocket_asclient_communication(void **start)
{
    unused(start);
    const char *port = "9998";
    rebrick_async_tcpsocket_t *client;
    rebrick_sockaddr_t addr;
    rebrick_util_ip_port_to_addr("127.0.0.1", port, &addr);
    struct callbackdata data;
    int32_t result = tcp_echo_start(atoi(port), 1);
    assert_int_equal(result, 0);
    fill_zero(&data, sizeof(struct callbackdata));
    connected_toserver = 0;
    result = tcp_echo_listen();
    result = rebrick_async_tcpsocket_new(&client, addr, &data, on_connection_accepted, on_connection_closed, on_datarecevied, on_datasend, 0);

    //check a little
    int counter = 10;
    while (counter)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(10000);
        if (connected_toserver)
            break;
        counter--;
    }

    assert_int_equal(connected_toserver, 1);
    datareceived_ok = 0;
    counter = 10;
    while (counter)
    {
        result = tcp_echo_send("deneme");
        if (result >= 0)
            break;
        counter--;
    }
    counter = 10;
    while (counter)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(10000);
        if (datareceived_ok)
            break;
        counter--;
    }
    assert_int_equal(datareceived_ok, 1);

    assert_string_equal(data.buffer, "deneme");
    rebrick_async_tcpsocket_send(client, "valla", 6, NULL);
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100);
    char recvbuf[1024];
    tcp_echo_recv(recvbuf);
    assert_string_equal(recvbuf, "valla");
}

int test_rebrick_async_tcpsocket(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_async_tcpsocket_asserver_communication),
        cmocka_unit_test(rebrick_async_tcpsocket_asclient_communication)};
    return cmocka_run_group_tests(tests, setup, teardown);
}
