#include "./socket/rebrick_udpsocket.h"
#include "./server_client/udpecho.h"
#include "cmocka.h"
#include "unistd.h"

#define loop(var, a, x)                           \
    var = a;                                      \
    while (var-- && (x))                          \
    {                                             \
        usleep(100);                              \
        uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
    }

#define UDPSERVER_PORT "9999"
static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);
    int32_t result = udp_echo_start(atoi(UDPSERVER_PORT));

    return result;
}

static int teardown(void **state)
{
    unused(state);
    udp_echo_close();
    uv_loop_close(uv_default_loop());
    return 0;
}

static int32_t flag = 0;
static char read_buffer[65536] = {'\0'};
static const char *testdata = "merhaba";
static int32_t closed = 0;
static void on_closed(rebrick_socket_t *socket, void *data)
{
    unused(socket);
    unused(data);
    closed = 1;
}

static void on_error_occured(rebrick_socket_t *socket, void *data, int error)
{
    unused(socket);
    unused(data);
    unused(error);
}
static void on_server_received(rebrick_socket_t *socket, void *data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);

    assert_string_equal(data, testdata);
    flag = 1;
    memset(read_buffer, 0, 512);
    memcpy(read_buffer, buffer, len < 65536 ? len : 65536);
}

static void on_server_send(rebrick_socket_t *socket, void *data, void *source)
{
    unused(data);
    unused(socket);
    unused(source);

    assert_string_equal(data, testdata);
    flag = 2;
}

static void rebrick_udpsocket_asserver_communication(void **start)
{
    unused(start);
    rebrick_udpsocket_t *server;
    const char *bind_ip = "0.0.0.0";
    const char *bind_port = "9090";
    rebrick_sockaddr_t bind;
    rebrick_util_to_rebrick_sockaddr(&bind, bind_ip, bind_port);

    const char *localhost_ip = "127.0.0.1";

    rebrick_sockaddr_t localhost;
    rebrick_util_to_rebrick_sockaddr(&localhost, localhost_ip, bind_port);

    const char *dest_ip = "127.0.0.1";
    const char *dest_port = "9999";
    rebrick_sockaddr_t client;
    rebrick_util_to_rebrick_sockaddr(&client, dest_ip, dest_port);
    create2(rebrick_udpsocket_callbacks_t, callbacks);
    callbacks.callback_data = cast(testdata, void *);
    callbacks.on_read = on_server_received;
    callbacks.on_write = on_server_send;
    callbacks.on_error = on_error_occured;

    int32_t result = rebrick_udpsocket_new(&server, &bind, &callbacks);
    assert_int_equal(result, 0);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);

    const char *msg = "hello world";

    flag = 0;
    udp_echo_send2(msg, &localhost.v4);
    //loop again
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    //check for received data
    int32_t max_check = 10;
    //loop(max_check,10,!flag)
    while (!flag && max_check)
    {
        usleep(10000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        max_check--;
    }
    //rebrick_free(buffer);
    assert_int_not_equal(max_check, 0);
    assert_string_equal(msg, read_buffer);
    flag = 0;
    char *reply = "got it";
    rebrick_clean_func_t clean = {};
    result = rebrick_udpsocket_write(server, &client, cast(reply, uint8_t *), strlen(reply) + 1, clean);
    assert_int_equal(result, 0);

    //check for received data
    max_check = 10;
    while (!flag && max_check)
    {
        usleep(10000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        max_check--;

        result = udp_echo_recv(read_buffer);
        if (result > 0)
            break;
    }
    assert_int_not_equal(max_check, 0);
    assert_string_equal(reply, read_buffer);

    result = rebrick_udpsocket_destroy(server);
    assert_int_equal(result, 0);
    max_check = 100;
    while (max_check--)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
}

static void on_dnsclient_error_occured(rebrick_socket_t *socket, void *data, int32_t error)
{

    unused(socket);
    unused(data);
    unused(error);
}

static int32_t received_count = 0;
static void on_dnsclient_received(rebrick_socket_t *socket, void *data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(data);
    unused(buffer);
    unused(len);

    received_count++;
}
static int32_t sended_count = 0;
static void on_dnsclient_send(rebrick_socket_t *socket, void *data, void *source)
{
    unused(data);
    unused(socket);
    unused(source);
    unused(data);

    sended_count++;
}

/////////////////////// memory tests ///////////////////////////////////////////////

/**
 * @brief create socket, send a packet, then destory socket
 * and test this situation more
 *
 * @param state
 */
static void test_rebrick_udpsocket_check_memory(void **state)
{
    //try sending the same dnsd packet
    //to dockerized bind server
    //and check memory of program

    //create and send sockets much

    unused(state);
    //read a sample dns packet
    char *testdata;
    size_t datalen;

    int32_t result = rebrick_util_file_read_allbytes("./test/testdata/testpacket1.packet", &testdata, &datalen);
    if (result)
        result = rebrick_util_file_read_allbytes("./testdata/testpacket1.packet", &testdata, &datalen);
    assert_int_equal(datalen, 37);

    const char *dest_ip = "127.0.0.1";
    const char *dest_port = "5555";
    rebrick_sockaddr_t destination;
    rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

    rebrick_sockaddr_t bindaddr;
    rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
    rebrick_udpsocket_t *dnsclient;

    create2(rebrick_udpsocket_callbacks_t, callbacks);
    callbacks.callback_data = NULL;
    callbacks.on_read = on_dnsclient_received;
    callbacks.on_write = on_dnsclient_send;
    callbacks.on_error = on_dnsclient_error_occured;

#define COUNTER 250
    for (int i = 0; i < COUNTER; ++i)
    {

        result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
        assert_int_equal(result, 0);

        sended_count = 0;
        received_count = 0;
        rebrick_clean_func_t clean = {};
        rebrick_udpsocket_write(dnsclient, &destination, cast(testdata, uint8_t *), datalen, clean);
        int counter = 10000;
        loop(counter, 10000, !sended_count);

        assert_int_equal(sended_count, 1);
        //data sended

        counter = 10000;
        loop(counter, 10000, !received_count);

        assert_int_equal(received_count, 1);
        rebrick_udpsocket_destroy(dnsclient);
        counter = 1000;
        loop(counter, 1000, FALSE);
    }
    rebrick_free(testdata);
}

/**
 * @brief create a socket
 * send lots of packets
 * at the end destory socket
 *
 * @param state
 */
static void test_rebrick_udpsocket_check_memory2(void **state)
{
    //try sending the same dnsd packet
    //to dockerized bind server
    //and check memory of program

    //create socket once, send packets mode

    unused(state);

    //read a sample dns packet
    char *testdata;
    size_t datalen;

    int32_t result = rebrick_util_file_read_allbytes("./test/testdata/testpacket1.packet", &testdata, &datalen);
    if (result)
        result = rebrick_util_file_read_allbytes("./testdata/testpacket1.packet", &testdata, &datalen);
    assert_int_equal(datalen, 37);

    const char *dest_ip = "127.0.0.1";
    const char *dest_port = "5555";
    rebrick_sockaddr_t destination;
    rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

    rebrick_sockaddr_t bindaddr;
    rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
    rebrick_udpsocket_t *dnsclient;

    create2(rebrick_udpsocket_callbacks_t, callbacks);
    callbacks.callback_data = NULL;
    callbacks.on_read = on_dnsclient_received;
    callbacks.on_write = on_dnsclient_send;
    callbacks.on_error = on_dnsclient_error_occured;

    result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
    assert_int_equal(result, 0);

#define COUNTER 250
    for (int i = 0; i < COUNTER; ++i)
    {

        sended_count = 0;
        received_count = 0;
        rebrick_clean_func_t clean = {};
        rebrick_udpsocket_write(dnsclient, &destination, cast(testdata, uint8_t *), datalen, clean);

        int counter = 10000;
        loop(counter, 10000, !sended_count);

        assert_int_equal(sended_count, 1);
        //data sended

        counter = 10000;
        loop(counter, 10000, !received_count);

        assert_true(received_count > 0);
    }
    rebrick_udpsocket_destroy(dnsclient);
    int32_t counter = 100;
    loop(counter, 100, FALSE);
    rebrick_free(testdata);
}

/**
 * @brief create a udp server and send packets with hping3
 * hping3 --flood --rand-source --udp -d 25  -p TARGET_PORT TARGET_IP
 * @param state
 */
static void test_rebrick_udpsocket_check_memory3(void **state)
{
    //create a udp server
    //and send packets with hping3

    unused(state);
    rebrick_sockaddr_t bindaddr;
    rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "9595");
    rebrick_udpsocket_t *dnsclient;

    create2(rebrick_udpsocket_callbacks_t, callbacks);
    callbacks.callback_data = NULL;
    callbacks.on_read = on_dnsclient_received;
    callbacks.on_write = NULL;
    callbacks.on_error = on_dnsclient_error_occured;

    int32_t result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
    assert_int_equal(result, 0);

    received_count = 0;
    //istenirse burası ile memory test yapılabilir
#define COUNTER2 250
    for (int i = 0; i < COUNTER2; ++i)
    {

        sended_count = 0;
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }

    rebrick_udpsocket_destroy(dnsclient);
    int32_t counter = 100;
    loop(counter, 1000, TRUE);
    /*  while (counter)
    {
        usleep(1000);
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        counter--;
    } */
    //assert_true(received_count > 0);
}

int test_rebrick_udpsocket(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_udpsocket_asserver_communication),
        cmocka_unit_test(test_rebrick_udpsocket_check_memory),
        cmocka_unit_test(test_rebrick_udpsocket_check_memory2),
        cmocka_unit_test(test_rebrick_udpsocket_check_memory3)};
    return cmocka_run_group_tests(tests, setup, teardown);
}
