#include "./socket/rebrick_tcpsocket.h"
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
    uv_loop_close(uv_default_loop());
    return 0;
}
struct callbackdata
{
    rebrick_tcpsocket_t *client;
    struct sockaddr *addr;
    char buffer[1024];
};


static void on_error_occured(rebrick_socket_t *socket,void *callbackdata,int32_t error){
    unused(socket);
    unused(callbackdata);
    unused(error);

}

int client_connected = 0;
static void on_newclient_connection(rebrick_socket_t *socket, void *callbackdata, const struct sockaddr *addr, void *client_handle)
{

    unused(socket);
    unused(callbackdata);
    unused(addr);
    unused(client_handle);
    struct callbackdata *data = cast(callbackdata, struct callbackdata *);

    data->client = client_handle;
    data->addr = cast(addr, struct sockaddr *);
    client_connected = 1;

}

static void on_read(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(callback_data);

    struct callbackdata *data = cast(callback_data, struct callbackdata *);
    memset(data->buffer, 0, 1024);
    memcpy(data->buffer, buffer, len);


}

static void rebrick_tcpsocket_asserver_communication(void **start)
{
    unused(start);
    const char *port = "9999";
    rebrick_tcpsocket_t *server;
    rebrick_sockaddr_t addr;
    struct callbackdata data;
    int32_t result = rebrick_util_ip_port_to_addr("0.0.0.0", port, &addr);
    assert_int_equal(result, 0);

    result = rebrick_tcpsocket_new(&server, addr, &data, on_newclient_connection, NULL, on_read, NULL,on_error_occured, 10);
    assert_int_equal(result, 0);

    client_connected = 0;

    result = tcp_echo_start(atoi(port), 0);
    //check loop
    int32_t counter = 20;
    while (counter-- && !client_connected)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }

    assert_int_equal(result, 0);
    usleep(100);
    assert_int_equal(client_connected, 1);
    //struct sockaddr_in *s = data.addr;
    //assert_int_equal(s->sin_addr.s_addr,INADDR_LOOPBACK);

    char *hello = "hello";
    tcp_echo_send(hello);
    //check loop
    counter = 20;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }

    assert_string_equal(data.buffer, hello);

    char *world = "world";
    rebrick_clean_func_t clean={};
    result = rebrick_tcpsocket_send(data.client, world, strlen(world), clean);
    assert_int_equal(result, 0);

    //check loop
    counter = 20;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }

    char readed[ECHO_BUF_SIZE] = {'\0'};
    result = tcp_echo_recv(readed);
    assert_int_equal(result, 5);

    assert_string_equal(readed, world);
    rebrick_tcpsocket_destroy(data.client);

    counter = 100;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(100);
    }

    rebrick_tcpsocket_destroy(server);

    counter = 100;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(100);
    }

    tcp_echo_stop();
}

int connected_toserver = 0;
static void on_connection_accepted(rebrick_socket_t *socket, void *callbackdata, const struct sockaddr *addr, void *client_handle)
{
    unused(callbackdata);
    unused(addr);

    unused(client_handle);
    unused(socket);
    struct callbackdata *data = cast(callbackdata, struct callbackdata *);
    unused(data);
    connected_toserver = 1;

}

static void on_connection_closed(rebrick_socket_t *socket, void *callbackdata)
{
    unused(socket);
    unused(callbackdata);
    struct callbackdata *data = cast(callbackdata, struct callbackdata *);
    unused(data);

}
static int datareceived_ok = 0;
static void on_datarecevied(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(callback_data);
    unused(addr);

    unused(socket);
    if(len>0){
    struct callbackdata *data = cast(callback_data, struct callbackdata *);
    memset(data->buffer, 0, 1024);
    memcpy(data->buffer, buffer, len);
    datareceived_ok = 1;
    }

}

static void on_datasend(rebrick_socket_t *socket, void *callback_data,void *source)
{
    unused(callback_data);
    unused(source);
    unused(socket);


}

static void rebrick_tcpsocket_asclient_communication(void **start)
{

    unused(start);
    const char *port = "9998";
    rebrick_tcpsocket_t *client;
    rebrick_sockaddr_t addr;
    rebrick_util_ip_port_to_addr("127.0.0.1", port, &addr);
    struct callbackdata data;
    int32_t result = tcp_echo_start(atoi(port), 1);
    assert_int_equal(result, 0);
    fill_zero(&data, sizeof(struct callbackdata));
    connected_toserver = 0;

    result = tcp_echo_listen();

    result = rebrick_tcpsocket_new(&client, addr, &data, on_connection_accepted, on_connection_closed, on_datarecevied, on_datasend,on_error_occured, 0);

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
    rebrick_clean_func_t cleanfunc={};
    rebrick_tcpsocket_send(client, "valla", 6, cleanfunc);

    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100);
    char recvbuf[ECHO_BUF_SIZE] = {'\0'};

    tcp_echo_recv(recvbuf);
    assert_string_equal(recvbuf, "valla");
    rebrick_tcpsocket_destroy(client);
    counter = 100;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(100);
    }

    tcp_echo_stop();
}

////////////////////////// memory tests /////////////////////////////////////

static void on_error_occured_memorytest(rebrick_socket_t *socket,void *callbackdata,int32_t error){
    unused(socket);
    unused(callbackdata);
    unused(error);
    rebrick_tcpsocket_destroy(cast(socket,rebrick_tcpsocket_t*));

}

int connected_to_memorytest = 0;
int connected_to_memorytest_counter=0;
rebrick_tcpsocket_t *connected_client;
static void on_connection_accepted_memorytest(rebrick_socket_t *socket, void *callbackdata, const struct sockaddr *addr, void *client_handle)
{
    unused(callbackdata);
    unused(addr);

    unused(client_handle);
    unused(socket);

    connected_to_memorytest = 1;
    connected_to_memorytest_counter++;
    connected_client = cast(client_handle, rebrick_tcpsocket_t *);

}

int connection_closed_memorytest = 0;
int connection_closed_memorytestcounter=0;
static void on_connection_closed_memorytest(rebrick_socket_t *socket, void *callbackdata)
{
    unused(socket);
    unused(callbackdata);

    connection_closed_memorytest = 1;
    connection_closed_memorytestcounter++;

}
static int datareceived_ok_memorytest = 0;
static char memorytestdata[1024 * 1024];
static int datareceived_ok_total_memorytest = 0;

static void on_datarecevied_memorytest(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(callback_data);
    unused(addr);

    unused(socket);
    memcpy(memorytestdata, buffer, len);

    datareceived_ok_memorytest = len;
    datareceived_ok_total_memorytest += len;

}

static int datasended_memorytest = 0;
static void on_datasend_memorytest(rebrick_socket_t *socket, void *callback_data,void *source)
{
    unused(callback_data);
    unused(source);
    unused(socket);
    datasended_memorytest = 10;

}

/**
 * @brief connect to a docker http server and get data
 * test folder altındaki, docker_ssl altındaki run.sh
 * @param start
 */
static void rebrick_tcpsocket_asclient_memory(void **start)
{

    unused(start);
    const char *port = "80";
    rebrick_tcpsocket_t *client;
    rebrick_sockaddr_t addr;
    rebrick_util_ip_port_to_addr("127.0.0.1", port, &addr);
    struct callbackdata data;

    fill_zero(&data, sizeof(struct callbackdata));

    char *head = "GET / HTTP/1.0\r\n\
Host: nodejs.org\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
#define COUNTER 100

    for (int i = 0; i < COUNTER; ++i)
    {

        int32_t result = rebrick_tcpsocket_new(&client, addr, &data, on_connection_accepted_memorytest, on_connection_closed_memorytest, on_datarecevied_memorytest, on_datasend_memorytest,on_error_occured_memorytest, 0);
        assert_int_equal(result, REBRICK_SUCCESS);

        //check a little
        int counter = 1000;
        while (--counter && !connected_to_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(1000);
        }

        datasended_memorytest = 0;
        datareceived_ok_memorytest = 0;
        connection_closed_memorytest = 0;
        rebrick_clean_func_t cleanfunc={};
        result = rebrick_tcpsocket_send(client, head, strlen(head) + 1, cleanfunc);

        counter = 1000;
        while (--counter && !datasended_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(1000);
        }
        assert_int_equal(datasended_memorytest, 10); //this value is used above

        counter = 1000;
        while (--counter && !datareceived_ok_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(1000);
        }
        assert_true(datareceived_ok_memorytest > 0);

        rebrick_tcpsocket_destroy(client);
        counter = 1000;
        while (--counter && !connection_closed_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(1000);
        }
        assert_true(connection_closed_memorytest != 0);
    }
}

static void rebrick_tcp_client_download_data(void **start)
{

    unused(start);
    const char *port = "80";
    rebrick_tcpsocket_t *client;
    rebrick_sockaddr_t addr;
    rebrick_util_ip_port_to_addr("127.0.0.1", port, &addr);
    struct callbackdata data;

    fill_zero(&data, sizeof(struct callbackdata));

    char *head = "GET /10m.ignore.txt HTTP/1.0\r\n\
Host: nodejs.org\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\
Accept: text/html\r\n\
\r\n";
#define COUNTER 100

    for (int i = 0; i < COUNTER; ++i)
    {

connection_closed_memorytest = 0;
        int32_t result = rebrick_tcpsocket_new(&client, addr, &data, on_connection_accepted_memorytest, on_connection_closed_memorytest, on_datarecevied_memorytest, on_datasend_memorytest,on_error_occured_memorytest, 0);
        assert_int_equal(result, REBRICK_SUCCESS);

        //check a little
        int counter = 1000;
        while (--counter && !connected_to_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(1000);
        }

        datasended_memorytest = 0;
        datareceived_ok_memorytest = 0;
        rebrick_clean_func_t cleanfunc={};
        result = rebrick_tcpsocket_send(client, head, strlen(head) + 1, cleanfunc);

        counter = 1000;
        datareceived_ok_total_memorytest = 1;
        while (counter && !connection_closed_memorytest)
        {
            usleep(100);
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            counter--;
        }
        if (!connection_closed_memorytest)
        {
            counter=100;
            rebrick_tcpsocket_destroy(client);

            while (counter-- && !connection_closed_memorytest)
            {
                usleep(100);
                uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            }
        }

        assert_true(connection_closed_memorytest != 0);
    }
}

/**
 * @brief create a http server
 * komut satırından
 * for i in {1..1000}
 * do
 * curl http://localhost:8585
 * done
 *
 * @param start
 */
static void rebrick_tcpsocket_asserver_memory(void **start)
{

    unused(start);
    const char *port = "8585";

    rebrick_sockaddr_t addr;
    rebrick_util_ip_port_to_addr("0.0.0.0", port, &addr);
    struct callbackdata data;

    fill_zero(&data, sizeof(struct callbackdata));

    char *html = "HTTP/1.1 200 OK\r\n\
Server: nginx\r\n\
Date: Fri, 23 Aug 2019 20:34:20 GMT\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 86\r\n\
Last-Modified: Sat, 10 Aug 2019 20:33:16 GMT\r\n\
Connection: close\r\n\
Vary: Accept-Encoding\r\n\
Accept-Ranges: bytes\r\n\
\r\n\
<html>\r\n\
    <body>\r\n\
        <h1>\r\n\
            it works!\r\n\
        </h1>\r\n\
    </body>\r\n\
</html>";
#undef COUNTER
#define COUNTER 100
    rebrick_tcpsocket_t *server;

    for (int i = 0; i < COUNTER; ++i)
    {

        connected_client=NULL;
        int32_t result = rebrick_tcpsocket_new(&server, addr, &data, on_connection_accepted_memorytest, on_connection_closed_memorytest, on_datarecevied_memorytest, on_datasend_memorytest,on_error_occured_memorytest, 10);
        assert_int_equal(result, REBRICK_SUCCESS);

        //check a little
        int counter = 100;
        connected_to_memorytest = 0;
        connected_to_memorytest_counter=0;
        while (--counter && !connected_to_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(100);
        }

        datasended_memorytest = 0;
        datareceived_ok_memorytest = 0;
        connection_closed_memorytest = 0;
        connection_closed_memorytestcounter=0;

        counter = 100;
        while (--counter && !datareceived_ok_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(100);
        }
        rebrick_clean_func_t cleanfunc={};
        //assert_true(datareceived_ok_memorytest > 0);
        if(connected_client)
        result = rebrick_tcpsocket_send(connected_client, html, strlen(html) + 1, cleanfunc);

        counter = 100;
        while (--counter && !datasended_memorytest)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(100);

        }
        //assert_int_equal(datasended_memorytest, 10); //this value is used above

        rebrick_tcpsocket_destroy(server);
        counter = 100;
        while (--counter && connection_closed_memorytestcounter!=2)
        {
            uv_run(uv_default_loop(), UV_RUN_NOWAIT);
            usleep(100);
        }


        //assert_true(connected_to_memorytest!=0);
    }

    //getchar();
}

int test_rebrick_tcpsocket(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_tcpsocket_asserver_communication),
        cmocka_unit_test(rebrick_tcpsocket_asclient_communication),
          cmocka_unit_test(rebrick_tcpsocket_asclient_memory),
         cmocka_unit_test(rebrick_tcp_client_download_data),
        cmocka_unit_test(rebrick_tcpsocket_asserver_memory)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
