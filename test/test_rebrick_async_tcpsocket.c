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
struct callbackdata{
    rebrick_async_tcpsocket_t *client;
    struct sockaddr *addr;
    char buffer[1024];
};

int client_connected=0;
static void on_newclient_connection(void *callbackdata, const struct sockaddr *addr,rebrick_async_tcpsocket_t *client_handle){
    struct callbackdata *data=cast(callbackdata,struct callbackdata*);

    data->client=client_handle;
    data->addr=addr;
    client_connected=1;
}

static void on_read(void *callback_data,const struct sockaddr *addr, const char *buffer,size_t len,void *deletedata){
        struct callbackdata *data=cast(callback_data,struct callbackdata*);
        memset(data->buffer,0,1024);
        memcpy(data->buffer,buffer,len);

}




static void rebrick_async_tcpsocket_asserver_communication(void **start)
{
     unused(start);
     const char *port="9999";
     rebrick_async_tcpsocket_t *server;
     rebrick_sockaddr_t addr;
     struct callbackdata data;
     int32_t result=rebrick_util_ip_port_to_addr("0.0.0.0",port,&addr);
     assert_int_equal(result,0);

     result=rebrick_async_tcpsocket_new(&server,addr,&data,on_newclient_connection,NULL,on_read,NULL,10);
     assert_int_equal(result,0);

     client_connected=0;

     result=tcp_echo_start(atoi(port),0);
    //check loop
     uv_run(uv_default_loop(),UV_RUN_NOWAIT);
     assert_int_equal(result,0);
     usleep(100);
     assert_int_equal(client_connected,1);
     struct sockaddr_in *s=&data.addr;
     //assert_int_equal(s->sin_addr.s_addr,INADDR_LOOPBACK);

     char *hello="hello";
     tcp_echo_send(hello);
     //check loop
     uv_run(uv_default_loop(),UV_RUN_NOWAIT);
     usleep(100);
     assert_string_equal(data.buffer,hello);

     char *world="world";
     result=rebrick_async_tcpsocket_send(data.client,world,strlen(world),NULL);
     assert_int_equal(result,0);

     //check loop
     uv_run(uv_default_loop(),UV_RUN_NOWAIT);
     usleep(100);
     char readed[1024]={'\0'};
     result=tcp_echo_recv(readed);
     assert_int_equal(result,5);

     assert_string_equal(readed,world);
     rebrick_async_tcpsocket_destroy(data.client);

    uv_run(uv_default_loop(),UV_RUN_NOWAIT);
     usleep(100);
     uv_run(uv_default_loop(),UV_RUN_NOWAIT);
     usleep(100);


}

int test_rebrick_async_tcpsocket(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_async_tcpsocket_asserver_communication)
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
