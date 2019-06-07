#include "./rebrick_async_udpsocket.h"
#include "./server_client/udpecho.h"
#include "cmocka.h"
#include "unistd.h"

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
    return 0;
}

static int32_t flag=0;
char read_buffer[65536];
const char *testdata="merhaba";
static int32_t on_server_received(void *data,const struct sockaddr *addr, const char *buffer,size_t len,void *deletedata){
    unused(addr);

    assert_string_equal(data,testdata);
    flag=1;
    memset(read_buffer,0,512);
    memcpy(read_buffer,buffer,len<65536?len:65536);
    return REBRICK_SUCCESS;
}

static int32_t on_server_send(void *data,int status){
    unused(data);
    assert_string_equal(data,testdata);
    flag=2;

    return REBRICK_SUCCESS+status-status;
}

static void rebrick_async_udpsocket_asserver_communication(void **start)
{
     unused(start);
      rebrick_async_udpsocket_t *server;
      const char *bind_ip="0.0.0.0";
      const char *bind_port="9090";
      rebrick_sockaddr_t bind;
      rebrick_util_to_socket(&bind,bind_ip,bind_port);


      const char *localhost_ip="127.0.0.1";

      rebrick_sockaddr_t localhost;
      rebrick_util_to_socket(&localhost,localhost_ip,bind_port);

      const char *dest_ip="127.0.0.1";
      const char *dest_port="9999";
      rebrick_sockaddr_t client;
      rebrick_util_to_socket(&client,dest_ip,dest_port);

      int32_t result=rebrick_async_udpsocket_new(&server,bind,cast(testdata,void*), &on_server_received,&on_server_send);
      assert_int_equal(result,0);
        //check loop
      uv_run(uv_default_loop(),UV_RUN_NOWAIT);

      const char *msg="hello world";
      char *buffer=new(sizeof(msg));
      strcpy(buffer,msg);
      flag=0;
      udp_echo_send2(msg,&localhost.v4);
      //loop again
      uv_run(uv_default_loop(),UV_RUN_NOWAIT);
        //check for received data
        int32_t max_check=10;
        while(!flag && max_check){
            usleep(10000);
            uv_run(uv_default_loop(),UV_RUN_NOWAIT);
            max_check--;
        }
       assert_int_not_equal(max_check,0);
       assert_string_equal(msg,read_buffer);
      flag=0;
      char *reply="got it";
      char *bufferreplay=new(sizeof(reply));
        strcpy(bufferreplay,reply);
     result= rebrick_async_udpsocket_send(server,&client, bufferreplay,sizeof(bufferreplay),NULL);
     assert_int_equal(result,0);
     // uv_run(uv_default_loop(),UV_RUN_NOWAIT);

      //check for received data
        max_check=10;
        while(!flag && max_check){
            usleep(10000);
            uv_run(uv_default_loop(),UV_RUN_NOWAIT);
            max_check--;
            result=udp_echo_recv(read_buffer);
            if(result>0)
            break;
        }
        assert_int_not_equal(max_check,0);
        assert_string_equal(reply,read_buffer);

       result= rebrick_async_udpsocket_destroy(server);
       assert_int_equal(result,0);



}

int test_rebrick_async_udpsocket(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_async_udpsocket_asserver_communication)
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
