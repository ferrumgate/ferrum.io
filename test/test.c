#include "rebrick_common.h"
#include "server_client/udpecho.h"
#include "rebrick_util.h"
#include "cmocka.h"
#include <unistd.h>

extern int test_rebrick_util();
extern int test_rebrick_config();
extern int test_rebrick_metrics();
extern int test_rebrick_context();
extern int test_rebrick_async_udpsocket();
extern int test_rebrick_backend_group();
extern int test_rebrick_backend();

/*  static void test_udpecho_server(){
    fprintf(stdout, "starting udp test server\n");
    udp_echo_start(8888);

   char buffer[512];
   const char *ip="192.168.1.1";
   const char *port="8080";
   rebrick_sockaddr_t addr;
   rebrick_util_to_socket(&addr,ip,port);


   udp_echo_send2("deneme",&addr.v4);

   while(1){
     // getchar();
   int result=udp_echo_recv(buffer);
   printf("%d %s\n",result, buffer);
    usleep(1000000);
   }


   exit(0);
} */

int main()
{
  fprintf(stdout, "starting test\n");
  // test_udpecho_server();
 if(test_rebrick_util())
   exit(1);
   if(test_rebrick_config())
   exit(1);
   if(test_rebrick_metrics())
   exit(1);
   if(test_rebrick_context())
   exit(1);
   if(test_rebrick_async_udpsocket())
   exit(1);


   return 0;


}