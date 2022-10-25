#include "./rebrick/common/rebrick_common.h"
#include "./rebrick/server_client/udpecho.h"
#include "./rebrick/server_client/tcpecho.h"
#include "./rebrick/common/rebrick_util.h"

#include "cmocka.h"
#include <unistd.h>

extern int test_rebrick_util();
extern int test_rebrick_resolve();
extern int test_rebrick_filestream();
extern int test_rebrick_timer();
extern int test_rebrick_udpsocket();
extern int test_rebrick_tcpsocket();
extern int test_rebrick_buffer();
extern int test_rebrick_buffers();
extern int test_rebrick_tls();
extern int test_rebrick_tlssocket();
extern int test_rebrick_http();
extern int test_rebrick_httpsocket();
extern int test_rebrick_http2socket();

int main() {
  fprintf(stdout, "starting test\n");

  /* if (test_rebrick_filestream())
    exit(1);

  if (test_rebrick_util())
    exit(1);

  if (test_rebrick_resolve())
    exit(1);

  if (test_rebrick_buffer())
    exit(1);

  if (test_rebrick_buffers())
    exit(1);

  if (test_rebrick_timer())
    exit(1);

  if (test_rebrick_udpsocket())
    exit(1);
 */
  if (test_rebrick_tcpsocket())
    exit(1);

  /*
    if (test_rebrick_tls())
      exit(1);

    if (test_rebrick_tlssocket())
      exit(1);

    // if (test_rebrick_http())
    //   exit(1);

    // if (test_rebrick_httpsocket())
    //   exit(1);

    // if (test_rebrick_http2socket())
    //   exit(1);

    /* extern void http2_socket_as_serverserver_create_get_server_push_streams(void **start);
    http2_socket_as_serverserver_create_get_server_push_streams(NULL);
      kill(getpid(), SIGSEGV);
    getchar(); */

  return 0;
}