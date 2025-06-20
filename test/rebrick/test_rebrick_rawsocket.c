#include "./rebrick/socket/rebrick_rawsocket.h"
#include "./server_client/tcpecho.h"
#include "cmocka.h"
#include "unistd.h"

#define TCPSERVER_PORT "9999"

#define loop(var, a, x)                       \
  var = a;                                    \
  while (var-- && (x)) {                      \
    usleep(100);                              \
    uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
  }

static int setup(void **state) {
  unused(state);
  fprintf(stdout, "****  %s ****\n", __FILE__);

  return 0;
}

static int teardown(void **state) {
  unused(state);
  uv_loop_close(uv_default_loop());
  return 0;
}
struct callbackdata {
  rebrick_rawsocket_t *client;
  struct sockaddr *addr;
  char buffer[1024];
};

int test_rebrick_rawsocket(void) {
  const struct CMUnitTest tests[] = {

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
