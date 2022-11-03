#include "./rebrick/netfilter/rebrick_conntrack.h"
#include "cmocka.h"
#include <unistd.h>

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

static int test = 0;

static int32_t callback(void *data) {
  unused(data);

  test++;
  return test;
}

static void test_rebrick_conntrack_get(void **start) {
  unused(start);
  new2(rebrick_conntrack_t, track);
  struct sockaddr_in peer;
  struct sockaddr_in local;
  int32_t result = rebrick_conntrack_get(cast(&peer, struct sockaddr *), cast(&local, struct sockaddr *), 0, &track);
  assert_int_not_equal(result, REBRICK_SUCCESS);
}

int test_rebrick_conntrack(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_rebrick_conntrack_get),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
