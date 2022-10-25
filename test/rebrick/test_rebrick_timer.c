#include "./rebrick/common/rebrick_timer.h"
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

static void timer_object_create_destroy(void **start) {
  unused(start);
  rebrick_timer_t *timer;
  int32_t result;
  test = 0;
  result = rebrick_timer_new(&timer, callback, (void *)5, 1, 1);

  assert_true(result == 0);
  // check loop

  int32_t counter = 5;
  loop(counter, 1000, !test);

  assert_true(test > 0);
  rebrick_timer_destroy(timer);
  // check loop
  loop(counter, 10, TRUE);
  int tmp = test;
  loop(counter, 1000, TRUE);
  assert_true(tmp == test);
}

static void timer_object_create_start_stop_destroy(void **start) {
  unused(start);
  rebrick_timer_t *timer;
  int32_t result;
  test = 0;
  int32_t counter;
  result = rebrick_timer_new(&timer, callback, (void *)5, 1, 0);

  assert_true(result == 0);
  // check loop
  loop(counter, 1000, TRUE);
  assert_true(test == 0);

  result = rebrick_timer_start(timer);
  assert_true(result == 0);
  // check loop
  loop(counter, 1000, TRUE);

  assert_true(test > 0);
  // check loop
  loop(counter, 1000, TRUE);
  assert_true(test > 0);
  result = rebrick_timer_stop(timer);
  assert_true(result == 0);

  int tmp = test;
  loop(counter, 1000, TRUE);
  assert_true(tmp == test);

  result = rebrick_timer_destroy(timer);
  assert_true(result == 0);
  loop(counter, 1000, TRUE);
}

int test_rebrick_timer(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(timer_object_create_destroy),
      cmocka_unit_test(timer_object_create_start_stop_destroy)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
