#include "ferrum/ferrum_syslog.h"
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

static void ferrum_object_create_destroy_success(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  setenv("SYSLOG_HOST", "www.google.com:9292", 1);

  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
}

static void ferrum_object_syslog_write(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  setenv("SYSLOG_HOST", "localhost:9292", 1);

  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  char *data = "/hello";
  result = ferrum_syslog_write(syslog, cast_to_uint8ptr(data), strlen(data));
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  result = ferrum_syslog_write(syslog, cast_to_uint8ptr(data), strlen(data));
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  result = ferrum_syslog_write(syslog, cast_to_uint8ptr(data), strlen(data));
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  result = ferrum_syslog_write(syslog, cast_to_uint8ptr(data), strlen(data));
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  result = ferrum_syslog_write(syslog, cast_to_uint8ptr(data), strlen(data));
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
}

int test_ferrum_syslog(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(ferrum_object_create_destroy_success),
      cmocka_unit_test(ferrum_object_syslog_write),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
