#include "./ferrum/ferrum_activity_log.h"
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

static void ferrum_activity_log_raw(void **start) {
  unused(start);
  int32_t counter;
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_result_t presult;
  memset(&presult, 0, sizeof(presult));
  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &client);

  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19192", &dest);

  ferrum_write_activity_log_raw(syslog, "test", "raw", &presult, &client, "123", "2323", FALSE, &dest, "12323", "12313");
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
}

int test_ferrum_activity_log(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_activity_log_raw)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
