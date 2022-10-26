#include "./ferrum/ferrum_config.h"
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

static void ferrum_config_object_create_destroy(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);
  assert_string_equal(config->type_name, "ferrum_config_t");

  ferrum_config_destroy(config);
}

static void ferrum_config_object_redis_ip_port() {
  ferrum_config_t *config = NULL;
  int32_t result;
  setenv("REDIS_HOST", "localhost:1234", 1);
  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  assert_true(strcmp(config->redis.ip, "127.0.0.1") || strcmp(config->redis.ip, "::1"));
  assert_int_equal(config->redis.port, 1234);

  ferrum_config_destroy(config);
}

static void ferrum_config_object_raw() {
  ferrum_config_t *config = NULL;
  int32_t result;
  setenv("RAW_DESTINATION_HOST", "localhost", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "9090", 1);
  setenv("RAW_DESTINATION_UDP_PORT", "8080", 1);
  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  assert_true(strcmp(config->raw.dest_ip, "127.0.0.1") || strcmp(config->raw.dest_ip, "::1"));
  assert_int_equal(config->raw.dest_tcp_port, 9090);
  assert_int_equal(config->raw.dest_udp_port, 8080);
  assert_int_equal(config->raw.dest_tcp_addr.v4.sin_port, ntohs(9090));
  assert_int_equal(config->raw.dest_udp_addr.v4.sin_port, ntohs(8080));
  ferrum_config_destroy(config);
}

int test_ferrum_config(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_config_object_create_destroy),
      cmocka_unit_test(ferrum_config_object_redis_ip_port),
      cmocka_unit_test(ferrum_config_object_raw),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
