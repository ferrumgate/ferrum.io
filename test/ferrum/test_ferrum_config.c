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

  assert_true(strcmp(config->redis.addr_str, "[127.0.0.1]:[1234]") == 0 || strcmp(config->redis.addr_str, "[::1]:[1234]") == 0);
  assert_true(strcmp(config->redis.ip, "127.0.0.1") == 0 || strcmp(config->redis.ip, "::1") == 0);
  assert_true(strcmp(config->redis.port, "1234") == 0);
  ferrum_config_destroy(config);
}

static void ferrum_config_object_service_id() {
  ferrum_config_t *config = NULL;
  int32_t result;
  setenv("SERVICE_ID", "1231as", 1);
  setenv("HOST_ID", "a1231as", 1);
  setenv("INSTANCE_ID", "b1231as", 1);
  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  assert_true(strcmp(config->service_id, "1231as"));
  assert_true(strcmp(config->host_id, "a1231as"));
  assert_true(strcmp(config->instance_id, "b1231as"));
  ferrum_config_destroy(config);
}

static void ferrum_config_object_disable_policy() {
  ferrum_config_t *config = NULL;
  int32_t result;
  setenv("DISABLE_POLICY", "true", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  assert_int_equal(config->is_policy_disabled, TRUE);
  ferrum_config_destroy(config);
}

static void ferrum_config_object_raw() {
  ferrum_config_t *config = NULL;
  int32_t result;
  setenv("RAW_DESTINATION_HOST", "localhost", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "9090", 1);
  setenv("RAW_DESTINATION_UDP_PORT", "8080", 1);
  setenv("RAW_LISTEN_IP", "192.168.91.91", 1);
  setenv("RAW_LISTEN_TCP_PORT", "9191", 1);
  setenv("RAW_LISTEN_UDP_PORT", "9292", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  assert_true(strcmp(config->raw.dest_tcp_addr_str, "[127.0.0.1]:[9090]") == 0 || strcmp(config->raw.dest_tcp_addr_str, "[::1]:[9090]") == 0);

  assert_int_equal(config->raw.dest_tcp_addr.v4.sin_port, htons(9090));
  assert_int_equal(config->raw.dest_udp_addr.v4.sin_port, htons(8080));

  assert_string_equal(config->raw.listen_tcp_addr_str, "[192.168.91.91]:[9191]");
  assert_string_equal(config->raw.listen_udp_addr_str, "[192.168.91.91]:[9292]");
  assert_int_equal(config->raw.listen_tcp_addr.v4.sin_port, htons(9191));
  assert_int_equal(config->raw.listen_udp_addr.v4.sin_port, htons(9292));

  ferrum_config_destroy(config);
}

int test_ferrum_config(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_config_object_create_destroy),
      cmocka_unit_test(ferrum_config_object_redis_ip_port),
      cmocka_unit_test(ferrum_config_object_raw),
      cmocka_unit_test(ferrum_config_object_disable_policy),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
