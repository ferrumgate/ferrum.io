#include "ferrum/ferrum_policy.h"
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
  const char *folder = "/tmp/test4";
  setenv("LMDB_FOLDER", folder, 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_policy_t *policy;

  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_policy_destroy(policy);
  ferrum_config_destroy(config);
}

static void ferrum_policy_execute_policy_disabled(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  const char *folder = "/tmp/test4";
  setenv("LMDB_FOLDER", folder, 1);
  setenv("DISABLE_POLICY", "true", 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  new2(ferrum_policy_result_t, presult);
  result = ferrum_policy_execute(policy, 12, &presult);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(presult.is_dropped, FALSE);
  assert_int_equal(presult.why, FERRUM_POLICY_DISABLED_POLICY);
  ferrum_policy_destroy(policy);
  ferrum_config_destroy(config);
  setenv("DISABLE_POLICY", "false", 1);
}

static void ferrum_policy_execute_policy_row_not_found(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  const char *folder = "/tmp/test4";
  setenv("LMDB_FOLDER", folder, 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  new2(ferrum_policy_result_t, presult);
  result = ferrum_policy_execute(policy, 12, &presult);
  assert_int_equal(result, FERRUM_ERR_POLICY);
  assert_int_equal(presult.is_dropped, TRUE);
  assert_int_equal(presult.why, FERRUM_POLICY_NOT_FOUND);

  ferrum_policy_destroy(policy);
  ferrum_config_destroy(config);
}

static void ferrum_policy_execute_policy_row_invalid(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  const char *folder = "/tmp/test4";
  setenv("LMDB_FOLDER", folder, 1);
  setenv("SERVICE_ID", "10", 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, folder, "ferrumgate", 2, 160000);
  assert_int_equal(result, FERRUM_SUCCESS);
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/authorize/track/id/12/service/id/10");
  lmdb->value.size = snprintf(lmdb->value.val, sizeof(lmdb->key.val) - 1, "/1/2/");
  result = ferrum_lmdb_put(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_lmdb_destroy(lmdb);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  new2(ferrum_policy_result_t, presult);
  result = ferrum_policy_execute(policy, 12, &presult);
  assert_int_equal(result, FERRUM_ERR_POLICY);
  assert_int_equal(presult.is_dropped, TRUE);
  assert_int_equal(presult.why, FERRUM_POLICY_INVALID_DATA);

  ferrum_policy_destroy(policy);
  ferrum_config_destroy(config);
  setenv("SERVICE_ID", "", 1);
}

static void ferrum_policy_execute_policy_row_ok(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  const char *folder = "/tmp/test4";
  setenv("LMDB_FOLDER", folder, 1);
  setenv("SERVICE_ID", "10", 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, folder, "ferrumgate", 2, 160000);
  assert_int_equal(result, FERRUM_SUCCESS);
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/authorize/track/id/12/service/id/10");
  lmdb->value.size = snprintf(lmdb->value.val, sizeof(lmdb->key.val) - 1, "/1/2/abc/def/ghi");
  result = ferrum_lmdb_put(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_lmdb_destroy(lmdb);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  new2(ferrum_policy_result_t, presult);
  result = ferrum_policy_execute(policy, 12, &presult);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(presult.is_dropped, TRUE);
  assert_int_equal(presult.why, 2);
  assert_string_equal(presult.policy_id, "abc");
  assert_string_equal(presult.tun_id, "def");
  assert_string_equal(presult.user_id, "ghi");

  ferrum_policy_destroy(policy);
  ferrum_config_destroy(config);
  setenv("SERVICE_ID", "", 1);
}

int test_ferrum_policy(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(ferrum_object_create_destroy_success),
      cmocka_unit_test(ferrum_policy_execute_policy_disabled),
      cmocka_unit_test(ferrum_policy_execute_policy_row_not_found),
      cmocka_unit_test(ferrum_policy_execute_policy_row_invalid),
      cmocka_unit_test(ferrum_policy_execute_policy_row_ok),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
