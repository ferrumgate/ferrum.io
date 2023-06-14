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
  setenv("POLICY_DB_FOLDER", folder, 1);
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
  setenv("POLICY_DB_FOLDER", folder, 1);
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
  setenv("POLICY_DB_FOLDER", folder, 1);
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
  setenv("POLICY_DB_FOLDER", folder, 1);
  setenv("SERVICE_ID", "10", 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, folder, "policy", 2, 160000);
  assert_int_equal(result, FERRUM_SUCCESS);
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authorize/track/id/12/service/id/10");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->key.val) - 1, "1,");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
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
  setenv("POLICY_DB_FOLDER", folder, 1);
  setenv("SERVICE_ID", "10", 1);
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, folder, "policy", 2, 160000);
  assert_int_equal(result, FERRUM_SUCCESS);
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authorize/track/id/12/service/id/10");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->key.val) - 1, "1,2,abc,def,ghi");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authorize/track/id/13/service/id/10");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->key.val) - 1, ",1,2,,,ghi");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authorize/track/id/14/service/id/10");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->key.val) - 1, "1,2,,,ghi");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authorize/track/id/15/service/id/10");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->key.val) - 1, "ab,2,,,ghi,");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authorize/track/id/16/service/id/10");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->key.val) - 1, "0,2,,ghi,,");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
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

  new2(ferrum_policy_result_t, presult2);
  result = ferrum_policy_execute(policy, 13, &presult2);
  assert_int_equal(result, FERRUM_ERR_POLICY);
  assert_int_equal(presult2.is_dropped, TRUE);
  assert_int_equal(presult2.why, FERRUM_POLICY_INVALID_DATA);
  assert_string_equal(presult2.policy_id, "");
  assert_string_equal(presult2.tun_id, "");
  assert_string_equal(presult2.user_id, "");

  new2(ferrum_policy_result_t, presult3);
  result = ferrum_policy_execute(policy, 14, &presult3);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(presult3.is_dropped, TRUE);
  assert_int_equal(presult3.why, 2);
  assert_string_equal(presult3.policy_id, "");
  assert_string_equal(presult3.tun_id, "");
  assert_string_equal(presult3.user_id, "ghi");

  new2(ferrum_policy_result_t, presult4);
  result = ferrum_policy_execute(policy, 15, &presult4);
  assert_int_equal(result, FERRUM_ERR_POLICY);
  assert_int_equal(presult4.is_dropped, TRUE);
  assert_int_equal(presult4.why, FERRUM_POLICY_INVALID_DATA);
  assert_string_equal(presult4.policy_id, "");
  assert_string_equal(presult4.tun_id, "");
  assert_string_equal(presult4.user_id, "");

  new2(ferrum_policy_result_t, presult5);
  result = ferrum_policy_execute(policy, 16, &presult5);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(presult5.is_dropped, FALSE);
  assert_int_equal(presult5.why, 2);
  assert_string_equal(presult5.policy_id, "");
  assert_string_equal(presult5.tun_id, "ghi");
  assert_string_equal(presult5.user_id, "");

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
