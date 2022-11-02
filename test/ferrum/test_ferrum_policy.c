#include "./ferrum/ferrum_policy.h"
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

static void test_ferrum_policy_replication_message_parse(void **start) {
  unused(start);

  int32_t result;
  new2(ferrum_policy_replication_message_t, msg);

  result = ferrum_policy_replication_message_parse(NULL, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  result = ferrum_policy_replication_message_parse("", &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  result = ferrum_policy_replication_message_parse("test", &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  char *memory = malloc(250);

  strcpy(memory, "/");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strcpy(memory, "//");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strcpy(memory, "///");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strcpy(memory, "/test");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strcpy(memory, "//test//");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strcpy(memory, "abc/reset/");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strcpy(memory, "5/reset/");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(msg.command_id, 5);
  assert_string_equal(msg.command, "reset");

  strcpy(memory, "5/update/acssd/askdfja/awllsd/asdfs/weqeq/qwqqwe/qdfasdfa/q23/1211ae");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(msg.command_id, 5);
  assert_string_equal(msg.command, "update");
  assert_string_equal(msg.arg1, "acssd");
  assert_string_equal(msg.arg2, "askdfja");
  assert_string_equal(msg.arg3, "awllsd");
  assert_string_equal(msg.arg4, "asdfs");
  assert_string_equal(msg.arg5, "weqeq");
  assert_string_equal(msg.arg6, "qwqqwe");
  assert_string_equal(msg.arg7, "qdfasdfa");
  assert_string_equal(msg.arg8, "q23");
  assert_string_equal(msg.arg9, "1211ae");

  free(memory);
}

static void test_ferrum_policy_replication_message_execute(void **start) {
  unused(start);

  int32_t result;

  ferrum_config_t *config = NULL;
  result = ferrum_config_new(&config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  int32_t counter;
  loop(counter, 100, TRUE);

  new2(ferrum_policy_replication_message_t, msg);
  char *memory = malloc(250);
  // check ok command
  strcpy(memory, "5/ok");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  result = ferrum_policy_replication_message_execute(policy, &msg);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(policy->last_command_id, 5);

  // check update command
  strcpy(memory, "10/update/1003/0/10/100/kowlaksdo");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  result = ferrum_policy_replication_message_execute(policy, &msg);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(policy->last_command_id, 10);
  assert_int_equal(HASH_COUNT(policy->table.rows), 1);
  assert_int_equal(policy->table.rows->client_id, 1003);
  assert_int_equal(policy->table.rows->is_drop, 0);
  assert_int_equal(policy->table.rows->policy_number, 10);
  assert_int_equal(policy->table.rows->why, 100);
  assert_string_equal(policy->table.rows->policy_id, "kowlaksdo");

  // check delete command
  strcpy(memory, "11/delete/1003");
  result = ferrum_policy_replication_message_parse(memory, &msg);
  result = ferrum_policy_replication_message_execute(policy, &msg);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(policy->last_command_id, 11);
  assert_int_equal(HASH_COUNT(policy->table.rows), 0);

  ferrum_config_destroy(config);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  free(memory);
}

static void test_redis_cmd_callback(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);

  ferrum_redis_cmd_destroy(cmd);
  int32_t counter;
  loop(counter, 1000, TRUE);
}

static void test_ferrum_policy_start(void **start) {
  unused(start);

  int32_t result;

  ferrum_config_t *config = NULL;
  result = ferrum_config_new(&config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  int32_t counter;
  loop(counter, 50000, TRUE);

  ferrum_redis_t *redis;
  result = ferrum_redis_new(&redis, "localhost", 6479, 5000, 10000);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 1, 1, test_redis_cmd_callback, policy);
  ferrum_redis_send(redis, cmd, "publish /policy/service/gateway1/mysqlservice/randominstance 5/update/1/2/3/4/5/6/7");
  loop(counter, 100, TRUE);

  assert_int_equal(HASH_COUNT(policy->table.rows), 1);

  ferrum_redis_cmd_t *cmd2;
  ferrum_redis_cmd_new(&cmd2, 1, 1, test_redis_cmd_callback, policy);
  ferrum_redis_send(redis, cmd2, "publish /policy/service/gateway1/mysqlservice/randominstance 5/update/1/2/3/4/5/6/7");
  loop(counter, 100, TRUE);
  assert_int_equal(HASH_COUNT(policy->table.rows), 1);

  ferrum_redis_destroy(redis);
  ferrum_policy_destroy(policy);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
}

int test_ferrum_policy(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ferrum_policy_replication_message_parse),
      cmocka_unit_test(test_ferrum_policy_replication_message_execute),
      cmocka_unit_test(test_ferrum_policy_start),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
