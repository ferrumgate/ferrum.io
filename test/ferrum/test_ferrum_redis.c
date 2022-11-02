#include "ferrum/ferrum_redis.h"
#include "cmocka.h"
#include <unistd.h>

// compiler unused function problem
static const void *nouse = redisLibuvAttach;

#define loop(var, a, x)                       \
  var = a;                                    \
  while (var-- && (x)) {                      \
    usleep(100);                              \
    uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
  }

static int setup(void **state) {
  unused(state);
  unused(nouse);
  fprintf(stdout, "****  %s ****\n", __FILE__);

  return 0;
}

static int teardown(void **state) {
  unused(state);

  uv_loop_close(uv_default_loop());
  return 0;
}
void debug1(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);
  assert_null(cmd->callback.arg2);

  ferrum_redis_cmd_destroy(cmd);
  // ferrum_redis_reply_free(reply);
  ferrum_redis_destroy(redis);
  int32_t counter;
  loop(counter, 1000, TRUE);
}

static void redis_object_create_destroy_success(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, 1000, 1200);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 10, 1, debug1, redis);

  loop(counter, 1000, TRUE);
  ferrum_redis_send(redis, cmd, "select 0");
  loop(counter, 1000, TRUE);
}

static void redis_object_create_destroy_success_not_connected(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;

  int32_t result = ferrum_redis_new(&redis, "localhost", 6375, 1000, 1200);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 1, 1, debug1, redis);

  loop(counter, 1000, TRUE);
  ferrum_redis_send(redis, cmd, "select 0");
  loop(counter, 1000, TRUE);
  ferrum_redis_destroy(redis);
  loop(counter, 1000, TRUE);
  ferrum_redis_cmd_destroy(cmd);
}

void debug2(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);
  assert_ptr_equal(0x50, cmd->callback.arg2);
  assert_int_equal(cmd->id, 5);
  ferrum_redis_cmd_destroy(cmd);
  // ferrum_redis_reply_free(reply);
  ferrum_redis_destroy(redis);
  int32_t counter;
  loop(counter, 1000, TRUE);
}

static void redis_object_create_destroy_success_cmd_type(void **start) {
  unused(start);

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, 1000, 1200);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new2(&cmd, 5, 10, debug2, redis, (void *)0x50);

  loop(counter, 1000, TRUE);
  ferrum_redis_send(redis, cmd, "select 0");
  loop(counter, 1000, TRUE);
}

void debug3(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);
  assert_int_equal(cmd->id, 5);
  ferrum_redis_cmd_destroy(cmd);
  // ferrum_redis_reply_free(reply);
  ferrum_redis_destroy(redis);
  int32_t counter;
  loop(counter, 1000, TRUE);
}

static void redis_object_create_destroy_success_set_get(void **start) {
  unused(start);

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, 1000, 1200);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 5, 10, debug3, redis);

  loop(counter, 1000, TRUE);
  result = ferrum_redis_send(redis, cmd, "select 0");
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
}

// we are starting redis with /test/prepare.run.sh
// docker run --name redistemp --rm -d -ti -p 6830:6379 redis:7.0-rc2
// docker rm redistemp
void debug4(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);
  // assert_int_equal(cmd->id, 5);

  // ferrum_redis_reply_free(reply);
  if (cmd->id == 7)
    ferrum_redis_destroy(redis);
  ferrum_redis_cmd_destroy(cmd);
  int32_t counter;
  loop(counter, 1000, TRUE);
}

static void redis_object_create_destroy_redis_down_and_up(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;
  printf("execute docker run --name redistemp --rm -d -ti -p 6830:6379 redis:7.0-rc2\n");
  int32_t sleeper = 10000000;
  usleep(sleeper);
  int32_t result = ferrum_redis_new(&redis, "localhost", 6830, 1000, 1200);
  assert_int_equal(result, FERRUM_SUCCESS);
  redis->connection_checker_elapsed_ms = 100;
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 5, 10, debug4, redis);
  loop(counter, 1000, TRUE);
  result = ferrum_redis_send(redis, cmd, "select 0");
  loop(counter, 1000, TRUE);
  assert_int_equal(result, FERRUM_SUCCESS);
  printf("execute docker stop redistemp\n");
  sleeper = 50000;
  while (sleeper) {
    usleep(sleeper);
    sleeper -= 100;
    loop(counter, 10, TRUE);
  }
  ferrum_redis_cmd_t *cmd2;
  result = ferrum_redis_cmd_new(&cmd2, 6, 10, debug4, redis);
  loop(counter, 1000, TRUE);
  result = ferrum_redis_send(redis, cmd2, "select 0");
  loop(counter, 1000, TRUE);
  assert_int_not_equal(result, FERRUM_SUCCESS);
  ferrum_redis_cmd_destroy(cmd2);
  printf("execute docker run --name redistemp --rm -d -ti -p 6830:6379 redis:7.0-rc2\n");
  sleeper = 50000;
  while (sleeper) {
    usleep(sleeper);
    sleeper -= 100;
    loop(counter, 10, TRUE);
  }
  ferrum_redis_cmd_t *cmd3;
  result = ferrum_redis_cmd_new(&cmd3, 7, 10, debug4, redis);
  loop(counter, 1000, TRUE);
  result = ferrum_redis_send(redis, cmd3, "select 0");
  loop(counter, 1000, TRUE);
  assert_int_equal(result, FERRUM_SUCCESS);
}
void debug5(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);

  ferrum_redis_cmd_destroy(cmd);
  // ferrum_redis_reply_free(reply);

  int32_t counter;
  loop(counter, 1000, TRUE);
}

static void redis_object_create_destroy_success_execute_get_set(void **start) {
  unused(start);

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, 1000, 1200);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);

  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 5, 10, debug5, redis);
  result = ferrum_redis_send(redis, cmd, "select 0");
  loop(counter, 1000, TRUE);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_cmd_t *cmd2;
  ferrum_redis_cmd_new(&cmd2, 6, 10, debug5, redis);
  result = ferrum_redis_send(redis, cmd2, "set hamza 10 ex 100");
  loop(counter, 1000, TRUE);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_cmd_t *cmd3;
  ferrum_redis_cmd_new(&cmd3, 6, 10, debug5, redis);
  result = ferrum_redis_send(redis, cmd3, "get hamza");
  loop(counter, 1000, TRUE);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_cmd_t *cmd4;
  ferrum_redis_cmd_new(&cmd4, 7, 10, debug5, redis);
  result = ferrum_redis_send(redis, cmd4, "get hamza22");
  loop(counter, 1000, TRUE);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_destroy(redis);
  loop(counter, 1000, TRUE);
}

void debugSub(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  // assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);
  if (reply && reply->type == REDIS_REPLY_STRING) {
    fprintf(stderr, "redis reply %s\n", reply->str);
  }
  if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) {

    fprintf(stderr, "redis reply %s\n", reply->element[2]->str);
  }
  // ferrum_redis_cmd_destroy(cmd);
  // ferrum_redis_reply_free(reply);

  // int32_t counter;
  //  loop(counter, 1000, TRUE);
}

static void redis_object_cmd_sub(void **start) {
  unused(start);

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t counter;
  ferrum_redis_t *redis;

  int32_t result = ferrum_redis_new_sub(&redis, "localhost", 6379, 1000, 1200, debugSub, NULL, "ferrum");
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);

  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_destroy(redis);

  loop(counter, 1000, TRUE);
}

int test_ferrum_redis(void) {
  unused(redis_object_create_destroy_redis_down_and_up);
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(redis_object_create_destroy_success),
      cmocka_unit_test(redis_object_create_destroy_success_not_connected),
      cmocka_unit_test(redis_object_create_destroy_success_cmd_type),
      cmocka_unit_test(redis_object_create_destroy_success_set_get),
      // cmocka_unit_test(redis_object_create_destroy_redis_down_and_up),
      cmocka_unit_test(redis_object_create_destroy_success_execute_get_set),
      cmocka_unit_test(redis_object_cmd_sub),
  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
