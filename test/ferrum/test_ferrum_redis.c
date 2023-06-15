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

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1200);
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

  int32_t result = ferrum_redis_new(&redis, "localhost", 6375, NULL, 1000, 1200);
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

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1200);
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

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1200);
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
  int32_t result = ferrum_redis_new(&redis, "localhost", 6830, NULL, 1000, 1200);
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

  int32_t result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1200);
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

  int32_t result = ferrum_redis_new_sub(&redis, "localhost", 6379, NULL, 1000, 1200, debugSub, NULL, "ferrum");
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);

  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_destroy(redis);

  loop(counter, 1000, TRUE);
}

int stream_item_count = 0;
char stream_id[16];
char stream_field[16];
char stream_value[16];
void debug_stream(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  // assert_non_null(reply);

  if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements == 1)
    if (reply->element[0]->type == REDIS_REPLY_ARRAY && reply->element[0]->elements > 1)
      if (reply->element[0]->element[1]->type == REDIS_REPLY_ARRAY && reply->element[0]->element[1]->elements) {
        for (size_t i = 0; i < reply->element[0]->element[1]->elements; ++i) {
          ferrum_redis_reply_t *row = reply->element[0]->element[1]->element[i];
          if (row->type == REDIS_REPLY_ARRAY && row->elements) {
            if (row->element[0]->type == REDIS_REPLY_STRING) {
              stream_item_count++;
              strncpy(stream_id, row->element[0]->str, sizeof(stream_id) - 1);
              strncpy(redis->stream.pos, row->element[0]->str, sizeof(redis->stream.pos) - 1);
            }
            if (row->elements > 1 && row->element[1]->type == REDIS_REPLY_ARRAY && row->element[1]->elements > 1) {
              if (row->element[1]->element[0]->type == REDIS_REPLY_STRING) {
                strncpy(stream_field, row->element[1]->element[0]->str, sizeof(stream_field) - 1);
              }
              if (row->element[1]->element[1]->type == REDIS_REPLY_STRING) {
                strncpy(stream_value, row->element[1]->element[1]->str, sizeof(stream_value) - 1);
              }
            }
          }
        }
      }
}

void empty_callback(redisAsyncContext *context, void *_reply, void *_privdata) {
  unused(context);
  unused(_reply);
  unused(_privdata);
}

static void redis_object_cmd_stream(void **start) {
  unused(start);

  char current_time_str[32] = {0};
  unused(current_time_str);
  char channel[32] = {0};

  int counter = 0;
  sprintf(channel, "%d%d%d", rebrick_util_rand(), rebrick_util_rand(), rebrick_util_rand());
  rebrick_log_debug("channel name is %s\n", channel);
  ferrum_redis_t *redisstream = NULL;
  int32_t result = ferrum_redis_new_stream(&redisstream, "localhost", 6379, NULL, 1000, 1000, 10, 1000, debug_stream, NULL, channel);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);

  ferrum_redis_t *redis;
  result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1200);
  ferrum_redis_cmd_t *cmd;
  loop(counter, 100, TRUE);
  result = ferrum_redis_cmd_new(&cmd, 1, 2, empty_callback, redis);
  assert_int_equal(result, FERRUM_SUCCESS);
  stream_item_count = 0;
  result = ferrum_redis_send(redis, cmd, "xadd %s 0-1 id hamza", channel);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, !stream_item_count);
  assert_string_equal(stream_id, "0-1");
  assert_string_equal(stream_field, "id");
  assert_string_equal(stream_value, "hamza");
  loop(counter, 1000, TRUE);

  stream_item_count = 0;
  result = ferrum_redis_send(redis, cmd, "xadd %s 0-2 id2 hamza2", channel);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, !stream_item_count);
  assert_string_equal(stream_id, "0-2");
  assert_string_equal(stream_field, "id2");
  assert_string_equal(stream_value, "hamza2");

  ferrum_redis_destroy(redisstream);

  loop(counter, 10000, TRUE);
  ferrum_redis_destroy(redis);
  loop(counter, 1000, TRUE);
  ferrum_redis_cmd_destroy(cmd);
  loop(counter, 1000, TRUE);
}

int test_ferrum_redis(void) {
  unused(redis_object_create_destroy_redis_down_and_up);
  const struct CMUnitTest tests[] = {
      /*       cmocka_unit_test(redis_object_create_destroy_success),
            cmocka_unit_test(redis_object_create_destroy_success_not_connected),
            cmocka_unit_test(redis_object_create_destroy_success_cmd_type),
            cmocka_unit_test(redis_object_create_destroy_success_set_get), */
      // cmocka_unit_test(redis_object_create_destroy_redis_down_and_up),
      /*   cmocka_unit_test(redis_object_create_destroy_success_execute_get_set),
        cmocka_unit_test(redis_object_cmd_sub), */
      cmocka_unit_test(redis_object_cmd_stream),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
