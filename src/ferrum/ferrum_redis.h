#ifndef __FERRUM_REDIS_H__
#define __FERRUM_REDIS_H__

#include "ferrum.h"
#include "hiredis/hiredis.h"
#include "hiredis/async.h"
#include "hiredis/adapters/libuv.h"

/**
 * @brief summary redis send cmd and pub/sub implementation with hiredis
 *
 */

#define FERRUM_REDIS_CHANNEL_NAME_LEN 256
#define FERRUM_STREAM_POS 128

typedef redisCallbackFn ferrum_redis_callback_t;
typedef redisReply ferrum_redis_reply_t;

#define ferrum_redis_reply_free(a) freeReplyObject(a)

typedef struct ferrum_redis_cmd {
  base_object();
  int64_t id;
  int32_t type;

  private_ struct {
    ferrum_redis_callback_t *func;
    void *arg1;
    void *arg2;
    void *arg3;
    void *arg4;
  } callback;
} ferrum_redis_cmd_t;

typedef struct ferrum_redis {
  base_object();
  char host[REBRICK_HOST_STR_LEN];
  char pass[REBRICK_PASS_STR_LEN];
  int32_t port;
  int32_t is_connected;
  redisAsyncContext *rcontext;
  rebrick_timer_t *connection_checker;
  int32_t connection_checker_elapsed_ms;
  int32_t query_timeout_ms;
  private_ struct {
    int32_t is_required;
    int32_t is_authenticated;
    ferrum_redis_cmd_t cmd;
  } auth;
  private_ struct {
    char channel[FERRUM_REDIS_CHANNEL_NAME_LEN];
    ferrum_redis_cmd_t cmd;
    int32_t isActived;
    int32_t isConnected;
  } subscribe;
  private_ struct {
    char channel[FERRUM_REDIS_CHANNEL_NAME_LEN];
    ferrum_redis_cmd_t cmd;
    ferrum_redis_cmd_t cmd_internal;
    int32_t isActived;
    int32_t isConnected;
    int32_t count;
    int32_t timeout;
    char pos[FERRUM_STREAM_POS];
  } stream;
  int32_t is_destroying;
  int32_t is_mock_error;
} ferrum_redis_t;

/**
 * @brief create a redis cmd
 */
int32_t ferrum_redis_cmd_new(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type,
                             ferrum_redis_callback_t *callback, void *callback_data1);
/*
 * @brief create a redis cmd
 */
int32_t ferrum_redis_cmd_new2(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type,
                              ferrum_redis_callback_t *callback, void *callback_data1,
                              void *callback_data2);

int32_t ferrum_redis_cmd_new3(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type,
                              ferrum_redis_callback_t *callback, void *callback_data1,
                              void *callback_data2, void *callback_data3);
int32_t ferrum_redis_cmd_new4(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type,
                              ferrum_redis_callback_t *callback, void *callback_data1,
                              void *callback_data2, void *callback_data3,
                              void *callback_data4);

/**
 * @brief destroy cmd object
 */
int32_t ferrum_redis_cmd_destroy(ferrum_redis_cmd_t *cmd);

/**
 * @brief connect to a redis
 * @param connection_check_ms check if connection is active in milisecond
 */
int32_t ferrum_redis_new(ferrum_redis_t **redis, const char *host, int32_t port, const char *pass, int32_t connection_check_ms, int32_t query_timeout_ms);
int32_t ferrum_redis_send(ferrum_redis_t *redis, ferrum_redis_cmd_t *command, const char *fmt, ...);
int32_t ferrum_redis_new_sub(ferrum_redis_t **redis, const char *host, int32_t port, const char *pass, int32_t connection_check_ms, int32_t query_timeout_ms,
                             ferrum_redis_callback_t *callback, void *callback_data, const char *channel);
int32_t ferrum_redis_new_stream(ferrum_redis_t **redis, const char *host, int32_t port, const char *pass, int32_t connection_check_ms, int32_t query_timeout_ms,
                                int32_t stream_count, int32_t stream_timeout, ferrum_redis_callback_t *callback, void *callback_data, const char *channel);
int32_t ferrum_redis_destroy(ferrum_redis_t *redis);

#endif