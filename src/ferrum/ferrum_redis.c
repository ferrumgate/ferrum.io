#include "ferrum_redis.h"

/* void debugCallback(redisAsyncContext *c, void *r, void *privdata) {
  (void)privdata; // unused
  redisReply *reply = r;
  if (reply == NULL) {
    // The DEBUG SLEEP command will almost always fail, because we have set a 1 second timeout
    printf("`DEBUG SLEEP` error: %s\n", c->errstr ? c->errstr : "unknown error");
    return;
  }
  // Disconnect after receiving the reply of DEBUG SLEEP (which will not)
  redisAsyncDisconnect(c);
} */

/* void getCallback(redisAsyncContext *c, void *r, void *privdata) {
  char current_time_str[32] = {0};
  redisReply *reply = r;
  if (reply == NULL) {
    printf("`GET key` error: %s\n", c->errstr ? c->errstr : "unknown error");
    return;
  }
  printf("`GET key` result: argv[%s]: %s\n", (char *)privdata, reply->str);

  // start another request that demonstrate timeout
  redisAsyncCommand(c, debugCallback, NULL, "DEBUG SLEEP %f", 1.5);
} */
void connectCallback(const redisAsyncContext *c, int status);
void disconnectCallback(const redisAsyncContext *c, int status);

static redisAsyncContext *createContext(const char *host, int32_t port, int32_t timeout_ms) {

  redisAsyncContext *rcontext = redisAsyncConnect(host, port);
  if (rcontext->err) {
    ferrum_log_error("redis context failed %s\n", rcontext->errstr);
    redisAsyncFree(rcontext);
    return NULL;
  }

  redisLibuvAttach(rcontext, uv_default_loop());
  redisAsyncSetConnectCallback(rcontext, connectCallback);
  redisAsyncSetDisconnectCallback(rcontext, disconnectCallback);
  int32_t second = timeout_ms / 1000;
  int32_t microsecond = timeout_ms - (second * 1000);
  redisAsyncSetTimeout(rcontext, (struct timeval){.tv_sec = second, .tv_usec = microsecond});
  return rcontext;
}

static int32_t reconnect(ferrum_redis_t *redis) {

  ferrum_log_debug("reconnecting redis %s:%d\n", redis->host, redis->port);

  redisAsyncContext *rcontext = createContext(redis->host, redis->port, redis->query_timeout_ms);
  if (!rcontext) {
    return FERRUM_ERR_REDIS;
  }
  redis->rcontext = rcontext;
  rcontext->data = redis;
  return FERRUM_SUCCESS;
}
static void stream_callback(redisAsyncContext *context, void *_reply, void *_privdata) {

  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  if (redis->stream.cmd.callback.func) {
    redis->stream.cmd.callback.func(context, _reply, _privdata);
    if (redis->is_destroying) {
      return;
    }
    int32_t result = ferrum_redis_send(redis, &redis->stream.cmd_internal,
                                       "xread count %d block %d streams %s %s",
                                       redis->stream.count, redis->stream.timeout, redis->stream.channel, redis->stream.pos);
    if (result) {
      ferrum_log_fatal("redis stream failed %s\n", context->c.errstr);
      redis->stream.isConnected = FALSE;
    }
  }
}

static void start_subscribe_or_read_stream(const redisAsyncContext *c, ferrum_redis_t *redis) {
  if (redis->subscribe.isActived) {
    int32_t result = ferrum_redis_send(redis, &redis->subscribe.cmd,
                                       "subscribe %s",
                                       redis->subscribe.channel);
    if (result) {
      ferrum_log_fatal("redis subscribe failed %s\n", c->errstr);
    } else
      redis->subscribe.isConnected = TRUE;
  }
  if (redis->stream.isActived) {

    int32_t result = ferrum_redis_send(redis, &redis->stream.cmd_internal,
                                       "xread count %d block %d streams %s %s",
                                       redis->stream.count, redis->stream.timeout,
                                       redis->stream.channel, redis->stream.pos);
    if (result) {
      ferrum_log_fatal("redis stream failed %s\n", c->errstr);
    } else
      redis->stream.isConnected = TRUE;
  }
}

static void authenticate_callback(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *); // we dont need to delete
  unused(cmd);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);

  if (reply == NULL) { // timeout
    rebrick_log_fatal("redis authenticate timedout\n");
    return;
  }
  if (reply->type == REDIS_REPLY_ERROR) {
    rebrick_log_fatal("redis authenticate failed\n");
    return;
  }
  rebrick_log_info("redis authenticated successfully\n");
  redis->auth.is_authenticated = TRUE;
  start_subscribe_or_read_stream(context, redis);
}

void connectCallback(const redisAsyncContext *c, int status) {

  ferrum_redis_t *redis = cast(c->data, ferrum_redis_t *);
  if (status != REDIS_OK) {
    ferrum_log_error("redis connect error: %s %s:%d\n", c->errstr, redis->host, redis->port);
    rebrick_timer_start(redis->connection_checker);
    return;
  }
  ferrum_log_info("redis connected to %s:%d\n", redis->host, redis->port);
  redis->is_connected = TRUE;

  if (redis->pass[0]) {
    redis->auth.cmd.callback.func = authenticate_callback;
    redis->auth.cmd.callback.arg1 = redis;
    redis->auth.is_required = TRUE;
    int32_t result = ferrum_redis_send(redis, &redis->auth.cmd, "auth %s", redis->pass);
    if (result) {
      ferrum_log_fatal("redis authenticate cmd failed %s\n", c->errstr);
    }
  } else {
    start_subscribe_or_read_stream(c, redis);
  }

  ferrum_log_debug("redis connected\n");
}

void disconnectCallback(const redisAsyncContext *c, int status) {
  ferrum_log_debug("redis disconnect callback status %d\n", status);
  if (status != REDIS_OK) {
    ferrum_log_error("redis disconnect because of error: %s\n", c->errstr);
    //  return;
  }
  ferrum_redis_t *redis = cast(c->data, ferrum_redis_t *);
  redis->is_connected = FALSE;

  if (status == REDIS_OK) {
    ferrum_redis_destroy(redis);
    ferrum_log_debug("redis disconnected by user\n");
  } else {
    rebrick_timer_start(redis->connection_checker);
  }
}
int32_t connection_check(void *data) {

  ferrum_redis_t *redis = cast(data, ferrum_redis_t *);
  ferrum_log_info("trying to connect redis %s:%d\n", redis->host, redis->port);
  if (redis->is_connected)
    return FERRUM_SUCCESS;
  if (!reconnect(redis)) // if reconnect is success
    rebrick_timer_stop(redis->connection_checker);
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_new(ferrum_redis_t **redis, const char *host, int32_t port, const char *pass, int32_t check_elapsed_ms, int32_t query_timeout_ms) {

  ferrum_redis_t *tmp = new1(ferrum_redis_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_redis_t);
  string_copy(tmp->host, host, REBRICK_HOST_STR_LEN - 1);
  tmp->port = port;
  if (pass && pass[0])
    string_copy(tmp->pass, pass, REBRICK_PASS_STR_LEN - 1);

  redisAsyncContext *rcontext = createContext(host, port, query_timeout_ms);
  if (!rcontext) {
    rebrick_free(tmp);
    return FERRUM_ERR_REDIS;
  }

  tmp->rcontext = rcontext;
  rcontext->data = tmp;
  tmp->connection_checker_elapsed_ms = check_elapsed_ms;
  rebrick_timer_new(&tmp->connection_checker, connection_check, tmp, tmp->connection_checker_elapsed_ms, 0);
  tmp->query_timeout_ms = query_timeout_ms;
  *redis = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_new_sub(ferrum_redis_t **redis, const char *host,
                             int32_t port, const char *pass, int32_t check_elapsed_ms, int32_t query_timeout_ms,
                             ferrum_redis_callback_t *callback, void *callbackdata, const char *channel) {
  int32_t result = ferrum_redis_new(redis, host, port, pass, check_elapsed_ms, query_timeout_ms);
  if (result)
    return result;
  ferrum_redis_t *tmp = *redis;
  tmp->subscribe.cmd.callback.func = callback;
  tmp->subscribe.cmd.callback.arg1 = callbackdata ? callbackdata : tmp;
  tmp->subscribe.cmd.id = 1;
  tmp->subscribe.cmd.type = 1;
  string_copy(tmp->subscribe.channel, channel, FERRUM_REDIS_CHANNEL_NAME_LEN - 1);
  tmp->subscribe.isActived = TRUE;
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_new_stream(ferrum_redis_t **redis, const char *host,
                                int32_t port, const char *pass, int32_t check_elapsed_ms, int32_t query_timeout_ms,
                                int32_t stream_count, int32_t stream_timeout, ferrum_redis_callback_t *callback, void *callbackdata,
                                const char *channel) {
  int32_t result = ferrum_redis_new(redis, host, port, pass, check_elapsed_ms, query_timeout_ms);
  if (result)
    return result;
  ferrum_redis_t *tmp = *redis;
  tmp->stream.cmd.callback.func = callback;
  tmp->stream.cmd.callback.arg1 = callbackdata ? callbackdata : tmp;
  tmp->stream.cmd.id = 1;
  tmp->stream.cmd.type = 1;
  tmp->stream.count = stream_count;
  tmp->stream.timeout = stream_timeout;
  tmp->stream.cmd_internal.callback.func = stream_callback;
  tmp->stream.cmd_internal.callback.arg1 = callbackdata ? callbackdata : tmp;
  tmp->stream.cmd_internal.id = 1;
  tmp->stream.cmd_internal.type = 1;
  string_copy(tmp->stream.channel, channel, FERRUM_REDIS_CHANNEL_NAME_LEN - 1);
  string_copy(tmp->stream.pos, "0", sizeof(tmp->stream.pos) - 1);
  tmp->stream.isActived = TRUE;
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_destroy(ferrum_redis_t *redis) {

  if (redis) {
    redis->is_destroying = TRUE;
    if (redis->connection_checker) {
      rebrick_timer_destroy(redis->connection_checker);
      redis->connection_checker = NULL;
    }

    if (redis->is_connected) {
      ferrum_log_debug("destroying redis connection context\n");
      redisAsyncDisconnect(redis->rcontext);
      return FERRUM_SUCCESS;
    }
    rebrick_free(redis);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_send(ferrum_redis_t *redis, ferrum_redis_cmd_t *command, const char *fmt, ...) {
  if (redis->is_mock_error) {
    return FERRUM_ERR_REDIS;
  }
  ferrum_log_debug("sending command\n");
  if (!redis->is_connected) {

    ferrum_log_error("redis is not connected\n");
    return FERRUM_ERR_REDIS;
  }
  va_list args;
  va_start(args, fmt);
  int32_t result = redisvAsyncCommand(redis->rcontext, command->callback.func, command, fmt, args);
  va_end(args);
  if (result) {
    ferrum_log_error("redis sending cmd error %d\n", result);
    return FERRUM_ERR_REDIS;
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_cmd_new(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type, ferrum_redis_callback_t *callback, void *callback_data) {

  ferrum_redis_cmd_t *tmp = new1(ferrum_redis_cmd_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_redis_cmd_t);
  tmp->id = id;
  tmp->type = type;
  tmp->callback.func = callback;

  tmp->callback.arg1 = callback_data;
  *cmd = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_cmd_new2(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type, ferrum_redis_callback_t *callback, void *callback_data1, void *callback_data2) {

  ferrum_redis_cmd_t *tmp;
  int32_t result = ferrum_redis_cmd_new(&tmp, id, type, callback, callback_data1);
  if (result) {
    ferrum_log_error("redis cmd create new2 failed with error: %d\n", result);
    return result;
  }
  tmp->callback.arg2 = callback_data2;
  *cmd = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_redis_cmd_new3(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type,
                              ferrum_redis_callback_t *callback, void *callback_data1, void *callback_data2, void *callback_data3) {

  ferrum_redis_cmd_t *tmp;
  int32_t result = ferrum_redis_cmd_new2(&tmp, id, type, callback, callback_data1,
                                         callback_data2);
  if (result) {
    ferrum_log_error("redis cmd create new3 failed with error: %d\n", result);
    return result;
  }
  tmp->callback.arg3 = callback_data3;
  *cmd = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_redis_cmd_new4(ferrum_redis_cmd_t **cmd, int64_t id, int32_t type,
                              ferrum_redis_callback_t *callback, void *callback_data1, void *callback_data2,
                              void *callback_data3, void *callback_data4) {

  ferrum_redis_cmd_t *tmp;
  int32_t result = ferrum_redis_cmd_new3(&tmp, id, type, callback, callback_data1,
                                         callback_data2, callback_data3);
  if (result) {
    ferrum_log_error("redis cmd create new3 failed with error: %d\n", result);
    return result;
  }
  tmp->callback.arg4 = callback_data4;
  *cmd = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_redis_cmd_destroy(ferrum_redis_cmd_t *cmd) {
  if (cmd) {

    rebrick_free(cmd);
  }
  return FERRUM_SUCCESS;
}