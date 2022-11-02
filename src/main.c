#include "ferrum/ferrum.h"
#include "ferrum/ferrum_redis.h"
#include "ferrum/ferrum_config.h"
#include "ferrum/ferrum_raw.h"

// compiler unused function problem
static const void *nouse = redisLibuvAttach;

void close_cb(uv_handle_t *handle) {
  unused(handle);
  unused(nouse);
  uv_stop(uv_default_loop());
}

void signal_cb(uv_signal_t *handle, int signum) {

  unused(signum);
  uv_signal_stop(handle);
  /*  rebrick_listener_t *listener = cast(handle->data, rebrick_listener_t *);
   rebrick_crontab_destroy(crontab); */
  uv_sleep(100);

  ferrum_log_warn("ctrl+break detected, shutting down\n");
  uv_close(cast(handle, uv_handle_t *), close_cb);
}
static void set_log_level() {
  char log_level[REBRICK_MAX_ENV_LEN] = {0};
  size_t log_level_size = sizeof(log_level);
  uv_os_getenv("LOG_LEVEL", log_level, &log_level_size);
  log_level_t level = REBRICK_LOG_ERROR;
  if (!strcmp(log_level, "OFF"))
    level = REBRICK_LOG_OFF;
  if (!strcmp(log_level, "FATAL"))
    level = REBRICK_LOG_FATAL;
  if (!strcmp(log_level, "ERROR"))
    level = REBRICK_LOG_ERROR;
  if (!strcmp(log_level, "WARN"))
    level = REBRICK_LOG_WARN;
  if (!strcmp(log_level, "INFO"))
    level = REBRICK_LOG_INFO;
  if (!strcmp(log_level, "DEBUG"))
    level = REBRICK_LOG_DEBUG;
  if (!strcmp(log_level, "ALL"))
    level = REBRICK_LOG_ALL;
  // set log level
  rebrick_log_level(level);
}

int main() {
  set_log_level();
  ferrum_log_warn("current version: %s\n", FERRUM_VERSION);
  int32_t result;

  ferrum_config_t *config;
  result = ferrum_config_new(&config);
  if (result) {
    ferrum_log_fatal("config create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  if (result) {
    ferrum_log_fatal("policy create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  if (config->raw.dest_tcp_addr_str[0] || config->raw.dest_udp_addr_str[0]) {
    ferrum_raw_t *raw;
    result = ferrum_raw_new(&raw, config, policy, rebrick_conntrack_get);
    if (result) {
      ferrum_log_fatal("raw create failed:%d\n", result);
      rebrick_kill_current_process(result);
    }
  }

  // capture ctrl+c
  uv_signal_t ctrl_c;
  uv_signal_init(uv_default_loop(), &ctrl_c);
  // ctrl_c.data = listener;
  uv_signal_start(&ctrl_c, signal_cb, SIGINT);

  //////////////////////////////////
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  uv_loop_close(uv_default_loop());
  return 0;
}