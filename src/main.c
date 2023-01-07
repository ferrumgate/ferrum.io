#include "ferrum/ferrum.h"
#include "ferrum/ferrum_redis.h"
#include "ferrum/ferrum_config.h"
#include "ferrum/ferrum_raw.h"

// compiler unused function problem
static const void *nouse = redisLibuvAttach;

typedef struct holder {
  ferrum_config_t *config;
  ferrum_policy_t *policy;
  ferrum_syslog_t *syslog;
  ferrum_raw_t *raw;
} holder_t;

void close_cb(uv_handle_t *handle) {
  unused(handle);
  unused(nouse);
  uv_stop(uv_default_loop());
}

void signal_cb(uv_signal_t *handle, int signum) {

  unused(signum);
  uv_signal_stop(handle);

  uv_sleep(100);

  ferrum_log_warn("ctrl+break detected, shutting down\n");
  holder_t *holder = cast(handle->data, holder_t *);
  if (holder->raw)
    ferrum_raw_destroy(holder->raw);
  if (holder->policy)
    ferrum_policy_destroy(holder->policy);
  if (holder->syslog)
    ferrum_syslog_destroy(holder->syslog);
  if (holder->config)
    ferrum_config_destroy(holder->config);
  uv_close(cast(handle, uv_handle_t *), close_cb);
}
static void set_log_level() {
  char log_level[REBRICK_MAX_ENV_LEN] = {0};
  size_t log_level_size = sizeof(log_level);
  uv_os_getenv("LOG_LEVEL", log_level, &log_level_size);
  log_level_t level = REBRICK_LOG_ERROR;
  if (!strcmp(log_level, "off"))
    level = REBRICK_LOG_OFF;
  if (!strcmp(log_level, "fatal"))
    level = REBRICK_LOG_FATAL;
  if (!strcmp(log_level, "error"))
    level = REBRICK_LOG_ERROR;
  if (!strcmp(log_level, "warn"))
    level = REBRICK_LOG_WARN;
  if (!strcmp(log_level, "info"))
    level = REBRICK_LOG_INFO;
  if (!strcmp(log_level, "debug"))
    level = REBRICK_LOG_DEBUG;
  if (!strcmp(log_level, "all"))
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

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  if (result) {
    ferrum_log_fatal("syslog create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }
  holder_t holder = {
      .config = config,
      .policy = policy,
      .syslog = syslog,

  };

  if (config->raw.dest_tcp_addr_str[0] || config->raw.dest_udp_addr_str[0]) {
    ferrum_raw_t *raw = NULL;
    result = ferrum_raw_new(&raw, config, policy, syslog, rebrick_conntrack_get);
    if (result) {
      ferrum_log_fatal("raw create failed:%d\n", result);
      rebrick_kill_current_process(result);
    }
    holder.raw = raw;
  }

  // capture ctrl+c
  uv_signal_t ctrl_c;
  uv_signal_init(uv_default_loop(), &ctrl_c);
  ctrl_c.data = &holder;
  uv_signal_start(&ctrl_c, signal_cb, SIGINT);

  //////////////////////////////////
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  uv_loop_close(uv_default_loop());
  return 0;
};