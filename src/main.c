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
  ferrum_dns_db_t *dns_db;
  ferrum_redis_t *redis_intel;
  ferrum_track_db_t *track_db;
  ferrum_authz_db_t *authz_db;
  ferrum_raw_t *raw;
  ferrum_cache_t *cache;
  ferrum_udpsocket_pool_t *udpsocket_pool;
  // uv_signal_t sigpipe;
} holder_t;

void close_cb(uv_handle_t *handle) {
  unused(handle);
  unused(nouse);
  uv_stop(uv_default_loop());
}

void signal_ignore_cb(uv_signal_t *handle, int signum) {
  unused(handle);
  unused(signum);
  // uv_signal_stop(handle);
  // uv_close(cast(handle, uv_handle_t *), NULL);
}

void signal_cb(uv_signal_t *handle, int signum) {

  unused(signum);
  uv_signal_stop(handle);

  ferrum_log_warn("ctrl+break detected, shutting down\n");
  holder_t *holder = cast(handle->data, holder_t *);
  if (holder->raw) {
    ferrum_log_debug("destroying ferrum raw\n");
    ferrum_raw_destroy(holder->raw);
  }
  if (holder->policy) {
    ferrum_log_debug("destroying ferrum policy\n");
    ferrum_policy_destroy(holder->policy);
  }
  if (holder->dns_db) {
    ferrum_log_debug("destroying ferrum dns db\n");
    ferrum_dns_db_destroy(holder->dns_db);
  }
  if (holder->redis_intel) {
    ferrum_log_debug("destroying ferrum redis intel\n");
    ferrum_redis_destroy(holder->redis_intel);
  }
  if (holder->track_db) {
    ferrum_log_debug("destroying ferrum track db\n");
    ferrum_track_db_destroy(holder->track_db);
  }
  if (holder->authz_db) {
    ferrum_log_debug("destroying ferrum authz db\n");
    ferrum_authz_db_destroy(holder->authz_db);
  }
  if (holder->syslog) {
    ferrum_log_debug("destroying ferrum syslog\n");
    ferrum_syslog_destroy(holder->syslog);
  }
  if (holder->cache) {
    ferrum_log_debug("destroying ferrum syslog\n");
    ferrum_cache_destroy(holder->cache);
  }

  if (holder->config) {
    ferrum_log_debug("destroying ferrum config\n");
    ferrum_config_destroy(holder->config);
  }
  if (holder->udpsocket_pool) {
    ferrum_log_debug("destroying udp socket pool\n");
    ferrum_udpsocket_pool_destroy(holder->udpsocket_pool);
  }

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

  ferrum_redis_t *redis_intel;
  result = ferrum_redis_new(&redis_intel, config->redis_intel.ip, config->redis_intel.port_int, config->redis_intel.pass, 5000, 300);
  if (result) {
    ferrum_log_fatal("redis intel create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  ferrum_dns_db_t *dns_db;
  result = ferrum_dns_db_new(&dns_db, config);
  if (result) {
    ferrum_log_fatal("dns db create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  if (result) {
    ferrum_log_fatal("syslog create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  ferrum_track_db_t *track_db;
  result = ferrum_track_db_new(&track_db, config);
  if (result) {
    ferrum_log_fatal("track db create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  ferrum_authz_db_t *authz_db;
  result = ferrum_authz_db_new(&authz_db, config);
  if (result) {
    ferrum_log_fatal("authz create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }
  ferrum_log_info("service protocol type %s\n", config->protocol_type);

  ferrum_cache_t *cache;
  if (!strcmp(config->protocol_type, "dns")) {
    result = ferrum_cache_new(&cache, 5000); // start dns cache
  } else {
    result = ferrum_cache_new(&cache, 0);
  }
  if (result) {
    ferrum_log_fatal("cache create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  ferrum_udpsocket_pool_t *udpsocket_pool;
  if (!strcmp(config->protocol_type, "dns")) {
    result = ferrum_udpsocket_pool_new(&udpsocket_pool, 16); // start socket pool for dns
  }
  if (result) {
    ferrum_log_fatal("dns socket pool failed create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }

  holder_t holder = {
      .config = config,
      .policy = policy,
      .syslog = syslog,
      .dns_db = dns_db,
      .redis_intel = redis_intel,
      .authz_db = authz_db,
      .track_db = track_db,
      .cache = cache,
      .udpsocket_pool = udpsocket_pool

  };

  if (config->raw.dest_tcp_addr_str[0] || config->raw.dest_udp_addr_str[0]) {
    ferrum_raw_t *raw = NULL;
    result = ferrum_raw_new(&raw, config, policy, syslog, redis_intel, dns_db, track_db, authz_db, cache, udpsocket_pool, rebrick_conntrack_get);
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
  // so important for reset connections
  // capture SIGPIPE
  signal(SIGPIPE, SIG_IGN);
  // uv_signal_t sigpipe;
  // uv_signal_init(uv_default_loop(), &sigpipe);
  // uv_signal_start(&sigpipe, signal_ignore_cb, SIGPIPE);
  //////////////////////////////////
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  for (int32_t wait = 0; wait < 5000; ++wait)
    uv_run(uv_default_loop(), UV_RUN_ONCE);

  uv_loop_close(uv_default_loop());
  return 0;
};