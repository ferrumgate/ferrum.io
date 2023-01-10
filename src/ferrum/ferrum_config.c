#include "ferrum_config.h"

int32_t ferrum_config_new(ferrum_config_t **config) {
  ferrum_config_t *tmp = new1(ferrum_config_t);
  constructor(tmp, ferrum_config_t);

  rebrick_util_gethostname(tmp->hostname);
  ferrum_log_warn("hostname is %s\n", tmp->hostname);

  /////////////////////// service id   ///////////////////

  size_t service_id_size = sizeof(tmp->service_id);
  uv_os_getenv("SERVICE_ID", tmp->service_id, &service_id_size);

  /////////////////////// gateway id   ///////////////////

  size_t gateway_id_size = sizeof(tmp->gateway_id);
  uv_os_getenv("GATEWAY_ID", tmp->gateway_id, &gateway_id_size);

  /////////////////////// instance id   ///////////////////

  size_t instance_id_size = sizeof(tmp->instance_id);
  uv_os_getenv("INSTANCE_ID", tmp->instance_id, &instance_id_size);

  /////////////////////// fill redis global server   ///////////////////

  char redis_host[REBRICK_MAX_ENV_LEN] = {0};
  size_t redis_host_size = sizeof(redis_host);
  uv_os_getenv("REDIS_HOST", redis_host, &redis_host_size);

  if (!redis_host[0])
    strncpy(redis_host, "localhost", REBRICK_HOST_STR_LEN);

  int32_t result = rebrick_util_resolve_sync(redis_host, &tmp->redis.addr, 6379);
  if (result) {
    rebrick_log_fatal("%s resolution failed with error:%d\n", redis_host, result);
    rebrick_kill_current_process(result);
  }

  rebrick_util_addr_to_string(&tmp->redis.addr, tmp->redis.addr_str);
  rebrick_log_warn("redis host:port is %s\n", tmp->redis.addr_str);

  rebrick_util_addr_to_ip_string(&tmp->redis.addr, tmp->redis.ip);
  rebrick_util_addr_to_port_string(&tmp->redis.addr, tmp->redis.port);

  size_t redis_pass_size = sizeof(tmp->redis.pass);
  uv_os_getenv("REDIS_PASS", tmp->redis.pass, &redis_pass_size);

  /////////////////////// fill redis local server   ///////////////////

  char redis_local_host[REBRICK_MAX_ENV_LEN] = {0};
  size_t redis_local_host_size = sizeof(redis_local_host);
  uv_os_getenv("REDIS_HOST", redis_local_host, &redis_local_host_size);

  if (!redis_local_host[0])
    strncpy(redis_local_host, "localhost", REBRICK_HOST_STR_LEN);

  result = rebrick_util_resolve_sync(redis_local_host, &tmp->redis_local.addr, 6379);
  if (result) {
    rebrick_log_fatal("%s resolution failed with error:%d\n", redis_local_host, result);
    rebrick_kill_current_process(result);
  }

  rebrick_util_addr_to_string(&tmp->redis_local.addr, tmp->redis_local.addr_str);
  rebrick_log_warn("redis local host:port is %s\n", tmp->redis_local.addr_str);

  rebrick_util_addr_to_ip_string(&tmp->redis_local.addr, tmp->redis_local.ip);
  rebrick_util_addr_to_port_string(&tmp->redis_local.addr, tmp->redis_local.port);

  size_t redis_local_pass_size = sizeof(tmp->redis_local.pass);
  uv_os_getenv("REDIS_PASS", tmp->redis_local.pass, &redis_local_pass_size);

  /////////////////////// listen raw   ///////////////////
  char raw_dest_host[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_dest_host_size = sizeof(raw_dest_host);
  uv_os_getenv("RAW_DESTINATION_HOST", raw_dest_host, &raw_dest_host_size);

  if (!raw_dest_host[0])
    strncpy(raw_dest_host, "localhost", REBRICK_HOST_STR_LEN);

  char raw_dest_tcp_port[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_dest_tcp_port_size = sizeof(raw_dest_tcp_port);
  uv_os_getenv("RAW_DESTINATION_TCP_PORT", raw_dest_tcp_port, &raw_dest_tcp_port_size);

  char raw_dest_udp_port[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_dest_udp_port_size = sizeof(raw_dest_udp_port);
  uv_os_getenv("RAW_DESTINATION_UDP_PORT", raw_dest_udp_port, &raw_dest_udp_port_size);
  // resolve it if needs
  if (raw_dest_tcp_port[0]) {
    result = rebrick_util_resolve_sync(raw_dest_host, &tmp->raw.dest_tcp_addr, atoi(raw_dest_tcp_port));
    if (result) {
      rebrick_log_fatal("%s resolution failed with error:%d\n", raw_dest_host, result);
      rebrick_kill_current_process(result);
    }
    rebrick_util_addr_to_string(&tmp->raw.dest_tcp_addr, tmp->raw.dest_tcp_addr_str);
    rebrick_log_warn("raw destination tcp addr: %s\n", tmp->raw.dest_tcp_addr_str);
  }

  if (raw_dest_udp_port[0]) {
    result = rebrick_util_resolve_sync(raw_dest_host, &tmp->raw.dest_udp_addr, atoi(raw_dest_udp_port));
    if (result) {
      rebrick_log_fatal("%s resolution failed with error:%d\n", raw_dest_host, result);
      rebrick_kill_current_process(result);
    }
    rebrick_util_addr_to_string(&tmp->raw.dest_udp_addr, tmp->raw.dest_udp_addr_str);
    rebrick_log_warn("raw destination udp addr: %s\n", tmp->raw.dest_udp_addr_str);
  }

  ///
  char raw_listen_ip[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_listen_ip_size = sizeof(raw_listen_ip);
  uv_os_getenv("RAW_LISTEN_IP", raw_listen_ip, &raw_listen_ip_size);

  if (raw_dest_tcp_port[0]) {
    char raw_listen_tcp_port[REBRICK_MAX_ENV_LEN] = {0};
    size_t raw_listen_tcp_port_size = sizeof(raw_listen_tcp_port);
    uv_os_getenv("RAW_LISTEN_TCP_PORT", raw_listen_tcp_port, &raw_listen_tcp_port_size);
    rebrick_util_ip_port_to_addr(raw_listen_ip[0] ? raw_listen_ip : "0.0.0.0", raw_listen_tcp_port[0] ? raw_listen_tcp_port : raw_dest_tcp_port, &tmp->raw.listen_tcp_addr);
    rebrick_util_addr_to_string(&tmp->raw.listen_tcp_addr, tmp->raw.listen_tcp_addr_str);
    rebrick_log_warn("raw listen tcp addr: %s\n", tmp->raw.listen_tcp_addr_str);
  }

  if (raw_dest_udp_port[0]) {
    char raw_listen_udp_port[REBRICK_MAX_ENV_LEN] = {0};
    size_t raw_listen_udp_port_size = sizeof(raw_listen_udp_port);
    uv_os_getenv("RAW_LISTEN_UDP_PORT", raw_listen_udp_port, &raw_listen_udp_port_size);
    rebrick_util_ip_port_to_addr(raw_listen_ip[0] ? raw_listen_ip : "0.0.0.0", raw_listen_udp_port[0] ? raw_listen_udp_port : raw_dest_udp_port, &tmp->raw.listen_udp_addr);
    rebrick_util_addr_to_string(&tmp->raw.listen_udp_addr, tmp->raw.listen_udp_addr_str);
    rebrick_log_warn("raw listen udp addr: %s\n", tmp->raw.listen_udp_addr_str);
  }

  /////////////////////// policy disabled ///////////////////
  char disable_policy[REBRICK_MAX_ENV_LEN] = {0};
  size_t disable_policy_size = sizeof(disable_policy);
  uv_os_getenv("DISABLE_POLICY", disable_policy, &disable_policy_size);
  if (!(strcmp(disable_policy, "true") || !strcmp(disable_policy, "TRUE")))
    tmp->is_policy_disabled = TRUE;

  /////////////////////// lmdb folder ///////////////////
  strncpy(tmp->lmdb_folder, "/var/lib/ferrumgate", sizeof(tmp->lmdb_folder));
  char lmdb_folder[REBRICK_MAX_ENV_LEN] = {0};
  size_t lmdb_folder_size = sizeof(lmdb_folder);
  uv_os_getenv("LMDB_FOLDER", lmdb_folder, &lmdb_folder_size);
  if (lmdb_folder[0])
    strncpy(tmp->lmdb_folder, lmdb_folder, sizeof(tmp->lmdb_folder) - 1);

  /////////////////////// syslog host port ///////////////////
  strncpy(tmp->syslog_host, "localhost:9191", sizeof(tmp->syslog_host));
  char syslog_host[REBRICK_MAX_ENV_LEN] = {0};
  size_t syslog_host_size = sizeof(syslog_host);
  uv_os_getenv("SYSLOG_HOST", syslog_host, &syslog_host_size);
  if (syslog_host[0])
    strncpy(tmp->syslog_host, syslog_host, sizeof(tmp->syslog_host) - 1);

  rebrick_log_warn("syslog host:port is %s\n", tmp->syslog_host);

  *config = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_config_destroy(ferrum_config_t *config) {
  if (config) {
    rebrick_free(config);
  }
  return FERRUM_SUCCESS;
}