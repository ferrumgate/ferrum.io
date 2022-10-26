#include "ferrum_config.h"

int32_t ferrum_config_new(ferrum_config_t **config) {
  ferrum_config_t *tmp = new1(ferrum_config_t);
  constructor(tmp, ferrum_config_t);

  rebrick_util_gethostname(tmp->hostname);
  ferrum_log_warn(__FILE__, __LINE__, "hostname is %s\n", tmp->hostname);

  /////////////////////// fill redis server   ///////////////////

  char redis_host[REBRICK_MAX_ENV_LEN] = {0};
  size_t redis_host_size = sizeof(redis_host);
  uv_os_getenv("REDIS_HOST", redis_host, &redis_host_size);

  if (redis_host[0]) {
    rebrick_log_warn(__FILE__, __LINE__, "environment variable REDIS_HOST %s\n", redis_host);
    strncpy(tmp->redis.host, redis_host, REBRICK_HOST_STR_LEN);
  } else
    strncpy(tmp->redis.host, "localhost", REBRICK_HOST_STR_LEN);

  int32_t result = rebrick_util_resolve_sync(tmp->redis.host, &tmp->redis.addr, 6379);
  if (result) {
    rebrick_log_fatal(__FILE__, __LINE__, "%s resolution failed with error:%d\n", tmp->redis.host, result);
    rebrick_kill_current_process(result);
  }
  rebrick_util_addr_to_ip_string(&tmp->redis.addr, tmp->redis.ip);
  char rport[REBRICK_PORT_STR_LEN] = {0};
  rebrick_util_addr_to_port_string(&tmp->redis.addr, rport);
  tmp->redis.port = atoi(rport);

  /////////////////////// listen raw   ///////////////////

  char raw_dest_host[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_dest_host_size = sizeof(raw_dest_host);
  uv_os_getenv("RAW_DESTINATION_HOST", raw_dest_host, &raw_dest_host_size);

  if (raw_dest_host[0]) {
    rebrick_log_warn(__FILE__, __LINE__, "environment variable RAW_DESTINATION_HOST %s\n", raw_dest_host);
    strncpy(tmp->raw.dest_host, raw_dest_host, REBRICK_HOST_STR_LEN);
  } else
    strncpy(tmp->raw.dest_host, "localhost", REBRICK_HOST_STR_LEN);

  char raw_dest_tcp_port[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_dest_tcp_port_size = sizeof(raw_dest_tcp_port);
  uv_os_getenv("RAW_DESTINATION_TCP_PORT", raw_dest_tcp_port, &raw_dest_tcp_port_size);

  char raw_dest_udp_port[REBRICK_MAX_ENV_LEN] = {0};
  size_t raw_dest_udp_port_size = sizeof(raw_dest_udp_port);
  uv_os_getenv("RAW_DESTINATION_UDP_PORT", raw_dest_udp_port, &raw_dest_udp_port_size);
  // resolve it if needs
  result = rebrick_util_resolve_sync(tmp->raw.dest_host, &tmp->raw.dest_tcp_addr, 1111);
  if (result) {
    rebrick_log_fatal(__FILE__, __LINE__, "%s resolution failed with error:%d\n", tmp->raw.dest_host, result);
    rebrick_kill_current_process(result);
  }

  rebrick_util_addr_to_ip_string(&tmp->raw.dest_tcp_addr, tmp->raw.dest_ip);
  if (raw_dest_tcp_port[0]) {
    tmp->raw.dest_tcp_port = atoi(raw_dest_tcp_port);
    rebrick_util_ip_port_to_addr(tmp->raw.dest_ip, raw_dest_tcp_port, &tmp->raw.dest_tcp_addr);
  }
  if (raw_dest_udp_port[0]) {
    tmp->raw.dest_udp_port = atoi(raw_dest_udp_port);
    rebrick_util_ip_port_to_addr(tmp->raw.dest_ip, raw_dest_udp_port, &tmp->raw.dest_udp_addr);
  }

  *config = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_config_destroy(ferrum_config_t *config) {
  if (config) {
    rebrick_free(config);
  }
  return FERRUM_SUCCESS;
}