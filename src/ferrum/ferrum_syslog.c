#include "ferrum_syslog.h"

static void on_resolve(const char *domain, int32_t type, rebrick_sockaddr_t addr, void *data) {

  char ip[REBRICK_IP_STR_LEN];
  rebrick_util_addr_to_ip_string(&addr, ip);
  ferrum_log_info("resolve %s type:%d to %s\n", domain, type, ip);
  ferrum_syslog_t *syslog = cast(data, ferrum_syslog_t *);
  memcpy(&syslog->dest_addr, &addr, sizeof(addr));
  if (syslog->dest_addr.base.sa_family == AF_INET)
    syslog->dest_addr.v4.sin_port = htons(syslog->dest_port);
  else
    syslog->dest_addr.v6.sin6_port = htons(syslog->dest_port);
}

static void on_error(const char *domain, int32_t type, int32_t error, void *data) {
  unused(data);
  ferrum_log_error("resolve domain %s with type %d failed with error %d \n", domain, type, error);
}

static int32_t resolve_log_host(void *callback) {
  unused(callback);
  ferrum_syslog_t *syslog = cast(callback, ferrum_syslog_t *);
  ferrum_log_info("resolving host %s again\n", syslog->dest_host);
  rebrick_resolve(syslog->dest_host, A, on_resolve, on_error, syslog);
  return FERRUM_SUCCESS;
}

int32_t ferrum_syslog_new(ferrum_syslog_t **syslog, ferrum_config_t *config) {
  int32_t result;

  ferrum_syslog_t *tmp = new1(ferrum_syslog_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_syslog_t);
  tmp->config = config;
  tmp->dest_port = 9191; // default

  char conf_syslog[REBRICK_IP_PORT_STR_LEN];
  strncpy(conf_syslog, config->syslog_host, sizeof(conf_syslog));
  char *conf_tmp = strtok(conf_syslog, ":");
  int32_t counter = 0;
  while (conf_tmp) {
    switch (counter) {
    case 0:
      strncpy(tmp->dest_host, conf_tmp, sizeof(tmp->dest_host));
      break;
    case 1:
      result = rebrick_util_to_int16_t(conf_tmp, &tmp->dest_port);
      if (result) {
        ferrum_log_error("port number is not valid %s\n", conf_tmp);
      }
      break;
    }
    counter++;
    conf_tmp = strtok(NULL, ":");
  }
  // safety
  rebrick_util_ip_port_to_addr("127.0.0.1", "9292", &tmp->dest_addr);

  result = rebrick_timer_new(&tmp->resolve_timer, resolve_log_host, tmp, 60000, FALSE);
  if (result) {
    ferrum_log_fatal("create timer failed with error:%d problem\n", result);
    rebrick_free(tmp);
    return result;
  }
  rebrick_sockaddr_t bind_addr;
  fill_zero(&bind_addr, sizeof(rebrick_sockaddr_t));
  rebrick_util_ip_port_to_addr("0.0.0.0", "0", &bind_addr);
  new2(rebrick_udpsocket_callbacks_t, callback);
  callback.callback_data = tmp;

  result = rebrick_udpsocket_new(&tmp->socket, &bind_addr, &callback);
  if (result) {
    ferrum_log_fatal("create timer failed with error:%d problem\n", result);
    rebrick_timer_destroy(tmp->resolve_timer);
    rebrick_free(tmp);
    return result;
  }

  rebrick_timer_start_after(tmp->resolve_timer, 1000);
  *syslog = tmp;

  return FERRUM_SUCCESS;
}

int32_t ferrum_syslog_destroy(ferrum_syslog_t *syslog) {
  if (syslog) {

    if (syslog->resolve_timer)
      rebrick_timer_destroy(syslog->resolve_timer);
    if (syslog->socket)
      rebrick_udpsocket_destroy(syslog->socket);
    rebrick_free(syslog);
  }
  return FERRUM_SUCCESS;
}
static void free_memory(void *data) {
  if (data)
    rebrick_free(data);
}

int32_t ferrum_syslog_write(const ferrum_syslog_t *syslog, uint8_t *buffer, size_t len) {

  uint8_t *data = rebrick_malloc(len);
  if (!data) {
    rebrick_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  fill_zero(data, len);
  memcpy(data, buffer, len);

  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = data;

  return rebrick_udpsocket_write(syslog->socket, &syslog->dest_addr, data, len, clean_func);
}
