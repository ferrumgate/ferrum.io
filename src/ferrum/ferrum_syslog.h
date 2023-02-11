#ifndef __FERRUM_SYSLOG_H__
#define __FERRUM_SYSLOG_H__

#include "ferrum.h"
#include "ferrum_config.h"

typedef struct ferrum_syslog {
  base_object();
  ferrum_config_t *config;
  rebrick_timer_t *resolve_timer;
  rebrick_sockaddr_t dest_addr;
  int16_t dest_port;
  char dest_host[REBRICK_HOST_STR_LEN];
  rebrick_udpsocket_t *socket;

} ferrum_syslog_t;

int32_t ferrum_syslog_new(ferrum_syslog_t **syslog, ferrum_config_t *config);
int32_t ferrum_syslog_write(const ferrum_syslog_t *syslog, uint8_t *buffer, size_t len);
int32_t ferrum_syslog_destroy(ferrum_syslog_t *syslog);

#endif