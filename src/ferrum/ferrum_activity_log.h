#ifndef __FERRUM_ACTIVITY_LOG_H__
#define __FERRUM_ACTIVITY_LOG_H__
#include "ferrum.h"
#include "ferrum_raw_socket_pair.h"

void ferrum_write_activity_log_raw(const ferrum_syslog_t *syslog, char *logid, char *protocol,
                                   const ferrum_policy_result_t *presult, rebrick_sockaddr_t *client,
                                   char *client_ip, char *client_port, int32_t is_tcp,
                                   rebrick_sockaddr_t *dest, char *dest_ip, char *dest_port);

enum ferrum_activity_log_dns_type {
  FERRUM_ACTIVITY_DNS_A,
  FERRUM_ACTIVITY_DNS_AAAA,
};
enum ferrum_dns_status {
  FERRUM_DNS_STATUS_ALLOW,
  FERRUM_DNS_STATUS_DENY,
  FERRUM_DNS_STATUS_ERROR,
  FERRUM_DNS_STATUS_INVALID
};

void ferrum_write_activity_log_dns(const ferrum_syslog_t *syslog, const char *logid, const char *protocol,
                                   const rebrick_sockaddr_t *client,
                                   const char *client_ip, const char *client_port, int32_t is_tcp,
                                   const rebrick_sockaddr_t *dest, char *dest_ip, char *dest_port,
                                   enum ferrum_activity_log_dns_type dnstype,
                                   const char *query,
                                   enum ferrum_dns_status status,
                                   const char *category_id,
                                   const char *authz_id,
                                   const char *list_id);

#endif