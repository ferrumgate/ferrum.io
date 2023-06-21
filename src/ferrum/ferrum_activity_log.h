#ifndef __FERRUM_ACTIVITY_LOG_H__
#define __FERRUM_ACTIVITY_LOG_H__
#include "ferrum.h"
#include "ferrum_raw_socket_pair.h"

void ferrum_write_activity_log(const ferrum_syslog_t *syslog, const char *log, size_t len);

void ferrum_write_activity_log_raw(const ferrum_syslog_t *syslog, const char *logid, const char *protocol,
                                   const ferrum_policy_result_t *presult, const rebrick_sockaddr_t *client,
                                   const char *client_ip, const char *client_port, int32_t is_tcp,
                                   const rebrick_sockaddr_t *dest, const char *dest_ip, const char *dest_port);

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

static inline const char *ferrum_activity_log_dns_type_to_str(enum ferrum_activity_log_dns_type x) {
  if (x == FERRUM_ACTIVITY_DNS_A)
    return "a";
  return "aaaa";
}
static inline const char *ferrum_dns_status_to_str(enum ferrum_dns_status x) {
  if (x == FERRUM_DNS_STATUS_ALLOW)
    return "allow";
  if (x == FERRUM_DNS_STATUS_DENY)
    return "deny";
  if (x == FERRUM_DNS_STATUS_ERROR)
    return "error";
  if (x == FERRUM_DNS_STATUS_INVALID)
    return "invalid";
  return "unknown";
}

void ferrum_write_activity_log_dns(const ferrum_syslog_t *syslog, const char *logid, const char *protocol,
                                   const rebrick_sockaddr_t *client,
                                   const char *client_ip, const char *client_port, int32_t is_tcp,
                                   const rebrick_sockaddr_t *dest,
                                   const char *dest_ip, const char *dest_port,
                                   uint32_t mark_id,
                                   const char *authz_id,
                                   const char *user_id,
                                   const char *tun_id,
                                   enum ferrum_activity_log_dns_type dnstype,
                                   const char *query,
                                   enum ferrum_dns_status status,
                                   const char *category_id,
                                   const char *list_id);

#endif