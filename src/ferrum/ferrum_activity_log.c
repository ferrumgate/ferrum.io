#include "ferrum_activity_log.h"

void ferrum_write_activity_log_raw(const ferrum_syslog_t *syslog, const char *logid, const char *protocol,
                                   const ferrum_policy_result_t *presult, const rebrick_sockaddr_t *client,
                                   const char *client_ip, const char *client_port, int32_t is_tcp,
                                   const rebrick_sockaddr_t *dest, const char *dest_ip, const char *dest_port) {

  // unused(client_addr);
  char log[1400] = {0};
  uint64_t now = rebrick_util_micro_time();
  // uint32_t rand = rebrick_util_rand(); // fast work

  const char *c_ip = client_ip;
  const char *c_port = client_port;
  char ip_str[REBRICK_IP_STR_LEN] = {0};
  char port_str[REBRICK_PORT_STR_LEN] = {0};

  // if client ip is null then convert to string for syslog
  if (!c_ip) {
    rebrick_util_addr_to_ip_string(client, ip_str); // dont need to check result

    c_ip = ip_str;
  }
  if (!c_port) {
    rebrick_util_addr_to_port_string(client, port_str); // dont need to check resutl
    c_port = port_str;
  }

  const char *d_ip = dest_ip;
  const char *d_port = dest_port;
  char dip_str[REBRICK_IP_STR_LEN] = {0};
  char dport_str[REBRICK_PORT_STR_LEN] = {0};

  // if client ip is null then convert to string for syslog
  if (!d_ip) {
    rebrick_util_addr_to_ip_string(dest, dip_str); // dont need to check result

    d_ip = dip_str;
  }
  if (!d_port) {
    rebrick_util_addr_to_port_string(dest, dport_str); // dont need to check resutl
    d_port = dport_str;
  }

  size_t len = snprintf(log, sizeof(log) - 1, ",%s,1,0,%s,%" PRId64 ",%u,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", logid, protocol, now, presult->client_id, presult->is_dropped,
                        presult->why, syslog->config->gateway_id, syslog->config->service_id, presult->policy_id, presult->user_id, presult->tun_id,
                        c_ip, c_port, is_tcp ? "tcp" : "udp", d_ip, d_port);
  ferrum_syslog_write(syslog, cast_to_uint8ptr(log), len);
}

void ferrum_write_activity_log(const ferrum_syslog_t *syslog, const char *log, size_t len) {
  ferrum_syslog_write(syslog, cast_to_uint8ptr(log), len);
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
                                   const char *list_id) {
  unused(syslog);
  unused(logid);
  unused(protocol);
  unused(client);
  unused(client_ip);
  unused(client_port);
  unused(is_tcp);
  unused(dest);
  unused(dest_ip);
  unused(dest_port);
  unused(dnstype);
  unused(query);
  unused(status);
  unused(category_id);
  unused(authz_id);
  unused(list_id);
  unused(mark_id);

  // unused(client_addr);
  char log[1400] = {0};
  uint64_t now = rebrick_util_micro_time();
  // uint32_t rand = rebrick_util_rand(); // fast work

  const char *c_ip = client_ip;
  const char *c_port = client_port;
  char ip_str[REBRICK_IP_STR_LEN] = {0};
  char port_str[REBRICK_PORT_STR_LEN] = {0};

  // if client ip is null then convert to string for syslog
  if (!c_ip) {
    rebrick_util_addr_to_ip_string(client, ip_str); // dont need to check result

    c_ip = ip_str;
  }
  if (!c_port) {
    rebrick_util_addr_to_port_string(client, port_str); // dont need to check resutl
    c_port = port_str;
  }

  const char *d_ip = dest_ip;
  const char *d_port = dest_port;
  char dip_str[REBRICK_IP_STR_LEN] = {0};
  char dport_str[REBRICK_PORT_STR_LEN] = {0};

  // if client ip is null then convert to string for syslog
  if (!d_ip) {
    rebrick_util_addr_to_ip_string(dest, dip_str); // dont need to check result

    d_ip = dip_str;
  }
  if (!d_port) {
    rebrick_util_addr_to_port_string(dest, dport_str); // dont need to check resutl
    d_port = dport_str;
  }
  // list id can be NULL, be carefull
  size_t len = snprintf(log, sizeof(log) - 1, ",%s,1,0,%s,%" PRId64 ",%u,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", logid, protocol, now, mark_id, 0,
                        0, syslog->config->gateway_id, syslog->config->service_id,
                        authz_id, user_id, tun_id,
                        c_ip, c_port, is_tcp ? "tcp" : "udp", d_ip, d_port,
                        ferrum_activity_log_dns_type_to_str(dnstype),
                        query,
                        ferrum_dns_status_to_str(status),
                        category_id);
  ferrum_syslog_write(syslog, cast_to_uint8ptr(log), len);
}