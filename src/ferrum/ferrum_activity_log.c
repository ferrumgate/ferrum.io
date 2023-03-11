#include "ferrum_activity_log.h"

void ferrum_write_activity_log_raw(const ferrum_syslog_t *syslog, char *logid, char *protocol, const ferrum_policy_result_t *presult, rebrick_sockaddr_t *client,
                                   char *client_ip, char *client_port, int32_t is_tcp,
                                   rebrick_sockaddr_t *dest, char *dest_ip, char *dest_port) {

  // unused(client_addr);
  char log[1400] = {0};
  uint64_t now = rebrick_util_micro_time();
  // uint32_t rand = rebrick_util_rand(); // fast work

  char *c_ip = client_ip;
  char *c_port = client_port;
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

  char *d_ip = dest_ip;
  char *d_port = dest_port;
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

  size_t len = snprintf(log, sizeof(log) - 1, ",%s,1,0,%s,%" PRId64 ",%d,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", logid, protocol, now, presult->client_id, presult->is_dropped,
                        presult->why, syslog->config->gateway_id, syslog->config->service_id, presult->policy_id, presult->user_id, presult->tun_id,
                        c_ip, c_port, is_tcp ? "tcp" : "udp", d_ip, d_port);
  ferrum_syslog_write(syslog, cast_to_uint8ptr(log), len);
}