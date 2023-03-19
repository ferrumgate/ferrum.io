#ifndef __FERRUM_PROTOCOL_H__
#define __FERRUM_PROTOCOL_H__
#include "../ferrum.h"
#include "../ferrum_dns.h"
#include "../ferrum_raw_socket_pair.h"
#include "../ferrum_activity_log.h"

struct ferrum_protocol;

/**
 * @brief after client to us, send to destinaton
 */
typedef int32_t (*process_input_udp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);
/**
 * @brief after destination read, send to client
 */
typedef int32_t (*process_output_udp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);

typedef int32_t (*process_input_tcp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);
typedef int32_t (*process_output_tcp_handler)(struct ferrum_protocol *protocol, const uint8_t *buf, size_t len);

typedef int32_t (*destroy_handler)(struct ferrum_protocol *protocol);

typedef struct ferrum_protocol {
  base_object();
  process_input_udp_handler process_input_udp;
  process_input_udp_handler process_output_udp;
  process_input_tcp_handler process_input_tcp;
  process_input_tcp_handler process_output_tcp;
  destroy_handler destroy;

  private_ const ferrum_config_t *config;
  private_ const ferrum_policy_t *policy;
  private_ const ferrum_syslog_t *syslog;
  private_ const ferrum_dns_t *dns;
  struct {
    ferrum_raw_udpsocket_pair_t *udp;
    ferrum_raw_tcpsocket_pair_t *tcp;
  } pair;

  struct {
    int64_t time;
    int32_t random;
  } log;

  void *data;
} ferrum_protocol_t;

#endif