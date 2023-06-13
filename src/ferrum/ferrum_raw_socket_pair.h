#ifndef __FERRUM_RAW_SOCKET_PAIR_H__
#define __FERRUM_RAW_SOCKET_PAIR_H__
#include "ferrum.h"
#include "ferrum_config.h"
#include "ferrum_redis.h"
#include "ferrum_policy.h"
#include "ferrum_syslog.h"

struct ferrum_protocol;

typedef struct ferrum_raw_udpsocket_pair {
  base_object();
  int32_t mark;
  int64_t last_used_time;
  char userId[FERRUM_ID_STR_LEN];
  char groupId[FERRUM_USER_MAX_GROUP_COUNT][FERRUM_ID_STR_LEN];
  /**
   * @brief last policy result is allowed
   */
  int64_t policy_last_allow_time;
  rebrick_sockaddr_t client_addr;
  char client_ip[REBRICK_IP_STR_LEN];
  char client_port[REBRICK_PORT_STR_LEN];
  rebrick_udpsocket_t *udp_socket;
  size_t source_socket_write_buf_len;

  rebrick_sockaddr_t udp_destination_addr;
  char udp_destination_ip[REBRICK_IP_STR_LEN];
  char udp_destination_port[REBRICK_PORT_STR_LEN];
  // server socket reference for sending back
  rebrick_udpsocket_t *udp_listening_socket;

  ferrum_policy_result_t policy_result;

  struct ferrum_raw_udpsocket_pair *prev;
  struct ferrum_raw_udpsocket_pair *next;
  UT_hash_handle hh;

  struct ferrum_protocol *protocol;

} ferrum_raw_udpsocket_pair_t;

typedef struct ferrum_raw_tcpsocket_pair {
  base_object();
  void *key;
  int32_t mark;
  int64_t last_used_time;

  // last policy result is allowed
  int64_t policy_last_allow_time;
  rebrick_tcpsocket_t *source;
  rebrick_tcpsocket_t *destination;
  rebrick_sockaddr_t client_addr;
  char client_ip[REBRICK_IP_STR_LEN];
  char client_port[REBRICK_PORT_STR_LEN];

  ferrum_policy_result_t policy_result;

  UT_hash_handle hh;
  struct ferrum_protocol *protocol;
} ferrum_raw_tcpsocket_pair_t;

struct udp_callback_data2 {
  rebrick_sockaddr_t addr;
  ssize_t len;
};

#endif