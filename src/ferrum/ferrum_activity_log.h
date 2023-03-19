#ifndef __FERRUM_ACTIVITY_LOG_H__
#define __FERRUM_ACTIVITY_LOG_H__
#include "ferrum.h"
#include "ferrum_raw_socket_pair.h"

void ferrum_write_activity_log_raw(const ferrum_syslog_t *syslog, char *logid, char *protocol,
                                   const ferrum_policy_result_t *presult, rebrick_sockaddr_t *client,
                                   char *client_ip, char *client_port, int32_t is_tcp,
                                   rebrick_sockaddr_t *dest, char *dest_ip, char *dest_port);

#endif