#ifndef __UDP_ECHO_H__
#define __UDP_ECHO_H__

#define ECHO_BUF_SIZE 65536
int udp_echo_start(int port);
int udp_echo_recv(char buf[ECHO_BUF_SIZE]);
int udp_echo_send(const char *msg);
int udp_echo_send2(const char *msg, const struct sockaddr_in *client);
void udp_echo_close();

#endif