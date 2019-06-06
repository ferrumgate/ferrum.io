#ifndef __TCPECHO_H__
#define __TCPECHO_H__

#define ECHO_BUF_SIZE 1024
int tcp_echo_start(int port,int isserver);
int tcp_echo_listen();
int tcp_echo_accept();
int tcp_echo_recv(char buf[ECHO_BUF_SIZE]);
int tcp_echo_send(const char *msg);

void tcp_echo_close_server();
void tcp_echo_close_client();
#endif