#include "tcpecho.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "udpecho.h"
#include <errno.h>
#include <pthread.h>

static int server_fd, client_fd = -1;
int err;
static struct sockaddr_in server, client;
static int is_server = 0;
static int on_error(const char *msg) {
  fprintf(stderr, "%s", msg);
  return -1;
}
int tcp_echo_start(int port, int isserver) {

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0)
    return on_error("Could not create socket\n");

  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  if (isserver) {
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // inet_pton(AF_INET,"192.168.43.238",&server.sin_addr);
  } else {
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    //  inet_pton(AF_INET,"192.168.43.238",&server.sin_addr);
  }

  int opt_val = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);

  if (isserver)
    err = bind(server_fd, (struct sockaddr *)&server, sizeof(server));
  else
    err = connect(server_fd, (struct sockaddr *)&server, sizeof(server));

  client_fd = server_fd;
  if (err < 0)
    return on_error("Could not bind socket\n");

  is_server = isserver;
  if (is_server) {
    err = listen(server_fd, 128);
    if (err < 0)
      return on_error("Could not listen on socket\n");
  }
  fcntl(server_fd, F_SETFL, O_NONBLOCK);
  return 0;
}
static pthread_t thread;
static int work = 1;
static void *threaded_listen(void *data) {
  (void)data;
  client_fd = -1;
  socklen_t client_len = sizeof(client);
  int clientfd_tmp;
  while (client_fd == -1 && work) {
    clientfd_tmp = accept(server_fd, (struct sockaddr *)&client, &client_len);

    if (clientfd_tmp > 0) {
      fcntl(clientfd_tmp, F_SETFL, O_NONBLOCK);
      client_fd = clientfd_tmp;
    }
    usleep(10000);
  }
  return data;
}
int tcp_echo_listen() {
  work = 1;
  pthread_create(&thread, NULL, threaded_listen, NULL);
  return 0;
}
int tcp_echo_stop() {
  work = 0;
  void *ret;
  pthread_join(thread, &ret);
  return 0;
}
int tcp_echo_recv(char buf[ECHO_BUF_SIZE]) {
  int read;
  memset(buf, 0, ECHO_BUF_SIZE);
  read = recv(client_fd, buf, ECHO_BUF_SIZE, 0);

  return read;
}
int tcp_echo_send(const char *msg) {
  err = send(client_fd, msg, strlen(msg) + 1, 0);
  if (err < 0)
    return on_error("tcp echo client write failed\n");
  return err;
}

void tcp_echo_close_server() {

  if (is_server)
    close(server_fd);
}
void tcp_echo_close_client() {
  close(client_fd);
}