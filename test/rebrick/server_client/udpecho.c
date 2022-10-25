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

static int sockfd;

// static    char *hello = "Hello from server";

// Driver code
int udp_echo_start(int port) {

  struct sockaddr_in servaddr, cliaddr;
  // Creating socket file descriptor
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  int optval = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
             (const void *)&optval, sizeof(int));

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));

  // Filling server information
  servaddr.sin_family = AF_INET; // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(port);

  // Bind the socket with the server address
  if (bind(sockfd, (const struct sockaddr *)&servaddr,
           sizeof(servaddr)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  fcntl(sockfd, F_SETFL, O_NONBLOCK);

  return 0;
}

int udp_echo_recv(char buf[ECHO_BUF_SIZE]) {

  socklen_t len;
  int n;

  memset(buf, 0, ECHO_BUF_SIZE);

  n = recvfrom(sockfd, buf, ECHO_BUF_SIZE - 1,
               MSG_WAITALL, NULL,
               &len);

  if (n < 0)
    return n;
  buf[n] = '\0';
  return n;
}

int udp_echo_send(const char *msg) {

  struct sockaddr_in6 cliaddr;
  memset(&cliaddr, 0, sizeof(cliaddr));

  sendto(sockfd, (const char *)msg, strlen(msg),
         MSG_CONFIRM, (const struct sockaddr *)&cliaddr,
         sizeof(struct sockaddr_in));
  return 0;
}
int udp_echo_send2(const char *msg, const struct sockaddr_in *client) {
  // int len=strlen(msg);
  errno = 0;
  ssize_t res = sendto(sockfd, (const char *)msg, strlen(msg),
                       MSG_CONFIRM, (const struct sockaddr *)client,
                       sizeof(struct sockaddr_in));
  printf("%s\n", strerror(errno));
  return res;
}

void udp_echo_close() {
  close(sockfd);
}