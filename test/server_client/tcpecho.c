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

static int server_fd, client_fd;
int err;
 struct sockaddr_in server, client;
int on_error(const char *msg)
{
    fprintf(stderr, "%s",msg);
    return -1;
}
int tcp_echo_start(int port, int isserver)
{



    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
       return on_error("Could not create socket\n");

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (isserver)
        server.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int opt_val = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);


    err = bind(server_fd, (struct sockaddr *)&server, sizeof(server));
    if (err < 0)
        return on_error("Could not bind socket\n");

   // fcntl(server_fd, F_SETFL, O_NONBLOCK);

    return 0;
}
int tcp_echo_listen(){

        err = listen(server_fd, 128);
        if (err < 0)
            return on_error("Could not listen on socket\n");
        socklen_t client_len = sizeof(client);
    client_fd = accept(server_fd, (struct sockaddr *) &client, &client_len);
    return client_fd;


}
int tcp_echo_recv(char buf[ECHO_BUF_SIZE])
{
    int read = recv(client_fd, buf, ECHO_BUF_SIZE, 0);


    return read;
}
int tcp_echo_send(const char *msg)
{
err = send(client_fd, msg, strlen(msg), 0);
      if (err < 0) return on_error("Client write failed\n");
    return 0;
}

void tcp_echo_close_server()
{
    close(server_fd);
}
void tcp_echo_close_client()
{
    close(client_fd);
}