#include "rebrick_rawsocket.h"

int32_t rebrick_rawsocket_new(rebrick_rawsocket_t **raw_socket,
                              const rebrick_rawsocket_callbacks_t *callbacks) {
  rebrick_rawsocket_t *tmp = new1(rebrick_rawsocket_t);
  constructor(tmp, rebrick_rawsocket_t);
  tmp->callback_data = callbacks ? callbacks->callback_data : NULL;
  tmp->raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (tmp->raw_socket < 0) {
    rebrick_log_fatal("raw socket creation failed\n");
    rebrick_free(tmp);
    return REBRICK_ERR_IO_ERR;
  }
  const int opt_on = 1;
  int32_t result = setsockopt(tmp->raw_socket, IPPROTO_IP, IP_HDRINCL, &opt_on, sizeof(opt_on));
  if (result < 0) {
    rebrick_log_fatal("setsockopt failed\n");
    rebrick_free(tmp);
    return REBRICK_ERR_IO_ERR;
  }

  *raw_socket = tmp;
  return REBRICK_SUCCESS;
}

int32_t rebrick_rawsocket_destroy(rebrick_rawsocket_t *socket) {
  if (socket) {
    close(socket->raw_socket);
    rebrick_free(socket);
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_rawsocket_write_udp(rebrick_rawsocket_t *socket, const rebrick_sockaddr_t *src_addr,
                                    const rebrick_sockaddr_t *dst_addr, uint8_t *buffer, size_t len,
                                    rebrick_clean_func_t clean_func) {

  unused(socket);
  unused(buffer);
  unused(len);
  unused(clean_func);
  rebrick_log_debug("raw socket write called\n");
  size_t total_size = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
  char *send_buffer = rebrick_malloc(total_size);
  struct iphdr *ip_header = (struct iphdr *)send_buffer;
  struct udphdr *udp_header = (struct udphdr *)(send_buffer + sizeof(struct iphdr));
  size_t offset_data = sizeof(struct iphdr) + sizeof(struct udphdr);

  memcpy(send_buffer + offset_data, buffer, len);
  ip_header->ihl = 5;
  ip_header->version = 4;
  ip_header->tos = 0;
  ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len);
  ip_header->id = htons(rebrick_util_rand16());
  ip_header->frag_off = 0;
  ip_header->ttl = 255;
  ip_header->protocol = IPPROTO_UDP;
  ip_header->check = 0;
  ip_header->saddr = src_addr->v4.sin_addr.s_addr;
  ip_header->daddr = dst_addr->v4.sin_addr.s_addr;
  ip_header->check = rebrick_util_net_ip_checksum(ip_header);
  udp_header->source = src_addr->v4.sin_port;
  udp_header->dest = dst_addr->v4.sin_port;
  udp_header->len = htons(sizeof(struct udphdr) + len);
  udp_header->check = rebrick_util_net_udp_checksum(ip_header, udp_header);

  int32_t result = sendto(socket->raw_socket, send_buffer, total_size, 0, cast_to_sockaddr(&dst_addr->v4), sizeof(struct sockaddr_in));
  if (result < 0) {
    rebrick_log_fatal("rawsocket sendto failed\n");
    rebrick_free(send_buffer);
    return REBRICK_ERR_IO_ERR;
  }
  rebrick_free(send_buffer);
  return REBRICK_SUCCESS;
}
