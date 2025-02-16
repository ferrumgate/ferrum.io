#ifndef __REBRICK_UTIL_NET_H__
#define __REBRICK_UTIL_NET_H__
#include "rebrick_common.h"

uint16_t rebrick_util_net_checksum(uint16_t *addr, uint32_t byteCount);
uint16_t rebrick_util_net_ip_checksum(struct iphdr *iphdr);
uint16_t rebrick_util_net_tcp_checksum(struct iphdr *iphdr, struct tcphdr *tcphdrp);
uint16_t rebrick_util_net_udp_checksum(struct iphdr *iphdr, struct udphdr *udphdrp);

#endif //__REBRICK_UTIL_NET_H__