#include "rebrick_util_net.h"

/* Compute checksum for count bytes starting at addr, using one's complement of
 * one's complement sum*/
uint16_t rebrick_util_net_checksum(uint16_t *addr, uint32_t count) {
  uint32_t sum = 0;
  while (count > 1) {
    sum += *addr++;
    count -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (count > 0) {
    sum += ((*addr) & htons(0xFF00));
  }
  // Fold sum to 16 bits: add carrier to result
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // one's complement
  sum = ~sum;
  return cast_to_uint16_t(sum);
}

uint16_t rebrick_util_net_ip_checksum(struct iphdr *iphdrp) {
  iphdrp->check = 0;
  return rebrick_util_net_checksum(cast_to_uint16ptr(iphdrp), iphdrp->ihl << 2);
}

/* set tcp checksum: given IP header and tcp segment */
uint16_t rebrick_util_net_tcp_checksum(struct iphdr *pIph, struct tcphdr *tcphdrp) {
  uint32_t sum = 0;
  uint16_t tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
  uint16_t *payload = cast_to_uint16ptr(tcphdrp);
  tcphdrp->check = 0;
  // add the pseudo header
  // the source ip
  sum += (pIph->saddr >> 16) & 0xFFFF;
  sum += (pIph->saddr) & 0xFFFF;
  // the dest ip
  sum += (pIph->daddr >> 16) & 0xFFFF;
  sum += (pIph->daddr) & 0xFFFF;
  // protocol and reserved: 6
  sum += htons(IPPROTO_TCP);
  // the length
  sum += htons(tcpLen);

  // add the IP payload
  while (tcpLen > 1) {
    sum += *payload++;
    tcpLen -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (tcpLen > 0) {
    // printf("+++++++++++padding, %dn", tcpLen);
    sum += ((*payload) & htons(0xFF00));
  }
  // Fold 32-bit sum to 16 bits: add carrier to result
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // set computation result
  return cast_to_uint16_t(~sum);
}

/* set udp checksum: given IP header and UDP datagram */
uint16_t rebrick_util_net_udp_checksum(struct iphdr *pIph, struct udphdr *udphdrp) {
  uint32_t sum = 0;
  uint16_t *payload = cast_to_uint16ptr(udphdrp);
  uint16_t udpLen = htons(udphdrp->len);
  udphdrp->check = 0;
  // add the pseudo header
  // the source ip
  sum += (pIph->saddr >> 16) & 0xFFFF;
  sum += (pIph->saddr) & 0xFFFF;
  // the dest ip
  sum += (pIph->daddr >> 16) & 0xFFFF;
  sum += (pIph->daddr) & 0xFFFF;
  // protocol and reserved: 17
  sum += htons(IPPROTO_UDP);
  // the length
  sum += udphdrp->len;

  // add the IP payload
  // initialize checksum to 0
  while (udpLen > 1) {
    sum += *payload++;
    udpLen -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (udpLen > 0) {
    // printf("+++++++++++++++padding: %dn", udpLen);
    sum += ((*payload) & htons(0xFF00));
  }
  // Fold sum to 16 bits: add carrier to result
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // printf("one's complementn");
  return cast_to_uint16_t(~sum);
}