#include "./rebrick/common/rebrick_util_net.h"
#include "cmocka.h"

static int setup(void **state) {
  unused(state);
  fprintf(stdout, "****  %s ****\n", __FILE__);
  return 0;
}
static int teardown(void **state) {
  unused(state);
  return 0;
}
/* A test case that does nothing and succeeds. */
static void null_test_success(void **state) {

  unused(state);
}

static void test_ipv4_ipchecksum(void **start) {
  unused(start);
  uint8_t packet_bytes[] = {0x45, 0x00, 0x00, 0x3c, 0x18, 0x61, 0x40,
                            0x00, 0x40, 0x11, 0xbe, 0x44, 0xc0, 0xa8,
                            0x58, 0xfa, 0x8e, 0xfa, 0xbb, 0x6e};
  struct iphdr *ip_header = (struct iphdr *)(packet_bytes);
  ip_header->check = 0;
  uint16_t result = rebrick_util_net_ip_checksum(ip_header);
  assert_int_equal(result, ntohs(0xbe44));
}

static void test_ipv4_ipudpchecksum(void **start) {
  unused(start);
  uint8_t ip_header_bytes[] = {0x45, 0x00, 0x00, 0x35, 0x00, 0x00, 0x40,
                               0x00, 0x39, 0x11, 0x0b, 0xec, 0x8e, 0xfb,
                               0x8d, 0x2e, 0xc0, 0xa8, 0x58, 0xfa};
  uint8_t udp_header_and_data_bytes[] = {
      0x01, 0xbb, 0xa4, 0xe1, 0x00, 0x21, 0x66, 0xb1, // header
                                                      // data
      0x43, 0xe8, 0xc3, 0x13, 0x2f, 0x97, 0x81, 0x1e, 0xf4, 0x68, 0x3a, 0x71,
      0x50, 0x13, 0x7d, 0x1a, 0x18, 0x2f, 0xa2, 0x1b, 0x0d, 0x29, 0x15, 0x64,
      0x2c};

  struct iphdr *ip_header = cast(ip_header_bytes, struct iphdr *);
  ip_header->check = 0;
  uint16_t ipHeaderChecksum = rebrick_util_net_ip_checksum(ip_header);
  assert_int_equal(ipHeaderChecksum, ntohs(0x0bec));
  struct udphdr *udp_header =
      cast(udp_header_and_data_bytes, struct udphdr *);
  uint16_t result = rebrick_util_net_udp_checksum(ip_header, udp_header);
  assert_int_equal(result, ntohs(0x66b1));
}

static void test_ipv4_iptcpchecksum(void **start) {
  unused(start);
  uint8_t ip_header_bytes[] = {0x45, 0x00, 0x00, 0x34, 0x1a, 0x67, 0x40,
                               0x00, 0x40, 0x06, 0x0e, 0xf5, 0xc0, 0xa8,
                               0x58, 0xfa, 0xcc, 0x8d, 0x2b, 0x38};
  uint8_t tcp_header_and_data_bytes[] = {
      0xe0, 0xc0, 0x01, 0xbb, 0xdd, 0xde, 0xbc, 0x90, 0x5b, 0xba, 0x12,
      0xa3, 0x80, 0x10, 0x01, 0xf5, 0x11, 0x8f, 0x00, 0x00, 0x01, 0x01,
      0x08, 0x0a, 0x0a, 0xd7, 0x86, 0x1c, 0xc0, 0x4f, 0x51, 0x01};

  struct iphdr *ip_header = cast(ip_header_bytes, struct iphdr *);
  struct tcphdr *tcpHeader = cast(tcp_header_and_data_bytes, struct tcphdr *);
  uint16_t result = rebrick_util_net_tcp_checksum(ip_header, tcpHeader);
  assert_int_equal(result, ntohs(0xd5d2));
}

int test_rebrick_util_net(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(null_test_success),
      cmocka_unit_test(test_ipv4_ipchecksum),
      cmocka_unit_test(test_ipv4_ipudpchecksum),
      cmocka_unit_test(test_ipv4_iptcpchecksum),

  };

  return cmocka_run_group_tests(tests, setup, teardown);
}
