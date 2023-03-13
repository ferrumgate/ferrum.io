#include "./ferrum/protocol/ferrum_protocol_dns.h"
#include "../rebrick/server_client/tcpecho.h"
#include "../rebrick/server_client/udpecho.h"
#include "cmocka.h"
#include <unistd.h>

#define loop(var, a, x)                       \
  var = a;                                    \
  while (var-- && (x)) {                      \
    usleep(100);                              \
    uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
  }

static int setup(void **state) {
  unused(state);
  fprintf(stdout, "****  %s ****\n", __FILE__);
  return 0;
}

static int teardown(void **state) {
  unused(state);
  uv_loop_close(uv_default_loop());
  return 0;
}

static int test = 0;

static int32_t callback(void *data) {
  unused(data);
  test++;
  return test;
}
static void on_udp_server_write(rebrick_socket_t *socket, void *callbackdata, void *source) {
  unused(socket);
  unused(callbackdata);
  rebrick_free(source);
}

int32_t ferrum_parse_dns_query(const uint8_t *buffer, size_t len, ferrum_dns_query_t *dns);

static void test_ferrum_parse_dns_query(void **start) {
  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_query_t dns;
  memset(&dns, 0, sizeof(dns));
  ferrum_parse_dns_query(packet_bytes, 55, &dns);
  assert_int_equal(dns.query_id, 0x95d4);
  assert_int_equal(dns.query_class, LDNS_RR_CLASS_IN);
  assert_int_equal(dns.query_type, LDNS_RR_TYPE_A);
  assert_string_equal(dns.query, "www.google.com");
  assert_int_equal(dns.edns.present, 1);

  unused(start);
}

int32_t ferrum_dns_reply_empty_packet(ferrum_dns_query_t *dns, ldns_pkt_rcode rcode, uint8_t **answer, size_t *answer_size);

static void test_ferrum_dns_reply_empty_packet(void **start) {
  unused(start);
  ferrum_dns_query_t dns;
  memset(&dns, 0, sizeof(dns));

  dns.query_id = 0xc550;
  dns.query_class = LDNS_RR_CLASS_IN;
  dns.query_type = LDNS_RR_TYPE_A;
  dns.flags.rd = 1;
  dns.edns.present = 1;
  uint8_t *answer = NULL;
  size_t answer_len = 0;
  // empty query test
  int32_t result = ferrum_dns_reply_empty_packet(&dns, LDNS_RCODE_NXDOMAIN, &answer, &answer_len);
  assert_int_equal(result, FERRUM_ERR_DNS);
  // test
  strncpy(dns.query, "test2.ferrumgate.com", 21);
  result = ferrum_dns_reply_empty_packet(&dns, LDNS_RCODE_NXDOMAIN, &answer, &answer_len);
  assert_int_equal(result, FERRUM_SUCCESS);

  char packet_bytes[] = {
      0xc5, 0x50, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x05, 0x74, 0x65, 0x73,
      0x74, 0x32, 0x0a, 0x66, 0x65, 0x72, 0x72, 0x75,
      0x6d, 0x67, 0x61, 0x74, 0x65, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00};
  assert_int_equal(answer_len, 49);
  for (size_t i = 0; i < answer_len; i++) {

    printf(", ");
    printf("0x%02X", answer[i]);
    if (!((i + 1) % 8))
      printf("\n");
  }
  printf("\n");
  assert_memory_equal(answer, packet_bytes, 49);
  rebrick_free(answer);
}

int32_t ferrum_dns_reply_ip_packet(ferrum_dns_query_t *dns, const char *ip, uint16_t ttl, uint8_t **answer, size_t *answer_size);

static void test_ferrum_dns_reply_ip_packet(void **start) {
  unused(start);
  ferrum_dns_query_t dns;
  memset(&dns, 0, sizeof(dns));
  dns.query_id = 0xc550;
  dns.query_class = LDNS_RR_CLASS_IN;
  dns.query_type = LDNS_RR_TYPE_A;
  dns.flags.rd = 1;
  dns.edns.present = 1;
  uint8_t *answer = NULL;
  size_t answer_len = 0;
  // empty query test
  int32_t result = ferrum_dns_reply_ip_packet(&dns, "199.36.158.100", 3600, &answer, &answer_len);
  assert_int_equal(result, FERRUM_ERR_DNS_BAD_ARGUMENT);
  // test
  strncpy(dns.query, "ferrumgate.com", 15);
  result = ferrum_dns_reply_ip_packet(&dns, "199.36.158.100", 3600, &answer, &answer_len);
  assert_int_equal(result, FERRUM_SUCCESS);

  char packet_bytes[] = {
      0xc5, 0x50, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x0a, 0x66, 0x65, 0x72,
      0x72, 0x75, 0x6d, 0x67, 0x61, 0x74, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x0e, 0x10, 0x00, 0x04, 0xc7, 0x24, 0x9e, 0x64,
      0x00, 0x00, 0x29, 0x05, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00};

  assert_int_equal(answer_len, 59);
  for (size_t i = 0; i < answer_len; i++) {

    printf(", ");
    printf("0x%02X", answer[i]);
    if (!((i + 1) % 8))
      printf("\n");
  }
  printf("\n");
  assert_memory_equal(answer, packet_bytes, 48);
  rebrick_free(answer);
}

int32_t reply_dns_empty(ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_query_t *dns, ldns_pkt_rcode rcode);

static void test_reply_dns_empty(void **start) {
  unused(start);
  int32_t counter;
  new2(ferrum_raw_udpsocket_pair_t, pair);
  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &client);
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19192", &dest);

  pair.client_addr = client;
  pair.udp_destination_addr = dest;

  rebrick_udpsocket_t *socket;
  new2(rebrick_udpsocket_callbacks_t, callback);

  rebrick_sockaddr_t bind;
  rebrick_util_ip_port_to_addr("127.0.0.1", "0", &bind);
  rebrick_udpsocket_new(&socket, &bind, &callback);
  pair.udp_listening_socket = socket;
  loop(counter, 100, TRUE);
  ferrum_dns_query_t dns;
  memset(&dns, 0, sizeof(dns));
  dns.query_id = 0xc550;
  dns.query_class = LDNS_RR_CLASS_IN;
  dns.query_type = LDNS_RR_TYPE_A;
  dns.flags.rd = 1;

  int32_t result = reply_dns_empty(&pair, &dns, LDNS_RCODE_NXDOMAIN);
  loop(counter, 100, TRUE);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strncpy(dns.query, "ferrumgate.com", 15);
  result = reply_dns_empty(&pair, &dns, LDNS_RCODE_NXDOMAIN);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);
  rebrick_udpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

int remove_recursive(const char *const path) {
  DIR *const directory = opendir(path);
  if (directory) {
    struct dirent *entry;
    while ((entry = readdir(directory))) {
      if (!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name)) {
        continue;
      }
      char filename[strlen(path) + strlen(entry->d_name) + 2];
      sprintf(filename, "%s/%s", path, entry->d_name);
      int (*const remove_func)(const char *) = entry->d_type == DT_DIR ? remove_recursive : unlink;
      if (remove_func(filename)) {
        fprintf(stderr, "%s\n", strerror(errno));
        closedir(directory);
        return -1;
      }
    }
    if (closedir(directory)) {
      return -1;
    }
  }
  return remove(path);
}

int test_ferrum_protocol_dns(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ferrum_parse_dns_query),
      cmocka_unit_test(test_ferrum_dns_reply_empty_packet),
      cmocka_unit_test(test_ferrum_dns_reply_ip_packet),
      cmocka_unit_test(test_reply_dns_empty),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
