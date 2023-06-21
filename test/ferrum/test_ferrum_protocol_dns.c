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

int32_t ferrum_dns_packet_from(const uint8_t *buffer, size_t len, ferrum_dns_packet_t *dns);

static void test_ferrum_parse_dns_query(void **start) {
  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_packet_new(dns);
  ferrum_dns_packet_from(packet_bytes, 55, dns);
  assert_int_equal(dns->query_id, 0x95d4);
  assert_int_equal(dns->query_class, LDNS_RR_CLASS_IN);
  assert_int_equal(dns->query_type, LDNS_RR_TYPE_A);
  assert_string_equal(dns->query, "www.google.com");
  assert_int_equal(dns->edns.present, 1);
  ferrum_dns_packet_destroy(dns);
  unused(start);
}

int32_t ferrum_dns_reply_empty_packet(ferrum_dns_packet_t *dns, ldns_pkt_rcode rcode, uint8_t **answer, size_t *answer_size);

static void test_ferrum_dns_reply_empty_packet(void **start) {
  unused(start);

  new4(ferrum_dns_packet_t, dns);

  dns->query_id = 0xc550;
  dns->query_class = LDNS_RR_CLASS_IN;
  dns->query_type = LDNS_RR_TYPE_A;
  dns->flags.rd = 1;
  dns->edns.present = 1;
  dns->query = rebrick_malloc(64);
  strcpy(dns->query, "");
  uint8_t *answer = NULL;
  size_t answer_len = 0;
  // empty query test
  int32_t result = ferrum_dns_reply_empty_packet(dns, LDNS_RCODE_NXDOMAIN, &answer, &answer_len);
  assert_int_equal(result, FERRUM_ERR_DNS);
  // test
  strncpy(dns->query, "test2.ferrumgate.com", 21);
  result = ferrum_dns_reply_empty_packet(dns, LDNS_RCODE_NXDOMAIN, &answer, &answer_len);
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
  ferrum_dns_packet_destroy(dns);
}

int32_t ferrum_dns_reply_ip_packet(ferrum_dns_packet_t *dns, const char *ip, uint16_t ttl, uint8_t **answer, size_t *answer_size);

static void test_ferrum_dns_reply_ip_packet(void **start) {
  unused(start);

  new4(ferrum_dns_packet_t, dns);
  dns->query_id = 0xc550;
  dns->query_class = LDNS_RR_CLASS_IN;
  dns->query_type = LDNS_RR_TYPE_A;
  dns->flags.rd = 1;
  dns->edns.present = 1;
  dns->query = rebrick_malloc(64);
  strcpy(dns->query, "");
  uint8_t *answer = NULL;
  size_t answer_len = 0;
  // empty query test
  int32_t result = ferrum_dns_reply_ip_packet(dns, "199.36.158.100", 3600, &answer, &answer_len);
  assert_int_equal(result, FERRUM_ERR_DNS_BAD_ARGUMENT);
  // test
  strncpy(dns->query, "ferrumgate.com", 15);
  result = ferrum_dns_reply_ip_packet(dns, "199.36.158.100", 3600, &answer, &answer_len);
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
  ferrum_dns_packet_destroy(dns);
}

int32_t reply_dns_empty(ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns, ldns_pkt_rcode rcode);

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
  new4(ferrum_dns_packet_t, dns);

  dns->query_id = 0xc550;
  dns->query_class = LDNS_RR_CLASS_IN;
  dns->query_type = LDNS_RR_TYPE_A;
  dns->flags.rd = 1;
  dns->query = rebrick_malloc(64);
  strcpy(dns->query, "");

  int32_t result = reply_dns_empty(&pair, dns, LDNS_RCODE_NXDOMAIN);
  loop(counter, 100, TRUE);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  strncpy(dns->query, "ferrumgate.com", 15);
  result = reply_dns_empty(&pair, dns, LDNS_RCODE_NXDOMAIN);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);
  rebrick_udpsocket_destroy(socket);
  loop(counter, 100, TRUE);
  ferrum_dns_packet_destroy(dns);
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
const char *folder = "/tmp/test41";
static void create_folders() {

  setenv("TRACK_DB_FOLDER", folder, 1);
  setenv("AUTHZ_DB_FOLDER", folder, 1);
  setenv("DNS_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

int32_t db_get_user_and_group_ids(ferrum_protocol_t *protocol, uint32_t mark);
static void test_db_get_user_and_group_ids_phase1(void **start) {
  unused(start);
  int32_t counter;
  create_folders();
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_authz_db_t *authz_db;
  result = ferrum_authz_db_new(&authz_db, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_track_db_t *track_db;
  result = ferrum_track_db_new(&track_db, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_protocol_t *protocol;
  ferrum_protocol_dns_new(&protocol, NULL, NULL, config, NULL, NULL, NULL, NULL, track_db, authz_db);
  track_db->lmdb->mock_error = TRUE;
  ferrum_lmdb_t *lmdb1;
  result = ferrum_lmdb_new(&lmdb1, folder, "track", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb2;
  result = ferrum_lmdb_new(&lmdb2, folder, "authz", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  // check time parameter

  protocol->identity.last_check = rebrick_util_micro_time();
  result = db_get_user_and_group_ids(protocol, 5);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(protocol->identity.user_id);

  // check track db gives error
  protocol->identity.last_check = 0;
  result = db_get_user_and_group_ids(protocol, 5);
  assert_int_not_equal(result, FERRUM_SUCCESS);
  assert_null(protocol->identity.user_id);

  // check track not found
  protocol->identity.user_id = strdup("test");
  protocol->identity.group_ids = strdup("test");
  track_db->lmdb->mock_error = FALSE; // set it default value
  protocol->identity.last_check = 0;
  result = db_get_user_and_group_ids(protocol, 5);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(protocol->identity.user_id);
  assert_null(protocol->identity.group_ids);

  // set lmdb data
  lmdb1->root->key.size = snprintf(lmdb1->root->key.val, sizeof(lmdb1->root->key) - 1, "/track/id/5/data");
  lmdb1->root->value.size = snprintf(lmdb1->root->value.val, sizeof(lmdb1->root->value) - 1, "userId=\"axd\"\ngroupIds=\",abc,def,\"");
  ferrum_lmdb_put(lmdb1, &lmdb1->root->key, &lmdb1->root->value);
  protocol->identity.last_check = 0;
  result = db_get_user_and_group_ids(protocol, 5);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(protocol->identity.user_id, "axd");
  assert_non_null(protocol->identity.group_ids);

  ferrum_config_destroy(config);
  ferrum_protocol_dns_destroy(protocol);
  ferrum_authz_db_destroy(authz_db);
  ferrum_track_db_destroy(track_db);
  ferrum_lmdb_destroy(lmdb1);
  ferrum_lmdb_destroy(lmdb2);

  loop(counter, 100, TRUE);
}

int32_t send_backend_directly(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns, const uint8_t *buffer, size_t len);

static void test_send_backend_directly(void **start) {
  unused(start);
  int32_t counter;
  create_folders();
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_raw_udpsocket_pair_t *pair;
  pair = new1(ferrum_raw_udpsocket_pair_t);
  constructor(pair, ferrum_raw_udpsocket_pair_t);
  // open a upd socket
  const char *dest_ip = "127.0.0.1";
  const char *dest_port = "5555";
  rebrick_sockaddr_t destination;
  rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_t *dnsclient;

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  callbacks.callback_data = NULL;

  result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
  assert_int_equal(result, FERRUM_SUCCESS);
  pair->udp_socket = dnsclient;

  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_packet_new(dns);
  ferrum_dns_packet_from(packet_bytes, sizeof(packet_bytes), dns);

  ferrum_protocol_t *protocol;
  ferrum_protocol_dns_new(&protocol, NULL, NULL, config, NULL, NULL, NULL, NULL, NULL, NULL);

  loop(counter, 100, TRUE);
  result = send_backend_directly(protocol, pair, dns, packet_bytes, sizeof(packet_bytes));
  assert_int_not_equal(result, FERRUM_SUCCESS);
  // pair->udp_destination_addr = destination;
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  ferrum_protocol_dns_destroy(protocol);
  loop(counter, 100, TRUE);

  rebrick_udpsocket_destroy(dnsclient);
  ferrum_dns_packet_destroy(dns);

  loop(counter, 100, TRUE);
  rebrick_free(pair);
}

int32_t reply_local_dns(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns);
static void test_reply_local_dns(void **start) {
  unused(start);
  int32_t counter;
  create_folders();
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_raw_udpsocket_pair_t *pair;
  pair = new1(ferrum_raw_udpsocket_pair_t);
  constructor(pair, ferrum_raw_udpsocket_pair_t);
  // open a upd socket
  const char *dest_ip = "127.0.0.1";
  const char *dest_port = "5555";
  rebrick_sockaddr_t destination;
  rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_t *dnsclient;

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  callbacks.callback_data = NULL;

  result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
  assert_int_equal(result, FERRUM_SUCCESS);
  pair->udp_socket = dnsclient;
  pair->udp_listening_socket = dnsclient;
  pair->client_addr = destination;

  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_packet_new(dns);
  ferrum_dns_packet_from(packet_bytes, sizeof(packet_bytes), dns);

  ferrum_dns_db_t *dns_db;
  result = ferrum_dns_db_new(&dns_db, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_protocol_t *protocol;
  ferrum_protocol_dns_new(&protocol, NULL, NULL, config, NULL, NULL, NULL, dns_db, NULL, NULL);

  loop(counter, 100, TRUE);
  // AAAA
  dns->query_type = LDNS_RR_TYPE_AAAA;
  result = reply_local_dns(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  // CNAME
  dns->query_type = LDNS_RR_TYPE_CNAME;
  result = reply_local_dns(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  // A, lmdb error
  dns_db->lmdb->mock_error = TRUE;
  dns->query_type = LDNS_RR_TYPE_A;
  result = reply_local_dns(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  // A, lmdb not error, empty ip
  dns_db->lmdb->mock_error = FALSE;
  dns->query_type = LDNS_RR_TYPE_A;
  result = reply_local_dns(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  // A, lmdb not error, ip
  strncpy(dns->query, "ferrumgate.com", strlen(dns->query) - 1);
  dns_db->lmdb->root->key.size = snprintf(dns_db->lmdb->root->key.val, sizeof(dns_db->lmdb->root->key.val) - 1, "/local/dns/ferrumgate.com/a");

  dns_db->lmdb->root->value.size = snprintf(dns_db->lmdb->root->value.val, sizeof(dns_db->lmdb->root->value.val) - 1, "192.168.1.1");

  result = ferrum_lmdb_put(dns_db->lmdb, &dns_db->lmdb->root->key, &dns_db->lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  dns_db->lmdb->mock_error = FALSE;
  dns->query_type = LDNS_RR_TYPE_A;
  result = reply_local_dns(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  // pair->udp_destination_addr = destination;
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  ferrum_protocol_dns_destroy(protocol);
  loop(counter, 100, TRUE);

  rebrick_udpsocket_destroy(dnsclient);
  ferrum_dns_packet_destroy(dns);
  ferrum_dns_db_destroy(dns_db);

  loop(counter, 100, TRUE);
  rebrick_free(pair);
}

int32_t db_get_authz_fqdn_intelligence(char *content, const char *name, char **fqdns, char **lists);

static void test_db_get_authz_fqdn_intelligence(void **start) {
  unused(start);
  char *fqdns;
  char *lists;
  int32_t result = db_get_authz_fqdn_intelligence(NULL, "ignore", &fqdns, &lists);
  assert_int_equal(result, FERRUM_SUCCESS);

  result = db_get_authz_fqdn_intelligence("[", "ignore", &fqdns, &lists);
  assert_int_not_equal(result, FERRUM_SUCCESS);

  result = db_get_authz_fqdn_intelligence("", "ignore", &fqdns, &lists);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(fqdns);
  assert_null(lists);

  result = db_get_authz_fqdn_intelligence("[fqdnIntelligence]\nignoreFqdns=\"test\"\nignoreLists=\"test2\"", "ignore", &fqdns, &lists);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(fqdns, "test");
  assert_string_equal(lists, "test2");
  rebrick_free(fqdns);
  rebrick_free(lists);
}

int merge_fqdn_for_redis(const char *fqdn, char **dest);
static void test_merge_fqdn_for_redis(void **start) {
  unused(start);

  char *merged;
  merge_fqdn_for_redis("www.ferrumgate.com", &merged);
  assert_string_equal(merged, "MGET /fqdn/www.ferrumgate.com/list /fqdn/ferrumgate.com/list /fqdn/com/list ");
  rebrick_free(merged);

  merge_fqdn_for_redis("...", &merged);
  assert_string_equal(merged, "MGET ");
  rebrick_free(merged);

  merge_fqdn_for_redis("", &merged);
  assert_string_equal(merged, "MGET ");
  rebrick_free(merged);

  merge_fqdn_for_redis("...www.ferrumgate.com", &merged);
  assert_string_equal(merged, "MGET /fqdn/www.ferrumgate.com/list /fqdn/ferrumgate.com/list /fqdn/com/list ");
  rebrick_free(merged);
  merge_fqdn_for_redis("...www.....ferrumgate.com...........", &merged);
  assert_string_equal(merged, "MGET /fqdn/www.....ferrumgate.com.........../list /fqdn/ferrumgate.com.........../list /fqdn/com.........../list ");
  rebrick_free(merged);

  merge_fqdn_for_redis("...www.....asdfa....e...wew.....asdf......ferrumgate....as....a....d....d..s.........com..............www.....asdfa....e...wew.....asdf......ferrumgate....as....a....d....d..s.........com..............www.....asdfa....e...wew.....asdf......ferrumgate....as....a....d....d..s.........com...........", &merged);

  rebrick_free(merged);
}
int split_fqdn_for_redis(const char *fqdn, ferrum_redis_dns_query_t **dest, size_t *dest_len);

static void test_split_fqdn_for_redis(void **start) {
  unused(start);

  ferrum_redis_dns_query_t *qredis;
  size_t qredis_len;
  int32_t result = split_fqdn_for_redis("www.ferrumgate.com", &qredis, &qredis_len);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(qredis_len, 3);
  assert_string_equal(qredis[0].query, "www.ferrumgate.com");
  assert_string_equal(qredis[1].query, "ferrumgate.com");
  assert_string_equal(qredis[2].query, "com");
  rebrick_free(qredis);

  result = split_fqdn_for_redis("...", &qredis, &qredis_len);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(qredis);
  assert_int_equal(qredis_len, 0);

  result = split_fqdn_for_redis("", &qredis, &qredis_len);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(qredis);
  assert_int_equal(qredis_len, 0);

  result = split_fqdn_for_redis("...www.ferrumgate.com", &qredis, &qredis_len);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(qredis_len, 3);
  assert_string_equal(qredis[0].query, "www.ferrumgate.com");
  assert_string_equal(qredis[1].query, "ferrumgate.com");
  assert_string_equal(qredis[2].query, "com");
  rebrick_free(qredis);

  result = split_fqdn_for_redis("...www.....ferrumgate.com...........", &qredis, &qredis_len);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(qredis_len, 3);
  assert_string_equal(qredis[0].query, "www.....ferrumgate.com...........");
  assert_string_equal(qredis[1].query, "ferrumgate.com...........");
  assert_string_equal(qredis[2].query, "com...........");
  rebrick_free(qredis);

  result = split_fqdn_for_redis("...www.....asdfa....e...wew.....asdf......ferrumgate....as....a....d....d..s.........com..............www.....asdfa....e...wew.....asdf......ferrumgate....as....a....d....d..s.........com..............www.....asdfa....e...wew.....asdf......ferrumgate....as....a....d....d..s.........com...........", &qredis, &qredis_len);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(qredis_len, 36);
  rebrick_free(qredis);
}

void flush_redis_callback(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  assert_non_null(redis);
  assert_non_null(cmd);
  assert_non_null(reply);
  assert_ptr_equal(redis, cmd->callback.arg1);
  assert_null(cmd->callback.arg2);

  ferrum_redis_cmd_destroy(cmd);
  int32_t counter;
  loop(counter, 1000, TRUE);
}
static void flush_redis(ferrum_redis_t *redis) {
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 10, 1, flush_redis_callback, redis);
  int32_t counter;

  int32_t result = ferrum_redis_send(redis, cmd, "flushdb");
  if (result) {
    ferrum_redis_cmd_destroy(cmd);
  }
  loop(counter, 1000, TRUE);
}

int32_t send_redis_intel_lists(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns);
static void test_send_redis_intel_lists(void **start) {
  unused(start);
  int32_t counter;
  create_folders();
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_raw_udpsocket_pair_t *pair;
  pair = new1(ferrum_raw_udpsocket_pair_t);
  constructor(pair, ferrum_raw_udpsocket_pair_t);
  // open a upd socket
  const char *dest_ip = "127.0.0.1";
  const char *dest_port = "5555";
  rebrick_sockaddr_t destination;
  rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_t *dnsclient;

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  callbacks.callback_data = NULL;

  result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
  assert_int_equal(result, FERRUM_SUCCESS);
  pair->udp_socket = dnsclient;
  pair->udp_listening_socket = dnsclient;
  pair->client_addr = destination;

  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_packet_new(dns);
  ferrum_dns_packet_from(packet_bytes, sizeof(packet_bytes), dns);

  ferrum_dns_db_t *dns_db;
  result = ferrum_dns_db_new(&dns_db, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_t *redis;
  result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1000);

  ferrum_protocol_t *protocol;
  ferrum_protocol_dns_new(&protocol, NULL, NULL, config, NULL, NULL, NULL, dns_db, NULL, NULL);
  protocol->redis_intel = redis;

  flush_redis(redis);
  loop(counter, 100, TRUE);

  // ferrum_redis_cmd_t *cmd;
  // ferrum_redis_cmd_new(&cmd, 10, 1, flush_redis_callback, redis);
  // ferrum_redis_send(redis, cmd, "sadd /fqdn/www.google.com/list abc def kls");
  // loop(counter, 1000, TRUE);

  // redis gives error
  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_received = TRUE;
  dns->state.redis_query_list[2].is_key_received = TRUE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == TRUE);
  assert_true(dns->state.is_redis_query_error == FALSE);
  assert_true(dns->state.is_redis_query_sended == FALSE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_received = FALSE;
  dns->state.redis_query_list[2].is_key_received = FALSE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == FALSE);
  assert_true(dns->state.is_redis_query_error == FALSE);
  assert_true(dns->state.is_redis_query_sended == FALSE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_received = TRUE;
  dns->state.redis_query_list[2].is_key_received = FALSE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == FALSE);
  assert_true(dns->state.is_redis_query_error == FALSE);
  assert_true(dns->state.is_redis_query_sended == FALSE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_exists = TRUE;
  dns->state.redis_query_list[2].is_key_received = TRUE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == FALSE);
  assert_true(dns->state.is_redis_query_error == FALSE);
  assert_true(dns->state.is_redis_query_sended == TRUE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_exists = TRUE;
  dns->state.redis_query_list[1].is_key_received = FALSE;
  dns->state.redis_query_list[2].is_key_received = FALSE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == FALSE);
  assert_true(dns->state.is_redis_query_error == FALSE);
  assert_true(dns->state.is_redis_query_sended == TRUE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[1].is_key_exists = TRUE;
  dns->state.redis_query_list[1].is_error = TRUE;
  dns->state.redis_query_list[2].is_key_received = FALSE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == FALSE);
  assert_true(dns->state.is_redis_query_error == TRUE);
  assert_true(dns->state.is_redis_query_sended == FALSE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);
  flush_redis(redis);
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 10, 1, flush_redis_callback, redis);
  ferrum_redis_send(redis, cmd, "sadd /fqdn/www.google.com/list abc def kls");
  loop(counter, 1000, TRUE);

  memset(&dns->state, 0, sizeof(dns->state));
  split_fqdn_for_redis(dns->query, &dns->state.redis_query_list, &dns->state.redis_query_list_len);
  dns->state.redis_query_list[0].is_key_received = TRUE;
  dns->state.redis_query_list[0].is_key_exists = TRUE;
  result = send_redis_intel_lists(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_true(dns->state.is_redis_query_not_found == FALSE);
  assert_true(dns->state.is_redis_query_error == FALSE);
  assert_true(dns->state.is_redis_query_sended == TRUE);
  loop(counter, 1000, TRUE);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);
  assert_true(strstr(dns->state.redis_response, ",abc,"));
  assert_true(strstr(dns->state.redis_response, ",def,"));
  assert_true(strstr(dns->state.redis_response, ",kls,"));

  // pair->udp_destination_addr = destination;
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  ferrum_protocol_dns_destroy(protocol);
  loop(counter, 100, TRUE);

  rebrick_udpsocket_destroy(dnsclient);
  ferrum_dns_packet_destroy(dns);
  ferrum_dns_db_destroy(dns_db);
  ferrum_redis_destroy(redis);

  loop(counter, 100, TRUE);
  rebrick_free(pair);
}

int32_t send_redis_intel(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns);
static void test_send_redis_intel(void **start) {
  unused(start);
  int32_t counter;
  create_folders();
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_raw_udpsocket_pair_t *pair;
  pair = new1(ferrum_raw_udpsocket_pair_t);
  constructor(pair, ferrum_raw_udpsocket_pair_t);
  // open a upd socket
  const char *dest_ip = "127.0.0.1";
  const char *dest_port = "5555";
  rebrick_sockaddr_t destination;
  rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_t *dnsclient;

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  callbacks.callback_data = NULL;

  result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
  assert_int_equal(result, FERRUM_SUCCESS);
  pair->udp_socket = dnsclient;
  pair->udp_listening_socket = dnsclient;
  pair->client_addr = destination;

  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_packet_new(dns);
  ferrum_dns_packet_from(packet_bytes, sizeof(packet_bytes), dns);

  ferrum_dns_db_t *dns_db;
  result = ferrum_dns_db_new(&dns_db, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_redis_t *redis;
  result = ferrum_redis_new(&redis, "localhost", 6379, NULL, 1000, 1000);

  ferrum_protocol_t *protocol;
  ferrum_protocol_dns_new(&protocol, NULL, NULL, config, NULL, NULL, NULL, dns_db, NULL, NULL);
  protocol->redis_intel = redis;

  flush_redis(redis);
  loop(counter, 100, TRUE);

  // there is no record at intel
  result = send_redis_intel(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  assert_true(dns->state.redis_query_list[0].is_key_sended);
  assert_true(dns->state.redis_query_list[0].is_key_received);
  assert_true(dns->state.redis_query_list[1].is_key_sended);
  assert_true(dns->state.redis_query_list[1].is_key_received);
  assert_true(dns->state.redis_query_list[2].is_key_sended);
  assert_true(dns->state.redis_query_list[2].is_key_received);
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  // set a record

  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 10, 1, flush_redis_callback, redis);
  ferrum_redis_send(redis, cmd, "sadd /fqdn/www.google.com/list abc def kls");
  loop(counter, 1000, TRUE);

  // redis gives error
  redis->is_mock_error = TRUE;
  result = send_redis_intel(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  assert_true(dns->state.redis_query_list[0].is_error);
  redis->is_mock_error = FALSE;
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  // there is record now
  result = send_redis_intel(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  assert_true(dns->state.is_redis_query_sended);
  assert_true(dns->state.is_redis_query_received);
  assert_true(strstr(dns->state.redis_response, ",abc,"));
  assert_true(strstr(dns->state.redis_response, ",def,"));
  assert_true(strstr(dns->state.redis_response, ",kls,"));
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  // set others
  ferrum_redis_cmd_new(&cmd, 10, 1, flush_redis_callback, redis);
  ferrum_redis_send(redis, cmd, "sadd /fqdn/google.com/list ufklm");
  loop(counter, 1000, TRUE);

  // check again
  result = send_redis_intel(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 1000, TRUE);
  assert_true(dns->state.is_redis_query_sended);
  assert_true(dns->state.is_redis_query_received);
  assert_true(strstr(dns->state.redis_response, ",abc,"));
  assert_true(strstr(dns->state.redis_response, ",def,"));
  assert_true(strstr(dns->state.redis_response, ",kls,"));
  rebrick_free_if_not_null_and_set_null(dns->state.redis_query_list);

  // pair->udp_destination_addr = destination;
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  ferrum_protocol_dns_destroy(protocol);
  loop(counter, 100, TRUE);

  rebrick_udpsocket_destroy(dnsclient);
  ferrum_dns_packet_destroy(dns);
  ferrum_dns_db_destroy(dns_db);
  ferrum_redis_destroy(redis);

  loop(counter, 100, TRUE);
  rebrick_free(pair);
}

int32_t process_dns_state(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns);
static void test_process_dns_state(void **start) {
  unused(start);

  unused(start);
  int32_t counter;
  create_folders();
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_raw_udpsocket_pair_t *pair;
  pair = new1(ferrum_raw_udpsocket_pair_t);
  constructor(pair, ferrum_raw_udpsocket_pair_t);
  // open a upd socket
  const char *dest_ip = "127.0.0.1";
  const char *dest_port = "5555";
  rebrick_sockaddr_t destination;
  rebrick_util_to_rebrick_sockaddr(&destination, dest_ip, dest_port);

  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_t *dnsclient;

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  callbacks.callback_data = NULL;

  result = rebrick_udpsocket_new(&dnsclient, &bindaddr, &callbacks);
  assert_int_equal(result, FERRUM_SUCCESS);
  pair->udp_socket = dnsclient;
  pair->udp_listening_socket = dnsclient;
  pair->client_addr = destination;

  uint8_t packet_bytes[] = {
      0x95, 0xd4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xca,
      0x54, 0x42, 0xa1, 0xc4, 0x77, 0xd7, 0x38};

  ferrum_dns_packet_new(dns);
  ferrum_dns_packet_from(packet_bytes, sizeof(packet_bytes), dns);

  ferrum_authz_db_t *authz_db;
  result = ferrum_authz_db_new(&authz_db, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_protocol_t *protocol;
  ferrum_protocol_dns_new(&protocol, NULL, pair, config, NULL, syslog, NULL, NULL, NULL, authz_db);

  dns->state.reply_buf = rebrick_malloc(sizeof(packet_bytes));
  memcpy(dns->state.reply_buf, packet_bytes, sizeof(packet_bytes));
  dns->state.reply_buf_len = sizeof(packet_bytes);

  dns->state.is_redis_query_error = FALSE;
  dns->state.is_redis_query_not_found = FALSE;
  dns->state.is_redis_query_received = FALSE;
  dns->state.is_backend_received = FALSE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  dns->state.is_redis_query_error = FALSE;
  dns->state.is_redis_query_not_found = FALSE;
  dns->state.is_redis_query_received = FALSE;
  dns->state.is_backend_received = TRUE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  dns->state.is_redis_query_error = TRUE;
  dns->state.is_redis_query_not_found = FALSE;
  dns->state.is_redis_query_received = FALSE;
  dns->state.is_backend_received = TRUE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  dns->state.is_redis_query_error = FALSE;
  dns->state.is_redis_query_not_found = TRUE;
  dns->state.is_redis_query_received = FALSE;
  dns->state.is_backend_received = TRUE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  dns->state.is_redis_query_error = FALSE;
  dns->state.is_redis_query_not_found = FALSE;
  dns->state.is_redis_query_received = TRUE;
  dns->state.is_backend_received = TRUE;

  // authz error
  dns->state.authz_id = strdup("abcdefg");
  authz_db->mock_error = TRUE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  // authz not found
  authz_db->mock_error = FALSE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  // authz

  const char *data = "\
[fqdnIntelligence]\
ignoreFqdns = \",google.com,\"\
ignoreLists = \"\"\
whiteFqdns = \"\"\
whiteLists = \"\"\
blackFqdns = \"\"\
blackLists = \"\"\
\
id = \"\"\
userOrgroupIds = \"\"\
";

  authz_db->lmdb->root->key.size = snprintf(authz_db->lmdb->root->key.val, sizeof(authz_db->lmdb->root->key.val) - 1, "%s", "/authz/id/abcdefg");
  authz_db->lmdb->root->value.size = snprintf(authz_db->lmdb->root->value.val, sizeof(authz_db->lmdb->root->value.val) - 1, "%s", data);
  result = ferrum_lmdb_put(authz_db->lmdb, &authz_db->lmdb->root->key, &authz_db->lmdb->root->value);

  // data parse problem
  authz_db->mock_error = FALSE;
  result = process_dns_state(protocol, pair, dns);
  dns->state.redis_response = strdup(",list1,list2,");
  assert_int_equal(result, FERRUM_SUCCESS);

  data = "\
[fqdnIntelligence]\n\
ignoreFqdns = \",google.com,\"\n\
ignoreLists = \"\"\n\
whiteFqdns = \"\"\n\
whiteLists = \"\"\n\
blackFqdns = \"\"\n\
blackLists = \"\"\n\
\n\
id = \"\"\n\
userOrgroupIds = \"\"\n\
";

  authz_db->lmdb->root->key.size = snprintf(authz_db->lmdb->root->key.val, sizeof(authz_db->lmdb->root->key.val) - 1, "/authz/id/abcdefg");
  authz_db->lmdb->root->value.size = snprintf(authz_db->lmdb->root->value.val, sizeof(authz_db->lmdb->root->value.val) - 1, "%s", data);
  result = ferrum_lmdb_put(authz_db->lmdb, &authz_db->lmdb->root->key, &authz_db->lmdb->root->value);

  // data exits in ignore list
  authz_db->mock_error = FALSE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  data = "\
[fqdnIntelligence]\n\
ignoreFqdns = \"\"\n\
ignoreLists = \",list1,\"\n\
whiteFqdns = \"\"\n\
whiteLists = \"\"\n\
blackFqdns = \"\"\n\
blackLists = \"\"\n\
\n\
id = \"\"\n\
userOrgroupIds = \"\"\n\
";

  authz_db->lmdb->root->key.size = snprintf(authz_db->lmdb->root->key.val, sizeof(authz_db->lmdb->root->key.val) - 1, "/authz/id/abcdefg");
  authz_db->lmdb->root->value.size = snprintf(authz_db->lmdb->root->value.val, sizeof(authz_db->lmdb->root->value.val) - 1, "%s", data);
  result = ferrum_lmdb_put(authz_db->lmdb, &authz_db->lmdb->root->key, &authz_db->lmdb->root->value);

  // data exits in ignore list
  authz_db->mock_error = FALSE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  data = "\
[fqdnIntelligence]\n\
ignoreFqdns = \",,\"\n\
ignoreLists = \"\"\n\
whiteFqdns = \",google.com,\"\n\
whiteLists = \"\"\n\
blackFqdns = \"\"\n\
blackLists = \"\"\n\
\n\
id = \"\"\n\
userOrgroupIds = \"\"\n\
";

  authz_db->lmdb->root->key.size = snprintf(authz_db->lmdb->root->key.val, sizeof(authz_db->lmdb->root->key.val) - 1, "/authz/id/abcdefg");
  authz_db->lmdb->root->value.size = snprintf(authz_db->lmdb->root->value.val, sizeof(authz_db->lmdb->root->value.val) - 1, "%s", data);
  result = ferrum_lmdb_put(authz_db->lmdb, &authz_db->lmdb->root->key, &authz_db->lmdb->root->value);

  // data exits in white list
  authz_db->mock_error = FALSE;
  result = process_dns_state(protocol, pair, dns);
  // dns->state.redis_response = strdup(",list1,list2,");
  assert_int_equal(result, FERRUM_SUCCESS);

  data = "\
[fqdnIntelligence]\n\
ignoreFqdns = \",,\"\n\
ignoreLists = \"\"\n\
whiteFqdns = \"\"\n\
whiteLists = \"\"\n\
blackFqdns = \",google.com,\"\n\
blackLists = \"\"\n\
\n\
id = \"\"\n\
userOrgroupIds = \"\"\n\
";

  authz_db->lmdb->root->key.size = snprintf(authz_db->lmdb->root->key.val, sizeof(authz_db->lmdb->root->key.val) - 1, "/authz/id/abcdefg");
  authz_db->lmdb->root->value.size = snprintf(authz_db->lmdb->root->value.val, sizeof(authz_db->lmdb->root->value.val) - 1, "%s", data);
  result = ferrum_lmdb_put(authz_db->lmdb, &authz_db->lmdb->root->key, &authz_db->lmdb->root->value);

  // data exits in black list
  authz_db->mock_error = FALSE;
  result = process_dns_state(protocol, pair, dns);
  assert_int_equal(result, FERRUM_SUCCESS);

  // pair->udp_destination_addr = destination;
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  ferrum_protocol_dns_destroy(protocol);
  loop(counter, 100, TRUE);
  ferrum_authz_db_destroy(authz_db);
  rebrick_udpsocket_destroy(dnsclient);
  ferrum_dns_packet_destroy(dns);
  ferrum_syslog_destroy(syslog);

  loop(counter, 100, TRUE);
  rebrick_free(pair);
}

int test_ferrum_protocol_dns(void) {
  const struct CMUnitTest tests[] = {
      // cmocka_unit_test(test_ferrum_parse_dns_query),
      // cmocka_unit_test(test_ferrum_dns_reply_empty_packet),
      // cmocka_unit_test(test_ferrum_dns_reply_ip_packet),
      // cmocka_unit_test(test_reply_dns_empty),
      // cmocka_unit_test(test_db_get_user_and_group_ids_phase1),
      // cmocka_unit_test(test_send_backend_directly),
      // cmocka_unit_test(test_reply_local_dns),
      // cmocka_unit_test(test_db_get_authz_fqdn_intelligence),
      // cmocka_unit_test(test_merge_fqdn_for_redis),
      // cmocka_unit_test(test_split_fqdn_for_redis),
      // cmocka_unit_test(test_send_redis_intel_lists),
      // cmocka_unit_test(test_send_redis_intel),
      cmocka_unit_test(test_process_dns_state)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
