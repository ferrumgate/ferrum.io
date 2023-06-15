#include "./ferrum/ferrum_raw.h"
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

static int remove_recursive(const char *const path) {
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

const char *policy_db_folder = "/tmp/abc";
const char *dns_db_folder = "/tmp/abcd";
static int setup(void **state) {

  unused(state);
  setenv("POLICY_DB_FOLDER", policy_db_folder, 1);
  setenv("DISABLE_POLICY", "true", 1);
  mkdir(policy_db_folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  setenv("DNS_DB_FOLDER", dns_db_folder, 1);
  mkdir(dns_db_folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  fprintf(stdout, "****  %s ****\n", __FILE__);
  return 0;
}

static int teardown(void **state) {
  unused(state);
  setenv("POLICY_DB_FOLDER", "", 1);
  setenv("DNS_DB_FOLDER", "", 1);
  setenv("DISABLE_POLICY", "", 1);
  uv_loop_close(uv_default_loop());
  return 0;
}

static int test = 0;

static int32_t callback(void *data) {
  unused(data);
  test++;
  return test;
}
int tcp_readed = 0;
static void tcp_on_read(rebrick_socket_t *socket, void *callback_data,
                        const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(socket);
  unused(callback_data);
  unused(addr);
  unused(buffer);

  tcp_readed += len;
}

static int32_t local_rebrick_conntrack_get(const struct sockaddr *peer, const struct sockaddr *local_addr,
                                           int istcp, rebrick_conntrack_t *track) {
  unused(peer);
  unused(local_addr);
  unused(istcp);
  unused(track);
  return FERRUM_SUCCESS;
}

static void ferrum_raw_tcp(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "80", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_TCP_PORT", "19191", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  rebrick_tcpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &dest);
  new2(rebrick_tcpsocket_callbacks_t, callback);
  callback.on_read = tcp_on_read;
  tcp_readed = 0;
  rebrick_tcpsocket_new(&client, NULL, &dest, 0, &callback);
  loop(counter, 10000, TRUE);

  char *head = "GET /100m.ignore.txt HTTP/1.1\r\n\
Host: nodejs.org\r\n\
User-Agent: ferrum\r\n\
Accept: text/html\r\n\
\r\n";
  new2(rebrick_clean_func_t, clean_func);
  rebrick_tcpsocket_write(client, (uint8_t *)head, strlen(head), clean_func);
  loop(counter, 20000, TRUE);
  assert_int_equal(tcp_readed, 0x6400118);

  rebrick_tcpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);
}

int tcp_error_occured = 0;
static void on_tcp_error(rebrick_socket_t *socket, void *callbackdata, int32_t error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  tcp_error_occured = 1;
}

static void ferrum_raw_tcp_destination_unreachable(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "81", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_TCP_PORT", "19191", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  loop(counter, 100, TRUE);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  rebrick_tcpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &dest);
  new2(rebrick_tcpsocket_callbacks_t, callback);
  callback.on_read = tcp_on_read;
  callback.on_error = on_tcp_error;
  tcp_readed = 0;
  tcp_error_occured = FALSE;
  rebrick_tcpsocket_new(&client, NULL, &dest, 0, &callback);
  loop(counter, 1000, TRUE);
  assert_int_equal(tcp_readed, 0);
  assert_int_equal(tcp_error_occured, TRUE);

  rebrick_tcpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);
}

static void ferrum_raw_tcp_destination_closed(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "9595", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_TCP_PORT", "19191", 1);

  tcp_echo_start(9595, TRUE);
  tcp_echo_listen();
  loop(counter, 20, TRUE);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  loop(counter, 100, TRUE);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  rebrick_tcpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &dest);
  new2(rebrick_tcpsocket_callbacks_t, callback);
  callback.on_read = tcp_on_read;
  callback.on_error = on_tcp_error;
  tcp_readed = 0;
  tcp_error_occured = FALSE;
  rebrick_tcpsocket_new(&client, NULL, &dest, 0, &callback);
  loop(counter, 1000, TRUE);
  char *hello = "hello";
  new2(rebrick_clean_func_t, clean_func);
  rebrick_tcpsocket_write(client, (uint8_t *)hello, strlen(hello), clean_func);
  loop(counter, 200, TRUE);
  tcp_echo_send(hello);
  loop(counter, 200, TRUE);
  assert_true(tcp_readed > 0);

  tcp_echo_stop();
  loop(counter, 200, TRUE);
  tcp_echo_close_client();
  tcp_echo_close_server();
  loop(counter, 200, TRUE);
  assert_int_equal(tcp_error_occured, TRUE);

  rebrick_tcpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);

  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);
}

static void ferrum_raw_tcp_client_closed(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "9595", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_TCP_PORT", "19191", 1);

  tcp_echo_start(9595, TRUE);
  tcp_echo_listen();
  loop(counter, 20, TRUE);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  rebrick_tcpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &dest);
  new2(rebrick_tcpsocket_callbacks_t, callback);
  callback.on_read = tcp_on_read;
  callback.on_error = on_tcp_error;
  tcp_readed = 0;
  tcp_error_occured = FALSE;
  rebrick_tcpsocket_new(&client, NULL, &dest, 0, &callback);
  loop(counter, 1000, TRUE);
  char *hello = "hello";
  new2(rebrick_clean_func_t, clean_func);
  rebrick_tcpsocket_write(client, (uint8_t *)hello, strlen(hello), clean_func);
  loop(counter, 200, TRUE);
  tcp_echo_send(hello);
  loop(counter, 200, TRUE);
  assert_true(tcp_readed > 0);

  loop(counter, 200, TRUE);

  rebrick_tcpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);

  tcp_echo_stop();
  tcp_echo_close_client();
  tcp_echo_close_server();
  loop(counter, 200, TRUE);
}

static int32_t received_dns_count = 0;
static void on_dnsclient_received(rebrick_socket_t *socket, void *data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(addr);
  unused(socket);
  unused(data);
  unused(buffer);
  unused(len);

  received_dns_count++;
}

static void ferrum_raw_udp(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_UDP_PORT", "5555", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_UDP_PORT", "8888", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  // read a sample dns packet
  char *testdata;
  size_t datalen;

  rebrick_udpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "8888", &dest);
  new2(rebrick_udpsocket_callbacks_t, callback);
  callback.on_read = on_dnsclient_received;
  received_dns_count = 0;
  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_new(&client, &bindaddr, &callback);
  loop(counter, 1000, TRUE);

  result = rebrick_util_file_read_allbytes("../test/rebrick/testdata/testpacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("../rebrick/testdata/testpacket1.packet", &testdata, &datalen);
  assert_int_equal(datalen, 37);
  new2(rebrick_clean_func_t, clean_func);

  rebrick_udpsocket_write(client, &dest, (uint8_t *)testdata, datalen, clean_func);
  loop(counter, 10000, !received_dns_count);
  assert_int_equal(received_dns_count, 1);
  rebrick_udpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);

  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);
  rebrick_free(testdata);
}

static void ferrum_raw_udp_disconnected_client(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_UDP_PORT", "5555", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_UDP_PORT", "8888", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  // read a sample dns packet
  char *testdata;
  size_t datalen;

  rebrick_udpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "8888", &dest);
  new2(rebrick_udpsocket_callbacks_t, callback);
  callback.on_read = on_dnsclient_received;
  received_dns_count = 0;
  rebrick_sockaddr_t bindaddr;
  rebrick_util_to_rebrick_sockaddr(&bindaddr, "0.0.0.0", "0");
  rebrick_udpsocket_new(&client, &bindaddr, &callback);
  loop(counter, 1000, TRUE);

  result = rebrick_util_file_read_allbytes("../test/rebrick/testdata/testpacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("../rebrick/testdata/testpacket1.packet", &testdata, &datalen);
  assert_int_equal(datalen, 37);
  new2(rebrick_clean_func_t, clean_func);

  rebrick_udpsocket_write(client, &dest, (uint8_t *)testdata, datalen, clean_func);
  loop(counter, 1, TRUE); // dont wait

  rebrick_udpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);

  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);

  rebrick_free(testdata);
}

int udp_error_occured = 0;
static void on_udp_error(rebrick_socket_t *socket, void *callbackdata, int32_t error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  udp_error_occured = 1;
}

static void ferrum_raw_udp_closed_destination(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "127.0.0.1", 1);
  setenv("RAW_DESTINATION_UDP_PORT", "9192", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_UDP_PORT", "19191", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_dns_db_t *dns;
  result = ferrum_dns_db_new(&dns, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_syslog_t *syslog;
  result = ferrum_syslog_new(&syslog, config);
  loop(counter, 100, TRUE);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, syslog, NULL, dns, NULL, NULL, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  rebrick_udpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &dest);
  new2(rebrick_udpsocket_callbacks_t, callback);
  callback.on_read = on_dnsclient_received;
  callback.on_error = on_udp_error;
  rebrick_sockaddr_t bind;
  rebrick_util_ip_port_to_addr("127.0.0.1", "0", &bind);
  rebrick_udpsocket_new(&client, &bind, &callback);
  loop(counter, 1000, TRUE);
  char *hello = "hello";
  new2(rebrick_clean_func_t, clean_func);
  received_dns_count = 0;
  udp_error_occured = 0;
  rebrick_udpsocket_write(client, &dest, (uint8_t *)hello, strlen(hello), clean_func);
  loop(counter, 200, TRUE);
  assert_true(received_dns_count == 0);
  assert_int_equal(udp_error_occured, FALSE);

  rebrick_udpsocket_destroy(client);
  loop(counter, 100, TRUE);
  ferrum_raw_destroy(raw);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);

  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);

  ferrum_dns_db_destroy(dns);
  loop(counter, 100, TRUE);
}

int test_ferrum_raw(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_raw_tcp),
      cmocka_unit_test(ferrum_raw_tcp_destination_unreachable),
      cmocka_unit_test(ferrum_raw_tcp_destination_closed),
      cmocka_unit_test(ferrum_raw_tcp_client_closed),
      cmocka_unit_test(ferrum_raw_udp),
      cmocka_unit_test(ferrum_raw_udp_disconnected_client),
      cmocka_unit_test(ferrum_raw_udp_closed_destination),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
