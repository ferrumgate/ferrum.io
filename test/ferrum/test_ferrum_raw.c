#include "./ferrum/ferrum_raw.h"
#include "../rebrick/server_client/tcpecho.h"
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
  setenv("RAW_DESTINATION_HOST", "localhost", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "80", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_TCP_PORT", "19191", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, local_rebrick_conntrack_get);
  loop(counter, 100, TRUE);

  rebrick_tcpsocket_t *client;
  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &dest);
  new2(rebrick_tcpsocket_callbacks_t, callback);
  callback.on_read = tcp_on_read;
  tcp_readed = 0;
  rebrick_tcpsocket_new(&client, NULL, &dest, 0, &callback);
  loop(counter, 1000, TRUE);

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
  setenv("RAW_DESTINATION_HOST", "localhost", 1);
  setenv("RAW_DESTINATION_TCP_PORT", "81", 1);
  setenv("RAW_LISTEN_IP", "127.0.0.1", 1);
  setenv("RAW_LISTEN_TCP_PORT", "19191", 1);

  result = ferrum_config_new(&config);
  assert_true(result >= 0);
  assert_non_null(config);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, local_rebrick_conntrack_get);
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
}

static void ferrum_raw_tcp_destination_closed(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "localhost", 1);
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
  result = ferrum_policy_new(&policy);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, local_rebrick_conntrack_get);
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
}

static void ferrum_raw_tcp_client_closed(void **start) {
  unused(start);
  ferrum_config_t *config = NULL;
  int32_t result;
  int32_t counter;
  setenv("RAW_DESTINATION_HOST", "localhost", 1);
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
  result = ferrum_policy_new(&policy);

  ferrum_raw_t *raw;
  result = ferrum_raw_new(&raw, config, policy, local_rebrick_conntrack_get);
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

  tcp_echo_stop();
  tcp_echo_close_client();
  tcp_echo_close_server();
  loop(counter, 200, TRUE);
}

int test_ferrum_raw(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_raw_tcp),
      cmocka_unit_test(ferrum_raw_tcp_destination_unreachable),
      cmocka_unit_test(ferrum_raw_tcp_destination_closed),
      cmocka_unit_test(ferrum_raw_tcp_client_closed),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
