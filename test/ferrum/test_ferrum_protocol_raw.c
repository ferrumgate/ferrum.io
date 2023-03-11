#include "./ferrum/protocol/ferrum_protocol_raw.h"
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
static void raw_process_input_udp(void **start) {
  unused(start);
  int32_t counter;
  ferrum_config_t *config;
  const char *folder = "/tmp/test5";
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  setenv("POLICY_DB_FOLDER", "/tmp/test5", 1);
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_result_t presult;
  memset(&presult, 0, sizeof(presult));
  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &client);

  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19192", &dest);

  ferrum_raw_udpsocket_pair_t pair;
  memset(&pair, 0, sizeof(pair));
  pair.client_addr = client;
  pair.udp_destination_addr = dest;

  rebrick_udpsocket_t *socket;
  new2(rebrick_udpsocket_callbacks_t, callback);

  rebrick_sockaddr_t bind;
  rebrick_util_ip_port_to_addr("127.0.0.1", "0", &bind);
  rebrick_udpsocket_new(&socket, &bind, &callback);

  loop(counter, 1000, TRUE);
  pair.udp_socket = socket;

  ferrum_protocol_t *protocol;
  result = ferrum_protocol_raw_new(&protocol, NULL, &pair, config, policy, syslog);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  protocol->process_input_udp(protocol, cast_to_const_uint8ptr("test"), 5);
  loop(counter, 100, TRUE);

  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);

  protocol->destroy(protocol);
  loop(counter, 100, TRUE);
  setenv("POLICY_DB_FOLDER", "", 1);
  rebrick_udpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

static void raw_process_output_udp(void **start) {
  unused(start);
  int32_t counter;
  ferrum_config_t *config;
  const char *folder = "/tmp/test5";
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  setenv("POLICY_DB_FOLDER", "/tmp/test5", 1);
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_result_t presult;
  memset(&presult, 0, sizeof(presult));
  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &client);

  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19192", &dest);

  ferrum_raw_udpsocket_pair_t pair;
  memset(&pair, 0, sizeof(pair));
  pair.client_addr = client;
  pair.udp_destination_addr = dest;

  rebrick_udpsocket_t *socket;
  new2(rebrick_udpsocket_callbacks_t, callback);
  callback.on_write = on_udp_server_write;
  rebrick_sockaddr_t bind;
  rebrick_util_ip_port_to_addr("127.0.0.1", "0", &bind);
  rebrick_udpsocket_new(&socket, &bind, &callback);
  loop(counter, 1000, TRUE);
  pair.udp_listening_socket = socket;

  ferrum_protocol_t *protocol;
  result = ferrum_protocol_raw_new(&protocol, NULL, &pair, config, policy, syslog);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  protocol->process_output_udp(protocol, cast_to_const_uint8ptr("test"), 5);
  loop(counter, 100, TRUE);

  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  protocol->destroy(protocol);
  setenv("POLICY_DB_FOLDER", "", 1);
  rebrick_udpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

static void raw_process_input_tcp(void **start) {
  unused(start);
  int32_t counter;
  ferrum_config_t *config;
  tcp_echo_start(9595, TRUE);
  tcp_echo_listen();
  const char *folder = "/tmp/test5";
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  setenv("POLICY_DB_FOLDER", "/tmp/test5", 1);
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_result_t presult;
  memset(&presult, 0, sizeof(presult));
  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &client);

  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "9595", &dest);

  ferrum_raw_tcpsocket_pair_t pair;
  memset(&pair, 0, sizeof(pair));
  pair.client_addr = client;

  rebrick_tcpsocket_t *socket;
  new2(rebrick_tcpsocket_callbacks_t, callback);

  rebrick_sockaddr_t bind;
  rebrick_util_ip_port_to_addr("127.0.0.1", "0", &bind);
  rebrick_tcpsocket_new(&socket, NULL, &dest, 0, &callback);
  loop(counter, 1000, TRUE);
  pair.destination = socket;

  ferrum_protocol_t *protocol;
  result = ferrum_protocol_raw_new(&protocol, &pair, NULL, config, policy, syslog);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  protocol->process_input_tcp(protocol, cast_to_const_uint8ptr("test"), 5);
  loop(counter, 100, TRUE);

  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  protocol->destroy(protocol);
  setenv("POLICY_DB_FOLDER", "", 1);
  rebrick_tcpsocket_destroy(socket);
  loop(counter, 100, TRUE);
  tcp_echo_stop();
  tcp_echo_close_client();
  tcp_echo_close_server();
  loop(counter, 100, TRUE);
}

static void raw_process_output_tcp(void **start) {
  unused(start);
  int32_t counter;
  ferrum_config_t *config;
  tcp_echo_start(9595, TRUE);
  tcp_echo_listen();
  const char *folder = "/tmp/test5";
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  setenv("POLICY_DB_FOLDER", "/tmp/test5", 1);
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_syslog_t *syslog;

  result = ferrum_syslog_new(&syslog, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_t *policy;
  result = ferrum_policy_new(&policy, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  ferrum_policy_result_t presult;
  memset(&presult, 0, sizeof(presult));
  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("127.0.0.1", "19191", &client);

  rebrick_sockaddr_t dest;
  rebrick_util_ip_port_to_addr("127.0.0.1", "9595", &dest);

  ferrum_raw_tcpsocket_pair_t pair;
  memset(&pair, 0, sizeof(pair));
  pair.client_addr = client;

  rebrick_tcpsocket_t *socket;
  new2(rebrick_tcpsocket_callbacks_t, callback);

  rebrick_sockaddr_t bind;
  rebrick_util_ip_port_to_addr("127.0.0.1", "0", &bind);
  rebrick_tcpsocket_new(&socket, NULL, &dest, 0, &callback);
  loop(counter, 1000, TRUE);
  pair.source = socket;

  ferrum_protocol_t *protocol;
  result = ferrum_protocol_raw_new(&protocol, &pair, NULL, config, policy, syslog);
  assert_int_equal(result, FERRUM_SUCCESS);
  loop(counter, 100, TRUE);

  protocol->process_output_tcp(protocol, cast_to_const_uint8ptr("test"), 5);
  loop(counter, 100, TRUE);

  loop(counter, 100, TRUE);
  ferrum_syslog_destroy(syslog);
  loop(counter, 100, TRUE);
  ferrum_policy_destroy(policy);
  loop(counter, 100, TRUE);
  ferrum_config_destroy(config);
  loop(counter, 100, TRUE);
  protocol->destroy(protocol);
  setenv("POLICY_DB_FOLDER", "", 1);
  rebrick_tcpsocket_destroy(socket);
  loop(counter, 100, TRUE);
  tcp_echo_stop();
  tcp_echo_close_client();
  tcp_echo_close_server();
  loop(counter, 100, TRUE);
}

int test_ferrum_protocol_raw(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(raw_process_input_udp),
      cmocka_unit_test(raw_process_output_udp),
      cmocka_unit_test(raw_process_input_tcp),
      cmocka_unit_test(raw_process_output_tcp),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
