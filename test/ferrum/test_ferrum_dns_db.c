#include "./ferrum/ferrum_dns_db.h"
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

static void test_ferrum_dns_db_new_destroy(void **start) {
  unused(start);
  const char *folder = "/tmp/test40";
  setenv("DNS_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_dns_db_t *dns;

  result = ferrum_dns_db_new(&dns, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_dns_db_destroy(dns);
  ferrum_config_destroy(config);
}

static void test_ferrum_dns_db_find_local_a(void **start) {
  unused(start);

  ferrum_lmdb_t *lmdb;

  const char *folder = "/tmp/test40";
  setenv("DNS_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_dns_db_t *dns;

  result = ferrum_dns_db_new(&dns, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  result = ferrum_lmdb_new(&lmdb, folder, "dns", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  char ip[REBRICK_IP_STR_LEN] = {0};
  result = ferrum_dns_db_find_local_a(dns, "ferrumgate.com", ip);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(ip, "");

  // save data
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/local/dns/ferrumgate.com/a");

  lmdb->value.size = snprintf(lmdb->value.val, sizeof(lmdb->value.val) - 1, "192.168.1.1");

  result = ferrum_lmdb_put(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  result = ferrum_dns_db_find_local_a(dns, "ferrumgate.com", ip);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(ip, "192.168.1.1");

  ferrum_lmdb_destroy(lmdb);
  ferrum_dns_db_destroy(dns);
  ferrum_config_destroy(config);
}

int test_ferrum_dns_db(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ferrum_dns_db_new_destroy),
      cmocka_unit_test(test_ferrum_dns_db_find_local_a),
  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
