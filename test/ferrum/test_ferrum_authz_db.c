#include "./ferrum/ferrum_authz_db.h"
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

static void test_ferrum_authz_db_new_destroy(void **start) {
  unused(start);
  const char *folder = "/tmp/test42";
  setenv("AUTHZ_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_authz_db_t *authz;

  result = ferrum_authz_db_new(&authz, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_authz_db_destroy(authz);
  ferrum_config_destroy(config);
  setenv("AUTHZ_DB_FOLDER", "", 1);
}

static void test_ferrum_authz_db_get_service_get_updatetime(void **start) {
  unused(start);

  ferrum_lmdb_t *lmdb;

  const char *folder = "/tmp/test42";
  setenv("AUTHZ_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_authz_db_t *authz;

  result = ferrum_authz_db_new(&authz, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  result = ferrum_lmdb_new(&lmdb, folder, "authz", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/service/id/2/user/list/updateTime");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "%d", 1000);
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  int64_t time;
  result = ferrum_authz_db_get_service_user_update_time(authz, "2", &time);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(time, 1000);

  result = ferrum_authz_db_get_service_user_update_time(authz, "3", &time);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(time, 0);

  ferrum_authz_db_service_user_row_t *row;
  result = ferrum_authz_db_get_service_user_data(authz, "3", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(row);

  // not valid data
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/service/id/2/user/list");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1,
                                    "\
[[rules]]\n \
userOrgroupIds=\",abc,def,\"\
id=\"gssh\"\
  ");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  result = ferrum_authz_db_get_service_user_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_ERR_AUTHZ_DB_PARSE);
  assert_null(row);

  // valid data but no rules

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/service/id/2/user/list");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1,
                                    "\
[[rules2]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\
  ");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  result = ferrum_authz_db_get_service_user_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(row);

  // valid data 1 rule

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/service/id/2/user/list");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1,
                                    "\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\
  ");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  result = ferrum_authz_db_get_service_user_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_non_null(row);
  assert_non_null(row->rows);
  assert_int_equal(row->rows_len, 1);
  assert_string_equal(row->rows[0].authz_id, "gssh");
  assert_string_equal(row->rows[0].user_or_group_ids, ",abc,def,");
  ferrum_authz_db_service_user_row_destroy(row);

  // valid data 2 rules
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/service/id/2/user/list");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1,
                                    "\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\
  ");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  result = ferrum_authz_db_get_service_user_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_non_null(row);
  assert_non_null(row->rows);
  assert_int_equal(row->rows_len, 2);
  assert_string_equal(row->rows[0].authz_id, "gssh");
  assert_string_equal(row->rows[0].user_or_group_ids, ",abc,def,");
  assert_string_equal(row->rows[1].authz_id, "1gssh");
  assert_string_equal(row->rows[1].user_or_group_ids, ",1abc,def,");
  ferrum_authz_db_service_user_row_destroy(row);

  // valid data realloc data
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/service/id/2/user/list");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1,
                                    "\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",abc,def,\"\n\
id=\"gssh\"\n\
[[rules]]\n\
userOrgroupIds=\",1abc,def,\"\n\
id=\"1gssh\"\n\
  ");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  result = ferrum_authz_db_get_service_user_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_non_null(row);
  assert_non_null(row->rows);
  assert_int_equal(row->rows_len, 20);
  ferrum_authz_db_service_user_row_destroy(row);

  ferrum_lmdb_destroy(lmdb);
  ferrum_authz_db_destroy(authz);
  ferrum_config_destroy(config);
}

static void test_ferrum_authz_db_get_authz_updatetime(void **start) {
  unused(start);

  ferrum_lmdb_t *lmdb;

  const char *folder = "/tmp/test42";
  setenv("AUTHZ_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_authz_db_t *authz;

  result = ferrum_authz_db_new(&authz, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  result = ferrum_lmdb_new(&lmdb, folder, "authz", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/id/2/updateTime");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "%d", 1000);
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  int64_t time;
  result = ferrum_authz_db_get_authz_update_time(authz, "2", &time);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(time, 1000);

  result = ferrum_authz_db_get_authz_update_time(authz, "3", &time);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(time, 0);

  // not found
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/id/3");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "id=\"gssh\"");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  ferrum_authz_db_authz_row_t *row;
  result = ferrum_authz_db_get_authz_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_null(row);

  // data
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/authz/id/2");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "id=\"gssh\"");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);

  result = ferrum_authz_db_get_authz_data(authz, "2", &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_non_null(row);
  assert_non_null(row->content);
  assert_string_equal(row->content, "id=\"gssh\"");
  ferrum_authz_db_authz_row_destroy(row);

  ferrum_lmdb_destroy(lmdb);
  ferrum_authz_db_destroy(authz);
  ferrum_config_destroy(config);
}

int test_ferrum_authz_db(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ferrum_authz_db_get_service_get_updatetime),
      cmocka_unit_test(test_ferrum_authz_db_get_authz_updatetime),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
