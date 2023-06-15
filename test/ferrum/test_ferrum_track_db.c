#include "./ferrum/ferrum_track_db.h"
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

static void test_ferrum_track_db_new_destroy(void **start) {
  unused(start);
  const char *folder = "/tmp/test41";
  setenv("TRACK_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_track_db_t *track;

  result = ferrum_track_db_new(&track, config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_track_db_destroy(track);
  ferrum_config_destroy(config);
  setenv("TRACK_DB_FOLDER", "", 1);
}

static void test_ferrum_track_db_get_data_get_updatetime(void **start) {
  unused(start);

  ferrum_lmdb_t *lmdb;

  const char *folder = "/tmp/test41";
  setenv("TRACK_DB_FOLDER", folder, 1);
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  ferrum_config_t *config;
  int32_t result = ferrum_config_new(&config);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_track_db_t *track;

  result = ferrum_track_db_new(&track, config);
  assert_int_equal(result, FERRUM_SUCCESS);

  result = ferrum_lmdb_new(&lmdb, folder, "track", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/track/id/2/data");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "userId=\"axd\"\ngroupIds=\",abc,def,\"");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/track/id/2/updateTime");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "%d", 1000);
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);

  int64_t time;
  result = ferrum_track_db_get_update_time(track, 2, &time);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(time, 1000);

  ferrum_track_db_row_t *row;
  result = ferrum_track_db_get_data(track, 2, &row);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(row->user_id, "axd");
  assert_string_equal(row->group_ids, ",abc,def,");
  ferrum_track_db_row_destroy(row);

  // parse error
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/track/id/2/data");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "[userId:\"axd\"\ngroupIds=\",abc,def,\"");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  result = ferrum_track_db_get_data(track, 2, &row);
  assert_int_equal(result, FERRUM_ERR_TRACK_DB_PARSE);

  // userId not ok
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/track/id/2/data");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "userId2=\"axd\"\ngroupIds=\",abc,def,\"");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  result = ferrum_track_db_get_data(track, 2, &row);
  assert_int_equal(result, FERRUM_ERR_TRACK_DB_PARSE);

  // groupids not ok
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "/track/id/2/data");
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "userId=\"axd\"\ngroupIds2=\",,\"");
  ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  result = ferrum_track_db_get_data(track, 2, &row);
  assert_int_equal(result, FERRUM_ERR_TRACK_DB_PARSE);

  ferrum_lmdb_destroy(lmdb);
  ferrum_track_db_destroy(track);
  ferrum_config_destroy(config);
}

int test_ferrum_track_db(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ferrum_track_db_get_data_get_updatetime),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
