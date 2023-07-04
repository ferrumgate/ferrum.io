#include "ferrum/ferrum_lmdb.h"
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

static void ferrum_object_create_destroy_success(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  ferrum_lmdb_t *lmdb;
  const char *folder = "/tmp/test4";
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  int32_t result = ferrum_lmdb_new(&lmdb, folder, "ferrumgate", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_lmdb_destroy(lmdb);
}
static void ferrum_object_check_open_file(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  ferrum_lmdb_t *lmdb;
  size_t working_dir_len = 128;
  char working_dir[working_dir_len];
  uv_cwd(working_dir, &working_dir_len);

  fprintf(stdout, "WORKING DIR %s\n", working_dir);
  strncat(working_dir, "/data", 10);
  int32_t result = ferrum_lmdb_new(&lmdb, working_dir, "ferrumgate", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  size_t len = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 1);
  lmdb->root->key.size = len;
  result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(lmdb->root->value.val, "hamza");
  ferrum_lmdb_destroy(lmdb);
}

static void ferrum_object_put_get_del_get(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  ferrum_lmdb_t *lmdb;
  const char *folder = "/tmp/test5";
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  int32_t result = ferrum_lmdb_new(&lmdb, folder, "ferrumgate", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  // save data
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 1);

  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value.val) - 1, "ferrum");

  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  // get again
  lmdb->root->value.size = 0;
  memset(lmdb->root->value.val, 0, sizeof(lmdb->root->value.val));
  result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(lmdb->root->value.val, "ferrum");

  // get not found
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 2);
  result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_ERR_LMDB_ROW_NOT_FOUND);

  // del
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 1);
  result = ferrum_lmdb_del(lmdb, &lmdb->root->key);
  assert_int_equal(result, FERRUM_SUCCESS);

  // get again
  //  get not found
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 1);
  result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_ERR_LMDB_ROW_NOT_FOUND);

  ferrum_lmdb_destroy(lmdb);
}

static void ferrum_object_put_get_del_get_multiple(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);

  const char *folder = "/tmp/test60";
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

  ferrum_lmdb_t *lmdb;
  int32_t result = ferrum_lmdb_new(&lmdb, folder, "ferrumgate", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb2;
  result = ferrum_lmdb_new(&lmdb2, folder, "ferrumgate", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb3;
  result = ferrum_lmdb_new(&lmdb3, folder, "test", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);

  // save data
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 1);
  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value.val) - 1, "ferrum");
  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  // get again
  lmdb->root->value.size = 0;
  memset(lmdb->root->value.val, 0, sizeof(lmdb->root->value.val));
  result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(lmdb->root->value.val, "ferrum");

  // get again
  lmdb2->root->value.size = 0;
  memset(lmdb2->root->value.val, 0, sizeof(lmdb2->root->value.val));
  result = ferrum_lmdb_get(lmdb2, &lmdb2->root->key, &lmdb2->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(lmdb2->root->value.val, "ferrum");

  // get not found
  lmdb3->root->key.size = snprintf(lmdb3->root->key.val, sizeof(lmdb3->root->key.val) - 1, "/test/%d", 2);
  result = ferrum_lmdb_get(lmdb3, &lmdb3->root->key, &lmdb3->root->value);
  assert_int_equal(result, FERRUM_ERR_LMDB_ROW_NOT_FOUND);

  ferrum_lmdb_destroy(lmdb);
  ferrum_lmdb_destroy(lmdb2);
  ferrum_lmdb_destroy(lmdb3);
}

static void ferrum_object_list_all(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  ferrum_lmdb_t *lmdb;
  const char *folder = "/tmp/test5";
  remove_recursive(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  int32_t result = ferrum_lmdb_new(&lmdb, folder, "dns", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  // save data
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 1);

  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value.val) - 1, "ferrum");

  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/test/%d", 2);

  lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value.val) - 1, "ferrum2");

  result = ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  ferrum_lmdb_t *lmdb2;
  result = ferrum_lmdb_new(&lmdb2, folder, "dns", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_lmdb_list_all(lmdb2);
  ferrum_lmdb_destroy(lmdb);
  ferrum_lmdb_destroy(lmdb2);
}

int test_ferrum_lmdb(void) {

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_object_check_open_file),
      cmocka_unit_test(ferrum_object_create_destroy_success),
      cmocka_unit_test(ferrum_object_put_get_del_get),
      cmocka_unit_test(ferrum_object_list_all)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
