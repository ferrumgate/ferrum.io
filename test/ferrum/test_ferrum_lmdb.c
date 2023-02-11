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

static void ferrum_object_create_destroy_success(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  ferrum_lmdb_t *lmdb;
  const char *folder = "/tmp/test4";
  rmdir(folder);
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
  size_t len = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/test/%d", 1);
  lmdb->key.size = len;
  result = ferrum_lmdb_get(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(lmdb->value.val, "hamza");
  ferrum_lmdb_destroy(lmdb);
}

static void ferrum_object_put_get_del_get(void **start) {
  unused(start);
  unused(start);
  char current_time_str[32] = {0};
  unused(current_time_str);
  ferrum_lmdb_t *lmdb;
  const char *folder = "/tmp/test5";
  rmdir(folder);
  mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  int32_t result = ferrum_lmdb_new(&lmdb, folder, "ferrumgate", 0, 0);
  assert_int_equal(result, FERRUM_SUCCESS);
  // save data
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/test/%d", 1);

  lmdb->value.size = snprintf(lmdb->value.val, sizeof(lmdb->value.val) - 1, "ferrum");

  result = ferrum_lmdb_put(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_SUCCESS);

  // get again
  lmdb->value.size = 0;
  memset(lmdb->value.val, 0, sizeof(lmdb->value.val));
  result = ferrum_lmdb_get(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_string_equal(lmdb->value.val, "ferrum");

  // get not found
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/test/%d", 2);
  result = ferrum_lmdb_get(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_ERR_LMDB_ROW_NOT_FOUND);

  // del
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/test/%d", 1);
  result = ferrum_lmdb_del(lmdb, &lmdb->key);
  assert_int_equal(result, FERRUM_SUCCESS);

  // get again
  //  get not found
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/test/%d", 1);
  result = ferrum_lmdb_get(lmdb, &lmdb->key, &lmdb->value);
  assert_int_equal(result, FERRUM_ERR_LMDB_ROW_NOT_FOUND);

  ferrum_lmdb_destroy(lmdb);
}

int test_ferrum_lmdb(void) {

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(ferrum_object_check_open_file),
      cmocka_unit_test(ferrum_object_create_destroy_success),
      cmocka_unit_test(ferrum_object_put_get_del_get),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
