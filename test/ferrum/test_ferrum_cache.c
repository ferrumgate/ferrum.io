#include "./ferrum/cache/ferrum_cache.h"
#include "cmocka.h"

static int setup(void **state) {
  unused(state);
  fprintf(stdout, "****  %s ****\n", __FILE__);
  return 0;
}

static int teardown(void **state) {
  unused(state);
  return 0;
}

static void cache_object_create_destroy(void **start) {
  unused(start);

  int32_t result;
  ferrum_cache_t *cache;
  result = ferrum_cache_new(&cache, 1000);
  assert_int_equal(result, FERRUM_SUCCESS);
  ferrum_cache_destroy(cache);
}

int test_ferrum_cache(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(cache_object_create_destroy),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
