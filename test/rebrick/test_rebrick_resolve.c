#include "./rebrick/common/rebrick_resolve.h"
#include "cmocka.h"
#include <unistd.h>
#include <string.h>

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

rebrick_sockaddr_t last_resolved_addr;
int32_t resolved;
static void on_resolve(const char *domain, int32_t type, rebrick_sockaddr_t addr) {

  char current_time_str[32] = {0};
  unused(current_time_str);
  char ip[REBRICK_IP_STR_LEN];
  rebrick_util_addr_to_ip_string(&addr, ip);
  rebrick_log_info("resolve %s type:%d to %s\n", domain, type, ip),
      last_resolved_addr = addr;
  resolved = TRUE;
}

int32_t last_error;
static void on_error(const char *domain, int32_t type, int32_t error) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  rebrick_log_error( "resolve domain %s with type %d failed with error %d \n", domain, type, error);
  last_error = error;
}

static void resolve_google_com_A(void **start) {
  unused(start);
  int32_t result = rebrick_resolve("www.google.com", A, on_resolve, on_error);
  assert_int_equal(result, REBRICK_SUCCESS);
  int32_t counter;
  last_error = 0;
  resolved = FALSE;
  loop(counter, 10000, !resolved);
  assert_int_equal(resolved, TRUE);
  assert_int_equal(last_error, 0);
  assert_int_equal(last_resolved_addr.v4.sin_family, AF_INET);
}

static void resolve_google_com_AAAA(void **start) {
  unused(start);
  int32_t result = rebrick_resolve("www.google.com", AAAA, on_resolve, on_error);
  assert_int_equal(result, REBRICK_SUCCESS);
  int32_t counter;
  last_error = 0;
  resolved = FALSE;
  loop(counter, 10000, !resolved);
  assert_int_equal(resolved, TRUE);
  assert_int_equal(last_error, 0);
  assert_int_equal(last_resolved_addr.v6.sin6_family, AF_INET6);
}

static void resolve_google2_com_failed(void **start) {
  unused(start);
  int32_t result = rebrick_resolve("www.google2.com", A, on_resolve, on_error);
  assert_int_equal(result, REBRICK_SUCCESS);
  int32_t counter;
  last_error = 0;
  resolved = FALSE;
  loop(counter, 10000, !last_error);
  assert_int_equal(resolved, FALSE);
  assert_true(last_error < 0);
}

static void resolve_sync_google_com(void **start) {
  unused(start);
  rebrick_sockaddr_t *addrlist;
  size_t len;
  int32_t result = rebrick_resolve_sync("www.google.com", A, &addrlist, &len);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_not_equal(len, 0);
  assert_ptr_not_equal(addrlist, NULL);
  if (addrlist)
    rebrick_free(addrlist);

  result = rebrick_resolve_sync("www.yahoo.com", A, &addrlist, &len);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_not_equal(len, 0);
  assert_ptr_not_equal(addrlist, NULL);
  if (addrlist)
    rebrick_free(addrlist);

  result = rebrick_resolve_sync("www.ya2hoo2.com", A, &addrlist, &len);
  assert_int_equal(result, REBRICK_ERR_RESOLV);
  assert_int_equal(len, 0);
  assert_ptr_equal(addrlist, NULL);
  if (addrlist)
    rebrick_free(addrlist);

  result = rebrick_resolve_sync("www.hamzakilic.com", AAAA, &addrlist, &len);
  assert_int_equal(result, REBRICK_ERR_RESOLV);
  assert_int_equal(len, 0);
  assert_ptr_equal(addrlist, NULL);
  if (addrlist)
    rebrick_free(addrlist);

  result = rebrick_resolve_sync("1.1.1.1", AAAA, &addrlist, &len);
  assert_int_equal(result, REBRICK_ERR_RESOLV);
  assert_int_equal(len, 0);
  assert_ptr_equal(addrlist, NULL);
  if (addrlist)
    rebrick_free(addrlist);

  result = rebrick_resolve_sync("1.1.1.1", A, &addrlist, &len);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(len, 1);
  assert_ptr_not_equal(addrlist, NULL);
  if (addrlist)
    rebrick_free(addrlist);
}

int test_rebrick_resolve(void) {
  const struct CMUnitTest tests[] = {

      cmocka_unit_test(resolve_google_com_A),
      cmocka_unit_test(resolve_google_com_AAAA),
      cmocka_unit_test(resolve_google2_com_failed),
      cmocka_unit_test(resolve_sync_google_com),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
