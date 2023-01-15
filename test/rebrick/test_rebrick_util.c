#include "./rebrick/common/rebrick_util.h"
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
/* A test case that does nothing and succeeds. */
static void null_test_success(void **state) {

  unused(state);
}

static void linked_items_success(void **start) {
  unused(start);
  char *str = "";
  rebrick_linked_item_t *list;

  str = "hamza";

  list = rebrick_util_create_linked_items(str, ".");
  assert_true(list);
  assert_true(rebrick_util_linked_item_count(list) == 1);
  rebrick_util_linked_item_destroy(list);

  str = "";

  list = rebrick_util_create_linked_items(str, ".");
  assert_true(!list);
  rebrick_util_linked_item_destroy(list);

  str = ".";

  list = rebrick_util_create_linked_items(str, ".");
  assert_true(!list);
  rebrick_util_linked_item_destroy(list);

  str = "..";

  list = rebrick_util_create_linked_items(str, ".");
  assert_true(!list);
  rebrick_util_linked_item_destroy(list);

  str = ".,";

  list = rebrick_util_create_linked_items(str, ".");
  assert_true(list);
  assert_true(rebrick_util_linked_item_count(list) == 1);
  rebrick_util_linked_item_destroy(list);

  str = ".,.";

  list = rebrick_util_create_linked_items(str, ".");
  assert_true(list);
  assert_true(rebrick_util_linked_item_count(list) == 1);
  rebrick_util_linked_item_destroy(list);

  str = ".,.";

  list = rebrick_util_create_linked_items(str, ",");

  assert_true(list);
  assert_true(rebrick_util_linked_item_count(list) == 2);
  rebrick_util_linked_item_destroy(list);
}

static void test_string_to_rebrick_socket_success() {
  const char *ipv4 = "192.168.1.1";
  const char *port = "9091";
  rebrick_sockaddr_t addr;
  int32_t result = rebrick_util_to_rebrick_sockaddr(&addr, ipv4, port);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET);
  assert_int_equal(ntohs(addr.v4.sin_port), 9091);
  char buff[128];

  inet_ntop(AF_INET, &addr.v4.sin_addr, buff, sizeof(buff));
  assert_string_equal(buff, ipv4);

  rebrick_util_addr_to_ip_string(&addr, buff);
  assert_string_equal(buff, ipv4);
  rebrick_util_addr_to_port_string(&addr, buff);
  assert_string_equal(buff, port);

  const char *ipv6 = "2001:db8:85a3::8a2e:370:7334";

  result = rebrick_util_to_rebrick_sockaddr(&addr, ipv6, port);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET6);

  inet_ntop(AF_INET6, &addr.v6.sin6_addr, buff, sizeof(buff));
  assert_string_equal(buff, ipv6);

  char *anyipv4 = "0.0.0.0";
  result = rebrick_util_to_rebrick_sockaddr(&addr, anyipv4, port);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET);

  inet_ntop(AF_INET, &addr.v4.sin_addr, buff, sizeof(buff));
  assert_string_equal(buff, anyipv4);

  const char *anyipv6 = "::";

  result = rebrick_util_to_rebrick_sockaddr(&addr, anyipv6, port);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET6);

  inet_ntop(AF_INET6, &addr.v6.sin6_addr, buff, sizeof(buff));
  assert_string_equal(buff, anyipv6);
}

static void test_rebrick_resolve_sync() {
  const char *domain = "www.google.com";
  rebrick_sockaddr_t addr;
  int32_t result = rebrick_util_resolve_sync(domain, &addr, 90);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET6);
  assert_int_equal(ntohs(addr.v6.sin6_port), 90);
  assert_int_not_equal(addr.v6.sin6_addr.__in6_u.__u6_addr16, 0);

  domain = "1.1.1.1:514";
  result = rebrick_util_resolve_sync(domain, &addr, 3);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET);
  assert_int_equal(ntohs(addr.v4.sin_port), 514);
  assert_int_equal(addr.v4.sin_addr.s_addr, 16843009);

  domain = "www.baidu.com:514";
  result = rebrick_util_resolve_sync(domain, &addr, 3);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(addr.base.sa_family, AF_INET);
  assert_int_equal(ntohs(addr.v4.sin_port), 514);
  assert_int_not_equal(addr.v4.sin_addr.s_addr, 0);
}
static void test_rebrick_util_to_int64_t() {
  int result;
  int64_t val;

  result = rebrick_util_to_int64_t("0", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, 0);

  result = rebrick_util_to_int64_t("-1", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, -1);

  result = rebrick_util_to_int64_t("9223372036854775807", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, 9223372036854775807);

  result = rebrick_util_to_int64_t("92233720368547758071", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);

  result = rebrick_util_to_int64_t("-9223372036854775808", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  // assert_int_equal(val, -9223372036854775808);

  result = rebrick_util_to_int64_t("-92233720368547758081", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);

  result = rebrick_util_to_int64_t("abc", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);
}

static void test_rebrick_util_to_int32_t() {
  int result;
  int32_t val;

  result = rebrick_util_to_int32_t("0", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, 0);

  result = rebrick_util_to_int32_t("-1", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, -1);

  result = rebrick_util_to_int32_t("2147483647", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, 2147483647);

  result = rebrick_util_to_int32_t("9147483647", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);

  result = rebrick_util_to_int32_t("-2147483648", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, -2147483648);

  result = rebrick_util_to_int32_t("-21474836481", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);
}

static void test_rebrick_util_to_uint32_t() {
  int result;
  uint32_t val;

  result = rebrick_util_to_uint32_t("0", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, 0);

  result = rebrick_util_to_uint32_t("-1", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);

  result = rebrick_util_to_uint32_t("4294967295", &val);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_int_equal(val, 4294967295);

  result = rebrick_util_to_uint32_t("42949672951", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);

  result = rebrick_util_to_uint32_t("-21474836481", &val);
  assert_int_equal(result, REBRICK_ERR_BAD_ARGUMENT);
}

static void test_rebrick_util_fill_random(void **start) {
  unused(start);
  char test[16] = {0};
  rebrick_util_fill_random(test, 15);
  assert_true(strlen(test));
}

int test_rebrick_util(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(null_test_success),
      cmocka_unit_test(linked_items_success),
      cmocka_unit_test(test_string_to_rebrick_socket_success),
      cmocka_unit_test(test_rebrick_resolve_sync),
      cmocka_unit_test(test_rebrick_util_to_int64_t),
      cmocka_unit_test(test_rebrick_util_to_int32_t),
      cmocka_unit_test(test_rebrick_util_to_uint32_t),
      cmocka_unit_test(test_rebrick_util_fill_random),
  };

  return cmocka_run_group_tests(tests, setup, teardown);
}
