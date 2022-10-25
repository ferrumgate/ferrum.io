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

int test_rebrick_util(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(null_test_success),
      cmocka_unit_test(linked_items_success),
      cmocka_unit_test(test_string_to_rebrick_socket_success)};

  return cmocka_run_group_tests(tests, setup, teardown);
}
