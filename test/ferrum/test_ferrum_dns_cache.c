#include "./ferrum/cache/ferrum_dns_cache.h"
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

static void dns_cache_page_object_create(void **start) {
  unused(start);
  int32_t result;
  ferrum_dns_cache_page_t *page;
  int32_t timeoutms = 10000;
  // int64_t now=ferrum_util_micro_time();
  result = ferrum_dns_cache_page_new(&page, timeoutms);
  assert_int_equal(result, 0);
  assert_true(page->drop_time > page->can_last_insert_time);
  int64_t diff = page->drop_time - page->can_last_insert_time;
  assert_int_equal(diff, timeoutms * 1000);
  result = ferrum_dns_cache_page_destroy(page);
  assert_int_equal(result, 0);
}

static void dns_cache_page_add_item() {

  int32_t result;
  ferrum_dns_cache_page_t *page;
  int32_t timeoutms = 10000;

  result = ferrum_dns_cache_page_new(&page, timeoutms);
  assert_int_equal(result, 0);

  result = ferrum_dns_cache_page_add_item(page, 0, NULL);
  assert_int_not_equal(result, 0);

  char *testdata;
  size_t datalen;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  ferrum_dns_packet_new(dnspacket);

  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  free(testdata);

  ferrum_dns_cache_page_add_item(page, dnspacket->query_crc, dnspacket);
  assert_int_equal(page->cache_len, 1);
  int32_t hashcount = HASH_COUNT(page->table);
  assert_int_equal(hashcount, 1);

  // add other packet

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket2);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket2);
  assert_int_equal(result, 0);
  dnspacket2->source = client;
  free(testdata);

  ferrum_dns_cache_page_add_item(page, dnspacket2->query_crc, dnspacket2);
  assert_int_equal(page->cache_len, 2);
  hashcount = HASH_COUNT(page->table);
  assert_int_equal(hashcount, 2);

  // add same packet again

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket3);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket3);
  assert_int_equal(result, 0);
  dnspacket3->source = client;
  free(testdata);

  ferrum_dns_cache_page_add_item(page, dnspacket3->query_crc, dnspacket3);
  assert_int_equal(page->cache_len, 3);
  hashcount = HASH_COUNT(page->table);
  assert_int_equal(hashcount, 2);
  ferrum_dns_cache_item_t *fitem = NULL;
  HASH_FIND_INT(page->table, &dnspacket3->query_crc, fitem);
  assert_non_null(fitem);
  int count = 0;
  ferrum_list_item_t *tmp;
  DL_COUNT(fitem->dnslist, tmp, count);
  assert_int_equal(count, 2);

  result = ferrum_dns_cache_page_destroy(page);
  assert_int_equal(result, 0);
}

static void dns_cache_page_find_item_and_remove() {

  int32_t result;
  ferrum_dns_cache_page_t *page;
  int32_t timeoutms = 10000;

  result = ferrum_dns_cache_page_new(&page, timeoutms);
  assert_int_equal(result, 0);

  result = ferrum_dns_cache_page_add_item(page, 0, NULL);
  assert_int_not_equal(result, 0);

  ////////////add some test data //////////////////////////
  rebrick_sockaddr_t server;
  rebrick_util_ip_port_to_addr("192.168.1.1", "53", &server);
  char *testdata;
  size_t datalen;
  /////////packet1
  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  ferrum_dns_packet_new(dnspacket);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  free(testdata);
  dnspacket->destination = server;

  ///////////packet2

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket2);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket2);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  free(testdata);
  dnspacket2->destination = server;

  /////////packet3

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket3);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket3);
  assert_int_equal(result, 0);
  dnspacket3->source = client;
  free(testdata);
  dnspacket3->destination = server;

  ///////////////// test data finished ///////////////////////////////////

  ferrum_dns_cache_page_add_item(page, dnspacket->query_crc, dnspacket);
  ferrum_dns_cache_page_add_item(page, dnspacket2->query_crc, dnspacket2);
  ferrum_dns_cache_page_add_item(page, dnspacket3->query_crc, dnspacket3);

  ////////////////find items////////////////////

  ferrum_dns_cache_founded_t founded;
  fill_zero(&founded, sizeof(founded));
  result = ferrum_dns_cache_page_find_item(page, dnspacket2->query_crc, dnspacket2->query_newid, &server, dnspacket2->query, &founded);
  assert_true(result == 0);
  assert_non_null(founded.dns);

  fill_zero(&founded, sizeof(founded));
  result = ferrum_dns_cache_page_find_item(page, 12, dnspacket2->query_newid, &server, dnspacket2->query, &founded);
  assert_true(result == 0);
  assert_null(founded.dns);

  /////////////////// remove  founded item/////////////////////////
  fill_zero(&founded, sizeof(founded));
  result = ferrum_dns_cache_page_find_item(page, dnspacket2->query_crc, dnspacket2->query_newid, &server, dnspacket2->query, &founded);
  int32_t saved = page->cache_len;
  result = ferrum_dns_cache_page_remove_item(page, &founded);
  assert_true(result == 0);
  assert_int_equal(page->cache_len, saved - 1);
  assert_null(founded.cache_item);

  //////////////add same packets twice
  ///////////packet4

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket4);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket4);
  assert_int_equal(result, 0);
  free(testdata);
  dnspacket4->destination = server;

  ///////////packet5

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket5);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket5);
  assert_int_equal(result, 0);
  dnspacket5->source = client;
  free(testdata);
  dnspacket5->destination = server;

  ferrum_dns_cache_page_add_item(page, dnspacket4->query_crc, dnspacket4);
  ferrum_dns_cache_page_add_item(page, dnspacket5->query_crc, dnspacket5);

  //////////////////////////////added packets////////

  fill_zero(&founded, sizeof(founded));
  result = ferrum_dns_cache_page_find_item(page, dnspacket4->query_crc, dnspacket4->query_newid, &server, dnspacket4->query, &founded);
  saved = page->cache_len;
  result = ferrum_dns_cache_page_remove_item(page, &founded);
  assert_true(result == 0);
  assert_int_equal(page->cache_len, saved - 1);
  assert_non_null(founded.cache_item->dnslist);

  result = ferrum_dns_cache_page_destroy(page);
  assert_int_equal(result, 0);
}

int test_ferrum_dns_cache_page(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(dns_cache_page_object_create),
      cmocka_unit_test(dns_cache_page_add_item),
      cmocka_unit_test(dns_cache_page_find_item_and_remove)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}

/////////////////////// ferrum_dns_cache /////////////////////

static void qcache_object_create(void **start) {
  unused(start);
  int32_t timeout = 10000;
  int32_t result;

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  /// test data

  char *testdata;
  size_t datalen;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  free(testdata);
  //////////////////////////////////////

  char *testdata2;
  size_t datalen2;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata2, &datalen2);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata2, &datalen2);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket2);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata2), datalen2, dnspacket2);
  assert_int_equal(result, 0);
  dnspacket2->source = client;
  free(testdata2);

  ////////////////////////////////////////////

  ferrum_dns_cache_t *qcache;
  result = ferrum_dns_cache_new(&qcache, timeout);
  assert_int_equal(result, 0);

  ///////
  result = ferrum_dns_cache_add(qcache, dnspacket);
  assert_int_equal(result, 0);

  size_t pagelen;
  result = ferrum_dns_cache_get_pageslen(qcache, &pagelen);
  assert_int_equal(pagelen, 1);

  // add other packet

  result = ferrum_dns_cache_add(qcache, dnspacket2);
  assert_int_equal(result, 0);
  result = ferrum_dns_cache_get_pageslen(qcache, &pagelen);
  assert_int_equal(pagelen, 1);

  ferrum_dns_cache_destroy(qcache);
}

static void qcache_object_create_multipage(void **start) {
  unused(start);
  int32_t timeout = 100;
  int32_t result;

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  /// test data

  char *testdata;
  size_t datalen;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  free(testdata);
  //////////////////////////////////////

  char *testdata2;
  size_t datalen2;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata2, &datalen2);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata2, &datalen2);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket2);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata2), datalen2, dnspacket2);
  assert_int_equal(result, 0);
  dnspacket2->source = client;
  free(testdata2);

  ////////////////////////////////////////////

  ferrum_dns_cache_t *qcache;
  result = ferrum_dns_cache_new(&qcache, timeout);
  assert_int_equal(result, 0);

  ///////
  result = ferrum_dns_cache_add(qcache, dnspacket);
  assert_int_equal(result, 0);

  size_t pagelen;
  result = ferrum_dns_cache_get_pageslen(qcache, &pagelen);
  assert_int_equal(pagelen, 1);
  usleep(200000);
  // add other packet

  result = ferrum_dns_cache_add(qcache, dnspacket2);
  assert_int_equal(result, 0);
  result = ferrum_dns_cache_get_pageslen(qcache, &pagelen);
  assert_int_equal(pagelen, 2);

  ferrum_dns_cache_destroy(qcache);
}

static void qcache_object_find_remove(void **start) {
  unused(start);
  int32_t timeout = 100;
  int32_t result;

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  rebrick_sockaddr_t server;
  rebrick_util_ip_port_to_addr("192.168.1.1", "53", &server);

  /// test data

  char *testdata;
  size_t datalen;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  dnspacket->destination = server;
  free(testdata);

  //////////////////////////////////////

  char *testdata2;
  size_t datalen2;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata2, &datalen2);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata2, &datalen2);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket2);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata2), datalen2, dnspacket2);
  assert_int_equal(result, 0);
  dnspacket2->source = client;
  dnspacket2->destination = server;
  free(testdata2);

  ////////////////////////////////////////////

  ferrum_dns_cache_t *qcache;
  result = ferrum_dns_cache_new(&qcache, timeout);
  assert_int_equal(result, 0);

  ///////
  result = ferrum_dns_cache_add(qcache, dnspacket);

  size_t pagelen;
  result = ferrum_dns_cache_get_pageslen(qcache, &pagelen);
  assert_int_equal(pagelen, 1);
  // wait for new page
  usleep(200000);
  // add other packet
  result = ferrum_dns_cache_add(qcache, dnspacket2);
  result = ferrum_dns_cache_get_pageslen(qcache, &pagelen);
  assert_int_equal(pagelen, 2);
  ////// read a new packet

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata2, &datalen2);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata2, &datalen2);

  ferrum_dns_packet_new(dnspacket3);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata2), datalen2, dnspacket3);
  dnspacket3->source = server;
  free(testdata2);

  ///////find packet
  /// for test make manipulation
  dnspacket3->query_id = dnspacket2->query_newid;
  ferrum_dns_cache_founded_t *founded;
  result = ferrum_dns_cache_find(qcache, dnspacket3, &founded);
  assert_true(result == 0);
  assert_non_null(founded);
  assert_non_null(founded->cache_item);
  assert_non_null(founded->dns);
  assert_non_null(founded->page);

  ferrum_dns_cache_remove_founded(qcache, founded);

  result = ferrum_dns_cache_find(qcache, dnspacket3, &founded);
  assert_true(result == 0);
  assert_non_null(founded);
  assert_non_null(founded->cache_item);
  assert_non_null(founded->dns);
  assert_non_null(founded->page);
  result = ferrum_dns_cache_remove(qcache, founded);
  assert_true(result == 0);

  result = ferrum_dns_cache_find(qcache, dnspacket, &founded);
  assert_true(result == 0);
  assert_non_null(founded);
  assert_null(founded->cache_item);
  assert_null(founded->dns);
  assert_null(founded->page);

  ferrum_dns_cache_remove_founded(qcache, founded);

  result = ferrum_dns_cache_find(qcache, dnspacket, &founded);
  assert_true(result == 0);
  assert_non_null(founded);
  assert_null(founded->cache_item);
  assert_null(founded->dns);
  assert_null(founded->page);
  result = ferrum_dns_cache_remove(qcache, founded);
  assert_true(result == 0);

  result = ferrum_dns_cache_find(qcache, dnspacket3, &founded);
  assert_true(result == 0);
  assert_non_null(founded);
  assert_null(founded->cache_item);
  assert_null(founded->dns);
  assert_null(founded->page);
  result = ferrum_dns_cache_remove(qcache, founded);
  assert_true(result == 0);
  ferrum_dns_packet_destroy(dnspacket3);

  ferrum_dns_cache_destroy(qcache);
}
void qcache_remove_timedoutdata(void **start) {
  unused(start);
  int32_t timeout = 100;
  int32_t result;

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  rebrick_sockaddr_t server;
  rebrick_util_ip_port_to_addr("192.168.1.1", "53", &server);

  /// test data

  char *testdata;
  size_t datalen;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  dnspacket->destination = server;
  free(testdata);

  //////////////

  ferrum_dns_cache_t *qcache;
  result = ferrum_dns_cache_new(&qcache, timeout);
  assert_int_equal(result, 0);
  //     ferrum_dns_cache_founded_t *founded2;
  /////////////////

  result = ferrum_dns_cache_add(qcache, dnspacket);
  usleep(100000);
  // ferrum_dns_cache_add()

  ///////////////////////second packet

  result = ferrum_dns_cache_get_pageslen(qcache, &datalen);
  assert_true(result == 0);
  assert_true(datalen == 1);

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket2);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket2);
  assert_int_equal(result, 0);
  dnspacket2->source = client;
  dnspacket2->destination = server;
  free(testdata);

  ///////////////////////////////////
  usleep(20000);
  result = ferrum_dns_cache_add(qcache, dnspacket2);
  usleep(100000);

  result = ferrum_dns_cache_get_pageslen(qcache, &datalen);
  assert_true(result == 0);
  assert_true(datalen == 2);
  printf("executing clear timeout\n");
  result = ferrum_dns_cache_clear_timedoutdata(qcache);
  printf("executed clear timeout\n");
  assert_true(result == 0);
  result = ferrum_dns_cache_get_pageslen(qcache, &datalen);
  assert_true(result == 0);
  assert_true(datalen == 1);

  ///////////////third  packet

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket3);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket3);
  assert_int_equal(result, 0);
  dnspacket3->source = client;
  dnspacket3->destination = server;
  free(testdata);
  ///////////////

  result = ferrum_dns_cache_add(qcache, dnspacket3);
  assert_true(result == 0);

  usleep(600000);
  result = ferrum_dns_cache_clear_timedoutdata(qcache);
  assert_true(result == 0);

  for (int i = 0; i < 10000; ++i) {
    result = rebrick_util_file_read_allbytes("./test/data/dnspacket2.packet", &testdata, &datalen);
    if (result)
      result = rebrick_util_file_read_allbytes("./data/dnspacket2.packet", &testdata, &datalen);
    assert_int_equal(result, 0);

    ferrum_dns_packet_new(dnspacket4);
    result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket4);
    assert_int_equal(result, 0);
    dnspacket4->source = client;
    dnspacket4->destination = server;
    free(testdata);
    ///////////////

    result = ferrum_dns_cache_add(qcache, dnspacket4);
    assert_true(result == 0);
    result = ferrum_dns_cache_clear_timedoutdata(qcache);
    assert_true(result == 0);
  }

  result = ferrum_dns_cache_destroy(qcache);
  assert_int_equal(result, FERRUM_SUCCESS);
}

__attribute__((unused)) static void qcache_object_performance_test(void **start) {

  ////// sample data /////////
  unused(start);
  int32_t timeout = 5000000;
  int32_t result;

  rebrick_sockaddr_t client;
  rebrick_util_ip_port_to_addr("192.168.1.100", "8080", &client);

  rebrick_sockaddr_t server;
  rebrick_util_ip_port_to_addr("192.168.1.1", "53", &server);

  char *testdata;
  size_t datalen;

  result = rebrick_util_file_read_allbytes("./test/data/dnspacket1.packet", &testdata, &datalen);
  if (result)
    result = rebrick_util_file_read_allbytes("./data/dnspacket1.packet", &testdata, &datalen);
  assert_int_equal(result, 0);

  ferrum_dns_packet_new(dnspacket);
  result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, dnspacket);
  assert_int_equal(result, 0);
  dnspacket->source = client;
  dnspacket->destination = server;

  //////////////////create qcache ////////////////////

  ferrum_dns_cache_t *qcache;
  result = ferrum_dns_cache_new(&qcache, timeout);
  assert_int_equal(result, 0);

  //////////start testing //////////////////////////

  char randomString[FERRUM_DNS_MAX_FQDN_LEN];

  int i;
  int64_t now0 = rebrick_util_micro_time();

#define TEST_SIZE 10000
  ferrum_dns_packet_t **dnslist = rebrick_malloc(sizeof(ferrum_dns_packet_t *) * TEST_SIZE);
  memset(dnslist, 0, sizeof(ferrum_dns_packet_t *) * TEST_SIZE);
  for (i = 0; i < TEST_SIZE; ++i) {
    ferrum_dns_packet_new(ptr);
    dnslist[i] = ptr;

    result = ferrum_dns_packet_from(cast_to_uint8ptr(testdata), datalen, ptr);
    assert_int_equal(result, 0);
    ferrum_dns_packet_t *item = dnslist[i];

    sprintf(randomString, "%d.%d.%d", rebrick_util_rand(), rebrick_util_rand(), rebrick_util_rand());
    free(item->query);
    item->query = rebrick_malloc(strlen(randomString) + 1);
    strcpy(item->query, randomString);
    item->source = dnspacket->source;
    item->destination = dnspacket->source;
    item->query_id = item->query_newid;
    item->query_crc = i;
  }
  int64_t now = rebrick_util_micro_time();
  printf("performace for prepares %d is %" PRId64 " milisecond \n", i, (now - now0) / 1000);
  for (i = 0; i < TEST_SIZE; ++i) {
    ferrum_dns_packet_t *ptr = dnslist[i];

    result = ferrum_dns_cache_add(qcache, ptr);
    assert_true(result == 0);
  }
  free(testdata);

  int64_t now2 = rebrick_util_micro_time();
  printf("performace for add %d is %" PRId64 " milisecond \n", i, (now2 - now) / 1000);

  now2 = rebrick_util_micro_time();

  for (i = 0; i < TEST_SIZE; ++i) {
    ferrum_dns_cache_founded_t *founded = NULL;
    ferrum_dns_packet_t *ptr = dnslist[TEST_SIZE - i - 1];
    // printf("searc key %d:\n",ptr->query_crc);
    //   if(ptr->query_crc==4)
    //   printf("ahanda\n");
    result = ferrum_dns_cache_find(qcache, ptr, &founded);
    assert_true(result == 0);
    assert_non_null(founded);
    assert_non_null(founded->dns);
    ferrum_dns_cache_remove(qcache, founded);
  }

  int64_t now3 = rebrick_util_micro_time();
  printf("performace for search and remove %d is %" PRId64 " milisecond \n", i, (now3 - now2) / 1000);

  free(dnslist);

  ferrum_dns_cache_destroy(qcache);
  ferrum_dns_packet_destroy(dnspacket);
}

int test_ferrum_dns_cache(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(qcache_object_create),
      cmocka_unit_test(qcache_object_create_multipage),
      cmocka_unit_test(qcache_object_find_remove),
      cmocka_unit_test(qcache_remove_timedoutdata),
      cmocka_unit_test(qcache_object_performance_test)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
