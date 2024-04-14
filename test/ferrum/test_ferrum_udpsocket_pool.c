#include "ferrum/pool/ferrum_udpsocket_pool.h"
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
static void ferrum_udpsocket_pool_create_destroy() {
  ferrum_udpsocket_pool_t *pool;
  int32_t result = ferrum_udpsocket_pool_new(&pool, 16);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(pool->max_count, 16);
  ferrum_udpsocket_pool_destroy(pool);
}

static void ferrum_udpsocket_pool_get_func() {
  ferrum_udpsocket_pool_t *pool;
  int32_t result = ferrum_udpsocket_pool_new(&pool, 16);
  assert_int_equal(result, FERRUM_SUCCESS);

  const char *bind_ip = "0.0.0.0";
  const char *bind_port = "0";
  rebrick_sockaddr_t bind;
  rebrick_util_to_rebrick_sockaddr(&bind, bind_ip, bind_port);

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  rebrick_udpsocket_t *socket;
  uint8_t is_from_cache;
  result = ferrum_udpsocket_pool_get(pool, &socket, &bind, &callbacks, &is_from_cache);
  assert_int_equal(result, FERRUM_SUCCESS);
  assert_int_equal(pool->in_use_count, 1);
  assert_ptr_equal(socket->pool, pool);
  assert_int_equal(socket->is_in_pool, FALSE);

  rebrick_udpsocket_destroy(socket);
  int32_t counter;
  loop(counter, 10, TRUE);
  ferrum_udpsocket_pool_destroy(pool);
}

static void ferrum_udpsocket_pool_get_func_error() {
  ferrum_udpsocket_pool_t *pool;
  int32_t result = ferrum_udpsocket_pool_new(&pool, 2);
  assert_int_equal(result, FERRUM_SUCCESS);

  const char *bind_ip = "0.0.0.0";
  const char *bind_port = "0";
  rebrick_sockaddr_t bind;
  rebrick_util_to_rebrick_sockaddr(&bind, bind_ip, bind_port);

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  int32_t counter;
  { // first socket
    uint8_t is_from_cache;
    rebrick_udpsocket_t *socket;
    result = ferrum_udpsocket_pool_get(pool, &socket, &bind, &callbacks, &is_from_cache);
    assert_int_equal(result, FERRUM_SUCCESS);
    assert_int_equal(pool->in_use_count, 1);
    rebrick_udpsocket_destroy(socket);
  }
  { // second socket
    uint8_t is_from_cache;
    rebrick_udpsocket_t *socket;
    result = ferrum_udpsocket_pool_get(pool, &socket, &bind, &callbacks, &is_from_cache);
    assert_int_equal(result, FERRUM_SUCCESS);
    assert_int_equal(pool->in_use_count, 2);
    rebrick_udpsocket_destroy(socket);
  }
  { // third socket gives error
    uint8_t is_from_cache;
    rebrick_udpsocket_t *socket;
    result = ferrum_udpsocket_pool_get(pool, &socket, &bind, &callbacks, &is_from_cache);
    assert_int_equal(result, FERRUM_ERR_POOL_REACHED_MAX);
    assert_int_equal(pool->in_use_count, 2);
  }

  loop(counter, 10, TRUE);
  ferrum_udpsocket_pool_destroy(pool);
}

static void ferrum_udpsocket_pool_get_set() {
  ferrum_udpsocket_pool_t *pool;
  int32_t result = ferrum_udpsocket_pool_new(&pool, 2);
  assert_int_equal(result, FERRUM_SUCCESS);

  const char *bind_ip = "0.0.0.0";
  const char *bind_port = "0";
  rebrick_sockaddr_t bind;
  rebrick_util_to_rebrick_sockaddr(&bind, bind_ip, bind_port);

  new2(rebrick_udpsocket_callbacks_t, callbacks);
  rebrick_udpsocket_t *socket1;
  int32_t counter;
  { // first socket
    uint8_t is_from_cache;
    result = ferrum_udpsocket_pool_get(pool, &socket1, &bind, &callbacks, &is_from_cache);
    assert_int_equal(result, FERRUM_SUCCESS);
    assert_int_equal(pool->in_use_count, 1);
    // put it back
    result = ferrum_udpsocket_pool_set(pool, socket1);
    assert_int_equal(result, FERRUM_SUCCESS);
    assert_int_equal(pool->in_use_count, 0);
    assert_int_equal(socket1->is_in_pool, TRUE);
  }
  rebrick_udpsocket_t *socket2;
  { // get it back
    uint8_t is_from_cache;
    result = ferrum_udpsocket_pool_get(pool, &socket2, &bind, &callbacks, &is_from_cache);
    assert_int_equal(result, FERRUM_SUCCESS);
    assert_int_equal(pool->in_use_count, 1);
    assert_ptr_equal(socket1, socket2);
    ferrum_udpsocket_pool_set(pool, socket2);
  }

  ferrum_udpsocket_pool_destroy(pool);
  loop(counter, 10, TRUE);
}

int test_ferrum_socket_pool(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(ferrum_udpsocket_pool_create_destroy),
      cmocka_unit_test(ferrum_udpsocket_pool_get_func),
      cmocka_unit_test(ferrum_udpsocket_pool_get_func_error),
      cmocka_unit_test(ferrum_udpsocket_pool_get_set),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}