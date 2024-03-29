#include "./rebrick/common/rebrick_tls.h"
#include "cmocka.h"

#include <unistd.h>
#include <limits.h>

static int setup(void **state) {
  unused(state);
  fprintf(stdout, "****  %s ****\n", __FILE__);

  rebrick_tls_init();
  int32_t counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
  rebrick_tls_cleanup();
  counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
  rebrick_tls_init();
  counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
  return 0;
}

static int teardown(void **state) {
  unused(state);

  rebrick_tls_cleanup();
  int32_t counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
  uv_loop_close(uv_default_loop());

  return 0;
}

static void tls_context_object_create_destroy_success(void **start) {
  unused(start);

  rebrick_tls_context_t *context = NULL;
  char pwd[PATH_MAX];
  getcwd(pwd, sizeof(pwd));
  fprintf(stdout, "current working directory %s:\n", pwd);
  const char *key = "deneme";
  int32_t result = rebrick_tls_context_new(&context, key, 0, 0, 0, 0, "./rebrick/data/domain.crt", "./rebrick/data/domain.key");
  assert_int_equal(result, 0);
  assert_non_null(context);

  rebrick_tls_context_t *out;
  rebrick_tls_context_get(key, &out);
  assert_non_null(out);
  assert_ptr_equal(out, context);
  rebrick_tls_context_destroy(context);
  int32_t counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
}

static void tls_context_object_create_fail(void **start) {
  unused(start);
  rebrick_tls_context_t *context = NULL;
  char pwd[PATH_MAX];
  getcwd(pwd, sizeof(pwd));
  fprintf(stdout, "current working directory %s:\n", pwd);
  int32_t result = rebrick_tls_context_new(&context, "deneme2", 0, 0, 0, 0, "./rebrick/data/domain_notvalid.crt", "./rebrick/data/domain.key");
  assert_int_not_equal(result, 0);
  assert_null(context);
  rebrick_tls_context_destroy(context);
  int32_t counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
}

static void tls_context_object_create_for_client(void **start) {
  unused(start);
  rebrick_tls_context_t *context = NULL;
  char pwd[PATH_MAX];
  getcwd(pwd, sizeof(pwd));
  fprintf(stdout, "current working directory %s:\n", pwd);
  int32_t result = rebrick_tls_context_new(&context, "deneme2", 0, 0, 0, 0, NULL, NULL);
  assert_int_equal(result, 0);
  assert_non_null(context);
  rebrick_tls_context_destroy(context);
  int32_t counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
}

static void tls_ssl_object_create(void **start) {
  unused(start);
  rebrick_tls_context_t *context = NULL;
  char pwd[PATH_MAX];
  getcwd(pwd, sizeof(pwd));
  fprintf(stdout, "current working directory %s:\n", pwd);
  const char *key = "deneme";
  int32_t result = rebrick_tls_context_new(&context, key, 0, 0, 0, 0, "./rebrick/data/domain.crt", "./rebrick/data/domain.key");
  assert_int_equal(result, 0);
  assert_non_null(context);

  rebrick_tls_ssl_t *tls = NULL;
  result = rebrick_tls_ssl_new(&tls, context);
  assert_int_equal(result, REBRICK_SUCCESS);
  assert_non_null(tls);
  assert_non_null(tls->ssl);
  rebrick_tls_ssl_destroy(tls);
  rebrick_tls_context_destroy(context);
  int32_t counter = 100;
  while (counter--) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(1000);
  }
}

int test_rebrick_tls(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(tls_context_object_create_destroy_success),
      cmocka_unit_test(tls_context_object_create_fail),
      cmocka_unit_test(tls_context_object_create_for_client),
      cmocka_unit_test(tls_ssl_object_create)

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
