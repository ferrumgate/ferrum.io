#include "rebrick_tls.h"
#include "cmocka.h"

#include <unistd.h>
#include <limits.h>

static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);
    return 0;
}

static int teardown(void **state)
{
    unused(state);
    return 0;
}
static void x(char *ss){
  ss[0]=10;
  ss[9]=0;
}

static void tls_context_object_create_destroy_success(void **start)
{
    unused(start);

    rebrick_tls_context_t *context=NULL;
    char pwd[PATH_MAX];
    getcwd(pwd, sizeof(pwd));
    fprintf(stdout, "current working directory %s:\n", pwd);
    const char *key="deneme";
    int32_t result = rebrick_tls_context_new(&context, key, 0, 0, 0, "./data/domain.crt", "./data/domain.key");
    assert_int_equal(result, 0);
    assert_non_null(context);

    rebrick_tls_context_t *out;
    rebrick_tls_context_get(key,&out);
    assert_non_null(out);
    assert_ptr_equal(out,context);
    rebrick_tls_context_destroy(context);

}



static void tls_context_object_create_fail(void **start)
{
    unused(start);
    rebrick_tls_context_t *context=NULL;
    char pwd[PATH_MAX];
    getcwd(pwd, sizeof(pwd));
    fprintf(stdout, "current working directory %s:\n", pwd);
    int32_t result = rebrick_tls_context_new(&context, "deneme2", 0, 0, 0, "./data/domain_notvalid.crt", "./data/domain.key");
    assert_int_not_equal(result, 0);
    assert_null(context);
    rebrick_tls_context_destroy(context);

}

static void tls_context_object_create_for_client(void **start)
{
    unused(start);
    rebrick_tls_context_t *context=NULL;
    char pwd[PATH_MAX];
    getcwd(pwd, sizeof(pwd));
    fprintf(stdout, "current working directory %s:\n", pwd);
    int32_t result = rebrick_tls_context_new(&context, "deneme2", 0, 0, 0, NULL, NULL);
    assert_int_equal(result, 0);
    assert_non_null(context);

}


static void tls_ssl_object_create(void **start){
    unused(start);
    rebrick_tls_context_t *context=NULL;
    char pwd[PATH_MAX];
    getcwd(pwd, sizeof(pwd));
    fprintf(stdout, "current working directory %s:\n", pwd);
    const char *key="deneme";
    int32_t result = rebrick_tls_context_new(&context, key, 0, 0, 0, "./data/domain.crt", "./data/domain.key");
    assert_int_equal(result, 0);
    assert_non_null(context);

    rebrick_tls_ssl_t *tls=NULL;
    result=rebrick_tls_ssl_new(&tls,context);
    assert_int_equal(result,0);
    assert_non_null(tls);
    assert_non_null(tls->ssl);
    rebrick_tls_ssl_destroy(tls);
}



int test_rebrick_tls(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tls_context_object_create_destroy_success),
        /* cmocka_unit_test(tls_context_object_create_fail),
        cmocka_unit_test(tls_context_object_create_for_client),
        cmocka_unit_test(tls_ssl_object_create) */

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
