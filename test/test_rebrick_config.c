#include "rebrick_config.h"
#include "cmocka.h"

static int setup(void**state){
    unused(state);
    fprintf(stdout,"****  %s ****\n",__FILE__);
    return 0;
}

static int teardown(void **state){
unused(state);
    return 0;
}

static void config_object_create_destroy_success(void **start){
    unused(start);
    rebrick_config_t *config=NULL;
    int32_t result;
    result=rebrick_config_new(&config);
    assert_true(result>=0);
    assert_non_null(config);
    assert_string_equal(config->type_name,"rebrick_config_t");

    rebrick_config_destroy(config);


}
static void config_object_listens_success(){

    rebrick_config_t *config=NULL;
    int32_t result;
    result=rebrick_config_new(&config);
    assert_true(result>=0);
    assert_non_null(config);

    //buradaki 9090 değeri Makefile içinden geliyor
    assert_int_equal(config->listen_port,9090);
    assert_int_equal(config->listen_family,REBRICK_IPV4_IPV6);

    rebrick_config_destroy(config);

}



int test_rebrick_config(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(config_object_create_destroy_success),
        cmocka_unit_test(config_object_listens_success)


    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

