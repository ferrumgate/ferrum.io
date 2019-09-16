#include "rebrick_async_httpsocket.h"
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

static void http_socket_as_client_create(void **start){
    unused(start);



}




int test_http_socket(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(http_socket_as_client_create)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

