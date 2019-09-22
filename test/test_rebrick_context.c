#include "./common/rebrick_context.h"
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


static void context_object_create(void **start){
    unused(start);
    rebrick_context_t *context=NULL;
    //set some ptr;
    void *ptr=(void*)10;
    int32_t result=rebrick_context_new(&context,ptr,ptr);
    assert_true(result==0);
    assert_non_null(context);
    assert_non_null(context->config);
    assert_non_null(context->metrics);
    rebrick_context_destroy(context);


}

int test_rebrick_context(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(context_object_create)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

