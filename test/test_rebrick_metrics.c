#include "rebrick_metrics.h"
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

static void metrics_object_create_destroy_success(void **start){
    unused(start);
    rebrick_metrics_t *metrics=NULL;
    int32_t result;
    result=rebrick_metrics_new(&metrics);
    assert_true(result>=0);
    assert_non_null(metrics);
    assert_string_equal(metrics->type_name,"rebrick_metrics_t");
    rebrick_metrics_destroy(metrics);


}


static void metrics_tostring(void **start){
    unused(start);
    rebrick_metrics_t *metrics=NULL;
    int32_t result;
    result=rebrick_metrics_new(&metrics);
    assert_int_equal(result,0);
    metrics->start_time=1;
    metrics->current_time=30;
    metrics->received_total=2;
    metrics->received_error_total=3;
    metrics->received_success_total=4;
    metrics->forward_total=5;
    metrics->forward_error_total=6;
    metrics->forward_success_total=7;

    char buffer[REBRICK_METRICS_MAX_STR_LEN];
    rebrick_metrics_tostring(metrics,buffer);
    const char *mustbuffer="start_time:1\n\
    current_time:30\n\
    received_total:2\n\
    received_error_total:3\n\
    received_success_total:4\n\
    forward_total:5\n\
    forward_error_total:6\n\
    forward_success_total:7\n";
    assert_string_equal(buffer,mustbuffer);
    rebrick_metrics_destroy(metrics);


}

int test_rebrick_metrics(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(metrics_object_create_destroy_success),
        cmocka_unit_test(metrics_tostring)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

