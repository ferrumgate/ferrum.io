#include "./common/rebrick_timer.h"
#include "cmocka.h"
#include <unistd.h>


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

static int test = 0;

static int32_t callback(void *data)
{
    unused(data);

    test++;
    return test;
}

static void timer_object_create_destroy(void **start)
{
    unused(start);
    rebrick_timer_t *timer;
    int32_t result;
    test = 0;
    result = rebrick_timer_new(&timer, callback,(void *) 5, 1, 1);

    assert_true(result == 0);
    //check loop

    int32_t counter=5;
    while(counter){
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(10000);
    counter--;
    if(test)
    break;
    }
    assert_true(test > 0);
    rebrick_timer_destroy(timer);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    int tmp = test;
    usleep(10000);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    assert_true(tmp == test);
}

static void timer_object_create_start_stop_destroy(void **start)
{
    unused(start);
    rebrick_timer_t *timer;
    int32_t result;
    test = 0;
    result = rebrick_timer_new(&timer, callback,(void*) 5, 1, 0);

    assert_true(result == 0);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100000);
    assert_true(test == 0);

    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    result = rebrick_timer_start(timer);
    assert_true(result == 0);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100000);
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    assert_true(test > 0);
    //check loop

    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100000);
    assert_true(test > 0);
    result = rebrick_timer_stop(timer);
    assert_true(result == 0);

    int tmp = test;
    usleep(100000);
    //check loop
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    usleep(100000);
    assert_true(tmp == test);

    result=rebrick_timer_destroy(timer);
    assert_true(result==0);
}

int test_rebrick_timer(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(timer_object_create_destroy),
        cmocka_unit_test(timer_object_create_start_stop_destroy)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
