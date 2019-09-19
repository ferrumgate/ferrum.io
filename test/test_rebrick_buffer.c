#include "rebrick_buffer.h"
#include "cmocka.h"
#define REBRICK_BUFFER_DEFAULT_MALLOC_SIZE 1024
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

static void buffer_init_add_success(void **start)
{
    unused(start);
    rebrick_buffer_t *buffer;
    char *deneme = "hamza";
    int32_t result = rebrick_buffer_new(&buffer, cast(deneme, uint8_t *), strlen(deneme), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);
    assert_memory_equal(buffer->buf, "hamza",5);
    assert_int_equal(buffer->len, 5);

    char *testdata = "deneme";
    rebrick_buffer_add(buffer, (uint8_t *)testdata, strlen(testdata));
    assert_memory_equal(buffer->buf, "hamzadeneme",11);
    assert_int_equal(buffer->len, 11);


    rebrick_buffer_destroy(buffer);
}

static void buffer_init_add_big_string_success(void **start)
{
    unused(start);
    rebrick_buffer_t *buffer;
    //big string
    char deneme[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32];
    memset(deneme, 0, sizeof(deneme));
    for (int i = 0; i < REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 3; ++i)
        deneme[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)deneme, sizeof(deneme), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);
    assert_int_equal(buffer->len,sizeof(deneme));
    assert_int_equal(buffer->malloc_size,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*2);
    assert_memory_equal(buffer->buf,deneme,sizeof(deneme));
    //add a small string
    uint8_t *deneme2 = (uint8_t *)"deneme";
    rebrick_buffer_add(buffer, deneme2, (size_t)6);

    assert_int_equal(buffer->len,sizeof(deneme)+6);
    assert_int_equal(buffer->malloc_size,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*2);
    assert_memory_equal(buffer->buf+buffer->len-6,deneme2,6);

    //add a big string
    char test[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
    for (int i = 0; i < REBRICK_BUFFER_DEFAULT_MALLOC_SIZE; ++i)
        test[i] = (i % 28) + 97;

    rebrick_buffer_add(buffer, (uint8_t *)test, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);

    assert_int_equal(buffer->len,sizeof(deneme)+6+sizeof(test));
    assert_int_equal(buffer->malloc_size,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*3);
    assert_memory_equal(buffer->buf+buffer->len-REBRICK_BUFFER_DEFAULT_MALLOC_SIZE,test,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);

    rebrick_buffer_destroy(buffer);
}

static void buffer_init_add_remove_fromhead_success(void **start)
{
    //0-10 test
    unused(start);
    rebrick_buffer_t *buffer;
    //big string full page
    char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);

    //0-10
    rebrick_buffer_remove(buffer, 0, 10);
    assert_int_equal(buffer->len,sizeof(part1)-10);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_memory_equal(buffer->buf,part1+10,buffer->len);

    rebrick_buffer_destroy(buffer);
}



static void buffer_init_add_remove_fromhead_success2(void **start)
{
    //0-10
    unused(start);
    rebrick_buffer_t *buffer;
    //big string full page
    char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*2+10];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*3);



    //10-REBRICK_BUFFERSIZE
    rebrick_buffer_remove(buffer, 10, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->len,sizeof(part1)-REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*2);
    assert_memory_equal(part1,buffer->buf,10);
    assert_memory_equal(buffer->buf+10, part1+10+REBRICK_BUFFER_DEFAULT_MALLOC_SIZE,buffer->len-10);

    rebrick_buffer_destroy(buffer);
}

static void buffer_init_add_remove_fromhead_success3(void **start)
{
    //0-REBRICK_BUFFER_DEFAULT_MALLOC_SIZE
    unused(start);
    rebrick_buffer_t *buffer;
    //big string full page
    char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);

    //add other buffer




    //0-10
    rebrick_buffer_remove(buffer, 0, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->len,0);
    assert_non_null(buffer->buf);


    rebrick_buffer_destroy(buffer);
}



static void buffer_init_add_remove_fromcenter_success(void **start)
{
    unused(start);
    //10-20
    unused(start);
    rebrick_buffer_t *buffer;
    //big string full page
    char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);

    //add other buffer
    char part2[32];
    memset(part2, 0, sizeof(part2));
    for (int i = 0; i < ssizeof(part2); ++i)
        part2[i] = (i % 28) + 97;
    result = rebrick_buffer_add(buffer, (uint8_t *)part2, sizeof(part2));
    assert_int_equal(result, 0);


    //10-20
    rebrick_buffer_remove(buffer, 10, 20);

    assert_int_equal(buffer->len, sizeof(part1)+sizeof(part2)-20);

    assert_memory_equal(buffer->buf, part1, 10);
    assert_memory_equal(buffer->buf + 10, part1 + 30, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 30);
    assert_memory_equal(buffer->buf+buffer->len-sizeof(part2),part2,sizeof(part2));

    rebrick_buffer_destroy(buffer);
}

static void buffer_init_add_remove_fromcenter_success2(void **start)
{
    unused(start);
    //REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-20
    unused(start);
    rebrick_buffer_t *buffer;
    //big string full page
    char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);

    //add other buffer
    char part2[32];
    memset(part2, 0, sizeof(part2));
    for (int i = 0; i < ssizeof(part2); ++i)
        part2[i] = (i % 28) + 97;
    result = rebrick_buffer_add(buffer, (uint8_t *)part2, sizeof(part2));
    assert_int_equal(result, 0);


    //REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-20
    rebrick_buffer_remove(buffer, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_memory_equal(buffer->buf,part1,sizeof(part1));

    rebrick_buffer_destroy(buffer);
}


static void buffer_init_add_remove_fromcenter_success3(void **start)
{
    unused(start);
    //REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-20
    unused(start);
    rebrick_buffer_t *buffer;
    //big string full page
    char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    int32_t result = rebrick_buffer_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);

    //add other buffer
    char part2[32];
    memset(part2, 0, sizeof(part2));
    for (int i = 0; i < ssizeof(part2); ++i)
        part2[i] = (i % 28) + 97;
    result = rebrick_buffer_add(buffer, (uint8_t *)part2, sizeof(part2));
    assert_int_equal(result, 0);


    //REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-20
    rebrick_buffer_remove(buffer, 0, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE*2);
    assert_int_equal(buffer->len,0);
    assert_int_equal(buffer->malloc_len,REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);


    rebrick_buffer_destroy(buffer);
}


static void buffer_check_memory(void **start)
{

    unused(start);

    unused(start);
#define LIST_SIZE 1000

    //big string full page
    uint8_t part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    //size_t totalbuflen = 0;
    for (int a = 0; a < LIST_SIZE; ++a)
    {
        rebrick_buffer_t *tmp;
        int32_t result = rebrick_buffer_new(&tmp, part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
        assert_int_equal(result, 0);
        rebrick_buffer_destroy(tmp);
    }


}

static void buffer_check_memory2(void **start)
{

    unused(start);
    unused(start);
#undef LIST_SIZE
#define LIST_SIZE 100

    //big string full page
    uint8_t part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE+32];
    memset(part1, 0, sizeof(part1));
    for (int i = 0; i < ssizeof(part1); ++i)
        part1[i] = (i % 28) + 97;
    // size_t totalbuflen = 0;
    for (int a = 0; a < LIST_SIZE; ++a)
    {
        rebrick_buffer_t *tmp;
        int32_t result = rebrick_buffer_new(&tmp, part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
        assert_int_equal(result, 0);
        int counter = 57;
        while (counter--)
        {
            result = rebrick_buffer_add(tmp, part1, sizeof(part1));
            assert_int_equal(result, 0);
        }
        rebrick_buffer_destroy(tmp);

    }


}

int test_rebrick_buffer(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(buffer_init_add_success),
        cmocka_unit_test(buffer_init_add_big_string_success),
        cmocka_unit_test(buffer_init_add_remove_fromhead_success),
        cmocka_unit_test(buffer_init_add_remove_fromhead_success2),
        cmocka_unit_test(buffer_init_add_remove_fromhead_success3),
        cmocka_unit_test(buffer_init_add_remove_fromcenter_success),
        cmocka_unit_test(buffer_init_add_remove_fromcenter_success2),
        cmocka_unit_test(buffer_init_add_remove_fromcenter_success3),

         cmocka_unit_test(buffer_check_memory),
        cmocka_unit_test(buffer_check_memory2),

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
