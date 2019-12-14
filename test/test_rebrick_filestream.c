#include "./file/rebrick_filestream.h"
#include "cmocka.h"
#include <unistd.h>

#define loop(var, a, x)                           \
    var = a;                                      \
    while (var-- && (x))                          \
    {                                             \
        usleep(100);                              \
        uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
    }

static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);
    return 0;
}

static int teardown(void **state)
{
    unused(state);
    uv_loop_close(uv_default_loop());
    return 0;
}

static int test = 0;

static int32_t callback(void *data)
{
    unused(data);

    test++;
    return test;
}

static void filestream_sync_read(void **start)
{
    unused(start);
    rebrick_filestream_t *file;
    int32_t result;
    test = 0;

    result = rebrick_filestream_new(&file, "./test/testdata/filestream_test.txt", O_RDWR, 0, NULL);
    if (result)
        result = rebrick_filestream_new(&file, "./testdata/filestream_test.txt", O_RDWR, 0, NULL);

    assert_true(result == 0);
    //check loop

    int32_t counter = 5;
    loop(counter, 1000, TRUE);
    ///start from beginning
    char buffer[1024] = {0};
    result = rebrick_filestream_read(file, cast(buffer, uint8_t *), 1024, -1);
    assert_true(result == 0);
    assert_string_equal(buffer, "hello world");

    //start reading from 6 offset
    memset(buffer, 0, sizeof(buffer));
    result = rebrick_filestream_read(file, cast(buffer, uint8_t *), 1024, 6);
    assert_true(result == 0);
    assert_string_equal(buffer, "world");
    rebrick_filestream_destroy(file);
    loop(counter, 1000, TRUE);
}
static void filestream_sync_write(void **start)
{
    unused(start);
    rebrick_filestream_t *file;
    int32_t result;
    test = 0;

    result = rebrick_filestream_new(&file, "/tmp/filestream_test.txt", O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR, NULL);

    assert_true(result == 0);
    //check loop

    int32_t counter = 5;
    loop(counter, 1000, TRUE);
    ///start from beginning
    const char *buffer = "hello world";
    result = rebrick_filestream_write(file, cast(buffer, uint8_t *), strlen(buffer), -1);
    assert_true(result == 0);
    result = rebrick_filestream_write(file, cast(buffer, uint8_t *), strlen(buffer), -1);
    assert_true(result == 0);

    char readbuffer[1024] = {0};
    result = rebrick_filestream_read(file, cast(readbuffer, u_int8_t *), sizeof(readbuffer), 0);
    assert_true(result == 0);
    assert_string_equal(readbuffer, "hello worldhello world");

    const char *buffer2 = "hello";
    result = rebrick_filestream_write(file, cast(buffer2, uint8_t *), strlen(buffer2), 6);
    assert_true(result == 0);

    result = rebrick_filestream_read(file, cast(readbuffer, u_int8_t *), sizeof(readbuffer), 0);
    assert_true(result == 0);
    assert_string_equal(readbuffer, "hello hellohello world");

    rebrick_filestream_destroy(file);
    loop(counter, 1000, TRUE);
}

static int32_t file_closed = 0;

static void on_file_close(rebrick_filestream_t *file, void *data)
{
    unused(file);
    unused(data);
    file_closed = TRUE;
}

static int32_t file_opened = 0;

static void on_file_open(rebrick_filestream_t *file, void *data)
{
    unused(file);
    unused(data);
    file_opened = TRUE;
}

static int32_t file_error = 0;

static void on_file_error(rebrick_filestream_t *file, void *data, int32_t error)
{
    unused(file);
    unused(data);
    unused(error);
    file_error = TRUE;
}

static int32_t file_readed = 0;

static void on_file_read(rebrick_filestream_t *file, void *data, uint8_t *buf, size_t len)
{
    unused(file);
    unused(data);
    file_readed = TRUE;
    unused(buf);
    unused(len);
}

static int32_t file_written = 0;

static void on_file_write(rebrick_filestream_t *file, void *data, uint8_t *buf, size_t len)
{
    unused(file);
    unused(data);
    file_written = TRUE;
    unused(buf);
    unused(len);
}

static void filestream_async_read(void **start)
{
    unused(start);
    rebrick_filestream_t *file;
    int32_t result;
    int32_t counter = 0;

    //burada path değişiyor o yüzden hangisi diye bulmak lazım
    new2(rebrick_filestream_callbacks_t, callbacks);
    callbacks.callback_data = NULL;
    callbacks.on_close = on_file_close;
    callbacks.on_error = on_file_error;
    callbacks.on_open = on_file_open;
    callbacks.on_read = on_file_read;
    callbacks.on_write = on_file_write;

    file_opened = FALSE;
    file_error = FALSE;
    file_readed = FALSE;
    file_written = FALSE;
    file_closed = FALSE;
    //try to find file
    result = rebrick_filestream_new(&file, "./test/testdata/filestream_test.txt", O_RDWR,0 , &callbacks);
    assert_true(result == 0);
    loop(counter, 100, TRUE);
    if (file_error)
    {
        rebrick_filestream_destroy(file);
        loop(counter, 100, TRUE);
        file_opened = FALSE;
        file_error = FALSE;
        file_readed = FALSE;
        file_written = FALSE;
        file_closed = FALSE;
        result = rebrick_filestream_new(&file, "./testdata/filestream_test.txt", O_RDWR ,0, &callbacks);
        assert_true(result == 0);
        loop(counter, 100, TRUE);
    }

    assert_true(file_opened == TRUE);
    //check loop
    loop(counter, 1000, TRUE);
    ///start from beginning
    char buffer[1024] = {0};
    result = rebrick_filestream_read(file, cast(buffer, uint8_t *), 1024, -1);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);
    assert_true(file_readed == TRUE);
    assert_string_equal(buffer, "hello world");

    //start reading from 6 offset
    memset(buffer, 0, sizeof(buffer));
    file_readed = FALSE;
    result = rebrick_filestream_read(file, cast(buffer, uint8_t *), 1024, 6);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);
    assert_true(file_readed == TRUE);
    assert_string_equal(buffer, "world");
    rebrick_filestream_destroy(file);
    loop(counter, 1000, TRUE);
    assert_true(file_closed == TRUE);
}

static void filestream_async_write(void **start)
{
    unused(start);
    rebrick_filestream_t *file;
    int32_t result;
    int32_t counter = 0;

    //burada path değişiyor o yüzden hangisi diye bulmak lazım
    new2(rebrick_filestream_callbacks_t, callbacks);
    callbacks.callback_data = NULL;
    callbacks.on_close = on_file_close;
    callbacks.on_error = on_file_error;
    callbacks.on_open = on_file_open;
    callbacks.on_read = on_file_read;
    callbacks.on_write = on_file_write;

    file_opened = FALSE;
    file_error = FALSE;
    file_readed = FALSE;
    file_written = FALSE;
    file_closed = FALSE;
    //try to find file
    result = rebrick_filestream_new(&file, "/tmp/filestream_test.txt", O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR, &callbacks);
    assert_true(result == 0);
    loop(counter, 100, TRUE);


    assert_true(result == 0);
    assert_true(file_opened==TRUE);
    //check loop

    loop(counter, 1000, TRUE);
    ///start from beginning
    const char *buffer = "hello world";
    result = rebrick_filestream_write(file, cast(buffer, uint8_t *), strlen(buffer), -1);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);
    result = rebrick_filestream_write(file, cast(buffer, uint8_t *), strlen(buffer), -1);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);

    char readbuffer[1024] = {0};
    result = rebrick_filestream_read(file, cast(readbuffer, u_int8_t *), sizeof(readbuffer), 0);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);
    assert_string_equal(readbuffer, "hello worldhello world");

    const char *buffer2 = "hello";
    result = rebrick_filestream_write(file, cast(buffer2, uint8_t *), strlen(buffer2), 6);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);

    result = rebrick_filestream_read(file, cast(readbuffer, u_int8_t *), sizeof(readbuffer), 0);
    assert_true(result == 0);
    loop(counter, 1000, TRUE);
    assert_string_equal(readbuffer, "hello hellohello world");

    rebrick_filestream_destroy(file);

    loop(counter, 1000, TRUE);
    assert_true(file_closed == TRUE);
}

int test_rebrick_filestream(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(filestream_sync_read),
        cmocka_unit_test(filestream_sync_write),
        cmocka_unit_test(filestream_async_read),
        cmocka_unit_test(filestream_async_write),

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
