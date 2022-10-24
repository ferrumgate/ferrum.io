#include "./http/rebrick_httpsocket.h"
#include "cmocka.h"
#include <unistd.h>

static int setup(void **state)
{
    unused(state);
    rebrick_tls_init();
    fprintf(stdout, "****  %s ****\n", __FILE__);
    return 0;
}

static int teardown(void **state)
{
    unused(state);
    rebrick_tls_cleanup();
    int32_t counter = 100;
    while (counter--)
    {
        uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        usleep(1000);
    }
    uv_loop_close(uv_default_loop());
    return 0;
}

static void rebrick_http_keyvalue_test(void **state)
{
    unused(state);
    int32_t result;
    rebrick_http_key_value_t *keyvalue;
    result = rebrick_http_key_value_new(&keyvalue, "hamza", "kilic");
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_memory_equal(keyvalue->key, "hamza", 5);
    assert_memory_equal(keyvalue->value, "kilic", 5);
    assert_int_equal(keyvalue->keylen, 5);
    assert_int_equal(keyvalue->valuelen, 5);

    rebrick_http_key_value_destroy(keyvalue);
}

static void rebrick_http_keyvalue_test2(void **state)
{
    unused(state);
    int32_t result;
    rebrick_http_key_value_t *keyvalue;
    result = rebrick_http_key_value_new2(&keyvalue, "hamza", 5, "kilic", 5);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_memory_equal(keyvalue->key, "hamza", 6);
    assert_memory_equal(keyvalue->value, "kilic", 6);
    assert_int_equal(keyvalue->keylen, 5);
    assert_int_equal(keyvalue->valuelen, 5);
    rebrick_http_key_value_destroy(keyvalue);
}

static void rebrick_http_header_test(void **state)
{
    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result = rebrick_http_header_new(&header, "http", "deneme.com", "POST", "/api/metrics", 1, 1);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_string_equal(header->host, "deneme.com");
    assert_string_equal(header->scheme, "http");
    assert_string_equal(header->path, "/api/metrics");
    assert_string_equal(header->method, "POST");

    assert_int_equal(header->major_version, 1);
    assert_int_equal(header->minor_version, 1);
    assert_int_equal(header->is_request, TRUE);
    assert_null(header->headers);
    assert_string_equal(header->status_code_str, "");
    assert_int_equal(header->status_code, 0);

    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_test2(void **state)
{
    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result = rebrick_http_header_new2(&header, "http", 4, "deneme.com", 10, "POST", 4, "/api/metrics", 12, 1, 1);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_string_equal(header->path, "/api/metrics");
    assert_string_equal(header->method, "POST");
    assert_string_equal(header->scheme, "http");
    assert_string_equal(header->host, "deneme.com");
    assert_int_equal(header->major_version, 1);
    assert_int_equal(header->minor_version, 1);
    assert_int_equal(header->is_request, TRUE);
    assert_string_equal(header->status_code_str, "");
    assert_int_equal(header->status_code, 0);

    assert_null(header->headers);
    result = rebrick_http_header_add_header(header, "content-type", "application/json");
    assert_int_equal(result, REBRICK_SUCCESS);
    int32_t founded;
    result = rebrick_http_header_contains_key(header, "content-type", &founded);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(founded, TRUE);

    result = rebrick_http_header_contains_key(header, "Content-Type", &founded);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(founded, TRUE);

    result = rebrick_http_header_remove_key(header, "content-type");
    assert_int_equal(result, REBRICK_SUCCESS);

    result = rebrick_http_header_contains_key(header, "content-type", &founded);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(founded, FALSE);

    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_test3(void **state)
{
    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result = rebrick_http_header_new3(&header, Rebrick_HttpStatus_OK, 1, 1);
    assert_int_equal(result, REBRICK_SUCCESS);

    assert_int_equal(header->major_version, 1);
    assert_int_equal(header->minor_version, 1);
    assert_int_equal(header->is_request, FALSE);
    assert_null(header->headers);
    assert_string_equal(header->path, "");
    assert_string_equal(header->method, "");
    assert_int_equal(header->status_code, 200);
    assert_string_equal(header->status_code_str, "OK");

    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_test4(void **state)
{
    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result = rebrick_http_header_new4(&header, 500, 1, 1);
    assert_int_equal(result, REBRICK_SUCCESS);

    assert_int_equal(header->major_version, 1);
    assert_int_equal(header->minor_version, 1);
    assert_int_equal(header->is_request, FALSE);
    assert_null(header->headers);
    assert_string_equal(header->path, "");
    assert_string_equal(header->method, "");
    assert_int_equal(header->status_code, 500);
    assert_string_equal(header->status_code_str, rebrick_httpstatus_reasonphrase(500));

    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_to_http_buffer_test(void **state)
{

    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result = rebrick_http_header_new(&header, "http", "deneme.com", "POST", "/api/metrics", 1, 1);
    assert_int_equal(result, REBRICK_SUCCESS);
    result = rebrick_http_header_add_header(header, "content-type", "application/json");
    assert_int_equal(result, REBRICK_SUCCESS);

    int32_t count;
    result = rebrick_http_header_count(header, &count);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_int_equal(count, 1);

    assert_int_equal(result, REBRICK_SUCCESS);
    rebrick_buffer_t *buffer;
    result = rebrick_http_header_to_http_buffer(header, &buffer);
    assert_int_equal(result, REBRICK_SUCCESS);
    assert_string_equal(buffer->buf, "POST /api/metrics HTTP/1.1\r\nhost:deneme.com\r\ncontent-type:application/json\r\n\r\n");
    rebrick_buffer_destroy(buffer);
    rebrick_http_header_destroy(header);
}

static void rebrick_http_header_to_http2_buffer_test(void **state)
{

    unused(state);
    int32_t result;
    rebrick_http_header_t *header;
    result = rebrick_http_header_new(&header, "http", "deneme.com", "POST", "/api/metrics", 2, 0);
    assert_int_equal(result, REBRICK_SUCCESS);
    result = rebrick_http_header_add_header(header, "content-type", "application/json");
    assert_int_equal(result, REBRICK_SUCCESS);

    nghttp2_nv *nv;
    size_t nvlen;
    result = rebrick_http_header_to_http2_buffer(header, &nv, &nvlen);
    assert_int_equal(result, REBRICK_SUCCESS);

    assert_int_equal(nvlen, 5);
    assert_memory_equal(nv[0].name, ":scheme", 7);
    assert_int_equal(nv[0].namelen, 7);
    assert_memory_equal(nv[0].value, "http", 4);
    assert_int_equal(nv[0].valuelen, 4);

    assert_memory_equal(nv[1].name, ":authority", 10);
    assert_int_equal(nv[1].namelen, 10);
    assert_memory_equal(nv[1].value, "deneme.com", 10);
    assert_int_equal(nv[1].valuelen, 10);

    assert_memory_equal(nv[2].name, ":method", 7);
    assert_int_equal(nv[2].namelen, 7);
    assert_memory_equal(nv[2].value, "POST", 4);
    assert_int_equal(nv[2].valuelen, 4);

    assert_memory_equal(nv[3].name, ":path", 5);
    assert_int_equal(nv[3].namelen, 5);
    assert_memory_equal(nv[3].value, "/api/metrics", 12);
    assert_int_equal(nv[3].valuelen, 12);

    assert_memory_equal(nv[4].name, "content-type", 12);
    assert_int_equal(nv[4].namelen, 12);
    assert_memory_equal(nv[4].value, "application/json", 16);
    assert_int_equal(nv[4].valuelen, 16);

    for (size_t i = 0; i < nvlen; ++i)
    {
        rebrick_free(nv[i].name);
        rebrick_free(nv[i].value);
    }
    rebrick_free(nv);
    rebrick_http_header_destroy(header);
}

int test_rebrick_http(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rebrick_http_keyvalue_test),
        cmocka_unit_test(rebrick_http_keyvalue_test2),
        cmocka_unit_test(rebrick_http_header_test),
        cmocka_unit_test(rebrick_http_header_test2),
        cmocka_unit_test(rebrick_http_header_test3),
        cmocka_unit_test(rebrick_http_header_test4),
        cmocka_unit_test(rebrick_http_header_to_http_buffer_test),
        cmocka_unit_test(rebrick_http_header_to_http2_buffer_test)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
