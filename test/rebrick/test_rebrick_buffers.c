#include "./rebrick/common/rebrick_buffers.h"
#include "cmocka.h"
#define REBRICK_BUFFER_DEFAULT_MALLOC_SIZE 1024
static int setup(void **state) {
  unused(state);
  fprintf(stdout, "****  %s ****\n", __FILE__);
  return 0;
}

static int teardown(void **state) {
  unused(state);
  return 0;
}

static void buffer_init_add_success(void **start) {
  unused(start);
  rebrick_buffers_t *buffer;
  char *deneme = "hamza";
  int32_t result = rebrick_buffers_new(&buffer, cast(deneme, uint8_t *), strlen(deneme), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);
  assert_string_equal(buffer->head_page->buf, "hamza");
  assert_int_equal(buffer->head_page->len, 5);

  char *testdata = "deneme";
  rebrick_buffers_add(buffer, (uint8_t *)testdata, strlen(testdata));
  assert_string_equal(buffer->head_page->buf, "hamzadeneme");
  assert_int_equal(buffer->head_page->len, 11);
  rebrick_buffers_page_t *tmp;
  int32_t counter;
  DL_COUNT(buffer->head_page, tmp, counter);
  assert_int_equal(counter, 1);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_big_string_success(void **start) {
  unused(start);
  rebrick_buffers_t *buffer;
  // big string
  char deneme[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32];
  memset(deneme, 0, sizeof(deneme));
  for (int i = 0; i < REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 3; ++i)
    deneme[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)deneme, sizeof(deneme), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);
  int32_t pagecount;
  rebrick_buffers_page_t *el;
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 2);
  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_memory_equal(buffer->head_page->buf, deneme, buffer->head_page->len);
  assert_int_equal(buffer->head_page->next->len, 32);

  assert_memory_equal(buffer->head_page->next->buf, deneme + (buffer->head_page->len), buffer->head_page->next->len);

  // add a small string
  uint8_t *deneme2 = (uint8_t *)"deneme";
  rebrick_buffers_add(buffer, deneme2, (size_t)6);

  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 2);
  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_memory_equal(buffer->head_page->buf, deneme, buffer->head_page->len);
  assert_int_equal(buffer->head_page->next->len, 32 + 6);
  assert_memory_equal(buffer->head_page->next->buf, deneme + buffer->head_page->len, buffer->head_page->next->len - 6);
  assert_memory_equal(buffer->head_page->next->buf + 32, deneme2, 6);

  // add a big string
  char test[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  for (int i = 0; i < REBRICK_BUFFER_DEFAULT_MALLOC_SIZE; ++i)
    test[i] = (i % 28) + 97;

  rebrick_buffers_add(buffer, (uint8_t *)test, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);

  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 3);
  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_memory_equal(buffer->head_page->buf, deneme, buffer->head_page->len);
  assert_int_equal(buffer->head_page->next->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_memory_equal(buffer->head_page->next->buf, deneme + REBRICK_BUFFER_DEFAULT_MALLOC_SIZE, 32);
  assert_memory_equal(buffer->head_page->next->buf + 32, deneme2, 6);
  assert_memory_equal(buffer->head_page->next->buf + 32 + 6, test, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 32 - 6);

  assert_int_equal(buffer->head_page->next->next->len, 32 + 6);
  assert_memory_equal(buffer->head_page->next->next->buf, test + REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 32 - 6, 32 + 6);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromhead_success(void **start) {
  // 0-10 test
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);
  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // 0-10
  rebrick_buffers_remove(buffer, 0, 10);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 1);
  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 10);
  assert_memory_equal(part1 + 10, buffer->head_page->buf, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 10);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromhead_success2(void **start) {
  // 0-10
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // 0-10
  rebrick_buffers_remove(buffer, 0, 10);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 2);
  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 10);
  assert_memory_equal(part1 + 10, buffer->head_page->buf, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 10);
  assert_int_equal(buffer->head_page->next->len, 32);
  assert_memory_equal(buffer->head_page->next->buf, part2, 32);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromhead_success3(void **start) {
  // 0-REBRICK_BUFFER_DEFAULT_MALLOC_SIZE
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // 0-10
  rebrick_buffers_remove(buffer, 0, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 1);
  assert_int_equal(buffer->head_page->len, 32);
  assert_memory_equal(buffer->head_page->buf, part2, 32);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromhead_success4(void **start) {
  // 0-REBRICK_BUFFER_DEFAULT_MALLOC_SIZE
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // 0-10
  rebrick_buffers_remove(buffer, 0, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 0);
  assert_null(buffer->head_page);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromcenter_success(void **start) {
  unused(start);
  // 10-20
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // 10-20
  rebrick_buffers_remove(buffer, 10, 20);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 2);
  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 20);
  assert_memory_equal(buffer->head_page->buf, part1, 10);
  assert_memory_equal(buffer->head_page->buf + 10, part1 + 30, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - 30);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromcenter_success2(void **start) {
  unused(start);
  // REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-20
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-20
  rebrick_buffers_remove(buffer, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE, 20);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 2);

  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_memory_equal(buffer->head_page->buf, part1, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);

  assert_int_equal(buffer->head_page->next->len, 12);
  assert_memory_equal(buffer->head_page->next->buf, part2 + 20, 12);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromcenter_success3(void **start) {
  unused(start);
  // REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-32
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-32
  rebrick_buffers_remove(buffer, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE, 32);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 1);

  assert_int_equal(buffer->head_page->len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_memory_equal(buffer->head_page->buf, part1, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);

  rebrick_buffers_destroy(buffer);
}

static void buffer_init_add_remove_fromcenter_success4(void **start) {
  unused(start);
  // 0-REBRICK_BUFFER_DEFAULT_MALLOC_SIZE+32
  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t pagecount;
  rebrick_buffers_page_t *el;

  // REBRICK_BUFFER_DEFAULT_MALLOC_SIZE-32
  rebrick_buffers_remove(buffer, 0, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32);
  DL_COUNT(buffer->head_page, el, pagecount);
  assert_int_equal(pagecount, 0);

  rebrick_buffers_destroy(buffer);
}

static void buffer_total_len(void **start) {
  unused(start);

  unused(start);
  rebrick_buffers_t *buffer;
  // big string full page
  char part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  int32_t result = rebrick_buffers_new(&buffer, (uint8_t *)part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
  assert_int_equal(result, 0);

  // add other buffer
  char part2[32];
  memset(part2, 0, sizeof(part2));
  for (int i = 0; i < ssizeof(part2); ++i)
    part2[i] = (i % 28) + 97;
  result = rebrick_buffers_add(buffer, (uint8_t *)part2, sizeof(part2));
  assert_int_equal(result, 0);

  int32_t total_len = rebrick_buffers_total_len(buffer);
  assert_int_equal(total_len, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32);

  rebrick_buffers_destroy(buffer);
}

static void buffer_check_memory(void **start) {

  unused(start);

  unused(start);
#define LIST_SIZE 1000

  // big string full page
  uint8_t part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  // size_t totalbuflen = 0;
  for (int a = 0; a < LIST_SIZE; ++a) {
    rebrick_buffers_t *tmp;
    int32_t result = rebrick_buffers_new(&tmp, part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);
    rebrick_buffers_destroy(tmp);
  }
}

static void buffer_check_memory2(void **start) {

  unused(start);
  unused(start);
#undef LIST_SIZE
#define LIST_SIZE 100

  // big string full page
  uint8_t part1[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE + 32];
  memset(part1, 0, sizeof(part1));
  for (int i = 0; i < ssizeof(part1); ++i)
    part1[i] = (i % 28) + 97;
  // size_t totalbuflen = 0;
  for (int a = 0; a < LIST_SIZE; ++a) {
    rebrick_buffers_t *tmp;
    int32_t result = rebrick_buffers_new(&tmp, part1, sizeof(part1), REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
    assert_int_equal(result, 0);
    int counter = 57;
    while (counter--) {
      result = rebrick_buffers_add(tmp, part1, sizeof(part1));
      assert_int_equal(result, 0);
    }
    rebrick_buffers_destroy(tmp);
  }
}

int test_rebrick_buffers(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(buffer_init_add_success),
      cmocka_unit_test(buffer_init_add_big_string_success),
      cmocka_unit_test(buffer_init_add_remove_fromhead_success),
      cmocka_unit_test(buffer_init_add_remove_fromhead_success2),
      cmocka_unit_test(buffer_init_add_remove_fromhead_success3),
      cmocka_unit_test(buffer_init_add_remove_fromhead_success4),
      cmocka_unit_test(buffer_init_add_remove_fromcenter_success),
      cmocka_unit_test(buffer_init_add_remove_fromcenter_success2),
      cmocka_unit_test(buffer_init_add_remove_fromcenter_success3),
      cmocka_unit_test(buffer_init_add_remove_fromcenter_success4),
      cmocka_unit_test(buffer_total_len),
      cmocka_unit_test(buffer_check_memory),
      cmocka_unit_test(buffer_check_memory2),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
