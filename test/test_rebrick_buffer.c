#include "rebrick_buffer.h"
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

static void buffer_init_add_success(void **start){
    unused(start);
    rebrick_buffer_t *buffer;
    int32_t result=rebrick_buffer_new2(&buffer);
    assert_int_equal(result,0);

    char *testdata="deneme";
    rebrick_buffer_add(buffer,(uint8_t *)testdata,strlen(testdata)+1);
    assert_string_equal(buffer->buf,"deneme");


   rebrick_buffer_destroy(buffer);


}
static void buffer_init_add_two_string_success(void **start){
    unused(start);
    rebrick_buffer_t *buffer;
    int32_t result=rebrick_buffer_new2(&buffer);
    assert_int_equal(result,0);

    char *testdata="deneme";
    rebrick_buffer_add(buffer,(uint8_t *)testdata,strlen(testdata));
    assert_int_equal(buffer->len,6);
    char *testdata2="kilic";
    rebrick_buffer_add(buffer,(uint8_t*)testdata2,strlen(testdata2)+1);
    assert_int_equal(buffer->len,12);

    assert_string_equal(buffer->buf,"denemekilic");


   rebrick_buffer_destroy(buffer);


}


static void buffer_init_add_big_string_success(void **start){
    unused(start);
    rebrick_buffer_t *buffer;
    int32_t result=rebrick_buffer_new2(&buffer);
    assert_int_equal(result,0);

    char *testdata="deneme";
    rebrick_buffer_add(buffer,(uint8_t *)testdata,strlen(testdata));
    char *testdata2="jwikabirgamhkyxgfdxjqsesuadcakukwxthxsarhscjtcsjhpsmuferppmbynrwbyajmkmbpialwcawdmzxhhcmwctwmzsubadyswvzmfgllwetwxgiamcumlzwgaxrxhvzihzgxddxloqgpzmphyjuysorwmpdygqncjfxjkrjziakutpnuxnbxmaoyunhnlxfbvytxqnbevkqedceshtuedpivliscyjmqmkyfybzdbkzygstuuxsyfwffbzulbzorkiyjesnvbglrtnfrjtxifvglzphvgaevmsicknqxqeuhbvwtnaajaaykgyvzqqrlxaktynuamrnzhfajuzdyubcyydjsjjqhbsndaprbvocemyavsaaszpswzjgcsbtqjdlozyobpsmajglsnlgksxjbfnuipfqqqiqvossiynubgcnmzwgxkexqdrbchxtajswrrxscdmxwmmoeacxxjbyqukhbccbjnketzfmptrlqoztsdabpdumdobl";
    rebrick_buffer_add(buffer,(uint8_t*)testdata2,strlen(testdata2)+1);

    assert_string_equal(buffer->buf,"denemejwikabirgamhkyxgfdxjqsesuadcakukwxthxsarhscjtcsjhpsmuferppmbynrwbyajmkmbpialwcawdmzxhhcmwctwmzsubadyswvzmfgllwetwxgiamcumlzwgaxrxhvzihzgxddxloqgpzmphyjuysorwmpdygqncjfxjkrjziakutpnuxnbxmaoyunhnlxfbvytxqnbevkqedceshtuedpivliscyjmqmkyfybzdbkzygstuuxsyfwffbzulbzorkiyjesnvbglrtnfrjtxifvglzphvgaevmsicknqxqeuhbvwtnaajaaykgyvzqqrlxaktynuamrnzhfajuzdyubcyydjsjjqhbsndaprbvocemyavsaaszpswzjgcsbtqjdlozyobpsmajglsnlgksxjbfnuipfqqqiqvossiynubgcnmzwgxkexqdrbchxtajswrrxscdmxwmmoeacxxjbyqukhbccbjnketzfmptrlqoztsdabpdumdobl");


   rebrick_buffer_destroy(buffer);


}

static void buffer_init_add_remove_fromhead_success(void **start){
    unused(start);
    rebrick_buffer_t *buffer;
    int32_t result=rebrick_buffer_new2(&buffer);
    assert_int_equal(result,0);

    char *testdata="deneme";
    rebrick_buffer_add(buffer,(uint8_t *)testdata,strlen(testdata));
    char *testdata2="jwikabirgamhkyxgfdxjqsesuadcakukwxthxsarhscjtcsjhpsmuferppmbynrwbyajmkmbpialwcawdmzxhhcmwctwmzsubadyswvzmfgllwetwxgiamcumlzwgaxrxhvzihzgxddxloqgpzmphyjuysorwmpdygqncjfxjkrjziakutpnuxnbxmaoyunhnlxfbvytxqnbevkqedceshtuedpivliscyjmqmkyfybzdbkzygstuuxsyfwffbzulbzorkiyjesnvbglrtnfrjtxifvglzphvgaevmsicknqxqeuhbvwtnaajaaykgyvzqqrlxaktynuamrnzhfajuzdyubcyydjsjjqhbsndaprbvocemyavsaaszpswzjgcsbtqjdlozyobpsmajglsnlgksxjbfnuipfqqqiqvossiynubgcnmzwgxkexqdrbchxtajswrrxscdmxwmmoeacxxjbyqukhbccbjnketzfmptrlqoztsdabpdumdobl";
    rebrick_buffer_add(buffer,(uint8_t*)testdata2,strlen(testdata2)+1);
    assert_int_equal(buffer->len,519);
    rebrick_buffer_remove(buffer,0,6);

    assert_string_equal(buffer->buf,testdata2);
    assert_int_equal(buffer->len,513);

   rebrick_buffer_destroy(buffer);


}

static void buffer_init_add_remove_fromcenter_success(void **start){
    unused(start);
    rebrick_buffer_t *buffer;
    int32_t result=rebrick_buffer_new2(&buffer);
    assert_int_equal(result,0);

    char *testdata="deneme";
    rebrick_buffer_add(buffer,(uint8_t *)testdata,strlen(testdata));
    char *testdata2="jwikabirgamhkyxgfdxjqsesuadcakukwxthxsarhscjtcsjhpsmuferppmbynrwbyajmkmbpialwcawdmzxhhcmwctwmzsubadyswvzmfgllwetwxgiamcumlzwgaxrxhvzihzgxddxloqgpzmphyjuysorwmpdygqncjfxjkrjziakutpnuxnbxmaoyunhnlxfbvytxqnbevkqedceshtuedpivliscyjmqmkyfybzdbkzygstuuxsyfwffbzulbzorkiyjesnvbglrtnfrjtxifvglzphvgaevmsicknqxqeuhbvwtnaajaaykgyvzqqrlxaktynuamrnzhfajuzdyubcyydjsjjqhbsndaprbvocemyavsaaszpswzjgcsbtqjdlozyobpsmajglsnlgksxjbfnuipfqqqiqvossiynubgcnmzwgxkexqdrbchxtajswrrxscdmxwmmoeacxxjbyqukhbccbjnketzfmptrlqoztsdabpdumdobl";
    rebrick_buffer_add(buffer,(uint8_t*)testdata2,strlen(testdata2)+1);
    assert_int_equal(buffer->len,519);
    rebrick_buffer_remove(buffer,6,10);

    assert_string_equal(buffer->buf,"denememhkyxgfdxjqsesuadcakukwxthxsarhscjtcsjhpsmuferppmbynrwbyajmkmbpialwcawdmzxhhcmwctwmzsubadyswvzmfgllwetwxgiamcumlzwgaxrxhvzihzgxddxloqgpzmphyjuysorwmpdygqncjfxjkrjziakutpnuxnbxmaoyunhnlxfbvytxqnbevkqedceshtuedpivliscyjmqmkyfybzdbkzygstuuxsyfwffbzulbzorkiyjesnvbglrtnfrjtxifvglzphvgaevmsicknqxqeuhbvwtnaajaaykgyvzqqrlxaktynuamrnzhfajuzdyubcyydjsjjqhbsndaprbvocemyavsaaszpswzjgcsbtqjdlozyobpsmajglsnlgksxjbfnuipfqqqiqvossiynubgcnmzwgxkexqdrbchxtajswrrxscdmxwmmoeacxxjbyqukhbccbjnketzfmptrlqoztsdabpdumdobl");
    assert_int_equal(buffer->len,509);

   rebrick_buffer_destroy(buffer);


}
int test_rebrick_buffer(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(buffer_init_add_success),
        cmocka_unit_test(buffer_init_add_two_string_success),
        cmocka_unit_test(buffer_init_add_big_string_success),
        cmocka_unit_test(buffer_init_add_remove_fromhead_success),
        cmocka_unit_test(buffer_init_add_remove_fromcenter_success)


    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

