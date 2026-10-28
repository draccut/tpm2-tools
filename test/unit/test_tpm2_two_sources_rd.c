#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../../tools/tpm2_two_sources_rd.c"

static void test_xor_buffers_standard(void **state) {
    (void) state;
    const uint8_t buf_a[]    = { 0x0F, 0xF0, 0x55, 0xAA };
    const uint8_t buf_b[]    = { 0x0F, 0x0F, 0xAA, 0x55 };
    uint8_t dst[4]           = { 0 };
    const uint8_t expected[] = { 0x00, 0xFF, 0xFF, 0xFF };
    xor_buffers(buf_a, buf_b, dst, 4);
    assert_memory_equal(dst, expected, 4);
}

static void test_sum_buffer_standard(void **state) {
    (void) state;
    const uint8_t buf[] = { 1, 2, 3, 4, 10 };
    uint32_t result = sum_buffer(buf, 5);
    assert_int_equal(result, 20);
}

static void test_sum_buffer_zero_length(void **state) {
    (void) state;
    const uint8_t buf[] = { 0 };
    uint32_t result = sum_buffer(buf, 0);
    assert_int_equal(result, 0);
}

static void test_is_text_extension_valid(void **state) {
    (void) state;
    assert_true(is_text_extension("key.c"));
    assert_true(is_text_extension("blob.rs"));
}

static void test_is_text_extension_invalid(void **state) {
    (void) state;
    assert_false(is_text_extension("image.png"));
    assert_false(is_text_extension("hexdump"));
}

/* test buffer with 18 Bytes to test line break at byte 16 */
static void test_write_hex_list_standard(void **state) {
    (void) state;
    const uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0xFF,
        0xAA, 0x55
    };
    char *result_str = NULL;
    size_t result_len = 0;
    FILE *mem_stream = open_memstream(&result_str, &result_len);
    assert_non_null(mem_stream);
    tool_rc rc = write_hex_list(mem_stream, buf, sizeof(buf));
    fclose(mem_stream);
    const char *expected = "0x01, 0x02, 0x03, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0xFF\n"
    "0xAA, 0x55\n";
    assert_int_equal(rc, tool_rc_success);
    assert_string_equal(result_str, expected);
    free(result_str);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_xor_buffers_standard),
        cmocka_unit_test(test_sum_buffer_standard),
        cmocka_unit_test(test_sum_buffer_zero_length),
        cmocka_unit_test(test_is_text_extension_valid),
        cmocka_unit_test(test_is_text_extension_invalid),
        cmocka_unit_test(test_write_hex_list_standard),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
