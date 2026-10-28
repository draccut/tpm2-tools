/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_random_ctx {
    UINT16 num_of_bytes;
    char   *output_file;
    bool   show_help;
} tpm_random_ctx;

static tpm_random_ctx ctx = {
    .num_of_bytes = 32,
    .output_file  = "/dev/stdout",
    .show_help    = false,
};

static void print_help(void)
{
    printf(
        "Usage: tpm2 tpm2_two_sources_rd [num_bytes] [output_file]\n"
        "Combines the generation of random values for symmetric encryption \n"
        "from a kernel-controlled random unit and from a TPM random unit. \n"
        "Queries every chip twice to confirm the module is working. \n"
        "Finally, performs a logical XOR on the two vectors, stores the result bits \n"
        "in a new vector, and prints them for piping or writes them to a file."

        "\n"
        "@VERSION 0.1.0\n"
        "\n"
        "Arguments:\n"
        "  num_bytes     Number of random bytes to generate (default: 32).\n"
        "                Use 0 to show this help message.\n"
        "  output_file   Optional path to write the random bytes.\n"
        "                If omitted, bytes are written to stdout.\n"
        "\n"
        "When a filename is given and the extension is one of\n"
        "  .rs  .c  .asm  .txt\n"
        "the output is written as a C-style hex list (0x11, 0xF2, ...),\n"
        "16 values per line.  Otherwise the raw binary is written.\n"
        "\n"
        "Examples:\n"
        "  tpm2 tpm2_two_sources_rd\n"
        "  tpm2 tpm2_two_sources_rd 64\n"
        "  tpm2 tpm2_two_sources_rd 32 random.bin\n"
        "  tpm2 tpm2_two_sources_rd 32 entropy.rs\n");
}

static bool is_text_extension(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) {
        return false;
    }
    const char *ext = dot + 1;
    return (!strcmp(ext, "rs") || !strcmp(ext, "c") || !strcmp(ext, "asm") || !strcmp(ext, "txt"));
}

static tool_rc get_random_from_tpm(ESYS_CONTEXT *ectx, UINT16 size, TPM2B_DIGEST **out)
{
    TPM2B_DIGEST cp_hash = { .size = 0 }; /* the API requires non-NULL pointers */
    TPM2B_DIGEST rp_hash = { .size = 0 }; /* the API requires non-NULL pointers */
    tool_rc rc = tpm2_getrandom(ectx, size, out,
                                &cp_hash, &rp_hash,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                TPM2_ALG_ERROR);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get random bytes from TPM");
    }
    return rc;
}

static tool_rc get_random_from_kernel(UINT16 size, uint8_t **out)
{
    *out = malloc(size);
    if (!*out) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        LOG_ERR("Could not open /dev/urandom: %s", strerror(errno));
        free(*out);
        *out = NULL;
        return tool_rc_general_error;
    }
    ssize_t n = read(fd, *out, size);
    close(fd);
    if (n != (ssize_t)size) {
        LOG_ERR("Short read from /dev/urandom");
        free(*out);
        *out = NULL;
        return tool_rc_general_error;
    }
    return tool_rc_success;
}

static void xor_buffers(const uint8_t *a, const uint8_t *b, uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

static uint32_t sum_buffer(const uint8_t *buf, size_t len)
{
    uint32_t s = 0;
    for (size_t i = 0; i < len; i++) {
        s += buf[i];
    }
    return s;
}

static tool_rc write_hex_list(FILE *out, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (fprintf(out, "0x%02X%s", buf[i], (i + 1 == len) ? "" : ", ") < 0) {
            return tool_rc_general_error;
        }
        if ((i + 1) % 16 == 0 && i + 1 < len) {
            if (fputc('\n', out) == EOF) {
                return tool_rc_general_error;
            }
        }
    }
    if (fputc('\n', out) == EOF) {
        return tool_rc_general_error;
    }
    return tool_rc_success;
}

static tool_rc write_and_verify(const uint8_t *buf, size_t len)
{
    FILE *out = NULL;
    out = fopen(ctx.output_file, "wb");
    bool as_text = is_text_extension(ctx.output_file);
    if (!out) {
        LOG_ERR("Could not open \"%s\": %s%s", ctx.output_file, strerror(errno), "\n");
        return tool_rc_general_error;
    }
    tool_rc rc;
    if (as_text) {
        rc = write_hex_list(out, buf, len);
    } else {
        if (files_write_bytes(out, buf, len)) {
            rc = tool_rc_success;
        } else {
            rc = tool_rc_general_error;
        }
    }
    fclose(out);
    return rc;
}

static tool_rc do_random_work(ESYS_CONTEXT *ectx)
{
    const UINT16 n = ctx.num_of_bytes;
    TPM2B_DIGEST *tpm1 = NULL;
    TPM2B_DIGEST *tpm2 = NULL;
    uint8_t      *ker1 = NULL;
    uint8_t      *ker2 = NULL;
    uint8_t      *xor_tpm = NULL;
    uint8_t      *xor_ker = NULL;
    uint8_t      *final   = NULL;
    tool_rc rc = tool_rc_general_error;
    rc = get_random_from_tpm(ectx, n, &tpm1);
    if (rc != tool_rc_success) goto out;
    rc = get_random_from_tpm(ectx, n, &tpm2);
    if (rc != tool_rc_success) goto out;
    if (tpm1->size != n || tpm2->size != n) {
        LOG_ERR("TPM returned unexpected size");
        goto out;
    }
    rc = get_random_from_kernel(n, &ker1);
    if (rc != tool_rc_success) goto out;
    rc = get_random_from_kernel(n, &ker2);
    if (rc != tool_rc_success) goto out;
    xor_tpm = malloc(n);
    if (!xor_tpm) goto out;
    xor_buffers(tpm1->buffer, tpm2->buffer, xor_tpm, n);
    if (sum_buffer(xor_tpm, n) == 0) {
        LOG_ERR("TPM RNG produced identical values twice  -  entropy failure");
        rc = tool_rc_general_error;
        goto out;
    }
    xor_ker = malloc(n);
    if (!xor_ker) goto out;
    xor_buffers(ker1, ker2, xor_ker, n);
    if (sum_buffer(xor_ker, n) == 0) {
        LOG_ERR("Kernel RNG produced identical values twice  -  entropy failure");
        rc = tool_rc_general_error;
        goto out;
    }
    final = malloc(n);
    if (!final) goto out;
    xor_buffers(xor_tpm, xor_ker, final, n);
    rc = write_and_verify(final, n);
    out:
    free(tpm1);
    free(tpm2);
    free(ker1);
    free(ker2);
    free(xor_tpm);
    free(xor_ker);
    free(final);
    return rc;
}

static bool on_args(int argc, char **argv)
{
    if (argc == 0) {
        ctx.show_help = true;
        return true;
    }
    if (argc > 2) {
        LOG_ERR("Too many arguments (max 2: num_bytes [output_file])");
        print_help();
        return false;
    }
    if (!tpm2_util_string_to_uint16(argv[0], &ctx.num_of_bytes)) {
        LOG_ERR("Invalid num_bytes: \"%s\"", argv[0]);
        return false;
    }
    if (ctx.num_of_bytes == 0) {
        ctx.show_help = true;
        return true;
    }
    if (argc == 2) {
        ctx.output_file = argv[1];
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts)
{
    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_args, 0);
    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags)
{
    UNUSED(flags);
    if (ctx.show_help) {
        print_help();
        return tool_rc_success;
    }
    return do_random_work(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx)
{
    UNUSED(ectx);
    return tool_rc_success;
}

TPM2_TOOL_REGISTER("tpm2_two_sources_rd",
                   tpm2_tool_onstart,
                   tpm2_tool_onrun,
                   tpm2_tool_onstop,
                   NULL);

