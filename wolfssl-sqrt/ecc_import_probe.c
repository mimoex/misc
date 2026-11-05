/* Test named-curve compressed-point import through the public API.
 * This path uses the curve's configured prime; it does NOT inject a modulus.
 */
#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

static int check_import(const char* name, const byte* encoded, word32 size, int curve_id)
{
    ecc_key key;
    int err = wc_ecc_init(&key);
    if (err != 0) {
        fprintf(stderr, "%s: wc_ecc_init=%d\n", name, err);
        return err;
    }
    err = wc_ecc_import_x963_ex(encoded, size, &key, curve_id);
    printf("%s: import_ret=%d\n", name, err);
    wc_ecc_free(&key);
    return err;
}

int main(void)
{
    /* P-256 base point x (SEC 2), y is odd => 0x03 prefix. */
    static const byte gx[32] = {
        0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,
        0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,
        0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96
    };
    byte point[33] = {0};
    int ok;
    int bad_square, bad_prefix, bad_len, bad_range;
    int bad = 0;

    point[0] = 0x03;
    memcpy(point + 1, gx, sizeof(gx));
    ok = check_import("valid_P256_G", point, sizeof(point), ECC_SECP256R1);

    /* x=1 is a quadratic nonresidue for x^3-3x+b on P-256. */
    memset(point, 0, sizeof(point));
    point[0] = 0x02;
    point[32] = 0x01;
    bad_square = check_import("P256_x1_no_sqrt", point, sizeof(point), ECC_SECP256R1);

    point[0] = 0x05; /* illegal compressed/uncompressed marker */
    bad_prefix = check_import("bad_prefix", point, sizeof(point), ECC_SECP256R1);

    point[0] = 0x02;
    bad_len = check_import("bad_length", point, sizeof(point) - 1, ECC_SECP256R1);

    memset(point + 1, 0xff, 32); /* x >= p */
    bad_range = check_import("P256_x_ge_p", point, sizeof(point), ECC_SECP256R1);

    if (ok != 0 || bad_square == 0 || bad_prefix == 0 || bad_len == 0 ||
            bad_range == 0) {
        bad = 1;
    }

#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
    {
        /* Standard secp224r1 base point: p mod 4 == 1 => Tonelli-Shanks. */
        static const byte p224_compressed_g[29] = {
            0x02,
            0xb7,0x0e,0x0c,0xbd,0x6b,0xb4,0xbf,0x7f,
            0x32,0x13,0x90,0xb9,0x4a,0x03,0xc1,0xd3,
            0x56,0xc2,0x11,0x22,0x34,0x32,0x80,0xd6,
            0x11,0x5c,0x1d,0x21
        };
        if (check_import("valid_P224_G_TonelliShanks", p224_compressed_g,
                         sizeof(p224_compressed_g), ECC_SECP224R1) != 0) {
            bad = 1;
        }
    }
#else
    puts("SKIP: P-224 not enabled by build (HAVE_ECC224/HAVE_ALL_CURVES absent)");
#endif


#if defined(HAVE_ECC_KOBLITZ) && (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES))
    {
        static const byte comp[]    = { 0x03, 0xa1, 0x45, 0x5b, 0x33, 0x4d, 0xf0, 0x99, 0xdf, 0x30, 0xfc, 0x28,
                                        0xa1, 0x69, 0xa4, 0x67, 0xe9, 0xe4, 0x70, 0x75, 0xa9, 0x0f, 0x7e, 0x65, 0x0e, 0xb6, 0xb7, 0xa4, 0x5c };
        static const byte uncomp[]  = { 0x04, 0xa1, 0x45, 0x5b, 0x33, 0x4d, 0xf0, 0x99, 0xdf, 0x30, 0xfc, 0x28,
                                        0xa1, 0x69, 0xa4, 0x67, 0xe9, 0xe4, 0x70, 0x75, 0xa9, 0x0f, 0x7e, 0x65,
                                        0x0e, 0xb6, 0xb7, 0xa4, 0x5c, 0x7e, 0x08, 0x9f, 0xed, 0x7f, 0xba, 0x34,
                                        0x42, 0x82, 0xca, 0xfb, 0xd6, 0xf7, 0xe3, 0x19, 0xf7, 0xc0, 0xb0, 0xbd,
                                        0x59, 0xe2, 0xca, 0x4b, 0xdb, 0x55, 0x6d, 0x61, 0xa5 };
        int c = check_import("secp224k1_compressed",
                             comp, sizeof(comp), ECC_SECP224K1);
        int u = check_import("secp224k1_uncompressed",
                             uncomp, sizeof(uncomp), ECC_SECP224K1);
        if (c != 0 || u != 0) bad = 1;
    }
#else
    puts("SKIP: secp224k1 is disabled");
#endif

    if (bad) {
        fprintf(stderr, "FAIL: unexpected public API result\n");
        return 1;
    }
    puts("PASS: valid compressed point accepted and malformed points rejected");
    return 0;
}
