/*
 * wolfSSL Ed25519 / Ed448 separate-import versus mode-import regression.
 * Compile twice, once normally and once with -DTEST_ED448.
 * Inputs: raw private seed and matching raw public key (NOT PEM/DER).
 */
#include <wolfssl/options.h>
#if defined(TEST_ED448)
    #include <wolfssl/wolfcrypt/ed448.h>
    #define ALGORITHM "Ed448"
    #define ED_KEY ed448_key
    #define KEY_SIZE ED448_KEY_SIZE
    #define ED_INIT wc_ed448_init
    #define ED_IMPORT_PRIVATE_ONLY wc_ed448_import_private_only
    #define ED_IMPORT_PUBLIC wc_ed448_import_public
    #define ED_IMPORT_BOTH wc_ed448_import_private_key
    #define ED_EXPORT_PUBLIC wc_ed448_export_public
    #define ED_EXPORT_PRIVATE wc_ed448_export_private
    #define ED_CHECK_KEY wc_ed448_check_key
    #define ED_FREE wc_ed448_free
#else
    #include <wolfssl/wolfcrypt/ed25519.h>
    #define ALGORITHM "Ed25519"
    #define ED_KEY ed25519_key
    #define KEY_SIZE ED25519_KEY_SIZE
    #define ED_INIT wc_ed25519_init
    #define ED_IMPORT_PRIVATE_ONLY wc_ed25519_import_private_only
    #define ED_IMPORT_PUBLIC wc_ed25519_import_public
    #define ED_IMPORT_BOTH wc_ed25519_import_private_key
    #define ED_EXPORT_PUBLIC wc_ed25519_export_public
    #define ED_EXPORT_PRIVATE wc_ed25519_export_private
    #define ED_CHECK_KEY wc_ed25519_check_key
    #define ED_FREE wc_ed25519_free
#endif

#include <stdio.h>
#include <string.h>

static int read_exact(const char* path, byte* out, size_t expected)
{
    FILE* f = fopen(path, "rb");
    size_t got;
    int extra;
    if (f == NULL) {
        perror(path);
        return -1;
    }
    got = fread(out, 1, expected, f);
    extra = fgetc(f);
    fclose(f);
    if (got != expected || extra != EOF) {
        fprintf(stderr, "%s: expected exactly %zu bytes (got %zu or extra data)\n",
                path, expected, got);
        return -1;
    }
    return 0;
}

static void print_hex(const byte* data, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) printf("%02x", (unsigned)data[i]);
    putchar('\n');
}

#define IMPORT_MODE_BOTH        0
#define IMPORT_MODE_SEC_PUB     1
#define IMPORT_MODE_PUB_SEC     2

static int run_case(const byte* seed, const byte* expected_pub, int mode)
{
    ED_KEY key;
    ED_KEY roundtrip;
    byte full[2 * KEY_SIZE];
    byte public_out[KEY_SIZE];
    word32 full_len = (word32)sizeof(full);
    word32 public_len = (word32)sizeof(public_out);
    int ret;
    int public_match, seed_match, suffix_match;

    ret = ED_INIT(&key);
    if (ret != 0) {
        fprintf(stderr, "key init returned %d\n", ret);
        return 1;
    }

    // Import keys, either mode or separate.
    if (mode == IMPORT_MODE_BOTH) {
        ret = ED_IMPORT_BOTH(seed, KEY_SIZE, expected_pub, KEY_SIZE, &key);
        printf("mode import: ret=%d\n", ret);
    }
    // Import keys separately, first private then public.
    else if (mode == IMPORT_MODE_SEC_PUB) {
        ret = ED_IMPORT_PRIVATE_ONLY(seed, KEY_SIZE, &key);
        printf("private-only import: ret=%d\n", ret);
        if (ret == 0) {
            ret = ED_IMPORT_PUBLIC(expected_pub, KEY_SIZE, &key);
            printf("public import: ret=%d\n", ret);
        }
    }
    // Import keys separately, first public then private.
    else if (mode == IMPORT_MODE_PUB_SEC) {
        ret = ED_IMPORT_PUBLIC(expected_pub, KEY_SIZE, &key);
        printf("public import: ret=%d\n", ret);
        if (ret == 0) {
            ret = ED_IMPORT_PRIVATE_ONLY(seed, KEY_SIZE, &key);
            printf("private-only import: ret=%d\n", ret);
        }
    }
    else {
        fprintf(stderr, "invalid mode value %d\n", mode);
        ret = 1;
    }
    if (ret != 0) goto error;

    ret = ED_CHECK_KEY(&key);

    printf("key->p: ");
    print_hex(key.p, KEY_SIZE);
    printf("key->k: ");
    print_hex(key.k, 2 * KEY_SIZE);

    printf("check_key: ret=%d\n", ret);
    if (ret != 0) goto error;

    ret = ED_EXPORT_PUBLIC(&key, public_out, &public_len);
    if (ret != 0) {
        fprintf(stderr, "export_public returned %d\n", ret);
        goto error;
    }
    ret = ED_EXPORT_PRIVATE(&key, full, &full_len);
    if (ret != 0) {
        fprintf(stderr, "export_private returned %d\n", ret);
        goto error;
    }

    public_match = (public_len == KEY_SIZE) &&
                   (memcmp(public_out, expected_pub, KEY_SIZE) == 0);
    seed_match = (full_len == 2 * KEY_SIZE) &&
                 (memcmp(full, seed, KEY_SIZE) == 0);
    suffix_match = (full_len == 2 * KEY_SIZE) &&
                   (memcmp(full + KEY_SIZE, expected_pub, KEY_SIZE) == 0);

    printf("export_public matches OpenSSL public key: %s\n", public_match ? "YES" : "NO");
    printf("export_private seed half matches:          %s\n", seed_match ? "YES" : "NO");
    printf("export_private public half matches:        %s\n", suffix_match ? "YES" : "NO <-- BUG REPRODUCED");
    printf("key->p versus key->k public half:         %s\n",
           memcmp(key.p, key.k + KEY_SIZE, KEY_SIZE) == 0 ? "SAME" : "DIFFERENT");

    printf("expected public:      ");
    print_hex(expected_pub, KEY_SIZE);
    printf("exported public half: ");
    print_hex(full + KEY_SIZE, KEY_SIZE);

    ret = ED_INIT(&roundtrip);
    if (ret != 0) {
        fprintf(stderr, "roundtrip init returned %d\n", ret);
        goto error;
    }
    ret = ED_IMPORT_BOTH(full, full_len, NULL, 0, &roundtrip);
    printf("reimport exported mode key: ret=%d (%s)\n", ret,
           ret == 0 ? "ACCEPTED" : "REJECTED");
    ED_FREE(&roundtrip);

    ED_FREE(&key);
    return (public_match && seed_match && (mode ? suffix_match : 1)) ? 0 : 1;
error:
    ED_FREE(&key);
    return 1;
}

int main(int argc, char** argv)
{
    byte seed[KEY_SIZE];
    byte public_key[KEY_SIZE];
    int ret1, ret2, ret3;
    if (argc != 3) {
        fprintf(stderr, "Usage: %s seed.raw pub.raw (%s, %d bytes each)\n",
                argv[0], ALGORITHM, KEY_SIZE);
        return 2;
    }
    if (read_exact(argv[1], seed, KEY_SIZE) != 0 ||
        read_exact(argv[2], public_key, KEY_SIZE) != 0)
        return 2;
    printf("seed: ");
    print_hex(seed, KEY_SIZE);
    printf("public: ");
    print_hex(public_key, KEY_SIZE);
    
    printf("=== %s separate imports(sec->pub) ===\n", ALGORITHM);
    ret1 = run_case(seed, public_key, IMPORT_MODE_SEC_PUB);
    printf("\n=== %s separate imports(pub->sec) ===\n", ALGORITHM);
    ret2 = run_case(seed, public_key, IMPORT_MODE_PUB_SEC);
    printf("\n=== %s mode import (control) ===\n", ALGORITHM);
    ret3 = run_case(seed, public_key, IMPORT_MODE_BOTH);
    printf("\n=== Results ===\n");
    printf("separate imports(sec->pub): %s\n", ret1 == 0 ? "PASS" : "FAIL");
    printf("separate imports(pub->sec): %s\n", ret2 == 0 ? "PASS" : "FAIL");
    printf("mode import (control):      %s\n", ret3 == 0 ? "PASS" : "FAIL");
    return (ret1 || ret2 || ret3) ? 1 : 0;
    
}
