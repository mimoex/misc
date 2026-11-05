/*
 * Reproduce Ed25519 / Ed448 combined-key export after separate ASN.1 imports.
 *
 * Build inside wolfssl/repro, linking the current libwolfssl.a.
 * Build twice: normal for Ed25519, -DTEST_ED448 for Ed448.
 *
 * Usage: ./repro_ed_asn25519 private.der public.der seed.raw public.raw
 * The DER files should be PKCS#8 private key (without embedded public key)
 * and SubjectPublicKeyInfo public key, respectively.
 *
 * Test-only program: never print the private seed or use generated keys
 * for production purposes.
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef TEST_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
    #define ALG_NAME "Ed448"
    #define ED_KEY ed448_key
    #define ED_KEY_SIZE ED448_KEY_SIZE
    #define ED_PUB_SIZE ED448_PUB_KEY_SIZE
    #define ED_PRIV_SIZE ED448_PRV_KEY_SIZE
    #define ED_INIT wc_ed448_init
    #define ED_FREE wc_ed448_free
    #define ED_DECODE_PRIV wc_Ed448PrivateKeyDecode
    #define ED_DECODE_PUB wc_Ed448PublicKeyDecode
    #define ED_CHECK wc_ed448_check_key
    #define ED_EXPORT wc_ed448_export_private
    #define ED_IMPORT_BOTH wc_ed448_import_private_key
#else
    #include <wolfssl/wolfcrypt/ed25519.h>
    #define ALG_NAME "Ed25519"
    #define ED_KEY ed25519_key
    #define ED_KEY_SIZE ED25519_KEY_SIZE
    #define ED_PUB_SIZE ED25519_PUB_KEY_SIZE
    #define ED_PRIV_SIZE ED25519_PRV_KEY_SIZE
    #define ED_INIT wc_ed25519_init
    #define ED_FREE wc_ed25519_free
    #define ED_DECODE_PRIV wc_Ed25519PrivateKeyDecode
    #define ED_DECODE_PUB wc_Ed25519PublicKeyDecode
    #define ED_CHECK wc_ed25519_check_key
    #define ED_EXPORT wc_ed25519_export_private
    #define ED_IMPORT_BOTH wc_ed25519_import_private_key
#endif

#include <stdio.h>
#include <string.h>

#define MAX_DER_SIZE 4096

static int read_bytes(const char* path, byte* out, size_t capacity,
                      word32* outLen)
{
    FILE* f;
    size_t n;
    int extra;

    f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    n = fread(out, 1, capacity, f);
    extra = fgetc(f);
    if (ferror(f) || extra != EOF) {
        fprintf(stderr, "Cannot read %s (too large or I/O error)\n", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    *outLen = (word32)n;
    if (n == 0) {
        fprintf(stderr, "File is empty: %s\n", path);
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

static int run_order(int private_first,
                     const byte* privDer, word32 privDerSz,
                     const byte* pubDer, word32 pubDerSz,
                     const byte* expectedSeed, const byte* expectedPub)
{
    ED_KEY key;
    ED_KEY restored;
    byte combined[ED_PRIV_SIZE];
    word32 index;
    word32 combinedLen;
    int ret;
    int ok;
    int initialized;
    int restoredInitialized;
    int seedMatches;
    int pubMatches;

    ok = 0;
    initialized = 0;
    restoredInitialized = 0;
    memset(&key, 0, sizeof(key));
    memset(&restored, 0, sizeof(restored));
    memset(combined, 0, sizeof(combined));

    printf("\n=== %s ASN.1 %s ===\n", ALG_NAME,
           private_first ? "private -> public" : "public -> private");

    ret = ED_INIT(&key);
    printf("key init: %d\n", ret);
    if (ret != 0)
        goto done;
    initialized = 1;

    index = 0;
    if (private_first) {
        ret = ED_DECODE_PRIV(privDer, &index, &key, privDerSz);
        printf("PKCS#8 private decode: %d (priv=%d, pub=%d)\n",
               ret, key.privKeySet, key.pubKeySet);
        if (ret != 0)
            goto done;
        if (key.pubKeySet) {
            printf("Private DER already includes a public key; this is "
                   "not the private-only decode path.\n");
            goto done;
        }
        index = 0;
        ret = ED_DECODE_PUB(pubDer, &index, &key, pubDerSz);
        printf("SPKI public decode:    %d (priv=%d, pub=%d)\n",
               ret, key.privKeySet, key.pubKeySet);
    }
    else {
        ret = ED_DECODE_PUB(pubDer, &index, &key, pubDerSz);
        printf("SPKI public decode:    %d (priv=%d, pub=%d)\n",
               ret, key.privKeySet, key.pubKeySet);
        if (ret != 0)
            goto done;
        index = 0;
        ret = ED_DECODE_PRIV(privDer, &index, &key, privDerSz);
        printf("PKCS#8 private decode: %d (priv=%d, pub=%d)\n",
               ret, key.privKeySet, key.pubKeySet);
    }
    if (ret != 0)
        goto done;

    ret = ED_CHECK(&key);
    printf("check_key:             %d\n", ret);
    if (ret != 0)
        goto done;

    combinedLen = (word32)sizeof(combined);
    ret = ED_EXPORT(&key, combined, &combinedLen);
    printf("export_private:        %d (length=%u)\n",
           ret, (unsigned)combinedLen);
    if (ret != 0)
        goto done;
    if (combinedLen != ED_PRIV_SIZE) {
        printf("Unexpected combined key size\n");
        goto done;
    }

    printf("\n--- Public key comparison ---\n");

    printf("Expected public key: ");
    print_hex(expectedPub, ED_PUB_SIZE);

    printf("key->p:              ");
    print_hex(key.p, ED_PUB_SIZE);

    printf("key->k public half:  ");
    print_hex(key.k + ED_KEY_SIZE, ED_PUB_SIZE);

    printf("Exported public key: ");
    print_hex(combined + ED_KEY_SIZE, ED_PUB_SIZE);

    seedMatches = (memcmp(combined, expectedSeed, ED_KEY_SIZE) == 0);
    pubMatches = (memcmp(combined + ED_KEY_SIZE,
                         expectedPub, ED_PUB_SIZE) == 0);
    printf("exported seed matches OpenSSL: %s\n",
           seedMatches ? "YES" : "NO");
    printf("exported pub matches OpenSSL:  %s\n",
           pubMatches ? "YES" : "NO");
    printf("key->p equals key->k suffix:  %s\n",
           memcmp(key.p, key.k + ED_KEY_SIZE, ED_PUB_SIZE) == 0
           ? "YES" : "NO");

    ret = ED_INIT(&restored);
    if (ret != 0) {
        printf("restore key init: %d\n", ret);
        goto done;
    }
    restoredInitialized = 1;
    ret = ED_IMPORT_BOTH(combined, combinedLen, NULL, 0, &restored);
    printf("re-import combined key: %d\n", ret);
    ok = seedMatches && pubMatches && (ret == 0);

 done:
    if (restoredInitialized)
        ED_FREE(&restored);
    if (initialized)
        ED_FREE(&key);
    memset(combined, 0, sizeof(combined));
    printf("Result: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main(int argc, char** argv)
{
    byte privDer[MAX_DER_SIZE];
    byte pubDer[MAX_DER_SIZE];
    byte rawSeed[ED_KEY_SIZE];
    byte rawPub[ED_PUB_SIZE];
    word32 privDerSz;
    word32 pubDerSz;
    word32 rawSeedSz;
    word32 rawPubSz;
    int result1;
    int result2;

    if (argc != 5) {
        fprintf(stderr,
            "Usage: %s private.der public.der seed.raw pub.raw\n", argv[0]);
        return 2;
    }
    if (read_bytes(argv[1], privDer, sizeof(privDer), &privDerSz) != 0 ||
        read_bytes(argv[2], pubDer, sizeof(pubDer), &pubDerSz) != 0 ||
        read_bytes(argv[3], rawSeed, sizeof(rawSeed), &rawSeedSz) != 0 ||
        read_bytes(argv[4], rawPub, sizeof(rawPub), &rawPubSz) != 0)
        return 2;

    if (rawSeedSz != ED_KEY_SIZE || rawPubSz != ED_PUB_SIZE) {
        fprintf(stderr, "Expected raw seed and pub key lengths: %d, %d\n",
                ED_KEY_SIZE, ED_PUB_SIZE);
        return 2;
    }

    printf("Testing %s: private DER=%u B, public DER=%u B\n",
           ALG_NAME, (unsigned)privDerSz, (unsigned)pubDerSz);
    result1 = run_order(1, privDer, privDerSz, pubDer, pubDerSz,
                        rawSeed, rawPub);
    result2 = run_order(0, privDer, privDerSz, pubDer, pubDerSz,
                        rawSeed, rawPub);
    memset(rawSeed, 0, sizeof(rawSeed));
    return result1 || result2;
}
