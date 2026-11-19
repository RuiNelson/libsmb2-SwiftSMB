/*
   libsmb2-SwiftSMB (MODS.md M7): tests for AES-GCM without OpenSSL (lib/aes-gcm.c).

   This program includes lib/aes-gcm.c itself, to reach each backend directly:

   - software: BearSSL's constant-time aes_ct64 and ghash_ctmul64;
   - libsmb2's own AES-128 through CommonCrypto (Apple only, AES-128 only);
   - the ARMv8 Cryptography Extensions (lib/aes-gcm-armv8.c);
   - x86 AES-NI and PCLMULQDQ (BearSSL's aes_x86ni and ghash_pclmul);
   - the hardware path as smb2_aes_gcm() reaches it, with its run-time
     self-check;
   - the system's OpenSSL, loaded with dlopen (lib/aes-gcm-dlopen.c);
   - smb2_aes_gcm() itself, the route a library user gets.

   A backend this machine does not have is reported as SKIP. Each other one
   is run against the NIST test cases, OpenSSL-generated vectors, and BearSSL's
   software GCM over many message and AAD lengths, with tampering and (for
   smb2_aes_gcm()) concurrent first use. A machine that has hardware AES but
   whose hardware path the self-check refused is a failure.

   Build and run with run.sh. Exit status 0 when nothing failed.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/aes-gcm.c"
#include "vectors.h"

#ifndef HAVE_BUILTIN_AES_GCM
#error compile with -DHAVE_BUILTIN_AES_GCM=1
#endif

typedef int (*impl_fn)(int, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t, uint8_t *,
                       size_t, uint8_t *);

static unsigned long checks, fails;
static const char *backend_name;
static size_t only_key_len; /* 0: both key sizes; else the one a backend takes, in bytes */

#define CHECK(cond, ...)                                                                                       \
        do {                                                                                                   \
                checks++;                                                                                      \
                if (!(cond)) {                                                                                 \
                        if (fails++ < 20) {                                                                    \
                                printf("  FAIL [%s] %s:%d: ", backend_name, "test", __LINE__);                  \
                                printf(__VA_ARGS__);                                                           \
                                printf("\n");                                                                  \
                        }                                                                                      \
                }                                                                                              \
        } while (0)

/* The reference: BearSSL's constant-time software GCM. */
static int software(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                    size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        return gcm_bearssl(&br_aes_ct64_ctr_vtable, br_ghash_ctmul64, enc, key, key_len, nonce, aad, aad_len, p,
                           plen, tag);
}

#ifdef SMB2_GCM_LIBSMB2_AES128
static int libsmb2_aes128(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                          size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        if (key_len != 16) {
                return SMB2_AES_GCM_UNAVAILABLE;
        }
        return gcm_bearssl(&libsmb2_aes128_ctr_vtable, br_ghash_ctmul64, enc, key, key_len, nonce, aad, aad_len, p,
                           plen, tag);
}
#endif

static int selected(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                    size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        return smb2_aes_gcm(enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
}

static void fill(uint8_t *buf, size_t len, uint32_t seed)
{
        uint32_t x = seed | 1;
        size_t i;

        for (i = 0; i < len; i++) {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                buf[i] = (uint8_t)(x >> 24);
        }
}

static size_t unhex(const char *h, uint8_t *out)
{
        size_t n = 0;
        unsigned int v;

        while (h[0] != '\0' && h[1] != '\0') {
                sscanf(h, "%2x", &v);
                out[n++] = (uint8_t)v;
                h += 2;
        }
        return n;
}

/* NIST's GCM test cases 2 to 4 (AES-128) and 14 to 16 (AES-256). */
static const struct gcm_vector nist[] = {
    {128, "00000000000000000000000000000000", "000000000000000000000000", "",
     "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
    {128, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"},
    {128, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"},
    {256, "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "",
     "00000000000000000000000000000000", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
    {256, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
     "b094dac5d93471bdec1a502270e3cc6c"},
    {256, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"}};

static void check_vector(impl_fn fn, const struct gcm_vector *v, const char *origin, size_t index)
{
        size_t cap = strlen(v->plaintext) / 2 + 1;
        uint8_t key[32], iv[12], aad[128], tag[16], want_tag[16], *pt, *ct, *buf;
        size_t kl = (size_t)v->key_bits / 8, al, pl, cl;

        if (only_key_len != 0 && kl != only_key_len) {
                return;
        }
        pt = malloc(3 * cap);
        ct = pt + cap;
        buf = ct + cap;
        unhex(v->key, key);
        unhex(v->iv, iv);
        al = unhex(v->aad, aad);
        pl = unhex(v->plaintext, pt);
        cl = unhex(v->ciphertext, ct);
        unhex(v->tag, want_tag);
        CHECK(pl == cl, "%s %zu: vector lengths", origin, index);

        memcpy(buf, pt, pl);
        CHECK(fn(1, key, kl, iv, aad, al, buf, pl, tag) == 0, "%s %zu: seal failed", origin, index);
        CHECK(memcmp(buf, ct, pl) == 0, "%s %zu (AES-%d, %zu bytes, %zu AAD): wrong ciphertext", origin, index,
              v->key_bits, pl, al);
        CHECK(memcmp(tag, want_tag, 16) == 0, "%s %zu (AES-%d, %zu bytes, %zu AAD): wrong tag", origin, index,
              v->key_bits, pl, al);

        memcpy(buf, ct, pl);
        memcpy(tag, want_tag, 16);
        CHECK(fn(0, key, kl, iv, aad, al, buf, pl, tag) == 0, "%s %zu: open failed", origin, index);
        CHECK(memcmp(buf, pt, pl) == 0, "%s %zu: wrong plaintext", origin, index);

        memcpy(buf, ct, pl);
        memcpy(tag, want_tag, 16);
        tag[0] ^= 0x80;
        CHECK(fn(0, key, kl, iv, aad, al, buf, pl, tag) == -1, "%s %zu: bad tag accepted", origin, index);
        free(pt);
}

/* One length pair against the software reference: same output, round trip, and tampering refused. */
static void check_case(impl_fn fn, size_t kl, size_t alen, size_t n, uint32_t seed, uint8_t *scratch)
{
        uint8_t key[32], nonce[12], aad[96], ref_tag[16], tag[16];
        uint8_t *msg = scratch, *ref = scratch + n + 1, *got = scratch + 2 * (n + 1);

        fill(key, kl, seed);
        fill(nonce, sizeof(nonce), seed + 1);
        fill(aad, alen, seed + 2);
        fill(msg, n, seed + 3);

        memcpy(ref, msg, n);
        CHECK(software(1, key, kl, nonce, aad, alen, ref, n, ref_tag) == 0, "reference seal");
        memcpy(got, msg, n);
        CHECK(fn(1, key, kl, nonce, aad, alen, got, n, tag) == 0, "seal AES-%zu n=%zu aad=%zu failed", kl * 8, n,
              alen);
        CHECK(memcmp(got, ref, n) == 0, "seal AES-%zu n=%zu aad=%zu: ciphertext differs", kl * 8, n, alen);
        CHECK(memcmp(tag, ref_tag, 16) == 0, "seal AES-%zu n=%zu aad=%zu: tag differs", kl * 8, n, alen);

        /* Opening the reference's output. */
        memcpy(got, ref, n);
        memcpy(tag, ref_tag, 16);
        CHECK(fn(0, key, kl, nonce, aad, alen, got, n, tag) == 0, "open AES-%zu n=%zu aad=%zu failed", kl * 8, n,
              alen);
        CHECK(memcmp(got, msg, n) == 0, "open AES-%zu n=%zu aad=%zu: plaintext differs", kl * 8, n, alen);

        /* Tampering: any one flipped bit of the tag, the ciphertext, or the AAD is refused. */
        memcpy(got, ref, n);
        memcpy(tag, ref_tag, 16);
        tag[(n + alen) % 16] ^= (uint8_t)(1u << (n % 8));
        CHECK(fn(0, key, kl, nonce, aad, alen, got, n, tag) == -1, "AES-%zu n=%zu: tampered tag accepted", kl * 8, n);
        if (n > 0) {
                memcpy(got, ref, n);
                memcpy(tag, ref_tag, 16);
                got[n / 2] ^= 0x04;
                CHECK(fn(0, key, kl, nonce, aad, alen, got, n, tag) == -1, "AES-%zu n=%zu: tampered data accepted",
                      kl * 8, n);
        }
        if (alen > 0) {
                memcpy(got, ref, n);
                memcpy(tag, ref_tag, 16);
                aad[alen / 2] ^= 0x01;
                CHECK(fn(0, key, kl, nonce, aad, alen, got, n, tag) == -1, "AES-%zu n=%zu: tampered AAD accepted",
                      kl * 8, n);
        }
}

static void run_grid(impl_fn fn)
{
        static const size_t extra[] = {135, 191, 192, 193, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047,
                                       4095, 4096, 4097, 4111, 4112, 4113, 4179, 8191, 8192, 8193, 12287, 12288,
                                       12289, 65535, 65536, 65537, 100003};
        static const size_t aads[] = {0, 1, 13, 15, 16, 17, 32, 33, 77, 96};
        size_t max_n = 100003, kl, i, a, n;
        uint8_t *scratch = malloc(3 * (max_n + 1));
        uint32_t seed = 1;

        for (kl = 16; kl <= 32; kl += 16) {
                if (only_key_len != 0 && kl != only_key_len) {
                        continue;
                }
                for (n = 0; n <= 134; n++) {
                        for (a = 0; a < sizeof(aads) / sizeof(aads[0]); a++) {
                                check_case(fn, kl, aads[a], n, seed++, scratch);
                        }
                }
                for (i = 0; i < sizeof(extra) / sizeof(extra[0]); i++) {
                        for (a = 0; a < sizeof(aads) / sizeof(aads[0]); a += 3) {
                                check_case(fn, kl, aads[a], extra[i], seed++, scratch);
                        }
                }
        }
        free(scratch);
}

struct thread_arg {
        unsigned id;
        unsigned long bad;
};

static void *thread_main(void *p)
{
        struct thread_arg *t = p;
        uint8_t key[32], nonce[12], aad[40], tag[16], ref_tag[16], msg[3000], a[3000], b[3000];
        unsigned i;

        for (i = 0; i < 300; i++) {
                size_t kl = (i & 1) ? 32 : 16, n = (i * 97 + t->id * 31) % 3000, al = (i * 7) % 40;
                uint32_t seed = t->id * 1000u + i;

                fill(key, kl, seed);
                fill(nonce, 12, seed + 1);
                fill(aad, al, seed + 2);
                fill(msg, n, seed + 3);
                memcpy(a, msg, n);
                memcpy(b, msg, n);
                if (software(1, key, kl, nonce, aad, al, a, n, ref_tag) != 0 ||
                    smb2_aes_gcm(1, key, kl, nonce, aad, al, b, n, tag) != 0 || memcmp(a, b, n) != 0 ||
                    memcmp(tag, ref_tag, 16) != 0 ||
                    smb2_aes_gcm(0, key, kl, nonce, aad, al, b, n, tag) != 0 || memcmp(b, msg, n) != 0) {
                        t->bad++;
                }
        }
        return NULL;
}

/* smb2_aes_gcm() from several threads that all hit its first use (the run-time self-check) together. */
static void run_threads(void)
{
        pthread_t th[8];
        struct thread_arg arg[8];
        unsigned i;

        for (i = 0; i < 8; i++) {
                arg[i].id = i + 1;
                arg[i].bad = 0;
                pthread_create(&th[i], NULL, thread_main, &arg[i]);
        }
        for (i = 0; i < 8; i++) {
                pthread_join(th[i], NULL);
                CHECK(arg[i].bad == 0, "thread %u: %lu wrong results", i + 1, arg[i].bad);
        }
}

/* 1: this backend does not take the request (or is not there), nothing touched. */
static int available(impl_fn fn)
{
        uint8_t key[16] = {0}, nonce[12] = {0}, buf[16] = {0}, tag[16];

        return fn(1, key, 16, nonce, NULL, 0, buf, sizeof(buf), tag) != SMB2_AES_GCM_UNAVAILABLE;
}

static int any_hardware_cpu;

static void run_backend(const char *name, impl_fn fn, const char *skip_reason, int threads, size_t key_len)
{
        unsigned long c0 = checks, f0 = fails;
        size_t i;

        backend_name = name;
        only_key_len = key_len;
        if (fn == NULL || !available(fn)) {
                printf("SKIP  %-34s %s\n", name, skip_reason != NULL ? skip_reason : "not available here");
                return;
        }
        for (i = 0; i < sizeof(nist) / sizeof(nist[0]); i++) {
                check_vector(fn, &nist[i], "NIST", i);
        }
        for (i = 0; i < sizeof(gcm_vectors) / sizeof(gcm_vectors[0]); i++) {
                check_vector(fn, &gcm_vectors[i], "OpenSSL", i);
        }
        run_grid(fn);
        if (threads) {
                run_threads();
        }
        printf("%s  %-34s %lu checks\n", fails == f0 ? "PASS" : "FAIL", name, checks - c0);
}

int main(void)
{
        impl_fn hardware_fn = NULL;
        const char *hardware_skip = "no hardware AES path in this build";

        printf("libsmb2-SwiftSMB AES-GCM tests\n");
        (void)any_hardware_cpu;

        run_backend("software (BearSSL aes_ct64)", software, NULL, 0, 0);

#ifdef SMB2_GCM_LIBSMB2_AES128
        run_backend("libsmb2 AES-128 (CommonCrypto)", libsmb2_aes128, NULL, 0, 16);
#else
        run_backend("libsmb2 AES-128 (CommonCrypto)", NULL, "Apple only", 0, 0);
#endif

#ifdef SMB2_GCM_ARMV8
        if (smb2_aes_gcm_armv8_supported()) {
                any_hardware_cpu = 1;
                run_backend("ARMv8 AES + PMULL", smb2_aes_gcm_armv8, NULL, 0, 0);
        } else {
                run_backend("ARMv8 AES + PMULL", NULL, "the CPU lacks AES or PMULL", 0, 0);
        }
#else
        run_backend("ARMv8 AES + PMULL", NULL, "not an ARMv8 Linux/Android build", 0, 0);
#endif

#ifdef SWIFTSMB_BEARSSL_X86NI
        if (gcm_x86ni_cpu()) {
                gcm_x86ni_ctr = br_aes_x86ni_ctr_get_vtable();
                gcm_x86ni_ghash = br_ghash_pclmul_get();
                if (gcm_x86ni_ctr != NULL && gcm_x86ni_ghash != 0) {
                        any_hardware_cpu = 1;
                        run_backend("x86 AES-NI + PCLMULQDQ", gcm_x86ni, NULL, 0, 0);
                } else {
                        run_backend("x86 AES-NI + PCLMULQDQ", NULL, "BearSSL found no support", 0, 0);
                }
        } else {
                run_backend("x86 AES-NI + PCLMULQDQ", NULL, "the CPU lacks AES-NI or PCLMULQDQ", 0, 0);
        }
#else
        run_backend("x86 AES-NI + PCLMULQDQ", NULL, "not an x86 build", 0, 0);
#endif

#ifdef SMB2_GCM_HW
        pthread_once(&gcm_hw_once, gcm_hw_init);
        if (gcm_hw_impl != NULL) {
                hardware_fn = gcm_hw;
        } else if (any_hardware_cpu) {
                backend_name = "hardware path (smb2_aes_gcm)";
                CHECK(0, "the CPU has hardware AES, but the run-time self-check refused the hardware path");
                hardware_skip = "refused by its own self-check (the failure is counted above)";
        } else {
                hardware_skip = "no hardware AES on this CPU";
        }
#endif
        run_backend("hardware path (smb2_aes_gcm)", hardware_fn, hardware_skip, 0, 0);

#if defined(SMB2_GCM_DLOPEN_OPENSSL) && defined(__linux__) && !defined(__ANDROID__)
        run_backend("system OpenSSL (dlopen)", smb2_aes_gcm_openssl, "no usable libcrypto", 0, 0);
#else
        run_backend("system OpenSSL (dlopen)", NULL, "Linux build with SMB2_GCM_DLOPEN_OPENSSL only", 0, 0);
#endif

        run_backend("smb2_aes_gcm() as a user gets it", selected, NULL, 1, 0);

        /* A key length SMB 3.1.1 never uses is refused by the public entry point. */
        {
                uint8_t key[24] = {0}, nonce[12] = {0}, buf[16] = {0}, tag[16];

                backend_name = "smb2_aes_gcm() arguments";
                CHECK(smb2_aes_gcm(1, key, 24, nonce, NULL, 0, buf, sizeof(buf), tag) == -1, "AES-192 accepted");
        }

        printf("%lu checks, %lu failures\n", checks, fails);
        return fails != 0;
}
