/*
   libsmb2-SwiftSMB (MODS.md M4): AES-GCM without OpenSSL, for smb3-seal.c.

   smb2_aes_gcm() tries, in this order:
   - A hook installed with swiftsmb_set_gcm_seal() (swiftsmb-gcm.h). SwiftSMB
     installs CryptoKit's AES.GCM on Apple platforms.
   - On Linux (not Android), when SMB2_GCM_DLOPEN_OPENSSL is defined, the
     system's OpenSSL libcrypto, loaded with dlopen (aes-gcm-dlopen.c,
     MODS.md M6), if there is a usable one.
   - Except on Apple platforms, the CPU's AES instructions (MODS.md M7): on
     AArch64 the ARMv8 AES and PMULL instructions (aes-gcm-armv8.c), on x86
     and x86-64 BearSSL's AES-NI counter mode with its PCLMULQDQ GHASH
     (lib/bearssl). They are detected at run time, and used only after a
     self-check against BearSSL's software GCM passed, once per process.
   - Otherwise BearSSL's GCM (lib/bearssl) with the constant-time
     br_ghash_ctmul64. Its block cipher is BearSSL's constant-time br_aes_ct64
     in counter mode, for AES-256-GCM (libsmb2 has no AES-256) and for
     AES-128-GCM. The exception is AES-128-GCM with CommonCrypto
     (HAVE_COMMONCRYPTO_COMMONCRYPTOR_H, Apple), which uses libsmb2's own
     AES128_ECB_encrypt() (aes_apple.c), as that is faster than br_aes_ct64.
     libsmb2's reference AES, which every other build would use, is 3 to 4
     times slower than br_aes_ct64, expands the key for every block, and is
     not constant-time.

   Built only with HAVE_BUILTIN_AES_GCM; otherwise libsmb2 offers GCM only
   with OpenSSL, as upstream does.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_BUILTIN_AES_GCM

#include "bearssl/swiftsmb_bearssl.h"
#include "bearssl_aead.h"
#include "bearssl_block.h"
#include "bearssl_hash.h"

#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "aes-gcm.h"
#include "aes-gcm-armv8.h"
#include "aes-gcm-dlopen.h"
#include "swiftsmb-gcm.h"

/* libsmb2-SwiftSMB (MODS.md M7): a hardware path for this architecture. */
#if defined(SMB2_GCM_ARMV8) || defined(SWIFTSMB_BEARSSL_X86NI)
#define SMB2_GCM_HW 1
#include <pthread.h>
#include <stdlib.h>
#endif
#ifdef SWIFTSMB_BEARSSL_X86NI
#include <cpuid.h>
#endif

#define GCM_BLOCK 16
#define GCM_IV 12

/* smb2_aes_gcm()'s signature, for the implementations it chooses from. */
typedef int (*smb2_gcm_impl_fn)(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                                const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag);

static swiftsmb_gcm_seal_fn swiftsmb_gcm_hook;

void swiftsmb_set_gcm_seal(swiftsmb_gcm_seal_fn fn)
{
        __atomic_store_n(&swiftsmb_gcm_hook, fn, __ATOMIC_RELEASE);
}

static void cleanse(void *ptr, size_t len)
{
        volatile unsigned char *p = ptr;

        while (len--) {
                *p++ = 0;
        }
}

#ifdef HAVE_COMMONCRYPTO_COMMONCRYPTOR_H
#define SMB2_GCM_LIBSMB2_AES128 1

/*
 * A BearSSL counter-mode class over libsmb2's AES-128, which takes the raw
 * key on every block. The counter block is the 12-byte IV and a 32-bit
 * big-endian counter, as br_block_ctr_class defines it.
 */
typedef struct {
        const br_block_ctr_class *vtable;
        unsigned char key[16];
} libsmb2_aes128_ctr_keys;

static void libsmb2_aes128_ctr_init(const br_block_ctr_class **ctx, const void *key, size_t len)
{
        libsmb2_aes128_ctr_keys *keys = (libsmb2_aes128_ctr_keys *)(void *)ctx;

        (void)len;
        memcpy(keys->key, key, sizeof(keys->key));
}

static uint32_t libsmb2_aes128_ctr_run(const br_block_ctr_class *const *ctx, const void *iv,
                                       uint32_t cc, void *data, size_t len)
{
        const libsmb2_aes128_ctr_keys *keys = (const libsmb2_aes128_ctr_keys *)(const void *)ctx;
        unsigned char *buf = data;
        unsigned char counter[GCM_BLOCK], stream[GCM_BLOCK];
        size_t n, i;

        memcpy(counter, iv, GCM_IV);
        while (len > 0) {
                counter[12] = (unsigned char)(cc >> 24);
                counter[13] = (unsigned char)(cc >> 16);
                counter[14] = (unsigned char)(cc >> 8);
                counter[15] = (unsigned char)cc;
                cc++;
                AES128_ECB_encrypt(counter, keys->key, stream);
                n = len < GCM_BLOCK ? len : GCM_BLOCK;
                for (i = 0; i < n; i++) {
                        buf[i] ^= stream[i];
                }
                buf += n;
                len -= n;
        }
        cleanse(stream, sizeof(stream));
        return cc;
}

static const br_block_ctr_class libsmb2_aes128_ctr_vtable = {
        sizeof(libsmb2_aes128_ctr_keys),
        16,
        4,
        libsmb2_aes128_ctr_init,
        libsmb2_aes128_ctr_run
};
#endif /* HAVE_COMMONCRYPTO_COMMONCRYPTOR_H */

/*
 * BearSSL's GCM over the counter-mode class vt and the GHASH gh. 0 on success,
 * -1 on failure, including a tag that does not match.
 */
static int gcm_bearssl(const br_block_ctr_class *vt, br_ghash gh, int enc, const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen,
                       uint8_t *tag)
{
        union {
                const br_block_ctr_class *vtable;
#ifdef SMB2_GCM_LIBSMB2_AES128
                libsmb2_aes128_ctr_keys aes128;
#endif
#ifdef SWIFTSMB_BEARSSL_X86NI
                br_aes_x86ni_ctr_keys x86ni;
#endif
                br_aes_ct64_ctr_keys ct64;
        } ctr;
        br_gcm_context gcm;
        int rc;

        ctr.vtable = vt;
        ctr.vtable->init(&ctr.vtable, key, key_len);
        br_gcm_init(&gcm, &ctr.vtable, gh);
        br_gcm_reset(&gcm, nonce, GCM_IV);
        br_gcm_aad_inject(&gcm, aad, aad_len);
        br_gcm_flip(&gcm);
        br_gcm_run(&gcm, enc ? 1 : 0, p, plen);
        if (enc) {
                br_gcm_get_tag(&gcm, tag);
                rc = 0;
        } else {
                /* Constant time; 1 when the tag matches. */
                rc = br_gcm_check_tag(&gcm, tag) ? 0 : -1;
        }
        cleanse(&ctr, sizeof(ctr));
        cleanse(&gcm, sizeof(gcm));
        return rc;
}

#ifdef SMB2_GCM_HW
/*
 * libsmb2-SwiftSMB (MODS.md M7): AES-GCM with the CPU's AES instructions.
 *
 * Nothing here executes one of them before the CPU was checked: the ARMv8
 * code checks getauxval(AT_HWCAP), and the x86 code CPUID, both in
 * gcm_hw_init(). The instructions live only in functions with target
 * attributes (aes-gcm-armv8.c, BearSSL's aes_x86ni*.c and ghash_pclmul.c),
 * which nothing calls before that check passed.
 *
 * Then a self-check, once per process: NIST's GCM test cases 2 and 14, and a
 * comparison with BearSSL's constant-time software GCM (br_aes_ct64 and
 * br_ghash_ctmul64) for AES-128 and AES-256, sealing and opening messages
 * that are not a multiple of 16 bytes with AAD of odd length, and refusing a
 * tampered tag and ciphertext. Any difference, or anything that stops the
 * check, leaves the hardware path unused, and smb2_aes_gcm() uses BearSSL's
 * software GCM.
 */

static pthread_once_t gcm_hw_once = PTHREAD_ONCE_INIT;
static smb2_gcm_impl_fn gcm_hw_impl;    /* NULL: no usable hardware path */

static int gcm_software(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                        size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        return gcm_bearssl(&br_aes_ct64_ctr_vtable, br_ghash_ctmul64, enc, key, key_len, nonce, aad, aad_len,
                           p, plen, tag);
}

#ifdef SWIFTSMB_BEARSSL_X86NI
static const br_block_ctr_class *gcm_x86ni_ctr;
static br_ghash gcm_x86ni_ghash;

/*
 * CPUID leaf 1: SSE2 (EDX bit 26), PCLMULQDQ (ECX bit 1), SSSE3 (bit 9),
 * SSE4.1 (bit 19) and AES-NI (bit 25), everything BearSSL's AES-NI counter
 * mode and PCLMULQDQ GHASH use. BearSSL checks AES-NI, SSE4.1 and PCLMULQDQ
 * again itself.
 */
static int gcm_x86ni_cpu(void)
{
        unsigned int eax, ebx, ecx, edx;
        const unsigned int need_ecx = (1U << 1) | (1U << 9) | (1U << 19) | (1U << 25);
        const unsigned int need_edx = 1U << 26;

        if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
                return 0;
        }
        return (ecx & need_ecx) == need_ecx && (edx & need_edx) == need_edx;
}

static int gcm_x86ni(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        return gcm_bearssl(gcm_x86ni_ctr, gcm_x86ni_ghash, enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
}
#endif /* SWIFTSMB_BEARSSL_X86NI */

/* NIST GCM test cases 2 (AES-128) and 14 (AES-256): zero key and IV, one zero block, no AAD. */
static int gcm_hw_known_answer(smb2_gcm_impl_fn impl)
{
        static const uint8_t ct128[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                          0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
        static const uint8_t tag128[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                           0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
        static const uint8_t ct256[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                                          0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};
        static const uint8_t tag256[16] = {0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                                           0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19};
        static const uint8_t zero[16] = {0};
        uint8_t key[32], nonce[GCM_IV], buf[16], tag[16];
        size_t kl;

        for (kl = 16; kl <= 32; kl += 16) {
                const uint8_t *ct = kl == 16 ? ct128 : ct256;
                const uint8_t *want = kl == 16 ? tag128 : tag256;

                memset(key, 0, sizeof(key));
                memset(nonce, 0, sizeof(nonce));
                memset(buf, 0, sizeof(buf));
                if (impl(1, key, kl, nonce, NULL, 0, buf, sizeof(buf), tag) != 0 ||
                    memcmp(buf, ct, 16) != 0 || memcmp(tag, want, 16) != 0) {
                        return 0;
                }
                if (impl(0, key, kl, nonce, NULL, 0, buf, sizeof(buf), tag) != 0 ||
                    memcmp(buf, zero, 16) != 0) {
                        return 0;
                }
        }
        return 1;
}

/* Deterministic test bytes (xorshift32); the self-check needs no secrets. */
static void gcm_hw_fill(uint8_t *buf, size_t len, uint32_t seed)
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

/*
 * The hardware path against BearSSL's software GCM. The sizes are not
 * multiples of 16 and exercise the four-block GHASH, single blocks, a partial
 * block, and (4179 bytes) more than one of aes-gcm-armv8.c's 4096-byte passes.
 */
static int gcm_hw_cross_check(smb2_gcm_impl_fn impl)
{
        static const struct {
                size_t aad_len;
                size_t plen;
        } cases[] = {{77, 151}, {32, 4179}, {13, 0}};
        enum { max_plen = 4179, max_aad = 77 };
        uint8_t key[32], nonce[GCM_IV], aad[max_aad], ref_tag[16], hw_tag[16];
        uint8_t *msg, *ref, *hw;
        size_t kl, c;
        int ok = 0;

        msg = malloc(3 * (size_t)max_plen);
        if (msg == NULL) {
                return 0;
        }
        ref = msg + max_plen;
        hw = ref + max_plen;
        for (kl = 16; kl <= 32; kl += 16) {
                for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
                        size_t alen = cases[c].aad_len, n = cases[c].plen;
                        uint32_t seed = (uint32_t)(kl * 131 + c * 7);

                        gcm_hw_fill(key, kl, seed);
                        gcm_hw_fill(nonce, sizeof(nonce), seed + 1);
                        gcm_hw_fill(aad, alen, seed + 2);
                        gcm_hw_fill(msg, n, seed + 3);

                        /* Sealing: the same ciphertext and tag. */
                        memcpy(ref, msg, n);
                        if (gcm_software(1, key, kl, nonce, aad, alen, ref, n, ref_tag) != 0) {
                                goto out;
                        }
                        memcpy(hw, msg, n);
                        if (impl(1, key, kl, nonce, aad, alen, hw, n, hw_tag) != 0 ||
                            memcmp(hw, ref, n) != 0 || memcmp(hw_tag, ref_tag, 16) != 0) {
                                goto out;
                        }

                        /* Opening BearSSL's ciphertext: the plaintext back. */
                        memcpy(hw, ref, n);
                        if (impl(0, key, kl, nonce, aad, alen, hw, n, ref_tag) != 0 ||
                            memcmp(hw, msg, n) != 0) {
                                goto out;
                        }

                        /* A tampered tag is refused. */
                        memcpy(hw, ref, n);
                        memcpy(hw_tag, ref_tag, 16);
                        hw_tag[(c + kl) % 16] ^= 0x01;
                        if (impl(0, key, kl, nonce, aad, alen, hw, n, hw_tag) != -1) {
                                goto out;
                        }

                        /* So is a tampered last ciphertext byte, or AAD byte. */
                        memcpy(hw, ref, n);
                        if (n > 0) {
                                hw[n - 1] ^= 0x80;
                        } else {
                                aad[alen - 1] ^= 0x80;
                        }
                        if (impl(0, key, kl, nonce, aad, alen, hw, n, ref_tag) != -1) {
                                goto out;
                        }
                }
        }
        ok = 1;
out:
        free(msg);
        return ok;
}

static void gcm_hw_init(void)
{
        smb2_gcm_impl_fn impl = NULL;

#ifdef SMB2_GCM_ARMV8
        if (smb2_aes_gcm_armv8_supported()) {
                impl = smb2_aes_gcm_armv8;
        }
#endif
#ifdef SWIFTSMB_BEARSSL_X86NI
        if (gcm_x86ni_cpu()) {
                /* Each NULL when BearSSL finds the CPU or the compiler lacking. */
                gcm_x86ni_ctr = br_aes_x86ni_ctr_get_vtable();
                gcm_x86ni_ghash = br_ghash_pclmul_get();
                if (gcm_x86ni_ctr != NULL && gcm_x86ni_ghash != 0) {
                        impl = gcm_x86ni;
                }
        }
#endif
        if (impl != NULL && gcm_hw_known_answer(impl) && gcm_hw_cross_check(impl)) {
                gcm_hw_impl = impl;
        }
}

/*
 * smb2_aes_gcm() with the CPU's AES instructions: 0, -1, or
 * SMB2_AES_GCM_UNAVAILABLE when there is no usable hardware path (or a
 * request it does not take), before touching the data.
 */
static int gcm_hw(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                  size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        int rc;

        if (pthread_once(&gcm_hw_once, gcm_hw_init) != 0 || gcm_hw_impl == NULL) {
                return SMB2_AES_GCM_UNAVAILABLE;
        }
        rc = gcm_hw_impl(enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
        if (rc != 0 && rc != SMB2_AES_GCM_UNAVAILABLE) {
                rc = -1;
        }
        return rc;
}
#endif /* SMB2_GCM_HW */

int smb2_aes_gcm(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        swiftsmb_gcm_seal_fn hook = __atomic_load_n(&swiftsmb_gcm_hook, __ATOMIC_ACQUIRE);
        const br_block_ctr_class *vt;
#if (defined(SMB2_GCM_DLOPEN_OPENSSL) && defined(__linux__) && !defined(__ANDROID__)) || defined(SMB2_GCM_HW)
        int rc;
#endif

        if (key_len != 16 && key_len != 32) {
                return -1;
        }
        if (hook != NULL) {
                return hook(enc ? 1 : 0, key, key_len, nonce, aad, aad_len, p, plen, tag) == 0 ? 0 : -1;
        }

#if defined(SMB2_GCM_DLOPEN_OPENSSL) && defined(__linux__) && !defined(__ANDROID__)
        /* libsmb2-SwiftSMB (MODS.md M6): the system's OpenSSL first. */
        rc = smb2_aes_gcm_openssl(enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
        if (rc != SMB2_AES_GCM_UNAVAILABLE) {
                return rc;
        }
#endif

#ifdef SMB2_GCM_HW
        /* libsmb2-SwiftSMB (MODS.md M7): then the CPU's AES instructions. */
        rc = gcm_hw(enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
        if (rc != SMB2_AES_GCM_UNAVAILABLE) {
                return rc;
        }
#endif

#ifdef SMB2_GCM_LIBSMB2_AES128
        vt = key_len == 16 ? &libsmb2_aes128_ctr_vtable : &br_aes_ct64_ctr_vtable;
#else
        vt = &br_aes_ct64_ctr_vtable;
#endif
        return gcm_bearssl(vt, br_ghash_ctmul64, enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
}

#else

typedef int aes_gcm_unused;

#endif /* HAVE_BUILTIN_AES_GCM */
