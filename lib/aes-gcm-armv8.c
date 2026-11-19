/*
   libsmb2-SwiftSMB (MODS.md M7): AES-GCM with the ARMv8 Cryptography Extensions.

   AES-128-GCM and AES-256-GCM for smb2_aes_gcm() (aes-gcm.c) on AArch64
   Linux and Android, with the AES (AESE, AESMC) and polynomial multiply
   (PMULL) instructions: gigabytes per second, where BearSSL's constant-time
   software AES does 150 to 200 MB/s. Constant-time as well: no table
   lookups, the key schedule included, and the tag check does not branch on
   the data.

   Only the functions marked ARMV8_TARGET may execute these instructions, and
   aes-gcm.c calls them only after smb2_aes_gcm_armv8_supported() found them
   in the CPU (getauxval(AT_HWCAP)) and a self-check against BearSSL passed.
   The file is not compiled with -march flags, so nothing else in libsmb2
   uses them.

   GHASH works on each block with the bits of every byte reversed (RBIT).
   GCM's bit order then becomes the plain one: bit k of the 128-bit
   little-endian value is the coefficient of x^k, so PMULL's carry-less
   products are the polynomial products, reduced modulo
   x^128 + x^7 + x^2 + x + 1. Four blocks are multiplied by H^4..H^1 and
   reduced once.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "aes-gcm-armv8.h"

#ifdef SMB2_GCM_ARMV8

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/auxv.h>
#endif

#include "aes-gcm-dlopen.h"

/*
 * Per-function target attributes, so the instructions are enabled only in
 * the functions below that carry ARMV8_TARGET. clang before 16 declares the
 * crypto intrinsics in arm_neon.h only when __ARM_FEATURE_AES or
 * __ARM_FEATURE_CRYPTO is defined (16 and later use target attributes there
 * too); defining them here only makes the declarations visible, and code
 * generation still follows each function's target attribute. gcc declares
 * them always, under its own target pragmas.
 */
#if defined(__clang__)
#if __clang_major__ < 16
#ifndef __ARM_FEATURE_AES
#define __ARM_FEATURE_AES 1
#endif
#ifndef __ARM_FEATURE_CRYPTO
#define __ARM_FEATURE_CRYPTO 1
#endif
#endif
#define ARMV8_TARGET __attribute__((target("neon,aes")))
#else
#define ARMV8_TARGET __attribute__((target("+simd+crypto")))
#endif

#include <arm_neon.h>

/* The kernel's AArch64 ABI values (arch/arm64/include/uapi/asm/hwcap.h). */
#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#define ARMV8_HWCAP_ASIMD (1UL << 1)
#define ARMV8_HWCAP_AES (1UL << 3)
#define ARMV8_HWCAP_PMULL (1UL << 4)

#define GCM_BLOCK 16
#define GCM_IV 12
/* Data hashed and encrypted per pass, small enough to stay in the L1 cache. */
#define GCM_CHUNK 4096
/* GCM's limit: the 32-bit block counter starts at 2. */
#define GCM_MAX_PLEN (((uint64_t)0xffffffffU - 1) * GCM_BLOCK)

struct armv8_gcm_key {
        uint8x16_t rk[15];      /* AES round keys */
        uint64x2_t h[4];        /* H, H^2, H^3, H^4, bits of each byte reversed */
        unsigned rounds;        /* 10 or 14 */
};

int smb2_aes_gcm_armv8_supported(void)
{
#if defined(__linux__) || defined(__ANDROID__)
        unsigned long hwcap = getauxval(AT_HWCAP);
        unsigned long need = ARMV8_HWCAP_ASIMD | ARMV8_HWCAP_AES | ARMV8_HWCAP_PMULL;

        return (hwcap & need) == need;
#else
        return 0;
#endif
}

static void armv8_cleanse(void *ptr, size_t len)
{
        volatile unsigned char *p = ptr;

        while (len--) {
                *p++ = 0;
        }
}

static uint32_t armv8_load32le(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void armv8_store64be(uint8_t *p, uint64_t v)
{
        int i;

        for (i = 7; i >= 0; i--) {
                p[i] = (uint8_t)v;
                v >>= 8;
        }
}

/* ---- AES ---- */

/*
 * SubWord: AESE with a zero round key on the word repeated in all four
 * columns. ShiftRows moves bytes between columns only, so it changes
 * nothing there, and lane 0 holds S-box(w), byte by byte.
 */
static ARMV8_TARGET uint32_t armv8_subword(uint32_t w)
{
        uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(w));

        v = vaeseq_u8(v, vdupq_n_u8(0));
        return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

/*
 * FIPS 197 key expansion. Words are little-endian, so RotWord is a right
 * rotation by 8 bits and Rcon goes into the low byte.
 */
static ARMV8_TARGET void armv8_key_expand(struct armv8_gcm_key *k, const uint8_t *key, size_t key_len)
{
        static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
        uint32_t w[60];
        unsigned nk = (unsigned)(key_len / 4);
        unsigned total, i;

        k->rounds = key_len == 16 ? 10 : 14;
        total = 4 * (k->rounds + 1);
        for (i = 0; i < nk; i++) {
                w[i] = armv8_load32le(key + 4 * i);
        }
        for (i = nk; i < total; i++) {
                uint32_t t = w[i - 1];

                if (i % nk == 0) {
                        t = armv8_subword(t);
                        t = ((t >> 8) | (t << 24)) ^ rcon[i / nk - 1];
                } else if (nk > 6 && i % nk == 4) {
                        t = armv8_subword(t);
                }
                w[i] = w[i - nk] ^ t;
        }
        for (i = 0; i <= k->rounds; i++) {
                k->rk[i] = vreinterpretq_u8_u32(vld1q_u32(&w[4 * i]));
        }
        armv8_cleanse(w, sizeof(w));
}

/*
 * AESE is AddRoundKey, ShiftRows and SubBytes; AESMC is MixColumns. The last
 * round has no MixColumns and ends with the last round key.
 */
static ARMV8_TARGET uint8x16_t armv8_aes(const struct armv8_gcm_key *k, uint8x16_t s)
{
        unsigned i;

        for (i = 0; i < k->rounds - 1; i++) {
                s = vaesmcq_u8(vaeseq_u8(s, k->rk[i]));
        }
        s = vaeseq_u8(s, k->rk[k->rounds - 1]);
        return veorq_u8(s, k->rk[k->rounds]);
}

/* Four blocks at once, interleaved so the AES unit stays busy. */
static ARMV8_TARGET void armv8_aes4(const struct armv8_gcm_key *k, uint8x16_t *s0, uint8x16_t *s1,
                                    uint8x16_t *s2, uint8x16_t *s3)
{
        uint8x16_t a = *s0, b = *s1, c = *s2, d = *s3;
        unsigned i;

        for (i = 0; i < k->rounds - 1; i++) {
                a = vaesmcq_u8(vaeseq_u8(a, k->rk[i]));
                b = vaesmcq_u8(vaeseq_u8(b, k->rk[i]));
                c = vaesmcq_u8(vaeseq_u8(c, k->rk[i]));
                d = vaesmcq_u8(vaeseq_u8(d, k->rk[i]));
        }
        a = vaeseq_u8(a, k->rk[k->rounds - 1]);
        b = vaeseq_u8(b, k->rk[k->rounds - 1]);
        c = vaeseq_u8(c, k->rk[k->rounds - 1]);
        d = vaeseq_u8(d, k->rk[k->rounds - 1]);
        *s0 = veorq_u8(a, k->rk[k->rounds]);
        *s1 = veorq_u8(b, k->rk[k->rounds]);
        *s2 = veorq_u8(c, k->rk[k->rounds]);
        *s3 = veorq_u8(d, k->rk[k->rounds]);
}

/* ---- GHASH ---- */

/* A GCM block (16 bytes) as a polynomial: bits of each byte reversed. */
static ARMV8_TARGET uint64x2_t armv8_gf_from_bytes(uint8x16_t b)
{
        return vreinterpretq_u64_u8(vrbitq_u8(b));
}

static ARMV8_TARGET uint8x16_t armv8_gf_to_bytes(uint64x2_t x)
{
        return vrbitq_u8(vreinterpretq_u8_u64(x));
}

static ARMV8_TARGET uint64x2_t armv8_clmul(poly64_t a, poly64_t b)
{
        return vreinterpretq_u64_p128(vmull_p64(a, b));
}

/*
 * Adds the 256-bit product a * b to the accumulators: lo = a0 b0,
 * mid = a0 b1 + a1 b0, hi = a1 b1 (a = a0 + a1 x^64, likewise b).
 */
static ARMV8_TARGET void armv8_gf_mul_acc(uint64x2_t a, uint64x2_t b, uint64x2_t *lo, uint64x2_t *mid,
                                          uint64x2_t *hi)
{
        poly64x2_t pa = vreinterpretq_p64_u64(a);
        poly64x2_t pb = vreinterpretq_p64_u64(b);
        poly64_t a0 = vgetq_lane_p64(pa, 0);
        poly64_t a1 = vgetq_lane_p64(pa, 1);
        poly64_t b0 = vgetq_lane_p64(pb, 0);
        poly64_t b1 = vgetq_lane_p64(pb, 1);

        *lo = veorq_u64(*lo, armv8_clmul(a0, b0));
        *hi = veorq_u64(*hi, armv8_clmul(a1, b1));
        *mid = veorq_u64(*mid, armv8_clmul(a0, b1));
        *mid = veorq_u64(*mid, armv8_clmul(a1, b0));
}

/*
 * Reduces lo + mid x^64 + hi x^128 modulo x^128 + x^7 + x^2 + x + 1. In
 * 64-bit words r0..r3 (r0 = lo[0], r1 = lo[1] + mid[0], r2 = hi[0] + mid[1],
 * r3 = hi[1]), x^128 = x^7 + x^2 + x + 1 = 0x87: r3 x^192 folds into
 * r3 * 0x87 at x^64 (at most 71 bits, so r1 and r2), then r2 x^128 into
 * r2 * 0x87 at x^0 (r0 and r1).
 */
static ARMV8_TARGET uint64x2_t armv8_gf_reduce(uint64x2_t lo, uint64x2_t mid, uint64x2_t hi)
{
        const uint64x2_t zero = vdupq_n_u64(0);
        const poly64_t r = (poly64_t)0x87;
        uint64x2_t t;

        lo = veorq_u64(lo, vextq_u64(zero, mid, 1));    /* [0, mid[0]] */
        hi = veorq_u64(hi, vextq_u64(mid, zero, 1));    /* [mid[1], 0] */

        t = armv8_clmul(vgetq_lane_p64(vreinterpretq_p64_u64(hi), 1), r);
        lo = veorq_u64(lo, vextq_u64(zero, t, 1));      /* r1 ^= t[0] */
        hi = veorq_u64(hi, vextq_u64(t, zero, 1));      /* r2 ^= t[1] */

        t = armv8_clmul(vgetq_lane_p64(vreinterpretq_p64_u64(hi), 0), r);
        return veorq_u64(lo, t);
}

static ARMV8_TARGET uint64x2_t armv8_gf_mul(uint64x2_t a, uint64x2_t b)
{
        uint64x2_t lo = vdupq_n_u64(0), mid = vdupq_n_u64(0), hi = vdupq_n_u64(0);

        armv8_gf_mul_acc(a, b, &lo, &mid, &hi);
        return armv8_gf_reduce(lo, mid, hi);
}

/*
 * GHASH of len bytes into x. A last partial block is padded with zeros; only
 * the last call for the AAD and for the data may have one.
 */
static ARMV8_TARGET uint64x2_t armv8_ghash(const struct armv8_gcm_key *k, uint64x2_t x, const uint8_t *p,
                                           size_t len)
{
        while (len >= 4 * GCM_BLOCK) {
                uint64x2_t lo = vdupq_n_u64(0), mid = vdupq_n_u64(0), hi = vdupq_n_u64(0);

                /* (x + b0) H^4 + b1 H^3 + b2 H^2 + b3 H */
                armv8_gf_mul_acc(veorq_u64(x, armv8_gf_from_bytes(vld1q_u8(p))), k->h[3], &lo, &mid, &hi);
                armv8_gf_mul_acc(armv8_gf_from_bytes(vld1q_u8(p + 16)), k->h[2], &lo, &mid, &hi);
                armv8_gf_mul_acc(armv8_gf_from_bytes(vld1q_u8(p + 32)), k->h[1], &lo, &mid, &hi);
                armv8_gf_mul_acc(armv8_gf_from_bytes(vld1q_u8(p + 48)), k->h[0], &lo, &mid, &hi);
                x = armv8_gf_reduce(lo, mid, hi);
                p += 4 * GCM_BLOCK;
                len -= 4 * GCM_BLOCK;
        }
        while (len >= GCM_BLOCK) {
                x = armv8_gf_mul(veorq_u64(x, armv8_gf_from_bytes(vld1q_u8(p))), k->h[0]);
                p += GCM_BLOCK;
                len -= GCM_BLOCK;
        }
        if (len > 0) {
                uint8_t last[GCM_BLOCK];

                memset(last, 0, sizeof(last));
                memcpy(last, p, len);
                x = armv8_gf_mul(veorq_u64(x, armv8_gf_from_bytes(vld1q_u8(last))), k->h[0]);
                armv8_cleanse(last, sizeof(last));
        }
        return x;
}

/* ---- Counter mode ---- */

/* The counter block: the IV in lanes 0 to 2, the counter big-endian in lane 3. */
static ARMV8_TARGET uint8x16_t armv8_counter(uint32x4_t iv, uint32_t cc)
{
        return vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(cc), iv, 3));
}

/* XORs the key stream from counter cc into len bytes; returns the next counter. */
static ARMV8_TARGET uint32_t armv8_ctr(const struct armv8_gcm_key *k, uint32x4_t iv, uint32_t cc, uint8_t *p,
                                       size_t len)
{
        while (len >= 4 * GCM_BLOCK) {
                uint8x16_t s0 = armv8_counter(iv, cc);
                uint8x16_t s1 = armv8_counter(iv, cc + 1);
                uint8x16_t s2 = armv8_counter(iv, cc + 2);
                uint8x16_t s3 = armv8_counter(iv, cc + 3);

                armv8_aes4(k, &s0, &s1, &s2, &s3);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), s0));
                vst1q_u8(p + 16, veorq_u8(vld1q_u8(p + 16), s1));
                vst1q_u8(p + 32, veorq_u8(vld1q_u8(p + 32), s2));
                vst1q_u8(p + 48, veorq_u8(vld1q_u8(p + 48), s3));
                cc += 4;
                p += 4 * GCM_BLOCK;
                len -= 4 * GCM_BLOCK;
        }
        while (len >= GCM_BLOCK) {
                vst1q_u8(p, veorq_u8(vld1q_u8(p), armv8_aes(k, armv8_counter(iv, cc))));
                cc++;
                p += GCM_BLOCK;
                len -= GCM_BLOCK;
        }
        if (len > 0) {
                uint8_t stream[GCM_BLOCK];
                size_t i;

                vst1q_u8(stream, armv8_aes(k, armv8_counter(iv, cc)));
                cc++;
                for (i = 0; i < len; i++) {
                        p[i] ^= stream[i];
                }
                armv8_cleanse(stream, sizeof(stream));
        }
        return cc;
}

/* ---- GCM ---- */

ARMV8_TARGET int smb2_aes_gcm_armv8(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                                    const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        struct armv8_gcm_key k;
        uint8_t j0[GCM_BLOCK], lens[GCM_BLOCK], s[GCM_BLOCK];
        uint32x4_t iv;
        uint64x2_t x, h;
        uint32_t cc = 2;        /* Counter 1 (J0) is for the tag. */
        uint32_t diff = 0;
        size_t off, n, i;
        int rc;

        if ((key_len != 16 && key_len != 32) || (uint64_t)plen > GCM_MAX_PLEN) {
                return SMB2_AES_GCM_UNAVAILABLE;
        }

        armv8_key_expand(&k, key, key_len);
        h = armv8_gf_from_bytes(armv8_aes(&k, vdupq_n_u8(0)));
        k.h[0] = h;
        k.h[1] = armv8_gf_mul(h, h);
        k.h[2] = armv8_gf_mul(k.h[1], h);
        k.h[3] = armv8_gf_mul(k.h[2], h);

        /* J0 = IV || 0x00000001, for a 12-byte IV. */
        memcpy(j0, nonce, GCM_IV);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
        iv = vreinterpretq_u32_u8(vld1q_u8(j0));

        x = armv8_ghash(&k, vdupq_n_u64(0), aad, aad_len);
        /* GHASH covers the ciphertext: after encrypting, before decrypting. */
        for (off = 0; off < plen; off += n) {
                n = plen - off < GCM_CHUNK ? plen - off : GCM_CHUNK;
                if (!enc) {
                        x = armv8_ghash(&k, x, p + off, n);
                }
                cc = armv8_ctr(&k, iv, cc, p + off, n);
                if (enc) {
                        x = armv8_ghash(&k, x, p + off, n);
                }
        }
        armv8_store64be(lens, (uint64_t)aad_len * 8);
        armv8_store64be(lens + 8, (uint64_t)plen * 8);
        x = armv8_ghash(&k, x, lens, GCM_BLOCK);

        /* Tag = E(K, J0) + GHASH. */
        vst1q_u8(s, veorq_u8(armv8_aes(&k, vld1q_u8(j0)), armv8_gf_to_bytes(x)));
        if (enc) {
                memcpy(tag, s, GCM_BLOCK);
                rc = 0;
        } else {
                /* Constant time: never memcmp. */
                for (i = 0; i < GCM_BLOCK; i++) {
                        diff |= (uint32_t)(s[i] ^ tag[i]);
                }
                rc = diff == 0 ? 0 : -1;
        }
        armv8_cleanse(&k, sizeof(k));
        armv8_cleanse(s, sizeof(s));
        return rc;
}

#else

typedef int aes_gcm_armv8_unused;

#endif /* SMB2_GCM_ARMV8 */
