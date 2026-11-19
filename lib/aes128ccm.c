/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2019 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif 

#include <stdio.h>
#include <string.h>

#include "compat.h"

#include "portable-endian.h"
#include "aes.h"
#include "aes128ccm.h"

#ifndef HAVE_OPENSSL

#if defined(__APPLE__) && defined(HAVE_COMMONCRYPTO_COMMONCRYPTOR_H)
/*
 * libsmb2-SwiftSMB (MODS.md M3): on Apple platforms the CCM below is the
 * reference implementation, under the _reference names and with internal
 * linkage. aes128ccm_encrypt() and aes128ccm_decrypt() further down run it
 * through CommonCrypto over the whole message, and fall back to it.
 */
#define AES128CCM_COMMONCRYPTO 1
static int aes128ccm_encrypt_reference(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen);
static int aes128ccm_decrypt_reference(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen);
#define aes128ccm_encrypt aes128ccm_encrypt_reference
#define aes128ccm_decrypt aes128ccm_decrypt_reference
#endif

static void aes_ccm_generate_b0(unsigned char *nonce, size_t nlen,
                                size_t alen, size_t plen, size_t mlen,
                                unsigned char *buf)
{
        uint32_t len;

        memset(buf, 0, 16);
        if (alen) {
                buf[0] |= 0x40;                   /* Adata */
        }
        buf[0] |= (((mlen - 2) / 2) << 3) & 0x38; /* M' */
        buf[0] |= (15 - nlen - 1) & 0x07;         /* L' */

        len = htobe32((uint32_t)plen);
        memcpy(&buf[12], &len, 4);
        memcpy(&buf[1], nonce, nlen);
}

static inline void bxory(unsigned char *b, unsigned char *y, size_t num)
{
        int i;

        for(i = 0; i < (int)num; i++) {
                b[i] = b[i] ^ y[i];
        }
}

static void ccm_generate_T(unsigned char *key,
                           unsigned char *nonce, size_t nlen,
                           unsigned char *aad, size_t alen,
                           unsigned char *p, size_t plen,
                           unsigned char *m, size_t mlen)
{
        unsigned char b[16] _U_, y[16]_U_;
        uint16_t l;

        aes_ccm_generate_b0(nonce, nlen, alen, plen, mlen, &b[0]);
        AES128_ECB_encrypt(b, key, y);

        /* Create Aad */
        if (alen) {
                /* First block */
                memset(b, 0, 16);
                l = htobe16((uint16_t)alen);
                memcpy(b, &l, 2);

                l = (alen > 14) ? 14 : (uint16_t)alen;
                memcpy(&b[2], aad, l);
                aad  += l;
                alen -= l;

                bxory(b, y, 16);
                AES128_ECB_encrypt(b, key, y);

                while (alen) {
                        memset(b, 0, 16);
                        l = (alen > 16) ? 16 : (uint16_t)alen;
                        memcpy(b, aad, l);
                        aad  += l;
                        alen -= l;

                        bxory(b, y, 16);
                        AES128_ECB_encrypt(b, key, y);
                }
        }

        /* Create Payload */
        while (plen) {
                memset(b, 0, 16);
                l = (plen > 16) ? 16 : (uint16_t)plen;
                memcpy(b, p, l);
                p    += l;
                plen -= l;

                bxory(b, y, 16);
                AES128_ECB_encrypt(b, key, y);
        }

        memcpy(m, y, mlen);
}

static void ccm_generate_s(unsigned char *key, unsigned char *nonce, size_t nlen,
                           size_t plen, int i, unsigned char *s)
{
        uint32_t l;

        memset(s, 0, 16);
        s[0] |= (15 - nlen - 1) & 0x07;

        l = htobe32(i);
        memcpy(&s[12], &l, 4);

        memcpy(&s[1], nonce, nlen);

        AES128_ECB_encrypt(s, key, s);
}

static void aes_ccm_crypt(unsigned char *key,
                          unsigned char *nonce, size_t nlen,
                          unsigned char *p, size_t plen)
{
        int j;
        size_t l;
        unsigned char s[16] _U_;

        j = 0;
        while (plen) {
                l = (plen > 16) ? 16 : plen;
                ccm_generate_s(key, nonce, nlen, plen, j + 1, &s[0]);
                bxory(&p[j * 16], &s[0], l);

                j++;
                plen -= l;
        }
}

int aes128ccm_encrypt(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen)
{
        unsigned char s[16] _U_;

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, m, mlen);
        ccm_generate_s(key, nonce, nlen, plen, 0, &s[0]);
        bxory(m, &s[0], mlen);

        aes_ccm_crypt(key, nonce, nlen, p, plen);

        return 0;
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        unsigned char s[16] _U_;
        unsigned char tmp[16];

        aes_ccm_crypt(key, nonce, nlen, p, plen);

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, tmp, mlen);
        ccm_generate_s(key, nonce, nlen, plen, 0, &s[0]);
        bxory(tmp, &s[0], mlen);

        return memcmp(tmp, m, mlen);
}

#ifdef AES128CCM_COMMONCRYPTO
#undef aes128ccm_encrypt
#undef aes128ccm_decrypt

/*
 * libsmb2-SwiftSMB (MODS.md M3): CCM over the whole message. The reference
 * code above sets the AES key up again for every 16-byte block, twice per
 * block of payload. CommonCrypto runs the two halves of CCM in bulk instead:
 * CBC-MAC as an AES-CBC encryption with a zero IV (the MAC is the last
 * output block), and the keystream as AES-CTR starting at counter block A0.
 */
#include <CommonCrypto/CommonCryptor.h>
#include <stdint.h>
#include <string.h>

#define CCM_BLOCK 16
#define CCM_KEY_LEN 16
/* CBC cannot run in place in CommonCrypto, so the MAC pass encrypts into this
 * much scratch space at a time. */
#define CCM_CHUNK 8192

/* The formatting upstream uses, which the fast path must reproduce exactly. */
static int ccm_fast_path_supported(size_t nlen, size_t alen, size_t plen, size_t mlen)
{
        /* The counter and the B0 length both live in bytes 12-15, so the nonce
         * must end before them, and the 32-bit block counter must not wrap. */
        if (nlen == 0 || nlen > 11) {
                return 0;
        }
        /* The tag lengths CCM defines: 4, 6, ..., 16. */
        if (mlen < 4 || mlen > CCM_BLOCK || mlen % 2) {
                return 0;
        }
        /* Upstream encodes the AAD length in two bytes. */
        if (alen >= 0xFF00) {
                return 0;
        }
        if ((uint64_t)plen > (uint64_t)UINT32_MAX) {
                return 0;
        }
        return 1;
}

/* Counter block A_i: flags L' = 15 - nlen - 1, the nonce, then i big-endian
 * in bytes 12-15. CommonCrypto's CTR increments the block as one big-endian
 * number, which matches as long as the low 32 bits do not wrap. */
static void ccm_counter_block(const unsigned char *nonce, size_t nlen, uint32_t i,
                              unsigned char a[CCM_BLOCK])
{
        memset(a, 0, CCM_BLOCK);
        a[0] = (unsigned char)((15 - nlen - 1) & 0x07);
        memcpy(&a[1], nonce, nlen);
        a[12] = (unsigned char)(i >> 24);
        a[13] = (unsigned char)(i >> 16);
        a[14] = (unsigned char)(i >> 8);
        a[15] = (unsigned char)i;
}

static int ccm_cbc_update(CCCryptorRef cbc, const unsigned char *in, size_t len,
                          unsigned char *scratch, unsigned char y[CCM_BLOCK])
{
        size_t moved;

        while (len) {
                size_t n = len > CCM_CHUNK ? CCM_CHUNK : len;

                if (CCCryptorUpdate(cbc, in, n, scratch, CCM_CHUNK, &moved) != kCCSuccess ||
                    moved != n) {
                        return -1;
                }
                memcpy(y, scratch + n - CCM_BLOCK, CCM_BLOCK);
                in += n;
                len -= n;
        }
        return 0;
}

/* The CBC-MAC T over B0, the formatted AAD, and the zero-padded payload. */
static int ccm_mac(const unsigned char *key,
                   const unsigned char *nonce, size_t nlen,
                   const unsigned char *aad, size_t alen,
                   const unsigned char *p, size_t plen,
                   size_t mlen, unsigned char y[CCM_BLOCK])
{
        static const unsigned char zero_iv[CCM_BLOCK];
        unsigned char scratch[CCM_CHUNK];
        unsigned char block[CCM_BLOCK];
        CCCryptorRef cbc = NULL;
        size_t full, rest, l;
        uint32_t len;
        int rc = -1;

        if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeCBC, kCCAlgorithmAES, ccNoPadding,
                                    zero_iv, key, CCM_KEY_LEN, NULL, 0, 0, 0, &cbc) != kCCSuccess) {
                return -1;
        }

        /* B0 */
        memset(block, 0, CCM_BLOCK);
        if (alen) {
                block[0] |= 0x40;
        }
        block[0] |= (unsigned char)((((mlen - 2) / 2) << 3) & 0x38);
        block[0] |= (unsigned char)((15 - nlen - 1) & 0x07);
        memcpy(&block[1], nonce, nlen);
        len = (uint32_t)plen;
        block[12] = (unsigned char)(len >> 24);
        block[13] = (unsigned char)(len >> 16);
        block[14] = (unsigned char)(len >> 8);
        block[15] = (unsigned char)len;
        if (ccm_cbc_update(cbc, block, CCM_BLOCK, scratch, y) != 0) {
                goto out;
        }

        /* The AAD: a two-byte length, then the data, zero-padded to blocks. */
        if (alen) {
                memset(block, 0, CCM_BLOCK);
                block[0] = (unsigned char)(alen >> 8);
                block[1] = (unsigned char)alen;
                l = alen > 14 ? 14 : alen;
                memcpy(&block[2], aad, l);
                if (ccm_cbc_update(cbc, block, CCM_BLOCK, scratch, y) != 0) {
                        goto out;
                }
                aad += l;
                alen -= l;
                full = alen - alen % CCM_BLOCK;
                if (full && ccm_cbc_update(cbc, aad, full, scratch, y) != 0) {
                        goto out;
                }
                rest = alen - full;
                if (rest) {
                        memset(block, 0, CCM_BLOCK);
                        memcpy(block, aad + full, rest);
                        if (ccm_cbc_update(cbc, block, CCM_BLOCK, scratch, y) != 0) {
                                goto out;
                        }
                }
        }

        /* The payload, zero-padded to blocks. */
        full = plen - plen % CCM_BLOCK;
        if (full && ccm_cbc_update(cbc, p, full, scratch, y) != 0) {
                goto out;
        }
        rest = plen - full;
        if (rest) {
                memset(block, 0, CCM_BLOCK);
                memcpy(block, p + full, rest);
                if (ccm_cbc_update(cbc, block, CCM_BLOCK, scratch, y) != 0) {
                        goto out;
                }
        }
        rc = 0;
 out:
        CCCryptorRelease(cbc);
        memset(scratch, 0, sizeof(scratch));
        return rc;
}

/* S0 (the keystream block that masks the tag) into s0, then the payload
 * XORed with S1, S2, ... in place. */
static int ccm_ctr(const unsigned char *key, const unsigned char *nonce, size_t nlen,
                   unsigned char *p, size_t plen, unsigned char s0[CCM_BLOCK])
{
        static const unsigned char zero[CCM_BLOCK];
        unsigned char a0[CCM_BLOCK];
        CCCryptorRef ctr = NULL;
        size_t moved;
        int rc = -1;

        ccm_counter_block(nonce, nlen, 0, a0);
        if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                    a0, key, CCM_KEY_LEN, NULL, 0, 0, kCCModeOptionCTR_BE,
                                    &ctr) != kCCSuccess) {
                return -1;
        }
        if (CCCryptorUpdate(ctr, zero, CCM_BLOCK, s0, CCM_BLOCK, &moved) != kCCSuccess ||
            moved != CCM_BLOCK) {
                goto out;
        }
        /* CTR is a stream mode, which CommonCrypto runs in place. */
        if (plen && (CCCryptorUpdate(ctr, p, plen, p, plen, &moved) != kCCSuccess ||
                     moved != plen)) {
                goto out;
        }
        rc = 0;
 out:
        CCCryptorRelease(ctr);
        return rc;
}

int aes128ccm_encrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        unsigned char t[CCM_BLOCK], s0[CCM_BLOCK];
        size_t i;

        if (!ccm_fast_path_supported(nlen, alen, plen, mlen) ||
            ccm_mac(key, nonce, nlen, aad, alen, p, plen, mlen, t) != 0) {
                return aes128ccm_encrypt_reference(key, nonce, nlen, aad, alen,
                                                            p, plen, m, mlen);
        }
        /* The MAC is over the plaintext, so it comes before the payload is
         * encrypted in place. */
        if (ccm_ctr(key, nonce, nlen, p, plen, s0) != 0) {
                return -1;
        }
        for (i = 0; i < mlen; i++) {
                m[i] = t[i] ^ s0[i];
        }
        return 0;
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        unsigned char t[CCM_BLOCK], s0[CCM_BLOCK];
        unsigned char diff = 0;
        size_t i;

        if (!ccm_fast_path_supported(nlen, alen, plen, mlen)) {
                return aes128ccm_decrypt_reference(key, nonce, nlen, aad, alen,
                                                            p, plen, m, mlen);
        }
        if (ccm_ctr(key, nonce, nlen, p, plen, s0) != 0) {
                return -1;
        }
        if (ccm_mac(key, nonce, nlen, aad, alen, p, plen, mlen, t) != 0) {
                return -1;
        }
        /* Constant time, unlike upstream's memcmp(). */
        for (i = 0; i < mlen; i++) {
                diff |= (unsigned char)((t[i] ^ s0[i]) ^ m[i]);
        }
        return diff ? -1 : 0;
}
#endif /* AES128CCM_COMMONCRYPTO */

#else /* HAVE_OPENSSL */

#include <limits.h>
#include <openssl/evp.h>

static int aes128ccm_openssl(int enc, unsigned char *key,
                             unsigned char *nonce, size_t nlen,
                             unsigned char *aad, size_t alen,
                             unsigned char *p, size_t plen,
                             unsigned char *m, size_t mlen)
{
        EVP_CIPHER_CTX *ctx;
        int outl, rc = -1;

        if (plen > INT_MAX || alen > INT_MAX) {
                return -1;
        }
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
                return -1;
        }
        if (EVP_CipherInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL, enc) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nlen, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)mlen, enc ? NULL : m) != 1 ||
            EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, enc) != 1 ||
            EVP_CipherUpdate(ctx, NULL, &outl, NULL, (int)plen) != 1 ||
            EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)alen) != 1 ||
            EVP_CipherUpdate(ctx, p, &outl, p, (int)plen) != 1) {
                goto out;
        }
        if (enc && (EVP_CipherFinal_ex(ctx, p + outl, &outl) != 1 ||
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)mlen, m) != 1)) {
                goto out;
        }
        rc = 0;
 out:
        EVP_CIPHER_CTX_free(ctx);
        return rc;
}

int aes128ccm_encrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        return aes128ccm_openssl(1, key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        return aes128ccm_openssl(0, key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

#endif /* HAVE_OPENSSL */
