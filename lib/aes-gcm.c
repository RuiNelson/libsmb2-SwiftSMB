/*
   libsmb2-SwiftSMB (MODS.md M4): AES-GCM without OpenSSL, for smb3-seal.c.

   Two implementations:
   - A hook installed with swiftsmb_set_gcm_seal() (swiftsmb-gcm.h). SwiftSMB
     installs CryptoKit's AES.GCM on Apple platforms.
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
#include "swiftsmb-gcm.h"

#define GCM_BLOCK 16
#define GCM_IV 12

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

int smb2_aes_gcm(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        swiftsmb_gcm_seal_fn hook = __atomic_load_n(&swiftsmb_gcm_hook, __ATOMIC_ACQUIRE);
        union {
                const br_block_ctr_class *vtable;
#ifdef SMB2_GCM_LIBSMB2_AES128
                libsmb2_aes128_ctr_keys aes128;
#endif
                br_aes_ct64_ctr_keys ct64;
        } ctr;
        br_gcm_context gcm;
        int rc;

        if (key_len != 16 && key_len != 32) {
                return -1;
        }
        if (hook != NULL) {
                return hook(enc ? 1 : 0, key, key_len, nonce, aad, aad_len, p, plen, tag) == 0 ? 0 : -1;
        }

#ifdef SMB2_GCM_LIBSMB2_AES128
        ctr.vtable = key_len == 16 ? &libsmb2_aes128_ctr_vtable : &br_aes_ct64_ctr_vtable;
#else
        ctr.vtable = &br_aes_ct64_ctr_vtable;
#endif
        ctr.vtable->init(&ctr.vtable, key, key_len);
        br_gcm_init(&gcm, &ctr.vtable, br_ghash_ctmul64);
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

#else

typedef int aes_gcm_unused;

#endif /* HAVE_BUILTIN_AES_GCM */
