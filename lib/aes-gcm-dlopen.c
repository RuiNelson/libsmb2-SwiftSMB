/*
   libsmb2-SwiftSMB (MODS.md M6): AES-GCM through the system's OpenSSL.

   On Linux, smb2_aes_gcm() (aes-gcm.c) first tries the libcrypto the system
   already has, loaded at run time with dlopen(). It uses AES-NI or the ARMv8
   AES instructions, at gigabytes per second, where BearSSL does 150 to 200
   MB/s. When there is no usable libcrypto, smb2_aes_gcm() falls back to
   BearSSL, so GCM is always available.

   Nothing of OpenSSL is compiled or linked in: no OpenSSL header is included
   (the few types and constants needed are declared here, with the values that
   OpenSSL 1.1, 3, and later share), so no Apache-2.0 code becomes part of this
   library. The library is loaded by fixed SONAME, never by a path.

   Built only with SMB2_GCM_DLOPEN_OPENSSL (and HAVE_BUILTIN_AES_GCM), on Linux
   but not Android, whose system libcrypto is not available to applications.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_BUILTIN_AES_GCM) && defined(SMB2_GCM_DLOPEN_OPENSSL) && \
    defined(__linux__) && !defined(__ANDROID__)

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "aes-gcm-dlopen.h"

/* EVP_CTRL_AEAD_GET_TAG and EVP_CTRL_AEAD_SET_TAG: the same in OpenSSL 1.1, 3, and later. */
#define OSSL_CTRL_GET_TAG 0x10
#define OSSL_CTRL_SET_TAG 0x11

typedef void *(*ossl_ctx_new_fn)(void);
typedef void (*ossl_ctx_free_fn)(void *ctx);
typedef const void *(*ossl_cipher_fn)(void);
typedef int (*ossl_init_fn)(void *ctx, const void *cipher, void *engine, const unsigned char *key,
                            const unsigned char *iv, int enc);
typedef int (*ossl_update_fn)(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
typedef int (*ossl_final_fn)(void *ctx, unsigned char *out, int *outl);
typedef int (*ossl_ctrl_fn)(void *ctx, int type, int arg, void *ptr);

static struct {
        ossl_ctx_new_fn ctx_new;
        ossl_ctx_free_fn ctx_free;
        ossl_cipher_fn aes128;
        ossl_cipher_fn aes256;
        ossl_init_fn init;
        ossl_update_fn update;
        ossl_final_fn final;
        ossl_ctrl_fn ctrl;
} ossl;

static pthread_once_t ossl_once = PTHREAD_ONCE_INIT;
static int ossl_usable;

static int ossl_seal(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag);

/*
 * Known-answer check of a library before it is used (NIST GCM test cases 2
 * and 14: all-zero key and IV, one zero block): a libcrypto that loads but
 * does not give the right answer, such as one whose providers are restricted,
 * is not used.
 */
static int ossl_known_answer(void)
{
        static const uint8_t ct128[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                          0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
        static const uint8_t tag128[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                           0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
        static const uint8_t ct256[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                                          0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};
        static const uint8_t tag256[16] = {0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                                           0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19};
        uint8_t key[32], nonce[12], buf[16], tag[16];
        size_t kl;

        for (kl = 16; kl <= 32; kl += 16) {
                memset(key, 0, sizeof(key));
                memset(nonce, 0, sizeof(nonce));
                memset(buf, 0, sizeof(buf));
                if (ossl_seal(1, key, kl, nonce, NULL, 0, buf, sizeof(buf), tag) != 0 ||
                    memcmp(buf, kl == 16 ? ct128 : ct256, 16) != 0 ||
                    memcmp(tag, kl == 16 ? tag128 : tag256, 16) != 0) {
                        return 0;
                }
        }
        return 1;
}

static void ossl_load(void)
{
        static const char *const names[] = {"libcrypto.so.3", "libcrypto.so.4", "libcrypto.so.1.1"};
        size_t i;

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                void *h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);

                if (h == NULL) {
                        continue;
                }
                ossl.ctx_new = (ossl_ctx_new_fn)dlsym(h, "EVP_CIPHER_CTX_new");
                ossl.ctx_free = (ossl_ctx_free_fn)dlsym(h, "EVP_CIPHER_CTX_free");
                ossl.aes128 = (ossl_cipher_fn)dlsym(h, "EVP_aes_128_gcm");
                ossl.aes256 = (ossl_cipher_fn)dlsym(h, "EVP_aes_256_gcm");
                ossl.init = (ossl_init_fn)dlsym(h, "EVP_CipherInit_ex");
                ossl.update = (ossl_update_fn)dlsym(h, "EVP_CipherUpdate");
                ossl.final = (ossl_final_fn)dlsym(h, "EVP_CipherFinal_ex");
                ossl.ctrl = (ossl_ctrl_fn)dlsym(h, "EVP_CIPHER_CTX_ctrl");
                if (ossl.ctx_new && ossl.ctx_free && ossl.aes128 && ossl.aes256 && ossl.init &&
                    ossl.update && ossl.final && ossl.ctrl) {
                        ossl_usable = 1;
                        if (ossl_known_answer()) {
                                return; /* The handle stays open for the life of the process. */
                        }
                        ossl_usable = 0;
                }
                dlclose(h);
        }
}

/*
 * 0 on success, -1 on failure (a tag that does not match included), and
 * SMB2_AES_GCM_UNAVAILABLE when it could not start, before touching the data.
 */
static int ossl_seal(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        const void *cipher;
        void *ctx;
        uint8_t fin[16];
        int outl = 0, rc = -1;

        if (plen > INT_MAX || aad_len > INT_MAX) {
                return SMB2_AES_GCM_UNAVAILABLE;
        }
        cipher = key_len == 16 ? ossl.aes128() : ossl.aes256();
        ctx = ossl.ctx_new();
        if (cipher == NULL || ctx == NULL) {
                if (ctx != NULL) {
                        ossl.ctx_free(ctx);
                }
                return SMB2_AES_GCM_UNAVAILABLE;
        }
        /* The default IV length of GCM is the 12 bytes SMB uses. */
        if (ossl.init(ctx, cipher, NULL, key, nonce, enc ? 1 : 0) != 1) {
                ossl.ctx_free(ctx);
                return SMB2_AES_GCM_UNAVAILABLE;
        }
        if (aad_len > 0 && ossl.update(ctx, NULL, &outl, aad, (int)aad_len) != 1) {
                goto out;
        }
        if (plen > 0 && ossl.update(ctx, p, &outl, p, (int)plen) != 1) {
                goto out;
        }
        if (!enc && ossl.ctrl(ctx, OSSL_CTRL_SET_TAG, 16, tag) != 1) {
                goto out;
        }
        if (ossl.final(ctx, fin, &outl) != 1) {
                goto out; /* For opening, the tag does not match. */
        }
        if (enc && ossl.ctrl(ctx, OSSL_CTRL_GET_TAG, 16, tag) != 1) {
                goto out;
        }
        rc = 0;
out:
        ossl.ctx_free(ctx); /* Wipes the key schedule. */
        return rc;
}

int smb2_aes_gcm_openssl(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag)
{
        pthread_once(&ossl_once, ossl_load);
        if (!ossl_usable || (key_len != 16 && key_len != 32)) {
                return SMB2_AES_GCM_UNAVAILABLE;
        }
        return ossl_seal(enc, key, key_len, nonce, aad, aad_len, p, plen, tag);
}

#else

typedef int aes_gcm_dlopen_unused;

#endif
