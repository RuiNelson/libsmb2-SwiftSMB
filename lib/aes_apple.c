#ifndef AES_APPLE_H_
#define AES_APPLE_H_

/*
   Copyright (C) 2025 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#include "aes_apple.h"

/* Use Apple's CommonCrypto only where it actually exists; otherwise
 * aes.c falls back to the portable reference AES implementation, e.g.
 * when building with a toolchain that doesn't see Apple's framework
 * headers at all. CommonCryptor.h (not the CommonCrypto.h umbrella,
 * which only exists from the 10.9 SDK onward) is the actual header
 * that declares the Cryptor API used below, and has shipped since
 * CommonCrypto was introduced in the 10.5 SDK. */
#if defined(__APPLE__) && defined(HAVE_COMMONCRYPTO_COMMONCRYPTOR_H)

#include <CommonCrypto/CommonCryptor.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "aes_reference.h"

#define AES128_KEY_LEN 16
#define AES128_BLOCK_SIZE 16

/*
 * libsmb2-SwiftSMB (MODS.md M2): callers (AES-CMAC signing in
 * smb2-signing.c, the reference AES-CCM) call this once per 16-byte block
 * with the same key. Creating and releasing a CCCryptor on every call cost
 * far more than the block itself, so each thread keeps the cryptor for the
 * last key it used and only creates a new one when the key changes.
 */
struct aes_apple_cache {
        CCCryptorRef cryptor;
        uint8_t key[AES128_KEY_LEN];
};

static pthread_key_t aes_apple_cache_key;
static pthread_once_t aes_apple_cache_once = PTHREAD_ONCE_INIT;
static int aes_apple_cache_ready;

static void aes_apple_cache_free(void *value)
{
        struct aes_apple_cache *cache = value;

        if (cache->cryptor != NULL) {
                CCCryptorRelease(cache->cryptor);
        }
        memset_s(cache, sizeof(*cache), 0, sizeof(*cache));
        free(cache);
}

static void aes_apple_cache_init(void)
{
        aes_apple_cache_ready =
                pthread_key_create(&aes_apple_cache_key, aes_apple_cache_free) == 0;
}

/* Constant time: the comparison must not reveal how much of the key matched. */
static int aes_apple_same_key(const uint8_t a[AES128_KEY_LEN], const uint8_t b[AES128_KEY_LEN])
{
        uint8_t diff = 0;
        int i;

        for (i = 0; i < AES128_KEY_LEN; i++) {
                diff |= a[i] ^ b[i];
        }
        return diff == 0;
}

static CCCryptorRef aes_apple_cryptor_for_key(const uint8_t *key)
{
        struct aes_apple_cache *cache;

        pthread_once(&aes_apple_cache_once, aes_apple_cache_init);
        if (!aes_apple_cache_ready) {
                return NULL;
        }
        cache = pthread_getspecific(aes_apple_cache_key);
        if (cache == NULL) {
                cache = calloc(1, sizeof(*cache));
                if (cache == NULL) {
                        return NULL;
                }
                if (pthread_setspecific(aes_apple_cache_key, cache) != 0) {
                        free(cache);
                        return NULL;
                }
        }
        if (cache->cryptor != NULL && aes_apple_same_key(cache->key, key)) {
                return cache->cryptor;
        }
        if (cache->cryptor != NULL) {
                CCCryptorRelease(cache->cryptor);
                cache->cryptor = NULL;
        }
        if (CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
                            key, AES128_KEY_LEN, NULL, &cache->cryptor) != kCCSuccess) {
                cache->cryptor = NULL;
                return NULL;
        }
        memcpy(cache->key, key, AES128_KEY_LEN);
        return cache->cryptor;
}

void AES128_ECB_encrypt_apple(const uint8_t *input, const uint8_t *key, uint8_t *output) {
        CCCryptorRef cryptor = aes_apple_cryptor_for_key(key);
        uint8_t block[AES128_BLOCK_SIZE];
        size_t moved = 0;

        if (cryptor != NULL) {
                /* ECB cannot run in place in CommonCrypto, and callers pass
                 * the same buffer for input and output. */
                memcpy(block, input, AES128_BLOCK_SIZE);
                if (CCCryptorUpdate(cryptor, block, AES128_BLOCK_SIZE, output,
                                    AES128_BLOCK_SIZE, &moved) == kCCSuccess &&
                    moved == AES128_BLOCK_SIZE) {
                        return;
                }
        }
        AES128_ECB_encrypt_reference((uint8_t *)(uintptr_t)input, key, output);
}

#endif

#endif

