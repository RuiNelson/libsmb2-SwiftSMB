/*
   libsmb2-SwiftSMB (MODS.md M7): AES-GCM with the ARMv8 Cryptography Extensions.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifndef _AES_GCM_ARMV8_H_
#define _AES_GCM_ARMV8_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Built on little-endian AArch64 other than Apple's (CryptoKit and
 * CommonCrypto cover those), with a clang or gcc that takes per-function
 * target attributes for the AES and PMULL instructions. Everywhere else,
 * including 32-bit Arm, it compiles to nothing.
 */
#if defined(HAVE_BUILTIN_AES_GCM) && defined(__aarch64__) && !defined(__AARCH64EB__) && \
    !defined(__APPLE__) && !defined(_WIN32) && \
    ((defined(__clang__) && __clang_major__ >= 8) || \
     (!defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 8))
#define SMB2_GCM_ARMV8 1

/*
 * 1 when the CPU has the AES and PMULL instructions (getauxval(AT_HWCAP) on
 * Linux and Android; 0 on any other system). Executes none of them.
 */
int smb2_aes_gcm_armv8_supported(void);

/*
 * smb2_aes_gcm() (aes-gcm.h) with the ARMv8 AES and PMULL instructions. Call
 * it only after smb2_aes_gcm_armv8_supported() returned 1: on a CPU without
 * them it dies with SIGILL. Returns 0 on success, -1 on failure (a tag that
 * does not match, with the data then unusable), or SMB2_AES_GCM_UNAVAILABLE
 * (aes-gcm-dlopen.h) for a request it does not take, before touching the data.
 */
int smb2_aes_gcm_armv8(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                       const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag);
#endif

#endif
