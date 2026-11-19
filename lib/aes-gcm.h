/*
   libsmb2-SwiftSMB (MODS.md M4): AES-GCM without OpenSSL.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifndef _AES_GCM_H_
#define _AES_GCM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef HAVE_BUILTIN_AES_GCM
/*
 * Seals (enc != 0) or opens one message in place with AES-GCM. key is 16
 * bytes (AES-128-GCM) or 32 bytes (AES-256-GCM), nonce 12 bytes, tag 16
 * bytes: written when sealing, checked when opening. Returns 0 on success,
 * -1 on failure, including a tag that does not match.
 */
int smb2_aes_gcm(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag);
#endif

#endif
