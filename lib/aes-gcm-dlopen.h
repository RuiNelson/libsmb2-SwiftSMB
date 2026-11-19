/*
   libsmb2-SwiftSMB (MODS.md M6): AES-GCM through the system's OpenSSL.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifndef _AES_GCM_DLOPEN_H_
#define _AES_GCM_DLOPEN_H_

#include <stddef.h>
#include <stdint.h>

/* Returned by smb2_aes_gcm_openssl() when it could not be used: no usable libcrypto, or a request it cannot take. */
#define SMB2_AES_GCM_UNAVAILABLE 1

/*
 * smb2_aes_gcm() (aes-gcm.h) through the system's libcrypto, found with
 * dlopen(). Returns 0 on success, -1 on failure (a tag that does not match
 * included, with the data then unusable), or SMB2_AES_GCM_UNAVAILABLE, in
 * which case nothing was touched and another implementation must be used.
 */
int smb2_aes_gcm_openssl(int enc, const uint8_t *key, size_t key_len, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len, uint8_t *p, size_t plen, uint8_t *tag);

#endif
