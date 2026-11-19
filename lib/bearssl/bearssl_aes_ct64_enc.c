/*
   libsmb2-SwiftSMB (MODS.md M4): compiles BearSSL's src/symcipher/aes_ct64_enc.c, unmodified,
   with swiftsmb_ symbol names (swiftsmb_bearssl.h). Only when
   HAVE_BUILTIN_AES_GCM is defined, on the compiler command line: this file
   must not include libsmb2's config.h or other headers before BearSSL's,
   whose inner.h defines functions such as MIN that libsmb2-private.h
   defines as macros. See UPSTREAM.md.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifdef HAVE_BUILTIN_AES_GCM
#include "swiftsmb_bearssl.h"
#include "upstream/src/symcipher/aes_ct64_enc.c"
#else
typedef int bearssl_aes_ct64_enc_unused;
#endif
