/*
   libsmb2-SwiftSMB (MODS.md M7): compiles BearSSL's src/symcipher/aes_x86ni_ctr.c, unmodified,
   with swiftsmb_ symbol names (swiftsmb_bearssl.h). Only on x86 and x86-64
   other than Apple's, when HAVE_BUILTIN_AES_GCM is defined on the compiler
   command line (SWIFTSMB_BEARSSL_X86NI in swiftsmb_bearssl.h). BearSSL
   enables AES-NI and PCLMULQDQ per function, and ../aes-gcm.c calls this
   code only after checking the CPU. This file must not include libsmb2's
   config.h or other headers before BearSSL's, whose inner.h defines functions
   such as MIN that libsmb2-private.h defines as macros. See UPSTREAM.md.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifdef HAVE_BUILTIN_AES_GCM
#include "swiftsmb_bearssl.h"
#endif
#ifdef SWIFTSMB_BEARSSL_X86NI
#include "upstream/src/symcipher/aes_x86ni_ctr.c"
#else
typedef int bearssl_aes_x86ni_ctr_unused;
#endif
