# BearSSL in libsmb2-SwiftSMB

Part of modification M4 in `../../MODS.md`: AES-128-GCM and AES-256-GCM without OpenSSL. These are the BearSSL
files `../aes-gcm.c` uses:

- the GCM mode (GHASH, counter, tag): `src/aead/gcm.c` with the constant-time `src/hash/ghash_ctmul64.c`;
- AES, in counter mode: the constant-time `aes_ct64` (`src/symcipher/aes_ct64.c`, `aes_ct64_enc.c`,
  `aes_ct64_ctr.c`), plus the two little-endian codec helpers it calls (`src/codec/enc32le.c`, `dec32le.c`). It
  serves AES-256-GCM, which libsmb2's AES (`../aes.c`, AES-128 only) cannot, and AES-128-GCM, because libsmb2's
  reference AES is 3 to 4 times slower and not constant-time.

The exception is AES-128-GCM where libsmb2 uses CommonCrypto (Apple): `../aes-gcm.c` wraps libsmb2's
`AES128_ECB_encrypt()` in a BearSSL counter-mode class there, as it is faster than `aes_ct64`.

Modification M7 adds BearSSL's x86 hardware code, used on x86 and x86-64 other than Apple's before the software
path above: AES-NI in counter mode (`src/symcipher/aes_x86ni.c`, `aes_x86ni_ctr.c`) and the PCLMULQDQ GHASH
(`src/hash/ghash_pclmul.c`). BearSSL enables these instructions per function (`BR_TARGET`), and
`br_aes_x86ni_ctr_get_vtable()` and `br_ghash_pclmul_get()` return `NULL` when the CPU or the compiler lacks them.
`../aes-gcm.c` checks CPUID and runs a self-check against the software path before it uses them. Their wrappers
compile only where `swiftsmb_bearssl.h` defines `SWIFTSMB_BEARSSL_X86NI`. On AArch64, M7 uses our own
`../aes-gcm-armv8.c`, since BearSSL has no Arm code.

BearSSL is under the MIT license (`upstream/LICENSE.txt`), which is compatible with libsmb2's LGPL-2.1-or-later.
The files of ours here are under the LGPL-2.1-or-later.

## Layout and build

- `upstream/` holds BearSSL's files unmodified. Builds must not compile them directly.
- Each `bearssl_*.c` here compiles one of them after `swiftsmb_bearssl.h`, which gives every BearSSL function and
  table a `swiftsmb_` prefix, so they never collide with, or bind to, another BearSSL in the same process.
- Everything is built only when `HAVE_BUILTIN_AES_GCM` is defined on the compiler command line; otherwise the
  wrappers and `../aes-gcm.c` compile to nothing, and libsmb2 offers GCM only with OpenSSL, as upstream does. The
  wrappers must not include libsmb2's `config.h` or headers first: BearSSL's `inner.h` defines functions such as
  `MIN` that `libsmb2-private.h` defines as macros.
- Header search path: `upstream/inc` (for `bearssl.h`) and `upstream/src` (for `inner.h`), after libsmb2's own
  `config.h` directory. `inner.h` finds BearSSL's `config.h` next to itself.
- The upstream CMake and autotools builds do not list these files, so they build libsmb2 as upstream does. SwiftSMB
  defines `HAVE_BUILTIN_AES_GCM` and compiles them through SwiftPM.

## Copied files

From BearSSL `v0.6` (commit `8ef7680081c61b486622f2d983c0d3d21e83caad`, https://www.bearssl.org/git/BearSSL),
unmodified. The five M4 algorithm files are identical on BearSSL's `master` as of April 2026, and the three M7 files
on `master` as of November 2026.

| File | SHA-256 |
|---|---|
| `upstream/LICENSE.txt` | `771bf18c8633ea69ec9b07d2e604c4b99b7bef41b0f5ce6385d24df4448f61ca` |
| `upstream/src/inner.h` | `05a4c5b30599a00deda2648fbb842c07eb783bc5a62589ba90c3fada36ad732a` |
| `upstream/src/config.h` | `785d0cea25a7bbcb2b6d32e096072ac00b12f4d0b4819aa95ca28816a0e484d0` |
| `upstream/src/aead/gcm.c` | `1bea4df57ed57cdcd3dc2a44e7dbbe5866ccf045e0722fb68a2801dffa2f640f` |
| `upstream/src/hash/ghash_ctmul64.c` | `a5a5986e621de05735fdfd257fd39f313400ff53631d575232c230d3184bc4b9` |
| `upstream/src/symcipher/aes_ct64.c` | `755144aacacfb0eb9434876661655d16b91caa4f54fa46351dc626a56d9048f1` |
| `upstream/src/symcipher/aes_ct64_enc.c` | `3e2b380ddbc0f5d9bd3f8622d552e052a6361948ecc4077486a17273fa0148c4` |
| `upstream/src/symcipher/aes_ct64_ctr.c` | `713a6e5afafa06f9bd608d5552abba5d38f5790a7d58f2c397c9257904a2943f` |
| `upstream/src/codec/enc32le.c` | `7faa71643fc74570fd4c550974a075ec05485a0b3805cbdc826d662cb347e79b` |
| `upstream/src/codec/dec32le.c` | `fb45ce9e370d72c495dfbb08267e2fd32dcf5215c28df5d2db24f842b2d2d43a` |
| `upstream/src/symcipher/aes_x86ni.c` (M7) | `22d6a00145c86407752103e75f1b5a31defef8d0a9821192a6f0808e656d454a` |
| `upstream/src/symcipher/aes_x86ni_ctr.c` (M7) | `cbc622657b5663024591631592822b82605deea91704714e98584d7ad9456518` |
| `upstream/src/hash/ghash_pclmul.c` (M7) | `3d7e2458ca4cfd9a8a1612dc56334b08b20d5b7ebc660ef60df715a2f5c75a8b` |
| `upstream/inc/bearssl.h` | `5e73cb64005a5efd5082932bb9b7a3301a748969841c45d7f61123006e9ca5fe` |
| `upstream/inc/bearssl_aead.h` | `9d90afbc65535335517c028817ac0704af6b58971f2c262a65eb26e0b4099201` |
| `upstream/inc/bearssl_block.h` | `a00b4a48c42c824f2ec4ee775672df9cec86ad455b08cb8ae7eb8c89e63d082a` |
| `upstream/inc/bearssl_ec.h` | `3ee566b317361828cce70a96ce22d34d865b8dea73e65de55a6f511076bab766` |
| `upstream/inc/bearssl_hash.h` | `adfe3039fe48962c7fd74a1031f6d9dde951fb12a6acdae65a39f4d8537d2ef9` |
| `upstream/inc/bearssl_hmac.h` | `a40c14a7a71d5b4fa21f8485d7ad3975d3a37b9cd8b9f72cd0fa032af8105614` |
| `upstream/inc/bearssl_kdf.h` | `dee68113a97743febd0fee22d545c9548d81a6448e5b28311fa8ce384ee48bd8` |
| `upstream/inc/bearssl_pem.h` | `ef36260e8568e5927178e92c2aab849be71bc07414c01baeb1d12a3a51a82c3e` |
| `upstream/inc/bearssl_prf.h` | `0162e674d6c49425bfa0e8e9c79b3d850530e7928288930284fb7ac940a12b17` |
| `upstream/inc/bearssl_rand.h` | `968335e8a2957e5bf64cb0b6b1f916e53bc330e8c66d5f2d2f658f415a56dd44` |
| `upstream/inc/bearssl_rsa.h` | `1d9538cb78269cd02ca9ec118f67930ba88730eece4427f973fda2cb7122f9ff` |
| `upstream/inc/bearssl_ssl.h` | `52ea66d52eac903661865d99a05b5621e743a4acb227d7faf154bb5ce1ea48f3` |
| `upstream/inc/bearssl_x509.h` | `92a1674630209ee2a35d078990f7d8a1bf98753b4ec97db9aa9c288f7c294ab1` |

`inner.h` declares much of BearSSL and includes `bearssl.h`, which includes every public header, so all of `inc/`
is needed even though only the files above are compiled.

## Speed

Without the CryptoKit hook or M7's hardware path, 1 MiB messages, -O2 build:

| | Apple M4 | Linux arm64 (same M4, Docker) |
|---|---|---|
| AES-128-GCM (libsmb2's AES) | ~620 MB/s (`../aes_apple.c`, CommonCrypto; used on Apple) | ~51 MB/s (reference AES, key expanded per block; no longer used) |
| AES-128-GCM (BearSSL `aes_ct64`) | ~230 MB/s | ~200 MB/s (used on Linux and Android) |
| AES-256-GCM (BearSSL `aes_ct64`) | ~177 MB/s | ~158 MB/s |

M7's hardware path, 1 MiB messages, -O2, in Docker on the same M4 (Linux arm64 native; Linux amd64 emulated, so
indicative only):

| | Linux arm64 gcc | Linux arm64 clang | Linux amd64 gcc | Linux amd64 clang |
|---|---|---|---|---|
| AES-128-GCM | ~4500 MB/s | ~6100 MB/s | ~3700 MB/s | ~3800 MB/s |
| AES-256-GCM | ~4200 MB/s | ~5600 MB/s | ~3200 MB/s | ~3300 MB/s |

## Updating

1. Check out the new BearSSL release tag in a separate clone.
2. Copy the files above over `upstream/`, and update the tag, commit, and hashes in this file.
3. Build. If a copied file calls a BearSSL function that is not compiled here, add its source file and a
   `bearssl_*.c` wrapper. If it defines a new global symbol, add its `swiftsmb_` name to `swiftsmb_bearssl.h`:
   `nm -g` on the `bearssl_*.o` objects must show no `br_` symbol (build for x86-64 too, where the M7 wrappers
   compile).
4. Check the result against the GCM test vectors (McGrew–Viega test cases 2–4 and 14–16) and a full OpenSSL build,
   and against a Samba server with `server smb3 encryption algorithms` set to `AES-128-GCM` and to `AES-256-GCM`,
   with SwiftSMB's CryptoKit hook and with `swiftsmb_set_gcm_seal(NULL)`.
