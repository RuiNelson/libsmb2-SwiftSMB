# libsmb2-SwiftSMB: modifications to upstream libsmb2

This repository is SwiftSMB's fork of [sahlberg/libsmb2](https://github.com/sahlberg/libsmb2). SwiftSMB builds it
directly, as the Git submodule `Vendored/libsmb2-SwiftSMB` of
[RuiNelson/SwiftSMB](https://github.com/RuiNelson/SwiftSMB).

This file lists every way this fork differs from upstream. Keep it current: a change that is not listed here will
be lost or fought over at the next upstream merge.

## Policy

- **At least the latest stable upstream release.** The fork always contains the newest `libsmb2-X.Y.Z` release tag
  of upstream. It may be ahead of it: upstream `master` is merged whenever SwiftSMB needs a fix or feature from it.
- **Merge, never rebase.** Upstream is merged into `master` (`git merge upstream/master` or `git merge libsmb2-X.Y.Z`),
  so the fork's history and SwiftSMB's submodule pointers stay valid. Resolve conflicts in favour of upstream's
  code plus our modification, and update the affected entries below.
- **Every modification has an entry** under [Modifications](#modifications): what, why, files, the upstream issue or
  pull request, and when it can be dropped. Add or update it in the same commit as the change.
- **Mark the code.** Each change to an upstream file carries a `libsmb2-SwiftSMB (MODS.md Mx)` comment, so a merge
  conflict shows whose change it is. Prefer additions next to upstream's code over rewriting it, to keep merges small.
- **Keep upstream's builds working.** The CMake and autotools builds (and the upstream CI that runs on every push)
  must build as before; additions that need more than that, such as M4, are opt-in through a macro.
- **Prefer upstream.** Report bugs and offer fixes upstream. Drop a modification once upstream has an equivalent,
  and move its entry to [Dropped](#dropped).
- **Licenses.** libsmb2 is LGPL-2.1-or-later. Code added here must be under a compatible license (LGPL-2.1-or-later
  for our own code; MIT, BSD, or similar for third-party code). Apache-2.0 (OpenSSL 3+) and LGPL-3/GPL-2 (Nettle)
  code would force LGPL-3 on the whole library, so it is not used.
- **Improvements are welcome.** The fork may improve on upstream: faster, safer, or more complete code. Third-party
  code may be added for something libsmb2 lacks or does worse, if its license is compatible, it is kept unmodified in
  its own directory, and the entry says why it beats upstream's.

## Upstream base

| | |
|---|---|
| Upstream | https://github.com/sahlberg/libsmb2.git (add it as the `upstream` remote) |
| Latest stable release contained | `libsmb2-7.0.0` |
| Last upstream commit merged | `70e7a9b` (`libsmb2-7.0.0-11-g70e7a9b`, upstream `master` on 2026-11-19) |

Update this table after every merge.

### Merging upstream

```sh
git remote add upstream https://github.com/sahlberg/libsmb2.git   # once per clone
git fetch upstream --tags
git tag --list 'libsmb2-*' --sort=-v:refname | head -3            # newest stable release
git merge libsmb2-X.Y.Z                                           # or upstream/master
```

Then check every entry below against the merged code, rebuild SwiftSMB, and run its unit and integration tests.

## Modifications

### M1. CommonCrypto AES on Apple platforms

- **What:** define `HAVE_COMMONCRYPTO_COMMONCRYPTOR_H` (when `__has_include(<CommonCrypto/CommonCryptor.h>)`) in the
  Apple configuration, so `lib/aes.c` uses `lib/aes_apple.c` instead of the reference AES.
- **Why:** upstream's `include/apple/config.h`, which Xcode and Swift Package Manager builds use, leaves it out, so
  those builds use the table-based reference AES. It is not constant-time, and it is slower. Only the CMake build
  detects the header.
- **Files:** `include/apple/config.h` (appended block).
- **Upstream:** [sahlberg/libsmb2#541](https://github.com/sahlberg/libsmb2/issues/541).
- **Drop when:** upstream's `apple/config.h` enables CommonCrypto.

### M2. Reuse the AES key schedule per thread (AES-CMAC signing)

- **What:** `AES128_ECB_encrypt_apple()` keeps one ECB `CCCryptor` per thread for the last key used (through
  `pthread_key_create`, released and wiped when the thread ends), and only creates a new one when the key changes.
  It falls back to the reference AES if CommonCrypto fails. The key comparison is constant-time.
- **Why:** upstream creates and releases a `CCCryptor` for every 16-byte block, which costs far more than the block
  itself. SMB3 signing (AES-128-CMAC in `lib/smb2-signing.c`) calls it once per block. Signing went from ~110 to
  ~1200 MB/s on an Apple M4.
- **Files:** `lib/aes_apple.c` (the body under `HAVE_COMMONCRYPTO_COMMONCRYPTOR_H`). `lib/aes.c` is unchanged.
- **Upstream:** [sahlberg/libsmb2#541](https://github.com/sahlberg/libsmb2/issues/541).
- **Drop when:** upstream sets up the AES key once per message.

### M3. Whole-message AES-CCM with CommonCrypto (SMB3 sealing)

- **What:** on Apple platforms with CommonCrypto, `aes128ccm_encrypt()` and `aes128ccm_decrypt()` run CCM as one
  AES-CBC pass with a zero IV for the MAC, plus one AES-CTR pass from counter block A0 for the keystream, each over
  the whole message. Upstream's code is left as it is, but on those platforms its two functions are renamed to
  `aes128ccm_encrypt_reference()` and `aes128ccm_decrypt_reference()` with internal linkage. They handle inputs
  outside the fast path (nonce, tag, or AAD lengths SMB never uses), and encryption falls back to them if the MAC
  cannot be set up. The tag comparison is constant-time; upstream uses `memcmp`.
- **Why:** upstream encrypts block by block through `AES128_ECB_encrypt()`, twice per 16 bytes, so sealing ran at
  ~70 MB/s. It now runs at ~2000 MB/s on an Apple M4. Verified byte for byte against upstream's implementation over
  1080 combinations of sizes, and against Samba.
- **Files:** `lib/aes128ccm.c`: a renaming block after `#ifndef HAVE_OPENSSL`, and the fast path before
  `#else /* HAVE_OPENSSL */`, both under `AES128CCM_COMMONCRYPTO`.
- **Upstream:** [sahlberg/libsmb2#541](https://github.com/sahlberg/libsmb2/issues/541).
- **Drop when:** upstream's CCM is comparably fast without OpenSSL.

### M4. AES-128-GCM and AES-256-GCM without OpenSSL

- **What:** SMB 3.1.1 sealing with AES-GCM in builds without OpenSSL, when `HAVE_BUILTIN_AES_GCM` is defined on the
  compiler command line (SwiftSMB defines it). Without it, the fork offers GCM only with OpenSSL, as upstream does.
  - `lib/smb2-cmd-negotiate.c` offers and accepts the GCM ciphers with `HAVE_OPENSSL` or `HAVE_BUILTIN_AES_GCM`.
  - `lib/smb3-seal.c` keeps upstream's OpenSSL `smb3_aesgcm()`, and without OpenSSL defines one that calls
    `smb2_aes_gcm()` (`lib/aes-gcm.c`).
  - `lib/aes-gcm.c` seals with BearSSL's GCM. Both AES-128-GCM and AES-256-GCM use BearSSL's constant-time `aes_ct64` in
    counter mode. The one exception is AES-128-GCM with CommonCrypto (Apple, `HAVE_COMMONCRYPTO_COMMONCRYPTOR_H`),
    which uses libsmb2's own `AES128_ECB_encrypt()` (M1, M2), as it is faster there. libsmb2's reference AES, which
    Linux and Android would otherwise use, is 3 to 4 times slower than `aes_ct64` (about 51 against 200 MB/s on Linux
    arm64), expands the key for every block, and is not constant-time. libsmb2 has no AES-256.
  - `lib/bearssl/upstream` holds BearSSL v0.6 (MIT) files, unmodified: the GCM mode
    (`src/aead/gcm.c` with the constant-time `src/hash/ghash_ctmul64.c`) and AES-256 (`aes_ct64`). The
    `lib/bearssl/bearssl_*.c` wrappers compile them with a `swiftsmb_` prefix on every symbol
    (`lib/bearssl/swiftsmb_bearssl.h`), so they never collide with another BearSSL in the same process.
    `lib/bearssl/UPSTREAM.md` has the file list, hashes, layout, and update procedure.
  - `swiftsmb_set_gcm_seal()` (`include/smb2/swiftsmb-gcm.h`) installs another GCM implementation that seals a whole
    message at once. SwiftSMB installs CryptoKit's `AES.GCM` on Apple platforms, and BearSSL is then not used. On Linux, M6 tries the
    system's OpenSSL before BearSSL. The
    `swiftsmb_` prefix marks it as this fork's API.
- **Why:** upstream builds GCM only with OpenSSL, and SwiftSMB does not link OpenSSL (OpenSSL 3+ is Apache-2.0,
  which would force LGPL-3 on the library). Without GCM, servers restricted to GCM, such as AES-256-GCM only, refuse
  encrypted connections.
- **Files:** `lib/smb3-seal.c`, `lib/smb2-cmd-negotiate.c` (guards), `lib/aes-gcm.c`, `lib/aes-gcm.h`,
  `lib/bearssl/`, `include/smb2/swiftsmb-gcm.h`. Upstream's CMake and autotools builds do not compile the new files.
- **Upstream:** none yet.
- **Drop when:** upstream supports GCM without OpenSSL.

### M5. Linux and Android configuration with a strong random source

- **What:** `include/linux/config.h`, a `config.h` for Linux and Android builds without a configure step, which
  defines `HAVE_GETRANDOM`, `HAVE_SYS_RANDOM_H` and `HAVE_DEV_URANDOM` on Linux, and only `HAVE_DEV_URANDOM` on
  Android.
- **Why:** such builds need a configuration, and upstream's `include/apple/config.h` does not suit Linux: it defines
  `HAVE_SOCKADDR_LEN` unconditionally, and Linux's `sockaddr` has no `sa_len`. Without a strong random source,
  `smb2_random_bytes()` (the NTLMv2 client challenge, the SMB 3.1.1 preauth salt, the client GUID, the nonce of every
  sealed message) falls back to `random()`, which is predictable and not thread-safe.
- **Files:** `include/linux/config.h` (new).
- **Upstream:** none needed. Upstream's own build systems detect these.
- **Drop when:** upstream ships an equivalent configuration for builds without a configure step.

### M6. System OpenSSL for AES-GCM on Linux, through dlopen

- **What:** with `SMB2_GCM_DLOPEN_OPENSSL` defined (SwiftSMB defines it on Linux, not on Android), `smb2_aes_gcm()` tries
  the system's `libcrypto` (SONAMEs `libcrypto.so.3`, `.so.4`, `.so.1.1`, in that order) before BearSSL.
  `lib/aes-gcm-dlopen.c` loads it once with `dlopen` and `dlsym` (the `EVP_CIPHER_CTX_*`, `EVP_aes_{128,256}_gcm`, and
  `EVP_Cipher*` functions), checks it with a known-answer test (NIST test cases 2 and 14), and then seals or opens each
  message through `EVP_CipherInit_ex` and friends. Anything that stops it before it touches the data (no library, a
  failed check, a message over `INT_MAX`, a cipher the library lacks) returns `SMB2_AES_GCM_UNAVAILABLE`, and
  `smb2_aes_gcm()` falls through to BearSSL. A failure after the data was touched, a tag that does not match
  included, is final.
- **Why:** OpenSSL uses AES-NI or the ARMv8 AES instructions, so it seals at gigabytes per second, where BearSSL's
  constant-time software AES does 150 to 200 MB/s.
- **License:** nothing of OpenSSL is compiled or linked in, and no OpenSSL header is included (the few constants and
  types are declared in the file), so no Apache-2.0 code becomes part of libsmb2. Whether the system has OpenSSL,
  and under which license, is up to the system. The library is loaded by fixed SONAME, never by a path or from the
  environment's directories beyond the dynamic loader's own search.
- **Not on Android:** applications cannot `dlopen` the system's `libcrypto` there. Static or musl builds without
  `dlopen`, or without OpenSSL, use BearSSL.
- **Files:** `lib/aes-gcm-dlopen.c`, `lib/aes-gcm-dlopen.h` (new), and a hook in `lib/aes-gcm.c`. The build links
  `libdl` on Linux (SwiftSMB's `Package.swift`). Upstream's CMake and autotools builds do not compile the new files.
- **Upstream:** none.
- **Drop when:** upstream supports GCM without linking OpenSSL, or SwiftSMB stops needing a software fallback.

## SwiftPM packaging in SwiftSMB

These are not changes to libsmb2's code, and they stay in SwiftSMB unless the fork becomes a Swift package itself.
SwiftSMB's `Package.swift` compiles this fork's `lib/` (excluding `lib/bearssl/upstream`, which the wrappers compile),
with `HAVE_BUILTIN_AES_GCM` defined, and `SMB2_GCM_DLOPEN_OPENSSL` on Linux.

- `Sources/libsmb2/include/config.h`: picks this fork's `include/linux/config.h` or `include/apple/config.h`.
- `Sources/libsmb2/include/module.modulemap`: module `SMB2` with `SMB2.Internal`, `SMB2.Raw`, and `SMB2.GCM`.
- One-line forwarder headers (`libsmb2-private.h`, `slist.h`, `portable-endian.h`, `asprintf.h`, `smb2/smb2-errors.h`,
  `smb2/libsmb2-share-enum.h`), because upstream's `include/` must not be on the header search path (it has its own
  `module.modulemap`).
- `Sources/libsmb2/xcode_compat.c`: a weak `__llvm_profile_runtime`, so the dynamic product links with coverage.

## Upstream bugs SwiftSMB works around

Candidates to fix here, and to report upstream.

- **Lease-break auto-acknowledgement.** In `oplock_break_cb()` in `lib/libsmb2.c`, the automatic lease-break
  acknowledgement copies the notification's flags (`rep_lease.flags = rep->lock.lease.flags;`), so
  `SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED` lands in the acknowledgement's reserved Flags field. Samba refuses it,
  and the conflicting open waits for the 35-second break timeout. It also acknowledges breaks that do not require
  it. SwiftSMB returns `SMB2_LEASE_STATE_NO_AUTO_ACK` from the callback and sends its own acknowledgement with Flags 0,
  only when one is required (`Sources/SwiftSMB/Bridge/Bridge-OpLockBreaks.swift`). Not reported upstream yet.

## Dropped

None yet.
