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
  pull request, and when it can be dropped.
- **Prefer upstream.** Report bugs and offer fixes upstream. Drop a modification once upstream has an equivalent,
  and move its entry to [Dropped](#dropped).
- **Licenses.** libsmb2 is LGPL-2.1-or-later. Code added here must be under a compatible license (LGPL-2.1-or-later
  for our own code; MIT, BSD, or similar for third-party code). Apache-2.0 (OpenSSL 3+) and LGPL-3/GPL-2 (Nettle)
  code would force LGPL-3 on the whole library, so it is not used.
- **Third-party code only for what libsmb2 lacks.** Do not bring in another implementation of something libsmb2
  already has.

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

The fork does not carry any of these yet. They are listed here so they are tracked from the start. Until they move, they
live in SwiftSMB under `Sources/libsmb2` (`patches/`, `gcm/`, `include/`), where SwiftPM compiles them on top of an
unmodified upstream checkout. Each entry names the file in SwiftSMB today and the file it changes in this repository.

### M1. CommonCrypto AES on Apple platforms

- **What:** define `HAVE_COMMONCRYPTO_COMMONCRYPTOR_H` (guarded by `__has_include(<CommonCrypto/CommonCryptor.h>)`)
  in the Apple configuration, so `lib/aes.c` uses `lib/aes_apple.c` instead of the reference AES.
- **Why:** upstream's `include/apple/config.h`, which `include/module.modulemap` builds against (Xcode and SwiftPM),
  leaves it out, so those builds use the table-based reference AES. It is not constant-time, and it is slower. Only
  the CMake build detects the header.
- **Files:** `include/apple/config.h`. In SwiftSMB today: `Sources/libsmb2/include/config.h`.
- **Upstream:** [sahlberg/libsmb2#541](https://github.com/sahlberg/libsmb2/issues/541).
- **Drop when:** upstream's `apple/config.h` enables CommonCrypto.

### M2. Reuse the AES key schedule per thread (AES-CMAC signing)

- **What:** on Apple platforms, `AES128_ECB_encrypt()` keeps one ECB `CCCryptor` per thread for the last key used
  (through `pthread_key_create`, released and wiped when the thread ends). It creates a new one only when the key
  changes, and falls back to the reference AES if CommonCrypto fails. The key comparison is constant-time.
- **Why:** upstream's `aes_apple.c` creates and releases a `CCCryptor` for every 16-byte block, which costs far more
  than the block itself. SMB3 signing (AES-128-CMAC in `lib/smb2-signing.c`) calls it once per block. Signing went
  from ~110 to ~1200 MB/s on an Apple M4.
- **Files:** `lib/aes.c`. In SwiftSMB today: `Sources/libsmb2/patches/aes.c`, which replaces upstream's file on Apple
  platforms and includes it unchanged elsewhere.
- **Upstream:** [sahlberg/libsmb2#541](https://github.com/sahlberg/libsmb2/issues/541).
- **Drop when:** upstream sets up the AES key once per message.

### M3. Whole-message AES-CCM with CommonCrypto (SMB3 sealing)

- **What:** on Apple platforms, `aes128ccm_encrypt()` and `aes128ccm_decrypt()` run CCM as one AES-CBC pass with a
  zero IV for the MAC, plus one AES-CTR pass from counter block A0 for the keystream, each over the whole message.
  Upstream's functions are still compiled, under a `swiftsmb_reference_` prefix, and handle inputs outside the fast
  path (nonce, tag, or AAD lengths SMB never uses). Encryption also falls back to them if the MAC cannot be set up.
  The tag comparison is constant-time; upstream uses `memcmp`.
- **Why:** upstream encrypts block by block through `AES128_ECB_encrypt()`, twice per 16 bytes, so sealing ran at
  ~70 MB/s. It now runs at ~2200 MB/s on an Apple M4. Verified byte for byte against upstream's implementation over
  1080 combinations of sizes, and against Samba.
- **Files:** `lib/aes128ccm.c`. In SwiftSMB today: `Sources/libsmb2/patches/aes128ccm.c`.
- **Upstream:** [sahlberg/libsmb2#541](https://github.com/sahlberg/libsmb2/issues/541).
- **Drop when:** upstream's CCM is comparably fast without OpenSSL.

### M4. AES-128-GCM and AES-256-GCM without OpenSSL

- **What:** SMB 3.1.1 sealing with AES-GCM in builds without OpenSSL.
  - `lib/smb3-seal.c` and `lib/smb2-cmd-negotiate.c` are built with `HAVE_OPENSSL` defined for those two files only:
    the first seals through `<openssl/evp.h>`, the second offers and accepts the GCM ciphers. `HAVE_OPENSSL` must not
    be defined for the whole library: it would move CCM and signing onto OpenSSL code that is not there.
  - `<openssl/evp.h>` is a shim of ours: the `EVP_*` calls `smb3_aesgcm()` makes, implemented in `evp_gcm.c` over
    BearSSL's GCM. No OpenSSL code is involved.
  - From BearSSL v0.6 (MIT), unmodified: the GCM mode (`src/aead/gcm.c`) with the constant-time
    `src/hash/ghash_ctmul64.c`, and the constant-time `aes_ct64` for AES-256 (`src/symcipher/aes_ct64.c`,
    `aes_ct64_enc.c`, `aes_ct64_ctr.c`, plus `src/codec/enc32le.c` and `dec32le.c`). libsmb2 has no AES-256 and no
    GHASH. AES-128-GCM uses libsmb2's own `AES128_ECB_encrypt()`.
  - Every BearSSL symbol gets a `swiftsmb_` prefix (`swiftsmb_bearssl.h`, included by one wrapper `.c` per BearSSL
    file), so it never collides with another BearSSL in the same process.
  - `swiftsmb_set_gcm_seal()` (`swiftsmb-gcm.h`) installs another GCM implementation that seals a whole message at
    once. SwiftSMB installs CryptoKit's `AES.GCM` on Apple platforms, and BearSSL is then not used.
- **Why:** upstream builds GCM only with OpenSSL, and SwiftSMB does not link OpenSSL. Without GCM, servers restricted
  to GCM, such as AES-256-GCM only, refuse encrypted connections.
- **Files:** in SwiftSMB today: `Sources/libsmb2/patches/smb3-seal.c`, `Sources/libsmb2/patches/smb2-cmd-negotiate.c`
  (wrappers that define `HAVE_OPENSSL` and include upstream's files), `Sources/libsmb2/gcm/` (shim, wrappers, BearSSL
  files, `UPSTREAM.md` with hashes and the update procedure), and `Sources/libsmb2/include/swiftsmb-gcm.h`.
- **Upstream:** none yet.
- **Drop when:** upstream supports GCM without OpenSSL.

### M5. Linux and Android configuration with a strong random source

- **What:** a `config.h` for Linux and Android builds outside CMake and autotools, which defines `HAVE_GETRANDOM`,
  `HAVE_SYS_RANDOM_H` and `HAVE_DEV_URANDOM` on Linux, and only `HAVE_DEV_URANDOM` on Android.
- **Why:** `smb2_random_bytes()` (the NTLMv2 client challenge, the SMB 3.1.1 preauth salt, the client GUID, the nonce
  of every sealed message) falls back to `random()` without them, which is predictable and not thread-safe.
- **Files:** in SwiftSMB today: `Sources/libsmb2/include/linux/config.h`, selected by `Sources/libsmb2/include/config.h`.
- **Upstream:** none needed. Upstream's own build systems detect these.
- **Drop when:** never, while SwiftPM builds this fork without a configure step.

## SwiftPM packaging in SwiftSMB

These are not changes to libsmb2's code, and they stay in SwiftSMB unless the fork becomes a Swift package itself:

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
