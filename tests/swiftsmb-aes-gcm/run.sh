#!/bin/sh
# libsmb2-SwiftSMB (MODS.md M7): build and run aes-gcm-test.c.
#
#   tests/swiftsmb-aes-gcm/run.sh                 # cc, optimised
#   CC=clang tests/swiftsmb-aes-gcm/run.sh
#   SANITIZE=1 tests/swiftsmb-aes-gcm/run.sh      # AddressSanitizer and UBSan
#
# On Linux it runs twice: without the dlopen of the system's OpenSSL (so the
# hardware path is what smb2_aes_gcm() uses), and with it (and -ldl).
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$here/../..
cc=${CC:-cc}
san=
[ -n "$SANITIZE" ] && san="-fsanitize=address,undefined -fno-omit-frame-pointer"

case $(uname -s) in
Darwin)
        cfg=apple
        extra="$root/lib/aes.c $root/lib/aes_reference.c $root/lib/aes_apple.c"
        ;;
*)
        cfg=linux
        extra=
        ;;
esac

build() { # $1 output, remaining: extra flags
        out=$1
        shift
        # shellcheck disable=SC2086
        "$cc" -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare $san \
                "-D_U_=__attribute__((unused))" -DHAVE_CONFIG_H=1 -DHAVE_BUILTIN_AES_GCM=1 "$@" \
                -I"$root/include/$cfg" -I"$root/include/smb2" -I"$root/lib" \
                -I"$root/lib/bearssl/upstream/inc" -I"$root/lib/bearssl/upstream/src" \
                "$here/aes-gcm-test.c" "$root/lib/aes-gcm-armv8.c" "$root/lib/aes-gcm-dlopen.c" \
                "$root"/lib/bearssl/bearssl_*.c $extra -lpthread -o "$out"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "== $cc, hardware path (no dlopen of OpenSSL)"
build "$tmp/test"
"$tmp/test"

if [ "$cfg" = linux ]; then
        echo
        echo "== $cc, with the dlopen of the system's OpenSSL"
        build "$tmp/test_dl" -DSMB2_GCM_DLOPEN_OPENSSL=1 -ldl
        "$tmp/test_dl"
fi
