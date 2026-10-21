#!/usr/bin/env bash
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
set -euo pipefail
export LC_ALL=C
: "${OPENSSL_VERSION:?run inside nix develop}"
: "${OPENSSL_LIB_DIR:?run inside nix develop}"
: "${CURL_LIB_DIR:?run inside nix develop}"
root=$(pwd)
spike=packages/cyberkrill/.lake/build/bin/linkspike
app=packages/cyberkrill/.lake/build/bin/cyberkrill
evidence=packages/http-curl/.lake/build/link-checks
mkdir -p "$evidence"
check="$root/scripts/check-one-openssl.sh"
lean_prefix=$(lean --print-prefix)

(cd packages/cyberkrill && lake build -v linkspike)
echo 'Lake linkspike response file (cc wrapper prepends nix OpenSSL -L):'
cat packages/cyberkrill/.lake/build/bin/linkspike.rsp
echo 'Packaged cc wrapper:'
cat "$lean_prefix/bin/cc"
"$spike" >"$evidence/spike.stdout" 2>"$evidence/spike.stderr"
cat "$evidence/spike.stdout" "$evidence/spike.stderr"
grep -F "OpenSSL/$OPENSSL_VERSION" "$evidence/spike.stdout"
grep -F 'secp256k1 context round trip: true' "$evidence/spike.stdout"
bash "$check" "$spike"
bash "$check" "$app"
readelf -d "$app"

# Lake uses getLeanCc + mkLeanLinkArgs for this target, as for lean_exe.
(cd packages/http-curl && lake build -v opensslTwin)
twin=packages/http-curl/.lake/build/bin/openssl-twin
"$twin" >"$evidence/twin.stdout" 2>"$evidence/twin.stderr"
cat "$evidence/twin.stdout" "$evidence/twin.stderr"
bash "$check" "$twin"
grep -F "OpenSSL $OPENSSL_VERSION" "$evidence/twin.stdout"
ldd "$twin" >"$evidence/twin.ldd"
ldd "$CURL_LIB_DIR/libcurl.so" >"$evidence/curl.ldd"
for lib in libssl.so.3 libcrypto.so.3; do
    grep -F "$OPENSSL_LIB_DIR/$lib" "$evidence/twin.ldd"
    grep -F "$OPENSSL_LIB_DIR/$lib" "$evidence/curl.ldd"
done

# Also exercise leanc, which Lake's executable linker does not invoke.
leanc packages/http-curl/test/openssl_fixture.c -L"$CURL_LIB_DIR" -lcurl \
    -o "$evidence/leanc-twin"
"$evidence/leanc-twin" >"$evidence/leanc.stdout" 2>"$evidence/leanc.stderr"
cat "$evidence/leanc.stdout" "$evidence/leanc.stderr"
grep -F "OpenSSL $OPENSSL_VERSION" "$evidence/leanc.stdout"
bash "$check" "$evidence/leanc-twin"

# A direct archive path deliberately bypasses the shared-provider precedence.
leanc packages/http-curl/test/openssl_fixture.c -L"$CURL_LIB_DIR" -lcurl \
    "$lean_prefix/lib/libcrypto.a" -o "$evidence/openssl-red"
set +e
bash "$check" "$evidence/openssl-red" >"$evidence/red.stdout" 2>"$evidence/red.stderr"
rc=$?
set -e
cat "$evidence/red.stdout" "$evidence/red.stderr"
echo "forced-static checker EXIT=$rc (expected 1)"
[[ $rc == 1 ]]
grep -E '^\((b|c)\)' "$evidence/red.stderr"

# Invocation failures must not satisfy the negative fixture assertion.
for bad in missing-argument missing-file non-ELF ldd-failure; do
    args=()
    case $bad in
        missing-file) args=("$evidence/does-not-exist");;
        non-ELF) args=(packages/http-curl/test/openssl_fixture.c);;
        ldd-failure) args=(packages/http-curl/.lake/build/c/openssl_fixture.o);;
    esac
    set +e
    bash "$check" "${args[@]}" >"$evidence/usage.stdout" 2>"$evidence/usage.stderr"
    rc=$?
    set -e
    cat "$evidence/usage.stdout" "$evidence/usage.stderr"
    echo "$bad EXIT=$rc (expected 2)"
    [[ $rc == 2 ]]
done
echo 'link spike, Lake/leanc green twins, forced-static red fixture: PASS'
