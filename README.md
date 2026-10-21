# lean-cyberkrill

Bitcoin, Lightning and Fedimint libraries for Lean 4, and a Lean port of the
[cyberkrill](https://github.com/douglaz/cyberkrill) command-line tool built on them.

Status: Phase 1a and both parts of Phase 1b complete: secp256k1 bindings, a bounded
HTTP(S) client with per-request CA selection, and a reusable HTTP/TLS recording stub.
Other packages remain skeletons; `plan.md` is the plan for v1.

## Packages

| Directory | Lake package | Root module | Contents (v1) |
|---|---|---|---|
| `packages/sha256` | `sha256` | `Sha256` | SHA-256 and SHA-256d |
| `packages/secp256k1` | `secp256k1` | `Secp256k1` | libsecp256k1 bindings (FFI) |
| `packages/bitcoin` | `bitcoin` | `Bitcoin` | Bitcoin encodings, transactions, PSBT, BIP39 |
| `packages/lightning` | `lightning` | `Lightning` | BOLT11 and LNURL |
| `packages/fedimint-invite` | `fedimint-invite` | `FedimintInvite` | Fedimint invite codes |
| `packages/http-curl` | `http-curl` | `HttpCurl` | HTTP(S) client over libcurl (FFI) |
| `packages/cyberkrill` | `cyberkrill` | `Cyberkrill`, `Main` | the CLI |

Dependencies: `bitcoin` needs `sha256`; `lightning` and `fedimint-invite` need `bitcoin`; the app needs
all six. Pure packages never import an FFI package.

## Building

The flake packages the official Lean v4.35.0 release for `x86_64-linux`.

```bash
nix develop -c lean --version                # Lean (version 4.35.0, ...)
cd packages/bitcoin && nix develop -c lake build && nix develop -c lake test
nix flake check                              # lake build + lake test for every package, in the sandbox
nix build && ./result/bin/cyberkrill
```

`nix/musl/` holds the recipe for building the toolchain against musl, for the static v1 release.

## Phase 1a: FFI link spike (1 of 2)

`secp256k1` now supplies a context create/destroy smoke check, and `http-curl` supplies
`curl_version()` as a Lean string. Both use custom Lake targets: `moreLinkObjs` carries
the C object and `moreLinkLibs` carries the nix shared library into importing executables.
Neither FFI package has a Lean dependency. Cryptographic bindings and vectors are
documented in Phase 1a (2 of 2) below; HTTP requests remain Phase 1b.

`nix develop` and the sandbox supply headers through nix's compiler flags and library
paths through `SECP256K1_LIB_DIR` and `CURL_LIB_DIR`. Missing paths produce an explicit
Lake build error. No root-package link flags substitute for these targets.
The spike only queries versions and creates a context; no test opens a connection.

### Dependency versions and OpenSSL direction

Measured on 2026-10-21 from `flake.lock` and this command (exit 0):

```bash
nix eval --json --impure --expr '
  let f = builtins.getFlake (toString ./.);
      p = f.inputs.nixpkgs.legacyPackages.x86_64-linux;
  in { secp = p.secp256k1.version; flags = p.secp256k1.configureFlags;
       curl = p.curl.version; ssl = p.openssl.version;
       sslPath = toString p.openssl.out; curlPath = toString p.curl.out; }'
```

| Dependency | Measured value |
|---|---|
| nixpkgs revision | `fe13242281a67641c0102cdb1087f0ebe586c7df` |
| libsecp256k1 | 0.8.0; configure flags `--enable-benchmark=no --enable-module-recovery` |
| curl | 8.22.0, OpenSSL backend |
| curl's OpenSSL | 3.5.8; `/nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8` |
| toolchain's static OpenSSL | 3.6.0 |
| Lean | 4.35.0, commit `eb6cafb7290e8bd5f2937522d8d804f58f02bafc` |
| compiler / linker / symbol scan / loader | GCC 16.2.0 / GNU ld 2.46 / GNU nm 2.46 / glibc ldd 2.44 |

`nix develop -c lean --version` and
`nix develop -c bash -c 'cc --version; ld --version; nm --version; ldd --version'`
reported those tool versions (exit 0). The archive measurement was
`nix develop -c bash -c 'grep -aoE "OpenSSL [0-9]+\.[0-9]+\.[0-9]+" "$(lean --print-prefix)/lib/libcrypto.a"'`:
`OpenSSL 3.6.0`, exit 0. Both `lib/libssl.a` and `lib/libcrypto.a` still exist in
`nix build --no-link --print-out-paths .#lean`'s output (checked with `test -f`, exit 0).

The direction is **the reverse (B): Lean's `-lssl -lcrypto` resolve to nix's shared
OpenSSL 3.5.8, the same library curl links; the toolchain's static 3.6.0 archives stay
in the toolchain but behind it in search order**. The packaged `cc` prepends the nix
OpenSSL `-L` before all caller arguments and appends the toolchain `-L`. Lake uses
this compiler directly. The `leanc` wrapper also prepends nix OpenSSL and defaults
to that same `cc` wrapper. This settles the dynamic glibc build; Phase 10a must
settle the musl static release separately.

### Evidence from the actual Lake artifacts

The following is historical Phase 1a (1 of 2) evidence from its sandboxed `nix flake check -L` run
(exit 0, derivation `/nix/store/402f697b06bwpr5vvdavcbqxrrvajp5x-cyberkrill-0.1.0.drv`),
captured on the Phase 1a (1 of 2) tree, commit `68ac5c2`; later phases change the check
derivation. `nix log` on that derivation replays it. Store paths can differ between sandbox
and host builds. The same checks also ran under `nix develop` (exit 0).
The check script captures fixture stdout and stderr separately before replaying
them; its host captures are under `packages/http-curl/.lake/build/link-checks/`.

Lake's verbose executable command was:

```text
/nix/store/nwpn6b4amk1z8i5b3cg0m4l29f72jbp2-lean4-bin-4.35.0/bin/cc -o /build/source/packages/cyberkrill/.lake/build/bin/linkspike @/build/source/packages/cyberkrill/.lake/build/bin/linkspike.rsp
```

The check prints both the response file and the wrapper. The response file's
library search arguments, in order, are:

```text
"-L/nix/store/jz20qgm8m5ni2nkl8snqj6hjsr8fdbqx-secp256k1-0.8.0/lib"
"-lsecp256k1"
"-L/nix/store/36alc2mwna4nzf6djdj2hvh4w4r3cai5-curl-8.22.0/lib"
"-lcurl"
"-L"
"/nix/store/nwpn6b4amk1z8i5b3cg0m4l29f72jbp2-lean4-bin-4.35.0/lib/lean"
```

Its later runtime flags include `-Wl,--as-needed -lgmp -luv -lssl -lcrypto`.
The wrapper expands that real Lake invocation as follows, placing OpenSSL before
the response file and every toolchain search directory:

```bash
exec /nix/store/j1938gsbvbhkyz4kbmvjk56r479mkw3s-gcc-wrapper-16.2.0/bin/cc -L/nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib "$@" -L/nix/store/nwpn6b4amk1z8i5b3cg0m4l29f72jbp2-lean4-bin-4.35.0/lib
```

The Lake-built spike ran with exit 0:

```text
libcurl/8.22.0 OpenSSL/3.5.8 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.70.0 ngtcp2/1.23.0 nghttp3/1.17.0 mit-krb5/1.22.2
secp256k1 context round trip: true
```

`bash scripts/check-one-openssl.sh packages/cyberkrill/.lake/build/bin/linkspike`
reported the following (exit 0). Counts come from both `nm --defined-only` and
`nm -D --defined-only`, matching `/ [TtDdRrBb] (SSL_|OPENSSL_|EVP_|CRYPTO_)/`.
The version scan is `grep -aoE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+'` over the
executable and every file resolved by `ldd`, deduplicated per file and globally.
The executable itself had no matching version string.

<details>
<summary>Full ldd closure, symbol counts and version strings</summary>

```text
OpenSSL audit: packages/cyberkrill/.lake/build/bin/linkspike
    linux-vdso.so.1 (0x00007ffff7fbe000)
    libsecp256k1.so.7 => /nix/store/jz20qgm8m5ni2nkl8snqj6hjsr8fdbqx-secp256k1-0.8.0/lib/libsecp256k1.so.7 (0x00007ffff7aa2000)
    libcurl.so.4 => /nix/store/36alc2mwna4nzf6djdj2hvh4w4r3cai5-curl-8.22.0/lib/libcurl.so.4 (0x00007ffff797d000)
    libm.so.6 => /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib/libm.so.6 (0x00007ffff785c000)
    libdl.so.2 => /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib/libdl.so.2 (0x00007ffff7fb1000)
    libgcc_s.so.1 => /nix/store/nwpn6b4amk1z8i5b3cg0m4l29f72jbp2-lean4-bin-4.35.0/lib/libgcc_s.so.1 (0x00007ffff7600000)
    libpthread.so.0 => /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib/libpthread.so.0 (0x00007ffff7fac000)
    libc.so.6 => /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib/libc.so.6 (0x00007ffff7200000)
    /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib/ld-linux-x86-64.so.2 => /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc0000)
    libnghttp3.so.9 => /nix/store/r9n1wja9zhj3w4r71pggxal3c6xqak2a-nghttp3-1.17.0/lib/libnghttp3.so.9 (0x00007ffff7f78000)
    libngtcp2_crypto_ossl.so.0 => /nix/store/8vq8ivlhfqkbhs7r9mmirsdp8gh8hmrm-ngtcp2-1.23.0/lib/libngtcp2_crypto_ossl.so.0 (0x00007ffff7f69000)
    libngtcp2.so.16 => /nix/store/8vq8ivlhfqkbhs7r9mmirsdp8gh8hmrm-ngtcp2-1.23.0/lib/libngtcp2.so.16 (0x00007ffff7f04000)
    libnghttp2.so.14 => /nix/store/sky8mslz50n51np0z4vhdq61jba12fh2-nghttp2-1.70.0-lib/lib/libnghttp2.so.14 (0x00007ffff7ed2000)
    libidn2.so.0 => /nix/store/q0lbdx5yv93a3md74kjhm0v2kljjii89-libidn2-2.3.8/lib/libidn2.so.0 (0x00007ffff782a000)
    libssh2.so.1 => /nix/store/6vqggv3cdqkh098nm8brbs2mwhn6bciy-libssh2-1.11.1/lib/libssh2.so.1 (0x00007ffff75b4000)
    libpsl.so.5 => /nix/store/lhk23vackrdgmxya733h3wp01xz622gn-libpsl-0.21.5/lib/libpsl.so.5 (0x00007ffff759e000)
    libssl.so.3 => /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libssl.so.3 (0x00007ffff747a000)
    libcrypto.so.3 => /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libcrypto.so.3 (0x00007ffff6a00000)
    libgssapi_krb5.so.2 => /nix/store/80z9njiswl9xm6qk93zsjr5bj8v0z2lm-krb5-1.22.2-lib/lib/libgssapi_krb5.so.2 (0x00007ffff741f000)
    libzstd.so.1 => /nix/store/ph4ib8mxy5yrw40k7a1l03bfd58hq6wj-zstd-1.5.7/lib/libzstd.so.1 (0x00007ffff7129000)
    libbrotlidec.so.1 => /nix/store/7fjvn38n3dnv092jbmb4m87ik5qvmj7g-brotli-1.2.0-lib/lib/libbrotlidec.so.1 (0x00007ffff781a000)
    libbrotlicommon.so.1 => /nix/store/7fjvn38n3dnv092jbmb4m87ik5qvmj7g-brotli-1.2.0-lib/lib/libbrotlicommon.so.1 (0x00007ffff7106000)
    libunistring.so.5 => /nix/store/jp8ql2fnd61xhvb4vsfp0bqwrzf16qrp-libunistring-1.4.2/lib/libunistring.so.5 (0x00007ffff6812000)
    libz.so.1 => /nix/store/wgw25d181h0qks7qsfp1bh7c5nd3f0s7-zlib-1.3.2/lib/libz.so.1 (0x00007ffff70e7000)
    libkrb5.so.3 => /nix/store/80z9njiswl9xm6qk93zsjr5bj8v0z2lm-krb5-1.22.2-lib/lib/libkrb5.so.3 (0x00007ffff6731000)
    libk5crypto.so.3 => /nix/store/80z9njiswl9xm6qk93zsjr5bj8v0z2lm-krb5-1.22.2-lib/lib/libk5crypto.so.3 (0x00007ffff70b7000)
    libcom_err.so.3 => /nix/store/80z9njiswl9xm6qk93zsjr5bj8v0z2lm-krb5-1.22.2-lib/lib/libcom_err.so.3 (0x00007ffff7ec6000)
    libkrb5support.so.0 => /nix/store/80z9njiswl9xm6qk93zsjr5bj8v0z2lm-krb5-1.22.2-lib/lib/libkrb5support.so.0 (0x00007ffff70a8000)
    libkeyutils.so.1 => /nix/store/gqd8w84mhr0h24fnc2p4m3hkicsnxsfm-keyutils-1.6.3-lib/lib/libkeyutils.so.1 (0x00007ffff70a1000)
    libresolv.so.2 => /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib/libresolv.so.2 (0x00007ffff671e000)
defined OpenSSL symbols (static): 0
defined OpenSSL symbols (dynamic): 0
version strings in /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libcrypto.so.3:
OpenSSL 3.5.8
one-OpenSSL checks (a), (b), (c): PASS
```

</details>

`libngtcp2_crypto_ossl.so.0` and `libk5crypto.so.3` are present but are not counted
as providers: the checker matches only basenames `libssl.so*` and `libcrypto.so*`.
The app's checker also exited 0 with zero static and dynamic defined OpenSSL
symbols, and only the same `OpenSSL 3.5.8` string in its closure.

`readelf -d packages/cyberkrill/.lake/build/bin/cyberkrill` exited 0. Its complete
NEEDED and RUNPATH entries before installation/fixup were:

```text
 0x0000000000000001 (NEEDED)             Shared library: [libsecp256k1.so.7]
 0x0000000000000001 (NEEDED)             Shared library: [libcurl.so.4]
 0x0000000000000001 (NEEDED)             Shared library: [libm.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [libdl.so.2]
 0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libpthread.so.0]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
 0x000000000000001d (RUNPATH)            Library runpath: [/nix/store/35jf3cmph45bryi1arjnsybgq0xq52k4-cyberkrill-0.1.0/lib:/nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib:/nix/store/jz20qgm8m5ni2nkl8snqj6hjsr8fdbqx-secp256k1-0.8.0/lib:/nix/store/36alc2mwna4nzf6djdj2hvh4w4r3cai5-curl-8.22.0/lib:/nix/store/nwpn6b4amk1z8i5b3cg0m4l29f72jbp2-lean4-bin-4.35.0/lib:/nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/lib:/nix/store/j7qx4s4mr17j1wqgvqdzj33lmrnzb387-gcc-16.2.0-lib/lib]
```

### Positive and negative checks

`lake build -v opensslTwin` in `packages/http-curl` uses Lake's `buildLeanExe`,
the same compiler and link-argument builder as `lean_exe linkspike`. Its C main
calls `OpenSSL_version(0)` and `curl_version()`; the ordinary runtime
`-lssl -lcrypto` must select the shared provider even with that reference.
The check also builds the same source through `leanc`, showing that its default
compiler chain selects shared nix OpenSSL. Because `leanc` defaults `LEAN_CC` to
the `cc` wrapper, which independently prepends the OpenSSL `-L`, this twin cannot
detect removal of `leanc`'s own `-L` alone.
Both builds, executions and checker invocations exited 0:

```text
OpenSSL 3.5.8 25 Aug 2026
libcurl/8.22.0 OpenSSL/3.5.8 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.70.0 ngtcp2/1.23.0 nghttp3/1.17.0 mit-krb5/1.22.2
defined OpenSSL symbols (static): 0
defined OpenSSL symbols (dynamic): 0
one-OpenSSL checks (a), (b), (c): PASS
```

The script compares `ldd` of the Lake twin and `$CURL_LIB_DIR/libcurl.so`:
both resolve `libssl.so.3` and `libcrypto.so.3` under
`/nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib`
(all four path assertions exited 0).

For the red fixture the script runs (from the same sandbox environment):

```bash
lean_prefix=$(lean --print-prefix)
leanc packages/http-curl/test/openssl_fixture.c -L"$CURL_LIB_DIR" -lcurl \
    "$lean_prefix/lib/libcrypto.a" -o packages/http-curl/.lake/build/link-checks/openssl-red
bash scripts/check-one-openssl.sh packages/http-curl/.lake/build/link-checks/openssl-red \
    >packages/http-curl/.lake/build/link-checks/red.stdout \
    2>packages/http-curl/.lake/build/link-checks/red.stderr
```

The build exited 0; the checker exited **1**, with 1,110 static and 1,081 dynamic
defined OpenSSL symbols. Captured stderr was:

```text
(b) packages/http-curl/.lake/build/link-checks/openssl-red defines OpenSSL symbols (static) alongside /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libssl.so.3
000000000022a480 T CRYPTO_128_unwrap
000000000022a650 T CRYPTO_128_unwrap_pad
000000000022a310 T CRYPTO_128_wrap
000000000022a510 T CRYPTO_128_wrap_pad
00000000000d6d50 T CRYPTO_THREAD_cleanup_local
00000000000d6d80 T CRYPTO_THREAD_compare_id
00000000000d6d70 T CRYPTO_THREAD_get_current_id
00000000000d6d20 T CRYPTO_THREAD_get_local
(b) packages/http-curl/.lake/build/link-checks/openssl-red defines OpenSSL symbols (dynamic) alongside /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libssl.so.3
000000000022a480 T CRYPTO_128_unwrap
000000000022a650 T CRYPTO_128_unwrap_pad
000000000022a310 T CRYPTO_128_wrap
000000000022a510 T CRYPTO_128_wrap_pad
00000000000d6d50 T CRYPTO_THREAD_cleanup_local
00000000000d6d80 T CRYPTO_THREAD_compare_id
00000000000d6d70 T CRYPTO_THREAD_get_current_id
00000000000d6d20 T CRYPTO_THREAD_get_local
(c) conflicting OpenSSL versions across packages/http-curl/.lake/build/link-checks/openssl-red and its closure:
OpenSSL 3.5.8
OpenSSL 3.6.0
```

This is an intentional rejection, required for the overall gate to pass.
Missing argument, missing file, non-ELF and ldd-failure invocations instead exited **2** with
`usage error:` diagnostics, so they cannot satisfy the fixture assertion.
The final sandbox log records these exits:

```text
forced-static checker EXIT=1 (expected 1)
missing-argument EXIT=2 (expected 2)
missing-file EXIT=2 (expected 2)
non-ELF EXIT=2 (expected 2)
ldd-failure EXIT=2 (expected 2)
```

The positive check was also seen red: temporarily remove
`-L${pkgs.openssl.out}/lib` from both `cc` and `leanc` in `flake.nix`, then run
`nix flake check -L`. It exited **1** in the Lake green twin's checker, naming
both (b) and (c), with the same 1,110/1,081 counts and 3.5.8/3.6.0 conflict.
The twin's run output was:

```text
OpenSSL 3.6.0 1 Oct 2025
libcurl/8.22.0 OpenSSL/3.6.0 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.70.0 ngtcp2/1.23.0 nghttp3/1.17.0 mit-krb5/1.22.2
```

That failing build is recorded by
`nix log /nix/store/0qigz2d8z9zkhl3nhv9295w4j4sqh2wf-cyberkrill-0.1.0.drv`.
After restoring both precedence flags, `nix flake check -L` exited **0**.
Only search precedence changed in that mutation; the fixture and expectations
stayed unchanged.

### Re-running the checks

From the repository root:

```bash
nix flake check -L
nix build && ./result/bin/cyberkrill
for p in secp256k1 http-curl cyberkrill; do
  (cd "packages/$p" && nix develop -c lake build && nix develop -c lake test)
done
(cd packages/cyberkrill && nix develop -c lake build linkspike && .lake/build/bin/linkspike)
nix develop -c bash scripts/check-one-openssl.sh packages/cyberkrill/.lake/build/bin/linkspike
nix develop -c bash scripts/check-link-spike.sh
```

All commands above exited 0 on 2026-10-21. The installed app printed
`cyberkrill 0.1.0`. The proof-placeholder scan
`grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages`
printed nothing and exited 1 (the expected no-match status).

### Deltas not taken

None. HTTP network tests and the musl release remain in their
existing later tasks.

## Phase 1a: secp256k1 bindings (2 of 2)

`Secp256k1` exposes these pure functions; inputs are borrowed (`@& ByteArray`),
never mutated, and successful object results are freshly allocated:

```lean
isValidPubkey (key : @& ByteArray) : Bool
verify (hash signature key : @& ByteArray) : Bool
recover (hash signature : @& ByteArray) (recid : UInt8) : Option ByteArray
sign (hash secretKey : @& ByteArray) : Option ByteArray
```

The functions are deterministic and thread-safe, so a verified Lean implementation
can replace them with the same types. Parse, verify and recover use the immutable
static context. Signing creates and destroys a context per call and uses the
default RFC 6979 nonce function without extra entropy. Signing is used only with
published test vectors in v1. `contextRoundTrip : IO Bool` is unchanged.

| Function | Bytes and returned errors |
|---|---|
| `isValidPubkey` | 33-byte compressed SEC1 (02/03) or 65-byte uncompressed (04). False for wrong lengths, invalid prefixes, invalid coordinates or off-curve points. |
| `verify` | 32-byte hash, 64-byte compact signature (big-endian r ‖ s), SEC1 key as above. False for any malformed input, r or s ≥ the curve order, zero scalars, high-S, or failure to verify. No normalisation. |
| `recover` | Same hash and compact signature; recid 0–3. Returns a 33-byte compressed SEC1 key, or none for wrong lengths, recid > 3, invalid scalars, or recovery failure. Preserves high-S. |
| `sign` | 32-byte hash and 32-byte secret key. Returns 65 bytes: compact r ‖ s (always low-S), then recid 0–3. None for wrong lengths, secret zero or ≥ the curve order, context failure or signing failure. |

Parse and verify both reject hybrid (06/07) keys, including matching parity;
tests cover both matching and mismatched parity. This matches rust-bitcoin
0.32.8's `PublicKey::from_slice` and `from_str`, which cyberkrill uses for PSBT
`partial_sigs` keys and descriptors. libsecp256k1's own parse, and so
`secp256k1::PublicKey::from_slice`, accepts a hybrid key whose prefix matches
the y parity; cyberkrill reaches it for PSBT `bip32_derivation` keys and for
`ln-encode-invoice`'s JSON keys. Owner decision (2026-10-21, bead
`lck-decide-hybrid-pubkey-xgr`): both paths follow it, through a second
function, `compressPubkey`, that Phase 4a (1 of 3) adds. The `bitcoin`
PSBT codec keeps 04 and hybrid bip32 keys as the bytes it read, where
rust-bitcoin rewrites them to 33-byte compressed, and the app rejects two
encodings of one point in one bip32 map, as cyberkrill does.
All buffer lengths and the
recovery-id range are guarded before libsecp256k1 sees the corresponding input.
The package keeps `"packages": []` in its Lake manifest and uses the existing
`moreLinkObjs` / `moreLinkLibs` targets.

### Vectors and generation

The 16 BOLT #11 examples come from
[`11-payment-encoding.md` at lightning/bolts @ `1914628`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/11-payment-encoding.md),
CC-BY-4.0. The contributors' attribution, exact commit, source path, and
“extracted and reformatted” note are in
`packages/secp256k1/bolt11.json.provenance`. The JSON contains heading lines,
precomputed SHA-256 signing digests, compact signatures and recovery ids.

Generation from the repository root (exit **0**, pinned nixpkgs Python 3.14.7):

```bash
nix shell --inputs-from . nixpkgs#python3 -c python3 -I packages/secp256k1/generate-bolt11.py
```

Generation is the only BOLT fixture step that fetches the spec; tests read local
data. The generator lowercases the invoice, removes the checksum and 104 signature
words, packs the remaining five-bit words MSB-first with zero padding, and hashes
the hrp bytes followed by those bytes.

Before adding the full vector assertions, `(cd packages/secp256k1 && nix develop
-c lake build && nix develop -c lake test)` exited **0**: L382's RFC 6979 signature
matched the published compact signature and recid byte-for-byte. The preliminary
L762 recovery through this binding returned
`02d0139ce7427d6dfffd26a326c18be754ef1e64672b42694ba5b23ef6e6e7803d`.
That key is pinned for Phase 5 (1 of 3)'s lookup table. The other 15 examples
recover the published payee `03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad`.
All 15 low-S signing results match the spec byte-for-byte. L762 signs as
(r, n − s_spec), with recid 1, and recovers the published payee. Every signing
result also passes recover and verify checks. No RFC 6979 fallback was needed.

Wycheproof's Apache-2.0-only
`testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json` is read from the non-flake
input pinned at `C2SP/wycheproof` @ `7a325932231bd7a724c791c8b0d65ea4d6d2f435`.
Neither its data nor derived data is committed. A nix `runCommand` uses Python's
`hashlib.sha256` on each message and writes `tcId digest` lines in the store.
`WYCHEPROOF_JSON` and `WYCHEPROOF_DIGESTS` expose both paths in the sandbox and
dev shell; missing variables or files fail the tests. `flake.lock` adds only
this input and its root reference; the nixpkgs node and narHash are unchanged.

### Final validation

On 2026-10-21, `nix flake check -L` rebuilt and exited **0**, using Lean 4.35.0
and libsecp256k1 0.8.0. The final check derivation is
`/nix/store/3v4n9j4qrf2c1k0kb3qh0zjnfdvvw6rr-cyberkrill-0.1.0.drv`.
It supersedes the historical Phase 1a (1 of 2) derivation cited above; later
phases change the derivation again. Replay its evidence with:

```bash
nix log /nix/store/3v4n9j4qrf2c1k0kb3qh0zjnfdvvw6rr-cyberkrill-0.1.0.drv
```

The final log records:

```text
bolt11 recovery: 16/16
bolt11 signing: 16/16
Wycheproof: 252 loaded / 95 accepted / 157 rejected
Wycheproof: 108 groups / 167 valid / 85 invalid / 72 valid high-S / 18 invalid non-64-byte
negative tests: PASS
secp256k1 context round trip: true
forced-static checker EXIT=1 (expected 1)
link spike, Lake/leanc green twins, forced-static red fixture: PASS
```

Every Wycheproof outcome is asserted individually. Its 72 high-S entries labelled
“valid” count as expected rejects: libsecp256k1 verify requires low-S and the
binding does not normalise. The other 85 rejects are labelled invalid, including
18 signatures of a length other than 64 bytes. Every group's key is 65 bytes,
its hash is SHA-256, and its type is `EcdsaP1363Verify`. Counts and unique test
and digest ids are checked, so missing data cannot silently pass.

The unchanged OpenSSL checker passed on `linkspike`, `cyberkrill`, the Lake twin
and the leanc twin: zero static and dynamic defined OpenSSL symbols in each,
with one shared libssl and libcrypto at 3.5.8. The forced-static fixture still
reported 1,110 static and 1,081 dynamic symbols, both 3.5.8 and 3.6.0 version
strings, and exit 1. All four usage-error checks exited 2.

These commands also exited **0**, with the host test printing the same counts:

```bash
nix build
./result/bin/cyberkrill
(cd packages/secp256k1 && nix develop -c lake build && nix develop -c lake test)
(cd packages/cyberkrill && nix develop -c lake build)
```

The app printed `cyberkrill 0.1.0`. The regenerated
`packages/secp256k1/.lake/build/ir/Secp256k1.c` declares the same five `lck_`
functions as the shim: zero, one, three, three and two runtime arguments
respectively, with recid as `uint8_t`, Bool as `uint8_t`, and arrays/results as
object pointers. None has a world argument. In `packages/secp256k1`, this also
compiled the generated declarations together with the definitions (exit **0**):

```bash
nix develop -c bash -c 'cc -fsyntax-only -I "$(lean --print-prefix)/include" -include .lake/build/ir/Secp256k1.c link_shim.c'
```

`grep -rn sorry --include='*.lean' packages` printed nothing and exited **1**
(expected no-match). There are no theorems in this phase. A tracked-file scan
found no Wycheproof files, and the BOLT example private key only in the test module.

### Negative-test red runs

From `packages/secp256k1`, `nix develop -c python3 -I check-negative-mutations.py`
exited **0**, detecting **42/42** separate production mutations (Lean 4.35.0,
libsecp256k1 0.8.0, host Python 3.13.15). Each case ran
`lake test -- --negative '<property>'`. Tests and expected values were unchanged.
The script captures stdout and stderr separately in `.lake/mutation-checks/`
and writes its command, exit and failure records there as `records.json`.

Each parse mutation returned true before parsing; each verify mutation returned
true before verification. Each recover or sign mutation returned some empty
bytes before validation. For recid cases only, the mutation removed `recid > 3`
from the production guard, exposing the actual libsecp256k1 ARG_CHECK and abort.
Each mutation was restored before the next one; the final green check used the
restored adapter. The failure line for each exit-1 row below was exactly
`assertion failed: <property>`. Both exit-134 rows reported
`illegal argument: recid >= 0 && recid <= 3`.

| Property (one command and mutation per row) | Exit |
|---|---|
| tampered signature | 1 |
| wrong-length key parse | 1 |
| wrong-length key verify | 1 |
| off-curve key parse | 1 |
| off-curve key verify | 1 |
| recid 4 | 134 |
| recid 255 | 134 |
| verify hash length 0 | 1 |
| recover hash length 0 | 1 |
| sign hash length 0 | 1 |
| sign secret length 0 | 1 |
| verify hash length 31 | 1 |
| recover hash length 31 | 1 |
| sign hash length 31 | 1 |
| sign secret length 31 | 1 |
| verify hash length 33 | 1 |
| recover hash length 33 | 1 |
| sign hash length 33 | 1 |
| sign secret length 33 | 1 |
| verify signature length 0 | 1 |
| recover signature length 0 | 1 |
| verify signature length 63 | 1 |
| recover signature length 63 | 1 |
| verify signature length 65 | 1 |
| recover signature length 65 | 1 |
| verify r zero | 1 |
| verify s zero | 1 |
| recover r zero | 1 |
| recover s zero | 1 |
| sign secret zero | 1 |
| verify r order | 1 |
| verify s order | 1 |
| recover r order | 1 |
| recover s order | 1 |
| sign secret order | 1 |
| verify r overflow | 1 |
| verify s overflow | 1 |
| recover r overflow | 1 |
| recover s overflow | 1 |
| sign secret overflow | 1 |
| invalid prefix parse | 1 |
| invalid prefix verify | 1 |

Here zero, order and overflow mean 0, n and 2²⁵⁶ − 1. The off-curve key uses
compressed x = 0. The mutation script disables core dumps and restores the C
source even on failure. To re-run it, then rebuild the restored binding:

```bash
(cd packages/secp256k1 && nix develop -c python3 -I check-negative-mutations.py && nix develop -c lake test)
```

### Deltas not taken

None.

## Phase 1b: http-curl (1 of 2)

`HttpCurl.request : Request → IO (Except Error Response)` sends synchronous GET
and POST requests through libcurl 8.22.0. `HttpCurl.version` is unchanged. The
package has no Lean dependencies and retains Lake's `moreLinkObjs`/`moreLinkLibs`
linking. Other packages and the OpenSSL checker are unchanged.

### Interface and contract

| Request field | Type, units and default |
|---|---|
| `method`, `url` | `Method.get` or `.post`; an `http://` or `https://` string |
| `headers` | `Array (String × String)`, default `#[]`; every supplied header is sent |
| `body` | `Option ByteArray`, default `none`; POST sends the bytes, including NULs |
| `basicAuth` | Optional username/password pair; default `none` |
| `maxResponseBytes` | `USize`, inclusive body-byte limit; default 1,048,576 |
| `connectTimeoutMs` | `UInt32` milliseconds, default 5,000; zero uses curl's 300-second connect default |
| `totalTimeoutMs` | `UInt32` milliseconds, default 30,000; zero disables the total timeout |
| `caFallback` | Optional `System.FilePath`, default `none`; tests only |

The connect timeout covers connection establishment, including TLS negotiation;
the total timeout covers the whole transfer, including connection establishment.
A GET with any `some body`, including an empty body, returns an input error.
POST with `none` sends an empty body. Redirects are not followed. Environment
proxies are disabled by `CURLOPT_PROXY = ""`, independently of host settings.

The API sends the caller's headers and does not remove curl's own headers.
An empty value, or one containing only spaces and tabs, is sent with an empty
value using curl's `Name;` form. Other values use `Name: value`; duplicate names
are preserved. Header-name and value validation applies before serialization.

`Response` carries a `UInt32` HTTP status, response headers as lowercase names
and trimmed UTF-8 values (duplicates preserved), and the body as `ByteArray`.
HTTP 4xx/5xx statuses are normal results. A write callback refuses the chunk
that would cross the body limit, without buffering it; exactly the limit is
accepted. Response headers have a separate aggregate 65,536-byte cap.

Errors are returned values. Generic curl failures carry `curl_easy_strerror(code)`
text, which depends only on the code and contains no request data. For curl 8.22.0,
code 52 is exactly `Server returned nothing (no headers, no data)`, pinned by T12.
Other error kinds and wrapper input errors retain fixed messages. No error uses
the request URL, headers, credentials or curl diagnostic buffer. Verbose curl
logging is disabled.

| Error | `CURLcode` mapping |
|---|---|
| `connect code message` | 6 (resolve host), 7 (connect) |
| `timeout code message` | 28 |
| `tls code message` | 35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91, 98 |
| `tooLarge limit` | Body callback limit abort (internal marker 1000), or 63 |
| `curl code message` | Every other curl failure; header-cap abort is 23 |

No CA source produces `tls 77`; curl's peer-verification and bad-file failures
remain `tls 60` and `tls 77`. Invalid input produces `curl 43`. Inputs reject
NULs in C-string fields, non-token header names, CR/LF in header values,
embedded URL credentials, and a colon in the basic-auth username. Invalid
UTF-8 response headers return `curl 8` rather than invoking a partial decoder.
The URL authority ends at the first `/`, `?` or `#` after `://`; only an `@`
inside that authority denotes embedded credentials. Thus a pathless URL such as
`http://127.0.0.1:<port>?q=a@b` is accepted.
Each request owns a fresh easy handle; the wrapper checks
`CURL_VERSION_THREADSAFE` and then calls `curl_global_init` exactly once per
process, under `pthread_once`, before the first request, because
`curl_version_info` is not thread-safe until libcurl is initialized. Every
request sees that one result, so a failed init is not retried. It sets
`CURLOPT_NOSIGNAL`. The successful real requests exercise that check on the
pinned curl build. Global cleanup is not called while other handles may exist.

### CA selection

**CA selection and the missing-source pre-check apply only to HTTPS; plain
HTTP is independent of CA state.** On every HTTPS request the wrapper reads
`SSL_CERT_FILE` anew, choosing in this order:

1. Non-empty `SSL_CERT_FILE`, used as given, including a missing path.
2. The test-only request field `caFallback`, if present.
3. The first existing path in this fixed probe list:
   `/etc/ssl/certs/ca-certificates.crt`,
   `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem`.

Empty `SSL_CERT_FILE` counts as unset. Without a source the request returns
the certificate error before connecting. Every HTTPS transfer explicitly sets
`CURLOPT_CAINFO`; `CURLOPT_CAPATH = ""` also disables compiled-in CA directories.
There is no embedded bundle and no reliance on OpenSSL's default trust paths.
`NIX_SSL_CERT_FILE` has no effect. No environment variable or CLI flag supplies
`caFallback`, so the release binary cannot set this hook.

### Local responder and test driver

The interpreter is nixpkgs Python **3.14.7**, using `http.server` and `ssl` in
`packages/http-curl/test/responder.py`. It binds only literal `127.0.0.1` on
port 0 by default and prints `READY <port> <closed-port>`. A separate bound, non-listening
socket reserves the connection-refused port for the server's lifetime.
`HttpCurlTestSupport.withStub` now waits for the ready line and terminates and
waits for each responder in `finally`, including on assertion failures. The
script also stops on stdin EOF if its launcher is killed. With no recording
files it serves the legacy routes below; with recordings it serves only entries
in those files (see Part 2).

`/echo` echoes body bytes and all request headers as `X-Echo-<lowercase name>`
response headers. Missing headers produce no echo, so an empty value can be
distinguished from an absent header. `/auth` accepts the
synthetic test credentials and returns 401 for others. `/exact` returns 64
bytes and `/one-over` returns 65 bytes. `/empty-reply` accepts the request and
closes the connection without sending headers or data, producing curl code 52.
`/oversize` sends 4,096 bytes without `Content-Length`, then keeps the
connection open for four seconds. `/stall` waits four seconds without answering.
The size test requires the size error within 1,500 ms, against a 3,000 ms total
timeout. The stall test uses a 300 ms total timeout and allows 1,200 ms slack,
also requiring completion within 1,500 ms. Each case additionally runs under
a separate two-second `timeout` deadline, so removing curl's timeout fails
by name instead of hanging the suite.

The `HttpCurlTestSupport` library generates a fresh EC certificate and key in a private
temporary directory, using nix's `openssl`:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=localhost -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
  -keyout "$tmp/server.key" -out "$tmp/ca.crt"
```

The launcher removes those exact files and their directory in `finally`. No key
or certificate is tracked. Missing tools fail the test. All URLs use literal
`127.0.0.1`; no test resolves a hostname or reaches the internet. Each CA case
runs in a fresh child whose environment explicitly sets or removes **both**
`SSL_CERT_FILE` and `NIX_SSL_CERT_FILE`. C9 changes `SSL_CERT_FILE` between two
requests in that child, proving the selection is per request.

Part 1 pins **22** legacy cases, retained in the **35** total in Part 2:

| Case | Acceptance property |
|---|---|
| T1 | GET status, outgoing header and response content type |
| T2 | Binary POST body and both outgoing headers |
| T3 | Correct synthetic basic auth succeeds |
| T4 | Wrong basic auth returns 401 as a normal response |
| T5 | Streaming size abort within 1,500 ms |
| T6 | Exactly 64 bytes succeeds with a limit of 64 |
| T7 | Stalled request times out within 1,500 ms |
| T8 | Closed port returns the connect kind |
| T9 | Error rendering contains neither synthetic username nor password |
| T10 | Empty and whitespace-only headers are present; non-empty control retains its value |
| T11 | Pathless query containing `@` succeeds; embedded userinfo is rejected |
| T12 | Empty reply returns generic curl code 52 and its exact libcurl message |
| T13 | Exactly 65 bytes returns the size error with a limit of 64 |
| C1 | Environment test CA permits TLS |
| C2 | Untrusted certificate fails |
| C3 | NIX_SSL_CERT_FILE does not supply trust |
| C4 | Empty SSL_CERT_FILE proceeds to the test-CA hook and TLS succeeds |
| C5 | Hook permits TLS with both CA environment variables removed |
| C6 | Missing hook path returns the certificate kind |
| C7 | Plain HTTP succeeds without a CA source |
| C8 | Non-empty environment CA takes precedence over the hook |
| C9 | Missing CA fails, then a changed environment CA succeeds in the same child |

### Final validation

On 2026-10-21, after the final changes under `packages/`, `scripts/` and
`flake.nix` were staged, `nix flake check -L` rebuilt and exited **0**.
`nix eval --raw .#checks.x86_64-linux.default.drvPath` (exit **0**) identified
the final check as
`/nix/store/iwz1ka24dwbilyn0b1pp7mxwdrawbsvm-cyberkrill-0.1.0.drv` (after the
one-time `curl_global_init` change; the check before it,
`/nix/store/y7983aprk7dw4pzgmiy3w2jci563y8j3-cyberkrill-0.1.0.drv`, printed
the same lines).
The quoted sandbox lines in this section come from that derivation, replayed
with `nix log` (exit **0**):

```text
T1: PASS
T2: PASS
T3: PASS
T4: PASS
T5: PASS
T6: PASS
T7: PASS
T8: PASS
T9: PASS
T10: PASS
T11: PASS
T12: PASS
T13: PASS
C1: PASS
C2: PASS
C3: PASS
C4: PASS
C5: PASS
C6: PASS
C7: PASS
C8: PASS
C9: PASS
http-curl cases: 22/22
bolt11 recovery: 16/16
bolt11 signing: 16/16
Wycheproof: 252 loaded / 95 accepted / 157 rejected
Wycheproof: 108 groups / 167 valid / 85 invalid / 72 valid high-S / 18 invalid non-64-byte
forced-static checker EXIT=1 (expected 1)
link spike, Lake/leanc green twins, forced-static red fixture: PASS
```

The same log retains every existing link-spike assertion, including both
green twins, the 1,110/1,081-symbol forced-static rejection, and all four
usage errors exiting 2. Its new audit names
`packages/http-curl/.lake/build/bin/HttpCurlTests`, which calls the wrapper:

```text
defined OpenSSL symbols (static): 0
defined OpenSSL symbols (dynamic): 0
version strings in /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libcrypto.so.3:
OpenSSL 3.5.8
one-OpenSSL checks (a), (b), (c): PASS
http-curl wrapper executable: one nix OpenSSL, version and ldd: PASS
```

The audit closure and the separately asserted `ldd` output both contain:

```text
libssl.so.3 => /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libssl.so.3 (0x00007ffff74dc000)
libcrypto.so.3 => /nix/store/cxd8d2vg70c3pa31v2473hphaa1v0j44-openssl-3.5.8/lib/libcrypto.so.3 (0x00007ffff6a00000)
```

The script asserts both paths lie under `$OPENSSL_LIB_DIR` and the set of
version lines is exactly `OpenSSL $OPENSSL_VERSION` (3.5.8).
It builds `HttpCurlTests` before auditing it. After DoD build and ABI checks,
`rm -rf packages/http-curl/.lake/build/bin` followed by
`nix develop -c bash scripts/check-link-spike.sh` from the repository root exited
**0**: the standalone script rebuilt the missing driver and passed its audit.
`nix build` and `./result/bin/cyberkrill` also exited **0**; the app printed
`cyberkrill 0.1.0`. In `packages/http-curl`, `nix develop -c lake build` and
`nix develop -c lake test` exited **0**, with the same 22 case lines and total
on the host. In `packages/cyberkrill`, `nix develop -c lake build` exited **0**.

The regenerated `HttpCurl.c` declares `lck_curl_request` with twelve runtime
arguments: `uint8_t`, three object pointers, `uint8_t`, two object pointers,
`size_t`, two `uint32_t`, `uint8_t`, and an object pointer. All object inputs
are borrowed. `RawResponse` has two object fields (headers/body), followed by
code/status at scalar offsets 0/4; the generated reads match the C constructor.
`lck_curl_version` still has no runtime arguments; the private
`lck_curl_error_message` takes one `uint32_t` and returns a Lean IO string result.
None of the three externs has a world argument. This combined
declaration/definition check exited **0**:

```bash
cd packages/http-curl
nix develop -c bash -c 'cc -fsyntax-only -I "$(lean --print-prefix)/include" -include .lake/build/ir/HttpCurl.c link_shim.c'
```

`grep -rn sorry --include='*.lean' packages` printed nothing and exited **1**
(the expected no-match status). The tracked-file certificate/key extension scan
and unchanged manifest check exited **0**. `git diff --exit-code 309e415 --
flake.lock packages/secp256k1 scripts/check-one-openssl.sh` exited **0** with
no output. After host `lake test`, `pgrep -af '^python3 -I test/responder.py'`
printed nothing and exited **1**. The AGENTS.md supervisor also reported
`EXIT=0` after both the host gates and final sandbox gate, including its
lingering-process checks.

### Production mutation red runs

`check-negative-mutations.py` changes production Lean/C only, one property per
run, then restores both source files in `finally`. The sandbox mode stages
only the adapter and restores its original index bytes afterward. It captures
stdout and stderr separately in `.lake/mutation-checks/`, and records the
commands, exits and failing lines in `host-records.json` and
`sandbox-records.json`. Tests and the responder are unchanged by mutations.

From `packages/http-curl`, the host command
`nix develop -c python3 -I check-negative-mutations.py` exited **0**, detecting
36 production mutations. Each row marked H ran `lake test -- --only CASE` on
the host, with CASE given in the first column. The sandbox command
`nix develop -c python3 -I check-negative-mutations.py --sandbox` exited **0**,
detecting two mutations. Each S row ran `nix flake check -L ../..` in the Nix
sandbox, where no probe path exists. All **38** individual broken-production
commands exited **1**. The last column records the failing line after the
common prefix `assertion failed: `.

| Case / environment | Production mutation | Failing assertion |
|---|---|---|
| T1 / H | Return status 0 | T1 status |
| T1 / H | Omit outgoing headers | T1 request header |
| T1 / H | Drop parsed content type | T1 response header |
| T2 / H | Send an empty POST body | T2 body |
| T2 / H | Drop first outgoing header | T2 headers |
| T2 / H | Drop second outgoing header | T2 headers |
| T3 / H | Omit basic auth | T3 right auth |
| T4 / H | Enable curl FAILONERROR | T4 normal response |
| T4 / H | Return status 0 | T4 status 401 |
| T5 / H | Report limit abort as generic write error | T5 streaming size |
| T5 / H | Remove streaming guard | T5 outer deadline (2s) |
| T5 / H | Delay the size error by 1,700 ms | T5 abort bound |
| T6 / H | Reject equality with the size limit | T6 inclusive limit |
| T6 / H | Zero received bytes | T6 exact body |
| T7 / H | Omit total timeout | T7 outer deadline (2s) |
| T7 / H | Map timeout to generic error | T7 timeout kind |
| T7 / H | Multiply total timeout by six | T7 timeout bound |
| T8 / H | Omit code 7 from connect mapping | T8 connect kind |
| T9 / H | Include username in error value | T9 user redaction |
| T9 / H | Include password in error value | T9 password redaction |
| T10 / H | Use the old `Name: value` form for empty values | T10 empty header present |
| T10 / H | Drop the non-empty control header | T10 full header |
| T10 / H | Use the empty-header form only for a zero-length value | T10 whitespace header present |
| T11 / H | End the authority only at `/` | T11 query at-sign |
| T11 / H | Remove the embedded-credential check | T11 reject userinfo |
| T12 / H | Replace the generic curl code with 23 | T12 curl code 52 |
| T12 / H | Replace libcurl's text with `HTTP transport failure` | T12 curl message |
| T13 / H | Admit `limit + 1` bytes | T13 one byte over limit |
| C1 / H | Replace environment CA with missing path | C1 environment CA |
| C2 / H | Map certificate failure to generic error | C2 untrusted CA |
| C3 / S | Remove missing-source precheck and CA-directory guard | C3 ignore NIX CA |
| C4 / H | Treat an empty SSL_CERT_FILE as set | C4 empty environment CA |
| C5 / H | Ignore fallback hook | C5 fallback hook |
| C6 / H | Map certificate failure to generic error | C6 missing hook |
| C7 / S | Apply CA rules to headerless plain `/echo` requests | C7 plain HTTP without CA |
| C8 / H | Prefer hook over environment CA | C8 environment precedence |
| C9 / H | Cache environment CA on first use | C9 per-request CA |
| C9 / H | Treat bad CA file as success | C9 initial missing CA |

C3 disables both independent guards of the same default-trust property; leaving
the empty CA-directory setting in place was separately observed to keep C3 green.
C7's mutation isolates the plain-HTTP CA property so the earlier transport
cases still execute before C7 fails. Every mutation was restored before the
final green builds. No mutation is part of the production wrapper.

The final mutation summaries (both commands exited **0**) were:

```text
negative mutations: 36/36 detected; production sources restored
negative mutations: 2/2 detected; production sources restored
```

### Re-running

From the repository root (the per-package commands start in the same directory
as the flake's package loop):

```bash
nix flake check -L
nix build && ./result/bin/cyberkrill
(cd packages/http-curl && nix develop -c lake build && nix develop -c lake test)
(cd packages/cyberkrill && nix develop -c lake build)
nix develop -c bash scripts/check-link-spike.sh
nix log /nix/store/iwz1ka24dwbilyn0b1pp7mxwdrawbsvm-cyberkrill-0.1.0.drv
nix eval --raw .#checks.x86_64-linux.default.drvPath
```

To repeat mutation checks, run the two commands above from `packages/http-curl`
with no concurrent reviewers or writers; then run the green checks again.

### Deltas not taken

None. The reusable recording stub is covered in Phase 1b (2 of 2) below.

## Phase 1b: http-curl (2 of 2)

### Replay server and command line

`packages/http-curl/test/responder.py` uses isolated `python3 -I` with the standard
library's `http.server`, `ssl`, `json` and `decimal`. The measured development
tools (`nix develop -c python3 --version`, `nix develop -c openssl version`,
`nix develop -c lean --version`, each exit 0) are Python 3.14.7, OpenSSL 3.5.8,
and Lean 4.35.0. The wrapper, CA logic, C shim and flake are unchanged.

From any `packages/<pkg>` directory:

```bash
python3 -I ../http-curl/test/responder.py --log requests.jsonl \
  --port 0 ../http-curl/test/example.json
# Add --tls --cert <certificate> --key <key> for TLS.
```

Recording files are positional, in precedence order; `--log` is required and
appends to that file. `--port` defaults to 0 (OS-selected free port), or takes a
fixed port. The address is always literal `127.0.0.1`; there is no host option.
The server prints exactly `READY <port> <closed-port>` to stdout after binding
and, for TLS, loading the certificate. A bound, non-listening socket reserves
the second port for the legacy connection-refused cases. Binding an occupied
listening port fails nonzero before READY. `SO_REUSEPORT` is not enabled.

Keep stdin open while using the server. EOF on stdin exits the process directly
with status 0, including when a silent TCP client stalls the TLS handshake in
`accept()`. The Lean launcher supplies a pipe, so a killed launcher also closes
it. On normal callback completion or an exception, the launcher calls Lean's
`IO.Process.Child.kill` if the stub is still running and reaps it exactly once.
In Lean 4.35 that sends SIGKILL, although its docstring says SIGTERM: a child
trapping TERM, killed this way, was observed to exit with status 137.
stderr is inherited, so unmatched diagnostics cannot fill an undrained pipe.
The script's HTTP/1.0 legacy routes exist only when **no recording files** were
passed. Loading even an empty recording disables all legacy fallback, for every
method, including methods outside GET/POST.

### Recording format and matching

The tested synthetic example is [test/example.json](packages/http-curl/test/example.json).
S5, S6 and S7 serve that same file over HTTP, trusted TLS and a runtime-selected
fixed port. A recording is an object with an `entries` array. A minimal entry is:

```json
{"entries":[{"method":"GET","path":"/example?date=synthetic","responses":[
  {"status":200,"headers":{"X-Fixture":"example"},"json":{"quote":0.10}}
]}]}
```

That entry is the first entry of the committed example. Entries have:

| Field | Meaning |
|---|---|
| `method`, `path` | Required HTTP method and exact request target, including query |
| `body` | Optional selector: exactly one of `{"json": value}`, `{"text": "UTF-8"}`, `{"base64": "bytes"}`; omission means empty bytes |
| `rpc` | Alternative to body matching: `{"method":"rpc-name","params":[variant1, variant2]}` |
| `responses` | Required nonempty ordered array of response objects |
| `repeat` | Optional boolean, default false; repeat the final response after exhaustion |
| `authorization` | Optional expected Authorization header value |
| `unauthorized` | Required with `authorization`; a response object with `status: 401` |

Methods and paths are case-sensitive. Paths are compared as received: no
percent-decoding, leading-slash collapse or query sorting. JSON matching sorts
object keys recursively, preserves array order, and compares numbers as exact
`Decimal` values: `0.1`, `0.10` and `1e-1` match. It performs no decimal arithmetic
or normalization, so digits beyond the default 28-digit context remain distinct.
Boolean values carry a separate type tag: `true` differs from `1`, and `false`
from `0`. JSON null and strings also remain distinct from other types.

`text` selectors encode UTF-8 and `base64` selectors decode bytes. If those bytes
are valid JSON, they use the same canonical matching; otherwise they match byte
for byte. Request bodies that are empty or invalid JSON follow that byte rule.
For `rpc`, the HTTP method and path still match exactly; the body must be a JSON
object with the specified `method` and one of the canonical `params` variants.
`id`, `jsonrpc` and other envelope fields are ignored. Each listed variant has
its **own cursor**, sharing the entry's response list. The S2 case exhausts each
variant before trying the next, so the success of a later variant cannot depend
on an earlier one leaving a shared response available. Canonically duplicate
variants resolve to the first variant's cursor.

The first matching entry in file/array order wins, even when exhausted. An auth
mismatch returns that entry's `unauthorized` response without consuming its
cursor. Auth is checked before exhaustion. Otherwise each matched request
consumes one ordered response; exhaustion returns 599 with `error: "exhausted"`,
or repeats the last response under `repeat: true`. An unmatched request returns
599 with `error: "unmatched"`. Recorded 404s remain ordinary recorded responses.

A response object has optional `status` (default 200), optional `headers` (a
name/value object), and either `json` (any JSON value, emitted with exact decimal
values and application/json) or `text` (UTF-8, text/plain; omission means empty).
A recorded `Content-Type` replaces the default, with a case-insensitive header
name comparison. The stub writes Content-Length itself. A recorded
`Content-Length` or `Transfer-Encoding` header, in any letter case and in any
response including `unauthorized`, is rejected at load: the stub exits 1 with a
`framing header` error before printing READY.

Both 599 diagnostics and each request-log line include `method`, `path` and
`body`. Body is the original UTF-8 text, or `{"base64":"..."}` for non-UTF-8
bytes. For example, an unmatched empty GET produces:

```json
{"error":"unmatched","method":"GET","path":"/missing?x=1","body":""}
```

599 diagnostics also go to stderr. The request log is UTF-8 JSONL, one object
per received request, including successes, 401s, unmatched and exhausted requests.
One lock serializes log append/flush, response-cursor allocation and replay
responses. The log is flushed before a response is sent and follows the same
handling order as cursor allocation. It records bodies, so fixtures must follow
the repository's synthetic-data rules; it does not record Authorization headers.

### Lean launcher

`lean_lib HttpCurlTestSupport` exports:

```lean
withStub (config : Config) (action : Stub → IO α) : IO α
Stub.url (stub : Stub) : String
Stub.readLog (stub : Stub) : IO String
```

`Config` has `tls : Bool := false`, `port : UInt16 := 0`,
`recordings : Array String := #[]`, and `logPath : Option FilePath := none`.
`Stub` exposes `port`, `closedPort`, `caCert`, `logPath`, `tempDir` and `tls`.
The CA path exists for TLS callbacks. TLS generates an EC key and one-day
self-signed certificate in a private temporary directory with
`subjectAltName=IP:127.0.0.1,DNS:localhost`. Set `SSL_CERT_FILE` to `stub.caCert`
before making trusted HTTPS requests. Environment setup belongs to the caller;
the launcher does not change it.

The launcher locates `../http-curl/test/responder.py` from any package directory.
It does not change working directory: recording paths and a supplied log path
are relative to the caller. Default logs live in the launcher's private directory.
The launcher removes its key, certificate, default log and directory in `finally`,
including startup and callback exceptions. A supplied log belongs to the caller
and is retained. A failure before READY raises
`stub failed before READY (exit N): ...`, preserving the stub's exit code instead
of masking it with a second `waitpid` error. If the stub exits during the
callback, cleanup observes that exit once and preserves the callback's result
or exception. `packages/cyberkrill/CyberkrillTests.lean` imports this library
and checks `HttpCurlTestSupport.withStub`; S11 also exercises trusted TLS with
the `cyberkrill` package as its working directory.

### Cases and negative checks

The driver pins **35/35**: the unchanged 22 T1–T13/C1–C9 cases above plus:

| Case | Assertions |
|---|---|
| S1 | Method/path/query/percent/body near misses; recursive key sorting, exact decimals, bool tags, array order; ordered responses |
| S2 | RPC method/params near misses; string id, numeric id and no-jsonrpc shapes; independent variant exhaustion |
| S3 | Missing/wrong auth 401; correct auth succeeds without cursor consumption |
| S4 | 599 diagnostics, unmatched/exhausted distinction, complete ordered flushed log, repeat-last |
| S5 | Example file over plain HTTP; response status, body, header and cleanup |
| S6 | Same example over trusted TLS and cleanup |
| S7 | Same example at a runtime-selected fixed port |
| S8 | Occupied listening port: nonzero exit, no READY, launcher error with that exit code; missing recording error with exit 1; recorded `Content-Length` (title case) and `transfer-encoding` (lower case) response headers fail nonzero before READY with a `framing header` error, while the same entry without them starts and serves its recorded status |
| S9 | Raw/binary bodies, recorded 404, binary log/diagnostic, first-entry precedence, no legacy fallback |
| S10 | Certificate/key/directory cleanup on callback exception |
| S11 | S6 from the sibling cyberkrill package directory |
| S12 | TLS stub exits within one second of stdin EOF while a silent TCP client stalls the handshake |
| S13 | Exactly one recorded content-type value for title, lower and mixed case header names, on text and JSON responses |

`HttpCurlTests --only <CASE>` retains its interface. All stub tests use the same
launcher that downstream tests import. S8 additionally runs the raw script to
observe startup stdout and exit status. S12 uses the launcher's temporary TLS
artifacts in `test/check-tls-eof.py`, which starts a second replay process, holds
a silent TCP connection, closes stdin and waits at most one second. The helper
kills and reaps that process in `finally` if it misses the deadline. Each case
runs under the existing two-second outer deadline.

Run `cd packages/http-curl && nix develop -c python3 -I check-stub-mutations.py`.
It applies one production mutation at a time, captures stdout and stderr into
separate `.lake/stub-mutation-checks/<case>-<mutation>.stdout`/`.stderr` files,
requires both a nonzero exit and the named assertion, and restores exact source
bytes in `finally`. It also rebuilds the restored executable. No tests, expected
values, fixtures or index entries are changed. Run without concurrent writers.
The measured run exited 0 and printed
`stub mutations: 72/72 detected; production sources restored`.

The following red-run table records every mutation. Each command is
`lake test -- --only <Case>` inside `nix develop`; each exit was **1**.
The assertion column omits the common `assertion failed: ` prefix. The mutation
names identify the exact replacements in `check-stub-mutations.py`.

| Case | Production mutation | Exit | Named assertion |
|---|---|---|---|
| S1 | `method` | 1 | `S1 method near miss` |
| S1 | `path` | 1 | `S1 path near miss` |
| S1 | `query` | 1 | `S1 query near miss` |
| S1 | `percent` | 1 | `S1 percent near miss` |
| S1 | `body` | 1 | `S1 body near miss` |
| S1 | `boolean` | 1 | `S1 boolean distinct` |
| S1 | `precision` | 1 | `S1 precision distinct` |
| S1 | `array-order` | 1 | `S1 array order` |
| S1 | `root-key-order` | 1 | `S1 key order and canonical exponent` |
| S1 | `nested-key-order` | 1 | `S1 key order and canonical exponent` |
| S1 | `exact-exponent` | 1 | `S1 key order and canonical exponent` |
| S1 | `trailing-zero` | 1 | `S1 canonical trailing zero` |
| S1 | `response-order` | 1 | `S1 ordered responses` |
| S2 | `rpc-method` | 1 | `S2 rpc method near miss` |
| S2 | `rpc-params` | 1 | `S2 rpc params near miss` |
| S2 | `string-id` | 1 | `S2 variant string id` |
| S2 | `numeric-id` | 1 | `S2 variant numeric id` |
| S2 | `no-jsonrpc` | 1 | `S2 variant no jsonrpc` |
| S2 | `per-variant-cursor` | 1 | `S2 variant numeric id` |
| S2 | `variant-exhaustion-string-id` | 1 | `S2 exhausted variant string id` |
| S2 | `variant-exhaustion-numeric-id` | 1 | `S2 exhausted variant numeric id` |
| S2 | `variant-exhaustion-no-jsonrpc` | 1 | `S2 exhausted variant no jsonrpc` |
| S3 | `missing-auth` | 1 | `S3 missing auth` |
| S3 | `wrong-auth` | 1 | `S3 wrong auth` |
| S3 | `auth-consumes` | 1 | `S3 right auth no consumption` |
| S4 | `unmatched-status` | 1 | `S4 unmatched status` |
| S4 | `diagnostic-method` | 1 | `S4 diagnostic method` |
| S4 | `diagnostic-path` | 1 | `S4 diagnostic path` |
| S4 | `diagnostic-body` | 1 | `S4 diagnostic body` |
| S4 | `unmatched-reason` | 1 | `S4 unmatched reason` |
| S4 | `exhausted-status` | 1 | `S4 exhausted status` |
| S4 | `exhausted-reason` | 1 | `S4 exhausted reason` |
| S4 | `log-complete` | 1 | `S4 log complete` |
| S4 | `log-flush` | 1 | `S4 log complete` |
| S4 | `log-order` | 1 | `S4 log order` |
| S4 | `log-method` | 1 | `S4 log method` |
| S4 | `log-body` | 1 | `S4 log body` |
| S4 | `repeat-first` | 1 | `S4 repeat first` |
| S4 | `repeat-last` | 1 | `S4 repeat last` |
| S4 | `repeat-enabled` | 1 | `S4 repeat repeat` |
| S5 | `example-status` | 1 | `S5 example status` |
| S5 | `example-body` | 1 | `S5 example body` |
| S5 | `example-header` | 1 | `S5 example header` |
| S6 | `example-status` | 1 | `S6 example status` |
| S6 | `example-body` | 1 | `S6 example body` |
| S6 | `example-header` | 1 | `S6 example header` |
| S7 | `example-status` | 1 | `S7 example status` |
| S7 | `example-body` | 1 | `S7 example body` |
| S7 | `example-header` | 1 | `S7 example header` |
| S7 | `fixed-port` | 1 | `S7 fixed port` |
| S8 | `occupied-exit` | 1 | `S8 occupied exit` |
| S8 | `occupied-ready` | 1 | `S8 occupied no ready` |
| S8 | `launcher-failure` | 1 | `S8 occupied launcher message` |
| S8 | `double-reap` | 1 | `S8 occupied launcher message` |
| S8 | `missing-recording-error` | 1 | `S8 missing recording launcher message` |
| S8 | `framing-content-length` | 1 | `S8 framing content-length rejected` |
| S8 | `framing-transfer-encoding` | 1 | `S8 framing transfer-encoding rejected` |
| S8 | `framing-case` | 1 | `S8 framing transfer-encoding rejected` |
| S9 | `recorded-status` | 1 | `S9 recorded 404` |
| S9 | `text-body` | 1 | `S9 text near miss` |
| S9 | `binary-body` | 1 | `S9 binary match` |
| S9 | `binary-diagnostic` | 1 | `S9 diagnostic binary` |
| S9 | `text-diagnostic` | 1 | `S9 diagnostic text` |
| S9 | `post-diagnostic` | 1 | `S9 diagnostic POST` |
| S9 | `precedence` | 1 | `S9 precedence` |
| S9 | `precedence-exhaustion` | 1 | `S9 precedence exhausted` |
| S9 | `binary-log` | 1 | `S9 log binary` |
| S9 | `no-legacy-fallback` | 1 | `S9 no legacy fallback` |
| S12 | `stalled-tls-eof` | 1 | `S12 TLS stdin EOF deadline` |
| S13 | `duplicate-content-type` | 1 | `S13 single recorded content-type /content-type/title` |
| S13 | `content-type-case` | 1 | `S13 single recorded content-type /content-type/lower` |
| S13 | `content-type-mixed-case` | 1 | `S13 single recorded content-type /content-type/mixed` |

### Final validation

On 2026-10-21, the staged implementation passed the following foreground gates.
Build/test gates used the AGENTS.md supervisor with separate stdout/stderr files
and preserved exit statuses; its exec watchdog was omitted to honor this run's
foreground-only rule. The mutation scripts also retain separate per-mutation
streams in `.lake/`. No gate output was piped through a filter.

| Directory | Command | Exit / observation |
|---|---|---|
| root | `nix flake check -L` | 0; sandbox `http-curl cases: 35/35`, `Built CyberkrillTests`, launcher declaration, link-spike and HttpCurlTests OpenSSL audits |
| root | `nix build` | 0 |
| root | `./result/bin/cyberkrill` | 0; `cyberkrill 0.1.0` |
| `packages/http-curl` | `nix develop -c lake build` | 0 |
| `packages/http-curl` | `nix develop -c lake test` | 0; `http-curl cases: 35/35` |
| `packages/cyberkrill` | `nix develop -c lake build` | 0 |
| `packages/cyberkrill` | `nix develop -c lake test` | 0; builds the launcher import and declaration reference |
| root | `nix develop -c bash scripts/check-link-spike.sh` | 0; includes HttpCurlTests one-OpenSSL audit |
| `packages/http-curl` | `nix develop -c python3 -I check-negative-mutations.py` | 0; `negative mutations: 36/36 detected; production sources restored` |
| `packages/http-curl` | `nix develop -c python3 -I check-stub-mutations.py` | 0; `stub mutations: 69/69 detected; production sources restored` (before review round 1; 72/72 after it, below) |
| root | `grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages` | 1; no matches |
| root | `git ls-files -- '*.key' '*.pem' '*.crt' '*.p12'` | 0; no paths |
| root | `git grep -n -e 'PRIVATE'' KEY'` | 1; no matches |
| root | `git diff --exit-code e75cfaa -- packages/http-curl/HttpCurl.lean packages/http-curl/link_shim.c scripts/check-link-spike.sh scripts/check-one-openssl.sh flake.lock flake.nix packages/secp256k1` | 0 |
| root | `git diff --exit-code e75cfaa -- ':(glob)**/lake-manifest.json'` | 0 |
| root | `git diff --check` | 0 |

The sandbox log includes the 35/35 summary, the app test's
`HttpCurlTestSupport.withStub` declaration, and the final HttpCurlTests
`http-curl wrapper executable: one nix OpenSSL, version and ldd: PASS` line.
No flake change or new C code was needed.

The table above was recorded before this work was rebased onto `master`
`e75cfaa`, which brought in Part 1's one-time `curl_global_init` change to
`link_shim.c`; the two `git diff --exit-code` rows were re-run against
`e75cfaa` (exit **0**). On the rebased tree, `nix flake check -L` rebuilt and
exited **0**; `nix eval --raw .#checks.x86_64-linux.default.drvPath` (exit
**0**) names the check
`/nix/store/qc5abg9iz4k9prjbywb0fb0nadgl2nqq-cyberkrill-0.1.0.drv`, and its
`nix log` (exit **0**) holds `http-curl cases: 35/35`, `S12: PASS`,
`S13: PASS`, `Built CyberkrillTests`, the `HttpCurlTestSupport.withStub`
declaration and the one-OpenSSL PASS line. The mutation scripts were not
re-run after the rebase: the files they mutate (`test/responder.py` and
`HttpCurlTestSupport.lean` for the stub script; `link_shim.c` and
`HttpCurl.lean` for Part 1's) are byte-identical to the pre-rebase tree and to
`master` respectively, and all 38 of Part 1's mutation targets still occur
exactly once. Review round 1 then made `test/responder.py` reject recorded
framing headers at load, so it is no longer byte-identical to the pre-rebase
tree and the stub script was re-run: in `packages/http-curl`,
`nix develop -c lake test` exited **0** with `http-curl cases: 35/35` and
`nix develop -c python3 -I check-stub-mutations.py` exited **0** with
`stub mutations: 72/72 detected; production sources restored`; at the root,
`nix flake check -L` exited **0** and the check drv is now
`/nix/store/4hqvfxcmg9f5lcnp91gj1b274230kar0-cyberkrill-0.1.0.drv`, whose
`nix log` holds `http-curl cases: 35/35` and `S8: PASS`.

After host tests, `pgrep -af 'python3 -I [^ ]*responder[.]py'` exited 1 with
no output. Gate streams are captured separately in root
`.lake/round2-<gate>.stdout` and `.stderr` files. The existing Manager-owned
tracker modification was left alone; implementation files are staged for the
Manager to commit.

### Deltas not taken

None.

## Licence

Dual-licensed under MIT or Apache-2.0, at your option: `LICENSE-MIT`, `LICENSE-APACHE`. Code copied from
other projects keeps its own licence notice next to it.

Each lakefile sets `license := "MIT OR Apache-2.0"` and
`licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]`. Lake accepts the relative paths:
`lake reservoir-config` in a package directory lists both files (Lake drops paths that don't exist).
It prints them as absolute paths.
