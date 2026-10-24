# lean-cyberkrill

Bitcoin, Lightning and Fedimint libraries for Lean 4, and a Lean port of the
[cyberkrill](https://github.com/douglaz/cyberkrill) command-line tool built on them.

Status: Phase 1a, both parts of Phase 1b, Phase 2, and Phase 3a implemented: secp256k1 bindings,
a bounded HTTP(S) client with per-request CA selection, a reusable HTTP/TLS recording stub,
proved SHA-256 and SHA-256d with NIST vectors, and hex, canonical CompactSize and exact
millisatoshi amounts with String round-trip proofs, plus proved Base58, Base58Check and
bech32/bech32m codecs with strict and lax bit regrouping, and scriptPubKey/address
conversion per network with round-trip proofs. Phase 3a is complete apart from
the 4-error theorem, which belongs to Phase 3b. Phase 4a (1 of 3) adds transaction
and PSBT codecs, supplied curve/hash operations, an optional BIP32 same-point
check, and hybrid-aware public-key compression. Phase 4a (2 of 3) adds pure
RIPEMD-160 and HASH160 with an exported PSBT preimage-hash value. Phase 4a (3 of 3)
adds PSBT validity, duplicate-key and trailing-data theorems, and the transaction
wire round-trip under its nine explicit preconditions. The PSBT field-parity
follow-up matches rust-bitcoin 0.32.8 on five non-curve field rules; the three
kept BIP rules are captured, tested and listed as a documented delta. The Phase 3b (1 of 2)
feasibility spike is delivered with a **stop** verdict: the complete split finite
check (220 chunk files, all passing) took **1,198 s** with four files checked at
once, against the ten-minute (600 s) added build budget. The full theorem remains
unproved; both Phase 3b beads are deferred until a new proof route is chosen.
Phase 4b adds pure English BIP39 entropy/word conversion, both round-trip
theorems and checksum soundness, with the 24 published English vectors and
deterministic 15/21-word and rejection cases.
Phase 4c adds SLIP-132 conversion among six public versions, string round-trip
and payload-preservation proofs, 12 BIP32 public vectors, 72 conversions and
48 offline cyberkrill goldens.
Other packages remain skeletons;
`plan.md` is the plan for v1.

## Packages

| Directory | Lake package | Root module | Contents (v1) |
|---|---|---|---|
| `packages/sha256` | `sha256` | `Sha256` | SHA-256 and SHA-256d |
| `packages/secp256k1` | `secp256k1` | `Secp256k1` | libsecp256k1 bindings (FFI) |
| `packages/bitcoin` | `bitcoin` | `Bitcoin` | Bitcoin encodings, transactions, PSBT, BIP39, SLIP-132 |
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

The verification records below write each temporary directory a check used as a shell variable
(`$TMP_ROOT`, `$UNICODE_DIR`, `$FETCH_DIR`, `$BIPS_DIR`, `$CORE_DIR_1`, `$CORE_DIR_2`). `$REPO`
denotes the repository root. Each temporary-directory variable was a
fresh directory outside the repository; set the variable to one before rerunning a command.

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
compressPubkey (key : @& ByteArray) : Option ByteArray
isValidXOnlyPubkey (key : @& ByteArray) : Bool
isValidDerSignature (sig : @& ByteArray) : Bool
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
| `compressPubkey` | libsecp256k1's own parse rule: 33-byte 02/03, 65-byte 04, or a 65-byte 06/07 hybrid whose tag matches y parity. Returns a fresh 33-byte compressed key, or none for an invalid encoding or point. |
| `isValidXOnlyPubkey` | Exactly 32 bytes, parsed by `secp256k1_xonly_pubkey_parse`. False for wrong lengths, out-of-field coordinates or off-curve points. |
| `isValidDerSignature` | Nonempty strict DER bytes, without a sighash byte, parsed by `secp256k1_ecdsa_signature_parse_der`. Encoding only: no verification, low-S rule or normalization. Well-encoded out-of-range integers follow the library's parse rule. |
| `verify` | 32-byte hash, 64-byte compact signature (big-endian r ‖ s), SEC1 key as above. False for any malformed input, r or s ≥ the curve order, zero scalars, high-S, or failure to verify. No normalisation. |
| `recover` | Same hash and compact signature; recid 0–3. Returns a 33-byte compressed SEC1 key, or none for wrong lengths, recid > 3, invalid scalars, or recovery failure. Preserves high-S. |
| `sign` | 32-byte hash and 32-byte secret key. Returns 65 bytes: compact r ‖ s (always low-S), then recid 0–3. None for wrong lengths, secret zero or ≥ the curve order, context failure or signing failure. |

The BIP340 public-key and Wycheproof DER parsing vectors and counts are
recorded in the [PSBT curve follow-up](#phase-4a-psbt-curve-parity-follow-up).

Parse and verify both reject hybrid (06/07) keys, including matching parity;
tests cover both matching and mismatched parity. This matches rust-bitcoin
0.32.8's `PublicKey::from_slice` and `from_str`, which cyberkrill uses for PSBT
`partial_sigs` keys and descriptors. libsecp256k1's own parse, and so
`secp256k1::PublicKey::from_slice`, accepts a hybrid key whose prefix matches
the y parity; cyberkrill reaches it for PSBT `bip32_derivation` keys and for
`ln-encode-invoice`'s JSON keys. Owner decision (2026-10-21, bead
`lck-decide-hybrid-pubkey-xgr`): both paths follow it, through a second
function, `compressPubkey`, implemented in Phase 4a (1 of 3). The `bitcoin`
PSBT codec keeps 04 and hybrid bip32 keys as the bytes it read, where
rust-bitcoin rewrites them to 33-byte compressed. The separate
`Psbt.checkBip32SamePoint` rejects two encodings of one point in one bip32 map,
as cyberkrill does; application wiring remains a later phase.
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

The app printed `cyberkrill 0.1.0`. At that step, the regenerated
`packages/secp256k1/.lake/build/ir/Secp256k1.c` declared the same five `lck_`
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
with no concurrent readers or writers; then run the green checks again.

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
`.lake/round2-<gate>.stdout` and `.stderr` files. The existing
tracker modification was left alone; implementation files are staged for a
separate commit.

### Deltas not taken

None.

## Phase 2: sha256

`import Sha256` provides `Sha256.hash : ByteArray → ByteArray` and
`Sha256.sha256d : ByteArray → ByteArray`. Both produce 32 bytes in raw digest
order. `hash` is `(Sha256.sha256 msg).toByteArray`, and `sha256d` is
`hash (hash msg)`: both use the copied implementation, with no second hash
implementation. The copied `Sha256.sha256 : ByteArray → Digest 32` and its
UTF-8 string wrapper remain available too.

`hash_spec` equates the output list with `Spec.sha256_bytes` of the input;
`hash_size` proves size 32. `sha256d_spec` equates its output list with the
specification applied twice, and `sha256d_size` proves size 32. These four
theorems connect the byte-array API that downstream packages call to the
copied specification. The specification is total; its FIPS interpretation
is for byte-aligned messages within the standard's length bound of fewer
than 2⁶⁴ bits. No cryptographic security property is claimed.

### Copy and port

Source: [pure-algebra/lean4-hash](https://github.com/pure-algebra/lean4-hash/tree/ab7eda433f0390fde7aa240189761540c9744c79),
commit `ab7eda433f0390fde7aa240189761540c9744c79`, MIT,
Copyright (c) 2026 The Fold Lab. Its verbatim MIT notice is
`packages/sha256/Sha256/LICENSE-MIT`; each copied file starts with a provenance
line referring to that notice. New files carry this repository's dual licence.

Modules **and namespaces** are renamed from `Hash.Sha256.*` to `Sha256.*`.
This keeps the package's names under its existing root, avoids claiming the
generic `Hash` module tree in a shared workspace, and avoids a collision with
an unmodified lean4-hash dependency. Lake retains `autoImplicit = false`,
`relaxedAutoImplicit = false`, and `warningAsError = true`. The package has
zero Lean dependencies, no Mathlib, and no C. `lakefile.lean` stays in use;
`Sha256Tests` is now an executable test driver, with a separate test-support
library rooted at `Sha256Tests.AxiomGate`.

All nine files come from upstream's `Hash/Sha256/`. Every file gains the
provenance line and the module/namespace rename. Beyond those shared changes,
the complete deviations are:

| Upstream file | Additional changes |
|---|---|
| `Vec.lean` | None. |
| `Spec.lean` | One `if_pos` → `ite_eq_left`, one `dif_pos` → `dite_eq_left`, two `dif_neg` → `dite_eq_right`; clarify that the PDF is vendored upstream, and that the known-answer tests on `Impl` are upstream's while this port's vectors run through the public API. |
| `Impl.lean` | One `dif_pos` and one `dif_neg` replaced as above; clarify that `Hash.Sha256.Kats` and kernel witnesses belong to upstream, while this port tests the public API at runtime. |
| `Lengths.lean` | None. |
| `Bridge.lean` | Clarify that the `Hash.Sha256.Kats` reference names upstream tests. |
| `Hex.lean` | None. It is required by `Digest`, retained with its proofs, and unused by our vector decoder. |
| `Digest.lean` | One `dif_pos` → `dite_eq_left`. |
| `Fast.lean` | Three `dif_pos` and three `dif_neg` replacements; clarify the historical kernel-witness statement and this port's runtime vector path. |
| `Api.lean` | Remove the five build-time CAVP guards and their prose (all five records run in ShortMsg); remove their two unused meta imports; replace the obsolete v4.33.1/external `Verified` recheck claim with the v4.35.0 kernel and this port's actual allowlist audit. |

No copied theorem statement changes except the namespace rename. All proofs
keep their meaning. Documentation paths such as `docs/SHA256-DAG.md` and
`test/contracts/…`, and historical v4.33.1 measurements, refer to upstream at
`ab7eda4`. `Context`, SHA-224 modules, and upstream test/audit roots are not
copied; the SHA-224 IV comparison within `Bridge` remains. General portability
fixes are recorded in [docs/upstream-fixes.md](docs/upstream-fixes.md).

### Specification review

Compared `Sha256/Spec.lean` with
[FIPS 180-4, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
Transcription fidelity between English/pseudocode and Lean remains a **human
trust step**, rather than a formal theorem. The non-mechanized comparisons
below cover the definitions, rather than inferring correctness from passing
vectors. Constants additionally have an independent mechanical check.

| Section | Comparison and result |
|---|---|
| §3.1 | `bitsOfNat (k+1)` emits bit `k` first; `bitsOfByte` uses 8 and `bitsOfWord` uses 32. `natOfBits` weights the head by 2^(tail length). Input and output are MSB first within each byte/word; words are emitted in state order. Non-mechanized comparison with the standard's big-endian convention. |
| §4.1.2 | `Ch` is `(x ∧ y) ⊕ (¬x ∧ z)`; `Maj` is the xor of the three pairwise ands. The large sigmas rotate by (2,13,22) and (6,11,25); the small sigmas rotate by (7,18) and (17,19), with logical shifts 3 and 10. Matched all six definitions and 32-bit word width by inspection. |
| §4.2.2 | Compared all 64 `K` literals, in order, with the table. `check-fips-constants.py` also independently derives all 64 from the fractional cube roots of the first 64 primes using integer arithmetic and exact floor-root inequalities; no floating-point approximation. |
| §5.3.3 | Compared all eight `H0` words in order. The same script independently derives all eight from the fractional square roots of the first eight primes. |
| §5.1.1 | `pad` appends `true`, then `(959 − length % 512) % 512` false bits, then `bitsOfNat 64 length`. Since 959 ≡ 447 modulo 512 and subtraction cannot truncate, the zero count is the least nonnegative solution of ℓ+1+k ≡ 448 modulo 512. The length is big endian. Non-mechanized arithmetic/transcription comparison; `length_pad` and `pad_prefix` also remain proved. |
| §5.2.1 | `parse` takes successive 512-bit blocks; `blockOfBits` selects 16 successive 32-bit slices starting at offset `32*i`. Non-mechanized comparison. The trailing-short-block total extension is irrelevant on padded input. |
| §6.2.2 | The first 16 schedule words are the block; the remaining 48 use offsets −2, −7, −15, −16 with σ1 and σ0 in the prescribed positions. `round` forms T1 and T2, updates all eight variables in the prescribed order, runs 64 rounds, then `compress` adds each final word to the incoming state modulo 2³². `hash` folds blocks in order from `H0`. Non-mechanized comparison of each recurrence, assignment, bound, and final addition. |

From the repository root, `nix develop -c python3 -I
packages/sha256/check-fips-constants.py` exited **0**, printing:

```text
FIPS K: 64/64 independently derived
FIPS H0: 8/8 independently derived
```

### Vector sources and counts

All vectors run through `Sha256.hash` or `Sha256.sha256d`, offline. The
executable reads committed data relative to `packages/sha256`, the working
directory used both by `nix develop -c lake test` and the flake's package loop.
The parser accepts LF and CRLF, enforces field ordering and complete records,
treats `Len = 0` as empty even when `Msg = 00`, and checks `Len = 8 × decoded
message bytes` for every nonempty record. Expected digests must be 32 bytes.
The hex helper is test-only; it does not call the copied `Hex` implementation.
Each set asserts its loaded count before hashing and prints its passed count.

| Set | Pinned count | Published source |
|---|---|---|
| FIPS examples | 3 | `abc` and the 448-bit message: [NIST SHA-256 intermediate examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf). One million `a`: [FIPS 180-2 Appendix B.3](https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf); all three are also published on [NIST NSRL Test Data](https://www.nist.gov/itl/ai/ai-standards-and-guidelines-group/nsrl-test-data). |
| CAVP ShortMsg | 65 | [lean4-hash's pinned NIST data](https://github.com/pure-algebra/lean4-hash/blob/ab7eda433f0390fde7aa240189761540c9744c79/vendor/nist-cavp-sha256/SHA256ShortMsg.rsp), unchanged LF bytes, 10,031 bytes. It differs from the ShortMsg member in NIST's zip. |
| CAVP LongMsg | 64 | [NIST byte-oriented SHA vectors](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip), member `shabytetestvectors/SHA256LongMsg.rsp`, downloaded 2026-10-21; unchanged CRLF bytes, 426,209 bytes. |
| SHA-256d | 1 | [Bitcoin Core v28.0 mainnet genesis fields/hash](https://github.com/bitcoin/bitcoin/blob/v28.0/src/kernel/chainparams.cpp#L135-L138), MIT. Version 1, zero previous block, the published merkle root, time 1231006505, bits 0x1d00ffff, nonce 2083236893 form the 80-byte header, each serialised little-endian; so the header holds the merkle root byte-reversed relative to its published display form `4a5e1e4b…deda33b`. The conventional displayed block hash is byte-reversed for comparison with raw SHA-256d output. |

The NIST `.rsp` files each have a `.provenance` sidecar recording the URL,
source path, revision/date, public-domain US Government licence and committed
byte digest. `sha256sum` reports:

```text
294ecec26959357405a621121bbfb01db4d45b9e834624b2d71aedd94ffde019  SHA256ShortMsg.rsp
6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974  SHA256LongMsg.rsp
```

The downloaded zip's SHA-256 is
`929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`.
Monte Carlo vectors are outside this phase.

### Axiom gate

`Sha256Tests/AxiomGate.lean` is newly written, using the upstream gate's
environment/axiom-collection approach, without copying its denylist or text.
It allows **exactly** `propext`, `Classical.choice`, and `Quot.sound`, with no
exemptions. It first resolves and checks these ten named theorems:

```text
Sha256.sha256_spec                 Sha256.sha256_impl
Sha256.sha256_ofList               Sha256.Bridge.sha256_bridge
Sha256.Fast.sha256_eq_impl          Sha256.Fast.size_sha256
Sha256.hash_spec                   Sha256.hash_size
Sha256.sha256d_spec                Sha256.sha256d_size
```

It then scans every theorem in every imported library module whose module name
is `Sha256` or below it, including private/generated theorems. The current
scan checks **346** theorems, including the copied proofs and four new API
proofs. Names in the explicit list resolve during elaboration; missing names
fail, and any reached axiom outside the allowlist fails `lake test` before
vectors run. The executable prints one gate summary line, even on cached
builds. `#print axioms` on all ten named theorems prints `[propext, Quot.sound]`.
The gate file contains no placeholder substring.

Later phases should create their own package's test-support gate with this
same allowlist, import all of their library modules, change the scanned module
prefix, and add their required named theorems as resolved name literals. Keep
the gate imported by the executable test driver. Adding a theorem to an
already imported module under the scanned prefix automatically includes it.

### Production mutation red runs

From `packages/sha256`, run:

```bash
nix develop -c python3 -I check-mutations.py
```

On Lean 4.35.0 with Lake 5.0.0-src+eb6cafb this exited **0**, printing `negative mutations: 3/3
detected; production sources restored`. The script saves subprocess stdout and
stderr separately, commands, working directories and exit codes in
`.lake/mutation-checks/`. Each production mutation is restored in `finally`;
no changed expectation or test setup is used to redden a vector.

| Mutation | Foreground command and observed exit | Failing evidence |
|---|---|---|
| Change K[0] from `0x428a2f98` to `0x428a2f99` in **both** `Spec` and `Fast` | `lake test`, **1** | Axiom gate ran with 0 offenders; FIPS **0/3**, ShortMsg **0/65**, LongMsg **0/64**, SHA-256d **0/1**. Failing lines: `assertion failed: FIPS examples abc digest`; `assertion failed: CAVP ShortMsg Len=0 digest`; `assertion failed: CAVP LongMsg Len=1304 digest`; `assertion failed: SHA-256d genesis digest`. |
| Make `Spec.length_bitsOfNat` use a temporary `Spec.auditProbe` axiom of the same statement | `lake test`, **1** | `SHA-256 axiom gate: Sha256.sha256_spec reaches disallowed axiom Sha256.Spec.auditProbe`. The allowlist stays unchanged. |
| Create a temporary untracked `.lean` file with the placeholder word under `packages/sha256` | The exact CI command below, via `bash --noprofile --norc -eo pipefail -c`, **1** | `packages/sha256/Sha256CiProbe-te1yhcb0.lean:5:-- sorry`. The script deletes that exact generated path. The same command exited **0** before and after the mutation. |

After restoring every mutation, the script's final `lake test` exited **0**
with the four pinned counts passing. Removing the build-time guards from
`Api.lean` is what lets the broken-constant run reach this executable suite;
the five witnesses are all retained as ShortMsg records.

### CI and validation

The `No sorry` step in `.github/workflows/ci.yml` now runs exactly:

```bash
rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages || rc=$?; test "$rc" -eq 1
```

Unlike negating grep, this accepts only its no-match status and rejects errors.
PyYAML **6.0.3** parsed the workflow and asserted the parsed `run` string equals
the literal command, exit **0**. Reproduce from the repository root:

```bash
nix shell --impure --expr 'let pkgs = import (builtins.getFlake (toString ./.)).inputs.nixpkgs {}; in pkgs.python3.withPackages (p: [p.pyyaml])' -c python3 -c 'import pathlib, runpy, yaml; data = yaml.safe_load(pathlib.Path(".github/workflows/ci.yml").read_text()); step = next(s for s in data["jobs"]["check"]["steps"] if s.get("name") == "No sorry"); assert step["run"] == runpy.run_path("packages/sha256/check-mutations.py")["CI_COMMAND"]; print("CI parsed run string matches exactly")'
```

On 2026-10-21, after staging the new files, these foreground commands exited
**0** (the repository's gate supervisor also returned `EXIT=0`):

```bash
nix flake check -L
nix build && ./result/bin/cyberkrill
(cd packages/sha256 && nix develop -c lake build && nix develop -c lake test)
(cd packages/cyberkrill && nix develop -c lake build)
sha256sum packages/sha256/testdata/SHA256ShortMsg.rsp packages/sha256/testdata/SHA256LongMsg.rsp
```

`nix develop -c lean --version` reported **4.35.0**, commit
`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, Release;
`nix develop -c lake --version` reported **5.0.0-src+eb6cafb (Lean version 4.35.0)**,
both exit **0**. From `packages/sha256`, `time nix develop -c lake test` exited
**0** in **0.655 seconds wall time** with cached build artifacts, including all
vectors and the million-byte message. A prior invocation rebuilding the test
modules took 3.481 seconds. Host and sandbox both printed:

```text
SHA-256 axiom gate: 346 library theorems; 10 named; 0 offenders
FIPS examples: 3/3
CAVP ShortMsg: 65/65
CAVP LongMsg: 64/64
SHA-256d: 1/1
```

The fresh sandbox check built derivation
`/nix/store/854fhfa3vlf0ci4fv1b6dvy6nc8dl1np-cyberkrill-0.1.0.drv` (after a
final doc-comment correction in `Spec.lean`; the run before it,
`/nix/store/5mdhqn4i80vcw9kabz1g0zqhw0v9r0rc-cyberkrill-0.1.0.drv`, printed the
same lines).
It also ran all six other packages' builds/tests, including secp256k1's BOLT
16/16 recovery and signing checks, all 252 Wycheproof vectors, and the
HTTP client's 22/22 cases. The existing link-spike and one-OpenSSL checks
ran unchanged, ending with `link spike, Lake/leanc green twins, forced-static
red fixture: PASS` and `http-curl wrapper executable: one nix OpenSSL, version
and ldd: PASS`. Both the sandbox install and `./result/bin/cyberkrill` printed
`cyberkrill 0.1.0`.

These additional commands printed nothing and exited **1**, their expected
no-match status:

```bash
grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages
grep -F sorry packages/sha256/Sha256Tests/AxiomGate.lean
grep -rn native_decide --include='*.lean' --exclude-dir=.lake packages/sha256
```

A comparison against the freshly fetched pinned upstream source confirmed
all **114 authored theorem statements** unchanged after namespace substitution
and whitespace normalization, and the MIT notice byte-identical. The diff
against `e75cfaa` is restricted to this package, this README, the CI step,
`docs/upstream-fixes.md`, and the pre-existing tracker claim. No
`flake.nix`, `flake.lock`, other package or OpenSSL script changed.
`git diff --cached --check` excluding the two unchanged `.rsp` data files
exited **0**; the raw NIST LongMsg bytes intentionally retain upstream trailing
space and a final blank line, checked by their digest instead.

After review, the branch was rebased from `e75cfaa` onto `3e0e228` (#7, the
replay stub). The only conflict was the status line at the top of this README.
On the rebased tree, `nix flake check -L` rebuilt
`/nix/store/fgxyls2a891awq54gv2pvcy0v7i087k6-cyberkrill-0.1.0.drv` and exited
**0**, printing the five SHA-256 lines above plus `http-curl cases: 35/35`,
`S12: PASS`, `S13: PASS` and `cyberkrill 0.1.0`.

### Deltas not taken

None. Incremental hashing, additional hash families, a public library hex
codec, and performance work remain outside Phase 2. Tracker updates and
commits are made separately; the tracker and other packages are untouched.

## Phase 3a: bitcoin primitives (1 of 4)

`import Bitcoin` exposes hex, canonical CompactSize and exact nonnegative amounts.
The package remains pure Lean, depending only on `sha256`, with no C, FFI or
Mathlib. The test driver is now an executable; `BitcoinTestSupport` roots the
elaboration-time axiom gate at `BitcoinTests.AxiomGate`.

### Public API

| Module / namespace | API and behavior |
|---|---|
| `Bitcoin.Hex` | `encode : ByteArray → String` emits lower-case hex; `decode : String → Option ByteArray` accepts either case, rejects odd length, prefixes, whitespace and non-hex characters, and accepts empty input. It reuses `Sha256.Hex` with case normalization. |
| `Bitcoin.CompactSize` | `compactSize`, `readCompactSize`, `unsignedLE`, `decodeLE`, `takeExact`, and the copied byte-vector/witness helpers. Readers return `Except DecodeError (value × rest)`, preserve unread bytes, distinguish truncation and noncanonical encodings, and accept only canonical widths. **Phase 4a imports `Bitcoin.CompactSize`.** The writer's round trip requires `value < 2^64`, the actual wire bound. |
| `Bitcoin.CompactSizeProofs` | Explicit rejection of each noncanonical wide tag, and truncation for any payload shorter than its tag's width. |
| `Bitcoin.Amount` | `Amount` has `msat : Nat`, `DecidableEq` and `Repr`. `Amount.Decimal` holds a natural mantissa and natural decimal exponent. `ofMsat`, `ofSats`, `toMsat`, `toSats?`, `toBtc`, `toSatDecimal`, `toMsatDecimal`, `ofDecimal`, `ofBtc?` and `ofJsonNumber` provide exact unit conversions. `ofJsonNumber` takes `Lean.JsonNumber` in BTC, rejecting a negative mantissa. |
| `Bitcoin.AmountText` (`Bitcoin.Amount` namespace) | `parseDecimal` scans decimal syntax without signs, whitespace or exponents; `parseBtc`, `parseSats` and `parseMsat` return `Option Amount`. `printBtc`, `printSats` and `printMsat` return canonical Strings. `parseScaled` and `printScaled` share the converter and printer core. |
| `Bitcoin.AmountCli` (`Bitcoin.Amount` namespace) | `parseInput : String → Except InputError Amount` follows `AmountInput::from_str` suffix order (`msats`, `msat`, `sats`, `sat`, `btc`, bare BTC), with exact arithmetic and the named rejections below. Errors distinguish empty input, invalid syntax, negative values, sub-msat values and CLI msat overflow. |

`Amount` is a structure over **unbounded `Nat` msat**. Negative amounts are not
representable. Amounts above 21,000,000 BTC and above 2^64−1 msat are representable;
range checks belong to consumers whose formats require them, such as Core's
`MAX_MONEY` and u64 wire fields. The library integer-msat parser is unbounded so
its print/parse law holds for every amount. The CLI `msat`/`msats` path keeps the
u64 bound because Rust parses that path as `u64`: its maximum is
`18446744073709551615`, and the next integer is rejected.

The shared converter accepts a decimal `m / 10^e` at scale `k` iff its value
`m * 10^k / 10^e` is a whole number of msat (`k = 11` for BTC, `3` for sats,
`0` for msat). Precision is judged **by value**, with no limit on written trailing
zero digits: `0.100000000000` BTC, `0.000000000010` BTC and `0.5000` sats are
accepted. A JsonNumber with exponent above 11 is accepted iff the extra power of
ten divides its mantissa. This keeps written trailing zeros from changing an
amount's validity. Nonzero sub-msat values are rejected rather than rounded.

Printers emit a digit before the decimal point, at most 11 BTC / 3 sats fractional
digits, no trailing fractional zeros and no exponent notation. Integral values
print as `1`, zero as `0`, and one msat as `0.00000000001` BTC or `0.001` sats.
The decimal scanner produces the exact mantissa/exponent and then calls the
shared converter; the String theorems cover that same executable path.

### Copy and portability

Source: [febyeji/lean-miniscript](https://github.com/febyeji/lean-miniscript/tree/cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd),
MIT, Copyright (c) 2026 Yeji Han. `Bitcoin/CompactSize.lean` combines the whole
`LeanMiniscript/Bitcoin/Serialization.lean`, `Deserialization.lean` L11–79, and
`DeserializationProofs.lean` L7–179. The verbatim upstream LICENSE is adjacent as
`Bitcoin/LICENSE-miniscript`, and the first line records the full commit, paths,
ranges and licence. `LeanMiniscript.Bitcoin` becomes `Bitcoin.CompactSize`.

The only proof port fixes replace deprecated `if_true`, `if_false`, `if_pos` and
`if_neg` with `ite_true`, `ite_false`, `ite_eq_left` and `ite_eq_right`.
Every copied theorem statement is preserved. The module imports only `Lean`;
transaction types and hashing imports are excluded. New rejection/truncation
theorems are in our separate dual-licensed file. See
[upstream fixes](docs/upstream-fixes.md#lean-miniscript).

### CLI syntax and reference capture

The decimal syntax follows the non-exponent, finite part of Rust's documented
[`f64::from_str` grammar](https://doc.rust-lang.org/std/primitive.f64.html#impl-FromStr-for-f64).
No whitespace is removed from the numeric substring, so `1 btc` and `5 sats`
are rejected. Leading zeros and mixed-case suffixes are accepted. Outer trimming
uses exactly Unicode White_Space: U+0009–000D, U+0020, U+0085, U+00A0, U+1680,
U+2000–200A, U+2028, U+2029, U+202F, U+205F and U+3000. All 25 characters have
individual capture/port cases; four nearby non-members are rejected.

| Named form | Decision | Fixture name |
|---|---|---|
| `.5` | Accept as 0.5 BTC | `leading-dot` |
| `5.` | Accept as 5 BTC | `trailing-dot` |
| `+5msat` | Accept as 5 msat | `leading-plus-msat` |
| `+0.5btc`, `+0.5` | Accept as 0.5 BTC | `leading-plus-btc`, `leading-plus-bare` |
| `-0`, `-0.0btc`, `-0.000sat` | Accept as zero on decimal paths | `negative-zero`, `negative-zero-btc`, `negative-zero-sats` |
| `-0msat` | Reject, matching Rust's unsigned integer parser | `negative-zero-msat` |
| `infinity` | Reject as a nonfinite value | `nonfinite-infinity` |

ASCII lowercasing suffices for the accepted language. Rechecked against default
Unicode 17.0.0 simple and unconditional special casing: the only non-ASCII input
mapping entirely to ASCII is U+212A KELVIN SIGN → `k`; no accepted form contains
`k`. `check-unicode.py` checks externally fetched
[UnicodeData.txt](https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt) and
[SpecialCasing.txt](https://www.unicode.org/Public/17.0.0/ucd/SpecialCasing.txt)
offline. No Unicode data is vendored. The run
`python3 -I packages/bitcoin/check-unicode.py "$UNICODE_DIR"/UnicodeData.txt "$UNICODE_DIR"/SpecialCasing.txt`
exited **0**, reporting `U+212A -> k (1/1)`.

From the repository root, this command exited **0**:

```bash
python3 packages/bitcoin/capture-cyberkrill.py
```

It cloned `douglaz/cyberkrill` at
`27cad1faba86260b06665a89f0af5134d23525c2` into a fresh temporary directory,
added one temporary test calling only `AmountInput::from_str` and
`as_millisats`, and fetched dependencies with that revision's own `nix develop`.
The fetch/version command was
`nix develop -c bash -c 'rustc --version && cargo --version && cargo fetch --locked'`
(exit **0**):

```text
rustc 1.89.0 (29483883e 2025-08-04)
cargo 1.89.0 (c24e10642 2025-06-23)
```

The actual build/test command ran with a fresh temporary HOME and private cargo
cache, no network interfaces except loopback, and exited **0**:

```bash
nix develop -c unshare -rn sh -c 'ip link set lo up && cargo test --offline --locked --target x86_64-unknown-linux-gnu -p cyberkrill-core --no-default-features --test amount_capture -- --nocapture --test-threads=1'
```

Output: `captured amounts: 124/124`. The script records stdout/stderr separately
under `packages/bitcoin/.lake/capture-checks/`. Its extracted output is committed
in `test-data/cyberkrill-amounts.json`; the adjacent provenance identifies the
source commit/path, MIT OR Apache-2.0 taken under MIT, and **captured output on
our own synthetic inputs**. The Lean executable reads every captured record and
checks rejection parity, exact equality, named rejection or the listed exact-value
difference. No hand-derived reference fallback was needed.

Accepted values differ in these four captured cases. These are value differences,
not additional rejection classes; no Phase 7a golden allowlist is introduced here.

| Input | Exact port msat | Captured cyberkrill msat | Difference |
|---|---|---|---|
| `200000000btc` | 20000000000000000000 | 18446744073709551615 | u64 saturation |
| `20000000000000000sat` | 20000000000000000000 | 18446744073709551615 | u64 saturation |
| `90071992.54740993btc` | 9007199254740993000 | 9007199254740994048 | binary `f64` rounding |
| `9007199254740.993sat` | 9007199254740993 | 9007199254740992 | binary `f64` rounding |

### Proofs and axiom audit

The gate first resolves all 26 named theorems below, then scans every theorem
in every imported module named `Bitcoin` or below it. `Bitcoin.lean` imports all
new library modules. Name components exclude `BitcoinTests` from the library
scan. There are **146 library theorems, 26 named, 0 offenders** (generated
structure/inductive theorems are included in the total). The allowlist is exactly
`propext`, `Classical.choice`, `Quot.sound`, with no exemptions. The executable
imports the gate, so audit failure fails `lake test`.

H1 is the public String hex round trip. C1/C2 are the wire-bounded round trip
and canonicality characterization; C3/C4 explicitly reject noncanonical and
truncated inputs. A1 characterizes successful exact conversion, including signed
JsonNumber inputs. A2 covers divisibility rejection and successful String parse
semantics. A3 states the three public String print/parse round trips for **every**
Amount. A4 covers constructors and inverse accessors. No theorem is weakened by
an amount range assumption.

The gate's `#print axioms` output, with the shared prefix `Bitcoin.` retained:

```text
'Bitcoin.Hex.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.readCompactSize_compactSize' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.readCompactSize_ok' depends on axioms: [propext, Quot.sound]
'Bitcoin.CompactSize.reject_fd' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.reject_fe' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.reject_ff' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.truncated_empty' does not depend on any axioms
'Bitcoin.CompactSize.truncated_tag' depends on axioms: [propext]
'Bitcoin.Amount.ofDecimal_iff' depends on axioms: [propext]
'Bitcoin.Amount.ofJsonNumber_iff' depends on axioms: [propext, Quot.sound]
'Bitcoin.Amount.ofDecimal_submsat' depends on axioms: [propext]
'Bitcoin.Amount.parseBtc_submsat' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.parseSats_submsat' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.parseBtc_exact' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.parseSats_exact' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.parseBtc_printBtc' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.parseSats_printSats' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.parseMsat_printMsat' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.ofSats_msat' does not depend on any axioms
'Bitcoin.Amount.toSats_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.toSats_ofSats' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Amount.ofBtc_toBtc' depends on axioms: [propext]
'Bitcoin.Amount.toBtc_exact' does not depend on any axioms
'Bitcoin.Amount.ofSatDecimal_toSatDecimal' depends on axioms: [propext]
'Bitcoin.Amount.ofMsatDecimal_toMsatDecimal' depends on axioms: [propext]
'Bitcoin.Amount.toMsat_ofMsat' does not depend on any axioms
```

### Vectors and red runs

All inputs are synthetic, derived from published format rules or captured on our
own inputs. CompactSize expected bytes are hand-derived from Bitcoin Core's
[`WriteCompactSize` in serialize.h](https://github.com/bitcoin/bitcoin/blob/v29.0/src/serialize.h).
Hex covers the full 0–255 byte alphabet; amount expectations follow decimal integer
arithmetic. No node, wallet, device, key or live service supplies a fixture.
Each set checks its loaded count against a pinned constant before checking values:

```text
Bitcoin axiom gate: 146 library theorems; 26 named; 0 offenders
hex: 12/12
CompactSize boundaries: 8/8
CompactSize noncanonical: 4/4
CompactSize truncated: 4/4
Amount: 36/36
CLI grammar: 124/124
cyberkrill cross-check: 124/124
```

From `packages/bitcoin`,
`TMPDIR="$TMP_ROOT" nix develop -c python3 -I check-mutations.py` exited **0**.
Every mutation ran `lake test` in the foreground and exited **1**, with these
observed failures; the script asserts the named proof's diagnostic location or
the exact vector/gate message, and restores the production file in `finally`.
Hex's round-trip proof still checks after dropping upper-case decoding; its
proof is adjusted to the simpler decoder without weakening the statement.

| Production mutation | Observed failure |
|---|---|
| Disable CompactSize minimum check | `Bitcoin.CompactSize.readCompactSize_ok`: `CompactSize.lean:236:10: unsolved goals` (also its other wide-tag branches). |
| Drop hex case normalization | `assertion failed: hex upper` |
| Round sub-msat values instead of rejecting | `Bitcoin.Amount.ofDecimal_iff`: `Amount.lean:59:4: simp made no progress`; the rejection theorem also fails. |
| Test `sat` before `msat` | `assertion failed: CLI grammar suffix-msat` |
| Drop the CLI msat u64 bound | `assertion failed: CLI grammar cli-msat-overflow` |
| Replace a library lemma's proof by a temporary axiom of the same statement | `Bitcoin.Amount.ofSats_msat reaches disallowed axiom Bitcoin.Amount.auditProbe` |

The final restored `lake test` exited **0**. Separate streams are retained under
`.lake/mutation-checks/`; compact command/exit/failure records are committed as
`test-data/mutations.json`. No temporary axiom remains in the library.

### Final validation

On 2026-10-21, with Lean v4.35.0 and `TMPDIR="$TMP_ROOT"`, the following commands
ran in the foreground under the repository's gate supervisor. New files were
staged before the flake check. The combined supervisor returned `EXIT=0`.

| Command | Working directory | Exit |
|---|---|---|
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; all seven counted sets and the axiom summary above |
| `nix flake check -L` | repository root | 0 |
| `nix build && ./result/bin/cyberkrill` | repository root | 0; `cyberkrill 0.1.0` |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages || rc=$?; test "$rc" -eq 1` | repository root | 0; no matches |
| `grep -rn native_decide --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | repository root | 1, expected: no matches; supervising `test "$rc" -eq 1` exited 0 |

The sandbox check built
`/nix/store/bsd4hjywr14qpiff71kf8sql16i901kl-cyberkrill-0.1.0.drv`.
`nix log` on that derivation exited **0** and confirms the new bitcoin sets plus
the existing SHA-256 gate and four vector sets, BOLT11 recovery/signing `16/16`
each, Wycheproof `252 loaded / 95 accepted / 157 rejected`, `http-curl cases:
35/35`, `S12: PASS`, `S13: PASS`, and the link-spike/OpenSSL checks. Lightning,
fedimint-invite and the app built in the same package loop. The app printed
`cyberkrill 0.1.0`. The capture, Unicode check and six-mutation runner commands
and exit codes are recorded in their sections above. No other package,
workflow, flake or tracker change is part of this implementation.

### Deltas not taken

None. The accepted named grammar forms above are retained. No additional policy
bound, input-length cap, whole-sat helper, golden harness or unrelated codec is
added; those belong to their later phases. Tracker updates and commits are made
separately.

## Phase 3a: base58 and Base58Check (2 of 4)

### Public API

Import `Bitcoin.Base58` for `Bitcoin.Base58.base58Encode : ByteArray → String`
and `base58Decode : String → Option ByteArray`. Import `Bitcoin.Base58Check`
for `base58CheckEncode : ByteArray → String` and
`base58CheckDecode : String → Except CheckError ByteArray`, in the same namespace.
The root `Bitcoin` module imports both library modules. The address phase can
import `Bitcoin.Base58Check` directly.

The codec converts between base 256 and base 58 using arbitrary-precision `Nat`,
counting leading zeros separately. The alphabet is
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. Each leading
zero byte becomes one `1`; empty bytes encode as the empty string. Character
lookup compares complete `Char` values, without truncating them to bytes.
Bitcoin Core's `DecodeBase58` skips leading and trailing whitespace; this
decoder rejects all whitespace, including a trailing space.

Base58Check appends `(Sha256.sha256d payload).extract 0 4` before encoding.
The three distinct error constructors are `CheckError.invalidBase58`,
`CheckError.tooShort` (fewer than four decoded bytes), and
`CheckError.checksumMismatch`. Four bytes are sufficient for an empty payload.
**Base58Check gives no error-detection guarantee.** No error-detection theorem
is claimed.

### Copied vectors and independent answers

`Bitcoin/Base58Vectors.lean` contains only `rawVectors`, L29–50 of
[`LeanMiniscript/Bitcoin/KeyEncodingExamples.lean`](https://github.com/febyeji/lean-miniscript/blob/cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd/LeanMiniscript/Bitcoin/KeyEncodingExamples.lean),
`febyeji/lean-miniscript` at `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`.
Its 21 raw Base58 vectors originate in Bitcoin Core's
`src/test/data/base58_encode_decode.json` at
`9be056a8a72b624dae9623b2f7bded92c2a21c91`. They contain no keys and none is
valid Base58Check. The file's first line is:

```text
-- Copied from febyeji/lean-miniscript @ cb9bc5f, LeanMiniscript/Bitcoin/KeyEncodingExamples.lean L29-50; MIT, see LICENSE-miniscript; originally Bitcoin Core src/test/data/base58_encode_decode.json @ 9be056a, MIT
```

The adjacent existing `Bitcoin/LICENSE-miniscript` is upstream's MIT notice,
Copyright (c) 2026 Yeji Han. A comparison with the freshly fetched pinned
LICENSE exited **0**. Integration removes `private` from `rawVectors` and wraps
the slice in `namespace BitcoinTests`; there are no port fixes. No upstream
helpers, WIF, invalid-key or BIP32 vectors are copied. Only the test executable
imports the vector module; `Bitcoin.lean` does not import it. The existing Lake
library layout builds it without a lakefile change.

Each runtime set pins its loaded count and exits nonzero on any failed assertion:

| Set | Pinned count | Source |
|---|---|---|
| `base58 vectors` | 21 | Copied slice above, case-insensitive hex decoded by `Bitcoin.Hex.decode`; both directions checked |
| `base58 leading zeros` | 5 | Hand-derived: empty, one zero, three zeros, `000001` ↔ `112`, `003a` ↔ `121` |
| `base58 invalid characters` | 6 | Our `0`, `O`, `I`, `l`, trailing space, U+0132 cases, each within or beside valid digits |
| `Base58Check known answers` | 4 | Our independently generated empty, leading-zero, all-zero and 40-byte synthetic payloads |
| `Base58Check rejections` | 2 | `111` gives `tooShort`; `3QJmnh` with its last character changed to `i` gives `checksumMismatch` |
| `Base58Check invalid alphabet` | 1 | Trailing space gives `invalidBase58` |

From `packages/bitcoin`, `python3 -I derive-base58check.py --write` and
`python3 -I derive-base58check.py` each exited **0**, reporting
`independent base58 vectors: 21/21` and `independent Base58Check answers: 4/4`.
The script first checks its own small Base58 encoder against all 21 copied
vectors, then uses Python `hashlib` for SHA-256d and writes or verifies
`test-data/base58check.json`. The Lean tests read that file. Expected values
never come from the Lean implementation. Payload lengths are 0, 5, 3 and 40
bytes; none is key- or address-shaped.

### Proofs and axiom audit

All four public theorems have the full required statements:

```lean
base58Decode_encode (b : ByteArray) :
  base58Decode (base58Encode b) = some b
base58Encode_of_decode (s : String) (b : ByteArray)
  (h : base58Decode s = some b) : base58Encode b = s
base58CheckDecode_encode (p : ByteArray) :
  base58CheckDecode (base58CheckEncode p) = .ok p
base58CheckDecode_sound (s : String) (p : ByteArray)
  (h : base58CheckDecode s = .ok p) :
  base58Decode s = some (p ++ (Sha256.sha256d p).extract 0 4)
```

`BitcoinTests/AxiomGate.lean` names all four and prints:

```text
'Bitcoin.Base58.base58Decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Base58.base58Encode_of_decode' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Base58.base58CheckDecode_encode' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Base58.base58CheckDecode_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
Bitcoin axiom gate: 502 library theorems; 42 named; 0 offenders
```

The gate covers both new library modules and all previously imported Bitcoin
modules, with the same three-axiom allowlist and no exemptions. The earlier
section's 146/26 totals describe Phase 3a (1 of 4); the initial Phase 3a (2 of 4)
totals were 226/30. The block above records the current full-library scan.

### Red runs

From `packages/bitcoin`, both
`TMPDIR="$TMP_ROOT" nix develop -c python3 -I check-mutations.py` and
`TMPDIR="$TMP_ROOT" nix develop -c python3 -I check-base58-mutations.py` exited **0**.
The first reruns the six existing mutations. The second changes production
code one property at a time, asserts a diagnostic inside the named theorem or
the runtime assertion below, and restores the source in `finally`.
Every mutated `lake test` exited **1**; both final restored runs exited **0**.

| New production mutation | Observed failure |
|---|---|
| Drop encoder leading zeros | B1, `Bitcoin.Base58.base58Decode_encode`, type mismatch |
| Map `0` to `1` before decoder alphabet lookup | B2, `Bitcoin.Base58.base58Encode_of_decode`, unsolved goals/type mismatch |
| Skip checksum comparison | K2, `Bitcoin.Base58.base58CheckDecode_sound`, application type mismatch |
| Merge short-input error into checksum-mismatch error | `assertion failed: Base58Check rejections short` |
| Use single SHA-256 in the shared checksum helper | K2, `Bitcoin.Base58.base58CheckDecode_sound`, deterministic elaboration timeout at `whnf` inside the theorem |
| Swap `A` and `B` in the shared alphabet | Proofs pass; `assertion failed: base58 vectors 516b6fcd0f` |

Separate stdout/stderr are retained under `.lake/base58-mutation-checks/` and
`.lake/mutation-checks/`. Compact records are in
`test-data/base58-mutations.json` and the regenerated `test-data/mutations.json`.
The single-SHA mutation is caught by K2 before runtime vectors. K2 states the
checksum as the first four bytes of `Sha256.sha256d`, so any checksum change that
alters what the decoder accepts makes K2 false and stops the build. The known
answers are a second, independent check of the same property: for each of their
four payloads, single SHA-256 and the last four bytes of SHA-256d both differ from
the committed checksum (checked with Python `hashlib`).

### Final validation

On 2026-10-21, Lean v4.35.0 (`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`),
with `TMPDIR="$TMP_ROOT"`, all gate commands ran in the foreground under the
repository's supervisor. New files were staged before the flake check; the
combined supervisor returned `EXIT=0`.

| Command | Working directory | Exit |
|---|---|---|
| `nix develop -c lean --version` | `packages/bitcoin` | 0; Lean 4.35.0 |
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; all existing and new counted sets |
| `python3 -I derive-base58check.py` | `packages/bitcoin` | 0; 21/21 and 4/4 |
| `python3 -I check-base58-copy.py "$FETCH_DIR"/KeyEncodingExamples.lean` | `packages/bitcoin` | 0; diff shows only removal of `private` |
| `cmp "$FETCH_DIR"/LICENSE-miniscript Bitcoin/LICENSE-miniscript` | `packages/bitcoin` | 0 |
| `nix flake check -L` | repository root | 0 |
| `nix build && ./result/bin/cyberkrill` | repository root | 0; `cyberkrill 0.1.0` |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | repository root | 0; no matches |
| `grep -rn native_decide --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | repository root | 1, expected; supervising `test "$rc" -eq 1` exited 0 |
| `grep -nE '\[[^]]*\]!\|get!\|head!\|tail!\|getLast!\|panic!\|unreachable!' packages/bitcoin/Bitcoin/Base58.lean packages/bitcoin/Bitcoin/Base58Check.lean` | repository root | 1, expected; supervising `test "$rc" -eq 1` exited 0 |
| `git diff --check` | repository root | 0 |

`nix log /nix/store/5jfcy7d8zf377gm8lwpqrqmydynawiwk-cyberkrill-0.1.0.drv`
exited **0**. Its separate streams are retained under
`packages/bitcoin/.lake/final-checks/nix-log.stdout` and `nix-log.stderr`.
The sandbox log confirms all new Base58 sets, the SHA-256 gate and vector sets,
BOLT11 recovery/signing `16/16` each, Wycheproof
`252 loaded / 95 accepted / 157 rejected`, `http-curl cases: 35/35`,
`S12: PASS`, `S13: PASS`, and the link-spike/OpenSSL checks. All seven packages
built in the package loop, and the app printed `cyberkrill 0.1.0`.
The known-answer generation, both mutation runners and final restored tests
have their commands and exits recorded above.

The pinned upstream file and notice were fetched with `curl -fL` from
`raw.githubusercontent.com/febyeji/lean-miniscript/cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd/`,
paths `LeanMiniscript/Bitcoin/KeyEncodingExamples.lean` and `LICENSE`,
respectively; both fetches exited **0**. After the comparison checks,
these foreground cleanup commands each exited **0**:

```bash
unlink "$FETCH_DIR"/KeyEncodingExamples.lean
unlink "$FETCH_DIR"/LICENSE-miniscript
rmdir "$FETCH_DIR"
test ! -e "$FETCH_DIR"
```

No temporary clone, private dependency cache or external result link was
created for this phase. The repository's `result` link remains available for
the app smoke test.

### Base58 long-input conversion

The executed conversion uses tail loops with proved `@[csimp]` substitutions.
The original definitions remain the specifications:

| Specification | Executed definition | Equality theorem and invariant |
|---|---|---|
| `value` | `valueTR`: Horner left fold over the reversed list | `value_eq_valueTR`, using `value_foldr` and `List.foldl_reverse` |
| `digits` | `digitsTR`: `digitsAux` accumulates reversed digits, then reverses | `digits_eq_digitsTR`; `digitsAux_eq` proves `digitsAux base hb n acc = (digits base hb n).reverse ++ acc` |
| `readChars` | `readCharsTR`: `readCharsAux` accumulates digits, then reverses | `readChars_eq_readCharsTR`; `readCharsAux_eq` proves equality to the original result with the reversed accumulator prefix |

Each substitution precedes its first compiled caller. B1, B2, K1 and K2 keep
their statements. No extra function was changed: `zeroCount` keeps its non-tail
definition and completed both leading-zero paths at one million elements in
the probe below.
No input-length guard or caller-side cap was added: B1 covers every byte array.

Decode time stays quadratic, as in base58ck **0.1.0**, `decode`,
[`src/lib.rs:64–92`](https://docs.rs/crate/base58ck/0.1.0/source/src/lib.rs),
whose per-character multiply-add traverses a base-256 buffer without a length
guard. Bitcoin Core's `DecodeBase58`,
[`src/base58.cpp:40–87` at 9be056a8a72b624dae9623b2f7bded92c2a21c91](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/base58.cpp#L40-L87),
also uses nested multiply-add, with the caller-supplied `max_ret_len` bound
checked at lines 50 and 71. A fresh `curl -fL` fetch of that pinned file exited
**0**; the fetched file was read only and removed afterwards.

The old measurements used a 16 GiB cap shared with other processes. The new
measurements each used their own 8 GiB scope with no swap. Peak memory was not
measured; these records establish completion under that cap and do not identify
the cause of the old kills.

| n | Old `z` decode, exit | New `z` decode, exit | New ones / zero-byte encode |
|---|---|---|---|
| 1,000 | 733 bytes in 1 ms, 0 | 733 bytes in 1 ms, 0 | 1,000 bytes / 1,000 chars |
| 10,000 | 7,323 bytes in 135 ms, 0 | 7,323 bytes in 33 ms, 0 | 10,000 bytes / 10,000 chars |
| 100,000 | 73,225 bytes in 4,451 ms, 0 | 73,225 bytes in 2,700 ms, 0 | 100,000 bytes / 100,000 chars |
| 300,000 | no output, 137 | 219,675 bytes in 24,310 ms, 0 | 300,000 bytes / 300,000 chars |
| 1,000,000 | no output, 137 | 732,248 bytes in 266,130 ms, 0 | 1,000,000 bytes / 1,000,000 chars |

All five commands below ran from `"$TMP_ROOT"` against the final Base58 source,
one at a time, with no build, tests or mutation check concurrent with a probe.
Each command exited **0**; each block contains its full probe stdout. Probe
stderr was empty. The supervisor additionally reported `EXIT=0` for each.

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue timeout 3600 ./.lake/build/bin/probe 1000
```

```text
1000: 733 bytes in 1 ms
1000 ones: 1000 bytes
1000 zero bytes encode: 1000 chars
```

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue timeout 3600 ./.lake/build/bin/probe 10000
```

```text
10000: 7323 bytes in 33 ms
10000 ones: 10000 bytes
10000 zero bytes encode: 10000 chars
```

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue timeout 3600 ./.lake/build/bin/probe 100000
```

```text
100000: 73225 bytes in 2700 ms
100000 ones: 100000 bytes
100000 zero bytes encode: 100000 chars
```

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue timeout 3600 ./.lake/build/bin/probe 300000
```

```text
300000: 219675 bytes in 24310 ms
300000 ones: 300000 bytes
300000 zero bytes encode: 300000 chars
```

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue timeout 3600 ./.lake/build/bin/probe 1000000
```

```text
1000000: 732248 bytes in 266130 ms
1000000 ones: 1000000 bytes
1000000 zero bytes encode: 1000000 chars
```

To repeat, set `REPO` to the repository root and `TMP_ROOT` to a fresh scratch
directory outside it, then paste this recipe. The build command exited **0**
in the recorded check. The unquoted lakefile heredoc expands `"$REPO"`; its
escaped backtick becomes Lean's name quotation. The probe source is unchanged.

```bash
cp "$REPO"/lean-toolchain "$TMP_ROOT"/
cat > "$TMP_ROOT"/lakefile.lean <<EOF
import Lake
open Lake DSL
package probe
require bitcoin from "$REPO/packages/bitcoin"
@[default_target]
lean_exe probe where
  root := \`Main
EOF
cat > "$TMP_ROOT"/Main.lean <<'EOF'
import Bitcoin
open Bitcoin.Base58
def main (args : List String) : IO Unit := do
  let n := args.head!.toNat!
  let s := String.ofList (List.replicate n 'z')
  let t0 ← IO.monoMsNow
  match base58Decode s with
  | none => IO.println s!"{n}: none"
  | some b => IO.println s!"{n}: {b.size} bytes in {(← IO.monoMsNow) - t0} ms"
  let s1 := String.ofList (List.replicate n '1')
  match base58Decode s1 with
  | none => IO.println s!"{n} ones: none"
  | some b => IO.println s!"{n} ones: {b.size} bytes"
  let enc := base58Encode (ByteArray.mk (Array.replicate n 0))
  IO.println s!"{n} zero bytes encode: {enc.length} chars"
EOF
cd "$TMP_ROOT"
TMPDIR="$(dirname "$TMP_ROOT")" nix develop "$REPO" -c lake build
for n in 1000 10000 100000 300000 1000000; do
  systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue timeout 3600 ./.lake/build/bin/probe "$n"
done
```

### Deltas not taken

No stricter v1 acceptance rule, input-length cap, address/network logic, WIF,
BIP32/SLIP-132, or Base58Check error-detection theorem is added. Conversion
retains the same accepted set and outputs. It is not subquadratic.

## Phase 3a: bech32 and bech32m (3 of 4)

### Public API

All names below are in `Bitcoin.Bech32`; `import Bitcoin` imports all three
library modules. They are pure Lean, with no FFI dependencies.

| Module | API and representation |
|---|---|
| `Bitcoin.Bech32` | `Symbol := BitVec 5`; `Variant.bech32` and `.bech32m`, with constants `1` and `0x2bc830a3`; `polymodStep`, `polymod`, `hrpExpand`, `verifyChecksum`, `createChecksum`, and `verifyChecksum_createChecksum` |
| `Bitcoin.Bech32Codec` | `charset`, `charOf`, total `encode hrp data v : String`, ASCII `lower`, `decode limit s : Except DecodeError (String × List Symbol × Variant)`, R and S |
| `Bitcoin.ConvertBits` | `convertbits8to5 : ByteArray → List (BitVec 5)`, strict `convertbits5to8 : List (BitVec 5) → Except PaddingError ByteArray`, `fesToBytesLax : List (BitVec 5) → ByteArray`, C and L |

`polymod : List Nat → BitVec 30` folds left from one. Each step extracts the
top five state bits, shifts the masked low 25 bits by five, XORs the input,
and conditionally XORs the five reference generator constants. There are no
lookup tables. `hrpExpand` returns the character code points shifted right
by five, a zero, then the code points masked by 31.
`verifyChecksum v hrp d` is the one-line residue comparison over the expanded
HRP and all data symbols, including the six checksum symbols. The symbol
type makes the five-bit bound intrinsic.

`encode` preserves the supplied HRP and appends `1`, the payload characters
and six checksum characters. It has no length limit. With a valid HRP that
has no ASCII uppercase letters, its output is lowercase. `decode` uses the
last `1`, accepts all-uppercase strings, lowercases ASCII letters, compares
whole data `Char`s, and returns the payload without its checksum and the
variant whose residue matched. Its rejection order is:

| Order | Rejection | `DecodeError` |
|---|---|---|
| 1 | `s.length > limit` | `tooLong` |
| 2 | Both uppercase and lowercase ASCII letters | `mixedCase` |
| 3 | No separator | `missingSeparator` |
| 4 | Empty HRP | `emptyHrp` |
| 5 | HRP over 83 characters | `hrpTooLong` |
| 6 | HRP code point outside 33–126 | `invalidHrp` |
| 7 | Data or checksum character outside the charset | `invalidCharacter` |
| 8 | Fewer than six data-part symbols | `shortChecksum` |
| 9 | Neither residue matches | `checksumMismatch` |

These nine rejection reasons include the separate HRP maximum at every caller
limit. Empty, then too-long, then invalid-character HRPs follow bech32 **0.11.1**,
`Hrp::parse`, `src/primitives/hrp.rs:83–88` (`MAX_HRP_LEN = 83` at line 20).
That crate counts bytes while this codec counts characters; non-ASCII HRPs are
rejected by both, so the accepted sets agree, although error kinds may differ.

The 8→5 conversion takes bits most-significant first and pads its last group
with zero bits. Strict 5→8 rejects `PaddingError.excessPadding` when at least
five bits remain, then `PaddingError.nonZeroPadding` when any remaining bit
is one. Excess padding takes precedence when both apply. There is no lax
mode flag. `fesToBytesLax` emits every complete byte and drops the remaining
bits without checking either their count or their value.

Later callers import `Bitcoin.Bech32Codec` for the string codec and
`Bitcoin.ConvertBits` for regrouping. Phase 3a (4 of 4) passes limit **90**;
BOLT11 in Phase 5 passes **7089** and uses the strict conversions; LNURL in
Phase 5 passes **1023** and uses `fesToBytesLax`; Phase 6 invites pass
**1023** and reuse `fesToBytesLax_convertbits8to5`. Phase 3b imports
`Bitcoin.Bech32` for the exact `polymod`, `hrpExpand` and `verifyChecksum`,
and `Bitcoin.Bech32Codec` for `decode_sound`. The Phase 3b feasibility lemma
is in `Bitcoin.Bech32Detection`.

### Vectors

`Bitcoin/Bech32Vectors.lean` contains exactly 40 strings extracted from
[bitcoin/bips](https://github.com/bitcoin/bips/tree/130b8e0fa7f30fa45532f080b87b8db27a79e46e)
at `130b8e0fa7f30fa45532f080b87b8db27a79e46e`:

| Path | Lines | Strings |
|---|---|---|
| `bip-0173.mediawiki` | 277–283 | 7 valid bech32 |
| `bip-0173.mediawiki` | 291–302 | 12 invalid bech32 |
| `bip-0350.mediawiki` | 156–162 | 7 valid bech32m |
| `bip-0350.mediawiki` | 167–180 | 14 invalid bech32m |

Its first line is a `--` provenance comment naming the source URL, full
commit, both paths and line ranges, BSD-2-Clause, and the adjacent
`Bitcoin/LICENSE-bips` notice. It has no dual-licence header and contains
only the strings in Lean definitions. The library root does not import it.
No reasons, warning text, address vectors or reference code are copied.

The strings are **extracted and reformatted**: the six `0x20`/`0x7F`/`0x80`
prefixes become code points U+0020/U+007F/U+0080, and the trailing `0xFF`
becomes U+00FF. These are code points in Lean strings, not raw invalid UTF-8
bytes. `check-bech32-copy.py` compares the complete generated file against
those exact line ranges in separately fetched sources, including the
provenance first line. Its `--write` option only creates a previously absent
vector file. The pinned root tree has no licence file; BIP2 links the BSD
licence to `https://opensource.org/license/BSD-2-Clause`. The notice quotes
both BIPs' `Authors:`, `License:` and Copyright sections, followed by the BSD
conditions and disclaimer from that link. Neither BIP supplies a copyright
year or holder line, and the notice does not invent one.

Every set checks its loaded count and runs as runtime assertions in
`lake test`, including in the Nix sandbox:

| Set | Pinned count | Checks |
|---|---|---|
| BIP173 bech32 valid | 7/7 | Variant and re-encoding to ASCII lowercase |
| BIP350 bech32m valid | 7/7 | Variant and re-encoding to ASCII lowercase |
| bech32 cross-variant | 14/14 | All fourteen valid vectors never decode as the other variant |
| BIP173 bech32 invalid | 12/12 | Exact error constructors at limit 90 |
| BIP350 bech32m invalid | 14/14 | Exact error constructors at limit 90 |
| bech32 length limits | 3/3 | `an83…` length is 90, accepted at 90, `tooLong` at 89 |
| bech32 mixed case | 1/1 | `A12uel5l` → `mixedCase` |
| bech32 non-ASCII | 1/1 | U+0132 in the data part → `invalidCharacter` |
| bech32 convertbits | 10/10 | Five hand-derived encodings, two isolated padding errors, lax non-zero padding, strict empty and strict `ff` |
| bech32 HRP maximum | 8/8 | Published 84-character HRPs reject with `hrpTooLong`, and published 83-character HRPs return the correct HRP, empty payload and variant, at both 1023 and 7089 |

The HRP set is last, after `bech32 convertbits`. It uses `bech32Invalid[3]`
and `bech32mInvalid[3]`, whose checksums have residues 1 and `0x2bc830a3`,
and `bech32Valid[2]` and `bech32mValid[2]` for the boundary. The existing
limit-90 expectations are unchanged: the two `an84…` strings still give
`tooLong` because the overall-length check comes first.

The regrouping answers follow directly from splitting binary bytes into
five-bit groups: `ff` is `11111|11100`, `0001` is
`00000|00000|00000|10000`, and `ff00` is `11111|11100|00000|00000`.
`[0]` leaves five zero bits and isolates excess padding. `[0,1]` is
`00000|00001`: it yields byte `00` and remaining bits `01`, isolating
non-zero padding; lax decoding drops those bits and returns exactly `[0]`.

The BIP reasons map to constructors without deviations:

| BIP reason and affected strings | Constructor |
|---|---|
| HRP character out of range: the six prefixed strings | `invalidHrp` |
| Overall max length exceeded: both `an84…` strings | `tooLong` |
| No separator: `pzry9x0s0muk`, `qyrz8wqd2c9m` | `missingSeparator` |
| Empty HRP: `1pzry9x0s0muk`, `10a06t8`, `1qzzfhee`, `1qyrz8wqd2c9m`, `16plkw9`, `1p2gdwpf` | `emptyHrp` |
| Invalid data character: `x1b4n0q5v`, `y1b0jsk6g`, `lt1igcx5c0` | `invalidCharacter` |
| Too short checksum: `li1dgmt3`, `in1muywd` | `shortChecksum` |
| Invalid checksum character: `de1lg7wt` + U+00FF, `mm1crxm3i`, `au1s5cgom` | `invalidCharacter` |
| Checksum calculated over uppercase HRP: `A1G7SGD8`, `M1VUXWEZ` | `checksumMismatch` |

### Proofs and axiom audit

The four named theorems quantify over the public functions:

| Obligation | Theorem | Statement |
|---|---|---|
| R | `decode_encode` | For every `limit`, variant, payload and non-empty HRP with code points 33–126, no ASCII uppercase letters, `hrp.length ≤ 83`, and `hrp.length + data.length + 7 ≤ limit`, decoding its encoding returns exactly `(hrp, data, v)`. There is no restriction on digits or `1`. |
| S | `decode_sound` | Successful `decode limit s = .ok (hrp, data, v)` supplies `chk` of length 6 such that `lower s = hrp ++ "1" ++ String.ofList ((data ++ chk).map charOf)` and `verifyChecksum v hrp (data ++ chk) = true`. The symbols come from `s` itself. |
| C | `convertbits5to8_convertbits8to5` | For every `bs : ByteArray`, `convertbits5to8 (convertbits8to5 bs) = .ok bs`. |
| L | `fesToBytesLax_convertbits8to5` | For every `bs : ByteArray`, `fesToBytesLax (convertbits8to5 bs) = bs`, using the same public encoder as C. |

The checksum proof uses linearity of the reference step and a six-symbol
packing lemma. The regrouping proofs show that packing adds fewer than five
zero bits and that complete-byte decoding drops the incomplete tail.
The new named `#print axioms` outputs are:

```text
'Bitcoin.Bech32.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Bech32.decode_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Bech32.convertbits5to8_convertbits8to5' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Bech32.fesToBytesLax_convertbits8to5' depends on axioms: [propext, Classical.choice, Quot.sound]
Bitcoin axiom gate: 502 library theorems; 42 named; 0 offenders
```

The gate scans all library theorems, including private helpers. Its allowlist
remains exactly `propext`, `Classical.choice`, and `Quot.sound`, with no
exemptions. The new proofs use Lean core only, with no extra axioms or
native proof evaluation.

### Red runs

`nix develop -c python3 -I check-bech32-mutations.py` from
`packages/bitcoin` exited **0**, detecting **18/18** independent mutations.
Every mutated `lake test` exited **1**; the final restored test exited **0**.
The runner checks diagnostics inside the named theorem, or requires the
axiom gate to pass before the specified runtime assertion fails. It restores
each production file in `finally`. Separate streams remain under
`packages/bitcoin/.lake/bech32-mutation-checks`; compact records are in
`packages/bitcoin/test-data/bech32-mutations.json`.

| # | Production mutation | Observed failure |
|---|---|---|
| 1 | First separator instead of last | Private `splitLast_append`, used by R |
| 2 | Skip checksum verification | S, `decode_sound` |
| 3 | Swap reported variants | S, `decode_sound` |
| 4 | Pad incomplete groups with ones | Private `ConvertBits` helper `write_read`, used by C and L |
| 5 | Emit the incomplete lax byte | L, `fesToBytesLax_convertbits8to5` |
| 6 | Change bech32m constant | `BIP350 bech32m valid A1LQFN3A` |
| 7 | Change one generator constant | `BIP173 bech32 valid A12UEL5L` |
| 8 | Swap `q` and `p` in the shared charset | `BIP173 bech32 valid abcdef1…` |
| 9 | Drop the zero from HRP expansion | `BIP173 bech32 valid A12UEL5L` |
| 10 | Remove mixed-case rejection | `bech32 mixed case A12uel5l` |
| 11 | Remove HRP range rejection | `BIP173 bech32 invalid` for U+0020 + `1nwldj5` |
| 12 | Remove empty-HRP rejection | `BIP173 bech32 invalid 1pzry9x0s0muk` |
| 13 | Ignore length limit | `BIP173 bech32 invalid an84…` |
| 14 | Remove short-checksum rejection | S, `decode_sound`, at its six-symbol length proof |
| 15 | Truncate charset input to its low byte | Private `charOf_readChar`, used by S |
| 16 | Remove non-zero-padding rejection | `bech32 convertbits nonzero-padding-only` |
| 17 | Remove excess-padding rejection | `bech32 convertbits excess-padding-only` |
| 18 | Merge empty-HRP into missing-separator error | `BIP173 bech32 invalid 1pzry9x0s0muk` |

The HRP boundary has two additional independent production mutations, outside
the unchanged eighteen-mutation list. Each command below is from
`packages/bitcoin`, with the repository supervisor and separate captured streams:

| Production mutation | Command | Exit | Observed failure |
|---|---|---|---|
| Change the new check from `> 83` to `> 84` | `nix develop -c lake test` | 1 | `uncaught exception: assertion failed: bech32 HRP maximum bech32-84-at-1023` |
| Change the new check from `> 83` to `> 82` | `nix develop -c lake test` | 1 | R, `decode_encode`: `error: Bitcoin/Bech32Codec.lean:264:55: omega could not prove the goal:` and the same diagnostic at `270:52` |

The first mutation printed
`Bitcoin axiom gate: 504 library theorems; 42 named; 0 offenders` before
the runtime assertion. The second stopped in R's two variant branches,
before runtime. Source restoration was in `finally` after each mutation;
the restored `nix develop -c lake test` exited **0**, with
`bech32 HRP maximum: 8/8` and the final 502/42/0 gate. No expectation changed.

The eleven existing runtime reds all report a passing gate with 42 named
theorems and 0 offenders first.
`nix develop -c python3 -I check-mutations.py` and
`nix develop -c python3 -I check-base58-mutations.py` were rerun afterwards:
both exited **0**, each detected **6/6**, and each restored `lake test`
exited **0**. Their current JSON differences are listed with the follow-up
validation below.

### Final validation

Commands ran in the foreground with `TMPDIR="$TMP_ROOT"`, Lean **4.35.0**
(`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`), and the repository gate
supervisor. Separate stdout/stderr files and exact command arrays remain
under `packages/bitcoin/.lake/final-bech32-checks`, with `commands.json`
recording exits. New files were staged before the flake check.

| Command | Directory | Exit |
|---|---|---|
| `nix develop -c lean --version` | root | 0 |
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; all existing and new pinned sets |
| `nix flake check -L` | root | 0 |
| `nix build --no-link --print-out-paths` | root | 0 |
| `/nix/store/zsha1p5k9s3xx86fcjkmcz3hzcgraj1c-cyberkrill-0.1.0/bin/cyberkrill` | root | 0; `cyberkrill 0.1.0` |
| `nix path-info --derivation /nix/store/zsha1p5k9s3xx86fcjkmcz3hzcgraj1c-cyberkrill-0.1.0` | root | 0 |
| `nix log /nix/store/v58irbfp8fxgnan85i192q098b1cvqzw-cyberkrill-0.1.0.drv` | root | 0 |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | root | 0; no matches |
| `grep -rn native_decide --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | root | 1, expected; no matches |
| `grep -nE '\]!\|get!\|head!\|tail!\|getLast!\|panic!\|unreachable!' packages/bitcoin/Bitcoin/Bech32.lean packages/bitcoin/Bitcoin/Bech32Codec.lean packages/bitcoin/Bitcoin/ConvertBits.lean` | root | 1, expected; no matches |
| `python3 -I packages/bitcoin/check-bech32-copy.py "$FETCH_DIR" --write` | root | 0; initial extraction, 40/40 |
| `python3 -I packages/bitcoin/check-bech32-copy.py "$FETCH_DIR"` | root | 0; final comparison, 40/40 |
| `git diff --check 442e885d00225a89edb7286b372de0e888e08d84` | root | 0 |

The sandbox log contains every new set, SHA-256's gate and vector sets,
BOLT11 recovery/signing **16/16** each, Wycheproof
**252 loaded / 95 accepted / 157 rejected**, `http-curl cases: 35/35`,
`S12: PASS`, `S13: PASS`, and the link-spike and one-OpenSSL checks.
All seven packages ran their build/test commands, and the app printed
`cyberkrill 0.1.0`.

### Cleanup

The fetch directory, `$FETCH_DIR` here, was a fresh temporary directory.
Its five `curl -fL <URL> -o <path>` fetches each exited **0**:

| Destination in that directory | URL |
|---|---|
| `bip-0173.mediawiki` | `https://raw.githubusercontent.com/bitcoin/bips/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0173.mediawiki` |
| `bip-0350.mediawiki` | `https://raw.githubusercontent.com/bitcoin/bips/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0350.mediawiki` |
| `bip-0002.mediawiki` | `https://raw.githubusercontent.com/bitcoin/bips/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0002.mediawiki` |
| `root.json` | `https://api.github.com/repos/bitcoin/bips/contents?ref=130b8e0fa7f30fa45532f080b87b8db27a79e46e` |
| `BSD-2-Clause.html` | `https://opensource.org/license/BSD-2-Clause` |

After the final copy comparison, each foreground cleanup command below
exited **0**. No temporary clone, private dependency cache or external Nix
result link was created. Required mutation logs, final validation logs and
normal build outputs remain under the ignored package `.lake/` directory.

```bash
unlink "$FETCH_DIR"/bip-0173.mediawiki
unlink "$FETCH_DIR"/bip-0350.mediawiki
unlink "$FETCH_DIR"/bip-0002.mediawiki
unlink "$FETCH_DIR"/root.json
unlink "$FETCH_DIR"/BSD-2-Clause.html
rmdir "$FETCH_DIR"
test ! -e "$FETCH_DIR"
unlink packages/bitcoin/.lake/bech32-work/Probe.lean
unlink packages/bitcoin/.lake/bech32-work/Bech32.olean
unlink packages/bitcoin/.lake/bech32-work/validate.py
unlink packages/bitcoin/.lake/bech32-work/run-gate.py
rmdir packages/bitcoin/.lake/bech32-work
test ! -e packages/bitcoin/.lake/bech32-work
```

### Deltas not taken

No stricter acceptance check is proposed here. Segwit address semantics,
BOLT11, LNURL and invite semantics remain in their later phases.

## Phase 3a: addresses (4 of 4)

### Public API

`import Bitcoin` includes `Bitcoin.Address`, a pure Lean module. All names
below are in `Bitcoin.Address`. The vector modules are imported only by tests.

| API | Contract |
|---|---|
| `Network` | Exactly `mainnet`, `testnet`, `signet`, `regtest` |
| `WitnessNetwork` | `mainnet`, shared `testnets`, or `regtest`; `hrp` gives `bc`, `tb`, or `bcrt` |
| `Value` | `p2pkh main hash`, `p2sh main hash`, or `witness network version program`; retains the network class, with `BEq` and `DecidableEq` |
| `Value.WellFormed`, `Value.validFor net` | Hash/program validity and the expected-network rule |
| `fromScript net script`, `Value.toScript` | Checked script recognition and parsed-address script construction |
| `encodeScript net script : Except Error String` | Address string, or `noAddress`; segwit output is lowercase and Base58 preserves case |
| `decode net text : Except Error Value` | Checked address parsing, including expected-network validation |
| `decodeScript net text : Except Error ByteArray` | Address to scriptPubKey, with named errors |
| `decodeLegacy text`, `requireNetwork net value` | Public Base58 stage and the same network check used by `decode` |
| `Value.encode` | Total formatter; use checked construction (`fromScript` or `decode`) for well-formed values |

Phases 4a/7c and 8 call `encodeScript` when displaying scriptPubKeys, mapping
`noAddress` to JSON `null`. Phase 5 calls it for fallback scripts and omits the
fallback when it returns `noAddress`. Address inputs in Phases 5 and 8 call
`decodeScript` with the expected `Network`; `networkMismatch` remains distinct.

### Network and script rules

These rules follow rust-bitcoin **0.32.8**, which cyberkrill @ `27cad1f` locks.
References are relative to that crate unless explicitly named otherwise.

| Rule | Source |
|---|---|
| P2PKH: exactly `76 a9 14 <20 bytes> 88 ac`; P2SH: exactly `a9 14 <20 bytes> 87` | `src/blockdata/script/borrowed.rs:200-216`; `src/address/mod.rs:568-604` |
| Witness script: length 4–42, opcode `00` or `51`–`60`, direct push of 2–40 bytes matching the remaining length | `src/blockdata/script/borrowed.rs:178-196` |
| Witness v0: exactly 20 or 32 bytes; v1–16: any 2–40 bytes, including v1/32 P2TR and generic witness programs | `src/blockdata/script/witness_program.rs:45-60` |
| Base58Check payload: one version byte and 20 hash bytes; P2PKH `00`/`6f`, P2SH `05`/`c4`, main/test respectively | `src/blockdata/constants.rs:37-43`; `src/address/mod.rs:833-859` |
| Legacy test versions work on testnet, signet and regtest; main versions only on mainnet | `src/network.rs:50-59`; `src/address/mod.rs:721-728` |
| HRPs: `bc` only mainnet, `tb` testnet/signet, `bcrt` only regtest; HRP comparison is case-insensitive | `src/address/mod.rs:205-226,721-728`; bech32 0.11.1 `src/primitives/hrp.rs:206-218` |
| Segwit: limit 90, non-empty data, version ≤16, bech32 for v0 and bech32m for v1–16, strict 5→8 padding and program lengths | `src/address/mod.rs:818-826`, calling bech32 0.11.1 `segwit::decode`; BIP173/BIP350 |
| Try segwit first; fall back to Base58 on every failed segwit validation except unknown HRP; never fall back on an unknown HRP after otherwise successful segwit validation | `src/address/mod.rs:818-833`, particularly `KnownHrp::from_hrp(hrp)?` |
| Check the expected network only after complete address validation; no trimming | `src/address/mod.rs:773-779,814-863` |

Every other script gives `noAddress`. Errors are values, with no partial indexing
or panics. The port has no `Testnet4`: cyberkrill selects only the four networks
above (`cyberkrill/src/main.rs:1494-1502,2298-2306`). Core's `testnet4` vectors
are tested as testnet because the prefixes and HRP agree.

There is no 50-character legacy guard (`lck-base58-long-input-3qk`), unlike
`src/address/mod.rs:830`. A canonical Base58 representation of a 25-byte body
(21-byte payload plus checksum) cannot exceed 50 characters. Extra leading
`1`s add decoded zero bytes, so cannot evade the exact body length. Omitting
the guard changes cost and error kind, without changing the accepted set.
`Bech32.decode` counts characters where Rust counts bytes; non-ASCII inputs are
rejected by both, so their accepted sets agree. The codec enforces the separate
83-character HRP maximum. For an otherwise valid string at limit 90, that bound
already follows from the separator and six checksum symbols; longer strings
receive `tooLong` first.

The errors intentionally retain useful segwit diagnostics where Rust's `FromStr`
falls through to a legacy error (or its length guard):

| Failure | `Error` constructor |
|---|---|
| Unrecognised script | `noAddress` |
| Empty segwit data; version >16; wrong bech32 variant | `emptyData`; `witnessVersion`; `checksumVariant` |
| Strict regrouping fails | `padding excessPadding` or `padding nonZeroPadding` |
| Invalid witness program length | `programLength` |
| Otherwise valid segwit with unknown HRP | `unknownHrp`, with no legacy fallback |
| Bech32 codec fails, then Base58Check fails | `base58 invalidBase58`, `base58 tooShort`, or `base58 checksumMismatch` |
| Valid Base58Check but wrong payload length or unknown version | `payloadLength` or `unknownVersion` |
| Fully valid address for another network | `networkMismatch`, used for no invalid string |

If segwit semantic validation fails and the Base58 stage succeeds, its parsed
value is used. If both fail, the segwit semantic error is retained. When the
bech32 codec itself fails, the Base58 error is returned. There is no unused
generic bech32 error constructor.

### Vectors

`Bitcoin/AddressVectors.lean` extracts only strings and scriptPubKey hex from
[bitcoin/bips @ 130b8e0fa7f30fa45532f080b87b8db27a79e46e](https://github.com/bitcoin/bips/tree/130b8e0fa7f30fa45532f080b87b8db27a79e46e).
Its first line names that URL, full commit, both paths and line ranges,
BSD-2-Clause, `Bitcoin/LICENSE-bips`, and “extracted and reformatted”. That
notice's extraction note covers both vector files. No reason prose or reference
code was copied. `check-address-copy.py SOURCE_DIRECTORY [--write]` compares the
entire file, provenance included, with exact lines in separately fetched BIPs.

| Runtime set | Source | Pinned count |
|---|---|---|
| BIP350 segwit valid | `bip-0350.mediawiki:186-193` | 8/8 |
| BIP173 v0 valid | `bip-0173.mediawiki:306,307,311` | 3/3 |
| BIP173 v1+ rejected | `bip-0173.mediawiki:308-310`, superseded by BIP350 | 3/3 |
| BIP350 segwit invalid | `bip-0350.mediawiki:197-211` | 15/15 |
| BIP173 segwit invalid | `bip-0173.mediawiki:315-324` | 10/10 |
| Core Base58 addresses | Public P2PKH/P2SH entries below | 22/22 |
| Named network mismatches | `bc` on testnet, main Base58 on testnet, `tb` on regtest | 3/3 |
| `bcrt` known answers | Independently derived encodings of BIP350 L186/L193 scripts | 2/2 |
| Address network matrix | Every BIP350/Core/`bcrt` valid vector × four networks | 128/128 |
| Script negatives | Hand-derived malformed scripts | 9/9 |
| Base58 address negatives | Independently derived synthetic payloads and changed Core checksum | 10/10 |

Every set checks its loaded count and uses runtime assertions in `lake test`,
including in the Nix sandbox. Valid vectors check decoding to the source script
and encoding back to the address (case-insensitively for segwit, exactly for
Base58). Invalid vectors assert the exact constructor on all four networks,
and never mismatch. Matrix expectations are written directly from the network
rule rather than calculated by the implementation's `validFor`.

The vector-to-constructor table uses the source line to identify each string:

| Source lines | Constructor (and earlier rule, where relevant) |
|---|---|
| BIP173 308–310 | `checksumVariant` |
| BIP350 197; BIP173 315 | `unknownHrp` |
| BIP350 198–202 | `checksumVariant` |
| BIP350 203,208; BIP173 316,321 | `base58 invalidBase58` after codec invalid-character/checksum/mixed-case failure |
| BIP350 204; BIP173 317 | `witnessVersion` |
| BIP350 205–207; BIP173 320 | `programLength` |
| BIP350 209 | `padding excessPadding` |
| BIP350 210; BIP173 323 | `padding nonZeroPadding` |
| BIP350 211; BIP173 324 | `emptyData` |
| BIP173 318,319,322 | `checksumVariant` precedes the listed program-length/padding reason: these v1+ strings use superseded bech32 |

The fetched BIP173 and BIP350 files have SHA-256
`b19eab06b264bbd15ad7f7d640fa34de8f4a8809fba8a6ecc3e165545b27a543` and
`63634b06aa8bae88b31929674736e74964c4598684269ac2b0b140c43a7a0dec`.

`Bitcoin/CoreAddressVectors.lean` comes from
[bitcoin/bitcoin @ 9be056a8a72b624dae9623b2f7bded92c2a21c91](https://github.com/bitcoin/bitcoin/tree/9be056a8a72b624dae9623b2f7bded92c2a21c91),
`src/test/data/key_io_valid.json`, SHA-256
`90bd1d35d12763e0d00c5400b2c9fe551e532a821e1e466c20cad3aced70a7fe`.
The first line names that URL, commit, path and MIT notice
`Bitcoin/LICENSE-bitcoin-core`. The notice is Core's verbatim `COPYING` at that
commit, SHA-256 `b028769f3852a9368ab10bd754ff01ebb741f84a2fa658c9aff82a631bc6ecfc`.

`python3 -I generate-core-addresses.py [--write]` fetches into a fresh
temporary directory, verifies the pinned hash, selects only public P2PKH/P2SH
entries, and asserts 22 with chain counts main/testnet4/signet/regtest = 6/6/6/4.
Only address, script and chain enter the vector file. The source contains secret
entries; it never enters the repository or logs, and is deleted in `finally`.
Default mode compares the file with a fresh extraction.

`python3 -I derive-addresses.py [--write]` is network-free and implements its own
small bech32 encoder and Base58Check encoder using Python `hashlib`. It
cross-checks all 11 valid BIP pairs, writes `test-data/address-regtest.json` and
`test-data/address-negatives.json`, or compares them by default. The negatives
cover unknown version `02` with a 20-byte body, every known version with 19- and
21-byte bodies, and a one-character checksum change to a Core address. Script
negatives cover v0/25 bytes, v1/1 and v1/41 bytes, non-version opcodes `50` and
`61`, a wrong push length, near-miss P2PKH/P2SH, and the empty script.

### Proofs and axiom audit

All statements quantify over public functions, every network, and every hash or
program of the stated size. F1 includes successful recognition in its conclusion.

| Obligation | Theorem | Statement |
|---|---|---|
| F1, P2PKH/P2SH | `p2pkh_script_roundtrip`, `p2sh_script_roundtrip` | For every 20-byte hash, `(fromScript net template).map Value.toScript = .ok template` |
| F1, witness | `witness_script_roundtrip` | The same equality for every `validProgram version program`, covering v0/20, v0/32, P2TR and all generic v1–16 programs |
| F2, segwit | `witness_string_roundtrip` | Encoding every valid witness template succeeds with a string whose `decodeScript net` is the original script |
| F2, legacy | `p2pkh_string_roundtrip`, `p2sh_string_roundtrip` | Encoding every 20-byte-hash template succeeds; `decodeLegacy`, then `requireNetwork net`, then `toScript` recovers that script |
| F2, link | `decode_of_bech32_error` | If `Bech32.decode 90 text` fails, `decode net text = (decodeLegacy text).bind (requireNetwork net)` |
| R, parsed-value form | `fromScript_toScript` | For every well-formed `a` valid on `net`, `fromScript net a.toScript = .ok a` |

The legacy round trip uses the Base58 stage because a Base58 string could also
be a single-case, checksummed segwit string with an unknown HRP. The general
decoder must reject that collision class without falling back, like rust-bitcoin.
The link theorem covers every Base58 string whose bech32 codec parse fails,
without imposing any extra hypothesis on the Base58 stage's round trip. No
assumption about SHA-256d outputs rules out the collision class.

The new `#print axioms` results are:

```text
'Bitcoin.Address.p2pkh_script_roundtrip' depends on axioms: [propext]
'Bitcoin.Address.p2sh_script_roundtrip' depends on axioms: [propext]
'Bitcoin.Address.witness_script_roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Address.witness_string_roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Address.p2pkh_string_roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Address.p2sh_string_roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Address.decode_of_bech32_error' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Address.fromScript_toScript' depends on axioms: [propext, Classical.choice, Quot.sound]
Bitcoin axiom gate: 502 library theorems; 42 named; 0 offenders
```

The gate imports the library root and scans every library theorem, including
helpers. The allowlist remains exactly `propext`, `Classical.choice`, `Quot.sound`,
with no exemptions. The address proofs use the additive
`convertbits8to5_length` lemma. The sole caller of Bech32's `decode_encode`,
private `decode_witness_encode`, discharges the new HRP bound by the three
literal HRPs `bc`, `tb`, and `bcrt`. Its statement and every public address
theorem statement remain unchanged.

### Red runs

`nix develop -c python3 -I check-address-mutations.py` from `packages/bitcoin`
exited **0**, detecting **20/20** independent production mutations. Every
mutated `lake test` exited **1**; restored tests exited **0**. The runner restores
the file in `finally`, saves separate streams in `.lake/address-mutation-checks`,
and records compact evidence in `test-data/address-mutations.json`.

| # | Mutation | Observed failure |
|---|---|---|
| 1 | P2PKH terminal template byte | `fromScript_p2pkh` |
| 2 | P2SH terminal template byte | `fromScript_p2sh` |
| 3 | Witness opcode mapping | `fromScript_witness` |
| 4 | Mainnet P2PKH version byte | `decodeLegacy_p2pkh` |
| 5 | Legacy test class invalid on regtest | `p2pkh_string_roundtrip` (also P2SH) |
| 6 | Regtest HRP becomes `tb` | `decode_witness_encode`, used by witness F2 |
| 7 | Merge mismatch into unknown-version error | Named `bc-on-testnet` mismatch assertion |
| 8 | Unknown HRP becomes mismatch | BIP350 L197 |
| 9 | Accept bech32 for v1+ | BIP173 L308 |
| 10 | Accept bech32m for v0 | BIP350 L201 |
| 11 | Remove explicit witness-version bound | BIP350 L204: `witnessVersion` changes to `programLength` |
| 12 | Remove v1+ program-length bounds | BIP350 L205 |
| 13 | Remove v0's 20/32 length rule | BIP350 L207 |
| 14 | Use lax regrouping on strict failure | BIP350 L209 |
| 15 | Treat empty data as version zero and no program | BIP350 L211: `emptyData` changes to `programLength` |
| 16 | Accept longer Base58 payloads | Synthetic version-0/body-21 assertion |
| 17 | Map unknown Base58 version to main P2PKH | Synthetic unknown-version assertion |
| 18 | Recognise v0 scripts of any program length | Script-negative v0/25 assertion |
| 19 | Hard-code mainnet decoding | `decode_witness_encode` (also the link theorem) |
| 20 | Check recognised HRP/network before witness semantics | BIP173 L308 on a nonmatching network |

All thirteen runtime reds report a passing 42-named axiom gate first. No
property was classified as redundant. In rows 11 and 15 another check still
rejects the input, but the exact-constructor assertions distinguish the rules.
The earlier `check-mutations.py`, `check-base58-mutations.py` and
`check-bech32-mutations.py` were rerun afterwards: exits **0**, detecting
**6/6**, **6/6**, and **18/18**, respectively. Each restored `lake test`
exited **0**. Current diagnostic-location and message differences are recorded
in the follow-up validation below; the mutation lists and expected failures
are unchanged.

### Final validation

Commands ran in the foreground with `TMPDIR="$TMP_ROOT"`, Lean **4.35.0**
(`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`), and the repository's gate
supervisor. Files were staged before the flake check. Separate stdout/stderr
and exact command arrays with exits remain in
`packages/bitcoin/.lake/final-address-checks/commands.json` and its adjacent logs.

| Command | Directory | Exit |
|---|---|---|
| `nix develop -c lean --version` | root | 0 |
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; every pinned set |
| `nix flake check -L` | root | 0 |
| `nix build --no-link --print-out-paths` | root | 0 |
| `/nix/store/rrbpfdjww1lfdffa9w1i9ppm39knmd1x-cyberkrill-0.1.0/bin/cyberkrill` | root | 0; `cyberkrill 0.1.0` |
| `nix path-info --derivation /nix/store/rrbpfdjww1lfdffa9w1i9ppm39knmd1x-cyberkrill-0.1.0` | root | 0 |
| `nix log /nix/store/r3z3wkb4ff1yknq73x7vy6ipsrwlfm0i-cyberkrill-0.1.0.drv` | root | 0 |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | root | 0; no matches |
| `grep -rn native_decide --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | root | 1, expected; no matches |
| `grep -nE '\]!\|get!\|head!\|tail!\|getLast!\|panic!\|unreachable!' packages/bitcoin/Bitcoin/Address.lean` | root | 1, expected; no matches |
| `python3 -I packages/bitcoin/check-address-copy.py "$BIPS_DIR" --write` | root | 0; initial extraction |
| `python3 -I packages/bitcoin/check-address-copy.py "$BIPS_DIR"` | root | 0; fresh BIP comparison, 39/39 |
| `python3 -I packages/bitcoin/generate-core-addresses.py --write` | root | 0; initial extraction |
| `python3 -I packages/bitcoin/generate-core-addresses.py` | root | 0; fresh Core comparison, 22/22 |
| `python3 -I packages/bitcoin/derive-addresses.py --write` | root | 0; initial derivation |
| `python3 -I packages/bitcoin/derive-addresses.py` | root | 0; comparison, 11 BIP pairs, 2 regtest, 10 negatives |
| `cmp packages/bitcoin/Bitcoin/LICENSE-bitcoin-core "$BIPS_DIR"/COPYING` | root | 0; fresh notice fetch |
| `git diff --check 73eedf608e59d7b4d404b729ab1b53462b2b6096` | root | 0 |
| `nix develop -c python3 -I check-address-mutations.py` | `packages/bitcoin` | 0; 20/20 |
| `nix develop -c python3 -I check-mutations.py` | `packages/bitcoin` | 0; 6/6 |
| `nix develop -c python3 -I check-base58-mutations.py` | `packages/bitcoin` | 0; 6/6 |
| `nix develop -c python3 -I check-bech32-mutations.py` | `packages/bitcoin` | 0; 18/18 |

The sandbox log shows all seven packages building and testing, all new address
sets, both axiom gates, BOLT11 recovery/signing **16/16** each, Wycheproof
**252 loaded / 95 accepted / 157 rejected**, `http-curl cases: 35/35`,
`S12: PASS`, `S13: PASS`, the link spike and one-OpenSSL checks, and
`cyberkrill 0.1.0`. The final restored package test ran after all mutation suites.

The staged secret-pattern scan is:

```bash
git diff --cached -U0 | grep '^+' | grep -n -E '[xt]prv|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
```

It printed **nothing** on either stream and exited **1** (no matches).

### Cleanup

The initial Core generator and fresh comparison removed these paths, with each
operation exiting **0**:

```bash
unlink "$CORE_DIR_1"/key_io_valid.json
rmdir "$CORE_DIR_1"
unlink "$CORE_DIR_2"/key_io_valid.json
rmdir "$CORE_DIR_2"
```

The initial and final `curl -fL <URL> -o <path>` commands each exited **0**:

| Path | URL |
|---|---|
| `"$BIPS_DIR"/bip-0173.mediawiki` | `https://raw.githubusercontent.com/bitcoin/bips/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0173.mediawiki` |
| `"$BIPS_DIR"/bip-0350.mediawiki` | `https://raw.githubusercontent.com/bitcoin/bips/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0350.mediawiki` |
| `"$BIPS_DIR"/COPYING` | `https://raw.githubusercontent.com/bitcoin/bitcoin/9be056a8a72b624dae9623b2f7bded92c2a21c91/COPYING` |

After the final comparisons, each command below exited **0**:

```bash
unlink "$BIPS_DIR"/bip-0173.mediawiki
unlink "$BIPS_DIR"/bip-0350.mediawiki
unlink "$BIPS_DIR"/COPYING
rmdir "$BIPS_DIR"
unlink packages/bitcoin/.lake/address-work/validate.py
unlink packages/bitcoin/.lake/address-work/gate-template.bash
rmdir packages/bitcoin/.lake/address-work
```

All three fetch directories and the scratch directory were checked absent. No
copy of the secret-bearing Core source created by this phase remains. Required
mutation streams, final validation logs and ordinary build outputs remain under
`.lake/`. No reference clone, private dependency cache or external Nix result link
was created for this phase. Gate commands use `TMPDIR="$TMP_ROOT"`; their supervisor
removes its private files and directory before reporting the final status.

### Deltas not taken

Base58 conversion uses proved tail loops without a length guard
(`lck-base58-long-input-3qk`); decode time stays quadratic, as in base58ck 0.1.0
and Bitcoin Core. The 300,000- and 1,000,000-character probes each exited **0**
under their own 8 GiB scope, yielding **219,675 bytes in 24,310 ms** and
**732,248 bytes in 266,130 ms**, respectively; the Base58 section records all five
probes and the rerun recipe. A Base58 fallback after unknown
HRP would make an unrestricted legacy round trip through `decode` possible, but would accept strings that
rust-bitcoin and cyberkrill reject; that exit-parity change requires the owner.
No additional stricter v1 check is proposed: generic v1–16 witness programs
retain rust-bitcoin's 2–40-byte rule.

## Phase 3a follow-up validation

The 2026-10-22 Base58 and HRP checks use Lean **4.35.0**, the repository's
supervisor, foreground commands, and separately captured stdout/stderr.
The five probe records and both HRP
boundary mutations are above. The final package build and test each exited
**0**, with every existing set at its pinned count, plus
`bech32 HRP maximum: 8/8`:

```text
Bitcoin axiom gate: 502 library theorems; 42 named; 0 offenders
```

All sixteen named axiom-output lines in the Base58, bech32 and address blocks
were compared against the final output and `63e561f`: **none changed**. The
three blocks now show the final gate count. The named list remains at 42;
the scan also includes the new private equality lemmas.

In the earlier check, from `packages/bitcoin`, each of these commands exited
**0**, detected the listed count, and ended with a restored `lake test` at exit
**0**. These results describe the unchanged sources; the mutation commands
were not repeated for the documentation update:

| Command | Detected |
|---|---|
| `nix develop -c python3 -I check-mutations.py` | 6/6 |
| `nix develop -c python3 -I check-base58-mutations.py` | 6/6 |
| `nix develop -c python3 -I check-bech32-mutations.py` | 18/18 |
| `nix develop -c python3 -I check-address-mutations.py` | 20/20 |

The regenerated JSON was compared field by field against
`63e561f36fcc1dd211dd560f9df05e0bea658286`. Command arrays, labels, exits,
broken theorems, assertion text and gate classifications are unchanged.
`test-data/mutations.json` is byte-identical. The differences in the other
three records are exactly:

| Record and mutation | Old → new diagnostic positions |
|---|---|
| `base58-mutations.json`, `drop-leading-zeros` | Lines 286→347, 297→358, 311→372 (all three columns on line 311); columns and messages unchanged |
| `base58-mutations.json`, `admit-zero` | Lines 288→349, 296→357 (both columns), 299→360; columns and messages unchanged |
| `address-mutations.json`, `mainnet-base58-version` | 310:17→311:17 |
| `address-mutations.json`, `legacy-regtest-network` | 352:2→353:2, 362:2→363:2 |
| `address-mutations.json`, `ignore-expected-network` | 368:71→369:71 |
| `bech32-mutations.json`, `skip-checksum` | 167:51→172:53, 259:12→270:52, 258:20→264:20, 264:10→270:10, 264:17→270:17 |
| `bech32-mutations.json`, `swapped-variants` | 167:75→172:77, 170:78→175:80, 258:11→264:55, 259:12→270:52 |
| `bech32-mutations.json`, `allow-short-checksum` | 176:18→181:20 |

The Base58 shifts follow the 61 inserted lines; the address shifts follow the
one-line proof discharge. The bech32 S proof gained the HRP rejection branch,
moving its diagnostics five lines and two indentation columns. R gained its
bound and now finishes each variant with `simp` followed by `omega`. Its
`skip-checksum` diagnostic at 270:52 and `swapped-variants` diagnostics at
264:55 and 270:52 therefore say `omega could not prove the goal:` instead of
`unsolved goals`. Those three message changes and the listed columns are the
only differences beyond line numbers. The named failure for both mutations
remains S, including its application-type-mismatch diagnostic.

Final commands and observed exits are below. The `nix build` and source-scan
rows are from the earlier check of the unchanged sources; the other commands
were rerun for this documentation update.

| Command | Directory | Exit |
|---|---|---|
| `nix develop -c lean --version` | root | 0; 4.35.0, commit `eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, Release |
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; all pinned sets and 502/42/0 gate |
| `nix flake check -L` | root | 0; existing derivation, `running 0 flake checks...`; build log retrieved below |
| `nix build --no-link --print-out-paths` | root | 0; earlier check |
| `nix log /nix/store/2dq1q14dvddssv3rkfi73h9qjh7782zj-cyberkrill-0.1.0.drv` | root | 0; includes HRP maximum 8/8 and 502/42/0 gate |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | root | 0; no matches, earlier check |
| `grep -rn native_decide --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | root | 1; no matches, earlier check |
| `grep -rn bv_decide --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | root | 1; no matches, earlier check |
| `grep -nE '\]!\|get!\|head!\|tail!\|getLast!\|panic!\|unreachable!' packages/bitcoin/Bitcoin/Base58.lean packages/bitcoin/Bitcoin/Base58Check.lean packages/bitcoin/Bitcoin/Bech32Codec.lean packages/bitcoin/Bitcoin/Address.lean` | root | 1; no matches, earlier check |
| `git diff --check 63e561f` | root | 0 |

The statement check extracts each header from `theorem` through `:= by`,
compares the worktree bytes to `git show 63e561f:<path>`, and requires equality
for B1, B2, K1, K2, S, C, L, private `decode_witness_encode`, and the eight
public address theorems. For R it requires equality after removing exactly
`(maxHrp : hrp.length ≤ 83)` and its indentation/newline. This comparison was
repeated for the documentation update and exited **0**. The only caller
found by `rg -n decode_encode packages --glob '*.lean' --glob '!**/.lake/**'`
(exit **0**), beyond declarations and axiom-print references, is the private
address proof at `Bitcoin/Address.lean:276`.

The sandbox log records the new HRP set at **8/8**, all other pinned Bitcoin
sets, the 502/42/0 gate, the SHA-256 gate, BOLT11 recovery/signing **16/16**
each, Wycheproof **252 loaded / 95 accepted / 157 rejected**, all seven
packages' build/test steps, `http-curl cases: 35/35`, `S12: PASS`, `S13: PASS`,
the link spike, one-OpenSSL checks, and `cyberkrill 0.1.0`. The build output is
`/nix/store/qv3krg94mqq9hclpgfl3lkfbdmrsv8rc-cyberkrill-0.1.0`; no result
link was created.

The final public-text scan of added lines in
`git diff 63e561f -- README.md packages` printed only the six probe command
lines (five measurements and one loop form), with no other matches.
`git diff --name-only 63e561f` lists the four Lean/test files, three mutation
records, README and `.beads/issues.jsonl`.
The Base58 source SHA-256 stayed
`0e9c396955f0e144ca05c9f4fd115cf296a25a02c153b95c33f02a568664455e`
after all five probes. Peak memory remains unmeasured; no extra conversion
function or fallback was needed.

### Follow-up cleanup

`TMP_ROOT` was the fresh probe package and `CORE_FETCH_DIR` the fresh Core
source fetch directory. Each exact-path command below exited **0**:

```bash
unlink "$CORE_FETCH_DIR"/base58.cpp
rmdir "$CORE_FETCH_DIR"
rm -r -- "$TMP_ROOT"
test ! -e "$TMP_ROOT"
test ! -e "$CORE_FETCH_DIR"
```

The probe work created only those two external directories. No reference
clone, private dependency cache or Nix result link was created. The gate
supervisor removed each of its private files with `unlink` and its directory
with `rmdir` before reporting the recorded status. Ordinary build
outputs remain in ignored `.lake/` directories. The probe directory's package
links were removed as links; their repository targets were preserved.

## Phase 3b: four-data-error feasibility spike (1 of 2)

**Verdict: stop.** The full per-variant theorem retains the data-length bound
**6–89**, substitutions in **1–4** positions, and five-bit symbols, including
checksum symbols. The decoder corollary counts differences in lowercase
charset indices. The theorem is not proved by this spike, and no weaker
statement is proposed.

The [proof plan](packages/bitcoin/docs/bech32-4-error-plan.md) specifies every
reduction from `decode_sound` through affine cancellation, distance columns,
shift normalization, binary elimination and checker soundness to the precise
finite fact. It includes the complete scratch sources, commands, version,
host, the measured split run and the length-90 failure. The experiment
checker and its soundness proof are not library additions.

`Bitcoin.Bech32Detection` adds
`Bitcoin.Bech32.verifyChecksum_residue_eq`, imported by `Bitcoin`. Its statement
is:

```lean
theorem verifyChecksum_residue_eq (v : Variant) (hrp : String) (d d' : List Symbol)
    (valid : verifyChecksum v hrp d = true) (valid' : verifyChecksum v hrp d' = true) :
    polymod (hrpExpand hrp ++ d.map BitVec.toNat) =
      polymod (hrpExpand hrp ++ d'.map BitVec.toNat)
```

This is the reduction from acceptance under the same variant to equal
residues. Its proof uses the real `verifyChecksum` and `polymod`; existing
definitions, theorem statements and private visibility are unchanged.
`nix develop -c lake env lean -Dprofiler=true Bitcoin/Bech32Detection.lean`
exited **0**, reporting **0.312 ms** cumulative type checking (**1.515 s**
whole command). No profiler option is retained in the source.

```text
'Bitcoin.Bech32.verifyChecksum_residue_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
Bitcoin axiom gate: 503 library theorems; 43 named; 0 offenders
```

The checker uses twenty binary columns for four normalized error positions,
with a literal column table certified equal to the real `polymodStep` columns
once per file. The full count is `C(88,3) = 109736`.

The budget is the wall time the theorem adds to `nix flake check` on the
public Linux CI runner (4 CPUs, 16 GB RAM), with the finite check split into
chunk files built at most four at a time. The complete split check was run,
not extrapolated: 220 files (219 of 500 units and one of 236), each checked
directly with `lean -Dprofiler=true`, four at once, in one 12 GiB memory-capped
scope.

| Measure | Value |
|---|---|
| Files passing | **220/220**, each exit 0; every `checked` depends only on `propext` |
| Coverage | exactly `triples 89`: 109,736 units, no gap, duplicate or extra; a red run with one unit removed fails |
| Four-way wall time | **1,198.049 s** against **600 s** |
| Scope memory peak | **6.2G**, exit 0, no OOM or timeout |
| Scope CPU time | **4,435 s**, about 3.7 cores busy |
| Per-file wall time | 8.1–33.4 s |
| Starting load | 18.37 / 23.03 / 15.72 on 16 logical CPUs |

The run was measured under load from other work on the host, so its wall
time is inflated, but CPU time divided by four is already about 1,109 s. The
CI runner's per-core speed is unmeasured. The per-file records are in
[bech32-4-error-chunks.tsv](packages/bitcoin/docs/bech32-4-error-chunks.tsv);
the chunk files are not committed. The reduction, checker soundness, coverage
and assembly proofs remain unmeasured and are excluded from that time.
Mathlib is unnecessary, so no `bitcoin-proofs` package or flake input is added.

The same checker on distances **{0,14,79,89}** exited **1** with:

```text
Tactic `decide` proved that the proposition
  checkSets [(14, 79, 89)] = true
is false
```

The following accepted records describe the earlier validation of the frozen
library change; the mutation commands were not repeated for the split
measurement, which left the library files unchanged. A separate temporary axiom replacing the new lemma's proof made
`nix develop -c lake test` exit
**1** at the allowlist check:

```text
BitcoinTests/AxiomGate.lean:67:0: Bitcoin axiom gate: Bitcoin.Bech32.verifyChecksum_residue_eq reaches disallowed axiom Bitcoin.Bech32.residue_eq_test
```

Removing the axiom and restoring the proof made the same command exit **0**.
The lemma's name was unchanged during this test.

All four foreground mutation commands from `packages/bitcoin` exited **0**:

| Command | Detected | Restored `lake test` exit |
|---|---:|---:|
| `nix develop -c python3 -I check-mutations.py` | 6/6 | 0 |
| `nix develop -c python3 -I check-base58-mutations.py` | 6/6 | 0 |
| `nix develop -c python3 -I check-bech32-mutations.py` | 18/18 | 0 |
| `nix develop -c python3 -I check-address-mutations.py` | 20/20 | 0 |

The **only** edits to the runners are their two pinned-count literals:
`42 named; 0 offenders` becomes `43 named; 0 offenders` in the bech32 and
address runners. Every mutation target, replacement and expected theorem or
assertion is unchanged. The new proof checks under the existing runtime
mutations, including generator and variant-constant changes.

Only one regenerated diagnostic moved: `test-data/mutations.json`, record
`axiom`, `BitcoinTests/AxiomGate.lean:66:0` → **67:0**. No other diagnostic,
detection kind, exit or record field changed. The Base58, bech32 and address
JSON files are byte-identical to `f072301`.

Final validation, after the split measurement. From `packages/bitcoin`, each
of these exited **0**:

```bash
nix develop -c lean --version
nix develop -c lake build
nix develop -c lake test
```

The version output was Lean **4.35.0**, commit
`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, Release. All pinned Bitcoin sets
passed unchanged, including HRP maximum **8/8**, address network matrix
**128/128**, and the **503/43/0** gate.

From the repository root, after the last edit under `packages/`:

| Command | Exit | Observation |
|---|---:|---|
| `nix eval --raw .#checks.x86_64-linux.default.drvPath` | 0 | derivation below |
| `nix flake check -L` | 0 | 135.356 s when first built; a repeat reused that build |
| `nix config show sandbox` | 0 | `true` |
| `nix build --no-link` | 0 | existing build, no result link |
| `nix log /nix/store/gqfvx3cmvz291r1j1z3wwzkjx43sc0aj-cyberkrill-0.1.0.drv` | 0 | log retrieved |

The evaluated and built derivation is:

```text
/nix/store/gqfvx3cmvz291r1j1z3wwzkjx43sc0aj-cyberkrill-0.1.0.drv
```

Its log contains:

```text
info: BitcoinTests/AxiomGate.lean:67:0: Bitcoin axiom gate: 503 library theorems; 43 named; 0 offenders
info: BitcoinTests/AxiomGate.lean:112:0: 'Bitcoin.Bech32.verifyChecksum_residue_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
```

`sha256sum -c` against the six library digests recorded before the split
measurement exited **0**:

```text
packages/bitcoin/Bitcoin/Bech32Detection.lean: OK
packages/bitcoin/Bitcoin.lean: OK
packages/bitcoin/BitcoinTests/AxiomGate.lean: OK
packages/bitcoin/check-bech32-mutations.py: OK
packages/bitcoin/check-address-mutations.py: OK
packages/bitcoin/test-data/mutations.json: OK
```

The unchanged-tree check printed nothing and exited **0**:

```bash
git diff --exit-code f0723015b70823a0f9d3edab854ec0e379819f31 -- packages/bitcoin \
  ':(exclude)packages/bitcoin/docs' \
  ':(exclude)packages/bitcoin/Bitcoin/Bech32Detection.lean' \
  ':(exclude)packages/bitcoin/Bitcoin.lean' \
  ':(exclude)packages/bitcoin/BitcoinTests/AxiomGate.lean' \
  ':(exclude)packages/bitcoin/check-bech32-mutations.py' \
  ':(exclude)packages/bitcoin/check-address-mutations.py' \
  ':(exclude)packages/bitcoin/test-data/mutations.json'
```

These policy gates each exited **0**; the searches printed nothing and
returned **1**, as required:

```bash
rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages || rc=$?; test "$rc" -eq 1
rc=0; grep -rnE 'native_decide|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean || rc=$?; test "$rc" -eq 1
git diff --check f0723015b70823a0f9d3edab854ec0e379819f31
```

The chunk files and the measurement's scratch directory, written here as
`"$TMP_ROOT"`, were removed with `rm -r -- "$TMP_ROOT"`, and
`test ! -e "$TMP_ROOT"` exited **0**. No reference clone or Mathlib source was
created. The experiment sources remain fenced in the proof plan.

## Phase 4a: transactions and PSBT (1 of 3)

`import Bitcoin` now includes transaction wire serialization/deserialization,
strict padded Base64, and BIP174 v0, BIP370 v2 and BIP371 PSBT framing and typed
fields. This package still imports only pure Lean and `sha256`, with no FFI,
Mathlib, sighash or PSBT role modules.

### API and supplied operations

| Module / namespace | Public interface |
|---|---|
| `Bitcoin.Transaction` / `Bitcoin` | `OutPoint`, `TxInput`, `TxOutput`, `Transaction`, `serializeOutPoint`, `serializeTxInput`, `serializeTxOutput`, `serializeTransaction`, `Transaction.signedVersion` |
| `Bitcoin.Deserialization` / `Bitcoin` | `readOutPoint`, `readTxInput`, `readTxOutput`, `readWitnessStack`, `WitnessTransaction`, `readTransaction`, `parseTransaction bytes (allowWitness := true)`, `serializeWitnessTransaction`, `Transaction.txid` |
| `Bitcoin.Base64` | `encode`, `decode`: RFC4648 standard alphabet, mandatory canonical padding |
| `Bitcoin.Psbt.Codec` / `Bitcoin.Psbt` | `Record`, `KeyValueMap`, `Psbt`, `PsbtError`, framing, `Record.WellFormed`, `KeyValueMap.Unique`, `KeyValueMap.WellFormed`, `Psbt.WellFormed`, `Psbt.encode`, `Psbt.serialize`, `decodePsbtWith` |
| `Bitcoin.Psbt.Fields` / `Bitcoin.Psbt` | Typed global/input/output fields, `Psbt.parse cap hashes bytes`, `p.decode cap hashes`, `Psbt.parseBase64 cap hashes text`, `p.toBase64`, `DecodedPsbt`, `determineLocktime`, `DecodedPsbt.unsignedTransaction` |
| `Bitcoin.Psbt.Capability` / `Bitcoin.Psbt` | `PubkeyCapability` supplies `isValidPubkey`, `isValidXOnlyPubkey`, `isValidDerSignature : ByteArray → Bool` and `compressPubkey : ByteArray → Option ByteArray`; `PreimageHashes` supplies `ripemd160` and `hash160` as one argument |
| `Bitcoin.Psbt.SamePoint` / `Bitcoin.Psbt` | `p.checkBip32SamePoint cap : Except PsbtError Unit`, with `duplicateBip32Point scope first second` retaining both raw key-data encodings |

SHA256 preimages call `Sha256.hash`; HASH256 preimages and transaction identifiers
call `Sha256.sha256d`. RIPEMD160 and HASH160 preimage checks call the supplied
parameter; Phase 4a (2 of 3) supplies their implementations. The strict
curve check handles partial-signature keys and global xpub points; x-only
validation handles Taproot keys and control-block internal keys, and DER
validation handles partial-signature values without their sighash byte.
Successful compression handles input
and output BIP32 derivation keys, including matching-parity hybrids.
`Secp256k1.compressPubkey` supplies that operation for later application wiring.

The PSBT library keeps every key's raw bytes, including 04 and hybrid BIP32
encodings. Framing rejects repeated raw keys. rust-bitcoin 0.32.8 instead rewrites
BIP32 keys to 33-byte compressed encodings. The separate point check walks the raw
input and output maps in wire order, starting a fresh point set in each map. It
returns the first colliding pair and the scope (`"input"` or `"output"`), without
pooling across maps. It ignores partial signatures and globals. A malformed key
propagates its decoding error; a rejected BIP32 key returns `invalidKey`, just as
parsing with that capability would. `parse` does not call the point check; the app
will call it separately in a later phase. This preserves the intended raw-byte
round-trip semantics for the later proof task.

### Exact copied slices and provenance

Source: [febyeji/lean-miniscript at cb9bc5f](https://github.com/febyeji/lean-miniscript/tree/cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd),
MIT, Copyright (c) 2026 Yeji Han. A fresh temporary checkout's `git rev-parse HEAD`
printed `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`, exit **0**.
`cmp packages/bitcoin/Bitcoin/LICENSE-miniscript "$TMP_ROOT"/miniscript/LICENSE`
exited **0**: the existing MIT notice is reused unchanged.

| Destination under `packages/bitcoin` | Source under `LeanMiniscript/` |
|---|---|
| `Bitcoin/ByteArrayRepr.lean` | `Script/Syntax.lean` L1–2 only |
| `Bitcoin/Transaction.lean` | `Bitcoin/Transaction.lean` L1–55 |
| `Bitcoin/Deserialization.lean` | `Bitcoin/Deserialization.lean` L81–170 |
| `Bitcoin/DeserializationProofs.lean` | `Bitcoin/DeserializationProofs.lean` L180–232 |
| `Bitcoin/Base64.lean` | `Bitcoin/Base64.lean` L1–79 |
| `Bitcoin/Psbt/Codec.lean` | `Psbt/Codec.lean` L1–157 |
| `Bitcoin/Psbt/Fields.lean` | `Psbt/Fields.lean` L1–582 |
| `Bitcoin/PsbtVectors.lean` (tests only) | `Psbt/Fixtures.lean` L8–70 and L95–178, byte-exact lists inside a namespace wrapper |

The earlier whole serialization file, initial reader slice and eleven proofs
remain in `Bitcoin.CompactSize`. It is the **only CompactSize codec**. The new
transaction namespace is `Bitcoin`; the new PSBT namespace is `Bitcoin.Psbt`;
the earlier `Bitcoin.CompactSize` namespace is opened where needed. The root
imports every new library module, and only the test executable imports vectors.
Lake's test-support roots now include `BitcoinTests.Psbt` as well as the gate.

Besides the namespace/import changes, transaction hashing uses `Sha256.sha256d`,
the framing error type gains `duplicateBip32Point`, and typed field decoding takes
the capability and hash parameter as described above. When Phase 4a (1 of 3)
landed, every other copied field rule and raw-key storage was unchanged; see
[Phase 4a: PSBT field parity follow-up](#phase-4a-psbt-field-parity-follow-up)
for the later decoding changes. The four new proof slices needed no port
fix; no theorem statement or proof was changed. All edits are enumerated in
[upstream fixes](docs/upstream-fixes.md#transaction-and-psbt-subset-phase-4a-1-of-3)
and reconstructed by `check-tx-psbt-copy.py`. The capability and point checker are
separate dual-licensed files.

The vector source is [bitcoin/bips at 927b6de](https://github.com/bitcoin/bips/tree/927b6de9915c9262615a6399de51b200f81e5aa4),
BSD-2-Clause, extracted by lean-miniscript's `scripts/generate_psbt_fixtures.py`.
Their first-line provenance names both sources, exact ranges and the new
`Bitcoin/LICENSE-psbt-bips`, which quotes the freshly fetched BIP174/370/371
author, licence and Copyright sections followed by the BSD conditions/disclaimer.
The intervening upstream fixture slice L72–94 is never copied.

### Vectors and synthetic checks

Each runtime vector set pins its loaded count before inspecting its elements:

| Set | Count | Assertions |
|---|---|---|
| BIP174 invalid | 20 | Hex and Base64 rejected |
| BIP370 invalid | 24 | Hex and Base64 rejected |
| BIP371 invalid | 11 | Hex and Base64 rejected |
| BIP174 valid | 10 | Parse, byte-exact reserialization, exact Base64 encoding, same PSBT from Base64 |
| BIP174 signer failures | 4 | Same four codec assertions; signer semantics are out of scope |
| BIP370 valid | 14 | Same four codec assertions |
| BIP371 valid | 6 | Same four codec assertions |
| BIP174 roles | 14 | Thirteen round trips; network transaction at index 7 gives exactly `magic` |
| BIP370 locktimes | 10 | Determined locktime, Base64 bytes, and unsigned-transaction locktime or exact incompatible-locktime error |

Pure top-level `BitcoinTests.PsbtTests.testCapability` is a **shape-only** stand-in:
strict validation accepts 33-byte 02/03 except x = 5, and 65-byte 04. Its x-only
operation rejects wrong lengths and x = 5; its DER operation rejects empty
and 31-prefixed bytes. Compression additionally
accepts 65-byte 06/07 with matching final-y-byte parity and returns parity plus x.
It makes no on-curve claim. It suffices for every valid/invalid vector above.
`testHashes.ripemd160` is the first 20 bytes of SHA256 of byte 160 followed by the
input; `testHashes.hash160` uses byte 192 instead. They differ and are sensitive
to input changes. Both are pure test definitions importable by later tests;
real-curve end-to-end wiring belongs to Phase 7c.

Additional named runtime checks cover the twenty invalid BIP174 Base64-to-hex
equalities, all six upstream structured errors, the two sighash-key cases, the
two CompactSize map cases, and key-source, Taproot-key-source and Taproot-tree
round trips. Four synthetic preimage sets check matching acceptance and exact
mismatch errors (**2/2 each**). Input and output hybrid tests each check raw
decoded key data and byte-exact serialization (**2/2 each**); partial signatures
reject that same synthetic hybrid. The hybrid and compressed keys share x and
parity under the stand-in. Same-point tests cover collisions in both scopes,
each encoding alone in both scopes, separate maps in both scopes, invalid keys
and malformed keys. None of these tests contains Wycheproof-derived bytes.

`audit-psbt-vectors.py` independently inventories all **113** published entries
with a small Python wire reader and `hashlib` txids. Its deterministic record is
`test-data/psbt-inventory.json`. There are **136** parseable transactions
(including repeated occurrences), **60** non-witness UTXO txid checks,
**56** matching checks, and **2** malformed global transactions. The Lean
driver pins each count and verifies every inventory row through the public
transaction parser/serializer with the appropriate `allowWitness` choice.
It also pins the following published invalid-vector exceptions explicitly:

| Published invalid entry | Observed property |
|---|---|
| `bip174Invalid[3]`, input 0 record 0 | No unsigned transaction is present, so its previous txid is unavailable |
| `bip174Invalid[4]`, input 0 record 1 | Second duplicate non-witness UTXO has a different txid from its prevout |
| `bip370Invalid[13]`, input 0 record 0 | Non-witness UTXO txid differs from the excluded global unsigned transaction's prevout |
| `bip370Invalid[17]`, input 0 record 0 | No previous-txid field is present, so there is no matching txid |
| `bip174Invalid[18]`, global record 0 | Witness-serialized unsigned transaction gives `truncated` with `allowWitness := false` |
| `bip174Invalid[19]`, global record 0 | Incorrect stated value size leaves transaction `trailingData` |

No exception is silently removed. The inventory also records unavailable map
boundaries: truncated maps in `bip174Invalid[1]`; absent transaction/counts in
`bip174Invalid[3]`, `[18]`, `[19]`, `bip370Invalid[14]` and `[15]`.
The RIPEMD160/HASH160-only invalid preimage-vector list is **none**:
`python3 -I packages/bitcoin/audit-psbt-vectors.py` reports input key type 10
records **0** and type 12 records **0**. Its untyped scan also checks all **1,030**
records across every map (including invalid PSBTs with missing globals), with
**0** records of either type and **0** scan errors. The synthetic tests exercise
both routes. To include transaction bytes in malformed PSBTs, the inventory
explicitly uses their inspected published map layouts for `bip174Invalid[3]`,
`[18]`, `bip370Invalid[14]` and `[15]`. For `[18]` the Lean check reads just its
input vector to obtain the prevout; it never counts the invalid global value as
a successful transaction parse.

Compression tests derive all inputs at runtime from the pinned non-flake
Wycheproof input: **108/108 keys**, **18 checks per key**, **1944/1944 checks**.
Each checks 04-to-compressed, matching hybrid, mismatched hybrid, both strict
hybrid rejections, compressed identity, 33-byte prefixes 04/06/07, 65-byte
prefixes 02/03, lengths 0/32/34/64/66, and two synthetic off-curve shapes.
No Wycheproof bytes or derived fixtures are stored in the repository.

### Proof and axiom audit

The gate's named list grows from **43 to 56**: nine of the eleven earlier
deserialization theorems were not named individually, and all four remaining
ones are now imported. It names all **15** from upstream's
`DeserializationProofs.lean` L7–232. At that phase, the gate printed
`Bitcoin axiom gate: 652 library theorems; 56 named; 0 offenders`.
Its allowlist is still exactly `propext`, `Classical.choice`, `Quot.sound`;
every theorem in every imported `Bitcoin` library module is scanned, including
private and generated theorems. No theorem statement is weakened.

The fifteen `#print axioms` results from `nix develop -c lake test` are:

```text
'Bitcoin.CompactSize.unsignedLE_length' depends on axioms: [propext]
'Bitcoin.CompactSize.decodeLE_unsignedLE' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.takeExact_append' depends on axioms: [propext]
'Bitcoin.CompactSize.compactSize_ne_nil' depends on axioms: [propext]
'Bitcoin.CompactSize.readCompactSize_compactSize' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.serializeByteVector_data' depends on axioms: [propext, Quot.sound]
'Bitcoin.CompactSize.readByteVector_encode' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.CompactSize.decodeLE_lt' depends on axioms: [propext, Quot.sound]
'Bitcoin.CompactSize.unsignedLE_decodeLE' depends on axioms: [propext, Quot.sound]
'Bitcoin.CompactSize.takeExact_ok' depends on axioms: [propext, Quot.sound]
'Bitcoin.CompactSize.readCompactSize_ok' depends on axioms: [propext, Quot.sound]
'Bitcoin.readByteVector_ok' depends on axioms: [propext, Quot.sound]
'Bitcoin.serializeWitness_foldl_data' depends on axioms: [propext, Quot.sound]
'Bitcoin.readMany_readByteVector' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.decodeAll_readWitnessStack' depends on axioms: [propext, Classical.choice, Quot.sound]
```

Only the `43 named; 0 offenders` literals in `check-bech32-mutations.py` and
`check-address-mutations.py` change to **56**. No earlier library source or
theorem-count assertion changes. The executable reports the actual scanned and
named totals; it does not substitute a hard-coded total for the scan.

### Transaction and PSBT red runs

From `packages/bitcoin`, `nix develop -c python3 -I check-psbt-mutations.py`
exited **0**, detecting **71/71** mutations; the final restored `lake test`
exited **0**. The optional resume mode reuses a completed record only when the
production sources, test sources, inventory, mutation and expected failure have
an identical fingerprint. Every record in this full run was executed afresh.
The default command without `--resume` always executes the complete suite.

Each row below ran **`lake test -- --psbt "<selector>"`**, with the selector in
column two, in the foreground and exited **1**. Each production change was
restored in `finally`. Separate stdout/stderr remain under
`.lake/psbt-mutation-checks`; exact command arrays, source paths, exits and
observed failure lines are in [psbt-mutations.json](packages/bitcoin/test-data/psbt-mutations.json).
Only the nine `count-` rows edit test data, deliberately removing one entry to
exercise the count pin. All other rows mutate production behavior.

| Mutation | Selector | Observed failure (exit 1) |
|---|---|---|
| `partial-compression` | `hybrid partial` | `assertion failed: hybrid partial rejected` |
| `strict-inBip32Derivation` | `hybrid input` | `assertion failed: hybrid parse: Bitcoin.Psbt.PsbtError.invalidKey "input" 6 "invalid public key"` |
| `compress-stored-inBip32Derivation` | `hybrid input` | `assertion failed: hybrid false raw decoded` |
| `strict-outBip32Derivation` | `hybrid output` | `assertion failed: hybrid parse: Bitcoin.Psbt.PsbtError.invalidKey "output" 2 "invalid public key"` |
| `compress-stored-outBip32Derivation` | `hybrid output` | `assertion failed: hybrid true raw decoded` |
| `same-raw-comparison` | `same input collision` | `assertion failed: same point false/2` |
| `same-ignore-output` | `same output collision` | `assertion failed: same point true/2` |
| `same-pool-input` | `same input separate` | `assertion failed: same point separate false` |
| `same-lone-input-hybrid` | `same input hybrid alone` | `assertion failed: same point false/1` |
| `same-lone-input-compressed` | `same input compressed alone` | `assertion failed: same point false/1` |
| `same-pool-output` | `same output separate` | `assertion failed: same point separate true` |
| `same-lone-output-hybrid` | `same output hybrid alone` | `assertion failed: same point true/1` |
| `same-lone-output-compressed` | `same output compressed alone` | `assertion failed: same point true/1` |
| `same-accept-invalid` | `same invalid` | `assertion failed: same invalid` |
| `same-skip-malformed` | `same malformed` | `assertion failed: same malformed` |
| `skip-sha256` | `SHA256 preimage` | `assertion failed: preimage 11 mismatch` |
| `skip-hash256` | `HASH256 preimage` | `assertion failed: preimage 13 mismatch` |
| `skip-ripemd160` | `RIPEMD160 preimage` | `assertion failed: preimage 10 mismatch` |
| `skip-hash160` | `HASH160 preimage` | `assertion failed: preimage 12 mismatch` |
| `hash256-single` | `HASH256 preimage` | `assertion failed: preimage 13 accepted` |
| `swap-ripemd160` | `RIPEMD160 preimage` | `assertion failed: preimage 10 accepted` |
| `swap-hash160` | `HASH160 preimage` | `assertion failed: preimage 12 accepted` |
| `txid-single` | `transactions` | `assertion failed: wire bip174Invalid[1] input txid` |
| `vector-bip174-invalid` | `BIP174 invalid` | `assertion failed: BIP174 invalid hex 4` |
| `vector-bip370-invalid` | `BIP370 invalid` | `assertion failed: BIP370 invalid hex 1` |
| `vector-bip371-invalid` | `BIP371 invalid` | `assertion failed: BIP371 invalid hex 1` |
| `vector-bip174-valid` | `BIP174 valid` | `assertion failed: BIP174 valid 0 serialize` |
| `vector-bip174-signer` | `BIP174 signer failures` | `assertion failed: BIP174 signer failures 0 serialize` |
| `vector-bip370-valid` | `BIP370 valid` | `assertion failed: BIP370 valid 0 serialize` |
| `vector-bip371-valid` | `BIP371 valid` | `assertion failed: BIP371 valid 0 serialize` |
| `vector-bip174-roles` | `BIP174 roles` | `assertion failed: BIP174 roles 0 serialize` |
| `vector-locktimes` | `BIP370 locktimes` | `assertion failed: locktime determine 0` |
| `unsigned-locktime` | `BIP370 locktimes` | `assertion failed: locktime transaction 0` |
| `incompatible-locktime` | `BIP370 locktimes` | `assertion failed: locktime incompatible 9` |
| `invalid-base64-bytes` | `invalid base64 bytes` | `assertion failed: invalid base64 bytes 0` |
| `network-magic` | `network magic` | `assertion failed: network magic` |
| `base64-error` | `base64 syntax` | `assertion failed: base64 syntax` |
| `same-check-partial` | `same ignores partial` | `assertion failed: same ignores partial` |
| `same-check-global` | `same ignores global` | `assertion failed: same ignores global` |
| `rewrite-raw-input` | `hybrid input` | `assertion failed: hybrid false raw serialization` |
| `rewrite-raw-output` | `hybrid output` | `assertion failed: hybrid true raw serialization` |
| `exact-duplicate` | `exact duplicate` | `assertion failed: exact duplicate` |
| `exact-unsigned` | `exact unsigned` | `assertion failed: exact unsigned` |
| `exact-excluded` | `exact excluded` | `assertion failed: exact excluded` |
| `exact-missing` | `exact missing` | `assertion failed: exact missing` |
| `exact-signature` | `exact signature` | `assertion failed: exact signature` |
| `exact-control` | `exact control` | `assertion failed: exact control` |
| `sighash-extra` | `sighash extra` | `assertion failed: sighash extra` |
| `sighash-valid` | `sighash valid` | `assertion failed: sighash valid` |
| `map-noncanonical` | `map noncanonical` | `error: Bitcoin/CompactSize.lean:236:10: unsolved goals` |
| `map-canonical` | `map canonical` | `assertion failed: map canonical` |
| `key-source` | `key source` | `assertion failed: key source` |
| `tap-key-source` | `tap key source` | `assertion failed: tap key source` |
| `tap-tree` | `tap tree` | `assertion failed: tap tree` |
| `trailing-data` | `trailing data` | `assertion failed: PSBT trailing data` |
| `count-bip174Invalid` | `BIP174 invalid` | `assertion failed: BIP174 invalid count` |
| `count-bip370Invalid` | `BIP370 invalid` | `assertion failed: BIP370 invalid count` |
| `count-bip371Invalid` | `BIP371 invalid` | `assertion failed: BIP371 invalid count` |
| `count-bip174Valid` | `BIP174 valid` | `assertion failed: BIP174 valid count` |
| `count-bip174SignerFailures` | `BIP174 signer failures` | `assertion failed: BIP174 signer failures count` |
| `count-bip370Valid` | `BIP370 valid` | `assertion failed: BIP370 valid count` |
| `count-bip371Valid` | `BIP371 valid` | `assertion failed: BIP371 valid count` |
| `count-bip174Roles` | `BIP174 roles` | `assertion failed: BIP174 roles count` |
| `count-bip370Locktimes` | `BIP370 locktimes` | `assertion failed: BIP370 locktimes count` |

Seven further production mutations cover the independent round-trip,
malformed-transaction, Base64 and SHA256 acceptance assertions. Each command
below runs from `packages/bitcoin`; each first failure line is recorded verbatim.

| Property | Mutation | Command | Exit | First failure line |
|---|---|---|---|---|
| BIP144 witness serialization round trip | `witness-marker-flag`: marker/flag `[0, 1]` becomes `[0, 3]` | `lake test -- --psbt "transactions"` | 1 | `uncaught exception: assertion failed: wire bip174Invalid[1] input roundtrip` |
| Legacy transaction serialization round trip | `legacy-version`: serialize version plus one | `lake test -- --psbt "transactions"` | 1 | `uncaught exception: assertion failed: wire bip174Invalid[0] network roundtrip` |
| Published malformed transaction 18 gives `truncated` | `malformed-witness-marker`: treat zero inputs as a witness marker regardless of `allowWitness` | `lake test -- --psbt "malformed transaction 18"` | 1 | `uncaught exception: assertion failed: malformed transaction 18` |
| Published malformed transaction 19 gives `trailingData` | `transaction-ignore-trailing`: `decodeAll` ignores unread bytes | `lake test -- --psbt "malformed transaction 19"` | 1 | `uncaught exception: assertion failed: malformed transaction 19` |
| Valid-set Base64 encoding | `valid-base64-encode`: append `A` in `Base64.encode` | `lake test -- --psbt "BIP174 valid"` | 1 | `uncaught exception: assertion failed: BIP174 valid 0 base64 encode` |
| Valid-set Base64 parsing | `valid-base64-decode`: append a decoded zero byte in `Base64.decode` | `lake test -- --psbt "BIP174 valid"` | 1 | `uncaught exception: assertion failed: BIP174 valid 0 base64 parse` |
| SHA256 preimage acceptance | `sha256-double`: use SHA256d in the SHA256 branch | `lake test -- --psbt "SHA256 preimage"` | 1 | `uncaught exception: assertion failed: preimage 11 accepted` |

The two malformed checks are also separately selectable. The ordinary
`transactions` action still runs all 136 wire rows, the 60 txid checks and then
both malformed checks in their original order. The full suite still reports
`published malformed transactions: 2/2` and `PSBT checks: 46/46`.
The runner requires the first assertion or build-error line to contain the
specified assertion, so a later matching assertion cannot mask an earlier failure.

The `map-noncanonical` production mutation fails in the unchanged theorem
`Bitcoin.CompactSize.readCompactSize_ok`, which pins canonicality, before
runtime. Every other row requires a passing 56-named axiom gate and then its
specified runtime assertion. No expected test value is changed. The initial
half-raw comparison experiment still detected the collision (exit 0) because
the second key was already compressed; the recorded mutation compares both
raw keys and fails the collision assertion as intended.

The existing Bitcoin mutation suites were rerun in full, each with a restored
`lake test` at exit **0**:

| Command from `packages/bitcoin` | Exit | Detection |
|---|---|---|
| `nix develop -c python3 -I check-mutations.py` | 0 | 6/6 |
| `nix develop -c python3 -I check-base58-mutations.py` | 0 | 6/6 |
| `nix develop -c python3 -I check-bech32-mutations.py` | 0 | 18/18 |
| `nix develop -c python3 -I check-address-mutations.py` | 0 | 20/20 |

The Base58, bech32 and address JSON records are byte-identical to the base
revision. In `test-data/mutations.json` only the temporary-axiom failure's
`BitcoinTests/AxiomGate.lean:67:0` changes to `:74:0`: the newly named theorems
insert seven lines before the gate invocation. No other recorded line number,
assertion, command, exit or failure classification changes.

For the red-run follow-up, `check-mutations.py` (6/6),
`check-base58-mutations.py` (6/6), `check-bech32-mutations.py` (18/18),
`check-address-mutations.py` (20/20) and
`secp256k1/check-negative-mutations.py` (42/42 plus 18/18) were not rerun.
Their scripts and production inputs have no retained changes; the PSBT driver
only extracts the existing malformed checks into separately selectable actions.
The counts above remain the earlier recorded results. Every temporary production
mutation in the follow-up was restored, and all production files were compared
against their pre-run bytes.

### Curve and key-pattern red runs

From `packages/secp256k1`, `nix develop -c python3 -I check-negative-mutations.py`
exited **0**. The original **42/42** negative mutations still fail their named
assertions (or the explicit recovery-id diagnostic), confirming that the new C
function does not disturb the runner's `index("lck_secp_<name>(")` lookup.
Its original records remain at `.lake/mutation-checks/records.json`.
The same command then detected **18/18** compression mutations. For each row
below, **`lake test -- --compression "<selector>"`** ran in the foreground and
exited **1**, with stdout/stderr captured separately under
`.lake/compression-mutation-checks` and compact records in its `records.json`.

| Selector | Production mutation | Observed assertion |
|---|---|---|
| `uncompressed` | `uncompressed-result` | `assertion failed: compression uncompressed` |
| `compressed identity` | `uncompressed-result` | `assertion failed: compression compressed identity` |
| `matching hybrid` | `strict-prefix` | `assertion failed: compression matching hybrid` |
| `mismatched hybrid` | `early-some` | `assertion failed: compression mismatched hybrid` |
| `33 prefix 4` | `early-some` | `assertion failed: compression 33 prefix 4` |
| `33 prefix 6` | `early-some` | `assertion failed: compression 33 prefix 6` |
| `33 prefix 7` | `early-some` | `assertion failed: compression 33 prefix 7` |
| `65 prefix 2` | `early-some` | `assertion failed: compression 65 prefix 2` |
| `65 prefix 3` | `early-some` | `assertion failed: compression 65 prefix 3` |
| `length 0` | `early-some` | `assertion failed: compression length 0` |
| `length 32` | `early-some` | `assertion failed: compression length 32` |
| `length 34` | `early-some` | `assertion failed: compression length 34` |
| `length 64` | `early-some` | `assertion failed: compression length 64` |
| `length 66` | `early-some` | `assertion failed: compression length 66` |
| `off-curve compressed` | `early-some` | `assertion failed: compression off-curve compressed` |
| `off-curve uncompressed` | `early-some` | `assertion failed: compression off-curve uncompressed` |
| `strict matching hybrid` | `strict-accept` | `assertion failed: compression strict matching hybrid` |
| `strict mismatched hybrid` | `strict-accept` | `assertion failed: compression strict mismatched hybrid` |

`early-some` returns `some` before validation; `strict-prefix` adds the strict
65-byte prefix restriction to compression; `uncompressed-result` selects
`SECP256K1_EC_UNCOMPRESSED` with a 65-byte buffer so the assertion, rather than
an unrelated buffer abort, catches the wrong output. `strict-accept` changes
only the strict parser's result. Removing just the compression length guard
was also measured with a full foreground `lake test`: exit **0**, all 108 keys
and 1944 checks still ran. That surviving experiment is recorded separately,
not counted among detected mutations. The source is restored in `finally`.

The workflow and key-pattern checks ran from the repository root (exit **0**):

```bash
nix shell --impure --expr 'let pkgs = import (builtins.getFlake (toString ./.)).inputs.nixpkgs {}; in pkgs.python3.withPackages (p: [p.pyyaml])' -c python3 -I packages/bitcoin/check-key-material.py
```

PyYAML **6.0.3** parsed `.github/workflows/ci.yml` and asserted that the new
step's `run` string equals exactly:

```bash
rc=0; grep -rEn --exclude-dir=.lake '[tx]prv[1-9A-HJ-NP-Za-km-z]{100,}' packages || rc=$?; test "$rc" -eq 1
```

The test executable runs the same grep with `..` as its root, requires exactly
exit 1, and prints `key-shaped grep: 1/1`. A temporary copy of `packages/`
(excluding `.lake/`) received one synthetic line, constructed as `tprv` followed
by **110 `z` characters**, in `bitcoin/synthetic-key-shape.txt`. It was never
planted in the repository. Both actual checks went red with the planted path:

| Check in the temporary copy | Command | Exit | Observed failure |
|---|---|---|---|
| CI | `bash -e -c "$CI_COMMAND"`, where `CI_COMMAND` is the exact literal above | 1 | `packages/bitcoin/synthetic-key-shape.txt:1:` |
| Test executable, from the copied `packages/bitcoin` | `"$REPO"/packages/bitcoin/.lake/build/bin/BitcoinTests` | 1 | `assertion failed: key-shaped grep: exit 0`, followed by `../bitcoin/synthetic-key-shape.txt:1:` |
| Restored CI copy | Same CI command after unlinking the synthetic file | 0 | Nothing on either stream |
| CI path-error check | Same CI command while `packages` is absent | 1 | `grep: packages: No such file or directory` |

The last check proves grep errors are rejected, rather than treated as no-match.
The helper removed exactly its freshly created copy and asserted its absence.
Separate streams remain under `.lake/key-material-checks`; compact records are
[key-material-mutations.json](packages/bitcoin/test-data/key-material-mutations.json).

The follow-up reran the same `check-key-material.py` command because it copies
the package tree and drives the rebuilt test executable: exit **0**, all four
recorded checks reproduced, PyYAML **6.0.3**. Its compact records are byte-identical
to the pre-run records, and it again removed its exact disposable copy.

### Final validation and cleanup

On 2026-10-22, all gates ran in the foreground with the repository's supervisor,
separate stdout/stderr, and `TMPDIR` set to a fresh private directory,
`$TMP_ROOT`. `REPO` denotes the checkout
root; `TMP_ROOT` denotes the fresh private temporary directory used for the
source checkout, three BIP fetches and shell temporary files. Lean reported
**4.35.0**, commit `eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, Release.
New files were staged before the flake check. No flake, lockfile or other
package's tracked source changed.

| Command | Directory | Exit / observation |
|---|---|---|
| `nix develop -c lean --version` | root | 0; 4.35.0 |
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; all pinned sets, 46/46 PSBT checks, 1/1 key-shaped grep, 652/56/0 axiom gate |
| `nix develop -c lake build` | `packages/secp256k1` | 0 |
| `nix develop -c lake test` | `packages/secp256k1` | 0; original BOLT/Wycheproof counts plus 108 keys and 1944 compression checks |
| `nix develop -c bash -c 'cc -fsyntax-only -I "$(lean --print-prefix)/include" -include .lake/build/ir/Secp256k1.c link_shim.c'` | `packages/secp256k1` | 0; all six generated declarations agree with the shim |
| `python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT"/miniscript` | root | 0; 8/8 copied files, exactly the documented edits |
| `cmp packages/bitcoin/Bitcoin/LICENSE-miniscript "$TMP_ROOT"/miniscript/LICENSE` | root | 0; notice reused byte-for-byte |
| `python3 -I packages/bitcoin/audit-psbt-vectors.py` | root | 0; 113 vectors, 136 transactions, 60 txid checks, all recorded exceptions, no preimage records |
| `nix flake check -L` | root | 0; all seven packages build and test in the sandbox |
| `nix build` | root | 0 |
| `./result/bin/cyberkrill` | root | 0; `cyberkrill 0.1.0` |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | root | 0; no matches |
| `rc=0; grep -rnE 'native_decide\|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean \|\| rc=$?; test "$rc" -eq 1` | root | 0; no matches |
| `grep -rEn --exclude-dir=.lake '[tx]prv[1-9A-HJ-NP-Za-km-z]{100,}' packages` | root | 1; no matches |
| CompactSize definition grep below | root | 0; exactly two lines, `CompactSize.lean:13` and `:50` |
| `grep -F sorry packages/bitcoin/BitcoinTests/AxiomGate.lean` | root | 1; no substring |
| `git diff --check e1a95626c185ac07a0a7e2c4d9f9368aca36a2d1` | root | 0; no upstream-data exceptions needed |

The single-codec definition check was:

```bash
grep -rn 'def readCompactSize\|def compactSize' --include='*.lean' --exclude-dir=.lake packages/bitcoin
```

The sandbox log includes every new PSBT and compression count, the 652/56/0
Bitcoin gate, SHA-256's unchanged 346/10/0 gate, `http-curl cases: 35/35`,
`S12: PASS`, `S13: PASS`, `link spike, Lake/leanc green twins, forced-static red
fixture: PASS`, and `http-curl wrapper executable: one nix OpenSSL, version and
ldd: PASS`. Both existing link-check scripts remain unchanged. The app printed
`cyberkrill 0.1.0`. Full command arrays, exits and separated streams remain
under `packages/bitcoin/.lake/final-tx-psbt`.

The required staged-diff key-material scan was run exactly, with `pipefail`:

```bash
git diff --cached -U0 | grep '^+' | grep -n -E '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
```

It printed **nothing on either stream**, exit **1** (no matches). No vector
exception was needed. The added-text scan of `git diff --cached -U0` also found
**0** local paths or process attributions, exit **0** for its assertion.
The implementation and the tracker change were later committed separately.

Cleanup used Python `shutil.rmtree` on exactly the fresh `TMP_ROOT`, followed
by an absence assertion: exit **0**. This removed its `miniscript` checkout,
`bip-0174.mediawiki`, `bip-0370.mediawiki`, `bip-0371.mediawiki`, shell temporary
files, caches and private gate helpers. The separately created key-grep copy
had already been removed by `check-key-material.py`, which asserted its
absence before exiting **0**. No existing external directory was removed.
Normal build outputs, separated validation/mutation logs and compact records
remain under ignored `.lake/` paths. No test or helper process remains running.

The red-run follow-up repeated the following gates under the same supervisor,
with a fresh private `TMP_ROOT`. It retained changes only to this README,
`check-psbt-mutations.py`, `test-data/psbt-mutations.json` and
`BitcoinTests/Psbt.lean`; all other tracked file bytes, including the unstaged
tracker change, matched their starting snapshot.

| Command / check | Directory | Exit / observation |
|---|---|---|
| `nix develop -c python3 -I check-psbt-mutations.py` | `packages/bitcoin` | 0; 71/71 detected, restored `lake test` exits 0 |
| `nix develop -c lake build` | `packages/bitcoin` | 0 |
| `nix develop -c lake test` | `packages/bitcoin` | 0; all pinned sets unchanged, 46/46 PSBT actions, 652/56/0 axiom gate |
| `check-key-material.py`, using the PyYAML command above | root | 0; all four recorded checks reproduced |
| `nix flake check -L` | root | 0; one check ran, rebuilding and testing all seven packages |
| `nix build --no-link --print-out-paths .#default` | root | 0 |
| Built `bin/cyberkrill` | root | 0; `cyberkrill 0.1.0` |
| `nix log` for the current default derivation | root | 0; all PSBT set counts, 136/136 wire rows, 60/60 txids, 2/2 malformed transactions, 46/46 actions and 652/56/0 gate present |
| The three proof-placeholder, library decision-tactic and private-key-pattern checks above | root | 0 each; no matches |
| `git diff --cached --check e1a95626c185ac07a0a7e2c4d9f9368aca36a2d1` | root | 0 |
| Exact staged-diff key-material pipeline above | root | 1; nothing printed on either stream, no vector exceptions |
| Public-text inspection of every added line against the same base | root | 0; no prohibited paths, names or process attributions |

The complete mutation run used the required 8 GiB memory scope and one-hour
timeout. Separated streams and command/exit records for this follow-up remain
under `packages/bitcoin/.lake/psbt-round2`; per-mutation streams remain under
`.lake/psbt-mutation-checks`. The fresh `TMP_ROOT` held only private gate helpers
and shell temporary files. Cleanup removed exactly that directory and asserted
its absence, exit **0**. The key-pattern helper had already removed its own
disposable copy. No pre-existing external directory was removed, and no test or
helper process remains running. The four changed files and the tracker change
were later committed separately.

### Review follow-up

Two library changes to copied code answer review findings; both are listed in
`docs/upstream-fixes.md` and in `check-tx-psbt-copy.py`'s documented edits.

- `serializeWitnessTransaction` chooses the BIP144 form only from the stacks of
  the transaction's inputs. Before, a non-empty stack beyond the inputs selected
  the marker and flag while every written stack was empty, which
  `parseTransaction` rejects as `superfluousWitness`. The new `surplus witness`
  check serializes the BIP174 valid 0 unsigned transaction with one extra
  non-empty stack and requires the legacy bytes. Production mutation
  `surplus-witness-format` restores the old guard and fails it:
  `assertion failed: surplus witness legacy`, exit **1**.
- `Base64.encodeList` and `decodeList` are tail-recursive accumulator loops.
  Results are unchanged: every Base64 vector and rejection check passes, and the
  three Base64 production mutations fail exactly as recorded. A standalone probe
  compiled `Bitcoin/Base64.lean` with `lean -c` and `leanc -O3` and a `main`
  that encodes `n` bytes (`i * 7 mod 256`), decodes the text and compares,
  under the default 8 MiB stack limit (`ulimit -s` prints `8192`) in a 12 GiB
  memory scope:

| Code | n | Result |
|---|---|---|
| Copied loops | 100,000; 1,000,000; 4,000,000; 16,000,000 | exit **0**, round trip equal |
| Copied loops | 48,000,000 | exit **134**, stderr `Stack overflow detected. Aborting.` |
| Accumulator loops | 1,000,000 | exit **0**, round trip equal |
| Accumulator loops | 48,000,000 | exit **0**, round trip equal, 10.9 s, 2.4 GB peak RSS |
| Accumulator loops | 96,000,000 | exit **0**, round trip equal, 22.2 s, 4.8 GB peak RSS |

Two checking scripts changed: `check-key-material.py` uses the default temporary
directory when `TMPDIR` is unset, and `check-tx-psbt-copy.py` refuses an
upstream checkout with local changes.

| Command | Result |
|---|---|
| `nix develop -c lake build`, `nix develop -c lake test` in `packages/bitcoin` | 0 / 0; `PSBT checks: 47/47`, 652/56/0 axiom gate |
| `nix develop -c python3 -I check-psbt-mutations.py surplus-witness-format valid-base64-encode valid-base64-decode invalid-base64-bytes witness-marker-flag txid-single malformed-witness-marker` | 0; 7/7 detected, restored `lake test` exits 0; the six existing records are identical to the committed ones |
| `python3 -I check-tx-psbt-copy.py "$TMP_ROOT/miniscript"` on a fresh clone at `cb9bc5f` | 0; 8/8 exact copies plus documented edits |
| The same with one line appended to an upstream file | 1; `AssertionError: upstream checkout has local changes` |
| The `check-key-material.py` command above, with `TMPDIR` unset | 0; both planted greps exit 1, restored scan exits 0 |
| `nix flake check -L` | 0 |

`test-data/psbt-mutations.json` now holds 72 records: the 71 from the full run
and `surplus-witness-format` from the subset run above.

### Deltas not taken

The two PSBT parity follow-ups below fixed every row of the earlier list,
including the four curve-dependent rules. The three kept BIP rules appear
under "Deltas taken". This is not a full parity audit; PSBT roles, signing and
application wiring remain later work. The hash and proof phases below supply
the real RIPEMD160/HASH160 and transaction/PSBT theorems.

## Phase 4a: RIPEMD-160 and HASH160 (2 of 3)

`import Bitcoin` exposes the following pure functions and the value used to
validate RIPEMD160/HASH160 PSBT preimages. There is no new dependency or FFI.

| Module | Public API |
|---|---|
| `Bitcoin.Ripemd160` | `Bitcoin.ripemd160 : ByteArray → ByteArray`, always 20 bytes; `Bitcoin.Ripemd160.hash` is the implementation |
| `Bitcoin.Ripemd160` | `Bitcoin.hash160 b = Bitcoin.ripemd160 (Sha256.hash b)` |
| `Bitcoin.Psbt.Hashes` | `Bitcoin.Psbt.preimageHashes : PreimageHashes`, filled with the two functions above |

Call `Psbt.parse cap preimageHashes bytes`, `p.decode cap preimageHashes`, or
`Psbt.parseBase64 cap preimageHashes text`. These signatures are unchanged.
SHA256 and HASH256 still call `Sha256.hash` and `Sha256.sha256d` directly.
The earlier phase's statements deferring the real hashes are historical;
application wiring and the transaction/PSBT proof obligations remain later work.

### Sources, generated expectations and test sets

The implementation was written from the algorithm description linked at
https://homes.esat.kuleuven.be/~bosselae/ripemd160.html. Only the page and its
pseudocode were read; no implementation was opened or copied. The page is cited
by URL only. Its code, prose and digest table are not included in the tree.

`packages/bitcoin/generate-ripemd160-vectors.py` sends each ASCII message as exact
bytes on stdin to `openssl dgst -ripemd160 -binary`, without a newline. It writes
only `test-data/ripemd160.json`, recording
`OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)`.
The fixture stores repeated messages as base strings plus repeat counts.
From the repository root:

```bash
nix develop -c python3 -I packages/bitcoin/generate-ripemd160-vectors.py
git diff --exit-code -- packages/bitcoin/test-data/ripemd160.json
```

The nine generated digests were compared with the RIPEMD-160 column on the
authors' page: **9/9 equal**. The comparison loaded the page into memory and
searched for each generated 40-character digest with word boundaries; it
asserted all nine matches and exited **0**. No downloaded page was saved.
The exact comparison command below used Python **3.13.15**:

```bash
python3 - <<'PY'
import json, re, urllib.request
from pathlib import Path
page = urllib.request.urlopen('https://homes.esat.kuleuven.be/~bosselae/ripemd160.html').read().decode()
rows = json.loads(Path('packages/bitcoin/test-data/ripemd160.json').read_text())['vectors']
for row in rows:
    assert re.search(r'\b' + row['digest'] + r'\b', page), row['message']
print('Generated OpenSSL digests compared with authors’ RIPEMD-160 column: 9/9 equal')
PY
```

| Counted set in `lake test` | Pinned count and expectations |
|---|---|
| RIPEMD-160 vectors | 9/9; empty, `a`, `abc`, `message digest`, alphabet, 56-byte message, alphanumeric, 8 × `1234567890`, one million `a`; generated digests and 20-byte output length |
| HASH160 BIP173 | 1/1; compressed public generator from bitcoin/bips @ `130b8e0fa7f30fa45532f080b87b8db27a79e46e`, `bip-0173.mediawiki:60-61`, address at line 64; expected program is extracted from existing `AddressVectors.bip350Valid[0]` |
| RIPEMD160 PSBT | 2/2; synthetic matching record accepted, one-byte preimage change rejected with the exact error |
| HASH160 PSBT | 2/2; the same acceptance and exact-error checks |

Every set asserts its list/array length before checking its cases and prints
the checked length. The two PSBT pairs reuse the existing action names
`RIPEMD160 preimage` and `HASH160 preimage`. Each key digest comes directly from
`Bitcoin.ripemd160` or `Bitcoin.hash160`, independently of the exported value
passed to `Psbt.parse`. The shape-only curve capability and stand-in hashes
remain available for the other tests.

`python3 -I packages/bitcoin/audit-psbt-vectors.py` exited **0**: the published
113 vectors still contain **0 input type-10 and 0 input type-12 records**
(also zero in the all-map audit). The earlier waiting list is empty. These new
preimage records are synthetic, rather than claimed published vectors.
The parity reference is rust-bitcoin 0.32.8,
`src/psbt/map/input.rs:294-325,500-528`: all four preimage kinds compare the hash
before insertion and return `InvalidPreimageHashPair` on mismatch.

### Structured mismatch error and stack use

Option A retains `.invalidValue "input" keyType "preimage does not match hash"`.
At that phase, `Bitcoin/Psbt/Codec.lean` and `Fields.lean` were unchanged;
the following line numbers refer to that revision. In `Fields.lean`,
`inputStep` sets scope to `"input"` at line 364. Its single branch for types
0x0a–0x0d is lines 398–410. That branch has exactly one value check, the
preimage comparison at line 402; no other path for these key types yields
`invalidValue "input" keyType _`. The length check at line 401 calls
`checkKeyData` (lines 155–157), which returns `invalidKey`. Duplicate raw keys
fail in framing with `duplicateKey` (`Codec.lean:106-107`), before typed decoding.
`decodeInput` at lines 466–472 adds only version-2 missing-field checks.
A caller therefore identifies a preimage mismatch by **constructor, scope and
key type**, never by the diagnostic reason string. Tests additionally pin the
complete error value for types 0x0a and 0x0c.

Padding uses bounded loops to append the marker, zeros and the low 64 bits of
the bit length. Word conversion uses fixed 16 × 4 loops per block; the outer
block loop carries five `UInt32` chaining words and runs 80 steps per block.
Output conversion is fixed at 5 × 4 bytes. No recursive call depth grows with
the input. This is a structural observation about the loops, independent of
the million-byte vector. There is no new named theorem or proof obligation.
At that phase, the axiom gate reported **652 library theorems; 56 named; 0 offenders**.

### Mutation and final validation records

The new mutation command, from `packages/bitcoin`, is
`nix develop -c python3 -I check-ripemd160-mutations.py`. It exited **0**,
detecting **8/8**, then ran restored `lake test` with exit **0**. It asserts
exact replacement counts, restores and rechecks file bytes in `finally`, and
records separate streams under `.lake/ripemd160-mutation-checks`. Compact
records are in `test-data/ripemd160-mutations.json`. Count mutations deliberately
remove test cases; the other mutations change production behavior.
Each table selector is passed after `lake test --`:

| Mutation | Selector | Exit | Observed first failure line |
|---|---|---|---|
| Round constant `0x5a827999` → `0x5a827998` | `--hash vectors` | 1 | `uncaught exception: assertion failed: RIPEMD-160 vectors 0 digest` |
| Remove one JSON vector | `--hash vectors` | 1 | `uncaught exception: assertion failed: RIPEMD-160 vectors count` |
| Remove BIP173 case | `--hash bip173` | 1 | `uncaught exception: assertion failed: HASH160 BIP173 count` |
| Remove RIPEMD160 PSBT mismatch case | `--psbt "RIPEMD160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 10 count` |
| Remove HASH160 PSBT mismatch case | `--psbt "HASH160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 12 count` |
| HASH160 omits SHA-256 | `--hash bip173` | 1 | `uncaught exception: assertion failed: HASH160 BIP173 digest` |
| Exported hash fields swapped | `--psbt "RIPEMD160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 10 accepted` |
| Length field reduced modulo one block | `--hash vectors` | 1 | `uncaught exception: assertion failed: RIPEMD-160 vectors 7 digest` |

The last mutation first fails on the 80-byte message. The real-hash PSBT
actions also retain the existing skip/swap coverage in
`check-psbt-mutations.py`; the full rerun and its four observations are recorded
below.

| Existing mutation against the real hashes | Selector after `lake test --` | Exit | Observed first failure line |
|---|---|---|---|
| `skip-ripemd160` | `--psbt "RIPEMD160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 10 mismatch` |
| `skip-hash160` | `--psbt "HASH160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 12 mismatch` |
| `swap-ripemd160` | `--psbt "RIPEMD160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 10 accepted` |
| `swap-hash160` | `--psbt "HASH160 preimage"` | 1 | `uncaught exception: assertion failed: preimage 12 accepted` |

All five existing commands were rerun in full, sequentially, from
`packages/bitcoin`, with prefix `nix develop -c python3 -I`:

| Script | Exit | Detections | Restored full `lake test` exit |
|---|---|---|---|
| `check-mutations.py` | 0 | 6/6 | 0 |
| `check-base58-mutations.py` | 0 | 6/6 | 0 |
| `check-bech32-mutations.py` | 0 | 18/18 | 0 |
| `check-address-mutations.py` | 0 | 20/20 | 0 |
| `check-psbt-mutations.py` | 0 | 72/72 | 0 |

The five existing JSON evidence files are byte-unchanged (`git diff --exit-code`
on those paths exited **0**). No recorded line number, pinned count or mutation
target changed; `AxiomGate.lean:74:0` is still the diagnostic location. No scope
timed out, and no checkpoint resume was needed. All six mutation commands and
the build commands used the repository's foreground gate supervisor and their
own capped scope:

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 nix develop -c lake test
```

The example checks `lake test`; substitute each command from the tables.
`TMPDIR` was set to the external temporary
area for each invocation. The scope limits were never raised.

### Final validation

On 2026-10-23 the development shell reported Lean **4.35.0** (commit
`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, Release), Lake
**5.0.0-src+eb6cafb**, Python **3.14.7**, and OpenSSL **3.5.8**.
The version command was `nix develop -c bash -c 'set -e; lean --version;
lake --version; python3 --version; openssl version'`, exit **0**.
The page-comparison command above used the host Python version recorded there.

| Command | Directory | Exit | Observation |
|---|---|---|---|
| `nix develop -c lake build` | `packages/bitcoin` | 0 | 38 jobs completed |
| `nix develop -c lake test` | `packages/bitcoin` | 0 | RIPEMD-160 9/9; BIP173 HASH160 1/1; preimages 10 and 12 each 2/2; all earlier counts unchanged; PSBT actions 47/47; axiom gate 652/56/0 |
| The six mutation commands above | `packages/bitcoin` | 0 each | 130/130 mutations detected in total; each restored full test exits 0 |
| `nix develop -c python3 -I packages/bitcoin/generate-ripemd160-vectors.py` | root | 0 | 9/9 generated using the recorded OpenSSL version |
| `git diff --exit-code -- packages/bitcoin/test-data/ripemd160.json` after regeneration | root | 0 | Staged fixture reproduced byte for byte |
| `python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT/miniscript"` | root | 0 | Fresh clone of `https://github.com/febyeji/lean-miniscript`, checked out at `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`; 8/8 exact copies plus documented edits |
| `python3 -I packages/bitcoin/audit-psbt-vectors.py` | root | 0 | 113 vectors; 0 type-10 and 0 type-12 records |
| `nix flake check -L`, with new files staged | root | 0 | All seven packages built and tested in the sandbox; new counts and 652/56/0 gate printed |
| `nix build` | root | 0 | Default executable built |
| `./result/bin/cyberkrill` | root | 0 | `cyberkrill 0.1.0` |
| `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | root | 0 | No matches; both streams empty |
| `grep -rnE 'native_decide\|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | root | 1 | Both streams empty |
| `grep -F sorry packages/bitcoin/BitcoinTests/AxiomGate.lean` | root | 1 | Both streams empty |
| `git diff --check 0af9d6590e1c5d54ae0ef5f7d5f9799238816a00` | root | 0 | Both streams empty |
| Staged-diff key-material pipeline below | root | 1 | Both streams empty; no match |
| Added-line public-text scan and staged-path inspection | root | 0 | No prohibited names, local paths or attribution; 13 intended files; tracker excluded |

The exact staged-diff key-material scan was:

```bash
git diff --cached -U0 | grep '^+' | grep -n -E '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
```

Its recorded stdout and stderr are empty, exit **1**. Build, test, sandbox and
static-check streams are captured separately under
`packages/bitcoin/.lake/phase4a-validation`; mutation streams remain in their
respective `.lake/*-mutation-checks` directories. Gates were never piped through
an output filter.

The fresh `TMP_ROOT` clone and directory were deleted by their exact created
path, with absence asserted, exit **0**. Each private gate directory was
removed before the supervisor reported its final status. The temporary gate
helper was also deleted and its absence checked, exit **0**. No temporary clone,
cache or helper process from this work session remains; normal `.lake` build
outputs and logs remain. The changes were staged before the flake check,
then committed after review and merged to master.

## Phase 4a: PSBT and transaction proofs (3 of 3)

`import Bitcoin` includes the following theorems. The capability and preimage
hashes remain arbitrary supplied functions; no curve implementation, FFI,
Mathlib, dependency, or acceptance-rule change is needed.

| Module | Full theorem name and statement |
|---|---|
| `Bitcoin.Psbt.Proofs` | `Bitcoin.Psbt.Psbt.roundtrip (cap) (hashes) (p) : valid cap hashes p → Psbt.parse cap hashes (Psbt.serialize p) = .ok p` |
| `Bitcoin.Psbt.Proofs` | `Bitcoin.Psbt.Psbt.unique_of_parse : Psbt.parse cap hashes bytes = .ok p → p.global.Unique ∧ (∀ m ∈ p.inputs, m.Unique) ∧ ∀ m ∈ p.outputs, m.Unique` |
| `Bitcoin.Psbt.Proofs` | `Bitcoin.Psbt.Psbt.no_trailing_data : Psbt.parse cap hashes bytes = .ok p → Psbt.parse cap hashes (bytes ++ extra) = .ok q → extra = ByteArray.empty` |
| `Bitcoin.TransactionProofs` | `Bitcoin.parseTransaction_serializeWitnessTransaction (tx) (witnesses) : tx.WellFormed witnesses → parseTransaction (serializeWitnessTransaction tx witnesses) = .ok ⟨tx, if witnesses.all List.isEmpty then tx.inputs.toList.map (fun _ => []) else witnesses⟩` |

The upstream references below were located by grep in a fresh
[cb9bc5f source tree](https://github.com/febyeji/lean-miniscript/tree/cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd)
and in the port. Port paths are relative to `packages/bitcoin/`.

| Upstream at `cb9bc5f` | What | Port location |
|---|---|---|
| `LeanMiniscript/Psbt/ParseProofs.lean:31-34` | `Psbt.parse_serialize` | `Bitcoin/Psbt/ParseProofs.lean:34-36` (docstring at `:32`) |
| `LeanMiniscript/Psbt/ParseProofs.lean:40` | `Psbt.serialize_parse` | `Bitcoin/Psbt/ParseProofs.lean:43-45` |
| `LeanMiniscript/Psbt/Fields.lean:536-539` | `Psbt.parse` | `Bitcoin/Psbt/Fields.lean:570-573`; `Psbt.decode` at `:560-567` |
| `LeanMiniscript/Psbt/Fields.lean:206-207` | `validPublicKey`, replaced by the capability | `Bitcoin/Psbt/Fields.lean:398` (`cap.isValidPubkey`), `:413` and `:517` (`cap.compressPubkey`) |
| `LeanMiniscript/Psbt/Fields.lean:272-276` | `preimageHash` | `Bitcoin/Psbt/Fields.lean:287-291` |
| `LeanMiniscript/Psbt/Codec.lean:68-69` | `KeyValueMap.WellFormed`, including `Unique` | `Bitcoin/Psbt/Codec.lean:70-71`; `KeyValueMap.Unique` at `:62-63` |
| `LeanMiniscript/Psbt/Codec.lean:127` | `throw .trailingData` | `Bitcoin/Psbt/Codec.lean:129` |
| `LeanMiniscript/Bitcoin/Deserialization.lean:115-170` | `readTransaction` to `serializeWitnessTransaction` | `Bitcoin/Deserialization.lean:43-96`: reader `:43-73`, serializer `:87-96` |
| `LeanMiniscript/Bitcoin/Deserialization.lean:120-123` | Zero-flag path | `Bitcoin/Deserialization.lean:48-51`; the branch's result is at `:52` (upstream `:124`) |
| `LeanMiniscript/Bitcoin/DeserializationProofs.lean:31` | `readCompactSize_compactSize` | `Bitcoin/CompactSize.lean:121` |

`Bitcoin.Psbt.valid cap hashes p` is exactly
`p.WellFormed ∧ ∃ d, p.decode cap hashes = .ok d`. It uses neither parsing nor
serialization. Framing invariants alone do not suffice: a supplied capability
can reject a field's key. The round-trip uses both hypotheses of the copied
`Psbt.parse_serialize`; uniqueness follows from `Psbt.serialize_parse` and each
map's `WellFormed`. The trailing-data proof reads the known serialized maps
with the extra suffix left unread, then applies the complete-frame check.
Raw BIP32 keys remain byte-exact; `checkBip32SamePoint` is still separate.

`Bitcoin.Transaction.WellFormed tx witnesses` has exactly these nine fields:

| Field | Hypothesis | Wire-format reason |
|---|---|---|
| `txidSize` | Every input txid has size 32 | `Bitcoin/Deserialization.lean:10` reads exactly 32 bytes; the serializer writes the supplied bytes raw. |
| `scriptSigSize` | Every input script size is less than `2^64` | Its byte-vector prefix is CompactSize. |
| `scriptPubKeySize` | Every output script size is less than `2^64` | The same CompactSize bound applies. |
| `witnessItemSize` | Every item in every witness stack has size less than `2^64` | Each item uses a CompactSize byte-vector prefix. |
| `inputCount` | Input count is less than `2^64` | CompactSize represents at most `2^64 - 1`. |
| `outputCount` | Output count is less than `2^64` | The same bound applies. |
| `witnessCount` | Every stack length is less than `2^64` | Each stack starts with its CompactSize item count. |
| `witnessesLength` | Witness count equals input count | `Bitcoin/Deserialization.lean:88-96` ignores surplus stacks and supplies empty missing stacks; the reader reads one stack per input. |
| `unambiguous` | Inputs are nonempty or outputs are empty | `Bitcoin/Deserialization.lean:47-52` treats an empty input vector as the witness marker; flag zero denotes empty inputs and outputs. |

The shared bound is the hypothesis of
`Bitcoin.CompactSize.readCompactSize_compactSize` at `Bitcoin/CompactSize.lean:121`.
The library definitions and their signatures are unchanged. The transaction
proof first establishes field readers with arbitrary suffixes, then vector and
witness-stack readers, and finally the legacy and BIP144 branches.

### Copied proof files

Source: [febyeji/lean-miniscript at cb9bc5f](https://github.com/febyeji/lean-miniscript/tree/cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd).
The fresh clone's `git rev-parse HEAD` printed
`cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`, exit **0**, before copying.

| Source range under `LeanMiniscript/` | Destination under `packages/bitcoin/` | All port edits |
|---|---|---|
| `Psbt/CodecProofs.lean` L1–280 | `Bitcoin/Psbt/CodecProofs.lean` | Imports/namespaces mapped to `Bitcoin.Psbt` and `Bitcoin`; open `Bitcoin.CompactSize`; three `if_false` references become `ite_false`, one `if_true` becomes `ite_true`; first-line MIT provenance. |
| `Psbt/ParseProofs.lean` L1–65 | `Bitcoin/Psbt/ParseProofs.lean` | Imports/namespace mapped to `Bitcoin.Psbt`; implicit capability/hash binders and arguments threaded through `decode` and `parse`; first-line MIT provenance. |

The original theorem statements and proof strategies are preserved, apart
from the required supplied-operation parameters. The deprecated-lemma warnings
were observed in the first compiler check before replacement. No other Lean
4.35 proof fix was needed. The existing `Bitcoin/LICENSE-miniscript` is reused
unchanged, byte-identical to upstream's `LICENSE`. No roles, examples, or new
fixture slices are copied. All edits are registered in
[upstream fixes](docs/upstream-fixes.md#transaction-and-psbt-proofs-phase-4a-3-of-3)
and reconstructed by `check-tx-psbt-copy.py`.

### Executable definitions and the published exception

The four new selectable `valid definition` actions pin and print **10/10**, **4/4**,
**14/14**, and **6/6**, respectively: **34/34** total. Each obtains raw maps without
the field decoder, requires byte-exact serialization, and separately asserts
the library `WellFormed` and successful decode before evaluating `valid` itself
through its computational `Decidable` instance. This lets a stricter field
decoder fail specifically at the decode assertion.

`--psbt 'Transaction WellFormed'` reads all **136** inventory rows with each
row's `allowWitness`. Its checks are generated from the actual nine proposition
types in `Transaction.WellFormed.mk`, with `transactionChecks_iff` proving that
their conjunction is precisely the library definition. No parallel hand-written
predicate supplies the test result. Each exception conjunct has its own assertion.
The earlier vector, transaction and txid counts are unchanged; PSBT actions are
now **52/52**, up from 47 with these five actions.

**Finding:** exactly **135/136** transactions satisfy the definition. The sole
exception is `bip174Valid[9]`, global record 0, “PSBT with 0 inputs”: version 2,
zero inputs, two outputs, and no witnesses. It satisfies the first eight fields
and fails only `unambiguous`. With witnesses allowed, its serialization returns
exactly `Bitcoin.CompactSize.DecodeError.truncated`.
The measurement command, from `packages/bitcoin`, was
`nix develop -c lake env lean measure-psbt-exception.lean`, exit **0**:

```text
Except.ok (2, 0, 2, 0, Except.error (Bitcoin.CompactSize.DecodeError.truncated))
```

The probe loads the published vector, reads its global map, parses the unsigned
transaction with `allowWitness := false`, then calls the default reader on
`serializeWitnessTransaction`. The permanent selectable test pins this measured
constructor. This published transaction demonstrates why the ninth hypothesis
is necessary; no expectation or acceptance rule is adjusted.

### Axiom gate and copy check

The gate reports **764 library theorems; 60 named; 0 offenders**. The four
required theorems add four names to the earlier 56. The total rises from 652
by 112 through the imports of `Bitcoin.Psbt.CodecProofs`,
`Bitcoin.Psbt.ParseProofs`, `Bitcoin.Psbt.Proofs`, and
`Bitcoin.TransactionProofs`, including generated auxiliary theorems and
decision-instance obligations. `nix develop -c lake test` reproduces the named
and library counts. Test-support theorems are outside the library scan.
The allowlist is unchanged.

Each required `#print axioms` output is:

```text
'Bitcoin.Psbt.Psbt.roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.Psbt.Psbt.unique_of_parse' depends on axioms: [propext, Quot.sound]
'Bitcoin.Psbt.Psbt.no_trailing_data' depends on axioms: [propext, Classical.choice, Quot.sound]
'Bitcoin.parseTransaction_serializeWitnessTransaction' depends on axioms: [propext, Classical.choice, Quot.sound]
```

From the repository root,
`python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT/miniscript"`
exited **0**, printing ten exact-copy rows and:

```text
transaction/PSBT copy: 10/10; MIT notice reused; forbidden fixture slice excluded
```

### Mutation evidence

Every mutation changes production code or a production-loaded vector/inventory
list, never the test's expected value. Each source replacement asserts its exact
match count; `finally` restores and rechecks the original bytes. Stdout and
stderr are separate under `.lake/psbt-mutation-checks`. The compact, reproducible
records are in `test-data/psbt-mutations.json`, apart from the executable script.

The theorem mode now requires a diagnostic in a named theorem in a named file.
It computes that declaration's range from the unmutated file; this also retains
the same-file `readCompactSize_ok` check. The resume fingerprint covers all
library/test Lean modules, root modules, the lakefile, mutation targets, the
transaction inventory, the measurement helper and the runner itself. Checkpoint
writes use an atomic rename, and discovery checks cannot certify checkpoints.
The four mutation scripts with named-count pins now require 60.

The first eight transaction fields are independently strengthened to
`False ∧ (original field)` for their per-conjunct red checks. Each strengthened
round-trip implication remains true. The proofs derive their original wire
requirements from these hypotheses without depending on a particular conjunction
shape, allowing the field assertions to fail at runtime. Replacing the ninth
field by `True` makes the transaction round-trip false for the published
zero-input/two-output transaction, so its red check is proof-caught. The separate
count/exception check drops the empty-output disjunct, causing the published
zero-input/zero-output transaction at `bip174Valid[8]` to fail the definition too.

The `valid` action's final conjunction check follows from its two separately
asserted halves; those halves evaluate the library predicates themselves. Its
byte-equality check is guaranteed by successful framing and the copied framing
proofs. A changed separator makes `decodeMapFuel_encode` false. Likewise, no
runtime-only mutation can make an accepted frame's `WellFormed` half false while
the framing theorems stay true: the strengthened key-length mutation is caught
inside `decodeMapFuel_ok`.

The mutation selecting an index-read error left the measured result unchanged
(`lake test` exit **0**), so it was not retained. Changing the txid reader's
truncation error instead reaches the measured-error assertion while successful
reads, and thus the round-trip statement, stay unchanged. A two-second TERM
check of `partial-compression` printed `mutation applied` before interruption,
exited **143**, and `git diff --exit-code -- Bitcoin/Psbt/Fields.lean` then
exited **0**. The command was
`nix develop -c timeout --preserve-status --signal=TERM 2 python3 -I check-psbt-mutations.py partial-compression`.
The subsequent package build and full test both exited **0**.

All heavy commands use one foreground scope at a time:

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 nix develop -c lake test
```

Other heavy commands use the same limits with their own command arguments.
The required gate supervisor captures streams separately and propagates the
actual command status. No gate is piped through an output filter. Full-suite
reruns follow all Lean, test and fixture edits.

### Red runs for the new tests

The new properties have the following red records. Each selector is passed as
`lake test -- --psbt 'selector'`; the reproducible outer command is
`nix develop -c python3 -I check-psbt-mutations.py LABEL` from `packages/bitcoin`.
The exit column is the mutated `lake test` status. Each completed runner then
restores the source and requires a full `lake test` at exit **0**.

| Property | Mutation label | Selector | Exit | Observed first failure line |
|---|---|---|---|---|
| BIP174 valid count | `valid-count-bip174Valid` | `BIP174 valid definition` | 1 | `uncaught exception: assertion failed: BIP174 valid valid count` |
| BIP174 signer count | `valid-count-bip174SignerFailures` | `BIP174 signer valid definition` | 1 | `uncaught exception: assertion failed: BIP174 signer valid count` |
| BIP370 valid count | `valid-count-bip370Valid` | `BIP370 valid definition` | 1 | `uncaught exception: assertion failed: BIP370 valid valid count` |
| BIP371 valid count | `valid-count-bip371Valid` | `BIP371 valid definition` | 1 | `uncaught exception: assertion failed: BIP371 valid valid count` |
| BIP174 decode half | `valid-decode-bip174Valid` | `BIP174 valid definition` | 1 | `uncaught exception: assertion failed: BIP174 valid valid decode 0` |
| BIP174 signer decode half | `valid-decode-bip174SignerFailures` | `BIP174 signer valid definition` | 1 | `uncaught exception: assertion failed: BIP174 signer valid decode 0` |
| BIP370 decode half | `valid-decode-bip370Valid` | `BIP370 valid definition` | 1 | `uncaught exception: assertion failed: BIP370 valid valid decode 0` |
| BIP371 decode half | `valid-decode-bip371Valid` | `BIP371 valid definition` | 1 | `uncaught exception: assertion failed: BIP371 valid valid decode 0` |
| `valid` well-formed half | `valid-formed` | `BIP174 valid definition` | 1 | `error: Bitcoin/Psbt/CodecProofs.lean:189:46: omega could not prove the goal:` |
| Vector bytes equal serialization | `valid-bytes` | `BIP174 valid definition` | 1 | `error: Bitcoin/Psbt/CodecProofs.lean:45:16: unsolved goals` |
| 135/136 and sole exception identity | `formed-count-exception` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed count and exception` |
| Exception txid size | `formed-conjunct-txidSize` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception txidSize` |
| Exception input script bound | `formed-conjunct-scriptSigSize` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception scriptSigSize` |
| Exception output script bound | `formed-conjunct-scriptPubKeySize` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception scriptPubKeySize` |
| Exception witness item bound | `formed-conjunct-witnessItemSize` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception witnessItemSize` |
| Exception input count bound | `formed-conjunct-inputCount` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception inputCount` |
| Exception output count bound | `formed-conjunct-outputCount` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception outputCount` |
| Exception witness stack bound | `formed-conjunct-witnessCount` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception witnessCount` |
| Exception witness/input length equality | `formed-conjunct-witnessesLength` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception witnessesLength` |
| Exception marker condition | `formed-conjunct-unambiguous` | `Transaction WellFormed` | 1 | `error: Bitcoin/TransactionProofs.lean:150:91: omega could not prove the goal:` |
| Measured witness-reader error | `formed-error` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception measured error` |
| Loaded inventory count | `formed-inventory-count` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed inventory count` |
| Exactly nine reflected fields | `formed-conjunct-count` | `Transaction WellFormed` | 1 | `uncaught exception: assertion failed: formed exception conjunct count` |

### Reclassified PSBT records

These fourteen existing records move from their earlier runtime assertions to
proof detection. The old assertion column omits the common
`uncaught exception: assertion failed:` prefix. File paths below are relative
to `packages/bitcoin`; each diagnostic is inside the named theorem's range.

| Record | Old assertion | New theorem and diagnostic | Why the statement becomes false |
|---|---|---|---|
| `trailing-data` | `PSBT trailing data` | `decodePsbtWith_ok`, `Bitcoin/Psbt/CodecProofs.lean:277:32`, invalid rewrite argument | Accepted input can include an unread suffix, so it is not the returned PSBT's exact encoding. |
| `vector-bip174-valid` | `BIP174 valid 0 serialize` | `decodeMapFuel_encode`, `Bitcoin/Psbt/CodecProofs.lean:45:16`, unsolved goals | A separator of 1 is read as a key length instead of a separator. |
| `vector-bip174-signer` | `BIP174 signer failures 0 serialize` | `decodeMapFuel_encode`, `Bitcoin/Psbt/CodecProofs.lean:45:16`, unsolved goals | The same separator edit breaks exact map re-reading. |
| `vector-bip370-valid` | `BIP370 valid 0 serialize` | `decodeMapFuel_encode`, `Bitcoin/Psbt/CodecProofs.lean:45:16`, unsolved goals | The same separator edit breaks exact map re-reading. |
| `vector-bip371-valid` | `BIP371 valid 0 serialize` | `decodeMapFuel_encode`, `Bitcoin/Psbt/CodecProofs.lean:45:16`, unsolved goals | The same separator edit breaks exact map re-reading. |
| `vector-bip174-roles` | `BIP174 roles 0 serialize` | `decodeMapFuel_encode`, `Bitcoin/Psbt/CodecProofs.lean:45:16`, unsolved goals | The same separator edit breaks exact map re-reading. |
| `map-canonical` | `map canonical` | `decodeMapFuel_encode`, `Bitcoin/Psbt/CodecProofs.lean:45:16`, unsolved goals | The reader returns a separator as unread data instead of the specified suffix. |
| `exact-duplicate` | `exact duplicate` | `decodeMapFuel_ok`, `Bitcoin/Psbt/CodecProofs.lean:198:18`, `simp` made no progress | Disabling the duplicate check accepts maps whose keys are not unique. |
| `vector-bip174-invalid` | `BIP174 invalid hex 4` | `decodeMapFuel_ok`, `Bitcoin/Psbt/CodecProofs.lean:198:18`, `simp` made no progress | The same duplicate-check edit contradicts accepted-map well-formedness. |
| `rewrite-raw-input` | `hybrid false raw serialization` | `Psbt.parse_serialize`, `Bitcoin/Psbt/ParseProofs.lean:36:55`, unsolved goals | Rewriting an accepted raw input key changes the returned PSBT. |
| `rewrite-raw-output` | `hybrid true raw serialization` | `Psbt.parse_serialize`, `Bitcoin/Psbt/ParseProofs.lean:36:55`, unsolved goals | Rewriting an accepted raw output key changes the returned PSBT. |
| `network-magic` | `network magic` | `decodePsbtWith_ok`, `Bitcoin/Psbt/CodecProofs.lean:245:4`, `simp` made no progress | Bytes with an arbitrary five-byte prefix can be accepted, but serialization restores PSBT magic. |
| `witness-marker-flag` | `wire bip174Invalid[1] input roundtrip` | `readTransaction_witness`, `Bitcoin/TransactionProofs.lean:169:37`, unsolved goals | Flag 3 sets an unsupported bit and the reader rejects the serialized transaction. |
| `legacy-version` | `wire bip174Invalid[0] network roundtrip` | `serializeTransaction_data`, `Bitcoin/TransactionProofs.lean:115:44`, unsolved goals | Serialization writes version plus one instead of the original version. |

For `network-magic`, the earlier unused-simp diagnostic in
`decodePsbtWith_encode` is not the selected evidence: that theorem's statement
stays true. The record instead selects the diagnostic inside
`decodePsbtWith_ok`, whose statement becomes false. `surplus-witness-format`,
`malformed-witness-marker`, and `transaction-ignore-trailing` retain their
original runtime detection. No retained record is classified solely because
the proof of an unchanged statement broke.

### Full mutation reruns

All six commands ran sequentially from `packages/bitcoin`, with the scope limits
above and separated command streams under `.lake/psbt-proof-validation`.
Each PSBT mutation also retains its separate streams and checkpoint under
`.lake/psbt-mutation-checks`. No one-hour continuation was needed.

| Command | Exit | Detections | Restored full `lake test` |
|---|---|---|---|
| `nix develop -c python3 -I check-mutations.py` | 0 | 6/6 | 0 |
| `nix develop -c python3 -I check-base58-mutations.py` | 0 | 6/6 | 0 |
| `nix develop -c python3 -I check-bech32-mutations.py` | 0 | 18/18 | 0 |
| `nix develop -c python3 -I check-address-mutations.py` | 0 | 20/20 | 0 |
| `nix develop -c python3 -I check-psbt-mutations.py` | 0 | 95/95 | 0 |
| `nix develop -c python3 -I check-ripemd160-mutations.py` | 0 | 8/8 | 0 |

Total: **153/153** detections. In `mutations.json`, only the `axiom` record's
`AxiomGate.lean` diagnostic moves from line 74 to line 77, because the named list
grew. `base58-mutations.json`, `bech32-mutations.json`, `address-mutations.json`
and `ripemd160-mutations.json` are byte-identical to their prior records:
`git diff --exit-code --` on those four paths exits **0**. No non-PSBT
classification changes.

`psbt-mutations.json` grows from 72 to 95 records: fourteen reclassifications
above, explicit same-file theorem metadata on the already proof-caught
`map-noncanonical`, and 23 new properties. All **57** previously runtime-caught
records that remain runtime-caught are unchanged, including their exact first
failures. There are now **18 proof-caught** and **77 runtime-caught** records.
Each new first failure matches the corresponding README row exactly.

A fresh capped invocation of
`nix develop -c python3 -I check-psbt-mutations.py --resume` exited **0**,
reused all **95** unchanged source/test fingerprints, and finished with restored
`lake test` at exit **0**. It applied no mutation again.

### Final validation and cleanup

| Command | Directory | Exit | Observation |
|---|---|---|---|
| `nix develop -c lake build` | `packages/bitcoin` | 0 | Library and all four proof modules build. |
| `nix develop -c lake test` | `packages/bitcoin` | 0 | Valid sets 10/10, 4/4, 14/14, 6/6; transaction hypotheses 135/136 with `truncated`; prior counts unchanged; 52/52 PSBT actions; 764/60/0 axiom gate. |
| The six full mutation commands above | `packages/bitcoin` | 0 each | 153/153 detected; every restored full test exits 0. |
| `nix develop -c python3 -I check-psbt-mutations.py --resume` | `packages/bitcoin` | 0 | 95 checkpoints reused; no mutation reapplied; restored full test exits 0. |
| `nix develop -c lake env lean measure-psbt-exception.lean` | `packages/bitcoin` | 0 | The measured tuple and `truncated` error printed above. |
| `python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT/miniscript"` | root | 0 | 10/10 again after all mutations; MIT notice unchanged. |
| `nix flake check -L`, with all new files staged | root | 0 | All seven packages build and test in the sandbox; new vector, action and axiom counts printed. |
| `nix build` | root | 0 | Default executable built. |
| `./result/bin/cyberkrill` | root | 0 | `cyberkrill 0.1.0`. |
| The proof-placeholder check below | root | 0 | No matching Lean source; its grep exits 1. |
| The library decision-tactic grep below | root | 1 | Both streams empty. |
| The axiom-gate substring grep below | root | 1 | Both streams empty. |
| `git diff --check 156c518b8c23fad785f8fa5fe534e122e4ffae31` | root | 0 | Both streams empty. |
| `git diff --exit-code 156c518 --` on the original copied codecs, vector module and transaction inventory | root | 0 | Byte-identical production code and inventory; no acceptance-rule edits. |
| Exact staged-diff key-material scan below | root | 1 | Both streams empty; no match. |
| Added-line public-text scan and staged-content checks | root | 0 | No forbidden names, local paths or attribution trailers; 20 intended files; staged bytes match the files. |
| Exact-created-path cleanup with absence assertions | root | 0 | Fresh clone, temporary shell/cache files and three temporary local helpers removed. |

The hygiene commands were:

```bash
rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages || rc=$?; test "$rc" -eq 1
grep -rnE 'native_decide|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean
grep -F sorry packages/bitcoin/BitcoinTests/AxiomGate.lean
git diff --cached -U0 | grep '^+' | grep -n -E '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
```

The final scan's stdout and stderr are both **empty**, exit **1**. Source,
evidence, validation and cleanup streams remain separated under
`packages/bitcoin/.lake/psbt-proof-validation`, with the individual mutation
streams in their existing directories. All foreground commands finished.

Cleanup removed exactly the fresh `TMP_ROOT` with `shutil.rmtree` and asserted
its absence. It separately unlinked and checked the absence of the temporary
`Measure.lean`, `Counts.lean`, and `gate-wrapper.bash` helpers under
`.lake/psbt-proof-validation`. The permanent measurement helper remains in the
package. Each private gate directory was removed by its supervisor before the
final status was reported. Initial private gate scratch directories inherited
the default temporary location; they were removed on exit. Later invocations
exported `TMPDIR` before bootstrap as well as inside the gate commands.
No temporary clone, cache, test or helper process from this work session remains.
Normal build outputs and logs remain.

The changes were staged on the feature branch before the flake check,
then committed after review and merged to master.

### Second-round checks

- The exception assertion now has the measurement directory, command and output
  directly above it; the action prints its collected exception and returned error.
- The upstream-to-port table above locates all ten references by grep in both
  trees; every supplied upstream range contains the named definition or branch,
  except that the zero-flag range `:120-123` ends one line before that branch's
  result at upstream `:124`.
- The new-test red records now have their own heading, before the reclassified
  records; both tables retain their original rows.

From `packages/bitcoin`,
`nix develop -c lake env lean measure-psbt-exception.lean` exited **0** and printed:

```text
Except.ok (2, 0, 2, 0, Except.error (Bitcoin.CompactSize.DecodeError.truncated))
```

The full test and the isolated transaction action printed the computed line:

```text
Transaction.WellFormed: 135/136; exception bip174Valid[9] global; witness reader: Bitcoin.CompactSize.DecodeError.truncated
```

Every heavy command below used its own foreground scope with `MemoryMax=8G`,
`MemorySwapMax=0`, `OOMPolicy=continue`, `TasksMax=4096` and `timeout 3600`,
through the gate supervisor described above. Commands ran sequentially with
separate stdout and stderr under the repository root's
`.lake/psbt-proof-second-round`. The PSBT
check started without `--resume`, produced 95 fresh checkpoints, and needed no
continuation. The four required axiom lines match those printed above.

`$FIRST_ROUND` names the first round's development commit. The squash merge
keeps only the final tree, so the two rows that compare against it record a
check made before merging and cannot be rerun from the merged history.

| Command | Directory | Exit | Observation |
|---|---|---|---|
| `nix develop -c lake build` | `packages/bitcoin` | 0 | Package builds. |
| `nix develop -c lake test` | `packages/bitcoin` | 0 | Valid sets 10/10, 4/4, 14/14, 6/6; computed transaction line above; earlier counts unchanged; PSBT 52/52; axiom gate 764/60/0. |
| `nix develop -c lake test -- --psbt 'Transaction WellFormed'` | `packages/bitcoin` | 0 | Computed transaction line above; PSBT 1/1. |
| `nix develop -c lake test -- --psbt 'BIP174 valid definition'` | `packages/bitcoin` | 0 | 10/10; PSBT 1/1. |
| `nix develop -c lake test -- --psbt 'BIP174 signer valid definition'` | `packages/bitcoin` | 0 | 4/4; PSBT 1/1. |
| `nix develop -c lake test -- --psbt 'BIP370 valid definition'` | `packages/bitcoin` | 0 | 14/14; PSBT 1/1. |
| `nix develop -c lake test -- --psbt 'BIP371 valid definition'` | `packages/bitcoin` | 0 | 6/6; PSBT 1/1. |
| `nix develop -c python3 -I check-mutations.py` | `packages/bitcoin` | 0 | 6/6 detected; restored full test exits 0. |
| `nix develop -c python3 -I check-base58-mutations.py` | `packages/bitcoin` | 0 | 6/6 detected; restored full test exits 0. |
| `nix develop -c python3 -I check-bech32-mutations.py` | `packages/bitcoin` | 0 | 18/18 detected; restored full test exits 0. |
| `nix develop -c python3 -I check-address-mutations.py` | `packages/bitcoin` | 0 | 20/20 detected; restored full test exits 0. |
| `nix develop -c python3 -I check-psbt-mutations.py` | `packages/bitcoin` | 0 | 95/95 detected; restored full test exits 0. |
| `nix develop -c python3 -I check-ripemd160-mutations.py` | `packages/bitcoin` | 0 | 8/8 detected; restored full test exits 0. |
| `git diff --exit-code "$FIRST_ROUND" -- 'packages/bitcoin/test-data/*.json'` | root | 0 | No output; all six evidence JSON files and the other JSON fixtures are byte-identical to the first round. |
| `git -C "$TMP_ROOT/miniscript" rev-parse HEAD` | root | 0 | Fresh clone prints `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`. |
| `python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT/miniscript"` | root | 0 | 10/10; MIT notice reused; forbidden fixture slice excluded. |
| `nix flake check -L`, with the two edited paths staged | root | 0 | All seven packages build and test; expected PSBT and axiom counts printed. |
| `nix build` | root | 0 | Default executable built. |
| `./result/bin/cyberkrill` | root | 0 | `cyberkrill 0.1.0`. |
| Proof-placeholder command below | root | 0 | Its grep exits 1; no matches. |
| Library decision-tactic grep below | root | 1 | No output. |
| Axiom-gate substring grep below | root | 1 | No output. |
| `git diff --check 156c518b8c23fad785f8fa5fe534e122e4ffae31` | root | 0 | No output. |
| `git diff --exit-code "$FIRST_ROUND" -- packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean packages/bitcoin/lakefile.lean flake.nix flake.lock` | root | 0 | No output; production, proof and build definitions unchanged. |
| Staged key-material scan below | root | 1 | Stdout and stderr empty. |
| Whole-change key-material scan below | root | 1 | Stdout and stderr empty. |
| Added-line public-text and staged-content checks | root | 0 | No forbidden names, local paths or attribution trailers; staged bytes equal the two edited files. |
| `git status --short` | root | 0 | Only staged `README.md` and `packages/bitcoin/BitcoinTests/Psbt.lean`; no untracked files. |
| Exact-created-path cleanup and absence assertions | root | 0 | Fresh clone, temporary helpers, scratch files and caches removed. |

The hygiene and key-material commands were:

```bash
rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages || rc=$?; test "$rc" -eq 1
grep -rnE 'native_decide|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean
grep -F sorry packages/bitcoin/BitcoinTests/AxiomGate.lean
git diff --cached -U0 | grep '^+' | grep -n -E '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
git diff 156c518 -U0 | grep '^+' | grep -n -E '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
```

Both key-material scans printed nothing on either stream and exited **1**.
The final added lines were also checked for the public-text restrictions.
Cleanup removed exactly the newly created `TMP_ROOT` using `shutil.rmtree`
and asserted its absence. `TMPDIR` was beneath that root before every gate
bootstrap. Each private gate directory was removed before its final status.
No temporary clone, cache, helper or process from this work session remains;
normal build outputs and logs remain. The two edited paths were staged on the
feature branch, then committed after review and merged to master.

## Phase 4a: PSBT field parity follow-up

Five decode rules now match rust-bitcoin 0.32.8 without a curve operation.
Framing, raw storage, serializers, supplied-operation call shapes and theorem
statements are unchanged. The earlier length/key checks precede new checks,
retaining the exact signature-length, control-size and hybrid-key errors.

| Rule | rust-bitcoin 0.32.8 source | Must-reject inputs and exact port reasons |
|---|---|---|
| Global xpub version is 0488b21e or 043587cf | `src/bip32.rs:789-801`, called at `src/psbt/map/global.rs:113-118` | `xpub-version`: `invalidKey "global" 1 "invalid extended key version"` |
| Partial signature is nonempty and ends in 01/02/03/81/82/83 | `src/crypto/ecdsa.rs:38-43`, `src/crypto/sighash.rs:447-460`, `src/psbt/serialize.rs:179-200` | `partial-sig-empty`: `invalidValue "input" 2 "empty ECDSA signature"`; `partial-sig-sighash`: `invalidValue "input" 2 "non-standard ECDSA sighash type"` |
| Both 65-byte Taproot signature fields end in 00/01/02/03/81/82/83 | `src/crypto/taproot.rs:30-44`, `src/crypto/sighash.rs:500-512`, `src/psbt/serialize.rs:273-283` | `tap-key-sig-sighash`, `tap-script-sig-sighash`: `invalidValue "input" 19/20 "non-standard Taproot sighash type"` respectively |
| Leaf versions are even and not annex 50 | `src/taproot/mod.rs:1105-1116,1187-1196,1236-1243`, `src/psbt/serialize.rs:310-313,326-336,380-396` | `leaf-script-odd`, `leaf-script-annex`: `invalidValue "input" 21 "invalid leaf version"`; `control-block-annex`: `invalidKey "input" 21 "invalid control block leaf version"`; `out-tap-tree-annex`: `invalidValue "output" 6 "invalid leaf version"` |
| Proprietary key has at most 1,024 bytes after the one-byte subtype | `src/psbt/raw.rs:48,158-173,193-199`, `src/consensus/encode.rs:159-168` | `proprietary-1025`: `invalidKey "input" 252 "proprietary key data exceeds 1024 bytes"` |

The proprietary limit counts at most 1,025 bytes after the identifier, including
the first subtype byte, in every scope. It does not start at the end of our
canonical CompactSize subtype. The curve follow-up below now checks DER and
xpub/x-only/internal curve points. Taproot signature bytes need only their
length check: secp256k1 0.29.1 `src/schnorr.rs:78-87` checks no other property.
The three kept port-stricter BIP rules are unchanged and listed below.

### Pinned offline CLI capture

The reference dry run listed nothing to build, exit **0**:

```bash
nix build --dry-run --no-link github:douglaz/cyberkrill/27cad1faba86260b06665a89f0af5134d23525c2
```

`nix build --no-link --print-out-paths` of that reference also exited **0**.
`capture-cyberkrill-psbt.py` derives inputs by published name from the pinned
BIP174/370/371 vectors, asserts one-record edits, and captures all 49 invocations
of `onchain-decode-psbt`. Each receives Base64 on stdin in a fresh HOME and
working directory under `unshare -rn`, with loopback enabled and an explicit
minimal environment. Binary resolution happens first with the caller's HOME.
Temporary workspaces are deleted even on failure. See
[test-data provenance](packages/bitcoin/test-data/README.md#psbt-field-parity-capture).

Regenerate or check from the repository root, with `TMPDIR` set:

```bash
TMPDIR="${TMP_ROOT:?}" python3 -I packages/bitcoin/capture-cyberkrill-psbt.py
TMPDIR="${TMP_ROOT:?}" python3 -I packages/bitcoin/capture-cyberkrill-psbt.py --check
```

The record is `test-data/cyberkrill-psbt-capture.json` under `packages/bitcoin`.
It holds the reference/revision, base names, edits, Base64 and separate streams.
The Lean actions read those exact bytes, pin 49 rows and counts **19/14/16**,
and select each unique name with `lake test -- --psbt 'parity NAME'`.
The original 24 BIP370 invalid inputs remain pinned, including indices 1–12.

In the original field-parity capture, cyberkrill exited **1** on all ten
must-reject inputs, and each stderr named the
rust-bitcoin 0.32.8 error's Display text; the tracker item's table gives its
Debug form. All five bases and all eight edited acceptance boundaries exited
**0**. The curve follow-up adds nine rejections and one base with no
hand-derived expectation. All sixteen port-stricter inputs exit **0** upstream and are rejected
by the port. The four new port-stricter tests return exactly the reasons the
tracker item names:
`decode truncated`, `decode nonCanonicalCompactSize`,
`invalidKey "input" 252 "malformed proprietary key"`, and
`invalidValue "global" 1 "path length must match the extended key depth"`.
Every one of the five rules was therefore implemented.

| Input | Class | cyberkrill exit | stderr summary | Port decoder |
|---|---|---|---|---|
| `xpub-version` | must-reject | 1 | xpub key error -  Can't deserialize ExtendedPublicKey from global XPUB key data | reject |
| `partial-sig-sighash` | must-reject | 1 | non-standard sighash type: 4 | reject |
| `partial-sig-empty` | must-reject | 1 | invalid ECDSA signature | reject |
| `tap-key-sig-sighash` | must-reject | 1 | non-standard sighash type: 4 | reject |
| `tap-script-sig-sighash` | must-reject | 1 | non-standard sighash type: 4 | reject |
| `leaf-script-odd` | must-reject | 1 | invalid leaf version | reject |
| `leaf-script-annex` | must-reject | 1 | invalid leaf version | reject |
| `control-block-annex` | must-reject | 1 | invalid control block | reject |
| `out-tap-tree-annex` | must-reject | 1 | invalid leaf version | reject |
| `proprietary-1025` | must-reject | 1 | 1: parse failed: data not consumed entirely when explicitly deserializing | reject |
| `base-xpub` | must-accept | 0 | empty | accept |
| `base-partial` | must-accept | 0 | empty | accept |
| `base-key` | must-accept | 0 | empty | accept |
| `base-script` | must-accept | 0 | empty | accept |
| `base-tree` | must-accept | 0 | empty | accept |
| `partial-sig-83` | must-accept | 0 | empty | accept |
| `tap-key-sig-00` | must-accept | 0 | empty | accept |
| `tap-key-sig-83` | must-accept | 0 | empty | accept |
| `leaf-script-c2` | must-accept | 0 | empty | accept |
| `out-tap-tree-c2` | must-accept | 0 | empty | accept |
| `control-block-c2` | must-accept | 0 | empty | accept |
| `tpub` | must-accept | 0 | empty | accept |
| `proprietary-1024` | must-accept | 0 | empty | accept |
| `key-type-fd01` | port-stricter | 0 | empty | reject |
| `key-type-fd0500` | port-stricter | 0 | empty | reject |
| `proprietary-subtype-fd01` | port-stricter | 0 | empty | reject |
| `xpub-depth` | port-stricter | 0 | empty | reject |
| `bip370-invalid-1` | port-stricter | 0 | empty | reject |
| `bip370-invalid-2` | port-stricter | 0 | empty | reject |
| `bip370-invalid-3` | port-stricter | 0 | empty | reject |
| `bip370-invalid-4` | port-stricter | 0 | empty | reject |
| `bip370-invalid-5` | port-stricter | 0 | empty | reject |
| `bip370-invalid-6` | port-stricter | 0 | empty | reject |
| `bip370-invalid-7` | port-stricter | 0 | empty | reject |
| `bip370-invalid-8` | port-stricter | 0 | empty | reject |
| `bip370-invalid-9` | port-stricter | 0 | empty | reject |
| `bip370-invalid-10` | port-stricter | 0 | empty | reject |
| `bip370-invalid-11` | port-stricter | 0 | empty | reject |
| `bip370-invalid-12` | port-stricter | 0 | empty | reject |

### Field-parity mutation evidence

During the field-parity step, all six full commands below completed sequentially,
each in its own foreground scope with `MemoryMax=8G`, `MemorySwapMax=0`, `OOMPolicy=continue`,
`TasksMax=4096` and `timeout 3600`. No capped continuation was needed.
Each runner requires a full restored `lake test` at exit **0**.

| Command from `packages/bitcoin` | Exit | Detected |
|---|---|---|
| `nix develop -c python3 -I check-mutations.py` | 0 | 6/6 |
| `nix develop -c python3 -I check-base58-mutations.py` | 0 | 6/6 |
| `nix develop -c python3 -I check-bech32-mutations.py` | 0 | 18/18 |
| `nix develop -c python3 -I check-address-mutations.py` | 0 | 20/20 |
| `nix develop -c python3 -I check-psbt-mutations.py` | 0 | 117/117 |
| `nix develop -c python3 -I check-ripemd160-mutations.py` | 0 | 8/8 |

Total: **175/175**. All 95 earlier PSBT records are unchanged, and the other
five mutation JSON files are byte-identical to the base revision. The 22 added
records below cover ten rejections, eight edited acceptance boundaries and four
kept stricter rules. Each changes production behavior, restores it in `finally`,
and records separate streams under `.lake/psbt-mutation-checks`.
The table gives each exact first failure. Selectors are passed to
`lake test -- --psbt 'SELECTOR'`; every mutated command exits **1**.

| Mutation label | Selector | Exit | First failure line |
|---|---|---|---|
| `parity-xpub-version` | `parity xpub-version` | 1 | `uncaught exception: assertion failed: parity xpub-version: expected Bitcoin.Psbt.PsbtError.invalidKey "global" 1 "invalid extended key version", got accepted` |
| `parity-partial-sig-empty` | `parity partial-sig-empty` | 1 | `uncaught exception: assertion failed: parity partial-sig-empty: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 2 "empty ECDSA signature", got Bitcoin.Psbt.PsbtError.invalidValue "input" 2 "non-standard ECDSA sighash type"` |
| `parity-partial-sig-sighash` | `parity partial-sig-sighash` | 1 | `uncaught exception: assertion failed: parity partial-sig-sighash: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 2 "non-standard ECDSA sighash type", got accepted` |
| `parity-tap-key-sig-sighash` | `parity tap-key-sig-sighash` | 1 | `uncaught exception: assertion failed: parity tap-key-sig-sighash: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 19 "non-standard Taproot sighash type", got accepted` |
| `parity-tap-script-sig-sighash` | `parity tap-script-sig-sighash` | 1 | `uncaught exception: assertion failed: parity tap-script-sig-sighash: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 20 "non-standard Taproot sighash type", got accepted` |
| `parity-leaf-script-odd` | `parity leaf-script-odd` | 1 | `uncaught exception: assertion failed: parity leaf-script-odd: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 21 "invalid leaf version", got accepted` |
| `parity-leaf-script-annex` | `parity leaf-script-annex` | 1 | `uncaught exception: assertion failed: parity leaf-script-annex: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 21 "invalid leaf version", got accepted` |
| `parity-control-block-annex` | `parity control-block-annex` | 1 | `uncaught exception: assertion failed: parity control-block-annex: expected Bitcoin.Psbt.PsbtError.invalidKey "input" 21 "invalid control block leaf version", got accepted` |
| `parity-out-tap-tree-annex` | `parity out-tap-tree-annex` | 1 | `uncaught exception: assertion failed: parity out-tap-tree-annex: expected Bitcoin.Psbt.PsbtError.invalidValue "output" 6 "invalid leaf version", got accepted` |
| `parity-proprietary-1025` | `parity proprietary-1025` | 1 | `uncaught exception: assertion failed: parity proprietary-1025: expected Bitcoin.Psbt.PsbtError.invalidKey "input" 252 "proprietary key data exceeds 1024 bytes", got accepted` |
| `parity-partial-sig-83` | `parity partial-sig-83` | 1 | `uncaught exception: assertion failed: parity partial-sig-83 accepted: Bitcoin.Psbt.PsbtError.invalidValue "input" 2 "non-standard ECDSA sighash type"` |
| `parity-tap-key-sig-00` | `parity tap-key-sig-00` | 1 | `uncaught exception: assertion failed: parity tap-key-sig-00 accepted: Bitcoin.Psbt.PsbtError.invalidValue "input" 19 "non-standard Taproot sighash type"` |
| `parity-tap-key-sig-83` | `parity tap-key-sig-83` | 1 | `uncaught exception: assertion failed: parity tap-key-sig-83 accepted: Bitcoin.Psbt.PsbtError.invalidValue "input" 19 "non-standard Taproot sighash type"` |
| `parity-leaf-script-c2` | `parity leaf-script-c2` | 1 | `uncaught exception: assertion failed: parity leaf-script-c2 accepted: Bitcoin.Psbt.PsbtError.invalidValue "input" 21 "invalid leaf version"` |
| `parity-out-tap-tree-c2` | `parity out-tap-tree-c2` | 1 | `uncaught exception: assertion failed: parity out-tap-tree-c2 accepted: Bitcoin.Psbt.PsbtError.invalidValue "output" 6 "invalid leaf version"` |
| `parity-control-block-c2` | `parity control-block-c2` | 1 | `uncaught exception: assertion failed: parity control-block-c2 accepted: Bitcoin.Psbt.PsbtError.invalidKey "input" 21 "invalid control block leaf version"` |
| `parity-tpub` | `parity tpub` | 1 | `uncaught exception: assertion failed: parity tpub accepted: Bitcoin.Psbt.PsbtError.invalidKey "global" 1 "invalid extended key version"` |
| `parity-proprietary-1024` | `parity proprietary-1024` | 1 | `uncaught exception: assertion failed: parity proprietary-1024 accepted: Bitcoin.Psbt.PsbtError.invalidKey "input" 252 "proprietary key data exceeds 1024 bytes"` |
| `parity-key-type-fd01` | `parity key-type-fd01` | 1 | `uncaught exception: assertion failed: parity key-type-fd01: expected Bitcoin.Psbt.PsbtError.decode (Bitcoin.CompactSize.DecodeError.truncated), got accepted` |
| `parity-key-type-fd0500` | `parity key-type-fd0500` | 1 | `uncaught exception: assertion failed: parity key-type-fd0500: expected Bitcoin.Psbt.PsbtError.decode (Bitcoin.CompactSize.DecodeError.nonCanonicalCompactSize), got accepted` |
| `parity-proprietary-subtype-fd01` | `parity proprietary-subtype-fd01` | 1 | `uncaught exception: assertion failed: parity proprietary-subtype-fd01: expected Bitcoin.Psbt.PsbtError.invalidKey "input" 252 "malformed proprietary key", got accepted` |
| `parity-xpub-depth` | `parity xpub-depth` | 1 | `uncaught exception: assertion failed: parity xpub-depth: expected Bitcoin.Psbt.PsbtError.invalidValue "global" 1 "path length must match the extended key depth", got accepted` |

No existing mutation anchor or pinned published-vector count changed. The new
capture JSON is added to the resume fingerprint inputs. Nine exact replacement
steps register the field edits in `check-tx-psbt-copy.py`; the fresh upstream
checkout at `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd` reconstructs all ten files.
The three port-location rows in the preceding proof-source table moved at
that step because `Fields.lean` gained decoding checks: parse/decode to 560/552,
capability calls to 397/411/511, and preimage hashing to 286–290.
Historical phase counts and earlier command records remain historical.

The current PSBT action count is **101/101** after both parity follow-ups,
with one selectable action for each of the 49 capture rows. The field-parity
step had 91/91 actions, up from 52/52. The gate remains **764 library theorems; 60 named;
0 offenders**, with only `propext`, `Classical.choice` and `Quot.sound` allowed.
No library theorem count, statement, proof module or axiom allowlist changes.

### Field-parity validation and changed files

During the field-parity step, the following results were re-recorded on
2026-10-23 after the documentation corrections. Every command used `TMPDIR="${TMP_ROOT:?}"`; the six full mutation
commands and their results are recorded above.

| Command | Directory | Exit | Observation |
|---|---|---|---|
| `nix develop -c lake build` | `packages/bitcoin` | 0 | Package builds. |
| `nix develop -c lake test` | `packages/bitcoin` | 0 | All existing vectors and exact errors retained; 91/91 PSBT actions; 764/60/0 axiom gate. |
| `nix flake check -L` | root | 0 | Cached seven-package check reused; `running 0 flake checks...`, `all checks passed!`. |
| `nix build` | root | 0 | Existing default executable reused. |
| `./result/bin/cyberkrill` | root | 0 | `cyberkrill 0.1.0`. |
| `nix build --dry-run --no-link github:douglaz/cyberkrill/27cad1faba86260b06665a89f0af5134d23525c2` | root | 0 | Nothing to build. |
| `TMPDIR="${TMP_ROOT:?}" python3 -I packages/bitcoin/capture-cyberkrill-psbt.py --check` | root | 0 | All 39 derived inputs and captured streams reproduce exactly; private capture workspace removed. |
| `python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT/miniscript"` | root | 0 | `transaction/PSBT copy: 10/10; MIT notice reused; forbidden fixture slice excluded`. |
| Proof-placeholder command in the preceding validation section | root | 0 | Its grep exits 1; both streams empty. |
| Library decision-tactic grep in the preceding validation section | root | 1 | Both streams empty. |
| Axiom-gate substring grep in the preceding validation section | root | 1 | Both streams empty. |
| `git diff --check 5baad8bf0e283a948828ee5bb749fae5b2491469` | root | 0 | Both streams empty. |
| Exact staged key-material scan below | root | 1 | stdout empty; stderr empty; no matches or vector exceptions. |
| Same key-material scan over `git diff -U0 5baad8bf0e283a948828ee5bb749fae5b2491469` | root | 1 | stdout empty; stderr empty; no matches or vector exceptions. |
| `git diff --exit-code -- packages/bitcoin/test-data/` | root | 0 | All capture and mutation records unchanged by verification. |

The exact key-material scan was:

```bash
git diff --cached -U0 | grep '^+' | grep -n -E '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'
```

Validation streams remain separate under
`packages/bitcoin/.lake/psbt-field-parity-validation`; mutation streams remain
in each runner's existing directory. All heavy commands used their own capped
foreground scope. The capture command removes its own private workspace.
Cleanup removed exactly the newly created `TMP_ROOT`, including the fresh
lean-miniscript clone and temporary caches, and asserted that the root, clone
and `packages/bitcoin/__pycache__` were absent. No pre-existing external path
was removed. Normal build outputs and validation logs remain.

The field-parity step changed or added these twelve paths relative to its base:

- `packages/bitcoin/Bitcoin/Psbt/Fields.lean`: five decoding rules and seven named reasons.
- `packages/bitcoin/BitcoinTests/Psbt.lean`: 39 actions reading the captured bytes.
- `packages/bitcoin/capture-cyberkrill-psbt.py`: derivation and offline capture, plus `--check`.
- `packages/bitcoin/test-data/cyberkrill-psbt-capture.json`: the 39 captured rows.
- `packages/bitcoin/check-psbt-mutations.py`: 22 mutations and capture fingerprinting.
- `packages/bitcoin/test-data/psbt-mutations.json`: 117 records, with the earlier 95 unchanged.
- `packages/bitcoin/check-tx-psbt-copy.py`: nine exact replacement steps.
- `packages/bitcoin/test-data/README.md`: capture provenance and regeneration.
- `docs/upstream-fixes.md`: each change to copied decoding code.
- `README.md`: rule, capture, mutation, delta and validation records; three moved source locations.
- `plan.md`: only the provisional §3 clause, replaced with the measured 16-input result.
- `.beads/issues.jsonl`: the tracker item's status.

## Phase 4a: PSBT curve parity follow-up

Four decoding rules now use the supplied curve capability, preserving pure
Lean package boundaries, raw bytes and every theorem statement. The capability
gains exactly `isValidXOnlyPubkey` and `isValidDerSignature`; the xpub rule
reuses `isValidPubkey`. The C bindings use the immutable static context in
`packages/secp256k1/link_shim.c`, including a length guard before the x-only
parser reads its fixed 32 bytes. DER parsing rejects empty input and applies
neither verification nor a low-S rule.

| Rule and sites | rust-bitcoin 0.32.8 / secp256k1 0.29.1 source | Must-reject vectors and exact port reasons |
|---|---|---|
| Global xpub point, bytes 45–77 | bitcoin `src/bip32.rs:789-815`, `src/psbt/map/global.rs:113-118`; secp256k1 `src/key.rs:444-462` | `xpub-point`: `invalidKey "global" 1 "invalid extended key point"` |
| Partial-signature DER, excluding the last sighash byte | bitcoin `src/crypto/ecdsa.rs:38-43`, `src/psbt/serialize.rs:179-200`; secp256k1 `src/ecdsa/mod.rs:52-71` | `partial-sig-der`, `partial-sig-no-der`: `invalidValue "input" 2 "invalid DER signature"` |
| Five x-only key sites | bitcoin `src/psbt/serialize.rs:263-266,295-301`, `src/psbt/map/input.rs:331,341,346`, `src/psbt/map/output.rs:85,95`; secp256k1 `src/key.rs:1162-1180` | `xonly-in-internal`: `invalidValue "input" 23 "invalid x-only public key"`; `xonly-out-internal`: `invalidValue "output" 5 "invalid x-only public key"`; `xonly-in-tap-bip32`: `invalidKey "input" 22 "invalid x-only public key"`; `xonly-out-tap-bip32`: `invalidKey "output" 7 "invalid x-only public key"`; `xonly-in-tap-script-sig`: `invalidKey "input" 20 "invalid x-only public key"` |
| Control-block internal key, bytes 1–32 | bitcoin `src/taproot/mod.rs:1105-1121`, `src/psbt/serialize.rs:310-313`; secp256k1 `src/key.rs:1162-1180` | `control-block-internal`: `invalidKey "input" 21 "invalid control block internal key"` |

All existing checks retain their order. Partial signatures check the key,
nonempty value, sighash and then DER. Script-signature keys check length and
x-only parse before signature-value checks. Taproot BIP32 keys check length
and x-only parse before the origin; internal-key values check length before
x-only parse. Control blocks retain size, missing leaf version, masked control
leaf version and value leaf version checks, then check the internal point.
Global xpub points are checked in `Psbt.decode` after global decoding and map
counts, before input/output decoding. `globalCounts`, the framing call and
every theorem statement stay textually unchanged; no proof repair was needed.
The axiom gate still reports **764 library theorems; 60 named; 0 offenders**.
The test capability remains a shape-only stand-in: it rejects compressed
02/03 encodings of x = 5, wrong-length x-only keys and x = 5, and empty or
31-prefixed DER, while accepting every pinned published valid vector.

### Curve-function vectors

`Secp256k1.isValidXOnlyPubkey` uses the public-key columns of
[BIP340 at bitcoin/bips @ 927b6de](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340/test-vectors.csv).
`generate-bip340.py` fetches only during generation and retains index, public
key and comment, lowercasing the hex. It asserts that no secret-key column or
nonempty secret-key value remains, comparing without case sensitivity.
`bip340-public-keys.json.provenance` records the dropped columns and the CSV's
BSD-2-Clause OR MIT OR CC0-1.0 offer under `bip-0340/LICENSE` at the pinned
commit, taken under MIT. The corrected `LICENSE-bip340` reproduces that offer,
names the authors and carries the MIT permission notice and disclaimer.
The comment column supplies the oracle: **19 rows, 17 parsed, indices 5 and
14 rejected**. Lengths 0/31 and x = 5 are also rejected. The valid published
32-byte key from row 0 parses; that same key plus one byte (33 bytes) is rejected.
The fresh test printed:

```text
BIP340 x-only: 19 rows / 17 parsed / rejected indices 5,14; lengths 0,31 and x=5 rejected; published valid key parsed / key plus one byte (33) rejected
```

The committed Euler check proves 5³ + 7 = 132 is a quadratic non-residue modulo
p = 2²⁵⁶ − 2³² − 977 independently of the curve binding.

From the root, the generation command exited **0** and its subsequent
`git diff --exit-code -- packages/secp256k1/bip340-public-keys.json` exited
**0**, reproducing the committed file:

```bash
TMPDIR="${TMP_ROOT:?}" python3 -I packages/secp256k1/generate-bip340.py
```

It printed `BIP340 public keys: 19 rows; only index, public key and comment;
no secret-key values` and `Euler x=5: True`. The Euler expression in that
script is `pow(132, (p - 1) // 2, p) == p - 1`.

`Secp256k1.isValidDerSignature` reads
[Wycheproof's DER file at 7a32593](https://github.com/C2SP/wycheproof/blob/7a325932231bd7a724c791c8b0d65ea4d6d2f435/testvectors_v1/ecdsa_secp256k1_sha256_test.json)
through the new `WYCHEPROOF_DER_JSON` variable in the existing flake input.
The Apache-2.0-only vectors and subsets remain outside the repository.
Tests require the variable/file, 476 cases, 109 `EcdsaVerify` groups and unique
case ids. Every `valid` case must parse; every case with `BerEncodedSignature`,
`InvalidEncoding` or `InvalidTypesInSignature` must fail. Other invalid cases
have no per-case parse assertion: verification verdicts do not determine DER
parsing, and libsecp256k1 permits well-encoded out-of-range integers.
The following aggregate counts are **measured regression counts**, separately
pinned from that oracle:

```text
Wycheproof DER measured: 476 cases / 109 groups; valid parsed 168; encoding rejected 162; ModifiedSignature rejected 31 / parsed 17; overall parsed 283 / rejected 193
```

The unchanged BIP174 one-signature DER part parses; replacing its first 30
byte by 31, and empty input, both fail. Its provenance comment cites
bitcoin/bips @ `927b6de9915c9262615a6399de51b200f81e5aa4`, `bip-0174.mediawiki`,
BSD-2-Clause, with the existing BIP174 notice. No bitcoin import is added to
the binding package. Existing BOLT, P1363 and compression counts are unchanged.

### Extended offline capture

The capture has **49 rows: 19 must-reject, 14 must-accept, 16 port-stricter**.
The original 39 row objects remain identical and in their original order;
the script checks equality before writing. Nine curve edits and the unchanged
`base-key-output` are appended. Every edit checks its byte offsets and lengths,
including preserving the xpub prefix, control byte and script-signature leaf
hash. All six distinct bases parse in the port and exit 0 in the reference.

| New input | Reference exit | stderr summary |
|---|---|---|
| `xpub-point` | 1 | `xpub key error -  Can't deserialize ExtendedPublicKey from global XPUB key data` |
| `partial-sig-der` | 1 | `invalid ECDSA signature` |
| `partial-sig-no-der` | 1 | `invalid ECDSA signature` |
| `xonly-in-internal` | 1 | `invalid xonly public key` |
| `xonly-in-tap-bip32` | 1 | `invalid xonly public key` |
| `xonly-in-tap-script-sig` | 1 | `invalid xonly public key` |
| `xonly-out-internal` | 1 | `invalid xonly public key` |
| `xonly-out-tap-bip32` | 1 | `invalid xonly public key` |
| `control-block-internal` | 1 | `invalid control block` |
| `base-key-output` | 0 | empty |

Each expected error is mechanically confirmed from stderr. No contingency
or hand-derived expectation was needed. The dry run of the pinned reference
exited 0 with nothing to build. The fresh `--check` invocation exited 0 with
`PSBT capture: 49/49; existing 39 rows unchanged; 9 curve errors confirmed;
temporary workspace removed`. The method remains stdin to the offline CLI
in a fresh empty HOME/working directory, with temporary workspaces removed.

### Curve-site mutation evidence

Eight independent production mutations bypass exactly one decoder site each.
The xpub mutation evaluates the capability call and ORs its result with `true`,
retaining the loop variable's use. The other seven replace their site's call
with `true`, anchored on that field's branch. Tests, expected values and the
test capability are unchanged. Every row ran `lake test -- --psbt 'SELECTOR'`,
exited **1**, and reached its runtime assertion after the 764/60/0 axiom gate.

| Mutation label | Selector | Exit | First failure line |
|---|---|---|---|
| `parity-xpub-point` | `parity xpub-point` | 1 | `uncaught exception: assertion failed: parity xpub-point: expected Bitcoin.Psbt.PsbtError.invalidKey "global" 1 "invalid extended key point", got accepted` |
| `parity-partial-sig-der` | `parity partial-sig-der` | 1 | `uncaught exception: assertion failed: parity partial-sig-der: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 2 "invalid DER signature", got accepted` |
| `parity-xonly-in-internal` | `parity xonly-in-internal` | 1 | `uncaught exception: assertion failed: parity xonly-in-internal: expected Bitcoin.Psbt.PsbtError.invalidValue "input" 23 "invalid x-only public key", got accepted` |
| `parity-xonly-out-internal` | `parity xonly-out-internal` | 1 | `uncaught exception: assertion failed: parity xonly-out-internal: expected Bitcoin.Psbt.PsbtError.invalidValue "output" 5 "invalid x-only public key", got accepted` |
| `parity-xonly-in-tap-bip32` | `parity xonly-in-tap-bip32` | 1 | `uncaught exception: assertion failed: parity xonly-in-tap-bip32: expected Bitcoin.Psbt.PsbtError.invalidKey "input" 22 "invalid x-only public key", got accepted` |
| `parity-xonly-out-tap-bip32` | `parity xonly-out-tap-bip32` | 1 | `uncaught exception: assertion failed: parity xonly-out-tap-bip32: expected Bitcoin.Psbt.PsbtError.invalidKey "output" 7 "invalid x-only public key", got accepted` |
| `parity-xonly-in-tap-script-sig` | `parity xonly-in-tap-script-sig` | 1 | `uncaught exception: assertion failed: parity xonly-in-tap-script-sig: expected Bitcoin.Psbt.PsbtError.invalidKey "input" 20 "invalid x-only public key", got accepted` |
| `parity-control-block-internal` | `parity control-block-internal` | 1 | `uncaught exception: assertion failed: parity control-block-internal: expected Bitcoin.Psbt.PsbtError.invalidKey "input" 21 "invalid control block internal key", got accepted` |

The fresh full invocation of `nix develop -c python3 -I check-psbt-mutations.py`
on 2026-10-24 exited **0** after **2160.69 seconds**:
`PSBT mutations: 125/125 detected; restored lake test: EXIT=0`.
All **117** existing record objects are identical to the base revision;
the eight runtime rows above are appended in `test-data/psbt-mutations.json`.
No existing diagnostic line number or pinned theorem count changed.
The generated record is byte-identical to the committed file. No timeout
continuation or `--resume` was needed.

The binding runner, `nix develop -c python3 -I check-negative-mutations.py`
from `packages/secp256k1`, exited **0** with **44/44** negative mutations
(the original 42 plus two) and **18/18** compression mutations detected.
Each new mutation returns true at the start of its production shim; it never
removes the fixed-length x-only guard or reads beyond an input. Separate
streams and records retain the existing `.lake/mutation-checks` layout.

| Property | Command | Exit | First failure line |
|---|---|---|---|
| x-only off-curve | `lake test -- --negative 'x-only off-curve'` | 1 | `uncaught exception: assertion failed: x-only off-curve` |
| DER empty | `lake test -- --negative 'DER empty'` | 1 | `uncaught exception: assertion failed: DER empty` |

The existing compression guard-removal experiment still exits **0**, recorded
separately from the 18 detected mutations. Every temporary adapter edit is
restored in `finally`.

### Final curve-parity validation

On 2026-10-24, commands ran in the foreground with separate stdout and stderr
under `packages/bitcoin/.lake/curve-parity-recheck-20261024`.
Every heavy command used its own scope with `MemoryMax=8G`, `MemorySwapMax=0`,
`OOMPolicy=continue`, `TasksMax=4096` and `timeout 3600`, one at a time.
`TMPDIR` was set to the private `TMP_ROOT`. No timeout continuation was needed.
`nix develop -c bash -c 'lean --version && python3 --version && git --version && nix --version'`
exited **0**: Lean **4.35.0** Release, Python **3.14.7**, Git **2.54.0**,
Nix **2.34.8**. The configured library directory identifies the pinned
libsecp256k1 **0.8.0** package, checked in the same invocation by
`test "${SECP256K1_LIB_DIR#*-secp256k1-0.8.0/}" != "$SECP256K1_LIB_DIR"`
and printing `libsecp256k1: 0.8.0`. Outside the development shell,
`python3 --version` exited **0** and printed **Python 3.13.15**; this is the
interpreter used for the capture, copy check and BIP340 generation.

All seven full mutation commands completed with these results:

| Directory | Command | Exit | Detected |
|---|---|---|---|
| `packages/bitcoin` | `nix develop -c python3 -I check-mutations.py` | 0 | 6/6 |
| `packages/bitcoin` | `nix develop -c python3 -I check-base58-mutations.py` | 0 | 6/6 |
| `packages/bitcoin` | `nix develop -c python3 -I check-bech32-mutations.py` | 0 | 18/18 |
| `packages/bitcoin` | `nix develop -c python3 -I check-address-mutations.py` | 0 | 20/20 |
| `packages/bitcoin` | `nix develop -c python3 -I check-psbt-mutations.py` | 0 | 125/125 |
| `packages/bitcoin` | `nix develop -c python3 -I check-ripemd160-mutations.py` | 0 | 8/8 |
| `packages/secp256k1` | `nix develop -c python3 -I check-negative-mutations.py` | 0 | 44/44 negative; 18/18 compression |

The Bitcoin total is **183/183**. All five other Bitcoin mutation-record
files are byte-identical to the base revision. The PSBT record appends eight
objects while retaining the original 117 unchanged. The only changed pinned
counts are PSBT actions **91 → 101**, capture rows **39 → 49** with classes
**10/13/16 → 19/14/16**, PSBT mutations **117 → 125**, and binding negative
mutations **42 → 44**. Published PSBT set counts and theorem counts are unchanged.

The fresh commands and observations are:

| Directory | Command | Exit | Observation |
|---|---|---|---|
| `packages/secp256k1` | `nix develop -c lake build` | 0 | Package builds. |
| `packages/secp256k1` | `nix develop -c lake test` | 0 | BOLT 16/16 recovery/signing; P1363 252 loaded / 95 accepted / 157 rejected; 108 compression keys / 1944 checks; BIP340 and measured DER counts above; `negative tests: PASS`. |
| `packages/bitcoin` | `nix develop -c lake build` | 0 | Package builds. |
| `packages/bitcoin` | `nix develop -c lake test` | 0 | All pinned valid/invalid sets retained; 101/101 PSBT actions; 764/60/0 axiom gate. |
| `packages/secp256k1` | `nix develop -c bash -c 'cc -fsyntax-only -I "$(lean --print-prefix)/include" -include .lake/build/ir/Secp256k1.c link_shim.c'` | 0 | Generated declarations and shim definitions compile together. |
| root | `nix flake check -L --max-jobs 1 --cores 4` | 0 | Actual rebuild in 110.55 seconds; all seven package builds/tests and the one-OpenSSL checks; `all checks passed!`. |
| root | `nix build --max-jobs 1 --cores 4` | 0 | Reuses the checked default executable; empty stdout, dirty-tree warning on stderr. |
| root | `./result/bin/cyberkrill` | 0 | `cyberkrill 0.1.0`; empty stderr. |
| root | `nix build --dry-run --no-link github:douglaz/cyberkrill/27cad1faba86260b06665a89f0af5134d23525c2` | 0 | Nothing to build; empty stdout/stderr. |
| root | `TMPDIR="${TMP_ROOT:?}" python3 -I packages/bitcoin/capture-cyberkrill-psbt.py --check` | 0 | 49/49 reproduced; temporary capture workspace removed. |
| root | `git diff --exit-code -- packages/bitcoin/test-data/cyberkrill-psbt-capture.json` | 0 | Both streams empty; capture file unchanged. |
| root | `git clone --no-checkout https://github.com/febyeji/lean-miniscript "$TMP_ROOT/miniscript"` | 0 | Fresh clone; copied nothing into the tree. |
| root | `git -C "$TMP_ROOT/miniscript" checkout cb9bc5f` | 0 | Pinned checkout. |
| root | `git -C "$TMP_ROOT/miniscript" rev-parse HEAD` | 0 | Asserted exact revision `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`. |
| root | `python3 -I packages/bitcoin/check-tx-psbt-copy.py "$TMP_ROOT/miniscript"` | 0 | Fresh pinned checkout; `transaction/PSBT copy: 10/10; MIT notice reused; forbidden fixture slice excluded`. |
| root | `TMPDIR="${TMP_ROOT:?}" python3 -I packages/secp256k1/generate-bip340.py` | 0 | 19 public-key rows; no secret-key values; `Euler x=5: True`. |
| root | `git diff --exit-code -- packages/secp256k1/bip340-public-keys.json` | 0 | Regeneration reproduces the committed file. |
| root | `grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages` | 1 | Both streams empty. |
| root | `grep -rnE 'native_decide\|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean packages/secp256k1/Secp256k1.lean` | 1 | Both streams empty. |
| root | `git diff --check 86f429e4fae17c88ab3ee894573c498cab75d1dd` | 0 | Both streams empty. |
| root | `git diff --stat 86f429e4fae17c88ab3ee894573c498cab75d1dd -- flake.lock plan.md AGENTS.md packages/cyberkrill packages/lightning packages/fedimint-invite packages/http-curl packages/sha256` | 0 | Empty; an additional assertion confirms those paths and all proof modules are unchanged. |
| root | `git diff --stat 86f429e4fae17c88ab3ee894573c498cab75d1dd -- ':(glob)packages/bitcoin/Bitcoin/**/*Proofs*.lean' packages/bitcoin/BitcoinTests/AxiomGate.lean` | 0 | Both streams empty. |
| root | `find packages -name __pycache__ -not -path '*/.lake/*'` | 0 | Both streams empty. |

The public-text scan over the full diff excluding the tracker
is recorded separately from the key-material scan. Both operate on saved added
lines, so each command runs unpiped and retains its own exit code and separate
streams. The scan commands below use `BASE=86f429e4fae17c88ab3ee894573c498cab75d1dd`
and `LOGS=packages/bitcoin/.lake/curve-parity-recheck-20261024`.

```bash
git diff -U0 "$BASE" > "$LOGS/21-key-diff.stdout" 2> "$LOGS/21-key-diff.stderr"
grep '^+' "$LOGS/21-key-diff.stdout" > "$LOGS/21-key-added.stdout" 2> "$LOGS/21-key-added.stderr"
grep -nE '[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$LOGS/21-key-added.stdout"
git diff -U0 "$BASE" -- . ':(exclude).beads/**' > "$LOGS/22-public-diff.stdout" 2> "$LOGS/22-public-diff.stderr"
grep '^+' "$LOGS/22-public-diff.stdout" > "$LOGS/22-public-added.stdout" 2> "$LOGS/22-public-added.stderr"
```

The public-text scan then ran a case-insensitive `grep -niP` over
`22-public-added.stdout` for every category AGENTS.md's "Public text" rule
forbids. The expression is not reproduced here because it consists of the
forbidden words themselves.
The key-material and public-text scans each exited **1**, with **empty stdout
and stderr**. The public-text expression permits the literal instruction
filename `AGENTS.md`; the broader initial expression matched that filename in
the boundary-check command above. No key-material exception was needed.

The changed paths are:

- Under `packages/bitcoin`, `Bitcoin/Psbt/Capability.lean`, `Bitcoin/Psbt/Fields.lean`
  and `BitcoinTests/Psbt.lean`: two operations, eight sites, nine rejections and
  one additional base.
- Under `packages/bitcoin`, `capture-cyberkrill-psbt.py`, `check-psbt-mutations.py`,
  `check-tx-psbt-copy.py`, `test-data/cyberkrill-psbt-capture.json`,
  `test-data/psbt-mutations.json` and `test-data/README.md`: reproducible capture,
  mutation evidence, exact copied-code registration and provenance.
- Under `packages/secp256k1`, `Secp256k1.lean`, `link_shim.c`,
  `Secp256k1Tests.lean`, `check-negative-mutations.py`, `generate-bip340.py`,
  `bip340-public-keys.json`, `bip340-public-keys.json.provenance` and
  `LICENSE-bip340`: bindings, vector tests, red runs and the corrected MIT licence record.
- `flake.nix`: only the additional DER-vector environment variable.
  `README.md`, `docs/upstream-fixes.md` and `.beads/issues.jsonl`: documentation
  and task status.

`plan.md` is unchanged. Its §2 `secp256k1` function list and `bitcoin`
capability description now omit the two new operations and their decoder
sites; those omissions are reported without editing the plan.

## Phase 4b: BIP39 entropy and English words

`import Bitcoin` exposes `Bitcoin.Bip39.entropyToMnemonic : ByteArray →
Except Error (List String)` and `mnemonicToEntropy : List String → Except
Error ByteArray`. Both functions are pure Lean and use the existing qualified
`Sha256.hash`. They add no dependency, FFI or CLI command.

| `Bitcoin.Bip39.Error` constructor | Meaning |
|---|---|
| `badEntropyLength` | Encoder input is not 16, 20, 24, 28 or 32 bytes |
| `badWordCount` | Decoder input is not 12, 15, 18, 21 or 24 words |
| `unknownWord position` | First unknown word; `position` is **zero-based** |
| `badChecksum` | The supplied checksum bits differ from the SHA-256 prefix |

The error type derives `Repr`, `DecidableEq` and `BEq`. Decoding checks **word
count first, then each word from left to right, then checksum**. Words must
match the published lines exactly: no case folding, trimming, Unicode
normalisation or four-letter-prefix expansion. The input is already split.
There is no v1 mnemonic-decoding command.

For ENT = eight times the byte length, CS = ENT/32. The encoder concatenates
the entropy with the first CS bits of `Sha256.hash e`, then emits 11-bit
big-endian indices. Fixed-width radix conversion preserves leading zero
bytes and indices. The decoder reverses that conversion and checks the
checksum before returning the entropy.

### Published sources and tests

The English list is [bitcoin/bips `bip-0039/english.txt`](https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0039/english.txt)
at `130b8e0fa7f30fa45532f080b87b8db27a79e46e`, SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
A fresh fetch confirmed 13,116 bytes, 2,048 LF-terminated lines, a final newline,
no CR, lowercase ASCII words of 3–8 letters, strict order and no duplicates.
`Bitcoin/bip39-english.txt` is byte-identical. The library's reformatted list
is checked against every line in order. One string literal is split into two
concatenated pieces to avoid a false positive in the proof-token scan.
The sidecar records provenance; `Bitcoin/LICENSE-bip39` reproduces the BIP's
authors, MIT declaration and copyright section, and the MIT permission notice
and disclaimer. The BIP supplies no copyright year or holder line.

The vector source is [trezor/python-mnemonic `vectors.json`](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json)
at `b57a5ad77a981e743f4167ab2f7927a55c1e82a8`, SHA-256
`fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8`.
The extract retains **24 English rows: eight each of 12, 18 and 24 words**,
with exactly `entropy` and `mnemonic` fields. It drops every seed and xprv
column and all eleven other languages. The MIT notice credits Pavol Rusnak,
2013–2016, in `test-data/LICENSE-python-mnemonic`; the extraction sidecar names
the changes. The full upstream JSON is never kept in the repository.

Regenerate from the root, with `TMP_ROOT` set to a private temporary workspace:

```bash
TMPDIR="${TMP_ROOT:?}" python3 -I packages/bitcoin/generate-bip39-vectors.py
git diff --exit-code -- packages/bitcoin/test-data/bip39-english-vectors.json
```

The script verifies the source digest and counts, permits only the two retained
fields, and asserts that none of the 24 English seeds or xprvs appears in its
output. The tests reject missing or extra fields. Every test set pins its count
before checking cases. Failure labels contain set/case identifiers, never words
or entropy. All derived cases are constructed at test time from published rows;
no derived mnemonic is committed and no entropy source is used.

| Printed BIP39 set | Count | Checks |
|---|---|---|
| `bip39 wordlist` | 2048/2048 | File digest, byte length, LF termination and ordered library equality |
| `bip39 English` | 24/24 | Published encoding and decoding |
| `bip39 English-12`, `English-18`, `English-24` | 8/8 each | Published word-count groups |
| `bip39 derived-15`, `derived-21` | 8/8 each | First 20/28 entropy bytes of every 24-word source; word counts and both round trips |
| `bip39 bad-checksum` | 40/40 | Last index bit flipped; checksum error |
| `bip39 bad-checksum-12/15/18/21/24` | 8/8 each | Every accepted word count covered |
| `bip39 unknown-word` | 5/5 | Absent string, capitalised word, trailing space, four-letter prefix and empty string; exact positions |
| `bip39 check-order` | 3/3 | Count before unknown word; unknown before checksum; first unknown position |
| `bip39 bad-word-count` | 8/8 | 11, 13, 25, 0, 14, 16, 20 and 22 words |
| `bip39 bad-entropy-length` | 5/5 | 0, 15, 17, 33 and 36 bytes by truncation or append |

`lake test -- --bip39 NAME` selects `wordlist`, `english`, `derived-15`,
`derived-21`, `bad-checksum`, `unknown-word`, `check-order`, `bad-word-count`
or `bad-entropy-length`. The complete suite includes them all. An independent
Python `hashlib` computation outside the tree matched all **16/16** derived
15/21-word encodings through `lake env lean --run "$TMP_ROOT/Cross.lean"
"$TMP_ROOT/derived-crosscheck.json"`, exit **0**. None of its derived output is
committed.

### Proof statements and checking cost

The following are the exact three statements in `Bitcoin/Bip39.lean`, in
namespace `Bitcoin.Bip39`. `validEntropyLength n` means
`n = 16 ∨ n = 20 ∨ n = 24 ∨ n = 28 ∨ n = 32`; `validWordCount n` means
`n = 12 ∨ n = 15 ∨ n = 18 ∨ n = 21 ∨ n = 24`.
`beNat` reads a byte array big-endian. The transparent generic `beDigits base`
reads a natural-number digit list big-endian, equivalently folding
`fun acc i => acc * base + i` from zero.

```lean
theorem mnemonicToEntropy_entropyToMnemonic (e : ByteArray)
    (h : validEntropyLength e.size) :
    ∃ ws, entropyToMnemonic e = .ok ws ∧ ws.length = e.size * 3 / 4 ∧
      mnemonicToEntropy ws = .ok e

theorem entropyToMnemonic_mnemonicToEntropy (ws : List String) (e : ByteArray)
    (h : mnemonicToEntropy ws = .ok e) : entropyToMnemonic e = .ok ws

theorem mnemonicToEntropy_checksum_mismatch
    (ws : List String) (idx : List Nat) (e : ByteArray)
    (hcount : validWordCount ws.length)
    (hidx : ∀ i ∈ idx, i < 2048)
    (hws : ws = idx.map (fun i => wordlist[i]!))
    (he_size : e.size = (ws.length * 11 - ws.length / 3) / 8)
    (he : beNat e = beDigits 2048 idx / 2 ^ (ws.length / 3))
    (hbad : beDigits 2048 idx % 2 ^ (ws.length / 3) ≠
      beNat (Sha256.hash e) / 2 ^ (256 - ws.length / 3)) :
    mnemonicToEntropy ws = .error .badChecksum
```

For every valid count and in-range index list, the entropy hypotheses are
satisfiable: the fixed-width big-endian encoding of N/2^CS fits in ENT/8 bytes,
since N < 2048^count = 2^(ENT+CS). The mismatch hypothesis compares the actual
trailing index bits with the prefix of `Sha256.hash` of that entropy, independently
of the decoder's checksum helper. **BIP39's checksum gives no error-detection
guarantee beyond this comparison, and none is claimed.**

The initial kernel experiment checked all 2,047 adjacent `String` comparisons
on the real list, outside the library. It used
`((words.zip words.tail).all (fun p => decide (p.1 < p.2))) = true`, proved by
`decide +kernel`. Its command, from `packages/bitcoin`, was:

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 "$TIME_BIN" -v nix develop -c lake env lean "$TMP_ROOT/Sorted.lean"
```

Here `TIME_BIN` is GNU Time **1.10**. The experiment exited **0** in **36.80 s**,
with **5,159,200 KiB** peak RSS. Its printed axioms were only `propext`,
`Classical.choice` and `Quot.sound`. That memory use left less headroom under
the 8 GiB cap than the permitted base-27 fallback. The fallback pads codes to
eight digits, checks increasing adjacent natural numbers, derives pairwise
order and then no duplicates. It exited **0** in **19.67 s**, with
**3,768,028 KiB** peak RSS and the same permitted axioms. An earlier scratch
decidability instance using a recursor failed code generation, exit **1**;
the structural recursive instance above is the measured successful version.

On the final sources, timed `nix develop -c lake build` took **0.56 s** cached.
Removing only the newly created wordlist-proof `.olean` and rebuilding with
the same command took **19.44 s**, **3,742,600 KiB** peak RSS, exit **0**:
**18.88 s** additional wall time. Lake reported the proof module itself at
18 s. The scope, timeout and `time -v` wrapper were identical to the example
above. No scope exceeded the cap or timed out.

The final fresh axiom gate is **852 library theorems; 65 named; 0 offenders**,
up from **764; 60; 0**. The 88 additions are 81 in `Bitcoin.Bip39` and seven
in `Bitcoin.Bip39WordlistProofs`: 31 explicit theorems and 57 generated
declarations. The five new named entries are T1–T3 above, `wordlist_nodup`
and `wordlist_length`, each with its own `#print axioms`. A fresh local
`nix develop -c lake test` printed
`'Bitcoin.Bip39.wordlist_length' depends on axioms: [propext]`, matching the
sandbox length check.
Both checks printed only the permitted three for the other named theorems.
The full library scan also passes. Every existing theorem statement is unchanged.

### Mutation evidence

From `packages/bitcoin`, `nix develop -c python3 -I check-bip39-mutations.py`
exited **0**, detecting **9/9**, then restored full `lake test` exited **0**.
The script uses exact-count production edits, restores and byte-checks sources
in `finally`, and stores separate streams under `.lake/bip39-mutation-checks`.
Compact records are in `test-data/bip39-mutations.json`. Each proof-caught
mutation pins exactly one theorem whose statement the edit falsifies. The
runner records the first diagnostic inside that theorem's range in the
original source and fails if none exists. Each selector
below follows `lake test -- --bip39`.

| Mutation | Selector | Exit | Pinned theorem or test and exact recorded failure line |
|---|---|---|---|
| `skip-checksum` | `bad-checksum` | 1 | T3 build: ``error: Bitcoin/Bip39.lean:373:9: Tactic `unfold` failed to unfold `checksum` in`` |
| `checksum-length-plus-one` | `english` | 1 | T1 build: ``error: Bitcoin/Bip39.lean:307:6: Tactic `rfl` failed: The left-hand side`` |
| `word-index-plus-one` | `english` | 1 | T1 build: ``error: Bitcoin/Bip39.lean:307:6: Tactic `rfl` failed: The left-hand side`` |
| `lookup-index-plus-one` | `english` | 1 | `lookup_get` build: `error: Bitcoin/Bip39.lean:182:11: unsolved goals` |
| `drop-word-count` | `bad-word-count` | 1 | T2 build: `error: Bitcoin/Bip39.lean:332:62: Application type mismatch: The argument` |
| `sorted-wordlist-file` | `wordlist` | 1 | Test: `uncaught exception: assertion failed: bip39 wordlist library equality` |
| `sorted-wordlist-vectors` | `english` | 1 | Test: `uncaught exception: assertion failed: bip39 English vector 0 encode` |
| `unknown-position-plus-one` | `unknown-word` | 1 | Test: `uncaught exception: assertion failed: bip39 unknown-word case 0 position` |
| `drop-entropy-length` | `bad-entropy-length` | 1 | Test: `uncaught exception: assertion failed: bip39 bad-entropy-length case 0 rejected` |

Reading each production edit explains why its pinned statement becomes false:

- `skip-checksum`: T3 requires `badChecksum` on mismatched checksum bits; the
  edited decoder returns success instead.
- `checksum-length-plus-one`: T1 fails on the published all-zero 16-byte
  entropy vector: the encoder appends five checksum bits while the decoder
  checks four, so decoding rejects the encoded words.
- `word-index-plus-one`: T1 fails because shifting every encoded word index
  changes the entropy bits recovered by the decoder, even if its checksum passes.
- `lookup-index-plus-one`: `lookup_get` requires index zero for the first
  dictionary word; the edited search returns one, already on a singleton list.
- `drop-word-count`: T2 fails on 13 known words with a matching checksum that
  decode to 17 bytes, which the encoder rejects as `badEntropyLength`.

These are proof failures inside theorems whose statements the edits falsify;
the runner checks diagnostic locations and does not prove that falsity.
The encoder guard and unknown-position edits reached their runtime assertions.
The ordered-list edits still satisfied the uniqueness theorem and were caught
independently by file equality and the published vectors.

After freezing all Lean sources, root imports and the lakefile, all seven
existing suites were checked once in full, sequentially, without checkpoint
resume. Each command is `nix develop -c python3 -I SCRIPT`, from the package
shown, in its own foreground scope with the same 8 GiB/3,600 s limits.

| Package | Script | Exit | Detected | Seconds | Restored full tests |
|---|---|---|---|---|---|
| bitcoin | `check-mutations.py` | 0 | 6/6 | 76.28 | 0 |
| bitcoin | `check-base58-mutations.py` | 0 | 6/6 | 77.02 | 0 |
| bitcoin | `check-bech32-mutations.py` | 0 | 18/18 | 299.68 | 0 |
| bitcoin | `check-address-mutations.py` | 0 | 20/20 | 218.30 | 0 |
| bitcoin | `check-psbt-mutations.py` | 0 | 125/125 | 2059.24 | 0 |
| bitcoin | `check-ripemd160-mutations.py` | 0 | 8/8 | 121.99 | 0 |
| secp256k1 | `check-negative-mutations.py` | 0 | 44/44 negative; 18/18 compression | 262.81 | 0 |

That is **245/245 existing mutations**, **254/254 including BIP39**.
The seven existing suites ran once on the final Lean sources; the later
change to the BIP39 runner and its records touched no Lean source, and the
frozen source fingerprints still match.
Source fingerprints matched after every suite. The four changed pins are
`60 named` → `65 named` in `check-address-mutations.py`,
`check-bech32-mutations.py`, `check-ripemd160-mutations.py` and
`check-psbt-mutations.py`. `check-mutations.py` regenerated only the permitted
`AxiomGate.lean:77:0` → `AxiomGate.lean:81:0` diagnostic in
`test-data/mutations.json`. `git diff --exit-code` on every other existing
mutation-record file and all of `packages/secp256k1` exited **0**, with empty
streams. No other existing mutation source or record changed.

### Final validation

On 2026-10-24, `nix develop -c bash -c 'lean --version; lake --version;
python3 --version'` exited **0**: Lean **4.35.0** (Release,
`eb6cafb7290e8bd5f2937522d8d804f58f02bafc`), Lake **5.0.0-src+eb6cafb**,
Python **3.14.7**. Host `python3 --version` reported **3.13.15** and
`"$TIME_BIN" --version` reported GNU Time **1.10**, both exit **0**.
Build, test and proof commands ran one at a time in the foreground under the
scope and timeout shown above. After the BIP39 runner change, the build, full
test, BIP39 mutations, sandbox check, default build and executable were run
again, each with stdout and stderr saved to separate files. Logs of the earlier
validation remain in `packages/bitcoin/.lake/bip39-validation`, and mutation
streams are in each suite's own `.lake` directory. No gate was piped through an
output filter.

| Directory | Command | Exit | Observation |
|---|---|---|---|
| bitcoin | `nix develop -c lake build` | 0 | 45 jobs; both round trips and independent checksum rejection compiled |
| bitcoin | `nix develop -c lake test` | 0 | All BIP39 counts above; all prior pinned sets; PSBT 101/101; axiom gate 852/65/0 |
| bitcoin / secp256k1 | The eight mutation commands above | 0 each | 254/254 detected; seven retained results plus the BIP39 9/9 rerun; every restored full test exited 0 |
| root | `nix flake check -L` | 0 | All seven package builds/tests in the sandbox, all BIP39 counts, 852/65/0 gate and `all checks passed!` |
| root | `nix build` | 0 | Default executable built |
| root | `./result/bin/cyberkrill` | 0 | `cyberkrill 0.1.0`; empty stderr |
| bitcoin | `git diff --exit-code -- Bitcoin/Bip39.lean Bitcoin/Bip39Wordlist.lean` | 0 | Both sources restored; both streams empty |
| root | `diff "$TMP_ROOT/bip39-mit.txt" "$TMP_ROOT/bip340-mit.txt"` after extracting each block from `MIT License` to EOF | 0 | Byte-identical blocks; both streams empty |
| root | Compare every frozen-source SHA-256 fingerprint | 0 | 45/45 matched |
| root | `git diff --stat` before staging the runner change | 0 | Only the runner, its record, `LICENSE-bip39` and the two READMEs, besides the tracker |
| root | `TMPDIR="$TMP_ROOT" python3 -I packages/bitcoin/generate-bip39-vectors.py` | 0 | 24 rows, eight each of 12/18/24, only entropy and mnemonic |
| root | `git diff --exit-code -- packages/bitcoin/test-data/bip39-english-vectors.json packages/bitcoin/test-data/bip39-english-vectors.json.provenance` | 0 | Both streams empty after regeneration |
| root | Fresh pinned wordlist fetch, then `cmp "$TMP_ROOT/english-fresh.txt" packages/bitcoin/Bitcoin/bip39-english.txt` | 0 | Source digest rechecked; byte-identical; empty comparison streams |
| root | `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | 0 | Both streams empty |
| root | `grep -rnE 'native_decide\|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | 1 | Both streams empty |
| root | `grep -F sorry packages/bitcoin/BitcoinTests/AxiomGate.lean` | 1 | Both streams empty |
| root | `git diff --check ca7800538a07f377c4ffd801b2bdbaf01a4ccb17` | 0 | Both streams empty |
| root | `git diff --stat ca7800538a07f377c4ffd801b2bdbaf01a4ccb17 -- flake.nix flake.lock AGENTS.md plan.md .github packages/sha256 packages/secp256k1 packages/cyberkrill packages/lightning packages/fedimint-invite packages/http-curl` | 0 | Both streams empty |
| root | `find packages -name __pycache__ -not -path '*/.lake/*'` | 0 | Both streams empty |

All existing Bitcoin printed counts remain the original pinned values:
hex 12; CompactSize boundaries/noncanonical/truncated 8/4/4; Amount 36;
CLI and amount cross-check 124 each; Base58 vectors/zeros/invalid 21/5/6;
Base58Check known/rejections/alphabet 4/2/1; Bech32 valid/Bech32m valid 7/7,
cross-variant 14, invalid 12/14, limits/mixed-case/non-ASCII 3/1/1,
regrouping 10 and HRP maximum 8; BIP350 valid/BIP173-v0/replaced 8/3/3,
invalid BIP350/BIP173 15/10; Core addresses 22, network mismatches 3,
regtest answers 2, network matrix 128, malformed scripts 9, Base58 negatives 10;
RIPEMD-160 9 and HASH160 BIP173 1. PSBT valid sets are 10/4/14/6,
invalid sets 20/24/11, re-encoded valid/signer/version-2/Taproot sets 10/4/14/6,
roles 14 and locktimes 10; transaction well-formedness is 135/136 with the
unchanged published exception; wire transactions 136/136 and non-witness txids
60/60 (56 matching, four published invalid exceptions); malformed transactions
2, invalid Base64 20, each of four preimage pairs 2, each hybrid pair 2,
each same-point case 1, PSBT actions 101 and key-shaped grep 1.
The sandbox also retains the earlier SHA-256, secp256k1 and HTTP/TLS counts
documented in their sections, with every package's tests passing.

The staged-content scans use saved added lines, with their own separate
stdout/stderr files:

1. The required extended-private-key/WIF expression over the added lines exited
   **1**, printing nothing on either stream.
2. The scan for twelve or more consecutive wordlist words found **24/24** lines,
   each exactly one of the extracted published English mnemonics, and **0** other
   matches; the assertion command exited **0**. No values were printed.
3. A fresh pinned vector fetch was kept outside the tree. Each of its 24 English
   seeds and 24 xprvs was checked using `git grep -F -- VALUE` over both
   `--cached` and the working tree: **96 calls**, each exit **1**, all streams
   empty. The asserting command exited **0**.

The public-text scan covered all added lines excluding `.beads/`. Its broad
`grep -niP` exited **0**, with five matches, all in required published data:
two wordlist values, their two reformatted literal entries and one permitted
published vector. Each matched data line was checked against the pinned list
or the 24-row extract. Removing only those five verified data lines and checking
the remaining added lines exited **1**, with empty stdout/stderr: no prohibited
names, local paths or attribution trailers in prose or code. The scan's
expression is not reproduced because it contains the forbidden names.
The assertions checking the five data matches and all 24 staged paths exited
**0**; index bytes matched the working files, the tracker was excluded and the
frozen Lean-source fingerprints still matched.

The changed files, with paths relative to `packages/bitcoin` except the root README:

| File | Purpose |
|---|---|
| Root `README.md` | API, proofs, sources, measurements and validation report |
| `Bitcoin.lean` | Export the new library and extend the module description |
| `Bitcoin/Bip39.lean` | Codec, errors, generic arithmetic helpers and T1–T3 |
| `Bitcoin/Bip39Wordlist.lean` | Reformatted MIT English wordlist constant |
| `Bitcoin/Bip39WordlistProofs.lean` | Kernel-checked uniqueness and length |
| `Bitcoin/bip39-english.txt` | Byte-identical pinned source |
| `Bitcoin/bip39-english.txt.provenance` | Source digest, attribution and licence |
| `Bitcoin/LICENSE-bip39` | BIP39-specific MIT record and notice |
| `BitcoinTests.lean` | Full-suite wiring, selector and usage |
| `BitcoinTests/Bip39.lean` | Published, derived, exact-match and rejection tests |
| `BitcoinTests/AxiomGate.lean` | Five new named entries and axiom prints |
| `lakefile.lean` | Register the BIP39 test root |
| `generate-bip39-vectors.py` | Reproducible two-column English extraction |
| `check-bip39-mutations.py` | Nine restored production-mutation checks with one pinned theorem per proof-caught edit |
| `check-address-mutations.py` | Named-theorem pin 65 |
| `check-bech32-mutations.py` | Named-theorem pin 65 |
| `check-psbt-mutations.py` | Named-theorem pin 65 |
| `check-ripemd160-mutations.py` | Named-theorem pin 65 |
| `test-data/bip39-english-vectors.json` | Only the 24 published English entropy/mnemonic pairs |
| `test-data/bip39-english-vectors.json.provenance` | Extraction provenance and dropped columns |
| `test-data/LICENSE-python-mnemonic` | Verbatim upstream MIT licence with source header |
| `test-data/bip39-mutations.json` | Exact observed diagnostics and detection classes |
| `test-data/mutations.json` | Permitted axiom-gate diagnostic line shift only |
| `test-data/README.md` | Fixture regeneration and mutation-record documentation |

Temporary fetches, independent expectations, scratch modules and private caches
are removed by their exact created directory; normal `.lake` build outputs and
validation logs remain. No process started for this work is left running.
The 24 scoped files were staged before the flake check, then committed after
review and merged to master.

### Deltas not taken

No seed derivation, BIP32, other language, entropy generation, normalisation,
prefix expansion, CLI command, SLIP-132 or fee-estimation work is included.
The PSBT parity rules, captures and statements stay unchanged.
`docs/upstream-fixes.md` is unchanged: no general upstream fix was needed.
`plan.md` was unchanged during that work; its §2 `bitcoin` row was updated
afterwards to “BIP39 entropy ↔ English words”, recording the reverse direction.
No follow-up is proposed and no tracker item was created or updated.

## Phase 4c: SLIP-132 public version conversion

`import Bitcoin` exposes the pure `Bitcoin.Slip132` module. Its six-entry
`Version` type is `xpub`, `ypub`, `zpub`, `tpub`, `upub`, `vpub`. The version
table follows [cyberkrill's slip132.rs:9-20](https://github.com/douglaz/cyberkrill/blob/27cad1faba86260b06665a89f0af5134d23525c2/cyberkrill-core/src/slip132.rs#L9-L20)
at `27cad1faba86260b06665a89f0af5134d23525c2`. The same six single-signature
public entries appear in [SLIP-0132](https://github.com/satoshilabs/slips/blob/570ed55b7fde158f1116be34fc2faa35dada5912/slip-0132.md),
which is cited only: its CC-BY-SA-4.0 text and table are not copied.

| Version | Four bytes | Network represented |
|---|---|---|
| xpub | `04 88 B2 1E` | mainnet |
| ypub | `04 9D 7C B2` | mainnet |
| zpub | `04 B2 47 46` | mainnet |
| tpub | `04 35 87 CF` | testnet/regtest |
| upub | `04 4A 52 62` | testnet/regtest |
| vpub | `04 5F 1C F6` | testnet/regtest |

All four functions below are public, in namespace `Bitcoin.Slip132`:

```lean
versionBytes : Version → ByteArray
versionOf : ByteArray → Option Version
decode : String → Except Error (Version × ByteArray)
convert : String → Version → Except Error String
```

`decode` returns the recognized version and the remaining 74-byte body.
`convert` accepts any of the six as source and target, including across
networks: an xpub may become a tpub, upub or vpub. Apart from its three checks,
conversion never checks or changes anything but the four version bytes.
The other 74 bytes pass through untouched. There is no BIP32 derivation,
multisig/private version, curve or key-prefix check, new dependency, C code,
CLI command or v1 caller. The package never imports `secp256k1`.

The public `Error` type derives `Repr`, `DecidableEq` and `BEq`. Its constructors
reflect the exact check order:

| Order | Constructor | Meaning |
|---|---|---|
| 1 | `base58 e` | The existing `Bitcoin.Base58.CheckError`, wrapped without merging errors |
| 2 | `wrongLength n` | Decoded payload length is not exactly 78, including lengths below four |
| 3 | `unknownVersion bytes` | The first four bytes are outside the six public entries |

### Exact theorem statements

These eight statements are in namespace `Bitcoin.Slip132`. They are all
registered in `namedTheorems` and each has a `#print axioms` line.

```lean
theorem versionBytes_size (v : Version) : (versionBytes v).size = 4

theorem versionOf_versionBytes (v : Version) : versionOf (versionBytes v) = some v

theorem versionOf_sound (b : ByteArray) (v : Version) (h : versionOf b = some v) :
    versionBytes v = b

theorem base58CheckEncode_of_decode (s : String) (p : ByteArray)
    (h : Base58.base58CheckDecode s = .ok p) : Base58.base58CheckEncode p = s

theorem decode_sound (s : String) (v : Version) (body : ByteArray)
    (h : decode s = .ok (v, body)) :
    Base58.base58CheckDecode s = .ok (versionBytes v ++ body) ∧ body.size = 74

theorem decode_encode (v : Version) (body : ByteArray) (h : body.size = 74) :
    decode (Base58.base58CheckEncode (versionBytes v ++ body)) = .ok (v, body)

theorem convert_payload (s s' : String) (v t : Version) (body : ByteArray)
    (h : decode s = .ok (v, body)) (hc : convert s t = .ok s') :
    Base58.base58CheckDecode s' = .ok (versionBytes t ++ body)

theorem convert_roundtrip (s s' : String) (v t : Version) (body : ByteArray)
    (h : decode s = .ok (v, body)) (hc : convert s t = .ok s') :
    convert s' v = .ok s
```

The final theorem returns the original **string**, using Base58's canonical
spelling and Base58Check soundness. `decode_sound` identifies the source's
74-byte body, and `convert_payload` identifies that same body after conversion.
The new string-level Base58Check lemma lives in `Slip132.lean`;
`Base58.lean` and `Base58Check.lean` remain byte-identical to the baseline.
No existing theorem statement changes. Library proofs use neither proof holes
nor `native_decide` nor `bv_decide`.

The axiom gate is **894 library theorems; 73 named; 0 offenders**, against
Phase 4b's **852; 65; 0**. The additions are the eight explicit statements above
and 34 generated library theorem declarations. The allowed axioms remain
`propext`, `Classical.choice` and `Quot.sound`; `versionBytes_size` uses none,
`versionOf_versionBytes` and `versionOf_sound` use only `propext` and
`Quot.sound`, and the remaining five use the permitted three.

### Sources, regeneration and counts

The source is [BIP32 bip-0032.mediawiki](https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0032.mediawiki)
at `130b8e0fa7f30fa45532f080b87b8db27a79e46e`, **BSD-2-Clause**. A fresh fetch
matched **28,032 bytes** and SHA-256
`e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f`.
Its author is Pieter Wuille; its licence declaration and Copyright section
are preserved in `Bitcoin/LICENSE-bips`. It supplies no year or holder line.

`generate-slip132-vectors.py` extracts only the six `ext pub` lines of vector 1
and six of vector 2, in order. It verifies the source digest, exact lengths and
prefixes and excludes all twelve corresponding private strings from its output.
The extract and its sidecar are `test-data/bip32-public-vectors.json` and
`.json.provenance`. The complete mediawiki document stays outside the tree.

`cross-check-slip132.py` uses Python **base58 2.1.1** from the pinned nixpkgs,
with literal bytes read from cyberkrill's table. It derives and checks **72**
version swaps, each with the expected prefix, Base58Check payload and unchanged
last 74 bytes. Its committed output is `test-data/slip132-derived.json`, with
a sidecar marked “derived: version bytes swapped”. Lean compares its own
72 conversions against these exact rows. Expected versions and strings never
come from the library table or conversion.

`capture-cyberkrill-slip132.py` appends only a temporary pure test inside
`slip132.rs`'s test module in a fresh clone at `27cad1f`. It calls
`parse_slip132_xpub(s)?.to_string()` for each independently derived
ypub/zpub/upub/vpub, in that order for each of the twelve sources. One private
`CARGO_HOME` serves online `cargo fetch --locked` and the subsequent offline
test. The actual build/test uses the clone's own environment:

```bash
nix develop -c unshare -rn sh -c 'ip link set lo up && cargo test --offline --locked --target x86_64-unknown-linux-gnu -p cyberkrill-core --no-default-features --features trezor -j 2 --lib slip132 -- --nocapture --test-threads=1'
```

The offline command has a temporary HOME and opens no connection. The **48**
captured rows are in `test-data/cyberkrill-slip132.json`, with producer, command,
BIP32 input provenance and “derived: version bytes swapped, converted back by
cyberkrill” in the sidecar. Lean checks both the golden input column's exact
order against its independent derivation and each conversion back to xpub or
tpub. Capture completed in **191.20 s**, exit **0**; the clone, Cargo cache and
temporary HOME were deleted, and their workspace's absence was asserted.
The hand-derived fallback was not used.

From the repository root, with `TMP_ROOT` a fresh private temporary workspace:

```bash
TMPDIR="${TMP_ROOT:?}" python3 -I packages/bitcoin/generate-slip132-vectors.py
TMPDIR="${TMP_ROOT:?}" nix shell --impure --expr 'let pkgs = import (builtins.getFlake (toString ./.)).inputs.nixpkgs {}; in pkgs.python3.withPackages (p: [p.base58])' -c python3 -I packages/bitcoin/cross-check-slip132.py
TMPDIR="${TMP_ROOT:?}" systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 python3 -I packages/bitcoin/capture-cyberkrill-slip132.py
```

All test sets pin their counts before checking cases and read committed files
only. They never use the network or any wallet, node or device data.

| Printed set | Count | Property |
|---|---|---|
| `slip132 vectors` | 12/12 | 111-character xpubs, 78-byte payloads and literal `04 88 B2 1E` version |
| `slip132 conversions` | 72/72 | Independent Python expectation, prefix and exact swapped payload |
| `slip132 roundtrips` | 72/72 | Convert every result back to the original xpub string |
| `slip132 goldens` | 48/48 | Input order, port-produced input and cyberkrill's converted output |
| `slip132 unknown-version` | 9/9 | Two BIP32 private versions, all-zero version, one-bit change to each of six public versions; each outside the independent table and rejected |
| `slip132 wrong-length` | 2/2 | 77 and 79 bytes, exact length errors |
| `slip132 short-payload` | 2/2 | Zero and three bytes, exact length errors |
| `slip132 Base58Check` | 2/2 | Changed checksum character and invalid alphabet, distinct wrapped errors |
| `slip132 check-order` | 2/2 | Length before unknown version; checksum before length and version |

Select sets with `lake test -- --slip132 NAME`, where `NAME` is `vectors`,
`conversions`, `roundtrips`, `goldens`, `unknown-version`, `wrong-length`,
`short-payload`, `base58check` or `check-order`. Negative strings are constructed
only at test time and never printed, including strings using private versions.
No published count differed from the brief.

### Production mutations and widened key-material checks

From `packages/bitcoin`, run
`nix develop -c python3 -I check-slip132-mutations.py` inside the capped scope
shown above. The runner makes exact-count production replacements, restores
the original bytes in `finally`, and records separate stdout/stderr under
`.lake/slip132-mutation-checks`. Its compact record is
`test-data/slip132-mutations.json`. It exited **0**, **4/4 detected**, in
**45.99 s**, and its final full restored `lake test` exited **0**.

| Production mutation | Detection | Exact assertion or theorem and first diagnostic |
|---|---|---|
| ypub table row's last byte changed from `B2` to `B3` | Test | `slip132 conversion 1 independent expectation` |
| Unknown-version rejection replaced by successful decoding; table unchanged | Theorem build | `decode_sound`, `Bitcoin/Slip132.lean:83:13: unsolved goals` |
| Required length changed from 78 to 79 | Theorem build | `decode_sound`, `Bitcoin/Slip132.lean:93:8: unsolved goals` |
| Source version re-encoded unchanged instead of swapped | Theorem build | `convert_payload`, `Bitcoin/Slip132.lean:110:66: unsolved goals` |

The wrong-byte test compares against the independently generated expected
string; the round-trip property alone would not detect that edit. Each
proof-caught record pins a statement falsified by its edit and records the
first diagnostic inside that declaration's range.

The live extended-private-key expression is widened from `[tx]prv…` to
`[tuvxyzUVYZ]prv[1-9A-HJ-NP-Za-km-z]{100,}` in exactly the CI step,
`BitcoinTests.lean` and `check-key-material.py`'s `CI_COMMAND`. It covers the
SLIP-132 private forms and their multisig forms as well as xprv/tprv. The
pre-edit widened scan printed nothing, exit **1**. Earlier Phase 4a records
with the old expression are historical and unchanged.

`check-key-material.py` uses **PyYAML 6.0.3** to compare the parsed CI command
exactly. In a disposable copy it plants each prefix alone, constructed by
concatenation: t/u/v/x/y/z/U/V/Y/Z followed by `prv` and 110 `z` characters.
All **20/20** CI/Bitcoin checks went red, exit **1**; the restored CI scan
exited **0**, and the missing-path check exited **1**. The runner exited **0**
in **7.01 s**, confirmed the copy was removed, and wrote **22** records.
No planted line appears literally in committed text: records preserve the
`<synthetic planted line>` placeholder and describe each plant in prose.

Run from the root after `lake test` has built BitcoinTests:

```bash
TMPDIR="${TMP_ROOT:?}" systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 nix shell --impure --expr 'let pkgs = import (builtins.getFlake (toString ./.)).inputs.nixpkgs {}; in pkgs.python3.withPackages (p: [p.pyyaml])' -c python3 -I packages/bitcoin/check-key-material.py
```

### Existing mutation suites and changed files

The Lean sources were frozen before these eight runs. Each command ran once,
sequentially, without checkpoint reuse, inside its own foreground scope:

```bash
systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 COMMAND
```

`TMPDIR` was set to the private `TMP_ROOT`. Separate streams and elapsed-time
records remain under `packages/bitcoin/.lake/slip132-validation`; each runner
also keeps its own separate mutation streams. The gate supervisor preserves
the command's real exit status. No gate was piped through an output filter.

| Package | Command | Exit | Detected | Wall seconds |
|---|---|---|---|---|
| bitcoin | `nix develop -c python3 -I check-mutations.py` | 0 | 6/6 | 102.47 |
| bitcoin | `nix develop -c python3 -I check-base58-mutations.py` | 0 | 6/6 | 87.70 |
| bitcoin | `nix develop -c python3 -I check-bech32-mutations.py` | 0 | 18/18 | 470.51 |
| bitcoin | `nix develop -c python3 -I check-address-mutations.py` | 0 | 20/20 | 258.28 |
| bitcoin | `nix develop -c python3 -I check-psbt-mutations.py` | 0 | 125/125 | 1870.17 |
| bitcoin | `nix develop -c python3 -I check-ripemd160-mutations.py` | 0 | 8/8 | 110.50 |
| bitcoin | `nix develop -c python3 -I check-bip39-mutations.py` | 0 | 9/9 | 91.12 |
| secp256k1 | `nix develop -c python3 -I check-negative-mutations.py` | 0 | 44/44 negative + 18/18 compression | 233.93 |

Total: **254/254 detected**. Each Bitcoin runner's final restored full
`lake test` exited **0**. The secp256k1 adapter was restored; its existing
redundant compression-length-guard probe still exits **0** and is not counted
as a detected mutation. Its source and both records have no diff.

The only existing pins changed are `65 named` → `73 named`, once each in
`check-address-mutations.py`, `check-bech32-mutations.py`,
`check-bip39-mutations.py`, `check-psbt-mutations.py` and
`check-ripemd160-mutations.py`. In `test-data/mutations.json`, the sole changed
diagnostic location is `BitcoinTests/AxiomGate.lean:81:0` → `:85:0`.
All other existing mutation records compare byte-identically with the baseline,
as do all of `packages/secp256k1` and the protected package sources.
The frozen Lean-source comparison matched **78/78** files.

The 29 changed/new files are listed below; paths are relative to
`packages/bitcoin` unless otherwise stated.

| File | Purpose |
|---|---|
| Root `README.md` | API, exact proofs, sources, results, status and the five specified historical corrections |
| Root `.github/workflows/ci.yml` | Only the widened private-key expression |
| `Bitcoin.lean` | Import the module and describe its public conversion proofs |
| `Bitcoin/Slip132.lean` | Six versions, lookup, errors, decoding, conversion and eight theorems |
| `Bitcoin/LICENSE-bips` | Add BIP32's BSD-2-Clause attribution and extract path |
| `BitcoinTests.lean` | Full-suite call, selector, usage and widened grep |
| `BitcoinTests/Slip132.lean` | Published, independent, golden, round-trip and negative sets |
| `BitcoinTests/AxiomGate.lean` | Eight named theorems and eight axiom prints |
| `lakefile.lean` | Test root and package description |
| `generate-slip132-vectors.py` | Pinned, digest-checked public-only BIP32 extraction |
| `cross-check-slip132.py` | Independent Python base58 derivation and 12/72/48 checks |
| `capture-cyberkrill-slip132.py` | Fresh-clone offline pure capture with asserted cleanup |
| `check-slip132-mutations.py` | Four production mutations and final restored full test |
| `check-key-material.py` | Widened CI command and ten isolated plants against both greps |
| `check-address-mutations.py` | Named-count pin 65 → 73 only |
| `check-bech32-mutations.py` | Named-count pin 65 → 73 only |
| `check-bip39-mutations.py` | Named-count pin 65 → 73 only |
| `check-psbt-mutations.py` | Named-count pin 65 → 73 only |
| `check-ripemd160-mutations.py` | Named-count pin 65 → 73 only |
| `test-data/README.md` | Fixture provenance, regeneration and mutation-record instructions |
| `test-data/bip32-public-vectors.json` | Twelve published public extended keys |
| `test-data/bip32-public-vectors.json.provenance` | Source, digest, BSD attribution and extraction |
| `test-data/slip132-derived.json` | Seventy-two independent expected conversions |
| `test-data/slip132-derived.json.provenance` | Literal-byte swap derivation and exact command |
| `test-data/cyberkrill-slip132.json` | Forty-eight captured conversions back to xpub/tpub |
| `test-data/cyberkrill-slip132.json.provenance` | Producer, inputs, command, licence and transformation |
| `test-data/slip132-mutations.json` | Four observed failures with detecting theorem/assertion |
| `test-data/key-material-mutations.json` | Twenty red checks, restored scan and missing-path check |
| `test-data/mutations.json` | Permitted diagnostic line shift only |

### Final validation and cleanup

The commands below ran with stdout and stderr saved separately; the build,
test, capture and mutation commands used the capped scope above. All required
commands completed within the cap and timeout. Initial proof-development checks
exited **1** while correcting local instance, identifier and simplification
errors; the corrected standalone module check exited **0** in **1.79 s**.
No theorem statement was weakened. The fresh initial library build exited
**0** in **5.05 s**, and the first complete test exited **0** in **19.91 s**.
The final cached local build/test and fresh sandbox run are recorded here.

`BASE` below is `1b093cd9193609013210a450fcf58d20f70216bf`.
`PROTECTED` denotes `flake.nix flake.lock AGENTS.md plan.md packages/sha256
packages/secp256k1 packages/lightning packages/fedimint-invite
packages/http-curl packages/cyberkrill`.

| Directory | Command | Exit | Observation |
|---|---|---|---|
| bitcoin | `nix develop -c lake build` | 0 | 46 jobs; final cached run 1.12 s |
| bitcoin | `nix develop -c lake test` | 0 | Final run 1.37 s; 12/72/72/48, negative sets 9/2/2/2/2, all earlier counts and 894/73/0 gate |
| root | `TMPDIR="$TMP_ROOT" python3 -I packages/bitcoin/generate-slip132-vectors.py` | 0 | Initial and repeated extraction each 12/12 |
| root | `git diff --exit-code -- packages/bitcoin/test-data/bip32-public-vectors.json packages/bitcoin/test-data/bip32-public-vectors.json.provenance` | 0 | Both streams empty after staging both paths and regenerating |
| root | The pinned `nix shell` / base58 cross-check command above | 0 | Initial and repeated runs each 12/72/48; base58 2.1.1 |
| root | `git diff --exit-code -- packages/bitcoin/test-data/slip132-derived.json packages/bitcoin/test-data/slip132-derived.json.provenance` | 0 | Both streams empty after staging both paths and regenerating |
| root | The capped capture command above | 0 | 48 rows; online fetch and offline test each exit 0; private workspace absent after cleanup |
| bitcoin | `nix develop -c python3 -I check-slip132-mutations.py` | 0 | 4/4 detected; full restored test exit 0 |
| bitcoin / secp256k1 | All eight commands in the preceding table | 0 each | 254/254 detected; times and restored results above |
| root | The pinned `nix shell` / PyYAML key-material command above | 0 | Twenty planted-line rejections plus restored and missing-path results; 22 records |
| root | `nix flake check -L` | 0 | Fresh sandbox build/tests of all seven packages; every SLIP-132 set, 894/73/0 and `all checks passed!`; 125.84 s |
| root | `nix build` | 0 | Default executable built; 1.07 s |
| root | `./result/bin/cyberkrill` | 0 | `cyberkrill 0.1.0`; empty stderr |
| root | `rc=0; grep -rnw sorry --include='*.lean' --exclude-dir=.lake packages \|\| rc=$?; test "$rc" -eq 1` | 0 | Both streams empty |
| root | `grep -rnE 'native_decide\|bv_decide' --include='*.lean' packages/bitcoin/Bitcoin packages/bitcoin/Bitcoin.lean` | 1 | Both streams empty |
| root | `grep -F sorry packages/bitcoin/BitcoinTests/AxiomGate.lean` | 1 | Both streams empty |
| root | `git diff --exit-code "$BASE" -- packages/bitcoin/Bitcoin/Base58.lean packages/bitcoin/Bitcoin/Base58Check.lean` | 0 | Both files byte-identical |
| root | `git diff --stat "$BASE" -- $PROTECTED` | 0 | Both streams empty |
| root | `git diff --exit-code "$BASE" -- $PROTECTED` | 0 | Both streams empty; also checks all secp256k1 records |
| root | `git diff --exit-code "$BASE" -- packages/bitcoin/test-data/{base58,bech32,address,psbt,ripemd160,bip39}-mutations.json` | 0 | All six other Bitcoin mutation records unchanged |
| root | Compare CI against the baseline with exactly its one expression replaced | 0 | Exact content equality; no other CI change |
| root | `git diff --check "$BASE"` | 0 | Both streams empty |
| root | `find packages -name __pycache__ -not -path '*/.lake/*'` | 0 | Both streams empty |
| root | Required stale-line grep over `README.md` | 1 | Both streams empty; all five specified corrections present; the earlier separate-commit sentence retained |
| root | Compare all frozen Lean SHA-256 fingerprints | 0 | 78/78 matched |

The three staged-content scans used throwaway commands outside the repository:

1. The required extended-private-key/WIF expression over saved added lines
   exited **1**, printing nothing on either stream.
2. All **252** added public-key occurrences (**72** unique strings) independently
   Base58Check-decoded to 78 bytes, with their last 74 bytes among the twelve
   published vector payloads. The assertion command exited **0**; no values
   were printed.
3. A fresh pinned mediawiki fetch went into its own empty directory outside the
   tree, with its byte count and digest rechecked. Each of its twelve vector-1/2
   private strings was searched using `git grep -F -- VALUE`, both working-tree
   and `--cached`: **24 calls**, each exit **1**, both streams empty. The
   assertion command exited **0**.

The index was checked against all **29** scoped working files and excludes the
pre-existing tracker claim. New files were staged by explicit path before the
flake check. Source, manifest and package boundaries are unchanged apart from
the listed module and test wiring. No process from these checks remains running.
The private temporary root, downloaded source documents, disposable scan scripts,
fingerprint record and scan inputs were deleted by the exact created directory,
with its absence asserted. The capture separately removed its fresh clone,
Cargo cache and temporary HOME, and the key-grep runner removed its disposable
copy. Normal `.lake` build outputs and separate validation logs remain.

### Deltas not taken

cyberkrill delegates to rust-bitcoin 0.32.8's `Xpub::decode`, which curve-checks
bytes 45..78 and rejects an invalid point. The pure conversion here performs
no curve check. cyberkrill checks the version before the 78-byte length and
panics while slicing a payload below four bytes; this module checks the length
first and returns `wrongLength` with that length. These differences are settled
for this library, which has no v1 caller. No tracker item or follow-up was
created, and `docs/upstream-fixes.md` is unchanged. `plan.md` is unchanged;
no sentence in it became stale. The remaining Phase 4 weight/fee work is outside
this change, as are CLI, BIP32 derivation and multisig/private conversions.

## Deltas taken

The following input classes are rejected although cyberkrill accepts them.
Reference behavior comes from the pinned offline amount and PSBT captures above.

| Class | Captured cyberkrill behavior | Port test names |
|---|---|---|
| Non-whole-msat precision | `0.000000000001` BTC and `0.0001sat` round to 0 msat. The port rejects both. Extra fractional **zero** digits remain accepted. | `sub-msat-btc`, `sub-msat-sats`; Amount `sub-msat`, `sats-sub-msat` |
| Exponent forms, including upper-case `E` and signed zero | `1e-3` / `1E-3` → 100000000 msat; `1e3` → 100000000000000; `1e-3sat` → 1; `+1e0btc` → 100000000000; `-0e3` → 0. | All six `exponent-…` cases in `cli.json` |
| Nonfinite `inf` / `nan` spellings, including leading `+`, signed NaN and case variants | `inf` / `+inf` saturate to 18446744073709551615; `nan`, `+nan`, `-nan` become 0. Tested bare and with BTC/sat suffixes. Negative infinity is already rejected by cyberkrill. | `nonfinite-inf`, `nonfinite-+inf`, `nonfinite-nan`, `nonfinite-+nan`, `nonfinite--nan` and their suffix variants |
| Named `infinity` form, including leading `+` and case variants | `infinity` / `+infinity` saturate to 18446744073709551615, bare and with BTC/sat suffixes. The port rejects every spelling; negative infinity already fails upstream. | `nonfinite-infinity`, `nonfinite-+infinity` and their suffix variants |

The amount rejection classes above are unchanged. Every input the reference
rejects in the 124-case amount capture is rejected by the port. The PSBT decoder
also keeps three BIP rules (owner decision, 2026-10-23): canonical CompactSize
key types and proprietary subtypes (BIP174), global xpub origin path length
equal to depth (BIP174), and no v2-only fields in v0 (BIP370). Their code is
unchanged. The following sixteen inputs all have captured cyberkrill exit **0**
and port decoder rejection; these are the fourth golden-parity exception in
plan §3. Select each with `lake test -- --psbt 'parity NAME'`.

| Rule | Input | Captured cyberkrill exit |
|---|---|---|
| Canonical CompactSize key types | `key-type-fd01` | 0 |
| Canonical CompactSize key types | `key-type-fd0500` | 0 |
| Canonical CompactSize proprietary subtype | `proprietary-subtype-fd01` | 0 |
| Global xpub depth/path equality | `xpub-depth` | 0 |
| No v2-only fields in v0 | `bip370-invalid-1` (`PSBT_GLOBAL_TX_VERSION`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-2` (`PSBT_GLOBAL_FALLBACK_LOCKTIME`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-3` (`PSBT_GLOBAL_INPUT_COUNT`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-4` (`PSBT_GLOBAL_OUTPUT_COUNT`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-5` (`PSBT_GLOBAL_TX_MODIFIABLE`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-6` (`PSBT_IN_PREVIOUS_TXID`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-7` (`PSBT_IN_OUTPUT_INDEX`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-8` (`PSBT_IN_SEQUENCE`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-9` (`PSBT_IN_REQUIRED_TIME_LOCKTIME`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-10` (`PSBT_IN_REQUIRED_HEIGHT_LOCKTIME`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-11` (`PSBT_OUT_AMOUNT`) | 0 |
| No v2-only fields in v0 | `bip370-invalid-12` (`PSBT_OUT_SCRIPT`) | 0 |

## Licence

Dual-licensed under MIT or Apache-2.0, at your option: `LICENSE-MIT`, `LICENSE-APACHE`. Code copied from
other projects keeps its own licence notice next to it.

Each lakefile sets `license := "MIT OR Apache-2.0"` and
`licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]`. Lake accepts the relative paths:
`lake reservoir-config` in a package directory lists both files (Lake drops paths that don't exist).
It prints them as absolute paths.
