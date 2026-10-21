# lean-cyberkrill

Bitcoin, Lightning and Fedimint libraries for Lean 4, and a Lean port of the
[cyberkrill](https://github.com/douglaz/cyberkrill) command-line tool built on them.

Status: Phase 1a (1 of 2): FFI link targets and the one-OpenSSL spike are implemented.
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
Neither FFI package has a Lean dependency. Cryptographic bindings and vectors remain
Phase 1a (2 of 2); HTTP requests remain Phase 1b.

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

The following evidence is copied from the sandboxed `nix flake check -L` run
(exit 0, derivation `/nix/store/402f697b06bwpr5vvdavcbqxrrvajp5x-cyberkrill-0.1.0.drv`).
`nix log` on that derivation replays it. Store paths can differ between sandbox
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

None. Additional bindings, network tests and the musl release remain in their
existing later tasks.

## Licence

Dual-licensed under MIT or Apache-2.0, at your option: `LICENSE-MIT`, `LICENSE-APACHE`. Code copied from
other projects keeps its own licence notice next to it.

Each lakefile sets `license := "MIT OR Apache-2.0"` and
`licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]`. Lake accepts the relative paths:
`lake reservoir-config` in a package directory lists both files (Lake drops paths that don't exist).
It prints them as absolute paths.
