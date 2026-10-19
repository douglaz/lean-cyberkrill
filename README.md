# lean-cyberkrill

Bitcoin, Lightning and Fedimint libraries for Lean 4, and a Lean port of the
[cyberkrill](https://github.com/douglaz/cyberkrill) command-line tool built on them.

Status: Phase 0 (bootstrap). The packages are empty skeletons; `plan.md` is the plan for v1.

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

## Licence

Dual-licensed under MIT or Apache-2.0, at your option: `LICENSE-MIT`, `LICENSE-APACHE`. Code copied from
other projects keeps its own licence notice next to it.

Each lakefile sets `license := "MIT OR Apache-2.0"` and
`licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]`. Lake accepts the relative paths:
`lake reservoir-config` in a package directory lists both files (Lake drops paths that don't exist).
It prints them as absolute paths.
