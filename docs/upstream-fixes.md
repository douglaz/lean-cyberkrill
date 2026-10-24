# Upstream fixes

These notes concern `pure-algebra/lean4-hash` at
`ab7eda433f0390fde7aa240189761540c9744c79` (MIT). Paths and line numbers below
refer to that revision. Sending patches remains Phase 10 work.

| File | Problem | Fix used in this port |
|---|---|---|
| `Hash/Sha256/Spec.lean` | Lean 4.35 deprecates `if_pos` at line 156, `dif_neg` at 264 and 344, and `dif_pos` at 340; warnings fail the build. | Use `ite_eq_left`, `dite_eq_right`, and `dite_eq_left`, respectively. Statements and proof steps otherwise stay unchanged. |
| `Hash/Sha256/Impl.lean` | `dif_pos` at 85 and `dif_neg` at 89 are deprecated. | Use `dite_eq_left` and `dite_eq_right`. |
| `Hash/Sha256/Fast.lean` | `dif_pos` twice at 173 and once at 263, and `dif_neg` twice at 174 and once at 265 are deprecated. | Use `dite_eq_left` and `dite_eq_right`. |
| `Hash/Sha256/Digest.lean` | `dif_pos` at 74 is deprecated. | Use `dite_eq_left`. |
| `Hash/Sha256/Api.lean` | The trust-base docstring hard-codes a kernel version and an external recheck target; either becomes misleading in a partial port. | Name the actual kernel and audit used by the build. This port names Lean 4.35.0 and its allowlist gate, without claiming an external recheck. |
| `Hash/Sha256/Api.lean` | Five build-time witnesses prevent a deliberately wrong but mutually consistent `Spec.K`/`Fast.K` from reaching executable vectors. | Cover all five witnesses in the counted runtime ShortMsg suite; remove the five guards and their now-unused meta imports. This lets proofs check while all four vector sets fail on the changed constant. |

The module/namespace rename and the doc clarifications about upstream-only
paths and tests are local integration changes, rather than proposed upstream
semantic changes. No theorem statement is weakened.

## lean-miniscript

Source: `febyeji/lean-miniscript` at
`cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd` (MIT, Copyright (c) 2026 Yeji Han).
Serialization and the initial deserialization/proof slices are copied in
Phase 3a (1 of 4), followed by the 21 `rawVectors` from
`LeanMiniscript/Bitcoin/KeyEncodingExamples.lean` L29–50 in Phase 3a (2 of 4).
Each module carries its exact ranges and uses the adjacent MIT notice.

| File | Problem | Fix used in this port |
|---|---|---|
| `LeanMiniscript/Bitcoin/DeserializationProofs.lean` L7–179 | Lean 4.35 deprecates `if_true`, `if_false`, `if_pos` and `if_neg`; warnings fail the build. | Replace them with `ite_true`, `ite_false`, `ite_eq_left` and `ite_eq_right`, respectively. No theorem statement or proof strategy changes. |

The slices are combined in `Bitcoin/CompactSize.lean`, importing only `Lean`.
`LeanMiniscript.Bitcoin` becomes `Bitcoin.CompactSize`. Those integration changes
and the provenance comment are the only other changes to the copied slices.

`Bitcoin/Base58Vectors.lean` copies only the raw Base58 vector definition.
No Lean 4.35 port fix was needed. Its integration changes remove `private` so
the runtime test driver can read the array, wrap it in `namespace BitcoinTests`,
and add the first-line provenance comment. No upstream helpers or other vector
sets are copied. The adjacent `Bitcoin/LICENSE-miniscript` remains byte-identical
to upstream's notice. The Base58 and Base58Check codecs and proofs are our own.

### Transaction and PSBT subset (Phase 4a, 1 of 3)

The same pinned revision supplies the following additional slices. The namespace
`LeanMiniscript.Bitcoin` becomes `Bitcoin` for transactions and the four remaining
deserialization proofs, and `LeanMiniscript.Bitcoin.Base64` becomes
`Bitcoin.Base64`. `LeanMiniscript.Psbt` becomes `Bitcoin.Psbt`.
The earlier `Bitcoin.CompactSize` mapping remains in place; the new code opens it
and never duplicates its codec. Every copied file gains a first-line provenance
comment referring to the reused MIT notice. No Lean 4.35 proof or deprecation fix
was needed in these new slices; all four theorem statements and proofs are intact
apart from the namespace context.

| File / exact slice | Problem | Fix used in this port |
|---|---|---|
| `LeanMiniscript/Script/Syntax.lean` L1–2 | The transaction structures derive `Repr ByteArray`, which Lean 4.35 core does not supply. | Copy only the instance to `Bitcoin/ByteArrayRepr.lean`; no script syntax or opcodes. |
| `LeanMiniscript/Bitcoin/Transaction.lean` L1–55 | Serialization already lives in the earlier copied codec; the script module is unnecessary. | Import `Bitcoin.CompactSize` and `Bitcoin.ByteArrayRepr`, open `CompactSize`. No other changes. |
| `LeanMiniscript/Bitcoin/Deserialization.lean` L81–170 | The first reader slice is already present, and the transaction identifier depends on a sighash module. | Import `Bitcoin.Transaction` and `Sha256`, open `CompactSize`, and replace `doubleSHA256` by `Sha256.sha256d`. No sighash code is copied. |
| `LeanMiniscript/Bitcoin/Deserialization.lean` `serializeWitnessTransaction` | A non-empty witness stack beyond the inputs selects the BIP144 form, but only the inputs' (empty) stacks are written, so `parseTransaction` rejects the result as `superfluousWitness`. | Choose the form from the first `tx.inputs.size` stacks only; surplus stacks are ignored, as they already were when writing. To send upstream. |
| `LeanMiniscript/Bitcoin/DeserializationProofs.lean` L180–232 | The first eleven theorems are already present. | Import `Bitcoin.Deserialization`, open `CompactSize`, retain the four remaining theorems unchanged. |
| `LeanMiniscript/Bitcoin/Base64.lean` L1–79 | `encodeList` and `decodeList` append each group after the recursive call returns, so the call stack grows with the input; a 48,000,000-byte round trip aborts with a stack overflow. | Namespace rename, and both traversals rewritten as tail-recursive accumulator loops with unchanged results. To send upstream. |
| `LeanMiniscript/Psbt/Codec.lean` L1–157 | The optional BIP32 point check needs its own structured diagnostic. | Import the new deserialization module, open `Bitcoin.CompactSize`, and add `duplicateBip32Point scope first second`. Framing and raw-byte serialization are unchanged. |
| `LeanMiniscript/Psbt/Fields.lean` L1–582 | Hard-coded curve and hash implementations prevent pure consumers from supplying their own. | Replace the ECDSA import/helper by `PubkeyCapability`, thread it through input/output and whole-PSBT decoders, use the strict check for partial signatures and compression success for both BIP32 scopes. Thread one `PreimageHashes` argument after the capability through input and whole-PSBT decoders. RIPEMD160/HASH160 call that parameter; SHA256/HASH256 call qualified `Sha256.hash`/`Sha256.sha256d`. Open `Bitcoin.CompactSize`. Other field rules and raw key storage are unchanged. |

The capability and optional `Psbt.checkBip32SamePoint` are separate, newly written
dual-licensed modules. Parsing does not call the point check. The fixture module
copies exactly `LeanMiniscript/Psbt/Fixtures.lean` L8–70 and L95–178 into
`BitcoinTests.PsbtVectors`, with no other change beyond the wrapper and provenance
line. The route is lean-miniscript, but the vectors originate in bitcoin/bips
at `927b6de9915c9262615a6399de51b200f81e5aa4`, under BSD-2-Clause; their notice
is `Bitcoin/LICENSE-psbt-bips`. The secret-bearing intermediate fixture slice is
excluded. `check-tx-psbt-copy.py` reconstructs all eight files from a separately
fetched checkout and asserts exact equality after precisely these edits. It
refuses a checkout with local changes.

### Transaction and PSBT proofs (Phase 4a, 3 of 3)

The same pinned revision supplies two complete proof files. Their statements and
proof strategies are preserved, with the capability and hash arguments added to
the statements that use validated parsing. No copied codec or field rule changes.

| File / exact slice | Problem | Fix used in this port |
|---|---|---|
| `LeanMiniscript/Psbt/CodecProofs.lean` L1–280 | Imports and namespaces refer to the upstream package. | Map them to `Bitcoin.Psbt` and `Bitcoin`, and open `Bitcoin.CompactSize`. Add the first-line MIT provenance comment and reuse `Bitcoin/LICENSE-miniscript` unchanged. |
| `LeanMiniscript/Psbt/CodecProofs.lean` L73, L116, L147, L153 | Lean 4.35 reports deprecated `if_false` / `if_true`. | Replace the three `if_false` references by `ite_false` and the one `if_true` by `ite_true`. To send upstream. |
| `LeanMiniscript/Psbt/ParseProofs.lean` L1–65 | The port's field decoder and validated parser take supplied operations. | Map imports and namespace to `Bitcoin.Psbt`; add implicit `cap : PubkeyCapability` and `hashes : PreimageHashes`, and thread them through each `decode` and `parse` call. Add the first-line MIT provenance comment. |

`check-tx-psbt-copy.py` now reconstructs ten files, including both proof files,
from a fresh checkout at `cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`.
Its `--write` mode creates absent destinations and checks existing ones.
There are no additional Base64, error-constructor, or qualified SHA256 edits in
these two proofs: they do not refer to those operations or match those errors.

### PSBT field parity follow-up

The source remains `febyeji/lean-miniscript` at
`cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`, `LeanMiniscript/Psbt/Fields.lean`
L1–582, MIT. Only typed decoding changes. A pinned offline cyberkrill
`onchain-decode-psbt` capture confirms each rejection on one-record edits of
published BIP174/370/371 vectors. `check-tx-psbt-copy.py` reconstructs all edits
as exact-count replacements, in addition to the earlier capability/hash edits.

| Site | Problem | Fix and rust-bitcoin 0.32.8 reference |
|---|---|---|
| `globalStep`, global xpub | Any four version bytes were accepted. | Require mainnet xpub or testnet tpub after the existing length check; `src/bip32.rs:789-801`, `src/psbt/map/global.rs:113-118`. |
| `inputStep`, partial signatures | Empty and non-standard sighash values were accepted. | Check emptiness separately before requiring a standard ECDSA sighash; retain key-check precedence and defer DER; `src/crypto/ecdsa.rs:38-43`, `src/crypto/sighash.rs:447-460`, `src/psbt/serialize.rs:179-200`. |
| `inputStep`, both Taproot signatures | A 65th byte could be any sighash. | After the unchanged length checks, require default or standard sighash in each field; `src/crypto/taproot.rs:30-44`, `src/crypto/sighash.rs:500-512`. |
| `inputStep`, leaf-script value | Leaf versions were unchecked. | Require even versions other than annex 0x50; `src/psbt/serialize.rs:326-336`, `src/taproot/mod.rs:1236-1243`. |
| `inputStep`, leaf-script control block | Masked control-block versions were unchecked. | Apply the same rule to byte 0 masked with 0xfe, after existing size checks; `src/taproot/mod.rs:1105-1116`, `src/psbt/serialize.rs:310-313`. |
| `decodeTapTree` | Even annex 0x50 was accepted. | Apply the shared leaf-version rule to every leaf, preserving completeness checking; `src/psbt/serialize.rs:380-396`. |
| `keepUnknown`, all three scopes | Proprietary key tails were unbounded. | Keep canonical CompactSize validation unchanged; additionally allow at most 1,025 bytes after the identifier, counting rust-bitcoin's one-byte subtype, including when our subtype is multi-byte; `src/psbt/raw.rs:48,158-173,193-199`. |

The helper additions and their uses are decode-only. Framing, serializers,
theorem statements, raw storage and the three kept BIP rules are unchanged.
The changes above are candidates to send upstream.

### PSBT curve parity follow-up

The same MIT `LeanMiniscript/Psbt/Fields.lean` slice now uses two additional
supplied operations: x-only key parsing and strict DER signature parsing.
The earlier field-parity row's deferred DER check is resolved here.
`check-tx-psbt-copy.py` registers each change as an exact-count replacement,
including the module comment's updated description of curve validation.

| Site | Problem | Fix and source |
|---|---|---|
| `Psbt.decode`, global xpubs | Embedded points were unchecked. | After global shape/version/path and map-count checks, require `isValidPubkey` on bytes 45–77; rust-bitcoin 0.32.8 `src/bip32.rs:789-815`, `src/psbt/map/global.rs:113-118`; secp256k1 0.29.1 `src/key.rs:444-462`. Keeping this in whole-PSBT decoding preserves `globalCounts` and all theorem statements. |
| `inputStep`, partial signatures | DER was unchecked. | After strict key, nonempty value and standard sighash checks, validate the value minus its final byte; rust-bitcoin 0.32.8 `src/crypto/ecdsa.rs:38-43`, `src/psbt/serialize.rs:179-200`; secp256k1 0.29.1 `src/ecdsa/mod.rs:52-71`. No low-S or normalization. |
| `inputStep` / `outputStep`, internal keys | Only lengths were checked. | After existing 32-byte checks, require x-only parsing; rust-bitcoin 0.32.8 `src/psbt/serialize.rs:263-266`, `src/psbt/map/input.rs:346`, `src/psbt/map/output.rs:85`; secp256k1 0.29.1 `src/key.rs:1162-1180`. |
| `inputStep` / `outputStep`, Taproot BIP32 keys | Only lengths were checked. | Validate key data after its 32-byte check and before decoding the origin; rust-bitcoin 0.32.8 `src/psbt/serialize.rs:263-266`, `src/psbt/map/input.rs:341`, `src/psbt/map/output.rs:95`; secp256k1 0.29.1 `src/key.rs:1162-1180`. |
| `inputStep`, Taproot script-signature keys | Only length was checked. | Validate the first 32 bytes after the 64-byte check, before signature-value checks; rust-bitcoin 0.32.8 `src/psbt/serialize.rs:295-301`, `src/psbt/map/input.rs:331`; secp256k1 0.29.1 `src/key.rs:1162-1180`. |
| `inputStep`, control blocks | Internal points were unchecked. | Validate bytes 1–32 after the existing size and both leaf-version checks; rust-bitcoin 0.32.8 `src/taproot/mod.rs:1105-1121`, `src/psbt/serialize.rs:310-313`; secp256k1 0.29.1 `src/key.rs:1162-1180`. |

The pinned offline CLI capture confirms all nine new rejection vectors by
their exact upstream error text, with the original 39 capture rows unchanged.
Raw storage, serializers, framing, kept BIP rules and theorem statements stay
unchanged. No proof repair was needed.

## cyberkrill

Source: `douglaz/cyberkrill` at `27cad1faba86260b06665a89f0af5134d23525c2`
(MIT OR Apache-2.0), the reference this port follows. These problems were
found while porting and are reported as upstream issues; cyberkrill is never
patched from this repository. Paths and line numbers refer to that revision.

| File | Problem | Fix used in this port |
|---|---|---|
| `cyberkrill-core/src/bitcoin_rpc.rs` L1354, L1390 ([#152](https://github.com/douglaz/cyberkrill/issues/152)) | On the Bitcoin Core path, `onchain-move-utxos --max-amount` clamps the input total to the cap, so a selection that overshoots the cap pays the excess to the miner, and `fee_sats` leaves it out. | Not built yet (Phase 8c). Decided: keep the largest-first selection, but the output is the full selected total minus the fee, with no clamp, as a documented and tested difference. |
| `cyberkrill-core/src/slip132.rs` L35 ([#153](https://github.com/douglaz/cyberkrill/issues/153)) | `parse_slip132_xpub` panics on a valid Base58Check string whose payload is 0 to 3 bytes, because it slices the version before any length check. | `Bitcoin.Slip132.decode` requires exactly 78 bytes before it reads the version, and returns `wrongLength` otherwise. |
| `cyberkrill-core/src/bitcoin_rpc.rs` L275–284; `cyberkrill/src/main.rs` L920, L992, L1046, L1049 ([#154](https://github.com/douglaz/cyberkrill/issues/154)) | The `--fee-rate` and `--fee` help says a bare number is sat/vB (or sat), but it parses as BTC, so `--fee-rate 15` means 1.5e9 sat/vB. | The amount parser matches cyberkrill (a bare number is BTC), and a Phase 4d test pins it. How the CLI treats an unsuffixed fee rate or fee is still open (Phase 7a). |
| `cyberkrill-core/src/bdk_wallet.rs` L614, L703 ([#155](https://github.com/douglaz/cyberkrill/issues/155)) | The BDK `onchain-create-psbt` and `onchain-create-funded-psbt` paths truncate `--fee-rate` to whole sat/vB (`rate as u64`): `20.5sats` becomes 20, and any rate below 1 sat/vB builds a zero-fee PSBT. | Nothing to port: the BDK backends are out of v1. `Bitcoin.Fee` takes the rate in msat/vB, so fractional rates are kept. |
| `cyberkrill-core/src/bdk_wallet.rs` L888–912 ([#156](https://github.com/douglaz/cyberkrill/issues/156)) | The BDK `onchain-move-utxos` path never sets a fee rate or fee on the builder, so BDK pays its 1 sat/vB default and returns the rest as change, while the JSON reports the planned fee and no change. Low rates fail with "Insufficient funds". | Nothing to port: the BDK backends are out of v1. The port's `onchain-move-utxos` (Phase 8c, Core path) will pay its computed fee, with one output and no change. |
