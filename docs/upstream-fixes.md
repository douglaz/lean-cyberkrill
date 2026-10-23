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
