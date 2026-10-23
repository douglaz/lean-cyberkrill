# btc-verified integration: external analysis and verification notes

This file records an external analysis of whether
[`ProofOfKeags/btc-verified`](https://github.com/ProofOfKeags/btc-verified), a Lean 4 formal model
of Bitcoin's consensus-critical structures, could help this repository. The analysis is reproduced
as received, minus its one-word conversational opening. It was not written against pinned commits,
so the [verification notes](#verification-notes) below (N1–N21) check each factual claim against
btc-verified @ [`2fdeb40`](https://github.com/ProofOfKeags/btc-verified/tree/2fdeb40ca2b3f289896ed14a3340ad231cd16538)
(2026-10-21) and this repository @ `5baad8b`, and record every correction. The plan's response is
the post-v1 Phase 11 in [`plan.md` §7](../plan.md#7-post-v1-transaction-equivalence-with-btc-verified-phase-11).

## The analysis

[btc-verified](https://github.com/ProofOfKeags/btc-verified) could significantly help [lean-cyberkrill](https://github.com/douglaz/lean-cyberkrill), particularly its Bitcoin transaction and serialization libraries. But I would integrate it selectively rather than replace your existing work.

After inspecting both repositories, the important distinction is that they have complementary goals:

* lean-cyberkrill is building practical, reusable Bitcoin, Lightning and Fedimint libraries in Lean 4, with a CLI on top.

* btc-verified is building a machine-checked model of Bitcoin's consensus-critical structures and semantics.

Your project already has meaningful formal proofs, including a SHA-256 implementation proved equivalent to a FIPS 180-4 specification, CompactSize correctness properties, address-codec round trips and exact amount handling.

The greatest opportunity is therefore using btc-verified to strengthen your Bitcoin transaction model, rather than duplicating its proofs or importing its entire consensus framework.

There are two immediate integration obstacles: lean-cyberkrill uses Lean 4.35.0, while btc-verified currently targets Lean 4.30.0-rc2; and btc-verified is Apache-2.0-only, while your project's contribution rules explicitly exclude copying Apache-only code into its dual MIT/Apache codebase.

Neither prevents using btc-verified as a separate dependency or as an independent reference implementation. They do make indiscriminate copying a poor choice.

### 1. Where btc-verified would help most

| Component                 | What lean-cyberkrill has                                              | Additional value from btc-verified                                  | Priority  |
| ------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------- | --------- |
| Transaction serialization | Legacy and SegWit codecs, with partial proofs                         | Complete round-trip, canonicality and representation invariants     | Very high |
| TXIDs / WTXIDs            | TXID calculation and witness-aware serialization                      | Formal commitment-binding theorems for both identifiers             | High      |
| Packed decoding           | ByteArray-based processing                                            | Fast codecs proved equivalent to abstract specification codecs      | High      |
| CompactSize               | Already proved canonical decoding and round trips                     | Composable verified codec abstractions                              | Medium    |
| PSBT                      | BIP174/370/371 parsing, maps and validation                           | No direct PSBT implementation; useful underlying transaction proofs | Medium    |
| SHA-256                   | Optimized implementation with FIPS specification correspondence proof | Mostly an alternative implementation                                | Low       |
| Bech32 / addresses        | Existing codecs and proofs                                            | No corresponding btc-verified modules                               | None      |
| Lightning / Fedimint      | Planned packages                                                      | No corresponding components                                         | None      |

Sources: [lean-cyberkrill Bitcoin package](https://github.com/douglaz/lean-cyberkrill/tree/master/packages/bitcoin/Bitcoin), [btc-verified transaction model](https://github.com/ProofOfKeags/btc-verified/blob/master/BtcVerified/Transaction/README.md), [packed codecs](https://github.com/ProofOfKeags/btc-verified/blob/master/BtcVerified/Packed/README.md).

### 2. A concrete weakness it could address

Consider these two files in your repository:

[Bitcoin/Transaction.lean](https://github.com/douglaz/lean-cyberkrill/blob/master/packages/bitcoin/Bitcoin/Transaction.lean) defines:

```lean
structure OutPoint where
  txid : ByteArray
  index : UInt32
```

Nothing in this type guarantees that `txid` has exactly 32 bytes.

The serializer simply concatenates that byte array with the output index. Consequently, an arbitrary `OutPoint` can be constructed whose serialization is not a valid Bitcoin outpoint.

btc-verified instead defines:

```lean
structure OutPoint where
  txid : Hash256
  vout : UInt32
```

Its hash type is exactly 256 bits.

A second example appears in your [Deserialization.lean](https://github.com/douglaz/lean-cyberkrill/blob/master/packages/bitcoin/Bitcoin/Deserialization.lean):

```lean
structure WitnessTransaction where
  transaction : Transaction
  witnesses : List (List ByteArray)
```

The witness-list length is not constrained to equal the input count. In fact, your serializer explicitly ignores excess witness stacks and substitutes empty stacks for missing ones.

This doesn't mean your parser is necessarily broken: it constructs matched lists when parsing valid wire data. But applications constructing transaction values directly can violate those invariants.

btc-verified's transaction type makes the input/witness correspondence structural, and its SegWit constructor requires nonempty witness data. Its decoder and encoder are then proved to satisfy round-trip and canonicality properties.

These are precisely the kinds of guarantees worth bringing into lean-cyberkrill.

### 3. Recommended integration approach

I would avoid restructuring your Bitcoin package immediately. Instead, establish a verification boundary.

lean-cyberkrill — Existing production codecs, PSBT support, CLI

Verification bridge — Type conversion, encoding equivalence, parser equivalence

btc-verified — Formal specification, proofs, verified codecs

The target proof would look conceptually like:

    encode_cyber(t) = encode_verified(convert(t))

for every well-formed transaction `t`.

A corresponding parser-equivalence theorem would establish that both implementations interpret the same accepted bytes as corresponding transaction values. For malformed inputs, acceptance and rejection behavior would need separate explicit treatment.

Once that bridge is proved, some of btc-verified's properties could be transported to your actual implementation instead of reproducing every proof.

### Proposed sequence

* Differential transaction testing first. Compare lean-cyberkrill, btc-verified and Bitcoin Core on transaction parsing, serialization, TXIDs and WTXIDs. Cover canonical and malformed encodings, SegWit edge cases, empty transactions, truncated inputs and CompactSize boundaries. The October update's differential-fuzzing approach is a useful starting point.

* Introduce a separate proof package. Something like `packages/bitcoin-proofs`, with adapters between the two transaction representations. Keep Mathlib and the Apache-only dependency out of your existing lightweight Bitcoin package. The Lean version mismatch needs resolving before both libraries can be imported into one proof environment.

* Prove agreement and strengthen the model. Start with outpoint encoding and fixed-width fields, then witness arity, transaction encoding, canonical decoding and finally TXID/WTXID relationships. Change the production types only when the migration clearly improves the API.

### 4. There is also a useful contribution in the opposite direction

Your SHA-256 work may actually be stronger than btc-verified's current SHA-256 implementation in one important respect.

btc-verified has executable SHA-256 and tests against known vectors. Your [Sha256/Api.lean](https://github.com/douglaz/lean-cyberkrill/blob/master/packages/sha256/Sha256/Api.lean) exposes:

```lean
theorem sha256_spec (msg : ByteArray) :
    (sha256 msg).toList =
      Spec.sha256_bytes msg.data.toList
```

That is a universal implementation-to-specification theorem, not merely a collection of test cases. Its significance still depends on the specification faithfully transcribing FIPS 180-4, but it is a stronger internal correctness connection.

You could potentially help btc-verified by providing a bridge from its SHA-256 function to yours, or by collaborating on adopting the proven implementation.

This could be mutually beneficial:

* btc-verified contributes the more mature transaction and commitment proofs.

* lean-cyberkrill contributes a proven optimized SHA-256 implementation and practical experience integrating the Bitcoin codecs into PSBT and application libraries.

### 5. What I would not change

Keep your Base58, Bech32, address, amount and PSBT modules for now.

In particular, btc-verified doesn't solve the deferred Bech32 four-error detection theorem described in your README. That's a separate algebraic proof problem.

Likewise, it doesn't currently implement PSBT semantics, BOLT11, LNURL or Fedimint invitation handling. It also lacks a complete verified Script interpreter, so adopting it would not make PSBT signing or Bitcoin spending authorization fully verified.

### Recommendation

I would make transaction equivalence with btc-verified a dedicated future phase in lean-cyberkrill, without blocking completion of your existing v1 roadmap.

The first deliverable should be a three-way compatibility test suite and an inventory of the mismatches between your transaction types and btc-verified's types. The second should be a machine-checked encoding-equivalence proof.

That gives you a concrete route toward a powerful property:

A usable Bitcoin library whose production transaction serialization is proved to agree with an independently formalized Bitcoin model, with differential testing against Bitcoin Core providing additional compatibility evidence.

That's substantially more valuable than merely having two independently tested Lean Bitcoin implementations.

## Verification notes

Paths are relative to each repository root: btc-verified @ `2fdeb40`, this repository @ `5baad8b`,
Bitcoin Core @ `fc6923c` (the commit btc-verified's `Kernel/abi.toml` pins). "Confirmed" means the
claim holds as written; anything else is a correction or an addition the plan relies on.

### Toolchain and licence

- **N1. Lean version: confirmed.** btc-verified's `lean-toolchain` is `leanprover/lean4:v4.30.0-rc2`,
   and its `lake-manifest.json` pins Mathlib `ee3a540` (also built for v4.30.0-rc2). This
   repository pins v4.35.0. Mathlib has a `v4.35.0` tag, so nothing on Mathlib's side blocks moving
   btc-verified forward.
- **N2. Licence: confirmed Apache-2.0 only** (`LICENSE`, `license := "Apache-2.0"` in
   `lakefile.lean`, README "License"). `Kernel/COPYING.bitcoin` is Bitcoin Core's MIT notice for the
   pinned C header. The "contribution rules" the analysis cites are AGENTS.md "Licence" and plan
   §5. Their text: Apache-2.0-only material is "kept out of the tree; use a pinned non-flake input
   read at test time". They don't say whether a build-time Lake `require` of such a package is
   allowed; plan §7 open question 2 asks the owner.
- **N3. Addition: btc-verified requires Mathlib** (`require "leanprover-community" / "mathlib"`), so
   any package that imports it takes Mathlib with it. Mathlib is Apache-2.0 as well. Plan §2
   confines Mathlib to a separate `<pkg>-proofs` package. §6 #2 allowed Mathlib as a pinned input
   of `bitcoin-proofs` only if the 4-error theorem needed it, and counted Mathlib's build time
   inside `nix flake check`.

### btc-verified's model

- **N4. `OutPoint`: confirmed** (`BtcVerified/Transaction/OutPoint.lean:33-38`: `txid : Hash256`,
   `vout : UInt32`).
- **N5. `Hash256`: correction in detail.** It is `abbrev Hash256 := Bytes 32`
   (`BtcVerified/Crypto/Hash256.lean:30`), where `Bytes n := { bytes : List UInt8 // bytes.length = n }`
   (`BtcVerified/Serialize/Bytes.lean:50`). So it is exactly 32 bytes, as a length-indexed
   `List UInt8` rather than a `ByteArray`. btc-verified's own `BtcVerified/Crypto/README.md` still
   says `BitVec 256`, which is stale.
- **N6. Transaction type: confirmed, with one correction.** `Tx` (`BtcVerified/Transaction/Tx.lean:162-176`)
   has three constructors: `legacy` (requires non-empty inputs), `empty` (zero inputs and zero
   outputs, Core's `version ‖ 00 ‖ 00 ‖ locktime` object), and `segwit`, a `CountedList SegwitInput`.
   Each `SegwitInput` bundles an input with its witness stack, so one-stack-per-input arity is
   structural. *Correction:* `segwit` does not require non-empty witness data for each input; it
   requires that **at least one** input's stack is non-empty (`hWitness : ∃ input ∈ inputs.val,
   input.witness.NonEmpty`). Our parser enforces the same rule (`superfluousWitness`,
   `packages/bitcoin/Bitcoin/Deserialization.lean:67`), and our serializer emits the legacy form
   when every in-range stack is empty.
- **N7. Round-trip and canonicality: confirmed.** `decodeTx_encodeTx` (`Tx.lean:394`):
   `decodeTx (encodeTx tx ++ rest) = some (tx, rest)`. `decodeTx_canonical` (`Tx.lean:493`):
   accepted bytes are `encodeTx tx ++ rest`. Both are stated over `List UInt8`, and `decodeTx`
   returns an `Option`, with no error categories.
- **N8. TXID/WTXID binding: confirmed, with a qualifier.** `Tx.txid_binding` and `Tx.wtxid_binding`
   (`BtcVerified/Transaction/Txid.lean:65,74`) say that equal ids imply equal bodies (or equal
   transactions) **or** an explicit double-SHA-256 collision. That is not unconditional injectivity.
- **N9. Packed codecs: confirmed.** `BtcVerified/Packed/README.md`: the packed codecs run over
   `ByteArray` through core's `Std.Data.ByteSlice`, and each instance is proved to compute exactly
   what the list-based specification computes, so round-trip and canonicality carry over. The
   README reports 195x (decode) and 4.4x (encode) over the spec on mainnet block 481824.
- **N10. SHA-256 tests only: confirmed.** `BtcVerified/Crypto/Sha256.lean` is a computable
    `List UInt8` SHA-256 checked by known-answer tests at build time, plus length lemmas and
    collision-resistance relations between `sha256` and `sha256d`. It has no specification theorem.
- **N11. Script interpreter: correction.** The analysis says btc-verified "lacks a complete verified
    Script interpreter". It has no interpreter at all yet. `Script` is the raw counted byte string
    (`BtcVerified/Script/README.md`), and the interpreter is roadmap milestone 6. There is also no
    PSBT, Base58, bech32, BOLT11, LNURL or Fedimint code (no file mentions any of them). So this
    work cannot help the bech32 4-error theorem: confirmed.
- **N12. Core's `MAX_SIZE`: addition.** Neither specification model enforces Core's `0x02000000`
    container-length limit. btc-verified applies it only at its kernel boundary, as a post-decode
    guard (`Kernel/Transaction.lean:12-20`), and our decoder has no such check. This is an expected
    Core-only rejection class.

### This repository

- **N13. `OutPoint.txid : ByteArray`: confirmed** (`packages/bitcoin/Bitcoin/Transaction.lean:10-13`).
    `serializeOutPoint` concatenates the bytes with the index (`:35-36`). The reader always takes
    exactly 32 bytes (`Deserialization.lean:9-12`), so only directly constructed values can break
    the width.
- **N14. `WitnessTransaction.witnesses : List (List ByteArray)`: confirmed** (`Deserialization.lean:32-35`).
    The serializer's docstring and code at `5baad8b` read "Missing stacks are treated as empty, and
    stacks beyond the inputs are ignored" (`:84-96`). PR #16 changed this: commit `6ebc355` made the
    marker decision look only at the inputs' stacks (`witnesses.take tx.inputs.size`), so a surplus
    non-empty stack no longer produces bytes the parser rejects. The analysis describes the code
    after that change.
- **N15. Proof level: "partial" was accurate, and the gap has since narrowed.** Before Phase 4a
    (3 of 3) the codec proofs stopped at CompactSize, byte vectors and witness stacks
    (`DeserializationProofs.lean`, `CompactSizeProofs.lean`). Phase 4a (3 of 3) (#19, `525a688`)
    adds `Transaction.WellFormed` with nine preconditions (`TransactionProofs.lean:12-21`) and
    proves the transaction round trip under them. Three of the preconditions are 32-byte txids, `witnesses.length = tx.inputs.size`, and
    `inputs > 0 ∨ outputs = 0`. So the two weaknesses in section 2 of the analysis become theorem
    hypotheses there, though not type invariants. The third precondition is exactly btc-verified's
    `legacy`/`empty` split.
- **N16. WTXID: correction.** We compute `Transaction.txid` (`Deserialization.lean:81-82`) but have no
    wtxid function. The table's "TXID calculation" is right, but a WTXID comparison needs one
    added.
- **N17. A mismatch already known.** Our non-witness reader (`parseTransaction … (allowWitness :=
    false)`, the PSBT unsigned-transaction path) accepts a zero-input transaction with outputs.
    btc-verified's `Tx` cannot represent one: `legacy` needs inputs, and `empty` needs zero outputs.
    One BIP174 test vector carries such a transaction: `bip174Valid[9]`, with 0 inputs and 2
    outputs. It is the only one of 136 embedded transactions that fails `Transaction.WellFormed`
    (README, Phase 4a (3 of 3)).
- **N18. SHA-256 attribution: addition.** `sha256_spec` and the specification it targets come from
    [`pure-algebra/lean4-hash`](https://github.com/pure-algebra/lean4-hash) @ `ab7eda4` (MIT), which
    this repository ported to v4.35.0 (plan §1). Any contribution to btc-verified carries lean4-hash's
    MIT notice; MIT code can go into an Apache-2.0 project. A second point: carrying btc-verified's
    TXID binding over to our `txid` needs a proof that btc-verified's `sha256` equals that
    specification. So the SHA-256 bridge is a prerequisite of the TXID step, not only a gift.
- **N19. Our other proofs** (SHA-256, CompactSize, address round trips, exact amounts): consistent with
    plan §2 and the merged Phases 2 and 3a. They were not re-audited here.

### The "October update"

- **N20. Identified.** It is "btc-verified October update: connecting map to territory", posted by
    btc-verified's author on Delving Bitcoin on 2026-10-19
    (<https://delvingbitcoin.org/t/btc-verified-october-update-connecting-map-to-territory/2964>).
    The same text is on the author's site. The method is implemented in btc-verified's `Fuzz/` and
    `Kernel/` directories. The facts below come from `Fuzz/README.md` and `Kernel/abi.toml` @
    `2fdeb40`:
    - **What is compared.** A libFuzzer harness gives the same transaction bytes to two libraries:
      Bitcoin Core's `libbitcoinkernel` and btc-verified's Lean implementation of nine of its C API
      entry points. Both are called through one C function table typed from the unmodified
      `bitcoinkernel.h`, with Core pinned at `fc6923c`.
    - **What is observed.** Create acceptance, serialization status and canonical bytes, the
      context-free check verdict, and the validation mode and result.
    - **Inputs.** Eight small inputs and three large boundary inputs (999,999, 1,000,000 and
      1,000,001 stripped bytes) are replayed on every run. A fresh corpus campaign then runs from a
      recorded seed and budget (`Fuzz/campaign.toml`, 4,096-byte mutation cap).
    - **Negative control.** A deliberately injected disagreement must fail on the changed verdict,
      save the input and both observations, and reproduce only with injection enabled.
    - **CI.** CI fails on any observed disagreement.

    That harness is C. This repository allows C only in `secp256k1` and `http-curl` (plan §1), so
    Phase 11 keeps the method but by default uses a C-free Core oracle (plan §7).
- **N21. Core oracle facts** (from Core @ `fc6923c`), used by plan §7:
    - `decoderawtransaction <hex> true` tries only the witness-aware deserializer, and `false` only
      the non-witness one. Each must consume the whole input. With the argument omitted, a heuristic
      picks between the two (`src/rpc/rawtransaction.cpp:461-466`, `src/core_io.cpp:154-223`).
    - `bitcoin-tx` always uses that heuristic (`src/bitcoin-tx.cpp:820`).
    - `decoderawtransaction` returns `txid`, `hash` (the wtxid) and `size`, but not the
      re-serialized bytes (`include_hex=false`).
    - An HTTP request body is limited to 32 MiB (`MAX_BODY_SIZE`, `src/httpserver.h:82`). Through
      RPC, then, Core never sees a transaction whose hex is larger than that, which includes any
      container just over `MAX_SIZE`.
