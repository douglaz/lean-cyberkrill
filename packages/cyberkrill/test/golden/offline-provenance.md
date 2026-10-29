# Offline invite and PSBT provenance

This sidecar applies to `hybrid-inputs.json`, `hybrid-reference.json`,
`offline-reference.json`, `offline-provenance.json`, `offline-errors.json`,
`offline-exceptions.json`, `offline-port-timings.json` and
`offline-mutation-record.json`, `offline-exact-comparator-record.json`,
`offline-history-recapture.json`, `ordered-boundary-regression.json`,
`cluster-regression.json` and
`offline-validation.json`.

Reference output source: https://github.com/douglaz/cyberkrill at
`27cad1faba86260b06665a89f0af5134d23525c2`. Captured material is taken under MIT.
The upstream declarations are recorded separately for each source path:

| Source path | Declared upstream licence | Selected licence |
|---|---|---|
| `cyberkrill/src/main.rs` | MIT (`cyberkrill/Cargo.toml`) | MIT |
| `fedimint-lite/src/lib.rs` | MIT OR Apache-2.0 (`fedimint-lite/Cargo.toml`) | MIT |

`offline-provenance.json` retains these per-source details alongside the selected
capture licence. The Phase 6 fixture README retains the input attribution and licence source.
Outputs are extracted into separate status/stdout/stderr/file records, with
JSON escaped and reformatted. Commands use only deterministic offline inputs.

The three primary invites are reused unchanged from
`packages/fedimint-invite/test-data/primary.json`; its README supplies the exact
upstream source locations, licence and published example API-secret provenance.
No new credential is constructed or captured. Additional invites and JSON
boundaries are synthetic constructions by `test/offline-inputs.py`, reusing
the existing Phase 6 deterministic BigSize/bech32 helper. Source-derived
expectations are hand-derived; only actual executable observations are called
captures.

The 67 ordered-help cases are synthetic argument/filename controls, captured
with the same pinned executable. They reuse published invite JSON only as
file data. The original 415 rows/results are retained unchanged when extending
the reference inventory. `test/boundary-regressions.py` records the observed
unfixed and repaired executions separately; `test/file-observation.py` uses
disposable Python producers to check raw UTF-8 and newline observation without
changing JSON values, types, status or streams.

An additional 102 short-help cluster cases reuse only published invite JSON
and the first published BIP174 PSBT. All were measured in isolation before
pinning 44 help successes and 58 earlier-error/value/terminator controls.
The first 482 capture rows, including their results and timings, remain
unchanged. `test/cluster-regressions.py` separately records 44 original named
runtime failures, 58 passing controls and 102 repaired greens. The original
ordered-help/file regression record remains fixed historical evidence;
current production reintroductions bind the later sources independently.

The unchanged BIP174/370/371 wire collections are in
`packages/bitcoin/Bitcoin/PsbtVectors.lean`, from
https://github.com/bitcoin/bips at
`927b6de9915c9262615a6399de51b200f81e5aa4`, `bip-0174.mediawiki`,
`bip-0370.mediawiki`, and `bip-0371.mediawiki`, via
https://github.com/febyeji/lean-miniscript at
`cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd`,
`LeanMiniscript/Psbt/Fixtures.lean`. All three BIPs are BSD-2-Clause;
`packages/bitcoin/Bitcoin/LICENSE-psbt-bips` retains Ava Chow's attribution,
the source notices, licence conditions and disclaimer. Changes: extraction into CLI argument rows;
the extracted-transaction role vector's wire bytes are encoded to Base64 to
exercise rejection. All other published Base64 strings are unchanged.
All 49 Phase 4a parity inputs retain their identities and exact bytes from
`packages/bitcoin/test-data/cyberkrill-psbt-capture.json` and its generator.

`test/hybrid-inputs.py` constructs synthetic transactions, key origins and DER
placeholder r=1,s=1,SIGHASH_ALL values from the mathematical public G and -G
coordinates for secp256k1 (SEC 2 v2 §2.4.1,
https://www.secg.org/sec2-v2.pdf). Coordinate facts are used to generate key
encodings; no text, fixture file, private scalar or signing operation is copied.
The nineteen initial isolated CLI observations in `hybrid-reference.json`
are repeated in the full capture inventory. The synthetic PSBT address scripts
use zero hashes or G, never an owner's address or wallet data.

`test/psbt-oracle.py` independently reads BIP370 wire fields, published locktime
pins, UTXO values and scripts to derive full expected v2 JSON. Those expectations
are hand-derived, not successful reference outputs: the pinned reference
rejects every version-2 input. Exact-amount exception pins record only observed
numeric differences. New scripts are original work under the repository's
MIT OR Apache-2.0 licence; no Apache-only or unlicensed corpus is copied.
