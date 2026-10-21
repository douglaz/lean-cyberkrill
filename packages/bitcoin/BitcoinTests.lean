/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import BitcoinTests.AxiomGate
import Bitcoin.Base58Vectors

open Bitcoin
open Bitcoin.Amount
open Bitcoin.CompactSize
open Bitcoin.Base58

namespace BitcoinTests

deriving instance DecidableEq for Except

private def check (label : String) (condition : Bool) : IO Unit :=
  unless condition do throw (IO.userError s!"assertion failed: {label}")

private def checks (label : String) (pinned : Nat) (cases : Array (String × Bool)) : IO Unit := do
  check s!"{label} count" (cases.size == pinned)
  for (name, ok) in cases do check s!"{label} {name}" ok
  IO.println s!"{label}: {cases.size}/{pinned}"

private def bytes (xs : List Nat) : ByteArray := ⟨(xs.map UInt8.ofNat).toArray⟩

private def hexTests : IO Unit := do
  let all := bytes (List.range 256)
  let allHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  checks "hex" 12 #[
    ("empty", Hex.decode "" == some (bytes [])),
    ("lower", Hex.decode "deadbeef" == some (bytes [222, 173, 190, 239])),
    ("upper", Hex.decode "DEADBEEF" == some (bytes [222, 173, 190, 239])),
    ("mixed", Hex.decode "DeAdbEeF" == some (bytes [222, 173, 190, 239])),
    ("all-256-encode-lower", Hex.encode all == allHex),
    ("all-256-decode", Hex.decode allHex == some all),
    ("all-256-roundtrip", Hex.decode (Hex.encode all) == some all),
    ("odd", Hex.decode "abc" == none),
    ("g", Hex.decode "0g" == none),
    ("space", Hex.decode "a " == none),
    ("prefix", Hex.decode "0x00" == none),
    ("non-ascii", Hex.decode "é0" == none)]

private def compactTests : IO Unit := do
  let vectors : Array (Nat × List UInt8) := #[
    (0, [0]), (252, [252]), (253, [253,253,0]), (65535, [253,255,255]),
    (65536, [254,0,0,1,0]), (4294967295, [254,255,255,255,255]),
    (4294967296, [255,0,0,0,0,1,0,0,0]),
    (18446744073709551615, [255,255,255,255,255,255,255,255,255])]
  check "CompactSize boundaries count" (vectors.size == 8)
  for (n, encoded) in vectors do
    check s!"CompactSize encode {n}" (compactSize n == encoded)
    check s!"CompactSize decode {n}" (decide (readCompactSize (encoded ++ [42,255]) = .ok (n, [42,255])))
  IO.println "CompactSize boundaries: 8/8"
  let noncanonical : Array (List UInt8) :=
    #[[253,252,0], [253,0,0], [254,255,255,0,0], [255,255,255,255,255,0,0,0,0]]
  checks "CompactSize noncanonical" 4 (noncanonical.map fun xs =>
    (s!"{repr xs}", decide (readCompactSize xs = .error .nonCanonicalCompactSize)))
  let truncated : Array (List UInt8) := #[[], [253,0], [254,0,0,0], [255,0,0,0,0,0,0,0]]
  checks "CompactSize truncated" 4 (truncated.map fun xs =>
    (s!"{repr xs}", decide (readCompactSize xs = .error .truncated)))

private def amountTests : IO Unit := do
  let huge : Amount := ⟨18446744073709551615001⟩
  checks "Amount" 36 #[
    ("one-sat", parseBtc "0.00000001" == some ⟨1000⟩),
    ("supply", parseBtc "21000000" == some ⟨2100000000000000000⟩),
    ("sub-msat", parseBtc "0.000000000001" == none),
    ("D2-btc", parseBtc "0.100000000000" == some ⟨10000000000⟩),
    ("D2-one-msat", parseBtc "0.000000000010" == some ⟨1⟩),
    ("D2-sats", parseSats "0.5000" == some ⟨500⟩),
    ("print-strip", (parseBtc "0.10").map printBtc == some "0.1"),
    ("print-one-msat-btc", printBtc ⟨1⟩ == "0.00000000001"),
    ("print-one-msat-sats", printSats ⟨1⟩ == "0.001"),
    ("print-zero", printBtc ⟨0⟩ == "0"),
    ("print-integral", printBtc ⟨100000000000⟩ == "1"),
    ("sats-three-digits", parseSats "1.234" == some ⟨1234⟩),
    ("sats-sub-msat", parseSats "0.0001" == none),
    ("integer-msat", parseMsat "123" == some ⟨123⟩),
    ("msat-not-decimal", parseMsat "1.0" == none),
    ("msat-not-empty", parseMsat "" == none),
    ("json-written-digits", ofJsonNumber ⟨10000000,8⟩ == some ⟨10000000000⟩),
    ("json-exponent12-accepted", ofJsonNumber ⟨1000000000000,12⟩ == some ⟨100000000000⟩),
    ("json-exponent12-rejected", ofJsonNumber ⟨1,12⟩ == none),
    ("json-negative", ofJsonNumber ⟨-1,0⟩ == none),
    ("json-zero", ofJsonNumber ⟨0,100⟩ == some ⟨0⟩),
    ("huge-msat-parse", parseMsat "18446744073709551615001" == some huge),
    ("huge-msat-roundtrip", parseMsat (printMsat huge) == some huge),
    ("huge-sats-roundtrip", parseSats (printSats huge) == some huge),
    ("huge-btc-roundtrip", parseBtc (printBtc huge) == some huge),
    ("msat-accessor", toMsat (ofMsat 17) == 17),
    ("sats-constructor", (ofSats 17).msat == 17000),
    ("sats-accessor", toSats? ⟨17000⟩ == some 17),
    ("fractional-sats-accessor", toSats? ⟨17001⟩ == none),
    ("btc-accessor", ofBtc? (toBtc huge) == some huge),
    ("sats-decimal-accessor", ofDecimal (toSatDecimal huge) 3 == some huge),
    ("msat-decimal-accessor", ofDecimal (toMsatDecimal huge) 0 == some huge),
    ("library-no-exponents", parseBtc "1e-3" == none),
    ("library-no-sign", parseBtc "+1" == none),
    ("library-no-whitespace", parseBtc "1 " == none),
    ("fractional-leading-zero", printSats ⟨1005⟩ == "1.005")]

private def expect {α : Type} (x : Except String α) : IO α :=
  match x with
  | .ok a => pure a
  | .error e => throw (IO.userError e)

private def load (path : System.FilePath) : IO (Array Lean.Json) := do
  let json ← expect (Lean.Json.parse (← IO.FS.readFile path))
  expect json.getArr?

private def text (j : Lean.Json) (key : String) : IO String :=
  expect (j.getObjValAs? String key)

private def value (j : Lean.Json) : IO (Option Nat) := do
  let v ← expect (j.getObjVal? "msat")
  if v == .null then return none
  let s ← expect v.getStr?
  match s.toNat? with
  | some n => return some n
  | none => throw (IO.userError s!"invalid fixture integer: {s}")

private def cliTests : IO Unit := do
  let cases ← load "test-data/cli.json"
  check "CLI grammar count" (cases.size == 124)
  for c in cases do
    let name ← text c "name"
    let input ← text c "input"
    let expected ← value c
    check s!"CLI grammar {name}" ((parseInput input).toOption.map Amount.msat == expected)
  IO.println "CLI grammar: 124/124"
  let captured ← load "test-data/cyberkrill-amounts.json"
  check "cyberkrill cross-check count" (captured.size == 124)
  for i in [:captured.size] do
    let row := captured[i]!
    let c := cases[i]!
    let name ← text c "name"
    check s!"cyberkrill cross-check input {name}"
      ((← text row "input") == (← text c "input") && (← text row "name") == name)
    let upstream ← value row
    let port ← value c
    if upstream != port then
      if port.isNone then
        check s!"cyberkrill named rejection {name}" ((c.getObjVal? "delta").isOk && upstream.isSome)
      else
        let difference ← text c "upstreamMsat"
        check s!"cyberkrill exact-value difference {name}"
          (upstream.isSome && difference.toNat? == upstream)
    else
      check s!"cyberkrill equality {name}" ((parseInput (← text c "input")).toOption.map Amount.msat == upstream)
  IO.println "cyberkrill cross-check: 124/124"

private def base58Tests : IO Unit := do
  check "base58 vectors count" (rawVectors.size == 21)
  for (raw, encoded) in rawVectors do
    match Hex.decode raw with
    | none => throw (IO.userError "invalid hex in base58 vectors")
    | some b =>
      check s!"base58 vectors {raw}" (base58Encode b == encoded && base58Decode encoded == some b)
  IO.println "base58 vectors: 21/21"
  let zeros : Array (List Nat × String) :=
    #[([], ""), ([0], "1"), ([0,0,0], "111"), ([0,0,1], "112"), ([0,58], "121")]
  checks "base58 leading zeros" 5 (zeros.map fun (raw, encoded) =>
    (encoded, base58Encode (bytes raw) == encoded && base58Decode encoded == some (bytes raw)))
  checks "base58 invalid characters" 6
    ((#["20g", "2Og", "2Ig", "2lg", "2g ", "2Ĳg"] : Array String).map fun s =>
      (s, base58Decode s == none))
  let answers ← load "test-data/base58check.json"
  check "Base58Check known answers count" (answers.size == 4)
  for row in answers do
    let name ← text row "name"
    let raw ← text row "payloadHex"
    let encoded ← text row "encoded"
    match Hex.decode raw with
    | none => throw (IO.userError "invalid hex in Base58Check known answers")
    | some p =>
      check s!"Base58Check known answers {name}"
        (base58CheckEncode p == encoded && base58CheckDecode encoded == .ok p)
  IO.println "Base58Check known answers: 4/4"
  -- The empty-payload answer is 3QJmnh; change its last alphabet character.
  checks "Base58Check rejections" 2 #[
    ("short", base58CheckDecode "111" == .error .tooShort),
    ("checksum", base58CheckDecode "3QJmni" == .error .checksumMismatch)]
  checks "Base58Check invalid alphabet" 1 #[
    ("invalid", base58CheckDecode "2g " == .error .invalidBase58)]

end BitcoinTests

def main : IO Unit := do
  IO.println s!"Bitcoin axiom gate: {BitcoinTests.auditedTheoremCount} library theorems; {BitcoinTests.namedTheorems.length} named; 0 offenders"
  BitcoinTests.hexTests
  BitcoinTests.compactTests
  BitcoinTests.amountTests
  BitcoinTests.cliTests
  BitcoinTests.base58Tests
