/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Lean.Data.Json

namespace BitcoinTests.Slip132Tests

open Bitcoin Bitcoin.Slip132

deriving instance DecidableEq for Except
deriving instance BEq for Except

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

private def checks (name : String) (pinned : Nat) (cases : Array (String × Bool)) : IO Unit := do
  check s!"{name} count" (cases.size == pinned)
  for (label, ok) in cases do check s!"{name} {label}" ok
  IO.println s!"{name}: {cases.size}/{pinned}"

-- Never render a failed input, especially a runtime-derived private-version string.
private def getOk {ε α : Type} (name : String) (value : Except ε α) : IO α :=
  match value with
  | .ok result => pure result
  | .error _ => throw <| IO.userError s!"assertion failed: {name}"

private def load (path : String) : IO (Array Lean.Json) := do
  let json ← getOk "slip132 JSON" (Lean.Json.parse (← IO.FS.readFile path))
  getOk "slip132 JSON rows" json.getArr?

private def field (row : Lean.Json) (key : String) : IO String :=
  getOk s!"slip132 field {key}" (row.getObjValAs? String key)

private def fromHex (s : String) : ByteArray := (Hex.decode s).getD ByteArray.empty

-- Independent literals from cyberkrill slip132.rs:9-20, never the library table.
private def targets : Array (Version × String × String) := #[
  (.xpub, "xpub", "0488b21e"), (.ypub, "ypub", "049d7cb2"), (.zpub, "zpub", "04b24746"),
  (.tpub, "tpub", "043587cf"), (.upub, "upub", "044a5262"), (.vpub, "vpub", "045f1cf6")]

private def sources : IO (Array (String × ByteArray)) := do
  let rows ← load "test-data/bip32-public-vectors.json"
  check "slip132 source count" (rows.size == 12)
  let mut result := #[]
  for i in [:rows.size] do
    let s ← getOk s!"slip132 source {i} string" rows[i]!.getStr?
    let p ← getOk s!"slip132 source {i} Base58Check" (Base58.base58CheckDecode s)
    check s!"slip132 source {i} shape" (s.length == 111 && s.startsWith "xpub" &&
      p.size == 78 && p.extract 0 4 == fromHex "0488b21e")
    result := result.push (s, p)
  pure result

def vectors : IO Unit := do
  let rows ← sources
  check "slip132 vectors count" (rows.size == 12)
  IO.println "slip132 vectors: 12/12"

def conversions : IO Unit := do
  let input ← sources
  let expected ← load "test-data/slip132-derived.json"
  check "slip132 conversions count" (expected.size == 72 && input.size * targets.size == 72)
  for i in [:expected.size] do
    let (s, p) := input[i / 6]!
    let (v, name, hex) := targets[i % 6]!
    let answer ← field expected[i]! "encoded"
    check s!"slip132 conversion {i} independent row"
      ((← field expected[i]! "source") == s && (← field expected[i]! "prefix") == name &&
        (← field expected[i]! "versionHex") == hex)
    check s!"slip132 conversion {i} independent expectation"
      (convert s v == .ok answer && answer.startsWith name)
    check s!"slip132 conversion {i} payload"
      (Base58.base58CheckDecode answer == .ok (fromHex hex ++ p.extract 4 p.size))
  IO.println "slip132 conversions: 72/72"

def roundtrips : IO Unit := do
  let input ← sources
  check "slip132 roundtrips count" (input.size * targets.size == 72)
  for i in [:input.size] do
    for j in [:targets.size] do
      let result ← getOk s!"slip132 roundtrip {i}/{j} forward" (convert input[i]!.1 targets[j]!.1)
      check s!"slip132 roundtrip {i}/{j} original string"
        (convert result .xpub == .ok input[i]!.1)
  IO.println "slip132 roundtrips: 72/72"

def goldens : IO Unit := do
  let input ← sources
  let rows ← load "test-data/cyberkrill-slip132.json"
  let selected := targets.filter (fun (_, name, _) => name != "xpub" && name != "tpub")
  check "slip132 goldens count" (rows.size == 48 && input.size * selected.size == 48)
  for i in [:rows.size] do
    let (_, p) := input[i / 4]!
    let (v, _, hex) := selected[i % 4]!
    let target : Version := if i % 4 < 2 then .xpub else .tpub
    let derived := Base58.base58CheckEncode (fromHex hex ++ p.extract 4 p.size)
    let captured ← field rows[i]! "input"
    check s!"slip132 golden {i} input order" (derived == captured)
    check s!"slip132 golden {i} port input" (convert input[i / 4]!.1 v == .ok captured)
    check s!"slip132 golden {i} conversion"
      (convert captured target == .ok (← field rows[i]! "output"))
  IO.println "slip132 goldens: 48/48"

def unknownVersions : IO Unit := do
  let (_, p) := (← sources)[0]!
  let known := targets.map (fun (_, _, hex) => fromHex hex)
  let mut versions := #[fromHex "0488ade4", fromHex "04358394", fromHex "00000000"]
  for b in known do versions := versions.push (b.set! 3 (b[3]! ^^^ 1))
  check "slip132 unknown-version count" (versions.size == 9)
  for i in [:versions.size] do
    let b := versions[i]!
    check s!"slip132 unknown-version {i} outside table" (!(known.contains b))
    let s := Base58.base58CheckEncode (b ++ p.extract 4 p.size)
    check s!"slip132 unknown-version {i} rejected"
      (convert s .xpub == .error (.unknownVersion b))
  IO.println "slip132 unknown-version: 9/9"

def lengths : IO Unit := do
  let (_, p) := (← sources)[0]!
  let cases := #[("77", p.extract 0 77), ("79", p ++ p.extract 0 1)]
  checks "slip132 wrong-length" 2 (cases.map fun (name, b) =>
    (name, convert (Base58.base58CheckEncode b) .xpub == .error (.wrongLength b.size)))

def shortPayloads : IO Unit := do
  let (_, p) := (← sources)[0]!
  let cases := #[p.extract 0 0, p.extract 0 3]
  checks "slip132 short-payload" 2 (cases.mapIdx fun i b =>
    (s!"{i}", convert (Base58.base58CheckEncode b) .xpub == .error (.wrongLength b.size)))

private def badChecksum (s : String) : String :=
  String.ofList (s.toList.take (s.length - 1) ++ [if s.toList.getLast! == '1' then '2' else '1'])

def base58Errors : IO Unit := do
  let (s, _) := (← sources)[0]!
  checks "slip132 Base58Check" 2 #[
    ("checksumMismatch", convert (badChecksum s) .xpub == .error (.base58 .checksumMismatch)),
    ("invalidBase58", convert (s ++ "0") .xpub == .error (.base58 .invalidBase58))]

def checkOrder : IO Unit := do
  let (_, p) := (← sources)[0]!
  let unknown := fromHex "00000000" ++ p.extract 4 77
  check "slip132 check-order source length" (unknown.size == 77)
  let encoded := Base58.base58CheckEncode unknown
  checks "slip132 check-order" 2 #[
    ("length before version", convert encoded .xpub == .error (.wrongLength 77)),
    ("checksum before length and version", convert (badChecksum encoded) .xpub ==
      .error (.base58 .checksumMismatch))]

def run (selection : Option String := none) : IO Unit := do
  match selection with
  | none =>
    vectors; conversions; roundtrips; goldens; unknownVersions
    lengths; shortPayloads; base58Errors; checkOrder
  | some "vectors" => vectors
  | some "conversions" => conversions
  | some "roundtrips" => roundtrips
  | some "goldens" => goldens
  | some "unknown-version" => unknownVersions
  | some "wrong-length" => lengths
  | some "short-payload" => shortPayloads
  | some "base58check" => base58Errors
  | some "check-order" => checkOrder
  | some _ => throw <| IO.userError "unknown slip132 test selection"

end BitcoinTests.Slip132Tests
