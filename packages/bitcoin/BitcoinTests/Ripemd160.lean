/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Bitcoin.AddressVectors
import Lean.Data.Json

namespace BitcoinTests.Ripemd160Tests

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

private def getOk {α : Type} (name : String) (value : Except String α) : IO α :=
  match value with
  | .ok result => pure result
  | .error error => throw <| IO.userError s!"assertion failed: {name}: {error}"

def vectors : IO Unit := do
  let fixture ← getOk "RIPEMD-160 fixture" (Lean.Json.parse (← IO.FS.readFile "test-data/ripemd160.json"))
  let rows ← getOk "RIPEMD-160 rows" (fixture.getObjValAs? (Array Lean.Json) "vectors")
  check "RIPEMD-160 vectors count" (rows.size == 9)
  for i in [:rows.size] do
    let message ← getOk "RIPEMD-160 message" (rows[i]!.getObjValAs? String "message")
    let repetitions ← getOk "RIPEMD-160 repeat" (rows[i]!.getObjValAs? Nat "repeat")
    let expected ← getOk "RIPEMD-160 digest" (rows[i]!.getObjValAs? String "digest")
    let mut input := ByteArray.empty
    for _ in [:repetitions] do input := input ++ message.toUTF8
    let digest := Bitcoin.ripemd160 input
    check s!"RIPEMD-160 vectors {i} digest" (Bitcoin.Hex.encode digest == expected)
    check s!"RIPEMD-160 vectors {i} length" (digest.size == 20)
  IO.println s!"RIPEMD-160 vectors: {rows.size}/9"

-- Extracted from https://github.com/bitcoin/bips @ 130b8e0fa7f30fa45532f080b87b8db27a79e46e, bip-0173.mediawiki L60-61; BSD-2-Clause, see Bitcoin/LICENSE-bips; public generator, reformatted.
private def bip173PublicKey : String :=
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

def bip173 : IO Unit := do
  let cases : List String := [bip173PublicKey]
  check "HASH160 BIP173 count" (cases.length == 1)
  let script := (Bitcoin.Hex.decode AddressVectors.bip350Valid[0]!.2).getD ByteArray.empty
  for key in cases do
    let publicKey := (Bitcoin.Hex.decode key).getD ByteArray.empty
    check "HASH160 BIP173 digest" (Bitcoin.hash160 publicKey == script.extract 2 22)
  IO.println s!"HASH160 BIP173: {cases.length}/1"

def run (selection : Option String := none) : IO Unit := do
  match selection with
  | none => vectors; bip173
  | some "vectors" => vectors
  | some "bip173" => bip173
  | some _ => throw <| IO.userError "unknown hash test selection"

end BitcoinTests.Ripemd160Tests
