/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Bitcoin.PsbtVectors
import Lean.Data.Json

namespace BitcoinTests.PsbtTests

open Bitcoin Bitcoin.CompactSize Bitcoin.Psbt PsbtVectors

deriving instance BEq for Except

def bytes (xs : List Nat) : ByteArray := ⟨(xs.map UInt8.ofNat).toArray⟩

/-- Synthetic encodings for routing and same-point checks, not curve fixtures. -/
def compressedKey : ByteArray := bytes (2 :: List.replicate 32 17)
def hybridKey : ByteArray := bytes (6 :: (List.replicate 32 17 ++ List.replicate 32 18))

/-- Shape-only stand-in: strict SEC1 lengths/prefixes; compression additionally
accepts parity-matching hybrids and retains x. It makes no on-curve claim. -/
def testCapability : PubkeyCapability where
  isValidPubkey key :=
    (key.size == 33 && (key[0]! == 2 || key[0]! == 3)) ||
    (key.size == 65 && key[0]! == 4)
  compressPubkey key :=
    if key.size == 33 && (key[0]! == 2 || key[0]! == 3) then some key
    else if key.size == 65 &&
        (key[0]! == 4 || key[0]!.toNat == 6 + key[64]!.toNat % 2) then
      some ((bytes [2 + key[64]!.toNat % 2]) ++ key.extract 1 33)
    else none

/-- Distinct, input-sensitive 20-byte stand-ins, available to later tests. -/
def testHashes : PreimageHashes where
  ripemd160 value := (Sha256.hash ((bytes [160]) ++ value)).extract 0 20
  hash160 value := (Sha256.hash ((bytes [192]) ++ value)).extract 0 20

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

private def getOk {ε α : Type} [Repr ε] (name : String) (x : Except ε α) : IO α :=
  match x with
  | .ok a => pure a
  | .error e => throw <| IO.userError s!"assertion failed: {name}: {repr e}"

def hex (s : String) : ByteArray := (Bitcoin.Hex.decode s).getD ByteArray.empty

private def parse := Psbt.parse testCapability testHashes
private def decode := Psbt.decode testCapability testHashes
private def parseText := Psbt.parseBase64 testCapability testHashes

private def roundTrip (name : String) (raw : String) (encoded : String) : IO Unit := do
  let p ← getOk (name ++ " parse") (parse (hex raw))
  check (name ++ " serialize") (p.serialize == hex raw)
  check (name ++ " base64 encode") (p.toBase64 == encoded)
  check (name ++ " base64 parse") (parseText encoded == .ok p)

private def invalidSet (name : String) (count : Nat) (vs : List (String × String × String)) : IO Unit := do
  check (name ++ " count") (vs.length == count)
  for i in [:vs.length] do
    let (_, raw, encoded) := vs[i]!
    check s!"{name} hex {i}" (!(parse (hex raw)).isOk)
    check s!"{name} base64 {i}" (!(parseText encoded).isOk)
  IO.println s!"{name}: {vs.length}/{count}"

private def validSet (name : String) (count : Nat) (vs : List (String × String × String)) : IO Unit := do
  check (name ++ " count") (vs.length == count)
  for i in [:vs.length] do
    let (_, raw, encoded) := vs[i]!
    roundTrip s!"{name} {i}" raw encoded
  IO.println s!"{name}: {vs.length}/{count}"

private def roles : IO Unit := do
  check "BIP174 roles count" (bip174Roles.length == 14)
  for i in [:bip174Roles.length] do
    let (_, raw, encoded) := bip174Roles[i]!
    if i == 7 then check "BIP174 roles network magic" (parse (hex raw) == .error .magic)
    else roundTrip s!"BIP174 roles {i}" raw encoded
  IO.println "BIP174 roles: 14/14"

private def locktimes : IO Unit := do
  check "BIP370 locktimes count" (bip370Locktimes.length == 10)
  for i in [:bip370Locktimes.length] do
    let (_, raw, encoded, expected) := bip370Locktimes[i]!
    let p ← getOk s!"locktime parse {i}" (parse (hex raw))
    let d ← getOk s!"locktime decode {i}" (decode p)
    check s!"locktime determine {i}"
      ((determineLocktime d.global.fallbackLocktime d.inputs).map UInt32.toNat == expected)
    check s!"locktime base64 {i}" (Base64.decode encoded == some (hex raw))
    match d.unsignedTransaction, expected with
    | .ok tx, some n => check s!"locktime transaction {i}" (tx.locktime.toNat == n)
    | .error e, none =>
      check s!"locktime incompatible {i}"
        (e == .invalidUnsignedTransaction "incompatible input locktimes")
    | _, _ => check s!"locktime transaction {i}" false
  IO.println "BIP370 locktimes: 10/10"

private def exactError (vs : List (String × String × String)) (i : Nat) (expected : PsbtError) : Bool :=
  match parse (hex vs[i]!.2.1) with
  | .error e => e == expected
  | .ok _ => false

private def base : IO Psbt := getOk "synthetic base" (parse (hex bip174Valid[0]!.2.1))

private def withInput (p : Psbt) (rs : List Record) : Psbt :=
  { p with inputs := [rs] }

private def bip32 (output : Bool) (key : ByteArray) : Record :=
  { key := recordKey (if output then KeyType.outBip32Derivation else KeyType.inBip32Derivation) key
    value := bytes [0, 0, 0, 0] }

private def withKeys (p : Psbt) (output : Bool) (keys : List ByteArray) : Psbt :=
  if output then { p with inputs := [[]], outputs := [keys.map (bip32 true), []] }
  else { p with inputs := [keys.map (bip32 false)] }

private def preimage (kind : Nat) (hash : ByteArray → ByteArray) : IO Unit := do
  let p ← base
  let value := bytes [0, 1, 2, 3]
  let digest := hash value
  let key := recordKey kind digest
  let good := withInput p [{ key, value }]
  check s!"preimage {kind} accepted" ((parse good.serialize).isOk)
  let bad := withInput p [{ key, value := value.set! 0 1 }]
  check s!"preimage {kind} mismatch"
    (parse bad.serialize == .error (.invalidValue "input" kind "preimage does not match hash"))
  IO.println s!"preimage {kind}: 2/2"

private def hybrid (output : Bool) : IO Unit := do
  let p := withKeys (← base) output [hybridKey]
  let parsed ← getOk "hybrid parse" (parse p.serialize)
  check s!"hybrid {output} raw serialization" (parsed.serialize == p.serialize)
  let d ← getOk "hybrid decode" (decode parsed)
  let keys := if output then d.outputs[0]!.bip32Derivation else d.inputs[0]!.bip32Derivation
  check s!"hybrid {output} raw decoded" (keys.map (·.1) == [hybridKey])
  IO.println s!"hybrid {output}: 2/2"

private def samePoint (output : Bool) (keys : List ByteArray) (collision : Bool) : IO Unit := do
  let p := withKeys (← base) output keys
  let parsed ← getOk "same point parse remains separate" (parse p.serialize)
  let expected := if collision then
    .error (.duplicateBip32Point (if output then "output" else "input") hybridKey compressedKey)
    else .ok ()
  check s!"same point {output}/{keys.length}" (parsed.checkBip32SamePoint testCapability == expected)
  IO.println s!"same point {output}/{keys.length}: 1/1"

private def samePointSeparate (output : Bool) : IO Unit := do
  let p ← base
  let p ← if output then
      pure { p with inputs := [[]], outputs := [[bip32 true hybridKey], [bip32 true compressedKey]] }
    else do
      -- Use a published two-input transaction so framing also remains valid.
      let two ← getOk "two input base" (parse (hex bip174Valid[1]!.2.1))
      pure { two with inputs := [[bip32 false hybridKey], [bip32 false compressedKey]] }
  let parsed ← getOk "separate maps parse" (parse p.serialize)
  check s!"same point separate {output}" (parsed.checkBip32SamePoint testCapability == .ok ())
  IO.println s!"same point separate {output}: 1/1"

/-- Test inventory reader preserves duplicate records in published invalid maps.
Production `decodeMap` correctly rejects these before typed decoding. -/
private def rawMap : Nat → List UInt8 → Except DecodeError (KeyValueMap × List UInt8)
  | 0, _ => .error .truncated
  | fuel + 1, data => do
    let (key, rest) ← readByteVector data
    if key.size == 0 then return ([], rest)
    let (value, rest) ← readByteVector rest
    let (map, rest) ← rawMap fuel rest
    return ({ key, value } :: map, rest)

private def vectorSet (name : String) : List (String × String × String) :=
  match name with
  | "bip174Invalid" => bip174Invalid
  | "bip174Valid" => bip174Valid
  | "bip174SignerFailures" => bip174SignerFailures
  | "bip174Roles" => bip174Roles
  | "bip370Invalid" => bip370Invalid
  | "bip370Valid" => bip370Valid
  | "bip371Invalid" => bip371Invalid
  | "bip371Valid" => bip371Valid
  | "bip370Locktimes" => bip370Locktimes.map fun (a, b, c, _) => (a, b, c)
  | _ => []

private def jsonNat (row : Lean.Json) (field : String) : IO Nat :=
  getOk ("inventory " ++ field) (row.getObjValAs? Nat field)

private def jsonText (row : Lean.Json) (field : String) : IO String :=
  getOk ("inventory " ++ field) (row.getObjValAs? String field)

private def malformedTransaction (index : Nat) (error : DecodeError) : IO Unit := do
  let raw := hex bip174Invalid[index]!.2.1
  let (global, _) ← getOk "malformed global map" (rawMap (raw.size + 1) (raw.data.toList.drop 5))
  check s!"malformed transaction {index}" (match parseTransaction global[0]!.value false with
    | .error e => e == error
    | .ok _ => false)

private def transactions : IO Unit := do
  let data ← getOk "inventory JSON" (Lean.Json.parse (← IO.FS.readFile "test-data/psbt-inventory.json"))
  let rows ← getOk "inventory rows" (data.getObjValAs? (Array Lean.Json) "transactions")
  check "wire transactions count" (rows.size == 136)
  let mut txidCount := 0
  let mut matchingCount := 0
  for row in rows do
    let name ← jsonText row "vector"
    let index ← jsonNat row "index"
    let scope ← jsonText row "scope"
    let label := s!"wire {name}[{index}] {scope}"
    let raw := hex (vectorSet name)[index]!.2.1
    let allowWitness ← getOk label (row.getObjValAs? Bool "allowWitness")
    let (value, global, input) ← if scope == "network" then pure (raw, [], []) else do
      let (global, rest) ← getOk label (rawMap (raw.size + 1) (raw.data.toList.drop 5))
      let record ← jsonNat row "record"
      if scope == "global" then pure (global[record]!.value, global, []) else do
        let mapIndex ← jsonNat row "map"
        let mut rest := rest
        let mut input : KeyValueMap := []
        for _ in [:mapIndex + 1] do
          let (map, after) ← getOk label (rawMap (raw.size + 1) rest)
          input := map
          rest := after
        pure (input[record]!.value, global, input)
    let tx ← getOk (label ++ " parse") (parseTransaction value allowWitness)
    check (label ++ " roundtrip") (serializeWitnessTransaction tx.transaction tx.witnesses == value)
    if scope == "input" then
      let mapIndex ← jsonNat row "map"
      let expected ← match global.find? (fun record => record.key[0]! == 0) with
        | some record => do
          if name == "bip174Invalid" && index == 18 then
            -- Read just the input vector after version/marker/flag. The full
            -- published transaction is invalid (superfluous witness); it is
            -- explicitly rejected below, never treated as a successful parse.
            let (count, rest) ← getOk label (readCompactSize (record.value.data.toList.drop 6))
            let (inputs, _) ← getOk label (readMany readTxInput count rest)
            pure (some inputs[mapIndex]!.previousOutput.txid)
          else
            let unsigned ← getOk label (parseTransaction record.value false)
            pure (some unsigned.transaction.inputs[mapIndex]!.previousOutput.txid)
        | none => pure (KeyValueMap.lookup input (bytes [14]))
      let pinned ← getOk label (row.getObjValAs? Bool "txidMatches")
      let equal := some tx.transaction.txid == expected
      check (label ++ " txid") (equal == pinned)
      txidCount := txidCount + 1
      if equal then matchingCount := matchingCount + 1
  check "non-witness txids count" (txidCount == 60)
  check "non-witness txids matching count" (matchingCount == 56)
  IO.println "wire transactions: 136/136; non-witness txids: 60/60 (56 matching, 4 published invalid exceptions)"
  malformedTransaction 18 .truncated
  malformedTransaction 19 .trailingData
  IO.println "published malformed transactions: 2/2"

def run (only : Option String := none) : IO Unit := do
  let mut ran := 0
  let perform := fun name (action : IO Unit) => do
    if only.isNone || only == some name then action; pure true else pure false
  let actions : List (String × IO Unit) := [
    ("BIP174 invalid", invalidSet "BIP174 invalid" 20 bip174Invalid),
    ("BIP370 invalid", invalidSet "BIP370 invalid" 24 bip370Invalid),
    ("BIP371 invalid", invalidSet "BIP371 invalid" 11 bip371Invalid),
    ("BIP174 valid", validSet "BIP174 valid" 10 bip174Valid),
    ("BIP174 signer failures", validSet "BIP174 signer failures" 4 bip174SignerFailures),
    ("BIP370 valid", validSet "BIP370 valid" 14 bip370Valid),
    ("BIP371 valid", validSet "BIP371 valid" 6 bip371Valid),
    ("BIP174 roles", roles), ("BIP370 locktimes", locktimes),
    ("transactions", transactions),
    ("network magic", check "network magic" (parse (hex bip174Roles[7]!.2.1) == .error .magic)),
    ("base64 syntax", check "base64 syntax" (parseText "?" == .error .base64)),
    ("invalid base64 bytes", do
      for i in [:bip174Invalid.length] do
        check s!"invalid base64 bytes {i}"
          (Base64.decode bip174Invalid[i]!.2.2 == some (hex bip174Invalid[i]!.2.1))
      IO.println "invalid base64 bytes: 20/20"),
    ("exact duplicate", check "exact duplicate" (exactError bip174Invalid 4 (.duplicateKey (hex "00")))),
    ("exact unsigned", check "exact unsigned" (exactError bip174Invalid 2
      (.invalidUnsignedTransaction "scriptSig must be empty"))),
    ("exact excluded", check "exact excluded" (exactError bip370Invalid 0 (.excludedField "global" 0))),
    ("exact missing", check "exact missing" (exactError bip370Invalid 14 (.missingField "global" 4))),
    ("exact signature", check "exact signature" (exactError bip371Invalid 1
      (.invalidValue "input" 19 "signature must be 64 or 65 bytes"))),
    ("exact control", check "exact control" (exactError bip371Invalid 9
      (.invalidKey "input" 21 "invalid control block size"))),
    ("sighash extra", check "sighash extra"
      (!(decodeInput testCapability testHashes 0 [⟨hex "0300", hex "01000000"⟩]).isOk)),
    ("sighash valid", check "sighash valid"
      ((decodeInput testCapability testHashes 0 [⟨hex "03", hex "01000000"⟩]).isOk)),
    ("map noncanonical", check "map noncanonical" (!(decodeMap [0xfd, 1, 0, 0, 0]).isOk)),
    ("map canonical", check "map canonical" (match decodeMap [1, 0, 0, 0] with
      | .ok (map, rest) => map == [⟨hex "00", ByteArray.empty⟩] && rest.isEmpty
      | .error _ => false)),
    ("key source", do
      let source : KeySource := { fingerprint := bytes [222, 173, 190, 239], path := [44, 0x80000000, 1] }
      check "key source" (decodeKeySource "input" 6 (encodeKeySource source) == .ok source)),
    ("tap key source", do
      let source : TapKeySource := {
        leafHashes := [bytes (List.replicate 32 17), bytes (List.replicate 32 34)]
        source := { fingerprint := bytes [222, 173, 190, 239], path := [44, 0x80000000, 1] } }
      check "tap key source" (decodeTapKeySource "input" 22 (encodeTapKeySource source) == .ok source)),
    ("tap tree", do
      let tree : List TapTreeLeaf := [{ depth := 0, leafVersion := 192, script := bytes [81] }]
      check "tap tree" (decodeTapTree (encodeTapTree tree) == .ok tree)),
    ("SHA256 preimage", preimage 11 Sha256.hash),
    ("HASH256 preimage", preimage 13 Sha256.sha256d),
    ("RIPEMD160 preimage", preimage 10 testHashes.ripemd160),
    ("HASH160 preimage", preimage 12 testHashes.hash160),
    ("hybrid input", hybrid false), ("hybrid output", hybrid true),
    ("hybrid partial", do
      let p := withInput (← base) [{ key := recordKey 2 hybridKey, value := bytes [48] }]
      check "hybrid partial rejected" (parse p.serialize == .error (.invalidKey "input" 2 "invalid public key"))),
    ("same input collision", samePoint false [hybridKey, compressedKey] true),
    ("same output collision", samePoint true [hybridKey, compressedKey] true),
    ("same input hybrid alone", samePoint false [hybridKey] false),
    ("same input compressed alone", samePoint false [compressedKey] false),
    ("same output hybrid alone", samePoint true [hybridKey] false),
    ("same output compressed alone", samePoint true [compressedKey] false),
    ("same input separate", samePointSeparate false), ("same output separate", samePointSeparate true),
    ("same invalid", do
      let p := withKeys (← base) false [bytes [2]]
      check "same invalid" (p.checkBip32SamePoint testCapability == .error (.invalidKey "input" 6 "invalid public key"))),
    ("same malformed", do
      let p := withInput (← base) [{ key := bytes [253], value := ByteArray.empty }]
      check "same malformed" (p.checkBip32SamePoint testCapability == .error (.decode .truncated))),
    ("same ignores partial", do
      let p := withInput (← base) ([hybridKey, compressedKey].map fun key =>
        { key := recordKey KeyType.inPartialSig key, value := bytes [48] })
      check "same ignores partial" (p.checkBip32SamePoint testCapability == .ok ())),
    ("same ignores global", do
      let p ← base
      let p := { p with global := [bip32 false hybridKey, bip32 false compressedKey] }
      check "same ignores global" (p.checkBip32SamePoint testCapability == .ok ())),
    ("trailing data", do
      let p ← base
      check "PSBT trailing data" (parse (p.serialize.push 0) == .error .trailingData)),
    ("surplus witness", do
      let unsigned ← match KeyValueMap.lookup (← base).global (bytes [0]) with
        | some value => getOk "surplus witness unsigned" (parseTransaction value false)
        | none => throw <| IO.userError "assertion failed: surplus witness unsigned"
      let tx := unsigned.transaction
      let witnesses := tx.inputs.toList.map (fun _ => []) ++ [[bytes [1]]]
      check "surplus witness legacy"
        (serializeWitnessTransaction tx witnesses == serializeTransaction tx))]
  let selectable := actions ++ [
    ("malformed transaction 18", malformedTransaction 18 .truncated),
    ("malformed transaction 19", malformedTransaction 19 .trailingData)]
  for (name, action) in (if only.isSome then selectable else actions) do
    if ← perform name action then ran := ran + 1
  check "PSBT selected check exists" (ran > 0)
  IO.println s!"PSBT checks: {ran}/{if only.isSome then 1 else actions.length}"

end BitcoinTests.PsbtTests
