/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Secp256k1
import Lean.Data.Json

open Lean

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

private def fromExcept (value : Except String α) : IO α :=
  match value with
  | .ok x => pure x
  | .error e => throw <| IO.userError e

private def hex (s : String) : IO ByteArray := do
  let chars := s.toList.toArray
  check "hex even length" (chars.size % 2 == 0)
  let mut result := ByteArray.empty
  for i in [:chars.size / 2] do
    let mut byte := 0
    for c in [chars[2*i]!, chars[2*i+1]!] do
      let n := c.toNat
      let digit ← if n ≥ 48 && n ≤ 57 then pure (n - 48)
        else if n ≥ 97 && n ≤ 102 then pure (n - 87)
        else throw <| IO.userError s!"invalid hex: {c}"
      byte := byte * 16 + digit
    result := result.push byte.toUInt8
  return result

private def hexString (bytes : ByteArray) : String := Id.run do
  let alphabet := "0123456789abcdef".toList.toArray
  let mut result := ""
  for b in bytes do
    result := result.push alphabet[b.toNat / 16]!
    result := result.push alphabet[b.toNat % 16]!
  return result

private def field (j : Json) (name : String) : IO Json :=
  fromExcept <| j.getObjVal? name

private def str (j : Json) (name : String) : IO String := do
  fromExcept <| (← field j name).getStr?

private def nat (j : Json) (name : String) : IO Nat := do
  fromExcept <| (← field j name).getNat?

private def bytes (j : Json) (name : String) : IO ByteArray := do hex (← str j name)

-- Only the BOLT #11 specification's published example secret is used in tests.
private def exampleSecret : IO ByteArray :=
  hex "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"

private def order : Nat :=
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

private def bigEndian (bytes : ByteArray) : Nat :=
  bytes.foldl (fun n b => n * 256 + b.toNat) 0

private def scalarBytes (n : Nat) : ByteArray := Id.run do
  let mut bytes := ByteArray.empty
  for i in [:32] do
    bytes := bytes.push (n / 256 ^ (31 - i) % 256).toUInt8
  return bytes

private def payee : IO ByteArray :=
  hex "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"

private def negativeTests (vector : Json) (only : Option String) : IO Unit := do
  let hash ← bytes vector "digest"
  let sig ← bytes vector "signature"
  let key ← payee
  let secret ← exampleSecret
  let wrongKey := key.extract 0 32
  let offCurve := (ByteArray.empty.push 2) ++ scalarBytes 0
  let ran ← IO.mkRef 0
  let test := fun name (run : Unit → Bool) => do
    if only.isNone || only == some name then
      ran.modify (· + 1)
      check name (run ())
      IO.println s!"negative {name}: PASS"
  test "tampered signature" fun _ => !Secp256k1.verify hash (sig.set! 0 (sig[0]! ^^^ 1)) key
  test "wrong-length key parse" fun _ => !Secp256k1.isValidPubkey wrongKey
  test "wrong-length key verify" fun _ => !Secp256k1.verify hash sig wrongKey
  test "off-curve key parse" fun _ => !Secp256k1.isValidPubkey offCurve
  test "off-curve key verify" fun _ => !Secp256k1.verify hash sig offCurve
  test "recid 4" fun _ => (Secp256k1.recover hash sig 4).isNone
  test "recid 255" fun _ => (Secp256k1.recover hash sig 255).isNone
  for length in [0, 31, 33] do
    let bad := scalarBytes 0 |>.extract 0 length
    let bad := if length == 33 then bad.push 0 else bad
    test s!"verify hash length {length}" fun _ => !Secp256k1.verify bad sig key
    test s!"recover hash length {length}" fun _ => (Secp256k1.recover bad sig 1).isNone
    test s!"sign hash length {length}" fun _ => (Secp256k1.sign bad secret).isNone
    test s!"sign secret length {length}" fun _ => (Secp256k1.sign hash bad).isNone
  for length in [0, 63, 65] do
    let bad := if length == 65 then sig.push 0 else sig.extract 0 length
    test s!"verify signature length {length}" fun _ => !Secp256k1.verify hash bad key
    test s!"recover signature length {length}" fun _ => (Secp256k1.recover hash bad 1).isNone
  for (name, scalar) in [("zero", 0), ("order", order), ("overflow", 2^256 - 1)] do
    let r := scalarBytes scalar ++ sig.extract 32 64
    let s := sig.extract 0 32 ++ scalarBytes scalar
    test s!"verify r {name}" fun _ => !Secp256k1.verify hash r key
    test s!"verify s {name}" fun _ => !Secp256k1.verify hash s key
    test s!"recover r {name}" fun _ => (Secp256k1.recover hash r 1).isNone
    test s!"recover s {name}" fun _ => (Secp256k1.recover hash s 1).isNone
    test s!"sign secret {name}" fun _ => (Secp256k1.sign hash (scalarBytes scalar)).isNone
  test "invalid prefix parse" fun _ => !Secp256k1.isValidPubkey (key.set! 0 4)
  test "invalid prefix verify" fun _ => !Secp256k1.verify hash sig (key.set! 0 4)
  check "negative selection exists" ((← ran.get) > 0)

private def boltTests (vectors : Array Json) : IO Unit := do
  let key ← payee
  check "BOLT compressed payee parses" (Secp256k1.isValidPubkey key)
  let secret ← exampleSecret
  let highKey ← hex "02d0139ce7427d6dfffd26a326c18be754ef1e64672b42694ba5b23ef6e6e7803d"
  let expectedLines := #[382, 410, 438, 466, 491, 516, 554, 579, 602, 625, 648, 682, 704, 707, 735, 762]
  check "BOLT count" (vectors.size == 16)
  for i in [:vectors.size] do
    let vector := vectors[i]!
    let line ← nat vector "line"
    check s!"BOLT heading {i}" (line == expectedLines[i]!)
    let hash ← bytes vector "digest"
    let sig ← bytes vector "signature"
    let recid := (← nat vector "recid").toUInt8
    check s!"BOLT lengths L{line}" (hash.size == 32 && sig.size == 64 && recid ≤ 3)
    let high := line == 762
    check s!"BOLT high-S L{line}" ((bigEndian (sig.extract 32 64) > order / 2) == high)
    check s!"BOLT recovery L{line}"
      (Secp256k1.recover hash sig recid == some (if high then highKey else key))
    let expected := if high then sig.extract 0 32 ++ scalarBytes (order - bigEndian (sig.extract 32 64))
      else sig
    let some signed := Secp256k1.sign hash secret
      | throw <| IO.userError s!"BOLT signing failed L{line}"
    check s!"BOLT signing bytes L{line}" (signed == expected.push recid)
    check s!"BOLT signing low-S L{line}" (bigEndian (signed.extract 32 64) ≤ order / 2)
    check s!"BOLT sign recover L{line}" (Secp256k1.recover hash (signed.extract 0 64) signed[64]! == some key)
    check s!"BOLT sign verify L{line}" (Secp256k1.verify hash (signed.extract 0 64) key)
    check s!"BOLT verify L{line}" (Secp256k1.verify hash sig key == !high)
  IO.println "bolt11 recovery: 16/16"
  IO.println "bolt11 signing: 16/16"

private def requiredEnv (name : String) : IO String := do
  let some value ← IO.getEnv name | throw <| IO.userError s!"missing required environment variable: {name}"
  return value

private def compressionChecks (key : ByteArray) (only : Option String := none) : IO Nat := do
  let parity := key[64]! % 2
  let compressed := (ByteArray.empty.push (2 + parity)) ++ key.extract 1 33
  let matching := key.set! 0 (6 + parity)
  let mismatched := key.set! 0 (7 - parity)
  let mut ran := 0
  let tests : Array (String × Bool) := #[
    ("uncompressed", Secp256k1.compressPubkey key == some compressed),
    ("matching hybrid", Secp256k1.compressPubkey matching == some compressed),
    ("mismatched hybrid", (Secp256k1.compressPubkey mismatched).isNone),
    ("strict matching hybrid", !Secp256k1.isValidPubkey matching),
    ("strict mismatched hybrid", !Secp256k1.isValidPubkey mismatched),
    ("compressed identity", Secp256k1.compressPubkey compressed == some compressed)]
  let mut cases := tests
  for tag in [4, 6, 7] do
    cases := cases.push (s!"33 prefix {tag}", (Secp256k1.compressPubkey (compressed.set! 0 tag)).isNone)
  for tag in [2, 3] do
    cases := cases.push (s!"65 prefix {tag}", (Secp256k1.compressPubkey (key.set! 0 tag)).isNone)
  for len in [0, 32, 34, 64, 66] do
    let bad := if len == 66 then key.push 0 else key.extract 0 len
    cases := cases.push (s!"length {len}", (Secp256k1.compressPubkey bad).isNone)
  for (name, bad) in [("off-curve compressed", (ByteArray.empty.push 2) ++ scalarBytes 0),
      ("off-curve uncompressed", (ByteArray.empty.push 4) ++ scalarBytes 0 ++ scalarBytes 0)] do
    cases := cases.push (name, (Secp256k1.compressPubkey bad).isNone)
  check "compression cases count" (cases.size == 18)
  for (name, ok) in cases do
    if only.isNone || only == some name then
      check ("compression " ++ name) ok
      ran := ran + 1
  check "compression selection exists" (ran > 0)
  return ran

private def selectedCompression (name : String) : IO Unit := do
  let path ← requiredEnv "WYCHEPROOF_JSON"
  let json ← fromExcept <| Json.parse (← IO.FS.readFile path)
  let groups ← fromExcept <| (← field json "testGroups").getArr?
  let key ← bytes (← field groups[0]! "publicKey") "uncompressed"
  let count ← compressionChecks key (some name)
  check "compression selected count" (count == 1)
  IO.println "compression selected: 1/1"

private def wycheproofTests : IO Unit := do
  let jsonPath ← requiredEnv "WYCHEPROOF_JSON"
  let digestPath ← requiredEnv "WYCHEPROOF_DIGESTS"
  let json ← fromExcept <| Json.parse (← IO.FS.readFile jsonPath)
  check "Wycheproof numberOfTests" ((← nat json "numberOfTests") == 252)
  let groups ← fromExcept <| (← field json "testGroups").getArr?
  check "Wycheproof groups" (groups.size == 108)
  let mut digests : Array (Nat × ByteArray) := #[]
  for line in (← IO.FS.readFile digestPath).splitOn "\n" do
    if line.isEmpty then continue
    let [id, digest] := line.splitOn " " | throw <| IO.userError "malformed digest line"
    let some id := id.toNat? | throw <| IO.userError "invalid digest tcId"
    check s!"duplicate digest {id}" (!(digests.any (·.1 == id)))
    let hash ← hex digest
    check s!"digest length {id}" (hash.size == 32)
    digests := digests.push (id, hash)
  check "Wycheproof digest count" (digests.size == 252)
  let mut ids : Array Nat := #[]
  let mut accepted := 0
  let mut invalid := 0
  let mut high := 0
  let mut short := 0
  let mut compressionCount := 0
  for group in groups do
    check "Wycheproof group type" ((← str group "type") == "EcdsaP1363Verify")
    check "Wycheproof SHA" ((← str group "sha") == "SHA-256")
    let key ← bytes (← field group "publicKey") "uncompressed"
    check "Wycheproof uncompressed key" (key.size == 65 && key[0]! == 4)
    check "Wycheproof key parses" (Secp256k1.isValidPubkey key)
    compressionCount := compressionCount + (← compressionChecks key)
    let tests ← fromExcept <| (← field group "tests").getArr?
    for test in tests do
      let id ← nat test "tcId"
      check s!"duplicate test {id}" (!(ids.contains id))
      ids := ids.push id
      let some (_, hash) := digests.find? (·.1 == id)
        | throw <| IO.userError s!"missing digest tcId {id}"
      let sig ← bytes test "sig"
      let result ← str test "result"
      check s!"Wycheproof result {id}" (result == "valid" || result == "invalid")
      let isHigh := sig.size == 64 && bigEndian (sig.extract 32 64) > order / 2
      let expected := result == "valid" && !isHigh
      let actual := Secp256k1.verify hash sig key
      check s!"Wycheproof tcId {id}" (actual == expected)
      if actual then accepted := accepted + 1
      if result == "invalid" then
        invalid := invalid + 1
        if sig.size != 64 then short := short + 1
      else if isHigh then high := high + 1
      -- Pin strict hybrid rejection for matching and mismatched parity alike.
      for tag in [6, 7] do
        let hybrid := key.set! 0 tag
        check s!"hybrid parse {id}/{tag}" (!Secp256k1.isValidPubkey hybrid)
        check s!"hybrid verify {id}/{tag}" (!Secp256k1.verify hash sig hybrid)
  check "Wycheproof counts" (ids.size == 252 && accepted == 95 && invalid == 85 && high == 72 && short == 18)
  IO.println "Wycheproof: 252 loaded / 95 accepted / 157 rejected"
  IO.println "Wycheproof: 108 groups / 167 valid / 85 invalid / 72 valid high-S / 18 invalid non-64-byte"
  check "compression group total" (compressionCount == 1944)
  IO.println "compression keys: 108/108; compression checks: 1944/1944 (18 per key)"

def main (args : List String) : IO Unit := do
  let vectors ← fromExcept <| (← fromExcept <| Json.parse (← IO.FS.readFile "bolt11.json")).getArr?
  check "BOLT count" (vectors.size == 16)
  match args with
  | ["--negative", name] => negativeTests vectors[0]! (some name); return
  | ["--compression", name] => selectedCompression name; return
  | [] => pure ()
  | _ => throw <| IO.userError "usage: Secp256k1Tests [--negative NAME | --compression NAME]"
  let first := vectors[0]!
  let digest ← bytes first "digest"
  let signature ← bytes first "signature"
  let recid := (← nat first "recid").toUInt8
  let some signed := Secp256k1.sign digest (← exampleSecret)
    | throw <| IO.userError "RFC 6979 preliminary signing failed"
  check "RFC 6979 preliminary byte equality" (signed == signature.push recid)
  IO.println "RFC 6979 preliminary byte equality: PASS"
  let high := vectors[15]!
  let some key := Secp256k1.recover (← bytes high "digest") (← bytes high "signature")
      (← nat high "recid").toUInt8
    | throw <| IO.userError "L762 preliminary recovery failed"
  IO.println s!"L762 preliminary recovered key: {hexString key}"
  negativeTests first none
  boltTests vectors
  wycheproofTests
  IO.println "negative tests: PASS"
