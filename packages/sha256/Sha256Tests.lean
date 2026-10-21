/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Sha256
import Sha256Tests.AxiomGate

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

-- Test-only decoding; the library's copied Hex module is not used here.
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
        else if n ≥ 65 && n ≤ 70 then pure (n - 55)
        else throw <| IO.userError s!"invalid hex: {c}"
      byte := byte * 16 + digit
    result := result.push byte.toUInt8
  return result

private structure VectorCase where
  name : String
  message : ByteArray
  digest : ByteArray

-- Len is authoritative, including the zero-length record's Msg = 00 marker.
-- Field ordering and final state are checked so truncated records cannot vanish.
private def parseRsp (text : String) : IO (Array VectorCase) := do
  let mut cases := #[]
  let mut length : Option Nat := none
  let mut message : Option ByteArray := none
  for raw in text.splitOn "\n" do
    let line := raw.trimAscii.toString
    if line.isEmpty || line.startsWith "#" || line == "[L = 32]" then continue
    let [key, value] := line.splitOn "="
      | throw <| IO.userError s!"invalid RSP line: {line}"
    let key := key.trimAscii.toString
    let value := value.trimAscii.toString
    match key with
    | "Len" =>
      check "RSP Len ordering" (length.isNone && message.isNone)
      let some n := value.toNat? | throw <| IO.userError "invalid RSP Len"
      length := some n
    | "Msg" =>
      let some n := length | throw <| IO.userError "RSP Msg without Len"
      check "RSP Msg ordering" message.isNone
      let decoded ← hex value
      if n == 0 then message := some ByteArray.empty
      else
        check s!"RSP Len = 8 * Msg bytes at {n}" (n == 8 * decoded.size)
        message := some decoded
    | "MD" =>
      let some n := length | throw <| IO.userError "RSP MD without Len"
      let some msg := message | throw <| IO.userError "RSP MD without Msg"
      let digest ← hex value
      check "RSP MD length" (digest.size == 32)
      cases := cases.push ⟨s!"Len={n}", msg, digest⟩
      length := none
      message := none
    | _ => throw <| IO.userError s!"unknown RSP field: {key}"
  check "RSP complete final record" (length.isNone && message.isNone)
  return cases

private def runSet (name : String) (expected : Nat) (cases : Array VectorCase)
    (hash : ByteArray → ByteArray) : IO Bool := do
  check s!"{name} loaded count" (cases.size == expected)
  let mut passed := 0
  let mut firstFailure : Option String := none
  for vector in cases do
    let actual := hash vector.message
    if actual.size == 32 && actual == vector.digest then passed := passed + 1
    else if firstFailure.isNone then firstFailure := some vector.name
  IO.println s!"{name}: {passed}/{expected}"
  if let some label := firstFailure then
    IO.eprintln s!"assertion failed: {name} {label} digest"
  return passed == expected

private def fipsCases : IO (Array VectorCase) := do
  -- NIST SHA256.pdf: one- and two-block samples; FIPS 180-2 Appendix B.3.
  -- Published URLs for these expected digests are listed in README's Phase 2 section.
  return #[
    ⟨"abc", "abc".toUTF8,
      ← hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"⟩,
    ⟨"448-bit", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8,
      ← hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"⟩,
    ⟨"million-a", ⟨Array.replicate 1000000 (97 : UInt8)⟩,
      ← hex "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"⟩]

private def genesisCases : IO (Array VectorCase) := do
  -- Bitcoin Core v28.0 src/kernel/chainparams.cpp, mainnet genesis fields.
  -- Conventional display hash is reversed to compare raw digest byte order.
  let header ← hex ("01000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" ++
    "29ab5f49ffff001d1dac2b7c")
  check "genesis header length" (header.size == 80)
  let displayed ← hex "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  return #[⟨"genesis", header, displayed.data.toList.reverse.toByteArray⟩]

def main : IO Unit := do
  IO.println s!"SHA-256 axiom gate: {Sha256Tests.auditedTheoremCount} library theorems; 10 named; 0 offenders"
  let fips ← runSet "FIPS examples" 3 (← fipsCases) Sha256.hash
  let short ← runSet "CAVP ShortMsg" 65
    (← parseRsp (← IO.FS.readFile "testdata/SHA256ShortMsg.rsp")) Sha256.hash
  let long ← runSet "CAVP LongMsg" 64
    (← parseRsp (← IO.FS.readFile "testdata/SHA256LongMsg.rsp")) Sha256.hash
  let double ← runSet "SHA-256d" 1 (← genesisCases) Sha256.sha256d
  check "SHA-256 vector suites" (fips && short && long && double)
