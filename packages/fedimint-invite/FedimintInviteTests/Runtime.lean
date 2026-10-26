/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInvite.Codec
import Lean

namespace FedimintInviteTests
open Lean FedimintInvite

private instance {ε α : Type} [BEq ε] [BEq α] : BEq (Except ε α) where
  beq a b := match a, b with
    | .ok x, .ok y => x == y
    | .error x, .error y => x == y
    | _, _ => false

private def field (j : Json) (key : String) : IO Json :=
  IO.ofExcept (j.getObjVal? key)

private def string (j : Json) : IO String := IO.ofExcept j.getStr?
private def nat (j : Json) : IO Nat := IO.ofExcept j.getNat?

private def check (label : String) (condition : Bool) : IO Unit :=
  unless condition do throw (IO.userError ("assertion failed: " ++ label))

private def bytes (hex : String) : IO ByteArray :=
  match Bitcoin.Hex.decode hex with
  | some b => pure b
  | none => throw (IO.userError "invalid fixture hex")

private def inviteOfJson (j : Json) : IO Invite := do
  let id ← string (← field j "federation_id")
  let gs ← IO.ofExcept (← field j "guardians").getArr?
  let guardians ← gs.toList.mapM fun g => do
    let peer ← nat (← field g "peer_id")
    check "fixture peer bound" (peer < 65536)
    return (⟨UInt16.ofNat peer, ← string (← field g "url")⟩ : Guardian)
  let secret ← field j "api_secret"
  let apiSecret ← if secret == .null then pure none else some <$> string secret
  return ⟨id, guardians, apiSecret⟩

private def errorJson (e : Error) : Json :=
  let (kind, details) : String × List Json := match e with
    | .truncatedBigSize w a => ("truncatedBigSize", [toJson w, toJson a])
    | .unexpectedPart n => ("unexpectedPart", [toJson n])
    | .overrun f n a => ("overrun", [toJson (match f with
        | .url => "url" | .secret => "secret" | .federation => "federation"), toJson n, toJson a])
    | .invalidUtf8 f => ("invalidUtf8", [toJson (if f == .url then "url" else "secret")])
    | .federationLength n => ("federationLength", [toJson n])
    | .guardianLength n c => ("guardianLength", [toJson n, toJson c])
    | .missingFederation => ("missingFederation", [])
    | .noGuardian => ("noGuardian", [])
    | .invalidHex => ("invalidHex", [])
    | .tooLong n => ("tooLong", [toJson n])
    | .prefix => ("prefix", [])
    | .wrongHrp hrp => ("wrongHrp", [toJson hrp])
    | .wrongVariant => ("wrongVariant", [])
    | .bech32 e => ("bech32." ++ (match e with
        | .tooLong => "tooLong" | .mixedCase => "mixedCase"
        | .missingSeparator => "missingSeparator" | .emptyHrp => "emptyHrp"
        | .hrpTooLong => "hrpTooLong" | .invalidHrp => "invalidHrp"
        | .invalidCharacter => "invalidCharacter" | .shortChecksum => "shortChecksum"
        | .checksumMismatch => "checksumMismatch"), [])
  Json.mkObj [("error", toJson kind), ("details", toJson details)]

private def checkDecoded (label : String) (result : Except Error Invite) (expected : Json) : IO Unit := do
  match result with
  | .ok actual =>
    match expected.getObjVal? "ok" with
    | .ok value => check label (actual == (← inviteOfJson value))
    | .error _ =>
      IO.println ("unexpected success: " ++ label)
      check label false
  | .error e =>
    if errorJson e != expected then IO.println s!"actual error: {repr e}"
    check label (errorJson e == expected)

private def readJson (path : String) : IO Json := do
  IO.ofExcept (Json.parse (← IO.FS.readFile path))

/-- Raw consensus decoding is not restricted to the string wrapper's size. -/
private def largeConsensus (descending : Bool) : IO Unit := do
  let count := 60000
  let ordered := (List.range count).map fun peer => (⟨UInt16.ofNat peer, ""⟩ : Guardian)
  let inv : Invite := ⟨String.ofList (List.replicate 64 '0'),
    if descending then ordered.reverse else ordered, none⟩
  let label := if descending then "large/descending" else "large/ascending"
  let encoded ← IO.ofExcept ((encodeConsensus inv).mapError (fun e => reprStr e))
  let start ← IO.monoMsNow
  let decoded := decodeConsensus encoded
  check (label ++ " exact fields") (decoded == .ok { inv with guardians := ordered })
  let elapsed ← IO.monoMsNow
  IO.println s!"{label}: {count} guardians; {encoded.size} bytes; {elapsed - start} ms"
  check (label ++ " processing budget") (elapsed - start < 5000)

private def runRow (row : Json) : IO Unit := do
  let label := (← string (← field row "group")) ++ "/" ++ (← string (← field row "name"))
  let op ← string (← field row "op")
  let input ← field row "input"
  let expected ← field row "expected"
  match op with
  | "consensus" => checkDecoded label (decodeConsensus (← bytes (← string input))) expected
  | "decode" => checkDecoded label (decode (← string input)) expected
  | "bigsize" =>
    let value ← nat input
    let hx ← string (← field expected "hex")
    let consumed ← nat (← field expected "consumed")
    check (label ++ " writer bytes") (writeBigSize value == (← bytes hx).data.toList)
    let encoded := (← bytes hx).data.toList
    check (label ++ " reader and consumed")
      (readBigSize (encoded ++ [42]) == .ok (value, [42]) && encoded.length == consumed)
  | "read-bigsize" =>
    let b := (← bytes (← string input)).data.toList
    check label (readBigSize (b ++ [42]) == .ok (← nat (← field expected "value"), [42]) &&
      b.length == (← nat (← field expected "consumed")))
  | "encode-error" =>
    match encodeConsensus (← inviteOfJson input) with
    | .error e => check label (errorJson e == expected)
    | .ok _ => check label false
  | "encode" =>
    let inv ← inviteOfJson input
    let expectedBytes ← bytes (← string (← field expected "hex"))
    check (label ++ " consensus bytes") (encodeConsensus inv == .ok expectedBytes)
    check (label ++ " string") (encode inv == .ok (← string (← field expected "string")))
    checkDecoded (label ++ " decoded fields")
      (decode (← string (← field expected "string"))) (← field expected "decoded")
  | "boundary" =>
    let inv ← inviteOfJson input
    let b ← bytes (← string (← field expected "hex"))
    let s ← string (← field expected "string")
    let size ← nat (← field expected "byte_length")
    let length ← nat (← field expected "string_length")
    check (label ++ " byte count") (b.size == size)
    check (label ++ " string count") (s.length == length)
    check (label ++ " same consensus bytes") (encodeConsensus inv == .ok b)
    check (label ++ " independent checksum")
      (Bitcoin.Bech32.decode 1024 s == .ok ("fed1", Bitcoin.Bech32.convertbits8to5 b, .bech32m))
    if size == 632 then
      check (label ++ " encode") (encode inv == .ok s)
      check (label ++ " decode") (decode s == .ok inv)
    else
      check (label ++ " encode cap") (encode inv == .error (.tooLong 1024))
      check (label ++ " decode cap") (decode s == .error (.bech32 .tooLong))
  | _ => throw (IO.userError ("unknown test operation " ++ op))

def run (args : List String) : IO UInt32 := do
  if args == ["--case", "large/ascending"] then
    largeConsensus false
    return 0
  if args == ["--case", "large/descending"] then
    largeConsensus true
    return 0
  let selection := match args with | ["--case", name] => some name | _ => none
  let primary ← IO.ofExcept (← readJson "test-data/primary.json").getArr?
  check "primary collection count" (primary.size == 3)
  if selection.isNone then
    for row in primary do
      let s ← string (← field row "encoded")
      let inv ← inviteOfJson (← field row "decoded")
      check "primary exact decoded fields" (decode s == .ok inv)
      check "primary exact encoded string" (encode inv == .ok s)
    IO.println "primary vectors: 3/3"
  let fixture ← readJson "test-data/synthetic.json"
  let rows ← IO.ofExcept (← field fixture "rows").getArr?
  check "synthetic total count" (rows.size == 82)
  let counts : List (String × Nat) := [("bigsize", 12), ("bigsize-truncated", 14),
    ("bigsize-lax", 3), ("lax", 4), ("parts", 8), ("errors", 13), ("encoding", 13),
    ("normalization", 2), ("wrapper", 9), ("padding", 2), ("boundaries", 2)]
  let mut executed := 0
  for (group, count) in counts do
    let mut loaded := 0
    for row in rows do
      if (← string (← field row "group")) == group then
        loaded := loaded + 1
        let label := group ++ "/" ++ (← string (← field row "name"))
        if selection.isNone || selection == some label then
          runRow row
          executed := executed + 1
    check (group ++ " collection count") (loaded == count)
    check (group ++ " manifest count") ((← nat (← field (← field fixture "counts") group)) == count)
    if selection.isNone then IO.println s!"{group}: {loaded}/{count}"
  check "executed count" (executed == if selection.isSome then 1 else 82)
  IO.println s!"runtime assertions: {executed}/{if selection.isSome then 1 else 82}"
  if selection.isNone then
    largeConsensus false
    largeConsensus true
    IO.println "large raw consensus cases: 2/2"
  return 0

end FedimintInviteTests
