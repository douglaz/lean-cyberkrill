/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Bolt11.Types

namespace Lightning.Bolt11

def readNat (symbols : List Symbol) : Nat :=
  symbols.foldl (fun acc word => acc * 32 + word.toNat) 0

def writeNat (value : Nat) : List Symbol :=
  if value = 0 then [] else writeNat (value / 32) ++ [BitVec.ofNat 5 value]
termination_by value
decreasing_by omega

def readBytes (bytes : ByteArray) : Nat :=
  bytes.data.foldl (fun acc byte => acc * 256 + byte.toNat) 0

def writeBytes (width value : Nat) : ByteArray :=
  ⟨(List.range width |>.map fun i => UInt8.ofNat (value / 256^(width - 1 - i))).toArray⟩

private def strictBytes (tag : Symbol) (data : List Symbol) : Except Error ByteArray :=
  (Bitcoin.Bech32.convertbits5to8 data).mapError fun _ => .nonCanonicalPadding tag

def decodeHop (cap : Curve) (bytes : ByteArray) : Except Error RouteHop := do
  let key := bytes.extract 0 33
  if !cap.isValidPubkey key then throw (.malformedField 3)
  return { nodeId := key
           shortChannelId := UInt64.ofNat (readBytes (bytes.extract 33 41))
           feeBaseMsat := UInt32.ofNat (readBytes (bytes.extract 41 45))
           feeProportionalMillionths := UInt32.ofNat (readBytes (bytes.extract 45 49))
           cltvExpiryDelta := UInt16.ofNat (readBytes (bytes.extract 49 51)) }

def encodeHop (hop : RouteHop) : ByteArray :=
  hop.nodeId ++ writeBytes 8 hop.shortChannelId.toNat ++ writeBytes 4 hop.feeBaseMsat.toNat ++
    writeBytes 4 hop.feeProportionalMillionths.toNat ++ writeBytes 2 hop.cltvExpiryDelta.toNat

private def integer (tag : Symbol) (data : List Symbol) : Except Error UInt64 := do
  if data.head? = some 0 then throw (.leadingZero tag)
  let value := readNat data
  if value ≥ 2^64 then throw (.malformedField tag)
  return UInt64.ofNat value

/-- Decode one field without semantic counts, feature requirements or signatures. -/
def decodeField (cap : Curve) (tag : Symbol) (data : List Symbol) : Except Error Field := do
  match tag.toNat with
  | 1 | 23 | 16 | 19 =>
    let expected := if tag.toNat = 19 then 53 else 52
    if data.length ≠ expected then return .raw tag data
    let bytes ← strictBytes tag data
    match tag.toNat with
    | 1 => return .paymentHash bytes
    | 23 => return .descriptionHash bytes
    | 16 => return .paymentSecret bytes
    | _ =>
      if !cap.isValidPubkey bytes then throw (.malformedField tag)
      return .payeePubkey bytes
  | 13 =>
    let bytes ← strictBytes tag data
    let some text := String.fromUTF8? bytes | throw (.malformedField tag)
    return .description text
  | 27 => return .metadata (← strictBytes tag data)
  | 6 => return .expiry (← integer 6 data)
  | 24 => return .minFinalCltvExpiryDelta (← integer 24 data)
  | 5 =>
    if data.head? = some 0 then throw (.leadingZero 5)
    return .features (readNat data)
  | 9 =>
    let version :: program := data | throw (.malformedField tag)
    if version.toNat > 18 then return .raw tag data
    let bytes ← strictBytes tag program
    if h : version.toNat < 17 then
      if bytes.size < 2 || bytes.size > 40 then throw (.malformedField tag)
      return .fallback (.segwit ⟨version.toNat, h⟩ bytes)
    else
      if bytes.size ≠ 20 then throw (.malformedField tag)
      return .fallback (if version.toNat = 17 then .p2pkh bytes else .p2sh bytes)
  | 3 =>
    let bytes ← strictBytes tag data
    if bytes.size % 51 ≠ 0 then throw (.malformedField tag)
    return .route (← (List.range (bytes.size / 51)).mapM fun i =>
      decodeHop cap (bytes.extract (i * 51) ((i + 1) * 51)))
  | _ => return .raw tag data

/-- Raw field framing and typing only; the curve capability validates typed node ids. -/
def decodeFields (cap : Curve) (symbols : List Symbol) : Except Error (List Field) := do
  match symbols with
  | [] => return []
  | tag :: hi :: lo :: rest =>
    let len := hi.toNat * 32 + lo.toNat
    if rest.length < len then throw .unexpectedEndOfTaggedFields
    let field ← decodeField cap tag (rest.take len)
    return field :: (← decodeFields cap (rest.drop len))
  | _ => throw .unexpectedEndOfTaggedFields
termination_by symbols.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

/-- Canonical field data; raw fields retain their exact symbols. -/
def fieldData : Field → List Symbol
  | .paymentHash b | .descriptionHash b | .paymentSecret b | .payeePubkey b | .metadata b =>
    Bitcoin.Bech32.convertbits8to5 b
  | .description text => Bitcoin.Bech32.convertbits8to5 text.toUTF8
  | .expiry n | .minFinalCltvExpiryDelta n => writeNat n.toNat
  | .features n => writeNat n
  | .fallback (.segwit version program) =>
    BitVec.ofNat 5 version.val :: Bitcoin.Bech32.convertbits8to5 program
  | .fallback (.p2pkh hash) => 17 :: Bitcoin.Bech32.convertbits8to5 hash
  | .fallback (.p2sh hash) => 18 :: Bitcoin.Bech32.convertbits8to5 hash
  | .route hops => Bitcoin.Bech32.convertbits8to5
    (hops.foldl (fun bytes hop => bytes ++ encodeHop hop) ByteArray.empty)
  | .raw _ data => data

def validFieldShape : Field → Bool
  | .paymentHash b | .descriptionHash b | .paymentSecret b => b.size == 32
  | .payeePubkey b => b.size == 33
  | .fallback (.segwit _ b) => 2 ≤ b.size && b.size ≤ 40
  | .fallback (.p2pkh b) | .fallback (.p2sh b) => b.size == 20
  | .route hops => hops.all fun hop => hop.nodeId.size == 33
  | _ => true

/-- Write canonical field data and 10-bit lengths, with raw fields verbatim.
The invoice encoder checks field shapes and length bounds separately. -/
def encodeFields (fields : List Field) : List Symbol :=
  fields.flatMap fun field =>
    let data := fieldData field
    [field.tag, BitVec.ofNat 5 (data.length / 32), BitVec.ofNat 5 data.length] ++ data

end Lightning.Bolt11
