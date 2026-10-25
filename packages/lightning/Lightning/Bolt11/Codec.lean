/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Bolt11.Fields
import Sha256

namespace Lightning.Bolt11

/-- SHA-256 of the lower-case, as-written HRP followed by the as-written data,
with zero bits appended to the final byte. Data excludes signature and checksum. -/
def signingHash (hrp : String) (data : List Symbol) : ByteArray :=
  let packed := (Bitcoin.Bech32.fesToBytesLax (data ++ [0, 0])).extract 0
    ((data.length * 5 + 7) / 8)
  Sha256.hash ((Bitcoin.Bech32.lower hrp).toUTF8 ++ packed)

def parseHrp (hrp : String) : Except Error Hrp := do
  if !(hrp.startsWith "ln") || hrp.length ≤ 2 then throw .malformedHrp
  let tail := hrp.toList.drop 2
  let currencyChars := tail.takeWhile fun c => !c.isDigit
  let amountTail := tail.drop currencyChars.length
  let digits := amountTail.takeWhile Char.isDigit
  let suffix := amountTail.drop digits.length
  let multiplier ← match suffix with
    | [] => pure none
    | c :: rest => do
      let m ← match c with
        | 'm' => pure Multiplier.milli | 'u' => pure Multiplier.micro
        | 'n' => pure Multiplier.nano | 'p' => pure Multiplier.pico
        | _ => throw Error.unknownSiPrefix
      if rest ≠ [] then throw .malformedHrp
      pure (some m)
  let currency ← match String.ofList currencyChars with
    | "bc" => pure Currency.bc | "tb" => pure Currency.tb | "bcrt" => pure Currency.bcrt
    | "sb" => pure Currency.sb | "tbs" => pure Currency.tbs | _ => throw Error.unknownCurrency
  let rawAmount ← if digits = [] then pure none else do
    let value := digits.foldl (fun n c => n * 10 + (c.toNat - '0'.toNat)) 0
    if value ≥ 2^64 then throw .invalidAmount
    if let some m := multiplier then
      if value * m.factor ≥ 2^64 then throw .invalidAmount
    pure (some (UInt64.ofNat value))
  return ⟨currency, rawAmount, multiplier⟩

def curveOrder : Nat :=
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def validSignature (signature : ByteArray) : Bool :=
  signature.size == 65 && signature.data[64]?.getD 255 ≤ 3 &&
    readBytes (signature.extract 0 32) < curveOrder &&
    readBytes (signature.extract 32 64) < curveOrder

def checkFieldCounts (fields : List Field) : Except Error Unit := do
  let hashes := fields.countP fun f => match f with | .paymentHash _ => true | _ => false
  if hashes = 0 then throw .noPaymentHash
  if hashes > 1 then throw .multiplePaymentHashes
  let descriptions := fields.countP fun f => match f with
    | .description _ | .descriptionHash _ => true | _ => false
  if descriptions = 0 then throw .noDescription
  if descriptions > 1 then throw .multipleDescriptions
  let secrets := fields.countP fun f => match f with | .paymentSecret _ => true | _ => false
  if secrets = 0 then throw .noPaymentSecret
  if secrets > 1 then throw .multiplePaymentSecrets

def checkFeatures (parts : Parts) : Except Error Unit := do
  let some features := parts.features | throw .invalidFeatures
  if features.requiresUnknown then throw .unknownRequiredFeatures
  if !features.supports 14 then throw .invalidFeatures

def checkPrecision (hrp : Hrp) : Except Error Unit := do
  if let some pico := hrp.picoAmount then
    if pico % 10 ≠ 0 then throw .impreciseAmount

def checkSignature (cap : Curve) (parts : Parts) (hash signature : ByteArray) :
    Except Error ByteArray := do
  let compact := signature.extract 0 64
  if let some key := parts.payeePubkey then
    if cap.verify hash compact key then return key else throw .verifyFailed
  else
    let some key := cap.recover hash compact (signature.data[64]?.getD 255) |
      throw .recoveryFailed
    return key

/-- Decode BOLT11 with a 7089-character limit; semantic checks follow field counts,
features, signature and finally whole-msat precision. -/
def decode (cap : Curve) (text : String) : Except Error Invoice := do
  let (hrpText, data, variant) ← match Bitcoin.Bech32.decode 7089 text with
    | .error .checksumMismatch => throw Error.badChecksum
    | .error reason => throw (Error.bech32 reason)
    | .ok result => pure result
  if variant ≠ .bech32 then throw .badChecksum
  if data.length < 104 then throw .tooShortDataPart
  let hrp ← parseHrp hrpText
  let signed := data.take (data.length - 104)
  if signed.length < 7 then throw .tooShortDataPart
  let fields ← decodeFields cap (signed.drop 7)
  let signature := Bitcoin.Bech32.fesToBytesLax (data.drop (data.length - 104))
  if !validSignature signature then throw .malformedSignature
  let parts : Parts := ⟨hrp, readNat (signed.take 7), fields⟩
  let hash := signingHash (String.ofList (text.toList.take hrpText.length)) signed
  checkFieldCounts fields
  checkFeatures parts
  let key ← checkSignature cap parts hash signature
  checkPrecision hrp
  return { toParts := parts, signature := signature, signingHash := hash, payeeKey := key }

def encodeHrp (hrp : Hrp) : Except EncodeError String := do
  if hrp.rawAmount.isNone && hrp.multiplier.isSome then throw .invalidHrp
  if hrp.rawAmount.isSome && hrp.picoAmount.isNone then throw .amountOverflow
  return "ln" ++ hrp.currency.text ++ (hrp.rawAmount.map (toString ·.toNat)).getD "" ++
    (hrp.multiplier.map Multiplier.text).getD ""

/-- Check the pico-u64 bound, then choose the largest exact unit: no multiplier
first, followed by milli, micro, nano and pico (zero uses no multiplier). -/
def hrpFromMsat (currency : Currency) (amount : Bitcoin.Amount) : Except EncodeError Hrp := do
  let pico := amount.msat * 10
  if pico ≥ 2^64 then throw .amountOverflow
  let choices : List (Option Multiplier × Nat) :=
    [(none, 1000000000000), (some .milli, 1000000000), (some .micro, 1000000),
      (some .nano, 1000), (some .pico, 1)]
  let (multiplier, factor) := (choices.find? fun pair => pico % pair.2 == 0).getD (some .pico, 1)
  return ⟨currency, some (UInt64.ofNat (pico / factor)), multiplier⟩

private def checkEncodeFields (fields : List Field) : Except EncodeError Unit := do
  for field in fields do
    if !validFieldShape field then throw (.invalidField field.tag)
    if (fieldData field).length > 1023 then throw .fieldTooLong

/-- The checks `decode` makes besides the signature, which lightning-invoice 0.34.0's
builder guarantees for every invoice it signs (`src/lib.rs:976-978`). -/
def checkParts (parts : Parts) : Except Error Unit := do
  checkFieldCounts parts.fields
  checkFeatures parts
  checkPrecision parts.hrp

def encodeData (parts : Parts) : Except EncodeError (String × List Symbol) := do
  let hrp ← encodeHrp parts.hrp
  if parts.timestamp ≥ 2^35 then throw .invalidTimestamp
  let timestamp := List.ofFn fun i : Fin 7 =>
    BitVec.ofNat 5 (parts.timestamp / 32^(6 - i.val))
  checkEncodeFields parts.fields
  (checkParts parts).mapError .invalidInvoice
  return (hrp, timestamp ++ encodeFields parts.fields)

/-- Preserve the supplied signature while canonically writing parsed parts. Refuse when
the written data's signing hash differs from the invoice's recorded one (a decoded
leading-zero HRP amount), since the signature would not cover the output; `sign` re-signs. -/
def encode (invoice : Invoice) : Except EncodeError String := do
  let (hrp, data) ← encodeData invoice.toParts
  if !validSignature invoice.signature then throw .malformedSignature
  if signingHash hrp data != invoice.signingHash then throw .signingHashMismatch
  return Bitcoin.Bech32.encode hrp
    (data ++ Bitcoin.Bech32.convertbits8to5 invoice.signature) .bech32

/-- Sign the exact canonical output data through the caller's curve capability. -/
def sign (cap : Curve) (parts : Parts) : Except EncodeError String := do
  let (hrp, data) ← encodeData parts
  let some signature := cap.sign (signingHash hrp data) | throw .signingFailed
  if !validSignature signature then throw .malformedSignature
  return Bitcoin.Bech32.encode hrp (data ++ Bitcoin.Bech32.convertbits8to5 signature) .bech32

end Lightning.Bolt11
