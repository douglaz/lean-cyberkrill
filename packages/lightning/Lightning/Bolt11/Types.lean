/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Address
import Bitcoin.Amount

namespace Lightning.Bolt11

abbrev Symbol := Bitcoin.Bech32.Symbol

/-- Supplied curve operations; the library performs no curve or secret-key operations.
Hashes are 32 bytes, compact signatures 64 bytes, and compressed keys 33 bytes.
Recovery uses the supplied recovery id without normalizing S. Verification requires low-S.
Signing closes over a caller-owned secret and returns 65 bytes, including recovery id.
Point validation must parse the entire compressed key. Failures return none or false. -/
structure Curve where
  recover : ByteArray → ByteArray → UInt8 → Option ByteArray
  verify : ByteArray → ByteArray → ByteArray → Bool
  sign : ByteArray → Option ByteArray
  isValidPubkey : ByteArray → Bool

inductive Currency where
  | bc | tb | bcrt | sb | tbs
  deriving Repr, DecidableEq, BEq

def Currency.text : Currency → String
  | .bc => "bc" | .tb => "tb" | .bcrt => "bcrt" | .sb => "sb" | .tbs => "tbs"

def Currency.network : Currency → Bitcoin.Address.Network
  | .bc => .mainnet | .tb => .testnet | .bcrt => .regtest | .sb => .regtest | .tbs => .signet

inductive Multiplier where
  | milli | micro | nano | pico
  deriving Repr, DecidableEq, BEq

def Multiplier.text : Multiplier → String
  | .milli => "m" | .micro => "u" | .nano => "n" | .pico => "p"

def Multiplier.factor : Multiplier → Nat
  | .milli => 1000000000 | .micro => 1000000 | .nano => 1000 | .pico => 1

structure Hrp where
  currency : Currency
  rawAmount : Option UInt64 := none
  multiplier : Option Multiplier := none
  deriving Repr, DecidableEq, BEq

def Hrp.picoAmount (hrp : Hrp) : Option Nat := do
  let amount ← hrp.rawAmount
  let pico := amount.toNat * (hrp.multiplier.map Multiplier.factor).getD 1000000000000
  if pico < 2^64 then some pico else none

def Hrp.amount (hrp : Hrp) : Option Bitcoin.Amount :=
  hrp.picoAmount.map fun pico => Bitcoin.Amount.ofMsat (pico / 10)

structure RouteHop where
  nodeId : ByteArray
  shortChannelId : UInt64
  feeBaseMsat : UInt32
  feeProportionalMillionths : UInt32
  cltvExpiryDelta : UInt16
  deriving DecidableEq, BEq

inductive Fallback where
  | segwit (version : Fin 17) (program : ByteArray)
  | p2pkh (hash : ByteArray)
  | p2sh (hash : ByteArray)
  deriving DecidableEq, BEq

def Fallback.script : Fallback → ByteArray
  | .segwit version program => Bitcoin.Address.witnessScript version.val program
  | .p2pkh hash => Bitcoin.Address.p2pkhScript hash
  | .p2sh hash => Bitcoin.Address.p2shScript hash

/-- Features as a natural bitset: bit zero is the least significant bit. -/
abbrev Features := Nat

def Features.has (bits : Features) (bit : Nat) : Bool := bits.testBit bit

def Features.requires (bits : Features) (even : Nat) : Bool := bits.has even

def Features.supports (bits : Features) (even : Nat) : Bool :=
  bits.has even || bits.has (even + 1)

def Features.known (bit : Nat) : Bool :=
  [8, 9, 14, 15, 16, 17, 48, 49, 56, 57].contains bit

def Features.unknownBits (bits : Features) : List Nat :=
  (List.range (bits.log2 + 1)).filter fun bit => bits.has bit && !Features.known bit

def Features.optionalBits (bits : Features) : List Nat :=
  (List.range (bits.log2 + 1)).filter fun bit => bit % 2 == 1 && bits.has bit

def Features.requiresUnknown (bits : Features) : Bool :=
  bits.unknownBits.any fun bit => bit % 2 == 0

inductive Field where
  | paymentHash (bytes : ByteArray)
  | description (text : String)
  | descriptionHash (bytes : ByteArray)
  | paymentSecret (bytes : ByteArray)
  | payeePubkey (bytes : ByteArray)
  | expiry (seconds : UInt64)
  | minFinalCltvExpiryDelta (delta : UInt64)
  | features (bits : Features)
  | metadata (bytes : ByteArray)
  | fallback (value : Fallback)
  | route (hops : List RouteHop)
  | raw (tag : Symbol) (data : List Symbol)
  deriving DecidableEq, BEq

def Field.tag : Field → Symbol
  | .paymentHash _ => 1 | .description _ => 13 | .descriptionHash _ => 23
  | .paymentSecret _ => 16 | .payeePubkey _ => 19 | .expiry _ => 6
  | .minFinalCltvExpiryDelta _ => 24 | .features _ => 5 | .metadata _ => 27
  | .fallback _ => 9 | .route _ => 3 | .raw tag _ => tag

inductive Error where
  | bech32 (reason : Bitcoin.Bech32.DecodeError)
  | badChecksum | tooShortDataPart | malformedHrp | unknownSiPrefix | unknownCurrency
  | invalidAmount | unexpectedEndOfTaggedFields
  | malformedField (tag : Symbol)
  | nonCanonicalPadding (tag : Symbol)
  | leadingZero (tag : Symbol)
  | malformedSignature
  | noPaymentHash | multiplePaymentHashes | noDescription | multipleDescriptions
  | noPaymentSecret | multiplePaymentSecrets | invalidFeatures | unknownRequiredFeatures
  | verifyFailed | recoveryFailed | impreciseAmount
  deriving Repr, DecidableEq, BEq

inductive EncodeError where
  | fieldTooLong | amountOverflow | invalidHrp | invalidTimestamp
  | invalidField (tag : Symbol)
  | malformedSignature | signingFailed | signingHashMismatch
  | invalidInvoice (reason : Error)
  deriving Repr, DecidableEq, BEq

structure Parts where
  hrp : Hrp
  timestamp : Nat
  fields : List Field
  deriving DecidableEq, BEq

structure Invoice extends Parts where
  signature : ByteArray
  signingHash : ByteArray
  payeeKey : ByteArray
  deriving DecidableEq, BEq

def Parts.first? {α : Type} (parts : Parts) (get : Field → Option α) : Option α :=
  parts.fields.findSome? get

def Parts.paymentHash (parts : Parts) : Option ByteArray :=
  parts.first? fun f => match f with | .paymentHash b => some b | _ => none
def Parts.paymentSecret (parts : Parts) : Option ByteArray :=
  parts.first? fun f => match f with | .paymentSecret b => some b | _ => none
def Parts.description (parts : Parts) : Option (String ⊕ ByteArray) :=
  parts.first? fun f => match f with
    | .description s => some (.inl s) | .descriptionHash b => some (.inr b) | _ => none
def Parts.payeePubkey (parts : Parts) : Option ByteArray :=
  parts.first? fun f => match f with | .payeePubkey b => some b | _ => none
def Parts.expiry (parts : Parts) : UInt64 :=
  (parts.first? fun f => match f with | .expiry n => some n | _ => none).getD 3600
def Parts.minFinalCltvExpiryDelta (parts : Parts) : UInt64 :=
  (parts.first? fun f => match f with | .minFinalCltvExpiryDelta n => some n | _ => none).getD 18
def Parts.features (parts : Parts) : Option Features :=
  parts.first? fun f => match f with | .features n => some n | _ => none
def Parts.metadata (parts : Parts) : Option ByteArray :=
  parts.first? fun f => match f with | .metadata b => some b | _ => none
def Parts.fallbacks (parts : Parts) : List Fallback :=
  parts.fields.filterMap fun f => match f with | .fallback v => some v | _ => none
def Parts.routeHints (parts : Parts) : List (List RouteHop) :=
  parts.fields.filterMap fun f => match f with | .route hops => some hops | _ => none
def Parts.fallbackAddresses (parts : Parts) : List String :=
  parts.fallbacks.filterMap fun f =>
    (Bitcoin.Address.encodeScript parts.hrp.currency.network f.script).toOption

end Lightning.Bolt11
