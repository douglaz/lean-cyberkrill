/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Hex
import Bitcoin.CompactSize
import Bitcoin.Bech32Codec
import Init.Data.String.Lemmas

namespace FedimintInvite

structure Guardian where
  peerId : UInt16
  url : String
  deriving Repr, DecidableEq, BEq

structure Invite where
  federationId : String
  guardians : List Guardian
  apiSecret : Option String
  deriving Repr, DecidableEq, BEq

inductive Field where
  | url | secret | federation
  deriving Repr, DecidableEq, BEq

inductive Error where
  | truncatedBigSize (width available : Nat)
  | unexpectedPart (remaining : Nat)
  | overrun (field : Field) (requested available : Nat)
  | invalidUtf8 (field : Field)
  | federationLength (length : Nat)
  | guardianLength (declared consumed : Nat)
  | missingFederation
  | noGuardian
  | invalidHex
  | tooLong (length : Nat)
  | prefix
  | wrongHrp (actual : String)
  | wrongVariant
  | bech32 (error : Bitcoin.Bech32.DecodeError)
  deriving Repr, DecidableEq, BEq

open Bitcoin.CompactSize in
/-- Fedimint BigSize, big endian and minimal on write. Natural lengths cross
the reference's u64 boundary here; round-trip hypotheses bound each use. -/
def writeBigSize (n : Nat) : List UInt8 :=
  let value := n % 2 ^ 64
  if value < 253 then [UInt8.ofNat value]
  else if value ≤ 65535 then 0xfd :: (unsignedLE 2 value).reverse
  else if value ≤ 4294967295 then 0xfe :: (unsignedLE 4 value).reverse
  else 0xff :: (unsignedLE 8 value).reverse

open Bitcoin.CompactSize in
/-- Wider-than-minimal values are accepted; at most eight big-endian bytes. -/
def readBigSize : List UInt8 → Except Error (Nat × List UInt8)
  | [] => .error (.truncatedBigSize 1 0)
  | tag :: rest =>
    if tag.toNat < 253 then .ok (tag.toNat, rest)
    else
      let width := if tag.toNat = 253 then 2 else if tag.toNat = 254 then 4 else 8
      match takeExact width rest with
      | .ok (data, after) => .ok (decodeLE data.reverse, after)
      | .error _ => .error (.truncatedBigSize width rest.length)

/-- Read a whole-buffer byte span, checking the natural-number bound first. -/
def readData (field : Field) (n : Nat) (bytes : List UInt8) :
    Except Error (ByteArray × List UInt8) :=
  if n ≤ bytes.length then .ok (⟨(bytes.take n).toArray⟩, bytes.drop n)
  else .error (.overrun field n bytes.length)

def readString (field : Field) (bytes : List UInt8) :
    Except Error (String × List UInt8) := do
  let (n, rest) ← readBigSize bytes
  let (data, rest) ← readData field n rest
  match String.fromUTF8? data with
  | none => .error (.invalidUtf8 field)
  | some s => .ok (s, rest)

inductive Part where
  | guardian (value : Guardian)
  | federation (bytes : ByteArray)
  | secret (value : String)

def stringBytes (s : String) : List UInt8 :=
  writeBigSize s.toUTF8.size ++ s.toUTF8.data.toList

def guardianData (g : Guardian) : List UInt8 :=
  stringBytes g.url ++ writeBigSize g.peerId.toNat

def encodePart : Part → List UInt8
  | .guardian g => [0] ++ writeBigSize (guardianData g).length ++ guardianData g
  | .federation bytes => [1] ++ writeBigSize bytes.size ++ bytes.data.toList
  | .secret s => [2] ++ stringBytes s

/-- Unknown discriminators stop immediately, without inspecting their payload. -/
def readPart (bytes : List UInt8) : Except Error (Option Part × List UInt8) := do
  let (variant, rest) ← readBigSize bytes
  if variant = 0 then
    let (declared, data) ← readBigSize rest
    let (url, afterUrl) ← readString .url data
    let (peer, afterPeer) ← readBigSize afterUrl
    let consumed := data.length - afterPeer.length
    if consumed = declared then
      .ok (some (.guardian ⟨UInt16.ofNat peer, url⟩), afterPeer)
    else .error (.guardianLength declared consumed)
  else if variant = 1 then
    let (n, rest) ← readBigSize rest
    if n = 32 then
      let (data, rest) ← readData .federation n rest
      .ok (some (.federation data), rest)
    else .error (.federationLength n)
  else if variant = 2 then
    let (s, rest) ← readString .secret rest
    .ok (some (.secret s), rest)
  else .ok (none, rest)

structure State where
  federation : Option String := none
  guardians : List Guardian := []
  secret : Option String := none
  deriving Repr, DecidableEq

def applyPart (state : State) : Part → State
  | .guardian g => { state with guardians := state.guardians ++ [g] }
  | .federation bytes => { state with federation := some (Bitcoin.Hex.encode bytes) }
  | .secret s => { state with secret := some s }

def readParts : Nat → List UInt8 → State → Except Error State
  | 0, _, state => .ok state
  | n + 1, bytes, state =>
    if bytes = [] then .error (.unexpectedPart (n + 1))
    else do
      let (part, rest) ← readPart bytes
      match part with
      | none => .ok state
      | some part => readParts n rest (applyPart state part)

/-- Left insertion before equal ids makes this tail-first sort stable. -/
def insertGuardian (g : Guardian) : List Guardian → List Guardian
  | [] => [g]
  | h :: rest => if g.peerId.toNat ≤ h.peerId.toNat then g :: h :: rest
                else h :: insertGuardian g rest

def sortGuardians : List Guardian → List Guardian
  | [] => []
  | g :: rest => insertGuardian g (sortGuardians rest)

def decodeConsensus (bytes : ByteArray) : Except Error Invite := do
  let (n, rest) ← readBigSize bytes.data.toList
  let state ← readParts n rest {}
  match state.federation with
  | none => .error .missingFederation
  | some id =>
    if state.guardians = [] then .error .noGuardian
    else .ok ⟨id, sortGuardians state.guardians, state.secret⟩

def inviteParts (inv : Invite) : Except Error (List Part) := do
  let federation ← if inv.federationId = "" then .ok [] else
    match Bitcoin.Hex.decode inv.federationId with
    | none => .error .invalidHex
    | some bytes => if bytes.size = 32 then .ok [Part.federation bytes]
                    else .error (.federationLength bytes.size)
  return inv.guardians.map Part.guardian ++ federation ++ inv.apiSecret.toList.map Part.secret

def encodeConsensus (inv : Invite) : Except Error ByteArray := do
  let parts ← inviteParts inv
  return ⟨(writeBigSize parts.length ++ parts.flatMap encodePart).toArray⟩

end FedimintInvite
