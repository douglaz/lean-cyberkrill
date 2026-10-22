/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Base58Check
import Bitcoin.Bech32Codec
import Bitcoin.ConvertBits

namespace Bitcoin.Address

inductive Network where
  | mainnet | testnet | signet | regtest
  deriving Repr, DecidableEq, BEq

inductive WitnessNetwork where
  | mainnet | testnets | regtest
  deriving Repr, DecidableEq, BEq

def Network.isMain : Network → Bool
  | .mainnet => true
  | _ => false

def Network.witness : Network → WitnessNetwork
  | .mainnet => .mainnet
  | .testnet | .signet => .testnets
  | .regtest => .regtest

def WitnessNetwork.hrp : WitnessNetwork → String
  | .mainnet => "bc"
  | .testnets => "tb"
  | .regtest => "bcrt"

/-- A parsed address retains its network class, including the shared legacy test class. -/
inductive Value where
  | p2pkh (main : Bool) (hash : ByteArray)
  | p2sh (main : Bool) (hash : ByteArray)
  | witness (network : WitnessNetwork) (version : Nat) (program : ByteArray)
  deriving DecidableEq, BEq

inductive Error where
  | noAddress
  | emptyData
  | witnessVersion
  | checksumVariant
  | padding (reason : Bitcoin.Bech32.PaddingError)
  | programLength
  | unknownHrp
  | base58 (reason : Bitcoin.Base58.CheckError)
  | payloadLength
  | unknownVersion
  | networkMismatch
  deriving Repr, DecidableEq, BEq

def validProgram (version : Nat) (program : ByteArray) : Prop :=
  version ≤ 16 ∧ 2 ≤ program.size ∧ program.size ≤ 40 ∧
    (version = 0 → program.size = 20 ∨ program.size = 32)

instance (v : Nat) (p : ByteArray) : Decidable (validProgram v p) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))

def Value.WellFormed : Value → Prop
  | .p2pkh _ h | .p2sh _ h => h.size = 20
  | .witness _ v p => validProgram v p

def Value.validFor (net : Network) : Value → Prop
  | .p2pkh main _ | .p2sh main _ => main = net.isMain
  | .witness network _ _ => network = net.witness

instance (net : Network) (a : Value) : Decidable (a.validFor net) := by
  cases a <;> unfold Value.validFor <;> infer_instance

def p2pkhScript (hash : ByteArray) : ByteArray :=
  ⟨([0x76, 0xa9, 0x14] ++ hash.data.toList ++ [0x88, 0xac]).toArray⟩

def p2shScript (hash : ByteArray) : ByteArray :=
  ⟨([0xa9, 0x14] ++ hash.data.toList ++ [0x87]).toArray⟩

def versionOpcode (v : Nat) : UInt8 := if v = 0 then 0 else UInt8.ofNat (0x50 + v)

def witnessScript (version : Nat) (program : ByteArray) : ByteArray :=
  ⟨(versionOpcode version :: UInt8.ofNat program.size :: program.data.toList).toArray⟩

def Value.toScript : Value → ByteArray
  | .p2pkh _ h => p2pkhScript h
  | .p2sh _ h => p2shScript h
  | .witness _ v p => witnessScript v p

/-- Recognise only the two legacy templates and minimally pushed witness programs. -/
def fromScript (net : Network) (script : ByteArray) : Except Error Value :=
  match script.data.toList with
  | 0x76 :: 0xa9 :: 0x14 :: tail =>
    if tail.length = 22 ∧ tail.drop 20 = [0x88, 0xac] then
      .ok (.p2pkh net.isMain ⟨(tail.take 20).toArray⟩)
    else .error .noAddress
  | 0xa9 :: 0x14 :: tail =>
    if tail.length = 21 ∧ tail.drop 20 = [0x87] then
      .ok (.p2sh net.isMain ⟨(tail.take 20).toArray⟩)
    else .error .noAddress
  | op :: push :: tail =>
    let version := if op = 0 then 0 else op.toNat - 0x50
    let program : ByteArray := ⟨tail.toArray⟩
    if (op = 0 ∨ 0x51 ≤ op.toNat ∧ op.toNat ≤ 0x60) ∧
        push.toNat = program.size ∧ validProgram version program then
      .ok (.witness net.witness version program)
    else .error .noAddress
  | _ => .error .noAddress

def legacyVersion (scriptHash main : Bool) : UInt8 :=
  if scriptHash then (if main then 0x05 else 0xc4)
  else (if main then 0x00 else 0x6f)

def witnessVariant (version : Nat) : Bitcoin.Bech32.Variant :=
  if version = 0 then .bech32 else .bech32m

/-- Format a well-formed parsed value. Use fromScript or decode for checked construction. -/
def Value.encode : Value → String
  | .p2pkh main h => Bitcoin.Base58.base58CheckEncode (⟨#[legacyVersion false main]⟩ ++ h)
  | .p2sh main h => Bitcoin.Base58.base58CheckEncode (⟨#[legacyVersion true main]⟩ ++ h)
  | .witness network v p => Bitcoin.Bech32.encode network.hrp
      (BitVec.ofNat 5 v :: Bitcoin.Bech32.convertbits8to5 p) (witnessVariant v)

/-- ScriptPubKey to lowercase segwit or case-sensitive Base58 address. -/
def encodeScript (net : Network) (script : ByteArray) : Except Error String :=
  (fromScript net script).map Value.encode

def requireNetwork (net : Network) (a : Value) : Except Error Value :=
  if a.validFor net then .ok a else .error .networkMismatch

private def decodeWitness (hrp : String) (data : List Bitcoin.Bech32.Symbol)
    (variant : Bitcoin.Bech32.Variant) : Except Error Value := do
  let version :: symbols := data | .error .emptyData
  let v := version.toNat
  if v > 16 then .error .witnessVersion else do
    if variant ≠ witnessVariant v then .error .checksumVariant else do
      let program ← (Bitcoin.Bech32.convertbits5to8 symbols).mapError Error.padding
      if ¬ validProgram v program then .error .programLength else do
        let network ← match hrp with
          | "bc" => .ok WitnessNetwork.mainnet
          | "tb" => .ok WitnessNetwork.testnets
          | "bcrt" => .ok WitnessNetwork.regtest
          | _ => .error Error.unknownHrp
        .ok (.witness network v program)

/-- The Base58Check stage, before the expected-network check. -/
def decodeLegacy (text : String) : Except Error Value := do
  let payload ← (Bitcoin.Base58.base58CheckDecode text).mapError Error.base58
  if payload.size ≠ 21 then .error .payloadLength else
    let hash := payload.extract 1 21
    match payload.data[0]?.getD (255 : UInt8) with
    | 0x00 => .ok (.p2pkh true hash)
    | 0x6f => .ok (.p2pkh false hash)
    | 0x05 => .ok (.p2sh true hash)
    | 0xc4 => .ok (.p2sh false hash)
    | _ => .error .unknownVersion

/-- Segwit parsing precedes Base58Check, with fallback for failed segwit validation.
Unknown HRPs are rejected after successful segwit validation. Network validation is last. -/
def decode (net : Network) (text : String) : Except Error Value := do
  let a ← match Bitcoin.Bech32.decode 90 text with
    | .ok (hrp, data, variant) =>
      match decodeWitness hrp data variant with
      | .ok a => .ok a
      | .error .unknownHrp => .error .unknownHrp
      | .error reason =>
        match decodeLegacy text with
        | .ok a => .ok a
        | .error _ => .error reason
    | .error _ => decodeLegacy text
  requireNetwork net a

def decodeScript (net : Network) (text : String) : Except Error ByteArray :=
  (decode net text).map Value.toScript

theorem fromScript_p2pkh (net : Network) (hash : ByteArray) (size : hash.size = 20) :
    fromScript net (p2pkhScript hash) = .ok (.p2pkh net.isMain hash) := by
  have len : hash.data.toList.length = 20 := size
  have take : (hash.data.toList ++ [0x88, 0xac]).take 20 = hash.data.toList := by
    rw [← len, List.take_left]
  have drop : (hash.data.toList ++ [0x88, 0xac]).drop 20 = [0x88, 0xac] := by
    rw [← len, List.drop_left]
  simp [fromScript, p2pkhScript, len, take, drop]

theorem fromScript_p2sh (net : Network) (hash : ByteArray) (size : hash.size = 20) :
    fromScript net (p2shScript hash) = .ok (.p2sh net.isMain hash) := by
  have len : hash.data.toList.length = 20 := size
  have take : (hash.data.toList ++ [0x87]).take 20 = hash.data.toList := by
    rw [← len, List.take_left]
  have drop : (hash.data.toList ++ [0x87]).drop 20 = [0x87] := by
    rw [← len, List.drop_left]
  simp [fromScript, p2shScript, len, take, drop]

theorem fromScript_witness (net : Network) (version : Nat) (program : ByteArray)
    (valid : validProgram version program) :
    fromScript net (witnessScript version program) =
      .ok (.witness net.witness version program) := by
  have opcode : (versionOpcode version).toNat = if version = 0 then 0 else 80 + version := by
    unfold versionOpcode
    split
    · rfl
    · simp only [UInt8.toNat_ofNat']
      exact Nat.mod_eq_of_lt (by have := valid.1; omega)
  have notPkh : versionOpcode version ≠ (118 : UInt8) := by
    intro h
    have eq := congrArg UInt8.toNat h
    rw [opcode] at eq
    change (if version = 0 then 0 else 80 + version) = 118 at eq
    have bound := valid.1
    split at eq <;> omega
  have notSh : versionOpcode version ≠ (169 : UInt8) := by
    intro h
    have eq := congrArg UInt8.toNat h
    rw [opcode] at eq
    change (if version = 0 then 0 else 80 + version) = 169 at eq
    have bound := valid.1
    split at eq <;> omega
  have programCopy : (ByteArray.mk program.data.toList.toArray) = program := by simp
  have push : (UInt8.ofNat program.size).toNat = program.size :=
    UInt8.toNat_ofNat_of_lt' (by change program.size < 256; have := valid.2.2.1; omega)
  have opZero : versionOpcode version = 0 ↔ version = 0 := by
    constructor
    · intro h
      have eq := congrArg UInt8.toNat h
      rw [opcode] at eq
      change (if version = 0 then 0 else 80 + version) = 0 at eq
      split at eq <;> omega
    · intro h; simp [versionOpcode, h]
  have versionBack : (if versionOpcode version = 0 then 0 else
      (versionOpcode version).toNat - 80) = version := by
    simp only [opZero, opcode]
    split <;> simp_all
  have opValid : versionOpcode version = 0 ∨
      81 ≤ (versionOpcode version).toNat ∧ (versionOpcode version).toNat ≤ 96 := by
    by_cases h : version = 0
    · left; exact opZero.mpr h
    · right; rw [opcode, ite_eq_right h]; have := valid.1; omega
  simp [fromScript, witnessScript, notPkh, notSh, programCopy, push,
    versionBack, opValid, valid]

/-- R, parsed-value form: every well-formed address valid on net is recovered from its script. -/
theorem fromScript_toScript (net : Network) (a : Value)
    (wellFormed : a.WellFormed) (network : a.validFor net) :
    fromScript net a.toScript = .ok a := by
  cases a with
  | p2pkh main hash =>
    change main = net.isMain at network
    subst main
    exact fromScript_p2pkh net hash wellFormed
  | p2sh main hash =>
    change main = net.isMain at network
    subst main
    exact fromScript_p2sh net hash wellFormed
  | witness networkClass version program =>
    change networkClass = net.witness at network
    subst networkClass
    exact fromScript_witness net version program wellFormed

private theorem decode_witness_encode (net : Network) (version : Nat) (program : ByteArray)
    (valid : validProgram version program) :
    decode net (Value.witness net.witness version program).encode =
      .ok (.witness net.witness version program) := by
  have versionNat : (BitVec.ofNat 5 version).toNat = version := by
    simp only [BitVec.toNat_ofNat]
    exact Nat.mod_eq_of_lt (by have := valid.1; omega)
  have fits : net.witness.hrp.length +
      (BitVec.ofNat 5 version :: Bitcoin.Bech32.convertbits8to5 program).length + 7 ≤ 90 := by
    have length := Bitcoin.Bech32.convertbits8to5_length program
    have bound := valid.2.2.1
    cases net <;> simp only [Network.witness, WitnessNetwork.hrp,
      show "bc".length = 2 by decide, show "tb".length = 2 by decide,
      show "bcrt".length = 4 by decide, List.length_cons] <;> omega
  have nonempty : net.witness.hrp ≠ "" := by cases net <;> decide
  have range : ∀ c ∈ net.witness.hrp.toList, 33 ≤ c.toNat ∧ c.toNat ≤ 126 := by
    cases net <;> decide
  have noUpper : ∀ c ∈ net.witness.hrp.toList, c.isUpper = false := by
    cases net <;> decide
  have encoded := Bitcoin.Bech32.decode_encode 90 net.witness.hrp
    (BitVec.ofNat 5 version :: Bitcoin.Bech32.convertbits8to5 program)
    (witnessVariant version) nonempty range noUpper fits
  simp only [Value.encode, decode, encoded]
  have notHigh : ¬ version > 16 := by have := valid.1; omega
  cases net <;>
    simp [decodeWitness, versionNat, notHigh, valid,
      Bitcoin.Bech32.convertbits5to8_convertbits8to5,
      requireNetwork, Value.validFor, Network.witness, WitnessNetwork.hrp,
      Except.mapError, bind, Except.bind]

/-- F for all witness templates, including v0's two lengths and every generic v1-16 program. -/
theorem witness_string_roundtrip (net : Network) (version : Nat) (program : ByteArray)
    (valid : validProgram version program) :
    ∃ text, encodeScript net (witnessScript version program) = .ok text ∧
      decodeScript net text = .ok (witnessScript version program) := by
  refine ⟨(Value.witness net.witness version program).encode, ?_, ?_⟩
  · simp [encodeScript, fromScript_witness net version program valid, Except.map]
  · simp [decodeScript, decode_witness_encode net version program valid, Except.map, Value.toScript]

theorem decodeLegacy_p2pkh (main : Bool) (hash : ByteArray) (size : hash.size = 20) :
    decodeLegacy (Value.p2pkh main hash).encode = .ok (.p2pkh main hash) := by
  have extract : (ByteArray.mk #[legacyVersion false main] ++ hash).extract 1 21 = hash :=
    ByteArray.extract_append_eq_right rfl (by change 21 = 1 + hash.size; omega)
  have payloadSize : (ByteArray.mk #[legacyVersion false main] ++ hash).size = 21 := by
    rw [ByteArray.size_append, size]
    rfl
  unfold Value.encode decodeLegacy
  rw [Bitcoin.Base58.base58CheckDecode_encode]
  simp only [Except.mapError, bind, Except.bind, payloadSize, ne_eq, not_true_eq_false,
    ↓reduceIte, extract]
  simp only [ByteArray.data_append,
    Array.getElem?_append_left (xs := #[legacyVersion false main]) (ys := hash.data)
      (i := 0) (by simp)]
  cases main <;> rfl

theorem decodeLegacy_p2sh (main : Bool) (hash : ByteArray) (size : hash.size = 20) :
    decodeLegacy (Value.p2sh main hash).encode = .ok (.p2sh main hash) := by
  have extract : (ByteArray.mk #[legacyVersion true main] ++ hash).extract 1 21 = hash :=
    ByteArray.extract_append_eq_right rfl (by change 21 = 1 + hash.size; omega)
  have payloadSize : (ByteArray.mk #[legacyVersion true main] ++ hash).size = 21 := by
    rw [ByteArray.size_append, size]
    rfl
  unfold Value.encode decodeLegacy
  rw [Bitcoin.Base58.base58CheckDecode_encode]
  simp only [Except.mapError, bind, Except.bind, payloadSize, ne_eq, not_true_eq_false,
    ↓reduceIte, extract]
  simp only [ByteArray.data_append,
    Array.getElem?_append_left (xs := #[legacyVersion true main]) (ys := hash.data)
      (i := 0) (by simp)]
  cases main <;> rfl

/-- F1: recognition succeeds and reconstructs the complete P2PKH script. -/
theorem p2pkh_script_roundtrip (net : Network) (hash : ByteArray) (size : hash.size = 20) :
    (fromScript net (p2pkhScript hash)).map Value.toScript = .ok (p2pkhScript hash) := by
  simp [fromScript_p2pkh net hash size, Except.map, Value.toScript]

/-- F1 for P2SH. -/
theorem p2sh_script_roundtrip (net : Network) (hash : ByteArray) (size : hash.size = 20) :
    (fromScript net (p2shScript hash)).map Value.toScript = .ok (p2shScript hash) := by
  simp [fromScript_p2sh net hash size, Except.map, Value.toScript]

/-- F1 for every valid witness version and program. -/
theorem witness_script_roundtrip (net : Network) (version : Nat) (program : ByteArray)
    (valid : validProgram version program) :
    (fromScript net (witnessScript version program)).map Value.toScript =
      .ok (witnessScript version program) := by
  simp [fromScript_witness net version program valid, Except.map, Value.toScript]

/-- F2: P2PKH strings round-trip through the public Base58 stage and network check. -/
theorem p2pkh_string_roundtrip (net : Network) (hash : ByteArray) (size : hash.size = 20) :
    ∃ text, encodeScript net (p2pkhScript hash) = .ok text ∧
      ((decodeLegacy text).bind (requireNetwork net)).map Value.toScript =
        .ok (p2pkhScript hash) := by
  refine ⟨(Value.p2pkh net.isMain hash).encode, ?_, ?_⟩
  · simp [encodeScript, fromScript_p2pkh net hash size, Except.map]
  · simp [decodeLegacy_p2pkh net.isMain hash size, requireNetwork, Value.validFor,
      Except.bind, Except.map, Value.toScript]

/-- F2 for P2SH, through the same Base58 stage and network check. -/
theorem p2sh_string_roundtrip (net : Network) (hash : ByteArray) (size : hash.size = 20) :
    ∃ text, encodeScript net (p2shScript hash) = .ok text ∧
      ((decodeLegacy text).bind (requireNetwork net)).map Value.toScript =
        .ok (p2shScript hash) := by
  refine ⟨(Value.p2sh net.isMain hash).encode, ?_, ?_⟩
  · simp [encodeScript, fromScript_p2sh net hash size, Except.map]
  · simp [decodeLegacy_p2sh net.isMain hash size, requireNetwork, Value.validFor,
      Except.bind, Except.map, Value.toScript]

/-- The general decoder uses the Base58 stage whenever the bech32 codec fails. -/
theorem decode_of_bech32_error (net : Network) (text : String)
    (reason : Bitcoin.Bech32.DecodeError) (failed : Bitcoin.Bech32.decode 90 text = .error reason) :
    decode net text = (decodeLegacy text).bind (requireNetwork net) := by
  simp [decode, failed, bind]

end Bitcoin.Address
