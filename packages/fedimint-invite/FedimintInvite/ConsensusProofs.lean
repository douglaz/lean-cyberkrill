/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInvite.Consensus

namespace FedimintInvite

theorem writeBigSize_ne_nil (value : Nat) : writeBigSize value ≠ [] := by
  unfold writeBigSize
  dsimp only
  split <;> (try split) <;> (try split) <;> simp

open Bitcoin.CompactSize in
theorem readBigSize_writeBigSize {value : Nat} (bound : value < 2 ^ 64)
    (rest : List UInt8) :
    readBigSize (writeBigSize value ++ rest) = .ok (value, rest) := by
  unfold writeBigSize
  rw [Nat.mod_eq_of_lt bound]
  by_cases small : value < 253
  · have m : value % 256 = value := Nat.mod_eq_of_lt (by omega)
    simp [small, readBigSize, m]
  · have wide (w : Nat) (fits : value < 256 ^ w) :
        (unsignedLE w value).reverse.length = w ∧
        decodeLE (unsignedLE w value).reverse.reverse = value := by
      simp [unsignedLE_length, decodeLE_unsignedLE, Nat.mod_eq_of_lt fits]
    by_cases two : value ≤ 65535
    · obtain ⟨len, dec⟩ := wide 2 (by omega)
      simp only [List.reverse_reverse] at dec
      simp [small, two, readBigSize, len, dec]
    · by_cases four : value ≤ 4294967295
      · obtain ⟨len, dec⟩ := wide 4 (by omega)
        simp only [List.reverse_reverse] at dec
        simp [small, two, four, readBigSize, len, dec]
      · obtain ⟨len, dec⟩ := wide 8 (by omega)
        simp only [List.reverse_reverse] at dec
        simp [small, two, four, readBigSize, len, dec]

theorem readData_append (field : Field) (data : ByteArray) (rest : List UInt8) :
    readData field data.size (data.data.toList ++ rest) = .ok (data, rest) := by
  have len : data.data.toList.length = data.size := by simp
  rw [← len]
  simp [readData, List.splitAt_eq]

theorem bigSizeWidth_writeBigSize (value : Nat) (rest : List UInt8) :
    bigSizeWidth (writeBigSize value ++ rest) = (writeBigSize value).length := by
  unfold writeBigSize
  dsimp only
  split
  · rename_i small
    have fits : value % 2 ^ 64 < 256 := by omega
    simp [bigSizeWidth, Nat.mod_eq_of_lt fits, small]
  · split <;> (try split) <;> simp [bigSizeWidth, Bitcoin.CompactSize.unsignedLE_length]

theorem string_utf8_roundTrip (s : String) : String.fromUTF8? s.toUTF8 = some s := by
  simp only [String.toUTF8_eq_toByteArray, String.fromUTF8?]
  simp only [dite_eq_left s.isValidUTF8]
  rfl

theorem readString_stringBytes (field : Field) (s : String)
    (bound : s.toUTF8.size < 2 ^ 64) (rest : List UInt8) :
    readString field (stringBytes s ++ rest) = .ok (s, rest) := by
  unfold readString stringBytes
  rw [List.append_assoc, readBigSize_writeBigSize bound]
  simp only [bind, Except.bind, readData_append, string_utf8_roundTrip]

theorem readPart_encode_guardian (g : Guardian)
    (urlBound : g.url.toUTF8.size < 2 ^ 64)
    (dataBound : (guardianData g).length < 2 ^ 64) (rest : List UInt8) :
    readPart (encodePart (.guardian g) ++ rest) = .ok (some (.guardian g), rest) := by
  have peerBound : g.peerId.toNat < 2 ^ 64 := Nat.lt_trans g.peerId.toNat_lt (by decide)
  simp only [encodePart, List.append_assoc, List.cons_append, List.nil_append]
  unfold readPart
  rw [show readBigSize (0 :: (writeBigSize (guardianData g).length ++ (guardianData g ++ rest))) =
    .ok (0, writeBigSize (guardianData g).length ++ (guardianData g ++ rest)) from rfl]
  dsimp only [bind, Except.bind]
  rw [readBigSize_writeBigSize dataBound]
  dsimp only [bind, Except.bind]
  rw [show guardianData g ++ rest = stringBytes g.url ++ (writeBigSize g.peerId.toNat ++ rest)
    by simp [guardianData, List.append_assoc], readString_stringBytes _ _ urlBound]
  dsimp only [bind, Except.bind]
  rw [readBigSize_writeBigSize peerBound]
  simp [guardianData, stringBytes, List.append_assoc, bigSizeWidth_writeBigSize,
    List.length_append]
  omega

theorem readPart_encode_federation (data : ByteArray) (size : data.size = 32)
    (rest : List UInt8) :
    readPart (encodePart (.federation data) ++ rest) = .ok (some (.federation data), rest) := by
  have bound : data.size < 2 ^ 64 := by omega
  simp only [encodePart, List.append_assoc, List.cons_append, List.nil_append]
  unfold readPart
  rw [show readBigSize (1 :: (writeBigSize data.size ++ (data.data.toList ++ rest))) =
    .ok (1, writeBigSize data.size ++ (data.data.toList ++ rest)) from rfl]
  dsimp only [bind, Except.bind]
  rw [readBigSize_writeBigSize bound]
  have taken := readData_append .federation data rest
  rw [size] at taken
  simp [size, taken]

theorem readPart_encode_secret (s : String) (bound : s.toUTF8.size < 2 ^ 64)
    (rest : List UInt8) :
    readPart (encodePart (.secret s) ++ rest) = .ok (some (.secret s), rest) := by
  simp only [encodePart, List.cons_append, List.nil_append]
  unfold readPart
  rw [show readBigSize (2 :: (stringBytes s ++ rest)) = .ok (2, stringBytes s ++ rest) from rfl]
  dsimp only [bind, Except.bind]
  rw [readString_stringBytes _ _ bound]
  rfl

def Part.Bounded : Part → Prop
  | .guardian g => g.url.toUTF8.size < 2 ^ 64 ∧ (guardianData g).length < 2 ^ 64
  | .federation data => data.size = 32
  | .secret s => s.toUTF8.size < 2 ^ 64

theorem readPart_encodePart (part : Part) (bound : part.Bounded) (rest : List UInt8) :
    readPart (encodePart part ++ rest) = .ok (some part, rest) := by
  cases part with
  | guardian g => exact readPart_encode_guardian g bound.1 bound.2 rest
  | federation data => exact readPart_encode_federation data bound rest
  | secret s => exact readPart_encode_secret s bound rest

theorem encodePart_ne_nil (part : Part) : encodePart part ≠ [] := by
  cases part <;> simp [encodePart]

theorem readParts_encodeParts (parts : List Part) (bound : ∀ part ∈ parts, part.Bounded)
    (rest : List UInt8) (state : State) :
    readParts parts.length (parts.flatMap encodePart ++ rest) state =
      .ok (parts.foldl applyPart state) := by
  induction parts generalizing state with
  | nil => rfl
  | cons part parts ih =>
    have nonempty : encodePart part ++ (parts.flatMap encodePart ++ rest) ≠ [] := by
      intro h
      exact encodePart_ne_nil part (List.append_eq_nil_iff.mp h).1
    simp only [List.length_cons, List.flatMap_cons, List.append_assoc, readParts,
      nonempty, ↓reduceIte]
    rw [readPart_encodePart part (bound part (by simp))]
    dsimp only [bind, Except.bind]
    exact ih (fun p hp => bound p (by simp [hp])) _

theorem foldl_guardians (guardians : List Guardian) (state : State) :
    (guardians.map Part.guardian).foldl applyPart state =
      { state with guardians := guardians.reverse ++ state.guardians } := by
  induction guardians generalizing state with
  | nil => simp
  | cons g gs ih =>
    simp [applyPart, ih, List.reverse_cons, List.append_assoc]

theorem sortGuardians_eq (guardians : List Guardian)
    (sortedUnique : guardians.Pairwise (fun a b => a.peerId.toNat < b.peerId.toNat)) :
    sortGuardians guardians = guardians := by
  apply List.mergeSort_of_pairwise
  exact sortedUnique.imp (fun h => by simpa using Nat.le_of_lt h)

theorem hex_encode_length (bytes : ByteArray) :
    (Bitcoin.Hex.encode bytes).length = 2 * bytes.size := by
  simp only [Bitcoin.Hex.encode, String.length_ofList, Sha256.Hex.length_encodeChars]

/-- Consensus round-trip, with no string-wrapper size restriction.
The 32-byte hexadecimal representation is exactly the 64 lowercase hex domain. -/
theorem consensus_roundTrip (inv : Invite) (federation : ByteArray)
    (fedSize : federation.size = 32)
    (fedId : inv.federationId = Bitcoin.Hex.encode federation)
    (nonempty : inv.guardians ≠ [])
    (sortedUnique : inv.guardians.Pairwise (fun a b => a.peerId.toNat < b.peerId.toNat))
    (partBound : inv.guardians.length + 1 + inv.apiSecret.toList.length < 2 ^ 64)
    (urlBound : ∀ g ∈ inv.guardians, g.url.toUTF8.size < 2 ^ 64)
    (dataBound : ∀ g ∈ inv.guardians, (guardianData g).length < 2 ^ 64)
    (secretBound : ∀ s ∈ inv.apiSecret, s.toUTF8.size < 2 ^ 64) :
    (encodeConsensus inv >>= decodeConsensus) = .ok inv := by
  have fedNonempty : inv.federationId ≠ "" := by
    intro h
    have len := hex_encode_length federation
    rw [← fedId, h, fedSize] at len
    contradiction
  let parts := inv.guardians.map Part.guardian ++ [Part.federation federation] ++
    inv.apiSecret.toList.map Part.secret
  have partsBound : ∀ p ∈ parts, p.Bounded := by
    intro p hp
    simp only [parts, List.mem_append, List.mem_map, List.mem_singleton] at hp
    rcases hp with (⟨g, hg, rfl⟩ | rfl) | ⟨s, hs, rfl⟩
    · exact ⟨urlBound g hg, dataBound g hg⟩
    · exact fedSize
    · exact secretBound s (by simpa using hs)
  have countBound : parts.length < 2 ^ 64 := by
    simp only [parts, List.length_append, List.length_map, List.length_singleton]
    omega
  have partsEq : inviteParts inv = .ok parts := by
    unfold inviteParts
    rw [ite_eq_right fedNonempty, fedId, Bitcoin.Hex.decode_encode]
    simp only [fedSize, ↓reduceIte, bind, Except.bind]
    rfl
  have encoded : encodeConsensus inv = .ok
      ⟨(writeBigSize parts.length ++ parts.flatMap encodePart).toArray⟩ := by
    simp only [encodeConsensus, partsEq, bind, Except.bind, pure, Except.pure]
  rw [encoded]
  dsimp only [bind, Except.bind]
  unfold decodeConsensus
  rw [readBigSize_writeBigSize countBound]
  dsimp only [bind, Except.bind]
  have parsed := readParts_encodeParts parts partsBound [] {}
  simp only [List.append_nil] at parsed
  rw [parsed]
  have folded : parts.foldl applyPart {} =
      (⟨some inv.federationId, inv.guardians.reverse, inv.apiSecret⟩ : State) := by
    simp only [parts, List.foldl_append, foldl_guardians]
    cases inv.apiSecret <;> simp [applyPart, ← fedId]
  rw [folded]
  dsimp only [bind, Except.bind]
  simp only [List.reverse_eq_nil_iff, List.reverse_reverse]
  rw [ite_eq_right nonempty, sortGuardians_eq _ sortedUnique]

end FedimintInvite
