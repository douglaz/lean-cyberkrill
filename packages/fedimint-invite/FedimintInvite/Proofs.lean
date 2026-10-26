/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInvite.Codec
import FedimintInvite.ConsensusProofs

namespace FedimintInvite

theorem bech32m_roundTrip (data : List Bitcoin.Bech32.Symbol)
    (fits : 4 + data.length + 7 ≤ 1023) :
    Bitcoin.Bech32.decode 1023 (Bitcoin.Bech32.encode "fed1" data .bech32m) =
      .ok ("fed1", data, .bech32m) := by
  apply Bitcoin.Bech32.decode_encode
  · decide
  · decide
  · decide
  · decide
  · exact fits

/-- Exact public wrapper length, including its separator and six checksum symbols. -/
theorem bech32m_encodedLength (bytes : ByteArray) :
    (Bitcoin.Bech32.encode "fed1" (Bitcoin.Bech32.convertbits8to5 bytes) .bech32m).length =
      4 + 1 + (bytes.size * 8 + 4) / 5 + 6 := by
  have checksumLength : (Bitcoin.Bech32.createChecksum "fed1"
      (Bitcoin.Bech32.convertbits8to5 bytes) .bech32m).length = 6 := by
    simp [Bitcoin.Bech32.createChecksum]
  simp only [Bitcoin.Bech32.encode, String.length_append, String.length_ofList,
    List.length_map, List.length_append, checksumLength,
    Bitcoin.Bech32.convertbits8to5_length_exact]
  rfl

theorem bech32m_fits_iff (bytes : ByteArray) :
    (Bitcoin.Bech32.encode "fed1" (Bitcoin.Bech32.convertbits8to5 bytes) .bech32m).length ≤ 1023 ↔
      bytes.size ≤ 632 := by
  rw [bech32m_encodedLength]
  omega

/-- Soundness is about checksum symbols in the original trimmed string. -/
theorem bech32m_checksumSound (input : String) (data : List Bitcoin.Bech32.Symbol)
    (success : decodePayload input = .ok data) :
    ∃ chk : List Bitcoin.Bech32.Symbol, chk.length = 6 ∧
      Bitcoin.Bech32.lower (trimInput input) = "fed1" ++ "1" ++
        String.ofList ((data ++ chk).map Bitcoin.Bech32.charOf) ∧
      Bitcoin.Bech32.verifyChecksum .bech32m "fed1" (data ++ chk) = true := by
  unfold decodePayload at success
  dsimp only at success
  split at success
  · simp at success
  · cases h : Bitcoin.Bech32.decode 1023 (trimInput input) with
    | error e => simp [h, Except.mapError, bind, Except.bind] at success
    | ok triple =>
      obtain ⟨hrp, data', variant⟩ := triple
      simp only [h, Except.mapError, bind, Except.bind] at success
      split at success
      · simp at success
      · rename_i hrpEq
        split at success
        · simp at success
        · rename_i variantEq
          simp only [Except.ok.injEq] at success
          have hh : hrp = "fed1" := by simpa using hrpEq
          have hv : variant = .bech32m := by simpa using variantEq
          subst hrp
          subst variant
          subst data'
          exact Bitcoin.Bech32.decode_sound 1023 (trimInput input) "fed1" data .bech32m h

private theorem dropWhite (xs : List Char) (all : ∀ c ∈ xs, whiteSpace c = false) :
    xs.dropWhile whiteSpace = xs := by
  cases xs with
  | nil => rfl
  | cons c cs => simp [List.dropWhile, all c (by simp)]

set_option maxRecDepth 4096 in
private theorem alphabet_notWhite :
    ∀ x : Bitcoin.Bech32.Symbol, whiteSpace (Bitcoin.Bech32.charOf x) = false := by decide

theorem trimInput_bech32m_encode (data : List Bitcoin.Bech32.Symbol) :
    trimInput (Bitcoin.Bech32.encode "fed1" data .bech32m) =
      Bitcoin.Bech32.encode "fed1" data .bech32m := by
  have all : ∀ c ∈ (Bitcoin.Bech32.encode "fed1" data .bech32m).toList,
      whiteSpace c = false := by
    intro c hc
    simp only [Bitcoin.Bech32.encode, String.toList_append, String.toList_ofList,
      List.mem_append, List.mem_map] at hc
    rcases hc with (hc | hc) | ⟨x, _, rfl⟩
    · have : ∀ c ∈ "fed1".toList, whiteSpace c = false := by decide
      exact this c hc
    · have : ∀ c ∈ "1".toList, whiteSpace c = false := by decide
      exact this c hc
    · exact alphabet_notWhite x
  unfold trimInput
  rw [dropWhite _ all, dropWhite _ (by simpa using all), List.reverse_reverse,
    String.ofList_toList]

theorem decodePayload_encode (data : List Bitcoin.Bech32.Symbol)
    (fits : 4 + data.length + 7 ≤ 1023) :
    decodePayload (Bitcoin.Bech32.encode "fed1" data .bech32m) = .ok data := by
  unfold decodePayload
  rw [trimInput_bech32m_encode]
  dsimp only
  have prefixEq : (Bitcoin.Bech32.encode "fed1" data .bech32m).toList.take 4 = "fed1".toList := by
    simp only [Bitcoin.Bech32.encode, String.toList_append, String.toList_ofList,
      List.append_assoc]
    change ("fed1".toList ++ _).take "fed1".toList.length = _
    exact List.take_left
  rw [ite_eq_right (by simpa using prefixEq), bech32m_roundTrip data fits]
  rfl

theorem invite_roundTrip (inv : Invite) (federation : ByteArray)
    (fedSize : federation.size = 32)
    (fedId : inv.federationId = Bitcoin.Hex.encode federation)
    (nonempty : inv.guardians ≠ [])
    (sortedUnique : inv.guardians.Pairwise (fun a b => a.peerId.toNat < b.peerId.toNat))
    (partBound : inv.guardians.length + 1 + inv.apiSecret.toList.length < 2 ^ 64)
    (urlBound : ∀ g ∈ inv.guardians, g.url.toUTF8.size < 2 ^ 64)
    (dataBound : ∀ g ∈ inv.guardians, (guardianData g).length < 2 ^ 64)
    (secretBound : ∀ s ∈ inv.apiSecret, s.toUTF8.size < 2 ^ 64)
    (s : String) (success : encode inv = .ok s) : decode s = .ok inv := by
  have consensus := consensus_roundTrip inv federation fedSize fedId nonempty sortedUnique
    partBound urlBound dataBound secretBound
  unfold encode at success
  cases h : encodeConsensus inv with
  | error e => simp [h, bind, Except.bind] at success
  | ok bytes =>
    simp only [h, bind, Except.bind] at success consensus
    split at success
    · simp [throw] at success
    · rename_i fits
      simp only [pure, Except.pure, Except.ok.injEq] at success
      subst s
      have bound : 4 + (Bitcoin.Bech32.convertbits8to5 bytes).length + 7 ≤ 1023 := by omega
      unfold decode
      rw [decodePayload_encode _ bound]
      dsimp only [bind, Except.bind]
      rw [Bitcoin.Bech32.fesToBytesLax_convertbits8to5]
      exact consensus

end FedimintInvite
