/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Psbt.ParseProofs

namespace Bitcoin.Psbt

/-- Framing invariants and successful field decoding, independently of parsing. -/
def valid (cap : PubkeyCapability) (hashes : PreimageHashes) (p : Psbt) : Prop :=
  p.WellFormed ∧ ∃ d, p.decode cap hashes = .ok d

instance (p : Psbt) : Decidable p.WellFormed := by
  unfold Psbt.WellFormed KeyValueMap.WellFormed KeyValueMap.Unique Record.WellFormed
  infer_instance

instance (cap : PubkeyCapability) (hashes : PreimageHashes) (p : Psbt) :
    Decidable (valid cap hashes p) := by
  unfold valid
  have : Decidable (∃ d, p.decode cap hashes = .ok d) := by
    cases h : p.decode cap hashes with
    | error e => exact isFalse (by simp)
    | ok d => exact isTrue ⟨d, rfl⟩
  infer_instance

theorem Psbt.roundtrip (cap : PubkeyCapability) (hashes : PreimageHashes) (p : Psbt)
    (h : valid cap hashes p) : Psbt.parse cap hashes (Psbt.serialize p) = .ok p := by
  obtain ⟨formed, d, decodes⟩ := h
  exact Psbt.parse_serialize formed decodes

theorem Psbt.unique_of_parse {cap : PubkeyCapability} {hashes : PreimageHashes}
    {bytes : ByteArray} {p : Psbt} (h : Psbt.parse cap hashes bytes = .ok p) :
    p.global.Unique ∧ (∀ m ∈ p.inputs, m.Unique) ∧ ∀ m ∈ p.outputs, m.Unique := by
  have formed := (Psbt.serialize_parse h).2.1
  exact ⟨formed.1.2, fun m member => (formed.2.1 m member).2,
    fun m member => (formed.2.2 m member).2⟩

theorem decodePsbtWith_encode_suffix
    (counts : KeyValueMap → Except PsbtError (Nat × Nat)) {p : Psbt}
    (formed : p.WellFormed)
    (counted : counts p.global = .ok (p.inputs.length, p.outputs.length))
    (extra : List UInt8) :
    decodePsbtWith counts (p.encode ++ extra) =
      if extra = [] then .ok p else .error .trailingData := by
  obtain ⟨globalFormed, inputsFormed, outputsFormed⟩ := formed
  have global := decodeMap_encode globalFormed
    (p.inputs.flatMap KeyValueMap.encode ++ (p.outputs.flatMap KeyValueMap.encode ++ extra))
  have inputs := decodeMaps_encode inputsFormed (p.outputs.flatMap KeyValueMap.encode ++ extra)
  have outputs := decodeMaps_encode outputsFormed extra
  have header : (p.encode ++ extra).take 5 = magicBytes := by simp [Psbt.encode, magicBytes]
  have body : (p.encode ++ extra).drop 5 = p.global.encode ++
      (p.inputs.flatMap KeyValueMap.encode ++ (p.outputs.flatMap KeyValueMap.encode ++ extra)) := by
    simp [Psbt.encode, magicBytes, List.append_assoc]
  simp [decodePsbtWith, header, body, global, counted, inputs, outputs,
    bind, Except.bind, pure, Except.pure, throw, throwThe, MonadExceptOf.throw]

theorem Psbt.no_trailing_data {cap : PubkeyCapability} {hashes : PreimageHashes}
    {bytes extra : ByteArray} {p q : Psbt}
    (first : Psbt.parse cap hashes bytes = .ok p)
    (second : Psbt.parse cap hashes (bytes ++ extra) = .ok q) : extra = ByteArray.empty := by
  obtain ⟨serialized, formed, decoded, decodes⟩ := Psbt.serialize_parse first
  rw [← serialized] at second
  unfold Psbt.parse at second
  have counted := globalCounts_of_decode decodes
  simp only [ByteArray.data_append, Array.toList_append, Psbt.serialize_data,
    decodePsbtWith_encode_suffix globalCounts formed counted] at second
  split at second
  · rename_i empty
    apply ByteArray.ext
    simpa using congrArg List.toArray empty
  · simp [bind, Except.bind] at second

end Bitcoin.Psbt
