/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Bolt11.AmountProofs
import Bitcoin.Bech32Codec

namespace Lightning.Bolt11

set_option linter.unusedSimpArgs false
set_option maxHeartbeats 1000000

private theorem throw_error {ε α : Type} (e : ε) :
    (throw e : Except ε α) = .error e := rfl

private theorem bytes_beq_eq (a b : ByteArray) (h : (a == b) = true) : a = b := by
  change (a.data == b.data) = true at h
  exact ByteArray.ext (beq_iff_eq.mp h)

/-- BOLT11's bit-level message: five MSB-first bits per original signed
symbol, padded with zero bits only through the last partial byte. -/
def specHash (hrp : String) (signed : List Symbol) : ByteArray :=
  Sha256.hash ((Bitcoin.Bech32.lower hrp).toUTF8 ++ Bitcoin.Bech32.padded5Bytes signed)

/-- Extract from the string itself, excluding its six checksum symbols and
104 signature symbols. No decoder length limit applies to this extraction. -/
def specHashFromString (s : String) : Option ByteArray := do
  let (hrp, data) ← Bitcoin.Bech32.extractData s
  return specHash hrp (data.take (data.length - 104))

theorem signingHash_spec (hrp : String) (data : List Symbol) :
    signingHash hrp data = specHash hrp data := by
  simp only [signingHash, specHash, Bitcoin.Bech32.fesToBytesLax_padded5Bytes]

theorem lower_idempotent (s : String) :
    Bitcoin.Bech32.lower (Bitcoin.Bech32.lower s) = Bitcoin.Bech32.lower s := by
  unfold Bitcoin.Bech32.lower
  simp only [String.toList_ofList, List.map_map]
  congr 1
  apply List.map_congr_left
  intro c _
  change c.toLower.toLower = c.toLower
  have lower : ¬ (c.toLower.val ≥ 'A'.val ∧ c.toLower.val ≤ 'Z'.val) := by
    unfold Char.toLower
    split
    · rename_i hc
      have lo := UInt32.le_iff_toNat_le.mp hc.1
      have hi := UInt32.le_iff_toNat_le.mp hc.2
      change 65 ≤ c.val.toNat at lo
      change c.val.toNat ≤ 90 at hi
      simp only [UInt32.toNat_add, UInt32.le_iff_toNat_le]
      change ¬ (65 ≤ (c.val.toNat + 32) % 4294967296 ∧
        (c.val.toNat + 32) % 4294967296 ≤ 90)
      omega
    · assumption
  exact dite_eq_right lower

theorem decode_trace (cap : Curve) (s : String) (inv : Invoice)
    (success : decode cap s = .ok inv) :
    ∃ hrp data, Bitcoin.Bech32.decode 7089 s = .ok (hrp, data, .bech32) ∧
      inv.signingHash = signingHash (String.ofList (s.toList.take hrp.length))
        (data.take (data.length - 104)) ∧
      checkSignature cap inv.toParts inv.signingHash inv.signature = .ok inv.payeeKey := by
  unfold decode at success
  cases hb : Bitcoin.Bech32.decode 7089 s with
  | error e => cases e <;> simp [hb, throw_error, Bind.bind, Except.bind] at success
  | ok result =>
    obtain ⟨hrp, data, variant⟩ := result
    simp only [hb, Bind.bind, Except.bind, Pure.pure, Except.pure] at success
    repeat' (split at success <;> (try simp only [Bind.bind, Except.bind, Pure.pure,
      Except.pure, throw_error, reduceCtorEq, Except.ok.injEq] at success) <;> try contradiction)
    subst inv
    refine ⟨hrp, data, ?_, ?_, ?_⟩
    · simpa using
        (by assumption : ¬ variant ≠ .bech32)
    · dsimp only
      try congr 1
    · assumption

/-- The recorded hash and the hash supplied to verification/recovery both
come from this successful decoder input's original signed symbols. -/
theorem decode_signingHash_spec (cap : Curve) (s : String) (inv : Invoice)
    (success : decode cap s = .ok inv) :
    specHashFromString s = some inv.signingHash ∧
      checkSignature cap inv.toParts inv.signingHash inv.signature = .ok inv.payeeKey := by
  obtain ⟨hrp, data, parsed, hash, checked⟩ := decode_trace cap s inv success
  refine ⟨?_, checked⟩
  simp only [specHashFromString, Bitcoin.Bech32.decode_extractData _ _ _ _ _ parsed,
    Bind.bind, Option.bind_some, Pure.pure, hash, signingHash_spec]
  unfold specHash
  rw [Bitcoin.Bech32.decode_lower_prefix _ _ _ _ _ parsed]
  have normalized : Bitcoin.Bech32.lower hrp = hrp := by
    have h := Bitcoin.Bech32.decode_lower_prefix _ _ _ _ _ parsed
    rw [← h, lower_idempotent]
  rw [normalized]

theorem encodeData_hrp (parts : Parts) (hrp : String) (data : List Symbol)
    (success : encodeData parts = .ok (hrp, data)) : encodeHrp parts.hrp = .ok hrp := by
  unfold encodeData at success
  simp only [Bind.bind, Except.bind, Pure.pure, Except.pure] at success
  repeat' (split at success <;> (try simp only [Bind.bind, Except.bind, Pure.pure,
    Except.pure, throw_error, reduceCtorEq, Except.ok.injEq, Prod.mk.injEq] at success) <;> try contradiction)
  all_goals simp_all

theorem decode_signature_check_spec (cap : Curve) (s : String) (inv : Invoice)
    (success : decode cap s = .ok inv) :
    ∃ hash, specHashFromString s = some hash ∧
      checkSignature cap inv.toParts hash inv.signature = .ok inv.payeeKey := by
  exact ⟨inv.signingHash, decode_signingHash_spec cap s inv success⟩

theorem encodeHrp_lower (parts : Parts) (hrp : String) (data : List Symbol)
    (success : encodeData parts = .ok (hrp, data)) :
    hrp.toList.map Char.toLower = hrp.toList := by
  have noUpper := (encodeHrp_properties _ _ (encodeData_hrp _ _ _ success)).2.2.1
  simpa only [List.map_id] using (List.map_congr_left (l := hrp.toList) (g := id)
    (fun c hc => by
      have hn : ¬ (c.val ≥ 'A'.val ∧ c.val ≤ 'Z'.val) := by
        simpa only [Char.isUpper, decide_eq_false_iff_not] using noUpper c hc
      unfold Char.toLower
      split
      · contradiction
      · rfl))

theorem signature_symbols_length (signature : ByteArray) (valid : validSignature signature = true) :
    (Bitcoin.Bech32.convertbits8to5 signature).length = 104 := by
  have size : signature.size = 65 := by
    simp only [validSignature, Bool.and_eq_true, beq_iff_eq] at valid
    omega
  rw [Bitcoin.Bech32.convertbits8to5_length_exact, size]

theorem writer_specHash (parts : Parts) (hrp : String) (data : List Symbol)
    (signature : ByteArray) (written : encodeData parts = .ok (hrp, data))
    (valid : validSignature signature = true) :
    specHashFromString (Bitcoin.Bech32.encode hrp
      (data ++ Bitcoin.Bech32.convertbits8to5 signature) .bech32) =
        some (signingHash hrp data) := by
  have len := signature_symbols_length signature valid
  simp only [specHashFromString, Bitcoin.Bech32.extractData_encode _ _ _
    (encodeHrp_lower _ _ _ written), Bind.bind, Option.bind_some, Pure.pure]
  simp only [List.length_append, len, Nat.add_sub_cancel, List.take_left, signingHash_spec]

theorem encode_signingHash_spec (inv : Invoice) (s : String)
    (success : encode inv = .ok s) : specHashFromString s = some inv.signingHash := by
  unfold encode at success
  cases hd : encodeData inv.toParts with
  | error e => simp [hd, Bind.bind, Except.bind] at success
  | ok pair =>
    obtain ⟨hrp, data⟩ := pair
    simp only [hd, Bind.bind, Except.bind, Pure.pure, Except.pure] at success
    split at success
    · simp only [throw_error, Except.bind, reduceCtorEq] at success
    split at success
    · simp only [throw_error, Except.bind, reduceCtorEq] at success
    have valid : validSignature inv.signature = true := by
      cases h : validSignature inv.signature <;> simp_all
    have hash : signingHash hrp data = inv.signingHash := by
      have h : ¬ (signingHash hrp data != inv.signingHash) = true := by assumption
      have equal : (signingHash hrp data == inv.signingHash) = true := by
        cases he : (signingHash hrp data == inv.signingHash) <;> simp_all [bne]
      exact bytes_beq_eq _ _ equal
    have output := Except.ok.inj success
    rw [← output, writer_specHash _ _ _ _ hd valid, hash]

/-- Identifies the actual signer call, its returned signature, and the output
framing. No law of the supplied curve capability is assumed. -/
theorem sign_signingHash_spec (cap : Curve) (parts : Parts) (s : String)
    (success : sign cap parts = .ok s) :
    ∃ hrp data signature, encodeData parts = .ok (hrp, data) ∧
      cap.sign (signingHash hrp data) = some signature ∧
      validSignature signature = true ∧
      s = Bitcoin.Bech32.encode hrp (data ++ Bitcoin.Bech32.convertbits8to5 signature) .bech32 ∧
      specHashFromString s = some (signingHash hrp data) := by
  unfold sign at success
  cases hd : encodeData parts with
  | error e => simp [hd, Bind.bind, Except.bind] at success
  | ok pair =>
    obtain ⟨hrp, data⟩ := pair
    simp only [hd, Bind.bind, Except.bind, Pure.pure, Except.pure] at success
    cases hs : cap.sign (signingHash hrp data) with
    | none =>
      repeat' (split at success <;> simp_all [hs])
    | some signature =>
      simp only [hs] at success
      repeat' (split at success <;> (try simp only [hs, Bind.bind, Except.bind, Pure.pure,
        Except.pure, throw_error, reduceCtorEq, Except.ok.injEq] at success) <;> try contradiction)
      refine ⟨hrp, data, signature, rfl, hs, ?_, ?_, ?_⟩
      · simp_all
      · exact success.symm
      · rw [← success]
        exact writer_specHash _ _ _ _ hd (by simp_all)

/-- Invoice framing at the decoder's limit. HRP validity and its 83-character
bound follow from encoder success; only the genuine total fit is a premise. -/
theorem invoice_bech32_roundTrip (parts : Parts) (hrp : String) (data : List Symbol)
    (signature : ByteArray) (written : encodeData parts = .ok (hrp, data))
    (valid : validSignature signature = true)
    (fits : hrp.length + data.length + 104 + 7 ≤ 7089) :
    Bitcoin.Bech32.decode 7089 (Bitcoin.Bech32.encode hrp
      (data ++ Bitcoin.Bech32.convertbits8to5 signature) .bech32) =
        .ok (hrp, data ++ Bitcoin.Bech32.convertbits8to5 signature, .bech32) := by
  obtain ⟨nonempty, range, lower, bound⟩ :=
    encodeHrp_properties _ _ (encodeData_hrp _ _ _ written)
  apply Bitcoin.Bech32.decode_encode _ _ _ _ nonempty range lower bound
  simpa only [List.length_append, signature_symbols_length signature valid,
    Nat.add_assoc] using fits

theorem invoice_checksumSound (cap : Curve) (s : String) (inv : Invoice)
    (success : decode cap s = .ok inv) :
    ∃ hrp data chk, Bitcoin.Bech32.decode 7089 s = .ok (hrp, data, .bech32) ∧
      chk.length = 6 ∧
      Bitcoin.Bech32.lower s = hrp ++ "1" ++ String.ofList ((data ++ chk).map Bitcoin.Bech32.charOf) ∧
      Bitcoin.Bech32.verifyChecksum .bech32 hrp (data ++ chk) = true := by
  obtain ⟨hrp, data, parsed, _⟩ := decode_trace cap s inv success
  obtain ⟨chk, length, reconstruction, verified⟩ :=
    Bitcoin.Bech32.decode_sound _ _ _ _ _ parsed
  exact ⟨hrp, data, chk, parsed, length, reconstruction, verified⟩

#print axioms signingHash_spec
#print axioms decode_trace
#print axioms decode_signingHash_spec
#print axioms decode_signature_check_spec
#print axioms encode_signingHash_spec
#print axioms sign_signingHash_spec
#print axioms invoice_bech32_roundTrip
#print axioms invoice_checksumSound

#print axioms lower_idempotent
#print axioms encodeData_hrp
#print axioms encodeHrp_lower
#print axioms signature_symbols_length
#print axioms writer_specHash

end Lightning.Bolt11
