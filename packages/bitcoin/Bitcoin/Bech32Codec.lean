/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bech32

namespace Bitcoin.Bech32

def charset : String := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def charOf (symbol : Symbol) : Char := charset.toList.getD symbol.toNat 'q'

private def readChar (c : Char) : Option Symbol :=
  (List.ofFn fun i : Fin 32 => BitVec.ofNat 5 i.val).find? fun symbol => charOf symbol == c

private theorem charOf_readChar (c : Char) (x : Symbol) (h : readChar c = some x) :
    charOf x = c := by
  exact beq_iff_eq.mp (List.find?_some (p := fun symbol : Symbol => charOf symbol == c) h)

set_option maxRecDepth 4096 in
private theorem alphabet_inverse : ∀ x : Symbol, readChar (charOf x) = some x := by decide

set_option maxRecDepth 4096 in
private theorem alphabet_properties : ∀ x : Symbol,
    (charOf x).toLower = charOf x ∧ (charOf x).isUpper = false ∧ charOf x ≠ '1' := by decide

private def readChars : List Char → Option (List Symbol)
  | [] => some []
  | c :: cs => do
    let x ← readChar c
    let xs ← readChars cs
    pure (x :: xs)

private theorem readChars_chars (xs : List Symbol) :
    readChars (xs.map charOf) = some xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp [readChars, alphabet_inverse, ih]

private theorem chars_readChars (cs : List Char) (xs : List Symbol)
    (h : readChars cs = some xs) : xs.map charOf = cs := by
  induction cs generalizing xs with
  | nil => simpa [readChars] using h.symm
  | cons c cs ih =>
    simp only [readChars] at h
    cases hc : readChar c with
    | none => simp [hc] at h
    | some x =>
      cases hs : readChars cs with
      | none => simp [hc, hs] at h
      | some ys =>
        have eq : x :: ys = xs := by simpa [hc, hs] using h
        rw [← eq, List.map_cons, charOf_readChar c x hc, ih ys hs]

/-- Preserve the supplied HRP and append the six BIP checksum symbols. -/
def encode (hrp : String) (data : List Symbol) (v : Variant) : String :=
  hrp ++ "1" ++ String.ofList ((data ++ createChecksum hrp data v).map charOf)

/-- Search the tail first, so an HRP may itself contain separators. -/
private def splitLast : List Char → Option (List Char × List Char)
  | [] => none
  | c :: cs =>
    match splitLast cs with
    | some (hrp, data) => some (c :: hrp, data)
    | none => if c = '1' then some ([], cs) else none

private theorem splitLast_none (cs : List Char) (no : ∀ c ∈ cs, c ≠ '1') :
    splitLast cs = none := by
  induction cs with
  | nil => rfl
  | cons c cs ih =>
    simp [splitLast, no c (by simp), ih (fun x hx => no x (by simp [hx]))]

private theorem splitLast_append (hrp data : List Char) (no : ∀ c ∈ data, c ≠ '1') :
    splitLast (hrp ++ '1' :: data) = some (hrp, data) := by
  induction hrp with
  | nil => simp [splitLast, splitLast_none data no]
  | cons c hrp ih => simp [splitLast, ih]

private theorem splitLast_sound (cs hrp data : List Char)
    (h : splitLast cs = some (hrp, data)) : cs = hrp ++ '1' :: data := by
  induction cs generalizing hrp data with
  | nil => simp [splitLast] at h
  | cons c cs ih =>
    simp only [splitLast] at h
    cases hs : splitLast cs with
    | none =>
      simp only [hs] at h
      split at h
      next hc => simp_all
      next hc => simp at h
    | some p =>
      obtain ⟨head, tail⟩ := p
      have eq : (c :: head, tail) = (hrp, data) := by simpa [hs] using h
      cases eq
      exact congrArg (List.cons c) (ih _ _ hs)

inductive DecodeError where
  | tooLong
  | mixedCase
  | missingSeparator
  | emptyHrp
  | hrpTooLong
  | invalidHrp
  | invalidCharacter
  | shortChecksum
  | checksumMismatch
  deriving Repr, DecidableEq, BEq

def lower (s : String) : String := String.ofList (s.toList.map Char.toLower)

private def validHrpChar (c : Char) : Bool := 33 ≤ c.toNat && c.toNat ≤ 126

/-- Decode with the caller's character limit and nine distinct rejection reasons. -/
def decode (limit : Nat) (s : String) : Except DecodeError (String × List Symbol × Variant) :=
  if s.length > limit then .error .tooLong
  else if s.toList.any Char.isUpper && s.toList.any Char.isLower then .error .mixedCase
  else match splitLast (s.toList.map Char.toLower) with
  | none => .error .missingSeparator
  | some (hrp, chars) =>
    if hrp = [] then .error .emptyHrp
    else if hrp.length > 83 then .error .hrpTooLong
    else if !hrp.all validHrpChar then .error .invalidHrp
    else match readChars chars with
    | none => .error .invalidCharacter
    | some ds =>
      if ds.length < 6 then .error .shortChecksum
      else
        let h := String.ofList hrp
        let data := ds.take (ds.length - 6)
        if verifyChecksum .bech32 h ds then .ok (h, data, .bech32)
        else if verifyChecksum .bech32m h ds then .ok (h, data, .bech32m)
        else .error .checksumMismatch

/-- S: success certifies the six checksum symbols actually present in the input. -/
theorem decode_sound (limit : Nat) (s hrp : String) (data : List Symbol) (v : Variant)
    (success : decode limit s = .ok (hrp, data, v)) :
    ∃ chk : List Symbol, chk.length = 6 ∧
      lower s = hrp ++ "1" ++ String.ofList ((data ++ chk).map charOf) ∧
      verifyChecksum v hrp (data ++ chk) = true := by
  unfold decode at success
  split at success
  next h => simp at success
  next h =>
    split at success
    next h => simp at success
    next h =>
      cases hs : splitLast (s.toList.map Char.toLower) with
      | none => simp [hs] at success
      | some p =>
        obtain ⟨hc, chars⟩ := p
        simp only [hs] at success
        split at success
        next h => simp at success
        next h =>
          split at success
          next h => simp at success
          next h =>
            split at success
            next h => simp at success
            next h =>
              cases hd : readChars chars with
              | none => simp [hd] at success
              | some ds =>
                simp only [hd] at success
                split at success
                next h => simp at success
                next long =>
                  have result : ∃ variant, verifyChecksum variant (String.ofList hc) ds = true ∧
                      (String.ofList hc, ds.take (ds.length - 6), variant) = (hrp, data, v) := by
                    split at success
                    next verified => exact ⟨.bech32, verified, Except.ok.inj success⟩
                    next notVerified =>
                      split at success
                      next verified => exact ⟨.bech32m, verified, Except.ok.inj success⟩
                      next notVerified => simp at success
                  obtain ⟨variant, verified, eq⟩ := result
                  cases eq
                  refine ⟨ds.drop (ds.length - 6), ?_, ?_, ?_⟩
                  · simp only [List.length_drop]
                    omega
                  · rw [List.take_append_drop]
                    apply String.toList_inj.mp
                    simp only [lower, String.toList_ofList, String.toList_append]
                    rw [chars_readChars chars ds hd]
                    simpa using splitLast_sound _ _ _ hs
                  · simpa only [List.take_append_drop] using verified

/-- R: round-trip for every caller limit and an HRP of at most 83 characters. -/
theorem decode_encode (limit : Nat) (hrp : String) (data : List Symbol) (v : Variant)
    (nonempty : hrp ≠ "")
    (range : ∀ c ∈ hrp.toList, 33 ≤ c.toNat ∧ c.toNat ≤ 126)
    (noUpper : ∀ c ∈ hrp.toList, c.isUpper = false)
    (maxHrp : hrp.length ≤ 83)
    (fits : hrp.length + data.length + 7 ≤ limit) :
    decode limit (encode hrp data v) = .ok (hrp, data, v) := by
  let ds := data ++ createChecksum hrp data v
  have checksumLength : (createChecksum hrp data v).length = 6 := by
    simp [createChecksum]
  have len : (encode hrp data v).length = hrp.length + data.length + 7 := by
    simp only [encode, String.length_append, String.length_ofList, List.length_map,
      List.length_append, checksumLength, show "1".length = 1 by decide]
    omega
  have upH : hrp.toList.any Char.isUpper = false := by
    exact List.any_eq_false.mpr (fun c hc => by simp [noUpper c hc])
  have upD : (ds.map charOf).any Char.isUpper = false := by
    apply List.any_eq_false.mpr
    intro c hc
    obtain ⟨x, _, rfl⟩ := List.mem_map.mp hc
    simp [(alphabet_properties x).2.1]
  have up : (encode hrp data v).toList.any Char.isUpper = false := by
    simpa only [encode, String.toList_append, String.toList_ofList, List.any_append,
      show "1".toList = ['1'] by rfl, List.any_cons, List.any_nil, Bool.or_false,
      show Char.isUpper '1' = false by decide, Bool.false_or, upH] using upD
  have lowerH : hrp.toList.map Char.toLower = hrp.toList := by
    have all : ∀ c ∈ hrp.toList, Char.toLower c = id c := by
      intro c hc
      have hn : ¬ (c.val ≥ 'A'.val ∧ c.val ≤ 'Z'.val) := by
        simpa only [Char.isUpper, decide_eq_false_iff_not] using noUpper c hc
      unfold Char.toLower
      split
      next h => exact False.elim (hn h)
      next h => rfl
    simpa only [List.map_id] using List.map_congr_left all
  have lowerD : (ds.map charOf).map Char.toLower = ds.map charOf := by
    have all : ∀ c ∈ ds.map charOf, Char.toLower c = id c := by
      intro c hc
      obtain ⟨x, _, rfl⟩ := List.mem_map.mp hc
      exact (alphabet_properties x).1
    simpa only [List.map_id] using List.map_congr_left all
  have normalized : (encode hrp data v).toList.map Char.toLower =
      hrp.toList ++ '1' :: ds.map charOf := by
    simp only [encode, String.toList_append, String.toList_ofList]
    change (hrp.toList ++ ['1'] ++ ds.map charOf).map Char.toLower = _
    rw [List.map_append, List.map_append, lowerH, lowerD]
    simp only [List.map_cons, List.map_nil, show Char.toLower '1' = '1' by decide,
      List.append_assoc, List.singleton_append]
  have split : splitLast ((encode hrp data v).toList.map Char.toLower) =
      some (hrp.toList, ds.map charOf) := by
    rw [normalized]
    apply splitLast_append
    intro c hc
    obtain ⟨x, _, rfl⟩ := List.mem_map.mp hc
    exact (alphabet_properties x).2.2
  have nonemptyList : hrp.toList ≠ [] := by
    intro h
    apply nonempty
    exact String.toList_inj.mp h
  have hrpOk : hrp.toList.all validHrpChar = true := by
    apply List.all_eq_true.mpr
    intro c hc
    simp only [validHrpChar, Bool.and_eq_true, decide_eq_true_eq]
    exact range c hc
  have enough : ¬ ds.length < 6 := by simp [ds, checksumLength]
  have dataPart : ds.take (ds.length - 6) = data := by
    simp [ds, checksumLength]
  have checked : verifyChecksum v hrp ds = true := verifyChecksum_createChecksum hrp data v
  unfold decode
  rw [ite_eq_right (by omega), up]
  simp only [Bool.false_and, Bool.false_eq_true, ↓reduceIte, split,
    nonemptyList, hrpOk, Bool.not_true, readChars_chars, enough,
    String.ofList_toList, dataPart]
  cases v with
  | bech32 => simp [checked, String.length_toList] <;> omega
  | bech32m =>
    have other : verifyChecksum .bech32 hrp ds = false := by
      unfold verifyChecksum at checked ⊢
      have residue := beq_iff_eq.mp checked
      simp [residue, Variant.constant]
    simp [other, checked, String.length_toList] <;> omega

end Bitcoin.Bech32
