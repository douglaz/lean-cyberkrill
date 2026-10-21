/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lean
import Init.Data.ByteArray.Lemmas

namespace Bitcoin.Base58

/- Little-endian natural-number digits. The public boundary reverses them. -/
private def value (base : Nat) : List Nat → Nat
  | [] => 0
  | d :: ds => d + base * value base ds

private def digits (base : Nat) (hb : 1 < base) (n : Nat) : List Nat :=
  if n = 0 then [] else n % base :: digits base hb (n / base)
termination_by n
decreasing_by exact Nat.div_lt_self (by omega) hb

private theorem value_digits (base : Nat) (hb : 1 < base) (n : Nat) :
    value base (digits base hb n) = n := by
  rw [digits]
  split
  next h => simp [value, h]
  next h =>
    simp only [value, value_digits base hb (n / base)]
    exact Nat.mod_add_div n base
termination_by n
decreasing_by exact Nat.div_lt_self (by omega) hb

private theorem digits_bound (base : Nat) (hb : 1 < base) (n : Nat) :
    ∀ d ∈ digits base hb n, d < base := by
  rw [digits]
  split
  · simp
  · intro d hd
    simp only [List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact Nat.mod_lt _ (by omega)
    · exact digits_bound base hb (n / base) d hd
termination_by n
decreasing_by exact Nat.div_lt_self (by omega) hb

/- Leading zeros are counted separately; `body` is the ordinary natural number. -/
private def zeroCount : List Nat → Nat
  | [] => 0
  | d :: ds => if d = 0 then zeroCount ds + 1 else 0

private def readNumber (base : Nat) (ds : List Nat) : Nat := value base ds.reverse

private def writeNumber (base : Nat) (hb : 1 < base) (zeros n : Nat) : List Nat :=
  List.replicate zeros 0 ++ (digits base hb n).reverse

private theorem value_eq_zero (base : Nat) (hb : 1 < base) (ds : List Nat) :
    value base ds = 0 ↔ ∀ d ∈ ds, d = 0 := by
  induction ds with
  | nil => simp [value]
  | cons d ds ih => simp [value, Nat.add_eq_zero_iff, Nat.mul_eq_zero, ih, show base ≠ 0 by omega]

private theorem digits_value (base : Nat) (hb : 1 < base) (ds : List Nat)
    (bound : ∀ d ∈ ds, d < base) :
    digits base hb (value base ds) = ds.take (ds.length - zeroCount ds.reverse) := by
  induction ds with
  | nil => simp [value, digits]
  | cons d ds ih =>
    have bd := bound d (by simp)
    have bt : ∀ x ∈ ds, x < base := fun x hx => bound x (by simp [hx])
    by_cases hv : value base ds = 0
    · have all := (value_eq_zero base hb ds).mp hv
      have z : zeroCount ds.reverse = ds.length := by
        have aux : ∀ xs : List Nat, (∀ x ∈ xs, x = 0) → zeroCount xs = xs.length := by
          intro xs hx
          induction xs with
          | nil => rfl
          | cons x xs hi => simp [zeroCount, hx x (by simp), hi (fun y hy => hx y (by simp [hy]))]
        simpa using aux ds.reverse (by simpa using all)
      have rev : zeroCount (ds.reverse ++ [d]) = ds.length + (if d = 0 then 1 else 0) := by
        have aux : ∀ xs : List Nat, (∀ x ∈ xs, x = 0) →
            zeroCount (xs ++ [d]) = xs.length + (if d = 0 then 1 else 0) := by
          intro xs hx
          induction xs with
          | nil => simp [zeroCount]
          | cons x xs hi =>
            simp [zeroCount, hx x (by simp), hi (fun y hy => hx y (by simp [hy])), Nat.add_comm, Nat.add_left_comm]
        simpa using aux ds.reverse (by simpa using all)
      by_cases hd : d = 0
      · simp only [value, hv, Nat.mul_zero, Nat.add_zero, List.reverse_cons, List.length_cons, rev]
        simp [hd, digits]
      · simp [value, hv, digits, hd, Nat.mod_eq_of_lt bd, Nat.div_eq_of_lt bd,
          List.reverse_cons, rev]
    · have hn : d + base * value base ds ≠ 0 := by
        intro h
        have := (Nat.add_eq_zero_iff.mp h).2
        have := (Nat.mul_eq_zero.mp this)
        omega
      have mod : (d + base * value base ds) % base = d := by simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt bd]
      have div : (d + base * value base ds) / base = value base ds := by simp [Nat.add_mul_div_left, Nat.div_eq_of_lt bd, show 0 < base by omega]
      have zr : zeroCount (ds.reverse ++ [d]) = zeroCount ds.reverse := by
        have aux : ∀ xs : List Nat, (∃ x ∈ xs, x ≠ 0) → zeroCount (xs ++ [d]) = zeroCount xs := by
          intro xs hx
          induction xs with
          | nil => simp at hx
          | cons x xs hi =>
            by_cases h : x = 0
            · simp only [List.mem_cons] at hx
              have ht : ∃ y ∈ xs, y ≠ 0 := by rcases hx with ⟨y, rfl | hy, hn⟩; exact False.elim (hn h); exact ⟨y, hy, hn⟩
              simp [zeroCount, h, hi ht]
            · simp [zeroCount, h]
        apply aux
        apply Classical.byContradiction
        intro h
        apply hv
        apply (value_eq_zero base hb ds).mpr
        intro x hx
        by_cases hz : x = 0
        · exact hz
        · exact False.elim (h ⟨x, by simpa using hx, hz⟩)
      have zl : zeroCount ds.reverse < ds.length := by
        have aux : ∀ xs : List Nat, zeroCount xs ≤ xs.length := by
          intro xs
          induction xs with
          | nil => exact Nat.le_refl _
          | cons x xs hi => simp only [zeroCount, List.length_cons]; split <;> omega
        have le := aux ds.reverse
        have ne : zeroCount ds.reverse ≠ ds.length := by
          intro eq
          have aux2 : ∀ xs : List Nat, zeroCount xs = xs.length → ∀ x ∈ xs, x = 0 := by
            intro xs
            induction xs with
            | nil => simp
            | cons x xs hi =>
              simp only [zeroCount, List.length_cons]
              split
              next h => intro e y hy; simp only [List.mem_cons] at hy; rcases hy with rfl | hy; exact h; exact hi (by omega) y hy
              next h => intro e; omega
          apply hv
          apply (value_eq_zero base hb ds).mpr
          simpa using aux2 ds.reverse (by simpa using eq)
        simp only [List.length_reverse] at le
        omega
      rw [value, digits, ite_eq_right hn, mod, div, ih bt]
      simp only [List.reverse_cons, zr, List.length_cons]
      have sub : ds.length + 1 - zeroCount ds.reverse = (ds.length - zeroCount ds.reverse) + 1 := by omega
      rw [sub, List.take_succ_cons]

private theorem zeros_le (ds : List Nat) : zeroCount ds ≤ ds.length := by
  induction ds with
  | nil => exact Nat.le_refl _
  | cons d ds ih => simp only [zeroCount, List.length_cons]; split <;> omega

private theorem zero_prefix (ds : List Nat) :
    ds.take (zeroCount ds) = List.replicate (zeroCount ds) 0 := by
  induction ds with
  | nil => rfl
  | cons d ds ih =>
    by_cases h : d = 0
    · simp [zeroCount, h, ih, List.replicate_succ]
    · simp [zeroCount, h]

private theorem write_read (base : Nat) (hb : 1 < base) (ds : List Nat)
    (bound : ∀ d ∈ ds, d < base) :
    writeNumber base hb (zeroCount ds) (readNumber base ds) = ds := by
  unfold writeNumber readNumber
  rw [digits_value base hb ds.reverse (by simpa using bound)]
  simp only [List.reverse_reverse, List.length_reverse, List.reverse_take]
  rw [Nat.sub_sub_self (zeros_le ds), ← zero_prefix, List.take_append_drop]

private theorem zeros_digits (base : Nat) (hb : 1 < base) (n : Nat) :
    zeroCount (digits base hb n).reverse = 0 := by
  have eq := digits_value base hb (digits base hb n) (digits_bound base hb n)
  rw [value_digits] at eq
  have len := congrArg List.length eq
  simp only [List.length_take] at len
  have le := zeros_le (digits base hb n).reverse
  simp only [List.length_reverse] at le
  omega

private theorem zeroCount_prefix (z : Nat) (ds : List Nat) :
    zeroCount (List.replicate z 0 ++ ds) = z + zeroCount ds := by
  induction z with
  | zero => simp
  | succ z ih => simp [List.replicate_succ, zeroCount, ih, Nat.add_comm, Nat.add_left_comm, Nat.add_assoc]

private theorem value_append_zeros (base : Nat) (ds : List Nat) (z : Nat) :
    value base (ds ++ List.replicate z 0) = value base ds := by
  have vz : value base (List.replicate z 0) = 0 := by
    induction z with
    | zero => rfl
    | succ z ih => simp [List.replicate_succ, value, ih]
  induction ds with
  | nil => exact vz
  | cons d ds ih => simp [value, ih]

private theorem read_write (base : Nat) (hb : 1 < base) (z n : Nat) :
    readNumber base (writeNumber base hb z n) = n := by
  simp [readNumber, writeNumber, List.reverse_append, value_append_zeros, value_digits]

private theorem zeros_write (base : Nat) (hb : 1 < base) (z n : Nat) :
    zeroCount (writeNumber base hb z n) = z := by
  simp [writeNumber, zeroCount_prefix, zeros_digits]

private def convert (base : Nat) (hb : 1 < base) (sourceBase : Nat) (ds : List Nat) : List Nat :=
  writeNumber base hb (zeroCount ds) (readNumber sourceBase ds)

private theorem convert_convert (a b : Nat) (ha : 1 < a) (hb : 1 < b)
    (ds : List Nat) (bound : ∀ d ∈ ds, d < a) :
    convert a ha b (convert b hb a ds) = ds := by
  simp only [convert, zeros_write, read_write]
  exact write_read a ha ds bound

private theorem convert_bound (base : Nat) (hb : 1 < base) (sourceBase : Nat) (ds : List Nat) :
    ∀ d ∈ convert base hb sourceBase ds, d < base := by
  intro d hd
  simp only [convert, writeNumber, List.mem_append, List.mem_replicate, List.mem_reverse] at hd
  rcases hd with ⟨_, rfl⟩ | hd
  · omega
  · exact digits_bound base hb _ d hd

private def alphabet : List Char := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toList

private def charOf (d : Nat) : Char := (alphabet[d]?).getD '?'

private def digitOf (c : Char) : Option Nat := alphabet.idxOf? c

private theorem digitOf_charOf (d : Nat) (hd : d < 58) : digitOf (charOf d) = some d := by
  have all : ∀ i : Fin 58, digitOf (charOf i.val) = some i.val := by decide
  exact all ⟨d, hd⟩

private def readChars : List Char → Option (List Nat)
  | [] => some []
  | c :: cs => do return (← digitOf c) :: (← readChars cs)

private theorem readChars_map (ds : List Nat) (bound : ∀ d ∈ ds, d < 58) :
    readChars (ds.map charOf) = some ds := by
  induction ds with
  | nil => rfl
  | cons d ds ih =>
    simp [List.map, readChars, digitOf_charOf d (bound d (by simp)),
      ih (fun x hx => bound x (by simp [hx]))]

private theorem readChars_ok (cs : List Char) (ds : List Nat) (h : readChars cs = some ds) :
    (∀ d ∈ ds, d < 58) ∧ ds.map charOf = cs := by
  induction cs generalizing ds with
  | nil => simp [readChars] at h; subst ds; simp
  | cons c cs ih =>
    cases hc : digitOf c with
    | none => simp [readChars, hc] at h
    | some d =>
      cases ht : readChars cs with
      | none => simp [readChars, hc, ht] at h
      | some tail =>
        have eq : d :: tail = ds := by simpa [readChars, hc, ht] using h
        subst ds
        obtain ⟨hd, he, _⟩ := List.idxOf?_eq_some_iff.mp hc
        have bd : d < 58 := by simpa [alphabet] using hd
        have ce : charOf d = c := by simpa [charOf, List.getElem?_eq_getElem hd] using he
        obtain ⟨bt, et⟩ := ih tail ht
        constructor
        · intro x hx; simp only [List.mem_cons] at hx; rcases hx with rfl | hx; exact bd; exact bt x hx
        · simp [ce, et]

/-- Bitcoin Base58, preserving every leading zero byte. -/
def base58Encode (b : ByteArray) : String :=
  String.ofList ((convert 58 (by decide) 256 (b.data.toList.map UInt8.toNat)).map charOf)

/-- Strict Base58: no whitespace or characters outside the Bitcoin alphabet. -/
def base58Decode (s : String) : Option ByteArray := do
  let ds ← readChars s.toList
  return ((convert 256 (by decide) 58 ds).map UInt8.ofNat).toByteArray

/-- B1: every byte array, including leading zeros, survives the public codec. -/
theorem base58Decode_encode (b : ByteArray) : base58Decode (base58Encode b) = some b := by
  have bound : ∀ d ∈ b.data.toList.map UInt8.toNat, d < 256 := by
    intro d hd
    obtain ⟨x, _, rfl⟩ := List.mem_map.mp hd
    exact x.toNat_lt
  have cv := convert_convert 256 58 (by decide) (by decide) _ bound
  have back : ((convert 256 (by decide) 58
      (convert 58 (by decide) 256 (b.data.toList.map UInt8.toNat))).map UInt8.ofNat).toByteArray = b := by
    rw [cv]
    apply ByteArray.ext
    simp [List.map_map, Function.comp_def]
  unfold base58Decode
  have chars : readChars (base58Encode b).toList =
      some (convert 58 (by decide) 256 (b.data.toList.map UInt8.toNat)) := by
    simpa only [base58Encode, String.toList_ofList] using
      readChars_map _ (convert_bound 58 (by decide) 256 (b.data.toList.map UInt8.toNat))
  rw [chars]
  exact congrArg some back

/-- B2: every accepted string is the encoder's canonical spelling. -/
theorem base58Encode_of_decode (s : String) (b : ByteArray)
    (h : base58Decode s = some b) : base58Encode b = s := by
  unfold base58Decode at h
  cases hd : readChars s.toList with
  | none => simp [hd] at h
  | some ds =>
    have eq : ((convert 256 (by decide) 58 ds).map UInt8.ofNat).toByteArray = b := by
      simpa [hd] using h
    rw [← eq]
    obtain ⟨bound, chars⟩ := readChars_ok s.toList ds hd
    have natmap : ((convert 256 (by decide) 58 ds).map UInt8.ofNat).map UInt8.toNat =
        convert 256 (by decide) 58 ds := by
      rw [List.map_map]
      have point : ∀ d ∈ convert 256 (by decide) 58 ds,
          (UInt8.toNat ∘ UInt8.ofNat) d = id d := by
        intro d hd
        exact UInt8.toNat_ofNat_of_lt' (convert_bound 256 (by decide) 58 ds d hd)
      simpa only [List.map_id] using List.map_congr_left point
    simp only [base58Encode, List.toList_data_toByteArray, natmap,
      convert_convert 58 256 (by decide) (by decide) ds bound, chars, String.ofList_toList]

end Bitcoin.Base58
