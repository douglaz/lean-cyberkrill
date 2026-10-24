/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bip39WordlistProofs
import Bitcoin.CompactSize
import Bitcoin.ByteArrayRepr
import Init.Data.ByteArray.Lemmas
import Sha256

namespace Bitcoin.Bip39

inductive Error where
  | badEntropyLength
  | badWordCount
  | unknownWord (position : Nat)
  | badChecksum
  deriving Repr, DecidableEq, BEq

/-- The five entropy lengths permitted by BIP39, in bytes. -/
def validEntropyLength (n : Nat) : Prop := n = 16 ∨ n = 20 ∨ n = 24 ∨ n = 28 ∨ n = 32

/-- The five permitted mnemonic lengths. -/
def validWordCount (n : Nat) : Prop := n = 12 ∨ n = 15 ∨ n = 18 ∨ n = 21 ∨ n = 24

instance (n : Nat) : Decidable (validEntropyLength n) := inferInstanceAs (Decidable (_ ∨ _))
instance (n : Nat) : Decidable (validWordCount n) := inferInstanceAs (Decidable (_ ∨ _))

/-- Big-endian value, including any leading zero bytes. -/
def beNat (bytes : ByteArray) : Nat := CompactSize.decodeLE bytes.data.toList.reverse

private def fromNat (width n : Nat) : ByteArray :=
  ⟨(CompactSize.unsignedLE width n).reverse.toArray⟩

-- Fixed-width radix conversion preserves leading zero digits.
private def digitsLE (base : Nat) : Nat → Nat → List Nat
  | 0, _ => []
  | width + 1, n => n % base :: digitsLE base width (n / base)

private def valueLE (base : Nat) : List Nat → Nat
  | [] => 0
  | x :: xs => x + base * valueLE base xs

/-- Generic big-endian radix value of a list of natural-number digits. -/
def beDigits (base : Nat) (xs : List Nat) : Nat := valueLE base xs.reverse

private def indices (count n : Nat) : List Nat := (digitsLE 2048 count n).reverse

private def lookup : List String → String → Option Nat
  | [], _ => none
  | a :: rest, word => if word = a then some 0 else (lookup rest word).map Nat.succ

private def lookupWords : Nat → List String → Except Error (List Nat)
  | _, [] => .ok []
  | position, word :: rest =>
    match lookup wordlist word with
    | none => .error (.unknownWord position)
    | some i => (lookupWords (position + 1) rest).map (i :: ·)

private def checksum (e : ByteArray) (cs : Nat) : Nat :=
  beNat (Sha256.hash e) / 2 ^ (256 - cs)

/-- Encode exactly 16, 20, 24, 28 or 32 supplied bytes as English BIP39 words.
No entropy is generated. Bits and 11-bit word indices are big-endian. -/
def entropyToMnemonic (e : ByteArray) : Except Error (List String) :=
  if validEntropyLength e.size then
    let cs := e.size / 4
    .ok ((indices (e.size * 3 / 4) (beNat e * 2 ^ cs + checksum e cs)).map
      (fun i => wordlist[i]!))
  else .error .badEntropyLength

/-- Decode exact, already-split English words. Positions are zero-based.
Checks run in order: word count, first unknown word from left to right, checksum.
No case folding, trimming, Unicode normalisation or prefix expansion occurs. -/
def mnemonicToEntropy (ws : List String) : Except Error ByteArray :=
  if validWordCount ws.length then
    match lookupWords 0 ws with
    | .error error => .error error
    | .ok idx =>
      let cs := ws.length / 3
      let n := beDigits 2048 idx
      let e := fromNat (ws.length * 4 / 3) (n / 2 ^ cs)
      if n % 2 ^ cs = checksum e cs then .ok e else .error .badChecksum
  else .error .badWordCount

private theorem fromNat_size (width n : Nat) : (fromNat width n).size = width := by
  change (CompactSize.unsignedLE width n).reverse.toArray.size = width
  simp [CompactSize.unsignedLE_length]

private theorem beNat_fromNat (width n : Nat) :
    beNat (fromNat width n) = n % 256 ^ width := by
  simp [beNat, fromNat, CompactSize.decodeLE_unsignedLE]

private theorem fromNat_beNat (e : ByteArray) : fromNat e.size (beNat e) = e := by
  have h := CompactSize.unsignedLE_decodeLE e.data.toList.reverse
  simp only [List.length_reverse, Array.length_toList] at h
  unfold fromNat beNat
  rw [show e.size = e.data.size from rfl, h]
  cases e
  simp

private theorem beNat_lt (e : ByteArray) : beNat e < 256 ^ e.size := by
  simpa [beNat] using CompactSize.decodeLE_lt e.data.toList.reverse

private theorem digits_length (base width n : Nat) : (digitsLE base width n).length = width := by
  induction width generalizing n with
  | zero => rfl
  | succ width ih => simp [digitsLE, ih]

private theorem value_digits (base width n : Nat) :
    valueLE base (digitsLE base width n) = n % base ^ width := by
  induction width generalizing n with
  | zero => simp [digitsLE, valueLE, Nat.mod_one]
  | succ width ih =>
    simp only [digitsLE, valueLE, ih]
    rw [Nat.pow_succ', Nat.mod_mul]

private theorem digits_value (base : Nat) (xs : List Nat) (hb : 0 < base)
    (bound : ∀ x ∈ xs, x < base) : digitsLE base xs.length (valueLE base xs) = xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    have hx := bound x (by simp)
    have ht : ∀ y ∈ xs, y < base := fun y hy => bound y (by simp [hy])
    have low : (x + base * valueLE base xs) % base = x := by
      simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hx]
    have high : (x + base * valueLE base xs) / base = valueLE base xs := by
      simp [Nat.add_mul_div_left, Nat.div_eq_of_lt hx, hb]
    simp [digitsLE, valueLE, low, high, ih ht]

private theorem digits_bound (base width n : Nat) (hb : 0 < base) :
    ∀ x ∈ digitsLE base width n, x < base := by
  induction width generalizing n with
  | zero => simp [digitsLE]
  | succ width ih =>
    intro x hx
    simp only [digitsLE, List.mem_cons] at hx
    rcases hx with rfl | hx
    · exact Nat.mod_lt _ hb
    · exact ih _ _ hx

private theorem value_lt (base : Nat) (xs : List Nat) (_hb : 0 < base)
    (bound : ∀ x ∈ xs, x < base) : valueLE base xs < base ^ xs.length := by
  induction xs with
  | nil => simp [valueLE]
  | cons x xs ih =>
    have hx := bound x (by simp)
    have ht := ih (fun y hy => bound y (by simp [hy]))
    simp only [valueLE, List.length_cons, Nat.pow_succ']
    have hle : valueLE base xs + 1 ≤ base ^ xs.length := by omega
    have hm := Nat.mul_le_mul_left base hle
    simp only [Nat.mul_add, Nat.mul_one] at hm
    omega

private theorem indices_length (count n : Nat) : (indices count n).length = count := by
  simp [indices, digits_length]

private theorem indices_bound (count n : Nat) : ∀ i ∈ indices count n, i < 2048 := by
  simpa [indices] using digits_bound 2048 count n (by decide)

private theorem beDigits_indices (count n : Nat) :
    beDigits 2048 (indices count n) = n % 2048 ^ count := by
  simp [beDigits, indices, value_digits]

private theorem indices_beDigits (idx : List Nat) (bound : ∀ i ∈ idx, i < 2048) :
    indices idx.length (beDigits 2048 idx) = idx := by
  unfold indices beDigits
  rw [← List.length_reverse (as := idx)]
  rw [digits_value _ _ (by decide) (by simpa using bound), List.reverse_reverse]

private theorem beDigits_lt (idx : List Nat) (bound : ∀ i ∈ idx, i < 2048) :
    beDigits 2048 idx < 2048 ^ idx.length := by
  simpa [beDigits] using value_lt 2048 idx.reverse (by decide) (by simpa using bound)

private theorem lookup_get (dict : List String) (nodup : dict.Nodup) (i : Nat)
    (hi : i < dict.length) : lookup dict dict[i] = some i := by
  induction dict generalizing i with
  | nil => simp at hi
  | cons a rest ih =>
    have hn := List.nodup_cons.mp nodup
    cases i with
    | zero => simp [lookup]
    | succ i =>
      have bound : i < rest.length := by simpa using hi
      have ne : rest[i] ≠ a := by
        intro eq
        exact hn.1 (eq ▸ List.getElem_mem bound)
      simp [lookup, ne, ih hn.2 i bound]

private theorem lookup_sound (dict : List String) (word : String) (i : Nat)
    (h : lookup dict word = some i) : ∃ hi : i < dict.length, dict[i] = word := by
  induction dict generalizing i with
  | nil => simp [lookup] at h
  | cons a rest ih =>
    unfold lookup at h
    split at h
    next eq =>
      have hz : i = 0 := by simpa using h.symm
      subst i
      exact ⟨by simp, eq.symm⟩
    next ne =>
      cases hr : lookup rest word with
      | none => simp [hr] at h
      | some j =>
        have he : i = j + 1 := by simpa [hr] using h.symm
        subst i
        obtain ⟨hj, eq⟩ := ih j hr
        exact ⟨by simpa using Nat.succ_lt_succ hj, by simpa using eq⟩

private theorem lookupWords_map (idx : List Nat) (bound : ∀ i ∈ idx, i < 2048)
    (position : Nat) :
    lookupWords position (idx.map (fun i => wordlist[i]!)) = .ok idx := by
  induction idx generalizing position with
  | nil => rfl
  | cons i idx ih =>
    have hi : i < wordlist.length := by rw [wordlist_length]; exact bound i (by simp)
    have hl : lookup wordlist wordlist[i]! = some i := by
      simpa only [getElem!_pos wordlist i hi] using lookup_get wordlist wordlist_nodup i hi
    simp only [List.map_cons, lookupWords, hl,
      ih (fun j hj => bound j (by simp [hj])), Except.map]

private theorem lookupWords_sound (ws : List String) (idx : List Nat) (position : Nat)
    (h : lookupWords position ws = .ok idx) :
    ws = idx.map (fun i => wordlist[i]!) ∧ (∀ i ∈ idx, i < 2048) := by
  induction ws generalizing idx position with
  | nil => simp [lookupWords] at h; subst idx; simp
  | cons word ws ih =>
    unfold lookupWords at h
    cases hl : lookup wordlist word with
    | none => simp [hl] at h
    | some i =>
      cases ht : lookupWords (position + 1) ws with
      | error error => simp [hl, ht, Except.map] at h
      | ok tail =>
        have he : idx = i :: tail := by simpa [hl, ht, Except.map] using h.symm
        subst idx
        obtain ⟨eq, bound⟩ := ih tail (position + 1) ht
        obtain ⟨hi, hw⟩ := lookup_sound wordlist word i hl
        have hi' : i < 2048 := by simpa [wordlist_length] using hi
        refine ⟨?_, ?_⟩
        · simp only [List.map_cons, getElem!_pos wordlist i hi, hw, eq]
        · intro j hj
          rcases List.mem_cons.mp hj with rfl | hj
          · exact hi'
          · exact bound j hj

private theorem entropy_lengths (n : Nat) (h : validEntropyLength n) :
    validWordCount (n * 3 / 4) ∧ (n * 3 / 4) * 4 / 3 = n ∧
    (n * 3 / 4) / 3 = n / 4 ∧
    2048 ^ (n * 3 / 4) = 256 ^ n * 2 ^ (n / 4) ∧ n / 4 ≤ 256 := by
  rcases h with rfl | rfl | rfl | rfl | rfl <;> decide

private theorem word_lengths (n : Nat) (h : validWordCount n) :
    validEntropyLength (n * 4 / 3) ∧ (n * 4 / 3) * 3 / 4 = n ∧
    (n * 4 / 3) / 4 = n / 3 ∧
    2048 ^ n = 256 ^ (n * 4 / 3) * 2 ^ (n / 3) ∧
    (n * 11 - n / 3) / 8 = n * 4 / 3 := by
  rcases h with rfl | rfl | rfl | rfl | rfl <;> decide

private theorem checksum_lt (e : ByteArray) (cs : Nat) (hcs : cs ≤ 256) :
    checksum e cs < 2 ^ cs := by
  have hb : beNat (Sha256.hash e) < 2 ^ 256 := by
    simpa only [Sha256.hash_size, show 256 ^ 32 = 2 ^ 256 by decide] using
      beNat_lt (Sha256.hash e)
  unfold checksum
  apply (Nat.div_lt_iff_lt_mul (Nat.two_pow_pos (256 - cs))).mpr
  rw [← Nat.pow_add]
  simpa only [Nat.add_sub_of_le hcs] using hb

private theorem combined_lt (e : ByteArray) (cs : Nat) (hcs : cs ≤ 256) :
    beNat e * 2 ^ cs + checksum e cs < 256 ^ e.size * 2 ^ cs := by
  have hb := beNat_lt e
  have hc := checksum_lt e cs hcs
  have hs : beNat e + 1 ≤ 256 ^ e.size := by omega
  have hm := Nat.mul_le_mul_right (2 ^ cs) hs
  simp only [Nat.add_mul, Nat.one_mul] at hm
  omega

private theorem combined_div (e : ByteArray) (cs : Nat) (hcs : cs ≤ 256) :
    (beNat e * 2 ^ cs + checksum e cs) / 2 ^ cs = beNat e := by
  have hc := checksum_lt e cs hcs
  rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.two_pow_pos cs), Nat.div_eq_of_lt hc]
  omega

private theorem combined_mod (e : ByteArray) (cs : Nat) (hcs : cs ≤ 256) :
    (beNat e * 2 ^ cs + checksum e cs) % 2 ^ cs = checksum e cs := by
  simp [Nat.add_mod, Nat.mod_eq_of_lt (checksum_lt e cs hcs)]

/-- T1: every permitted entropy length encodes with the specified word count and decodes exactly. -/
theorem mnemonicToEntropy_entropyToMnemonic (e : ByteArray)
    (h : validEntropyLength e.size) :
    ∃ ws, entropyToMnemonic e = .ok ws ∧ ws.length = e.size * 3 / 4 ∧
      mnemonicToEntropy ws = .ok e := by
  let idx := indices (e.size * 3 / 4) (beNat e * 2 ^ (e.size / 4) + checksum e (e.size / 4))
  let ws := idx.map (fun i => wordlist[i]!)
  obtain ⟨hc, hn, hcs, hp, hbound⟩ := entropy_lengths e.size h
  have len : ws.length = e.size * 3 / 4 := by simp [ws, idx, indices_length]
  have read : lookupWords 0 ws = .ok idx := lookupWords_map _ (indices_bound _ _) _
  have numeric : beDigits 2048 idx = beNat e * 2 ^ (e.size / 4) + checksum e (e.size / 4) := by
    dsimp only [idx]
    rw [beDigits_indices, Nat.mod_eq_of_lt]
    rw [hp]
    exact combined_lt e _ hbound
  refine ⟨ws, ?_, len, ?_⟩
  · unfold entropyToMnemonic
    split
    · rfl
    · contradiction
  · unfold mnemonicToEntropy
    rw [len, ite_eq_left hc, read]
    dsimp only
    rw [numeric, hcs, hn,
      combined_div e _ hbound, fromNat_beNat, combined_mod e _ hbound]
    simp

/-- T2: successful decoding re-encodes to exactly the original, already-split words. -/
theorem entropyToMnemonic_mnemonicToEntropy (ws : List String) (e : ByteArray)
    (h : mnemonicToEntropy ws = .ok e) : entropyToMnemonic e = .ok ws := by
  unfold mnemonicToEntropy at h
  split at h
  next hc =>
    cases hr : lookupWords 0 ws with
    | error error => simp [hr] at h
    | ok idx =>
      simp only [hr] at h
      split at h
      next check =>
        have he : fromNat (ws.length * 4 / 3) (beDigits 2048 idx / 2 ^ (ws.length / 3)) = e := by
          simpa only [Except.ok.injEq] using h
        obtain ⟨eq, bound⟩ := lookupWords_sound ws idx 0 hr
        have length : idx.length = ws.length := by rw [eq, List.length_map]
        obtain ⟨hv, hn, hcs, hp, _⟩ := word_lengths ws.length hc
        have quotient : beDigits 2048 idx / 2 ^ (ws.length / 3) < 256 ^ (ws.length * 4 / 3) := by
          apply (Nat.div_lt_iff_lt_mul (Nat.two_pow_pos _)).mpr
          rw [← hp, ← length]
          exact beDigits_lt idx bound
        have size : e.size = ws.length * 4 / 3 := by rw [← he, fromNat_size]
        have value : beNat e = beDigits 2048 idx / 2 ^ (ws.length / 3) := by
          rw [← he, beNat_fromNat, Nat.mod_eq_of_lt quotient]
        have check' : checksum e (ws.length / 3) = beDigits 2048 idx % 2 ^ (ws.length / 3) := by
          rw [← he]
          exact check.symm
        unfold entropyToMnemonic
        rw [size]
        split
        · dsimp only
          rw [hcs, hn, value, check', Nat.mul_comm (_ / _), Nat.div_add_mod]
          rw [← length, indices_beDigits idx bound, ← eq]
        · contradiction
      next check => simp at h
  next hc => simp at h

/-- T3: independently specified big-endian indices with a mismatched SHA-256 prefix are rejected.
The supplied entropy has exactly the byte width and value spelled by those indices. -/
theorem mnemonicToEntropy_checksum_mismatch
    (ws : List String) (idx : List Nat) (e : ByteArray)
    (hcount : validWordCount ws.length)
    (hidx : ∀ i ∈ idx, i < 2048)
    (hws : ws = idx.map (fun i => wordlist[i]!))
    (he_size : e.size = (ws.length * 11 - ws.length / 3) / 8)
    (he : beNat e = beDigits 2048 idx / 2 ^ (ws.length / 3))
    (hbad : beDigits 2048 idx % 2 ^ (ws.length / 3) ≠
      beNat (Sha256.hash e) / 2 ^ (256 - ws.length / 3)) :
    mnemonicToEntropy ws = .error .badChecksum := by
  have read : lookupWords 0 ws = .ok idx := by rw [hws]; exact lookupWords_map idx hidx 0
  obtain ⟨_, _, _, _, width⟩ := word_lengths ws.length hcount
  have entropy : fromNat (ws.length * 4 / 3) (beDigits 2048 idx / 2 ^ (ws.length / 3)) = e := by
    rw [← width, ← he_size, ← he, fromNat_beNat]
  unfold mnemonicToEntropy
  rw [ite_eq_left hcount, read]
  dsimp only
  rw [entropy]
  unfold checksum
  rw [ite_eq_right hbad]

end Bitcoin.Bip39
