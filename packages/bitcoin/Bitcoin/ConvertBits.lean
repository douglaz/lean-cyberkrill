/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lean
import Init.Data.ByteArray.Lemmas

namespace Bitcoin.Bech32

private def writeBits {w : Nat} (x : BitVec w) : List Bool :=
  List.ofFn fun i : Fin w => x.getMsbD i.val

private def readBits (w : Nat) (bits : List Bool) : BitVec w :=
  (BitVec.ofBoolListBE (List.ofFn fun i : Fin w => bits.getD i.val false)).cast (by simp)

private theorem write_read (w : Nat) (bits : List Bool) :
    writeBits (readBits w bits) = bits.take w ++ List.replicate (w - bits.length) false := by
  apply List.ext_getElem
  · simp only [writeBits, List.length_ofFn, List.length_append, List.length_take,
      List.length_replicate]
    omega
  · intro i hi hj
    simp only [writeBits, List.length_ofFn] at hi
    by_cases hb : i < bits.length
    · have hm : i < min w bits.length := by omega
      simp [writeBits, readBits, List.getD_eq_getElem?_getD,
        hb, hm]
    · have hm : ¬ i < min w bits.length := by omega
      simp [writeBits, readBits, List.getElem_append, List.getD_eq_getElem?_getD,
        hb, hm]

private theorem read_write {w : Nat} (x : BitVec w) : readBits w (writeBits x) = x := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have hr : w - 1 - i < w := by omega
  have hr2 : w - 1 - (w - 1 - i) = i := by omega
  simp only [readBits, BitVec.getLsbD_cast, BitVec.getLsbD_ofBoolListBE,
    List.length_ofFn, decide_eq_true hi, Bool.true_and]
  simp [writeBits, List.getD_eq_getElem?_getD, hr, BitVec.getMsbD, hr2]

private def pack (w : Nat) (hw : 0 < w) (bits : List Bool) : List (BitVec w) :=
  if bits = [] then [] else readBits w bits :: pack w hw (bits.drop w)
termination_by bits.length
decreasing_by
  simp only [List.length_drop]
  have : 0 < bits.length := List.length_pos_iff.mpr ‹bits ≠ []›
  omega

private def unpack (w : Nat) (hw : 0 < w) (bits : List Bool) : List (BitVec w) :=
  if bits.length < w then [] else readBits w bits :: unpack w hw (bits.drop w)
termination_by bits.length
decreasing_by simp only [List.length_drop]; omega

private theorem pack_flat (w : Nat) (hw : 0 < w) (bits : List Bool) :
    ∃ padding, padding < w ∧
      ((pack w hw bits).map writeBits).flatten = bits ++ List.replicate padding false := by
  rw [pack]
  split
  next h => exact ⟨0, hw, by simp [h]⟩
  next h =>
    by_cases short : bits.length ≤ w
    · have drop : bits.drop w = [] := List.drop_eq_nil_iff.mpr short
      refine ⟨w - bits.length, ?_, ?_⟩
      · have : 0 < bits.length := List.length_pos_iff.mpr h
        omega
      · simp [List.map_cons, List.flatten_cons, write_read, drop, pack,
          List.take_of_length_le short]
    · obtain ⟨padding, bound, eq⟩ := pack_flat w hw (bits.drop w)
      refine ⟨padding, bound, ?_⟩
      simp only [List.map_cons, List.flatten_cons, write_read, eq]
      have sub : w - bits.length = 0 := by omega
      simp [sub, ← List.append_assoc]
termination_by bits.length
decreasing_by simp only [List.length_drop]; have : 0 < bits.length := List.length_pos_iff.mpr ‹bits ≠ []›; omega

private theorem unpack_flat {w : Nat} (hw : 0 < w) (xs : List (BitVec w))
    (tail : List Bool) (short : tail.length < w) :
    unpack w hw ((xs.map writeBits).flatten ++ tail) = xs := by
  induction xs with
  | nil => simp [unpack, short]
  | cons x xs ih =>
    have len : (writeBits x).length = w := by simp [writeBits]
    have whole : ¬ (writeBits x ++ (xs.map writeBits).flatten ++ tail).length < w := by
      simp only [List.length_append, len]
      omega
    rw [List.map_cons, List.flatten_cons, unpack, ite_eq_right whole]
    have rd : readBits w (writeBits x ++ (xs.map writeBits).flatten ++ tail) = x := by
      have eq : readBits w (writeBits x ++ (xs.map writeBits).flatten ++ tail) =
          readBits w (writeBits x) := by
        apply BitVec.eq_of_getMsbD_eq
        intro i hi
        simp [readBits, List.getD_eq_getElem?_getD, List.getElem?_append, len, hi]
      rw [eq, read_write]
    rw [rd]
    have drop : (writeBits x ++ (xs.map writeBits).flatten ++ tail).drop w =
        (xs.map writeBits).flatten ++ tail := by
      rw [List.append_assoc, List.drop_append_of_le_length (by omega)]
      simp [← len]
    rw [drop, ih]

inductive PaddingError where
  | excessPadding
  | nonZeroPadding
  deriving Repr, DecidableEq, BEq

/-- Regroup bytes most-significant bit first, padding the final symbol with zero bits. -/
def convertbits8to5 (bs : ByteArray) : List (BitVec 5) :=
  pack 5 (by decide) ((bs.data.toList.map fun b => writeBits b.toBitVec).flatten)

/-- Emit complete bytes and drop all incomplete trailing bits, unchecked. -/
def fesToBytesLax (symbols : List (BitVec 5)) : ByteArray :=
  ⟨((unpack 8 (by decide) ((symbols.map writeBits).flatten)).map UInt8.ofBitVec).toArray⟩

/-- Strict regrouping. Excess padding takes precedence over non-zero padding. -/
def convertbits5to8 (symbols : List (BitVec 5)) : Except PaddingError ByteArray :=
  let bits := (symbols.map writeBits).flatten
  if bits.length % 8 ≥ 5 then .error .excessPadding
  else if (bits.drop (bits.length / 8 * 8)).any id then .error .nonZeroPadding
  else .ok (fesToBytesLax symbols)

/-- L: regrouping zero-padded symbols laxly recovers every original byte. -/
theorem fesToBytesLax_convertbits8to5 (bs : ByteArray) :
    fesToBytesLax (convertbits8to5 bs) = bs := by
  obtain ⟨padding, bound, eq⟩ := pack_flat 5 (by decide)
    ((bs.data.toList.map fun b => writeBits b.toBitVec).flatten)
  unfold fesToBytesLax convertbits8to5
  rw [eq]
  have bytes : (bs.data.toList.map fun b => writeBits b.toBitVec).flatten =
      ((bs.data.toList.map UInt8.toBitVec).map writeBits).flatten := by
    simp only [List.map_map, Function.comp_def]
  rw [bytes, unpack_flat (by decide) _ _ (by simp; omega)]
  cases bs with
  | mk data =>
    congr 1
    rw [List.map_map]
    change ((data.toList.map (fun b : UInt8 => b)).toArray) = data
    simp

/-- C: strict decoding of the public zero-padded byte encoder always succeeds. -/
theorem convertbits5to8_convertbits8to5 (bs : ByteArray) :
    convertbits5to8 (convertbits8to5 bs) = .ok bs := by
  obtain ⟨padding, bound, eq⟩ := pack_flat 5 (by decide)
    ((bs.data.toList.map fun b => writeBits b.toBitVec).flatten)
  have len : (bs.data.toList.map fun b => writeBits b.toBitVec).flatten.length =
      bs.size * 8 := by
    have aux (xs : List UInt8) :
        (xs.map fun b => writeBits b.toBitVec).flatten.length = xs.length * 8 := by
      induction xs with
      | nil => rfl
      | cons x xs ih =>
        have lx : (writeBits x.toBitVec).length = 8 := by simp [writeBits]
        simp only [List.map_cons, List.flatten_cons, List.length_append, lx, ih,
          List.length_cons, Nat.add_mul]
        omega
    exact aux bs.data.toList
  have size : ((convertbits8to5 bs).map writeBits).flatten.length = bs.size * 8 + padding := by
    simp only [convertbits8to5, eq, List.length_append, List.length_replicate, len]
  have rem : ((convertbits8to5 bs).map writeBits).flatten.length % 8 = padding := by
    rw [size]
    omega
  have start : ((convertbits8to5 bs).map writeBits).flatten.length / 8 * 8 = bs.size * 8 := by
    rw [size]
    omega
  unfold convertbits5to8
  dsimp only
  rw [rem, ite_eq_right (by omega), start]
  have drop : (((convertbits8to5 bs).map writeBits).flatten).drop (bs.size * 8) =
      List.replicate padding false := by
    change (((pack 5 (by decide) _).map writeBits).flatten).drop _ = _
    rw [eq, ← len, List.drop_left]
  rw [drop]
  simp [fesToBytesLax_convertbits8to5]

/-- The padded encoder adds fewer than five bits, so addresses fit their 90-character limit. -/
theorem convertbits8to5_length (bs : ByteArray) :
    5 * (convertbits8to5 bs).length ≤ 8 * bs.size + 4 := by
  have flatLength {w : Nat} (xs : List (BitVec w)) :
      (xs.map writeBits).flatten.length = w * xs.length := by
    induction xs with
    | nil => simp
    | cons x xs ih =>
      simp only [List.map_cons, List.flatten_cons, List.length_append,
        writeBits, List.length_ofFn, ih, List.length_cons, Nat.mul_add, Nat.mul_one]
      omega
  obtain ⟨padding, bound, eq⟩ := pack_flat 5 (by decide)
    ((bs.data.toList.map fun b => writeBits b.toBitVec).flatten)
  have bitsLength : (bs.data.toList.map fun b => writeBits b.toBitVec).flatten.length =
      8 * bs.size := by
    simpa only [List.map_map, Function.comp_def, List.length_map,
      Array.length_toList, ByteArray.size] using flatLength (bs.data.toList.map UInt8.toBitVec)
  have h := congrArg List.length eq
  rw [flatLength, List.length_append, List.length_replicate, bitsLength] at h
  change 5 * (convertbits8to5 bs).length = 8 * bs.size + padding at h
  omega

end Bitcoin.Bech32
