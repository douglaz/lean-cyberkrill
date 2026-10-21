/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lean

namespace Bitcoin.Bech32

abbrev Symbol := BitVec 5

inductive Variant where
  | bech32
  | bech32m
  deriving Repr, DecidableEq, BEq

def Variant.constant : Variant → BitVec 30
  | .bech32 => 1
  | .bech32m => 0x2bc830a3

/-- One reference-polymod iteration; the state has exactly thirty bits. -/
def polymodStep (chk value : BitVec 30) : BitVec 30 :=
  let b := chk >>> 25
  let next := ((chk &&& 0x1ffffff) <<< 5) ^^^ value
  ([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3] : List (BitVec 30)).zipIdx.foldl
    (fun acc (gen, i) => acc ^^^ (if b.getLsbD i then gen else 0)) next

/-- BIP173's left-to-right checksum fold, initially one. -/
def polymod (values : List Nat) : BitVec 30 :=
  (values.map (BitVec.ofNat 30)).foldl polymodStep 1

def hrpExpand (hrp : String) : List Nat :=
  hrp.toList.map (fun c => c.toNat >>> 5) ++ [0] ++
    hrp.toList.map (fun c => c.toNat &&& 31)

def verifyChecksum (v : Variant) (hrp : String) (d : List Symbol) : Bool :=
  polymod (hrpExpand hrp ++ d.map BitVec.toNat) == v.constant

def createChecksum (hrp : String) (data : List Symbol) (v : Variant) : List Symbol :=
  let p := polymod (hrpExpand hrp ++ data.map BitVec.toNat ++ [0,0,0,0,0,0]) ^^^ v.constant
  (List.range 6).map fun i => (p >>> (5 * (5 - i))).setWidth 5

private theorem select_xor (a b : Bool) (k : BitVec 30) :
    (if a ^^ b then k else 0) = (if a then k else 0) ^^^ (if b then k else 0) := by
  cases a <;> cases b <;> simp

private theorem mask_xor (a b mask : BitVec 30) :
    (a ^^^ b) &&& mask = (a &&& mask) ^^^ (b &&& mask) := by
  apply BitVec.eq_of_getLsbD_eq
  intro i _
  simp [Bool.and_xor_distrib_right]

private theorem step_linear (a b x y : BitVec 30) :
    polymodStep (a ^^^ b) (x ^^^ y) = polymodStep a x ^^^ polymodStep b y := by
  simp only [polymodStep, List.zipIdx_cons, List.zipIdx_nil, List.foldl_cons,
    List.foldl_nil, BitVec.ushiftRight_xor_distrib, BitVec.getLsbD_xor,
    select_xor, mask_xor, BitVec.shiftLeft_xor_distrib]
  ac_rfl

private theorem fold_linear (xs ys : List (BitVec 30)) (a b : BitVec 30)
    (len : xs.length = ys.length) :
    (List.zipWith (· ^^^ ·) xs ys).foldl polymodStep (a ^^^ b) =
      xs.foldl polymodStep a ^^^ ys.foldl polymodStep b := by
  induction xs generalizing ys a b with
  | nil => cases ys <;> simp_all
  | cons x xs ih =>
    cases ys with
    | nil => simp at len
    | cons y ys =>
      simp only [List.zipWith_cons_cons, List.foldl_cons, step_linear]
      apply ih
      simpa using len

private theorem fold_split (xs : List (BitVec 30)) (a : BitVec 30) :
    xs.foldl polymodStep a =
      (List.replicate xs.length 0).foldl polymodStep a ^^^ xs.foldl polymodStep 0 := by
  have z : List.zipWith (fun x y : BitVec 30 => x ^^^ y) (List.replicate xs.length 0) xs = xs := by
    induction xs with
    | nil => rfl
    | cons x xs ih =>
      simp only [List.length_cons, List.replicate_succ, List.zipWith_cons_cons,
        List.cons.injEq]
      exact ⟨BitVec.zero_xor, ih⟩
  have h := fold_linear (List.replicate xs.length 0) xs a 0 (by simp)
  have az : a ^^^ (0 : BitVec 30) = a := BitVec.xor_zero
  rw [z, az] at h
  exact h

private theorem pack_six (p : BitVec 30) :
    (((List.range 6).map fun i => ((p >>> (5 * (5 - i))).setWidth 5).setWidth 30).foldl
      polymodStep 0) = p := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have cases : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨
      i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨ i = 13 ∨ i = 14 ∨
      i = 15 ∨ i = 16 ∨ i = 17 ∨ i = 18 ∨ i = 19 ∨ i = 20 ∨ i = 21 ∨
      i = 22 ∨ i = 23 ∨ i = 24 ∨ i = 25 ∨ i = 26 ∨ i = 27 ∨ i = 28 ∨ i = 29 := by omega
  rcases cases with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [List.range_succ, polymodStep, BitVec.getLsbD_setWidth, BitVec.getLsbD_ofNat]

private theorem finish_checksum (state c : BitVec 30) :
    let p := (List.replicate 6 0).foldl polymodStep state ^^^ c
    ((List.range 6).map fun i => ((p >>> (5 * (5 - i))).setWidth 5).setWidth 30).foldl
      polymodStep state = c := by
  dsimp only
  rw [fold_split]
  simp only [List.length_map, List.length_range, pack_six]
  rw [← BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor]

/-- The six appended checksum symbols produce exactly the selected residue. -/
theorem verifyChecksum_createChecksum (hrp : String) (data : List Symbol) (v : Variant) :
    verifyChecksum v hrp (data ++ createChecksum hrp data v) = true := by
  unfold verifyChecksum createChecksum polymod
  simp only [List.map_append, List.map_map, List.foldl_append]
  have widen (x : Symbol) : BitVec.ofNat 30 x.toNat = x.setWidth 30 := by
    apply BitVec.eq_of_toNat_eq
    simp
  simp only [Function.comp_def, widen]
  have zeros : List.map (BitVec.ofNat 30) [0,0,0,0,0,0] = List.replicate 6 0 := rfl
  rw [zeros, finish_checksum]
  simp

end Bitcoin.Bech32
