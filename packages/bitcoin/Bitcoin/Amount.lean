/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lean

namespace Bitcoin

/-- Nonnegative, unbounded millisatoshis. Wire and policy bounds belong to callers. -/
structure Amount where
  msat : Nat
  deriving Repr, DecidableEq

namespace Amount

structure Decimal where
  mantissa : Nat
  exponent : Nat
  deriving Repr, DecidableEq

def ofMsat (n : Nat) : Amount := ⟨n⟩
def ofSats (n : Nat) : Amount := ⟨1000 * n⟩
def toMsat (a : Amount) : Nat := a.msat
def toBtc (a : Amount) : Decimal := ⟨a.msat, 11⟩
def toSatDecimal (a : Amount) : Decimal := ⟨a.msat, 3⟩
def toMsatDecimal (a : Amount) : Decimal := ⟨a.msat, 0⟩

/-- Convert only when the exact decimal value is a whole number of msat. -/
def ofDecimal (d : Decimal) (scale : Nat) : Option Amount :=
  let numerator := d.mantissa * 10^scale
  let denominator := 10^d.exponent
  if numerator % denominator = 0 then some ⟨numerator / denominator⟩ else none

def ofBtc? (d : Decimal) : Option Amount := ofDecimal d 11

def ofJsonNumber (n : Lean.JsonNumber) : Option Amount :=
  if n.mantissa < 0 then none else ofDecimal ⟨n.mantissa.toNat, n.exponent⟩ 11

def toSats? (a : Amount) : Option Nat :=
  if a.msat % 1000 = 0 then some (a.msat / 1000) else none

theorem ofDecimal_iff (d : Decimal) (k : Nat) (a : Amount) :
    ofDecimal d k = some a ↔ a.msat * 10^d.exponent = d.mantissa * 10^k := by
  have pos : 0 < 10^d.exponent := Nat.pow_pos (by decide)
  unfold ofDecimal
  dsimp only
  split
  · rename_i h
    simp only [Option.some.injEq]
    constructor
    · intro ha
      subst a
      exact Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero h)
    · intro ha
      cases a
      congr
      exact Nat.div_eq_of_eq_mul_left pos ha.symm
  · rename_i h
    simp only [reduceCtorEq, false_iff]
    intro ha
    apply h
    rw [← ha, Nat.mul_mod_left]

theorem ofDecimal_submsat (d : Decimal) (k : Nat)
    (h : ¬ 10^d.exponent ∣ d.mantissa * 10^k) : ofDecimal d k = none := by
  simp [ofDecimal, Nat.dvd_iff_mod_eq_zero] at *
  exact h

theorem ofJsonNumber_iff (n : Lean.JsonNumber) (a : Amount) :
    ofJsonNumber n = some a ↔
      (a.msat : Int) * 10^n.exponent = n.mantissa * 10^11 := by
  have pos : (0 : Int) < 10^n.exponent := Int.pow_pos (by decide)
  unfold ofJsonNumber
  split
  · rename_i h
    simp only [reduceCtorEq, false_iff]
    intro heq
    have lhs : (0 : Int) ≤ (a.msat : Int) * 10^n.exponent :=
      Int.mul_nonneg (Int.natCast_nonneg _) (Int.le_of_lt pos)
    have rhs : n.mantissa * 10^11 < (0 : Int) :=
      Int.mul_neg_of_neg_of_pos h (by decide)
    omega
  · rename_i h
    rw [ofDecimal_iff]
    have hm : (n.mantissa.toNat : Int) = n.mantissa := Int.toNat_of_nonneg (by omega)
    constructor <;> intro heq
    · have hc := congrArg (fun x : Nat => (x : Int)) heq
      simpa [hm] using hc
    · have : (a.msat : Int) * (10 : Int)^n.exponent =
          (n.mantissa.toNat : Int) * (10 : Int)^11 := by rw [hm]; exact heq
      exact_mod_cast this

theorem ofSats_msat (n : Nat) : (ofSats n).msat = 1000 * n := rfl

theorem toSats_iff (a : Amount) (n : Nat) :
    toSats? a = some n ↔ a.msat = 1000 * n := by
  unfold toSats?
  split
  · rename_i h
    simp only [Option.some.injEq]
    omega
  · rename_i h
    simp only [reduceCtorEq, false_iff]
    omega

theorem toSats_ofSats (n : Nat) : toSats? (ofSats n) = some n :=
  (toSats_iff _ _).mpr rfl

theorem ofBtc_toBtc (a : Amount) : ofBtc? (toBtc a) = some a := by
  apply (ofDecimal_iff _ _ _).mpr
  rfl

theorem toBtc_exact (a : Amount) : toBtc a = ⟨a.msat, 11⟩ := rfl

theorem ofSatDecimal_toSatDecimal (a : Amount) : ofDecimal (toSatDecimal a) 3 = some a := by
  apply (ofDecimal_iff _ _ _).mpr
  rfl

theorem ofMsatDecimal_toMsatDecimal (a : Amount) : ofDecimal (toMsatDecimal a) 0 = some a := by
  apply (ofDecimal_iff _ _ _).mpr
  rfl

theorem toMsat_ofMsat (n : Nat) : toMsat (ofMsat n) = n := rfl

end Amount
end Bitcoin
