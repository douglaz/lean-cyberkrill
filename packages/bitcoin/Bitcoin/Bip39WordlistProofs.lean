/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bip39Wordlist
import Lean

namespace Bitcoin.Bip39

-- Pad to eight base-27 digits so prefixes precede their extensions.
private def wordCode (w : String) : Nat :=
  w.toList.foldl (fun n c => n * 27 + (c.toNat - 96)) 0 * 27 ^ (8 - w.toList.length)

private def steps : List Nat → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => a < b ∧ steps (b :: rest)

private def stepsDec : (ns : List Nat) → Decidable (steps ns)
  | [] => isTrue True.intro
  | [_] => isTrue True.intro
  | a :: b :: ns =>
    letI := stepsDec (b :: ns)
    inferInstanceAs (Decidable (a < b ∧ steps (b :: ns)))

private instance (ns : List Nat) : Decidable (steps ns) := stepsDec ns

set_option maxRecDepth 100000 in
set_option maxHeartbeats 0 in
private theorem sorted_codes : steps (wordlist.map wordCode) := by
  decide +kernel

private theorem steps_pairwise (ns : List Nat) (h : steps ns) : ns.Pairwise (· < ·) := by
  induction ns with
  | nil => simp
  | cons a ns ih =>
    cases ns with
    | nil => simp
    | cons b ns =>
      obtain ⟨ab, tail⟩ := h
      have pair := ih tail
      rw [List.pairwise_cons] at pair ⊢
      refine ⟨?_, List.pairwise_cons.mpr pair⟩
      intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact ab
      · exact Nat.lt_trans ab (pair.1 x hx)

/-- The published list has no duplicate words; checked by its increasing base-27 codes. -/
theorem wordlist_nodup : wordlist.Nodup := by
  apply List.Pairwise.of_map wordCode ?_ (steps_pairwise _ sorted_codes)
  intro a b hab eq
  subst b
  exact (Nat.lt_irrefl _ hab)

set_option maxRecDepth 100000 in
/-- There are exactly 2,048 indexed words. -/
theorem wordlist_length : wordlist.length = 2048 := by decide +kernel

end Bitcoin.Bip39
