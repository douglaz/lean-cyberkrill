/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Lean

namespace BitcoinTests

open Lean Meta Elab Term Bitcoin

/-- Read the propositions from the library structure's constructor. This keeps
each executable check tied to the actual field, including under mutations. -/
elab "transactionConjuncts%(" tx:term "," witnesses:term ")" : term => do
  let tx ← elabTermEnsuringType tx (mkConst ``Transaction)
  let witnesses ← elabTermEnsuringType witnesses
    (mkApp (mkConst ``List [0]) (mkApp (mkConst ``List [0]) (mkConst ``ByteArray)))
  let constructor := mkApp2 (mkConst ``Transaction.WellFormed.mk) tx witnesses
  forallTelescopeReducing (← inferType constructor) fun fields _ => do
    let checks ← fields.toList.mapM fun field => do
      let proposition ← inferType field
      let decision ← synthInstance (mkApp (mkConst ``Decidable) proposition)
      pure (mkApp2 (mkConst ``decide) proposition decision)
    mkListLit (mkConst ``Bool) checks

def transactionChecks (tx : Transaction) (witnesses : List (List ByteArray)) : List Bool :=
  transactionConjuncts%(tx, witnesses)

theorem transactionChecks_iff (tx : Transaction) (witnesses : List (List ByteArray)) :
    (transactionChecks tx witnesses).all id = true ↔ tx.WellFormed witnesses := by
  unfold transactionChecks
  constructor
  · intro h
    constructor <;> simp_all <;> grind
  · intro h
    cases h
    simp_all <;> grind

end BitcoinTests
