/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bech32

namespace Bitcoin.Bech32

/-- Two checksums accepted under the same variant have equal polymod residues.
This is the first algebraic reduction for data-substitution detection. -/
theorem verifyChecksum_residue_eq (v : Variant) (hrp : String) (d d' : List Symbol)
    (valid : verifyChecksum v hrp d = true) (valid' : verifyChecksum v hrp d' = true) :
    polymod (hrpExpand hrp ++ d.map BitVec.toNat) =
      polymod (hrpExpand hrp ++ d'.map BitVec.toNat) := by
  exact (beq_iff_eq.mp valid).trans (beq_iff_eq.mp valid').symm

end Bitcoin.Bech32
