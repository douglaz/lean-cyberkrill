/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Amount
import Bitcoin.CompactSize

/-! P2WPKH weight prediction and cyberkrill-compatible binary64 fee estimation. -/
namespace Bitcoin.Fee

/-- Predict P2WPKH_MAX inputs and 22-byte output scripts, including count prefixes. -/
def estimateWeight (inputs outputs : Nat) : Nat :=
  let cs := fun n => (Bitcoin.CompactSize.compactSize n).length
  let scriptLength := 0
  let signatureLength := 72
  let publicKeyLength := 33
  let outputScriptLength := 22
  let scriptSize := scriptLength + cs scriptLength
  let witnessSize := signatureLength + cs signatureLength +
    publicKeyLength + cs publicKeyLength + cs 2
  let inputWeight := inputs * (4 * scriptSize + witnessSize + 4 * (32 + 4 + 4))
  let nonInputSize := 4 + cs inputs + cs outputs +
    outputs * (8 + outputScriptLength + cs outputScriptLength) + 4
  4 * nonInputSize + inputWeight + (if inputs > 0 then 2 else 0)

/-- Whole virtual bytes, rounding weight upward. -/
def vbytes (weight : Nat) : Nat := (weight + 3) / 4

/-- Whole-satoshi fee at a rate in msat/vB. Preserve division before multiplication,
binary64 rounding, and the saturating Rust u64 boundary conversions. -/
def estimateFee (weight : Nat) (rate : Bitcoin.Amount) : Bitcoin.Amount :=
  let v := (min (vbytes weight) 18446744073709551615).toUInt64.toFloat
  let r := (min rate.msat 18446744073709551615).toUInt64.toFloat
  Bitcoin.Amount.ofSats (v * (r / 1000.0)).round.toUInt64.toNat

end Bitcoin.Fee
