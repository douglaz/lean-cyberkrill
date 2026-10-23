/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Bitcoin.PsbtVectors

open Bitcoin Bitcoin.Psbt BitcoinTests.PsbtVectors

-- Measure the published zero-input transaction with both reader modes.
#eval do
  let raw := (Hex.decode bip174Valid[9]!.2.1).getD ByteArray.empty
  let result := do
    let (global, _) ← decodeMap (raw.data.toList.drop 5)
    let tx ← liftDecode (parseTransaction global[0]!.value false)
    pure (tx.transaction.version, tx.transaction.inputs.size, tx.transaction.outputs.size,
      tx.witnesses.length, parseTransaction (serializeWitnessTransaction tx.transaction tx.witnesses))
  IO.println (repr result)
