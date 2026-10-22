/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Psbt.Fields

namespace Bitcoin.Psbt

private def checkMap (cap : PubkeyCapability) (scope : String) (keyType : Nat)
    (map : KeyValueMap) : Except PsbtError Unit := do
  let mut seen : List (ByteArray × ByteArray) := []
  for record in map do
    let (kind, raw) ← splitKey record.key
    if kind == keyType then
      let some compressed := cap.compressPubkey raw
        | throw (.invalidKey scope keyType "invalid public key")
      if let some (first, _) := seen.find? (fun (_, point) => point == compressed) then
        throw (.duplicateBip32Point scope first raw)
      seen := seen ++ [(raw, compressed)]

/-- Check BIP32 derivation keys in the raw input and output maps, independently
for each map, in wire order. Return the first colliding pair, retaining both raw
key-data encodings and the scope ("input" or "output"). Partial signatures and
global records are ignored. A malformed record key propagates its decode error;
a BIP32 key rejected by the capability returns `invalidKey`, as parsing with the
same capability would. This optional check is deliberately separate from `parse`.
-/
def Psbt.checkBip32SamePoint (cap : PubkeyCapability) (psbt : Psbt) : Except PsbtError Unit := do
  for map in psbt.inputs do checkMap cap "input" KeyType.inBip32Derivation map
  for map in psbt.outputs do checkMap cap "output" KeyType.outBip32Derivation map

end Bitcoin.Psbt
