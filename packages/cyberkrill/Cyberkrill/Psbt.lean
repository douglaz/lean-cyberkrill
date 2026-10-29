/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Psbt.SamePoint
import Bitcoin.Address
import FedimintInvite.Codec
import Cyberkrill.Capabilities
import Cyberkrill.Amounts
import Lean

namespace Cyberkrill.PsbtCli
open Lean Bitcoin Bitcoin.Psbt

def network (input : String) : Except Error Address.Network :=
  match input.toLower with
  | "mainnet" | "bitcoin" => .ok .mainnet
  | "testnet" => .ok .testnet
  | "signet" => .ok .signet
  | "regtest" => .ok .regtest
  | _ => .error (.offline "invalidNetwork")

private def networkText : Address.Network → String
  | .mainnet => "bitcoin" | .testnet => "testnet" | .signet => "signet" | .regtest => "regtest"

private def parseError : PsbtError → Error
  | .base64 => .offline "psbtBase64"
  | .decode _ => .offline "psbtFraming"
  | .magic => .offline "psbtMagic"
  | .duplicateKey _ => .offline "psbtDuplicateKey"
  | .duplicateBip32Point scope _ _ => .offline ("psbtDuplicatePoint:" ++ scope)
  | .trailingData => .offline "psbtTrailingData"
  | .invalidKey scope kind reason => .offline s!"psbtInvalidKey:{scope}:{kind}:{reason}"
  | .invalidValue scope kind reason => .offline s!"psbtInvalidValue:{scope}:{kind}:{reason}"
  | .unsupportedVersion _ => .offline "psbtVersion"
  | .missingField scope kind => .offline s!"psbtMissingField:{scope}:{kind}"
  | .excludedField scope kind => .offline s!"psbtExcludedField:{scope}:{kind}"
  | .mapCount => .offline "psbtMapCount"
  | .invalidUnsignedTransaction reason => .offline ("psbtTransaction:" ++ reason)

/-- Every app consumer uses this boundary, retaining the pure codec's raw keys. -/
def parse (input : String) : Except Error DecodedPsbt := do
  let psbt ← (Psbt.parseBase64 pubkeys preimageHashes (FedimintInvite.trimInput input)).mapError parseError
  let _ ← (psbt.checkBip32SamePoint pubkeys).mapError parseError
  (psbt.decode pubkeys preimageHashes).mapError parseError

private def btc (sats : Nat) : Json :=
  -- JsonNumber stores an exact decimal coefficient and exponent, never Float.
  .num ⟨Int.ofNat sats, 8⟩

private def inputValue (input : TxInput) (fields : InputFields) : Option UInt64 :=
  fields.witnessUtxo.map (·.amount) <|>
    (fields.nonWitnessUtxo.bind fun tx => tx.outputs[input.previousOutput.index.toNat]?.map (·.amount))

def decode (input : String) (net : Address.Network) : Except Error String := do
  let decoded ← parse input
  let tx ← decoded.unsignedTransaction.mapError parseError
  let mut inputs := []
  let mut totalInput := 0
  let mut allValues := true
  for ((input, fields), index) in (tx.inputs.toList.zip decoded.inputs).zipIdx do
    let mut values := [("index", toJson index),
      ("txid", toJson (Hex.encode ⟨input.previousOutput.txid.data.toList.reverse.toArray⟩)),
      ("vout", toJson input.previousOutput.index.toNat), ("sequence", toJson input.sequence.toNat)]
    match inputValue input fields with
    | none => allValues := false
    | some value =>
      values := values ++ [("value_sats", toJson value.toNat), ("value_btc", btc value.toNat)]
      totalInput := (totalInput + value.toNat) % 2^64
    if !fields.partialSigs.isEmpty then
      values := values ++ [("signatures", toJson fields.partialSigs.length)]
    inputs := inputs ++ [Json.mkObj values]
  let outputs := tx.outputs.toList.zipIdx.map fun (output, index) => Json.mkObj [
    ("index", toJson index), ("value_sats", toJson output.amount.toNat),
    ("value_btc", btc output.amount.toNat), ("script_pubkey", toJson (Hex.encode output.scriptPubKey)),
    ("address", toJson (Address.encodeScript net output.scriptPubKey).toOption)]
  let totalOutput := tx.outputs.foldl (fun sum out => (sum + out.amount.toNat) % 2^64) 0
  return (Json.mkObj [("network", toJson (networkText net)), ("version", toJson tx.signedVersion),
    ("locktime", toJson tx.locktime.toNat), ("input_count", toJson tx.inputs.size),
    ("output_count", toJson tx.outputs.size), ("inputs", toJson inputs), ("outputs", toJson outputs),
    ("total_input_value", if allValues then toJson totalInput else .null),
    ("total_output_value", toJson totalOutput),
    ("fee", if allValues then toJson (totalInput - totalOutput) else .null)]).pretty

end Cyberkrill.PsbtCli
