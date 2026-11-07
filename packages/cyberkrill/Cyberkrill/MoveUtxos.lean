/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.PsbtCommands

namespace Cyberkrill.MoveUtxos
open Lean Bitcoin

structure Args where
  inputs : Array String
  destination : String
  feeRate : Option Amount := none
  fee : Option Amount := none
  maxAmount : Option String := none
  descriptor : Option String := none
  walletFile : Option String := none
  rpc : RpcFlags := {}
  network : String := "mainnet"
  output : Option String := none
  psbtOutput : Option String := none

/-- Validate grammar during parsing; whole-sat flooring and fiat conversion are
runtime checks. Share grouped/finite fiat grammar with the creation commands
without applying their comma-separated output-entry scanner. -/
def validateMax (text : String) : Except Error Unit := do
  match parseAmount text with
  | .ok _ => return
  | .error e =>
    if PsbtCommands.fiatValid text then return else throw e

def maximum (text : String) : Except Error Amount := do
  floorSat (← parseAmount text)

/-- Read only the requested array element, matching the command's response
consumption. The strict CoreRpc.getRawTransaction API remains unchanged. -/
def requestedValue (raw : Json) (index : Nat) : Except CoreRpc.Error Amount := do
  let outputs ← (raw.getObjValAs? (Array Json) "vout").mapError (fun _ => .invalidResult)
  let some output := outputs[index]? | throw .invalidResult
  let value ← (output.getObjVal? "value").mapError (fun _ => .invalidResult)
  CoreRpc.amount value

/-- Stable descending selection with an optional threshold, never a clamp. -/
def select (values : Array (CoreRpc.Input × Amount)) (maximum : Option Amount) :
    Array CoreRpc.Input × Amount := Id.run do
  let ordered := match maximum with
    | none => values.toList
    | some _ => values.toList.mergeSort (fun a b => a.2.msat ≥ b.2.msat)
  let mut inputs := #[]
  let mut total : Amount := ⟨0⟩
  for (input, value) in ordered do
    if maximum.any (fun cap => total.msat ≥ cap.msat) then break
    inputs := inputs.push input
    total := ⟨total.msat + value.msat⟩
  return (inputs, total)

/-- Expand and fetch every input before selection, retaining one supplied
client, exact values, repeated inputs and the original lookup order. -/
def fetch (client : CoreRpc.Client) (args : Args) (maximum : Option Amount) :
    IO (Except Error PsbtCommands.Result) := do
  let inputs ← match ← PsbtCommands.expand client args.inputs with
    | .error e => return .error e
    | .ok inputs => pure inputs
  let mut values := #[]
  for input in inputs do
    let raw ← match ← client.call "getrawtransaction" #[.str input.txid, .bool true] with
      | .error e => return .error (.onchain e.message)
      | .ok raw => pure raw
    match requestedValue raw input.vout with
    | .error e => return .error (.onchain e.message)
    | .ok amount => values := values.push (input, amount)
  let (selected, total) := select values maximum
  if selected.isEmpty then return .error (.onchain "emptySelection: No UTXOs selected")
  let fee ← match args.feeRate, args.fee with
    | some rate, none => pure (Fee.estimateFee (Fee.estimateWeight selected.size 1) rate)
    | none, some fee => pure (Amount.ofSats (fee.msat / 1000))
    | none, none => return .error (.onchain "missingFee: Specify either --fee-rate or --fee")
    | some _, some _ => return .error (.onchain "feeConflict: Specify only one fee method")
  unless total.msat > fee.msat do
    return .error (.onchain "insufficientFunds: Selected total must exceed the fee")
  let output : Amount := ⟨total.msat - fee.msat⟩
  match ← client.createPsbt selected #[(args.destination, output)] with
  | .error e => return .error (.onchain e.message)
  | .ok psbt => return do
    -- Validate original RPC spelling before the offline parser's trimming.
    unless (Base64.decode psbt).isSome do throw (.offline "psbtBase64")
    let _ ← PsbtCli.parse psbt
    return { psbt, feeSats := fee.msat / 1000, changePosition := .null }

end Cyberkrill.MoveUtxos
