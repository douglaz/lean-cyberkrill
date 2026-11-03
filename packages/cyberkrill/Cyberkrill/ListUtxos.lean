/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.CoreRpc
import Cyberkrill.Frozenkrill
import Cyberkrill.Amounts

namespace Cyberkrill.ListUtxos
open Lean CoreRpc

structure Args where
  descriptor : Option String := none
  addresses : Option String := none
  walletFile : Option String := none
  rpc : RpcFlags := {}
  network : String := "mainnet"
  minConf : Nat := 1
  maxConf : Nat := 9999999
  output : Option String := none

def networkValid (name : String) : Bool :=
  ["mainnet", "bitcoin", "testnet", "signet", "regtest"].contains name.toLower

def splitAddresses (text : String) : Array String :=
  (text.splitOn "," |>.map (fun s => Bitcoin.Amount.trimInput s) |>.filter (!·.isEmpty)).toArray

private def optionalString (raw : Json) (key : String) : Except CoreRpc.Error Json := do
  match raw.getObjVal? key with
  | .error _ | .ok .null => return .null
  | .ok value =>
    let _ ← value.getStr?.mapError (fun _ => CoreRpc.Error.invalidResult)
    return value

def outputUtxo (u : Utxo) : Except CoreRpc.Error (Nat × Json) := do
  let shape := fun {α} (e : Except String α) => e.mapError (fun _ => CoreRpc.Error.invalidResult)
  let confirmations ← shape (u.raw.getObjValAs? Nat "confirmations")
  unless confirmations ≤ 4294967295 && u.vout ≤ 4294967295 do throw .invalidResult
  let spendable ← shape (u.raw.getObjValAs? Bool "spendable")
  let solvable ← shape (u.raw.getObjValAs? Bool "solvable")
  let safe ← shape (u.raw.getObjValAs? Bool "safe")
  let script ← shape (u.raw.getObjValAs? String "scriptPubKey")
  let address ← optionalString u.raw "address"
  let descriptor ← optionalString u.raw "descriptor"
  let sats := u.amount.msat / 1000
  return (confirmations, Json.mkObj [("txid", .str u.txid), ("vout", toJson u.vout),
    ("amount_sats", toJson sats), ("confirmations", toJson confirmations),
    ("spendable", toJson spendable), ("solvable", toJson solvable), ("safe", toJson safe),
    ("address", address), ("script_pub_key", .str script), ("descriptor", descriptor)])

def summarize (values : Array Utxo) (bounds : Option (Nat × Nat)) : Except CoreRpc.Error Json := do
  let mut outputs := #[]
  let mut total := 0
  for value in values do
    let (conf, output) ← outputUtxo value
    if bounds.all (fun (lo, hi) => lo ≤ conf && conf ≤ hi) then
      outputs := outputs.push output
      total := total + value.amount.msat / 1000
  return Json.mkObj [("utxos", .arr outputs), ("total_amount_sats", toJson total),
    ("total_count", toJson outputs.size)]

/-- All composed calls retain the supplied client's authentication and limits.
Wallet halves concatenate without deduplicating across the two invocations. -/
def fetch (client : Client) (args : Args) (wallet : Option Frozenkrill.Wallet) : IO (Except CoreRpc.Error Json) := do
  let values ← match args.descriptor, args.addresses, wallet with
    | some descriptor, _, _ => client.listUnspentForDescriptor descriptor
    | _, some addresses, _ => client.listUnspent args.minConf args.maxConf (some (splitAddresses addresses))
    | _, _, some wallet => do
      let receiving ← match ← client.listUnspentForDescriptor wallet.receiving with
        | .error e => return .error e
        | .ok values => pure values
      match ← client.listUnspentForDescriptor wallet.change with
      | .error e => pure (.error e)
      | .ok change => pure (.ok (receiving ++ change))
    | _, _, _ => pure (.error .invalidResult)
  return values.bind fun values => summarize values
    (if args.addresses.isSome then none else some (args.minConf, args.maxConf))

end Cyberkrill.ListUtxos
