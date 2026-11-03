/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.CoreRpc
import Cyberkrill.Amounts
import Cyberkrill.Psbt
import Bitcoin.Fee

namespace Cyberkrill.PsbtCommands
open Lean Bitcoin

structure Args where
  funded : Bool := false
  inputs : Array String := #[]
  outputs : String
  feeRate : Option Amount := none
  confTarget : Option Nat := none
  estimateMode : Option String := none
  descriptor : Option String := none
  walletFile : Option String := none
  rpc : RpcFlags := {}
  network : String := "mainnet"
  output : Option String := none
  psbtOutput : Option String := none

def unsigned32 (s : String) : Option Nat := do
  let digits := String.ofList (match s.toList with | '+' :: rest => rest | cs => cs)
  if digits.isEmpty || !digits.toList.all (fun c => '0' ≤ c && c ≤ '9') then none
  else
    let n ← digits.toNat?
    if n ≤ 4294967295 then some n else none

def descriptorLike (s : String) : Bool := s.contains '(' || s.contains '['

private def invalidOutput : Error := .onchain "invalidOutputs: Expected nonempty address:amount entries"

-- Rust's candidate scan excludes vertical tab; its final suffix trim is Unicode.
private def asciiSpace (c : Char) : Bool := [' ', '\t', '\r', '\n', '\x0c'].contains c
private def asciiDigit (c : Char) : Bool := '0' ≤ c && c ≤ '9'
private def asciiLetter (c : Char) : Bool := ('a' ≤ c && c ≤ 'z') || ('A' ≤ c && c ≤ 'Z')

-- The separator scanner recognizes a prospective fiat number before validating
-- its grouping. A comma within that number belongs to the same output entry.
private def fiatComma (before remaining : List Char) : Bool := Id.run do
  let parts := (String.ofList before).splitOn ":"
  unless parts.length > 1 do return false
  let candidate := parts.getLast!.toList ++ remaining
  let number := candidate.dropWhile asciiSpace |>.takeWhile (fun c => asciiDigit c || c == '.' || c == ',')
  unless number.any asciiDigit do return false
  let start := (candidate.takeWhile asciiSpace).length
  let comma := parts.getLast!.length
  unless start ≤ comma && comma < start + number.length do return false
  let afterNumber := candidate.dropWhile asciiSpace |>.drop number.length
  let unit := afterNumber.dropWhile asciiSpace |>.takeWhile asciiLetter
  unless unit.length == 3 do return false
  let tail := afterNumber.dropWhile asciiSpace |>.drop unit.length |>.dropWhile Amount.rustWhitespace
  return tail.isEmpty || tail.head? == some ','

def splitOutputs (s : String) : Array String := Id.run do
  let mut entries := #[]
  let mut current := []
  let mut remaining := s.toList
  for c in s.toList do
    if c == ',' && !fiatComma current remaining then
      entries := entries.push (String.ofList current)
      current := []
    else current := current ++ [c]
    remaining := remaining.drop 1
  return entries.push (String.ofList current)

private def fiatValid (s : String) : Bool := Id.run do
  unless recognizableFiat s do return false
  let cs := (Amount.trimInput s).toList
  let suffix := cs.reverse.takeWhile (fun c => !(asciiDigit c || c == '.' || c == ','))
  let number := Amount.trimInput (String.ofList (cs.take (cs.length - suffix.length)))
  if number.isEmpty || ['-', '+', '.'].contains (number.toList.head!) || number.endsWith "." then return false
  let parts := number.splitOn "."
  -- Group checks precede f64 parsing, as in parse_fiat_number. The scanner
  -- deliberately remains narrower: it only protects commas in candidates.
  if number.contains ',' then
    unless parts.length ≤ 2 && !(parts.drop 1).any (·.contains ',') do return false
    let groups := parts.head!.splitOn ","
    unless groups.all (fun g => !g.isEmpty && g.toList.all asciiDigit) do return false
    let western := groups.head!.length ≤ 3 && groups.tail.all (·.length == 3)
    let indian := groups.length ≥ 3 && groups.head!.length ≤ 3 && groups.getLast!.length == 3 &&
      (groups.tail.take (groups.length - 2)).all (·.length == 2)
    unless western || indian do return false
  let exponentParts := (number.replace "," "").toLower.splitOn "e"
  unless exponentParts.length ≤ 2 do return false
  let mantissaParts := exponentParts.head!.splitOn "."
  unless mantissaParts.length ≤ 2 do return false
  let digits := String.intercalate "" mantissaParts
  unless !digits.isEmpty && digits.toList.all asciiDigit do return false
  let mut exponent : Int := 0
  if exponentParts.length == 2 then
    let raw := exponentParts[1]!
    let unsigned := String.ofList (raw.toList.dropWhile (fun c => c == '+' || c == '-'))
    unless !unsigned.isEmpty && unsigned.toList.all asciiDigit && raw.length - unsigned.length ≤ 1 do return false
    let some value := unsigned.toNat? | return false
    exponent := if raw.startsWith "-" then -Int.ofNat (min value 10000) else Int.ofNat (min value 10000)
  let some mantissa := digits.toNat? | return false
  let fraction := if mantissaParts.length == 2 then mantissaParts[1]!.length else 0
  let scale := exponent - Int.ofNat fraction
  -- Float is used only to recognize the refused fiat class, never an output.
  let value : Float := OfScientific.ofScientific mantissa (scale < 0) scale.natAbs
  return value.isFinite

/-- Parse all entries first, then check Bitcoin precision, then refuse fiat.
The second Core-facing split rejects colons remaining in destinations, after
input expansion, matching the complete handler-to-client path. -/
def parseOutputs (s : String) : Except Error (Array (String × Amount)) := do
  let mut parsed : Array (String × Option Amount) := #[]
  for entry in splitOutputs s do
    let parts := (Amount.trimInput entry).splitOn ":"
    unless parts.length ≥ 2 do throw invalidOutput
    let address := Amount.trimInput (String.intercalate ":" (parts.take (parts.length - 1)))
    let value := Amount.trimInput parts.getLast!
    if address.isEmpty then throw invalidOutput
    let amount ← match parseAmount value with
      | .ok amount => pure (some amount)
      | .error e => if fiatValid value then pure none else throw e
    parsed := parsed.push (address, amount)
  for (_, value) in parsed do
    if let some value := value then let _ ← exactWholeSat value
  if parsed.any (fun (_, value) => value.isNone) then throw .fiatNotSupported
  let mut outputs := #[]
  for (address, value) in parsed do
    outputs := (outputs.filter (fun (key, _) => key != address)).push (address, value.getD (Amount.ofSats 0))
  return outputs

private def rpc (action : IO (Except CoreRpc.Error α)) : IO (Except Error α) := do
  return (← action).mapError (fun e => .onchain e.message)

def expand (client : CoreRpc.Client) (inputs : Array String) : IO (Except Error (Array CoreRpc.Input)) := do
  let mut result := #[]
  for input in inputs do
    let input := Amount.trimInput input
    if descriptorLike input then
      match ← rpc (client.listUnspentForDescriptor input) with
      | .error e => return .error e
      | .ok values =>
        for u in values do
          result := result.push { txid := u.txid, vout := u.vout }
    else
      let parts := input.splitOn ":"
      unless parts.length == 2 do
        return .error (.onchain "invalidInput: Expected txid:vout or descriptor")
      let some vout := unsigned32 parts[1]! |
        return .error (.onchain "invalidVout: Expected an unsigned 32-bit decimal")
      result := result.push { txid := parts[0]!, vout }
  if result.isEmpty then return .error (.onchain "emptyInputs: No valid inputs after expansion")
  return .ok result

private def derive (client : CoreRpc.Client) (descriptor : String) : IO (Except CoreRpc.Error String) := do
  let .ok info ← client.call "getdescriptorinfo" #[.str descriptor] | return .error .invalidResult
  let .ok desc := info.getObjValAs? String "descriptor" | return .error .invalidResult
  let .ok addresses ← client.call "deriveaddresses" #[.str desc] | return .error .invalidResult
  let .ok addresses := addresses.getArr? | return .error .invalidResult
  let some address := addresses[0]? | return .error .invalidResult
  return address.getStr?.mapError (fun _ => .invalidResult)

private def used (client : CoreRpc.Client) (address : String) : IO (Except CoreRpc.Error Bool) := do
  match ← client.call "getreceivedbyaddress" #[.str address, toJson (0 : Nat)] with
  | .ok (.num n) => return (CoreRpc.amount (.num n)).map (fun a => a.msat > 0)
  | .ok _ => return .ok false
  | .error _ =>
    return (← client.call "listunspent" #[toJson (0 : Nat), toJson (9999999 : Nat), toJson #[address]]).map
      (fun raw => match raw.getArr? with | .ok values => !values.isEmpty | .error _ => false)

def changeAddress (client : CoreRpc.Client) (inputs : Array String) : IO (Except CoreRpc.Error (Option String)) := do
  for input in inputs do
    let input := Amount.trimInput input
    let parts := input.splitOn "<0;1>"
    if descriptorLike input && parts.length > 1 then
      let descriptor := parts.head! ++ "1" ++ String.intercalate "<0;1>" parts.tail
      for index in [:200] do
        let indexed := ((descriptor.replace "*" (toString index)).splitOn "#").head!
        if let .ok address ← derive client indexed then
          match ← used client address with
          | .error e => return .error e
          | .ok false => return .ok (some address)
          | .ok true => pure ()
  return .ok none

structure Result where
  psbt : String
  feeSats : Nat
  changePosition : Json

def Result.json (result : Result) : Json := Json.mkObj [
  ("psbt", .str result.psbt), ("fee_sats", toJson result.feeSats),
  ("change_position", result.changePosition)]

private def checkedPsbt (psbt : String) : Except Error String := do
  unless (Base64.decode psbt).isSome do throw (.offline "psbtBase64")
  let _ ← PsbtCli.parse psbt
  return psbt

/-- Expand, probe and submit using one supplied client, including its limits. -/
def fetch (client : CoreRpc.Client) (args : Args) (outputs : Array (String × Amount)) : IO (Except Error Result) := do
  let inputs ← match ← expand client args.inputs with
    | .error e => return .error e
    | .ok inputs => pure inputs
  if outputs.any (fun (address, _) => address.contains ':') then return .error invalidOutput
  if args.funded then
    let change ← match ← rpc (changeAddress client args.inputs) with
      | .error e => return .error e
      | .ok change => pure change
    let options := (change.map (fun s => [("changeAddress", .str s)])).getD [] ++
      (args.confTarget.map (fun n => [("conf_target", toJson n)])).getD [] ++
      (args.estimateMode.map (fun s => [("estimate_mode", .str s)])).getD [] ++
      (args.feeRate.map (fun a => [("fee_rate", Json.num ⟨Int.ofNat a.msat, 3⟩)])).getD []
    match ← rpc (client.walletCreateFundedPsbtCommand inputs outputs options) with
    | .error e => return .error e
    | .ok raw => return do
      let psbt ← (raw.getObjValAs? String "psbt").mapError (fun _ => Error.onchain CoreRpc.Error.invalidResult.message)
      let psbt ← checkedPsbt psbt
      let result ← (CoreRpc.fundedCommandResult raw).mapError (fun e => Error.onchain e.message)
      let fee ← exactWholeSat result.fee
      unless fee.msat / 1000 ≤ 18446744073709551615 do
        throw (.onchain "invalidFee: Fee exceeds unsigned 64-bit satoshis")
      return { psbt, feeSats := fee.msat / 1000, changePosition := toJson result.changePosition }
  else
    match ← rpc (client.createPsbt inputs outputs) with
    | .error e => return .error e
    | .ok psbt => return do
      let psbt ← checkedPsbt psbt
      return {
        psbt, feeSats := (args.feeRate.map (fun rate =>
          (Fee.estimateFee (Fee.estimateWeight inputs.size outputs.size) rate).msat / 1000)).getD 0,
        changePosition := .null }

end Cyberkrill.PsbtCommands
