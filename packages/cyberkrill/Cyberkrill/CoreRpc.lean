/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Amount
import HttpCurl
import Cyberkrill.RpcFlags

namespace Cyberkrill.CoreRpc
open Lean Bitcoin

/-- Failure data deliberately excludes request/response bodies, credentials and IO exceptions. -/
inductive Error where
  | transport
  | http (status : UInt32)
  | rpc (code : Option Int)
  | malformed
  | missingResult
  | invalidResult
  | invalidAmount
  deriving BEq, Repr

def Error.message : Error → String
  | .transport => "rpcTransport: HTTP transport failed"
  | .http status => s!"rpcHttp: HTTP {status}"
  | .rpc _ => "rpcError: Core rejected the request"
  | .malformed => "rpcMalformed: invalid JSON response"
  | .missingResult => "rpcMissingResult: response has no result"
  | .invalidResult => "rpcInvalidResult: unexpected result shape"
  | .invalidAmount => "rpcInvalidAmount: expected nonnegative exact millisatoshis"

def pairAuth (user password : Option String) : Option (String × String) := do
  return (← user, ← password)

-- Match the Unicode whitespace accepted around the reference cookie.
private def cookieSpace (c : Char) : Bool :=
  let n := c.toNat
  (9 ≤ n && n ≤ 13) || n == 32 || n == 0x85 || n == 0xA0 || n == 0x1680 ||
    (0x2000 ≤ n && n ≤ 0x200A) || [0x2028, 0x2029, 0x202F, 0x205F, 0x3000].contains n

/-- Trim the cookie, then split at the first colon; empty components remain present. -/
def parseCookie (cookie : String) : Option (String × String) :=
  let trimmed := String.ofList (cookie.toList.dropWhile cookieSpace |>.reverse.dropWhile cookieSpace |>.reverse)
  match trimmed.splitOn ":" with
  | user :: password :: rest => some (user, String.intercalate ":" (password :: rest))
  | _ => none

/-- An explicitly empty directory denotes the working directory, as in the reference. -/
def cookiePath (directory : String) : System.FilePath :=
  if directory.isEmpty then System.FilePath.mk ".cookie"
  else System.FilePath.mk directory / ".cookie"

def resolveAuth (flags : RpcFlags) : IO (Option (String × String)) := do
  if let some directory := flags.bitcoinDir then
    try
      if let some auth := parseCookie (← IO.FS.readFile (cookiePath directory)) then
        return some auth
    catch _ => pure ()
  return pairAuth flags.user flags.password

/-- The URL is caller supplied; HttpCurl owns URL validation, limits and deadlines. -/
structure Client where
  url : String
  auth : Option (String × String) := none
  /-- Whole-transfer deadline in milliseconds; zero follows HttpCurl's unlimited setting. -/
  totalTimeoutMs : UInt32 := 30000

def Client.ofFlags (flags : RpcFlags) : IO Client := do
  return { url := flags.url, auth := ← resolveAuth flags }

def decodeResponse (response : HttpCurl.Response) : Except Error Json := do
  unless response.status >= 200 && response.status < 300 do throw (.http response.status)
  let some body := String.fromUTF8? response.body | throw .malformed
  let value ← (Json.parse body).mapError (fun _ => Error.malformed)
  let _ ← value.getObj?.mapError (fun _ => Error.malformed)
  if let .ok error := value.getObjVal? "error" then
    unless error == .null do throw (.rpc (error.getObjValAs? Int "code").toOption)
  value.getObjVal? "result" |>.mapError (fun _ => Error.missingResult)

-- JsonNumber's printer can emit an empty fractional part for zero with a large
-- exponent. Canonicalize zero recursively, leaving every exact value unchanged.
private partial def wireJson : Json → Json
  | .num n => if n.mantissa == 0 then .num 0 else .num n
  | .arr values => .arr (values.map wireJson)
  | .obj fields => Json.mkObj (fields.toArray.toList.map fun (k, v) => (k, wireJson v))
  | value => value

def Client.call (client : Client) (method : String) (params : Array Json) : IO (Except Error Json) := do
  let body := Json.mkObj [("jsonrpc", .str "2.0"), ("id", .str "cyberkrill"),
    ("method", .str method), ("params", .arr params)]
  match ← HttpCurl.request {
      method := .post, url := client.url, basicAuth := client.auth,
      totalTimeoutMs := client.totalTimeoutMs,
      headers := #[("Content-Type", "application/json")], body := some (wireJson body).compress.toUTF8 } with
  | .error _ => return .error .transport
  | .ok response => return decodeResponse response

private def shape (value : Except String α) : Except Error α := value.mapError (fun _ => .invalidResult)
def amount (value : Json) : Except Error Amount := do
  let .num n := value | throw .invalidAmount
  let some a := Amount.ofJsonNumber n | throw .invalidAmount
  return a

/-- Exact BTC JSON number, including values above binary64 or u64 precision. -/
def amountJson (value : Amount) : Json :=
  .num ⟨Int.ofNat value.msat, if value.msat == 0 then 0 else 11⟩

private def field (value : Json) (name : String) : Except Error Json := shape (value.getObjVal? name)
private def string (value : Json) (name : String) : Except Error String := shape (value.getObjValAs? String name)
private def nat (value : Json) (name : String) : Except Error Nat := shape (value.getObjValAs? Nat name)

/-- The original object retains additional Core fields for later command consumers. -/
structure Utxo where
  txid : String
  vout : Nat
  amount : Amount
  raw : Json

def utxo (raw : Json) : Except Error Utxo := do
  return {
    txid := ← string raw "txid", vout := ← nat raw "vout",
    amount := ← amount (← field raw "amount"), raw }

def Client.listUnspent (client : Client) (minConf : Nat := 0) (maxConf : Nat := 9999999)
    (addresses : Option (Array String) := none) : IO (Except Error (Array Utxo)) := do
  let params := #[toJson minConf, toJson maxConf] ++
    (addresses.map (fun a => #[toJson a])).getD #[]
  return (← client.call "listunspent" params).bind fun raw => do
    (← shape raw.getArr?).mapM utxo

structure ScanObject where
  descriptor : String
  range : Option (Nat × Nat) := none

def ScanObject.json (object : ScanObject) : Json := Json.mkObj <|
  [("desc", .str object.descriptor)] ++
    (object.range.map (fun (lo, hi) => [("range", toJson #[lo, hi])])).getD []

structure ScanResult where
  success : Bool
  height : Nat
  unspents : Array Utxo
  total : Amount
  raw : Json

def Client.scanTxOutSet (client : Client) (objects : Array ScanObject) : IO (Except Error ScanResult) := do
  return (← client.call "scantxoutset" #[.str "start", .arr (objects.map (·.json))]).bind fun raw => do
    return {
      success := ← shape (raw.getObjValAs? Bool "success"), height := ← nat raw "height",
      unspents := ← (← shape (← field raw "unspents").getArr?).mapM utxo,
      total := ← amount (← field raw "total_amount"), raw }

structure DescriptorInfo where
  descriptor : String
  checksum : String
  isRange : Bool
  raw : Json

def Client.getDescriptorInfo (client : Client) (descriptor : String) : IO (Except Error DescriptorInfo) := do
  return (← client.call "getdescriptorinfo" #[.str descriptor]).bind fun raw => do
    return {
      descriptor := ← string raw "descriptor", checksum := ← string raw "checksum",
      isRange := ← shape (raw.getObjValAs? Bool "isrange"), raw }

def Client.deriveAddresses (client : Client) (descriptor : String)
    (range : Option (Nat × Nat) := none) : IO (Except Error (Array String)) := do
  let params := #[.str descriptor] ++ (range.map (fun (lo, hi) => #[toJson #[lo, hi]])).getD #[]
  return (← client.call "deriveaddresses" params).bind fun raw => shape (fromJson? raw)

structure Input where
  txid : String
  vout : Nat
  sequence : Option UInt32 := none

def Input.json (input : Input) : Json := Json.mkObj <|
  [("txid", .str input.txid), ("vout", toJson input.vout)] ++
    (input.sequence.map (fun n => [("sequence", toJson n.toNat)])).getD []

private def outputsJson (outputs : Array (String × Amount)) : Json :=
  Json.mkObj (outputs.toList.map fun (address, value) => (address, amountJson value))

def Client.createPsbt (client : Client) (inputs : Array Input) (outputs : Array (String × Amount))
    (locktime : UInt32 := 0) (replaceable : Bool := false) : IO (Except Error String) := do
  return (← client.call "createpsbt" #[.arr (inputs.map (·.json)), outputsJson outputs,
    toJson locktime.toNat, toJson replaceable]).bind fun raw => shape raw.getStr?

structure FundedPsbt where
  psbt : String
  fee : Amount
  changePosition : Int

/-- Options are Core's JSON object; fee_rate remains an exact numeric JsonNumber. -/
def Client.walletCreateFundedPsbt (client : Client) (inputs : Array Input)
    (outputs : Array (String × Amount)) (options : Json) (locktime : UInt32 := 0)
    (bip32Derivs : Option Bool := none) : IO (Except Error FundedPsbt) := do
  let params := #[.arr (inputs.map (·.json)), outputsJson outputs, toJson locktime.toNat, options] ++
    (bip32Derivs.map (fun b => #[toJson b])).getD #[]
  return (← client.call "walletcreatefundedpsbt" params).bind fun raw => do
    return {
      psbt := ← string raw "psbt", fee := ← amount (← field raw "fee"),
      changePosition := ← shape (raw.getObjValAs? Int "changepos") }

/-- Item-level import failures are returned intact, just as Core reports them. -/
def Client.importDescriptors (client : Client) (descriptors : Array String) : IO (Except Error (Array Json)) := do
  let imports := descriptors.map fun descriptor => Json.mkObj [
    ("desc", .str descriptor), ("timestamp", .str "now"), ("range", toJson #[0, 1000]),
    ("watchonly", .bool true), ("label", .str "cyberkrill_import")]
  return (← client.call "importdescriptors" #[.arr imports]).bind fun raw => shape raw.getArr?

structure ChainInfo where
  chain : String
  blocks : Nat
  bestBlockHash : String

def Client.getBlockchainInfo (client : Client) : IO (Except Error ChainInfo) := do
  return (← client.call "getblockchaininfo" #[]).bind fun raw => do
    return {
      chain := ← string raw "chain", blocks := ← nat raw "blocks",
      bestBlockHash := ← string raw "bestblockhash" }

def Client.getReceivedByAddress (client : Client) (address : String) (minConf : Nat := 0) : IO (Except Error Amount) := do
  return (← client.call "getreceivedbyaddress" #[.str address, toJson minConf]).bind amount

structure RawTransaction where
  txid : String
  outputs : Array Amount
  raw : Json

def Client.getRawTransaction (client : Client) (txid : String) : IO (Except Error RawTransaction) := do
  return (← client.call "getrawtransaction" #[.str txid, .bool true]).bind fun raw => do
    return {
      txid := ← string raw "txid", raw,
      outputs := ← (← shape (← field raw "vout").getArr?).mapM fun output => do amount (← field output "value") }

structure BlockInfo where
  hash : String
  height : Nat
  time : Nat
  transactions : Array String
  raw : Json

def Client.getBlock (client : Client) (hash : String) (verbosity : Option Nat := none) : IO (Except Error BlockInfo) := do
  let params := #[.str hash] ++ (verbosity.map (fun v => #[toJson v])).getD #[]
  return (← client.call "getblock" params).bind fun raw => do
    return {
      hash := ← string raw "hash", height := ← nat raw "height", time := ← nat raw "time",
      transactions := ← shape (raw.getObjValAs? (Array String) "tx"), raw }

/-- Import without historical rescan; ignore import failure and continue listing.
Older funds may be missed. Expansion and deduplication retain first-seen order. -/
def Client.listUnspentForDescriptor (client : Client) (descriptor : String) : IO (Except Error (Array Utxo)) := do
  if let .ok info ← client.getDescriptorInfo descriptor then
    let _ ← client.importDescriptors #[info.descriptor]
  let descriptors := if (descriptor.splitOn "<0;1>").length > 1 then
    #[descriptor.replace "<0;1>" "0", descriptor.replace "<0;1>" "1"] else #[descriptor]
  let mut result := #[]
  for desc in descriptors do
    let info ← match ← client.getDescriptorInfo desc with
      | .error e => return .error e
      | .ok info => pure info
    let addresses ← match ← client.deriveAddresses info.descriptor (some (0, 99)) with
      | .error e => return .error e
      | .ok addresses => pure addresses
    let utxos ← client.listUnspent 0 9999999 (some addresses)
    match utxos with
    | .error e => return .error e
    | .ok values =>
      for value in values do
        unless result.any (fun u => u.txid == value.txid && u.vout == value.vout) do
          result := result.push value
  return .ok result

end Cyberkrill.CoreRpc
