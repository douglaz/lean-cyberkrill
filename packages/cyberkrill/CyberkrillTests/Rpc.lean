/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Lean Cyberkrill CoreRpc Bitcoin

private def arr (j : Json) : IO (Array Json) := getOk "RPC fixture array" j.getArr?
private def item (j : Json) (key : String) : IO Json := getOk "RPC fixture field" (j.getObjVal? key)
private def num (j : Json) : IO Nat := getOk "RPC fixture natural" (fromJson? j)
private def str (j : Json) : IO String := getOk "RPC fixture text" j.getStr?
private def btc (j : Json) : IO Amount := getOk "RPC fixture amount" (CoreRpc.amount j)
private def eqAmount (name : String) (a : Amount) (expected : Json) : IO Unit := do
  check name (a == (← btc expected))

private def inputs (j : Json) : IO (Array CoreRpc.Input) := do
  (← arr j).mapM fun raw => do
    return { txid := ← text raw "txid", vout := ← num (← item raw "vout") }

private def outputs (j : Json) : IO (Array (String × Amount)) := do
  let fields ← getOk "RPC outputs object" j.getObj?
  fields.toArray.mapM fun (address, value) => do return (address, ← btc value)

private def checkUtxos (values : Array Utxo) (expected : Json) : IO Unit := do
  let expected ← arr expected
  check "RPC UTXO count" (values.size == expected.size)
  for value in values, raw in expected do
    check "RPC UTXO txid/order" (value.txid == (← text raw "txid"))
    check "RPC UTXO vout" (value.vout == (← num (← item raw "vout")))
    eqAmount "RPC UTXO exact amount" value.amount (← item raw "amount")
    check "RPC UTXO retained fields" (value.raw == raw)

/-- Dispatch through the public wrappers, rebuilding typed arguments from the source selectors. -/
private def wrapper (client : Client) (method : String) (p : Array Json) (expected : Json) : IO Unit := do
  match method with
  | "getdescriptorinfo" =>
    let info ← getOk "RPC getdescriptorinfo success" (← client.getDescriptorInfo (← str p[0]!))
    check "RPC descriptor result" (info.descriptor == (← text expected "descriptor") &&
      info.checksum == (← text expected "checksum"))
    check "RPC descriptor range" (info.isRange == (← getOk "fixture range" (expected.getObjValAs? Bool "isrange")))
  | "deriveaddresses" =>
    let range ← if p.size == 1 then pure none else do
      let r ← arr p[1]!
      pure (some (← num r[0]!, ← num r[1]!))
    let value ← getOk "RPC deriveaddresses success" (← client.deriveAddresses (← str p[0]!) range)
    check "RPC derived address order" (toJson value == expected)
  | "listunspent" =>
    let addresses ← getOk "RPC fixture address filter" (fromJson? p[2]! : Except String (Array String))
    let value ← getOk "RPC listunspent success" (← client.listUnspent (← num p[0]!) (← num p[1]!) (some addresses))
    checkUtxos value expected
  | "scantxoutset" =>
    let objects ← (← arr p[1]!).mapM fun object => do
      let range ← match object.getObjVal? "range" with
        | .error _ => pure none
        | .ok r => do let r ← arr r; pure (some (← num r[0]!, ← num r[1]!))
      pure ({ descriptor := ← text object "desc", range } : ScanObject)
    let value ← getOk "RPC scantxoutset success" (← client.scanTxOutSet objects)
    check "RPC scan height/success" (value.success && value.height == (← num (← item expected "height")))
    eqAmount "RPC scan exact total" value.total (← item expected "total_amount")
    checkUtxos value.unspents (← item expected "unspents")
  | "createpsbt" =>
    let value ← getOk "RPC createpsbt success" (← client.createPsbt (← inputs p[0]!) (← outputs p[1]!)
      (← num p[2]!).toUInt32 (← getOk "RPC replaceable fixture" (fromJson? p[3]!)))
    check "RPC PSBT bytes" (value == (← str expected))
  | "walletcreatefundedpsbt" =>
    let value ← getOk "RPC walletcreatefundedpsbt success" (← client.walletCreateFundedPsbt
      (← inputs p[0]!) (← outputs p[1]!) p[3]! (← num p[2]!).toUInt32)
    check "RPC funded PSBT bytes" (value.psbt == (← text expected "psbt"))
    eqAmount "RPC funded exact fee" value.fee (← item expected "fee")
    check "RPC funded change position" (toJson value.changePosition == (← item expected "changepos"))
  | "importdescriptors" =>
    let descriptors ← (← arr p[0]!).mapM fun raw => text raw "desc"
    let value ← getOk "RPC importdescriptors response" (← client.importDescriptors descriptors)
    check "RPC actual import failure" (.arr value == expected && value.any fun raw =>
      (raw.getObjVal? "success").toOption == some (.bool false))
  | "getblockchaininfo" =>
    let value ← getOk "RPC getblockchaininfo success" (← client.getBlockchainInfo)
    check "RPC chain/height/hash" (value.chain == "regtest" && value.blocks == (← num (← item expected "blocks")) &&
      value.bestBlockHash == (← text expected "bestblockhash"))
  | "getreceivedbyaddress" =>
    let value ← getOk "RPC getreceivedbyaddress success" (← client.getReceivedByAddress (← str p[0]!) (← num p[1]!))
    eqAmount "RPC received exact amount" value expected
  | "getrawtransaction" =>
    let value ← getOk "RPC getrawtransaction success" (← client.getRawTransaction (← str p[0]!))
    check "RPC verbose transaction identity" (value.txid == (← text expected "txid") && value.raw == expected)
    let expectedOutputs ← arr (← item expected "vout")
    check "RPC transaction output count" (value.outputs.size == expectedOutputs.size)
    for a in value.outputs, raw in expectedOutputs do eqAmount "RPC transaction exact value" a (← item raw "value")
  | "getblock" =>
    let value ← getOk "RPC getblock success" (← client.getBlock (← str p[0]!))
    check "RPC block identity/height/time" (value.hash == (← text expected "hash") &&
      value.height == (← num (← item expected "height")) && value.time == (← num (← item expected "time")))
    check "RPC block transaction order" (toJson value.transactions == (← item expected "tx"))
  | _ => throw (IO.userError "assertion failed: eleven RPC wrapper inventory")

def rpcReplay (url path : String) : IO Unit := do
  let client : Client := { url, auth := pairAuth (some "lck") (some "lck-throwaway") }
  let entries ← arr (← item (← load path) "entries")
  let mut count := 0
  for entry in entries do
    let rpc ← item entry "rpc"
    let method ← text rpc "method"
    for params in ← arr (← item rpc "params") do
      let params ← arr params
      for response in ← arr (← item entry "responses") do
        let envelope ← getOk "RPC recorded envelope" (Json.parse (← text response "text"))
        if let .ok error := envelope.getObjVal? "error" then
          if error != .null then
            let result ← client.call method params
            check "RPC recorded invalid amount -3" (match result with | .error (.rpc (some (-3))) => true | _ => false)
            count := count + 1
            continue
        wrapper client method params (← item envelope "result")
        count := count + 1
  IO.println s!"RPC wrapper responses: {count}"

def rpcContinuation (url path : String) : IO Unit := do
  let data ← load path
  let entries ← arr (← item data "entries")
  let variants ← arr (← item (← item entries[0]! "rpc") "params")
  let params ← arr variants[0]!
  let descriptor ← str params[0]!
  let client : Client := { url, auth := some ("lck", "lck-throwaway") }
  let values ← getOk "RPC ignored import continuation" (← client.listUnspentForDescriptor descriptor)
  let lists := entries.filter fun e => (e.getObjVal? "rpc" >>= (·.getObjValAs? String "method")).toOption == some "listunspent"
  let mut expected := #[]
  for entry in lists do
    let response := (← arr (← item entry "responses"))[0]!
    let envelope ← getOk "continuation envelope" (Json.parse (← text response "text"))
    expected := expected ++ (← arr (← item envelope "result"))
  checkUtxos values (.arr expected)
  IO.println "RPC ignored-import continuation: 1/1"

def rpcContinuationFailure (url path : String) : IO Unit := do
  let entries ← arr (← item (← load path) "entries")
  let variants ← arr (← item (← item entries[0]! "rpc") "params")
  let params ← arr variants[0]!
  let client : Client := { url, auth := some ("lck", "wrong-descriptor-password") }
  let result ← client.listUnspentForDescriptor (← str params[0]!)
  check "RPC descriptor helper HTTP 401" (match result with | .error (.http 401) => true | _ => false)
  IO.println "RPC descriptor helper error class: 1/1"

def rpcRequest : IO Unit := do
  let request ← getOk "RPC synthetic driver input" (Json.parse (← (← IO.getStdin).readToEnd))
  if (request.getObjValAs? String "dir").toOption == some "" then
    -- Refuse an accidental root lookup before any filesystem access, including
    -- during the detecting mutation. The integration then reads its owned file.
    check "RPC empty directory relative cookie path" ((cookiePath "").toString == ".cookie")
  let client ← Client.ofFlags {
    url := ← text request "url",
    bitcoinDir := (request.getObjValAs? String "dir").toOption,
    user := (request.getObjValAs? String "user").toOption,
    password := (request.getObjValAs? String "password").toOption }
  let client := { client with totalTimeoutMs :=
    ((request.getObjValAs? Nat "totalTimeoutMs").toOption.map Nat.toUInt32).getD client.totalTimeoutMs }
  if (request.getObjValAs? String "operation").toOption == some "scan" then
    let result ← client.scanTxOutSet #[]
    match result with
    | .ok scan => IO.println (Json.mkObj [("success", toJson scan.success), ("height", toJson scan.height)]).compress
    | .error e => IO.println (Json.mkObj [("error", .str e.message)]).compress
    return
  if (request.getObjValAs? String "operation").toOption == some "create" then
    let values ← (← arr (← item request "amounts")).mapM btc
    let result ← client.createPsbt #[{ txid := "synthetic", vout := 2, sequence := some 7 }]
      (values.mapIdx fun i a => (s!"synthetic-{i}", a)) 12 true
    match result with
    | .ok psbt => IO.println (Json.mkObj [("result", .str psbt)]).compress
    | .error e => IO.println (Json.mkObj [("error", .str e.message)]).compress
    return
  if (request.getObjValAs? String "operation").toOption == some "received" then
    let result ← client.getReceivedByAddress "synthetic" 7
    match result with
    | .ok a => IO.println (Json.mkObj [("msat", toJson a.msat)]).compress
    | .error e => IO.println (Json.mkObj [("error", .str e.message)]).compress
    return
  let result ← client.call (← text request "method") (← arr (← item request "params"))
  match result with
  | .error e => IO.println (Json.mkObj [("error", .str e.message), ("kind", .str (reprStr e))]).compress
  | .ok value => IO.println (Json.mkObj [("result", value)]).compress

def rpcPure : IO Unit := do
  check "RPC default transfer deadline" (({ url := "http://example.invalid:18444" } : Client).totalTimeoutMs == 30000)
  IO.println "RPC default transfer deadline: 1/1"
  let defaults ← getOk "RPC default flags" (RpcFlags.parse [])
  check "RPC default URL and absent credentials" (defaults == ({} : RpcFlags) &&
    defaults.url == "http://127.0.0.1:8332" && defaults.bitcoinDir.isNone &&
    defaults.user.isNone && defaults.password.isNone)
  let mut flagCount := 1
  for attached in [false, true] do
    let flag := fun k v => if attached then [k ++ "=" ++ v] else [k, v]
    let explicit ← getOk "RPC explicit flags" (RpcFlags.parse (flag "--rpc-url" "http://example.invalid:18443" ++
      flag "--rpc-user" "user" ++ flag "--rpc-password" "pass"))
    check "RPC explicit flag values" (explicit.url == "http://example.invalid:18443" && explicit.user == some "user" && explicit.password == some "pass")
    for credential in ["--rpc-user", "--rpc-password"] do
      check "RPC directory conflicts with either credential" ((RpcFlags.parse (flag "--bitcoin-dir" "explicit" ++ flag credential "value")).toOption.isNone)
      flagCount := flagCount + 1
    let directory ← getOk "RPC directory flag" (RpcFlags.parse (flag "--bitcoin-dir" "explicit"))
    check "RPC explicit directory" (directory.bitcoinDir == some "explicit")
    flagCount := flagCount + 2
  counted "RPC shared flags" flagCount 9
  let pairs := [(none, none, none), (some "u", none, none), (none, some "p", none),
    (some "", some "", some ("", "")), (some "u", some "p", some ("u", "p"))]
  for (u, p, expected) in pairs do check "RPC both credentials present" (pairAuth u p == expected)
  counted "RPC credential pairs" pairs.length 5
  let cookies := [("  u:p:q\n", some ("u", "p:q")), (":", some ("", "")), ("u:", some ("u", "")),
    (":p", some ("", "p")), ("malformed", none), ("  ", none),
    ("\u00a0u:p:q\u3000", some ("u", "p:q")), ("\u000bu:p\u000c", some ("u", "p"))]
  for (input, expected) in cookies do check "RPC cookie trim/first colon" (parseCookie input == expected)
  counted "RPC cookie parsing" cookies.length 8
  let amounts := [("1e-11", some 1), ("0.0000000000100", some 1), ("1.23456789012", some 123456789012),
    ("9007199254740993", some 900719925474099300000000000),
    ("18446744073709551617e-11", some 18446744073709551617), ("1e3", some 100000000000000),
    ("-1", none), ("1e-12", none), ("0.0000000000010", none), ("0e-20", some 0)]
  for (input, expected) in amounts do
    let value ← getOk "RPC numeric JSON fixture" (Json.parse input)
    let actual := (CoreRpc.amount value).toOption.map (·.msat)
    check s!"RPC exact incoming precision {input}" (actual == expected)
    if let some msat := expected then
      let encoded := amountJson ⟨msat⟩
      let decoded ← getOk "RPC outgoing numeric JSON" (Json.parse encoded.compress)
      check s!"RPC exact outgoing precision/type {input}" ((CoreRpc.amount decoded).toOption.map (·.msat) == some msat)
  counted "RPC exact numeric cases" amounts.length 10
  check "RPC input sequence option" (((CoreRpc.Input.json { txid := "synthetic", vout := 2, sequence := some 7 }).getObjValAs? Nat "sequence").toOption == some 7)
  check "RPC flags remain scoped" ((Cyberkrill.parseCommand ["version", "--rpc-user=x"]).toOption.isNone)
  IO.println "RPC pure optional/scoped boundaries: 2/2"

end CyberkrillTests
