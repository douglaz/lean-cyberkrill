/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support
import Std.Sync.Mutex

namespace CyberkrillTests
open Cyberkrill Lean

private def exact (s : String) : IO Exact := do
  let some value := Exact.parse s | throw (IO.userError "invalid exact fixture")
  return value

private def ratio (n : Exact) : Json := Json.mkObj [
  ("numerator", .str (toString n.numerator)), ("denominator", .str (toString n.denominator))]

private def outcome {α : Type} (render : α → Json) : Except String α → Json
  | .ok value => Json.mkObj [("ok", render value)]
  | .error e => Json.mkObj [("error", .str e)]

def priceEvaluate : IO Unit := do
  let j ← getOk "price input JSON" (Json.parse (← (← IO.getStdin).readToEnd))
  let rows ← getOk "price input rows" j.getArr?
  let mut outputs := #[]
  for row in rows do
    let op ← text row "op"
    let result ← match op with
      | "parse" => do
        let result := PriceFeed.parse (← text row "source") (← text row "currency") (← text row "body")
        pure (outcome (fun value => value.map ratio |>.getD .null) result)
      | "grammar" => do
        pure (outcome (fun f => Json.mkObj [("amount", ratio f.amount), ("currency", .str f.currency)])
          ((parseFiat (← text row "input")).mapError Error.message))
      | "convert" => do
        let amount ← exact (← text row "amount")
        let price ← exact (← text row "price")
        let mode := match ← text row "mode" with
          | "whole" => FiatConversionPrecision.wholeSat
          | "floor" => .floorSat
          | _ => .millisat
        pure (outcome (fun a => toJson a.msat)
          ((convertFiat ⟨amount, "USD"⟩ ((row.getObjValAs? String "currency").toOption.getD "USD") price mode).mapError Error.message))
      | "aggregate" => do
        let entries ← getOk "quotes" (row.getObjValAs? (Array Json) "quotes")
        let quotes ← entries.mapM fun q => do
          return PriceFeed.Quote.mk (← text q "source") (← exact (← text q "price"))
        pure (outcome (fun p => Json.mkObj [
          ("price", ratio p.price), ("sources", toJson (p.sources.map (·.source))),
          ("warning", .str (PriceFeed.spreadWarning p)), ("breadcrumb", .str (PriceFeed.breadcrumb p))])
          (PriceFeed.aggregate "USD" quotes))
      | "median" => do
        let values ← getOk "median values" (row.getObjValAs? (Array String) "values")
        pure ((PriceFeed.median (← values.mapM exact)).map ratio |>.getD .null)
      | "display" => do
        let value ← exact (← text row "value")
        pure (Json.mkObj [("fixed", .str (value.fixed 2)), ("json", value.json)])
      | "cross-output" => do
        let input ← text row "input"
        let fiat ← getOk "cross fiat" (parseFiat input)
        let some price ← getOk "cross parser" (PriceFeed.parse "fedi" fiat.currency (← text row "body"))
          | throw (IO.userError "cross price absent")
        let amount ← getOk "cross conversion" (convertFiat fiat fiat.currency price .millisat)
        let out ← getOk "cross output" (conversionOutput input none amount (some (fiat, ⟨fiat.currency,price,#[]⟩)))
        getOk "cross JSON output" (Json.parse out.stdout)
      | "response" => do
        let source ← text row "source"
        let some feed := PriceFeed.feeds.find? (·.source == source) | throw (IO.userError "fixture feed")
        let status ← getOk "fixture status" (row.getObjValAs? Nat "status")
        let bytes ← match (row.getObjValAs? (Array Nat) "bytes").toOption with
          | some bytes => pure (ByteArray.mk (bytes.map Nat.toUInt8))
          | none => pure (← text row "body").toUTF8
        pure (outcome (fun value => value.map ratio |>.getD .null)
          (PriceFeed.response feed "USD" ⟨status.toUInt32, #[], bytes⟩))
      | _ => throw (IO.userError "unknown price operation")
    outputs := outputs.push (Json.mkObj [("id", .str (← text row "id")), ("result", result)])
  IO.println (Json.arr outputs).compress

def priceRun : IO Unit := do
  let j ← getOk "price run JSON" (Json.parse (← (← IO.getStdin).readToEnd))
  let bases ← getOk "test feed URLs" (j.getObjValAs? (Array String) "feeds")
  let history ← text j "history"
  let rpc ← text j "rpc"
  let args ← getOk "test argv" (j.getObjValAs? (List String) "args")
  let result ← runWithTestUrls version ⟨bases, history, rpc⟩ args
  IO.println (Json.mkObj [("status", toJson result.status.toNat), ("stdout", .str result.stdout),
    ("stderr", .str result.stderr)]).compress

private def safeUrls : TestUrls :=
  ⟨Array.replicate 9 "http://127.0.0.1:19431", "http://127.0.0.1:19431", "http://127.0.0.1:19431"⟩

def priceFormerRefusals : IO Unit := do
  let rows := ["100USD", "2081.74BRL", "1,000 USD", "-bad1usd", " 1 EUR "]
  counted "guarded former fiat inputs" rows.length 5
  let body := "{\"bitcoin\":{\"usd\":95000,\"brl\":95000,\"eur\":95000},\"data\":{\"rates\":{\"USD\":95000,\"BRL\":95000,\"EUR\":95000}},\"USD\":{\"last\":95000},\"BRL\":{\"last\":95000},\"EUR\":{\"last\":95000},\"last\":95000,\"rate\":95000,\"result\":{\"PAIR\":{\"c\":[95000]}},\"prices\":{\"BTC/USD\":{\"rate\":95000},\"BRL/USD\":{\"rate\":1},\"EUR/USD\":{\"rate\":1}}}"
  for input in rows do
    let calls ← Std.Mutex.new (0 : Nat)
    let request := fun (_ : HttpCurl.Request) => do
      calls.atomically (modify (· + 1))
      return Except.ok (HttpCurl.Response.mk 200 #[] body.toUTF8)
    let result ← runWithTestUrls version safeUrls ["convert-amount", "--", input] (request := request)
    let n ← calls.atomically get
    if input == "-bad1usd" then
      check "former malformed fiat before requests" (result.status == 1 && result.stdout.isEmpty && n == 0)
    else
      check "former fiat now converts" (result.status == 0 && n == 9 && result.stderr.startsWith "[price-feed] median")

def priceTasks : IO Unit := do
  let calls ← Std.Mutex.new (0 : Nat)
  let contracts ← Std.Mutex.new true
  let request := fun (r : HttpCurl.Request) => do
    contracts.atomically (modify (fun valid => valid && r.totalTimeoutMs == 8000 &&
      r.connectTimeoutMs == 0 && r.maxResponseBytes == 1048576))
    calls.atomically (modify (· + 1))
    if r.url.startsWith "https://api.coingecko.com/" then throw (IO.userError "synthetic task failure")
    if r.url.startsWith "https://api.coinbase.com/" then
      return Except.error (HttpCurl.Error.timeout 28 "Request timed out")
    if r.url.startsWith "https://blockchain.info/" then
      return Except.ok (HttpCurl.Response.mk 200 #[] "{".toUTF8)
    return Except.ok (HttpCurl.Response.mk 200 #[] "{}".toUTF8)
  let result ← PriceFeed.fetch "USD" (request := request)
  check "per-feed deadline and response bound" (← contracts.atomically get)
  let .error error := result.price | throw (IO.userError "task failure lost quorum refusal")
  let n ← calls.atomically get
  let controls := [
    ("task failure distinct", (error.splitOn "feed task failed: synthetic task failure").length == 2),
    ("transport issue distinct", (error.splitOn "coinbase: Coinbase request failed:").length == 2 &&
      (error.splitOn "timeout").length == 2),
    ("parse issue distinct", (error.splitOn "blockchain.info: Invalid Blockchain.info JSON").length == 2),
    ("absent quote distinct", (error.splitOn "gemini: no USD quote").length == 2),
    ("all feed tasks waited", n == 9)]
  for (name, condition) in controls do check name condition
  counted "task/transport/parse/absence" controls.length 5
  counted "per-feed request contracts" n 9

def priceGuards : IO Unit := do
  let calls ← Std.Mutex.new (0 : Nat)
  let request := fun (_ : HttpCurl.Request) => do
    calls.atomically (modify (· + 1))
    throw (IO.userError "guard allowed transport")
  let guarded : Services := { productionServices with
    coreClient := fun _ => do
      calls.atomically (modify (· + 1))
      throw (IO.userError "guard allowed Core client") }
  let encodedOverride := Bitcoin.Bech32.encode "lnurl"
    (Bitcoin.Bech32.convertbits8to5 "https://127.0.0.1:8332/".toUTF8) .bech32
  let badUrls := ["http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:8332", "http://127.0.0.1:08332",
    "http://127.0.0.1:65536", "http://localhost:19431", "http://127.1:19431", "http://127.0.0.1.evil:19431",
    "http://127.0.0.1:19431@evil", "http://evil@127.0.0.1:19431", "http://%31%32%37.0.0.1:19431",
    "http://127.0.0.1:19431\\@evil", "http://127.0.0.1:19431/https://evil", "http://127.0.0.1:19431/%40evil",
    "http://[::1]:19431", "ftp://127.0.0.1:19431", " http://127.0.0.1:19431", "http://127.0.0.1:19431:\n",
    "http://127.0.0.1:19431/?next=https%253A%252F%252Fevil.invalid%253A443",
    "http://127.0.0.1:19431/?next=https%25253A%25252F%25252Fevil.invalid%25253A443",
    "http://127.0.0.1:19431/?next=https%253A%252F%252Fevil.invalid%253A8332",
    "http://127.0.0.1:19431/?next=https%2525253A%2525252F%2525252Fevil.invalid%2525253A443",
    "http://127.0.0.1:19431/?endpoint=127.0.0.1:8332",
    "http://127.0.0.1:19431/?next=" ++ encodedOverride,
    "http://127.0.0.1:19431/?next=" ++ Bitcoin.Bech32.encode "lnurl"
      (Bitcoin.Bech32.convertbits8to5 "https://evil.invalid:443/".toUTF8) .bech32,
    "http://127.0.0.1:19431/?next=" ++ Bitcoin.Bech32.encode "fed1"
      (Bitcoin.Bech32.convertbits8to5 "https://evil.invalid:443/".toUTF8) .bech32m]
  counted "override URL refusals" badUrls.length 26
  for url in badUrls do
    for slot in [:11] do
      let urls := if slot < 9 then { safeUrls with feedBases := safeUrls.feedBases.set! slot url }
        else if slot == 9 then { safeUrls with coinGeckoHistory := url } else { safeUrls with dcaRpc := url }
      let result ← runWithTestUrls version urls ["convert-amount", "1sat"] (services := guarded) (request := request)
      check "every unused override slot before action" (result.status == 1 && result.stdout.isEmpty && result.stderr.startsWith "testUrlRefused:")
  let incomplete := [#[], #["http://127.0.0.1:19431"], Array.replicate 10 "http://127.0.0.1:19431"]
  for bases in incomplete do
    let r ← runWithTestUrls version { safeUrls with feedBases := bases } ["version"] (services := guarded) (request := request)
    check "incomplete override refused" (r.status == 1 && r.stdout.isEmpty)
  counted "override incomplete counts" incomplete.length 3
  let commands := ["onchain-list-utxos", "onchain-create-psbt", "onchain-create-funded-psbt", "onchain-move-utxos"]
  let refusedArgs := [[], ["--rpc-url", "http://127.0.0.1:8332"], ["--rpc-url=http://localhost:19431"],
    ["--", "--rpc-url", "http://127.0.0.1:19431"]]
  for command in commands do
    for args in refusedArgs do
      let r ← runWithTestUrls version safeUrls (command :: args) (services := guarded) (request := request)
      check "explicit Core argv guard" (r.status == 1 && r.stdout.isEmpty && r.stderr.startsWith "test")
  counted "Core argv refusals" (commands.length * refusedArgs.length) 16
  for command in commands do
    check "explicit permitted Core URL accepted" ((safeUrls.validate [command, "--rpc-url", "http://127.0.0.1:19431"]).isOk)
  counted "Core URL acceptance controls" commands.length 4
  let embedded := ["http://127.0.0.1:8332/a", "user@127.0.0.1:08332", "https%253A%252F%252F127.0.0.1%253A8332"]
  let bytes := "https://127.0.0.1:8332/invite".toUTF8
  let encoded := [Bitcoin.Bech32.encode "lnurl" (Bitcoin.Bech32.convertbits8to5 bytes) .bech32,
    Bitcoin.Bech32.encode "fed1" (Bitcoin.Bech32.convertbits8to5 bytes) .bech32m]
  for token in embedded ++ encoded do
    let r ← runWithTestUrls version safeUrls ["version", token] (services := guarded) (request := request)
    check "nested URL port refused" (r.status == 1 && r.stderr.startsWith "testArgRefused:")
  counted "nested URL refusals" (embedded ++ encoded).length 5
  let encode := fun (s : String) => s.replace "%" "%25" |>.replace ":" "%3A" |>.replace "/" "%2F"
  let mut nestedControls := 0
  let depths := [4, 5, 6, 12]
  for depth in depths do
    let hidden := (List.range depth).foldl (fun s _ => encode s) "https://evil.invalid:443/"
    let port := (List.range depth).foldl (fun s _ => encode s) "https://127.0.0.1:8332/"
    check "permitted decode exhaustion" (!TestUrls.permitted ("http://127.0.0.1:19431/?next=" ++ hidden))
    let concealed := [hidden, port, "%GG", "%FF", "%5Cevil", "%00",
      Bitcoin.Bech32.encode "lnurl" (Bitcoin.Bech32.convertbits8to5 hidden.toUTF8) .bech32,
      Bitcoin.Bech32.encode "fed1" (Bitcoin.Bech32.convertbits8to5 hidden.toUTF8) .bech32m,
      Bitcoin.Bech32.encode "lnurl" (Bitcoin.Bech32.convertbits8to5 port.toUTF8) .bech32]
    for target in concealed do
      for slot in [:11] do
        let url := "http://127.0.0.1:19431/?next=" ++ target
        let urls := if slot < 9 then { safeUrls with feedBases := safeUrls.feedBases.set! slot url }
          else if slot == 9 then { safeUrls with coinGeckoHistory := url } else { safeUrls with dcaRpc := url }
        let r ← runWithTestUrls version urls ["convert-amount", "1sat"] (services := guarded) (request := request)
        check "nested override fail closed" (r.status == 1 && r.stdout.isEmpty && r.stderr.startsWith "testUrlRefused:")
        nestedControls := nestedControls + 1
    let wrapped := [port,
      Bitcoin.Bech32.encode "lnurl" (Bitcoin.Bech32.convertbits8to5 port.toUTF8) .bech32,
      Bitcoin.Bech32.encode "fed1" (Bitcoin.Bech32.convertbits8to5 port.toUTF8) .bech32m]
    for token in wrapped do
      let r ← runWithTestUrls version safeUrls ["version", token] (services := guarded) (request := request)
      check "nested argv fail closed" (r.status == 1 && r.stdout.isEmpty && r.stderr.startsWith "testArgRefused:")
      nestedControls := nestedControls + 1
  counted "nested decoding boundary refusals" nestedControls 408
  counted "permitted decoding boundary controls" depths.length 4
  let safeEncoded := ["/?x=plain", "/?x=%41", "/?x=%2541", "/?x=%252541", "/?x=%25252541"]
  for tail in safeEncoded do
    let r ← runWithTestUrls version { safeUrls with coinGeckoHistory := "http://127.0.0.1:19431" ++ tail }
      ["convert-amount", "1sat"] (services := guarded) (request := request)
    check "safe encoded override fixed point" (r.status == 0 && r.stderr.isEmpty && !r.stdout.isEmpty)
  counted "safe encoded override controls" safeEncoded.length 5
  let safeMaterial := "https://127.0.0.1:19431/fixture"
  let safeArgs := [safeMaterial,
    Bitcoin.Bech32.encode "lnurl" (Bitcoin.Bech32.convertbits8to5 safeMaterial.toUTF8) .bech32,
    Bitcoin.Bech32.encode "fed1" (Bitcoin.Bech32.convertbits8to5 safeMaterial.toUTF8) .bech32m]
  for token in safeArgs do
    check "safe embedded argv material" ((safeUrls.validate ["version", token]).isOk)
  counted "safe embedded argv controls" safeArgs.length 3
  let invalid := ["+1USD", "-1USD", ".5USD", "5.USD", "1,23USD", "-bad1usd", "1.2.3USD"]
  for input in invalid do
    let r ← runWithTestUrls version safeUrls ["convert-amount", "--", input] (services := guarded) (request := request)
    check "invalid fiat before fetch" (r.status == 1 && r.stdout.isEmpty)
  counted "malformed fiat no-fetch" invalid.length 7
  let bitcoin := [".5", "5.", "+5msat", "+0.5btc", "+0.5", "-0", "-0.0btc", "-0.000sat", "0.5000sat"]
  for input in bitcoin do
    let r ← runWithTestUrls version safeUrls ["convert-amount", "--", input] (services := guarded) (request := request)
    check "Bitcoin priority no-fetch" (r.status == 0 && r.stderr.isEmpty && !(r.stdout.splitOn "fiat_source").length > 1)
  counted "Bitcoin priority spellings" bitcoin.length 9
  check "all guard tests zero transport" ((← calls.atomically get) == 0)

end CyberkrillTests
