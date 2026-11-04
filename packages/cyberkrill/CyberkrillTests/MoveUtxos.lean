/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Lean Cyberkrill Bitcoin

def moveFetch : IO Unit := do
  let payload ← getOk "move request" (Json.parse (← (← IO.getStdin).readToEnd))
  let args ← getOk "move argv" (payload.getObjValAs? (Array String) "args")
  let timeout := (payload.getObjValAs? Nat "timeout").toOption.getD 30000
  let size := (payload.getObjValAs? Nat "bytes").toOption.getD 1048576
  let services := { productionServices with coreClient := fun flags => do
    let client ← CoreRpc.Client.ofFlags flags
    return { client with totalTimeoutMs := timeout.toUInt32, maxResponseBytes := size.toUSize } }
  let status ← runWith version services args.toList
  check "move fetch status" (status == ((payload.getObjValAs? Nat "status").toOption.getD 0).toUInt32)

def moveOrdering (only : String := "") : IO Unit := do
  let events ← IO.mkRef ([] : List String)
  let services := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      return fun _ => events.modify (· ++ ["json"])
    coreClient := fun _ => do
      events.modify (· ++ ["client"])
      pure { url := "injected" }
    move := fun _ _ _ => do
      events.modify (· ++ ["move"])
      pure (.error (.onchain "unexpectedMove")) }
  for (name, extras, error, expected) in [
      ("missing-fee", [], "missingFee:", ["open"]),
      ("missing-before-network", ["--network", "bad"], "missingFee:", ["open"]),
      ("network-before-backend", ["--fee", "1sat", "--network", "bad", "--wallet-file", "x"], "invalidNetwork:", ["open"]),
      ("fiat", ["--fee", "1sat", "--max-amount", "100USD"], "fiatNotSupported:", ["open"]),
      ("fiat-exponent", ["--fee", "1sat", "--max-amount", "1,234.5e2USD"], "fiatNotSupported:", ["open"]),
      ("floor", ["--fee", "1sat", "--max-amount", "0.1sat"], "lessThanOneSat:", ["open"]),
      ("typed-fee", ["--fee", "bare"], "feeUnitRequired:", []),
      ("typed-maximum", ["--max-amount", "broken"], "invalidNumber:", []),
      ("fee-exclusive", ["--fee-rate", "1sat", "--fee", "1sat"], "invalidArguments:", [])] do
    if only.isEmpty || only == name then
      events.set []
      let (status, out, err) ← runCase services
        (["onchain-move-utxos", "--inputs", "a:0", "--destination", "destination", "-o", "json"] ++ extras)
      check ("move runtime ordering " ++ name) (status == 1 && out.isEmpty && err.startsWith error &&
        (← events.get) == expected)

/-- Exercise the strict RPC wrapper and the narrower command contract on the
same synthetic result; no captured Core behavior is claimed. -/
def moveRaw : IO Unit := do
  let payload ← getOk "move raw request" (Json.parse (← (← IO.getStdin).readToEnd))
  let url ← getOk "move raw URL" (payload.getObjValAs? String "url")
  let raw ← getOk "move raw payload" (payload.getObjVal? "raw")
  let index ← getOk "move raw index" (payload.getObjValAs? Nat "index")
  let valid ← getOk "move raw validity" (payload.getObjValAs? Bool "valid")
  let requested ← getOk "move raw requested amount" (MoveUtxos.requestedValue raw index)
  check "move requested array index" (requested.msat == 2000)
  let result ← ({ url } : CoreRpc.Client).getRawTransaction "synthetic"
  check "move strict raw result" (match result with
    | .error .invalidResult | .error .invalidAmount => !valid
    | .ok transaction => valid && transaction.txid == "synthetic" &&
        transaction.outputs.map (·.msat) == #[1000, 2000]
    | _ => false)

def moveInjected : IO Unit := do
  let events ← IO.mkRef ([] : List String)
  let base := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      return fun _ => events.modify (· ++ ["json"])
    coreClient := fun flags => do
      check "move RPC flags retained" (flags.url == "injected")
      events.modify (· ++ ["client"])
      pure { url := flags.url }
    move := fun client args maximum => do
      check "move supplied client" (client.url == "injected")
      check "move inputs/destination/fee" (args.inputs == #["a:0", "b:1"] &&
        args.destination == "destination" && args.fee.map (·.msat) == some 1500)
      check "move floored maximum" (maximum.map (·.msat) == some 1000)
      events.modify (· ++ ["move"])
      pure (.ok { psbt := "injected-result", feeSats := 1, changePosition := .null })
    writeOrdinaryFile := fun _ value => do
      check "move raw original" (value == "injected-result")
      events.modify (· ++ ["raw"]) }
  let common := ["onchain-move-utxos", "--inputs", "a:0", "--inputs=b:1",
    "--destination", "destination", "--fee", "1.5sat", "--max-amount=1.999sat",
    "--rpc-url", "injected", "-o", "json", "--psbt-output=raw"]
  let mut count := 0
  for (name, extra, error) in [
      ("success", [], ""),
      ("ignored-descriptor", ["--descriptor", "ignored"], ""),
      ("network", ["--network", "bad"], "invalidNetwork:"),
      ("wallet", ["--wallet-file", "unread"], "unsupportedWalletFile:"),
      ("wallet-directory", ["--wallet-file", "unread", "--bitcoin-dir", "unused"], "unsupportedWalletFile:"),
      ("bdk", ["--descriptor", "ignored", "--bitcoin-dir", "unused"], "unsupportedBackend:")] do
    events.set []
    let (status, out, err) ← runCase base (common ++ extra)
    let observed ← events.get
    check ("move injected " ++ name) (out.isEmpty &&
      if error.isEmpty then status == 0 && err.isEmpty &&
        observed == ["open", "client", "move", "raw", "json"]
      else status == 1 && err.startsWith error && observed == ["open"])
    count := count + 1
    events.set []
    let failed := { base with openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"]); throw (IO.userError "private-sentinel") }
    let (status, out, err) ← runCase failed (common ++ extra)
    check ("move open precedence " ++ name) (status == 1 && out.isEmpty &&
      err == "outputFailure: Cannot write output\n" && (← events.get) == ["open"])
    count := count + 1
  for (name, services, expected) in [
      ("raw", { base with writeOrdinaryFile := fun _ _ => do
        events.modify (· ++ ["raw"]); throw (IO.userError "private-sentinel") },
        ["open", "client", "move", "raw"]),
      ("json", { base with openOrdinaryFile := fun _ => do
        events.modify (· ++ ["open"])
        return fun _ => do events.modify (· ++ ["json"]); throw (IO.userError "private-sentinel") },
        ["open", "client", "move", "raw", "json"]),
      ("client", { base with coreClient := fun _ => do
        events.modify (· ++ ["client"]); throw (IO.userError "private-sentinel") },
        ["open", "client"])] do
    events.set []
    let (status, out, err) ← runCase services common
    check ("move failure " ++ name) (status == 1 && out.isEmpty && !err.isEmpty &&
      (err.splitOn "private-sentinel").length == 1 && (← events.get) == expected)
    count := count + 1
  moveOrdering
  count := count + 9
  let values : Array (CoreRpc.Input × Amount) := #[
    ({ txid := "a", vout := 0 }, ⟨2000⟩), ({ txid := "b", vout := 1 }, ⟨1000⟩),
    ({ txid := "c", vout := 2 }, ⟨2000⟩)]
  for (cap, names, amount) in [
      (none, #["a", "b", "c"], 5000),
      (some (Amount.mk 0), #[], 0),
      (some ⟨1000⟩, #["a"], 2000),
      (some ⟨2000⟩, #["a"], 2000),
      (some ⟨3000⟩, #["a", "c"], 4000),
      (some ⟨6000⟩, #["a", "c", "b"], 5000)] do
    let (selected, total) := MoveUtxos.select values cap
    check "move stable exact selection" (selected.map (·.txid) == names && total.msat == amount)
    count := count + 1
  for (value, index, expected) in [
      ("{\"vout\":[{\"n\":9,\"value\":0.00000001},{}]}", 0, some 1000),
      ("{\"txid\":false,\"vout\":[{}, {\"value\":0.00000002}]}", 1, some 2000),
      ("{\"vout\":[{}]}", 0, none),
      ("{\"vout\":[{\"value\":-1}]}", 0, none),
      ("{\"vout\":[{\"value\":0.000000000001}]}", 0, none),
      ("{\"vout\":[]}", 0, none)] do
    let raw ← getOk "move synthetic JSON" (Json.parse value)
    check "move narrow requested value" ((MoveUtxos.requestedValue raw index).toOption.map (·.msat) == expected)
    count := count + 1
  for value in ["1,23USD", "1e500USD"] do
    let parsed := parseCommand ["onchain-move-utxos", "--max-amount", value, "--help"]
    check "move malformed fiat before help" (match parsed with | .error (.amount .invalidNumber) => true | _ => false)
    count := count + 1
  counted "move injection/selection/lookup" count 38

end CyberkrillTests
