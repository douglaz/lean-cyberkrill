/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Lean Cyberkrill

def psbtFetch : IO Unit := do
  let payload ← getOk "PSBT request" (Json.parse (← (← IO.getStdin).readToEnd))
  let url ← text payload "url"
  let inputs ← getOk "PSBT inputs" (payload.getObjValAs? (Array String) "inputs")
  let outputs ← getOk "PSBT outputs" (PsbtCommands.parseOutputs (← text payload "outputs"))
  let funded := (payload.getObjValAs? Bool "funded").toOption.getD false
  let timeout := (payload.getObjValAs? Nat "timeout").toOption.getD 30000
  let size := (payload.getObjValAs? Nat "bytes").toOption.getD 1048576
  let rate ← (payload.getObjValAs? String "fee").toOption.mapM fun s => getOk "PSBT fee" (parseFee s)
  let client : CoreRpc.Client := {
    url, auth := some ("lck", "lck-throwaway"),
    totalTimeoutMs := timeout.toUInt32, maxResponseBytes := size.toUSize }
  match ← PsbtCommands.fetch client { inputs, outputs := "", funded, feeRate := rate } outputs with
  | .error e => IO.println (Json.mkObj [("error", .str e.message)]).compress
  | .ok result => IO.println result.json.compress

/-- Source-derived scanner controls, never reference CLI or price-feed calls. -/
def psbtWhitespace (only : Option String := none) : IO Unit := do
  let events ← IO.mkRef ([] : List String)
  let services := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      return fun _ => events.modify (· ++ ["json"])
    coreClient := fun _ => do
      events.modify (· ++ ["client"])
      throw (IO.userError "unexpected client")
    readFile := fun _ => do
      events.modify (· ++ ["read"])
      throw (IO.userError "unexpected read") }
  let mut count := 0
  for (commandPrefix, command) in [("create", "onchain-create-psbt"), ("funded", "onchain-create-funded-psbt")] do
    for (name, outputs, error) in [
        ("grouped-control", "destination:1,234USD", Error.fiatNotSupported),
        ("nbsp", "destination:1,234USD\u00a0", Error.fiatNotSupported),
        ("precedence", "destination:1msat,other:1,234USD\u00a0", Error.wholeSatRequired),
        ("vertical-tab", "d:1,000\x0bUSD", Error.onchain "invalidOutputs: Expected nonempty address:amount entries"),
        ("unicode-separator", "destination:1,234USD\u2003,other:1sat", Error.fiatNotSupported),
        ("internal-unicode", "destination:1,234\u00a0USD", Error.onchain "invalidOutputs: Expected nonempty address:amount entries")] do
      let label := commandPrefix ++ "-" ++ name
      if only.isSome && only != some label then continue
      events.set []
      let (status, out, err) ← runCase services [command, "--inputs", "synthetic:0", "--outputs", outputs, "-o", "output"]
      check ("PSBT scanner whitespace " ++ label) (status == 1 && out.isEmpty && err == error.message ++ "\n" &&
        (← events.get) == ["open"])
      count := count + 1
  check "PSBT scanner whitespace inventory" (count == if only.isSome then 1 else 12)
  IO.println s!"PSBT scanner whitespace: {count} source-derived controls; exact errors/status/empty stdout; retained writer only"

def psbtInjected : IO Unit := do
  if let some selected ← IO.getEnv "LCK_TEST_PSBT_WHITESPACE" then
    psbtWhitespace (some selected)
    return
  let events ← IO.mkRef ([] : List String)
  let base := { productionServices with
    coreClient := fun _ => do events.modify (· ++ ["client"]); pure { url := "unused" }
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      return fun _ => events.modify (· ++ ["json"])
    writeOrdinaryFile := fun _ text => do
      check "PSBT raw no newline" (text == "recorded-result")
      events.modify (· ++ ["raw"])
    readFile := fun _ => do events.modify (· ++ ["read"]); pure "private-sentinel"
    psbt := fun _ _ outputs => do
      check "PSBT collapse before orchestration" (outputs.size == 1 && (outputs[0]?.map (·.2.msat)) == some 1000)
      events.modify (· ++ ["rpc"])
      pure (.ok { psbt := "recorded-result", feeSats := 0, changePosition := .null }) }
  let mut count := 0
  for command in ["onchain-create-psbt", "onchain-create-funded-psbt"] do
    let common := [command, "--inputs", "synthetic:0", "--outputs", "destination:2sats,destination:1sat", "-o", "output"]
    events.set []
    let (status, out, err) ← runCase base (common ++ ["--psbt-output", "raw"])
    check "PSBT retained single writer/raw before JSON" (status == 0 && out.isEmpty && err.isEmpty &&
      (← events.get) == ["open", "client", "rpc", "raw", "json"])
    count := count + 1
    events.set []
    let throwing := { base with writeOrdinaryFile := fun _ _ => do
      events.modify (· ++ ["raw"]); throw (IO.userError "private-sentinel") }
    let (status, out, err) ← runCase throwing (common ++ ["--psbt-output", "raw"])
    check "PSBT raw failure before JSON" (status == 1 && out.isEmpty && err.startsWith "outputFailure:" &&
      (← events.get) == ["open", "client", "rpc", "raw"])
    count := count + 1
    for extra in [["--network", "bad"], ["--wallet-file", "unread"],
        ["--descriptor", "ignored", "--bitcoin-dir", "unused"]] do
      events.set []
      let (status, _, _) ← runCase base (common ++ extra)
      check "PSBT early truncate before execution refusal" (status == 1 && (← events.get) == ["open"])
      count := count + 1
      events.set []
      let services := { base with openOrdinaryFile := fun _ => do
        events.modify (· ++ ["open"]); throw (IO.userError "private-sentinel") }
      let (status, _, err) ← runCase services (common ++ extra)
      check "PSBT writer failure precedence" (status == 1 && err == "outputFailure: Cannot write output\n" &&
        (← events.get) == ["open"])
      count := count + 1
    for outputs in ["destination:1USD", "destination:1,234.56USD", "destination:12,34,567INR"] do
      events.set []
      let (status, _, err) ← runCase base [command, "--inputs", "synthetic:0", "--outputs", outputs, "-o", "output"]
      check "PSBT fiat has no client or child" (status == 1 && err.startsWith "fiatNotSupported:" && (← events.get) == ["open"])
      count := count + 1
    for (outputs, error) in [
        ("destination:123,45,678INR", "fiatNotSupported:"),
        ("destination:1e5USD", "fiatNotSupported:"),
        ("destination:1.2e+5USD", "fiatNotSupported:"),
        ("destination:1e-500USD", "fiatNotSupported:"),
        ("destination:1,234.5e2USD", "invalidOutputs:"),
        ("destination:1msat,other:123,45,678INR", "wholeSatRequired:"),
        ("destination:1msat,other:1e5USD", "wholeSatRequired:"),
        ("destination:1e5USD,broken", "invalidOutputs:"),
        ("destination:123,45,678INR,broken", "invalidOutputs:"),
        ("destination:1e500USD", "invalidNumber:"),
        ("destination:1eUSD", "invalidNumber:"),
        ("destination:+1USD", "invalidNumber:"),
        ("destination:.5USD", "invalidNumber:"),
        ("destination:1.USD", "invalidNumber:"),
        ("destination:1,23USD", "invalidNumber:"),
        ("destination:1234,56,789INR", "invalidNumber:"),
        ("destination:1e5btc", "invalidNumber:")] do
      events.set []
      let (status, out, err) ← runCase base [command, "--inputs", "synthetic:0", "--outputs", outputs, "-o", "output"]
      check ("PSBT fiat classification/precedence " ++ outputs) (status == 1 && out.isEmpty && err.startsWith error &&
        (← events.get) == ["open"])
      count := count + 1
    for flags in [["--fee-rate", "0.00000001"], ["--bitcoin-dir", "unused", "--rpc-user", "private-sentinel"]] do
      events.set []
      let (status, _, _) ← runCase base (common ++ flags)
      check "PSBT parse refusal has no IO" (status == 1 && (← events.get).isEmpty)
      count := count + 1
    for name in ["mainnet", "BITCOIN", "testnet", "Signet", "REGTEST"] do
      events.set []
      let (status, _, _) ← runCase base (common ++ ["--network", name, "--descriptor", "ignored"])
      check "PSBT network aliases and ignored descriptor" (status == 0 && (← events.get) == ["open", "client", "rpc", "json"])
      count := count + 1
  for value in ["0", "+0", "4294967295", "+0001"] do
    check "PSBT u32 accepts" ((PsbtCommands.unsigned32 value).isSome)
  for value in ["", " ", " 1", "1 ", "1_0", "++1", "+-1", "-1", "4294967296", "١"] do
    check "PSBT u32 refuses" ((PsbtCommands.unsigned32 value).isNone)
  let result := PsbtCommands.parseOutputs "destination:1msat,other:1USD"
  check "PSBT precision before fiat" (result matches .error .wholeSatRequired)
  check "PSBT parse entries before precision" (PsbtCommands.parseOutputs "destination:1msat,broken" matches .error (.onchain _))
  check "PSBT injected inventory" (count == 70)
  IO.println s!"PSBT injection: {count}/70 writer/refusal controls; 14/14 u32; 2/2 parsing precedence; fiat zero IO beyond writer"
  psbtWhitespace

end CyberkrillTests
