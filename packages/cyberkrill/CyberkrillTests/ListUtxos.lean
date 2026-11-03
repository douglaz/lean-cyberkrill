/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Lean Cyberkrill

def walletReader : IO Unit := do
  let content ← (← IO.getStdin).readToEnd
  match Frozenkrill.parse content with
  | .error _ => IO.println "invalidWallet"
  | .ok wallet => IO.println (Json.mkObj [("receiving", .str wallet.receiving), ("change", .str wallet.change)]).compress

def listFetch : IO Unit := do
  let payload ← getOk "list input" (Json.parse (← (← IO.getStdin).readToEnd))
  let url ← text payload "url"
  let descriptor ← text payload "descriptor"
  let timeout ← getOk "list timeout" (payload.getObjValAs? Nat "timeout")
  let bytes ← getOk "list size" (payload.getObjValAs? Nat "bytes")
  let client : CoreRpc.Client := {
    url, auth := some ("lck", "lck-throwaway"),
    totalTimeoutMs := timeout.toUInt32, maxResponseBytes := bytes.toUSize }
  let result ← ListUtxos.fetch client { descriptor := some descriptor, minConf := 0 } none
  match result with
  | .error e => IO.println (Json.mkObj [("error", .str e.message)]).compress
  | .ok result => IO.println result.compress

def listSplit : IO Unit := do
  let events ← IO.mkRef ([] : List String)
  let services := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      return fun _ => events.modify (· ++ ["write"])
    readFile := fun _ => do events.modify (· ++ ["read"]); pure "{}"
    coreClient := fun _ => do events.modify (· ++ ["client"]); pure { url := "unused" }
    listUtxos := fun _ _ _ => do events.modify (· ++ ["rpc"]); pure (.ok .null) }
  let mut count := 0
  for flag in ["--descriptor", "--addresses", "--wallet-file", "--rpc-url", "--bitcoin-dir",
      "--rpc-user", "--rpc-password"] do
    for value in ["--help", "-x", "-abc", "--", "--output=unused"] do
      for suffix in [[], ["--help"]] do
        events.set []
        let args := ["onchain-list-utxos", "-o", "unused", flag, value] ++ suffix
        let (status, out, err) ← runCase services args
        check "list split refusal side effects" ((← events.get).isEmpty)
        check "list split value refusal" (status != 0 && out.isEmpty && err.startsWith "invalidArguments:")
        count := count + 1
    for value in ["-x", "--help", "--", "a=b=c", ""] do
      match parseCommand ["onchain-list-utxos", flag ++ "=" ++ value] with
      | .ok (.listUtxos args) =>
        let actual := match flag with
          | "--descriptor" => args.descriptor
          | "--addresses" => args.addresses
          | "--wallet-file" => args.walletFile
          | "--rpc-url" => some args.rpc.url
          | "--bitcoin-dir" => args.rpc.bitcoinDir
          | "--rpc-user" => args.rpc.user
          | _ => args.rpc.password
        check "list attached value bytes" (actual == some value)
      | _ => check "list attached value acceptance" false
      count := count + 1
    for value in ["-", ""] do
      match parseCommand ["onchain-list-utxos", flag, value] with
      | .ok (.listUtxos _) => pure ()
      | _ => check "list split dash/empty acceptance" false
      count := count + 1
    events.set []
    let (status, out, err) ← runCase services ["onchain-list-utxos", "--help", flag, "-x", "-o", "unused"]
    check "list help before split refusal" (status == 0 && !out.isEmpty && err.isEmpty && (← events.get).isEmpty)
    count := count + 1
  check "list split inventory" (count == 126)
  IO.println s!"list split values: {count} injected/parser checks; refusals have zero side effects"

def listInjected : IO Unit := do
  listSplit
  let events ← IO.mkRef ([] : List String)
  let services := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      return fun text => do
        check "list writer newline" (!text.endsWith "\n")
        events.modify (· ++ ["write"])
    readFile := fun _ => do
      events.modify (· ++ ["read"])
      throw (IO.userError "private-wallet-sentinel")
    coreClient := fun _ => do
      events.modify (· ++ ["client"])
      pure { url := "unused" }
    listUtxos := fun _ args _ => do
      check "list confirmation defaults" (args.minConf == 1 && args.maxConf == 9999999)
      events.modify (· ++ ["fetch"])
      pure (.ok (Json.mkObj [("utxos", .arr #[]), ("total_amount_sats", toJson (0 : Nat)), ("total_count", toJson (0 : Nat))])) }
  let (status, out, err) ← runCase services ["onchain-list-utxos", "--addresses", "", "-o", "unused"]
  check "list dispatch" (status == 0 && out.isEmpty && err.isEmpty)
  check "list retained single writer" ((← events.get) == ["open", "client", "fetch", "write"])
  for (args, expected, message) in [
      (["--network", "bad"], ["open"], "invalidNetwork"),
      (["--wallet-file", "unused"], ["open", "read"], "walletReadFailure"),
      ([], ["open"], "missingSource"),
      (["--descriptor", "unused", "--bitcoin-dir", "unused"], ["open"], "unsupportedBackend")] do
    events.set []
    let (status, out, err) ← runCase services (["onchain-list-utxos", "-o", "unused"] ++ args)
    check ("list runtime " ++ message) (status == 1 && out.isEmpty && err.startsWith message)
    check ("list writer before " ++ message) ((← events.get) == expected)
  let refused := { services with openOrdinaryFile := fun _ => throw (IO.userError "output-secret") }
  let (status, out, err) ← runCase refused ["onchain-list-utxos", "--network", "bad", "-o", "unused"]
  check "list output failure precedence" (status == 1 && out.isEmpty && err.startsWith "outputFailure")
  for args in [["--min-conf", "+0", "--max-conf=4294967295"], ["--min-conf=2", "--max-conf", "1"]] do
    match parseCommand ("onchain-list-utxos" :: args) with
    | .ok (.listUtxos _) => pure ()
    | _ => check "list u32 accepted" false
  for value in ["-1", "4294967296", "1_0", "", "1.0", "1e2", "--help"] do
    check "list u32 rejected before help" ((parseCommand ["onchain-list-utxos", "--min-conf", value, "--help"]).toOption.isNone)
  for (flag, value) in [("--descriptor=--help", "--help"), ("--rpc-password=--help", "--help"), ("--wallet-file=--help", "--help")] do
    match parseCommand ["onchain-list-utxos", flag, value] with
    | .ok (.help _) => pure ()
    | _ => check "list attached value followed by help" false
  for name in ["MAINNET", "Bitcoin", "testnet", "SIGNET", "regtest"] do
    check "list network names" (ListUtxos.networkValid name)
  check "list address split" (ListUtxos.splitAddresses " , a, b ,," == #["a", "b"])
  match parseCommand ["--help"] with
  | .ok (.help text) => check "list truthful root help" ((text.splitOn "onchain-list-utxos").length > 1)
  | _ => check "list truthful root help" false
  match parseCommand ["onchain-list-utxos", "--help", "--min-conf", "bad"] with
  | .ok (.help _) => pure ()
  | _ => check "list help before typed value" false
  IO.println "list injected/parser/writer checks passed"

end CyberkrillTests
