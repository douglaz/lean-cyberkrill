/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cli
import Cyberkrill.Amounts
import Bitcoin.Bip39
import Cyberkrill.PrivateOutput
import Cyberkrill.Lightning
import Cyberkrill.Invite
import Cyberkrill.Psbt
import Cyberkrill.ListUtxos
import Cyberkrill.PsbtCommands
import Cyberkrill.MoveUtxos
import Cyberkrill.PriceFeed
import Cyberkrill.GenerateInvoice
import Cyberkrill.FetchConfig

namespace Cyberkrill

open Lean

inductive Command where
  | version
  | convert (input : String) (unit : Option String)
  | mnemonic (words : Nat) (output : Option String)
  | decodeInvoice (input output : Option String)
  | decodeLnurl (input output : Option String)
  | encodeInvoice (input : Option String) (key : String) (output : Option String)
  | generateInvoice (address amount : String) (comment output : Option String)
  | fetchConfig (invite : String) (output : Option String)
  | decodeInvite (input output : Option String)
  | encodeInvite (input : String) (skipSecret : Bool) (output : Option String)
  | decodePsbt (input : Option String) (network : String) (output : Option String)
  | listUtxos (args : ListUtxos.Args)
  | createPsbt (args : PsbtCommands.Args)
  | moveUtxos (args : MoveUtxos.Args)
  | help (text : String)

private def psbtFlags (funded : Bool) : Array Cli.Flag :=
  RpcFlags.flags ++ #[
    ⟨none, "descriptor", "Accepted without a directory; requires BDK with bitcoin-dir", String⟩,
    ⟨none, "wallet-file", "Unsupported on PSBT commands", String⟩,
    ⟨none, "network", "mainnet (default), bitcoin, testnet, signet or regtest", String⟩,
    ⟨none, "inputs", "Repeatable txid:vout or output descriptor", String⟩,
    ⟨none, "outputs", "Required comma-separated address:amount entries", String⟩,
    ⟨none, "fee-rate", "Optional rate with an explicit Bitcoin unit, for example 2.5sats", String⟩,
    ⟨some "o", "output", "Write JSON to a file", String⟩,
    ⟨none, "psbt-output", "Write raw Base64 PSBT without a newline", String⟩] ++
    (if funded then #[⟨none, "conf-target", "Confirmation target (unsigned 32-bit)", String⟩,
      ⟨none, "estimate-mode", "Core fee estimation mode", String⟩] else #[])

private def parser : Cli.Cmd :=
  Cli.Cmd.mk "cyberkrill" none "Bitcoin, Lightning and Fedimint tools"
    (run := fun _ => pure 0)
    (subCmds := #[
      Cli.Cmd.mk "onchain-move-utxos" none "Consolidate selected UTXOs using Bitcoin Core RPC"
        (flags := RpcFlags.flags ++ #[
          ⟨none, "descriptor", "Accepted without a directory; requires BDK with bitcoin-dir", String⟩,
          ⟨none, "wallet-file", "Unsupported on PSBT commands", String⟩,
          ⟨none, "network", "mainnet (default), bitcoin, testnet, signet or regtest", String⟩,
          ⟨none, "inputs", "Required repeatable txid:vout or output descriptor", String⟩,
          ⟨none, "destination", "Required sole destination", String⟩,
          ⟨none, "max-amount", "Selection threshold, floored to whole sats; bare values are BTC", String⟩,
          ⟨none, "fee-rate", "Rate with an explicit Bitcoin unit, for example 2.5sats", String⟩,
          ⟨none, "fee", "Absolute fee with an explicit Bitcoin unit, for example 1000sats", String⟩,
          ⟨some "o", "output", "Write JSON to a file", String⟩,
          ⟨none, "psbt-output", "Write raw Base64 PSBT without a newline", String⟩])
        (run := fun _ => pure 0),
      Cli.Cmd.mk "onchain-create-psbt" none "Create a PSBT using Bitcoin Core RPC"
        (flags := psbtFlags false) (run := fun _ => pure 0),
      Cli.Cmd.mk "onchain-create-funded-psbt" none "Create a funded PSBT using Bitcoin Core RPC"
        (flags := psbtFlags true) (run := fun _ => pure 0),
      Cli.Cmd.mk "onchain-list-utxos" none "List UTXOs using Bitcoin Core RPC"
        (flags := RpcFlags.flags ++ #[
          ⟨none, "descriptor", "Output descriptor", String⟩,
          ⟨none, "addresses", "Comma-separated addresses", String⟩,
          ⟨none, "wallet-file", "Public frozenkrill JSON export", String⟩,
          ⟨none, "network", "mainnet (default), bitcoin, testnet, signet or regtest", String⟩,
          ⟨none, "min-conf", "Minimum confirmations (default 1)", String⟩,
          ⟨none, "max-conf", "Maximum confirmations (default 9999999)", String⟩,
          ⟨some "o", "output", "Write JSON to a file", String⟩])
        (run := fun _ => pure 0),
      Cli.Cmd.mk "version" none "Print the package version as JSON" (run := fun _ => pure 0),
      Cli.Cmd.mk "convert-amount" none "Convert BTC, sats, msats or fiat exactly; nine price feeds, quorum three; bare amounts are BTC"
        (flags := #[⟨none, "as", "Scalar output: btc, sats or msats", String⟩])
        (positionalArgs := #[⟨"amount", "Bitcoin or fiat amount", String⟩]) (run := fun _ => pure 0),
      Cli.Cmd.mk "generate-mnemonic" none "Generate an English BIP39 mnemonic using OS entropy"
        (flags := #[⟨some "w", "words", "12, 15, 18, 21 or 24 (default)", String⟩,
                    ⟨some "o", "output", "Create a new owner-only JSON file instead of stdout", String⟩])
        (run := fun _ => pure 0),
      Cli.Cmd.mk "ln-decode-invoice" none "Decode a BOLT11 invoice from an argument or all stdin"
        (flags := #[⟨some "o", "output", "Write JSON to a file", String⟩])
        (variableArg? := some ⟨"input", "Optional literal invoice", String⟩)
        (run := fun _ => pure 0),
      Cli.Cmd.mk "ln-generate-invoice" none "Request an invoice from a Lightning address; Bitcoin or fiat amounts"
        (flags := #[⟨some "c", "comment", "Optional payment request comment", String⟩,
                    ⟨some "o", "output", "Write JSON to a file", String⟩])
        (positionalArgs := #[⟨"address", "Lightning address", String⟩,
                             ⟨"amount", "Bitcoin or fiat amount", String⟩])
        (run := fun _ => pure 0),
      Cli.Cmd.mk "ln-decode-lnurl" none "Decode LNURL bech32 without fetching the URL"
        (flags := #[⟨some "o", "output", "Write JSON to a file", String⟩])
        (variableArg? := some ⟨"input", "Optional literal LNURL", String⟩)
        (run := fun _ => pure 0),
      Cli.Cmd.mk "ln-encode-invoice" none "Sign an invoice JSON file, or stdin when omitted or '-'"
        (flags := #[⟨some "k", "private-key", "Signing key in hex", String⟩,
                    ⟨some "o", "output", "Write the invoice to a file", String⟩])
        (variableArg? := some ⟨"input", "Optional UTF-8 JSON file or '-'", String⟩)
        (run := fun _ => pure 0),
      Cli.Cmd.mk "fm-decode-invite" none "Decode a literal invite or all stdin"
        (flags := #[⟨some "o", "output", "Write JSON to a file", String⟩])
        (variableArg? := some ⟨"input", "Optional literal invite", String⟩)
        (run := fun _ => pure 0),
      Cli.Cmd.mk "fm-fetch-config" none "Fetch federation configuration from an invite's guardians"
        (flags := #[⟨some "o", "output", "Write JSON to a file", String⟩])
        (positionalArgs := #[⟨"invite_code", "Fedimint invite code", String⟩])
        (run := fun _ => pure 0),
      Cli.Cmd.mk "fm-encode-invite" none "Encode a JSON file, or '-' for all stdin"
        (flags := #[⟨none, "skip-api-secret", "Omit the API secret", Unit⟩,
                    ⟨some "o", "output", "Write the invite and newline to a file", String⟩])
        (positionalArgs := #[⟨"input", "UTF-8 JSON file or '-'", String⟩])
        (run := fun _ => pure 0),
      Cli.Cmd.mk "onchain-decode-psbt" none "Decode Base64, an existing file, or all stdin"
        (flags := #[⟨none, "network", "mainnet (default), bitcoin, testnet, signet or regtest", String⟩,
                    ⟨some "o", "output", "Write JSON and newline to a file", String⟩])
        (variableArg? := some ⟨"input", "Optional Base64 or existing UTF-8 filename", String⟩)
        (run := fun _ => pure 0)])

-- Match the reference u32 argument grammar before semantic count validation.
-- Lean's natural scanner alone also accepts underscores and rejects '+'.
private def wordCount? (s : String) : Option Nat := do
  let digits := String.ofList (match s.toList with | '+' :: rest => rest | cs => cs)
  if digits.isEmpty || !digits.toList.all (fun c => '0' ≤ c && c ≤ '9') then none
  else
    let n ← digits.toNat?
    if n ≤ 4294967295 then some n else none

-- The dependency's whitespace reader accepts option tokens as flag values.
-- Only an attached output value can start with '-' (apart from literal '-').
-- Skip consumed values so filenames are never inspected as option syntax.
private def valueFlags : List String :=
  ["-o", "--output", "-w", "--words", "-k", "--private-key", "--network", "--as",
   "--descriptor", "--addresses", "--wallet-file", "--rpc-url", "--bitcoin-dir",
   "--rpc-user", "--rpc-password", "--min-conf", "--max-conf", "--inputs", "--outputs",
   "--fee-rate", "--psbt-output", "--conf-target", "--estimate-mode"]

private def commandValueFlags (command : String) : List String :=
  if command == "onchain-move-utxos" then
    valueFlags ++ ["--fee", "--destination", "--max-amount"]
  else if command == "ln-generate-invoice" then valueFlags ++ ["-c", "--comment"]
  else valueFlags

private def outputArgsValid (valueFlags : List String) : List String → Bool
  | "--" :: _ => true
  | flag :: value :: rest =>
    if flag == "-o" || flag == "--output" then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest
    else if flag == "-w" || flag == "--words" then outputArgsValid valueFlags rest
    else if flag == "-k" || flag == "--private-key" then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest
    else if flag == "--network" then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest
    else if (flag == "-c" || flag == "--comment") && valueFlags.contains flag then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest
    else if (flag == "--destination" || flag == "--max-amount") && valueFlags.contains flag then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest
    else if ["--descriptor", "--addresses", "--wallet-file", "--rpc-url", "--bitcoin-dir",
        "--rpc-user", "--rpc-password", "--inputs", "--outputs", "--psbt-output", "--estimate-mode"].contains flag then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest
    else if valueFlags.contains flag then outputArgsValid valueFlags rest
    else outputArgsValid valueFlags (value :: rest)
  | _ => true

-- The dependency reads '=' before short-prefix values. Insert only the option
-- separator in short attachments; every byte after '-o' remains filename data.
-- Leave consumed whitespace operands and everything after '--' untouched.
private def outputParserArgs (valueFlags : List String) : List String → List String
  | "--" :: rest => "--" :: rest
  | flag :: rest =>
    if valueFlags.contains flag then
      match rest with
      | value :: tail => flag :: value :: outputParserArgs valueFlags tail
      | [] => [flag]
    else
      let flag := if (flag.startsWith "-o" || flag.startsWith "-k" ||
          (valueFlags.contains "-c" && flag.startsWith "-c")) &&
          !(flag.startsWith "-o=" || flag.startsWith "-k=" || flag.startsWith "-c=") && flag.contains '=' then
        (flag.take 2).toString ++ "=" ++ (flag.drop 2).toString else flag
      flag :: outputParserArgs valueFlags rest
  | [] => []

-- Help ends parsing at its position. Whitespace option operands and the
-- terminator shield help-looking filenames; output attachments remain data.
-- Short help ends its cluster immediately, ignoring the remaining bytes.
private def throughHelp (valueFlags : List String) : List String → List String
  | "--" :: rest => "--" :: rest
  | flag :: rest =>
    if flag == "--help" || flag.startsWith "-h" then ["-h"]
    else if valueFlags.contains flag then
      match rest with
      | value :: tail => flag :: value :: throughHelp valueFlags tail
      | [] => [flag]
    else flag :: throughHelp valueFlags rest
  | [] => []

-- These two flags are strings in the dependency parser, but their reference
-- types are an enum and u32. Check their parse-time values in argv order,
-- before a later help return. Mnemonic count semantics stay in execution.
private def validateTypedArgs (command : String) (args : List String) : Except Error Unit := do
  let valueFlags := commandValueFlags command
  if command == "onchain-create-psbt" || command == "onchain-create-funded-psbt" ||
      command == "onchain-move-utxos" then
    let mut pending : Option String := none
    let mut shield := false
    for flag in args do
      if let some name := pending then
        if name == "--fee-rate" || name == "--fee" then let _ ← parseFee flag
        else if name == "--max-amount" then MoveUtxos.validateMax flag
        else unless (PsbtCommands.unsigned32 flag).isSome do
          throw (.onchain "invalidConfTarget: Expected an unsigned 32-bit decimal")
        pending := none
      else if shield then shield := false
      else if flag == "--" || flag == "-h" then return
      else
        let name := (flag.splitOn "=").head!
        if name == "--fee-rate" ||
            (command == "onchain-move-utxos" && (name == "--fee" || name == "--max-amount")) ||
            (command == "onchain-create-funded-psbt" && name == "--conf-target") then
          if flag == name then pending := some name
          else
            let value := String.intercalate "=" (flag.splitOn "=").tail
            if name == "--fee-rate" || name == "--fee" then let _ ← parseFee value
            else if name == "--max-amount" then MoveUtxos.validateMax value
            else unless (PsbtCommands.unsigned32 value).isSome do
              throw (.onchain "invalidConfTarget: Expected an unsigned 32-bit decimal")
        else if valueFlags.contains flag then shield := true
    if pending.isSome then throw .invalidArguments
    return
  if command == "onchain-list-utxos" then
    let mut bound := false
    let mut shield := false
    for flag in args do
      if bound then
        unless (wordCount? flag).isSome do throw (.onchain "invalidConfirmations: Expected an unsigned 32-bit decimal")
        bound := false
      else if shield then shield := false
      else if flag == "--" || flag == "-h" then return
      else
        let name := (flag.splitOn "=").head!
        if name == "--min-conf" || name == "--max-conf" then
          if flag == name then bound := true
          else unless (wordCount? (String.intercalate "=" (flag.splitOn "=").tail)).isSome do
            throw (.onchain "invalidConfirmations: Expected an unsigned 32-bit decimal")
        else if valueFlags.contains flag then shield := true
    if bound then throw .invalidArguments
    return
  unless command == "convert-amount" || command == "generate-mnemonic" do return
  let check := fun value => do
    if command == "convert-amount" then
      unless ["btc", "sats", "msats"].contains value do throw .invalidUnit
    else
      unless (wordCount? value).isSome do throw .invalidWordCount
  let mut pending := false
  let mut shield := false
  for flag in args do
    if pending then
      check flag
      pending := false
    else if shield then shield := false
    else if flag == "--" || flag == "-h" then return
    else if command == "convert-amount" && flag == "--as" then pending := true
    else if command == "convert-amount" && flag.startsWith "--as=" then
      check (flag.drop 5).toString
    else if command == "generate-mnemonic" && (flag == "-w" || flag == "--words") then
      pending := true
    else if command == "generate-mnemonic" && flag.startsWith "--words=" then
      check (flag.drop 8).toString
    else if command == "generate-mnemonic" && flag.startsWith "-w" then
      check (flag.drop (if flag.startsWith "-w=" then 3 else 2)).toString
    else if ["-o", "--output", "-k", "--private-key", "--network"].contains flag then
      shield := true
  if pending then throw .invalidArguments

-- Cli rejects duplicate flags. Collect only this repeatable option ourselves,
-- respecting consumed values and the option terminator; other duplicates retain
-- Cli's refusal. Required arguments are checked after effective help.
private def collectInputs (valueFlags : List String) : List String → Except Error (List String × Array String)
  | "--" :: rest => .ok ("--" :: rest, #[])
  | "--inputs" :: value :: rest => do
    let (args, inputs) ← collectInputs valueFlags rest
    return (args, #[value] ++ inputs)
  | ["--inputs"] => .error .invalidArguments
  | flag :: rest => do
    if flag.startsWith "--inputs=" then
      let (args, inputs) ← collectInputs valueFlags rest
      return (args, #[(flag.drop 9).toString] ++ inputs)
    else if valueFlags.contains flag then
      match rest with
      | value :: tail =>
        let (args, inputs) ← collectInputs valueFlags tail
        return (flag :: value :: args, inputs)
      | [] => return ([flag], #[])
    else
      let (args, inputs) ← collectInputs valueFlags rest
      return (flag :: args, inputs)
  | [] => .ok ([], #[])

def parseCommand (args : List String) : Except Error Command := do
  let flags := commandValueFlags (args.head?.getD "")
  let throughHelp := throughHelp flags
  let outputArgsValid := outputArgsValid flags
  let outputParserArgs := outputParserArgs flags
  let collectInputs := collectInputs flags
  let args := throughHelp args
  validateTypedArgs (args.head?.getD "") args.tail
  let routed := ["generate-mnemonic", "ln-decode-invoice", "ln-decode-lnurl", "ln-encode-invoice",
    "ln-generate-invoice",
    "fm-decode-invite", "fm-encode-invite", "fm-fetch-config", "onchain-decode-psbt", "onchain-list-utxos",
    "onchain-create-psbt", "onchain-create-funded-psbt", "onchain-move-utxos"].contains
    (args.head?.getD "")
  if routed then
    unless outputArgsValid args.tail do throw .invalidArguments
  let args := if routed then (args.head?.getD "") :: outputParserArgs args.tail else args
  let psbt := ["onchain-create-psbt", "onchain-create-funded-psbt", "onchain-move-utxos"].contains (args.head?.getD "")
  let (operands, inputs) ← if psbt then collectInputs args.tail else pure (args.tail, #[])
  let args := if psbt then args.head! :: operands else args
  let (cmd, p) ← (parser.parse args).mapError fun _ => Error.invalidArguments
  if p.variableArgs.size > 1 then throw .invalidArguments
  if p.hasFlag "help" || args.isEmpty then return .help cmd.help
  let flag := fun name => (p.flag? name).map (·.value)
  match cmd.meta.name with
  | "onchain-move-utxos" =>
    if inputs.isEmpty then throw .invalidArguments
    let some destination := flag "destination" | throw .invalidArguments
    if p.hasFlag "fee-rate" && p.hasFlag "fee" then throw .invalidArguments
    if p.hasFlag "descriptor" && p.hasFlag "wallet-file" then throw .invalidArguments
    let rpc ← RpcFlags.ofParsed p |>.mapError Error.onchain
    let rate ← (flag "fee-rate").mapM parseFee
    let fee ← (flag "fee").mapM parseFee
    return .moveUtxos {
      inputs, destination, rpc, feeRate := rate, fee,
      maxAmount := flag "max-amount", descriptor := flag "descriptor",
      walletFile := flag "wallet-file", network := (flag "network").getD "mainnet",
      output := flag "output", psbtOutput := flag "psbt-output" }
  | "onchain-create-psbt" | "onchain-create-funded-psbt" =>
    let funded := cmd.meta.name == "onchain-create-funded-psbt"
    if !funded && inputs.isEmpty then throw .invalidArguments
    let some outputs := flag "outputs" | throw .invalidArguments
    if p.hasFlag "descriptor" && p.hasFlag "wallet-file" then throw .invalidArguments
    let rpc ← RpcFlags.ofParsed p |>.mapError Error.onchain
    let rate ← (flag "fee-rate").mapM parseFee
    return .createPsbt {
      funded, inputs, outputs, rpc, feeRate := rate,
      descriptor := flag "descriptor", walletFile := flag "wallet-file",
      network := (flag "network").getD "mainnet", output := flag "output",
      psbtOutput := flag "psbt-output", estimateMode := flag "estimate-mode",
      confTarget := (flag "conf-target").bind PsbtCommands.unsigned32 }
  | "onchain-list-utxos" =>
    let sources := ["descriptor", "addresses", "wallet-file"].filter p.hasFlag
    if sources.length > 1 then throw .invalidArguments
    let rpc ← RpcFlags.ofParsed p |>.mapError Error.onchain
    return .listUtxos {
      rpc, descriptor := flag "descriptor", addresses := flag "addresses",
      walletFile := flag "wallet-file", network := (flag "network").getD "mainnet",
      minConf := (wordCount? ((flag "min-conf").getD "1")).getD 1,
      maxConf := (wordCount? ((flag "max-conf").getD "9999999")).getD 9999999,
      output := flag "output" }
  | "version" => return .version
  | "ln-generate-invoice" =>
    let some address := p.positionalArg? "address" | throw .invalidArguments
    let some amount := p.positionalArg? "amount" | throw .invalidArguments
    return .generateInvoice address.value amount.value (flag "comment") (flag "output")
  | "convert-amount" =>
    let some arg := p.positionalArg? "amount" | throw .invalidArguments
    let unit := flag "as"
    if let some u := unit then
      unless ["btc", "sats", "msats"].contains u do throw .invalidUnit
    return .convert arg.value unit
  | "generate-mnemonic" =>
    let some words := wordCount? ((flag "words").getD "24") | throw .invalidWordCount
    return .mnemonic words (flag "output")
  | "fm-encode-invite" =>
    let some input := p.positionalArg? "input" | throw .invalidArguments
    return .encodeInvite input.value (p.hasFlag "skip-api-secret") (flag "output")
  | "fm-fetch-config" =>
    let some invite := p.positionalArg? "invite_code" | throw .invalidArguments
    return .fetchConfig invite.value (flag "output")
  | "ln-decode-invoice" | "ln-decode-lnurl" | "ln-encode-invoice" |
      "fm-decode-invite" | "onchain-decode-psbt" =>
    if p.variableArgs.size > 1 then throw .invalidArguments
    let input := p.variableArgs[0]?.map (·.value)
    match cmd.meta.name with
    | "ln-decode-invoice" => return .decodeInvoice input (flag "output")
    | "ln-decode-lnurl" => return .decodeLnurl input (flag "output")
    | "fm-decode-invite" => return .decodeInvite input (flag "output")
    | "onchain-decode-psbt" => return .decodePsbt input ((flag "network").getD "mainnet") (flag "output")
    | _ =>
      let some key := flag "private-key" | throw .invalidArguments
      return .encodeInvoice input key (flag "output")
  | _ => throw .invalidArguments

structure Output where
  stdout : String := ""
  stderr : String := ""
  file : Option (String × String) := none
  ordinaryFile : Option ((String → IO Unit) × String) := none

/-- Internal injection is intentionally absent from CLI flags and environment. -/
structure Services where
  entropy : Nat → IO ByteArray
  stdout : String → IO Unit
  stderr : String → IO Unit
  writeFile : String → String → IO Unit
  readStdin : IO String := do (← IO.getStdin).readToEnd
  readFile : String → IO String := fun path => IO.FS.readFile path
  pathExists : String → IO Bool := fun path => System.FilePath.pathExists path
  openOrdinaryFile : String → IO (String → IO Unit) := fun path => do
    let handle ← IO.FS.Handle.mk path .write
    return fun text => do
      handle.putStr text
      handle.flush
  coreClient : RpcFlags → IO CoreRpc.Client := CoreRpc.Client.ofFlags
  listUtxos : CoreRpc.Client → ListUtxos.Args → Option Frozenkrill.Wallet → IO (Except CoreRpc.Error Json) := ListUtxos.fetch
  psbt : CoreRpc.Client → PsbtCommands.Args → Array (String × Bitcoin.Amount) → IO (Except Error PsbtCommands.Result) := PsbtCommands.fetch
  move : CoreRpc.Client → MoveUtxos.Args → Option Bitcoin.Amount → IO (Except Error PsbtCommands.Result) := MoveUtxos.fetch
  writeOrdinaryFile : String → String → IO Unit := fun path text => IO.FS.writeFile path text
  price : String → IO PriceFeed.Result := PriceFeed.fetch
  lnurlRequest : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.Response) := HttpCurl.request
  configRequest : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.AcquiredResponse) := HttpCurl.requestDetailed

def productionServices : Services where
  entropy := fun n => IO.getRandomBytes n.toUSize
  stdout := fun s => do (← IO.getStdout).putStr s; (← IO.getStdout).flush
  stderr := fun s => do (← IO.getStderr).putStr s
  writeFile := writePrivateFile

def entropyBytes : Nat → Except Error Nat
  | 12 => .ok 16 | 15 => .ok 20 | 18 => .ok 24 | 21 => .ok 28 | 24 => .ok 32
  | _ => .error .invalidWordCount

def conversionOutput (input : String) (unit : Option String) (a : Bitcoin.Amount)
    (fiat : Option (FiatAmount × PriceFeed.Price) := none) : Except Error Output := do
  let sats := a.msat / 1000
  match unit with
  | some "btc" => return { stdout := a.printBtc ++ "\n" }
  | some "sats" => return { stdout := toString sats ++ "\n", stderr :=
      if a.msat % 1000 != 0 then
        s!"[convert-amount] note: input has fractional satoshis ({a.msat} msat); --as sats floors to {sats} sat\n"
      else "" }
  | some "msats" => return { stdout := toString a.msat ++ "\n" }
  | some _ => throw .invalidUnit
  | none =>
    -- Write the already validated exact decimal directly, including zero.
    let text := "{\"input\":" ++ (Lean.Json.str input).compress ++
      ",\"btc\":" ++ a.printBtc ++ ",\"sats\":" ++ toString sats ++
      ",\"msats\":" ++ toString a.msat ++ (match fiat with
        | none => ""
        | some (f, p) => ",\"fiat_source\":" ++ (Json.mkObj [
          ("amount", f.amount.json), ("currency", .str p.currency),
          ("price_per_btc", p.price.json),
          ("feeds", toJson (p.sources.map (·.source)))]).compress) ++ "}\n"
    return { stdout := text }

def conversion (input : String) (unit : Option String) : Except Error Output := do
  let a ← parseAmount input
  conversionOutput input unit a

def convertWith (services : Services) (input : String) (unit : Option String) : IO (Except Error Output) := do
  let parsed ← match parseBitcoinOrFiat input with
    | .error e => return .error e
    | .ok parsed => pure parsed
  match parsed with
  | .inl amount => return conversionOutput input unit amount
  | .inr fiat =>
    let result ← services.price fiat.currency
    -- Feed diagnostics and breadcrumb precede conversion, including failures.
    if !result.diagnostics.isEmpty then services.stderr result.diagnostics
    let price ← match result.price with
      | .error e => return .error (.onchain e)
      | .ok price => pure price
    services.stderr (PriceFeed.breadcrumb price)
    return do
      let amount ← convertFiat fiat price.currency price.price .millisat
      conversionOutput input unit amount (some (fiat, price))

/-- Quotes live only for this call. Each miss emits diagnostics and its
breadcrumb before conversion, even when that conversion subsequently fails. -/
def convertAmounts (services : Services) (values : Array (Bitcoin.Amount ⊕ FiatAmount))
    (precision : FiatConversionPrecision) : IO (Except Error (Array Bitcoin.Amount)) := do
  let mut prices : Array PriceFeed.Price := #[]
  let mut amounts := #[]
  for value in values do
    match value with
    | .inl amount => amounts := amounts.push amount
    | .inr fiat =>
      let cached := prices.find? (·.currency == fiat.currency)
      let result ← match cached with
        | some price => pure (Except.ok price)
        | none => do
          let result ← services.price fiat.currency
          if !result.diagnostics.isEmpty then services.stderr result.diagnostics
          pure (result.price.mapError Error.onchain)
      let price ← match result with
        | .error e => return .error e
        | .ok price => pure price
      if cached.isNone then
        services.stderr (PriceFeed.breadcrumb price)
        prices := prices.push price
      match convertFiat fiat price.currency price.price precision with
      | .error e => return .error e
      | .ok amount => amounts := amounts.push amount
  return .ok amounts

private def outputsWith (services : Services) (text : String) :
    IO (Except Error (Array (String × Bitcoin.Amount))) := do
  let parsed ← match PsbtCommands.prepareOutputs text with
    | .error e => return .error e
    | .ok parsed => pure parsed
  let amounts ← match ← convertAmounts services (parsed.map (·.2)) .wholeSat with
    | .error e => return .error e
    | .ok amounts => pure amounts
  return do
    let amounts ← amounts.mapM exactWholeSat
    return PsbtCommands.collapseOutputs ((parsed.map (·.1)).zip amounts)

private def maximumWith (services : Services) (text : String) : IO (Except Error Bitcoin.Amount) := do
  let parsed ← match parseBitcoinOrFiat text with
    | .error e => return .error e
    | .ok parsed => pure parsed
  match parsed with
  | .inl _ => return MoveUtxos.maximum text
  | .inr _ =>
    match ← convertAmounts services #[parsed] .floorSat with
    | .error e => return .error e
    | .ok amounts =>
      let some amount := amounts[0]? | return .error .invalidArguments
      return .ok amount

private def lightningOutput (text : String) (writer : Option (String → IO Unit)) (newline : Bool) : Output :=
  match writer with
  | none => { stdout := text ++ if newline then "\n" else "" }
  | some write => { ordinaryFile := some (write, text) }

private def lightningInput (services : Services) (input : Option String) (fromFile : Bool) :
    IO (Except Error String) := do
  try
    match input with
    | none => return .ok (← services.readStdin)
    | some value =>
      if fromFile then
        return .ok (← if value == "-" then services.readStdin else services.readFile value)
      else return .ok value
  catch _ => return .error .inputFailure

-- Decoder writers are created after input acquisition and before decoding,
-- including on invalid input, and retained until the JSON write completes.
-- Encoding opens its writer only after signing.
private def prepareDecodeOutput (services : Services) (path : Option String) :
    IO (Except Error (Option (String → IO Unit))) := do
  try
    match path with
    | none => return .ok none
    | some path => return .ok (some (← services.openOrdinaryFile path))
  catch _ => return .error .outputFailure

def execute (version : String) (services : Services)
    (configLimits : FetchConfig.Limits := {}) : Command → IO (Except Error Output)
  | .fetchConfig invite path => do
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    match ← FetchConfig.fetch invite services.configRequest services.stderr configLimits with
    | .error e => return .error e
    | .ok result => return .ok (lightningOutput result.pretty writer false)
  | .generateInvoice address input comment path => do
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    let parsed ← match parseBitcoinOrFiat input with
      | .error e => return .error e | .ok parsed => pure parsed
    let amounts ← match ← convertAmounts services #[parsed] .millisat with
      | .error e => return .error e | .ok amounts => pure amounts
    let some amount := amounts[0]? | return .error .invalidArguments
    match ← GenerateInvoice.fetch address amount comment services.lnurlRequest with
    | .error e => return .error e
    | .ok result => return .ok (lightningOutput result.pretty writer false)
  | .moveUtxos args => do
    let .ok writer ← prepareDecodeOutput services args.output | return .error .outputFailure
    if args.feeRate.isNone && args.fee.isNone then
      return .error (.onchain "missingFee: Specify either --fee-rate or --fee")
    if args.feeRate.isSome && args.fee.isSome then
      return .error (.onchain "feeConflict: Specify only one fee method")
    unless ListUtxos.networkValid args.network do
      return .error (.onchain "invalidNetwork: Expected mainnet, bitcoin, testnet, signet or regtest")
    if args.walletFile.isSome then
      return .error (.onchain "unsupportedWalletFile: PSBT wallet-file routing requires BDK")
    if args.descriptor.isSome && args.rpc.bitcoinDir.isSome then
      return .error (.onchain "unsupportedBackend: descriptor with bitcoin-dir requires BDK")
    let maximumResult ← match args.maxAmount with
      | none => pure (.ok none)
      | some text => do pure ((← maximumWith services text).map some)
    let maximum ← match maximumResult with
      | .error e => return .error e
      | .ok maximum => pure maximum
    let client ← try services.coreClient args.rpc catch _ =>
      return .error (.onchain "rpcTransport: Cannot initialize Core client")
    match ← services.move client args maximum with
    | .error e => return .error e
    | .ok result =>
      if let some path := args.psbtOutput then
        try
          services.writeOrdinaryFile path result.psbt
        catch _ => return .error .outputFailure
      return .ok (lightningOutput result.json.pretty writer false)
  | .createPsbt args => do
    let .ok writer ← prepareDecodeOutput services args.output | return .error .outputFailure
    unless ListUtxos.networkValid args.network do
      return .error (.onchain "invalidNetwork: Expected mainnet, bitcoin, testnet, signet or regtest")
    if args.walletFile.isSome then
      return .error (.onchain "unsupportedWalletFile: PSBT wallet-file routing requires BDK")
    if args.descriptor.isSome && args.rpc.bitcoinDir.isSome then
      return .error (.onchain "unsupportedBackend: descriptor with bitcoin-dir requires BDK")
    if args.funded && args.inputs.isEmpty then
      return .error (.onchain "missingInputs: Provide inputs for Core funded PSBT creation")
    let outputs ← match ← outputsWith services args.outputs with
      | .error e => return .error e
      | .ok outputs => pure outputs
    let client ← try services.coreClient args.rpc catch _ =>
      return .error (.onchain "rpcTransport: Cannot initialize Core client")
    match ← services.psbt client args outputs with
    | .error e => return .error e
    | .ok result =>
      if let some path := args.psbtOutput then
        try services.writeOrdinaryFile path result.psbt catch _ => return .error .outputFailure
      return .ok (lightningOutput result.json.pretty writer false)
  | .listUtxos args => do
    let .ok writer ← prepareDecodeOutput services args.output | return .error .outputFailure
    unless ListUtxos.networkValid args.network do
      return .error (.onchain "invalidNetwork: Expected mainnet, bitcoin, testnet, signet or regtest")
    if args.descriptor.isSome && args.rpc.bitcoinDir.isSome then
      return .error (.onchain "unsupportedBackend: descriptor with bitcoin-dir requires BDK")
    if args.descriptor.isNone && args.addresses.isNone && args.walletFile.isNone then
      return .error (.onchain "missingSource: Provide descriptor, addresses or wallet-file")
    let wallet ← match args.walletFile with
      | none => pure none
      | some path =>
        let content ← try services.readFile path catch _ =>
          return .error (.onchain "walletReadFailure: Cannot read wallet export")
        match Frozenkrill.parse content with
        | .error _ => return .error (.onchain "invalidWallet: Invalid frozenkrill export")
        | .ok wallet => pure (some wallet)
    let client ← try services.coreClient args.rpc catch _ =>
      return .error (.onchain "rpcTransport: Cannot initialize Core client")
    match ← services.listUtxos client args wallet with
    | .error e => return .error (.onchain e.message)
    | .ok result => return .ok (lightningOutput result.pretty writer false)
  | .version => pure (.ok { stdout := (Lean.Json.mkObj [("version", .str version)]).compress ++ "\n" })
  | .help text => pure (.ok { stdout := text ++ "\n" })
  | .convert input unit => convertWith services input unit
  | .decodeInvite input path => do
    let .ok text ← lightningInput services input false | return .error .inputFailure
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    return (InviteCli.decode text).map (fun invite => lightningOutput (InviteCli.render invite) writer false)
  | .encodeInvite input skipSecret path => do
    let .ok text ← lightningInput services (some input) true | return .error .inputFailure
    let invite ← match InviteCli.encode text skipSecret with
      | .ok invite => pure invite
      | .error e => return .error e
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    return .ok (match writer with
      | none => { stdout := invite ++ "\n" }
      | some write => { ordinaryFile := some (write, invite ++ "\n") })
  | .decodePsbt input net path => do
    let net ← match PsbtCli.network net with
      | .ok net => pure net
      | .error e => return .error e
    let text ← try
      match input with
      | none => pure (← services.readStdin)
      | some value =>
        if ← services.pathExists value then services.readFile value else pure value
      catch _ => return .error .inputFailure
    let text ← match PsbtCli.decode text net with
      | .ok text => pure text
      | .error e => return .error e
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    return .ok (match writer with
      | none => { stdout := text ++ "\n" }
      | some write => { ordinaryFile := some (write, text ++ "\n") })
  | .decodeInvoice input path => do
    let .ok text ← lightningInput services input false | return .error .inputFailure
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    return (LightningCli.decodeInvoice text).map (lightningOutput · writer false)
  | .decodeLnurl input path => do
    let .ok text ← lightningInput services input false | return .error .inputFailure
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    return (LightningCli.decodeLnurl text).map (lightningOutput · writer false)
  | .encodeInvoice input key path => do
    let .ok text ← lightningInput services input true | return .error .inputFailure
    let invoice ← match LightningCli.encodeInvoice text key with
      | .ok invoice => pure invoice
      | .error e => return .error e
    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure
    return .ok (lightningOutput invoice writer true)
  | .mnemonic words path => do
    let .ok size := entropyBytes words | return .error .invalidWordCount
    let entropy ← try services.entropy size catch _ => return .error .entropyFailure
    if entropy.size != size then return .error .shortEntropy
    let .ok ws := Bitcoin.Bip39.entropyToMnemonic entropy | return .error .shortEntropy
    let text := (Lean.Json.mkObj [("mnemonic", toJson (String.intercalate " " ws)),
      ("words", toJson words), ("entropy_bits", toJson (size * 8))]).compress ++ "\n"
    return .ok (match path with
      | none => { stdout := text }
      | some p => { file := some (p, text) })

/-- All diagnostics are fixed messages: no IO exception can disclose output. -/
def reportError (services : Services) (error : Error) : IO UInt32 := do
  try services.stderr (error.message ++ "\n") catch _ => pure ()
  return 1

def runWith (version : String) (services : Services) (args : List String)
    (configLimits : FetchConfig.Limits := {}) : IO UInt32 := do
  let cmd ← match parseCommand args with
    | .error e => return ← reportError services e
    | .ok cmd => pure cmd
  match ← execute version services configLimits cmd with
  | .error e => reportError services e
  | .ok out =>
    try
      if let some (path, text) := out.file then services.writeFile path text
      if let some (write, text) := out.ordinaryFile then write text
      if !out.stderr.isEmpty then services.stderr out.stderr
      if !out.stdout.isEmpty then services.stdout out.stdout
      return 0
    catch e => reportError services (match e with
      | .alreadyExists .. => if out.file.isSome then .outputPathExists else .outputFailure
      | _ => .outputFailure)

/-- Future fee registrations share this refusal boundary, before backend action. -/
def runFeeWith (services : Services) (input : String)
    (consume : Bitcoin.Amount → IO UInt32) : IO UInt32 :=
  match parseFee input with
  | .error e => reportError services e
  | .ok a => consume a

end Cyberkrill
