/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cli
import Cyberkrill.Amounts
import Bitcoin.Bip39
import Cyberkrill.PrivateOutput

namespace Cyberkrill

open Lean

inductive Command where
  | version
  | convert (input : String) (unit : Option String)
  | mnemonic (words : Nat) (output : Option String)
  | help (text : String)

private def parser : Cli.Cmd :=
  Cli.Cmd.mk "cyberkrill" none "Bitcoin, Lightning and Fedimint tools (offline subset)"
    (run := fun _ => pure 0)
    (subCmds := #[
      Cli.Cmd.mk "version" none "Print the package version as JSON" (run := fun _ => pure 0),
      Cli.Cmd.mk "convert-amount" none "Convert BTC, sats or msats exactly; bare amounts are BTC"
        (flags := #[⟨none, "as", "Scalar output: btc, sats or msats", String⟩])
        (positionalArgs := #[⟨"amount", "Bitcoin amount", String⟩]) (run := fun _ => pure 0),
      Cli.Cmd.mk "generate-mnemonic" none "Generate an English BIP39 mnemonic using OS entropy"
        (flags := #[⟨some "w", "words", "12, 15, 18, 21 or 24 (default)", String⟩,
                    ⟨some "o", "output", "Create a new owner-only JSON file instead of stdout", String⟩])
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
private def outputArgsValid : List String → Bool
  | "--" :: _ => true
  | flag :: value :: rest =>
    if flag == "-o" || flag == "--output" then
      (!(value.startsWith "-") || value == "-") && outputArgsValid rest
    else if flag == "-w" || flag == "--words" then outputArgsValid rest
    else outputArgsValid (value :: rest)
  | _ => true

-- The dependency reads '=' before short-prefix values. Insert only the option
-- separator in short attachments; every byte after '-o' remains filename data.
-- Leave consumed whitespace operands and everything after '--' untouched.
private def outputParserArgs : List String → List String
  | "--" :: rest => "--" :: rest
  | flag :: rest =>
    if flag == "-o" || flag == "--output" || flag == "-w" || flag == "--words" then
      match rest with
      | value :: tail => flag :: value :: outputParserArgs tail
      | [] => [flag]
    else
      let flag := if flag.startsWith "-o" && !flag.startsWith "-o=" && flag.contains '=' then
        "-o=" ++ (flag.drop 2).toString else flag
      flag :: outputParserArgs rest
  | [] => []

def parseCommand (args : List String) : Except Error Command := do
  if args.head? == some "generate-mnemonic" then
    unless outputArgsValid args.tail do throw .invalidArguments
  let args := if args.head? == some "generate-mnemonic" then
    "generate-mnemonic" :: outputParserArgs args.tail else args
  let (cmd, p) ← (parser.parse args).mapError fun _ => Error.invalidArguments
  if p.hasFlag "help" || args.isEmpty then return .help cmd.help
  let flag := fun name => (p.flag? name).map (·.value)
  match cmd.meta.name with
  | "version" => return .version
  | "convert-amount" =>
    let some arg := p.positionalArg? "amount" | throw .invalidArguments
    let unit := flag "as"
    if let some u := unit then
      unless ["btc", "sats", "msats"].contains u do throw .invalidUnit
    return .convert arg.value unit
  | "generate-mnemonic" =>
    let some words := wordCount? ((flag "words").getD "24") | throw .invalidWordCount
    return .mnemonic words (flag "output")
  | _ => throw .invalidArguments

structure Output where
  stdout : String := ""
  stderr : String := ""
  file : Option (String × String) := none

/-- Internal injection is intentionally absent from CLI flags and environment. -/
structure Services where
  entropy : Nat → IO ByteArray
  stdout : String → IO Unit
  stderr : String → IO Unit
  writeFile : String → String → IO Unit

def productionServices : Services where
  entropy := fun n => IO.getRandomBytes n.toUSize
  stdout := fun s => do (← IO.getStdout).putStr s
  stderr := fun s => do (← IO.getStderr).putStr s
  writeFile := writePrivateFile

def entropyBytes : Nat → Except Error Nat
  | 12 => .ok 16 | 15 => .ok 20 | 18 => .ok 24 | 21 => .ok 28 | 24 => .ok 32
  | _ => .error .invalidWordCount

def conversion (input : String) (unit : Option String) : Except Error Output := do
  if recognizableFiat input then throw .fiatNotSupported
  let a ← parseAmount input
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
      ",\"msats\":" ++ toString a.msat ++ "}\n"
    return { stdout := text }

def execute (version : String) (services : Services) : Command → IO (Except Error Output)
  | .version => pure (.ok { stdout := (Lean.Json.mkObj [("version", .str version)]).compress ++ "\n" })
  | .help text => pure (.ok { stdout := text ++ "\n" })
  | .convert input unit => pure (conversion input unit)
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

def runWith (version : String) (services : Services) (args : List String) : IO UInt32 := do
  let cmd ← match parseCommand args with
    | .error e => return ← reportError services e
    | .ok cmd => pure cmd
  match ← execute version services cmd with
  | .error e => reportError services e
  | .ok out =>
    try
      if let some (path, text) := out.file then services.writeFile path text
      if !out.stderr.isEmpty then services.stderr out.stderr
      if !out.stdout.isEmpty then services.stdout out.stdout
      return 0
    catch e => reportError services (match e with
      | .alreadyExists .. => .outputPathExists
      | _ => .outputFailure)

/-- Future fee registrations share this refusal boundary, before backend action. -/
def runFeeWith (services : Services) (input : String)
    (consume : Bitcoin.Amount → IO UInt32) : IO UInt32 :=
  match parseFee input with
  | .error e => reportError services e
  | .ok a => consume a

end Cyberkrill
