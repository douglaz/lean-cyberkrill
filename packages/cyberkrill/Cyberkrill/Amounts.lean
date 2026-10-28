/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.AmountCli

namespace Cyberkrill

inductive Error where
  | amount (cause : Bitcoin.Amount.InputError)
  | fiatNotSupported | lessThanOneSat | wholeSatRequired | feeUnitRequired
  | invalidArguments | invalidUnit | invalidWordCount
  | entropyFailure | shortEntropy | outputFailure | outputPathExists
  | inputFailure | invalidInvoiceJson | badPublicKey | badPrivateKey
  | lightning (code : String)
  deriving Repr, DecidableEq

def Error.message : Error → String
  | .amount .empty => "empty: Amount is empty"
  | .amount .invalidNumber => "invalidNumber: Expected a finite decimal without exponent syntax"
  | .amount .negative => "negative: Amount must be nonnegative"
  | .amount .subMillisatoshi => "subMillisatoshi: Amount has sub-msat precision"
  | .amount .millisatoshiOverflow => "millisatoshiOverflow: Millisatoshi input exceeds u64"
  | .fiatNotSupported => "fiatNotSupported: Fiat conversion is not yet supported"
  | .lessThanOneSat => "lessThanOneSat: Nonzero amount becomes less than one sat"
  | .wholeSatRequired => "wholeSatRequired: Amount must be a whole number of sats"
  | .feeUnitRequired => "feeUnitRequired: Specify a Bitcoin unit, for example 15sats"
  | .invalidArguments => "invalidArguments: Invalid command arguments; use --help"
  | .invalidUnit => "invalidUnit: --as requires btc, sats or msats"
  | .invalidWordCount => "invalidWordCount: Choose 12, 15, 18, 21 or 24 words"
  | .entropyFailure => "entropyFailure: Cannot acquire entropy"
  | .shortEntropy => "shortEntropy: Entropy source returned the wrong byte count"
  | .outputFailure => "outputFailure: Cannot write output"
  | .outputPathExists => "outputPathExists: Refusing an existing output path"
  | .inputFailure => "inputFailure: Cannot read UTF-8 input"
  | .invalidInvoiceJson => "invalidInvoiceJson: Invalid invoice description"
  | .badPublicKey => "badPublicKey: Invalid public key"
  | .badPrivateKey => "badPrivateKey: Invalid signing key"
  | .lightning code => code ++ ": Invalid Lightning input"

def parseAmount (s : String) : Except Error Bitcoin.Amount :=
  (Bitcoin.Amount.parseInput s).mapError .amount

private def satsResult (a : Bitcoin.Amount) (sats : Nat) : Except Error Bitcoin.Amount :=
  if a.msat != 0 && sats == 0 then .error .lessThanOneSat
  else .ok (Bitcoin.Amount.ofSats sats)

/-- Shared by later on-chain output consumers; half up, with no wire bound. -/
def wholeSat (a : Bitcoin.Amount) : Except Error Bitcoin.Amount :=
  satsResult a ((a.msat + 500) / 1000)

def floorSat (a : Bitcoin.Amount) : Except Error Bitcoin.Amount :=
  satsResult a (a.msat / 1000)

def exactWholeSat (a : Bitcoin.Amount) : Except Error Bitcoin.Amount :=
  if a.msat % 1000 != 0 then .error .wholeSatRequired else .ok a

def hasBitcoinUnit (s : String) : Bool :=
  let s := String.ofList ((Bitcoin.Amount.trimInput s).toList.map Bitcoin.Amount.asciiLower)
  ["msats", "msat", "sats", "sat", "btc"].any (fun unit => s.endsWith unit)

/-- Only fee flags use this rule. Ordinary amounts retain bare-BTC syntax. -/
def parseFee (s : String) : Except Error Bitcoin.Amount :=
  if hasBitcoinUnit s then parseAmount s else .error .feeUnitRequired

/-- Match the reference's currency suffix recognition before any backend action.
Malformed numeric prefixes are refused here too, without attempting a feed. -/
def recognizableFiat (s : String) : Bool :=
  let cs := (Bitcoin.Amount.trimInput s).toList
  let suffix := cs.reverse.takeWhile fun c => !(c.isDigit || c == '.' || c == ',')
  let unit := Bitcoin.Amount.trimInput (String.ofList suffix.reverse)
  suffix.length < cs.length && unit.length == 3 &&
    unit.toList.all (fun c => ('a' ≤ c && c ≤ 'z') || ('A' ≤ c && c ≤ 'Z')) &&
    !hasBitcoinUnit unit

end Cyberkrill
