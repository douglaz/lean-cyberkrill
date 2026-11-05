/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.Amounts
import Lean.Data.Json

namespace Cyberkrill

/-- Nonnegative rational arithmetic. Constructors exposed for supplied quotes;
conversion validates denominators and prices before division. -/
structure Exact where
  numerator : Nat
  denominator : Nat := 1
  deriving Repr, BEq, Inhabited

namespace Exact

def ofRatio (n d : Nat) : Exact :=
  let g := n.gcd d
  ⟨n / g, d / g⟩

def lt (a b : Exact) : Bool := a.numerator * b.denominator < b.numerator * a.denominator
def equal (a b : Exact) : Bool := a.numerator * b.denominator == b.numerator * a.denominator
def add (a b : Exact) : Exact :=
  ofRatio (a.numerator * b.denominator + b.numerator * a.denominator) (a.denominator * b.denominator)
def div (a b : Exact) : Exact := ofRatio (a.numerator * b.denominator) (a.denominator * b.numerator)
def mul (a b : Exact) : Exact := ofRatio (a.numerator * b.numerator) (a.denominator * b.denominator)

def round (a : Exact) : Nat := (2 * a.numerator + a.denominator) / (2 * a.denominator)

/-- Fixed decimal display uses ties to even, as the reference formatter does. -/
def fixed (a : Exact) (digits : Nat) : String := Id.run do
  let scaled := a.numerator * 10^digits
  let q := scaled / a.denominator
  let r := scaled % a.denominator
  let n := q + if 2*r > a.denominator || (2*r == a.denominator && q % 2 == 1) then 1 else 0
  if digits == 0 then return toString n
  let tail := toString (n % 10^digits)
  return toString (n / 10^digits) ++ "." ++ String.ofList (List.replicate (digits - tail.length) '0') ++ tail

/-- Exact terminating decimals retain all their digits. Repeating quotients use
at least 24 fractional places, extending the scale for tiny positive values.
Arithmetic never uses that display value. -/
def json (a : Exact) : Lean.Json := Id.run do
  let a := ofRatio a.numerator a.denominator
  let mut d := a.denominator
  let mut twos := 0
  let mut fives := 0
  for _ in [:a.denominator.log2 + 1] do
    if d % 2 == 0 && d != 0 then d := d / 2; twos := twos + 1
  for _ in [:a.denominator.log2 + 1] do
    if d % 5 == 0 && d != 0 then d := d / 5; fives := fives + 1
  let digits := if d == 1 then max twos fives else
    24 + (toString a.denominator).length - (toString a.numerator).length
  let digits := if d == 1 then digits else max 24 digits
  -- Canonicalize zero: the JSON number printer does not preserve a long zero
  -- fractional scale as valid JSON.
  return match (Lean.Json.parse (a.fixed digits)).toOption.getD .null with
    | .num n => if n.mantissa == 0 then .num 0 else .num n
    | other => other

private def digits (s : String) : Bool := !s.isEmpty && s.toList.all (fun c => '0' ≤ c && c ≤ '9')

/-- Rust decimal/scientific numeric syntax, parsed as a rational without a
binary floating point intermediate. A negative zero remains zero. -/
def parse (text : String) : Option Exact := do
  let (negative, s) := match text.toList with
    | '-' :: rest => (true, String.ofList rest)
    | '+' :: rest => (false, String.ofList rest)
    | _ => (false, text)
  let parts := (s.replace "E" "e").splitOn "e"
  if parts.length > 2 then none else do
    let base := parts.head!
    let rawExponent := if parts.length == 1 then "0" else parts[1]!
    let unsignedExponent := match rawExponent.toList with
      | '+' :: cs | '-' :: cs => String.ofList cs | _ => rawExponent
    if !digits unsignedExponent then none else do
    let decimals := base.splitOn "."
    if decimals.length > 2 then none else do
      let whole := decimals.head!
      let fraction := if decimals.length == 2 then decimals[1]! else ""
      let coefficient := whole ++ fraction
      if !digits coefficient then none else do
        -- Zero needs no exponent or large integer allocation, even with an
        -- arbitrarily long syntactically valid exponent.
        if coefficient.toList.all (· == '0') then return ⟨0, 1⟩
        if coefficient.length > 1024 || negative then none else do
          let exponentDigits := String.ofList (unsignedExponent.toList.dropWhile (· == '0'))
          if exponentDigits.length > 6 then none else do
          let exponent ← do
            let magnitude ← (if exponentDigits.isEmpty then "0" else exponentDigits).toNat?
            some (if rawExponent.startsWith "-" then -(magnitude : Int) else (magnitude : Int))
          let power := exponent - (fraction.length : Int)
          if power.natAbs > 1024 then none else do
            let n ← coefficient.toNat?
            if power ≥ 0 then some (ofRatio (n * 10^power.toNat) 1)
            else some (ofRatio n (10^power.natAbs))

end Exact

structure FiatAmount where
  amount : Exact
  currency : String
  deriving Repr

inductive FiatConversionPrecision where
  | millisat | wholeSat | floorSat
  deriving Repr, BEq, Inhabited

private def fiatError (message : String) : Error := .onchain ("invalidFiat: " ++ message)

def parseFiat (input : String) : Except Error FiatAmount := do
  let cs := (Bitcoin.Amount.trimInput input).toList
  let suffix := cs.reverse.takeWhile fun c => !('0' ≤ c && c ≤ '9') && c != '.' && c != ','
  let currency := (Bitcoin.Amount.trimInput (String.ofList suffix.reverse)).toUpper
  unless currency.length == 3 && currency.toList.all (fun c => 'A' ≤ c && c ≤ 'Z') &&
      !hasBitcoinUnit currency do throw (fiatError "Expected a three-letter fiat currency")
  let number := Bitcoin.Amount.trimInput (String.ofList (cs.take (cs.length - suffix.length)))
  if number.isEmpty || number.startsWith "+" || number.startsWith "-" ||
      number.startsWith "." || number.endsWith "." then throw (fiatError "Invalid number in amount")
  if number.contains ',' then
    let decimals := number.splitOn "."
    unless decimals.length ≤ 2 && !(decimals[1]?.getD "").contains ',' do
      throw (fiatError "Invalid comma placement in amount")
    let groups := decimals.head!.splitOn ","
    let digits := fun (s : String) => !s.isEmpty && s.toList.all (fun c => '0' ≤ c && c ≤ '9')
    let first := groups.head!
    let western := digits first && first.length ≤ 3 &&
      groups.tail.all (fun s => s.length == 3 && digits s)
    let indian := groups.length ≥ 3 && digits first && first.length ≤ 3 &&
      (groups.getLast!).length == 3 && digits groups.getLast! &&
      (groups.tail.take (groups.length - 2)).all (fun s => s.length == 2 && digits s)
    unless western || indian do throw (fiatError "Invalid comma placement in amount")
  let some amount := Exact.parse (number.replace "," "") | throw (fiatError "Invalid number in amount")
  -- The reference refuses decimal strings that overflow its finite numeric range.
  unless amount.lt ⟨2^1024 - 2^970, 1⟩ do throw (fiatError "Invalid number in amount")
  return ⟨amount, currency⟩

/-- Bitcoin parsing has priority, including its named invalid-unit errors. -/
def parseBitcoinOrFiat (input : String) : Except Error (Bitcoin.Amount ⊕ FiatAmount) :=
  match parseAmount input with
  | .ok amount => .ok (.inl amount)
  | .error e => if hasBitcoinUnit input || !recognizableFiat input then .error e
    else (parseFiat input).map Sum.inr

def convertFiat (fiat : FiatAmount) (currency : String) (price : Exact)
    (precision : FiatConversionPrecision) : Except Error Bitcoin.Amount := do
  unless currency == fiat.currency do throw (.onchain s!"BTC price currency mismatch: expected {fiat.currency}, got {currency}")
  if price.numerator == 0 || price.denominator == 0 || fiat.amount.denominator == 0 then
    throw (.onchain "Invalid BTC price")
  let rounded := ((fiat.amount.div price).mul ⟨100000000000, 1⟩).round
  if rounded > 18446744073709551615 then
    throw (.onchain "Converted fiat amount is outside the supported range")
  if fiat.amount.numerator != 0 && rounded == 0 then
    throw (.onchain "Converted non-zero fiat amount is less than 1 msat")
  let result ← match precision with
    | .millisat => pure (Bitcoin.Amount.mk rounded)
    | .wholeSat => wholeSat ⟨rounded⟩
    | .floorSat => floorSat ⟨rounded⟩
  if result.msat > 18446744073709551615 then
    throw (.onchain "Converted fiat amount is outside the supported range")
  return result

end Cyberkrill
