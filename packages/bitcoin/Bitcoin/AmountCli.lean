/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.AmountText

namespace Bitcoin.Amount

inductive InputError where
  | empty
  | invalidNumber
  | negative
  | subMillisatoshi
  | millisatoshiOverflow
  deriving Repr, DecidableEq

/-- The Unicode White_Space property used by Rust str::trim. -/
def rustWhitespace (c : Char) : Bool :=
  let n := c.toNat
  (9 ≤ n && n ≤ 13) || n == 32 || n == 0x85 || n == 0xa0 || n == 0x1680 ||
    (0x2000 ≤ n && n ≤ 0x200a) || n == 0x2028 || n == 0x2029 ||
    n == 0x202f || n == 0x205f || n == 0x3000

def asciiLower (c : Char) : Char :=
  if 'A' ≤ c && c ≤ 'Z' then Char.ofNat (c.toNat + 32) else c

def trimInput (s : String) : String :=
  String.ofList ((s.toList.dropWhile rustWhitespace).reverse.dropWhile rustWhitespace).reverse

def stripSuffix (s suffix : String) : String :=
  String.ofList (s.toList.take (s.toList.length - suffix.toList.length))

def stripPlus (s : String) : String :=
  match s.toList with
  | '+' :: cs => String.ofList cs
  | _ => s

private def requireSome {α : Type} (error : InputError) : Option α → Except InputError α
  | some a => .ok a
  | none => .error error

/-- Decimal CLI paths accept one sign, including negative zero, but no exponent
or nonfinite values. Syntax is scanned before exact conversion. -/
def parseSigned (s : String) (k : Nat) : Except InputError Amount := do
  let (negative, chars) := match s.toList with
    | '-' :: cs => (true, cs)
    | '+' :: cs => (false, cs)
    | cs => (false, cs)
  let d ← requireSome .invalidNumber (parseDecimal (String.ofList chars))
  if negative && d.mantissa != 0 then throw .negative
  requireSome .subMillisatoshi (ofDecimal d k)

def parseCliMsat (s : String) : Except InputError Amount := do
  let a ← requireSome .invalidNumber (parseMsat (stripPlus s))
  if a.msat ≤ 18446744073709551615 then return a else throw .millisatoshiOverflow

/-- cyberkrill AmountInput suffix order, with exact decimal arithmetic. -/
def parseInput (input : String) : Except InputError Amount :=
  let s := String.ofList ((trimInput input).toList.map asciiLower)
  if s.isEmpty then .error .empty
  else if s.endsWith "msats" then parseCliMsat (stripSuffix s "msats")
  else if s.endsWith "msat" then parseCliMsat (stripSuffix s "msat")
  else if s.endsWith "sats" then parseSigned (stripSuffix s "sats") 3
  else if s.endsWith "sat" then parseSigned (stripSuffix s "sat") 3
  else if s.endsWith "btc" then parseSigned (stripSuffix s "btc") 11
  else parseSigned s 11

end Bitcoin.Amount
