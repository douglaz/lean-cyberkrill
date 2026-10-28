/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.Amounts
import Lean

namespace Cyberkrill.InvoiceJson
open Lean

private inductive Syntax where
  | atom (value : Json) (literal : String)
  | object (fields : List (String × Syntax)) (validKeys : Bool)
  | array (values : List Syntax)
  deriving Inhabited

private def skip (cs : List Char) : List Char := cs.dropWhile (fun c => [' ', '\t', '\r', '\n'].contains c)

private def hexDigit (c : Char) : Nat :=
  if '0' ≤ c && c ≤ '9' then c.toNat - '0'.toNat
  else c.toLower.toNat - 'a'.toNat + 10

-- The value parser replaces lone UTF-16 surrogates. Check the original tokens
-- where Serde requests strings, but preserve IgnoredAny's skip behavior.
private def validStringChars : List Char → Bool
  | '\\' :: 'u' :: a :: b :: c :: d :: rest =>
    let unit := ((hexDigit a * 16 + hexDigit b) * 16 + hexDigit c) * 16 + hexDigit d
    if 0xD800 ≤ unit && unit ≤ 0xDBFF then
      match rest with
      | '\\' :: 'u' :: e :: f :: g :: h :: tail =>
        let low := ((hexDigit e * 16 + hexDigit f) * 16 + hexDigit g) * 16 + hexDigit h
        0xDC00 ≤ low && low ≤ 0xDFFF && validStringChars tail
      | _ => false
    else !(0xDC00 ≤ unit && unit ≤ 0xDFFF) && validStringChars rest
  | '\\' :: _ :: rest => validStringChars rest
  | _ :: rest => validStringChars rest
  | [] => true

private partial def stringToken (cs : List Char) (acc : List Char := ['"']) :
    Except Error (String × List Char) := do
  match cs with
  | [] => throw .invalidInvoiceJson
  | '\\' :: c :: rest => stringToken rest (c :: '\\' :: acc)
  | '"' :: rest => return (String.ofList ('"' :: acc).reverse, rest)
  | c :: rest => stringToken rest (c :: acc)

-- Retain lexical numbers and duplicate keys: Lean.Json's value representation
-- erases positive exponents and repeated keys, while the reference rejects them
-- for typed unsigned fields and known struct fields, respectively.
private partial def parseSyntax (cs : List Char) : Except Error (Syntax × List Char) := do
  let cs := skip cs
  match cs with
  | '{' :: rest =>
    let rec object (cs : List Char) (fields : List (String × Syntax)) (validKeys : Bool) := do
      match skip cs with
      | '}' :: rest => return (Syntax.object fields.reverse validKeys, rest)
      | '"' :: tail =>
        let (keyToken, tail) ← stringToken tail
        let validKeys := validKeys && validStringChars keyToken.toList
        let .ok (.str key) := Json.parse keyToken | throw Error.invalidInvoiceJson
        let ':' :: tail := skip tail | throw Error.invalidInvoiceJson
        let (value, tail) ← parseSyntax tail
        match skip tail with
        | ',' :: tail => object tail ((key, value) :: fields) validKeys
        | '}' :: tail => return (Syntax.object ((key, value) :: fields).reverse validKeys, tail)
        | _ => throw Error.invalidInvoiceJson
      | _ => throw Error.invalidInvoiceJson
    object rest [] true
  | '[' :: rest =>
    let rec array (cs : List Char) (values : List Syntax) := do
      match skip cs with
      | ']' :: rest => return (Syntax.array values.reverse, rest)
      | tail =>
        let (value, tail) ← parseSyntax tail
        match skip tail with
        | ',' :: tail => array tail (value :: values)
        | ']' :: tail => return (Syntax.array (value :: values).reverse, tail)
        | _ => throw Error.invalidInvoiceJson
    array rest []
  | '"' :: rest =>
    let (token, rest) ← stringToken rest
    let .ok value := Json.parse token | throw .invalidInvoiceJson
    return (.atom value token, rest)
  | _ =>
    let token := cs.takeWhile fun c => !([',', '}', ']', ' ', '\t', '\r', '\n'].contains c)
    if token.isEmpty then throw .invalidInvoiceJson
    let literal := String.ofList token
    let .ok value := Json.parse literal | throw .invalidInvoiceJson
    return (.atom value literal, cs.drop token.length)

private def digits (s : String) : Bool :=
  !s.isEmpty && s.toList.all (fun c => '0' ≤ c && c ≤ '9')

private def structLength (actual expected : Nat) : Bool := actual == expected

private def structFields (value : Syntax) (known : List String) :
    Except Error (List (String × Syntax)) := do
  match value with
  | .object fields validKeys =>
    unless validKeys do throw .invalidInvoiceJson
    return fields
  | .array values =>
    unless structLength values.length known.length do throw .invalidInvoiceJson
    return known.zip values
  | _ => throw .invalidInvoiceJson

private partial def checkStrings (value : Syntax) : Except Error Unit := do
  match value with
  | .atom (.str _) literal =>
    unless validStringChars literal.toList do throw .invalidInvoiceJson
  | .object fields validKeys =>
    unless validKeys do throw .invalidInvoiceJson
    for (_, v) in fields do checkStrings v
  | .array values => for v in values do checkStrings v
  | _ => pure ()

private def checkObject (value : Syntax) (known numbers : List String) :
    Except Error (List (String × Syntax)) := do
  let fields ← structFields value known
  let names := fields.map (·.1) |>.filter (known.contains ·)
  unless names.eraseDups.length == names.length do throw .invalidInvoiceJson
  for (key, value) in fields do
    if known.contains key && key != "routes" && key != "fees" then checkStrings value
    if numbers.contains key then
      if let .atom (.num _) literal := value then
        unless digits literal do throw .invalidInvoiceJson
  return fields

private partial def checkEnumSyntax : Syntax → Except Error Unit
  | .object [(_, value)] true => checkEnumSyntax value
  | .object _ _ => throw .invalidInvoiceJson
  | _ => pure ()

def validateSyntax (input : String) : Except Error Unit := do
  let (root, rest) ← parseSyntax input.toList
  unless (skip rest).isEmpty do throw .invalidInvoiceJson
  let fields ← checkObject root ["network", "amount_msats", "timestamp", "timestamp_millis", "payment_hash",
    "payment_secret", "features", "description", "description_hash", "destination", "expiry_seconds",
    "min_final_cltv_expiry", "fallback_addresses", "routes"]
    ["amount_msats", "timestamp_millis", "expiry_seconds", "min_final_cltv_expiry"]
  for (key, value) in fields do
    if key == "network" then checkEnumSyntax value
    if key == "features" then
      if let .array values := value then
        for value in values do checkEnumSyntax value
    if key == "routes" then
      if let .array routes := value then
        for route in routes do
          if let .array hops := route then
            for hop in hops do
              let fields ← checkObject hop ["src_node_id", "short_channel_id", "fees", "cltv_expiry_delta",
                "htlc_minimum_msat", "htlc_maximum_msat"]
                ["short_channel_id", "cltv_expiry_delta", "htlc_minimum_msat", "htlc_maximum_msat"]
              for (key, value) in fields do
                if key == "fees" then
                  let _ ← checkObject value ["base_msat", "proportional_millionths"]
                    ["base_msat", "proportional_millionths"]

/-- Struct sequences have every declaration slot, including optional slots.
Objects keep their normal required/optional field rules. -/
def structObject (value : Json) (fields : List String) : Except Error Json := do
  match value with
  | .arr values =>
    unless structLength values.size fields.length do throw .invalidInvoiceJson
    return Json.mkObj (fields.zip values.toList)
  | .obj _ => return value
  | _ => throw .invalidInvoiceJson

/-- Serde unit enums accept a string or a single-key object with null content. -/
def enumName (value : Json) : Except Error String := do
  if let .str s := value then return s
  let .ok obj := value.getObj? | throw .invalidInvoiceJson
  let [(name, .null)] := obj.toList | throw .invalidInvoiceJson
  return name

-- Rust char::is_whitespace uses Unicode White_Space, including non-ASCII
-- separators that Lean's ASCII JSON whitespace scanner must not consume.
private def timeSpace (c : Char) : Bool :=
  (9 ≤ c.toNat && c.toNat ≤ 13) || [0x20, 0x85, 0xA0, 0x1680,
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000].contains c.toNat ||
    (0x2000 ≤ c.toNat && c.toNat ≤ 0x200A)

private def timeTrim (cs : List Char) : List Char := cs.dropWhile timeSpace

private def timeNumber (cs : List Char) (width : Nat) : Option (Nat × List Char) := do
  let ds := cs.take width |>.takeWhile (fun c => '0' ≤ c && c ≤ '9')
  if ds.isEmpty then none else
    return (← (String.ofList ds).toNat?, cs.drop ds.length)

private def timeComponent (cs : List Char) : Option (Nat × List Char) :=
  timeNumber (timeTrim cs) 2

private def timePunctuation (cs : List Char) (c : Char) : Option (List Char) := do
  let x :: rest := timeTrim cs | none
  if x == c then some rest else none

private def timeOffset (cs : List Char) : Option Int := do
  let cs := timeTrim cs
  if cs.head? == some 'Z' || cs.head? == some 'z' then
    if (timeTrim cs.tail).isEmpty then return 0 else none
  else if (String.ofList (cs.take 3)).toLower == "utc" then
    if (timeTrim (cs.drop 3)).isEmpty then return 0 else none
  else
    let sign :: rest := cs | none
    unless ['+', '-', '−'].contains sign do none
    let (hours, rest') ← timeNumber rest 2
    unless rest.length - rest'.length == 2 && hours < 24 do none
    let rest := rest'.dropWhile fun c => c == ':' || timeSpace c
    let (minutes, tail) ← timeNumber rest 2
    unless rest.length - tail.length == 2 && minutes < 60 && (timeTrim tail).isEmpty do none
    let offset : Int := .ofNat (hours * 3600 + minutes * 60)
    return if sign == '+' then offset else -offset

private def parseTimestamp (input : String) : Option Unit := do
  let chars := timeTrim input.toList
  let signed := ['+', '-'].contains (chars.headD ' ')
  let negative := chars.head? == some '-'
  let (year, rest) ← timeNumber (if signed then chars.tail else chars)
    (if signed then chars.length else 4)
  -- Chrono's signed scanner first checks the positive magnitude as i64.
  if year > 9223372036854775807 then none else do
    let year : Int := if negative then -(.ofNat year) else .ofNat year
    unless -262143 ≤ year && year ≤ 262142 do none
    let rest ← timePunctuation rest '-'
    let (month, rest) ← timeComponent rest
    let rest ← timePunctuation rest '-'
    let (day, rest) ← timeComponent rest
    let separator :: rest := rest | none
    unless ['T', 't', ' '].contains separator do none
    let (hour, rest) ← timeComponent rest
    let rest ← timePunctuation rest ':'
    let (minute, rest) ← timeComponent rest
    let rest ← timePunctuation rest ':'
    let (second, rest) ← timeComponent rest
    let leap := year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    let days := if month == 2 then (if leap then 29 else 28)
      else if [4, 6, 9, 11].contains month then 30 else 31
    unless 1 ≤ month && month ≤ 12 && 1 ≤ day && day ≤ days &&
        hour < 24 && minute < 60 && second ≤ 60 do none
    let rest ← if rest.head? == some '.' then do
      let ds := rest.tail.takeWhile fun c => '0' ≤ c && c ≤ '9'
      if ds.isEmpty then none else some (rest.drop (ds.length + 1))
      else some rest
    let offset ← timeOffset rest
    -- Leap seconds are represented by second 59 plus excess nanoseconds.
    -- Offsets are below one day, so only the two endpoint dates can cross
    -- Chrono's UTC date range after conversion from a valid local date.
    let utc : Int := .ofNat (hour * 3600 + minute * 60 + min second 59) - offset
    if year == -262143 && month == 1 && day == 1 && utc < 0 then none
    else if year == 262142 && month == 12 && day == 31 && utc ≥ 86400 then none
    else some ()

/-- Chrono 0.4.42's relaxed FromStr grammar and local/UTC date ranges.
Signing still uses timestamp_millis. See format/parse.rs and scan.rs at that
version; this parser adds no date or JSON dependency. -/
def timestampValid (input : String) : Bool := (parseTimestamp input).isSome

end Cyberkrill.InvoiceJson
