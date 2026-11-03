/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lean

namespace Cyberkrill.Frozenkrill
open Lean

/-- Public descriptors only; all export fields are checked before returning them. -/
structure Wallet where
  receiving : String
  change : String
  deriving BEq, Repr

private def required (j : Json) (key : String) : Except String Json := j.getObjVal? key
private def string (j : Json) (key : String) : Except String String := do
  (← required j key).getStr?

def u32 (j : Json) : Except String Nat := do
  let n ← j.getNat?
  if n ≤ 4294967295 then return n else throw "u32"

private def optional (j : Json) (key : String) (check : Json → Except String α) : Except String Unit := do
  match j.getObjVal? key with
  | .error _ | .ok .null => pure ()
  | .ok value => let _ ← check value; pure ()

private def digit (c : Char) : Bool := '0' ≤ c && c ≤ '9'

-- JsonNumber can normalize an exponent-form number to an integer. Serde's
-- u32 reader still rejects that floating token, including negative zero. After validating the original
-- JSON, mask floating tokens with a type none of these schemas accepts. Quoted
-- strings and unknown fields retain their deserialization behavior.
private partial def schemaNumbers (cs : List Char) (quoted escaped : Bool := false) : List Char :=
  match cs with
  | [] => []
  | c :: rest =>
    if quoted then
      c :: schemaNumbers rest (escaped || c != '"') (!escaped && c == '\\')
    else if c == '"' then c :: schemaNumbers rest true false
    else if digit c || c == '-' then
      let token := cs.takeWhile (fun c => digit c || ['-', '+', '.', 'e', 'E'].contains c)
      let remaining := schemaNumbers (cs.drop token.length) false false
      (if token == "-0".toList || token.any (fun c => ['.', 'e', 'E'].contains c)
       then "false".toList else token) ++ remaining
    else c :: schemaNumbers rest false false

private def separator (cs : List Char) : List Char :=
  match cs with | ' ' :: rest | '-' :: rest => rest | _ => cs

-- Search left to right, retaining the first syntactic match even when its
-- numeric bounds fail. Each separator is at most one ASCII space or hyphen.
private def firstMultisig : List Char → Option (String × String)
  | [] => none
  | c :: rest =>
    let cs := c :: rest
    let m := cs.takeWhile digit
    let afterM := separator (cs.drop m.length)
    let found := match afterM with
      | 'o' :: 'f' :: tail =>
        let n := (separator tail).takeWhile digit
        if m.isEmpty || n.isEmpty then none else some (String.ofList m, String.ofList n)
      | _ => none
    found.orElse fun _ => firstMultisig rest

def singlesig (value : String) : Except String Bool := do
  let value := value.toLower
  if value == "singlesig" then return true
  let some (m, n) := firstMultisig value.toList | throw "sigtype"
  let some m := m.toNat? | throw "sigtype"
  let some n := n.toNat? | throw "sigtype"
  unless m ≤ 4294967295 && n ≤ 4294967295 && 0 < m && m ≤ n && n ≤ 15 do throw "sigtype"
  return false

private def addresses (j : Json) (key : String) : Except String Unit := do
  for item in ← (← required j key).getArr? do
    -- Serde's struct visitor also accepts exactly three positional fields.
    let item ← match item with
      | .arr values => do
        unless values.size == 3 do throw "address arity"
        pure (Json.mkObj [("address", values[0]?.getD .null),
          ("derivation_path", values[1]?.getD .null), ("index", values[2]?.getD .null)])
      | _ => pure item
    let _ ← string item "address"
    optional item "derivation_path" Json.getStr?
    optional item "index" u32

-- Keep field occurrences and original UTF-16 escapes until the selected
-- schemas have checked them. Ignored values retain Serde's skip behavior.
private inductive Syntax where
  | atom (validString : Bool)
  | object (fields : List (String × Syntax)) (validKeys : Bool)
  | array (values : List Syntax)
  deriving Inhabited

private def skip (cs : List Char) : List Char :=
  cs.dropWhile (fun c => [' ', '\t', '\r', '\n'].contains c)

private def hexDigit (c : Char) : Nat :=
  if '0' ≤ c && c ≤ '9' then c.toNat - '0'.toNat
  else c.toLower.toNat - 'a'.toNat + 10

-- Json.parse has already checked escape structure and hex digits. Only the
-- surrogate pairing information is lost by its replacement decoding.
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
    Except String (String × List Char) := do
  match cs with
  | [] => throw "string"
  | '\\' :: c :: rest => stringToken rest (c :: '\\' :: acc)
  | '"' :: rest => return (String.ofList ('"' :: acc).reverse, rest)
  | c :: rest => stringToken rest (c :: acc)

private partial def parseSyntax (cs : List Char) : Except String (Syntax × List Char) := do
  match skip cs with
  | '{' :: rest =>
    let rec object (cs : List Char) (fields : List (String × Syntax)) (validKeys : Bool) := do
      match skip cs with
      | '}' :: rest => return (Syntax.object fields.reverse validKeys, rest)
      | '"' :: tail =>
        let (token, tail) ← stringToken tail
        let .str key ← Json.parse token | throw "field"
        let ':' :: tail := skip tail | throw "field"
        let (value, tail) ← parseSyntax tail
        let fields := (key, value) :: fields
        let validKeys := validKeys && validStringChars token.toList
        match skip tail with
        | ',' :: tail => object tail fields validKeys
        | '}' :: tail => return (Syntax.object fields.reverse validKeys, tail)
        | _ => throw "object"
      | _ => throw "object"
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
        | _ => throw "array"
    array rest []
  | '"' :: tail =>
    let (token, tail) ← stringToken tail
    return (.atom (validStringChars token.toList), tail)
  | tail =>
    let token := tail.takeWhile fun c => !([',', '}', ']', ' ', '\t', '\r', '\n'].contains c)
    if token.isEmpty then throw "atom"
    return (.atom true, tail.drop token.length)

private def checkObject (value : Syntax) (known : List String) :
    Except String (List (String × Syntax)) := do
  let .object fields validKeys := value | throw "object"
  unless validKeys do throw "field escape"
  let names := fields.map (·.1) |>.filter (known.contains ·)
  unless names.eraseDups.length == names.length do throw "duplicate field"
  for (key, value) in fields do
    if known.contains key then
      if let .atom valid := value then
        unless valid do throw "string escape"
  return fields

private def checkSyntax (text : String) (single : Bool) : Except String Unit := do
  let (root, rest) ← parseSyntax text.toList
  unless (skip rest).isEmpty do throw "trailing data"
  let known := ["wallet", "version", "sigtype", "script_type", "network",
    "receiving_addresses", "change_addresses"] ++
    (if single then ["master_fingerprint", "singlesig_xpub", "singlesig_derivation_path",
      "multisig_xpub", "multisig_derivation_path", "multisig_receiving_output_descriptor_key",
      "multisig_change_output_descriptor_key", "singlesig_receiving_output_descriptor",
      "singlesig_change_output_descriptor"] else ["receiving_output_descriptor", "change_output_descriptor"])
  let fields ← checkObject root known
  for (key, value) in fields do
    if key == "receiving_addresses" || key == "change_addresses" then
      if let .array values := value then
        for item in values do
          if let .array slots := item then
            for slot in slots do
              if let .atom valid := slot then
                unless valid do throw "slot escape"
          else
            let _ ← checkObject item ["address", "derivation_path", "index"]

/-- Reimplementation of the pinned MIT export detector and two deserialization
schemas; provenance is recorded in test/list-utxos-provenance.json. -/
def parse (text : String) : Except String Wallet := do
  let _ ← Json.parse text
  let j ← Json.parse (String.ofList (schemaNumbers text.toList))
  unless (← string j "wallet") == "frozenkrill" do throw "wallet"
  optional j "version" u32
  optional j "sigtype" Json.getStr?
  let single ← singlesig (← string j "sigtype")
  checkSyntax text single
  let _ ← u32 (← required j "version")
  for key in ["script_type", "network"] do let _ ← string j key
  addresses j "receiving_addresses"
  addresses j "change_addresses"
  if single then
    for key in ["master_fingerprint", "singlesig_xpub", "singlesig_derivation_path",
        "multisig_xpub", "multisig_derivation_path", "multisig_receiving_output_descriptor_key",
        "multisig_change_output_descriptor_key"] do let _ ← string j key
    return {
      receiving := ← string j "singlesig_receiving_output_descriptor",
      change := ← string j "singlesig_change_output_descriptor" }
  else
    return {
      receiving := ← string j "receiving_output_descriptor",
      change := ← string j "change_output_descriptor" }

end Cyberkrill.Frozenkrill
