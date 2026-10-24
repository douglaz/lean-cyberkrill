/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Lean.Data.Json

namespace BitcoinTests.FeeTests

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

private def checks (name : String) (pinned : Nat) (cases : Array (String × Bool)) : IO Unit := do
  check s!"{name} count" (cases.size == pinned)
  for (label, ok) in cases do check s!"{name} {label}" ok
  IO.println s!"{name}: {cases.size}/{pinned}"

private def getOk {ε α : Type} (name : String) (value : Except ε α) : IO α :=
  match value with
  | .ok result => pure result
  | .error _ => throw <| IO.userError s!"assertion failed: {name}"

private def field (row : Lean.Json) (key : String) : IO String :=
  getOk s!"fee field {key}" (row.getObjValAs? String key)

private def number (row : Lean.Json) (key : String) : IO Nat := do
  match (← field row key).toNat? with
  | some n => pure n
  | none => throw <| IO.userError s!"assertion failed: fee decimal {key}"

private def rows (name : String) (count : Nat) : IO (Array Lean.Json) := do
  let json ← getOk "fee JSON" (Lean.Json.parse (← IO.FS.readFile "test-data/cyberkrill-fee.json"))
  let result ← getOk s!"fee JSON {name}" (json.getObjValAs? (Array Lean.Json) name)
  check s!"fee {name} count" (result.size == count)
  pure result

private def rateNames : Array String := #["0msat", "1msat", "1000msat", "1sat", "0.5sat",
  "0.1sat", "0.01sat", "1.15sats", "2.5sats", "15sats", "20sats", "100sats", "0.00000002",
  "0.00000002btc", "15", "9007199254740993msat", "18446744073709551615msat", "200000000btc"]

private def shapeCounts : Array (Nat × Nat) := #[(0,0), (0,1), (1,0), (1,1), (1,2), (2,2),
  (3,1), (5,1), (10,1), (20,1), (252,1), (253,1), (1,252), (1,253), (65535,1), (65536,1)]

private def directWeights : Array Nat := #[0, 1, 3, 4, 5, 36028797018963972,
  36028797018963980, 18446744073709551615]

private def parseRate (name : String) : IO Bitcoin.Amount :=
  getOk s!"fee rate {name} parses" (Bitcoin.Amount.parseInput name)

def rates : IO Unit := do
  let captured ← rows "rates" 18
  check "fee rate grid count" (rateNames.size == 18)
  for i in [:captured.size] do
    let name ← field captured[i]! "rate"
    check s!"fee rate {i} order" (name == rateNames[i]!)
    let expected ← number captured[i]! "msat"
    let actual ← parseRate name
    if name == "200000000btc" then
      check "fee rate above-u64 Phase 3a difference"
        (actual.msat == 20000000000000000000 && expected == 18446744073709551615)
    else check s!"fee rate {name} msat" (actual.msat == expected)
  IO.println "fee rates: 18/18"

def shapes : IO Unit := do
  let captured ← rows "shapes" 16
  check "fee shape grid count" (shapeCounts.size == 16)
  for i in [:captured.size] do
    let (inputs, outputs) := shapeCounts[i]!
    check s!"fee shape {i} order"
      ((← number captured[i]! "inputs") == inputs && (← number captured[i]! "outputs") == outputs)
    let weight := Bitcoin.Fee.estimateWeight inputs outputs
    check s!"fee shape ({inputs},{outputs}) weight" (weight == (← number captured[i]! "weight"))
    check s!"fee shape ({inputs},{outputs}) vbytes"
      (Bitcoin.Fee.vbytes weight == (← number captured[i]! "vbytes"))
  IO.println "fee shapes: 16/16"

def shapeFees : IO Unit := do
  let captured ← rows "shapeFees" 288
  check "fee shape fee grid count" (shapeCounts.size * rateNames.size == 288)
  for i in [:captured.size] do
    let (inputs, outputs) := shapeCounts[i / 18]!
    let name := rateNames[i % 18]!
    check s!"fee shape fee {i} order" ((← number captured[i]! "inputs") == inputs &&
      (← number captured[i]! "outputs") == outputs && (← field captured[i]! "rate") == name)
    let actual := Bitcoin.Fee.estimateFee (Bitcoin.Fee.estimateWeight inputs outputs) (← parseRate name)
    check s!"fee shape ({inputs},{outputs}) at {name} sats"
      (Bitcoin.Amount.toSats? actual == some (← number captured[i]! "sats"))
  IO.println "fee shape fees: 288/288"

def weightFees : IO Unit := do
  let captured ← rows "weightFees" 144
  check "fee direct weight grid count" (directWeights.size == 8 && directWeights.size * rateNames.size == 144)
  for i in [:captured.size] do
    let weight := directWeights[i / 18]!
    let name := rateNames[i % 18]!
    check s!"fee direct fee {i} order" ((← number captured[i]! "weight") == weight &&
      (← field captured[i]! "rate") == name)
    let actual := Bitcoin.Fee.estimateFee weight (← parseRate name)
    check s!"fee weight {weight} at {name} sats"
      (Bitcoin.Amount.toSats? actual == some (← number captured[i]! "sats"))
  IO.println "fee direct-weight fees: 144/144"

-- Every named literal is checked against both the port and its captured row.
def pins : IO Unit := do
  let capturedShapes ← rows "shapes" 16
  let mut cases := #[]
  for (index, inputs, outputs, wu, vb) in #[(3,1,1,438,110), (5,2,2,834,209),
      (7,5,1,1526,382), (1,0,1,164,41)] do
    let weight := Bitcoin.Fee.estimateWeight inputs outputs
    cases := cases.push (s!"({inputs},{outputs}) WU {wu}",
      weight == wu && (← number capturedShapes[index]! "weight") == wu)
    cases := cases.push (s!"({inputs},{outputs}) vB {vb}",
      Bitcoin.Fee.vbytes weight == vb && (← number capturedShapes[index]! "vbytes") == vb)
  let capturedFees ← rows "shapeFees" 288
  for (index, inputs, outputs, name, sats) in #[(3*18+7,1,1,"1.15sats",126),
      (5*18+4,2,2,"0.5sat",105), (11*18+16,253,1,"18446744073709551615msat",18446744073709551615)] do
    let row := capturedFees[index]!
    let actual := Bitcoin.Fee.estimateFee (Bitcoin.Fee.estimateWeight inputs outputs) (← parseRate name)
    cases := cases.push (s!"({inputs},{outputs}) at {name} = {sats}",
      Bitcoin.Amount.toSats? actual == some sats && (← number row "sats") == sats &&
      (← number row "inputs") == inputs && (← number row "outputs") == outputs &&
      (← field row "rate") == name)
  let capturedWeights ← rows "weightFees" 144
  for (index, weight, sats) in #[(5*18+3,36028797018963972,9007199254740992),
      (6*18+3,36028797018963980,9007199254740996)] do
    let actual := Bitcoin.Fee.estimateFee weight (← parseRate "1sat")
    cases := cases.push (s!"weight {weight} ties to even = {sats}",
      Bitcoin.Amount.toSats? actual == some sats &&
      (← number capturedWeights[index]! "sats") == sats &&
      (← number capturedWeights[index]! "weight") == weight &&
      (← field capturedWeights[index]! "rate") == "1sat")
  let capturedRates ← rows "rates" 18
  cases := cases.push ("bare 15 is BTC", (← parseRate "15").msat == 1500000000000 &&
    (← number capturedRates[14]! "msat") == 1500000000000 &&
    (← field capturedRates[14]! "rate") == "15")
  checks "fee named pins" 14 cases
  checks "fee upstream ranges" 3 (#[(1,1,109,112), (2,2,206,212), (5,1,378,385)].map
    fun (inputs, outputs, low, high) =>
      let vb := Bitcoin.Fee.vbytes (Bitcoin.Fee.estimateWeight inputs outputs)
      (s!"({inputs},{outputs}) {low}..={high}", low ≤ vb && vb ≤ high))

def run (selection : Option String := none) : IO Unit := do
  match selection with
  | none =>
    rates; shapes; shapeFees; weightFees; pins
    IO.println "fee captured rows: 466/466"
  | some "rates" => rates
  | some "shapes" => shapes
  | some "shape-fees" => shapeFees
  | some "weight-fees" => weightFees
  | some "pins" => pins
  | some _ => throw <| IO.userError "unknown fee test selection"

end BitcoinTests.FeeTests
