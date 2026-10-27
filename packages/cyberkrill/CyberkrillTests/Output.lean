/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Cyberkrill Lean

def outputTokens : List String :=
  ["-w", "--words", "--seed", "-name", "-h", "--help", "--output", "-o", "--"]

/-- Each selector runs its own dispatch, so one refusal cannot mask another. -/
def outputRefusal (i : Nat) : IO Unit := do
  check "output refusal selector" (i < 18)
  let alias := if i < 9 then "-o" else "--output"
  let calls ← IO.mkRef 0
  let writes ← IO.mkRef 0
  let services := { productionServices with
    entropy := fun _ => do
      calls.modify (· + 1)
      -- Published all-zero 256-bit entropy; output is captured, never printed.
      return ByteArray.mk (Array.replicate 32 0)
    writeFile := fun _ _ => writes.modify (· + 1) }
  let (status, out, err) ← runCase services
    ["generate-mnemonic", alias, outputTokens[i % 9]!]
  -- Separate assertions identify every boundary property even on a selected run.
  check s!"output refusal {i} status" (status == 1)
  check s!"output refusal {i} stdout" out.isEmpty
  check s!"output refusal {i} error" (err == Error.invalidArguments.message ++ "\n")
  check s!"output refusal {i} entropy" ((← calls.get) == 0)
  check s!"output refusal {i} writes" ((← writes.get) == 0)

def outputEqualsCases : List (List String × String) :=
  [(["-o-name=a"], "-name=a"), (["-ofoo=bar"], "foo=bar"),
   (["-oordinary=name"], "ordinary=name"), (["-o-name=a=b"], "-name=a=b"),
   (["-o=-name=a"], "-name=a"), (["--output=-name=a"], "-name=a"),
   (["-o=foo=bar=baz"], "foo=bar=baz"), (["--output=foo=bar=baz"], "foo=bar=baz")]

/-- Literal equals bytes pass through the actual parser, dispatch and writer. -/
def outputEquals (i : Nat) : IO Unit := do
  check "output equals selector" (i < outputEqualsCases.length)
  let published ← getOk "output equals published rows"
    ((← load "../bitcoin/test-data/bip39-english-vectors.json").getArr?)
  counted "output equals published rows" published.size 24
  let entropy ← bytes published[0]! "entropy"
  let phrase ← text published[0]! "mnemonic"
  let expected := (Json.mkObj [("mnemonic", toJson phrase), ("words", toJson (12 : Nat)),
    ("entropy_bits", toJson (128 : Nat))]).compress ++ "\n"
  let calls ← IO.mkRef (#[] : Array Nat)
  let files ← IO.mkRef (#[] : Array (String × String))
  let (args, path) := outputEqualsCases[i]!
  let (status, out, err) ← runCase { productionServices with
    entropy := fun n => do
      calls.modify (·.push n)
      return entropy
    writeFile := fun p s => files.modify (·.push (p, s)) }
    (["generate-mnemonic", "-w", "12"] ++ args)
  check s!"output equals {i} status" (status == 0)
  check s!"output equals {i} stdout" out.isEmpty
  check s!"output equals {i} stderr" err.isEmpty
  check s!"output equals {i} exact path and JSON" ((← files.get) == #[(path, expected)])
  check s!"output equals {i} entropy size and calls" ((← calls.get) == #[16])

def outputEqualsAll : IO Unit := do
  counted "output attached equals paths" outputEqualsCases.length 8
  for i in [:outputEqualsCases.length] do outputEquals i

def outputBoundaries : IO Unit := do
  counted "output option-token refusals" (outputTokens.length * 2) 18
  for i in [:18] do outputRefusal i
  let missing := [["-o"], ["--output"]]
  let duplicates := [["-o", "a", "-o", "b"], ["-o", "a", "--output", "b"],
    ["--output=a", "-o", "b"], ["--output=a", "--output=b"]]
  counted "output missing values" missing.length 2
  counted "output duplicates" duplicates.length 4
  let calls ← IO.mkRef 0
  let writes ← IO.mkRef 0
  let services := { productionServices with
    entropy := fun _ => do
      calls.modify (· + 1)
      return ByteArray.mk (Array.replicate 32 0)
    writeFile := fun _ _ => writes.modify (· + 1) }
  for i in [:(missing ++ duplicates).length] do
    let (status, out, err) ← runCase services ("generate-mnemonic" :: (missing ++ duplicates)[i]!)
    check s!"output malformed {i}" (status == 1 && out.isEmpty &&
      err == Error.invalidArguments.message ++ "\n" && (← calls.get) == 0 && (← writes.get) == 0)
  -- Exact published phrase is read from the existing fixture, never recorded anew.
  let published ← getOk "output published rows" ((← load "../bitcoin/test-data/bip39-english-vectors.json").getArr?)
  counted "output published rows" published.size 24
  let entropy ← bytes published[0]! "entropy"
  let phrase ← text published[0]! "mnemonic"
  let expected := (Json.mkObj [("mnemonic", toJson phrase), ("words", toJson (12 : Nat)),
    ("entropy_bits", toJson (128 : Nat))]).compress ++ "\n"
  let controls := [(["-o", "ordinary.json"], "ordinary.json"),
    (["--output", "ordinary.json"], "ordinary.json"),
    (["-o", "-"], "-"), (["--output", "-"], "-"),
    (["--output=-name"], "-name"), (["-o=-name"], "-name"),
    (["-o-name"], "-name"), (["--output=--words"], "--words"),
    (["-o=--words"], "--words"), (["-o--words"], "--words"),
    (["--output= a=b \t"], " a=b \t"), (["-o", "a=b \t"], "a=b \t")]
  counted "output literal path controls" controls.length 12
  for i in [:controls.length] do
    let (args, path) := controls[i]!
    calls.set 0
    let files ← IO.mkRef (#[] : Array (String × String))
    let (status, out, err) ← runCase { services with
      entropy := fun n => do
        calls.modify (· + 1)
        check s!"output control {i} entropy size" (n == 16)
        return entropy
      writeFile := fun p s => files.modify (·.push (p, s)) }
      (["generate-mnemonic", "-w", "12"] ++ args)
    check s!"output control {i} routing" (status == 0 && out.isEmpty && err.isEmpty)
    check s!"output control {i} exact path and JSON" ((← files.get) == #[(path, expected)])
    check s!"output control {i} entropy calls" ((← calls.get) == 1)
  outputEqualsAll

end CyberkrillTests
