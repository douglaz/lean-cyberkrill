/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support
namespace CyberkrillTests
open Cyberkrill Lean

def injected (plus : Bool := false) : IO Unit := do
  let input ← (← IO.getStdin).getLine
  let rows ← getOk "mnemonic oracle input" ((Json.parse input).bind Json.getArr?)
  counted "mnemonic exact oracle" rows.size 40
  for count in [12,15,18,21,24] do
    counted s!"mnemonic words {count}" (rows.filter fun j => (j.getObjValAs? Nat "words").toOption == some count).size 8
  for i in [:rows.size] do
    let row := rows[i]!
    let entropy ← bytes row "entropy"
    let expected ← text row "mnemonic"
    let words ← getOk "oracle count" (row.getObjValAs? Nat "words")
    let calls ← IO.mkRef 0
    let requested ← IO.mkRef 0
    let services := { productionServices with entropy := fun n => do
      calls.modify (· + 1)
      requested.set n
      return entropy }
    let args := ["generate-mnemonic", "--words", (if plus then "+" else "") ++ toString words]
    let (status, stdout, stderr) ← runCase services args
    if plus then
      check s!"mnemonic exact status {i}" (status == 0 && stderr.isEmpty && (← calls.get) == 1)
    check "mnemonic entropy mapping" ((← requested.get) == entropy.size)
    check s!"mnemonic exact status {i}" (status == 0 && stderr.isEmpty && (← calls.get) == 1)
    let actual ← getOk s!"mnemonic JSON {i}" (Json.parse stdout)
    let expectedJson := Json.mkObj [("mnemonic", toJson expected), ("words", toJson words),
      ("entropy_bits", toJson (entropy.size * 8))]
    check s!"mnemonic exact value {i}" (actual == expectedJson)
    IO.FS.withTempDir fun dir => do
      let path := dir / "mnemonic.json"
      let (status, out, err) ← runCase services (args ++ ["--output", path.toString])
      check "mnemonic file stdout" (status == 0 && out.isEmpty && err.isEmpty)
      check s!"mnemonic file contents {i}" ((← IO.FS.readFile path) == stdout)
    if words == 24 then
      let (status, out, err) ← runCase services ["generate-mnemonic"]
      check "mnemonic default 24" (status == 0 && out == stdout && err.isEmpty)
  counted "mnemonic file routing" rows.size 40
  counted "mnemonic default" 8 8

def wordCountRejections : IO Unit := do
  let invalid := ["1_2", "1_5", "1_8", "2_1", "2_4", "", "+", "++12", "+1_2",
    " 12", "12 ", "１２", "12.0", "4294967296", "0", "13", "-12"]
  counted "mnemonic word-count rejections" invalid.length 17
  for i in [:invalid.length] do
    let calls ← IO.mkRef 0
    let services := { productionServices with entropy := fun _ => do
      calls.modify (· + 1)
      -- Published all-zero 128-bit entropy; never draw fresh bytes on this path.
      return ByteArray.mk (Array.replicate 16 0) }
    let (status, out, err) ← runCase services ["generate-mnemonic", "-w", invalid[i]!]
    check s!"word-count rejection before entropy {i}" (status == 1 && out.isEmpty &&
      err == Error.invalidWordCount.message ++ "\n" && (← calls.get) == 0)

def mnemonicErrors : IO Unit := do
  counted "mnemonic boundary paths" 6 6
  let calls ← IO.mkRef 0
  let throwing := { productionServices with entropy := fun _ => do
    calls.modify (· + 1); throw (IO.userError "sensitive-sentinel") }
  let (status, out, err) ← runCase throwing ["generate-mnemonic", "-w", "11"]
  check "mnemonic validate before entropy" (status == 1 && out.isEmpty &&
    (← calls.get) == 0 && err == Error.invalidWordCount.message ++ "\n")
  let (status, out, err) ← runCase throwing ["generate-mnemonic"]
  check "mnemonic entropy error" (status == 1 && out.isEmpty && err == Error.entropyFailure.message ++ "\n")
  let short := { productionServices with entropy := fun _ => pure ByteArray.empty }
  let (status, out, err) ← runCase short ["generate-mnemonic"]
  check "mnemonic short read" (status == 1 && out.isEmpty && err == Error.shortEntropy.message ++ "\n")
  let published ← getOk "English rows" ((← load "../bitcoin/test-data/bip39-english-vectors.json").getArr?)
  counted "existing English" published.size 24
  let e ← bytes published[0]! "entropy"
  let services := { productionServices with entropy := fun _ => pure e }
  IO.FS.withTempDir fun dir => do
    let (status, out, err) ← runCase services ["generate-mnemonic", "-w", "12", "-o", (dir / "missing" / "child").toString]
    check "mnemonic file failure secret free" (status == 1 && out.isEmpty && err == Error.outputFailure.message ++ "\n")
  let errors ← IO.mkRef ""
  let status ← runWith version { services with
    stdout := fun _ => throw (IO.userError "sensitive-sentinel")
    stderr := fun s => errors.modify (· ++ s) } ["generate-mnemonic", "-w", "12"]
  check "mnemonic stdout failure secret free" (status == 1 && (← errors.get) == Error.outputFailure.message ++ "\n")
  let outputPath ← IO.mkRef ""
  let (status, out, err) ← runCase { services with writeFile := fun path _ => outputPath.set path }
    ["generate-mnemonic", "-w", "12", "--output=-name"]
  check "mnemonic output path preservation" (status == 0 && out.isEmpty && err.isEmpty &&
    (← outputPath.get) == "-name")
end CyberkrillTests
