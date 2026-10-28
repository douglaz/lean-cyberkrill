/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support
namespace CyberkrillTests
open Cyberkrill

def helpers (only : String) : IO Unit := do
  selected only "version" do
    counted "package version" 1 1
    let (status, out, err) ← runCase productionServices ["version"]
    let j ← getOk "version JSON" (Lean.Json.parse out)
    check "version package constant" (status == 0 && err.isEmpty &&
      j == Lean.Json.mkObj [("version", .str version)])
  selected only "whole-round" do
    counted "whole half-up" 2 2
    for (input, expected) in [(1500, 2000), (1499, 1000)] do
      check "wholeSat half-up" ((wholeSat ⟨input⟩).toOption.map (·.msat) == some expected)
  selected only "whole-tiny" do
    counted "whole tiny" 2 2
    check "wholeSat tiny" (match wholeSat ⟨499⟩ with | .error .lessThanOneSat => true | _ => false)
    check "wholeSat zero" ((wholeSat ⟨0⟩).toOption.map (·.msat) == some 0)
  selected only "floor-tiny" do
    counted "floor tiny" 3 3
    check "floorSat tiny" (match floorSat ⟨999⟩ with | .error .lessThanOneSat => true | _ => false)
    check "floorSat zero" ((floorSat ⟨0⟩).toOption.map (·.msat) == some 0)
    check "floorSat value" ((floorSat ⟨1999⟩).toOption.map (·.msat) == some 1000)
  selected only "whole-exact" do
    counted "whole exact" 2 2
    check "exact wholeSat rejects" (match exactWholeSat ⟨1500⟩ with | .error .wholeSatRequired => true | _ => false)
    check "exact wholeSat accepts" ((exactWholeSat ⟨2000⟩).toOption.map (·.msat) == some 2000)
  selected only "fee" do
    let unitless := ["15", "0", "+15", "-0", "+0.5", ".5", " 15 "]
    counted "unitless fee" unitless.length 7
    for input in unitless do
      check "fee unit requirement" (match parseFee input with | .error .feeUnitRequired => true | _ => false)
      let out ← IO.mkRef ""
      let err ← IO.mkRef ""
      let called ← IO.mkRef false
      let services := { productionServices with
        stdout := fun s => out.modify (· ++ s)
        stderr := fun s => err.modify (· ++ s) }
      let status ← runFeeWith services input fun _ => do called.set true; return 0
      check "fee refusal boundary" (status == 1 && (← out.get).isEmpty && !(← called.get) &&
        (← err.get) == Error.feeUnitRequired.message ++ "\n")
    let valid := [("15sats",15000), ("0btc",0), ("+0.5sat",500), ("\u00a0.001SaTs\u00a0",1),
      ("2MSATS",2), ("0.00000000001BTC",1)]
    counted "explicit fee" valid.length 6
    for (input, expected) in valid do
      check "fee exact value" ((parseFee input).toOption.map (·.msat) == some expected)
    counted "invalid explicit fee" 3 3
    for input in ["0.0001sat", "1e3btc", "-1sat"] do
      check "fee amount validity" (parseFee input |>.toOption.isNone)
  selected only "entropy-source" do
    counted "production entropy" 1 1
    let random ← productionServices.entropy 32
    check "entropy production length" (random.size == 32)
end CyberkrillTests
