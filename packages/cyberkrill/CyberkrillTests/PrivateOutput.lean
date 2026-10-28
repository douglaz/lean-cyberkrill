/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Cyberkrill Lean

/-- Exercise the production writer using published entropy, without printing a phrase. -/
def privateOutput (path : String) (nul : Bool := false) : IO Unit := do
  let rows ← getOk "private output fixture" ((← load "../bitcoin/test-data/bip39-english-vectors.json").getArr?)
  let entropy ← bytes rows[0]! "entropy"
  let (status, out, err) ← runCase { productionServices with entropy := fun _ => pure entropy }
    ["generate-mnemonic", "-w", "12", "-o", if nul then path ++ String.singleton (Char.ofNat 0) ++ "suffix" else path]
  IO.println (Json.mkObj [("status", toJson status.toNat),
    ("stdout_empty", toJson out.isEmpty), ("stderr", toJson err)]).compress

end CyberkrillTests
