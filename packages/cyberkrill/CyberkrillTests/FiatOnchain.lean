/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Cyberkrill Lean

/-- Several guarded invocations share a process, but never a quote cache. -/
def fiatOnchainRun : IO Unit := do
  let input ← getOk "fiat command batch" (Json.parse (← (← IO.getStdin).readToEnd))
  let rows ← getOk "fiat command rows" input.getArr?
  let mut results := #[]
  for row in rows do
    let bases ← getOk "fiat feed bases" (row.getObjValAs? (Array String) "feeds")
    let rpc ← text row "rpc"
    let args ← getOk "fiat argv" (row.getObjValAs? (List String) "args")
    let clients ← IO.mkRef (0 : Nat)
    let services := { productionServices with coreClient := fun flags => do
      clients.modify (· + 1)
      CoreRpc.Client.ofFlags flags }
    let result ← runWithTestUrls version ⟨bases, bases[0]!, rpc⟩ args (services := services)
    results := results.push (Json.mkObj [("status", toJson result.status.toNat),
      ("stdout", .str result.stdout), ("stderr", .str result.stderr), ("clients", toJson (← clients.get))])
  IO.println (Json.arr results).compress

end CyberkrillTests
