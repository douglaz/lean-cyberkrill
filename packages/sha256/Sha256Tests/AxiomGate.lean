/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Sha256
import Lean
import Lean.Util.CollectAxioms

/-! An elaboration-time allowlist over every theorem in the library's modules.
The executable imports this module, so audit failures fail `lake test`. -/

open Lean Elab Command

namespace Sha256Tests

private def namedTheorems : List Name :=
  [``Sha256.sha256_spec, ``Sha256.sha256_impl, ``Sha256.sha256_ofList,
   ``Sha256.Bridge.sha256_bridge, ``Sha256.Fast.sha256_eq_impl,
   ``Sha256.Fast.size_sha256,
   ``Sha256.hash_spec, ``Sha256.hash_size, ``Sha256.sha256d_spec, ``Sha256.sha256d_size]

private def allowedAxioms : List Name :=
  [``propext, ``Classical.choice, ``Quot.sound]

private def checkAxioms (name : Name) : CommandElabM Unit := do
  for axiomName in ← collectAxioms name do
    unless allowedAxioms.contains axiomName do
      throwError "SHA-256 axiom gate: {name} reaches disallowed axiom {axiomName}"

elab "#sha256_axiom_gate" : command => do
  let env ← getEnv
  -- Audit these first so a failure identifies the public trust path.
  for name in namedTheorems do
    unless (env.find? name).any (fun info => info matches .thmInfo _) do
      throwError "SHA-256 axiom gate: missing theorem {name}"
    checkAxioms name
  let mut count := 0
  for (name, info) in env.constants.toList do
    if info matches .thmInfo _ then
      if let some index := env.getModuleIdxFor? name then
        if `Sha256 |>.isPrefixOf env.header.moduleNames[index.toNat]! then
          checkAxioms name
          count := count + 1
  unless count ≥ namedTheorems.length do
    throwError "SHA-256 axiom gate: incomplete library scan"
  elabCommand (← `(def $(mkIdent `auditedTheoremCount) : Nat := $(quote count)))

#sha256_axiom_gate

#print axioms Sha256.sha256_spec
#print axioms Sha256.sha256_impl
#print axioms Sha256.sha256_ofList
#print axioms Sha256.Bridge.sha256_bridge
#print axioms Sha256.Fast.sha256_eq_impl
#print axioms Sha256.Fast.size_sha256
#print axioms Sha256.hash_spec
#print axioms Sha256.hash_size
#print axioms Sha256.sha256d_spec
#print axioms Sha256.sha256d_size

end Sha256Tests
