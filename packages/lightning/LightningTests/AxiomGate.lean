/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning
import Lean.Util.CollectAxioms

open Lean Elab Command

namespace LightningTests.AxiomGate

private def namedTheorems : List Name :=
  [``Lightning.Lnurl.bech32_roundTrip, ``Lightning.Lnurl.bech32_checksumSound]

private def allowedAxioms : List Name :=
  [``propext, ``Classical.choice, ``Quot.sound]

private def checkAxioms (name : Name) : CommandElabM Unit := do
  for axiomName in ← collectAxioms name do
    unless allowedAxioms.contains axiomName do
      throwError "Lightning axiom gate: {name} reaches disallowed axiom {axiomName}"

elab "#lightning_axiom_gate" : command => do
  let env ← getEnv
  unless namedTheorems.length == 2 do
    throwError "Lightning axiom gate: expected two named theorems"
  for name in namedTheorems do
    unless (env.find? name).any (fun info => info matches .thmInfo _) do
      throwError "Lightning axiom gate: missing theorem {name}"
    checkAxioms name
  let mut count := 0
  for (name, info) in env.constants.toList do
    if info matches .thmInfo _ then
      if let some index := env.getModuleIdxFor? name then
        if `Lightning |>.isPrefixOf env.header.moduleNames[index.toNat]! then
          checkAxioms name
          count := count + 1
  unless count ≥ namedTheorems.length do
    throwError "Lightning axiom gate: incomplete library scan"
  elabCommand (← `(def $(mkIdent `libraryCount) : Nat := $(quote count)))
  elabCommand (← `(def $(mkIdent `namedCount) : Nat := $(quote namedTheorems.length)))

#lightning_axiom_gate

def run : IO Unit :=
  IO.println s!"Lightning axioms: library {libraryCount}/{libraryCount}; named {namedCount}/2; offenders 0/0"

end LightningTests.AxiomGate
