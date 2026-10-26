/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInvite
import Lean.Util.CollectAxioms

open Lean Elab Command
namespace FedimintInviteTests

private def namedTheorems : List Name := [``FedimintInvite.consensus_roundTrip,
  ``FedimintInvite.invite_roundTrip, ``FedimintInvite.bech32m_roundTrip,
  ``FedimintInvite.bech32m_checksumSound]

private def allowedAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

private def checkAxioms (name : Name) : CommandElabM Unit := do
  for axiomName in ← collectAxioms name do
    unless allowedAxioms.contains axiomName do
      throwError "Invite axiom gate: {name} reaches disallowed axiom {axiomName}"

elab "#invite_axiom_gate" : command => do
  let env ← getEnv
  unless namedTheorems.length = 4 do throwError "Invite axiom gate: named count changed"
  for name in namedTheorems do
    unless (env.find? name).any (fun info => info matches .thmInfo _) do
      throwError "Invite axiom gate: missing theorem {name}"
    checkAxioms name
  let mut count := 0
  for (name, info) in env.constants.toList do
    if info matches .thmInfo _ then
      if let some index := env.getModuleIdxFor? name then
        if `FedimintInvite |>.isPrefixOf env.header.moduleNames[index.toNat]! then
          checkAxioms name
          count := count + 1
  unless count ≥ namedTheorems.length do throwError "Invite axiom gate: incomplete library scan"
  logInfo m!"Invite axiom gate: {count} library theorems; 4 named; 0 offenders"
  elabCommand (← `(def $(mkIdent `auditedTheoremCount) : Nat := $(quote count)))

#invite_axiom_gate
#print axioms FedimintInvite.consensus_roundTrip
#print axioms FedimintInvite.invite_roundTrip
#print axioms FedimintInvite.bech32m_roundTrip
#print axioms FedimintInvite.bech32m_checksumSound

end FedimintInviteTests
