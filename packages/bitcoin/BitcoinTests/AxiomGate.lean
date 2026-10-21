/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Lean.Util.CollectAxioms

open Lean Elab Command

namespace BitcoinTests

def namedTheorems : List Name :=
  [``Bitcoin.Hex.decode_encode,
   ``Bitcoin.CompactSize.readCompactSize_compactSize, ``Bitcoin.CompactSize.readCompactSize_ok,
   ``Bitcoin.CompactSize.reject_fd, ``Bitcoin.CompactSize.reject_fe, ``Bitcoin.CompactSize.reject_ff,
   ``Bitcoin.CompactSize.truncated_empty, ``Bitcoin.CompactSize.truncated_tag,
   ``Bitcoin.Amount.ofDecimal_iff, ``Bitcoin.Amount.ofJsonNumber_iff,
   ``Bitcoin.Amount.ofDecimal_submsat,
   ``Bitcoin.Amount.parseBtc_submsat, ``Bitcoin.Amount.parseSats_submsat,
   ``Bitcoin.Amount.parseBtc_exact, ``Bitcoin.Amount.parseSats_exact,
   ``Bitcoin.Amount.parseBtc_printBtc, ``Bitcoin.Amount.parseSats_printSats,
   ``Bitcoin.Amount.parseMsat_printMsat,
   ``Bitcoin.Amount.ofSats_msat, ``Bitcoin.Amount.toSats_iff,
   ``Bitcoin.Amount.toSats_ofSats, ``Bitcoin.Amount.ofBtc_toBtc,
   ``Bitcoin.Amount.toBtc_exact, ``Bitcoin.Amount.ofSatDecimal_toSatDecimal,
   ``Bitcoin.Amount.ofMsatDecimal_toMsatDecimal, ``Bitcoin.Amount.toMsat_ofMsat]

private def allowedAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

private def checkAxioms (name : Name) : CommandElabM Unit := do
  for axiomName in ← collectAxioms name do
    unless allowedAxioms.contains axiomName do
      throwError "Bitcoin axiom gate: {name} reaches disallowed axiom {axiomName}"

elab "#bitcoin_axiom_gate" : command => do
  let env ← getEnv
  for name in namedTheorems do
    unless (env.find? name).any (fun info => info matches .thmInfo _) do
      throwError "Bitcoin axiom gate: missing theorem {name}"
    checkAxioms name
  let mut count := 0
  for (name, info) in env.constants.toList do
    if info matches .thmInfo _ then
      if let some index := env.getModuleIdxFor? name then
        if `Bitcoin |>.isPrefixOf env.header.moduleNames[index.toNat]! then
          checkAxioms name
          count := count + 1
  unless count ≥ namedTheorems.length do
    throwError "Bitcoin axiom gate: incomplete library scan"
  logInfo m!"Bitcoin axiom gate: {count} library theorems; {namedTheorems.length} named; 0 offenders"
  elabCommand (← `(def $(mkIdent `auditedTheoremCount) : Nat := $(quote count)))

#bitcoin_axiom_gate

#print axioms Bitcoin.Hex.decode_encode
#print axioms Bitcoin.CompactSize.readCompactSize_compactSize
#print axioms Bitcoin.CompactSize.readCompactSize_ok
#print axioms Bitcoin.CompactSize.reject_fd
#print axioms Bitcoin.CompactSize.reject_fe
#print axioms Bitcoin.CompactSize.reject_ff
#print axioms Bitcoin.CompactSize.truncated_empty
#print axioms Bitcoin.CompactSize.truncated_tag
#print axioms Bitcoin.Amount.ofDecimal_iff
#print axioms Bitcoin.Amount.ofJsonNumber_iff
#print axioms Bitcoin.Amount.ofDecimal_submsat
#print axioms Bitcoin.Amount.parseBtc_submsat
#print axioms Bitcoin.Amount.parseSats_submsat
#print axioms Bitcoin.Amount.parseBtc_exact
#print axioms Bitcoin.Amount.parseSats_exact
#print axioms Bitcoin.Amount.parseBtc_printBtc
#print axioms Bitcoin.Amount.parseSats_printSats
#print axioms Bitcoin.Amount.parseMsat_printMsat
#print axioms Bitcoin.Amount.ofSats_msat
#print axioms Bitcoin.Amount.toSats_iff
#print axioms Bitcoin.Amount.toSats_ofSats
#print axioms Bitcoin.Amount.ofBtc_toBtc
#print axioms Bitcoin.Amount.toBtc_exact
#print axioms Bitcoin.Amount.ofSatDecimal_toSatDecimal
#print axioms Bitcoin.Amount.ofMsatDecimal_toMsatDecimal
#print axioms Bitcoin.Amount.toMsat_ofMsat

end BitcoinTests
