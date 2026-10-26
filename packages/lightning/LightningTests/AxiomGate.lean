/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning
import Lean.Util.CollectAxioms

open Lean Elab Command

namespace LightningTests.AxiomGate

private def namedTheorems : List Name :=
  [``Lightning.Lnurl.bech32_roundTrip,
   ``Lightning.Lnurl.bech32_checksumSound,
   ``Lightning.Bolt11.readNat_writeNat,
   ``Lightning.Bolt11.writeNat_head,
   ``Lightning.Bolt11.integer_writeNat,
   ``Lightning.Bolt11.strictBytes_encode,
   ``Lightning.Bolt11.string_utf8_roundTrip,
   ``Lightning.Bolt11.keptRaw_iff_staysRaw,
   ``Lightning.Bolt11.decodeField_keptRaw,
   ``Lightning.Bolt11.readBytes_writeBytes,
   ``Lightning.Bolt11.decodeHop_encodeHop,
   ``Lightning.Bolt11.route_roundTrip,
   ``Lightning.Bolt11.decodeField_fieldData,
   ``Lightning.Bolt11.decodeFields_encodeFields,
   ``Lightning.Bolt11.parseHrp_encodeHrp,
   ``Lightning.Bolt11.parseHrp_spelling,
   ``Lightning.Bolt11.hrpFromMsat_roundTrip,
   ``Lightning.Bolt11.encodeHrp_properties,
   ``Lightning.Bolt11.checkPrecision_rejects,
   ``Lightning.Bolt11.checkPrecision_accepts,
   ``Lightning.Bolt11.checkPrecision_unavailable,
   ``Lightning.Bolt11.hrpFromMsat_exact,
   ``Lightning.Bolt11.hrpFromMsat_overflow,
   ``Lightning.Bolt11.hrp_amount_canonical,
   ``Lightning.Bolt11.hrp_amount_absent,
   ``Lightning.Bolt11.signingHash_spec,
   ``Lightning.Bolt11.decode_trace,
   ``Lightning.Bolt11.decode_signingHash_spec,
   ``Lightning.Bolt11.decode_signature_check_spec,
   ``Lightning.Bolt11.encode_signingHash_spec,
   ``Lightning.Bolt11.sign_signingHash_spec,
   ``Lightning.Bolt11.invoice_bech32_roundTrip,
   ``Lightning.Bolt11.invoice_checksumSound,
   ``Lightning.Bolt11.readNat_append,
   ``Lightning.Bolt11.writeBytes_size,
   ``Lightning.Bolt11.writeBytes_succ,
   ``Lightning.Bolt11.encodeHop_size,
   ``Lightning.Bolt11.lower_idempotent,
   ``Lightning.Bolt11.encodeData_hrp,
   ``Lightning.Bolt11.encodeHrp_lower,
   ``Lightning.Bolt11.signature_symbols_length,
   ``Lightning.Bolt11.writer_specHash]

private def allowedAxioms : List Name :=
  [``propext, ``Classical.choice, ``Quot.sound]

private def checkAxioms (name : Name) : CommandElabM Unit := do
  for axiomName in ← collectAxioms name do
    unless allowedAxioms.contains axiomName do
      throwError "Lightning axiom gate: {name} reaches disallowed axiom {axiomName}"

elab "#lightning_axiom_gate" : command => do
  let env ← getEnv
  unless namedTheorems.length == 42 do
    throwError "Lightning axiom gate: expected 42 named theorems"
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
  IO.println s!"Lightning axioms: library {libraryCount}/{libraryCount}; named {namedCount}/42; offenders 0/0"

end LightningTests.AxiomGate
