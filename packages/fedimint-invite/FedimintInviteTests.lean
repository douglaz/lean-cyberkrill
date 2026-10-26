/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInviteTests.Runtime
import FedimintInviteTests.AxiomGate

def main (args : List String) : IO UInt32 := do
  IO.println s!"Invite axiom gate: {FedimintInviteTests.auditedTheoremCount} library theorems; 4 named; 0 offenders"
  FedimintInviteTests.run args
