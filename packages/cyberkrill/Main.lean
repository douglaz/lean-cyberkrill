/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill

def main (args : List String) : IO UInt32 :=
  Cyberkrill.runWith Cyberkrill.version Cyberkrill.productionServices args
