/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Secp256k1
import HttpCurl

def main : IO UInt32 := do
  IO.println (← HttpCurl.version)
  let ok ← Secp256k1.contextRoundTrip
  IO.println s!"secp256k1 context round trip: {ok}"
  return if ok then 0 else 1
