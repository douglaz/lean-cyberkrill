/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import LightningTests.Bolt11
import LightningTests.Lnurl

def main (args : List String) : IO Unit := do
  match args with
  | ["--hash", invoice] =>
    match Bitcoin.Bech32.decode 7089 invoice with
    | .error _ => throw (IO.userError "invalid hash input")
    | .ok (hrp, data, _) =>
      IO.println (Bitcoin.Hex.encode (Lightning.Bolt11.signingHash hrp (data.take (data.length - 104))))
  | [] => do
    LightningTests.Bolt11.run
    LightningTests.Lnurl.run
  | ["--case", name] => LightningTests.Bolt11.run (some name)
  | ["--lnurl-case", name] => LightningTests.Lnurl.run (some name)
  | _ => throw (IO.userError "usage: LightningTests [--case NAME | --hash INVOICE | --lnurl-case NAME]")
