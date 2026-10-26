/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Bolt11.Codec

open Lightning.Bolt11

-- This executable is used only while the named production mutation is present.
-- It imports the executable codec without importing the theorem it falsifies.
private def cap : Curve := {
  recover := fun _ _ _ => some ByteArray.empty
  verify := fun _ _ _ => true
  sign := fun _ => none
  isValidPubkey := fun _ => true }

private def fields : List Field := [
  .paymentHash ⟨Array.replicate 32 0⟩, .paymentSecret ⟨Array.replicate 32 0⟩,
  .description "", .features (2^14)]

private def require (label : String) (ok : Bool) : IO Unit := do
  unless ok do throw (IO.userError ("counterexample failed: " ++ label))

def main (args : List String) : IO Unit := do
  match args with
  | ["signature-boundary"] =>
    let signed := List.replicate 7 0 ++ encodeFields (fields ++ [.raw 2 [0]])
    let data := signed ++ List.replicate 103 0
    let text := Bitcoin.Bech32.encode "lnbc" data .bech32
    let .ok inv := decode cap text | throw (IO.userError "shifted decoder must succeed")
    require "shifted hash differs from trace" (inv.signingHash !=
      signingHash "lnbc" (data.take (data.length - 104)))
    IO.println "signature-boundary: successful decode; trace hash equality false"
  | ["length-7090"] =>
    let initial := List.replicate 7 0 ++
      encodeFields (fields ++ List.replicate 6 (.raw 2 (List.replicate 1023 0)))
    let filler := 7090 - 4 - 7 - 104 - initial.length - 3
    let data := initial ++ encodeFields [.raw 2 (List.replicate filler 0)] ++ List.replicate 104 0
    let text := Bitcoin.Bech32.encode "lnbc" data .bech32
    require "exactly 7090 characters" (text.length == 7090)
    require "mutated decode succeeds" (decode cap text).isOk
    require "7089 parse fails" (match Bitcoin.Bech32.decode 7089 text with
      | .error .tooLong => true | _ => false)
    IO.println "length-7090: successful decode; required 7089 source parse fails"
  | _ => throw (IO.userError "expected a supported proof counterexample")
