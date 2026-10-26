/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInvite.Consensus
import Bitcoin.ConvertBits

namespace FedimintInvite

/-- Rust's Unicode White_Space property, used only at the outer boundary. -/
def whiteSpace (c : Char) : Bool :=
  let n := c.toNat
  (9 ≤ n && n ≤ 13) || n == 32 || n == 133 || n == 160 || n == 5760 ||
    (8192 ≤ n && n ≤ 8202) || [8232, 8233, 8239, 8287, 12288].contains n

def trimInput (s : String) : String :=
  String.ofList (s.toList.dropWhile whiteSpace |>.reverse.dropWhile whiteSpace |>.reverse)

/-- Validate the original checksum before regrouping, retaining raw payload symbols. -/
def decodePayload (input : String) : Except Error (List Bitcoin.Bech32.Symbol) := do
  let text := trimInput input
  if text.toList.take 4 ≠ "fed1".toList then .error .prefix
  else do
    let (hrp, data, variant) ← (Bitcoin.Bech32.decode 1023 text).mapError .bech32
    if hrp ≠ "fed1" then .error (.wrongHrp hrp)
    else if variant ≠ .bech32m then .error .wrongVariant
    else .ok data

def decode (input : String) : Except Error Invite := do
  let data ← decodePayload input
  decodeConsensus (Bitcoin.Bech32.fesToBytesLax data)

def encode (inv : Invite) : Except Error String := do
  let bytes ← encodeConsensus inv
  let data := Bitcoin.Bech32.convertbits8to5 bytes
  let length := 4 + 1 + data.length + 6
  if length > 1023 then throw (.tooLong length)
  return Bitcoin.Bech32.encode "fed1" data .bech32m

end FedimintInvite
