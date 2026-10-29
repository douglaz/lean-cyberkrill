/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import FedimintInvite.Codec
import Cyberkrill.InvoiceJson

namespace Cyberkrill.InviteCli
open Lean FedimintInvite

private def failure : Error := .offline "invalidInvite"

/-- The reference's heuristic is deliberately confined to the app. It sees
original payload bytes, only after a valid wrapper and failed consensus parse. -/
def fallback (bytes : ByteArray) : Except Error Invite := do
  let mut guardians := []
  for pos in [:bytes.size] do
    if pos + 6 < bytes.size then
      let marker := bytes.extract pos (pos + 6)
      if marker == "wss://".toUTF8 || marker == "https:".toUTF8 then
        let tail := (bytes.extract (pos + 6) bytes.size).data.toList.takeWhile
          (fun b => b.toNat > 31 && b.toNat < 127)
        if !tail.isEmpty then
          let url := String.fromUTF8! (marker ++ ⟨tail.toArray⟩)
          guardians := guardians ++ [⟨UInt16.ofNat guardians.length, url⟩]
  if guardians.isEmpty then throw failure
  let id := if bytes.size ≥ 64 then bytes.extract (bytes.size - 32) bytes.size
    else bytes.extract 0 (min 32 bytes.size)
  return ⟨Bitcoin.Hex.encode id, guardians, none⟩

def decode (input : String) : Except Error Invite := do
  let symbols ← (decodePayload input).mapError fun _ => failure
  let bytes := Bitcoin.Bech32.fesToBytesLax symbols
  match decodeConsensus bytes with
  | .ok invite => return invite
  | .error _ => fallback bytes

def render (invite : Invite) : String :=
  (Json.mkObj [("federation_id", toJson invite.federationId),
    ("guardians", toJson (invite.guardians.map fun g =>
      Json.mkObj [("peer_id", toJson g.peerId.toNat), ("url", toJson g.url)])),
    ("api_secret", toJson invite.apiSecret)]).pretty

private def jsonResult (value : Except String α) : Except Error α :=
  value.mapError fun _ => .offline "invalidInviteJson"

private def parseJson (input : String) : Except Error Invite := do
  let j ← jsonResult (Json.parse input)
  let _ ← (InvoiceJson.validateInviteSyntax input).mapError fun _ => Error.offline "invalidInviteJson"
  let j ← (InvoiceJson.structObject j ["federation_id", "guardians", "api_secret"]).mapError
    fun _ => Error.offline "invalidInviteJson"
  let id ← jsonResult ((← jsonResult (j.getObjVal? "federation_id")).getStr?)
  let gs ← jsonResult ((← jsonResult (j.getObjVal? "guardians")).getArr?)
  let guardians ← gs.toList.mapM fun g => do
    let g ← (InvoiceJson.structObject g ["peer_id", "url"]).mapError
      fun _ => Error.offline "invalidInviteJson"
    let peer ← jsonResult ((← jsonResult (g.getObjVal? "peer_id")).getNat?)
    if peer ≥ 65536 then throw (Error.offline "invalidInviteJson")
    let url ← jsonResult ((← jsonResult (g.getObjVal? "url")).getStr?)
    return (⟨UInt16.ofNat peer, url⟩ : Guardian)
  let secret ← match j.getObjVal? "api_secret" with
    | .error _ | .ok .null => pure none
    | .ok value => some <$> jsonResult value.getStr?
  return ⟨id, guardians, secret⟩

def encode (input : String) (skipSecret : Bool) : Except Error String := do
  let invite ← parseJson input
  let invite := if skipSecret then { invite with apiSecret := none } else invite
  (FedimintInvite.encode invite).mapError fun _ => failure

end Cyberkrill.InviteCli
