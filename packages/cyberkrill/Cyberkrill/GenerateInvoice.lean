/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.Lightning
import Lightning.Lnurl.Models
import HttpCurl

namespace Cyberkrill.GenerateInvoice
open Lean

private def lnurlError (e : Lightning.LnurlError) : Error :=
  .lightning ((reprStr e).replace "Lightning.LnurlError." "")

/-- reqwest 0.12.28's default policy follows at most ten redirects. Every
hop uses the supplied capability, retaining its guard, TLS checks and bounds. -/
private def getResponse (request : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.Response))
    (url : String) (remaining : Nat) : IO (Except Error HttpCurl.Response) := do
  let req : HttpCurl.Request := {
    url := url
    connectTimeoutMs := 1000
    totalTimeoutMs := 2000
    maxResponseBytes := 1048576 }
  let response ← match ← request req with
    | .error e => return .error (.lightning ("lnurlTransport: " ++ reprStr e))
    | .ok response => pure response
  if [301, 302, 303, 307, 308].contains response.status.toNat then
    if let some (_, location) := response.headers.find? (fun pair => pair.1 == "location") then
      match Lightning.Lnurl.resolveRedirect url location with
      | .error e => return .error (lnurlError e)
      | .ok none => pure ()
      | .ok (some next) =>
        match remaining with
        | 0 => return .error (.lightning "lnurlTransport: redirectLimit")
        | fuel + 1 => return ← getResponse request next fuel
  return .ok response

/-- HTTP status is intentionally not a JSON success condition. -/
private def getJson (request : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.Response))
    (url : String) : IO (Except Error Json) := do
  match ← getResponse request url 10 with
  | .error e => return .error e
  | .ok response => return do
    let some text := String.fromUTF8? response.body | throw (.lightning "malformedResponse: UTF-8")
    (Json.parse text).mapError (fun _ => .lightning "malformedResponse: JSON")

/-- LNURL-pay invoice acquisition only. Invoice validation and JSON use the
ordinary decoder; the provider's range and optional byte limit precede callback IO. -/
def fetch (address : String) (amount : Bitcoin.Amount) (comment : Option String)
    (request := HttpCurl.request) : IO (Except Error Json) := do
  let url ← match Lightning.lightningAddressUrl address >>= Lightning.Lnurl.normalizeUrl with
    | .error e => return .error (lnurlError e)
    | .ok url => pure url
  let response ← match ← getJson request url with
    | .error e => return .error e | .ok j => pure j
  let pay ← match Lightning.LnurlPayRequest.fromJson response with
    | .error e => return .error (lnurlError e) | .ok pay => pure pay
  if amount.msat < pay.minSendable.msat || amount.msat > pay.maxSendable.msat then
    return .error (.lightning s!"Amount {amount.msat} msats is outside allowed range: {pay.minSendable.msat} - {pay.maxSendable.msat} msats")
  if let some text := comment then
    if let some limit := pay.commentAllowed then
      if text.toUTF8.size > limit then
        return .error (.lightning s!"Comment length {text.toUTF8.size} exceeds maximum allowed length: {limit}")
  let callback ← match Lightning.Lnurl.callbackUrl pay.callback amount.msat comment with
    | .error e => return .error (lnurlError e) | .ok url => pure url
  let response ← match ← getJson request callback with
    | .error e => return .error e | .ok j => pure j
  return do
    let result ← (Lightning.LnurlPayCallback.fromJson response).mapError lnurlError
    let decoded ← LightningCli.decodeInvoice result.pr
    let decoded ← (Json.parse decoded).mapError (fun _ => .lightning "malformedResponse: decoded invoice")
    return Json.mkObj [("lightning_address", toJson address), ("amount_msats", toJson amount.msat),
      ("comment", toJson comment), ("invoice", toJson result.pr), ("decoded_invoice", decoded)]

end Cyberkrill.GenerateInvoice
