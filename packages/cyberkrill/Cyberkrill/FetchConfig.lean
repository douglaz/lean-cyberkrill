/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.Invite
import Lightning.Lnurl.Url
import HttpCurl

namespace Cyberkrill.FetchConfig
open Lean

/-- Fetch/decode failures continue guardian iteration. Validation and config
parsing use the outer Error channel and never enter this channel. -/
inductive FetchError where
  | transport (code : String)
  | decode (code : String)

def FetchError.message : FetchError → String
  | .transport code | .decode code => code

private def failure (code : String) : Error := .onchain code

/-- Global replacement precedes trimming, including URL query/path text. Invite
decoding already caps the consensus payload; redirects have a separate bound. -/
def configUrl (url : String) : String :=
  let rewritten := (url.replace "wss://" "https://").replace "ws://" "http://"
  String.ofList (rewritten.toList.reverse.dropWhile (· == '/')).reverse ++ "/config"

private def numberBounded (token : String) : Except FetchError Unit := do
  if token.length > 2048 then throw (.decode "fmJsonTokenLimit")
  let unsigned := if token.startsWith "-" then (token.drop 1).toString else token
  let parts := (unsigned.replace "E" "e").splitOn "e"
  if (parts.head!.replace "." "").length > 1024 then throw (.decode "fmJsonCoefficientLimit")
  let exponent := parts[1]?.getD "0"
  let exponent := if exponent.startsWith "+" || exponent.startsWith "-" then
    (exponent.drop 1).toString else exponent
  let digits := String.ofList (exponent.toList.dropWhile (· == '0'))
  if digits.length > 4 || digits.toNat?.getD 0 > 1024 then throw (.decode "fmJsonExponentLimit")

/-- serde_json::Value rejects numbers that round to infinity. Like the price
preflight, compare against the binary64 overflow midpoint without allocating
large powers for tiny numbers or zero. Lexical bounds have already run. -/
private def finiteNumber (token : String) : Bool := Id.run do
  let unsigned := if token.startsWith "-" then (token.drop 1).toString else token
  let parts := (unsigned.replace "E" "e").splitOn "e"
  let decimals := parts.head!.splitOn "."
  let fraction := decimals[1]?.getD ""
  let coefficient := decimals.head! ++ fraction
  let significant := String.ofList (coefficient.toList.dropWhile (· == '0'))
  if significant.isEmpty then return true
  let raw := parts[1]?.getD "0"
  let digits := String.ofList (raw.toList.dropWhile (fun c => c == '+' || c == '-' || c == '0'))
  let magnitude := digits.toNat?.getD 0
  let exponent : Int := if raw.startsWith "-" then -(magnitude : Int) else magnitude
  let order := (significant.length : Int) - 1 + exponent - fraction.length
  if order < 308 then return true
  if order > 308 then return false
  let power := exponent - (fraction.length : Int)
  let n := significant.toNat?.getD 0
  let midpoint := 2^1024 - 2^970
  return if power ≥ 0 then n * 10^power.toNat < midpoint
    else n < midpoint * 10^power.natAbs

private def hex? (chars : List Char) : Option Nat := do
  if chars.length != 4 then none else do
    let mut n := 0
    for c in chars do
      let d ← if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
        else if 'a' ≤ c.toLower && c.toLower ≤ 'f' then some (c.toLower.toNat - 'a'.toNat + 10)
        else none
      n := 16 * n + d
    return n

/-- Lexical bounds precede all recursive parsing and numeric expansion, even
for fields that the config projection ignores. Escaped quotes stay quoted.
Value deserialization, unlike IgnoredAny, also rejects lone UTF-16 surrogates. -/
private def preflight (body : String) : Except FetchError Unit := do
  let mut rest := body.toList
  let mut quoted := false
  let mut depth := 0
  for _ in [:rest.length] do
    let c :: tail := rest | break
    rest := tail
    if quoted then
      if c == '\\' then
        if rest.head? == some 'u' then
          if let some unit := hex? (rest.drop 1 |>.take 4) then
            if 0xD800 ≤ unit && unit ≤ 0xDBFF then
              let low := rest.drop 5
              unless low.take 2 == ['\\', 'u'] &&
                  ((hex? (low.drop 2 |>.take 4)).any fun n => 0xDC00 ≤ n && n ≤ 0xDFFF) do
                throw (.decode "fmJsonDecode")
              rest := low.drop 6
            else
              if 0xDC00 ≤ unit && unit ≤ 0xDFFF then throw (.decode "fmJsonDecode")
              rest := rest.drop 5
          else rest := rest.drop 1
        else rest := rest.drop 1
      else if c == '"' then quoted := false
    else if c == '"' then quoted := true
    else if c == '-' || ('0' ≤ c && c ≤ '9') then
      let chars := rest.takeWhile (fun ch => "0123456789eE+.-".contains ch)
      rest := rest.drop chars.length
      let token := String.ofList (c :: chars)
      numberBounded token
      unless finiteNumber token do throw (.decode "fmJsonNumberRange")
      if (rest.dropWhile (fun ch => " \t\r\n".contains ch)).head? == some ':' then
        throw (.decode "fmJsonDecode")
    else if c == '[' || c == '{' then
      depth := depth + 1
      if depth ≥ 128 then throw (.decode "fmJsonDepthLimit")
    else if c == ']' || c == '}' then
      depth := depth - 1

private def urlError (e : Lightning.LnurlError) : FetchError :=
  .transport (match e with
    | .unsupportedScheme => "unsupportedScheme"
    | .unsupportedUrlForm _ => "unsupportedUrlForm"
    | _ => "fmInvalidUrl")

private def transportError : HttpCurl.Error → FetchError
  | .tooLarge _ => .transport "fmResponseTooLarge"
  | .timeout _ _ => .transport "fmTimeout"
  | .connect _ _ => .transport "fmConnect"
  | .tls _ _ => .transport "fmTls"
  | .curl _ _ => .transport "fmTransport"

/-- Each hop reaches the supplied capability, so tests guard every destination.
POST switches to GET on 301/302/303, dropping its body and content headers;
307/308 retain them, as in tower-http 0.6.8. -/
private def response (request : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.AcquiredResponse))
    (req : HttpCurl.Request) (remaining : Nat) : IO (Except FetchError HttpCurl.AcquiredResponse) := do
  if req.url.utf8ByteSize > 8192 then return .error (.transport "fmUrlLimit")
  let result ← request req
  let r ← match result with
    | .error e => return .error (transportError e)
    | .ok r => pure r
  if r.body.size > req.maxResponseBytes.toNat then return .error (.transport "fmResponseTooLarge")
  if [301, 302, 303, 307, 308].contains r.status.toNat then
    if let some (_, location) := r.headers.find? (fun h => h.1 == "location") then
      if location.utf8ByteSize > 8192 then return .error (.transport "fmUrlLimit")
      match Lightning.Lnurl.resolveRedirect req.url location with
      | .error e => return .error (urlError e)
      | .ok none => pure ()
      | .ok (some next) =>
        let previous := req.url
        let req := if [301, 302, 303].contains r.status.toNat then
            { req with
              method := .get, body := none
              headers := req.headers.filter (fun h => !["content-type", "content-length",
                "content-encoding", "transfer-encoding"].contains h.1.toLower) }
          else req
        let referer := ((Lightning.Lnurl.normalizeUrl previous).toOption.getD previous).splitOn "#" |>.headD ""
        let req := if previous.startsWith "https://" && next.startsWith "http://" then req else
          { req with headers := (req.headers.filter (fun h => h.1.toLower != "referer")).push ("Referer", referer) }
        match remaining with
        | 0 => return .error (.transport "fmRedirectLimit")
        | n + 1 => return ← response request { req with url := next } n
  return .ok r

private def successful (r : HttpCurl.AcquiredResponse) : Bool := 200 ≤ r.status.toNat && r.status.toNat < 300

private def fromGuardian (request : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.AcquiredResponse))
    (url : String) : IO (Except FetchError Json) := do
  let url ← match Lightning.Lnurl.normalizeUrl url with
    | .error e => return .error (urlError e)
    | .ok url => pure ((url.splitOn "#").headD "")
  let req : HttpCurl.Request := {
    url := url
    connectTimeoutMs := 1000
    totalTimeoutMs := 2000
    maxResponseBytes := 1048576 }
  let get ← response request req 10
  let result ← match get with
    | .ok r => if successful r then pure get else
        response request { req with
          method := .post, body := some "{}".toUTF8
          headers := #[("Content-Type", "application/json")] } 10
    | .error _ => response request { req with
        method := .post, body := some "{}".toUTF8
        headers := #[("Content-Type", "application/json")] } 10
  return do
    let r ← result
    unless successful r do throw (.transport "fmHttpStatus")
    if r.bodyError.isSome then throw (.decode "fmBodyRead")
    let some text := String.fromUTF8? r.body | throw (.decode "fmUtf8Decode")
    preflight text
    (Json.parse text).mapError (fun _ => .decode "fmJsonDecode")

private def field (j : Json) (key : String) : Option Json := (j.getObjVal? key).toOption
private def string (j : Json) (key : String) : Option String := (field j key).bind (·.getStr?.toOption)

private def peer? (text : String) : Option Nat := do
  let digits := if text.startsWith "+" then (text.drop 1).toString else text
  if digits.isEmpty || !digits.toList.all (fun c => '0' ≤ c && c ≤ '9') then none else do
    let significant := digits.toList.dropWhile (· == '0')
    if significant.length > 5 then none else do
      let n := (String.ofList significant).toNat?.getD 0
      if n ≤ 65535 then some n else none

/-- Match the reference's weak existence/id validation before semantic parsing. -/
private def validate (config : Json) (id : String) : Except Error Bool := do
  unless ((field config "global").bind (field · "api_endpoints")).isSome do
    throw (failure "fmMissingApiEndpoints")
  match field config "federation_id" with
  | none => return true
  | some value =>
    let .ok value := value.getStr? | throw (failure "fmFederationIdType")
    unless value == id do throw (failure "fmFederationIdMismatch")
    return false

private def parseConfig (config : Json) (id : String) : Except Error Json := do
  let global := (field config "global").getD .null
  let endpoints := (field global "api_endpoints").getD .null
  let .ok endpoints := endpoints.getObj? | throw (failure "fmInvalidApiEndpoints")
  let metadataValue := (field global "meta").getD .null
  let metadata := metadataValue.getObj?.toOption.map (·.toList) |>.getD []
  let metadata := metadata.filterMap fun (key, value) => value.getStr?.toOption.map (key, ·)
  -- serde_json's default map iterates lexicographically; stable numeric sorting
  -- preserves that order for spellings such as +1, 01 and 1.
  let endpoints := endpoints.toList.mergeSort (fun a b => a.1 ≤ b.1)
  let mut guardians : List (Nat × Json) := []
  for (key, value) in endpoints do
    let some peer := peer? key | throw (failure "fmInvalidPeerId")
    let .ok url := value.getStr? | throw (failure "fmEndpointType")
    let name := string metadataValue s!"guardian_{peer}_name"
    guardians := (peer, Json.mkObj [("peer_id", toJson peer),
      ("name", toJson name), ("url", .str url)]) :: guardians
  guardians := guardians.reverse.mergeSort (fun a b => a.1 ≤ b.1)
  return Json.mkObj [("federation_id", .str id),
    ("federation_name", toJson (string metadataValue "federation_name")),
    ("guardians", toJson (guardians.map (·.2))),
    ("consensus_version", .str ((string global "consensus_version").getD "unknown")),
    ("modules", (field config "modules").getD (Json.mkObj [])),
    ("meta", Json.mkObj (metadata.map fun (k, v) => (k, .str v)))]

def fetch (input : String) (request := HttpCurl.requestDetailed)
    (warn : String → IO Unit := fun _ => pure ()) : IO (Except Error Json) := do
  let invite ← match InviteCli.decode input with
    | .error e => return .error e | .ok invite => pure invite
  let mut last := "fmNoGuardian"
  for guardian in invite.guardians do
    match ← fromGuardian request (configUrl guardian.url) with
    | .error e => last := e.message
    | .ok config =>
      match validate config invite.federationId with
      | .error e => return .error e
      | .ok missing =>
        if missing then warn "Could not verify federation ID from config\n"
        return parseConfig config invite.federationId
  return .error (failure ("fmAllGuardiansFailed: " ++ last))

end Cyberkrill.FetchConfig
