/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.App
import Lightning.Lnurl.Url
import Bitcoin.ConvertBits

namespace Cyberkrill

/-- Explicit library parameter only. All slots are required, including the
reserved history and RPC slots; none is read from the release environment. -/
structure TestUrls where
  feedBases : Array String
  coinGeckoHistory : String
  dcaRpc : String

namespace TestUrls

private def encodedMaterial (s : String) : List String := Id.run do
  let mut materials := []
  for startText in ["lnurl1", "fed11"] do
    for tail in (s.toLower.splitOn startText).tail do
      let token := startText ++ String.ofList (tail.toList.takeWhile fun c => Bitcoin.Bech32.charset.contains c)
      if let some (_, data) := Bitcoin.Bech32.extractData token then
        let bytes := Bitcoin.Bech32.fesToBytesLax data
        materials := String.ofList (bytes.data.toList.map fun b => Char.ofNat b.toNat) :: materials
  return materials

private def concealedTarget : Nat → String → Bool
  | 0, _ => true
  | fuel + 1, token => Id.run do
    if token.contains '@' || token.contains '\\' ||
        !token.toList.all (fun c => c.toNat > 32) || (token.splitOn "://").length != 1 then return true
    let .ok bytes := Lightning.Lnurl.percentDecode token true | return true
    let some decoded := String.fromUTF8? bytes | return true
    if decoded != token && concealedTarget fuel decoded then return true
    return (encodedMaterial token).any (concealedTarget fuel)

def permitted (url : String) (allowPathSpace : Bool := false) : Bool := Id.run do
  let .ok parts := Lightning.Lnurl.parseUrl url | return false
  unless parts.host == "127.0.0.1" do return false
  let startText := parts.scheme ++ "://127.0.0.1:"
  unless url.startsWith startText do return false
  let tail := (url.drop startText.length).toString.toList
  let digits := tail.takeWhile (fun c => '0' ≤ c && c ≤ '9')
  let rest := String.ofList (tail.drop digits.length)
  let some port := (String.ofList digits).toNat? | return false
  unless port > 0 && port < 65536 && port != 8332 do return false
  unless rest.isEmpty || rest.startsWith "/" || rest.startsWith "?" || rest.startsWith "#" do return false
  unless url.toList.all (fun c => c.toNat > 32 && c != '\\') do return false
  let mut decoded := rest
  for _ in [:5] do
    if decoded.contains '@' || decoded.contains '\\' ||
        !decoded.toList.all (fun c => c.toNat > 32 || (allowPathSpace && c == ' ')) || (decoded.splitOn "://").length != 1 then return false
    let .ok bytes := Lightning.Lnurl.percentDecode decoded true | return false
    let some next := String.fromUTF8? bytes | return false
    if next == decoded then return !(encodedMaterial decoded).any (concealedTarget 5)
    decoded := next
  -- Exhausting the decoding budget never constitutes validation.
  return false

private def defaultPort (s : String) : Bool :=
  (s.splitOn ":").tail.any fun tail =>
    let digits := tail.toList.takeWhile (fun c => '0' ≤ c && c ≤ '9')
    (String.ofList digits).toNat? == some 8332

private def concealedPort : Nat → String → Bool
  | 0, _ => true
  | fuel + 1, token => Id.run do
    if defaultPort token then return true
    let .ok bytes := Lightning.Lnurl.percentDecode token true | return true
    let some decoded := String.fromUTF8? bytes | return true
    if decoded != token && concealedPort fuel decoded then return true
    return (encodedMaterial token).any (concealedPort fuel)

def forbiddenPort (token : String) : Bool := concealedPort 5 token

def validate (urls : TestUrls) (args : List String) : Except Error Unit := do
  unless urls.feedBases.size == PriceFeed.feeds.size &&
      (urls.feedBases ++ #[urls.coinGeckoHistory, urls.dcaRpc]).all (fun url => permitted url && !forbiddenPort url) do
    throw (.onchain "testUrlRefused: Complete explicit loopback URLs with permitted ports are required")
  if args.any forbiddenPort then throw (.onchain "testArgRefused: Default RPC port is forbidden")
  if args.head? == some "fm-fetch-config" then
    if let .ok (.fetchConfig input _) := parseCommand args then
      if let .ok invite := InviteCli.decode input then
        for guardian in invite.guardians do
          let .ok url := Lightning.Lnurl.normalizeUrl (FetchConfig.configUrl guardian.url)
            | throw (.onchain "testConfigRefused: Explicit loopback guardian is required")
          unless permitted url && !forbiddenPort url do
            throw (.onchain "testConfigRefused: Explicit loopback guardian is required")
  if args.head? == some "ln-generate-invoice" then
    if let .ok (.generateInvoice address _ _ _) := parseCommand args then
      if let .ok raw := Lightning.lightningAddressUrl address then
        match Lightning.Lnurl.normalizeUrl raw with
        | .error _ => throw (.onchain "testLnurlRefused: Explicit loopback Lightning address is required")
        | .ok url =>
          unless permitted url true do throw (.onchain "testLnurlRefused: Explicit loopback Lightning address is required")
  if ["onchain-list-utxos", "onchain-create-psbt", "onchain-create-funded-psbt", "onchain-move-utxos"].contains (args.head?.getD "") then
    let mut found := false
    let mut pending := false
    for token in args.tail do
      if token == "--" then break
      if pending then
        unless permitted token do throw (.onchain "testRpcRefused: Explicit loopback RPC URL is required")
        found := true
        pending := false
      else if token == "--rpc-url" then pending := true
      else if token.startsWith "--rpc-url=" then
        unless permitted (token.drop 10).toString do throw (.onchain "testRpcRefused: Explicit loopback RPC URL is required")
        found := true
    unless found && !pending do throw (.onchain "testRpcRefused: Explicit loopback RPC URL is required")

end TestUrls

structure TestRun where
  status : UInt32
  stdout : String
  stderr : String

/-- Guard every URL and argv before any service action, then use the real app
dispatch and supplied bounded transport. Captured streams stay separate. -/
def runWithTestUrls (version : String) (urls : TestUrls) (args : List String)
    (services : Services := productionServices) (request := HttpCurl.request) : IO TestRun := do
  let out ← IO.mkRef ""
  let err ← IO.mkRef ""
  let services := { services with
    stdout := fun s => out.modify (· ++ s)
    stderr := fun s => err.modify (· ++ s)
    price := fun currency => PriceFeed.fetch currency urls.feedBases request
    configRequest := fun req => do
      unless TestUrls.permitted req.url && !TestUrls.forbiddenPort req.url do
        return .error (.curl 43 "Test config target refused")
      request req
    lnurlRequest := fun req => do
      unless TestUrls.permitted req.url true && !TestUrls.forbiddenPort req.url do
        return .error (.curl 43 "Test LNURL target refused")
      request req }
  let status ← match urls.validate args with
    | .error e => reportError services e
    | .ok _ => runWith version services args
  return ⟨status, ← out.get, ← err.get⟩

end Cyberkrill
