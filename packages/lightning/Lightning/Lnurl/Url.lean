/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Lnurl.Types

namespace Lightning.Lnurl

private def hexDigit (b : UInt8) : Option Nat :=
  if 48 ≤ b && b ≤ 57 then some (b.toNat - 48)
  else if 65 ≤ b && b ≤ 70 then some (b.toNat - 55)
  else if 97 ≤ b && b ≤ 102 then some (b.toNat - 87)
  else none

private def percentBytes (strict : Bool) : List UInt8 → Except LnurlError (List UInt8)
  | [] => .ok []
  | b :: bs => do
    if b == 37 then
      if let a :: c :: rest := bs then
        if let (some hi, some lo) := (hexDigit a, hexDigit c) then
          return UInt8.ofNat (16 * hi + lo) :: (← percentBytes strict rest)
      if strict then throw .invalidHost
    return b :: (← percentBytes strict bs)

/-- One percent-decoding pass; query decoding preserves malformed escapes. -/
def percentDecode (s : String) (strict : Bool := false) : Except LnurlError ByteArray := do
  return ⟨(← percentBytes strict s.toUTF8.data.toList).toArray⟩

/-- Consume the maximal valid prefix of a multibyte sequence on malformed UTF-8. -/
private def continuation (remaining code lo hi : Nat) (bs : List UInt8) : Nat × List UInt8 × Bool :=
  match remaining, bs with
  | 0, _ => (code, bs, true)
  | _ + 1, [] => (code, [], false)
  | n + 1, b :: rest =>
    if lo ≤ b.toNat && b.toNat ≤ hi then
      continuation n (code * 64 + b.toNat - 128) 128 191 rest
    else (code, bs, false)

private def lossyLoop : Nat → List UInt8 → List Char
  | 0, _ => []
  | _ + 1, [] => []
  | fuel + 1, b :: bs =>
    if b < 128 then Char.ofNat b.toNat :: lossyLoop fuel bs
    else
      let (n, code, lo, hi) :=
        if 194 ≤ b && b ≤ 223 then (1, b.toNat - 192, 128, 191)
        else if 224 ≤ b && b ≤ 239 then
          (2, b.toNat - 224, if b == 224 then 160 else 128, if b == 237 then 159 else 191)
        else if 240 ≤ b && b ≤ 244 then
          (3, b.toNat - 240, if b == 240 then 144 else 128, if b == 244 then 143 else 191)
        else (0, 0, 0, 0)
      if n == 0 then '�' :: lossyLoop fuel bs
      else
        let (value, rest, valid) := continuation n code lo hi bs
        (if valid then Char.ofNat value else '�') :: lossyLoop fuel rest

/-- UTF-8 replacement with maximal-subpart consumption, as in form_urlencoded. -/
def lossyUtf8 (bs : ByteArray) : String :=
  String.ofList (lossyLoop bs.size bs.data.toList)

private def formComponent (s : String) : Except LnurlError String := do
  let plus := String.ofList (s.toList.map fun c => if c == '+' then ' ' else c)
  let bytes ← percentDecode plus false
  return lossyUtf8 bytes

/-- Last decoded duplicate wins, including collisions introduced by percent decoding. -/
def queryPairs (s : String) : Except LnurlError (List (String × String)) := do
  let mut result := []
  for piece in s.splitOn "&" do
    if piece.isEmpty then continue
    let chars := piece.toList
    let key ← formComponent (String.ofList (chars.takeWhile (· != '=')))
    let value ← formComponent (String.ofList ((chars.dropWhile (· != '=')).drop 1))
    result := result.filter (fun pair => pair.1 != key) ++ [(key, value)]
  return result

private def escapedByte (b : UInt8) : String :=
  let digits := "0123456789ABCDEF".toList
  String.ofList ['%', digits.getD (b.toNat / 16) '0', digits.getD (b.toNat % 16) '0']

/-- url 2.5.7 SPECIAL_QUERY, applied after separating the raw fragment. -/
def specialQuery (s : String) : String :=
  String.join (s.toUTF8.data.toList.map fun b =>
    if b ≤ 32 || b ≥ 127 || [34, 35, 39, 60, 62].contains b then escapedByte b
    else String.singleton (Char.ofNat b.toNat))

private def asciiDigits (s : String) : Bool :=
  !s.isEmpty && s.toList.all (fun c => '0' ≤ c && c ≤ '9')

private def ipv4Number (s : String) : Bool :=
  if s.isEmpty then false
  else if s.startsWith "0x" || s.startsWith "0X" then
    (s.toList.drop 2).all (fun c => (hexDigit (UInt8.ofNat c.toNat)).isSome)
  else if s.length ≥ 2 && s.startsWith "0" then
    (s.toList.drop 1).all (fun c => '0' ≤ c && c ≤ '7')
  else asciiDigits s

private def endsInNumber (host : String) : Bool :=
  let parts := host.splitOn "."
  let last := if parts.getLast?.getD "" == "" then (parts.dropLast).getLast?.getD ""
    else parts.getLast?.getD ""
  asciiDigits last || ipv4Number last

private def normalizeHost (raw : String) : Except LnurlError String := do
  let bytes ← percentDecode raw
  let some decoded := String.fromUTF8? bytes | throw .invalidHost
  let host := Bitcoin.Bech32.lower decoded
  if host.isEmpty then throw .missingHost
  if host.toList.any (fun c => c.toNat > 127) ||
      (host.splitOn ".").any (·.startsWith "xn--") then
    throw (.unsupportedUrlForm .idnaRequired)
  if host.toList.any (fun c => c.toNat ≤ 32 || c.toNat == 127 ||
      "%#/:<>?@[\\]^|".toList.contains c) then throw .invalidHost
  if endsInNumber host then
    let parts := host.splitOn "."
    if parts.length != 4 || !(parts.all asciiDigits) ||
        parts.any (fun p => p.length > 1 && p.startsWith "0") then
      throw (.unsupportedUrlForm .ipv4Form)
    if parts.any (fun p => p.toNat?.getD 256 > 255) then throw .invalidIpv4
  return host

private def validatePort (port : String) : Except LnurlError Unit := do
  if port.isEmpty then return
  if !asciiDigits port || port.toNat?.getD 65536 > 65535 then throw .invalidPort

/-- Pure HTTP(S) subset parser. The source string is never rewritten in the output. -/
def parseUrl (source : String) : Except LnurlError UrlParts := do
  let endTrimmed := source.toList.dropWhile (fun c => c.toNat ≤ 32)
    |>.reverse.dropWhile (fun c => c.toNat ≤ 32) |>.reverse
  let cleaned := endTrimmed.filter (fun c => c != '\t' && c != '\r' && c != '\n')
  let scheme := Bitcoin.Bech32.lower (String.ofList (cleaned.takeWhile (· != ':')))
  if scheme != "http" && scheme != "https" then throw .unsupportedScheme
  let afterScheme := (cleaned.dropWhile (· != ':')).drop 1
  let afterSlashes := afterScheme.dropWhile (fun c => c == '/' || c == '\\')
  let authority := afterSlashes.takeWhile (fun c => c != '/' && c != '\\' && c != '?' && c != '#')
  let rest := afterSlashes.drop authority.length
  if authority.contains '@' then throw (.unsupportedUrlForm .userinfo)
  if authority.head? == some '[' then throw (.unsupportedUrlForm .ipv6)
  let hostChars := authority.takeWhile (· != ':')
  let portChars := authority.drop hostChars.length
  if !portChars.isEmpty then validatePort (String.ofList (portChars.drop 1))
  let host ← normalizeHost (String.ofList hostChars)
  let beforeFragment := rest.takeWhile (· != '#')
  let queryStart := beforeFragment.dropWhile (· != '?')
  let query := if queryStart.isEmpty then none else some (specialQuery (String.ofList (queryStart.drop 1)))
  let pairs ← match query with | none => pure [] | some q => queryPairs q
  return ⟨scheme, host, scheme ++ "://" ++ host ++ "/", query, pairs⟩

end Lightning.Lnurl
