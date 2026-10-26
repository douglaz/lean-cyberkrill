/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Lnurl.Url
import Bitcoin.ConvertBits

namespace Lightning

/-- Rust str::trim's Unicode White_Space set, independent of ASCII URL cleanup. -/
def Lnurl.whiteSpace (c : Char) : Bool :=
  let n := c.toNat
  (9 ≤ n && n ≤ 13) || n == 32 || n == 133 || n == 160 || n == 5760 ||
    (8192 ≤ n && n ≤ 8202) || [8232, 8233, 8239, 8287, 12288].contains n

def Lnurl.trimInput (s : String) : String :=
  String.ofList (s.toList.dropWhile Lnurl.whiteSpace |>.reverse.dropWhile Lnurl.whiteSpace |>.reverse)

def decodeLnurl (input : String) : Except LnurlError LnurlOutput := do
  let text := Lnurl.trimInput input
  if !(Bitcoin.Bech32.lower text).startsWith "lnurl" then throw .wrongPrefix
  let (hrp, data, _variant) ← (Bitcoin.Bech32.decode 1023 text).mapError .bech32
  if hrp != "lnurl" then throw .wrongHrp
  let bytes := Bitcoin.Bech32.fesToBytesLax data
  let some url := String.fromUTF8? bytes | throw .invalidUtf8
  let parts ← Lnurl.parseUrl url
  return ⟨text, url, parts.host, parts.base, parts.query, parts.queryParams⟩

/-- Literal LUD-16 construction; intentionally no trimming, escaping or URL validation. -/
def lightningAddressUrl (address : String) : Except LnurlError String := do
  let parts := address.splitOn "@"
  if parts.length != 2 then throw .malformedAddress
  let user := parts[0]?.getD ""
  let domain := parts[1]?.getD ""
  if user.isEmpty || domain.isEmpty then throw .malformedAddress
  return "https://" ++ domain ++ "/.well-known/lnurlp/" ++ user

end Lightning
