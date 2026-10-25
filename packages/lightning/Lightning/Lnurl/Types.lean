/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bech32Codec
import Bitcoin.Amount

namespace Lightning

inductive UnsupportedUrlForm where
  | userinfo | ipv6 | ipv4Form | idnaRequired
  deriving Repr, BEq, DecidableEq

inductive LnurlError where
  | wrongPrefix
  | wrongHrp
  | bech32 (error : Bitcoin.Bech32.DecodeError)
  | invalidUtf8
  | unsupportedScheme
  | unsupportedUrlForm (reason : UnsupportedUrlForm)
  | missingHost
  | invalidHost
  | invalidPort
  | invalidIpv4
  | malformedAddress
  | malformedResponse (field : String)
  deriving Repr, BEq, DecidableEq

/-- Parsed subset of special URLs. Query pairs have unique decoded keys. -/
structure Lnurl.UrlParts where
  scheme : String
  host : String
  base : String
  query : Option String
  queryParams : List (String × String)
  deriving Repr, BEq, DecidableEq

structure LnurlOutput where
  bech32 : String
  url : String
  host : String
  base : String
  query : Option String
  queryParams : List (String × String)
  deriving Repr, BEq, DecidableEq

structure LnurlPayRequest where
  callback : String
  maxSendable : Bitcoin.Amount
  minSendable : Bitcoin.Amount
  metadata : String
  tag : String
  commentAllowed : Option Nat
  deriving Repr, DecidableEq

structure LnurlPayCallback where
  pr : String
  routes : Option (Array String)
  deriving Repr, BEq, DecidableEq

end Lightning
