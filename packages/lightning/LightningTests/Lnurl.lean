/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning
import LightningTests.AxiomGate

namespace LightningTests.Lnurl
open Lightning

private def check (label : String) (ok : Bool) : IO Unit :=
  unless ok do throw (IO.userError s!"assertion failed: {label}")

private def getOk {ε α : Type} (label : String) (value : Except ε α) : IO α :=
  match value with
  | .ok v => pure v
  | .error _ => throw (IO.userError s!"assertion failed: {label}")

private def text (j : Lean.Json) (field : String) : IO String :=
  getOk s!"fixture field {field}" (j.getObjValAs? String field)

private def errorName : LnurlError → String
  | .wrongPrefix => "wrongPrefix"
  | .wrongHrp => "wrongHrp"
  | .bech32 e => "bech32:" ++ match e with
    | .tooLong => "tooLong" | .mixedCase => "mixedCase" | .missingSeparator => "missingSeparator"
    | .emptyHrp => "emptyHrp" | .hrpTooLong => "hrpTooLong" | .invalidHrp => "invalidHrp"
    | .invalidCharacter => "invalidCharacter" | .shortChecksum => "shortChecksum"
    | .checksumMismatch => "checksumMismatch"
  | .invalidUtf8 => "invalidUtf8"
  | .unsupportedScheme => "unsupportedScheme"
  | .unsupportedUrlForm r => "unsupportedUrlForm:" ++ match r with
    | .userinfo => "userinfo" | .ipv6 => "ipv6" | .ipv4Form => "ipv4Form" | .idnaRequired => "idnaRequired"
  | .missingHost => "missingHost"
  | .invalidHost => "invalidHost"
  | .invalidPort => "invalidPort"
  | .invalidIpv4 => "invalidIpv4"
  | .malformedAddress => "malformedAddress"
  | .malformedResponse f => "malformedResponse:" ++ f

private def expectError {α : Type} (label expected : String) (actual : Except LnurlError α) : IO Unit :=
  check label (match actual with | .error e => errorName e == expected | .ok _ => false)

private def urlCase (row : Lean.Json) (label : String) : IO Unit := do
  let input ← text row "input"
  -- Also pin the exact decoded source for URL errors and refusals.
  if let some source := (row.getObjValAs? String "url").toOption then
    let encoded := (row.getObjValAs? String "bech32").toOption.getD input
    let (_, symbols, _) ← getOk (label ++ " source codec") (Bitcoin.Bech32.decode 1024 encoded)
    check (label ++ " source") (String.fromUTF8? (Bitcoin.Bech32.fesToBytesLax symbols) == some source)
  if let some err := (row.getObjValAs? String "error").toOption then
    let actual := decodeLnurl input
    if actual.isOk then IO.println s!"unexpected success: {label}"
    expectError label err actual
  else
    let out ← getOk label (decodeLnurl input)
    check (label ++ " bech32") (out.bech32 == (← text row "bech32"))
    check (label ++ " url") (out.url == (← text row "url"))
    check (label ++ " host") (out.host == (← text row "host"))
    check (label ++ " base") (out.base == (← text row "base"))
    let query ← getOk label (row.getObjValAs? (Option String) "query")
    check (label ++ " query") (out.query == query)
    let pairs ← getOk label (row.getObjValAs? (Array (Array String)) "pairs")
    check (label ++ " pairs count") (out.queryParams.length == pairs.size)
    for pair in pairs do
      check (label ++ " pairs " ++ pair[0]!) (out.queryParams.lookup pair[0]! == some pair[1]!)

private def addressCase (row : Lean.Json) (label : String) : IO Unit := do
  let actual := lightningAddressUrl (← text row "input")
  if let some err := (row.getObjValAs? String "error").toOption then expectError label err actual
  else check label (actual.toOption == some (← text row "output"))

private def requestCase (row : Lean.Json) (label : String) : IO Unit := do
  let parsed ← getOk label (Lean.Json.parse (← text row "input"))
  let actual := LnurlPayRequest.fromJson parsed
  if let some err := (row.getObjValAs? String "error").toOption then expectError label err actual
  else
    let out ← getOk label actual
    let expected ← getOk label (row.getObjVal? "expected")
    let nat (field : String) : IO Nat := getOk label (expected.getObjValAs? Nat field)
    check (label ++ " callback") (out.callback == (← text expected "callback"))
    check (label ++ " maxSendable") (out.maxSendable.msat == (← nat "maxSendable"))
    check (label ++ " minSendable") (out.minSendable.msat == (← nat "minSendable"))
    check (label ++ " metadata") (out.metadata == (← text expected "metadata"))
    check (label ++ " tag") (out.tag == (← text expected "tag"))
    check (label ++ " commentAllowed") (out.commentAllowed ==
      ((expected.getObjValAs? (Option Nat) "commentAllowed").toOption.getD none))

private def callbackCase (row : Lean.Json) (label : String) : IO Unit := do
  let parsed ← getOk label (Lean.Json.parse (← text row "input"))
  let actual := LnurlPayCallback.fromJson parsed
  if let some err := (row.getObjValAs? String "error").toOption then expectError label err actual
  else
    let out ← getOk label actual
    let expected ← getOk label (row.getObjVal? "expected")
    check (label ++ " pr") (out.pr == (← text expected "pr"))
    check (label ++ " routes") (out.routes ==
      ((expected.getObjValAs? (Option (Array String)) "routes").toOption.getD none))

/-- Measured syntax losses at the Lean.Json boundary, kept as executable assertions. -/
def measurements : IO Unit := do
  IO.println "Lean.Json measurements: Lean 4.35.0; Lean.Json.parse; exponent stores decimal scale"
  let cases : Array (String × Int × Nat × Bool) := #[
    ("1.0", 10, 1, false), ("1e3", 1000, 0, true), ("1e0", 1, 0, true),
    ("1.0e1", 10, 0, true), ("1.5", 15, 1, false), ("-0", 0, 0, true)]
  check "JSON measurements count" (cases.size == 6)
  for (raw, mantissa, exponent, accepted) in cases do
    let source := "{\"callback\":\"literal\",\"metadata\":\"literal\",\"tag\":\"literal\",\"minSendable\":0,\"maxSendable\":" ++ raw ++ "}"
    let parsed ← getOk "measurement parse" (Lean.Json.parse source)
    let .num n ← getOk "measurement field" (parsed.getObjVal? "maxSendable")
      | throw (IO.userError "measurement is not a number")
    check ("JSON measurement " ++ raw) (n.mantissa == mantissa && n.exponent == exponent &&
      (LnurlPayRequest.fromJson parsed).isOk == accepted)
    IO.println s!"input={source}; maxSendable=num(mantissa={n.mantissa}, exponent={n.exponent}); accepted={accepted}"
  let duplicate := "{\"callback\":\"literal\",\"metadata\":\"literal\",\"tag\":\"literal\",\"minSendable\":0,\"maxSendable\":1,\"maxSendable\":2}"
  let parsed ← getOk "duplicate parse" (Lean.Json.parse duplicate)
  let out ← getOk "duplicate model" (LnurlPayRequest.fromJson parsed)
  check "JSON duplicate surviving value" (out.maxSendable.msat == 2)
  IO.println s!"input={duplicate}; representation={parsed.compress}; accepted=true; surviving maxSendable={out.maxSendable.msat}"
  IO.println "JSON measurements: 7/7"

def run (selector : Option String := none) : IO Unit := do
  let json ← getOk "LNURL fixture JSON" (Lean.Json.parse (← IO.FS.readFile "test-data/lnurl.json"))
  let reference ← getOk "reference JSON" (Lean.Json.parse (← IO.FS.readFile "test-data/lnurl-reference.json"))
  for (set, count) in [("url-supported", 35), ("url-refusal", 13), ("url-error", 23),
      ("lnurl-positive", 8), ("lnurl-negative", 12), ("address", 11),
      ("json-request", 43), ("json-callback", 16), ("lnurl-reference", 1)] do
    let rows ← if set == "lnurl-reference" then getOk set reference.getArr?
      else getOk set (json.getObjValAs? (Array Lean.Json) set)
    check (set ++ " count") (rows.size == count)
    let mut executed := 0
    for row in rows do
      let name ← text row "name"
      if selector.isSome && selector != some set && selector != some (set ++ ":" ++ name) then continue
      executed := executed + 1
      let label := set ++ " " ++ name
      if set == "address" then addressCase row label
      else if set == "json-request" then requestCase row label
      else if set == "json-callback" then callbackCase row label
      else urlCase row label
    if executed > 0 then IO.println s!"{set}: {executed}/{count}"
  if selector.isNone || selector == some "reference-shape" then
    let rows ← getOk "reference shape rows" reference.getArr?
    check "reference shape row count" (rows.size == 1)
    let input ← text rows[0]! "input"
    let (hrp, data, _) ← getOk "reference shape codec" (Bitcoin.Bech32.decode 1023 input)
    let properties : Array (String × Bool) := #[
      ("characters", input.length == 73), ("hrp", hrp == "lnurl"),
      ("payload symbols", data.length == 61), ("checksum symbols", input.length - 6 - data.length == 6),
      ("payload bits", data.length * 5 == 305),
      ("bytes", (Bitcoin.Bech32.fesToBytesLax data).size == 38),
      ("dropped bits", data.length * 5 % 8 == 1)]
    check "reference shape count" (properties.size == 7)
    for (name, ok) in properties do check ("reference shape " ++ name) ok
    IO.println "reference shape: 7/7"
  if selector.isNone || selector == some "json-measurements" then measurements
  if selector.isNone then LightningTests.AxiomGate.run

end LightningTests.Lnurl
