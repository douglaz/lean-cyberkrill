/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning
import Bitcoin.Hex
import Lean.Data.Json

namespace LightningTests.Bolt11
open Lightning.Bolt11

def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw (IO.userError s!"assertion failed: {name}")

private def getOk {ε α : Type} (name : String) (value : Except ε α) : IO α :=
  match value with
  | .ok result => pure result
  | .error _ => throw (IO.userError s!"assertion failed: {name}")

private def text (row : Lean.Json) (key : String) : IO String :=
  getOk s!"JSON field {key}" (row.getObjValAs? String key)

private def hex (s : String) : IO ByteArray := do
  let some bytes := Bitcoin.Hex.decode s | throw (IO.userError "invalid fixture hex")
  return bytes

private def hexField (row : Lean.Json) (key : String) : IO ByteArray := do
  hex (← text row key)

private def rows (json : Lean.Json) (set : String) (count : Nat) : IO (Array Lean.Json) := do
  let result ← getOk s!"JSON set {set}" (json.getObjValAs? (Array Lean.Json) set)
  check s!"{set} count" (result.size == count)
  return result

private structure Entry where
  hash : ByteArray
  signature : ByteArray
  key : ByteArray
  deriving BEq

private def lowS (signature : ByteArray) : Bool :=
  readBytes (signature.extract 32 64) ≤ curveOrder / 2

private def capability (json : Lean.Json) : IO Curve := do
  let table ← rows json "table" 23
  let entries ← table.mapM fun row => do
    return Entry.mk (← hexField row "hash") (← hexField row "signature") (← hexField row "pubkey")
  let pairs := entries.toList.map fun e => (e.hash, e.signature)
  check "table distinct pairs" (pairs.eraseDups.length == 22)
  let keyStrings ← getOk "JSON keys" (json.getObjValAs? (Array String) "keys")
  check "accepted keys count" (keyStrings.size == 4)
  let keys ← keyStrings.mapM hex
  IO.println "capability rows: 23/23; distinct pairs: 22/22; accepted keys: 4/4"
  return {
    recover := fun hash compact recid =>
      (entries.find? fun entry => entry.hash == hash &&
        entry.signature == compact.push recid).map (·.key)
    verify := fun hash compact key => lowS compact && entries.any fun entry =>
      entry.hash == hash && entry.signature.extract 0 64 == compact && entry.key == key
    sign := fun hash => (entries.find? fun entry => entry.hash == hash && lowS entry.signature).map (·.signature)
    isValidPubkey := fun key => keys.contains key }

private def expectedError (row : Lean.Json) : IO Error := do
  let tag := BitVec.ofNat 5 ((row.getObjValAs? Nat "tag").toOption.getD 0)
  match ← text row "error" with
  | "missingSeparator" => return .bech32 .missingSeparator
  | "mixedCase" => return .bech32 .mixedCase
  | "hrpTooLong" => return .bech32 .hrpTooLong
  | "tooLong" => return .bech32 .tooLong
  | "badChecksum" => return .badChecksum
  | "tooShortDataPart" => return .tooShortDataPart
  | "malformedHrp" => return .malformedHrp
  | "unknownCurrency" => return .unknownCurrency
  | "unknownSiPrefix" => return .unknownSiPrefix
  | "invalidAmount" => return .invalidAmount
  | "unexpectedEndOfTaggedFields" => return .unexpectedEndOfTaggedFields
  | "malformedField" => return .malformedField tag
  | "nonCanonicalPadding" => return .nonCanonicalPadding tag
  | "leadingZero" => return .leadingZero tag
  | "malformedSignature" => return .malformedSignature
  | "noPaymentHash" => return .noPaymentHash
  | "multiplePaymentHashes" => return .multiplePaymentHashes
  | "noDescription" => return .noDescription
  | "multipleDescriptions" => return .multipleDescriptions
  | "noPaymentSecret" => return .noPaymentSecret
  | "multiplePaymentSecrets" => return .multiplePaymentSecrets
  | "invalidFeatures" => return .invalidFeatures
  | "unknownRequiredFeatures" => return .unknownRequiredFeatures
  | "verifyFailed" => return .verifyFailed
  | "recoveryFailed" => return .recoveryFailed
  | "impreciseAmount" => return .impreciseAmount
  | other => throw (IO.userError s!"unknown fixture error {other}")

private def selected (selector : Option String) (set name : String) : Bool :=
  selector.isNone || selector == some set || selector == some (set ++ ":" ++ name)

private def decoded (cap : Curve) (row : Lean.Json) (label : String) : IO Invoice := do
  getOk label (decode cap (← text row "invoice"))

private def rejected (cap : Curve) (row : Lean.Json) (label : String) : IO Unit := do
  let expected ← expectedError row
  let actual := decode cap (← text row "invoice")
  check label (match actual with | .error error => error == expected | .ok _ => false)

private def accepted (cap : Curve) (row : Lean.Json) (label : String) : IO Invoice := do
  let inv ← decoded cap row label
  check s!"{label} independent digest" (inv.signingHash == (← hexField row "hash"))
  check s!"{label} payee" (inv.payeeKey == (← hexField row "pubkey"))
  return inv

private def find (json : Lean.Json) (set : String) (count : Nat) (name : String) : IO Lean.Json := do
  let all ← rows json set count
  let some row := all.find? fun row => (row.getObjValAs? String "name").toOption == some name |
    throw (IO.userError s!"missing fixture {name}")
  return row

private def checkCases (name : String) (count : Nat) (cases : Array (String × Bool)) : IO Unit := do
  check s!"{name} count" (cases.size == count)
  for (label, ok) in cases do check s!"{name} {label}" ok
  IO.println s!"{name}: {count}/{count}"

private def literals (cap : Curve) (json : Lean.Json) : IO Unit := do
  let valid ← rows json "valid" 16
  let amounts : Array (Option Nat) := #[none, some 250000000, some 250000000,
    some 2000000000, some 2000000000, some 2000000000, some 2000000000,
    some 2000000000, some 2000000000, some 2000000000, some 967878534,
    some 2500000000, some 2500000000, some 2500000000, some 1000000000, none]
  check "amount literals count" (amounts.size == 16)
  for i in [:valid.size] do
    let inv ← decoded cap valid[i]! s!"amount literal {i} decode"
    check s!"amount literal {i}" ((inv.hrp.amount.map (·.msat)) == amounts[i]!)
  IO.println "amount literals: 16/16"
  let addresses : Array (String × String) := #[
    ("L491", "mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP"),
    ("L516", "1RustyRX2oai4EYYDpQGWvEL62BBGqN9T"),
    ("L554", "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"),
    ("L579", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    ("L602", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"),
    ("L625", "bc1pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszse2s3lm")]
  check "fallback literals count" (addresses.size == 6)
  for (name, address) in addresses do
    let inv ← decoded cap (← find json "valid" 16 name) s!"fallback {name} decode"
    check s!"fallback literal {name}" (inv.toParts.fallbackAddresses == [address])
  IO.println "fallback literals: 6/6"
  let donation ← decoded cap valid[0]! "donation literals decode"
  let coffee ← decoded cap valid[1]! "coffee literals decode"
  let items ← decoded cap (← find json "valid" 16 "L648") "items literals decode"
  let metadata ← decoded cap (← find json "valid" 16 "L735") "metadata literals decode"
  checkCases "getter literals" 12 #[
    ("timestamp", donation.timestamp == 1496314658),
    ("expiry default", donation.toParts.expiry == 3600),
    ("cltv default", donation.toParts.minFinalCltvExpiryDelta == 18),
    ("expiry explicit", coffee.toParts.expiry == 60),
    ("week explicit", items.toParts.expiry == 604800),
    ("cltv explicit", items.toParts.minFinalCltvExpiryDelta == 10),
    ("description", coffee.toParts.description == some (.inl "1 cup coffee")),
    ("payment hash", donation.toParts.paymentHash == some (← hex "0001020304050607080900010203040506070809000102030405060708090102")),
    ("payment secret", donation.toParts.paymentSecret == some (← hex "1111111111111111111111111111111111111111111111111111111111111111")),
    ("metadata", metadata.toParts.metadata == some (← hex "01fafaf0")),
    ("hash description", (← decoded cap valid[3]! "hash description decode").toParts.description ==
      some (.inr (← hex "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"))),
    ("UTF-8", (← decoded cap valid[2]! "UTF-8 decode").toParts.description == some (.inl "ナンセンス 1杯"))]
  let route ← decoded cap (← find json "valid" 16 "L516") "route literal decode"
  let hop1 : RouteHop := ⟨(← hex "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"),
    66051 * 2^40 + 263430 * 2^16 + 1800, 1, 20, 3⟩
  let hop2 : RouteHop := ⟨(← hex "039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"),
    197637 * 2^40 + 395016 * 2^16 + 2314, 2, 30, 4⟩
  check "route literals count" (route.toParts.routeHints == [[hop1, hop2]])
  IO.println "route hop literals: 2/2"
  let features := (← decoded cap (← find json "valid" 16 "L682") "feature literals decode").toParts.features.getD 0
  checkCases "feature literals" 7 #[
    ("var onion", features.requires 8 && features.supports 8),
    ("secret", features.requires 14 && features.supports 14),
    ("mpp absent", !features.supports 16),
    ("metadata absent", !features.supports 48),
    ("trampoline absent", !features.supports 56),
    ("unknown optional", features.unknownBits == [99]),
    ("optional bits", features.optionalBits == [99])]

private def limits (cap : Curve) (json : Lean.Json) : IO Unit := do
  let base ← decoded cap (← find json "valid" 16 "L382") "limits base decode"
  let overflow ← decoded cap (← find json "positive" 4 "amount-none") "limits overflow decode"
  let failed {α : Type} (value : Except EncodeError α) (e : EncodeError) :=
    match value with | .error actual => actual == e | .ok _ => false
  let tooLong := { base with fields := base.fields ++ [.raw 2 (List.replicate 1024 0)] }
  let badTyped := { base with fields := [.paymentHash ByteArray.empty] }
  checkCases "encoder limits" 7 #[
    ("fieldTooLong", failed (encode tooLong) .fieldTooLong &&
      failed (sign cap tooLong.toParts) .fieldTooLong),
    ("msat overflow", failed (hrpFromMsat .bc (Bitcoin.Amount.ofMsat (2^64 / 10 + 1))) .amountOverflow),
    ("hrp overflow", failed (encode overflow) .amountOverflow),
    ("timestamp", failed (encode { base with timestamp := 2^35 }) .invalidTimestamp),
    ("signature", failed (encode { base with signature := ByteArray.empty }) .malformedSignature),
    ("typed field", failed (encode badTyped) (.invalidField 1) &&
      failed (sign cap badTyped.toParts) (.invalidField 1)),
    ("multiplier without amount", failed (encodeHrp ⟨.bc, none, some .pico⟩) .invalidHrp)]
  let largeParts : Invoice :=
    { base with fields := base.fields ++ List.replicate 7 (.raw 2 (List.replicate 1023 0)) }
  let (largeHrp, largeData) ← getOk "encoder unlimited data" (encodeData largeParts.toParts)
  let large := { largeParts with signingHash := signingHash largeHrp largeData }
  let largeText ← getOk "encoder unlimited output" (encode large)
  check "encoder unlimited length" (largeText.length > 7089 &&
    match decode cap largeText with | .error e => e == .bech32 .tooLong | _ => false)
  IO.println "encoder total length: 1/1"
  let values : Array (Nat × String) := #[(100000000000, "lnbc1"), (100000000, "lnbc1m"),
    (100000, "lnbc1u"), (100, "lnbc1n"), (1, "lnbc10p"), (0, "lnbc0")]
  check "amount writer count" (values.size == 6)
  for (msat, hrp) in values do
    let built ← getOk "amount writer construction" (hrpFromMsat .bc (Bitcoin.Amount.ofMsat msat))
    check s!"amount writer {msat}" ((encodeHrp built).toOption == some hrp)
  IO.println "amount writer: 6/6"

private def layers (cap : Curve) (json : Lean.Json) : IO Unit := do
  let base ← decoded cap (← find json "valid" 16 "L382") "layers base decode"
  let fs : List Field := [.expiry 0, .minFinalCltvExpiryDelta 0, .features 0,
    .description "", .metadata ByteArray.empty, .route [], .raw 2 [0, 31]]
  let wire := encodeFields fs
  check "field layer no semantics" ((decodeFields cap wire).toOption == some fs)
  let rawFs := [.raw 1 [], .raw 23 [], .raw 16 [], .raw 19 [], .raw 9 [31, 1]]
  let rawWire := encodeFields rawFs
  check "field layer raw fixed lengths" ((decodeFields cap rawWire).toOption == some rawFs)
  let repeated : Parts := { base.toParts with fields :=
    [.paymentHash ByteArray.empty, .paymentHash base.signature, .paymentSecret ByteArray.empty,
     .paymentSecret base.signature, .description "first", .descriptionHash base.signature,
     .payeePubkey base.payeeKey, .payeePubkey ByteArray.empty,
     .expiry 1, .expiry 2, .minFinalCltvExpiryDelta 3, .minFinalCltvExpiryDelta 4,
     .features 5, .features 6, .metadata ByteArray.empty, .metadata base.signature,
     .fallback (.p2pkh base.signature), .fallback (.p2sh base.signature), .route [], .route []] }
  checkCases "field layers and getters" 12 #[
    ("no semantics", (decodeFields cap wire).toOption == some fs),
    ("raw fixed lengths", (decodeFields cap rawWire).toOption == some rawFs),
    ("first p", repeated.paymentHash == some ByteArray.empty),
    ("first s", repeated.paymentSecret == some ByteArray.empty),
    ("first description", repeated.description == some (.inl "first")),
    ("first n", repeated.payeePubkey == some base.payeeKey),
    ("first x", repeated.expiry == 1),
    ("first c", repeated.minFinalCltvExpiryDelta == 3),
    ("first 9", repeated.features == some 5),
    ("first m", repeated.metadata == some ByteArray.empty),
    ("all f", repeated.fallbacks.length == 2),
    ("all r", repeated.routeHints == [[], []])]
  let currencies : Array (String × Currency × Bitcoin.Address.Network) :=
    #[("bc", .bc, .mainnet), ("tb", .tb, .testnet), ("bcrt", .bcrt, .regtest),
      ("sb", .sb, .regtest), ("tbs", .tbs, .signet)]
  check "currency mappings count" (currencies.size == 5)
  for (name, currency, network) in currencies do
    check s!"currency {name}" ((parseHrp ("ln" ++ name)).toOption == some ⟨currency, none, none⟩ &&
      currency.network == network)
  IO.println "currency mappings: 5/5"
  let invalidSignatures := [
    writeBytes 32 curveOrder ++ base.signature.extract 32 65,
    base.signature.extract 0 32 ++ writeBytes 32 curveOrder ++ base.signature.extract 64 65,
    base.signature.extract 0 64 |>.push 4]
  check "signature bounds count" (invalidSignatures.length == 3)
  for sig in invalidSignatures do
    let (hrp, data) ← getOk "signature bounds data" (encodeData base.toParts)
    let invoice := Bitcoin.Bech32.encode hrp (data ++ Bitcoin.Bech32.convertbits8to5 sig) .bech32
    check "signature bounds" (match decode cap invoice with | .error .malformedSignature => true | _ => false)
  IO.println "signature bounds: 3/3"

def run (selector : Option String := none) : IO Unit := do
  let json ← getOk "fixture JSON" (Lean.Json.parse (← IO.FS.readFile "test-data/bolt11.json"))
  let cap ← capability json
  for (set, count) in [("valid",16), ("invalid",15), ("nfields",2), ("negative",20),
      ("positive",4), ("outside",3), ("small",3)] do
    let cases ← rows json set count
    let mut executed := 0
    for row in cases do
      let name ← text row "name"
      if !selected selector set name then continue
      executed := executed + 1
      let label := s!"{set} {name}"
      if set == "valid" || set == "positive" || name == "n-low" then
        let inv ← accepted cap row label
        if set == "positive" then
          match name with
          | "fallback-25" => check label (inv.toParts.fallbacks.length == 1 && inv.toParts.fallbackAddresses == [])
          | "amount-none" => check label (inv.hrp.rawAmount == some 20000000 && inv.hrp.amount.isNone)
          | "amount-leading-zero" => check label (inv.hrp.amount.map (·.msat) == some 250000000)
          | "n-amount-leading-zero" => check label (inv.hrp.rawAmount == some 25 &&
              inv.toParts.payeePubkey == some inv.payeeKey &&
              cap.verify inv.signingHash (inv.signature.extract 0 64) inv.payeeKey)
          | _ => throw (IO.userError "unknown positive fixture")
        if name == "n-low" then
          check "nfields low verification" (inv.toParts.payeePubkey == some inv.payeeKey &&
            cap.verify inv.signingHash (inv.signature.extract 0 64) inv.payeeKey)
      else if name == "L814" then
        let inv ← decoded cap row "invalid L814 accepted for parity"
        check "invalid L814 payee" (inv.payeeKey == (← hex "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        check "invalid L814 raw n" (inv.toParts.payeePubkey.isNone && inv.fields.any fun f =>
          match f with | .raw 19 data => data.length == 52 | _ => false)
      else
        if name == "n-high" then
          let (_, data, _) ← getOk "nfields high bech32" (Bitcoin.Bech32.decode 7089 (← text row "invoice"))
          let fs ← getOk "nfields high fields" (decodeFields cap ((data.take (data.length - 104)).drop 7))
          let parts : Parts := ⟨⟨.bc, some 25, some .milli⟩, 0, fs⟩
          check "nfields high passes preceding checks" ((checkFieldCounts fs).isOk &&
            (checkFeatures parts).isOk && validSignature (← hexField row "signature"))
        rejected cap row label
    if executed > 0 then IO.println s!"{set}: {executed}/{count}"
  if selector.isNone || selector == some "reencode" then
    let cases := (← rows json "valid" 16) |>.push (← find json "invalid" 15 "L814")
    check "re-encoding count" (cases.size == 17)
    for row in cases do
      let name ← text row "name"
      let inv ← decoded cap row s!"reencode {name} decode"
      check s!"reencode {name}" ((encode inv).toOption == some (Bitcoin.Bech32.lower (← text row "invoice")))
    IO.println "re-encodings: 17/17"
    let stale := #["amount-leading-zero", "n-amount-leading-zero"]
    check "re-encoding refusal count" (stale.size == 2)
    for name in stale do
      let inv ← decoded cap (← find json "positive" 4 name) s!"reencode {name} decode"
      check s!"reencode {name} refused"
        (match encode inv with | .error .signingHashMismatch => true | _ => false)
    IO.println "re-encoding refusals: 2/2"
  if selector.isNone || selector == some "sign" then
    let row ← find json "nfields" 2 "n-low"
    let inv ← decoded cap row "sign decode"
    check "encoder signing path" ((sign cap inv.toParts).toOption == some (← text row "invoice"))
    IO.println "encoder signing path: 1/1"
    check "signing hash cross-check" (inv.signingHash == (← hexField row "hash"))
    IO.println "signing hash cross-check: 1/1"
  if selector.isNone || selector == some "literals" then literals cap json
  if selector.isNone || selector == some "limits" then limits cap json
  if selector.isNone || selector == some "layers" then layers cap json

end LightningTests.Bolt11
