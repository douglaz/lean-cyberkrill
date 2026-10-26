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
  let without (drop : Field → Bool) : Invoice := { base with fields := base.fields.filter (!drop ·) }
  let refused (inv : Invoice) (e : Error) :=
    failed (encode inv) (.invalidInvoice e) && failed (sign cap inv.toParts) (.invalidInvoice e)
  checkCases "encoder semantic refusals" 7 #[
    ("no p", refused (without fun | .paymentHash _ => true | _ => false) .noPaymentHash),
    ("two p", refused { base with fields := base.fields ++ [.paymentHash base.signingHash] }
      .multiplePaymentHashes),
    ("no s", refused (without fun | .paymentSecret _ => true | _ => false) .noPaymentSecret),
    ("no description", refused (without fun
      | .description _ | .descriptionHash _ => true | _ => false) .noDescription),
    ("no 9", refused (without fun | .features _ => true | _ => false) .invalidFeatures),
    ("unknown even feature", refused { base with fields := base.fields.map fun
      | .features _ => .features (2^14 + 2^100) | f => f } .unknownRequiredFeatures),
    ("imprecise amount", refused { base with hrp := ⟨.bc, some 1, some .pico⟩ } .impreciseAmount)]
  let rawRefused (tag : Symbol) (data : List Symbol) :=
    let inv : Invoice := { base with fields := base.fields ++ [.raw tag data] }
    failed (encode inv) (.invalidField tag) && failed (sign cap inv.toParts) (.invalidField tag)
  let rawKept (tag : Symbol) (data : List Symbol) :=
    (encodeData { base.toParts with fields := base.fields ++ [.raw tag data] }).isOk
  checkCases "encoder raw fields" 6 #[
    ("typed-length p refused", rawRefused 1 (fieldData (.paymentHash base.signingHash))),
    ("typed-length n refused", rawRefused 19 (fieldData (.payeePubkey base.payeeKey))),
    ("known fallback version refused",
      rawRefused 9 (fieldData (.fallback (.p2pkh (base.signingHash.extract 0 20))))),
    ("description refused", rawRefused 13 []),
    ("wrong-length p kept", rawKept 1 (List.replicate 51 0)),
    ("unknown fallback version kept", rawKept 9 [19, 0])]
  let offCurve := ByteArray.mk (Array.replicate 33 2)
  let hop (key : ByteArray) : RouteHop :=
    { nodeId := key, shortChannelId := 0, feeBaseMsat := 0, feeProportionalMillionths := 0,
      cltvExpiryDelta := 0 }
  let signWith (f : Field) := sign cap { base.toParts with fields := base.fields ++ [f] }
  let routeKey ← hex "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"
  checkCases "sign curve points" 3 #[
    ("payee", failed (signWith (.payeePubkey offCurve)) (.invalidInvoice (.malformedField 19))),
    ("route node", failed (signWith (.route [hop offCurve])) (.invalidInvoice (.malformedField 3))),
    ("published route node reaches the signer",
      failed (signWith (.route [hop routeKey])) .signingFailed)]
  let samples : List (List Symbol) := [[], [0], [1], [19], [31, 1], List.replicate 51 0,
    List.replicate 52 0, List.replicate 53 0, 17 :: List.replicate 32 0, 19 :: List.replicate 32 0]
  let mut classified := 0
  for tag in List.range 32 do
    for data in samples do
      let raw := match decodeField cap (BitVec.ofNat 5 tag) data with
        | .ok (.raw _ _) => true | _ => false
      check s!"raw classification {tag} {data.length}" (staysRaw (BitVec.ofNat 5 tag) data == raw)
      classified := classified + 1
  check "raw classification count" (classified == 320)
  IO.println "raw classification: 320/320"
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

/-- A numeric bit-packing path, reading the source string directly. This uses
neither the production hash/convertbits helpers nor the proof's Bool packing. -/
private def directSpecHash (s : String) : IO ByteArray := do
  let chars := s.toList.reverse.takeWhile (· != '1') |>.reverse
  let hrp := String.ofList (s.toList.take (s.length - chars.length - 1))
  let alphabet := "qpzry9x8gf2tvdw0s3jn54khce6mua7l".toList
  let symbols ← chars.mapM fun c => do
    let some n := alphabet.idxOf? c.toLower | throw (IO.userError "spec hash alphabet")
    return n
  let signed := symbols.take (symbols.length - 6 - 104)
  let bits := signed.flatMap fun n => (List.range 5).map fun i => n / 2^(4-i) % 2
  let bytes := (List.range ((bits.length + 7) / 8)).map fun i => UInt8.ofNat
    ((List.range 8).foldl (fun acc j => 2 * acc + bits.getD (8*i+j) 0) 0)
  return Sha256.hash ((String.ofList (hrp.toList.map Char.toLower)).toUTF8 ++ ⟨bytes.toArray⟩)

private def specHashes (cap : Curve) (json : Lean.Json) : IO Unit := do
  let cases := ((← rows json "valid" 16).push (← find json "invalid" 15 "L814")) ++
    (← rows json "positive" 4)
  check "direct spec hash loaded count" (cases.size == 21)
  let mut executed := 0
  for row in cases do
    let name ← text row "name"
    let source ← text row "invoice"
    let inv ← decoded cap row s!"direct spec hash {name} decode"
    check s!"direct spec hash {name}" (inv.signingHash == (← directSpecHash source))
    executed := executed + 1
  check "direct spec hash executed count" (executed == 21)
  IO.println "direct spec hashes: 21/21"

private def amountBoundaries : IO Unit := do
  let currencies : Array Currency := #[.bc, .tb, .bcrt, .sb, .tbs]
  let values : Array (Nat × String) := #[(0, "0"), (1, "10p"), (100, "1n"),
    (100000, "1u"), (100000000, "1m"), (100000000000, "1"),
    (967878534, "9678785340p"), (1844674407370955161, "18446744073709551610p")]
  check "amount boundary loaded count" (currencies.size == 5 && values.size == 8)
  let mut executed := 0
  for currency in currencies do
    for (msat, suffix) in values do
      let hrp ← getOk "amount boundary build" (hrpFromMsat currency (Bitcoin.Amount.ofMsat msat))
      check "amount boundary exact" (hrp.amount.map (·.msat) == some msat)
      check "amount boundary pico" (hrp.picoAmount == some (msat * 10))
      let written ← getOk "amount boundary encode" (encodeHrp hrp)
      check "amount boundary canonical unit" (written == "ln" ++ currency.text ++ suffix)
      check "amount boundary parse" ((parseHrp written).toOption == some hrp)
      executed := executed + 1
  check "amount boundary executed count" (executed == 40)
  IO.println "amount boundaries: 40/40"
  let overflow : Array Nat := #[1844674407370955162, 18446744073709551616, 10^30]
  check "amount overflow loaded count" (overflow.size == 3)
  let mut overflowCount := 0
  for currency in currencies do
    for msat in overflow do
      check "amount boundary overflow" (match hrpFromMsat currency (Bitcoin.Amount.ofMsat msat) with
        | .error .amountOverflow => true | _ => false)
      overflowCount := overflowCount + 1
  check "amount overflow executed count" (overflowCount == 15)
  IO.println "amount overflows: 15/15"
  let picoValues : Array (UInt64 × Bool) := #[(0, true), (10, true),
    (18446744073709551610, true), (1, false), (9, false), (11, false),
    (19, false), (18446744073709551615, false)]
  check "pico boundary loaded count" (picoValues.size == 8)
  let mut picoCount := 0
  let mut reverseCount := 0
  for (pico, precise) in picoValues do
    let hrp : Hrp := ⟨.bc, some pico, some .pico⟩
    check "pico boundary rejection" (match checkPrecision hrp with
      | .ok () => precise | .error .impreciseAmount => !precise | _ => false)
    if precise then
      let canonical ← getOk "reverse amount construction"
        (hrpFromMsat .bc (Bitcoin.Amount.ofMsat (pico.toNat / 10)))
      check "reverse amount equality" (canonical.amount == hrp.amount)
      reverseCount := reverseCount + 1
    picoCount := picoCount + 1
  check "pico boundary executed count" (picoCount == 8)
  check "reverse amount executed count" (reverseCount == 3)
  IO.println "pico boundaries: 8/8; reverse precise amounts: 3/3"
  let absent : Hrp := ⟨.bc, none, none⟩
  let unavailable : Hrp := ⟨.bc, some 20000000, none⟩
  checkCases "unavailable amounts" 2 #[
    ("absent", absent.picoAmount.isNone && absent.amount.isNone && (checkPrecision absent).isOk),
    ("raw overflow", unavailable.picoAmount.isNone && unavailable.amount.isNone &&
      (checkPrecision unavailable).isOk && (parseHrp "lnbc20000000").toOption == some unavailable)]

private def rawCounterexample (cap : Curve) : IO Unit := do
  let raw : Field := .raw 1 (List.replicate 52 0)
  let expected : List Field := [.paymentHash ⟨Array.replicate 32 0⟩]
  let cases := #[raw]
  check "KeptRaw counterexample loaded count" (cases.size == 1)
  let mut executed := 0
  for field in cases do
    check "KeptRaw typed zero payment hash" ((decodeFields cap (encodeFields [field])).toOption == some expected)
    executed := executed + 1
  check "KeptRaw counterexample executed count" (executed == 1)
  IO.println "KeptRaw counterexample: 1/1"

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
  if selector.isNone || selector == some "spec-hashes" then specHashes cap json
  if selector.isNone || selector == some "amount-boundaries" then amountBoundaries
  if selector.isNone || selector == some "raw-counterexample" then rawCounterexample cap

end LightningTests.Bolt11
