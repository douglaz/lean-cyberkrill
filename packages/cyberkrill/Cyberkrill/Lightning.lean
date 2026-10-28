/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.Amounts
import Cyberkrill.Capabilities
import Cyberkrill.InvoiceJson
import Std.Time
import Lean

namespace Cyberkrill
namespace LightningCli
open Lean Lightning.Bolt11

private def invoiceError : Lightning.Bolt11.Error → Error
  | .nonCanonicalPadding tag => .lightning s!"nonCanonicalPadding: tag={tag.toNat}"
  | .leadingZero tag => .lightning s!"leadingZero: tag={tag.toNat}"
  | e => .lightning ((reprStr e).replace "Lightning.Bolt11.Error." "")

private def urlError : Lightning.LnurlError → Error
  | .unsupportedUrlForm reason => .lightning ("unsupportedUrlForm:" ++
      (reprStr reason).replace "Lightning.UnsupportedUrlForm." "")
  | e => .lightning ((reprStr e).replace "Lightning.LnurlError." "")

private def networkText : Currency → String
  | .bc => "bitcoin" | .tb => "testnet" | .bcrt => "regtest"
  | .tbs => "signet" | .sb => "simnet"

private def addressNetwork : Currency → Bitcoin.Address.Network
  | .bc => .mainnet | .bcrt => .regtest | .tbs => .signet | .tb | .sb => .testnet

private def timestampText (seconds : Nat) : String :=
  let time := Std.Time.DateTime.ofTimestampWithZone
    (Std.Time.Timestamp.ofSecondsSinceUnixEpoch (.ofNat seconds)) .UTC
  time.format "uuuu-MM-dd'T'HH:mm:ss'Z'"

private def featuresJson (bits : Features) : Json := Id.run do
  let mut values := []
  for (name, bit) in [("basic_mpp", 16), ("payment_metadata", 48),
      ("payment_secret", 14), ("trampoline_routing", 56)] do
    if bits.supports bit then
      values := values ++ [Json.mkObj [(name, toJson (if bits.requires bit then "required" else "optional"))]]
  if !bits.unknownBits.isEmpty then
    values := values ++ [Json.mkObj [("unknown_bits", toJson
      (if bits.requiresUnknown then "required" else "optional"))]]
  if bits.supports 8 then
    values := values ++ [Json.mkObj [("variable_length_onion", toJson
      (if bits.requires 8 then "required" else "optional"))]]
  if !bits.optionalBits.isEmpty then values := values ++ [toJson "any_optional_bits"]
  return toJson values

private def hopJson (hop : RouteHop) : Json := Json.mkObj [
  ("src_node_id", toJson (Bitcoin.Hex.encode hop.nodeId)),
  ("short_channel_id", toJson hop.shortChannelId.toNat),
  ("fees", Json.mkObj [("base_msat", toJson hop.feeBaseMsat.toNat),
    ("proportional_millionths", toJson hop.feeProportionalMillionths.toNat)]),
  ("cltv_expiry_delta", toJson hop.cltvExpiryDelta.toNat),
  ("htlc_minimum_msat", .null), ("htlc_maximum_msat", .null)]

def decodeInvoice (input : String) : Except Error String := do
  let inv ← (decode (bolt11Curve ByteArray.empty) input).mapError invoiceError
  let parts := inv.toParts
  let fallbacks := parts.fallbacks.filterMap fun f =>
    (Bitcoin.Address.encodeScript parts.hrp.currency.network f.script).toOption
  let j := Json.mkObj [
    ("network", toJson (networkText parts.hrp.currency)),
    ("amount_msats", toJson (parts.hrp.amount.map (·.msat))),
    ("timestamp", toJson (timestampText parts.timestamp)),
    ("timestamp_millis", toJson (parts.timestamp * 1000)),
    ("payment_hash", toJson (Bitcoin.Hex.encode (parts.paymentHash.getD ByteArray.empty))),
    ("payment_secret", toJson (Bitcoin.Hex.encode (parts.paymentSecret.getD ByteArray.empty))),
    ("features", featuresJson (parts.features.getD 0)),
    ("description", toJson (parts.description.bind fun d => match d with | .inl s => some s | _ => none)),
    ("description_hash", toJson (parts.description.bind fun d => match d with
      | .inr b => some (Bitcoin.Hex.encode b) | _ => none)),
    ("destination", toJson (Bitcoin.Hex.encode inv.payeeKey)),
    ("expiry_seconds", toJson parts.expiry.toNat),
    ("min_final_cltv_expiry", toJson parts.minFinalCltvExpiryDelta.toNat),
    ("fallback_addresses", toJson fallbacks),
    ("routes", toJson (parts.routeHints.map fun hops => toJson (hops.map hopJson)))]
  return j.pretty

def decodeLnurl (input : String) : Except Error String := do
  let value ← (Lightning.decodeLnurl input).mapError urlError
  return (Json.mkObj [("bech32", toJson value.bech32), ("url", toJson value.url),
    ("host", toJson value.host), ("base", toJson value.base), ("query", toJson value.query),
    ("query_params", Json.mkObj (value.queryParams.map fun (k, v) => (k, toJson v)))]).pretty

private def jsonResult (value : Except String α) : Except Error α :=
  value.mapError fun _ => .invalidInvoiceJson

private def field (j : Json) (name : String) : Except Error Json :=
  jsonResult (j.getObjVal? name)

private def text (j : Json) : Except Error String := jsonResult j.getStr?

private def unsigned (j : Json) (bits : Nat) : Except Error Nat := do
  let n ← jsonResult j.getNat?
  if n ≥ 2^bits then throw .invalidInvoiceJson
  return n

private def optional (j : Json) (name : String) (parse : Json → Except Error α) :
    Except Error (Option α) :=
  match j.getObjVal? name with
  | .error _ | .ok .null => pure none
  | .ok value => some <$> parse value

private def hash (j : Json) : Except Error ByteArray := do
  let s ← text j
  let some b := Bitcoin.Hex.decode s | throw .invalidInvoiceJson
  if b.size != 32 then throw .invalidInvoiceJson
  return b

private def pubkey (j : Json) : Except Error ByteArray := do
  let s ← text j
  let some b := Bitcoin.Hex.decode s | throw .badPublicKey
  let some key := Secp256k1.compressPubkey b | throw .badPublicKey
  return key

private def list (j : Json) (parse : Json → Except Error α) : Except Error (List α) := do
  let rows ← jsonResult j.getArr?
  rows.toList.mapM parse

private def checkFeature (j : Json) : Except Error Unit := do
  if (InvoiceJson.enumName j).toOption == some "any_optional_bits" then return
  let obj ← jsonResult j.getObj?
  let pairs := obj.toList
  let [(name, status)] := pairs | throw .invalidInvoiceJson
  unless ["basic_mpp", "payment_metadata", "payment_secret", "trampoline_routing",
      "unknown_bits", "variable_length_onion"].contains name do throw .invalidInvoiceJson
  let value ← InvoiceJson.enumName status
  unless ["required", "optional"].contains value do throw .invalidInvoiceJson

private def routeHop (j : Json) : Except Error RouteHop := do
  let j ← InvoiceJson.structObject j ["src_node_id", "short_channel_id", "fees", "cltv_expiry_delta",
    "htlc_minimum_msat", "htlc_maximum_msat"]
  let key ← pubkey (← field j "src_node_id")
  let id ← unsigned (← field j "short_channel_id") 64
  let fees ← InvoiceJson.structObject (← field j "fees") ["base_msat", "proportional_millionths"]
  let base ← unsigned (← field fees "base_msat") 32
  let prop ← unsigned (← field fees "proportional_millionths") 32
  let delta ← unsigned (← field j "cltv_expiry_delta") 16
  let _ ← optional j "htlc_minimum_msat" (unsigned · 64)
  let _ ← optional j "htlc_maximum_msat" (unsigned · 64)
  return ⟨key, UInt64.ofNat id, UInt32.ofNat base, UInt32.ofNat prop, UInt16.ofNat delta⟩

private def fallback (currency : Currency) (j : Json) : Except Error Fallback := do
  let address ← text j
  let value ← (Bitcoin.Address.decode (addressNetwork currency) address).mapError fun _ =>
    Error.lightning "invalidFallback"
  match value with
  | .p2pkh _ h => return .p2pkh h
  | .p2sh _ h => return .p2sh h
  | .witness _ version program =>
    if version == 0 || (version == 1 && program.size == 32) then
      if h : version < 17 then return .segwit ⟨version, h⟩ program
      else throw (.lightning "invalidFallback")
    else throw (.lightning "unsupportedFallback")

/-- The reference builder selects m/u/n/p, including m for zero and whole BTC. -/
def builderHrp (currency : Currency) (amount : Option Nat) : Except Error Hrp := do
  let some msat := amount | return ⟨currency, none, none⟩
  let pico := msat * 10
  if pico ≥ 2^64 then throw (.lightning "amountOverflow")
  let choices : List (Multiplier × Nat) :=
    [(.milli, 1000000000), (.micro, 1000000), (.nano, 1000), (.pico, 1)]
  let (m, factor) := (choices.find? fun p => pico % p.2 == 0).getD (.pico, 1)
  return ⟨currency, some (UInt64.ofNat (pico / factor)), some m⟩

def encodeInvoice (input keyText : String) : Except Error String := do
  let j ← jsonResult (Json.parse input)
  InvoiceJson.validateSyntax input
  let j ← InvoiceJson.structObject j ["network", "amount_msats", "timestamp", "timestamp_millis", "payment_hash",
    "payment_secret", "features", "description", "description_hash", "destination", "expiry_seconds",
    "min_final_cltv_expiry", "fallback_addresses", "routes"]
  let net ← InvoiceJson.enumName (← field j "network")
  let currency ← match net with
    | "bitcoin" | "mainnet" => pure Currency.bc | "testnet" => pure Currency.tb
    | "regtest" => pure Currency.bcrt | "signet" => pure Currency.tbs
    | "simnet" => pure Currency.sb | _ => throw Error.invalidInvoiceJson
  let amount ← optional j "amount_msats" (unsigned · 64)
  let timestamp ← text (← field j "timestamp")
  unless InvoiceJson.timestampValid timestamp do throw .invalidInvoiceJson
  let millis ← unsigned (← field j "timestamp_millis") 128
  let paymentHash ← hash (← field j "payment_hash")
  let secret ← hash (← field j "payment_secret")
  let _ ← list (← field j "features") checkFeature
  let description ← optional j "description" text
  let descriptionHash ← optional j "description_hash" hash
  let destination ← pubkey (← field j "destination")
  let expiry ← unsigned (← field j "expiry_seconds") 64
  let cltv ← unsigned (← field j "min_final_cltv_expiry") 64
  let fallbacks ← list (← field j "fallback_addresses") (fallback currency)
  let routes ← list (← field j "routes") (fun j => list j routeHop)
  let some key := Bitcoin.Hex.decode keyText | throw .badPrivateKey
  if key.size != 32 || readBytes key == 0 || readBytes key ≥ curveOrder then throw .badPrivateKey
  let desc := match description, descriptionHash with
    | some d, _ => Field.description d | none, some h => .descriptionHash h
    | none, none => .description ""
  let fields := [desc, .paymentHash paymentHash, .paymentSecret secret, .features (2^8 + 2^14),
    .minFinalCltvExpiryDelta (UInt64.ofNat cltv), .expiry (UInt64.ofNat expiry), .payeePubkey destination] ++
    fallbacks.map Field.fallback ++ (routes.filter (!·.isEmpty)).map Field.route
  let parts : Parts := ⟨← builderHrp currency amount, (millis / 1000) % 2^64, fields⟩
  (sign (bolt11Curve key) parts).mapError fun e =>
    .lightning ((reprStr e).replace "Lightning.Bolt11.EncodeError." "")

end LightningCli
end Cyberkrill
