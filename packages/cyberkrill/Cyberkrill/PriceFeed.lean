/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill.Fiat
import HttpCurl
import Lightning.Lnurl.Url

namespace Cyberkrill.PriceFeed
open Lean

structure Feed where
  source : String
  label : String
  base : String
  path : String → String
  missing404 : Bool := false
  deriving Inhabited

def feeds : Array Feed := #[
  ⟨"coingecko", "CoinGecko", "https://api.coingecko.com", fun c => "/api/v3/simple/price?ids=bitcoin&vs_currencies=" ++ c.toLower, false⟩,
  ⟨"coinbase", "Coinbase", "https://api.coinbase.com", fun _ => "/v2/exchange-rates?currency=BTC", false⟩,
  ⟨"blockchain.info", "Blockchain.info", "https://blockchain.info", fun _ => "/ticker", false⟩,
  ⟨"kraken", "Kraken", "https://api.kraken.com", fun c => "/0/public/Ticker?pair=XBT" ++ c, false⟩,
  ⟨"fedi", "Fedi", "https://price-feed.dev.fedibtc.com", fun _ => "/latest", false⟩,
  ⟨"cex.io", "CEX.IO", "https://cex.io", fun c => "/api/ticker/BTC/" ++ c, true⟩,
  ⟨"bitstamp", "Bitstamp", "https://www.bitstamp.net", fun c => "/api/v2/ticker/btc" ++ c.toLower, true⟩,
  ⟨"yadio", "Yadio", "https://api.yadio.io", fun c => "/convert/1/BTC/" ++ c, true⟩,
  ⟨"gemini", "Gemini", "https://api.gemini.com", fun c => "/v1/pubticker/btc" ++ c.toLower, true⟩]

structure Quote where
  source : String
  price : Exact
  deriving Repr, Inhabited

structure Price where
  currency : String
  price : Exact
  sources : Array Quote
  deriving Repr, Inhabited

def field (j : Json) (path : List String) : Option Json :=
  path.foldlM (fun j key => (j.getObjVal? key).toOption) j

private def codeUnit (cs : List Char) : Option Nat := do
  if cs.length != 4 then none else
    cs.foldlM (fun n c => do
      let digit ← if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
        else if 'a' ≤ c.toLower && c.toLower ≤ 'f' then some (c.toLower.toNat - 'a'.toNat + 10)
        else none
      return n * 16 + digit) 0

private def decimalSyntax (text : String) (jsonNumber := false) : Bool := Id.run do
  let digits := fun (s : String) => !s.isEmpty && s.toList.all (fun c => '0' ≤ c && c ≤ '9')
  let unsigned := if text.startsWith "-" || (!jsonNumber && text.startsWith "+") then
    (text.drop 1).toString else text
  let parts := (unsigned.replace "E" "e").splitOn "e"
  unless parts.length ≤ 2 do return false
  if let some exponent := parts[1]? then
    let exponent := if exponent.startsWith "+" || exponent.startsWith "-" then
      (exponent.drop 1).toString else exponent
    unless digits exponent do return false
  let decimals := parts.head!.splitOn "."
  unless decimals.length ≤ 2 do return false
  let whole := decimals.head!
  let fraction := decimals[1]?.getD ""
  if jsonNumber then
    return digits whole && (whole.length == 1 || !whole.startsWith "0") &&
      (decimals.length == 1 || digits fraction)
  return digits (whole ++ fraction)

/-- Preserve numeric tokens without asking Lean's JSON parser to expand them.
Original JSON strings (including keys) get an `s` prefix; numeric tokens become
`n` plus their index. The disjoint encodings cannot be supplied by input values.
Check the complete grammar, Unicode and reference container limit first. -/
private def prepareJson (body : String) : Option (Json × Array String) := do
  let (encoded, numbers) ← Id.run do
    let mut rest := body.toList
    let mut quoted := false
    let mut depth := 0
    let mut output : List Char := []
    let mut numbers : Array String := #[]
    for _ in [:rest.length] do
      let c :: tail := rest | break
      rest := tail
      if quoted then
        output := c :: output
        if c == '"' then quoted := false
        else if c == '\\' then
          let escape :: tail := rest | return none
          rest := tail
          output := escape :: output
          if escape == 'u' then
            let some unit := codeUnit (rest.take 4) | return none
            output := (rest.take 4).reverse ++ output
            rest := rest.drop 4
            if 0xD800 ≤ unit && unit ≤ 0xDBFF then
              let '\\' :: 'u' :: tail := rest | return none
              let some low := codeUnit (tail.take 4) | return none
              unless 0xDC00 ≤ low && low ≤ 0xDFFF do return none
              output := (['\\', 'u'] ++ tail.take 4).reverse ++ output
              rest := tail.drop 4
            else if 0xDC00 ≤ unit && unit ≤ 0xDFFF then return none
      else if c == '"' then
        quoted := true
        output := 's' :: c :: output
      else if c == '-' || ('0' ≤ c && c ≤ '9') then
        let chars := rest.takeWhile (fun ch => "0123456789eE+.-".contains ch)
        rest := rest.drop chars.length
        let token := String.ofList (c :: chars)
        unless token.length ≤ 2048 && decimalSyntax token true do return none
        -- A numeric value cannot be an object key. Encoding it as a string
        -- must not repair invalid original JSON, including nested keys.
        if (rest.dropWhile (fun ch => " \t\r\n".contains ch)).head? == some ':' then return none
        output := ("\"n" ++ toString numbers.size ++ "\"").toList.reverse ++ output
        numbers := numbers.push token
      else
        if c == '[' || c == '{' then
          depth := depth + 1
          if depth ≥ 128 then return none
        else if c == ']' || c == '}' then
          if depth == 0 then return none
          depth := depth - 1
        output := c :: output
    return some (String.ofList output.reverse, numbers)
  let j ← (Json.parse encoded).toOption
  return (j, numbers)

/-- Only classify range here; ignored tiny values and zero need no decimal
power allocation. At the upper boundary compare with the overflow midpoint.
Selected prices instead keep the existing exact decimal range. -/
private def finiteJsonNumber (token : String) : Bool := Id.run do
  let unsigned := if token.startsWith "-" then (token.drop 1).toString else token
  let parts := (unsigned.replace "E" "e").splitOn "e"
  let decimals := parts.head!.splitOn "."
  let fraction := decimals[1]?.getD ""
  let coefficient := decimals.head! ++ fraction
  let significant := String.ofList (coefficient.toList.dropWhile (· == '0'))
  let rawExponent := parts[1]?.getD "0"
  let exponentDigits := String.ofList (rawExponent.toList.dropWhile (fun c => c == '+' || c == '-' || c == '0'))
  let magnitude := if exponentDigits.length > 5 then 100000 else exponentDigits.toNat?.getD 0
  let exponent : Int := if rawExponent.startsWith "-" then -(magnitude : Int) else magnitude
  if significant.isEmpty then return true
  let order := (significant.length : Int) - 1 + exponent - fraction.length
  if order < 308 then return true
  if order > 308 then return false
  -- order = 308 bounds this power by the lexical token length, even for a
  -- long coefficient. Neither large positive nor tiny exponents reach here.
  let power := exponent - (fraction.length : Int)
  let n := significant.toNat?.getD 0
  let value := if power ≥ 0 then Exact.ofRatio (n * 10^power.toNat) 1
    else Exact.ofRatio n (10^power.natAbs)
  return value.lt ⟨2^1024 - 2^970, 1⟩

private abbrev Selection := ExceptT String (StateM (Array Nat))

private def positive (numbers : Array String) (j : Json) (label invalid : String) : Selection Exact := do
  let .str encoded := j | throw (label ++ " is not a number")
  let numeric := encoded.startsWith "n"
  let text ← if numeric then do
    let some index := (encoded.drop 1).toString.toNat? | throw invalid
    let some token := numbers[index]? | throw invalid
    modify (·.push index)
    pure token
  else pure (encoded.drop 1).toString
  let unsigned := if text.startsWith "+" || text.startsWith "-" then (text.drop 1).toString else text
  if ["inf", "infinity", "nan"].contains unsigned.toLower then
    throw (label ++ " must be positive")
  unless decimalSyntax text do throw (label ++ " is not a number")
  -- Classification does not require constructing the magnitude of a negative
  -- decimal. Check syntax before its sign, including malformed double signs.
  if text.startsWith "-" then throw (label ++ " must be positive")
  let some value := Exact.parse text | throw (if numeric then invalid else label ++ " is not a number")
  if value.numerator == 0 || value.denominator == 0 then throw (label ++ " must be positive")
  return value

private def encodedField (j : Json) (path : List String) : Option Json :=
  field j (path.map ("s" ++ ·))

private def selected (numbers : Array String) (j : Option Json) (label invalid : String) : Selection (Option Exact) :=
  j.mapM (positive numbers · label invalid)

private def parseSelected (source currency : String) (j : Json) (numbers : Array String)
    (invalid : String) : Selection (Option Exact) := do
  let get := encodedField j
  let select := fun path label => selected numbers (get path) label invalid
  match source with
  | "coingecko" => select ["bitcoin", currency.toLower] "CoinGecko price"
  | "coinbase" => select ["data", "rates", currency] "Coinbase rate"
  | "blockchain.info" => select [currency, "last"] "Blockchain.info last price"
  | "kraken" =>
    if let some (.arr errors) := get ["error"] then
      unless errors.isEmpty do return none
    let some (.obj result) := get ["result"] | return none
    let mut candidates : Array (String × Exact × Array Nat) := #[]
    for (pair, ticker) in result.toArray do
      if let some (.arr close) := encodedField ticker ["c"] then
        if let some value := close[0]? then
          set (#[] : Array Nat)
          let price ← positive numbers value "Kraken close price" invalid
          candidates := candidates.push (pair, price, ← getThe (Array Nat))
    let sorted := candidates.qsort (fun a b => a.1 < b.1)
    let chosen := if candidates.size == 1 then candidates[0]?
      else sorted.find? (fun p => p.1.endsWith currency)
    -- Every candidate is validated, but only the returned price contributes
    -- exact tokens. Losing candidates still undergo whole-body range checks.
    set (chosen.map (·.2.2) |>.getD #[])
    return chosen.map (·.2.1)
  | "fedi" =>
    let some btc ← select ["prices", "BTC/USD", "rate"] "Fedi rate" | return none
    if currency == "USD" then return some btc
    let some fiat ← select ["prices", currency ++ "/USD", "rate"] "Fedi rate" | return none
    return some (btc.div fiat)
  | "cex.io" =>
    if (get ["error"]).isSome then return none
    select ["last"] "CEX.IO last price"
  | "yadio" =>
    if (get ["error"]).isSome then return none
    select ["rate"] "Yadio rate"
  | "gemini" =>
    if let some (.str result) := get ["result"] then
      if result.toLower == "serror" then return none
    select ["last"] "Gemini last price"
  | "bitstamp" => select ["last"] "Bitstamp last price"
  | _ => throw "Unknown price feed"

/-- These are the fields consumed by the pinned reference, including the
whole-body JSON checks and missing versus invalid selected values. Numeric
selection records only tokens contributing to a returned quote; other tokens
undergo the exact finite-range classification, with captured boundary deltas. -/
def parse (source currency body : String) : Except String (Option Exact) := do
  let label := (feeds.find? (·.source == source)).map (·.label) |>.getD source
  let invalid := "Invalid " ++ label ++ " JSON"
  let some (j, numbers) := prepareJson body | throw invalid
  let (result, used) := ((parseSelected source currency j numbers invalid).run).run #[]
  let quoted := match result with | .ok (some _) => true | _ => false
  for i in [:numbers.size] do
    unless (quoted && used.contains i) || finiteJsonNumber numbers[i]! do throw invalid
  result

def median (values : Array Exact) : Option Exact := do
  if values.isEmpty then none else do
    let sorted := values.qsort Exact.lt
    let middle := sorted.size / 2
    if sorted.size % 2 == 0 then
      return ((← sorted[middle - 1]?).add (← sorted[middle]?)).div ⟨2, 1⟩
    else sorted[middle]?

def spreadWarning (p : Price) : String := Id.run do
  let some lo := p.sources[0]? | return ""
  let some hi := p.sources.back? | return ""
  -- max/min > 1.02, compared by cross products; no saturating subtraction.
  let ratio := hi.price.div lo.price
  unless (Exact.mk 102 100).lt ratio do return ""
  let spread := Exact.ofRatio ((ratio.numerator - ratio.denominator) * 100) ratio.denominator
  return s!"[price-feed] BTC price feed spread for {p.currency} is {spread.fixed 2}% ({lo.source}={lo.price.fixed 2}, {hi.source}={hi.price.fixed 2}); using median BTC/{p.currency}={p.price.fixed 2}\n"

def aggregate (currency : String) (quotes : Array Quote) : Except String Price := do
  if quotes.size < 3 then
    let word := if quotes.size == 1 then "feed" else "feeds"
    throw s!"Only {quotes.size} BTC price {word} responded for {currency}; need at least 3 to compute a manipulation-resistant median"
  for q in quotes do
    if q.price.numerator == 0 || q.price.denominator == 0 then throw "Invalid BTC price"
  let sources := quotes.qsort fun a b =>
    a.price.lt b.price || (a.price.equal b.price && a.source < b.source)
  let some price := median (sources.map (·.price)) | throw "At least one BTC price source is required"
  return ⟨currency, price, sources⟩

def breadcrumb (p : Price) : String :=
  s!"[price-feed] median BTC/{p.currency} = {p.price.fixed 2} from {p.sources.size} feeds: " ++
    String.intercalate ", " (p.sources.toList.map (·.source)) ++ "\n"

def response (feed : Feed) (currency : String) (r : HttpCurl.Response) : Except String (Option Exact) := do
  if r.status == 404 && feed.missing404 then return none
  if r.status ≥ 400 then throw s!"{feed.label} returned an unsuccessful status: HTTP {r.status}"
  let body := Lightning.Lnurl.lossyUtf8 r.body
  parse feed.source currency body

def fetchOne (feed : Feed) (currency : String) (base : String)
    (request : HttpCurl.Request → IO (Except HttpCurl.Error HttpCurl.Response)) : IO (Except String (Option Exact)) := do
  let result ← request {
    url := base ++ feed.path currency
    headers := #[("User-Agent", "cyberkrill/0.1.0")]
    connectTimeoutMs := 0
    totalTimeoutMs := 8000 }
  return match result with
    | .error error => .error s!"{feed.label} request failed: {repr error}"
    | .ok r => response feed currency r

structure Result where
  price : Except String Price
  diagnostics : String

/-- Dedicated tasks are required because the transport blocks its calling
thread. All tasks start before any wait; collection follows completion order. -/
def fetch (currency : String) (bases : Array String := feeds.map (·.base))
    (request := HttpCurl.request) : IO Result := do
  if bases.size != feeds.size then return ⟨.error "Incomplete feed URLs", ""⟩
  let mut tasks := []
  for i in [:feeds.size] do
    let feed := feeds[i]!
    let base := bases[i]!
    let task ← IO.asTask (do
      let result ← fetchOne feed currency base request
      return (feed.source, result)) Task.Priority.dedicated
    tasks := task :: tasks
  let mut quotes := #[]
  let mut issues := #[]
  for _ in [:feeds.size] do
    let first :: rest := tasks | break
    let (result, remaining) ← IO.waitAny' (first :: rest)
    tasks := remaining
    match result with
    | .error error => issues := issues.push s!"feed task failed: {error}"
    | .ok (source, .error error) => issues := issues.push s!"{source}: {error}"
    | .ok (source, .ok none) => issues := issues.push s!"{source}: no {currency} quote"
    | .ok (source, .ok (some price)) => quotes := quotes.push ⟨source, price⟩
  let summary := if issues.isEmpty then "" else
    s!"BTC price feed issues for {currency}: " ++ String.intercalate "; " issues.toList
  match aggregate currency quotes with
  | .error e => return ⟨.error (if summary.isEmpty then e else summary ++ ": " ++ e), ""⟩
  | .ok p => return ⟨.ok p, spreadWarning p ++ (if summary.isEmpty then "" else "[price-feed] " ++ summary ++ "\n")⟩

end Cyberkrill.PriceFeed
