/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

/-! # HttpCurl

A bounded HTTP(S) client over libcurl. Requests are synchronous IO actions. -/

namespace HttpCurl

/-- Report the linked libcurl and TLS backend versions; performs no network I/O. -/
@[extern "lck_curl_version"]
opaque version : IO String

/-- Supported HTTP methods. GET requests cannot carry a body. -/
inductive Method where
  /-- Request the resource without a request body. -/
  | get
  /-- Submit an optional body to the resource. -/
  | post
  deriving BEq, Repr

/-- Request settings. Timeouts are milliseconds (zero uses curl's defaults: connect
300 seconds, total unlimited). The limit counts body bytes, inclusive. `caFallback`
is a test-only replacement for the system bundle probe list. -/
structure Request where
  /-- HTTP verb; defaults to GET. -/
  method : Method := .get
  /-- An HTTP(S) URL without embedded credentials. -/
  url : String
  /-- Header name/value pairs; duplicate names are preserved. -/
  headers : Array (String × String) := #[]
  /-- POST body bytes. `some` is rejected for GET, even if empty. -/
  body : Option ByteArray := none
  /-- Optional HTTP basic-auth username and password. -/
  basicAuth : Option (String × String) := none
  /-- Inclusive body-byte limit, representable in the platform's address size. -/
  maxResponseBytes : USize := 1048576
  /-- Connect timeout in milliseconds; zero means curl's 300-second default. -/
  connectTimeoutMs : UInt32 := 5000
  /-- Whole-transfer timeout in milliseconds; zero disables this timeout. -/
  totalTimeoutMs : UInt32 := 30000
  /-- Test-only CA path replacing system probes; SSL_CERT_FILE still wins. -/
  caFallback : Option System.FilePath := none

/-- HTTP status, response headers (including duplicates), and unmodified body bytes.
HTTP error statuses such as 401 are ordinary responses. -/
structure Response where
  /-- Final HTTP status code. -/
  status : UInt32
  /-- Lowercase names and trimmed UTF-8 values, including duplicate headers. -/
  headers : Array (String × String)
  /-- Unmodified response body bytes. -/
  body : ByteArray

/-- Transport failures. Messages contain fixed descriptions or libcurl's static error
text, never request data.
`tooLarge` carries the requested body-byte limit; other variants carry a CURLcode. -/
inductive Error where
  /-- Host resolution or connection establishment failed. -/
  | connect (code : UInt32) (message : String)
  /-- The connection or whole-transfer deadline expired. -/
  | timeout (code : UInt32) (message : String)
  /-- TLS negotiation or certificate verification failed. -/
  | tls (code : UInt32) (message : String)
  /-- The response body exceeded the inclusive requested limit. -/
  | tooLarge (limit : USize)
  /-- Another curl failure, or invalid input detected by the wrapper. -/
  | curl (code : UInt32) (message : String)
  deriving Repr

/-- A final acquired response may have a failed body/trailer read. Receive,
partial-file and malformed-trailer errors enter this channel; byte limits and
deadlines remain transport errors. -/
structure AcquiredResponse extends Response where
  bodyError : Option Error := none
  /-- Detailed values preserve arbitrary accepted bytes and first-field identity.
  Supplied capabilities may omit this and use the UTF-8 response headers. -/
  headerBytes : Option (Array (String × ByteArray)) := none

private structure RawResponse where
  headers : ByteArray
  body : ByteArray
  code : UInt32
  status : UInt32

@[extern "lck_curl_request"]
private opaque perform (post : Bool) (url : @& String) (headers : @& Array String)
    (body : @& ByteArray) (auth : Bool) (user password : @& String)
    (limit : USize) (connectMs totalMs : UInt32) (hasFallback : Bool)
    (fallback : @& String) (http1 : Bool) : IO RawResponse

@[extern "lck_curl_error_message"]
private opaque errorMessage (code : UInt32) : IO String

private def invalid : Except Error AcquiredResponse :=
  .error (.curl 43 "Invalid request input")

private def hasNul (s : String) : Bool := s.contains '\x00'

private def headerName (s : String) : Bool :=
  !s.isEmpty && s.toList.all (fun c => c.toNat < 128 &&
    (c.isAlphanum || "!#$%&'*+-.^_`|~".contains c))

/-- Remember the final header terminator even when curl subsequently supplies
trailer lines. Scan bounded raw bytes so error precedence does not require UTF-8. -/
private def finalHeadersComplete (bytes : ByteArray) : Bool := Id.run do
  let mut complete := false
  let mut interim := false
  for i in [:bytes.size] do
    if !complete && (i == 0 || bytes[i - 1]! == 10) && i + 5 ≤ bytes.size &&
        bytes[i]! == 72 && bytes[i + 1]! == 84 && bytes[i + 2]! == 84 &&
        bytes[i + 3]! == 80 && bytes[i + 4]! == 47 then
      complete := false
      -- Only interim responses permit another status block. Once final headers
      -- end, subsequent lines are trailers even if they start with HTTP/.
      interim := false
      for j in [i + 5:bytes.size] do
        if bytes[j]! == 10 then break
        if bytes[j]! == 32 then
          interim := j + 1 < bytes.size && bytes[j + 1]! == 49
          break
    if i ≥ 1 && bytes[i]! == 10 && (bytes[i - 1]! == 10 ||
        (i ≥ 2 && bytes[i - 2]! == 10 && bytes[i - 1]! == 13)) then
      if !interim then complete := true
  return complete

private def valueByte (b : UInt8) : Bool :=
  b == 9 || (32 ≤ b && b != 127)

private def trimValue (bytes : ByteArray) : ByteArray := Id.run do
  let mut first := 0
  let mut last := bytes.size
  while first < last && (bytes[first]! == 32 || bytes[first]! == 9) do first := first + 1
  while first < last && (bytes[last - 1]! == 32 || bytes[last - 1]! == 9) do last := last - 1
  return bytes.extract first last

private def parseField (line : ByteArray) : Option (String × ByteArray) := do
  let colon ← line.data.findIdx? (· == 58)
  let name ← String.fromUTF8? (line.extract 0 colon)
  unless headerName name do none
  let value := line.extract (colon + 1) line.size
  unless value.data.all valueByte do none
  return (name.toLower, trimValue value)

private def parseStatus (line : ByteArray) : Option (Bool × Nat) := do
  unless line.size ≥ 12 do none
  let version := line.extract 0 8
  unless version == "HTTP/1.0".toUTF8 || version == "HTTP/1.1".toUTF8 do none
  unless line[8]! == 32 do none
  let digits := line.extract 9 12
  unless digits.data.all (fun b => 48 ≤ b && b ≤ 57) do none
  let status := (digits[0]!.toNat - 48) * 100 + (digits[1]!.toNat - 48) * 10 + digits[2]!.toNat - 48
  unless status ≥ 100 do none
  if line.size > 12 then
    unless line[12]! == 32 && (line.extract 13 line.size).data.all valueByte do none
  return (version == "HTTP/1.0".toUTF8, status)

/-- hyper 1.8.1 Client::decoder: special bodyless statuses precede framing;
Transfer-Encoding takes precedence over Content-Length. -/
private def validFraming (http10 : Bool) (status : Nat)
    (headers : Array (String × ByteArray)) : Bool := Id.run do
  if status < 200 || status == 204 || status == 304 then return true
  if headers.any (fun h => h.1 == "transfer-encoding") then return !http10
  let mut length : Option Nat := none
  for (name, bytes) in headers do
    if name != "content-length" then continue
    let some text := String.fromUTF8? bytes | return false
    for part in text.splitOn "," do
      let part := part.trimAscii.toString
      if part.isEmpty || !part.toList.all (fun c => '0' ≤ c && c ≤ '9') then return false
      let mut n := 0
      for c in part.toList do
        n := n * 10 + c.toNat - 48
        if n > 18446744073709551615 then return false
      if n > 18446744073709551613 || (length.isSome && length != some n) then return false
      length := some n
  return true

/-- Only length-delimited bodies need reconciliation with delivered bytes.
The head parser has already checked every length spelling and repeated value.
Bodyless statuses and any Transfer-Encoding retain their library body handling. -/
private def shortContentLength (status : UInt32)
    (headers : Array (String × ByteArray)) (size : Nat) : Bool := Id.run do
  if status < 200 || status == 204 || status == 304 then return false
  if headers.any (fun h => h.1 == "transfer-encoding") then return false
  let some (_, bytes) := headers.find? (fun h => h.1 == "content-length") | return false
  let some text := String.fromUTF8? bytes | return false
  let some length := (text.splitOn ",").head!.trimAscii.toString.toNat? | return false
  return size < length

private structure ParsedHeaders where
  headers : Array (String × ByteArray) := #[]
  acquired : Bool := false
  invalidHead : Bool := false
  invalidTrailer : Bool := false

/-- Byte grammar from httparse 1.10.1, applied separately to each response head
and to trailers. hyper refuses a completed set of 100 trailers; its byte limit includes
the final CRLF and rejects on reaching 16 KiB. libcurl omits that final CRLF
from its trailer callbacks, so account for it explicitly when trailers exist. -/
private def parseDetailedHeaders (bytes : ByteArray) : ParsedHeaders := Id.run do
  let mut result : ParsedHeaders := {}
  let mut start := 0
  let mut readingHeaders := false
  let mut interimBlock := false
  let mut http10 := false
  let mut status := 0
  let mut fields := 0
  let mut trailerCount := 0
  let mut trailerBytes := 0
  for i in [:bytes.size] do
    if bytes[i]! != 10 then continue
    let stop := if i > start && bytes[i - 1]! == 13 then i - 1 else i
    let line := bytes.extract start stop
    let wireSize := i + 1 - start
    start := i + 1
    if result.acquired then
      if !line.isEmpty then
        trailerCount := trailerCount + 1
        trailerBytes := trailerBytes + wireSize
        if (parseField line).isNone || trailerCount ≥ 100 || trailerBytes + 2 ≥ 16384 then
          result := { result with invalidTrailer := true }
    else if !readingHeaders then
      if line.isEmpty then continue
      match parseStatus line with
      | none => result := { result with invalidHead := true }
      | some (version, code) =>
        result := { result with headers := #[] }
        readingHeaders := true
        fields := 0
        http10 := version
        status := code
        interimBlock := code < 200 && code != 101
    else if line.isEmpty then
      if !validFraming http10 status result.headers then
        result := { result with invalidHead := true }
      if !interimBlock then result := { result with acquired := true }
      readingHeaders := false
    else
      fields := fields + 1
      if fields > 100 then result := { result with invalidHead := true }
      match parseField line with
      | none => result := { result with invalidHead := true }
      | some field => result := { result with headers := result.headers.push field }
  return result

/-- Send a GET or POST with no redirects or environment proxies. Only HTTP(S) URLs
without embedded credentials are accepted. NUL in C-string inputs, invalid header
names, CR/LF in values, and GET bodies return a structured error before connecting.
HTTPS selects SSL_CERT_FILE per request, then the test hook, then system probes. -/
private def requestImpl (req : Request) (detailed : Bool) : IO (Except Error AcquiredResponse) := do
  if hasNul req.url || !(req.url.startsWith "http://" || req.url.startsWith "https://") then
    return invalid
  let authority := ((req.url.splitOn "://").drop 1).headD ""
  if (authority.toList.takeWhile (fun c => c != '/' && c != '?' && c != '#')).contains '@' then
    return invalid
  if req.method == .get && req.body.isSome then return invalid
  for (name, value) in req.headers do
    if !headerName name || hasNul value || value.contains '\r' || value.contains '\n' then
      return invalid
  let (user, password) := req.basicAuth.getD ("", "")
  let fallback := req.caFallback.map (·.toString) |>.getD ""
  if hasNul user || user.contains ':' || hasNul password || hasNul fallback then return invalid
  let raw ← perform (req.method == .post) req.url
    (req.headers.map fun (k, v) =>
      if v.toList.all (fun c => c == ' ' || c == '\t') then k ++ ";" else k ++ ": " ++ v)
    (req.body.getD ByteArray.empty)
    req.basicAuth.isSome user password req.maxResponseBytes req.connectTimeoutMs
    req.totalTimeoutMs req.caFallback.isSome fallback detailed
  let code := raw.code
  if code == 1000 || code == 63 then return .error (.tooLarge req.maxResponseBytes)
  if code == 6 || code == 7 then return .error (.connect code "Connection failed")
  if code == 28 then return .error (.timeout code "Request timed out")
  -- The header callback's fixed 65,536-byte cap reports a write error. Body
  -- overflow has its distinct code above; neither becomes a body-read error.
  if code == 23 then
    let description ← errorMessage code
    return .error (.curl code description)
  if [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91, 98].contains code then
    return .error (.tls code "TLS or certificate failure")
  -- A status alone does not prove final headers were acquired (e.g. interim
  -- 100 or an interrupted header). Require a completed final header block.
  let parsed := if detailed then parseDetailedHeaders raw.headers else {}
  let acquired := parsed.acquired && finalHeadersComplete raw.headers && !parsed.invalidHead
  let incomplete := acquired && code != 0
  if code != 0 && (!detailed || !incomplete) then return .error (.curl code (← errorMessage code))
  let mut headers : Array (String × String) := #[]
  let mut headerBytes : Option (Array (String × ByteArray)) := none
  let mut bodyError : Option Error := none
  if detailed then
    if !acquired then return .error (.curl 8 "Invalid or incomplete response headers")
    let description ← if incomplete then errorMessage code else pure ""
    let invalidTrailer := parsed.invalidTrailer
    bodyError := if invalidTrailer then some (.curl 8 "Invalid response trailer")
      else if incomplete then some (.curl code description)
      else if shortContentLength raw.status parsed.headers raw.body.size then
        some (.curl 18 "Incomplete response body")
      else none
    headers := parsed.headers.map fun (name, value) => (name, (String.fromUTF8? value).getD "")
    headerBytes := some parsed.headers
  else
    let some headerText := String.fromUTF8? raw.headers
      | return .error (.curl 8 "Invalid response header encoding")
    for line in headerText.splitOn "\r\n" do
      match line.splitOn ":" with
      | name :: value :: rest =>
        headers := headers.push (name.toLower, (String.intercalate ":" (value :: rest)).trimAscii.toString)
      | _ => pure ()
  return .ok {
    status := raw.status
    headers := headers
    body := raw.body
    bodyError := bodyError
    headerBytes := headerBytes }

/-- Opt-in final response acquisition, with incomplete bodies kept separate.
Interim or incomplete final headers never count as acquired responses. -/
def requestDetailed (req : Request) : IO (Except Error AcquiredResponse) :=
  requestImpl req true

/-- Check delivered HTTP/1 response heads and trailers without a request, using
the detailed operation's byte grammar and aggregate header work bound. -/
def validResponseHeaders (bytes : ByteArray) : Bool :=
  if bytes.size > 65536 then false else
    let parsed := parseDetailedHeaders bytes
    parsed.acquired && !parsed.invalidHead && !parsed.invalidTrailer

/-- Legacy whole-transfer operation: incomplete bodies remain transport errors.
The opt-in requestDetailed shares every input guard and resource bound. -/
def request (req : Request) : IO (Except Error Response) := do
  let result ← requestImpl req false
  return do
    let acquired ← result
    match acquired.bodyError with
    | some error => throw error
    | none => return acquired.toResponse

end HttpCurl
