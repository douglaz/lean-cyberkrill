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

private structure RawResponse where
  headers : ByteArray
  body : ByteArray
  code : UInt32
  status : UInt32

@[extern "lck_curl_request"]
private opaque perform (post : Bool) (url : @& String) (headers : @& Array String)
    (body : @& ByteArray) (auth : Bool) (user password : @& String)
    (limit : USize) (connectMs totalMs : UInt32) (hasFallback : Bool)
    (fallback : @& String) : IO RawResponse

@[extern "lck_curl_error_message"]
private opaque errorMessage (code : UInt32) : IO String

private def invalid : Except Error Response :=
  .error (.curl 43 "Invalid request input")

private def hasNul (s : String) : Bool := s.contains '\x00'

private def headerName (s : String) : Bool :=
  !s.isEmpty && s.toList.all (fun c => c.toNat < 128 &&
    (c.isAlphanum || "!#$%&'*+-.^_`|~".contains c))

/-- Send a GET or POST with no redirects or environment proxies. Only HTTP(S) URLs
without embedded credentials are accepted. NUL in C-string inputs, invalid header
names, CR/LF in values, and GET bodies return a structured error before connecting.
HTTPS selects SSL_CERT_FILE per request, then the test hook, then system probes. -/
def request (req : Request) : IO (Except Error Response) := do
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
    req.totalTimeoutMs req.caFallback.isSome fallback
  let code := raw.code
  if code == 1000 || code == 63 then return .error (.tooLarge req.maxResponseBytes)
  if code == 6 || code == 7 then return .error (.connect code "Connection failed")
  if code == 28 then return .error (.timeout code "Request timed out")
  if [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91, 98].contains code then
    return .error (.tls code "TLS or certificate failure")
  if code != 0 then return .error (.curl code (← errorMessage code))
  let some headerText := String.fromUTF8? raw.headers
    | return .error (.curl 8 "Invalid response header encoding")
  let mut headers := #[]
  for line in headerText.splitOn "\r\n" do
    match line.splitOn ":" with
    | name :: value :: rest =>
      headers := headers.push (name.toLower, (String.intercalate ":" (value :: rest)).trimAscii.toString)
    | _ => pure ()
  return .ok { status := raw.status, headers, body := raw.body }

end HttpCurl
