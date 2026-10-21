/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import HttpCurl
import HttpCurlTestSupport
import Lean.Data.Json
import Std.Async.System

open HttpCurl

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

private def success (name : String) (value : Except Error Response) : IO Response := do
  match value with
  | .ok response => return response
  | .error error => throw <| IO.userError s!"assertion failed: {name}: {repr error}"

private def isTls : Except Error Response → Bool
  | .error (.tls ..) => true
  | _ => false

private def is2xx (r : Response) : Bool := r.status >= 200 && r.status < 300

private def caseNames : Array String :=
  #["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9",
    "T10", "T11", "T12", "T13",
    "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"]

private def runCase (name http tls closed ca : String) : IO Unit := do
  let base : Request := { url := http ++ "/echo", totalTimeoutMs := 3000 }
  let tlsReq : Request := { base with url := tls ++ "/echo" }
  match name with
  | "T1" =>
    let r ← success "T1 GET" (← request { base with headers := #[("X-Echo", "get-value")] })
    check "T1 status" (is2xx r)
    check "T1 request header" (r.headers.contains ("x-echo-x-echo", "get-value"))
    check "T1 response header" (r.headers.contains ("content-type", "application/octet-stream"))
  | "T2" =>
    let body := ByteArray.mk #[0, 1, 13, 10, 127, 128, 255, 0]
    let r ← success "T2 POST" (← request { base with
      method := .post
      body := some body
      headers := #[("X-Echo", "post-value"), ("X-Other", "second-value")] })
    check "T2 body" (r.body == body)
    check "T2 headers" (r.headers.contains ("x-echo-x-echo", "post-value") &&
      r.headers.contains ("x-echo-x-other", "second-value"))
  | "T3" =>
    let r ← success "T3 auth" (← request { base with
      url := http ++ "/auth"
      basicAuth := some ("synthetic-user", "synthetic-password") })
    check "T3 right auth" (is2xx r)
  | "T4" =>
    let r ← success "T4 normal response" (← request { base with
      url := http ++ "/auth"
      basicAuth := some ("wrong-user", "wrong-password") })
    check "T4 status 401" (r.status == 401)
  | "T5" =>
    let start ← IO.monoMsNow
    let result ← request { base with url := http ++ "/oversize", maxResponseBytes := 64 }
    check "T5 streaming size" (match result with | .error (.tooLarge n) => n == 64 | _ => false)
    check "T5 abort bound" ((← IO.monoMsNow) - start <= 1500)
  | "T6" =>
    let r ← success "T6 inclusive limit" (← request { base with
      url := http ++ "/exact"
      maxResponseBytes := 64 })
    check "T6 exact body" (r.body == ByteArray.mk (Array.replicate 64 120))
  | "T7" =>
    let start ← IO.monoMsNow
    let result ← request { base with url := http ++ "/stall", totalTimeoutMs := 300 }
    check "T7 timeout kind" (match result with | .error (.timeout 28 _) => true | _ => false)
    check "T7 timeout bound" ((← IO.monoMsNow) - start <= 1500)
  | "T8" =>
    check "T8 connect kind" (match ← request { base with url := closed } with
      | .error (.connect 7 _) => true | _ => false)
  | "T9" =>
    let result ← request { base with
      url := closed
      basicAuth := some ("synthetic-user", "synthetic-password") }
    let .error error := result | throw <| IO.userError "assertion failed: T9 expected error"
    let rendered := reprStr error
    check "T9 user redaction" ((rendered.splitOn "synthetic-user").length == 1)
    check "T9 password redaction" ((rendered.splitOn "synthetic-password").length == 1)
  | "T10" =>
    let r ← success "T10 headers" (← request { base with
      headers := #[("X-Empty", ""), ("X-Full", "full-value"), ("X-Whitespace", " \t ")] })
    check "T10 empty header present" (r.headers.contains ("x-echo-x-empty", ""))
    check "T10 full header" (r.headers.contains ("x-echo-x-full", "full-value"))
    check "T10 whitespace header present" (r.headers.contains ("x-echo-x-whitespace", ""))
  | "T11" =>
    check "T11 query at-sign" (is2xx (← success "T11 query at-sign"
      (← request { base with url := http ++ "?q=a@b" })))
    let userinfo := "http://user:pw@" ++ ((http.splitOn "://").drop 1).headD "" ++ "/echo"
    check "T11 reject userinfo" (match ← request { base with url := userinfo } with
      | .error (.curl 43 "Invalid request input") => true | _ => false)
  | "T12" =>
    let result ← request { base with url := http ++ "/empty-reply" }
    check "T12 curl code 52" (match result with | .error (.curl 52 _) => true | _ => false)
    check "T12 curl message" (match result with
      | .error (.curl 52 message) => message == "Server returned nothing (no headers, no data)"
      | _ => false)
  | "T13" =>
    check "T13 one byte over limit" (match ← request { base with
        url := http ++ "/one-over", maxResponseBytes := 64 } with
      | .error (.tooLarge n) => n == 64 | _ => false)
  | "C1" => check "C1 environment CA" (is2xx (← success "C1 environment CA" (← request tlsReq)))
  | "C2" => check "C2 untrusted CA" (isTls (← request tlsReq))
  | "C3" => check "C3 ignore NIX CA" (isTls (← request tlsReq))
  | "C4" => check "C4 empty environment CA" (is2xx (← success "C4 empty environment CA"
      (← request { tlsReq with caFallback := some ca })))
  | "C5" => check "C5 fallback hook" (is2xx (← success "C5 fallback hook"
      (← request { tlsReq with caFallback := some ca })))
  | "C6" => check "C6 missing hook" (isTls (← request { tlsReq with caFallback := some (ca ++ ".missing") }))
  | "C7" => check "C7 plain HTTP without CA" (is2xx (← success "C7 plain HTTP without CA" (← request base)))
  | "C8" => check "C8 environment precedence" (isTls (← request { tlsReq with caFallback := some ca }))
  | "C9" =>
    check "C9 initial missing CA" (isTls (← request tlsReq))
    Std.Async.System.setEnvVar "SSL_CERT_FILE" ca
    check "C9 per-request CA" (is2xx (← success "C9 per-request CA" (← request tlsReq)))
  | _ => throw <| IO.userError s!"unknown case: {name}"

private def stubNames : Array String :=
  #["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13"]

private def replayConfig : HttpCurlTestSupport.Config :=
  { recordings := #["../http-curl/test/example.json"] }

private def parsed (text : String) : IO Lean.Json :=
  IO.ofExcept (Lean.Json.parse text)

private def field (json : Lean.Json) (key : String) : IO Lean.Json :=
  IO.ofExcept (json.getObjVal? key)

private def stringField (json : Lean.Json) (key : String) : IO String := do
  IO.ofExcept ((← field json key).getStr?)

private def replayRequest (stub : HttpCurlTestSupport.Stub) (path : String)
    (body : Option String := none) (headers : Array (String × String) := #[]) : IO Response := do
  success "stub transport" (← request {
    url := stub.url ++ path, method := if body.isSome then .post else .get
    body := body.map String.toUTF8, headers, totalTimeoutMs := 1000 })

private def textBody (r : Response) : String := String.fromUTF8! r.body

private def runStubCase (name : String) : IO Unit := do
  let withReplay := HttpCurlTestSupport.withStub replayConfig
  match name with
  | "S1" => withReplay fun stub => do
    check "S1 method near miss" ((← replayRequest stub "/verb").status == 599)
    check "S1 method match" (textBody (← replayRequest stub "/verb" (some "")) == "post")
    let body := "{\"n\":123456789012345678901234567890.1,\"nested\":{\"a\":2,\"z\":[true,1e-1]}}"
    check "S1 path near miss" ((← replayRequest stub "/other?a=%2F&b=2" body).status == 599)
    check "S1 query near miss" ((← replayRequest stub "/match?b=2&a=%2F" body).status == 599)
    check "S1 percent near miss" ((← replayRequest stub "/match?a=/&b=2" body).status == 599)
    let path := "/match?a=%2F&b=2"
    check "S1 body near miss" ((← replayRequest stub path (some "{} ")).status == 599)
    let boolMiss := body.replace "true" "1"
    check "S1 boolean distinct" ((← replayRequest stub path boolMiss).status == 599)
    let precisionMiss := body.replace "890.1" "890.2"
    check "S1 precision distinct" ((← replayRequest stub path precisionMiss).status == 599)
    let arrayMiss := body.replace "[true,1e-1]" "[1e-1,true]"
    check "S1 array order" ((← replayRequest stub path arrayMiss).status == 599)
    check "S1 key order and canonical exponent" (textBody (← replayRequest stub path body) == "first")
    check "S1 canonical trailing zero" (textBody (← replayRequest stub path
      (body.replace "1e-1" "0.10")) == "second")
    check "S1 ordered responses" (textBody (← replayRequest stub path
      (body.replace "1e-1" "0.1")) == "third")
  | "S2" => withReplay fun stub => do
    check "S2 rpc method near miss" ((← replayRequest stub "/rpc"
      "{\"method\":\"other\",\"params\":[]}").status == 599)
    check "S2 rpc params near miss" ((← replayRequest stub "/rpc"
      "{\"method\":\"synthetic\",\"params\":[1]}").status == 599)
    for (shape, label) in #[
        ("{\"jsonrpc\":\"2.0\",\"id\":\"cyberkrill\",\"method\":\"synthetic\",\"params\":[\"x\",0.1]}", "string id"),
        ("{\"id\":7,\"method\":\"synthetic\",\"params\":{\"n\":1.0}}", "numeric id"),
        ("{\"method\":\"synthetic\",\"params\":[]}", "no jsonrpc")] do
      let r ← replayRequest stub "/rpc" shape
      check s!"S2 variant {label}" (r.status == 200)
      check s!"S2 variant {label}" ((← stringField (← parsed (textBody r)) "result") == "rpc-ok")
      check s!"S2 exhausted variant {label}" ((← replayRequest stub "/rpc" shape).status == 599)
  | "S3" => withReplay fun stub => do
    let missing ← replayRequest stub "/auth"
    check "S3 missing auth" (missing.status == 401 && textBody missing == "synthetic unauthorized")
    check "S3 wrong auth" ((← replayRequest stub "/auth" none
      #[("Authorization", "Bearer wrong-synthetic")]).status == 401)
    check "S3 right auth no consumption" (textBody (← replayRequest stub "/auth" none
      #[("Authorization", "Bearer synthetic-test-only")]) == "authorized")
  | "S4" => withReplay fun stub => do
    let paths := #["/sequence", "/missing?x=1", "/sequence", "/auth"]
    let mut responses := #[]
    for path in paths do responses := responses.push (← replayRequest stub path)
    let some unmatched := responses[1]? | throw <| IO.userError "S4 missing unmatched response"
    let some exhausted := responses[2]? | throw <| IO.userError "S4 missing exhausted response"
    check "S4 unmatched status" (unmatched.status == 599)
    let diagnostic ← parsed (textBody unmatched)
    check "S4 diagnostic method" ((← stringField diagnostic "method") == "GET")
    check "S4 diagnostic path" ((← stringField diagnostic "path") == "/missing?x=1")
    check "S4 diagnostic body" ((← stringField diagnostic "body") == "")
    check "S4 unmatched reason" ((← stringField diagnostic "error") == "unmatched")
    check "S4 exhausted status" (exhausted.status == 599)
    check "S4 exhausted reason" ((← stringField (← parsed (textBody exhausted)) "error") == "exhausted")
    let lines := (← stub.readLog).splitOn "\n" |>.filter (!·.isEmpty)
    check "S4 log complete" (lines.length == 4)
    let mut seen := #[]
    for line in lines do
      let value ← parsed line
      seen := seen.push (← stringField value "path")
      check "S4 log method" ((← stringField value "method") == "GET")
      check "S4 log body" ((← stringField value "body") == "")
    check "S4 log order" (seen == paths)
    for (expected, label) in #[("start", "first"), ("last", "last"), ("last", "repeat")] do
      check s!"S4 repeat {label}" (textBody (← replayRequest stub "/repeat") == expected)
  | "S5" | "S6" | "S7" =>
    let port ← if name == "S7" then
        HttpCurlTestSupport.withStub {} (fun s => pure s.port)
      else pure 0
    let savedDir ← IO.mkRef (none : Option System.FilePath)
    HttpCurlTestSupport.withStub { replayConfig with tls := name == "S6", port } fun stub => do
      savedDir.set (some stub.tempDir)
      if name == "S6" then Std.Async.System.setEnvVar "SSL_CERT_FILE" stub.caCert.toString
      if name == "S7" then check "S7 fixed port" (stub.port == port)
      let r ← replayRequest stub "/example?date=synthetic"
      check s!"{name} example status" (r.status == 200)
      check s!"{name} example body" (textBody r == "{\"quote\":0.10}")
      check s!"{name} example header" (r.headers.contains ("x-fixture", "example"))
    if let some dir ← savedDir.get then
      check s!"{name} cleanup" (!(← dir.pathExists))
  | "S8" => HttpCurlTestSupport.withStub {} fun occupied => do
    let result ← IO.Process.output {
      cmd := "python3", args := #["-I", "../http-curl/test/responder.py", "--port",
        toString occupied.port, "--log", (occupied.tempDir / "requests.jsonl").toString] }
    check "S8 occupied exit" (result.exitCode != 0)
    check "S8 occupied no ready" (!(result.stdout.startsWith "READY"))
    let raised ← try
        HttpCurlTestSupport.withStub { port := occupied.port } (fun _ => pure ())
        pure ""
      catch error => pure error.toString
    check "S8 occupied launcher message"
      (raised.startsWith s!"stub failed before READY (exit {result.exitCode}):")
    let missing := (occupied.tempDir / "missing-recording.json").toString
    let raised ← try
        HttpCurlTestSupport.withStub { recordings := #[missing] } (fun _ => pure ())
        pure ""
      catch error => pure error.toString
    check "S8 missing recording launcher message"
      (raised.startsWith "stub failed before READY (exit 1):")
  | "S9" => withReplay fun stub => do
    check "S9 text near miss" ((← replayRequest stub "/text" "other").status == 599)
    let r ← replayRequest stub "/text" "synthetic raw"
    check "S9 recorded 404" (r.status == 404 && textBody r == "recorded absence")
    let binary := ByteArray.mk #[255, 0]
    let r ← success "S9 binary transport" (← request {
      url := stub.url ++ "/binary", method := .post, body := some binary })
    check "S9 binary match" (textBody r == "binary-ok")
    let r ← success "S9 binary diagnostic" (← request {
      url := stub.url ++ "/unknown", method := .post, body := some binary })
    check "S9 diagnostic binary" ((← stringField (← field (← parsed (textBody r)) "body") "base64") == "/wA=")
    let r ← replayRequest stub "/unknown" "synthetic body"
    check "S9 diagnostic text" ((← stringField (← parsed (textBody r)) "body") == "synthetic body")
    check "S9 diagnostic POST" ((← stringField (← parsed (textBody r)) "method") == "POST")
    check "S9 precedence" (textBody (← replayRequest stub "/precedence") == "earlier")
    check "S9 precedence exhausted" ((← replayRequest stub "/precedence").status == 599)
    let lines := (← stub.readLog).splitOn "\n" |>.filter (!·.isEmpty)
    let binaryLog ← parsed lines[2]!
    check "S9 log binary" ((← stringField (← field binaryLog "body") "base64") == "/wA=")
    check "S9 no legacy fallback" ((← replayRequest stub "/echo").status == 599)
  | "S10" =>
    let dirRef ← IO.mkRef (none : Option System.FilePath)
    try
      HttpCurlTestSupport.withStub { tls := true } fun stub => do
        dirRef.set (some stub.tempDir)
        throw <| IO.userError "synthetic callback failure"
    catch _ => pure ()
    let some dir ← dirRef.get | throw <| IO.userError "S10 callback not reached"
    check "S10 exception cleanup" (!(← dir.pathExists))
  | "S11" =>
    let result ← IO.Process.output {
      cmd := (← IO.appPath).toString, args := #["--stub-case", "S6"], cwd := some "../cyberkrill" }
    IO.eprint result.stderr
    check "S11 sibling package TLS" (result.exitCode == 0)
  | "S12" => HttpCurlTestSupport.withStub { tls := true } fun stub => do
    let result ← IO.Process.output {
      cmd := "python3", args := #["-I", "../http-curl/test/check-tls-eof.py",
        stub.tempDir.toString] }
    IO.print result.stdout
    IO.eprint result.stderr
    check "S12 TLS stdin EOF deadline" (result.exitCode == 0)
  | "S13" => withReplay fun stub => do
    for (path, expected) in #[
        ("/content-type/title", "text/html"),
        ("/content-type/lower", "application/synthetic+json"),
        ("/content-type/mixed", "text/synthetic")] do
      let response ← replayRequest stub path
      let types := response.headers.filter (fun header => header.1 == "content-type")
      check s!"S13 single recorded content-type {path}" (types == #[("content-type", expected)])
  | _ => throw <| IO.userError s!"unknown stub case: {name}"

private def runTests (only : Option String) : IO Unit := do
    HttpCurlTestSupport.withStub {} fun http => do
      HttpCurlTestSupport.withStub { tls := true } fun tls => do
        let cert := tls.caCert
        let mut count := 0
        for name in caseNames ++ stubNames do
          if only.isSome && only != some name then continue
          let ssl : Option String :=
            if name == "C1" then some cert.toString
            else if name == "C4" then some ""
            else if name == "C8" || name == "C9" then some (cert.toString ++ ".missing")
            else none
          let nix := if name == "C3" then some cert.toString else none
          let args := if stubNames.contains name then #["--stub-case", name] else
            #["--case", name, http.url, tls.url, s!"http://127.0.0.1:{http.closedPort}/", cert.toString]
          let result ← IO.Process.output {
            cmd := "timeout", args := #["--kill-after=1s", "2s", (← IO.appPath).toString] ++ args
            env := #[("SSL_CERT_FILE", ssl), ("NIX_SSL_CERT_FILE", nix)] }
          IO.print result.stdout
          IO.eprint result.stderr
          check s!"{name} outer deadline (2s)" (result.exitCode != 124 && result.exitCode != 137)
          check s!"{name} child exit {result.exitCode}" (result.exitCode == 0)
          IO.println s!"{name}: PASS"
          count := count + 1
        check "pinned case count" (count == if only.isSome then 1 else 35)
        IO.println s!"http-curl cases: {count}/{if only.isSome then 1 else 35}"

def main (args : List String) : IO Unit := do
  match args with
  | ["--stub-case", name] => runStubCase name
  | ["--case", name, http, tls, closed, ca] => runCase name http tls closed ca
  | ["--only", name] => runTests (some name)
  | [] => runTests none
  | _ => throw <| IO.userError "usage: HttpCurlTests [--only CASE]"
