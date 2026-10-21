/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import HttpCurl
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

private def withResponder (args : Array String) (action : String → String → IO Unit) : IO Unit := do
  let child ← IO.Process.spawn {
    cmd := "python3", args := #["-I", "test/responder.py"] ++ args
    stdin := .null, stdout := .piped, stderr := .inherit }
  try
    let ready ← child.stdout.getLine
    let ["READY", port, closed] := ready.trimAscii.toString.splitOn " "
      | throw <| IO.userError s!"responder failed to become ready: {ready}"
    check "responder port" (port.toNat?.isSome && closed.toNat?.isSome)
    action port closed
  finally
    child.kill
    let _ ← child.wait

private def runTests (only : Option String) : IO Unit := do
  let dir ← IO.FS.createTempDir
  let cert := dir / "ca.crt"
  let key := dir / "server.key"
  try
    let generated ← IO.Process.output {
      cmd := "openssl", args := #["req", "-x509", "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost", "-keyout", key.toString,
      "-out", cert.toString] }
    check "openssl certificate generation" (generated.exitCode == 0)
    withResponder #[] fun http closed => do
      withResponder #["--cert", cert.toString, "--key", key.toString] fun tls _ => do
        let mut count := 0
        for name in caseNames do
          if only.isSome && only != some name then continue
          let ssl : Option String :=
            if name == "C1" then some cert.toString
            else if name == "C4" then some ""
            else if name == "C8" || name == "C9" then some (cert.toString ++ ".missing")
            else none
          let nix := if name == "C3" then some cert.toString else none
          let result ← IO.Process.output {
            cmd := "timeout", args := #["--kill-after=1s", "2s",
            (← IO.appPath).toString, "--case", name, s!"http://127.0.0.1:{http}",
            s!"https://127.0.0.1:{tls}", s!"http://127.0.0.1:{closed}/", cert.toString]
            env := #[("SSL_CERT_FILE", ssl), ("NIX_SSL_CERT_FILE", nix)] }
          IO.print result.stdout
          IO.eprint result.stderr
          check s!"{name} outer deadline (2s)" (result.exitCode != 124 && result.exitCode != 137)
          check s!"{name} child exit {result.exitCode}" (result.exitCode == 0)
          IO.println s!"{name}: PASS"
          count := count + 1
        check "pinned case count" (count == if only.isSome then 1 else 22)
        IO.println s!"http-curl cases: {count}/{if only.isSome then 1 else 22}"
  finally
    if ← cert.pathExists then IO.FS.removeFile cert
    if ← key.pathExists then IO.FS.removeFile key
    IO.FS.removeDir dir

def main (args : List String) : IO Unit := do
  match args with
  | ["--case", name, http, tls, closed, ca] => runCase name http tls closed ca
  | ["--only", name] => runTests (some name)
  | [] => runTests none
  | _ => throw <| IO.userError "usage: HttpCurlTests [--only CASE]"
