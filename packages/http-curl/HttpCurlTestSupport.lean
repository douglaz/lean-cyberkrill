/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

/-! Test-only loopback replay launcher, usable from every packages/<pkg> directory. -/
namespace HttpCurlTestSupport

/-- Paths are relative to the caller's working directory. Port zero selects a free port. -/
structure Config where
  tls : Bool := false
  port : UInt16 := 0
  recordings : Array String := #[]
  logPath : Option System.FilePath := none

/-- Resources owned by `withStub`; paths remain valid throughout its callback. -/
structure Stub where
  port : UInt16
  closedPort : UInt16
  caCert : System.FilePath
  logPath : System.FilePath
  tempDir : System.FilePath
  tls : Bool

/-- The literal loopback URL for this stub. -/
def Stub.url (stub : Stub) : String :=
  s!"{if stub.tls then "https" else "http"}://127.0.0.1:{stub.port}"

/-- Read the flushed JSONL request log. -/
def Stub.readLog (stub : Stub) : IO String := IO.FS.readFile stub.logPath

/-- Start, wait for READY, run the callback, then stop and reap the server and remove
its private artifacts, even on exceptions. stderr is inherited, never an undrained pipe.
The child also stops on stdin EOF if its launcher is killed. -/
def withStub (config : Config) (action : Stub → IO α) : IO α := do
  let dir ← IO.FS.createTempDir
  let cert := dir / "ca.crt"
  let key := dir / "server.key"
  let ownedLog := dir / "requests.jsonl"
  let logPath := config.logPath.getD ownedLog
  try
    if config.tls then
      let generated ← IO.Process.output {
        cmd := "openssl", args := #["req", "-x509", "-newkey", "ec",
          "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
          "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost", "-keyout", key.toString,
          "-out", cert.toString] }
      unless generated.exitCode == 0 do
        throw <| IO.userError s!"openssl certificate generation: {generated.stderr}"
    let child ← IO.Process.spawn {
      cmd := "python3"
      args := #["-I", "../http-curl/test/responder.py", "--port", toString config.port,
        "--log", logPath.toString] ++
        (if config.tls then #["--tls", "--cert", cert.toString, "--key", key.toString] else #[]) ++
        config.recordings
      stdin := .piped, stdout := .piped, stderr := .inherit }
    let reaped ← IO.mkRef false
    try
      let ready ← child.stdout.getLine
      let ["READY", port, closed] := ready.trimAscii.toString.splitOn " "
        | do
          let exitCode ← child.wait
          reaped.set true
          throw <| IO.userError s!"stub failed before READY (exit {exitCode}): {ready}"
      let some port := port.toNat? | throw <| IO.userError "invalid stub port"
      let some closed := closed.toNat? | throw <| IO.userError "invalid closed port"
      unless port > 0 && port <= 65535 && closed > 0 && closed <= 65535 do
        throw <| IO.userError "stub port out of range"
      action {
        port := port.toUInt16
        closedPort := closed.toUInt16
        caCert := cert
        logPath := logPath
        tempDir := dir
        tls := config.tls }
    finally
      unless ← reaped.get do
        if (← child.tryWait).isNone then
          child.kill
          let _ ← child.wait
  finally
    for path in #[cert, key, ownedLog] do
      if ← path.pathExists then IO.FS.removeFile path
    IO.FS.removeDir dir

end HttpCurlTestSupport
