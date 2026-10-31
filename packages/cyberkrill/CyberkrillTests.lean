/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Helpers
import CyberkrillTests.Capabilities
import CyberkrillTests.Mnemonic
import CyberkrillTests.Output
import CyberkrillTests.PrivateOutput
import CyberkrillTests.Offline
import CyberkrillTests.Rpc

open CyberkrillTests

private def suite (name : String) (action : IO Unit) : IO Unit := do
  let out ← IO.getStdout
  let err ← IO.getStderr
  out.flush
  err.putStrLn s!"suite start: {name}"
  err.flush
  try action finally
    out.flush
    err.flush
  err.putStrLn s!"suite complete: {name}"
  err.flush

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | ["--rpc-pure"] => rpcPure
    | ["--rpc-request"] => rpcRequest
    | ["--rpc-replay", url, path] => rpcReplay url path
    | ["--rpc-continuation", url, path] => rpcContinuation url path
    | ["--rpc-continuation-auth", url, path] => rpcContinuationFailure url path
    | ["--injected"] => injected
    | ["--injected-plus"] => injected true
    | ["--private-output", path] => privateOutput path
    | ["--private-output-nul", path] => privateOutput path true
    | ["--word-count-rejections"] => wordCountRejections
    | ["--output-refusal", n] =>
      let some i := n.toNat? | throw (IO.userError "invalid output selector")
      outputRefusal i
    | ["--output-boundaries"] => outputBoundaries
    | ["--offline-boundaries"] => offlineBoundaries
    | ["--output-equals", n] =>
      let some i := n.toNat? | throw (IO.userError "invalid output selector")
      outputEquals i
    | ["--check", name] => helpers name; capabilities name
    | [] =>
      suite "rpc-pure" rpcPure
      suite "helpers" (helpers "all")
      suite "capabilities" (capabilities "all")
      suite "mnemonic-errors" mnemonicErrors
      suite "word-count-rejections" wordCountRejections
      suite "output-boundaries" outputBoundaries
      suite "offline-boundaries" offlineBoundaries
      suite "CLI and harness driver" do
        let result ← IO.Process.output { cmd := "python3", args := #["-B", "test/driver.py"] }
        (← IO.getStdout).putStr result.stdout
        (← IO.getStderr).putStr result.stderr
        check "CLI and harness driver" (result.exitCode == 0)
      suite "RPC client replay driver" do
        let rpc ← IO.Process.output { cmd := "python3", args := #["-B", "test/rpc-client.py"] }
        (← IO.getStdout).putStr rpc.stdout
        (← IO.getStderr).putStr rpc.stderr
        check "RPC client replay driver" (rpc.exitCode == 0)
      suite "RPC network safety driver" do
        let safety ← IO.Process.output { cmd := "python3", args := #["-B", "test/network-safety.py"] }
        (← IO.getStdout).putStr safety.stdout
        (← IO.getStderr).putStr safety.stderr
        check "RPC network safety driver" (safety.exitCode == 0)
    | _ => throw (IO.userError "invalid test selector")
    return 0
  catch e =>
    (← IO.getStderr).putStrLn e.toString
    return 1
