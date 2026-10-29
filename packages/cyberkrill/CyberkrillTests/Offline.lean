/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Cyberkrill Lean

/-- Acquisition failures cannot touch a later boundary. Successful writes use
the closure returned by the one ordinary open, never the private writer. -/
def offlineBoundaries : IO Unit := do
  let primary ← getOk "offline primary" ((← load "../fedimint-invite/test-data/primary.json").getArr?)
  counted "offline primary fixtures" primary.size 3
  let invite ← text primary[0]! "encoded"
  let model ← getOk "offline primary model" (primary[0]!.getObjVal? "decoded")
  let hybrid ← getOk "offline hybrid inventory" ((← load "test/golden/hybrid-inputs.json").getArr?)
  counted "offline hybrid fixtures" hybrid.size 19
  let psbt ← text hybrid[0]! "input_base64"
  let events ← IO.mkRef ([] : List String)
  let service := { productionServices with
    entropy := fun _ => do events.modify (· ++ ["entropy"]); throw (IO.userError "unavailable")
    readStdin := do events.modify (· ++ ["stdin"]); throw (IO.userError "unavailable")
    readFile := fun p => do events.modify (· ++ ["read:" ++ p]); throw (IO.userError "unavailable")
    pathExists := fun p => do events.modify (· ++ ["exists:" ++ p]); return true
    openOrdinaryFile := fun p => do events.modify (· ++ ["open:" ++ p]); throw (IO.userError "unavailable")
    writeFile := fun _ _ => throw (IO.userError "private writer reached") }
  let typedHelp := [
    (["convert-amount", "--as=x", "-hx"], false),
    (["convert-amount", "--as", "x", "-hx"], false),
    (["convert-amount", "--as", "--", "-hx"], false),
    (["generate-mnemonic", "-w", "abc", "-hx"], false),
    (["generate-mnemonic", "-w=abc", "-hx"], false),
    (["generate-mnemonic", "-w", "99999999999", "-hh"], false),
    (["generate-mnemonic", "-w", "--", "-hx"], false),
    (["generate-mnemonic", "-w", "13", "-hx"], true),
    (["generate-mnemonic", "--words=+13", "-hh"], true),
    (["generate-mnemonic", "--words=4294967295", "-hx"], true),
    (["generate-mnemonic", "-hx", "-w", "abc"], true),
    (["convert-amount", "-hx", "--as=x"], true)]
  counted "carried typed help injected cases" typedHelp.length 12
  for (args, help) in typedHelp do
    events.set []
    let (code, out, err) ← runCase service args
    check "carried typed help status" (if help then code == 0 && !out.isEmpty && err.isEmpty
      else code == 1 && out.isEmpty && !err.isEmpty)
    check "carried typed help no actions" ((← events.get).isEmpty)
  for command in ["fm-decode-invite", "fm-encode-invite", "onchain-decode-psbt"] do
    for suffix in [["--help", "--unknown"], ["-h", "-o"],
        ["-o", "dest", "--help", "--network"], ["--help", "--", "extra"],
        ["-hx"], ["-hh"], ["-ho", "--unknown"], ["-h=1"], ["-h--unknown"],
        ["-hq", "--unknown"], ["-ho", "x"], ["-h=x"], ["-hinv.json"],
        ["-hx", "--help"], ["-hh", "-hx"], ["-o-hx", "-hx"],
        ["--output=-hx", "-hh"]] do
      events.set []
      let (code, out, err) ← runCase service (command :: suffix)
      check ("offline ordered help " ++ command) (code == 0 && !out.isEmpty && err.isEmpty)
      check ("offline help no actions " ++ command) ((← events.get).isEmpty)
  let cases := [
    (["onchain-decode-psbt", "source", "--network=bad", "-o", "dest"], [], "invalidNetwork"),
    (["fm-decode-invite", "-o", "dest"], ["stdin"], "inputFailure"),
    (["fm-decode-invite", "bad", "-o", "dest"], ["open:dest"], "outputFailure"),
    (["fm-encode-invite", "source", "-o", "dest"], ["read:source"], "inputFailure"),
    (["onchain-decode-psbt", "source", "-o", "dest"], ["exists:source", "read:source"], "inputFailure")]
  for (args, expected, error) in cases do
    events.set []
    let (code, out, err) ← runCase service args
    check ("offline error order " ++ error) (code == 1 && out.isEmpty && err.startsWith (error ++ ":"))
    check ("offline boundary events " ++ error) ((← events.get) == expected)
  let good := { service with readStdin := pure "{", readFile := fun _ => pure "{" }
  for command in ["fm-encode-invite", "onchain-decode-psbt"] do
    events.set []
    let (code, out, _) ← runCase good [command, "-", "-o", "dest"]
    check ("offline late open " ++ command) (code == 1 && out.isEmpty &&
      (← events.get) == if command == "onchain-decode-psbt" then ["exists:-"] else [])
  for (command, input, content, newline) in [
      ("fm-decode-invite", invite, "", false),
      ("fm-encode-invite", "source", model.compress, true),
      ("onchain-decode-psbt", "source", psbt, true)] do
    events.set []
    let written ← IO.mkRef ""
    let calls ← IO.mkRef 0
    let service := { service with
      readFile := fun p => do events.modify (· ++ ["read:" ++ p]); return content
      openOrdinaryFile := fun p => do
        calls.modify (· + 1)
        events.modify (· ++ ["open:" ++ p])
        return fun value => do
          events.modify (· ++ ["write:" ++ p])
          written.set value }
    let (code, out, err) ← runCase service [command, input, "-o", "dest"]
    check ("offline retained writer " ++ command) (code == 0 && out.isEmpty && err.isEmpty && (← calls.get) == 1)
    let value ← written.get
    check ("offline writer newline " ++ command) (!value.isEmpty && value.endsWith "\n" == newline)
    check ("offline final writer event " ++ command) ((← events.get).getLast? == some "write:dest")
    let failing := { service with
      openOrdinaryFile := fun _ => pure (fun _ => throw (IO.userError "do not disclose this exception")) }
    let (code, out, err) ← runCase failing [command,input,"-o","dest"]
    check ("offline failed write " ++ command) (code == 1 && out.isEmpty && err == Error.outputFailure.message ++ "\n")
  events.set []
  let literalServices := { service with
    pathExists := fun _ => pure false
    readStdin := pure psbt }
  let (code, out, err) ← runCase literalServices ["onchain-decode-psbt", "-"]
  check "offline dash literal" (code == 1 && out.isEmpty && err.startsWith "psbtBase64:" && (← events.get).isEmpty)
  IO.println "offline injected IO: network/read/open/decode/write order, one writer, failures and dash routing"

end CyberkrillTests
