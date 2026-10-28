/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cyberkrill
namespace CyberkrillTests
open Cyberkrill Lean

def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw (IO.userError s!"assertion failed: {name}")

def getOk {ε α : Type} (label : String) : Except ε α → IO α
  | .ok a => pure a
  | .error _ => throw (IO.userError s!"assertion failed: {label}")

def hex (s : String) : IO ByteArray :=
  match Bitcoin.Hex.decode s with
  | some b => pure b
  | none => throw (IO.userError "assertion failed: fixture hex")

def text (j : Json) (key : String) : IO String :=
  getOk "fixture string" (j.getObjValAs? String key)

def bytes (j : Json) (key : String) : IO ByteArray := do hex (← text j key)

def load (path : String) : IO Json := do
  getOk "fixture JSON" (Json.parse (← IO.FS.readFile path))

def counted (name : String) (n expected : Nat) : IO Unit := do
  check s!"{name} count" (n == expected)
  IO.println s!"{name}: {n}/{expected}"

def runCase (services : Services) (args : List String) : IO (UInt32 × String × String) := do
  let out ← IO.mkRef ""
  let err ← IO.mkRef ""
  let code ← runWith version { services with
    stdout := fun s => out.modify (· ++ s), stderr := fun s => err.modify (· ++ s) } args
  return (code, ← out.get, ← err.get)

def selected (only name : String) (action : IO Unit) : IO Unit :=
  if only == "all" || only == name then action else pure ()
end CyberkrillTests
