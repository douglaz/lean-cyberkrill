/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Cyberkrill Lean

def generateInvoiceRun : IO Unit := do
  let input ← getOk "LNURL command batch" (Json.parse (← (← IO.getStdin).readToEnd))
  let rows ← getOk "LNURL command rows" input.getArr?
  let mut results := #[]
  for row in rows do
    let bases ← getOk "LNURL feed bases" (row.getObjValAs? (Array String) "feeds")
    let args ← getOk "LNURL argv" (row.getObjValAs? (List String) "args")
    let replace := (row.getObjValAs? Bool "replace").toOption.getD false
    let services := { productionServices with openOrdinaryFile := fun path => do
      let write ← productionServices.openOrdinaryFile path
      if replace then
        IO.FS.rename path (path ++ ".opened")
        IO.FS.writeFile path "replacement leaf"
      return write }
    let result ← runWithTestUrls version ⟨bases, bases[0]!, bases[0]!⟩ args services
    results := results.push (Json.mkObj [("status", toJson result.status.toNat),
      ("stdout", .str result.stdout), ("stderr", .str result.stderr)])
  IO.println (Json.arr results).compress

def generateInvoiceOrdering : IO Unit := do
  let events ← IO.mkRef ([] : List String)
  let service := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      throw (IO.userError "synthetic open failure")
    price := fun _ => do
      events.modify (· ++ ["price"])
      return ⟨.error "unexpected price", ""⟩
    lnurlRequest := fun _ => do
      events.modify (· ++ ["network"])
      return .error (.curl 43 "unexpected network") }
  for amount in ["invalid", "1USD", "1sat"] do
    events.set []
    let (status, out, err) ← runCase service ["ln-generate-invoice", "user@127.0.0.1:19443", amount, "-o", "unused"]
    check "LNURL output open precedence" (status == 1 && out.isEmpty && err.startsWith "outputFailure:")
    check "LNURL no action before writer" ((← events.get) == ["open"])
  IO.println "LNURL injected writer ordering: 3/3"
  let urls : TestUrls := ⟨Array.replicate 9 "https://127.0.0.1:19443", "https://127.0.0.1:19443", "https://127.0.0.1:19443"⟩
  for address in ["user@external.invalid", "user@127.0.0.1", "user@127.0.0.1:8332",
      "user%2540external.invalid@127.0.0.1:19443"] do
    events.set []
    let guarded := { service with stdout := fun _ => pure (), stderr := fun _ => pure () }
    let result ← runWithTestUrls version urls ["ln-generate-invoice", address, "1USD", "-o", "unused"] guarded
    check "LNURL initial guard before action" (result.status == 1 && (← events.get).isEmpty)
  let calls ← IO.mkRef ([] : List String)
  let request := fun (req : HttpCurl.Request) => do
    calls.modify (· ++ [req.url])
    return .ok ({ status := 302, headers := #[("location", "https://external.invalid/pay")], body := ByteArray.empty } : HttpCurl.Response)
  let result ← runWithTestUrls version urls
    ["ln-generate-invoice", "user@127.0.0.1:19443", "2sat"] productionServices request
  check "LNURL redirected guard before transport" (result.status == 1 && result.stdout.isEmpty &&
    (result.stderr.splitOn "Test LNURL target refused").length == 2 &&
    (← calls.get) == ["https://127.0.0.1:19443/.well-known/lnurlp/user"])
  IO.println "LNURL injected guards: initial 4/4 before action; redirect 1/1 before transport"

end CyberkrillTests
