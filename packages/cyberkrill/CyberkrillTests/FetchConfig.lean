/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support

namespace CyberkrillTests
open Cyberkrill Lean

def fetchConfigRun : IO Unit := do
  let input ← getOk "config batch" (Json.parse (← (← IO.getStdin).readToEnd))
  let rows ← getOk "config rows" input.getArr?
  let mut results := #[]
  for row in rows do
    let args ← getOk "config argv" (row.getObjValAs? (List String) "args")
    let calls ← IO.mkRef (#[] : Array Json)
    let injected := (row.getObjValAs? Bool "injected").toOption.getD false
    let guarded := (row.getObjValAs? Bool "guarded").toOption.getD false
    let replies := (row.getObjValAs? (Array Json) "replies").toOption.getD #[]
    let request := fun (req : HttpCurl.Request) => do
      let index := (← calls.get).size
      calls.modify (·.push (Json.mkObj [("method", .str (if req.method == .get then "GET" else "POST")),
        ("url", .str req.url), ("body", .str (String.fromUTF8! (req.body.getD ByteArray.empty))),
        ("headers", toJson req.headers), ("bytes", toJson req.maxResponseBytes.toNat),
        ("connect", toJson req.connectTimeoutMs.toNat), ("total", toJson req.totalTimeoutMs.toNat)]))
      if !injected then
        let result ← HttpCurl.request req
        let tag := match result with
          | .ok _ => "ok"
          | .error (.tooLarge _) => "tooLarge"
          | .error (.timeout _ _) => "timeout"
          | .error _ => "error"
        calls.modify fun values => values.modify index fun value =>
          match value.getObj? with
          | .error _ => value
          | .ok fields => Json.mkObj (("transport", .str tag) :: fields.toList)
        return result
      let reply := replies[index]?.getD .null
      match (reply.getObjValAs? String "error").toOption with
      | some "timeout" => return .error (.timeout 28 "synthetic timeout")
      | some "size" => return .error (.tooLarge req.maxResponseBytes)
      | some _ => return .error (.connect 7 "synthetic disconnect")
      | none =>
        let body := match (reply.getObjValAs? (Array Nat) "bytes").toOption with
          | some bytes => ByteArray.mk (bytes.map UInt8.ofNat)
          | none => ((reply.getObjValAs? String "body").toOption.getD "").toUTF8
        return .ok {
          status := UInt32.ofNat ((reply.getObjValAs? Nat "status").toOption.getD 200)
          headers := (reply.getObjValAs? (Array (String × String)) "headers").toOption.getD #[]
          body := body }
    let replace := (row.getObjValAs? Bool "replace").toOption.getD false
    let services := { productionServices with
      configRequest := request
      openOrdinaryFile := fun path => do
        let write ← productionServices.openOrdinaryFile path
        if replace then
          IO.FS.rename path (path ++ ".opened")
          IO.FS.writeFile path "replacement leaf"
        return write }
    let result ← if injected && !guarded then do
        let (status, out, err) ← runCase services args
        pure (⟨status, out, err⟩ : TestRun)
      else
        let bases := Array.replicate 9 "http://127.0.0.1:19444"
        runWithTestUrls version ⟨bases, bases[0]!, bases[0]!⟩ args services request
    results := results.push (Json.mkObj [("status", toJson result.status.toNat),
      ("stdout", .str result.stdout), ("stderr", .str result.stderr), ("calls", toJson (← calls.get))])
  IO.println (Json.arr results).compress

def fetchConfigOrdering : IO Unit := do
  let events ← IO.mkRef ([] : List String)
  let services := { productionServices with
    openOrdinaryFile := fun _ => do
      events.modify (· ++ ["open"])
      throw (IO.userError "synthetic open failure")
    configRequest := fun _ => do
      events.modify (· ++ ["network"])
      return .error (.connect 7 "unexpected network") }
  let (status, out, err) ← runCase services ["fm-fetch-config", "malformed", "-o", "unused"]
  check "config writer before invite decode" (status == 1 && out.isEmpty && err.startsWith "outputFailure:")
  check "config no action before writer" ((← events.get) == ["open"])
  IO.println "config injected ordering: 2/2"

end CyberkrillTests
