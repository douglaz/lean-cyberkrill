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
    let shortLimits := (row.getObjValAs? Bool "short_limits").toOption.getD false
    let replies := (row.getObjValAs? (Array Json) "replies").toOption.getD #[]
    let request := fun (req : HttpCurl.Request) => do
      let index := (← calls.get).size
      calls.modify (·.push (Json.mkObj [("method", .str (if req.method == .get then "GET" else "POST")),
        ("url", .str req.url), ("body", .str (String.fromUTF8! (req.body.getD ByteArray.empty))),
        ("headers", toJson req.headers), ("bytes", toJson req.maxResponseBytes.toNat),
        ("connect", toJson req.connectTimeoutMs.toNat), ("total", toJson req.totalTimeoutMs.toNat)]))
      if !injected then
        let result ← HttpCurl.requestDetailed req
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
          headerBytes := (reply.getObjValAs? (Array (String × Array Nat)) "header_bytes").toOption.map
            (·.map fun (name, bytes) => (name, ByteArray.mk (bytes.map UInt8.ofNat)))
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
    let result ← if injected && !guarded && !shortLimits then do
        let (status, out, err) ← runCase services args
        pure (⟨status, out, err⟩ : TestRun)
      else
        let bases := Array.replicate 9 "http://127.0.0.1:19444"
        let limits : FetchConfig.Limits := if shortLimits then
          { connectTimeoutMs := 1000, totalTimeoutMs := 2000 } else {}
        runWithTestUrls version ⟨bases, bases[0]!, bases[0]!⟩ args services
          (configRequest := request) (configLimits := limits)
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

/-- Both operations see the same owned local framing fixture independently. -/
def fetchHttpRun : IO Unit := do
  let input ← getOk "config HTTP input" (Json.parse (← (← IO.getStdin).readToEnd))
  let url ← getOk "config HTTP URL" (input.getObjValAs? String "url")
  check "config HTTP loopback" (TestUrls.permitted url && !TestUrls.forbiddenPort url)
  if let .ok bytes := input.getObjValAs? (Array Nat) "header_bytes" then
    IO.println (toJson (HttpCurl.validResponseHeaders (ByteArray.mk (bytes.map UInt8.ofNat)))).compress
    return
  let req : HttpCurl.Request := { url := url, totalTimeoutMs := 2000 }
  let legacy ← HttpCurl.request req
  let detailed ← HttpCurl.requestDetailed req
  let (kind, status) := match detailed with
    | .error _ => ("error", 0)
    | .ok r => (if r.bodyError.isSome then "body" else "ok", r.status.toNat)
  let legacyCode := match legacy with | .error (.curl code _) => code.toNat | _ => 0
  let detailedCode := match detailed with | .error (.curl code _) => code.toNat | _ => 0
  let legacyLocation := match legacy with
    | .ok r => (r.headers.find? (fun h => h.1 == "location")).map (·.2) |>.getD ""
    | .error _ => ""
  let detailedLocation := match detailed with
    | .ok r => (r.headers.find? (fun h => h.1 == "location")).map (·.2) |>.getD ""
    | .error _ => ""
  let responseJson (status : UInt32) (headers : Array (String × String)) (body : ByteArray) :=
    Json.mkObj [("status", toJson status.toNat), ("headers", toJson headers),
      ("body", toJson (body.data.map UInt8.toNat))]
  let legacyResponse := match legacy with
    | .ok r => responseJson r.status r.headers r.body
    | .error _ => Json.null
  let detailedResponse := match detailed with
    | .ok r => responseJson r.status r.headers r.body
    | .error _ => Json.null
  IO.println (Json.mkObj [("legacy", .str (match legacy with | .error _ => "error" | .ok _ => "ok")),
    ("legacy_response", legacyResponse), ("detailed_response", detailedResponse),
    ("legacy_code", toJson legacyCode), ("detailed_code", toJson detailedCode),
    ("legacy_location", .str legacyLocation), ("detailed_location", .str detailedLocation),
    ("detailed", .str kind), ("status", toJson status)]).compress

end CyberkrillTests
