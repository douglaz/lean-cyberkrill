/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Lnurl.Types

namespace Lightning

private def stringField (j : Lean.Json) (field : String) : Except LnurlError String :=
  (j.getObjValAs? String field).mapError (fun _ => .malformedResponse field)

private def boundedInteger (j : Lean.Json) (field : String) (bound : Nat) : Except LnurlError Nat := do
  let .num n := j | throw (.malformedResponse field)
  if n.mantissa < 0 || n.exponent != 0 || n.mantissa.toNat > bound then
    throw (.malformedResponse field)
  return n.mantissa.toNat

private def msatField (j : Lean.Json) (field : String) : Except LnurlError Bitcoin.Amount := do
  let value ← (j.getObjVal? field).mapError (fun _ => .malformedResponse field)
  return ⟨← boundedInteger value field 18446744073709551615⟩

def LnurlPayRequest.fromJson (j : Lean.Json) : Except LnurlError LnurlPayRequest := do
  let callback ← stringField j "callback"
  let maxSendable ← msatField j "maxSendable"
  let minSendable ← msatField j "minSendable"
  let metadata ← stringField j "metadata"
  let tag ← stringField j "tag"
  let commentAllowed ← match (j.getObjVal? "commentAllowed").toOption with
    | none | some .null => pure none
    | some v => do pure (some (← boundedInteger v "commentAllowed" 65535))
  return ⟨callback, maxSendable, minSendable, metadata, tag, commentAllowed⟩

def LnurlPayCallback.fromJson (j : Lean.Json) : Except LnurlError LnurlPayCallback := do
  let pr ← stringField j "pr"
  let routes ← match (j.getObjVal? "routes").toOption with
    | none | some .null => pure none
    | some (.arr vs) => do
      pure (some (← vs.mapM fun v => v.getStr?.mapError (fun _ => .malformedResponse "routes")))
    | some _ => throw (.malformedResponse "routes")
  return ⟨pr, routes⟩

end Lightning
