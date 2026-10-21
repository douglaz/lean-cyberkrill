-- Copied from pure-algebra/lean4-hash @ ab7eda4, Hash/Sha256/Api.lean; MIT, see LICENSE-MIT
module

public import Sha256.Bridge
public import Sha256.Digest
public import Sha256.Fast

/-!
# `Sha256.Api` — the public functions

What a consumer calls. `sha256 : ByteArray → Digest 32`, its `String`
convenience wrapper, and the three theorems that say what the result is.

`sha256` computes through `Sha256.Fast`, the native layer, and the three
theorems below are proved through `Fast.sha256_eq_impl` and then
`Bridge.sha256_bridge`. Their statements are the ones stage S1.3 landed against
`Sha256.Impl`; the S1.4 retarget changed the definition and not one statement.
-/

@[expose] public section

namespace Sha256

/-- SHA-256 of a byte string.

**Meaning**: `sha256_spec`. The digest is `Sha256.Spec.sha256_bytes` of the
input bytes, that is, the function FIPS 180-4 defines.

**Trust base**: the FIPS 180-4 transcription in `Sha256.Spec`, whose fidelity
to the published standard is a named human step
(`test/contracts/sha256.contract.md`, C2); the Lean v4.35.0 kernel; and the
allowlist audit in `Sha256Tests.AxiomGate`. No security
property of any kind is claimed. -/
def sha256 (msg : ByteArray) : Digest 32 := ⟨Fast.sha256 msg, Fast.size_sha256 msg⟩

/-- SHA-256 of the UTF-8 encoding of a string. `String.toUTF8` is a wrapper; no
theorem is stated about the encoding itself. -/
def sha256String (s : String) : Digest 32 := sha256 s.toUTF8

theorem sha256_impl (msg : ByteArray) :
    (sha256 msg).toList = Impl.sha256 msg.data.toList :=
  Fast.sha256_eq_impl msg

theorem sha256_spec (msg : ByteArray) :
    (sha256 msg).toList = Spec.sha256_bytes msg.data.toList := by
  rw [sha256_impl, Bridge.sha256_bridge]

theorem sha256_ofList (l : List UInt8) : (sha256 l.toByteArray).toList = Impl.sha256 l := by
  rw [sha256_impl, List.toList_data_toByteArray]

end Sha256
