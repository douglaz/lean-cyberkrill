/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Base58
import Sha256

namespace Bitcoin.Base58

inductive CheckError where
  | invalidBase58
  | tooShort
  | checksumMismatch
  deriving Repr, DecidableEq, BEq

private def checksum (p : ByteArray) : ByteArray := (Sha256.sha256d p).extract 0 4

private theorem checksum_size (p : ByteArray) : (checksum p).size = 4 := by
  simp [checksum, ByteArray.size_extract, Sha256.sha256d_size]

/-- Append the first four bytes of SHA-256d and encode in Bitcoin Base58. -/
def base58CheckEncode (p : ByteArray) : String := base58Encode (p ++ checksum p)

/-- Decode strictly and distinguish alphabet, length and checksum failures. -/
def base58CheckDecode (s : String) : Except CheckError ByteArray :=
  match base58Decode s with
  | none => .error .invalidBase58
  | some b =>
    if b.size < 4 then .error .tooShort else
      let p := b.extract 0 (b.size - 4)
      if b = p ++ checksum p then .ok p else .error .checksumMismatch

/-- K1: the public Base58Check codec round-trips every payload. -/
theorem base58CheckDecode_encode (p : ByteArray) :
    base58CheckDecode (base58CheckEncode p) = .ok p := by
  have size : (p ++ checksum p).size = p.size + 4 := by
    simp [ByteArray.size_append, checksum_size]
  have first : (p ++ checksum p).extract 0 ((p ++ checksum p).size - 4) = p := by
    rw [size, Nat.add_sub_cancel]
    exact ByteArray.extract_append_eq_left rfl
  simp only [base58CheckDecode, base58CheckEncode, base58Decode_encode, first]
  simp [size]

/-- K2: success ties the returned payload to the complete SHA-256d-checked bytes. -/
theorem base58CheckDecode_sound (s : String) (p : ByteArray)
    (h : base58CheckDecode s = .ok p) :
    base58Decode s = some (p ++ (Sha256.sha256d p).extract 0 4) := by
  unfold base58CheckDecode at h
  cases hd : base58Decode s with
  | none => simp [hd] at h
  | some b =>
    simp only [hd] at h
    split at h
    next hs => simp at h
    next hs =>
      split at h
      next he =>
        have ep : b.extract 0 (b.size - 4) = p := by simpa using h
        simpa only [ep, checksum] using congrArg some he
      next he => simp at h

end Bitcoin.Base58
