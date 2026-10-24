/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Base58Check
import Bitcoin.ByteArrayRepr

namespace Bitcoin.Slip132

/-- The six single-signature public versions in cyberkrill's slip132.rs:9-20
at 27cad1faba86260b06665a89f0af5134d23525c2. -/
inductive Version where
  | xpub | ypub | zpub | tpub | upub | vpub
  deriving Repr, DecidableEq, BEq, Inhabited

/-- The four bytes replaced by conversion, including across networks. -/
def versionBytes : Version → ByteArray
  | .xpub => ⟨#[0x04, 0x88, 0xB2, 0x1E]⟩
  | .ypub => ⟨#[0x04, 0x9D, 0x7C, 0xB2]⟩
  | .zpub => ⟨#[0x04, 0xB2, 0x47, 0x46]⟩
  | .tpub => ⟨#[0x04, 0x35, 0x87, 0xCF]⟩
  | .upub => ⟨#[0x04, 0x4A, 0x52, 0x62]⟩
  | .vpub => ⟨#[0x04, 0x5F, 0x1C, 0xF6]⟩

/-- Recognize exactly the six public versions. -/
def versionOf (bytes : ByteArray) : Option Version :=
  ([.xpub, .ypub, .zpub, .tpub, .upub, .vpub] : List Version).find?
    (fun v => decide (versionBytes v = bytes))

inductive Error where
  | base58 (error : Base58.CheckError)
  | wrongLength (length : Nat)
  | unknownVersion (bytes : ByteArray)
  deriving Repr, DecidableEq, BEq

/-- Check Base58Check, then 78-byte length, then version. Return the version
and the untouched 74-byte body. There is no curve or key-prefix check. -/
def decode (s : String) : Except Error (Version × ByteArray) :=
  match Base58.base58CheckDecode s with
  | .error e => .error (.base58 e)
  | .ok p =>
    if p.size = 78 then
      match versionOf (p.extract 0 4) with
      | none => .error (.unknownVersion (p.extract 0 4))
      | some v => .ok (v, p.extract 4 p.size)
    else .error (.wrongLength p.size)

/-- Convert to any of the six public versions. Only the version bytes change. -/
def convert (s : String) (target : Version) : Except Error String :=
  match decode s with
  | .error e => .error e
  | .ok (_, body) => .ok (Base58.base58CheckEncode (versionBytes target ++ body))

theorem versionBytes_size (v : Version) : (versionBytes v).size = 4 := by
  cases v <;> rfl

theorem versionOf_versionBytes (v : Version) : versionOf (versionBytes v) = some v := by
  cases v <;> decide

theorem versionOf_sound (b : ByteArray) (v : Version) (h : versionOf b = some v) :
    versionBytes v = b := by
  have := List.find?_some h
  simpa using this

/-- Canonical spelling of every string accepted by the existing Base58Check API. -/
theorem base58CheckEncode_of_decode (s : String) (p : ByteArray)
    (h : Base58.base58CheckDecode s = .ok p) : Base58.base58CheckEncode p = s := by
  exact Base58.base58Encode_of_decode s _ (Base58.base58CheckDecode_sound s p h)

theorem decode_sound (s : String) (v : Version) (body : ByteArray)
    (h : decode s = .ok (v, body)) :
    Base58.base58CheckDecode s = .ok (versionBytes v ++ body) ∧ body.size = 74 := by
  unfold decode at h
  cases hd : Base58.base58CheckDecode s with
  | error e => simp [hd] at h
  | ok p =>
    simp only [hd] at h
    split at h
    next hs =>
      cases hv : versionOf (p.extract 0 4) with
      | none => simp [hv] at h
      | some w =>
        simp only [hv, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        have front := versionOf_sound _ w hv
        have whole : versionBytes w ++ p.extract 4 p.size = p := by
          rw [front, ByteArray.extract_append_extract]
          simpa [hs] using (ByteArray.extract_zero_size (b := p))
        constructor
        · rw [whole]
        · simp [ByteArray.size_extract, hs]
    next hs => simp at h

theorem decode_encode (v : Version) (body : ByteArray) (h : body.size = 74) :
    decode (Base58.base58CheckEncode (versionBytes v ++ body)) = .ok (v, body) := by
  have size : (versionBytes v ++ body).size = 78 := by
    simp [ByteArray.size_append, versionBytes_size, h]
  have front : (versionBytes v ++ body).extract 0 4 = versionBytes v :=
    ByteArray.extract_append_eq_left (versionBytes_size v).symm
  have tail : (versionBytes v ++ body).extract 4 78 = body :=
    ByteArray.extract_append_eq_right (versionBytes_size v).symm (by
      rw [← ByteArray.size_append, size])
  simp [decode, Base58.base58CheckDecode_encode, size, front, versionOf_versionBytes, tail]

/-- The converted string decodes to the target version and the source body. -/
theorem convert_payload (s s' : String) (v t : Version) (body : ByteArray)
    (h : decode s = .ok (v, body)) (hc : convert s t = .ok s') :
    Base58.base58CheckDecode s' = .ok (versionBytes t ++ body) := by
  simp only [convert, h, Except.ok.injEq] at hc
  rw [← hc, Base58.base58CheckDecode_encode]

/-- Every accepted string survives conversion to any target and back. -/
theorem convert_roundtrip (s s' : String) (v t : Version) (body : ByteArray)
    (h : decode s = .ok (v, body)) (hc : convert s t = .ok s') :
    convert s' v = .ok s := by
  obtain ⟨hd, size⟩ := decode_sound s v body h
  simp only [convert, h, Except.ok.injEq] at hc
  rw [← hc]
  simp only [convert, decode_encode t body size]
  rw [base58CheckEncode_of_decode s _ hd]

end Bitcoin.Slip132
