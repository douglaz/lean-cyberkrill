/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.CompactSize

namespace Bitcoin.CompactSize

theorem reject_fd (v : Nat) (h : v < 253) (rest : List UInt8) :
    readCompactSize (0xfd :: unsignedLE 2 v ++ rest) = .error .nonCanonicalCompactSize := by
  have taken := takeExact_append (unsignedLE 2 v) rest
  rw [unsignedLE_length] at taken
  have decoded : decodeLE (unsignedLE 2 v) = v := by
    rw [decodeLE_unsignedLE, Nat.mod_eq_of_lt (by omega)]
  simp [readCompactSize, taken, decoded, h]

theorem reject_fe (v : Nat) (h : v < 65536) (rest : List UInt8) :
    readCompactSize (0xfe :: unsignedLE 4 v ++ rest) = .error .nonCanonicalCompactSize := by
  have taken := takeExact_append (unsignedLE 4 v) rest
  rw [unsignedLE_length] at taken
  have decoded : decodeLE (unsignedLE 4 v) = v := by
    rw [decodeLE_unsignedLE, Nat.mod_eq_of_lt (by omega)]
  simp [readCompactSize, taken, decoded, h]

theorem reject_ff (v : Nat) (h : v < 2^32) (rest : List UInt8) :
    readCompactSize (0xff :: unsignedLE 8 v ++ rest) = .error .nonCanonicalCompactSize := by
  have taken := takeExact_append (unsignedLE 8 v) rest
  rw [unsignedLE_length] at taken
  have decoded : decodeLE (unsignedLE 8 v) = v := by
    rw [decodeLE_unsignedLE, Nat.mod_eq_of_lt (by omega)]
  simp [readCompactSize, taken, decoded, h]

theorem truncated_empty : readCompactSize [] = .error .truncated := rfl

theorem truncated_tag (tag : UInt8) (bytes : List UInt8)
    (htag : tag = 0xfd ∨ tag = 0xfe ∨ tag = 0xff)
    (short : bytes.length < (if tag = 0xfd then 2 else if tag = 0xfe then 4 else 8)) :
    readCompactSize (tag :: bytes) = .error .truncated := by
  rcases htag with rfl | rfl | rfl <;>
    simp_all [readCompactSize, takeExact, Nat.not_le_of_lt]

end Bitcoin.CompactSize
