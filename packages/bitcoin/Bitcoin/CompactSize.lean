-- Copied from febyeji/lean-miniscript @ cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd: LeanMiniscript/Bitcoin/Serialization.lean (whole), Deserialization.lean L11-79, DeserializationProofs.lean L7-179; MIT, see LICENSE-miniscript.
import Lean

namespace Bitcoin.CompactSize

/-- Fixed-width unsigned little-endian serialization. Callers use bounded
    transaction fields; this helper encodes the low `width` bytes. -/
def unsignedLE : Nat → Nat → List UInt8
  | 0, _ => []
  | width + 1, value => UInt8.ofNat value :: unsignedLE width (value / 256)

/-- Bitcoin CompactSize, for lengths representable by uint64. -/
def compactSize (value : Nat) : List UInt8 :=
  if value < 253 then [UInt8.ofNat value]
  else if value ≤ 65535 then 0xfd :: unsignedLE 2 value
  else if value ≤ 4294967295 then 0xfe :: unsignedLE 4 value
  else 0xff :: unsignedLE 8 value

def serializeByteVector (bytes : ByteArray) : ByteArray :=
  ⟨(compactSize bytes.size).toArray⟩ ++ bytes

/-- Serialize the entire transaction-input witness, in wire order. This
    includes the item count and each item's CompactSize length prefix. -/
def serializeWitness (items : List ByteArray) : ByteArray :=
  items.foldl (fun bytes item => bytes ++ serializeByteVector item)
    ⟨(compactSize items.length).toArray⟩

inductive DecodeError where
  | truncated
  | nonCanonicalCompactSize
  | unknownTransactionFlags
  | superfluousWitness
  | trailingData
  deriving Repr, DecidableEq

abbrev Decoder (α : Type) := List UInt8 → Except DecodeError (α × List UInt8)

/-- Little-endian unsigned integer of all supplied bytes. -/
def decodeLE : List UInt8 → Nat
  | [] => 0
  | byte :: rest => byte.toNat + 256 * decodeLE rest

/-- Split exactly `count` bytes from the front. -/
def takeExact (count : Nat) : Decoder (List UInt8) := fun bytes =>
  if count ≤ bytes.length then .ok (bytes.take count, bytes.drop count)
  else .error .truncated

/-- Read a canonical CompactSize. Wider encodings of values that fit in a
shorter form are rejected. -/
def readCompactSize : Decoder Nat
  | [] => .error .truncated
  | tag :: rest =>
      if tag.toNat < 253 then .ok (tag.toNat, rest)
      else
        let width := if tag.toNat = 253 then 2 else if tag.toNat = 254 then 4 else 8
        let minimum := if tag.toNat = 253 then 253
          else if tag.toNat = 254 then 65536 else 4294967296
        match takeExact width rest with
        | .error error => .error error
        | .ok (bytes, rest) =>
            if decodeLE bytes < minimum then .error .nonCanonicalCompactSize
            else .ok (decodeLE bytes, rest)

/-- Encoding of a length-prefixed byte vector, as a byte list. -/
def encodeByteVector (bytes : ByteArray) : List UInt8 :=
  compactSize bytes.size ++ bytes.data.toList

/-- A CompactSize length followed by that many bytes. -/
def readByteVector : Decoder ByteArray := fun bytes =>
  match readCompactSize bytes with
  | .error error => .error error
  | .ok (count, rest) =>
      match takeExact count rest with
      | .error error => .error error
      | .ok (data, rest) => .ok (⟨data.toArray⟩, rest)

def readUInt32 : Decoder UInt32 := fun bytes => do
  let (data, rest) ← takeExact 4 bytes
  return (UInt32.ofNat (decodeLE data), rest)

def readUInt64 : Decoder UInt64 := fun bytes => do
  let (data, rest) ← takeExact 8 bytes
  return (UInt64.ofNat (decodeLE data), rest)

/-- Read `count` items with one decoder. -/
def readMany {α : Type} (decoder : Decoder α) : Nat → Decoder (List α)
  | 0, bytes => .ok ([], bytes)
  | count + 1, bytes => do
      let (item, rest) ← decoder bytes
      let (items, rest) ← readMany decoder count rest
      return (item :: items, rest)

/-- Require that a decoder consumes its entire input. -/
def decodeAll {α : Type} (decoder : Decoder α) (bytes : ByteArray) : Except DecodeError α := do
  let (value, rest) ← decoder bytes.data.toList
  if rest.isEmpty then return value else throw .trailingData
theorem unsignedLE_length (width value : Nat) : (unsignedLE width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [unsignedLE, ih]

theorem decodeLE_unsignedLE (width value : Nat) :
    decodeLE (unsignedLE width value) = value % 256 ^ width := by
  induction width generalizing value with
  | zero => simp [unsignedLE, decodeLE, Nat.mod_one]
  | succ width ih =>
    have byte : (UInt8.ofNat value).toNat = value % 256 := UInt8.toNat_ofNat'
    simp only [unsignedLE, decodeLE, ih, byte]
    rw [Nat.pow_succ', Nat.mod_mul]

theorem takeExact_append (bytes rest : List UInt8) :
    takeExact bytes.length (bytes ++ rest) = .ok (bytes, rest) := by
  simp [takeExact]

theorem compactSize_ne_nil (value : Nat) : compactSize value ≠ [] := by
  unfold compactSize
  split <;> (try split) <;> (try split) <;> simp

/-- Every value representable by Core's uint64 CompactSize reads back exactly,
including the canonical-width check. -/
theorem readCompactSize_compactSize {value : Nat} (bound : value < 2 ^ 64)
    (rest : List UInt8) :
    readCompactSize (compactSize value ++ rest) = .ok (value, rest) := by
  unfold compactSize
  by_cases small : value < 253
  · have : value % 256 = value := Nat.mod_eq_of_lt (by omega)
    simp [small, readCompactSize, this]
  · by_cases two : value ≤ 65535
    · have length := unsignedLE_length 2 value
      have decoded : decodeLE (unsignedLE 2 value) = value := by
        rw [decodeLE_unsignedLE]; exact Nat.mod_eq_of_lt (by omega)
      have taken := takeExact_append (unsignedLE 2 value) rest
      rw [length] at taken
      simp only [small, two, ite_false, ite_true, List.cons_append, readCompactSize]
      simp [taken, decoded, small]
    · by_cases four : value ≤ 4294967295
      · have length := unsignedLE_length 4 value
        have decoded : decodeLE (unsignedLE 4 value) = value := by
          rw [decodeLE_unsignedLE]; exact Nat.mod_eq_of_lt (by omega)
        have taken := takeExact_append (unsignedLE 4 value) rest
        rw [length] at taken
        simp only [small, two, four, ite_false, ite_true, List.cons_append, readCompactSize]
        have notMinimal : ¬ value < 65536 := by omega
        simp [taken, decoded, notMinimal]
      · have length := unsignedLE_length 8 value
        have decoded : decodeLE (unsignedLE 8 value) = value := by
          rw [decodeLE_unsignedLE]; exact Nat.mod_eq_of_lt (by omega)
        have taken := takeExact_append (unsignedLE 8 value) rest
        rw [length] at taken
        simp only [small, two, four, ite_false, List.cons_append, readCompactSize]
        have notMinimal : ¬ value < 4294967296 := by omega
        simp [taken, decoded, notMinimal]

theorem serializeByteVector_data (bytes : ByteArray) :
    (serializeByteVector bytes).data.toList = encodeByteVector bytes := by
  simp [serializeByteVector, encodeByteVector, ByteArray.data_append]

theorem readByteVector_encode {bytes : ByteArray} (bound : bytes.size < 2 ^ 64)
    (rest : List UInt8) :
    readByteVector (encodeByteVector bytes ++ rest) = .ok (bytes, rest) := by
  have taken := takeExact_append bytes.data.toList rest
  have length : bytes.data.toList.length = bytes.size := by simp
  rw [length] at taken
  unfold readByteVector encodeByteVector
  rw [List.append_assoc, readCompactSize_compactSize bound]
  simp only [taken]

/-! ## Accepted encodings are canonical

Every successful read consumed exactly the canonical encoding of its result,
so re-serializing a read value reproduces the consumed bytes. -/

theorem decodeLE_lt (bytes : List UInt8) : decodeLE bytes < 256 ^ bytes.length := by
  induction bytes with
  | nil => simp [decodeLE]
  | cons byte rest ih =>
    have := byte.toNat_lt
    simp only [decodeLE, List.length_cons, Nat.pow_succ']
    omega

theorem unsignedLE_decodeLE (bytes : List UInt8) :
    unsignedLE bytes.length (decodeLE bytes) = bytes := by
  induction bytes with
  | nil => rfl
  | cons byte rest ih =>
    have small := byte.toNat_lt
    have low : (UInt8.ofNat (byte.toNat + 256 * decodeLE rest)) = byte := by
      apply UInt8.toNat_inj.mp
      rw [UInt8.toNat_ofNat']
      omega
    have high : (byte.toNat + 256 * decodeLE rest) / 256 = decodeLE rest := by omega
    simp only [List.length_cons, unsignedLE, decodeLE, low, high, ih]

theorem takeExact_ok {count : Nat} {bytes taken rest : List UInt8}
    (read : takeExact count bytes = .ok (taken, rest)) :
    bytes = taken ++ rest ∧ taken.length = count := by
  unfold takeExact at read
  split at read
  · rename_i enough
    simp only [Except.ok.injEq, Prod.mk.injEq] at read
    obtain ⟨rfl, rfl⟩ := read
    exact ⟨(List.take_append_drop count bytes).symm, by simp; omega⟩
  · simp at read

/-- A successful CompactSize read consumed the canonical encoding of the
value, which is below 2^64. -/
theorem readCompactSize_ok {bytes rest : List UInt8} {value : Nat}
    (read : readCompactSize bytes = .ok (value, rest)) :
    bytes = compactSize value ++ rest ∧ value < 2 ^ 64 := by
  cases bytes with
  | nil => simp [readCompactSize] at read
  | cons tag tail =>
    have tagBound := tag.toNat_lt
    unfold readCompactSize at read
    by_cases small : tag.toNat < 253
    · simp only [small, ite_true, Except.ok.injEq, Prod.mk.injEq] at read
      obtain ⟨rfl, rfl⟩ := read
      have tagEq : UInt8.ofNat tag.toNat = tag := UInt8.ofNat_toNat
      refine ⟨?_, by omega⟩
      simp [compactSize, small, tagEq]
    · simp only [small, ite_false] at read
      cases takenEq : takeExact (if tag.toNat = 253 then 2 else if tag.toNat = 254 then 4 else 8)
          tail with
      | error error => simp [takenEq] at read
      | ok pair =>
        obtain ⟨taken, after⟩ := pair
        simp only [takenEq] at read
        obtain ⟨split, length⟩ := takeExact_ok takenEq
        have roundTrip := unsignedLE_decodeLE taken
        have bound := decodeLE_lt taken
        subst split
        by_cases two : tag.toNat = 253
        · simp only [two, ite_true] at length read
          rw [length] at roundTrip bound
          by_cases low : decodeLE taken < 253
          · simp [low] at read
          · simp only [low, ite_false, Except.ok.injEq, Prod.mk.injEq] at read
            obtain ⟨rfl, rfl⟩ := read
            have tagEq : tag = 0xfd := UInt8.toNat_inj.mp (by simpa using two)
            refine ⟨?_, by omega⟩
            simp only [compactSize]
            rw [ite_eq_right (by omega), ite_eq_left (by omega), roundTrip, tagEq]
            rfl
        · by_cases four : tag.toNat = 254
          · have notTwo : (254 : Nat) ≠ 253 := by decide
            simp only [four, notTwo, ite_false, ite_true] at length read
            rw [length] at roundTrip bound
            by_cases low : decodeLE taken < 65536
            · simp [low] at read
            · simp only [low, ite_false, Except.ok.injEq, Prod.mk.injEq] at read
              obtain ⟨rfl, rfl⟩ := read
              have tagEq : tag = 0xfe := UInt8.toNat_inj.mp (by simpa using four)
              refine ⟨?_, by omega⟩
              simp only [compactSize]
              rw [ite_eq_right (by omega), ite_eq_right (by omega), ite_eq_left (by omega), roundTrip, tagEq]
              rfl
          · simp only [two, four, ite_false] at length
            simp only [two, four, ite_false] at read
            rw [length] at roundTrip bound
            by_cases low : decodeLE taken < 4294967296
            · simp [low] at read
            · simp only [low, ite_false, Except.ok.injEq, Prod.mk.injEq] at read
              obtain ⟨rfl, rfl⟩ := read
              have tagEq : tag = 0xff := UInt8.toNat_inj.mp (by simp; omega)
              refine ⟨?_, by omega⟩
              simp only [compactSize]
              rw [ite_eq_right (by omega), ite_eq_right (by omega), ite_eq_right (by omega), roundTrip, tagEq]
              rfl

end Bitcoin.CompactSize
