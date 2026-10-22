-- Copied from febyeji/lean-miniscript @ cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd, LeanMiniscript/Bitcoin/DeserializationProofs.lean L180-232; MIT, see LICENSE-miniscript
import Bitcoin.Deserialization

namespace Bitcoin

open CompactSize

theorem readByteVector_ok {bytes rest : List UInt8} {vector : ByteArray}
    (read : readByteVector bytes = .ok (vector, rest)) :
    bytes = encodeByteVector vector ++ rest ∧ vector.size < 2 ^ 64 := by
  unfold readByteVector at read
  split at read
  · simp at read
  · rename_i count after counted
    obtain ⟨countSplit, countBound⟩ := readCompactSize_ok counted
    split at read
    · simp at read
    · rename_i data remaining taken
      obtain ⟨dataSplit, dataLength⟩ := takeExact_ok taken
      simp only [Except.ok.injEq, Prod.mk.injEq] at read
      obtain ⟨rfl, rfl⟩ := read
      have size : (⟨data.toArray⟩ : ByteArray).size = count := by
        simp [ByteArray.size, dataLength]
      refine ⟨?_, by omega⟩
      simp only [encodeByteVector, size, countSplit, dataSplit, List.append_assoc]

/-! ## Witness stacks -/

theorem serializeWitness_foldl_data (items : List ByteArray) (start : ByteArray) :
    (items.foldl (fun bytes item => bytes ++ serializeByteVector item) start).data.toList =
      start.data.toList ++ items.flatMap encodeByteVector := by
  induction items generalizing start with
  | nil => simp
  | cons item items ih =>
    simp only [List.foldl_cons, ih, List.flatMap_cons, ByteArray.data_append, Array.toList_append,
      serializeByteVector_data, List.append_assoc]

theorem readMany_readByteVector (items : List ByteArray)
    (bounded : ∀ item ∈ items, item.size < 2 ^ 64) (rest : List UInt8) :
    readMany readByteVector items.length (items.flatMap encodeByteVector ++ rest) =
      .ok (items, rest) := by
  induction items with
  | nil => rfl
  | cons item items ih =>
    simp only [List.length_cons, List.flatMap_cons, List.append_assoc, readMany,
      readByteVector_encode (bounded item (by simp)), bind, Except.bind,
      ih (fun other member => bounded other (by simp [member]))]
    rfl

/-- The serialized witness stack written by finalizers decodes to the same
items, as `PSBT_IN_FINAL_SCRIPTWITNESS` values are read. -/
theorem decodeAll_readWitnessStack (items : List ByteArray)
    (count : items.length < 2 ^ 64) (bounded : ∀ item ∈ items, item.size < 2 ^ 64) :
    decodeAll readWitnessStack (serializeWitness items) = .ok items := by
  have data : (serializeWitness items).data.toList =
      compactSize items.length ++ (items.flatMap encodeByteVector ++ []) := by
    simp [serializeWitness, serializeWitness_foldl_data]
  simp only [decodeAll, readWitnessStack, data, readCompactSize_compactSize count,
    bind, Except.bind, readMany_readByteVector items bounded]
  rfl
