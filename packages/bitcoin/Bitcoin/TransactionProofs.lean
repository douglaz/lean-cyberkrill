/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.DeserializationProofs

namespace Bitcoin

open CompactSize

/-- The nine wire-format preconditions for lossless transaction serialization. -/
structure Transaction.WellFormed (tx : Transaction) (witnesses : List (List ByteArray)) : Prop where
  txidSize : ∀ input ∈ tx.inputs, input.previousOutput.txid.size = 32
  scriptSigSize : ∀ input ∈ tx.inputs, input.scriptSig.size < 2 ^ 64
  scriptPubKeySize : ∀ output ∈ tx.outputs, output.scriptPubKey.size < 2 ^ 64
  witnessItemSize : ∀ stack ∈ witnesses, ∀ item ∈ stack, item.size < 2 ^ 64
  inputCount : tx.inputs.size < 2 ^ 64
  outputCount : tx.outputs.size < 2 ^ 64
  witnessCount : ∀ stack ∈ witnesses, stack.length < 2 ^ 64
  witnessesLength : witnesses.length = tx.inputs.size
  unambiguous : tx.inputs.size > 0 ∨ tx.outputs.size = 0

theorem readUInt32_unsignedLE (value : UInt32) (rest : List UInt8) :
    readUInt32 (unsignedLE 4 value.toNat ++ rest) = .ok (value, rest) := by
  have taken := takeExact_append (unsignedLE 4 value.toNat) rest
  rw [unsignedLE_length] at taken
  simp [readUInt32, taken, Functor.map, Except.map, decodeLE_unsignedLE,
    Nat.mod_eq_of_lt value.toNat_lt]

theorem readUInt64_unsignedLE (value : UInt64) (rest : List UInt8) :
    readUInt64 (unsignedLE 8 value.toNat ++ rest) = .ok (value, rest) := by
  have taken := takeExact_append (unsignedLE 8 value.toNat) rest
  rw [unsignedLE_length] at taken
  simp [readUInt64, taken, Functor.map, Except.map, decodeLE_unsignedLE,
    Nat.mod_eq_of_lt value.toNat_lt]

theorem readOutPoint_serialize (point : OutPoint) (size : point.txid.size = 32)
    (rest : List UInt8) :
    readOutPoint ((serializeOutPoint point).data.toList ++ rest) = .ok (point, rest) := by
  have taken := takeExact_append point.txid.data.toList (unsignedLE 4 point.index.toNat ++ rest)
  have length : point.txid.data.toList.length = 32 := by simpa using size
  rw [length] at taken
  simp [serializeOutPoint, readOutPoint, List.append_assoc, taken, readUInt32_unsignedLE,
    bind, Except.bind, pure, Except.pure]

theorem readTxInput_serialize (input : TxInput)
    (txid : input.previousOutput.txid.size = 32) (script : input.scriptSig.size < 2 ^ 64)
    (rest : List UInt8) :
    readTxInput ((serializeTxInput input).data.toList ++ rest) = .ok (input, rest) := by
  simp [serializeTxInput, readTxInput, List.append_assoc, readOutPoint_serialize _ txid,
    serializeByteVector_data, readByteVector_encode script, readUInt32_unsignedLE,
    bind, Except.bind, pure, Except.pure]

theorem readTxOutput_serialize (output : TxOutput) (script : output.scriptPubKey.size < 2 ^ 64)
    (rest : List UInt8) :
    readTxOutput ((serializeTxOutput output).data.toList ++ rest) = .ok (output, rest) := by
  simp [serializeTxOutput, readTxOutput, List.append_assoc, readUInt64_unsignedLE,
    serializeByteVector_data, readByteVector_encode script,
    bind, Except.bind, pure, Except.pure]

theorem serialize_foldl_data {α : Type} (encode : α → ByteArray) (items : List α)
    (start : ByteArray) :
    (items.foldl (fun bytes item => bytes ++ encode item) start).data.toList =
      start.data.toList ++ items.flatMap (fun item => (encode item).data.toList) := by
  induction items generalizing start with
  | nil => simp
  | cons item items ih => simp [ih, List.append_assoc]

theorem readMany_serialize {α : Type} (decoder : Decoder α) (encode : α → ByteArray)
    (items : List α)
    (reads : ∀ item ∈ items, ∀ rest, decoder ((encode item).data.toList ++ rest) = .ok (item, rest))
    (rest : List UInt8) :
    readMany decoder items.length (items.flatMap (fun item => (encode item).data.toList) ++ rest) =
      .ok (items, rest) := by
  induction items with
  | nil => rfl
  | cons item items ih =>
    simp only [List.length_cons, List.flatMap_cons, List.append_assoc, readMany,
      reads item (by simp), bind, Except.bind,
      ih (fun other member => reads other (by simp [member]))]
    rfl

theorem readWitnessStack_serialize (items : List ByteArray)
    (count : items.length < 2 ^ 64) (bounded : ∀ item ∈ items, item.size < 2 ^ 64)
    (rest : List UInt8) :
    readWitnessStack ((serializeWitness items).data.toList ++ rest) = .ok (items, rest) := by
  simp only [serializeWitness, serializeWitness_foldl_data, readWitnessStack, List.append_assoc,
    readCompactSize_compactSize count, bind, Except.bind, readMany_readByteVector items bounded]

theorem map_range_getD {α : Type} (items : List α) (fallback : α) :
    (List.range items.length).map (fun i => items.getD i fallback) = items := by
  apply List.ext_getElem
  · simp
  · intro i h₁ h₂
    simp only [List.getElem_map, List.getElem_range]
    exact (List.getElem_eq_getD fallback).symm

theorem serializeWitnesses_data (tx : Transaction) (witnesses : List (List ByteArray))
    (length : witnesses.length = tx.inputs.size) :
    ((List.range tx.inputs.size).foldl
      (fun bytes index => bytes ++ serializeWitness (witnesses.getD index [])) ByteArray.empty).data.toList =
      witnesses.flatMap (fun stack => (serializeWitness stack).data.toList) := by
  rw [← length]
  have mapped := map_range_getD witnesses []
  have folded := serialize_foldl_data serializeWitness witnesses ByteArray.empty
  rw [← mapped, List.foldl_map] at folded
  simpa only [ByteArray.data_empty, Array.toList_empty, List.nil_append, mapped] using folded

theorem serializeTransaction_data (tx : Transaction) :
    (serializeTransaction tx).data.toList = unsignedLE 4 tx.version.toNat ++
      (compactSize tx.inputs.size ++
      (tx.inputs.toList.flatMap (fun i => (serializeTxInput i).data.toList) ++
      (compactSize tx.outputs.size ++
      (tx.outputs.toList.flatMap (fun o => (serializeTxOutput o).data.toList) ++
      unsignedLE 4 tx.locktime.toNat)))) := by
  simp [serializeTransaction, ← Array.foldl_toList, serialize_foldl_data, List.append_assoc]

theorem readMany_inputs (tx : Transaction) (witnesses : List (List ByteArray))
    (h : tx.WellFormed witnesses) (rest : List UInt8) :
    readMany readTxInput tx.inputs.size
      (tx.inputs.toList.flatMap (fun i => (serializeTxInput i).data.toList) ++ rest) =
      .ok (tx.inputs.toList, rest) := by
  have txidSize : ∀ i ∈ tx.inputs, i.previousOutput.txid.size = 32 := by
    have := h.txidSize
    grind
  have scriptSize : ∀ i ∈ tx.inputs, i.scriptSig.size < 2 ^ 64 := by
    have := h.scriptSigSize
    grind
  simpa using readMany_serialize readTxInput serializeTxInput tx.inputs.toList
    (fun i member => readTxInput_serialize i (txidSize i (by simpa using member))
      (scriptSize i (by simpa using member))) rest

theorem readMany_outputs (tx : Transaction) (witnesses : List (List ByteArray))
    (h : tx.WellFormed witnesses) (rest : List UInt8) :
    readMany readTxOutput tx.outputs.size
      (tx.outputs.toList.flatMap (fun o => (serializeTxOutput o).data.toList) ++ rest) =
      .ok (tx.outputs.toList, rest) := by
  have scriptSize : ∀ o ∈ tx.outputs, o.scriptPubKey.size < 2 ^ 64 := by
    have := h.scriptPubKeySize
    grind
  simpa using readMany_serialize readTxOutput serializeTxOutput tx.outputs.toList
    (fun o member => readTxOutput_serialize o (scriptSize o (by simpa using member))) rest

theorem readTransaction_legacy (tx : Transaction) (witnesses : List (List ByteArray))
    (h : tx.WellFormed witnesses) (rest : List UInt8) :
    readTransaction true ((serializeTransaction tx).data.toList ++ rest) =
      .ok (⟨tx, tx.inputs.toList.map (fun _ => [])⟩, rest) := by
  have inputCount : tx.inputs.size < 2 ^ 64 := by have := h.inputCount; omega
  have outputCount : tx.outputs.size < 2 ^ 64 := by have := h.outputCount; omega
  have unambiguous : tx.inputs.size > 0 ∨ tx.outputs.size = 0 := by have := h.unambiguous; omega
  by_cases empty : tx.inputs.size = 0
  · have outputEmpty : tx.outputs.size = 0 := unambiguous.resolve_left (by omega)
    have inputs : tx.inputs = #[] := Array.eq_empty_of_size_eq_zero empty
    have outputs : tx.outputs = #[] := Array.eq_empty_of_size_eq_zero outputEmpty
    simp [serializeTransaction_data, inputs, outputs, compactSize, readTransaction,
      readUInt32_unsignedLE, readCompactSize, takeExact, decodeLE,
      bind, Except.bind, pure, Except.pure]
    cases tx
    simp_all
  · simp [serializeTransaction_data, List.append_assoc, readTransaction,
      readUInt32_unsignedLE, readCompactSize_compactSize inputCount,
      readCompactSize_compactSize outputCount, empty, readMany_inputs tx witnesses h,
      readMany_outputs tx witnesses h, bind, Except.bind, pure, Except.pure]

theorem readTransaction_witness (tx : Transaction) (witnesses : List (List ByteArray))
    (h : tx.WellFormed witnesses) (nonempty : witnesses.all List.isEmpty = false)
    (rest : List UInt8) :
    readTransaction true ((serializeWitnessTransaction tx witnesses).data.toList ++ rest) =
      .ok (⟨tx, witnesses⟩, rest) := by
  have inputCount : tx.inputs.size < 2 ^ 64 := by have := h.inputCount; omega
  have outputCount : tx.outputs.size < 2 ^ 64 := by have := h.outputCount; omega
  have length : witnesses.length = tx.inputs.size := by have := h.witnessesLength; omega
  have witnessCount : ∀ stack ∈ witnesses, stack.length < 2 ^ 64 := by have := h.witnessCount; grind
  have itemSize : ∀ stack ∈ witnesses, ∀ item ∈ stack, item.size < 2 ^ 64 := by have := h.witnessItemSize; grind
  have positive : tx.inputs.size ≠ 0 := by
    intro zero
    have nil : witnesses = [] := List.eq_nil_of_length_eq_zero (by have := h.witnessesLength; omega)
    simp [nil] at nonempty
  have stacks := readMany_serialize readWitnessStack serializeWitness witnesses
    (fun stack member => readWitnessStack_serialize stack (witnessCount stack member)
      (itemSize stack member)) (unsignedLE 4 tx.locktime.toNat ++ rest)
  rw [length] at stacks
  have taken : witnesses.take tx.inputs.size = witnesses :=
    List.take_of_length_le (by have := h.witnessesLength; omega)
  unfold serializeWitnessTransaction
  split
  · simp_all <;> grind
  simp only [ByteArray.data_append, Array.toList_append]
  rw [serializeWitnesses_data tx witnesses length]
  simp only [← Array.foldl_toList, serialize_foldl_data]
  have zero (r : List UInt8) : readCompactSize (0 :: r) = .ok (0, r) := rfl
  have flag (r : List UInt8) : takeExact 1 (1 :: r) = .ok ([1], r) := by simp [takeExact]
  simp [List.append_assoc, readTransaction, readUInt32_unsignedLE, zero, flag,
    readCompactSize_compactSize inputCount, readCompactSize_compactSize outputCount,
    readMany_inputs tx witnesses h, readMany_outputs tx witnesses h,
    stacks, nonempty, bind, Except.bind, pure, Except.pure, decodeLE]

/-- Lossless BIP144 parsing, with the legacy empty-stack normalization explicit. -/
theorem parseTransaction_serializeWitnessTransaction (tx : Transaction)
    (witnesses : List (List ByteArray)) (h : tx.WellFormed witnesses) :
    parseTransaction (serializeWitnessTransaction tx witnesses) = .ok
      ⟨tx, if witnesses.all List.isEmpty then tx.inputs.toList.map (fun _ => []) else witnesses⟩ := by
  cases empty : witnesses.all List.isEmpty with
  | false =>
    have read := readTransaction_witness tx witnesses h empty []
    simp only [List.append_nil] at read
    simp [parseTransaction, decodeAll, read, bind, Except.bind, pure, Except.pure]
  | true =>
    have taken : witnesses.take tx.inputs.size = witnesses := List.take_of_length_le (by have := h.witnessesLength; omega)
    have read := readTransaction_legacy tx witnesses h []
    simp only [List.append_nil] at read
    unfold serializeWitnessTransaction
    split
    · simp [parseTransaction, decodeAll, read,
        bind, Except.bind, pure, Except.pure]
    · simp_all <;> grind

end Bitcoin
