-- Copied from febyeji/lean-miniscript @ cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd, LeanMiniscript/Bitcoin/Deserialization.lean L81-170; MIT, see LICENSE-miniscript
import Bitcoin.Transaction
import Sha256

namespace Bitcoin

open CompactSize

def readOutPoint : Decoder OutPoint := fun bytes => do
  let (txid, rest) ← takeExact 32 bytes
  let (index, rest) ← readUInt32 rest
  return ({ txid := ⟨txid.toArray⟩, index }, rest)

def readTxInput : Decoder TxInput := fun bytes => do
  let (previousOutput, rest) ← readOutPoint bytes
  let (scriptSig, rest) ← readByteVector rest
  let (sequence, rest) ← readUInt32 rest
  return ({ previousOutput, scriptSig, sequence }, rest)

def readTxOutput : Decoder TxOutput := fun bytes => do
  let (amount, rest) ← readUInt64 bytes
  let (scriptPubKey, rest) ← readByteVector rest
  return ({ amount, scriptPubKey }, rest)

/-- One input's witness stack: an item count and length-prefixed items. -/
def readWitnessStack : Decoder (List ByteArray) := fun bytes => do
  let (count, rest) ← readCompactSize bytes
  readMany readByteVector count rest

/-- A transaction together with its per-input witness stacks. Stacks are
empty for non-witness serialization. -/
structure WitnessTransaction where
  transaction : Transaction
  witnesses : List (List ByteArray)
  deriving Repr, Inhabited

/-- Core's transaction reader. With `allowWitness`, an empty input vector is
read as the BIP144 marker and a flag byte follows; flag bit 0 selects witness
stacks and any other bit is rejected. A zero flag ends both vectors, as in
Core. A witness flag with only empty stacks is rejected as superfluous.
Without `allowWitness`, an empty input vector is an ordinary zero-input
transaction. -/
def readTransaction (allowWitness : Bool) : Decoder WitnessTransaction := fun bytes => do
  let (version, rest) ← readUInt32 bytes
  let (inputCount, rest) ← readCompactSize rest
  let (flags, inputs, outputs, rest) ← do
    if inputCount = 0 ∧ allowWitness then
      let (flag, rest) ← takeExact 1 rest
      let flag := decodeLE flag
      if flag = 0 then
        -- Core reads a zero flag as an empty input and output vector.
        pure (0, [], [], rest)
      else
        let (inputCount, rest) ← readCompactSize rest
        let (inputs, rest) ← readMany readTxInput inputCount rest
        let (outputCount, rest) ← readCompactSize rest
        let (outputs, rest) ← readMany readTxOutput outputCount rest
        pure (flag, inputs, outputs, rest)
    else
      let (inputs, rest) ← readMany readTxInput inputCount rest
      let (outputCount, rest) ← readCompactSize rest
      let (outputs, rest) ← readMany readTxOutput outputCount rest
      pure (0, inputs, outputs, rest)
  let (witnesses, rest) ← do
    if flags % 2 = 1 then
      let (witnesses, rest) ← readMany readWitnessStack inputs.length rest
      if witnesses.all List.isEmpty then throw .superfluousWitness
      pure (witnesses, rest)
    else pure (inputs.map (fun _ => []), rest)
  if flags / 2 ≠ 0 then throw .unknownTransactionFlags
  let (locktime, rest) ← readUInt32 rest
  return ({ transaction := { version, inputs := inputs.toArray, outputs := outputs.toArray, locktime }
            witnesses }, rest)

/-- Parse a complete transaction byte string. -/
def parseTransaction (bytes : ByteArray) (allowWitness : Bool := true) :
    Except DecodeError WitnessTransaction :=
  decodeAll (readTransaction allowWitness) bytes

/-- Transaction identifier bytes in wire order. -/
def Transaction.txid (tx : Transaction) : ByteArray :=
  Sha256.sha256d (serializeTransaction tx)

/-- BIP144 serialization. The marker and flag are emitted only when some
witness stack is nonempty, as in Core; otherwise this is the legacy form.
Missing stacks are treated as empty. -/
def serializeWitnessTransaction (tx : Transaction) (witnesses : List (List ByteArray)) : ByteArray :=
  if witnesses.all List.isEmpty then serializeTransaction tx
  else
    ⟨(unsignedLE 4 tx.version.toNat ++ [0, 1] ++ compactSize tx.inputs.size).toArray⟩ ++
      tx.inputs.foldl (fun bytes input => bytes ++ serializeTxInput input) ByteArray.empty ++
      ⟨(compactSize tx.outputs.size).toArray⟩ ++
      tx.outputs.foldl (fun bytes output => bytes ++ serializeTxOutput output) ByteArray.empty ++
      (List.range tx.inputs.size).foldl
        (fun bytes index => bytes ++ serializeWitness (witnesses.getD index [])) ByteArray.empty ++
      ⟨(unsignedLE 4 tx.locktime.toNat).toArray⟩

end Bitcoin
