-- Copied from febyeji/lean-miniscript @ cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd, LeanMiniscript/Bitcoin/Base64.lean L1-79; MIT, see LICENSE-miniscript
namespace Bitcoin.Base64

/-! RFC4648 section 4 Base64 with mandatory padding. Decoding is strict: the
length must be a multiple of four, only the standard alphabet is accepted,
padding may appear only at the end, and unused low bits of the final group
must be zero, which makes accepted encodings canonical.

The executable contract is exercised by RFC4648 vectors, every byte value,
and strict rejection vectors in `Base64Examples`.
-/

def alphabet : Array Char :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toList.toArray

private def symbol (value : Nat) : Char := alphabet[value % 64]!

private def encodeGroup : List UInt8 → List Char
  | [a] =>
      let n := a.toNat * 65536
      [symbol (n / 262144), symbol (n / 4096), '=', '=']
  | [a, b] =>
      let n := a.toNat * 65536 + b.toNat * 256
      [symbol (n / 262144), symbol (n / 4096), symbol (n / 64), '=']
  | a :: b :: c :: _ =>
      let n := a.toNat * 65536 + b.toNat * 256 + c.toNat
      [symbol (n / 262144), symbol (n / 4096), symbol (n / 64), symbol n]
  | [] => []

/-- Groups go into an accumulator, so the traversal is tail recursive and
large inputs do not grow the call stack. -/
private def encodeList (fuel : Nat) (bytes : List UInt8) : List Char :=
  go fuel bytes #[]
where
  go : Nat → List UInt8 → Array Char → List Char
    | 0, _, acc => acc.toList
    | fuel + 1, bytes, acc =>
        match bytes with
        | [] => acc.toList
        | _ => go fuel (bytes.drop 3) (acc ++ encodeGroup (bytes.take 3))

def encode (bytes : ByteArray) : String :=
  String.ofList (encodeList bytes.size bytes.data.toList)

private def value (char : Char) : Option Nat :=
  if 'A' ≤ char ∧ char ≤ 'Z' then some (char.toNat - 'A'.toNat)
  else if 'a' ≤ char ∧ char ≤ 'z' then some (char.toNat - 'a'.toNat + 26)
  else if '0' ≤ char ∧ char ≤ '9' then some (char.toNat - '0'.toNat + 52)
  else if char = '+' then some 62
  else if char = '/' then some 63
  else none

private def decodeGroup (last : Bool) : List Char → Option (List UInt8)
  | [a, b, '=', '='] => do
      guard last
      let n := (← value a) * 262144 + (← value b) * 4096
      guard (n % 65536 == 0)
      return [UInt8.ofNat (n / 65536)]
  | [a, b, c, '='] => do
      guard last
      let n := (← value a) * 262144 + (← value b) * 4096 + (← value c) * 64
      guard (n % 256 == 0)
      return [UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256)]
  | [a, b, c, d] => do
      let n := (← value a) * 262144 + (← value b) * 4096 + (← value c) * 64 + (← value d)
      return [UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]
  | _ => none

/-- Tail recursive, like `encodeList`. -/
private def decodeList (fuel : Nat) (chars : List Char) : Option (List UInt8) :=
  go fuel chars #[]
where
  go : Nat → List Char → Array UInt8 → Option (List UInt8)
    | 0, _, _ => none
    | fuel + 1, chars, acc =>
        match chars with
        | [] => some acc.toList
        | _ =>
            let rest := chars.drop 4
            match decodeGroup rest.isEmpty (chars.take 4) with
            | none => none
            | some group => go fuel rest (acc ++ group)

def decode (text : String) : Option ByteArray := do
  let chars := text.toList
  guard (chars.length % 4 == 0)
  let bytes ← decodeList (chars.length + 1) chars
  return ⟨bytes.toArray⟩

end Bitcoin.Base64
