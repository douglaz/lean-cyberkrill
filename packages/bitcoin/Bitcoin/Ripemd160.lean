/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Sha256

/-! RIPEMD-160, written from the algorithm description linked at
https://homes.esat.kuleuven.be/~bosselae/ripemd160.html.
All word arithmetic wraps at 32 bits; input and output words are little-endian.
The padding, word, block and step traversals use bounded loops. -/

namespace Bitcoin
namespace Ripemd160

private def leftWords : Array Nat := #[
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]

private def rightWords : Array Nat := #[
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]

private def leftRotations : Array UInt32 := #[
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]

private def rightRotations : Array UInt32 := #[
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]

private def leftConstants : Array UInt32 :=
  #[0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
private def rightConstants : Array UInt32 :=
  #[0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0]

private def rotate (x n : UInt32) : UInt32 := (x <<< n) ||| (x >>> (32 - n))

private def mix (round : Nat) (x y z : UInt32) : UInt32 :=
  match round with
  | 0 => x ^^^ y ^^^ z
  | 1 => (x &&& y) ||| (~~~x &&& z)
  | 2 => (x ||| ~~~y) ^^^ z
  | 3 => (x &&& z) ||| (y &&& ~~~z)
  | _ => x ^^^ (y ||| ~~~z)

private def pad (input : ByteArray) : ByteArray := Id.run do
  let mut padded := input.push 128
  for _ in [:(55 + 64 - input.size % 64) % 64] do
    padded := padded.push 0
  let bits := input.size.toUInt64 * 8
  for i in [:8] do
    padded := padded.push ((bits >>> (8 * i).toUInt64).toUInt8)
  return padded

/-- Hash arbitrary bytes to the 20-byte RIPEMD-160 digest. -/
def hash (input : ByteArray) : ByteArray := Id.run do
  let padded := pad input
  let mut h0 : UInt32 := 0x67452301
  let mut h1 : UInt32 := 0xefcdab89
  let mut h2 : UInt32 := 0x98badcfe
  let mut h3 : UInt32 := 0x10325476
  let mut h4 : UInt32 := 0xc3d2e1f0
  for block in [:padded.size / 64] do
    let mut words : Array UInt32 := #[]
    for word in [:16] do
      let mut value : UInt32 := 0
      for byte in [:4] do
        value := value ||| (padded[block * 64 + word * 4 + byte]!.toUInt32 <<< (8 * byte).toUInt32)
      words := words.push value
    let mut a := h0; let mut b := h1; let mut c := h2; let mut d := h3; let mut e := h4
    let mut ar := h0; let mut br := h1; let mut cr := h2; let mut dr := h3; let mut er := h4
    for step in [:80] do
      let round := step / 16
      let next := rotate (a + mix round b c d + words[leftWords[step]!]! +
        leftConstants[round]!) leftRotations[step]! + e
      a := e; e := d; d := rotate c 10; c := b; b := next
      let nextRight := rotate (ar + mix (4 - round) br cr dr + words[rightWords[step]!]! +
        rightConstants[round]!) rightRotations[step]! + er
      ar := er; er := dr; dr := rotate cr 10; cr := br; br := nextRight
    let nextH0 := h1 + c + dr
    h1 := h2 + d + er
    h2 := h3 + e + ar
    h3 := h4 + a + br
    h4 := h0 + b + cr
    h0 := nextH0
  let mut digest := ByteArray.empty
  for word in #[h0, h1, h2, h3, h4] do
    for byte in [:4] do
      digest := digest.push ((word >>> (8 * byte).toUInt32).toUInt8)
  return digest

end Ripemd160

/-- RIPEMD-160 with a 20-byte little-endian digest. -/
def ripemd160 : ByteArray → ByteArray := Ripemd160.hash

/-- Bitcoin HASH160: RIPEMD-160 of a single SHA-256 digest. -/
def hash160 (input : ByteArray) : ByteArray := ripemd160 (Sha256.hash input)

end Bitcoin
