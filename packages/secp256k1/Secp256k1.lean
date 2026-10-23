/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

/-! Pure, deterministic, thread-safe curve operations over borrowed byte arrays.
No input is mutated; successful object results are freshly allocated. -/

namespace Secp256k1

/-- Create and destroy a context without touching any key material. -/
@[extern "lck_secp_context_round_trip"]
opaque contextRoundTrip : IO Bool

/-- `isValidPubkey key` accepts a 33-byte compressed (02/03) or 65-byte
uncompressed (04) SEC1 public key. Returns false for wrong lengths, hybrid
encodings, invalid prefixes, or points outside the curve. -/
@[extern "lck_secp_pubkey_parse"]
opaque isValidPubkey (key : @& ByteArray) : Bool

/-- Parse a 32-byte BIP340 x-only public key. Returns false for every other
length, coordinates outside the field, or points outside the curve. -/
@[extern "lck_secp_xonly_pubkey_parse"]
opaque isValidXOnlyPubkey (key : @& ByteArray) : Bool

/-- Parse a nonempty strict DER ECDSA signature, without its sighash byte.
This checks encoding only: no verification, low-S check or normalisation.
Well-encoded out-of-range integers follow libsecp256k1's parse rule. -/
@[extern "lck_secp_der_signature_parse"]
opaque isValidDerSignature (sig : @& ByteArray) : Bool

/-- Parse a 33-byte 02/03 or 65-byte 04 SEC1 key, also accepting a 65-byte
06/07 hybrid key whose tag matches y's parity. Return its canonical 33-byte
compressed encoding, or none for malformed lengths, prefixes or curve points.
Uses libsecp256k1's parse rule without a separate prefix restriction. -/
@[extern "lck_secp_compress_pubkey"]
opaque compressPubkey (key : @& ByteArray) : Option ByteArray

/-- `verify hash signature key` checks a 32-byte message hash and 64-byte compact
ECDSA signature (big-endian r ‖ s) against a SEC1 key as in `isValidPubkey`.
Returns false for malformed lengths/keys, r or s ≥ the curve order, zero scalars,
high-S signatures (no normalisation), or a signature that does not verify. -/
@[extern "lck_secp_verify"]
opaque verify (hash signature key : @& ByteArray) : Bool

/-- `recover hash signature recid` returns a fresh 33-byte compressed SEC1 key.
The hash is 32 bytes, signature is 64-byte big-endian r ‖ s, and recid is 0–3.
High-S is preserved. Returns none for wrong lengths, recid > 3, r or s ≥ the
curve order, zero scalars, or failure to recover a curve point. -/
@[extern "lck_secp_recover"]
opaque recover (hash signature : @& ByteArray) (recid : UInt8) : Option ByteArray

/-- `sign hash secretKey` returns a fresh 65-byte recoverable ECDSA signature:
64-byte big-endian r ‖ s (low-S), followed by recid (0–3). Uses deterministic
RFC 6979, without extra entropy. Both inputs must be 32 bytes. Returns none for
wrong lengths, secret key zero or ≥ the curve order, or signing/context failure.
Signing is used only with published test vectors in v1. -/
@[extern "lck_secp_sign"]
opaque sign (hash secretKey : @& ByteArray) : Option ByteArray

end Secp256k1
