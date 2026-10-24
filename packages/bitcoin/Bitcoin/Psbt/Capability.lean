/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

namespace Bitcoin.Psbt

/-- Supplied curve operations. Partial signatures use strict SEC1 validation;
BIP32 derivations use the curve parser that also accepts matching hybrid keys.
Successful compression returns the canonical 33-byte point encoding. Global
xpub points use strict SEC1 validation; Taproot keys use x-only validation.
Partial-signature DER validation checks encoding without verification or low-S. -/
structure PubkeyCapability where
  isValidPubkey : ByteArray → Bool
  compressPubkey : ByteArray → Option ByteArray
  isValidXOnlyPubkey : ByteArray → Bool
  isValidDerSignature : ByteArray → Bool

/-- The two preimage hashes supplied by the caller. SHA256 and HASH256 always
use the sha256 package directly. -/
structure PreimageHashes where
  ripemd160 : ByteArray → ByteArray
  hash160 : ByteArray → ByteArray

end Bitcoin.Psbt
