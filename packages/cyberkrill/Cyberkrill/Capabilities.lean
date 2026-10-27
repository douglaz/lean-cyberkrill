/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Lightning
import Secp256k1

namespace Cyberkrill

def pubkeys : Bitcoin.Psbt.PubkeyCapability where
  isValidPubkey := Secp256k1.isValidPubkey
  compressPubkey := Secp256k1.compressPubkey
  isValidXOnlyPubkey := Secp256k1.isValidXOnlyPubkey
  isValidDerSignature := Secp256k1.isValidDerSignature

def preimageHashes : Bitcoin.Psbt.PreimageHashes where
  ripemd160 := Bitcoin.ripemd160
  hash160 := Bitcoin.hash160

/-- The caller owns the key; there is no default signing secret. -/
def bolt11Curve (secret : ByteArray) : Lightning.Bolt11.Curve where
  recover := Secp256k1.recover
  verify := Secp256k1.verify
  sign := fun hash => Secp256k1.sign hash secret
  isValidPubkey := Secp256k1.isValidPubkey

end Cyberkrill
