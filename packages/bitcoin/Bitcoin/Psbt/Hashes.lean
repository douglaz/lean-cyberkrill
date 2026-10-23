/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Psbt.Capability
import Bitcoin.Ripemd160

namespace Bitcoin.Psbt

/-- Pure hash operations for PSBT RIPEMD160 and HASH160 preimage validation. -/
def preimageHashes : PreimageHashes where
  ripemd160 := Bitcoin.ripemd160
  hash160 := Bitcoin.hash160

end Bitcoin.Psbt
