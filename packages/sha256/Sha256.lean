/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

import Sha256.Api

/-! SHA-256 and SHA-256d over byte arrays, with specification and size proofs. -/

namespace Sha256

/-- SHA-256 through the copied, proved implementation. -/
def hash (msg : ByteArray) : ByteArray := (sha256 msg).toByteArray

theorem hash_spec (msg : ByteArray) :
    (hash msg).data.toList = Spec.sha256_bytes msg.data.toList := sha256_spec msg

theorem hash_size (msg : ByteArray) : (hash msg).size = 32 :=
  Digest.size_toByteArray (sha256 msg)

/-- SHA-256 applied twice, in raw digest byte order. -/
def sha256d (msg : ByteArray) : ByteArray := hash (hash msg)

theorem sha256d_spec (msg : ByteArray) :
    (sha256d msg).data.toList = Spec.sha256_bytes (Spec.sha256_bytes msg.data.toList) := by
  rw [sha256d, hash_spec, hash_spec]

theorem sha256d_size (msg : ByteArray) : (sha256d msg).size = 32 := hash_size (hash msg)

end Sha256
