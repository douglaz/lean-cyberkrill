/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

/-! # Secp256k1

Link target and context smoke check. Parsing, verification, recovery and signing
bindings arrive in Phase 1a (2 of 2). -/

namespace Secp256k1

/-- Create and destroy a context without touching any key material. -/
@[extern "lck_secp_context_round_trip"]
opaque contextRoundTrip : IO Bool

end Secp256k1
