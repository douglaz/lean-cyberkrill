/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package secp256k1 where
  version := v!"0.1.0"
  description := "libsecp256k1 bindings: pubkey parsing, ECDSA verify, recovery and signing"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]

@[default_target]
lean_lib Secp256k1

@[test_driver]
lean_lib Secp256k1Tests
