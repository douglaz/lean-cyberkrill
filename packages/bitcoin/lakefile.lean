/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package bitcoin where
  version := v!"0.1.0"
  description := "Bitcoin encodings: hex, CompactSize, base58, bech32, addresses, amounts, transactions, PSBT, BIP39"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

require sha256 from ".." / "sha256"

@[default_target]
lean_lib Bitcoin

lean_lib BitcoinTestSupport where
  roots := #[`BitcoinTests.AxiomGate]

@[test_driver]
lean_exe BitcoinTests
