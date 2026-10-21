/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package sha256 where
  version := v!"0.1.0"
  description := "SHA-256 and SHA-256d"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

@[default_target]
lean_lib Sha256

lean_lib Sha256TestSupport where
  roots := #[`Sha256Tests.AxiomGate]

@[test_driver]
lean_exe Sha256Tests
