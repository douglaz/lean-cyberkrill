/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package lightning where
  version := v!"0.1.0"
  description := "BOLT11 invoices and LNURL"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

require bitcoin from ".." / "bitcoin"

@[default_target]
lean_lib Lightning

lean_lib LightningTestSupport where
  roots := #[`LightningTests.Bolt11]

@[test_driver]
lean_exe LightningTests
