/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package «fedimint-invite» where
  version := v!"0.1.0"
  description := "Fedimint invite codes"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]

require bitcoin from ".." / "bitcoin"

@[default_target]
lean_lib FedimintInvite

@[test_driver]
lean_lib FedimintInviteTests
