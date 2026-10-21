/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package cyberkrill where
  version := v!"0.1.0"
  description := "cyberkrill command-line tool"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]

require sha256 from ".." / "sha256"
require secp256k1 from ".." / "secp256k1"
require bitcoin from ".." / "bitcoin"
require lightning from ".." / "lightning"
require «fedimint-invite» from ".." / "fedimint-invite"
require «http-curl» from ".." / "http-curl"

lean_lib Cyberkrill

@[default_target]
lean_exe cyberkrill where
  root := `Main

lean_exe linkspike where
  root := `LinkSpike

@[test_driver]
lean_lib CyberkrillTests
