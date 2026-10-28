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
require Cli from ".lake" / "packages" / "Cli"

target privateOutputShim (pkg) : System.FilePath := do
  let src ← inputFile (pkg.dir / "private_output.c") true
  buildO (pkg.buildDir / "c" / "private_output.o") src
    #["-I", (← getLeanIncludeDir).toString] #["-fPIC", "-Wall", "-Wextra", "-Werror"] (← getLeanCc)

lean_lib Cyberkrill where
  moreLinkObjs := #[privateOutputShim]

@[default_target]
lean_exe cyberkrill where
  root := `Main

lean_exe linkspike where
  root := `LinkSpike

lean_lib CyberkrillTestSupport where
  globs := #[.submodules `CyberkrillTests]

@[test_driver]
lean_exe CyberkrillTests where
  extraDepTargets := #[`cyberkrill]
