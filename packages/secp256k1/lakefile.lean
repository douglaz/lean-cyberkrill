/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL
open System (FilePath)

package secp256k1 where
  version := v!"0.1.0"
  description := "libsecp256k1 bindings: pubkey parsing, ECDSA verify, recovery and signing"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]

target secpShim (pkg) : FilePath := do
  let src ← inputFile (pkg.dir / "link_shim.c") true
  buildO (pkg.buildDir / "c" / "link_shim.o") src
    #["-I", (← getLeanIncludeDir).toString] #["-fPIC"] (← getLeanCc)

target secpLib : Dynlib := do
  let some dir ← IO.getEnv "SECP256K1_LIB_DIR"
    | error "SECP256K1_LIB_DIR is missing; build inside nix develop"
  let path := System.FilePath.mk dir / "libsecp256k1.so"
  unless ← path.pathExists do
    error s!"libsecp256k1 is missing: {path}"
  return Job.pure { name := "secp256k1", path }

@[default_target]
lean_lib Secp256k1 where
  moreLinkObjs := #[secpShim]
  moreLinkLibs := #[secpLib]

@[test_driver]
lean_exe Secp256k1Tests
