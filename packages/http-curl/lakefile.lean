/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL
open System (FilePath)

package «http-curl» where
  version := v!"0.1.0"
  description := "HTTP(S) client over libcurl"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]

target curlShim (pkg) : FilePath := do
  let src ← inputFile (pkg.dir / "link_shim.c") true
  buildO (pkg.buildDir / "c" / "link_shim.o") src
    #["-I", (← getLeanIncludeDir).toString] #["-fPIC"] (← getLeanCc)

target curlLib : Dynlib := do
  let some dir ← IO.getEnv "CURL_LIB_DIR"
    | error "CURL_LIB_DIR is missing; build inside nix develop"
  let path := System.FilePath.mk dir / "libcurl.so"
  unless ← path.pathExists do
    error s!"libcurl is missing: {path}"
  return Job.pure { name := "curl", path }

-- Positive OpenSSL reference, linked with Lake's real executable-link machinery.
target opensslFixtureO (pkg) : FilePath := do
  let src ← inputFile (pkg.dir / "test" / "openssl_fixture.c") true
  buildO (pkg.buildDir / "c" / "openssl_fixture.o") src #[] #[] (← getLeanCc)

target opensslTwin (pkg) : FilePath := do
  buildLeanExe (pkg.binDir / "openssl-twin")
    #[← opensslFixtureO.fetch] #[← curlLib.fetch]

@[default_target]
lean_lib HttpCurl where
  moreLinkObjs := #[curlShim]
  moreLinkLibs := #[curlLib]

@[test_driver]
lean_lib HttpCurlTests
