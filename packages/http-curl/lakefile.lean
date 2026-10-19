/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lake
open Lake DSL

package «http-curl» where
  version := v!"0.1.0"
  description := "HTTP(S) client over libcurl"
  license := "MIT OR Apache-2.0"
  licenseFiles := #["../../LICENSE-MIT", "../../LICENSE-APACHE"]

@[default_target]
lean_lib HttpCurl

@[test_driver]
lean_lib HttpCurlTests
