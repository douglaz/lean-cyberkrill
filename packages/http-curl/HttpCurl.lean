/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/

/-! # HttpCurl

Link target and version smoke check only. The HTTP(S) client arrives in Phase 1b. -/

namespace HttpCurl

/-- Report the linked libcurl and TLS backend versions; performs no network I/O. -/
@[extern "lck_curl_version"]
opaque version : IO String

end HttpCurl
