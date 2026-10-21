/*
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
*/
#include <lean/lean.h>
#include <curl/curl.h>

LEAN_EXPORT lean_obj_res lck_curl_version(void) {
    return lean_io_result_mk_ok(lean_mk_string(curl_version()));
}
