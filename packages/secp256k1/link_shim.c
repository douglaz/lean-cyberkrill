/*
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
*/
#include <lean/lean.h>
#include <secp256k1.h>

LEAN_EXPORT lean_obj_res lck_secp_context_round_trip(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) return lean_io_result_mk_ok(lean_box(0));
    secp256k1_context_destroy(ctx);
    return lean_io_result_mk_ok(lean_box(1));
}
