/*
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
*/
#include <lean/lean.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>

/* Option ByteArray: none is scalar 0; some is tag 1 with one object field. */
static lean_obj_res some_bytes(const unsigned char *bytes, size_t len) {
    lean_object *array = lean_alloc_sarray(1, len, len);
    memcpy(lean_sarray_cptr(array), bytes, len);
    lean_object *result = lean_alloc_ctor(1, 1, 0);
    lean_ctor_set(result, 0, array);
    return result;
}

static int parse_key(b_lean_obj_arg key, secp256k1_pubkey *parsed) {
    size_t len = lean_sarray_size(key);
    if (len != 33 && len != 65) return 0;
    const unsigned char *bytes = lean_sarray_cptr(key);
    if ((len == 33 && bytes[0] != 2 && bytes[0] != 3) ||
        (len == 65 && bytes[0] != 4)) return 0;
    return secp256k1_ec_pubkey_parse(secp256k1_context_static, parsed, bytes, len);
}

LEAN_EXPORT uint8_t lck_secp_pubkey_parse(b_lean_obj_arg key) {
    secp256k1_pubkey parsed;
    return parse_key(key, &parsed);
}

LEAN_EXPORT lean_obj_res lck_secp_compress_pubkey(b_lean_obj_arg key) {
    size_t input_len = lean_sarray_size(key);
    if (input_len != 33 && input_len != 65) return lean_box(0);
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed,
                                  lean_sarray_cptr(key), input_len)) return lean_box(0);
    unsigned char bytes[33];
    size_t len = sizeof(bytes);
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, bytes, &len, &parsed,
                                     SECP256K1_EC_COMPRESSED)) return lean_box(0);
    return some_bytes(bytes, len);
}

LEAN_EXPORT uint8_t lck_secp_verify(b_lean_obj_arg hash, b_lean_obj_arg signature,
                                    b_lean_obj_arg key) {
    if (lean_sarray_size(hash) != 32 || lean_sarray_size(signature) != 64) return 0;
    secp256k1_pubkey parsed;
    secp256k1_ecdsa_signature sig;
    if (!parse_key(key, &parsed)) return 0;
    if (!secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &sig,
                                               lean_sarray_cptr(signature))) return 0;
    return secp256k1_ecdsa_verify(secp256k1_context_static, &sig,
                                lean_sarray_cptr(hash), &parsed);
}

LEAN_EXPORT lean_obj_res lck_secp_recover(b_lean_obj_arg hash,
                                         b_lean_obj_arg signature, uint8_t recid) {
    if (lean_sarray_size(hash) != 32 || lean_sarray_size(signature) != 64 || recid > 3)
        return lean_box(0);
    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_pubkey key;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_static,
            &sig, lean_sarray_cptr(signature), recid)) return lean_box(0);
    if (!secp256k1_ecdsa_recover(secp256k1_context_static, &key, &sig,
                               lean_sarray_cptr(hash))) return lean_box(0);
    unsigned char bytes[33];
    size_t len = sizeof(bytes);
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, bytes, &len, &key,
                                     SECP256K1_EC_COMPRESSED)) return lean_box(0);
    return some_bytes(bytes, len);
}

LEAN_EXPORT lean_obj_res lck_secp_sign(b_lean_obj_arg hash, b_lean_obj_arg secret_key) {
    if (lean_sarray_size(hash) != 32 || lean_sarray_size(secret_key) != 32)
        return lean_box(0);
    if (!secp256k1_ec_seckey_verify(secp256k1_context_static,
                                   lean_sarray_cptr(secret_key))) return lean_box(0);
    /* Per-call ownership avoids shared mutable state and static-context ARG_CHECK. */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) return lean_box(0);
    secp256k1_ecdsa_recoverable_signature sig;
    unsigned char bytes[65];
    int recid = 0;
    int ok = secp256k1_ecdsa_sign_recoverable(ctx, &sig, lean_sarray_cptr(hash),
                                            lean_sarray_cptr(secret_key), NULL, NULL);
    if (ok) ok = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, bytes,
                                                                      &recid, &sig);
    secp256k1_context_destroy(ctx);
    if (!ok) return lean_box(0);
    bytes[64] = (unsigned char)recid;
    return some_bytes(bytes, sizeof(bytes));
}

LEAN_EXPORT lean_obj_res lck_secp_context_round_trip(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) return lean_io_result_mk_ok(lean_box(0));
    secp256k1_context_destroy(ctx);
    return lean_io_result_mk_ok(lean_box(1));
}
