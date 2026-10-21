/*
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
*/
#include <lean/lean.h>
#include <curl/curl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

LEAN_EXPORT lean_obj_res lck_curl_version(void) {
    return lean_io_result_mk_ok(lean_mk_string(curl_version()));
}

LEAN_EXPORT lean_obj_res lck_curl_error_message(uint32_t code) {
    return lean_io_result_mk_ok(lean_mk_string(curl_easy_strerror((CURLcode)code)));
}

struct buffer {
    unsigned char *data;
    size_t size, limit;
    int exceeded;
};

static size_t receive(char *data, size_t size, size_t count, void *context) {
    struct buffer *b = context;
    if (size && count > SIZE_MAX / size) return 0;
    size_t bytes = size * count;
    if (bytes > b->limit - b->size) {
        b->exceeded = 1;
        return 0;
    }
    if (!bytes) return 0;
    unsigned char *next = realloc(b->data, b->size + bytes);
    if (!next) return 0;
    b->data = next;
    memcpy(b->data + b->size, data, bytes);
    b->size += bytes;
    return bytes;
}

static lean_object *bytes_object(const struct buffer *b) {
    lean_object *result = lean_alloc_sarray(1, b->size, b->size);
    if (b->size) memcpy(lean_sarray_cptr(result), b->data, b->size);
    return result;
}

/* RawResponse: two objects, then code/status uint32_t at scalar offsets 0/4.
   Checked against regenerated HttpCurl.c by the documented ABI syntax check. */
static lean_object *response(uint32_t code, uint32_t status,
                             struct buffer *headers, struct buffer *body) {
    lean_object *result = lean_alloc_ctor(0, 2, 8);
    lean_ctor_set(result, 0, bytes_object(headers));
    lean_ctor_set(result, 1, bytes_object(body));
    lean_ctor_set_uint32(result, 2 * sizeof(void *), code);
    lean_ctor_set_uint32(result, 2 * sizeof(void *) + 4, status);
    free(headers->data);
    free(body->data);
    return lean_io_result_mk_ok(result);
}

static const char *ca_source(uint8_t has_fallback, const char *fallback) {
    const char *env = getenv("SSL_CERT_FILE");
    if (env && *env) return env;
    if (has_fallback) return fallback;
    static const char *paths[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem"
    };
    struct stat info;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (stat(paths[i], &info) == 0) return paths[i];
    return NULL;
}

LEAN_EXPORT lean_obj_res lck_curl_request(uint8_t post, b_lean_obj_arg url,
        b_lean_obj_arg headers, b_lean_obj_arg body, uint8_t auth,
        b_lean_obj_arg user, b_lean_obj_arg password, size_t limit,
        uint32_t connect_ms, uint32_t total_ms, uint8_t has_fallback,
        b_lean_obj_arg fallback) {
    struct buffer received = { .limit = limit };
    struct buffer received_headers = { .limit = 65536 };
    CURLcode code = CURLE_OK;
    long status = 0;
    CURL *curl = NULL;
    struct curl_slist *list = NULL;
    /* Repeated global_init is safe only on a thread-safe libcurl build.
       No global_cleanup: other callers may still own easy handles. */
    if (!(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_THREADSAFE)) {
        code = CURLE_FAILED_INIT;
        goto done;
    }
    code = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (code != CURLE_OK) goto done;
    curl = curl_easy_init();
    if (!curl) { code = CURLE_FAILED_INIT; goto done; }
#define SET(option, value) do { code = curl_easy_setopt(curl, option, value); \
    if (code != CURLE_OK) goto done; } while (0)
    SET(CURLOPT_URL, lean_string_cstr(url));
    SET(CURLOPT_PROTOCOLS_STR, "http,https");
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_CONNECTTIMEOUT_MS, (long)connect_ms);
    SET(CURLOPT_TIMEOUT_MS, (long)total_ms);
    SET(CURLOPT_WRITEFUNCTION, receive);
    SET(CURLOPT_WRITEDATA, &received);
    SET(CURLOPT_HEADERFUNCTION, receive);
    SET(CURLOPT_HEADERDATA, &received_headers);
    if (strncmp(lean_string_cstr(url), "https://", 8) == 0) {
        const char *ca = ca_source(has_fallback, lean_string_cstr(fallback));
        if (!ca || !*ca) { code = CURLE_SSL_CACERT_BADFILE; goto done; }
        SET(CURLOPT_CAINFO, ca);
        /* Disable a compiled-in CA directory as well as default-file fallback. */
        SET(CURLOPT_CAPATH, "");
    }
    for (size_t i = 0; i < lean_array_size(headers); ++i) {
        struct curl_slist *next = curl_slist_append(list,
            lean_string_cstr(lean_array_get_core(headers, i)));
        if (!next) { code = CURLE_OUT_OF_MEMORY; goto done; }
        list = next;
    }
    SET(CURLOPT_HTTPHEADER, list);
    if (auth) {
        SET(CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
        SET(CURLOPT_USERNAME, lean_string_cstr(user));
        SET(CURLOPT_PASSWORD, lean_string_cstr(password));
    }
    if (post) {
        size_t length = lean_sarray_size(body);
        if (length > INT64_MAX) { code = CURLE_BAD_FUNCTION_ARGUMENT; goto done; }
        SET(CURLOPT_POST, 1L);
        SET(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)length);
        SET(CURLOPT_POSTFIELDS, length ? (const char *)lean_sarray_cptr(body) : "");
    }
    code = curl_easy_perform(curl);
    if (code == CURLE_OK) code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
done:
    if (curl) curl_easy_cleanup(curl);
    curl_slist_free_all(list);
    return response(received.exceeded ? 1000 : (uint32_t)code, (uint32_t)status,
                    &received_headers, &received);
#undef SET
}
