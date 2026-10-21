#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Isolate production mutations, capture separate streams, restore source/index.

Run from this package inside nix develop. --sandbox selects C3/C7; it stages
only the adapter for each nix flake check, then restores its original index bytes.
No tests, expectations, responder code or tracker files are mutated.
"""
import argparse
import json
from pathlib import Path
import subprocess


def mutations():
    yield "T1", "status", "lean", "status := raw.status", "status := 0", "T1 status"
    yield "T1", "request-header", "c", "SET(CURLOPT_HTTPHEADER, list);", "/* omit headers */", "T1 request header"
    yield "T1", "response-header", "lean", 'headers := headers.push (name.toLower,', 'if name.toLower != "content-type" then headers := headers.push (name.toLower,', "T1 response header"
    yield "T2", "body", "c", "size_t length = lean_sarray_size(body);", "size_t length = 0;", "T2 body"
    for index in [0, 1]:
        yield "T2", f"header-{index}", "c", "struct curl_slist *next = curl_slist_append(list,", f"if (i == {index}) continue;\n        struct curl_slist *next = curl_slist_append(list,", "T2 headers"
    yield "T3", "auth", "c", "if (auth) {", "if (0) {", "T3 right auth"
    yield "T4", "http-status", "c", "SET(CURLOPT_PROXY, \"\");", "SET(CURLOPT_PROXY, \"\"); SET(CURLOPT_FAILONERROR, 1L);", "T4 normal response"
    yield "T4", "status-code", "lean", "status := raw.status", "status := 0", "T4 status 401"
    yield "T5", "size-kind", "c", "received.exceeded ? 1000", "received.exceeded ? 23", "T5 streaming size"
    yield "T5", "stream-abort", "c", "if (bytes > b->limit - b->size)", "if (0)", "T5 outer deadline (2s)"
    yield "T5", "abort-bound", "lean", 'if code == 1000 || code == 63 then return .error (.tooLarge req.maxResponseBytes)', 'if code == 1000 || code == 63 then\n    IO.sleep 1700\n    return .error (.tooLarge req.maxResponseBytes)', "T5 abort bound"
    yield "T6", "inclusive-boundary", "c", "if (bytes > b->limit - b->size)", "if (bytes >= b->limit - b->size)", "T6 inclusive limit"
    yield "T6", "exact-body", "c", "memcpy(b->data + b->size, data, bytes);", "memset(b->data + b->size, 0, bytes);", "T6 exact body"
    yield "T7", "total-timeout", "c", "SET(CURLOPT_TIMEOUT_MS, (long)total_ms);", "/* omit timeout */", "T7 outer deadline (2s)"
    yield "T7", "timeout-kind", "lean", '.timeout code "Request timed out"', '.curl code "Request timed out"', "T7 timeout kind"
    yield "T7", "timeout-bound", "c", "SET(CURLOPT_TIMEOUT_MS, (long)total_ms);", "SET(CURLOPT_TIMEOUT_MS, (long)total_ms * 6);", "T7 timeout bound"
    yield "T8", "connect-kind", "lean", "code == 6 || code == 7", "code == 6", "T8 connect kind"
    yield "T9", "user-redaction", "lean", '.connect code "Connection failed"', '.connect code user', "T9 user redaction"
    yield "T9", "password-redaction", "lean", '.connect code "Connection failed"', '.connect code password', "T9 password redaction"
    yield "T10", "empty-header", "lean", 'then k ++ ";" else k ++ ": " ++ v', 'then k ++ ": " ++ v else k ++ ": " ++ v', "T10 empty header present"
    yield "T10", "full-header", "c", "struct curl_slist *next = curl_slist_append(list,", "if (i == 1) continue;\n        struct curl_slist *next = curl_slist_append(list,", "T10 full header"
    yield "T10", "whitespace-header", "lean", "v.toList.all (fun c => c == ' ' || c == '\\t')", "v.isEmpty", "T10 whitespace header present"
    authority = "(authority.toList.takeWhile (fun c => c != '/' && c != '?' && c != '#')).contains '@'"
    yield "T11", "query-authority", "lean", authority, '((authority.splitOn "/").headD "").contains \'@\'', "T11 query at-sign"
    yield "T11", "userinfo", "lean", authority, "false", "T11 reject userinfo"
    yield "T12", "curl-code", "lean", '.curl code (← errorMessage code)', '.curl 23 (← errorMessage code)', "T12 curl code 52"
    yield "T12", "curl-message", "lean", '.curl code (← errorMessage code)', '.curl code "HTTP transport failure"', "T12 curl message"
    yield "T13", "one-over-boundary", "c", "if (bytes > b->limit - b->size)", "if (bytes > b->limit - b->size + 1)", "T13 one byte over limit"
    yield "C1", "environment-ca", "c", 'if (env && *env) return env;', 'if (env && *env) return "/missing-http-curl-ca";', "C1 environment CA"
    for case, assertion in [("C2", "untrusted CA"), ("C6", "missing hook")]:
        yield case, "certificate-kind", "lean", '.tls code "TLS or certificate failure"', '.curl code "TLS or certificate failure"', f"{case} {assertion}"
    # The explicit-source precheck and empty CAPATH independently prevent curl
    # fallback. Disable both protections to test the one no-default-trust property.
    yield "C3", "no-curl-fallback", "c", 'if (!ca || !*ca) { code = CURLE_SSL_CACERT_BADFILE; goto done; }\n        SET(CURLOPT_CAINFO, ca);\n        /* Disable a compiled-in CA directory as well as default-file fallback. */\n        SET(CURLOPT_CAPATH, "");', 'if (ca && *ca) { SET(CURLOPT_CAINFO, ca); }', "C3 ignore NIX CA"
    yield "C4", "empty-is-set", "c", 'if (env && *env) return env;', 'if (env) return env;', "C4 empty environment CA"
    yield "C5", "fallback-hook", "c", "if (has_fallback) return fallback;", "/* ignore hook */", "C5 fallback hook"
    yield "C7", "http-ca-scope", "c", 'if (strncmp(lean_string_cstr(url), "https://", 8) == 0)', 'if (strncmp(lean_string_cstr(url), "https://", 8) == 0 || (lean_array_size(headers) == 0 && strstr(lean_string_cstr(url), "/echo")))', "C7 plain HTTP without CA"
    yield "C8", "environment-precedence", "c", 'if (env && *env) return env;\n    if (has_fallback) return fallback;', 'if (has_fallback) return fallback;\n    if (env && *env) return env;', "C8 environment precedence"
    yield "C9", "per-request-env", "c", 'const char *env = getenv("SSL_CERT_FILE");', 'static char *cached = NULL;\n    if (!cached) cached = strdup(getenv("SSL_CERT_FILE") ? getenv("SSL_CERT_FILE") : "");\n    const char *env = cached;', "C9 per-request CA"
    yield "C9", "initial-missing-ca", "c", 'received.exceeded ? 1000 : (uint32_t)code', 'received.exceeded ? 1000 : (code == CURLE_SSL_CACERT_BADFILE ? 0 : (uint32_t)code)', "C9 initial missing CA"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox", action="store_true")
    args = parser.parse_args()
    paths = {"c": Path("link_shim.c"), "lean": Path("HttpCurl.lean")}
    originals = {kind: path.read_text() for kind, path in paths.items()}
    logs = Path(".lake/mutation-checks")
    logs.mkdir(parents=True, exist_ok=True)
    records = []
    index = subprocess.run(["git", "show", ":packages/http-curl/link_shim.c"], capture_output=True, check=True).stdout
    try:
        for case, label, kind, old, new, assertion in mutations():
            if (case in ["C3", "C7"]) != args.sandbox:
                continue
            original = originals[kind]
            assert original.count(old) == 1, (case, label, old)
            mutated = original.replace(old, new)
            paths[kind].write_text(mutated)
            assert paths[kind].read_text() == mutated and new in mutated
            assert mutated.count(old) == new.count(old)
            if args.sandbox:
                subprocess.run(["git", "add", "--", "link_shim.c"], check=True)
                command = ["nix", "flake", "check", "-L", "../.."]
            else:
                command = ["lake", "test", "--", "--only", case]
            prefix = logs / f"{case}-{label}"
            with prefix.with_suffix(".stdout").open("wb") as out, prefix.with_suffix(".stderr").open("wb") as err:
                result = subprocess.run(command, stdout=out, stderr=err)
            output = prefix.with_suffix(".stdout").read_text() + prefix.with_suffix(".stderr").read_text()
            failure = f"assertion failed: {assertion}"
            assert result.returncode != 0, (case, label, "mutation survived", output)
            assert failure in output, (case, label, "wrong failure", output)
            records.append(dict(case=case, mutation=label, command=command, exit=result.returncode, failure=failure))
            print(f"{case}/{label}: EXIT={result.returncode}; {failure}", flush=True)
            paths[kind].write_text(original)
            assert paths[kind].read_text() == original
    finally:
        for kind, path in paths.items():
            path.write_text(originals[kind])
            assert path.read_text() == originals[kind]
        if args.sandbox:
            # Restore exactly the entry the script found, without staging other work.
            blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], input=index, capture_output=True, check=True).stdout.decode().strip()
            subprocess.run(["git", "-C", "../..", "update-index", "--cacheinfo", f"100644,{blob},packages/http-curl/link_shim.c"], check=True)
    destination = logs / ("sandbox-records.json" if args.sandbox else "host-records.json")
    expected = 2 if args.sandbox else 36
    assert len(records) == expected, ("dropped mutation", len(records), expected)
    destination.write_text(json.dumps(records, indent=2) + "\n")
    print(f"negative mutations: {len(records)}/{expected} detected; production sources restored", flush=True)


if __name__ == "__main__":
    main()
