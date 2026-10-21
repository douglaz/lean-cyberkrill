#!/usr/bin/env bash
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
set -euo pipefail
export LC_ALL=C

usage_error() { echo "usage error: $*" >&2; exit 2; }
[[ $# == 1 ]] || usage_error "check-one-openssl.sh <executable>"
exe=$1
[[ -f $exe ]] || usage_error "missing file: $exe"
for tool in readelf ldd nm grep awk sort realpath; do
    command -v "$tool" >/dev/null || usage_error "required tool missing: $tool"
done
readelf -h "$exe" >/dev/null 2>&1 || usage_error "not an ELF file: $exe"
if ! closure=$(ldd "$exe" 2>&1); then
    usage_error "ldd failed for $exe: $closure"
fi
[[ $closure != *"not found"* ]] || usage_error "unresolved dependency for $exe: $closure"
printf 'OpenSSL audit: %s\n%s\n' "$exe" "$closure"

# ldd includes the transitive closure. Include the ELF interpreter too.
paths=()
while IFS= read -r path; do
    [[ -z $path ]] || paths+=("$(realpath -e -- "$path")")
done < <(awk '$2 == "=>" && $3 ~ /^\// {print $3}
             $1 ~ /^\// {print $1}' <<<"$closure")
ssl=() crypto=()
while IFS= read -r path; do
    [[ -n $path ]] || continue
    case ${path##*/} in
        libssl.so*) ssl+=("$path");;
        libcrypto.so*) crypto+=("$path");;
    esac
done < <(printf '%s\n' "${paths[@]}" | sort -u)

failed=0
# This dynamic-build gate requires one of each, including rejecting no provider.
if [[ ${#ssl[@]} != 1 || ${#crypto[@]} != 1 ]]; then
    printf '(a) expected one libssl and one libcrypto, found %s and %s: %s\n' \
        "${#ssl[@]}" "${#crypto[@]}" "${ssl[*]} ${crypto[*]}" >&2
    failed=1
fi
for mode in static dynamic; do
    args=(--defined-only)
    [[ $mode == static ]] || args+=(-D)
    if ! symbols=$(nm "${args[@]}" -- "$exe" 2>&1); then
        usage_error "nm ($mode) failed for $exe: $symbols"
    fi
    matches=$(awk '/ [TtDdRrBb] (SSL_|OPENSSL_|EVP_|CRYPTO_)/ {print}' <<<"$symbols")
    count=$(awk 'NF {n++} END {print n+0}' <<<"$matches")
    printf 'defined OpenSSL symbols (%s): %s\n' "$mode" "$count"
    if [[ $count != 0 && ${#ssl[@]} != 0 ]]; then
        printf '(b) %s defines OpenSSL symbols (%s) alongside %s\n' \
            "$exe" "$mode" "${ssl[*]}" >&2
        awk 'NR <= 8 {print}' <<<"$matches" >&2
        failed=1
    fi
done

versions=()
for path in "$exe" "${paths[@]}"; do
    if found=$(grep -aoE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+' -- "$path"); then
        unique=$(sort -u <<<"$found")
        printf 'version strings in %s:\n%s\n' "$path" "$unique"
        versions+=("$unique")
    else
        rc=$?
        [[ $rc == 1 ]] || usage_error "version scan failed for $path (exit $rc)"
    fi
done
distinct=$(printf '%s\n' "${versions[@]}" | sort -u)
count=$(awk 'NF {n++} END {print n+0}' <<<"$distinct")
if (( count > 1 )); then
    printf '(c) conflicting OpenSSL versions across %s and its closure:\n%s\n' \
        "$exe" "$distinct" >&2
    failed=1
fi
if (( failed )); then exit 1; fi
echo 'one-OpenSSL checks (a), (b), (c): PASS'
