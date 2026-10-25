# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Generate synthetic LNURL fixtures; URL expectations are hand-derived.

Reproduce the Python environment (assign its returned store path to PYTHON_ENV):
nix build --impure --no-link --print-out-paths --expr 'let p = (builtins.getFlake "github:NixOS/nixpkgs/fe13242281a67641c0102cdb1087f0ebe586c7df").legacyPackages.x86_64-linux; in p.python3.withPackages (ps: [ ps.bech32 ])'
Then: "$PYTHON_ENV/bin/python3" -I generate-lnurl.py --check
"""
import argparse
import importlib.metadata
import json
from pathlib import Path

import bech32

ROOT = Path(__file__).resolve().parent


def encode_bytes(data, hrp="lnurl", variant="bech32", nonzero=False):
    symbols = bech32.convertbits(data, 8, 5)
    if nonzero:
        assert len(data) * 8 % 5
        symbols[-1] |= 1
    residue = 1 if variant == "bech32" else 0x2BC830A3
    value = bech32.bech32_polymod(bech32.bech32_hrp_expand(hrp) + symbols + [0] * 6) ^ residue
    check = [(value >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(bech32.CHARSET[s] for s in symbols + check)


def fixtures():
    sets = {k: [] for k in ["url-supported", "url-refusal", "url-error", "lnurl-positive",
                            "lnurl-negative", "address", "json-request", "json-callback"]}

    def good(name, url, host="example.com", scheme="https", query=None, pairs=(), group="url-supported", **kw):
        encoded = encode_bytes(url.encode(), **kw)
        sets[group].append(dict(name=name, input=encoded, bech32=encoded, url=url, host=host,
                                base=f"{scheme}://{host}/", query=query, pairs=list(pairs)))

    def bad(name, url, error, group="url-error"):
        sets[group].append(dict(name=name, input=encode_bytes(url.encode()), url=url, error=error))

    good("case-duplicates", "HTTPS://EXAMPLE.COM:00443/p?q=a+b&%61=first&a=last#frag",
         query="q=a+b&%61=first&a=last", pairs=[("q", "a b"), ("a", "last")])
    good("form-pieces", "https://example.com/?q=%2B+%20&empty=&flag&&x=a=b",
         query="q=%2B+%20&empty=&flag&&x=a=b", pairs=[("q", "+  "), ("empty", ""), ("flag", ""), ("x", "a=b")])
    good("malformed-query", "https://example.com/?q=%ZZ&x=%FF&y=%E2%82", query="q=%ZZ&x=%FF&y=%E2%82",
         pairs=[("q", "%ZZ"), ("x", "�"), ("y", "�")])
    good("special-query", "https://example.com/?q=a b'café", query="q=a%20b%27caf%C3%A9", pairs=[("q", "a b'café")])
    good("query-encode-set", 'https://example.com/?q="<>\x01%2f\x7f', query="q=%22%3C%3E%01%2f%7F",
         pairs=[("q", '"<>\x01/\x7f')])
    good("no-query", "https://example.com/")
    good("empty-query", "https://example.com/?", query="")
    good("empty-query-fragment", "https://example.com/?#fragment", query="")
    good("encoded-fragment", "https://example.com/?q=%23#fragment", query="q=%23", pairs=[("q", "#")])
    good("url-cleanup", "\x00 \x1fhttps://ex\tample.com/pa\rth?x=a\nb \x00", query="x=ab", pairs=[("x", "ab")])
    for name, url in [("no-slashes", "https:example.com"), ("one-slash", "https:/example.com"),
                      ("backslashes", "https:\\\\/\\example.com/path"), ("domain-dot", "https://example.com.")]:
        good(name, url, host="example.com." if name == "domain-dot" else "example.com")
    good("encoded-host", "https://%65XAMPLE.com")
    for name, port in [("port-zero", "0"), ("port-max", "65535"), ("port-leading", "00080"), ("port-empty", "")]:
        good(name, f"https://example.com:{port}/")
    for name, url, host, scheme in [
        ("loopback", "https://127.0.0.1:8080/", "127.0.0.1", "https"),
        ("ipv4-zero", "http://0.0.0.0/", "0.0.0.0", "http"),
        ("ipv4-max", "https://255.255.255.255/", "255.255.255.255", "https"),
        ("encoded-ipv4", "https://1%2e2%2e3%2e4/", "1.2.3.4", "https")]:
        good(name, url, host=host, scheme=scheme)
    good("backslash-at", "https://example.com\\@evil.invalid/")
    good("path-at", "https://example.com/path@name?x=@y", query="x=@y", pairs=[("x", "@y")])
    # ASCII domains follow URL/UTS46's permissive ASCII processing, not DNS validation.
    for name, host in [("underscore", "_service.example.com"), ("hyphens", "-a-.example.com"),
                       ("empty-label", "a..example.com"), ("ascii-punctuation", "a!$&'()*+,;=_.example.com"),
                       ("long-label", "a" * 64 + ".example.com")]:
        good(name, f"https://{host}/", host=host)
    good("http-case", "HTTP://EXAMPLE.ORG/path", host="example.org", scheme="http")
    good("query-keys", "https://example.com/?%61=one&a=two&=empty&%2B=plus&+=space",
         query="%61=one&a=two&=empty&%2B=plus&+=space", pairs=[("a", "two"), ("", "empty"), ("+", "plus"), (" ", "space")])
    good("query-utf8-subparts", "https://example.com/?a=%E0%80%80&b=%F0%90%80&c=%ED%A0%80&d=%C3%A9&e=%E2%82x",
         query="a=%E0%80%80&b=%F0%90%80&c=%ED%A0%80&d=%C3%A9&e=%E2%82x",
         pairs=[("a", "���"), ("b", "�"), ("c", "���"), ("d", "é"), ("e", "�x")])
    good("percent-once", "https://example.com/?q=%252f&x=%2f", query="q=%252f&x=%2f", pairs=[("q", "%2f"), ("x", "/")])
    good("fragment-no-query", "https://example.com/#?ignored")
    for name, url, reason in [
        ("userinfo", "https://user@example.com/", "userinfo"),
        ("userinfo-multiple", "https://a@b@example.com/", "userinfo"),
        ("ipv6", "https://[::1]/", "ipv6"),
        ("ipv4-hex", "https://0x7f000001/", "ipv4Form"),
        ("ipv4-integer", "https://2130706433/", "ipv4Form"),
        ("ipv4-short", "https://127.1/", "ipv4Form"),
        ("ipv4-octal", "https://0177.0.0.1/", "ipv4Form"),
        ("ipv4-leading", "https://127.0.0.010/", "ipv4Form"),
        ("ipv4-dot", "https://127.0.0.1./", "ipv4Form"),
        ("unicode-host", "https://bücher.invalid/", "idnaRequired"),
        ("encoded-unicode-host", "https://%C3%BC.invalid/", "idnaRequired"),
        ("punycode-host", "https://xn--bcher-kva.invalid/", "idnaRequired"),
        ("punycode-upper", "https://XN--BCHER-KVA.invalid/", "idnaRequired")]:
        bad(name, url, "unsupportedUrlForm:" + reason, "url-refusal")
    for name, url, error in [
        ("missing-host", "https://", "missingHost"), ("missing-host-query", "https://?q=x", "missingHost"),
        ("encoded-hash", "https://%23/", "invalidHost"), ("encoded-slash", "https://%2f/", "invalidHost"),
        ("encoded-at", "https://%40/", "invalidHost"), ("encoded-null", "https://%00/", "invalidHost"),
        ("malformed-host", "https://%ZZ.invalid/", "invalidHost"),
        ("truncated-host", "https://%.invalid/", "invalidHost"),
        ("host-invalid-utf8", "https://%FF.invalid/", "invalidHost"),
        ("host-truncated-utf8", "https://%E2%82.invalid/", "invalidHost"),
        ("numeric-domain", "https://foo.123/", "unsupportedUrlForm:ipv4Form"),
        ("ipv4-overflow", "https://127.0.0.256/", "invalidIpv4"),
        ("port-overflow", "https://example.com:65536/", "invalidPort"),
        ("port-negative", "https://example.com:-1/", "invalidPort"),
        ("port-letters", "https://example.com:abc/", "invalidPort"),
        ("port-sign", "https://example.com:+80/", "invalidPort"),
        ("port-colon", "https://example.com:80:90/", "invalidPort"),
        ("relative", "/example.com/path", "unsupportedScheme"),
        ("scheme", "ftp://example.com/", "unsupportedScheme"),
        ("host-space", "https://exam ple.com/", "invalidHost"),
        ("host-del", "https://example.com%7f/", "invalidHost"),
        ("host-double-percent", "https://%2565xample.com/", "invalidHost"),
        ("host-caret", "https://exa^mple.com/", "invalidHost")]:
        bad(name, url, error)
    good("lowercase", "https://example.com/", group="lnurl-positive")
    good("uppercase", "https://example.org/", host="example.org", group="lnurl-positive")
    sets["lnurl-positive"][-1]["input"] = sets["lnurl-positive"][-1]["bech32"] = sets["lnurl-positive"][-1]["input"].upper()
    good("unicode-trim", "https://example.com/", group="lnurl-positive")
    sets["lnurl-positive"][-1]["input"] = "\u00a0" + sets["lnurl-positive"][-1]["input"] + "\u3000"
    good("all-whitespace", "https://example.com/", group="lnurl-positive")
    whitespace = "".join(map(chr, list(range(9, 14)) + [32, 133, 160, 5760] + list(range(8192, 8203)) + [8232, 8233, 8239, 8287, 12288]))
    sets["lnurl-positive"][-1]["input"] = whitespace + sets["lnurl-positive"][-1]["input"] + whitespace
    good("long", "https://example.com/" + "a" * 100, group="lnurl-positive")
    good("limit-1022", "https://example.com/" + "a" * (631 - 20), group="lnurl-positive")
    # Prefix is 20 bytes: verify boundary sizes instead of trusting the calculation.
    assert len(sets["lnurl-positive"][-1]["input"]) == 1022
    good("bech32m", "https://example.com/", group="lnurl-positive", variant="bech32m")
    good("nonzero-padding", "https://example.com/?q=x", query="q=x", pairs=[("q", "x")],
         group="lnurl-positive", nonzero=True)
    negative = sets["lnurl-negative"]
    for name, value, error in [
        ("prefix", "not_an_lnurl", "wrongPrefix"),
        ("prefix-valid-codec", encode_bytes(b"https://example.com/", hrp="other"), "wrongPrefix"),
        ("hrp", encode_bytes(b"https://example.com/", hrp="lnurlx"), "wrongHrp"),
        ("invalid-utf8", encode_bytes(b"https://example.com/\xff"), "invalidUtf8"),
        ("missing-separator", "LNURL", "bech32:missingSeparator"),
        ("short-checksum", "lnurl1q", "bech32:shortChecksum"),
        ("checksum", "lnurl1qqqqqq", "bech32:checksumMismatch"),
        ("character", "lnurl1iiiiii", "bech32:invalidCharacter"),
        ("mixed-case", "LNURL1qqqqqq", "bech32:mixedCase"),
        ("hrp-long", "lnurl" + "x" * 79 + "1qqqqqq", "bech32:hrpTooLong"),
        ("hrp-character", "lnurl 1qqqqqq", "bech32:invalidHrp"),
        ("limit-1024", encode_bytes(("https://example.com/" + "a" * (632 - 20)).encode()), "bech32:tooLong")]:
        negative.append(dict(name=name, input=value, error=error))
    assert len(negative[-1]["input"]) == 1024
    negative[-1]["url"] = "https://example.com/" + "a" * (632 - 20)
    for address in ["user@example.com", "user+tag@example.com", "_@example.com", " user @example.com ", "a/b@example.com"]:
        user, domain = address.split("@")
        sets["address"].append(dict(name="address-" + str(len(sets["address"])), input=address,
                                    output=f"https://{domain}/.well-known/lnurlp/{user}"))
    for name, address in [("no-at", "invalid"), ("three-parts", "user@domain@com"),
                          ("empty-domain", "user@"), ("empty-user", "@domain.com"),
                          ("empty-both", "@"), ("empty-example-user", "@example.com")]:
        sets["address"].append(dict(name=name, input=address, error="malformedAddress"))
    request = dict(callback="https://example.com/callback", maxSendable=10000, minSendable=1000,
                   metadata="not nested JSON", tag="unchecked-tag")

    def model(group, name, value, field=None):
        row = dict(name=name, input=json.dumps(value, ensure_ascii=False, separators=(",", ":")))
        if field: row["error"] = "malformedResponse:" + field
        else: row["expected"] = value
        sets[group].append(row)

    for name, extra in [("absent", {}), ("null", dict(commentAllowed=None)),
                        ("zero", dict(commentAllowed=0)), ("max", dict(commentAllowed=65535)),
                        ("unknown", dict(ignored=[1, 2])), ("bounds", dict(maxSendable=2**64-1, minSendable=0))]:
        model("json-request", name, request | extra)
    # Business policy is outside deserialization.
    model("json-request", "no-policy", request | dict(callback="literal callback", maxSendable=0, minSendable=10))
    for field in request:
        model("json-request", "missing-" + field, {k: v for k, v in request.items() if k != field}, field)
        for suffix, value in [("type", []), ("null", None)]:
            model("json-request", suffix + "-" + field, request | {field: value}, field)
    for field in ["maxSendable", "minSendable"]:
        for suffix, value in [("negative", -1), ("overflow", 2**64), ("fraction", 1.5), ("float", 1.0),
                              ("string", "1000"), ("bool", True)]:
            model("json-request", suffix + "-" + field, request | {field: value}, field)
    for suffix, value in [("overflow", 65536), ("negative", -1), ("fraction", 1.5), ("float", 1.0),
                          ("string", "2"), ("array", []), ("object", {}), ("bool", False)]:
        model("json-request", "comment-" + suffix, request | dict(commentAllowed=value), "commentAllowed")
    model("json-request", "error-reply", dict(status="ERROR", reason="synthetic refusal"), "callback")
    for name, value in [("absent", dict(pr="synthetic-pr")), ("null", dict(pr="synthetic-pr", routes=None)),
                        ("empty", dict(pr="synthetic-pr", routes=[])),
                        ("strings", dict(pr="synthetic-pr", routes=["synthetic-route", ""])),
                        ("unknown", dict(pr="synthetic-pr", ignored=42))]:
        model("json-callback", name, value)
    for name, value, field in [("missing-pr", {}, "pr"), ("type-pr", dict(pr=1), "pr"),
        ("null-pr", dict(pr=None), "pr"), ("route-number", dict(pr="synthetic-pr", routes=[1]), "routes"),
        ("route-mixed", dict(pr="synthetic-pr", routes=["synthetic-route", 1]), "routes"),
        ("route-null-member", dict(pr="synthetic-pr", routes=[None]), "routes"),
        ("routes-string", dict(pr="synthetic-pr", routes="route"), "routes"),
        ("routes-object", dict(pr="synthetic-pr", routes={}), "routes"),
        ("routes-bool", dict(pr="synthetic-pr", routes=False), "routes"),
        ("routes-number", dict(pr="synthetic-pr", routes=0), "routes"),
        ("error-reply", dict(status="ERROR", reason="synthetic refusal"), "pr")]:
        model("json-callback", name, value, field)
    return sets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    assert importlib.metadata.version("bech32") == "1.2.0"
    data = fixtures()
    counts = {key: len(rows) for key, rows in data.items()}
    assert counts == {'url-supported': 35, 'url-refusal': 13, 'url-error': 23, 'lnurl-positive': 8,
                      'lnurl-negative': 12, 'address': 11, 'json-request': 43, 'json-callback': 16}, counts
    artifacts = {
        "test-data/lnurl.json": json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        "test-data/lnurl.json.provenance":
            "Synthetic fixtures generated by the committed script generate-lnurl.py.\n"
            "bech32 1.2.0; bech32m uses BIP350 residue 0x2bc830a3.\n"
            "URL expectations hand-derived from url 2.5.7, form_urlencoded 1.2.2,\n"
            "percent-encoding 2.3.2 and idna 1.1.0 source, pinned by cyberkrill\n"
            "https://github.com/douglaz/cyberkrill/tree/27cad1faba86260b06665a89f0af5134d23525c2\n"
            "No Rust execution or network requests supply test expectations.\n"
            "Own LUD-06 JSON uses only the cited field shapes, with synthetic strings.\n",
    }
    for name, content in artifacts.items():
        path = ROOT / name
        if args.check:
            assert path.read_text() == content, name
        else:
            path.write_text(content)
    for key, count in counts.items():
        print(f"{key}: {count}/{count}")
    print(f"generator artifacts: {len(artifacts)}/2")


if __name__ == "__main__":
    main()
