# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Mutate production behavior, require named acceptance failures, restore exact bytes."""
import json
from pathlib import Path
import signal
import subprocess
import time

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/lnurl-mutation-checks"
CODEC = "Lightning/Lnurl/Codec.lean"
URL = "Lightning/Lnurl/Url.lean"
MODELS = "Lightning/Lnurl/Models.lean"


def cases():
    result = [
        ("strict-padding", CODEC, "let bytes := Bitcoin.Bech32.fesToBytesLax data",
         "let bytes ← (Bitcoin.Bech32.convertbits5to8 data).mapError (fun _ => LnurlError.invalidUtf8)",
         "lnurl-positive:nonzero-padding", "lnurl-positive nonzero-padding"),
        ("reject-bech32m", CODEC, 'if hrp != "lnurl" then throw .wrongHrp',
         'if _variant == .bech32m then throw (.bech32 .checksumMismatch)\n  if hrp != "lnurl" then throw .wrongHrp',
         "lnurl-positive:bech32m", "lnurl-positive bech32m"),
        ("limit-90", CODEC, "Bitcoin.Bech32.decode 1023 text", "Bitcoin.Bech32.decode 90 text",
         "lnurl-positive:long", "lnurl-positive long"),
        ("limit-1024", CODEC, "Bitcoin.Bech32.decode 1023 text", "Bitcoin.Bech32.decode 1024 text",
         "lnurl-negative:limit-1024", "lnurl-negative limit-1024"),
        ("prefix-case", CODEC, '(Bitcoin.Bech32.lower text).startsWith "lnurl"',
         'text.startsWith "LNURL"', "lnurl-positive:lowercase", "lnurl-positive lowercase"),
        ("prefix-removed", CODEC, 'if !(Bitcoin.Bech32.lower text).startsWith "lnurl" then throw .wrongPrefix',
         'if false then throw .wrongPrefix', "lnurl-negative:prefix", "lnurl-negative prefix"),
        ("ascii-trim", CODEC,
         'String.ofList (s.toList.dropWhile Lnurl.whiteSpace |>.reverse.dropWhile Lnurl.whiteSpace |>.reverse)',
         '(String.trimAscii s).copy', "lnurl-positive:unicode-trim", "lnurl-positive unicode-trim"),
        ("lossy-lnurl", CODEC, 'let some url := String.fromUTF8? bytes | throw .invalidUtf8',
         'let url := Lnurl.lossyUtf8 bytes', "lnurl-negative:invalid-utf8", "lnurl-negative invalid-utf8"),
        ("empty-address-user", CODEC, 'if user.isEmpty || domain.isEmpty then throw .malformedAddress',
         'if domain.isEmpty then throw .malformedAddress', "address:empty-example-user", "address empty-example-user"),
        ("three-address-parts", CODEC, 'if parts.length != 2 then throw .malformedAddress',
         'if parts.length < 2 then throw .malformedAddress', "address:three-parts", "address three-parts"),
        ("routes-null", MODELS, '| none | some .null => pure none\n    | some (.arr vs)',
         '| none => pure none\n    | some .null => throw (.malformedResponse "routes")\n    | some (.arr vs)',
         "json-callback:null", "json-callback null"),
        ("comment-bound", MODELS, 'n.mantissa.toNat > bound',
         '(n.mantissa.toNat > bound && field != "commentAllowed")',
         "json-request:comment-overflow", "json-request comment-overflow"),
        ("max-msat-bound", MODELS, 'n.mantissa.toNat > bound',
         '(n.mantissa.toNat > bound && field != "maxSendable")',
         "json-request:overflow-maxSendable", "json-request overflow-maxSendable"),
        ("min-msat-bound", MODELS, 'n.mantissa.toNat > bound',
         '(n.mantissa.toNat > bound && field != "minSendable")',
         "json-request:overflow-minSendable", "json-request overflow-minSendable"),
        ("host-case", URL, 'let host := Bitcoin.Bech32.lower decoded', 'let host := decoded',
         "url-supported:case-duplicates", "url-supported case-duplicates host"),
        ("special-query", URL, 'some (specialQuery (String.ofList (queryStart.drop 1)))',
         'some (String.ofList (queryStart.drop 1))', "url-supported:special-query", "url-supported special-query query"),
        ("plus-literal", URL, "if c == '+' then ' ' else c", "if c == '+' then '+' else c",
         "url-supported:case-duplicates", "url-supported case-duplicates pairs q"),
        ("duplicate-first", URL, 'result := result.filter (fun pair => pair.1 != key) ++ [(key, value)]',
         'result := if result.any (fun pair => pair.1 == key) then result else result ++ [(key, value)]',
         "url-supported:case-duplicates", "url-supported case-duplicates pairs a"),
        ("malformed-query-reject", URL, 'let bytes ← percentDecode plus false', 'let bytes ← percentDecode plus true',
         "url-supported:malformed-query", "url-supported malformed-query"),
        ("strict-query-utf8", URL, 'return lossyUtf8 bytes',
         'let some decoded := String.fromUTF8? bytes | throw .invalidUtf8\n  return decoded',
         "url-supported:malformed-query", "url-supported malformed-query"),
        ("absent-query", URL, 'if queryStart.isEmpty then none else some',
         'if queryStart.isEmpty then some "" else some', "url-supported:no-query", "url-supported no-query query"),
        ("empty-query", URL, 'if queryStart.isEmpty then none else some',
         'if queryStart.length ≤ 1 then none else some', "url-supported:empty-query", "url-supported empty-query query"),
        ("port-validation", URL, 'if !portChars.isEmpty then validatePort (String.ofList (portChars.drop 1))',
         'if !portChars.isEmpty then pure ()', "url-error:port-overflow", "url-error port-overflow"),
        ("authority-backslash", URL,
         "afterSlashes.takeWhile (fun c => c != '/' && c != '\\\\' && c != '?' && c != '#')",
         "afterSlashes.takeWhile (fun c => c != '/' && c != '?' && c != '#')",
         "url-supported:backslash-at", "url-supported backslash-at"),
        ("allow-userinfo", URL, "if authority.contains '@' then throw (.unsupportedUrlForm .userinfo)",
         "let authority := (authority.reverse.takeWhile (· != '@')).reverse",
         "url-refusal:userinfo", "url-refusal userinfo"),
        ("allow-ipv6", URL, "if authority.head? == some '[' then throw (.unsupportedUrlForm .ipv6)",
         "if authority.head? == some '[' then\n"
         "    let host := String.ofList (authority.takeWhile (· != ']') ++ [']'])\n"
         '    return ⟨scheme, host, scheme ++ "://" ++ host ++ "/", none, []⟩',
         "url-refusal:ipv6", "url-refusal ipv6"),
        ("allow-nonascii", URL, 'if host.toList.any (fun c => c.toNat > 127) ||', 'if false ||',
         "url-refusal:unicode-host", "url-refusal unicode-host"),
        ("allow-encoded-nonascii", URL, 'if host.toList.any (fun c => c.toNat > 127) ||', 'if false ||',
         "url-refusal:encoded-unicode-host", "url-refusal encoded-unicode-host"),
        ("allow-punycode", URL, '(host.splitOn ".").any (·.startsWith "xn--") then', 'false then',
         "url-refusal:punycode-host", "url-refusal punycode-host"),
        ("allow-uppercase-punycode", URL, '(host.splitOn ".").any (·.startsWith "xn--") then', 'false then',
         "url-refusal:punycode-upper", "url-refusal punycode-upper"),
    ]
    # Return success for each refused IPv4 property; a later octet check must not mask it.
    for label, condition, fixture in [
        ("hex", 'host.startsWith "0x"', "ipv4-hex"),
        ("integer", 'parts.length == 1', "ipv4-integer"),
        ("short", 'parts.length < 4', "ipv4-short"),
        ("octal", '(parts.head?.getD "").length > 1 && (parts.head?.getD "").startsWith "0"', "ipv4-octal"),
        ("leading", 'parts.any (fun p => p.length > 1 && p.startsWith "0")', "ipv4-leading"),
        ("dot", 'host.endsWith "."', "ipv4-dot")]:
        old = 'let parts := host.splitOn "."\n    if parts.length'
        new = f'let parts := host.splitOn "."\n    if {condition} then return host\n    if parts.length'
        result.append(("allow-ipv4-" + label, URL, old, new,
                       "url-refusal:" + fixture, "url-refusal " + fixture))
    assert len(result) == 36
    return result


def run(label, selection=None):
    command = ["lake", "test"] + (["--", "--lnurl-case", selection] if selection else [])
    out, err = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    start = time.monotonic()
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
    return result.returncode, command, out.read_text() + err.read_text(), time.monotonic() - start


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {name: (PACKAGE / name).read_bytes() for name in [CODEC, URL, MODELS]}
    records = []
    try:
        for label, source, old, new, selection, expected in cases():
            path = PACKAGE / source
            original = originals[source]
            text = original.decode()
            assert text.count(old) == 1, (label, text.count(old))
            changed = text.replace(old, new)
            assert changed != text and new in changed
            try:
                assert path.read_bytes() == original
                path.write_text(changed)
                assert path.read_text() == changed
                status, command, output, elapsed = run(label, selection)
                assert status == 1, (label, status, output)
                failures = [line for line in output.splitlines() if "assertion failed:" in line]
                assert failures and failures[0].endswith("assertion failed: " + expected), (label, output)
                success = "unexpected success: " + expected in output.splitlines()
                if label.startswith("allow-") or label == "limit-1024":
                    assert success, (label, "mutation must actually succeed", output)
                records.append(dict(mutation=label, source=source, command=command, exit=status,
                                    property=expected, failure=failures[0],
                                    unexpected_success=success, wall_seconds=round(elapsed, 3)))
                print(f"{label}: EXIT={status}; {failures[0]}; {elapsed:.3f}s", flush=True)
            finally:
                path.write_bytes(original)
                assert path.read_bytes() == original
    finally:
        for name, original in originals.items():
            assert (PACKAGE / name).read_bytes() == original
    status, command, output, elapsed = run("restored-tests")
    assert status == 0, output
    for name, original in originals.items():
        assert (PACKAGE / name).read_bytes() == original
    record = dict(mutations=records, count=36, restored=dict(command=command, exit=status,
                  wall_seconds=round(elapsed, 3)))
    (PACKAGE / "test-data/lnurl-mutations.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"LNURL mutations: {len(records)}/36; restored lake test: EXIT=0; {elapsed:.3f}s", flush=True)


if __name__ == "__main__":
    main()
