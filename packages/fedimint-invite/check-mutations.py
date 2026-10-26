# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independently mutate production code and require selected runtime assertions."""
import json
from pathlib import Path
import signal
import subprocess
import time

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/invite-mutations"
CONSENSUS = "FedimintInvite/Consensus.lean"
CODEC = "FedimintInvite/Codec.lean"
RECORD = PACKAGE / "test-data/mutations.json"


def cases():
    rows = [
        ("big-endian", CONSENSUS, "decodeLE data.reverse", "decodeLE data",
         "bigsize/256", "bigsize/256 reader and consumed"),
        ("nonminimal", CONSENSUS,
         "| .ok (data, after) => .ok (decodeLE data.reverse, after)",
         "| .ok (data, after) => if decodeLE data.reverse < 253 then\n"
         "          .error (.truncatedBigSize width rest.length) else .ok (decodeLE data.reverse, after)",
         "lax/nonminimal", "lax/nonminimal"),
        ("peer-truncation", CONSENSUS, "UInt16.ofNat peer, url", "UInt16.ofNat (peer % 65535), url",
         "lax/peer-truncation", "lax/peer-truncation"),
        ("unknown-stop", CONSENSUS, "| none => .ok state", "| none => .error .missingFederation",
         "lax/unknown-stop", "lax/unknown-stop"),
        ("trailing", CONSENSUS, "| 0, _, state => .ok state",
         "| 0, bytes, state => if bytes = [] then .ok state else .error (.unexpectedPart 0)",
         "lax/trailing", "lax/trailing"),
        ("sort", CONSENSUS, "sortGuardians state.guardians", "state.guardians",
         "parts/unsorted", "parts/unsorted"),
        ("stable-sort", CONSENSUS, "g.peerId.toNat ≤ h.peerId.toNat", "g.peerId.toNat < h.peerId.toNat",
         "parts/stable-duplicates", "parts/stable-duplicates"),
        ("federation-last", CONSENSUS,
         "| .federation bytes => { state with federation := some (Bitcoin.Hex.encode bytes) }",
         "| .federation bytes => if state.federation.isSome then state else\n"
         "      { state with federation := some (Bitcoin.Hex.encode bytes) }",
         "parts/last-federation", "parts/last-federation"),
        ("secret-last", CONSENSUS, "| .secret s => { state with secret := some s }",
         "| .secret s => if state.secret.isSome then state else { state with secret := some s }",
         "parts/last-secret", "parts/last-secret"),
        ("url-utf8", CONSENSUS, "match String.fromUTF8? data with",
         'match (if field == .url then some ((String.fromUTF8? data).getD "�") else String.fromUTF8? data) with',
         "errors/url-utf8", "errors/url-utf8"),
        ("secret-utf8", CONSENSUS, "match String.fromUTF8? data with",
         'match (if field == .secret then some ((String.fromUTF8? data).getD "�") else String.fromUTF8? data) with',
         "errors/secret-utf8", "errors/secret-utf8"),
        ("guardian-length", CONSENSUS, "if consumed = declared then", "if true then",
         "errors/guardian-length", "errors/guardian-length"),
        ("absent-secret", CONSENSUS, "inv.apiSecret.toList.map Part.secret",
         '(inv.apiSecret.toList ++ (if inv.apiSecret.isNone then [""] else [])).map Part.secret',
         "encoding/absent-secret", "encoding/absent-secret consensus bytes"),
        ("empty-secret-wire", CONSENSUS, "inv.apiSecret.toList.map Part.secret",
         '((inv.apiSecret.toList).filter (· != "")).map Part.secret',
         "encoding/empty-secret", "encoding/empty-secret consensus bytes"),
        ("empty-secret-model", CONSENSUS, "| .secret s => { state with secret := some s }",
         '| .secret s => { state with secret := if s = "" then none else some s }',
         "encoding/empty-secret", "encoding/empty-secret decoded fields"),
        ("hrp", CODEC, 'if hrp ≠ "fed1" then', "if false then",
         "wrapper/wrong-hrp", "wrapper/wrong-hrp"),
        ("variant", CODEC, "if variant ≠ .bech32m then", "if false then",
         "wrapper/wrong-variant", "wrapper/wrong-variant"),
        ("prefix-case", CODEC, 'if text.toList.take 4 ≠ "fed1".toList then', "if false then",
         "wrapper/uppercase", "wrapper/uppercase"),
        ("mixed-case", CODEC, "Bitcoin.Bech32.decode 1023 text",
         "Bitcoin.Bech32.decode 1023 (Bitcoin.Bech32.lower text)",
         "wrapper/mixed-case", "wrapper/mixed-case"),
        ("unicode-trim", CODEC,
         "String.ofList (s.toList.dropWhile whiteSpace |>.reverse.dropWhile whiteSpace |>.reverse)",
         "(s.trimAscii).copy", "wrapper/unicode-space", "wrapper/unicode-space"),
        ("nonzero-padding", CODEC, "decodeConsensus (Bitcoin.Bech32.fesToBytesLax data)",
         "let bytes ← (Bitcoin.Bech32.convertbits5to8 data).mapError (fun _ => Error.invalidHex)\n"
         "  decodeConsensus bytes", "padding/nonzero-padding", "padding/nonzero-padding"),
        ("extra-symbol", CODEC, "decodeConsensus (Bitcoin.Bech32.fesToBytesLax data)",
         "let bytes ← (Bitcoin.Bech32.convertbits5to8 data).mapError (fun _ => Error.invalidHex)\n"
         "  decodeConsensus bytes", "padding/extra-symbol", "padding/extra-symbol"),
        ("checksum", CODEC, "(Bitcoin.Bech32.decode 1023 text).mapError .bech32",
         "(match Bitcoin.Bech32.extractData text with\n"
         "      | some (h, d) => Except.ok (h, d, Bitcoin.Bech32.Variant.bech32m)\n"
         "      | none => Except.error (Error.bech32 .checksumMismatch))",
         "wrapper/bad-checksum", "wrapper/bad-checksum"),
        ("encode-cap", CODEC, "length > 1023", "length > 1024",
         "boundaries/633", "boundaries/633 encode cap"),
        ("decode-cap", CODEC, "Bitcoin.Bech32.decode 1023 text", "Bitcoin.Bech32.decode 1024 text",
         "boundaries/633", "boundaries/633 decode cap"),
        ("encode-order", CONSENSUS, "inv.guardians.map Part.guardian",
         "(sortGuardians inv.guardians).map Part.guardian",
         "encoding/encode-order", "encoding/encode-order consensus bytes"),
        ("empty-id", CONSENSUS, 'if inv.federationId = "" then .ok []',
         'if inv.federationId = "" then .error .invalidHex',
         "encoding/empty-id", "encoding/empty-id consensus bytes"),
        ("no-guardian-encode", CONSENSUS, "let parts ← inviteParts inv",
         "if inv.guardians = [] then throw .noGuardian\n  let parts ← inviteParts inv",
         "encoding/no-guardian", "encoding/no-guardian consensus bytes"),
        ("url-byte-length", CONSENSUS, "stringBytes g.url ++ writeBigSize g.peerId.toNat",
         "(writeBigSize g.url.length ++ g.url.toUTF8.data.toList) ++ writeBigSize g.peerId.toNat",
         "encoding/unicode", "encoding/unicode consensus bytes"),
        ("secret-byte-length", CONSENSUS, "| .secret s => [2] ++ stringBytes s",
         "| .secret s => [2] ++ writeBigSize s.length ++ s.toUTF8.data.toList",
         "encoding/unicode", "encoding/unicode consensus bytes"),
        ("secret-prefix", CONSENSUS, "| .secret s => [2] ++ stringBytes s",
         "| .secret s => [2] ++ writeBigSize (stringBytes s).length ++ stringBytes s",
         "encoding/empty-secret", "encoding/empty-secret consensus bytes"),
    ]
    assert len(rows) == 31
    return rows


def run(label, command):
    out = LOGS / (label + ".stdout")
    err = LOGS / (label + ".stderr")
    assert out != err and out != RECORD and err != RECORD
    start = time.monotonic()
    with out.open("wb") as stdout, err.open("wb") as stderr:
        p = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
    return p.returncode, out.read_text(), err.read_text(), round(time.monotonic() - start, 3)


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    assert RECORD.resolve() != Path(__file__).resolve()
    for signum in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {name: (PACKAGE / name).read_bytes() for name in [CONSENSUS, CODEC]}
    records = []
    try:
        for label, source, old, new, selection, assertion in cases():
            path = PACKAGE / source
            original = originals[source]
            text = original.decode()
            assert text.count(old) == 1, (label, text.count(old))
            assert path.read_bytes() == original
            try:
                changed = text.replace(old, new)
                assert new in changed and changed != text
                path.write_text(changed)
                assert path.read_text() == changed
                build = ["lake", "build", "inviteRuntime"]
                status, out, err, build_wall = run(label + "-build", build)
                assert status == 0, (label, "incidental build failure", status, out, err)
                command = [".lake/build/bin/inviteRuntime", "--case", selection]
                status, out, err, test_wall = run(label + "-test", command)
                detecting = "assertion failed: " + assertion
                failures = [line for line in (out + err).splitlines() if "assertion failed:" in line]
                assert status == 1 and len(failures) == 1 and failures[0].endswith(detecting), (
                    label, status, out, err)
                records.append(dict(mutation=label, source=source, production_edit=dict(old=old, new=new),
                                    build_command=build, build_exit=0, command=command, exit=status,
                                    assertion=assertion, stdout=out.splitlines(), stderr=err.splitlines(),
                                    build_wall_seconds=build_wall, test_wall_seconds=test_wall))
                print(f"{label}: build EXIT=0; test EXIT=1; {detecting}", flush=True)
            finally:
                path.write_bytes(original)
                assert path.read_bytes() == original
    finally:
        for name, original in originals.items():
            assert (PACKAGE / name).read_bytes() == original
    restored = []
    for label, command in [("restored-build", ["lake", "build"]), ("restored-tests", ["lake", "test"])]:
        status, out, err, wall = run(label, command)
        assert status == 0, (label, status, out, err)
        restored.append(dict(command=command, exit=status, wall_seconds=wall))
    assert len(records) == 31
    RECORD.write_text(json.dumps(dict(count=31, mutations=records, restored=restored), indent=2) + "\n")
    print("invite mutations: 31/31; restored lake build and lake test: EXIT=0", flush=True)


if __name__ == "__main__":
    main()
