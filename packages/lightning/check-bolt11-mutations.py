# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Break one production property at a time and require its named acceptance assertion."""
import json
from pathlib import Path
import signal
import subprocess

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/bolt11-mutation-checks"
CODEC = "Lightning/Bolt11/Codec.lean"
FIELDS = "Lightning/Bolt11/Fields.lean"


def cases():
    result = [
        ("hrp-case", CODEC, "(Bitcoin.Bech32.lower hrp).toUTF8", "hrp.toUTF8",
         "valid:L704", "valid L704"),
        ("hash-padding", CODEC,
         "(Bitcoin.Bech32.fesToBytesLax (data ++ [0, 0])).extract 0\n    ((data.length * 5 + 7) / 8)",
         "Bitcoin.Bech32.fesToBytesLax data", "valid:L382", "valid L382"),
        ("signature-boundary", CODEC, "let signed := data.take (data.length - 104)",
         "let signed := data.take (data.length - 103)", "valid:L382", "valid L382"),
        ("lax-byte-fields", FIELDS,
         "private def strictBytes (tag : Symbol) (data : List Symbol) : Except Error ByteArray :=\n"
         "  (Bitcoin.Bech32.convertbits5to8 data).mapError fun _ => .nonCanonicalPadding tag",
         "private def strictBytes (_tag : Symbol) (data : List Symbol) : Except Error ByteArray :=\n"
         "  .ok (Bitcoin.Bech32.fesToBytesLax data)",
         "negative:payment-hash-padding", "negative payment-hash-padding"),
        ("expiry-leading-zero", FIELDS, "if data.head? = some 0 then throw (.leadingZero tag)",
         "if tag ≠ 6 ∧ data.head? = some 0 then throw (.leadingZero tag)",
         "negative:expiry-leading-zero", "negative expiry-leading-zero"),
        ("cltv-leading-zero", FIELDS, "if data.head? = some 0 then throw (.leadingZero tag)",
         "if tag ≠ 24 ∧ data.head? = some 0 then throw (.leadingZero tag)",
         "negative:cltv-leading-zero", "negative cltv-leading-zero"),
        ("features-leading-zero", FIELDS, "if data.head? = some 0 then throw (.leadingZero 5)",
         "if false then throw (.leadingZero 5)",
         "negative:features-leading-zero", "negative features-leading-zero"),
        ("hrp-leading-zero", CODEC, "  let rawAmount ← if digits = [] then pure none else do",
         "  if digits.head? = some '0' then throw .invalidAmount\n"
         "  let rawAmount ← if digits = [] then pure none else do",
         "positive:amount-leading-zero", "positive amount-leading-zero"),
        ("recover-instead-of-verify", CODEC,
         "  if let some key := parts.payeePubkey then\n"
         "    if cap.verify hash compact key then return key else throw .verifyFailed",
         "  if let some _key := parts.payeePubkey then\n"
         "    let some recovered := cap.recover hash compact (signature.data[64]?.getD 255) |\n"
         "      throw .recoveryFailed\n    return recovered",
         "nfields:n-high", "nfields n-high"),
        ("recovery-byte-range", CODEC, "signature.data[64]?.getD 255 ≤ 3 &&\n    ", "",
         "negative:recovery-byte", "negative recovery-byte"),
        ("signature-before-counts", CODEC,
         "  checkFieldCounts fields\n  checkFeatures parts\n"
         "  let key ← checkSignature cap parts hash signature",
         "  let key ← checkSignature cap parts hash signature\n"
         "  checkFieldCounts fields\n  checkFeatures parts",
         "invalid:L821", "invalid L821"),
        ("pico-precision", CODEC, "if pico % 10 ≠ 0 then throw .impreciseAmount",
         "if pico % 10 > 10 then throw .impreciseAmount", "invalid:L851", "invalid L851"),
        ("bech32m", CODEC, "if variant ≠ .bech32 then throw .badChecksum",
         "if variant ≠ .bech32 ∧ variant ≠ .bech32m then throw .badChecksum",
         "negative:bech32m", "negative bech32m"),
        ("length-7090", CODEC, "Bitcoin.Bech32.decode 7089 text", "Bitcoin.Bech32.decode 7090 text",
         "outside:length-7090", "outside length-7090"),
        ("wrong-fixed-length", FIELDS, "if data.length ≠ expected then return .raw tag data",
         "if data.length ≠ expected then throw (.malformedField tag)",
         "invalid:L814", "invalid L814 accepted for parity"),
        ("unknown-even-feature", CODEC, "if features.requiresUnknown then throw .unknownRequiredFeatures",
         "if features.requiresUnknown && false then throw .unknownRequiredFeatures",
         "invalid:L792", "invalid L792"),
        ("unknown-fallback", FIELDS, "if version.toNat > 18 then return .raw tag data",
         "if version.toNat > 18 then throw (.malformedField tag)", "valid:L707", "valid L707"),
        ("encode-stale-signature", CODEC,
         "  if signingHash hrp data != invoice.signingHash then throw .signingHashMismatch\n", "",
         "reencode", "reencode amount-leading-zero refused"),
        ("encode-unchecked-parts", CODEC, "  (checkParts parts).mapError .invalidInvoice\n", "",
         "limits", "encoder semantic refusals no p"),
        ("encode-typed-raw", FIELDS, "  | .raw tag data => staysRaw tag data\n", "",
         "limits", "encoder raw fields typed-length p refused"),
        ("sign-unchecked-points", CODEC,
         "  let _ ← (decodeFields cap (encodeFields parts.fields)).mapError .invalidInvoice\n", "",
         "limits", "sign curve points payee")]
    assert len(result) == 21
    return result


def run(label, selection=None):
    command = ["lake", "test"] + (["--", "--case", selection] if selection else [])
    out, err = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
    return result.returncode, command, out.read_text() + err.read_text()


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {name: (PACKAGE / name).read_bytes() for name in [CODEC, FIELDS]}
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
                status, command, output = run(label, selection)
                assert status == 1, (label, status, output)
                failures = [line for line in output.splitlines() if "assertion failed:" in line]
                assert failures and "assertion failed: " + expected in failures[0], (label, output)
                records.append(dict(mutation=label, source=source, command=command, exit=status,
                                    property=expected, failure=failures[0]))
                print(f"{label}: EXIT={status}; {failures[0]}", flush=True)
            finally:
                path.write_bytes(original)
                assert path.read_bytes() == original
    finally:
        for name, original in originals.items():
            assert (PACKAGE / name).read_bytes() == original
    status, _, output = run("restored-tests")
    assert status == 0, output
    for name, original in originals.items():
        assert (PACKAGE / name).read_bytes() == original
    (PACKAGE / "test-data/bolt11-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"BOLT11 mutations: {len(records)}/21 detected; restored lake test: EXIT=0")


if __name__ == "__main__":
    main()
