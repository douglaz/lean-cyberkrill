# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Break one production property at a time and require its named acceptance assertion."""
import json
from pathlib import Path
import re
import signal
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/bolt11-mutation-checks"
CODEC = "Lightning/Bolt11/Codec.lean"
FIELDS = "Lightning/Bolt11/Fields.lean"
PROOFS = "Lightning/Bolt11/Proofs.lean"
AMOUNTS = "Lightning/Bolt11/AmountProofs.lean"
# Last codec-only revision: these 21 runtime observations predate the proofs.
# Never read HEAD here: it contains proof-era records after this change lands.
RUNTIME_BASE = "730c23ae4481e4f66e05b633a70d510e1594d96b"

# A proof stop is admitted only at a declaration actually falsified by the edit.
# These examples explain that falsity independently of the proof's tactic shape.
PROOF_STOPS = {
    "hrp-case": (PROOFS, "signingHash_spec", "Uppercase HRP hashes different UTF-8 bytes from its lowercase form."),
    "hash-padding": (PROOFS, "signingHash_spec", "A one-symbol [1] tail loses its final partial byte."),
    "signature-boundary": (PROOFS, "decode_trace", "With a constant successful recovery capability, use timestamp plus valid fields ending in symbol zero and append 103 zero signature symbols. The shifted parser succeeds, but its signed prefix includes one more symbol than the trace conclusion."),
    "hrp-leading-zero": (AMOUNTS, "parseHrp_spelling", "The representable zero HRP encodes as lnbc0, now rejected; this also falsifies parseHrp_encodeHrp and hrpFromMsat_roundTrip at zero."),
    "pico-precision": (AMOUNTS, "checkPrecision_rejects", "Available pico 1 is imprecise but is now accepted."),
    "bech32m": (PROOFS, "decode_trace", "A valid invoice framed with bech32m can succeed, contrary to the bech32 conclusion."),
    "length-7090": (PROOFS, "decode_trace", "A valid 7090-character invoice can succeed while its 7089-limited bech32 parse fails."),
    "wrong-fixed-length": (FIELDS, "decodeField_keptRaw", "KeptRaw 1 [] now errors rather than returning raw."),
    "unknown-fallback": (FIELDS, "decodeField_keptRaw", "KeptRaw 9 [19] now errors rather than returning raw."),
    "encode-stale-signature": (PROOFS, "encode_signingHash_spec", "A semantically valid invoice with an arbitrary stale recorded hash now encodes successfully."),
    "typed-zero-payment-hash": (FIELDS, "decodeField_fieldData", "A representable payment hash of 32 zero bytes now decodes to raw."),
    "amount-exact": (AMOUNTS, "hrpFromMsat_exact", "Zero msat is now represented by ten pico, giving one msat."),
    "amount-reverse": (AMOUNTS, "hrpFromMsat_exact", "Canonicalizing ten pico through one msat now returns twenty pico, changing the amount."),
    "amount-overflow-bound": (AMOUNTS, "hrpFromMsat_overflow", "1844674407370955162 msat is now accepted despite exceeding the pico-u64 bound."),
    "amount-milli": (AMOUNTS, "hrpFromMsat_exact", "100000000 msat selects milli but the changed divisor makes its represented pico product incorrect."),
    "amount-micro": (AMOUNTS, "hrpFromMsat_exact", "100000 msat selects micro but the changed divisor makes its represented pico product incorrect."),
    "amount-nano": (AMOUNTS, "hrpFromMsat_exact", "100 msat selects nano but the changed divisor makes its represented pico product incorrect."),
    "amount-pico": (AMOUNTS, "hrpFromMsat_exact", "One msat selects pico but the changed divisor represents five pico."),
    "amount-unavailable": (AMOUNTS, "checkPrecision_unavailable", "An absent amount now gives impreciseAmount instead of success."),
    "direct-spec-hash": (PROOFS, "signingHash_spec", "Dropping the padded final byte disagrees with the direct original-string spec digest."),
}


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
    result += [
        ("typed-zero-payment-hash", FIELDS, "| 1 => return .paymentHash bytes",
         "| 1 => return .raw tag data", "raw-counterexample", "KeptRaw typed zero payment hash"),
        ("amount-exact", CODEC, "let pico := amount.msat * 10", "let pico := amount.msat * 10 + 10",
         "amount-boundaries", "amount boundary exact"),
        ("amount-reverse", CODEC, "let pico := amount.msat * 10", "let pico := amount.msat * 20",
         "amount-boundaries", "reverse amount equality"),
        ("amount-overflow-bound", CODEC, "if pico ≥ 2^64 then throw .amountOverflow",
         "if pico ≥ 2^65 then throw .amountOverflow", "amount-boundaries", "amount boundary overflow"),
        ("amount-milli", CODEC, "(some .milli, 1000000000)", "(some .milli, 100000000)",
         "amount-boundaries", "amount boundary canonical unit"),
        ("amount-micro", CODEC, "(some .micro, 1000000)", "(some .micro, 100000)",
         "amount-boundaries", "amount boundary canonical unit"),
        ("amount-nano", CODEC, "(some .nano, 1000)", "(some .nano, 100)",
         "amount-boundaries", "amount boundary canonical unit"),
        ("amount-pico", CODEC, "(some .pico, 1)]", "(some .pico, 2)]",
         "amount-boundaries", "amount boundary canonical unit"),
        ("amount-unavailable", CODEC,
         "  if let some pico := hrp.picoAmount then\n    if pico % 10 ≠ 0 then throw .impreciseAmount",
         "  if let some pico := hrp.picoAmount then\n    if pico % 10 ≠ 0 then throw .impreciseAmount\n"
         "  else throw .impreciseAmount", "amount-boundaries", "unavailable amounts absent"),
        ("direct-spec-hash", CODEC,
         "(Bitcoin.Bech32.fesToBytesLax (data ++ [0, 0])).extract 0\n    ((data.length * 5 + 7) / 8)",
         "Bitcoin.Bech32.fesToBytesLax data", "spec-hashes", "direct spec hash L382"),
        ("amount-canonical-choice", CODEC,
         "[(none, 1000000000000), (some .milli, 1000000000), (some .micro, 1000000),\n"
         "      (some .nano, 1000), (some .pico, 1)]",
         "[(some .pico, 1), (none, 1000000000000), (some .milli, 1000000000),\n"
         "      (some .micro, 1000000), (some .nano, 1000)]",
         "amount-boundaries", "amount boundary canonical unit"),
        ("amount-raw-overflow-acceptance", CODEC,
         "    pure (some (UInt64.ofNat value))",
         "    if multiplier.isNone && value * 1000000000000 ≥ 2^64 then throw .invalidAmount\n"
         "    pure (some (UInt64.ofNat value))",
         "amount-boundaries", "unavailable amounts raw overflow")]
    assert len(result) == 33
    assert len({case[0] for case in result}) == 33
    return result


def proof_failure(label, output):
    source, theorem, explanation = PROOF_STOPS[label]
    lines = (PACKAGE / source).read_text().splitlines()
    starts = [i for i, line in enumerate(lines) if re.match(r"(?:private )?theorem " + theorem + r"\b", line)]
    assert len(starts) == 1, (label, starts)
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r"(?:private )?(?:theorem|def) |#print|end ", lines[i])), len(lines))
    errors = []
    for line in output.splitlines():
        match = re.match(r"error: " + re.escape(source) + r":(\d+):(\d+): (.*)", line)
        if match and start + 1 <= int(match[1]) <= end:
            errors.append(line)
    assert errors, (label, source, theorem, output)
    errors = [error for error in errors if not any(word in error for word in
              ["Unknown", "unknown", "unexpected token", "maximum", "unused", "failed to synthesize"])]
    assert errors, (label, "no theorem-specific proof failure")
    return dict(disposition="proof-caught", theorem="Lightning.Bolt11." + theorem,
                proof_source=source, declaration_lines=[start + 1, end],
                failure=errors[0], falsification=explanation)


def run(label, selection=None):
    command = ["lake", "test"] + (["--", "--case", selection] if selection else [])
    out, err = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
    return result.returncode, command, out.read_text() + err.read_text()


def counterexample(label):
    command = ["lake", "env", "lean", "--run", "LightningTests/ProofCounterexamples.lean", label]
    out, err = LOGS / f"{label}-witness.stdout", LOGS / f"{label}-witness.stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
    assert result.returncode == 0, (label, out.read_text(), err.read_text())
    return dict(command=command, exit=result.returncode, observation=out.read_text().strip(),
                stdout=f".lake/bolt11-mutation-checks/{label}-witness.stdout",
                stderr=f".lake/bolt11-mutation-checks/{label}-witness.stderr")


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def historical_runtime():
    historical = json.loads(subprocess.run(
        ["git", "show", f"{RUNTIME_BASE}:packages/lightning/test-data/bolt11-mutations.json"],
        cwd=PACKAGE, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout)
    prior = {entry["mutation"]: entry for entry in historical}
    assert len(historical) == len(prior) == 21
    assert all("historical_runtime" not in entry and entry["exit"] == 1
               and "assertion failed:" in entry["failure"] for entry in historical)
    return prior


def main():
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {name: (PACKAGE / name).read_bytes() for name in [CODEC, FIELDS]}
    prior = historical_runtime()
    records = []
    selected = set(sys.argv[1:])
    try:
        for label, source, old, new, selection, expected in cases():
            if selected and label not in selected:
                continue
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
                if failures:
                    assert "assertion failed: " + expected in failures[0], (label, output)
                    evidence = dict(disposition="runtime-caught", failure=failures[0])
                else:
                    assert label in PROOF_STOPS, (label, output)
                    evidence = proof_failure(label, output)
                    if label in ("signature-boundary", "length-7090"):
                        evidence["counterexample"] = counterexample(label)
                records.append(dict(mutation=label, source=source, command=command, exit=status,
                                    property=expected, **evidence,
                                    stdout=f".lake/bolt11-mutation-checks/{label}.stdout",
                                    stderr=f".lake/bolt11-mutation-checks/{label}.stderr",
                                    historical_runtime=prior.get(label)))
                print(f"{label}: EXIT={status}; {evidence['disposition']}; {evidence['failure']}", flush=True)
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
    if not selected:
        assert len(records) == 33
        (PACKAGE / "test-data/bolt11-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"BOLT11 mutations: {len(records)}/{len(records)} detected; restored lake test: EXIT=0")


if __name__ == "__main__":
    main()
