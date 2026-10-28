#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled production mutations, runtime assertions and exact restored sources."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cases import APP


def mutations():
    app, adapter, errors = "Cyberkrill/App.lean", "Cyberkrill/Lightning.lean", "Cyberkrill/Amounts.lean"
    routing = [(["--routing"], "")]

    def case(name, assertion): return (["--case", name], assertion)

    rows = [
        ("invoice-dispatch", app, "(LightningCli.decodeInvoice text).map", "(LightningCli.decodeLnurl text).map",
         [case("valid/L410", "success status")]),
        ("lnurl-dispatch", app, "(LightningCli.decodeLnurl text).map", "(LightningCli.decodeInvoice text).map",
         [case("lnurl-reference/cyberkrill", "success status")]),
        ("signing-dispatch", app, "(LightningCli.encodeInvoice text key).map", "(LightningCli.decodeInvoice text).map",
         [case("encode/valid/L410", "success status")]),
        ("literal-input", app, "else return .ok value", 'else return .ok ""', [case("valid/L410", "success status")]),
        ("file-input", app, "else services.readFile value", "else pure value", [(["--routing"], "encoder input routing")]),
        ("ordinary-file-output", app, "some p => { ordinaryFile := some (p, text) }", "some _ => { stdout := text }",
         [(["--routing"], "ordinary output status/streams")]),
        ("encoded-newline", app, "(LightningCli.encodeInvoice text key).map (lightningOutput · path true)",
         "(LightningCli.encodeInvoice text key).map (lightningOutput · path false)", [case("encode/valid/L410", "unlisted difference")]),
        ("decoded-newline", app, "(LightningCli.decodeInvoice text).map (lightningOutput · path false)",
         "(LightningCli.decodeInvoice text).map (lightningOutput · path true)", [case("valid/L410", "Lightning stdout newline")]),
        ("builder-field-order", adapter, "[desc, .paymentHash paymentHash,", "[.paymentHash paymentHash, desc,",
         [case("encode/valid/L410", "unlisted difference")]),
        ("builder-feature-default", adapter, ".features (2^8 + 2^14)", ".features (2^14)",
         [case("encode/valid/L410", "unlisted difference")]),
        ("builder-hrp", adapter, "[(.milli, 1000000000),", "[(.micro, 1000000),",
         [case("builder/amount-100000000000", "unlisted difference"), case("builder/amount-0", "unlisted difference")]),
        ("timestamp-json", adapter, "toJson (parts.timestamp * 1000)", "toJson (parts.timestamp * 1000 + 1)",
         [case("valid/L410", "unlisted difference")]),
        ("route-retention", adapter, "(routes.filter (!·.isEmpty)).map Field.route", "(routes.filter (fun _ => false)).map Field.route",
         [case("encode/valid/L516", "unlisted difference")]),
        ("public-key-normalization", adapter, "Secp256k1.compressPubkey b", "if b.size == 33 then Secp256k1.compressPubkey b else none",
         [case("builder/destination-uncompressed", "success status"), case("builder/route-uncompressed", "success status"),
          case("builder/destination-hybrid", "success status"), case("builder/route-hybrid", "success status")]),
        ("hybrid-parity", adapter, "Secp256k1.compressPubkey b", "Secp256k1.compressPubkey (if b.size == 65 then b.set! 0 4 else b)",
         [case("builder/destination-mismatched", "ordinary failure"), case("builder/route-mismatched", "ordinary failure")]),
        ("json-lexical-validation", adapter, "InvoiceJson.validateSyntax input", "pure ()",
         [case("json/duplicate-known", "ordinary failure"), case("json/exponent-amount_msats", "ordinary failure")]),
        ("json-rfc3339-validation", adapter, "unless InvoiceJson.timestampValid timestamp do throw .invalidInvoiceJson",
         "unless InvoiceJson.timestampValid timestamp || !timestamp.isEmpty do throw .invalidInvoiceJson",
         [case("json/timestamp-6", "ordinary failure")]),
        ("json-enum-shapes", adapter, "let value ← InvoiceJson.enumName status", "let value ← text status",
         [case("json/feature-4", "success status")]),
        ("route-u16-bound", adapter, 'unsigned (← field j "cltv_expiry_delta") 16', 'unsigned (← field j "cltv_expiry_delta") 32',
         [case("json/hop-overflow-cltv_expiry_delta", "ordinary failure")]),
        ("ordinary-write-flush", app, "    handle.flush", "    pure ()", [(["--routing"], "ordinary write failure status")]),
        ("refusal-status", app, "  return 1\n", "  return 0\n",
         [case(name, "refusal port status") for name in importlib.import_module("lightning-compare").REFUSALS]),
        ("refusal-stream", app, 'services.stderr (error.message ++', 'services.stdout (error.message ++',
         [case(name, "refusal stdout") for name in importlib.import_module("lightning-compare").REFUSALS]),
        ("refusal-identity", errors, 'code ++ ": Invalid Lightning input"', '"wrongLightningError: Invalid Lightning input"',
         [case(name, "refusal error identity") for name in importlib.import_module("lightning-compare").REFUSALS]),
        ("signing-hash-payee-output", adapter, "Bitcoin.Hex.encode inv.payeeKey", "Bitcoin.Hex.encode (parts.payeePubkey.getD ByteArray.empty)",
         [case("positive/amount-leading-zero", "wrong pinned values")]),
        ("explicit-n-verification", adapter, "decode (bolt11Curve ByteArray.empty) input",
         "decode { (bolt11Curve ByteArray.empty) with verify := fun _ _ _ => false } input",
         [case("positive/n-amount-leading-zero", "leading-zero port status/stderr")]),
        ("route-fee-json", adapter, "toJson hop.feeBaseMsat.toNat", "toJson (hop.feeBaseMsat.toNat + 1)",
         [case("valid/L516", "unlisted difference")]),
        ("lnurl-query-json", adapter, "(k, toJson v)", "(k, toJson (v ++ k))",
         [case("lnurl-reference/cyberkrill", "unlisted difference")]),
    ]
    old = '''  (sign (bolt11Curve key) parts).mapError fun e =>
    .lightning ((reprStr e).replace "Lightning.Bolt11.EncodeError." "")'''
    new = '''  let result ← (sign (bolt11Curve key) parts).mapError fun e =>
    Error.lightning ((reprStr e).replace "Lightning.Bolt11.EncodeError." "")
  let _ ← (decode (bolt11Curve key) result).mapError invoiceError
  return result'''
    rows.append(("explicit-n-signing-policy", adapter, old, new, [case("builder/explicit-n-mismatch", "success status")]))
    rows.append(("json-enum-duplicate", "Cyberkrill/InvoiceJson.lean",
                 'if key == "network" then checkEnumSyntax value', 'if key == "network" then pure ()',
                 [case("json/duplicate-network-enum", "ordinary failure")]))
    assert len(rows) == 29
    return rows


def bound_paths():
    paths = [APP / "Cyberkrill" / name for name in
             ["App.lean", "Amounts.lean", "Capabilities.lean", "Lightning.lean", "InvoiceJson.lean", "PrivateOutput.lean"]]
    paths += [APP / "test" / name for name in ["lightning-mutate.py", "lightning.py", "lightning-compare.py",
              "lightning-cases.py", "compare.py", "selftest.py", "driver.py", "verify.py"]]
    paths += [APP / name for name in ["Main.lean", "CyberkrillTests.lean", "lakefile.lean", "private_output.c"]]
    paths += sorted((APP / "CyberkrillTests").glob("*.lean"))
    paths += [APP / "test/golden" / name for name in ["lightning-reference.json", "lightning-routing-reference.json", "lightning-provenance.json"]]
    return paths


def fingerprints():
    return {str(p.relative_to(APP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound_paths()}


def verify():
    data = json.loads((APP / "test/golden/lightning-mutation-record.json").read_bytes())
    assert data["source_sha256"] == fingerprints(), "stale Lightning mutation evidence"
    planned = mutations()
    assert data["count"] == len(data["mutations"]) == len(planned) == 29
    edits = {(r[1], r[2], r[3]) for r in planned}
    old_edits = {(r[1], r[2], r[3]) for r in importlib.import_module("mutate").mutations()}
    assert len(edits) == 29 and len(edits - old_edits) == data["new_distinct"] == 28
    executions = 0
    for record, (name, path, old, new, tests) in zip(data["mutations"], planned):
        assert (record["property"], record["file"], record["replace"], record["with_text"]) == (name, path, old, new)
        assert record["build"]["status"] == record["restore_build"]["status"] == 0
        assert len(record["checks"]) == len(tests)
        for check, (args, assertion) in zip(record["checks"], tests):
            assert check["command"] == ["timeout", "--foreground", "180", "python3", "-B", "test/lightning.py", *args]
            assert check["assertion"] == assertion and check["red"]["status"] == 1 and check["green"]["status"] == 0
            assert assertion in check["red"]["failure"] and "AssertionError:" in check["red"]["failure"]
            executions += 1
    assert executions == data["executions"] == 92
    assert data["restored_full"]["status"] == 0
    print("Lightning mutation evidence: 29 distinct edits (28 new), 92 runtime reds, restored full suite exit 0")


def main():
    if sys.argv[1:] == ["--verify"]:
        verify(); return
    assert not sys.argv[1:]
    os.chdir(APP)
    logs = APP / ".lake/lightning-mutations"
    logs.mkdir(parents=True, exist_ok=True)
    rows = mutations()
    originals = {Path(r[1]): Path(r[1]).read_bytes() for r in rows}
    hashes = fingerprints()
    signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def write(path, data):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            path.write_bytes(data)
            assert path.read_bytes() == data, "mutation exact write/restoration"
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def restore():
        for path, data in originals.items(): write(path, data)

    def interrupted(signum, _):
        restore()
        raise SystemExit(128 + signum)

    for signum in signals: signal.signal(signum, interrupted)

    def command(label, args):
        bounded = ["timeout", "--foreground", "180", *args]
        start = time.monotonic()
        proc = subprocess.run(bounded, stdin=subprocess.DEVNULL, capture_output=True, timeout=190)
        for stream in ["stdout", "stderr"]: (logs / (label + "." + stream)).write_bytes(getattr(proc, stream))
        (logs / (label + ".status")).write_text(str(proc.returncode) + "\n")
        return proc, dict(command=bounded, status=proc.returncode, seconds=round(time.monotonic() - start, 3))

    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    records = []
    try:
        for name, relative, old, new, tests in rows:
            path = Path(relative)
            original = originals[path]
            source = original.decode()
            assert source.count(old) == 1, "unique production mutation: " + name
            checks = []
            try:
                write(path, source.replace(old, new, 1).encode())
                compiled, compilation = command(name + "-build", build)
                assert compiled.returncode == 0, "production mutation must compile: " + name
                for i, (args, assertion) in enumerate(tests):
                    proc, red = command(f"{name}-{i}-red", ["python3", "-B", "test/lightning.py", *args])
                    assert proc.returncode == 1, "production mutation runtime red: " + name
                    error = proc.stderr.decode()
                    assert assertion in error and "AssertionError:" in error, "production detecting assertion: " + name
                    red["failure"] = error.splitlines()[-1]
                    checks.append(dict(command=red["command"], assertion=assertion, red=red))
            finally:
                write(path, original)
            restored, restoration = command(name + "-restore-build", build)
            assert restored.returncode == 0, "restored production compilation: " + name
            for i, (check, (args, _)) in enumerate(zip(checks, tests)):
                proc, check["green"] = command(f"{name}-{i}-green", ["python3", "-B", "test/lightning.py", *args])
                assert proc.returncode == 0, "restored production test: " + name
            records.append(dict(property=name, file=relative, replace=old, with_text=new,
                                build=compilation, restore_build=restoration, checks=checks))
            print(f"{name}: compiled, {len(checks)} runtime red(s), restored green(s)", flush=True)
        proc, full = command("restored-full", ["lake", "test"])
        assert proc.returncode == 0, "restored full suite"
        assert fingerprints() == hashes, "final production/test/checker bytes restored"
        executions = sum(len(r["checks"]) for r in records)
        assert executions == 92
        record = dict(count=29, new_distinct=28, executions=executions,
                      source_sha256=hashes, mutations=records, restored_full=full)
        Path("test/golden/lightning-mutation-record.json").write_text(json.dumps(record, indent=2) + "\n")
    finally:
        restore()
    verify()


if __name__ == "__main__":
    main()
