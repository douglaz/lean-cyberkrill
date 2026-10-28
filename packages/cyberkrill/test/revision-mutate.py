#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent compiled production regressions and restored executable checks."""
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
import revisions


def mutations():
    syntax = "Cyberkrill/InvoiceJson.lean"
    adapter = "Cyberkrill/Lightning.lean"
    app = "Cyberkrill/App.lean"
    scope = "test/scope.py"
    rows = [
        ("timestamp-compact-offset", syntax, "rest'.length == 2 && hours < 24", "rest'.length == 2 && hours < 24 && rest'.head? == some ':'", "timestamp/compact-zone", "success status"),
        ("timestamp-expanded-year", syntax, "year ≤ 262142 do none", "year ≤ 9999 do none", "timestamp/expanded-year", "success status"),
        ("timestamp-unicode-space", syntax, "cs.dropWhile timeSpace", "cs.dropWhile (· == ' ')", "timestamp/zone-nbsp", "success status"),
        ("timestamp-utc-minimum", syntax, "day == 1 && utc < 0", "day == 1 && utc < -86400", "timestamp/utc-underflow", "failure status"),
        ("timestamp-utc-maximum", syntax, "day == 31 && utc ≥ 86400", "day == 31 && utc ≥ 172800", "timestamp/utc-overflow", "failure status"),
        ("timestamp-calendar", syntax, "day ≤ days &&", "day ≤ days + 1 &&", "timestamp/date-leap-invalid", "failure status"),
        ("timestamp-separator", syntax, "['T', 't', ' '].contains separator", "['T', 't', ' ', '\\t'].contains separator", "timestamp/tab-separator", "failure status"),
        ("timestamp-offset-bound", syntax, "rest'.length == 2 && hours < 24", "rest'.length == 2 && hours < 25", "timestamp/zone-hour-overflow", "failure status"),
        ("surrogate-high-required-pair", syntax, "| _ => false\n    else", "| _ => true\n    else", "unicode/known-high", "failure status"),
        ("surrogate-low-refusal", syntax, "!(0xDC00 ≤ unit && unit ≤ 0xDFFF)", "!(0xDC00 ≤ unit && unit < 0xDC00)", "unicode/known-low", "failure status"),
        ("surrogate-pair-second-unit", syntax, "0xDC00 ≤ low && low ≤ 0xDFFF", "low ≤ 0xFFFF", "unicode/known-high-ascii", "failure status"),
        ("surrogate-known-field-name", syntax, "unless validKeys do throw .invalidInvoiceJson\n    return fields", "unless validKeys || !fields.isEmpty do throw .invalidInvoiceJson\n    return fields", "unicode/field-name-high", "failure status"),
        ("surrogate-ignored-value", syntax, 'if known.contains key && key != "routes" && key != "fees" then checkStrings value', 'if key != "routes" && key != "fees" then checkStrings value', "unicode/ignored-high", "success status"),
        ("sequence-root-mapping", adapter, 'let net ← InvoiceJson.enumName (← field j "network")', 'let j ← if let .arr _ := (← jsonResult (Json.parse input)) then throw Error.invalidInvoiceJson else pure j\n  let net ← InvoiceJson.enumName (← field j "network")', "sequence/root-length-14", "success status"),
        ("sequence-hop-mapping", adapter, 'let j ← InvoiceJson.structObject j ["src_node_id"', 'let j ← if let .arr _ := j then throw Error.invalidInvoiceJson else InvoiceJson.structObject j ["src_node_id"', "sequence/hop-length-6", "success status"),
        ("sequence-fee-mapping", adapter, 'let fees ← InvoiceJson.structObject (← field j "fees")', 'let fees ← if let .arr _ := (← field j "fees") then throw Error.invalidInvoiceJson else InvoiceJson.structObject (← field j "fees")', "sequence/fees-length-2", "success status"),
        ("sequence-lexical-number", syntax, "unless digits literal do throw .invalidInvoiceJson", "unless digits literal || literal.contains 'e' do throw .invalidInvoiceJson", "sequence/root-unsigned", "failure status"),
        ("sequence-length-bound", syntax, "actual == expected", "actual ≥ expected", "sequence/root-length-15", "failure status"),
        ("simnet-decode-network", adapter, "Bitcoin.Address.encodeScript parts.hrp.currency.network", "Bitcoin.Address.encodeScript (addressNetwork parts.hrp.currency)", "simnet/decode", "unlisted difference"),
        ("simnet-encode-network", adapter, "| .bc => .mainnet | .bcrt => .regtest | .tbs => .signet | .tb | .sb => .testnet", "| .bc => .mainnet | .bcrt | .sb => .regtest | .tbs => .signet | .tb => .testnet", "simnet/encode", "success status"),
        ("decoder-create-invoice", app, "let .ok () ← prepareDecodeOutput services path | return .error .outputFailure\n    return (LightningCli.decodeInvoice", "let .ok () ← prepareDecodeOutput services none | return .error .outputFailure\n    return (LightningCli.decodeInvoice", "output/ln-decode-invoice-create", "failed output existence/bytes"),
        ("decoder-truncate-lnurl", app, "let .ok () ← prepareDecodeOutput services path | return .error .outputFailure\n    return (LightningCli.decodeLnurl", "let .ok () ← prepareDecodeOutput services none | return .error .outputFailure\n    return (LightningCli.decodeLnurl", "output/ln-decode-lnurl-truncate", "failed output existence/bytes"),
        ("decoder-open-before-decode", app, "catch _ => return .error .outputFailure\n\ndef execute", "catch _ => return .ok ()\n\ndef execute", "output/ln-decode-invoice-open-error", "error ordering/identity"),
        ("decoder-read-before-open", app, "let .ok text ← lightningInput services input false | return .error .inputFailure\n    let .ok () ← prepareDecodeOutput services path | return .error .outputFailure\n    return (LightningCli.decodeLnurl", "let .ok () ← prepareDecodeOutput services path | return .error .outputFailure\n    let .ok text ← lightningInput services input false | return .error .inputFailure\n    return (LightningCli.decodeLnurl", "output/ln-decode-lnurl-read-before-open", "error ordering/identity"),
        ("encoder-late-output", app, "let .ok text ← lightningInput services input true | return .error .inputFailure", "let .ok text ← lightningInput services input true | return .error .inputFailure\n    let .ok () ← prepareDecodeOutput services path | return .error .outputFailure", "output/encode-preserve", "failed output existence/bytes"),
        ("scope-accept-closed", scope, 'current["status"] in ["in_progress", "closed"]', 'current["status"] in ["in_progress"]', "scope/closed", "closure validation"),
        ("scope-closure-reason", scope, 'assert current["close_reason"].strip(), "nonempty closure reason"', 'assert isinstance(current["close_reason"], str), "closure reason type"', "scope/closed-empty-reason", "closure validation"),
        ("scope-closure-order", scope, 'assert date(original["updated_at"]) <= closed <= updated, "closure timestamp order"', 'assert closed <= updated, "closure timestamp order"', "scope/closed-wrong-order", "closure validation"),
        ("scope-unrelated-record", scope, 'assert all(original[k] == current[k] for k in original if k != ISSUE)', 'assert all(original[k]["id"] == current[k]["id"] for k in original if k != ISSUE)', "scope/unrelated", "closure validation"),
        ("scope-decision-preservation", scope, '{"status", "updated_at", "closed_at", "close_reason"}', '{"status", "updated_at", "closed_at", "close_reason", "description"}', "scope/decision-text", "closure validation"),
    ]
    assert len(rows) == 30
    return rows


def fingerprints():
    paths = importlib.import_module("lightning-mutate").bound_paths()
    paths += [APP / "test" / name for name in ["revisions.py", "revision-cases.py", "capture-revisions.py",
              "revision-mutate.py", "scope.py", "validate.py", "record-revision-regressions.py"]]
    paths += [APP / "test/golden" / name for name in ["revision-reference.json", "revision-provenance.json", "revision-regression-record.json"]]
    return {str(p.relative_to(APP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def verify():
    record = json.loads((APP / "test/golden/revision-mutation-record.json").read_bytes())
    assert record["source_sha256"] == fingerprints(), "stale revision mutation evidence"
    assert record["count"] == len(record["mutations"]) == len(mutations()) == 30
    assert len({tuple(r[1:4]) for r in mutations()}) == 30, "distinct revision production edits"
    for observed, (name, path, old, new, case, assertion) in zip(record["mutations"], mutations()):
        assert (observed["property"], observed["file"], observed["replace"], observed["with_text"]) == (name, path, old, new)
        assert observed["case"] == case and observed["assertion"] == assertion
        assert observed["build"]["status"] == observed["restore_build"]["status"] == observed["green"]["status"] == 0
        assert observed["red"]["status"] == 1 and assertion in observed["failure"] and "AssertionError:" in observed["failure"]
    assert record["restored_full"]["status"] == record["regressions_green"]["status"] == record["scope_green"]["status"] == 0
    print("revision mutation evidence: 30 distinct edits/runtime reds; restored full suite and all 183 regressions exit 0")


def main():
    if sys.argv[1:] == ["--verify"]:
        verify(); return
    assert not sys.argv[1:]
    os.chdir(APP)
    logs = APP / ".lake/revision-mutations"
    logs.mkdir(parents=True, exist_ok=True)
    rows = mutations()
    originals = {Path(r[1]): Path(r[1]).read_bytes() for r in rows}
    hashes = fingerprints()
    managed = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def write(path, data):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            path.write_bytes(data)
            assert path.read_bytes() == data, "revision exact source restoration"
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def restore():
        for path, data in originals.items(): write(path, data)

    def interrupted(signum, _):
        restore()
        raise SystemExit(128 + signum)

    for signum in managed: signal.signal(signum, interrupted)

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
        for name, relative, old, new, case, assertion in rows:
            path = Path(relative)
            source = originals[path].decode()
            assert source.count(old) == 1, "unique production mutation: " + name
            args = ["python3", "-B", "test/revisions.py", *( ["--scope", case.split("/", 1)[1]] if case.startswith("scope/") else ["--case", case])]
            try:
                write(path, source.replace(old, new, 1).encode())
                proc, compiled = command(name + "-build", build)
                assert proc.returncode == 0, "revision production must compile: " + name
                proc, red = command(name + "-red", args)
                failure = proc.stderr.decode().splitlines()[-1] if proc.stderr else ""
                assert proc.returncode == 1 and assertion in failure and "AssertionError:" in failure, "revision runtime detecting assertion: " + name
            finally: write(path, originals[path])
            proc, restored = command(name + "-restore-build", build)
            assert proc.returncode == 0, "revision restored compilation: " + name
            proc, green = command(name + "-green", args)
            assert proc.returncode == 0, "revision restored check: " + name
            records.append(dict(property=name, file=relative, replace=old, with_text=new, case=case,
                                assertion=assertion, failure=failure, build=compiled, red=red,
                                restore_build=restored, green=green))
            print(f"{name}: compiled, runtime red 1 ({assertion}), restored green 0", flush=True)
        proc, full = command("restored-full", ["lake", "test"])
        assert proc.returncode == 0, "revision restored full suite"
        proc, regressions = command("regressions-green", ["python3", "-B", "test/revisions.py"])
        assert proc.returncode == 0, "all revision regressions restored green"
        proc, scope = command("scope-green", ["python3", "-B", "test/revisions.py", "--scope"])
        assert proc.returncode == 0, "all nine synthetic scope cases restored green"
        assert fingerprints() == hashes, "final exact production/test/checker restoration"
        record = dict(count=len(records), source_sha256=hashes, mutations=records, restored_full=full, regressions_green=regressions, scope_green=scope)
        (APP / "test/golden/revision-mutation-record.json").write_text(json.dumps(record, indent=2) + "\n")
    finally: restore()
    verify()


if __name__ == "__main__": main()
