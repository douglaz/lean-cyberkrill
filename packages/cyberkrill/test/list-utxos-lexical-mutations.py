#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent lexical branch controls on synthetic public-export variants."""
import hashlib
import importlib
import json
from pathlib import Path
import signal
import sys
import time

from evidence_history import publish_history
from cases import APP

M = importlib.import_module("list-utxos-mutations")
L = importlib.import_module("list-utxos")
DEST = APP / "test/golden/list-utxos-lexical-mutation-record.json"
SOURCE = APP / "Cyberkrill/Frozenkrill.lean"
PREVIOUS_SHA256 = "8205d47929b2ce52fd60b27b612d5e86f053d8512abe7b1919e1095863eb2838"


def edits():
    return [
        ("high-pair-required", '| _ => false\n    else', '| _ => true\n    else'),
        ("low-surrogate-refused", '!(0xDC00 ≤ unit && unit ≤ 0xDFFF)', 'true'),
        ("pair-second-unit", '0xDC00 ≤ low && low ≤ 0xDFFF', 'low ≤ 0xFFFF'),
        ("escaped-field-name", 'let .str key ← Json.parse token | throw "field"',
         'let .str decoded ← Json.parse token | throw "field"\n        let key := if token.contains \'\\\\\' then token else decoded'),
        ("nested-field-name", 'unless validKeys do throw "field escape"',
         'unless validKeys || known.contains "address" do throw "field escape"'),
        ("ignored-duplicate", 'fields.map (·.1) |>.filter (known.contains ·)', 'fields.map (·.1)'),
        ("ignored-surrogate", 'if known.contains key then', 'if true then'),
        ("valid-pair", '0xDC00 ≤ low && low ≤ 0xDFFF && validStringChars tail', 'false'),
        ("ordinary-unicode", '.atom (validStringChars token.toList)',
         '.atom (validStringChars token.toList && token.toList.all (fun c => c.toNat < 128))'),
    ]


def check(name):
    for kind in ["single", "multisig"]:
        original = json.loads((APP / f"test/recordings/shared/frozenkrill-{kind}.json").read_bytes())
        raw = json.dumps(original)
        if name in {"high-pair-required", "low-surrogate-refused", "pair-second-unit", "valid-pair", "ordinary-unicode"}:
            token = {"high-pair-required": '"\\ud800"', "low-surrogate-refused": '"\\udc00"',
                     "pair-second-unit": '"\\ud800\\u0041"', "valid-pair": '"\\ud83d\\ude00"',
                     "ordinary-unicode": '"日本語"'}[name]
            value = json.dumps(dict(original, network="raw-token")).replace('"raw-token"', token)
        elif name == "escaped-field-name":
            value = '{"\\u0077allet":"frozenkrill",' + raw[1:]
        elif name == "nested-field-name":
            value = json.dumps(dict(original, receiving_addresses="raw-token")).replace(
                '"raw-token"', '[{"address":"synthetic","\\ud800":null}]')
        elif name == "ignored-duplicate": value = '{"unknown":false,"unknown":true,' + raw[1:]
        elif name == "ignored-surrogate": value = '{"unknown":"\\ud800",' + raw[1:]
        else: raise ValueError(name)
        result = L.reader(value.encode())
        valid = name in {"ignored-duplicate", "ignored-surrogate", "valid-pair", "ordinary-unicode"}
        assert (result != "invalidWallet") == valid, "wallet lexical branch " + name
        if valid:
            prefix = "singlesig_" if kind == "single" else ""
            assert json.loads(result) == dict(receiving=original[prefix + "receiving_output_descriptor"],
                                             change=original[prefix + "change_output_descriptor"]), "wallet lexical descriptors " + name


def fingerprints():
    return dict(M.fingerprints(), **{"test/list-utxos-lexical-mutations.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})


PRE_PSBT_SHA256 = 'a31ab2e1625bff057b56362d03bee1923a30c650c0cf81bfdf0f542672d21003'

def verify():
    record = json.loads(DEST.read_bytes())
    retained = record["pre_psbt_observation"]
    assert hashlib.sha256((json.dumps(retained, indent=2) + "\n").encode()).hexdigest() == PRE_PSBT_SHA256, "retained pre-PSBT observation"
    previous = record["previous_observation"]
    assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256, "retained lexical branch observation"
    assert record["source_sha256"] == fingerprints(), "stale lexical branch evidence"
    assert record["count"] == len(record["checks"]) == len(edits()) == 9
    for row, (name, old, new) in zip(record["checks"], edits()):
        assert (row["property"], row["replace"], row["with_text"]) == (name, old, new)
        assert [row[k]["status"] for k in ["build", "red", "restore_build", "green"]] == [0, 1, 0, 0]
    assert record["baseline"]["status"] == record["restored_full"]["status"] == 0
    print("wallet lexical branches: 9 compiled edits; 9 named runtime reds; 18 restored schema controls")


def main():
    if sys.argv[1:2] == ["--case"]:
        name, = sys.argv[2:]; check(name); return
    if sys.argv[1:] == ["--verify"]: verify(); return
    assert not sys.argv[1:]
    M.CANCELLED = None
    M.LOGS = APP / ".lake/validation/list-lexical-mutations" / str(time.time_ns())
    M.LOGS.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_bytes(); hashes = fingerprints()
    prior = json.loads(DEST.read_bytes())
    pre_psbt = prior.get("pre_psbt_observation", {k: v for k, v in prior.items() if not k.endswith("_observation")})
    assert hashlib.sha256((json.dumps(pre_psbt, indent=2) + "\n").encode()).hexdigest() == PRE_PSBT_SHA256, "original pre-PSBT observation"
    previous = prior.get("previous_observation", prior)
    assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256
    managed = [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]
    def restore():
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try: SOURCE.write_bytes(original); assert SOURCE.read_bytes() == original
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    # The shared command owns cleanup; source restoration follows its unwind.
    def interrupted(signum, _): raise SystemExit(M.remember_cancellation(signum))
    handlers = {sig: signal.signal(sig, interrupted) for sig in managed}
    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    records = []
    try:
        baseline = M.command("baseline", build, 0)
        for name, _, _ in edits(): check(name)
        for name, old, new in edits():
            assert original.decode().count(old) == 1, "unique lexical branch mutation " + name
            args = ["python3", "-B", "test/list-utxos-lexical-mutations.py", "--case", name]
            try:
                changed = original.decode().replace(old, new, 1).encode()
                SOURCE.write_bytes(changed); assert SOURCE.read_bytes() == changed
                compiled = M.command(name + "-build", build, 0)
                red = M.command(name + "-red", args, 1, "wallet lexical branch " + name)
            finally: restore()
            restored = M.command(name + "-restore-build", build, 0)
            green = M.command(name + "-green", args, 0)
            records.append(dict(property=name, replace=old, with_text=new, build=compiled, red=red, restore_build=restored, green=green))
            print(name + ": build/red/restore/green 0/1/0/0", flush=True)
        full = M.command("restored-full", ["python3", "-B", "test/list-utxos.py"], 0)
        assert fingerprints() == hashes, "lexical branch exact restoration"
        publish_history(DEST, json.dumps(dict(pre_psbt_observation=pre_psbt, count=len(records), source_sha256=hashes, previous_observation=previous, baseline=baseline,
                                        checks=records, restored_full=full), indent=2) + "\n")
        verify()
    except SystemExit:
        restore(); raise
    except BaseException:
        restore(); M.command("failure-restore-build", build, 0); raise
    finally:
        restore()
        for sig, handler in handlers.items(): signal.signal(sig, handler)


if __name__ == "__main__": main()
