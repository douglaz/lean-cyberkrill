# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Detect individual production fee mutations, restoring exact bytes in finally."""
import json
from pathlib import Path
import signal
import subprocess

PACKAGE = Path(__file__).resolve().parent
LIBRARY = "Bitcoin/Fee.lean"
LOGS = PACKAGE / ".lake/fee-mutation-checks"
GATE = "894 library theorems; 73 named; 0 offenders"


def replace(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    changed = text.replace(old, new)
    assert changed != text and new in changed and old not in changed
    return changed


def mutations(text):
    cases = [
        ("vbytes-floor", "(weight + 3) / 4", "weight / 4", "shapes",
         "fee shape (1,0) vbytes"),
        ("drop-witness-flag", "(if inputs > 0 then 2 else 0)", "0", "shapes",
         "fee shape (1,0) weight"),
        ("always-witness-flag", "(if inputs > 0 then 2 else 0)", "2", "shapes",
         "fee shape (0,0) weight"),
        ("signature-length", "let signatureLength := 72", "let signatureLength := 73", "shapes",
         "fee shape (1,0) weight"),
        ("output-script-length", "let outputScriptLength := 22", "let outputScriptLength := 21", "shapes",
         "fee shape (0,1) weight"),
        ("input-count-compactsize", "4 + cs inputs + cs outputs", "4 + 1 + cs outputs", "shapes",
         "fee shape (253,1) weight"),
        ("output-count-compactsize", "4 + cs inputs + cs outputs", "4 + cs inputs + 1", "shapes",
         "fee shape (1,253) weight"),
        ("fee-floor", ").round.toUInt64", ").floor.toUInt64", "pins",
         "fee named pins (2,2) at 0.5sat = 105"),
        ("multiply-before-divide", "(v * (r / 1000.0))", "(r * v / 1000.0)", "pins",
         "fee named pins (1,1) at 1.15sats = 126"),
        ("wrapping-rate", "(min rate.msat 18446744073709551615).toUInt64", "rate.msat.toUInt64",
         "shape-fees", "fee shape (0,0) at 200000000btc sats"),
    ]
    assert len(cases) == 10
    return [(label, replace(text, old, new), selection, expected)
            for label, old, new, selection, expected in cases]


def run(label, selection):
    command = ["lake", "test"] + (["--", "--fee", selection] if selection else [])
    out, err = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
    return result.returncode, command, out.read_text() + err.read_text()


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    path = PACKAGE / LIBRARY
    original = path.read_bytes()
    records = []
    for label, changed, selection, expected in mutations(original.decode()):
        assert path.read_bytes() == original
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            status, command, output = run(label, selection)
            assert status == 1, (label, status, output)
            assert GATE in output, (label, output)
            failures = [line for line in output.splitlines() if "assertion failed:" in line]
            assert failures and failures[0].endswith("assertion failed: " + expected), (label, output)
            records.append(dict(mutation=label, source=LIBRARY, command=command, exit=status,
                                caught_by="test", property=expected, failure=failures[0]))
            print(f"{label}: EXIT={status}; {failures[0]}", flush=True)
        finally:
            path.write_bytes(original)
            assert path.read_bytes() == original
    status, _, output = run("restored-tests", None)
    assert status == 0 and GATE in output, output
    assert path.read_bytes() == original
    (PACKAGE / "test-data/fee-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"fee mutations: {len(records)}/10 detected; restored lake test: EXIT=0", flush=True)


if __name__ == "__main__":
    main()
