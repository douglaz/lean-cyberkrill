# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Mutate production conversion, pin detection, and restore exact source bytes."""
import json
from pathlib import Path
import re
import signal
import subprocess

PACKAGE = Path(__file__).resolve().parent
LIBRARY = "Bitcoin/Slip132.lean"
LOGS = PACKAGE / ".lake/slip132-mutation-checks"


def replace(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    changed = text.replace(old, new)
    assert changed != text and new in changed
    return changed


def mutations(text):
    cases = [
        ("wrong-table-byte", "| .ypub => ⟨#[0x04, 0x9D, 0x7C, 0xB2]⟩",
         "| .ypub => ⟨#[0x04, 0x9D, 0x7C, 0xB3]⟩", "conversions",
         "slip132 conversion 1 independent expectation"),
        ("drop-unknown-version", "| none => .error (.unknownVersion (p.extract 0 4))",
         "| none => .ok (.xpub, p.extract 4 p.size)", "unknown-version", "theorem:decode_sound"),
        ("length-off-by-one", "if p.size = 78 then", "if p.size = 79 then",
         "wrong-length", "theorem:decode_sound"),
        ("skip-version-swap",
         "def convert (s : String) (target : Version) : Except Error String :=\n"
         "  match decode s with\n  | .error e => .error e\n"
         "  | .ok (_, body) => .ok (Base58.base58CheckEncode (versionBytes target ++ body))",
         "def convert (s : String) (_target : Version) : Except Error String :=\n"
         "  match decode s with\n  | .error e => .error e\n"
         "  | .ok (source, body) => .ok (Base58.base58CheckEncode (versionBytes source ++ body))",
         "conversions", "theorem:convert_payload")]
    assert len(cases) == 4
    return [(label, replace(text, old, new), selection, expected)
            for label, old, new, selection, expected in cases]


def declaration_range(text, name):
    declaration = re.search(r"^theorem " + re.escape(name) + r"\b", text, re.M)
    assert declaration, name
    start = text[:declaration.start()].count("\n") + 1
    following = re.search(r"\n(?:theorem |def |end )", text[declaration.end():])
    end = declaration.end() + following.start() if following else len(text)
    return start, text[:end].count("\n") + 1


def run(label, selection):
    command = ["lake", "test"] + (["--", "--slip132", selection] if selection else [])
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
    path = PACKAGE / LIBRARY
    original = path.read_bytes()
    text = original.decode()
    records = []
    for label, changed, selection, expected in mutations(text):
        assert path.read_bytes() == original
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            status, command, output = run(label, selection)
            assert status == 1, (label, status, output)
            record = dict(mutation=label, source=LIBRARY, command=command, exit=status)
            if expected.startswith("theorem:"):
                theorem = expected.split(":", 1)[1]
                start, end = declaration_range(text, theorem)
                diagnostic = re.compile(r"^error: " + re.escape(LIBRARY) + r":(\d+):")
                failures = [line for line in output.splitlines() if diagnostic.search(line) and
                            start <= int(diagnostic.search(line)[1]) <= end]
                assert failures, (label, theorem, output)
                record.update(caught_by="theorem build", theorem_file=LIBRARY, theorem=theorem)
            else:
                assert "894 library theorems; 73 named; 0 offenders" in output
                failures = [line for line in output.splitlines() if "assertion failed:" in line]
                assert failures and "assertion failed: " + expected in failures[0], (label, output)
                record.update(caught_by="test", property=expected)
            record["failure"] = failures[0]
            records.append(record)
            print(f"{label}: EXIT={status}; {record['caught_by']}; {failures[0]}", flush=True)
        finally:
            path.write_bytes(original)
            assert path.read_bytes() == original
    status, _, output = run("restored-tests", None)
    assert status == 0, output
    assert path.read_bytes() == original
    (PACKAGE / "test-data/slip132-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"SLIP-132 mutations: {len(records)}/4 detected; restored lake test: EXIT=0")


if __name__ == "__main__":
    main()
