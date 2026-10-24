# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Check BIP39 production mutations sequentially, restoring exact source bytes."""
import json
from pathlib import Path
import re
import signal
import subprocess

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/bip39-mutation-checks"
LIBRARY = "Bitcoin/Bip39.lean"
WORDLIST = "Bitcoin/Bip39Wordlist.lean"
T1 = "mnemonicToEntropy_entropyToMnemonic"
T2 = "entropyToMnemonic_mnemonicToEntropy"
T3 = "mnemonicToEntropy_checksum_mismatch"


def replace(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    changed = text.replace(old, new)
    assert changed != text and new in changed
    return changed


def mutations(originals):
    cases = []

    def add(label, source, old, new, selection, expected):
        cases.append((label, source, replace(originals[source], old, new), selection, expected))

    add("skip-checksum", LIBRARY, "if n % 2 ^ cs = checksum e cs then", "if True then",
        "bad-checksum", "theorem:" + T3)
    add("checksum-length-plus-one", LIBRARY, "let cs := e.size / 4", "let cs := e.size / 4 + 1",
        "english", "theorem:" + T1)
    add("word-index-plus-one", LIBRARY,
        "(fun i => wordlist[i]!))\n  else .error .badEntropyLength",
        "(fun i => wordlist[(i + 1) % 2048]!))\n  else .error .badEntropyLength",
        "english", "theorem:" + T1)
    add("lookup-index-plus-one", LIBRARY,
        "if word = a then some 0 else", "if word = a then some 1 else",
        "english", "theorem:lookup_get")
    add("drop-word-count", LIBRARY, "if validWordCount ws.length then", "if True then",
        "bad-word-count", "theorem:" + T2)
    for label, selection, expected in [
            ("sorted-wordlist-file", "wordlist", "bip39 wordlist library equality"),
            ("sorted-wordlist-vectors", "english", "bip39 English vector 0 encode")]:
        add(label, WORDLIST, '  "abandon",', '  "abandom",', selection, expected)
    add("unknown-position-plus-one", LIBRARY,
        ".error (.unknownWord position)", ".error (.unknownWord (position + 1))",
        "unknown-word", "bip39 unknown-word case 0 position")
    add("drop-entropy-length", LIBRARY, "if validEntropyLength e.size then", "if True then",
        "bad-entropy-length", "bip39 bad-entropy-length case 0 rejected")
    assert len(cases) == 9
    return cases


def run(label, selection):
    command = ["lake", "test"] + (["--", "--bip39", selection] if selection else [])
    stdout, stderr = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    return result.returncode, command, stdout.read_text() + stderr.read_text()


def declaration_range(text, name):
    declaration = re.search(r"^(?:private )?theorem " + re.escape(name) + r"\b", text, re.M)
    assert declaration, name
    start = text[:declaration.start()].count("\n") + 1
    following = re.search(r"\n(?:private )?(?:theorem |def |end )", text[declaration.end():])
    end_offset = declaration.end() + following.start() if following else len(text)
    return start, text[:end_offset].count("\n") + 1


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {name: (PACKAGE / name).read_bytes() for name in (LIBRARY, WORDLIST)}
    texts = {name: content.decode() for name, content in originals.items()}
    cases = mutations(texts)
    records = []
    for label, source, changed, selection, expected in cases:
        assert all((PACKAGE / name).read_bytes() == data for name, data in originals.items())
        path = PACKAGE / source
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            status, command, output = run(label, selection)
            assert status == 1, (label, status, output)
            if expected.startswith("theorem:"):
                theorem = expected.split(":", 1)[1]
                start, end = declaration_range(texts[LIBRARY], theorem)
                diagnostic = re.compile(r"^error: " + re.escape(LIBRARY) + r":(\d+):")
                failures = [line for line in output.splitlines() if diagnostic.search(line) and
                            start <= int(diagnostic.search(line)[1]) <= end]
            else:
                assert re.search(r"Bitcoin axiom gate: \d+ library theorems; 65 named; 0 offenders", output), output
                failures = [line for line in output.splitlines()
                            if "assertion failed:" in line or line.startswith("error:")]
            assert failures, (label, expected, output)
            first = failures[0]
            record = dict(mutation=label, source=source, command=command, exit=status, failure=first)
            if expected.startswith("theorem:"):
                record.update(caught_by="theorem build", theorem_file=LIBRARY, theorem=theorem)
            else:
                assert "assertion failed: " + expected in first, (label, output)
                record.update(caught_by="test", property=expected)
            records.append(record)
            print(f"{label}: EXIT={status}; {record['caught_by']}; {first}", flush=True)
        finally:
            path.write_bytes(originals[source])
            assert path.read_bytes() == originals[source]
    status, _, output = run("restored-tests", None)
    assert status == 0, output
    assert all((PACKAGE / name).read_bytes() == data for name, data in originals.items())
    (PACKAGE / "test-data/bip39-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"BIP39 mutations: {len(records)}/9 detected; restored lake test: EXIT=0")


if __name__ == "__main__":
    main()
