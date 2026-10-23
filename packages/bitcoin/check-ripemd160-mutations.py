# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Check independent hash mutations; keep streams and records separate.

Use nix develop -c python3 -I check-ripemd160-mutations.py without concurrent
writers. Every test is foreground; sources are restored and byte-checked even
on failure. The PSBT skip/swap mutations live in check-psbt-mutations.py.
"""
import json
from pathlib import Path
import re
import subprocess

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/ripemd160-mutation-checks"


def replace(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    changed = text.replace(old, new)
    assert changed != text and new in changed
    return changed


def mutations(originals):
    cases = []

    def add(label, source, old, new, selection, expected):
        cases.append((label, source, replace(originals[source], old, new), selection, expected))

    library = "Bitcoin/Ripemd160.lean"
    tests = "BitcoinTests/Ripemd160.lean"
    psbt = "BitcoinTests/Psbt.lean"
    fixture = "test-data/ripemd160.json"
    add("round-constant", library, "0x5a827999", "0x5a827998",
        ["--hash", "vectors"], "RIPEMD-160 vectors 0 digest")
    rows = json.loads(originals[fixture])
    first = json.dumps(rows["vectors"][0], indent=2)
    first = "\n".join("    " + line for line in first.splitlines()) + ",\n"
    add("count-vectors", fixture, first, "", ["--hash", "vectors"], "RIPEMD-160 vectors count")
    add("count-bip173", tests, "[bip173PublicKey]", "[]",
        ["--hash", "bip173"], "HASH160 BIP173 count")
    for number, name in [(10, "ripemd160"), (12, "hash160")]:
        add("count-psbt-" + name, psbt,
            f"preimage {number} Bitcoin.{name} preimageHashes [true, false]",
            f"preimage {number} Bitcoin.{name} preimageHashes [true]",
            ["--psbt", "RIPEMD160 preimage" if number == 10 else "HASH160 preimage"],
            f"preimage {number} count")
    add("hash160-composition", library, "ripemd160 (Sha256.hash input)", "ripemd160 input",
        ["--hash", "bip173"], "HASH160 BIP173 digest")
    add("miswired-hashes", "Bitcoin/Psbt/Hashes.lean",
        "ripemd160 := Bitcoin.ripemd160\n  hash160 := Bitcoin.hash160",
        "ripemd160 := Bitcoin.hash160\n  hash160 := Bitcoin.ripemd160",
        ["--psbt", "RIPEMD160 preimage"], "preimage 10 accepted")
    # The 80-byte message is the first case whose length exceeds one block.
    add("length-padding", library, "let bits := input.size.toUInt64 * 8",
        "let bits := (input.size % 64).toUInt64 * 8",
        ["--hash", "vectors"], "RIPEMD-160 vectors 7 digest")
    return cases


def run(label, selection):
    command = ["lake", "test"] + (["--", *selection] if selection else [])
    stdout, stderr = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    return result.returncode, command, stdout.read_text() + stderr.read_text()


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    names = ["Bitcoin/Ripemd160.lean", "Bitcoin/Psbt/Hashes.lean", "BitcoinTests/Ripemd160.lean",
             "BitcoinTests/Psbt.lean", "test-data/ripemd160.json"]
    originals = {name: (PACKAGE / name).read_bytes() for name in names}
    cases = mutations({name: content.decode() for name, content in originals.items()})
    records = []
    for label, source, changed, selection, expected in cases:
        assert all((PACKAGE / name).read_bytes() == content for name, content in originals.items())
        path = PACKAGE / source
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            status, command, output = run(label, selection)
            assert status == 1, (label, status, output)
            assert re.search(r"Bitcoin axiom gate: \d+ library theorems; 60 named; 0 offenders", output), output
            failures = [line for line in output.splitlines()
                        if "assertion failed:" in line or line.startswith("error:")]
            assert failures and "assertion failed: " + expected in failures[0], (label, output)
            records.append(dict(property=expected, mutation=label, source=source,
                                command=command, exit=status, failure=failures[0]))
            print(f"{label}: EXIT={status}; {failures[0]}", flush=True)
        finally:
            path.write_bytes(originals[source])
            assert path.read_bytes() == originals[source]
    status, _, output = run("restored-tests", None)
    assert status == 0, output
    assert all((PACKAGE / name).read_bytes() == content for name, content in originals.items())
    (PACKAGE / "test-data/ripemd160-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"RIPEMD-160 mutations: {len(records)}/{len(cases)} detected; restored lake test: EXIT=0")


if __name__ == "__main__":
    main()
