# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent Base58 production mutations, restored even on assertion failure.

Run python3 -I check-mutations.py first for the six existing properties, then
this script in nix develop. Every lake test runs in the foreground. Separate
streams remain in .lake/base58-mutation-checks; evidence is written to JSON.
"""

import json
from pathlib import Path
import re
import subprocess


PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/base58-mutation-checks"


def replace_once(data, old, new):
    assert data.count(old) == 1, f"mutation target count: {old!r}"
    changed = data.replace(old, new)
    assert new in changed and changed.count(old) == new.count(old)
    return changed


def run(label):
    with (LOGS / f"{label}.stdout").open("wb") as out, \
            (LOGS / f"{label}.stderr").open("wb") as err:
        result = subprocess.run(["lake", "test"], cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
    output = (LOGS / f"{label}.stdout").read_text() + (LOGS / f"{label}.stderr").read_text()
    failures = [line for line in output.splitlines()
                if "assertion failed:" in line or line.startswith("error:")]
    return dict(label=label, command=["lake", "test"], exit=result.returncode,
                failures=failures), output


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    base = PACKAGE / "Bitcoin/Base58.lean"
    check = PACKAGE / "Bitcoin/Base58Check.lean"
    originals = {p: p.read_text() for p in [base, check]}
    mutations = [
        ("drop-leading-zeros", base,
         replace_once(originals[base],
                      '(convert 58 (by decide) 256 (b.data.toList.map UInt8.toNat)).map charOf',
                      '(writeNumber 58 (by decide) 0 (readNumber 256 (b.data.toList.map UInt8.toNat))).map charOf'),
         "base58Decode_encode", None),
        ("admit-zero", base,
         replace_once(originals[base], 'let ds ← readChars s.toList',
                      "let ds ← readChars (s.toList.map fun c => if c = '0' then '1' else c)"),
         "base58Encode_of_decode", None),
        ("skip-checksum", check,
         replace_once(originals[check], 'if b = p ++ checksum p then', 'if True then'),
         "base58CheckDecode_sound", None),
        ("merge-errors", check,
         replace_once(originals[check], '.error .tooShort', '.error .checksumMismatch'),
         None, "assertion failed: Base58Check rejections short"),
        ("single-sha256", check,
         replace_once(replace_once(originals[check],
                                   'private def checksum (p : ByteArray) : ByteArray := (Sha256.sha256d p).extract 0 4',
                                   'private def checksum (p : ByteArray) : ByteArray := (Sha256.hash p).extract 0 4'),
                      'Sha256.sha256d_size', 'Sha256.hash_size'),
         "base58CheckDecode_sound", None),
        ("swapped-alphabet", base,
         replace_once(originals[base], '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
                      '123456789BACDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'),
         None, "assertion failed: base58 vectors"),
    ]
    records = []
    for label, path, changed, theorem, expected in mutations:
        assert all(p.read_text() == text for p, text in originals.items())
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            record, output = run(label)
            assert record["exit"] == 1, output
            if theorem:
                start = changed[:changed.index("theorem " + theorem)].count("\n") + 1
                after = changed.find("\n/--", changed.index("theorem " + theorem) + 1)
                end = changed[:after].count("\n") + 1 if after >= 0 else len(changed.splitlines())
                locations = re.findall(r"error: Bitcoin/[^:]+:(\d+):\d+:", output)
                assert any(start <= int(line) < end for line in locations), output
                record["brokenTheorem"] = "Bitcoin.Base58." + theorem
            else:
                assert expected in output, output
                assert "Bitcoin axiom gate:" in output, "proofs must check before vectors"
            records.append(record)
            print(json.dumps(record), flush=True)
        finally:
            path.write_text(originals[path])
            assert path.read_text() == originals[path]
    record, output = run("restored-tests")
    assert record["exit"] == 0, output
    records.append(record)
    print(json.dumps(record), flush=True)
    (PACKAGE / "test-data/base58-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print("base58 mutations: 6/6 detected; production sources restored")


if __name__ == "__main__":
    main()
