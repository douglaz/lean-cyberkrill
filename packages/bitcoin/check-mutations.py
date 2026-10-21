# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Six independent production mutations; foreground runs, always restored.

Run from nix develop with no concurrent writers. Stdout and stderr stay separate
under .lake/mutation-checks; the compact evidence is in test-data/mutations.json.
"""

import json
from pathlib import Path
import re
import subprocess


PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/mutation-checks"


def replace_once(data, old, new):
    assert data.count(old) == 1, f"mutation target count: {old!r}"
    result = data.replace(old, new)
    assert new in result and result.count(old) == new.count(old)
    return result


def run(label):
    with (LOGS / f"{label}.stdout").open("wb") as out, \
            (LOGS / f"{label}.stderr").open("wb") as err:
        result = subprocess.run(["lake", "test"], cwd=PACKAGE, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
    output = (LOGS / f"{label}.stdout").read_text() + (LOGS / f"{label}.stderr").read_text()
    lines = [line for line in output.splitlines()
             if "assertion failed:" in line or "disallowed axiom" in line or line.startswith("error:")]
    record = dict(label=label, command=["lake", "test"], exit=result.returncode, failures=lines)
    return record, output


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    compact = PACKAGE / "Bitcoin/CompactSize.lean"
    hexf = PACKAGE / "Bitcoin/Hex.lean"
    amount = PACKAGE / "Bitcoin/Amount.lean"
    cli = PACKAGE / "Bitcoin/AmountCli.lean"
    originals = {p: p.read_text() for p in [compact, hexf, amount, cli]}
    mutations = [
        ("canonical-minimum", compact,
         replace_once(originals[compact], "if decodeLE bytes < minimum then",
                      "if decodeLE bytes < minimum && false then"),
         "readCompactSize_ok"),
        ("uppercase-hex", hexf,
         replace_once(originals[hexf].split("theorem decode_encode", 1)[0],
                      "(s.toList.map Char.toLower)", "s.toList") +
         "theorem decode_encode (bytes : ByteArray) : decode (encode bytes) = some bytes := by\n"
         "  simpa [decode, encode, String.toList_ofList] using Sha256.Hex.decodeChars?_encodeChars bytes\n\n"
         "end Bitcoin.Hex\n",
         "assertion failed: hex upper"),
        ("sub-msat-rounding", amount,
         replace_once(originals[amount],
                      "if numerator % denominator = 0 then some ⟨numerator / denominator⟩ else none",
                      "if numerator % denominator = 0 then some ⟨numerator / denominator⟩ "
                      "else some ⟨(numerator + denominator / 2) / denominator⟩"),
         "ofDecimal_iff"),
        ("suffix-order", cli,
         replace_once(originals[cli],
                      'else if s.endsWith "msats" then',
                      'else if s.endsWith "sat" then parseSigned (stripSuffix s "sat") 3\n'
                      '  else if s.endsWith "msats" then'),
         "assertion failed: CLI grammar suffix-msat"),
        ("cli-u64-bound", cli,
         replace_once(originals[cli], "if a.msat ≤ 18446744073709551615 then",
                      "if a.msat ≤ 18446744073709551615 || true then"),
         "assertion failed: CLI grammar cli-msat-overflow"),
        ("axiom", amount,
         replace_once(originals[amount],
                      "theorem ofSats_msat (n : Nat) : (ofSats n).msat = 1000 * n := rfl",
                      "axiom auditProbe (n : Nat) : (ofSats n).msat = 1000 * n\n\n"
                      "theorem ofSats_msat (n : Nat) : (ofSats n).msat = 1000 * n := auditProbe n"),
         "reaches disallowed axiom Bitcoin.Amount.auditProbe"),
    ]
    records = []
    for label, path, changed, expected in mutations:
        assert all(p.read_text() == s for p, s in originals.items())
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            record, output = run(label)
            assert record["exit"] == 1, output
            if label in ["canonical-minimum", "sub-msat-rounding"]:
                # Require an actual diagnostic inside the theorem that pins the
                # broken property, rather than an unrelated compilation error.
                start = changed[:changed.index("theorem " + expected)].count("\n") + 1
                after = changed.find("\ntheorem ", changed.index("theorem " + expected) + 1)
                end = changed[:after].count("\n") + 1 if after >= 0 else len(changed.splitlines())
                locations = re.findall(r"error: Bitcoin/[^:]+:(\d+):\d+:", output)
                assert any(start <= int(line) < end for line in locations), output
                record["brokenTheorem"] = "Bitcoin." + ("CompactSize." if path == compact else "Amount.") + expected
            else:
                assert expected in output, output
                if label != "axiom":
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
    (PACKAGE / "test-data/mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print("negative mutations: 6/6 detected; production sources restored")


if __name__ == "__main__":
    main()
