# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Run eighteen independent production mutations and restore sources in finally.

Run in nix develop. Each lake test is foreground, with separate streams under
.lake/bech32-mutation-checks. Records distinguish proof failures from assertions
that run after the axiom gate. Private helper theorems count when they pin the
mutated property. No test expectations or proof statements are changed.
"""

import json
from pathlib import Path
import re
import subprocess


PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/bech32-mutation-checks"


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
    core = PACKAGE / "Bitcoin/Bech32.lean"
    codec = PACKAGE / "Bitcoin/Bech32Codec.lean"
    bits = PACKAGE / "Bitcoin/ConvertBits.lean"
    originals = {p: p.read_text() for p in [core, codec, bits]}
    mutations = []

    def add(label, path, old, new, theorem=None, assertion=None):
        mutations.append((label, path, replace_once(originals[path], old, new), theorem, assertion))

    add("first-separator", codec, "match splitLast cs with",
        "match (if c = '1' then none else splitLast cs) with", theorem="splitLast_append")
    add("skip-checksum", codec, "if verifyChecksum .bech32 h ds then", "if true then",
        theorem="decode_sound")
    swapped = replace_once(originals[codec], ".ok (h, data, .bech32)", ".ok (h, data, .bech32m)")
    swapped = replace_once(swapped, "else if verifyChecksum .bech32m h ds then .ok (h, data, .bech32m)",
                           "else if verifyChecksum .bech32m h ds then .ok (h, data, .bech32)")
    mutations.append(("swapped-variants", codec, swapped, "decode_sound", None))
    add("one-padding", bits, "bits.getD i.val false", "bits.getD i.val true", theorem="write_read")
    add("emit-lax-trailing-byte", bits,
        "((unpack 8 (by decide) ((symbols.map writeBits).flatten)).map UInt8.ofBitVec).toArray",
        "((pack 8 (by decide) ((symbols.map writeBits).flatten)).map UInt8.ofBitVec).toArray",
        theorem="fesToBytesLax_convertbits8to5")
    add("bech32m-constant", core, "| .bech32m => 0x2bc830a3", "| .bech32m => 0x2bc830a2",
        assertion="assertion failed: BIP350 bech32m valid")
    add("generator-constant", core, "0x3b6a57b2,", "0x3b6a57b3,",
        assertion="assertion failed: BIP173 bech32 valid")
    add("charset-order", codec, "qpzry9x8gf2tvdw0s3jn54khce6mua7l", "pqzry9x8gf2tvdw0s3jn54khce6mua7l",
        assertion="assertion failed: BIP173 bech32 valid")
    add("hrp-expansion-zero", core, "hrp.toList.map (fun c => c.toNat >>> 5) ++ [0] ++",
        "hrp.toList.map (fun c => c.toNat >>> 5) ++",
        assertion="assertion failed: BIP173 bech32 valid")
    add("allow-mixed-case", codec,
        "else if s.toList.any Char.isUpper && s.toList.any Char.isLower then",
        "else if s.toList.any Char.isUpper && false && s.toList.any Char.isLower then",
        assertion="assertion failed: bech32 mixed case A12uel5l")
    add("allow-hrp-range", codec, "else if !hrp.all validHrpChar then",
        "else if !hrp.all validHrpChar && false then",
        assertion="assertion failed: BIP173 bech32 invalid")
    add("allow-empty-hrp", codec, "if hrp = [] then", "if hrp = [] ∧ False then",
        assertion="assertion failed: BIP173 bech32 invalid 1pzry9x0s0muk")
    add("ignore-length-limit", codec, "if s.length > limit then", "if s.length > limit ∧ False then",
        assertion="assertion failed: BIP173 bech32 invalid an84")
    add("allow-short-checksum", codec, "if ds.length < 6 then", "if ds.length < 6 ∧ False then",
        theorem="decode_sound")
    add("truncate-data-char", codec, "find? fun symbol => charOf symbol == c",
        "find? fun symbol => charOf symbol == Char.ofNat (c.toNat % 256)", theorem="charOf_readChar")
    add("allow-nonzero-padding", bits,
        "else if (bits.drop (bits.length / 8 * 8)).any id then",
        "else if (bits.drop (bits.length / 8 * 8)).any id && false then",
        assertion="assertion failed: bech32 convertbits nonzero-padding-only")
    add("allow-excess-padding", bits, "if bits.length % 8 ≥ 5 then",
        "if bits.length % 8 ≥ 5 ∧ False then",
        assertion="assertion failed: bech32 convertbits excess-padding-only")
    add("merge-errors", codec, "then .error .emptyHrp", "then .error .missingSeparator",
        assertion="assertion failed: BIP173 bech32 invalid 1pzry9x0s0muk")
    assert len(mutations) == 18

    records = []
    for label, path, changed, theorem, assertion in mutations:
        assert all(p.read_text() == text for p, text in originals.items())
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            record, output = run(label)
            assert record["exit"] == 1, output
            if theorem:
                declarations = list(re.finditer(r"^(?:private )?(?:theorem|def|inductive) (\w+)",
                                                changed, re.MULTILINE))
                index = next(i for i, m in enumerate(declarations) if m[1] == theorem)
                start = changed[:declarations[index].start()].count("\n") + 1
                end = (changed[:declarations[index + 1].start()].count("\n") + 1
                       if index + 1 < len(declarations) else len(changed.splitlines()) + 1)
                locations = re.findall(r"error: " + re.escape(str(path.relative_to(PACKAGE))) +
                                       r":(\d+):\d+:", output)
                assert any(start <= int(line) < end for line in locations), output
                record["brokenTheorem"] = "Bitcoin.Bech32." + theorem
            else:
                assert assertion in output, output
                assert "Bitcoin axiom gate:" in output and "34 named; 0 offenders" in output
                record["assertion"] = assertion.removeprefix("assertion failed: ")
                record["axiomGatePassed"] = True
            records.append(record)
            print(json.dumps(record), flush=True)
        finally:
            path.write_text(originals[path])
            assert path.read_text() == originals[path]
    record, output = run("restored-tests")
    assert record["exit"] == 0, output
    records.append(record)
    print(json.dumps(record), flush=True)
    (PACKAGE / "test-data/bech32-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print("bech32 mutations: 18/18 detected; production sources restored")


if __name__ == "__main__":
    main()
