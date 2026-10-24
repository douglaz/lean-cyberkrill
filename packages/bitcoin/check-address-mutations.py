# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Twenty independent address production mutations; always restore the source.

Run in nix develop with python3 -I and no concurrent writers. Every lake test
is foreground; separate streams remain under .lake/address-mutation-checks.
The compact record pins a theorem diagnostic or a runtime assertion after the gate.
"""

import json
from pathlib import Path
import re
import subprocess


PACKAGE = Path(__file__).resolve().parent
SOURCE = PACKAGE / "Bitcoin/Address.lean"
LOGS = PACKAGE / ".lake/address-mutation-checks"


def replace_once(source, old, new):
    assert source.count(old) == 1, f"mutation target count: {old!r}"
    changed = source.replace(old, new)
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
    original = SOURCE.read_text()
    mutations = []

    def add(label, old, new, theorem=None, assertion=None):
        mutations.append((label, replace_once(original, old, new), theorem, assertion))

    add("p2pkh-template", "[0x76, 0xa9, 0x14] ++ hash.data.toList ++ [0x88, 0xac]",
        "[0x76, 0xa9, 0x14] ++ hash.data.toList ++ [0x89, 0xac]",
        theorem="fromScript_p2pkh")
    add("p2sh-template", "[0xa9, 0x14] ++ hash.data.toList ++ [0x87]",
        "[0xa9, 0x14] ++ hash.data.toList ++ [0x88]",
        theorem="fromScript_p2sh")
    add("witness-opcode", "UInt8.ofNat (0x50 + v)", "UInt8.ofNat (0x4f + v)",
        theorem="fromScript_witness")
    add("mainnet-base58-version", "else (if main then 0x00 else 0x6f)",
        "else (if main then 0x01 else 0x6f)", theorem="decodeLegacy_p2pkh")
    add("legacy-regtest-network", "if a.validFor net then", "if a.validFor net ∧ "
        "(net ≠ .regtest ∨ (match a with | .witness _ _ _ => true | _ => false) = true) then",
        theorem="p2pkh_string_roundtrip")
    add("regtest-hrp", '| .regtest => "bcrt"', '| .regtest => "tb"', theorem="decode_witness_encode")
    add("merge-mismatch", "else .error .networkMismatch", "else .error .unknownVersion",
        assertion="address network mismatch bc-on-testnet")
    add("unknown-hrp-mismatch", "| _ => .error Error.unknownHrp", "| _ => .error Error.networkMismatch",
        assertion="BIP350 segwit invalid tc1")
    add("allow-bech32-v1", "if variant ≠ witnessVariant v then",
        "if variant ≠ witnessVariant v ∧ v = 0 then", assertion="BIP173 v1+ rejected")
    add("allow-bech32m-v0", "if variant ≠ witnessVariant v then",
        "if variant ≠ witnessVariant v ∧ v ≠ 0 then", assertion="BIP350 segwit invalid bc1qw508")
    add("allow-high-version", "if v > 16 then", "if v > 16 ∧ False then",
        assertion="BIP350 segwit invalid BC130")
    add("allow-v1-program-length", "if ¬ validProgram v program then",
        "if ¬ validProgram v program ∧ v = 0 then", assertion="BIP350 segwit invalid bc1pw5")
    add("allow-v0-program-length", "if ¬ validProgram v program then",
        "if ¬ validProgram v program ∧ (v ≠ 0 ∨ program.size < 2 ∨ 40 < program.size) then",
        assertion="BIP350 segwit invalid BC1QR508")
    add("lax-padding", "(Bitcoin.Bech32.convertbits5to8 symbols).mapError Error.padding",
        "((match Bitcoin.Bech32.convertbits5to8 symbols with | .ok p => .ok p "
        "| .error _ => .ok (Bitcoin.Bech32.fesToBytesLax symbols)) : "
        "Except Bitcoin.Bech32.PaddingError ByteArray).mapError Error.padding",
        assertion="BIP350 segwit invalid bc1p0xlx")
    add("allow-empty-data", "let version :: symbols := data | .error .emptyData",
        "let version := data.headD (BitVec.ofNat 5 0)\n  let symbols := data.drop 1",
        assertion="BIP350 segwit invalid bc1gmk9yu")
    add("allow-long-base58-payload", "if payload.size ≠ 21 then .error .payloadLength else",
        "if payload.size ≠ 21 then\n"
        "    if payload.size > 21 then .ok (.p2pkh true (payload.extract 1 21))\n"
        "    else .error .payloadLength\n  else",
        assertion="Base58 address negatives version-0-body-21")
    add("allow-unknown-base58-version", "| _ => .error .unknownVersion",
        "| _ => .ok (.p2pkh true hash)", assertion="Base58 address negatives unknown-version")
    add("recognise-invalid-v0-script", "push.toNat = program.size ∧ validProgram version program then",
        "push.toNat = program.size ∧ (validProgram version program ∨ version = 0) then",
        assertion="address script negatives v0-length25")
    add("ignore-expected-network", "  requireNetwork net a", "  requireNetwork .mainnet a",
        theorem="decode_witness_encode")
    old = """      match decodeWitness hrp data variant with
      | .ok a => .ok a
      | .error .unknownHrp => .error .unknownHrp
      | .error reason =>
        match decodeLegacy text with
        | .ok a => .ok a
        | .error _ => .error reason"""
    new = """      if (hrp = "bc" ∨ hrp = "tb" ∨ hrp = "bcrt") ∧ hrp ≠ net.witness.hrp then
        .error .networkMismatch
      else
""" + "\n".join("  " + line for line in old.splitlines())
    add("premature-network-check", old, new, assertion="BIP173 v1+ rejected")
    assert len(mutations) == 20
    records = []
    for number, (label, changed, theorem, assertion) in enumerate(mutations, 1):
        assert SOURCE.read_text() == original
        try:
            SOURCE.write_text(changed)
            assert SOURCE.read_text() == changed
            record, output = run(label)
            record["property"] = number
            assert record["exit"] == 1, output
            if theorem:
                declarations = list(re.finditer(r"^(?:private )?(?:theorem|def|inductive) (\w+)",
                                                changed, re.MULTILINE))
                index = next(i for i, m in enumerate(declarations) if m[1] == theorem)
                start = changed[:declarations[index].start()].count("\n") + 1
                end = (changed[:declarations[index + 1].start()].count("\n") + 1
                       if index + 1 < len(declarations) else len(changed.splitlines()) + 1)
                locations = re.findall(r"error: Bitcoin/Address.lean:(\d+):\d+:", output)
                assert any(start <= int(line) < end for line in locations), output
                record["brokenTheorem"] = "Bitcoin.Address." + theorem
            else:
                assert "assertion failed: " + assertion in output, output
                gate = re.search(r"Bitcoin axiom gate: \d+ library theorems; 65 named; 0 offenders", output)
                assert gate, "axiom gate must pass before the runtime assertion\n" + output
                record["assertion"] = assertion
                record["axiomGatePassed"] = True
            records.append(record)
            print(json.dumps(record), flush=True)
        finally:
            SOURCE.write_text(original)
            assert SOURCE.read_text() == original
    record, output = run("restored-tests")
    assert record["exit"] == 0, output
    records.append(record)
    (PACKAGE / "test-data/address-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(json.dumps(record), flush=True)
    print("address mutations: 20/20 detected; production source restored")


if __name__ == "__main__":
    main()
