# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Run inside nix develop, with no concurrent writers; restore every mutation.

Commands run in the foreground. Separate stdout/stderr and exit codes are
retained under .lake/mutation-checks. Only production declarations are mutated.
"""

import json
from pathlib import Path
import subprocess
import tempfile


PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent.parent
RECORDS = PACKAGE / ".lake/mutation-checks"
CI_COMMAND = ('rc=0; grep -rnw sorry --include=\'*.lean\' --exclude-dir=.lake packages '
              '|| rc=$?; test "$rc" -eq 1')


def run(label, command, cwd=PACKAGE):
    with (RECORDS / f"{label}.stdout").open("wb") as out, \
            (RECORDS / f"{label}.stderr").open("wb") as err:
        result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
    stdout = (RECORDS / f"{label}.stdout").read_text()
    stderr = (RECORDS / f"{label}.stderr").read_text()
    record = dict(label=label, command=command, cwd=str(cwd), exit=result.returncode,
                  failures=[line for line in (stdout + stderr).splitlines()
                            if "assertion failed:" in line or "disallowed axiom" in line])
    print(json.dumps(record), flush=True)
    return record, stdout + stderr


def replace_once(data, old, new):
    assert data.count(old) == 1, f"mutation target count: {old!r}"
    result = data.replace(old, new)
    assert new in result and old not in result
    return result


def main():
    RECORDS.mkdir(parents=True, exist_ok=True)
    records = []
    paths = [PACKAGE / "Sha256/Spec.lean", PACKAGE / "Sha256/Fast.lean"]
    originals = {path: path.read_bytes() for path in paths}
    try:
        for path, data in originals.items():
            path.write_bytes(replace_once(data, b"0x428a2f98", b"0x428a2f99"))
        record, output = run("round-constant", ["lake", "test"])
        records.append(record)
        assert record["exit"] == 1
        assert "SHA-256 axiom gate:" in output, "proofs must check before vectors run"
        for group, label in [("FIPS examples", "abc"), ("CAVP ShortMsg", "Len=0"),
                             ("CAVP LongMsg", "Len=1304"), ("SHA-256d", "genesis")]:
            assert f"assertion failed: {group} {label} digest" in output
    finally:
        for path, data in originals.items():
            path.write_bytes(data)
            assert path.read_bytes() == data

    spec = paths[0]
    old = (b"@[simp] theorem length_bitsOfNat (k n : Nat) : (bitsOfNat k n).length = k := by\n"
           b"  induction k with\n  | zero => rfl\n"
           b"  | succ k ih => simp only [bitsOfNat, List.length_cons, ih]")
    new = (b"axiom auditProbe (k n : Nat) : (bitsOfNat k n).length = k\n\n"
           b"@[simp] theorem length_bitsOfNat (k n : Nat) : (bitsOfNat k n).length = k :=\n"
           b"  auditProbe k n")
    try:
        spec.write_bytes(replace_once(originals[spec], old, new))
        record, output = run("axiom", ["lake", "test"])
        records.append(record)
        assert record["exit"] == 1
        assert ("SHA-256 axiom gate: Sha256.sha256_spec reaches disallowed axiom "
                "Sha256.Spec.auditProbe") in output
    finally:
        spec.write_bytes(originals[spec])
        assert spec.read_bytes() == originals[spec]

    command = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", CI_COMMAND]
    record, _ = run("ci-clean", command, ROOT)
    records.append(record)
    assert record["exit"] == 0
    with tempfile.NamedTemporaryFile(mode="w", prefix="Sha256CiProbe-", suffix=".lean",
                                     dir=PACKAGE, delete=False) as probe:
        probe_path = Path(probe.name)
        probe.write("/-\nCopyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the\n"
                    "Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.\n-/\n"
                    "-- sorry\n")
    try:
        record, output = run("ci-placeholder", command, ROOT)
        records.append(record)
        assert record["exit"] == 1 and probe_path.name in output
    finally:
        probe_path.unlink()
    record, _ = run("ci-restored", command, ROOT)
    records.append(record)
    assert record["exit"] == 0
    record, _ = run("restored-tests", ["lake", "test"])
    records.append(record)
    assert record["exit"] == 0
    (RECORDS / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    print("negative mutations: 3/3 detected; production sources restored")


if __name__ == "__main__":
    main()
