# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Validate the parsed CI step and both key-shaped greps in a disposable copy.

Run with a Python environment containing PyYAML after building BitcoinTests.
The temporary copy is outside the repository; only synthetic text is planted.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import yaml

PACKAGE = Path(__file__).resolve().parent
REPO = PACKAGE.parent.parent
CI_COMMAND = "rc=0; grep -rEn --exclude-dir=.lake '[tx]prv[1-9A-HJ-NP-Za-km-z]{100,}' packages || rc=$?; test \"$rc\" -eq 1"
LOGS = PACKAGE / ".lake/key-material-checks"


def run(label, command, directory):
    out, err = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run(command, cwd=directory, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
    return result.returncode, out.read_text(), err.read_text()


def main():
    workflow = yaml.safe_load((REPO / ".github/workflows/ci.yml").read_text())
    step = next(step for step in workflow["jobs"]["check"]["steps"]
                if step.get("name") == "No extended private key material")
    assert step["run"] == CI_COMMAND
    print(f"PyYAML {yaml.__version__}: workflow parses; CI run string matches exactly")
    LOGS.mkdir(parents=True, exist_ok=True)
    records = []
    root = Path(tempfile.mkdtemp(prefix="psbt-key-grep-", dir=os.environ["TMPDIR"]))
    try:
        shutil.copytree(REPO / "packages", root / "packages", ignore=shutil.ignore_patterns(".lake", "__pycache__"))
        planted = root / "packages/bitcoin/synthetic-key-shape.txt"
        planted.write_text("t" + "prv" + "z" * 110 + "\n")
        status, out, err = run("ci-planted", ["bash", "-e", "-c", CI_COMMAND], root)
        assert status == 1 and "packages/bitcoin/synthetic-key-shape.txt:1:" in out and not err
        records.append(dict(property="CI key-shaped grep", command=["bash", "-e", "-c", CI_COMMAND],
                            exit=status, failure="packages/bitcoin/synthetic-key-shape.txt:1: <synthetic planted line>"))
        binary = PACKAGE / ".lake/build/bin/BitcoinTests"
        status, out, err = run("lake-planted", [str(binary)], root / "packages/bitcoin")
        assert status == 1 and "assertion failed: key-shaped grep: exit 0" in err
        assert "../bitcoin/synthetic-key-shape.txt:1:" in err
        records.append(dict(property="bitcoin test key-shaped grep", command=["BitcoinTests"],
                            exit=status, failure="assertion failed: key-shaped grep: exit 0; ../bitcoin/synthetic-key-shape.txt:1: <synthetic planted line>"))
        planted.unlink()
        status, out, err = run("ci-restored", ["bash", "-e", "-c", CI_COMMAND], root)
        assert status == 0 and not out and not err
        records.append(dict(property="restored CI scan", command=["bash", "-e", "-c", CI_COMMAND], exit=status))
        (root / "packages").rename(root / "saved-packages")
        try:
            status, out, err = run("ci-missing-path", ["bash", "-e", "-c", CI_COMMAND], root)
            assert status == 1 and not out and "packages" in err
            records.append(dict(property="CI rejects grep errors", command=["bash", "-e", "-c", CI_COMMAND],
                                exit=status, failure="grep: packages: No such file or directory"))
        finally:
            (root / "saved-packages").rename(root / "packages")
    finally:
        # This exact directory was created above; no pre-existing path is removed.
        shutil.rmtree(root)
        assert not root.exists()
    (PACKAGE / "test-data/key-material-mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    for record in records:
        print(f"{record['property']}: EXIT={record['exit']}; {record.get('failure', 'no matches')}")
    print("disposable key-grep copy removed")


if __name__ == "__main__":
    main()
