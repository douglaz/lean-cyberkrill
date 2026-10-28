#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Record literal short-attached equals paths through injected production dispatch."""
import hashlib
import json
import os
import subprocess
import sys
import time

from cases import APP

CASES = ["-o-name=a", "-ofoo=bar", "-oordinary=name", "-o-name=a=b",
         "-o=-name=a", "--output=-name=a", "-o=foo=bar=baz", "--output=foo=bar=baz"]
FILES = ["CyberkrillTests/Output.lean", "CyberkrillTests/Support.lean", "CyberkrillTests.lean",
         "test/attached-output-regressions.py"]


def fingerprints(paths):
    return {p: hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in paths}


def main():
    mode, = sys.argv[1:]
    assert mode in ["before", "after"]
    os.chdir(APP)
    logs = APP / ".lake/attached-output-regressions"
    logs.mkdir(parents=True, exist_ok=True)
    path = APP / "test/golden/attached-output-regression-record.json"
    record = {} if mode == "before" else json.loads(path.read_text())
    tests = fingerprints(FILES)
    if mode == "after":
        assert record["before"]["tests_sha256"] == tests, "attached output tests changed after reds"
    rows = []
    assert len(CASES) == 8
    print("attached equals output cases: 8/8 (four regressions, four controls)", flush=True)
    for i, token in enumerate(CASES):
        command = ["timeout", "--foreground", "30", ".lake/build/bin/CyberkrillTests", "--output-equals", str(i)]
        start = time.monotonic()
        p = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
        elapsed = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            (logs / f"{mode}-{i}.{stream}").write_bytes(getattr(p, stream))
        (logs / f"{mode}-{i}.status").write_text(str(p.returncode) + "\n")
        expected = 1 if mode == "before" and i < 4 else 0
        assertion = f"output equals {i} status" if expected else ""
        assert p.returncode == expected, f"attached output {mode} {i}: unexpected exit {p.returncode}"
        assert p.stderr.decode() == (f"assertion failed: {assertion}\n" if expected else ""), f"attached output assertion {i}"
        rows.append(dict(case=i, token=token, command=command, status=p.returncode,
                         seconds=elapsed, detecting_assertion=assertion))
        print(f"{mode} attached output {i}: exit {p.returncode}" + (f" ({assertion})" if expected else ""), flush=True)
    record[mode] = dict(tests_sha256=tests, source_sha256=fingerprints(["Cyberkrill/App.lean"]), checks=rows)
    path.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
