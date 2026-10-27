#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Record separate bounded regression runs before and after production fixes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from cases import APP
from regressions import CHECKS


def fingerprint(paths):
    return {p: hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in paths}


def main():
    mode, = sys.argv[1:]
    assert mode in ["before", "after"]
    os.chdir(APP)
    logs = APP / ".lake/regressions"
    logs.mkdir(parents=True, exist_ok=True)
    record_path = APP / "test/golden/regression-record.json"
    record = {} if mode == "before" else json.loads(record_path.read_text())
    tests = fingerprint(["test/regressions.py", "test/record-regressions.py",
                         "CyberkrillTests/Mnemonic.lean", "CyberkrillTests.lean"])
    if mode == "after":
        assert record["before"]["tests_sha256"] == tests, "regression tests changed after red runs"
    rows = []
    assertions = ["word-count rejection before entropy", "mnemonic exact status 0",
                  "bare negative-zero refused 0", "", "subprocess stdout CRLF preserved",
                  "subprocess stdout CR preserved", "subprocess stderr CRLF preserved",
                  "subprocess stderr CR preserved", "dotted leaf collision refused",
                  "bracket leaf collision refused"]
    assert len(CHECKS) == len(assertions) == 10
    for (name, _), assertion in zip(CHECKS.items(), assertions):
        command = ["timeout", "--foreground", "60", "python3", "-B", "test/regressions.py", name]
        start = time.monotonic()
        p = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=70)
        elapsed = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            (logs / f"{mode}-{name}.{stream}").write_bytes(getattr(p, stream))
        (logs / f"{mode}-{name}.status").write_text(str(p.returncode) + "\n")
        expected = 1 if mode == "before" and assertion else 0
        assert p.returncode == expected, f"regression {mode} {name}: unexpected exit {p.returncode}"
        if expected:
            assert assertion in p.stderr.decode() and "AssertionError:" in p.stderr.decode(), f"regression wrong assertion: {name}"
        rows.append(dict(property=name, command=command, status=p.returncode, seconds=elapsed,
                         detecting_assertion=assertion if expected else ""))
        print(f"{mode} {name}: exit {p.returncode}" + (f" ({assertion})" if expected else ""), flush=True)
    record[mode] = dict(tests_sha256=tests, source_sha256=fingerprint([
        "Cyberkrill/App.lean", "test/driver.py", "test/compare.py"]), checks=rows)
    record_path.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
