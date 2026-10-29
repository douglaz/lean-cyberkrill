#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Immutable original typed-help failures, separate from current mutations."""
import hashlib
import importlib
import json
import subprocess
import sys
import time

from cases import APP, ROOT


def hashes():
    return {name:hashlib.sha256((APP/name).read_bytes()).hexdigest() for name in [
        "Cyberkrill/App.lean", "test/carried-help.py", "test/carried-regressions.py",
        "test/offline-inputs.py", "test/golden/offline-reference.json"]}


def main():
    mode, = sys.argv[1:]
    assert mode in ["before", "after", "current", "--verify"]
    destination = APP/"test/golden/carried-regression.json"
    rows = importlib.import_module("offline-inputs").carried_help_cases()
    if mode == "--verify":
        record = json.loads(destination.read_bytes())
        assert record["current"]["source_sha256"] == hashes(), "stale current carried regressions"
        assert len(record["current"]["checks"]) == 32 and all(r["status"] == 0 for r in record["current"]["checks"])
        assert len(record["before"]["checks"]) == len(record["after"]["checks"]) == len(rows) == 32
        for row, red, green in zip(rows,record["before"]["checks"],record["after"]["checks"]):
            assert red["case"] == green["case"] == row["id"] and red["command"] == green["command"]
            failing = not row.get("help") and row["id"] != "carried-help/words-missing-help"
            assert red["status"] == int(failing) and green["status"] == 0
            assert red["failure"] == ("AssertionError: carried help preceding typed error: " + row["id"] if failing else "")
        assert record["before"]["source_sha256"]["Cyberkrill/App.lean"] != record["after"]["source_sha256"]["Cyberkrill/App.lean"]
        print("carried regressions: 17 original named runtime failures, 15 controls, 32 restored greens")
        return
    logs = APP/".lake/carried-regressions"; logs.mkdir(exist_ok=True)
    checks = []
    for index,row in enumerate(rows):
        command = ["timeout", "--foreground", "30", "python3", "-B", "packages/cyberkrill/test/carried-help.py", row["id"]]
        start = time.monotonic()
        p = subprocess.run(command,cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,timeout=35)
        streams = {}
        for stream in ["stdout", "stderr"]:
            value = getattr(p,stream)
            (logs/f"{mode}-{index}.{stream}").write_bytes(value)
            streams[stream+"_sha256"] = hashlib.sha256(value).hexdigest()
        (logs/f"{mode}-{index}.status").write_text(str(p.returncode)+"\n")
        expected = int(mode == "before" and not row.get("help") and row["id"] != "carried-help/words-missing-help")
        failure = next((line for line in p.stderr.decode().splitlines() if line.startswith("AssertionError:")), "")
        assert p.returncode == expected, "carried regression status: "+row["id"]+": "+p.stderr.decode()
        assert failure == ("AssertionError: carried help preceding typed error: " + row["id"] if expected else ""), failure
        checks.append(dict(command=command,case=row["id"],status=p.returncode,seconds=round(time.monotonic()-start,6),failure=failure,**streams))
    record = {} if mode == "before" else json.loads(destination.read_bytes())
    assert mode not in record, "original observations are immutable"
    record[mode] = dict(source_sha256=hashes(),checks=checks)
    destination.write_text(json.dumps(record,indent=2)+"\n")
    print(f"carried regressions {mode}: {len(checks)} checks, {sum(r['status'] for r in checks)} runtime failures")


if __name__ == "__main__": main()
