#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Preserve original short-cluster failures and independent passing controls."""
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import time

from cases import APP, ROOT


def hashes():
    return {name:hashlib.sha256((APP/name).read_bytes()).hexdigest() for name in [
        "Cyberkrill/App.lean", "test/cluster-help.py", "test/cluster-regressions.py",
        "test/offline-inputs.py", "test/golden/offline-reference.json"]}


def main():
    mode, = sys.argv[1:]
    assert mode in ["before", "after", "--verify"]
    destination = APP/"test/golden/cluster-regression.json"
    rows = importlib.import_module("offline-inputs").cluster_help_cases()
    if mode == "--verify":
        record = json.loads(destination.read_bytes())
        # Preserve original observations. Current parser reintroductions are
        # executed and bound separately by offline-mutate.py.
        assert hashlib.sha256(destination.read_bytes()).hexdigest() == "3d7e617eb178812f022c16ac4f81025a59c2b687e860262e50f96cb044503c40", "historical cluster observations unchanged"
        for key in record["before"]["source_sha256"]:
            if key != "Cyberkrill/App.lean":
                assert record["before"]["source_sha256"][key] == record["after"]["source_sha256"][key]
        assert record["before"]["source_sha256"]["Cyberkrill/App.lean"] != record["after"]["source_sha256"]["Cyberkrill/App.lean"]
        assert len(record["before"]["checks"]) == len(record["after"]["checks"]) == len(rows) == 102
        for row, red, green in zip(rows,record["before"]["checks"],record["after"]["checks"]):
            assert red["case"] == green["case"] == row["id"] and red["command"] == green["command"]
            assert red["status"] == (1 if row.get("help") else 0) and green["status"] == 0
            if row.get("help"): assert red["failure"] == "AssertionError: cluster help short circuit: " + row["id"]
            else: assert red["failure"] == ""
        print("historical cluster regressions: 44 original named runtime failures, 58 controls, 102 former greens; current reintroductions recorded separately")
        return
    logs = APP/".lake/cluster-regressions"; logs.mkdir(exist_ok=True)
    checks = []
    for index,row in enumerate(rows):
        command = ["timeout", "--foreground", "30", "python3", "-B", "packages/cyberkrill/test/cluster-help.py", row["id"]]
        start = time.monotonic()
        p = subprocess.run(command,cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,timeout=35)
        elapsed = round(time.monotonic()-start,6)
        streams = {}
        for stream in ["stdout", "stderr"]:
            value = getattr(p,stream)
            (logs/f"{mode}-{index}.{stream}").write_bytes(value)
            streams[stream+"_sha256"] = hashlib.sha256(value).hexdigest()
        (logs/f"{mode}-{index}.status").write_text(str(p.returncode)+"\n")
        expected = 1 if mode == "before" and row.get("help") else 0
        assert p.returncode == expected, "cluster regression status: "+row["id"]+": "+p.stderr.decode()
        failure = next((line for line in p.stderr.decode().splitlines() if line.startswith("AssertionError:")), "")
        if expected: assert failure == "AssertionError: cluster help short circuit: " + row["id"]
        checks.append(dict(command=command,case=row["id"],status=p.returncode,seconds=elapsed,failure=failure,**streams))
    record = {} if mode == "before" else json.loads(destination.read_bytes())
    assert mode not in record, "original observations are immutable"
    record[mode] = dict(source_sha256=hashes(),checks=checks)
    destination.write_text(json.dumps(record,indent=2)+"\n")
    print(f"cluster regressions {mode}: {len(checks)} checks, {sum(r['status'] for r in checks)} runtime failures")


if __name__ == "__main__": main()
