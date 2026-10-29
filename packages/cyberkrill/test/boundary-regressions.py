#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Record unfixed runtime failures separately from restored final checks."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

from cases import APP, ROOT


def cases():
    rows = []
    for command in ["fm-decode-invite", "fm-encode-invite", "onchain-decode-psbt"]:
        for name in ["help-unknown", "help-missing-output", "short-help-unknown"]:
            rows.append(("ordered-help.py", f"ordered-help/{command}/{name}", 1, "ordered help short circuit"))
        rows.append(("ordered-help.py", f"ordered-help/{command}/unknown-help", 0, ""))
    rows.append(("ordered-help.py", "ordered-help/onchain-decode-psbt/help-missing-network", 1, "ordered help short circuit"))
    for command in ["fm-encode-invite", "onchain-decode-psbt"]:
        for name in ["crlf", "cr"]:
            rows.append(("file-observation.py", command+"/"+name, 1, "file comparator accepted newline/field"))
        rows.append(("file-observation.py", command+"/control", 0, ""))
    rows.append(("file-observation.py", "fm-decode-invite/control", 0, ""))
    assert len(rows) == 20 and sum(r[2] for r in rows) == 14
    return rows


def hashes(names):
    return {name:hashlib.sha256((APP/name).read_bytes()).hexdigest() for name in names}


def main():
    mode, = sys.argv[1:]
    assert mode in ["before", "after", "--verify"]
    destination = APP/"test/golden/ordered-boundary-regression.json"
    tests = ["test/ordered-help.py", "test/file-observation.py", "test/boundary-regressions.py"]
    production = ["Cyberkrill/App.lean", "test/capture-offline.py", "test/offline-compare.py"]
    if mode == "--verify":
        record = json.loads(destination.read_bytes())
        # Fixed original observations; current production reintroductions live
        # in offline-mutation-record.json after later parser/observer changes.
        assert hashlib.sha256(destination.read_bytes()).hexdigest() == "16140c1064bb09c8ed968c1107b3bade752a9f8fc2af14e155beced7d43cfbae"
        assert record["before"]["tests_sha256"] == record["after"]["tests_sha256"]
        for red, green, (script, case, status, assertion) in zip(record["before"]["checks"], record["after"]["checks"], cases()):
            assert red["case"] == green["case"] == case and red["command"] == green["command"]
            assert red["status"] == status and green["status"] == 0
            assert not status or (assertion in red["failure"] and "AssertionError:" in red["failure"])
        assert len(record["before"]["checks"]) == len(record["after"]["checks"]) == 20
        print("historical ordered/file regressions: 14 original runtime failures, 6 controls, 20 former greens; current reintroductions recorded separately")
        return
    logs = APP/".lake/ordered-boundary-regressions"; logs.mkdir(exist_ok=True)
    checks = []
    for index,(script,case,status,assertion) in enumerate(cases()):
        command = ["timeout", "--foreground", "30", "python3", "-B", "packages/cyberkrill/test/"+script, case]
        start = time.monotonic()
        p = subprocess.run(command,cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,timeout=35)
        for stream in ["stdout", "stderr"]: (logs/f"{mode}-{index}.{stream}").write_bytes(getattr(p,stream))
        (logs/f"{mode}-{index}.status").write_text(str(p.returncode)+"\n")
        assert p.returncode == (status if mode == "before" else 0), "boundary regression status: "+case+": "+p.stderr.decode()
        failure = next((line for line in p.stderr.decode().splitlines() if line.startswith("AssertionError:")), "")
        assert mode != "before" or not status or assertion in failure, "named before-fix failure: "+case
        checks.append(dict(command=command,case=case,status=p.returncode,seconds=round(time.monotonic()-start,6),failure=failure))
    record = {} if mode == "before" else json.loads(destination.read_bytes())
    assert mode not in record
    record[mode] = dict(tests_sha256=hashes(tests),source_sha256=hashes(production),checks=checks)
    destination.write_text(json.dumps(record,indent=2)+"\n")
    print(f"ordered/file regressions {mode}: {len(checks)} measured checks, {sum(r['status'] for r in checks)} runtime failures")


if __name__ == "__main__": main()
