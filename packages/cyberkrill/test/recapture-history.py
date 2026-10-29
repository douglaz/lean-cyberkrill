#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Recapture retained Lightning observations without rewriting historical files."""
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import time

from cases import APP, ROOT, BUILD, PIN
from compare import differences, exact_json


def equivalent(a,b,command):
    assert a.endswith("\n") == b.endswith("\n"), "historical recapture newline"
    if command.startswith("ln-decode") and a and b:
        assert not differences(exact_json(a),exact_json(b)), "historical recapture complete JSON"
    else: assert a == b, "historical recapture exact bytes"


def main():
    names=["lightning-reference.json","lightning-routing-reference.json","revision-reference.json","l814-reference.json"]
    paths=[APP/"test/golden"/name for name in names]
    hashes={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in zip(names,paths)}
    destination=APP/"test/golden/offline-history-recapture.json"
    script_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if sys.argv[1:] == ["--verify"]:
        record=json.loads(destination.read_bytes())
        assert record["historical_sha256"] == hashes and record["script_sha256"] == script_hash
        assert record["build"] == BUILD and record["commit"] == PIN and record["build_status"] == 0
        assert len(record["executions"]) == 532 and all(r["comparison_status"] == 0 for r in record["executions"])
        print("retained recaptures: 531 plus separate L814; portable complete JSON and exact stream/newline/file checks")
        return
    assert not sys.argv[1:]
    logs=APP/".lake/history-recapture"; logs.mkdir(parents=True,exist_ok=True)
    start=time.monotonic()
    build=subprocess.run(BUILD,cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,timeout=1800)
    for stream in ["stdout","stderr"]: (logs/("build."+stream)).write_bytes(getattr(build,stream))
    (logs/"build.status").write_text(str(build.returncode)+"\n")
    assert build.returncode == 0, "required producer build failed; separate logs retained"
    producer=Path(build.stdout.decode().strip())/"bin/cyberkrill"
    revision=importlib.import_module("revisions")
    executions=[]
    for name,path in zip(names,paths):
        data=json.loads(path.read_bytes()); rows=data if isinstance(data,list) else [data]
        for row in rows:
            normalized={**row,"files":row.get("files",{}),"outputs":row.get("outputs",[])}
            result,outputs,seconds=revision.execute(producer,normalized,isolated=True)
            ref=row["result"]; command=row["args"][0]
            assert result["status"] == ref["status"] and result["stderr"] == ref["stderr"], row["id"]+" historical status/stderr"
            equivalent(ref["stdout"],result["stdout"],command)
            original_outputs=row.get("output_bytes",{})
            assert outputs.keys() == original_outputs.keys()
            for output in outputs:
                before,after=original_outputs[output],outputs[output]
                assert (before is None) == (after is None), row["id"]+" historical output existence"
                if before is not None: equivalent(bytes.fromhex(before).decode(),bytes.fromhex(after).decode(),command)
            executions.append(dict(source=name,id=row["id"],reference_status=result["status"],comparison_status=0,seconds=seconds))
    assert len(executions) == 532
    assert {name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in zip(names,paths)} == hashes
    record=dict(commit=PIN,build=BUILD,build_status=0,seconds=round(time.monotonic()-start,3),
        execution='unshare -rn with fresh temporary HOME/cwd, loopback only, timeout --foreground 15 "$PRODUCER"; original deterministic inputs and separate streams',
        historical_sha256=hashes,script_sha256=script_hash,executions=executions)
    destination.write_text(json.dumps(record,indent=2)+"\n")
    print("retained recaptures: 532 isolated executions matched; original observations unchanged")


if __name__ == "__main__": main()
