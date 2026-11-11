#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture the pinned config command against owned synthetic loopback replies."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile

from cases import APP, PIN
from evidence import write_record
import network

C=importlib.import_module("fetch-config")


def capture(executable, completed):
    assert network.isolated(), "reference config capture requires a new network namespace"
    f=C.fixtures(); observations=[]
    rows=C.reference_cases()
    # Reference numeric refusals can move to a second guardian where exact
    # arithmetic accepts the first. Keep both canned endpoints ready in those
    # controls; observations record actual requests rather than predicting them.
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary);(root/"home").mkdir()
        for row in rows:
            steps=list(row["steps"])
            if row.get("invite")=="two" and not any(s["path"]=="/second/config" for s in steps):
                steps.append(dict(method="GET",path="/second/config",body="",response=dict(body=json.dumps(C.ready_config(f,row)))))
            args=["fm-fetch-config",f["invites"][row.get("invite","single")]]
            network.refuse_spawn(args,C.BASE)
            with C.responder(root,steps) as log:
                result=C.invoke(executable,args,root,timeout=20)
                requests=[json.loads(line) for line in log.read_text().splitlines()]
            stdout=result.stdout.decode();stderr=result.stderr.decode()
            if row.get("error"):
                assert result.returncode!=0 and stderr and not stdout, "reference expected rejection " + row["name"]
            else:
                assert result.returncode==0 and stdout and not stdout.endswith("\n"), "reference independent success " + row["name"]
                if not row.get("warning"):
                    assert not stderr, "reference success stderr " + row["name"]
            observations.append(dict(name=row["name"],status=result.returncode,stdout=stdout,stderr=stderr,requests=requests))
            print("reference config "+row["name"]+": exit "+str(result.returncode),flush=True)
    record=dict(source="https://github.com/douglaz/cyberkrill",revision=PIN,licence="MIT",kind="independent pinned CLI capture on synthetic local guardian replies",
                command=["fm-fetch-config","synthetic invite from fetch-config.json"],
                fixture_sha256=hashlib.sha256(C.FIXTURE.read_bytes()).hexdigest(),
                cases_sha256=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest(),
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),captures=observations)
    write_record(C.REFERENCE,json.dumps(record,indent=2)+"\n")
    provenance=json.loads(C.PROVENANCE.read_bytes())
    provenance["capture_sha256"]=hashlib.sha256(C.REFERENCE.read_bytes()).hexdigest()
    write_record(C.PROVENANCE,json.dumps(provenance,indent=2)+"\n")
    completed.write_text("complete\n")
    print(f"reference config captures: {len(observations)}/{len(rows)}",flush=True)


def main():
    if sys.argv[1:2]==["--inside"]:
        assert len(sys.argv)==4;capture(sys.argv[2],Path(sys.argv[3]));return 0
    assert not sys.argv[1:]
    result=network.run_owned(["nix","build","--no-link","--print-out-paths","github:douglaz/cyberkrill/"+PIN],timeout=1200,capture_output=True)
    assert result.returncode==0,result.stderr.decode()
    executable=Path(result.stdout.decode().strip())/"bin/cyberkrill"
    assert executable.is_file(), "pinned reference binary"
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        completed=Path(temporary)/"completed"
        status=network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),"--inside",str(executable),str(completed)],timeout=600)
        assert status==0 and completed.is_file() and completed.read_text()=="complete\n", "reference capture ran without SKIP"
    return 0


if __name__=="__main__":sys.exit(main())
