#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Bounded offline reference capture, with fresh HOME/cwd for each execution."""
import importlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cases import APP, BUILD, PIN, ROOT

INPUTS = importlib.import_module("offline-inputs")


def run_case(executable, row, isolated=False):
    root = Path(tempfile.mkdtemp(prefix="offline-command-", dir=os.environ["TMPDIR"]))
    owned = []
    try:
        for name, text in row.get("files", {}).items():
            assert Path(name).name == name and name not in [".", ".."]
            path = root / name
            path.write_text(text, encoding="utf-8"); owned.append(path)
        for name, value in row.get("file_hex", {}).items():
            assert Path(name).name == name
            path = root / name
            path.write_bytes(bytes.fromhex(value)); owned.append(path)
        for name in row.get("directories", []):
            assert Path(name).name == name
            path = root / name
            path.mkdir(); owned.append(path)
        command = [str(executable), *row["args"]]
        if isolated:
            command = ["unshare", "-rn", "sh", "-c",
                       'ip link set lo up && exec timeout --foreground 15 "$@"', "capture", *command]
        start = time.monotonic()
        payload = row.get("input")
        p = subprocess.run(command, cwd=root, env={**os.environ,"HOME":str(root),"PYTHONDONTWRITEBYTECODE":"1"},
                           input=payload.encode() if payload is not None else None,
                           stdin=subprocess.DEVNULL if payload is None else None, capture_output=True, timeout=20)
        assert p.returncode not in [124,137], "capture timed out: " + row["id"]
        observed = {}
        for name in row.get("observe", []):
            path = root / name
            observed[name] = dict(exists=path.exists(), content=path.read_bytes().decode("utf-8") if path.is_file() else None)
            if path.exists() and path not in owned: owned.append(path)
        return dict(status=p.returncode,stdout=p.stdout.decode(),stderr=p.stderr.decode(),files=observed), round(time.monotonic()-start,6)
    finally:
        for path in reversed(owned):
            if path.is_dir(): path.rmdir()
            else: path.unlink()
        root.rmdir()


def main():
    check = sys.argv[1:] == ["--check"]
    extend = sys.argv[1:] in [["--extend"], ["--refresh"]]
    assert check or extend or not sys.argv[1:]
    logs = APP / ".lake/offline-capture"
    logs.mkdir(parents=True,exist_ok=True)
    start = time.monotonic()
    build = subprocess.run(BUILD,cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,timeout=1800)
    build_seconds = round(time.monotonic()-start,6)
    for stream in ["stdout","stderr"]: (logs / ("build."+stream)).write_bytes(getattr(build,stream))
    (logs/"build.status").write_text(str(build.returncode)+"\n")
    assert build.returncode == 0, "required producer build failed; separate build logs retained"
    producer = Path(build.stdout.decode().strip())/"bin/cyberkrill"
    rows = INPUTS.inventory()
    records = []
    for row in rows:
        result, seconds = run_case(producer,row,True)
        if "expected_success" in row:
            assert (result["status"] == 0) == row["expected_success"], "hybrid capture contradicts decision: "+row["id"]
        records.append({**row,"result":result,"seconds":seconds})
    destination = APP/"test/golden/offline-reference.json"
    if check or extend:
        from compare import exact_json, differences
        comparator = importlib.import_module("offline-compare")
        original = json.loads(destination.read_bytes())
        assert len(original) == len(records) if check else len(original) <= len(records)
        for index,(before,after) in enumerate(zip(original,records)):
            assert {k:v for k,v in before.items() if k not in ["result","seconds"]} == {k:v for k,v in after.items() if k not in ["result","seconds"]}
            a,b = before["result"],after["result"]
            assert a.keys() == b.keys() and a["status"] == b["status"] and a["stderr"] == b["stderr"]
            def equivalent(left,right):
                if a["status"] == 0 and before["args"][0] != "fm-encode-invite" and not before.get("help"):
                    comparator.check_newline(left,right,before["id"])
                    if left: assert not differences(exact_json(left),exact_json(right)), before["id"]
                else: assert left == right, before["id"]
            equivalent(a["stdout"],b["stdout"])
            assert a["files"].keys() == b["files"].keys()
            for name in a["files"]:
                left,right=a["files"][name],b["files"][name]
                assert left["exists"] == right["exists"]
                if name in before.get("files", {}) and left["content"] == before["files"][name]:
                    assert left == right, before["id"] + " unchanged input bytes"
                elif left["content"] is None: assert right["content"] is None
                else: equivalent(left["content"],right["content"])
            if extend: records[index] = before
    if not check:
        destination.write_text(json.dumps(records,ensure_ascii=True,indent=2)+"\n")
        provenance = dict(source="https://github.com/douglaz/cyberkrill",commit=PIN,
            paths=["cyberkrill/src/main.rs","fedimint-lite/src/lib.rs"],licence="MIT OR Apache-2.0, taken under MIT",
            build=BUILD,build_status=0,build_seconds=build_seconds,
            execution='unshare -rn sh -c \'ip link set lo up && exec timeout --foreground 15 "$@"\' capture "$PRODUCER" ...',
            environment='fresh temporary HOME and cwd "$TMP_ROOT", closed stdin unless the record specifies input',
            records=len(records),published_counts=INPUTS.COUNTS,
            record_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            input_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [
                ROOT/"packages/bitcoin/Bitcoin/PsbtVectors.lean",
                ROOT/"packages/bitcoin/test-data/cyberkrill-psbt-capture.json",
                ROOT/"packages/fedimint-invite/test-data/primary.json"]},
            scripts_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(INPUTS.__file__),Path(__file__).with_name("hybrid-inputs.py")]})
        (destination.parent/"offline-provenance.json").write_text(json.dumps(provenance,indent=2)+"\n")
    print(f"offline {'recaptures' if check else 'captures'}: {len(records)}/{len(rows)}; separated streams/status/files; finite offline executions")


if __name__ == "__main__": main()
