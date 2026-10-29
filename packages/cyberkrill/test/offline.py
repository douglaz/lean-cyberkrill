#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Actual argv/EOF/file goldens, independent v2 JSON and adversarial comparison."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys

from cases import APP, ROOT, PIN, BUILD
from compare import exact_json

CAPTURE=importlib.import_module("capture-offline")
INPUTS=importlib.import_module("offline-inputs")
COMPARE=importlib.import_module("offline-compare")


def records():
    rows=json.loads((APP/"test/golden/offline-reference.json").read_bytes())
    assert [{k:v for k,v in r.items() if k not in ["result","seconds"]} for r in rows] == INPUTS.inventory(), "offline exact input inventory"
    assert len(rows) == 616 and len(INPUTS.invites()) == 100, "offline independently pinned counts"
    original = json.dumps(rows[:584], sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(original).hexdigest() == "52114188b7493cfa67ab564d67fb540bae61ad640d5179a89649dacdd2e0180f", "original 584 capture observations unchanged"
    prefix = json.dumps(rows[:482], sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(prefix).hexdigest() == "70d96d5dae5d8c458f1d141e496fa1cf677386ab474e9745715d65552abfeb11", "original 482 capture observations unchanged"
    assert len(INPUTS.psbts()) == 204 and len(INPUTS.synthetic_psbts()) == 33 and len(INPUTS.routing_cases()) == 78
    assert len(INPUTS.ordered_help_cases()) == 67, "ordered help independently pinned count"
    assert len(INPUTS.cluster_help_cases()) == 102, "cluster help independently pinned count"
    assert len(INPUTS.carried_help_cases()) == 32, "carried typed help independently pinned count"
    assert INPUTS.COUNTS == dict(bip174Valid=10,bip174SignerFailures=4,bip174Roles=14,bip174Invalid=20,bip370Valid=14,bip370Invalid=24,bip370Locktimes=10,bip371Valid=6,bip371Invalid=11)
    print("offline captures: 616/616; invite 100, published/parity/hybrid/network 204, synthetic PSBT 33, argv/IO 78, ordered help 67, cluster help 102, carried typed help 32",flush=True)
    return rows


def provenance():
    source=json.loads((APP/"test/golden/offline-provenance.json").read_bytes())
    assert source["licence"] == "MIT", "offline selected capture licence"
    assert source.get("source_licences") == {
        "cyberkrill/src/main.rs": "MIT",
        "fedimint-lite/src/lib.rs": "MIT OR Apache-2.0, taken under MIT",
    }, "offline per-source licences"
    assert source["commit"] == PIN and source["build"] == BUILD and source["build_status"] == 0 and source["records"] == 616
    assert source["record_sha256"] == hashlib.sha256((APP/"test/golden/offline-reference.json").read_bytes()).hexdigest()
    for path,digest in source["input_sha256"].items(): assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == digest, "offline input digest: "+path
    for path,digest in source["scripts_sha256"].items(): assert hashlib.sha256((APP/"test"/path).read_bytes()).hexdigest() == digest, "offline capture script digest: "+path
    hybrids=json.loads((APP/"test/golden/hybrid-inputs.json").read_bytes())
    assert hybrids == importlib.import_module("hybrid-inputs").derive()
    assert len(hybrids) == 19 and sum(r["expected_success"] for r in hybrids) == 10
    exceptions=json.loads((APP/"test/golden/offline-exceptions.json").read_bytes())
    actual={e["id"]:e["port"]["stderr"] for e in exceptions if e["kind"] == "bip-rules"}
    assert actual == importlib.import_module("record-offline").bip_errors(), "offline exact BIP refusal identities"
    readme=(ROOT/"README.md").read_text(encoding="utf-8")
    for entry in exceptions:
        if entry["kind"] == "amount":
            for pin in entry["fields"]:
                row=f"| `{entry['id']}` | `{pin['field']}` | {pin['reference']} | {pin['port']} |"
                assert row in readme, "README exact PSBT numeric pin: "+entry["id"]


def selftest(rows,exceptions,errors):
    by_id={r["id"]:r for r in rows}
    tested=0
    def rejects(entry,ref,port,exception=None,error_pins=None,finish=False):
        checker=COMPARE.Comparator([entry] if exception is None else exception,
            ({entry["id"]:errors[entry["id"]]} if entry["id"] in errors else {}) if error_pins is None else error_pins)
        try:
            checker.compare(by_id[entry["id"]],ref,port)
            if finish: checker.finish()
        except (AssertionError,ValueError,KeyError,TypeError): return
        raise AssertionError("offline comparator accepted a falsified boundary: "+entry["id"])
    for entry in exceptions:
        row=by_id[entry["id"]]; ref=entry["reference"]
        if entry["kind"] == "amount":
            # Exact replacement changes only the explicitly allowlisted number.
            port=copy.deepcopy(ref)
            for field in entry["fields"]:
                assert port["stdout"].count(field["reference"]) == 1
                port["stdout"]=port["stdout"].replace(field["reference"],field["port"])
        else: port=entry["port"]
        checker=COMPARE.Comparator([entry],{entry["id"]:errors[entry["id"]]} if entry["id"] in errors else {})
        checker.compare(row,ref,port); checker.finish()
        for side in ["reference","port"]:
            for key,value in [("status",2),("stdout","garbage\n"),("stderr","wrongReason: unrelated\n"),("files",{"unused":dict(exists=True,content="x")})]:
                bad=copy.deepcopy(ref if side == "reference" else port); bad[key]=value
                rejects(entry,bad if side == "reference" else ref,bad if side == "port" else port); tested+=1
        rejects(entry,ref,port,exception=[]); tested+=1
        extra={**copy.deepcopy(entry),"id":"unused"}
        rejects(entry,ref,port,exception=[entry,extra],finish=True); tested+=1
        if entry["kind"] in ["v2","amount"]:
            for field,value in [("version",77),("unrelated",0),("network","wrong")]:
                bad=copy.deepcopy(port); obj=exact_json(bad["stdout"]); obj[field]=value
                bad["stdout"]=COMPARE.ORACLE.exact_text(obj)+"\n"
                rejects(entry,ref,bad); tested+=1
            bad=copy.deepcopy(entry)
            if entry["kind"] == "amount": bad["fields"][0]["port"]="0"
            else: bad["port"]["stdout"]='{}\n'
            rejects(entry,ref,port,exception=[bad]); tested+=1
    unchanged = 0
    for row in rows:
        if not row["id"].startswith("cluster-help/") or row.get("help") or row["result"]["status"]:
            continue
        ref = row["result"]
        for path, content in row["files"].items():
            if ref["files"][path]["content"] != content: continue
            candidate = copy.deepcopy(ref)
            candidate["files"][path]["content"] += "\n"
            try: COMPARE.Comparator([], {}).compare(row, ref, candidate)
            except AssertionError as error:
                assert "offline unchanged input bytes" in str(error), "input bytes detecting assertion"
            else: raise AssertionError("offline comparator accepted changed input bytes: " + row["id"])
            unchanged += 1
    assert unchanged == 38, "unchanged input byte boundary count"
    tested += unchanged
    assert tested == 668, "offline comparator falsification count"
    print(f"offline comparator falsifications: {tested}; all 53 exception identities and 38 unchanged-input byte boundaries",flush=True)


def main():
    args=sys.argv[1:]
    only=None
    if args[:1] == ["--case"]: _,only=args
    elif args: assert args in [["--installed"],["--selftest"],["--evidence"]]
    rows=records()
    exceptions=json.loads((APP/"test/golden/offline-exceptions.json").read_bytes())
    errors=json.loads((APP/"test/golden/offline-errors.json").read_bytes())
    assert len(exceptions) == 53 and len(errors) == 276, "offline exception/error inventory"
    assert {kind:sum(e["kind"] == kind for e in exceptions) for kind in ["v2","bip-rules","amount"]} == {"v2":23,"bip-rules":28,"amount":2}
    if args in [["--selftest"],["--evidence"]]:
        provenance(); selftest(rows,exceptions,errors)
        importlib.import_module("offline-exact-selftest").main(True)
        return
    if args == ["--installed"]:
        wanted={"invite/primary-0","invite-json/primary-1","invite-json/primary-skip-1","bip174Valid/0","bip370Valid/0",
                "routing/fm-decode-invite/output-0","routing/fm-encode-invite/output-0","routing/onchain-decode-psbt/output-0"}
        wanted.update("ordered-help/"+command+"/"+name
            for command in ["fm-decode-invite","fm-encode-invite","onchain-decode-psbt"]
            for name in ["help-unknown","unknown-help"])
        rows=[r for r in rows if r["id"] in wanted]
        wanted.update("cluster-help/"+command+"/"+name
            for command in ["fm-decode-invite","fm-encode-invite","onchain-decode-psbt"]
            for name in ["hx","output-short-hyphen"])
        rows=[r for r in records() if r["id"] in wanted]
        wanted.update(r["id"] for r in INPUTS.carried_help_cases())
        rows=[r for r in records() if r["id"] in wanted]
        assert len(rows) == 52
    if only:
        rows=[r for r in rows if r["id"] == only]; assert len(rows) == 1, "offline selected case"
    selected={r["id"] for r in rows}
    checker=COMPARE.Comparator([e for e in exceptions if e["id"] in selected],{k:v for k,v in errors.items() if k in selected})
    executable=ROOT/"result/bin/cyberkrill" if args == ["--installed"] else APP/".lake/build/bin/cyberkrill"
    for row in rows:
        actual,_=CAPTURE.run_case(executable,row)
        checker.compare(row,row["result"],actual)
    checker.finish()
    if only is None and args != ["--installed"]:
        selftest(records(),exceptions,errors)
        importlib.import_module("offline-exact-selftest").main(True)
    print(f"offline CLI comparisons: {len(rows)}/{len(rows)}; complete JSON, exact decimals, streams/newlines/files",flush=True)


if __name__ == "__main__": main()
