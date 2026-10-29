#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Change one JSON property at a time while retaining every exact decimal."""
import copy
from decimal import Decimal
import hashlib
import importlib
import json
from pathlib import Path
import sys

from cases import APP
from compare import exact_json

COMPARE=importlib.import_module("offline-compare")
ORACLE=importlib.import_module("psbt-oracle")


def main(verify=False):
    exceptions=json.loads((APP/"test/golden/offline-exceptions.json").read_bytes())
    rows={r["id"]:r for r in json.loads((APP/"test/golden/offline-reference.json").read_bytes())}
    errors=json.loads((APP/"test/golden/offline-errors.json").read_bytes())
    checks=[]
    for entry in exceptions:
        if entry["kind"] == "bip-rules": continue
        name=entry["id"]; ref=entry["reference"]
        port=copy.deepcopy(entry.get("port",ref))
        if entry["kind"] == "amount":
            obj=exact_json(port["stdout"])
            obj["outputs"][0]["value_btc"]=Decimal(entry["fields"][0]["port"])
            port["stdout"]=ORACLE.exact_text(obj)+"\n"
        baseline=exact_json(port["stdout"])
        checker=COMPARE.Comparator([entry],{})
        checker.compare(rows[name],ref,port); checker.finish()
        for field,replacement in [("version",Decimal(77)),("network","wrong"),("unexpected",Decimal(0))]:
            changed=copy.deepcopy(baseline)
            changed[field]=replacement
            assert all(changed[key] == baseline[key] for key in baseline if key != field), "exact selftest changes only selected field"
            candidate={**port,"stdout":ORACLE.exact_text(changed)+"\n"}
            try: COMPARE.Comparator([entry],{}).compare(rows[name],ref,candidate)
            except AssertionError as error:
                # A key-set assertion or the selected field must detect it;
                # numeric rounding cannot stand in for the changed property.
                message=str(error)
                if field == "unexpected": assert "field set" in message
                elif entry["kind"] == "v2": assert "offline v2 complete JSON" in message
                else: assert "offline numeric field pin" in message
                checks.append(dict(id=name,property=field,status=1,assertion=message))
            else: raise AssertionError("exact comparator accepted unrelated property: "+name)
        for replacement in [Decimal(0),"0",None,True]:
            changed=copy.deepcopy(baseline)
            changed["outputs"][0]["value_btc"]=replacement
            candidate={**port,"stdout":ORACLE.exact_text(changed)+"\n"}
            try: COMPARE.Comparator([entry],{}).compare(rows[name],ref,candidate)
            except AssertionError as error:
                checks.append(dict(id=name,property="value_btc-"+type(replacement).__name__,status=1,assertion=str(error)))
            else: raise AssertionError("exact comparator accepted changed numeric leaf: "+name)
        body=port["stdout"].rstrip("\n")
        for suffix in ["", "\n\n", "\r\n", "\n \n"]:
            candidate={**port,"stdout":body+suffix}
            try: COMPARE.Comparator([entry],{}).compare(rows[name],ref,candidate)
            except AssertionError as error:
                assert "newline" in str(error), "single-property newline detecting assertion"
                checks.append(dict(id=name,property="newline-"+repr(suffix),status=1,assertion=str(error)))
            else: raise AssertionError("exact comparator accepted incorrect final newline: "+name)
    assert len(checks) == 275, "exact comparator independently selected property count"
    paths=[Path(__file__),APP/"test/offline-compare.py",APP/"test/compare.py",APP/"test/psbt-oracle.py",
           APP/"test/golden/offline-exceptions.json",APP/"test/golden/offline-reference.json"]
    record=dict(count=275,checks=checks,source_sha256={str(p.relative_to(APP)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    destination=APP/"test/golden/offline-exact-comparator-record.json"
    if verify or sys.argv[1:] == ["--verify"]: assert json.loads(destination.read_bytes()) == record
    else:
        assert not sys.argv[1:]
        destination.write_text(json.dumps(record,indent=2)+"\n")
    print("exact comparator: 275 independent single-property refusals; exact decimals and final newline boundaries")


if __name__ == "__main__": main()
