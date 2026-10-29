#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Record current executions; derive v2 pins independently and bound BIP deltas."""
from decimal import Decimal
import importlib
import json
import sys

from cases import APP
from compare import differences,exact_json

CAPTURE=importlib.import_module("capture-offline")
ORACLE=importlib.import_module("psbt-oracle")


def bip_errors():
    reasons={"key-type-fd01":"psbtFraming", "key-type-fd0500":"psbtFraming",
        "proprietary-subtype-fd01":"psbtInvalidKey:input:252:malformed proprietary key",
        "xpub-depth":"psbtInvalidValue:global:1:path length must match the extended key depth"}
    result={"parity/"+key:value+": Invalid offline input\n" for key,value in reasons.items()}
    fields=[("global",n) for n in range(2,7)]+[("input",n) for n in range(14,19)]+[("output",3),("output",4)]
    for index,(scope,kind) in enumerate(fields,1):
        text=f"psbtExcludedField:{scope}:{kind}: Invalid offline input\n"
        result[f"parity/bip370-invalid-{index}"]=text
        result[f"bip370Invalid/{index}"]=text
    assert len(result) == 28
    return result


def main():
    check=sys.argv[1:] == ["--check"]
    assert check or not sys.argv[1:]
    rows=json.loads((APP/"test/golden/offline-reference.json").read_bytes())
    exceptions=[]; errors={}; executions=[]
    for row in rows:
        actual,seconds=CAPTURE.run_case(APP/".lake/build/bin/cyberkrill",row)
        ref=row["result"]; name=row["id"]
        executions.append(dict(id=name,status=actual["status"],seconds=seconds))
        if actual["status"]:
            assert actual["status"] == 1 and actual["stdout"] == "" and actual["stderr"], name
            errors[name]=actual["stderr"]
        if row.get("psbt_version") == 2:
            expected=ORACLE.expected(row)
            assert ref["status"] == 1 and ref["stdout"] == "" and "PSBT versions greater than 0" in ref["stderr"], name
            if expected is None:
                assert actual["status"] == 1 and actual["stderr"] == "psbtTransaction:incompatible input locktimes: Invalid offline input\n", name
            else:
                assert actual["status"] == 0 and actual["stderr"] == "" and actual["stdout"].endswith("\n"), name
                pin=dict(status=0,stdout=ORACLE.exact_text(expected)+"\n",stderr="",files={})
                assert not differences(exact_json(pin["stdout"]),exact_json(actual["stdout"])), name
                exceptions.append(dict(id=name,kind="v2",reference=ref,port=pin))
        elif name in bip_errors():
            assert ref["status"] == 0 and ref["stderr"] == "" and actual["status"] == 1 and actual["stderr"] == bip_errors()[name], name
            exceptions.append(dict(id=name,kind="bip-rules",reference=ref,port=actual))
        elif ref["status"] == 0:
            assert actual["status"] == 0 and actual["stderr"] == ref["stderr"] == "", name
            if row.get("help") or not ref["stdout"] or row["args"][0] == "fm-encode-invite": continue
            diffs=differences(exact_json(ref["stdout"]),exact_json(actual["stdout"]))
            if diffs:
                assert name in ["synthetic-psbt/large-exact","synthetic-psbt/max-output"], "unranked numeric delta: "+name
                assert len(diffs) == 1 and diffs[0][0] == 'stdout["outputs"][0]["value_btc"]'
                assert all(type(a) is type(b) is Decimal for _,a,b in diffs)
                exceptions.append(dict(id=name,kind="amount",reference=ref,
                    fields=[dict(field=field,reference=str(a),port=str(b)) for field,a,b in diffs]))
        else: assert actual["status"] == 1, "unranked success delta: "+name
    assert len(exceptions) == 53 and len(errors) == 276
    for path,value in [("offline-exceptions.json",exceptions),("offline-errors.json",errors)]:
        destination=APP/"test/golden"/path
        if check: assert json.loads(destination.read_bytes()) == value, "changed offline observed pins: "+path
        else: destination.write_text(json.dumps(value,ensure_ascii=True,indent=2)+"\n")
    if not check:
        (APP/"test/golden/offline-port-timings.json").write_text(json.dumps(dict(
            executable=".lake/build/bin/cyberkrill", executions=executions),indent=2)+"\n")
    print(f"current offline executions: {len(rows)}; 53 exact exceptions, 276 named failures; independent v2 expected JSON")


if __name__ == "__main__": main()
