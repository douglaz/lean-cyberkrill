# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Structural JSON comparison with exact decimals and leaf-specific exceptions."""
from decimal import Decimal
import json


def exact_json(text):
    def invalid(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(text, parse_int=Decimal, parse_float=Decimal, parse_constant=invalid)


def differences(ref, port, field="stdout"):
    if type(ref) is not type(port):
        return [(field, ref, port)]
    if isinstance(ref, dict):
        assert ref.keys() == port.keys(), f"field set: {field}"
        # JSON string quoting distinguishes literal punctuation in keys from
        # nesting, and quoted object keys from unquoted numeric array indices.
        return [diff for key in ref for diff in differences(ref[key], port[key], field + "[" + json.dumps(key, ensure_ascii=True) + "]")]
    if isinstance(ref, list):
        assert len(ref) == len(port), f"array length: {field}"
        return [diff for i, (r, p) in enumerate(zip(ref, port))
                for diff in differences(r, p, f"{field}[{i}]")]
    return [] if ref == port else [(field, ref, port)]


class Comparator:
    def __init__(self, amounts=(), refusals=()):
        self.amounts = {(e["case"], e["field"]): e for e in amounts}
        self.refusals = {e["case"]: e for e in refusals}
        assert len(self.amounts) == len(amounts), "duplicate amount entry"
        assert len(self.refusals) == len(refusals), "duplicate refusal entry"
        self.used_amounts = set()
        self.used_refusals = set()

    def compare(self, case, ref, port):
        name, mode = case["id"], case["mode"]
        if name in self.refusals:
            entry = self.refusals[name]
            assert ref["status"] == entry["reference_status"] == 0, f"refusal reference status: {name}"
            assert port["status"] == entry["port_status"] != 0, f"refusal port status: {name}"
            assert ref["stdout"] == entry["reference_stdout"], f"refusal reference stdout: {name}"
            assert ref["stderr"] == entry["reference_stderr"], f"refusal reference stderr: {name}"
            assert port["stdout"] == "", f"refusal stdout: {name}"
            assert port["stderr"] == entry["port_stderr"], f"refusal error identity: {name}"
            assert port["stderr"].startswith(entry["error"] + ":"), f"refusal named error: {name}"
            self.used_refusals.add(name)
            return
        if ref["status"] != 0:
            assert mode == "failure", f"unexpected reference failure: {name}"
            assert port["status"] > 0 and port["stdout"] == "" and port["stderr"], f"ordinary failure: {name}"
            return
        assert port["status"] == ref["status"] == 0, f"success status: {name}"
        if mode == "version":
            value = exact_json(ref["stdout"])
            actual = exact_json(port["stdout"])
            assert set(value) == set(actual) == {"version"}, "version fields"
            assert isinstance(value["version"], str) and isinstance(actual["version"], str), "version type"
            assert ref["stderr"] == port["stderr"] == "", "version stderr"
            return
        assert mode in ["json", "scalar"], f"missing named refusal: {name}"
        diffs = differences(exact_json(ref["stdout"]), exact_json(port["stdout"])) if mode == "json" else differences(ref["stdout"], port["stdout"])
        diffs += differences(ref["stderr"], port["stderr"], "stderr")
        for field, expected, actual in diffs:
            key = (name, field)
            assert key in self.amounts, f"unlisted difference: {name} {field}"
            entry = self.amounts[key]
            if entry["kind"] == "number":
                assert type(expected) is type(actual) is Decimal, f"number type: {key}"
                r, p = Decimal(entry["reference"]), Decimal(entry["port"])
            else:
                assert entry["kind"] == "string" and type(expected) is type(actual) is str, f"string type: {key}"
                r, p = entry["reference"], entry["port"]
            assert expected == r and actual == p, f"wrong pinned values: {name} {field}"
            self.used_amounts.add(key)

    def finish(self):
        assert self.used_amounts == self.amounts.keys(), "unused amount entries"
        assert self.used_refusals == self.refusals.keys(), "unused refusal entries"
