#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Short help in parsing order, with file/value/terminator shields."""
import importlib
import json
import sys

from cases import APP

CAPTURE = importlib.import_module("capture-offline")
INPUTS = importlib.import_module("offline-inputs")
COMPARE = importlib.import_module("offline-compare")


def main():
    selected = sys.argv[1:]
    assert not selected or len(selected) == 1
    rows = INPUTS.cluster_help_cases()
    refs = {r["id"]:r for r in json.loads((APP/"test/golden/offline-reference.json").read_bytes())}
    errors = json.loads((APP/"test/golden/offline-errors.json").read_bytes())
    assert len(rows) == 102 and sum(bool(r.get("help")) for r in rows) == 44
    if selected:
        rows = [r for r in rows if r["id"] == selected[0]]
        assert len(rows) == 1
    for row in rows:
        actual, _ = CAPTURE.run_case(APP/".lake/build/bin/cyberkrill", row)
        ref = refs[row["id"]]["result"]
        if row.get("help"):
            assert actual["status"] == 0 and actual["stderr"] == "" and "USAGE:" in actual["stdout"], "cluster help short circuit: " + row["id"]
            untouched = {name:dict(exists=name in row["files"],content=row["files"].get(name)) for name in row["observe"]}
            assert ref["files"] == actual["files"] == untouched, "cluster help no file effects: " + row["id"]
        elif ref["status"]:
            assert actual["status"] == 1 and actual["stdout"] == "" and actual["stderr"] == errors[row["id"]], "cluster help earlier error or operand: " + row["id"]
        else:
            assert actual["status"] == 0 and actual["stderr"] == "", "cluster help value shield: " + row["id"]
            checker = COMPARE.Comparator([], {})
            checker.compare(row, ref, actual); checker.finish()
        if row.get("help") or ref["status"]:
            assert actual["files"] == ref["files"], "cluster help file effects: " + row["id"]
    print(f"cluster help: {len(rows)} comparisons; inventory 102, help 44, earlier errors/data 58")


if __name__ == "__main__": main()
