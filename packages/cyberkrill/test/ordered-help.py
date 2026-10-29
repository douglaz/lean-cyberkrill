#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Ordered help, earlier errors and help-looking filename/terminator data."""
import importlib
import json
import sys

from cases import APP

CAPTURE = importlib.import_module("capture-offline")
INPUTS = importlib.import_module("offline-inputs")


def main():
    selected = sys.argv[1:]
    assert not selected or len(selected) == 1
    rows = INPUTS.ordered_help_cases()
    refs = {r["id"]:r for r in json.loads((APP/"test/golden/offline-reference.json").read_bytes())}
    assert len(rows) == 67 and sum(bool(r.get("help")) for r in rows) == 35
    if selected:
        rows = [r for r in rows if r["id"] == selected[0]]
        assert len(rows) == 1
    for row in rows:
        actual, _ = CAPTURE.run_case(APP/".lake/build/bin/cyberkrill", row)
        ref = refs[row["id"]]["result"]
        if row.get("help"):
            assert actual["status"] == 0 and actual["stderr"] == "" and "USAGE:" in actual["stdout"], "ordered help short circuit: " + row["id"]
        elif ref["status"]:
            assert actual["status"] == 1 and actual["stdout"] == "" and actual["stderr"], "ordered help earlier error or operand: " + row["id"]
        else:
            assert actual["status"] == 0 and actual["stdout"] == ref["stdout"] and actual["stderr"] == "", "ordered help filename data: " + row["id"]
        assert actual["files"] == ref["files"], "ordered help file effects: " + row["id"]
    print(f"ordered help: {len(rows)} comparisons; inventory 67, help 35, earlier errors/data 32")


if __name__ == "__main__": main()
