#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Typed parser errors precede later help; runtime semantics follow help."""
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
    rows = INPUTS.carried_help_cases()
    refs = {r["id"]:r for r in json.loads((APP/"test/golden/offline-reference.json").read_bytes())}
    errors = json.loads((APP/"test/golden/offline-errors.json").read_bytes())
    assert len(rows) == 32 and sum(bool(r.get("help")) for r in rows) == 14
    if selected:
        rows = [r for r in rows if r["id"] == selected[0]]
        assert len(rows) == 1
    for row in rows:
        actual, _ = CAPTURE.run_case(APP/".lake/build/bin/cyberkrill", row)
        ref = refs[row["id"]]["result"]
        assert (ref["status"] == 0) == bool(row.get("help")), "carried help reference outcome: " + row["id"]
        if row.get("help"):
            assert actual["status"] == 0 and actual["stderr"] == "" and "USAGE:" in actual["stdout"], "carried help before runtime: " + row["id"]
        else:
            assert actual["status"] == 1 and actual["stdout"] == "", "carried help preceding typed error: " + row["id"]
            # Fixed secret-free diagnostics; available before port recapture.
            error = "invalidUnit" if "/enum-" in row["id"] else "invalidWordCount"
            messages = {"invalidArguments":"Invalid command arguments; use --help",
                        "invalidUnit":"--as requires btc, sats or msats",
                        "invalidWordCount":"Choose 12, 15, 18, 21 or 24 words"}
            expected = error + ": " + messages[error] + "\n"
            assert actual["stderr"] == expected, "carried help named error: " + row["id"]
            assert errors.get(row["id"], expected) == expected
        untouched = {name:dict(exists=True,content=text) for name,text in row["files"].items()}
        assert ref["files"] == actual["files"] == untouched, "carried help no file effects: " + row["id"]
        checker = COMPARE.Comparator([], {row["id"]:expected} if ref["status"] else {})
        checker.compare(row, ref, actual); checker.finish()
    print(f"carried typed help: {len(rows)} comparisons; inventory 32, earlier errors 18, help controls 14")


if __name__ == "__main__": main()
