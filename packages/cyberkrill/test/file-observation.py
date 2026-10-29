#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Real disposable producers falsify only output-file newlines or one JSON leaf."""
import importlib
import json
from pathlib import Path
import sys

from cases import APP

CAPTURE = importlib.import_module("capture-offline")
COMPARE = importlib.import_module("offline-compare")


def main():
    selected = sys.argv[1:]
    assert not selected or len(selected) == 1
    rows = {r["id"]:r for r in json.loads((APP/"test/golden/offline-reference.json").read_bytes())}
    count = 0
    for command in ["fm-encode-invite", "onchain-decode-psbt", "fm-decode-invite"]:
        row = rows[f"routing/{command}/output-0"]
        ref = row["result"]
        name, = ref["files"]
        original = ref["files"][name]["content"]
        body = original.rstrip("\n")
        variants = [("control", original)]
        if command == "fm-decode-invite":
            assert not original.endswith("\n")
            variants += [("lf", body+"\n"), ("crlf", body+"\r\n"), ("cr", body+"\r"), ("extra", body+"\n\n")]
            obj = json.loads(original); obj["federation_id"] = "changed"
            variants += [("field", json.dumps(obj))]
        else:
            assert original.endswith("\n") and not original.endswith("\n\n")
            variants += [("crlf", original.replace("\n", "\r\n")),
                         ("cr", original.replace("\n", "\r")), ("missing", body), ("extra", original+"\n")]
        for label, text in variants:
            identity = command+"/"+label
            if selected and selected[0] != identity: continue
            raw = text.encode("utf-8")
            # Assert the actual producer bytes independently of the observer.
            script = ("from pathlib import Path; p=Path("+repr(name)+"); p.write_bytes("+repr(raw)+"); assert p.read_bytes()=="+repr(raw))
            actual, _ = CAPTURE.run_case(Path(sys.executable), {**row, "args":["-B", "-c", script]})
            assert actual["status"] == 0 and actual["stdout"] == actual["stderr"] == "", "file producer control: "+identity
            checker = COMPARE.Comparator([], {})
            try:
                checker.compare(row, ref, actual); checker.finish()
            except AssertionError as error:
                assert label != "control", "file LF/no-newline passing control: "+identity
                expected = "offline unlisted difference" if label == "field" else "offline output newline"
                assert expected in str(error), "file intended detecting assertion: "+identity+": "+str(error)
            else:
                assert label == "control", "file comparator accepted newline/field: "+identity
            assert actual["files"][name]["content"] == text, "file UTF-8 byte spelling: "+identity
            count += 1
    assert count == (1 if selected else 16), "file boundary independently pinned count"
    print(f"ordinary file boundary: {count} real-process checks; full inventory 3 controls, 12 newline refusals, 1 JSON-leaf refusal")


if __name__ == "__main__": main()
