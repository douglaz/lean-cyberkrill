#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Executable regression checks for timestamp, JSON sequence and file semantics."""
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from unittest.mock import patch

from cases import APP, ROOT
from compare import Comparator, exact_json

CASES = importlib.import_module("revision-cases")
KEY = importlib.import_module("lightning-cases").SPEC_KEY
GOLDEN = APP / "test/golden/revision-reference.json"


def execute(executable, row, isolated=False):
    home = Path(tempfile.mkdtemp(prefix="invoice-regression-", dir=os.environ["TMPDIR"]))
    paths = {home / name for name in row["files"] | dict.fromkeys(row["outputs"])}
    try:
        for name, text in row["files"].items(): (home / name).write_text(text, encoding="utf-8")
        args = [KEY if a == "{published_key}" else a for a in row["args"]]
        command = [str(executable), *args]
        if isolated:
            command = ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec timeout --foreground 15 "$@"',
                       "capture", *command]
        payload = bytes.fromhex(row["input_hex"]) if "input_hex" in row else (
            row["input"].encode() if row.get("input") is not None else None)
        start = time.monotonic()
        proc = subprocess.run(command, cwd=home, env={**os.environ, "HOME": str(home)},
                              input=payload, stdin=subprocess.DEVNULL if payload is None else None,
                              capture_output=True, timeout=20)
        result = dict(status=proc.returncode, stdout=proc.stdout.decode(), stderr=proc.stderr.decode())
        assert KEY not in result["stdout"] + result["stderr"], row["id"] + " key disclosure"
        assert proc.returncode not in [124, 137] and "unshare:" not in result["stderr"], row["id"] + " isolation/timeout"
        outputs = {name: (home / name).read_bytes().hex() if (home / name).is_file() else None for name in row["outputs"]}
        return result, outputs, round(time.monotonic() - start, 3)
    finally:
        for path in paths:
            if path.is_file(): path.unlink()
        home.rmdir()


def compare(row, actual, outputs):
    name, reference = row["id"], row["result"]
    if reference["status"]:
        assert actual["status"] == 1, name + " failure status"
        assert actual["stdout"] == "", name + " failure stdout"
        assert actual["stderr"], name + " failure stderr"
        assert ":" in actual["stderr"] and "panic" not in actual["stderr"], name + " named diagnostic"
        if row["error"]:
            assert actual["stderr"].startswith(row["error"] + ":"), name + " error ordering/identity"
    else:
        mode = "json" if row["args"][0].startswith("ln-decode") else "scalar"
        Comparator().compare(dict(id=name, mode=mode), reference, actual)
        assert actual["stdout"].endswith("\n") == reference["stdout"].endswith("\n"), name + " stdout newline"
    assert outputs == row["output_bytes"], name + " failed output existence/bytes"
    if name == "simnet/decode":
        assert exact_json(actual["stdout"])["fallback_addresses"] == [
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"], name + " regtest fallback"


def captures():
    rows = json.loads(GOLDEN.read_bytes())
    original = json.loads((APP / "test/golden/lightning-reference.json").read_bytes())
    inputs = CASES.cases(original)
    inputs.append(CASES.decode_case(rows))
    assert [{k: v for k, v in r.items() if k not in ["result", "seconds", "output_bytes"]} for r in rows] == inputs, "revision capture construction"
    assert len(rows) == 174, "revision capture count"
    for group, count, accepted in [("timestamp", 58, 31), ("unicode", 34, 24),
                                    ("sequence", 68, 14), ("simnet", 2, 2), ("output", 12, 0)]:
        selected = [r for r in rows if r["id"].startswith(group + "/")]
        assert len(selected) == count and sum(r["result"]["status"] == 0 for r in selected) == accepted, group + " inventory/status pins"
    for row in rows:
        ref = row["result"]
        assert ref["status"] in [0, 1], row["id"] + " reference status"
        assert (not ref["stderr"]) if not ref["status"] else (ref["stderr"] and not ref["stdout"]), row["id"] + " reference streams"
    provenance = json.loads((APP / "test/golden/revision-provenance.json").read_bytes())
    assert provenance["build_status"] == 0 and provenance["count"] == len(rows)
    for name, digest in provenance["sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, "stale revision capture: " + name
    return rows


def selftest():
    rows = captures()
    checks = 0

    def bad(row, actual, outputs, assertion):
        nonlocal checks
        try: compare(row, actual, outputs)
        except (AssertionError, ValueError) as error:
            assert assertion in str(error), "revision harness detecting assertion"
        else: raise AssertionError("revision harness accepted changed result")
        checks += 1

    for row in rows:
        ref, outputs = row["result"], row["output_bytes"]
        # Reference diagnostics differ in wording. Supply the named port error
        # for a positive comparator control, never as an executable capture.
        port = {**ref, "status": 1, "stderr": (row["error"] or "decodeFailure") + ": invalid input\n"} if ref["status"] else ref
        compare(row, port, outputs); checks += 1
        if ref["status"]:
            bad(row, {**port, "status": 0}, outputs, "failure status")
            bad(row, {**port, "stdout": "leak"}, outputs, "failure stdout")
            bad(row, {**port, "stderr": ""}, outputs, "failure stderr")
            if row["error"]:
                bad(row, {**port, "stderr": "wrong: invalid input\n"}, outputs, "error ordering/identity")
        else:
            bad(row, {**port, "status": 1}, outputs, "success status")
            bad(row, {**port, "stderr": "warning"}, outputs, "unlisted difference")
            if row["args"][0] == "ln-encode-invoice":
                bad(row, {**port, "stdout": port["stdout"].removesuffix("\n")}, outputs, "unlisted difference")
            else:
                obj = json.loads(port["stdout"]); obj["timestamp_millis"] += 1
                bad(row, {**port, "stdout": json.dumps(obj)}, outputs, "unlisted difference")
                obj = json.loads(port["stdout"]); del obj["payment_hash"]
                bad(row, {**port, "stdout": json.dumps(obj)}, outputs, "field set")
        for filename, data in outputs.items():
            bad(row, port, {**outputs, filename: "" if data is None else None}, "failed output existence/bytes")
            bad(row, port, {**outputs, filename: "00"}, "failed output existence/bytes")
    assert checks == 812, "revision harness self-test count"
    print(f"revision comparator controls and falsifications: {checks}/{checks}")


def scope_case(name):
    scope = importlib.import_module("scope")
    path = ROOT / ".beads/issues.jsonl"
    rows = [json.loads(line) for line in path.read_bytes().splitlines()]
    issue = next(r for r in rows if r["id"] == scope.ISSUE)
    if name != "claim":
        issue.update(status="closed", closed_at=issue["updated_at"], close_reason="Implemented offline Lightning commands and validated parity.")
    valid = name in ["claim", "closed"]
    if name == "closed-missing-time": issue.pop("closed_at")
    if name == "closed-empty-reason": issue["close_reason"] = "  "
    if name == "closed-bad-time": issue["closed_at"] = "bad"
    if name == "closed-wrong-order": issue["closed_at"] = "2020-01-01T00:00:00Z"
    if name == "claim-with-closure": issue.update(status="in_progress")
    if name == "decision-text": issue["description"] += " changed"
    if name == "unrelated":
        other = next(r for r in rows if r["id"] != scope.ISSUE)
        other["status"] = "open" if other["status"] == "closed" else "closed"
    content = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
    read = Path.read_bytes

    def replacement(p): return content if p == path else read(p)

    error = ""
    try:
        with patch.object(Path, "read_bytes", replacement), redirect_stdout(io.StringIO()): scope.main()
    except AssertionError as exc: error = str(exc)
    assert bool(error) != valid, "scope/" + name + " closure validation"


SCOPE_CASES = ["claim", "closed", "closed-missing-time", "closed-empty-reason", "closed-bad-time",
               "closed-wrong-order", "claim-with-closure", "decision-text", "unrelated"]


def main():
    args = sys.argv[1:]
    if args == ["--selftest"]:
        selftest(); return
    if args and args[0] == "--scope":
        for name in args[1:] or SCOPE_CASES: scope_case(name)
        print("synthetic scope shapes checked")
        return
    rows = captures()
    if args:
        assert len(args) == 2 and args[0] == "--case"
        rows = [r for r in rows if r["id"] == args[1]]
        assert len(rows) == 1
    for row in rows:
        actual, outputs, _ = execute(APP / ".lake/build/bin/cyberkrill", row)
        compare(row, actual, outputs)
    print(f"revision executable captures: {len(rows)}/{len(rows)}")
    if not args:
        print("revision inventory: timestamps 58/58, Unicode 34/34, sequences 68/68, simnet 2/2, output failures 12/12")
        print("Lightning captures: 357 retained + 174 regression captures = 531; separate early L814 capture retained")


if __name__ == "__main__": main()
