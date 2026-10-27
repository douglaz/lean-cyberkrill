#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent injected output-option reds/greens; public refusals only after spies."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cases import APP
from driver import EXE, TEST, run

TOKENS = ["-w", "--words", "--seed", "-name", "-h", "--help", "--output", "-o", "--"]
ARGS = [["generate-mnemonic", alias, token] for alias in ["-o", "--output"] for token in TOKENS]
FILES = ["CyberkrillTests/Output.lean", "CyberkrillTests/Mnemonic.lean", "CyberkrillTests.lean",
         "test/output-regressions.py", "test/driver.py"]


def fingerprints(paths):
    return {p: hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in paths}


def public_checks():
    # Establish all no-entropy/no-write boundaries with published injected bytes
    # before any public invocation, including when selected outside lake test.
    p = run([str(TEST), "--output-boundaries"])
    assert p["status"] == 0, "injected output safety boundary: " + p["stderr"]
    print(p["stdout"], end="")
    print(f"public output-option refusals: {len(ARGS)}/18", flush=True)
    assert len(ARGS) == 18
    for i, args in enumerate(ARGS):
        p = run([str(EXE), *args])
        assert p == dict(status=1, stdout="", stderr="invalidArguments: Invalid command arguments; use --help\n"), f"public output refusal {i}"


def refresh():
    """Reintroduce the output guard defect against current tests, retaining history."""
    os.chdir(APP)
    path = Path("Cyberkrill/App.lean")
    original = path.read_bytes()
    old = "unless outputArgsValid args.tail do throw .invalidArguments"
    new = "pure ()"
    assert original.decode().count(old) == 1, "unique output guard target"
    bound = FILES + ["CyberkrillTests/Support.lean", "Cyberkrill/App.lean",
                     "test/golden/output-regression-record.json"]
    hashes = fingerprints(bound)
    logs = Path(".lake/output-regression-refresh")
    logs.mkdir(parents=True, exist_ok=True)
    signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def write(data):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            path.write_bytes(data)
            assert path.read_bytes() == data, "output source bytes"
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def interrupted(signum, _):
        write(original)
        raise SystemExit(128 + signum)

    for signum in signals:
        signal.signal(signum, interrupted)

    def command(label, args, expected, assertion=""):
        bounded = ["timeout", "--foreground", "180", *args]
        start = time.monotonic()
        p = subprocess.run(bounded, stdin=subprocess.DEVNULL, capture_output=True, timeout=190)
        elapsed = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            (logs / f"{label}.{stream}").write_bytes(getattr(p, stream))
        (logs / f"{label}.status").write_text(str(p.returncode) + "\n")
        assert p.returncode == expected, "output refresh exit: " + label
        if assertion:
            assert p.stderr.decode() == f"assertion failed: {assertion}\n", "output refresh assertion: " + label
        return dict(command=bounded, status=p.returncode, seconds=elapsed)

    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    rows = []
    print("current output refusal reintroductions: 18/18", flush=True)
    try:
        try:
            write(original.decode().replace(old, new, 1).encode())
            compiled = command("build", build, 0)
            for i, args in enumerate(ARGS):
                assertion = f"output refusal {i} status"
                red = command(f"red-{i}", [".lake/build/bin/CyberkrillTests", "--output-refusal", str(i)], 1, assertion)
                rows.append(dict(case=i, args=args, red=red, detecting_assertion=assertion))
                print(f"output refusal {i}: runtime red 1 ({assertion})", flush=True)
        finally:
            write(original)
        restored = command("restore-build", build, 0)
        for i, row in enumerate(rows):
            row["green"] = command(f"green-{i}", [".lake/build/bin/CyberkrillTests", "--output-refusal", str(i)], 0)
        final = command("boundaries", [".lake/build/bin/CyberkrillTests", "--output-boundaries"], 0)
        assert fingerprints(bound) == hashes, "output sources restored exactly"
        Path("test/golden/output-regression-refresh.json").write_text(json.dumps(dict(
            source_sha256=hashes, file=str(path), replace=old, with_text=new,
            build=compiled, restore_build=restored, checks=rows, restored_all=final), indent=2) + "\n")
        print("current output evidence: 18/18 runtime reds; 18/18 restored greens; all boundaries green", flush=True)
    finally:
        write(original)


def main():
    mode, = sys.argv[1:]
    if mode == "refresh":
        refresh()
        return
    assert mode in ["before", "after"]
    os.chdir(APP)
    logs = APP / ".lake/output-regressions"
    logs.mkdir(parents=True, exist_ok=True)
    path = APP / "test/golden/output-regression-record.json"
    record = {} if mode == "before" else json.loads(path.read_text())
    tests = fingerprints(FILES)
    if mode == "after":
        assert record["before"]["tests_sha256"] == tests, "output regression tests changed after reds"
    rows = []
    assert len(ARGS) == 18
    print("independent output-option regressions: 18/18", flush=True)
    for i, args in enumerate(ARGS):
        command = ["timeout", "--foreground", "30", ".lake/build/bin/CyberkrillTests", "--output-refusal", str(i)]
        start = time.monotonic()
        p = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
        elapsed = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            (logs / f"{mode}-{i}.{stream}").write_bytes(getattr(p, stream))
        (logs / f"{mode}-{i}.status").write_text(str(p.returncode) + "\n")
        expected = 1 if mode == "before" else 0
        assertion = f"output refusal {i} status"
        assert p.returncode == expected, f"output regression {mode} {i}: unexpected exit {p.returncode}"
        if expected:
            assert p.stderr.decode() == f"assertion failed: {assertion}\n", f"output regression wrong assertion {i}"
        rows.append(dict(case=i, args=args, command=command, status=p.returncode,
                         seconds=elapsed, detecting_assertion=assertion if expected else ""))
        print(f"{mode} output {i}: exit {p.returncode}" + (f" ({assertion})" if expected else ""), flush=True)
    record[mode] = dict(tests_sha256=tests, source_sha256=fingerprints(["Cyberkrill/App.lean"]), checks=rows)
    path.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
