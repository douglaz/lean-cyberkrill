#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Reintroduce the equals-attachment defect against unchanged current tests."""
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
import signal
import subprocess

from cases import APP


def main():
    os.chdir(APP)
    path = Path("Cyberkrill/App.lean")
    original = path.read_bytes()
    old, new = '(args.head?.getD "") :: outputParserArgs args.tail else args', '(args.head?.getD "") :: args.tail else args'
    assert original.decode().count(old) == 1
    bound = [path, Path(__file__).relative_to(APP), Path("CyberkrillTests.lean"),
        Path("test/attached-output-regressions.py"), *sorted(Path("CyberkrillTests").glob("*.lean"))]
    hashes = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in bound}
    logs = Path(".lake/attached-output-refresh")
    logs.mkdir(parents=True, exist_ok=True)

    managed = [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]
    def write(data):
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            path.write_bytes(data)
            assert path.read_bytes() == data
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def restore():
        write(original)

    def interrupted(signum, _):
        restore()
        raise SystemExit(128 + signum)

    for signum in managed:
        signal.signal(signum, interrupted)

    def command(label, args, expected):
        p = subprocess.run(["timeout", "--foreground", "180", *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=190)
        for stream in ["stdout", "stderr"]: (logs / (label + "." + stream)).write_bytes(getattr(p, stream))
        assert p.returncode == expected, "attached refresh status: " + label
        return dict(command=args, status=p.returncode), p.stderr.decode()

    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    rows = []
    try:
        write(original.decode().replace(old, new, 1).encode())
        compiled, _ = command("red-build", build, 0)
        for i, token in enumerate(import_module("attached-output-regressions").CASES):
            args = [".lake/build/bin/CyberkrillTests", "--output-equals", str(i)]
            red, error = command("red-" + str(i), args, 1 if i < 4 else 0)
            assertion = f"output equals {i} status" if i < 4 else ""
            assert error == (f"assertion failed: {assertion}\n" if assertion else "")
            rows.append(dict(case=i, token=token, red=red, detecting_assertion=assertion))
    finally:
        restore()
    restored, _ = command("restore-build", build, 0)
    for row in rows:
        row["green"], _ = command("green-" + str(row["case"]), row["red"]["command"], 0)
    assert {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in bound} == hashes
    Path("test/golden/attached-output-refresh.json").write_text(json.dumps(dict(source_sha256=hashes,
        replace=old, with_text=new, build=compiled, restore_build=restored, checks=rows), indent=2) + "\n", encoding="utf-8")
    print("current attached output: 4/4 runtime reds, 4/4 controls, 8/8 restored greens")


if __name__ == "__main__":
    main()
