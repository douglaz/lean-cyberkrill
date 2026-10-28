#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Bounded foreground validation; separate streams, statuses and wall times."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from cases import APP, ROOT


def main():
    mode, = sys.argv[1:]
    assert mode in ["app", "repo"]
    directory = APP / ".lake/validation"
    directory.mkdir(parents=True, exist_ok=True)
    if mode == "app":
        checks = [("build", APP, ["nix", "develop", "-c", "lake", "build"], 600),
                  ("test", APP, ["nix", "develop", "-c", "lake", "test"], 600)]
    else:
        checks = [
            ("flake-check", ROOT, ["nix", "flake", "check", "-L"], 3600),
            ("nix-build", ROOT, ["nix", "build", "-L"], 3600),
            ("installed-version", ROOT, ["./result/bin/cyberkrill", "version"], 30),
            ("proof-token-scan", ROOT, ["bash", "-c", 'rc=0; grep -rnw sorry --include="*.lean" --exclude-dir=.lake packages || rc=$?; test "$rc" -eq 1'], 60),
            ("private-key-scan", ROOT, ["bash", "-c", 'rc=0; grep -rEn --exclude-dir=.lake "[tuvxyzUVYZ]prv[1-9A-HJ-NP-Za-km-z]{100,}" packages || rc=$?; test "$rc" -eq 1'], 60),
        ]
    records = []
    for name, cwd, args, limit in checks:
        start = time.monotonic()
        proc = subprocess.run(["timeout", "--foreground", str(limit), *args], cwd=cwd,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=limit+10)
        elapsed = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            (directory / (name + "." + stream)).write_bytes(getattr(proc, stream))
        (directory / (name + ".status")).write_text(str(proc.returncode) + "\n")
        records.append(dict(command=args, cwd=str(cwd.relative_to(ROOT)) or ".",
                            status=proc.returncode, seconds=elapsed))
        (directory / (mode + ".json")).write_text(json.dumps(records, indent=2) + "\n")
        print(f"{name}: exit {proc.returncode}, {elapsed:.3f}s", flush=True)
        if proc.returncode:
            sys.stdout.buffer.write(proc.stdout)
            sys.stderr.buffer.write(proc.stderr)
            return proc.returncode
        if name == "installed-version":
            assert json.loads(proc.stdout) == {"version": "0.1.0"}
    return 0


if __name__ == "__main__":
    sys.exit(main())
