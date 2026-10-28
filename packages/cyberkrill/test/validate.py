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

NATIVE_SCAN = """import pathlib, re, subprocess
roots = {'Sha256', 'Secp256k1', 'Bitcoin', 'Lightning', 'FedimintInvite', 'HttpCurl', 'Cyberkrill'}
tracked = subprocess.check_output(['git', 'ls-files', '-z', '--', 'packages']).decode().split(chr(0))
paths = [pathlib.Path(p) for p in tracked if p and pathlib.Path(p).suffix == '.lean']
paths = [p for p in paths if len(p.parts) >= 3 and (p.parts[2] in roots or p.parts[2].removesuffix('.lean') in roots)]
assert len(paths) == 74, 'library/proof source inventory'
assert {p.parts[2].removesuffix('.lean') for p in paths} == roots, 'library root inventory'
bad = [str(p) for p in paths if re.search(r'\\b(?:native_decide|bv_decide)\\b', p.read_text())]
assert not bad, 'native decision in library: ' + ', '.join(bad)
print(f'library/proof native-decision scan: {len(paths)}/74 tracked files; zero offenders')
"""


def main():
    mode, = sys.argv[1:]
    assert mode in ["app", "repo", "evidence"]
    directory = APP / ".lake/validation"
    directory.mkdir(parents=True, exist_ok=True)
    if mode == "app":
        checks = [("build", APP, ["nix", "develop", "-c", "lake", "build"], 600),
                  ("test", APP, ["nix", "develop", "-c", "lake", "test"], 600)]
    elif mode == "evidence":
        checks = [
            ("evidence", ROOT, ["python3", "-B", "packages/cyberkrill/test/verify.py"], 300),
            ("harness", ROOT, ["python3", "-B", "packages/cyberkrill/test/selftest.py"], 300),
            ("scope", ROOT, ["python3", "-B", "packages/cyberkrill/test/scope.py"], 120),
            ("scope-shapes", ROOT, ["python3", "-B", "packages/cyberkrill/test/revisions.py", "--scope"], 120),
            ("lightning", ROOT, ["python3", "-B", "packages/cyberkrill/test/lightning.py"], 180),
            ("revisions", ROOT, ["python3", "-B", "packages/cyberkrill/test/revisions.py"], 180),
        ]
    else:
        checks = [
            ("flake-check", ROOT, ["nix", "flake", "check", "-L"], 3600),
            ("nix-build", ROOT, ["nix", "build", "-L"], 3600),
            ("installed-version", ROOT, ["./result/bin/cyberkrill", "version"], 30),
            ("installed-lightning", ROOT, ["python3", "-B", "packages/cyberkrill/test/lightning.py", "--installed"], 90),
            ("native-library-scan", ROOT, ["python3", "-B", "-c", NATIVE_SCAN], 60),
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
