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
assert len(paths) == 78, 'library/proof source inventory'
assert {'packages/cyberkrill/Cyberkrill/CoreRpc.lean', 'packages/cyberkrill/Cyberkrill/RpcFlags.lean'} <= {str(p) for p in paths}, 'Core RPC/flags source inventory'
assert {p.parts[2].removesuffix('.lean') for p in paths} == roots, 'library root inventory'
bad = [str(p) for p in paths if re.search(r'\\b(?:native_decide|bv_decide)\\b', p.read_text())]
assert not bad, 'native decision in library: ' + ', '.join(bad)
print(f'library/proof native-decision scan: {len(paths)}/78 tracked files; zero offenders')
"""


def main():
    mode, = sys.argv[1:]
    assert mode in ["app", "repo", "evidence", "refresh"]
    directory = APP / ".lake/validation"
    directory.mkdir(parents=True, exist_ok=True)
    if mode == "app":
        checks = [("build", APP, ["nix", "develop", "-c", "lake", "build"], 600),
                  ("test", APP, ["nix", "develop", "-c", "lake", "test"], 600)]
    elif mode == "evidence":
        checks = [
            ("rpc-client", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-client.py"], 180),
            ("network-safety", ROOT, ["python3", "-B", "packages/cyberkrill/test/network-safety.py"], 120),
            ("rpc-client-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-client-mutations.py", "--verify"], 120),
            ("rpc-recordings", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-recordings.py"], 180),
            ("rpc-safety", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-recording-safety.py"], 120),
            ("rpc-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-recording-mutations.py"], 180),
            ("evidence", ROOT, ["python3", "-B", "packages/cyberkrill/test/verify.py"], 300),
            ("harness", ROOT, ["python3", "-B", "packages/cyberkrill/test/selftest.py"], 300),
            ("scope", ROOT, ["python3", "-B", "packages/cyberkrill/test/scope.py"], 120),
            ("scope-shapes", ROOT, ["python3", "-B", "packages/cyberkrill/test/revisions.py", "--scope"], 120),
            ("lightning", ROOT, ["python3", "-B", "packages/cyberkrill/test/lightning.py"], 180),
            ("revisions", ROOT, ["python3", "-B", "packages/cyberkrill/test/revisions.py"], 180),
            ("offline-evidence", ROOT, ["python3", "-B", "packages/cyberkrill/test/offline.py", "--evidence"], 120),
            ("offline-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/offline-mutate.py", "--verify"], 120),
            ("history-recapture", ROOT, ["python3", "-B", "packages/cyberkrill/test/recapture-history.py", "--verify"], 120),
            ("exact-comparator", ROOT, ["python3", "-B", "packages/cyberkrill/test/offline-exact-selftest.py", "--verify"], 120),
            ("ordered-help", ROOT, ["python3", "-B", "packages/cyberkrill/test/ordered-help.py"], 120),
            ("cluster-help", ROOT, ["python3", "-B", "packages/cyberkrill/test/cluster-help.py"], 120),
            ("cluster-regressions", ROOT, ["python3", "-B", "packages/cyberkrill/test/cluster-regressions.py", "--verify"], 120),
            ("carried-help", ROOT, ["python3", "-B", "packages/cyberkrill/test/carried-help.py"], 120),
            ("carried-regressions", ROOT, ["python3", "-B", "packages/cyberkrill/test/carried-regressions.py", "--verify"], 120),
            ("file-observation", ROOT, ["python3", "-B", "packages/cyberkrill/test/file-observation.py"], 120),
            ("ordered-boundary-regressions", ROOT, ["python3", "-B", "packages/cyberkrill/test/boundary-regressions.py", "--verify"], 120),
        ]
    elif mode == "refresh":
        checks = [
            ("retained-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/mutate.py"], 3000),
            ("lightning-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/lightning-mutate.py"], 3000),
            ("revision-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/revision-mutate.py"], 3000),
            ("regression-refresh", ROOT, ["python3", "-B", "packages/cyberkrill/test/refresh-regressions.py"], 1800),
            ("output-refresh", ROOT, ["python3", "-B", "packages/cyberkrill/test/output-regressions.py", "refresh"], 600),
            ("attached-refresh", ROOT, ["python3", "-B", "packages/cyberkrill/test/refresh-attached-output.py"], 600),
            ("history-recapture", ROOT, ["python3", "-B", "packages/cyberkrill/test/recapture-history.py"], 1900),
            ("capture-check", ROOT, ["python3", "-B", "packages/cyberkrill/test/capture-offline.py", "--check"], 1900),
            ("port-check", ROOT, ["python3", "-B", "packages/cyberkrill/test/record-offline.py", "--check"], 180),
            ("offline-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/offline-mutate.py"], 6000),
        ]
    else:
        checks = [
            ("flake-check", ROOT, ["nix", "flake", "check", "-L"], 3600),
            ("nix-build", ROOT, ["nix", "build", "-L"], 3600),
            ("installed-version", ROOT, ["./result/bin/cyberkrill", "version"], 30),
            ("installed-lightning", ROOT, ["python3", "-B", "packages/cyberkrill/test/lightning.py", "--installed"], 90),
            ("installed-offline", ROOT, ["python3", "-B", "packages/cyberkrill/test/offline.py", "--installed"], 90),
            ("installed-rpc-replay", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-recordings.py"], 180),
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
