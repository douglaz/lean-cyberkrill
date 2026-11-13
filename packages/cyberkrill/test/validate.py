#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Bounded foreground validation; separate streams, statuses and wall times."""
import json
from contextlib import chdir
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cases import APP, ROOT
from network import run_owned

NATIVE_SCAN = """import pathlib, re, subprocess
roots = {'Sha256', 'Secp256k1', 'Bitcoin', 'Lightning', 'FedimintInvite', 'HttpCurl', 'Cyberkrill'}
tracked = subprocess.check_output(['git', 'ls-files', '-z', '--', 'packages']).decode().split(chr(0))
paths = [pathlib.Path(p) for p in tracked if p and pathlib.Path(p).suffix == '.lean']
paths = [p for p in paths if len(p.parts) >= 3 and (p.parts[2] in roots or p.parts[2].removesuffix('.lean') in roots)]
assert len(paths) == 87, 'library/proof source inventory'
assert 'packages/cyberkrill/Cyberkrill/GenerateInvoice.lean' in {str(p) for p in paths}, 'LNURL flow source inventory'
assert 'packages/cyberkrill/Cyberkrill/FetchConfig.lean' in {str(p) for p in paths}, 'config fetch source inventory'
assert {'packages/cyberkrill/Cyberkrill/CoreRpc.lean', 'packages/cyberkrill/Cyberkrill/RpcFlags.lean'} <= {str(p) for p in paths}, 'Core RPC/flags source inventory'
assert {p.parts[2].removesuffix('.lean') for p in paths} == roots, 'library root inventory'
bad = [str(p) for p in paths if re.search(r'\\b(?:native_decide|bv_decide)\\b', p.read_text())]
assert not bad, 'native decision in library: ' + ', '.join(bad)
print(f'library/proof native-decision scan: {len(paths)}/87 tracked files; zero offenders')
"""


def main():
    mode, *selected = sys.argv[1:]
    assert not selected or mode in ["campaigns", "refresh"], "only campaign and refresh batches support named selection"
    assert mode in ["app", "repo", "evidence", "refresh", "campaigns", "fiat", "lightning", "lnurl", "http", "sandbox"]
    directory = APP / ".lake/validation"
    directory.mkdir(parents=True, exist_ok=True)
    if mode == "app":
        checks = [("build", APP, ["nix", "develop", "-c", "lake", "build"], 600),
                  ("test", APP, ["nix", "develop", "-c", "lake", "test"], 600)]
    elif mode == "http":
        package = ROOT / "packages/http-curl"
        checks = [("http-build", package, ["nix", "develop", "-c", "lake", "build"], 600),
                  ("http-test", package, ["nix", "develop", "-c", "lake", "test"], 600)]
    elif mode == "lightning":
        package = ROOT / "packages/lightning"
        checks = [("lightning-build", package, ["nix", "develop", "-c", "lake", "build"], 600),
                  ("lightning-test", package, ["nix", "develop", "-c", "lake", "test"], 600)]
    elif mode == "lnurl":
        checks = [("lnurl-replay", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/generate-invoice.py"], 300)]
    elif mode == "sandbox":
        checks = [("fresh-sandbox", ROOT, ["nix", "build", "--rebuild", "-L"], 3600)]
    elif mode == "fiat":
        checks = [
            ("fiat-build", APP, ["nix", "develop", "-c", "lake", "build", "cyberkrill", "CyberkrillTests"], 600),
            ("fiat-replay", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/fiat-onchain.py"], 300),
            ("fiat-creation-retained", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/psbt-commands.py"], 300),
            ("fiat-move-retained", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/move-utxos.py"], 300),
            ("fiat-recordings", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/rpc-recordings.py"], 300),
            ("fiat-rpc-client", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/rpc-client.py"], 300),
            ("fiat-recording-safety", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/rpc-recording-safety.py"], 180),
            ("fiat-recording-mutations", ROOT, ["nix", "develop", "-c", "python3", "-B", "packages/cyberkrill/test/rpc-recording-mutations.py"], 300),
        ]
    elif mode == "evidence":
        checks = [
            ("config-replay", ROOT, ["python3", "-B", "packages/cyberkrill/test/fetch-config.py"], 300),
            ("config-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/fetch-config-mutations.py", "--verify"], 120),
            ("lnurl-replay", ROOT, ["python3", "-B", "packages/cyberkrill/test/generate-invoice.py"], 300),
            ("lnurl-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/generate-invoice-mutations.py", "--verify"], 120),
            ("fiat-onchain", ROOT, ["python3", "-B", "packages/cyberkrill/test/fiat-onchain.py"], 300),
            ("fiat-onchain-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/fiat-onchain-mutations.py", "--verify"], 120),
            ("price-feeds", ROOT, ["python3", "-B", "packages/cyberkrill/test/price-feeds.py"], 240),
            ("price-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/price-mutations.py", "--verify"], 120),
            ("move-scope-bytes", ROOT, ["python3", "-B", "packages/cyberkrill/test/move-utxos.py", "scope-bytes"], 120),
            ("move-utxos", ROOT, ["python3", "-B", "packages/cyberkrill/test/move-utxos.py"], 240),
            ("move-utxos-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/move-utxos-mutations.py", "--verify"], 120),
            ("psbt-commands", ROOT, ["python3", "-B", "packages/cyberkrill/test/psbt-commands.py"], 240),
            ("psbt-commands-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/psbt-commands-mutations.py", "--verify"], 120),
            ("list-utxos", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos.py"], 180),
            ("list-utxos-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-mutations.py", "--verify"], 120),
            ("list-utxos-lexical-mutations", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-lexical-mutations.py", "--verify"], 120),
            ("list-utxos-lifecycle", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-lifecycle.py"], 120),
            ("list-utxos-lifecycle-evidence", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-lifecycle.py", "--verify"], 120),
            ("fifo", ROOT, ["python3", "-B", "packages/cyberkrill/test/fifo.py"], 90),
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
    elif mode == "campaigns":
        checks = [
            ("http-negative", ROOT / "packages/http-curl", ["python3", "-B", "check-negative-mutations.py"], 3600),
            ("http-stub", ROOT / "packages/http-curl", ["python3", "-B", "check-stub-mutations.py"], 3600),
            ("config-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/fetch-config-mutations.py"], 3600),
            ("lnurl-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/generate-invoice-mutations.py"], 2400),
            ("fiat-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/fiat-onchain-mutations.py"], 2400),
            ("price-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/price-mutations.py"], 7200),
            ("move-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/move-utxos-mutations.py"], 7200),
            ("creation-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/psbt-commands-mutations.py"], 7200),
            ("list-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-mutations.py"], 7200),
            ("lexical-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-lexical-mutations.py"], 3600),
            ("lifecycle-record", ROOT, ["python3", "-B", "packages/cyberkrill/test/list-utxos-lifecycle.py", "--record"], 300),
            ("rpc-campaign", ROOT, ["python3", "-B", "packages/cyberkrill/test/rpc-client-mutations.py"], 14400),
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
    if selected:
        assert len(selected) == len(set(selected)) and set(selected) <= {c[0] for c in checks}, "known distinct campaign names"
        checks = [c for c in checks if c[0] in selected]
    records = []
    for name, cwd, args, limit in checks:
        if mode in ["campaigns", "refresh"] and name != "lifecycle-record":
            args = ["nix", "develop", "-c", *args]
        start = time.monotonic()
        # Keep an owned, existing temp parent for the complete child lifetime.
        # A development shell may replace TMPDIR, so restore it explicitly at
        # that boundary before Lake/Lean starts.
        with tempfile.TemporaryDirectory(prefix=name + "-tmp-", dir=directory) as temporary:
            environment = dict(os.environ, TMPDIR=temporary, PYTHONDONTWRITEBYTECODE="1")
            command = args
            if args[:3] == ["nix", "develop", "-c"]:
                command = args[:3] + ["env", "TMPDIR=" + temporary, *args[3:]]
            with chdir(cwd):
                proc = run_owned(["timeout", "--foreground", str(limit), *command],
                                 env=environment, capture_output=True, timeout=limit+10)
        elapsed = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            (directory / (name + "." + stream)).write_bytes(getattr(proc, stream))
        (directory / (name + ".status")).write_text(str(proc.returncode) + "\n")
        records.append(dict(command=command, cwd=str(cwd.relative_to(ROOT)) or ".",
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
