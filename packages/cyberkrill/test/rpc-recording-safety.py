#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Refusal-only entry checks and portable recording checks; never launch a node."""
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

G = importlib.import_module("generate-rpc-recordings")
KEY_PATTERN = r"[tuvxyzUVYZ]prv[1-9A-HJ-NP-Za-km-z]{100,}"
HOST_PATTERN = r"/(?:home|Users|root|tmp|var/tmp|nix/store)/|/run/user/|[A-Za-z]:[\\/](?:Users|Windows)[\\/]"


def portable(name, data):
    text = data.decode("utf-8")
    assert re.search(KEY_PATTERN, text) is None, "private extended key in recording"
    assert re.search(HOST_PATTERN, text) is None, "host path in recording"
    assert re.search(r"(?<![A-Za-z0-9])[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])", text) is None, "WIF-shaped recording material"
    if name == "bitcoin-dir/.cookie":
        assert data == G.COOKIE, "fixed disposable cookie"
        return
    value = json.loads(text)
    def visit(obj):
        if isinstance(obj, dict):
            assert not ({"seed", "seed_bytes", "private_key", "privatekey", "mnemonic", "rpcpassword", "password"} & obj.keys()) or name == "shared/provenance.json", "private field in recording"
            for key, item in obj.items():
                if key == "authorization": assert item == G.AUTH, "unexpected recording credentials"
                visit(item)
        elif isinstance(obj, list):
            for item in obj: visit(item)
        elif isinstance(obj, str):
            assert not obj.startswith("Basic ") or obj == G.AUTH, "unexpected Basic credentials"
            if obj.lstrip().startswith(('{', '[')):
                try: nested = json.loads(obj)
                except ValueError: return
                visit(nested)
    visit(value)


def scan(root):
    assert root.is_dir() and not root.is_symlink(), "real recording directory required"
    proc = subprocess.run(["grep", "-rEn", KEY_PATTERN + "|" + "/" + "home/", str(root)], stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=15)
    assert proc.returncode == 1, "recording safety grep requires exit 1"
    files = list(root.rglob("*"))
    assert files, "nonempty recording tree"
    for path in files:
        assert not path.is_symlink(), "no recording symlink"
        if path.is_file(): portable(path.relative_to(root).as_posix(), path.read_bytes())


def refusals():
    username = subprocess.run(["id", "-un"], check=True, capture_output=True, timeout=5).stdout.decode().strip()
    passwd = subprocess.run(["getent", "passwd", username], check=True, capture_output=True, timeout=5).stdout.decode().split(":")
    # Construct strings only. Never stat/read/create anything in this owner tree.
    unsafe = passwd[5] + "/.bitcoin/not-created-recording-guard"
    cases = [(["--datadir", unsafe], "refused real-home bitcoin datadir"),
             (["--rpcport", "8332"], "refused unsafe/default port"),
             (["--port", "8333"], "refused unsafe/default port"),
             (["--rpcport", "8333"], "refused unsafe/default port"),
             (["--port", "8332"], "refused unsafe/default port"),
             (["--rpcport", "18443"], "refused unsafe/default port"),
             (["--network", "mainnet"], "refused non-regtest network"),
             (["--rpc-host", "example.invalid"], "refused non-loopback RPC host")]
    for args, assertion in cases:
        proc = subprocess.run([sys.executable, "-B", str(G.HERE / "generate-rpc-recordings.py"), *args], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=10)
        assert proc.returncode == 1 and not proc.stdout and assertion in proc.stderr.decode(), "entry refusal: " + assertion
        assert b"owned datadir=" not in proc.stderr, "guard before creation/launch"
    print(f"RPC entry refusals: {len(cases)}/8 (real-home string only, ports and network)")


def main():
    # Relative to the package, independent of the invoking working directory.
    scan(G.HERE.parent / "test/recordings")
    refusals()
    print("RPC recording safety: grep exit 1, portable data and disposable credentials")


if __name__ == "__main__": main()
