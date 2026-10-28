#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture pinned reference file outcomes using explicitly public RNG input."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cases import APP, BUILD, PIN, ROOT


def main():
    built = subprocess.run(BUILD, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=1800)
    assert built.returncode == 0, "pinned reference build failed"
    producer = Path(built.stdout.decode().strip()) / "bin/cyberkrill"
    rows = []
    with tempfile.TemporaryDirectory(prefix="private-reference-", dir=os.environ["TMPDIR"]) as scratch:
        root = Path(scratch)
        for kind in ["regular", "symlink", "dangling-symlink", "hardlink", "device"]:
            repeats = []
            for repetition in range(2):
                home = root / (kind + str(repetition))
                home.mkdir()
                target, backing = home / "output.json", home / "backing.json"
                if kind == "regular": target.write_bytes(b"public-sentinel")
                elif kind in ["symlink", "hardlink"]:
                    backing.write_bytes(b"public-sentinel")
                    if kind == "symlink": target.symlink_to(backing)
                    else: os.link(backing, target)
                elif kind == "dangling-symlink": target.symlink_to(backing)
                else: target = Path("/dev/null")
                command = ["unshare", "-rn", "sh", "-c",
                    'ip link set lo up && umask 022 && exec timeout --foreground 30 "$@"', "capture",
                    "python3", "-B", str(APP / "test/reference-entropy.py"), str(producer), str(target), str(home / "entropy.json")]
                result = subprocess.run(command, cwd=home, env={**os.environ, "HOME": str(home)},
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
                logs = APP / ".lake/private-reference"
                logs.mkdir(parents=True, exist_ok=True)
                (logs / (kind + ".stdout")).write_bytes(result.stdout)
                (logs / (kind + ".stderr")).write_bytes(result.stderr)
                (logs / (kind + ".status")).write_text(str(result.returncode) + "\n", encoding="utf-8")
                assert result.returncode == 0 and result.stdout == result.stderr == b"", "reference private-output capture failed: " + kind
                evidence = json.loads((home / "entropy.json").read_bytes())
                assert evidence["status"] == 0 and 32 in evidence["getrandom_sizes"]
                if kind != "device":
                    payload = target.read_bytes()
                    value = json.loads(payload)
                    assert set(value) == {"mnemonic", "words", "entropy_bits"} and value["words"] == 12 and value["entropy_bits"] == 128
                    assert len(value["mnemonic"].split()) == 12
                    evidence["output_sha256"] = hashlib.sha256(payload).hexdigest()
                    assert target.stat().st_mode & 0o777 == 0o644, "reference default permissions"
                repeats.append(evidence)
            assert repeats[0] == repeats[1], "reference public-entropy reproducibility"
            rows.append(dict(id="mnemonic-output-" + kind, kind=kind,
                reference=dict(status=0, stdout="", stderr=""), repetitions=repeats))
    bound = ["test/capture-private-output.py", "test/reference-entropy.py"]
    record = dict(provenance=dict(source="https://github.com/douglaz/cyberkrill", commit=PIN,
        path="cyberkrill/src/main.rs:2649-2697", licence="MIT OR Apache-2.0, taken under MIT",
        build=BUILD, build_status=built.returncode, producer=str(producer),
        execution="unshare -rn; loopback only; temporary HOME; closed stdin; timeout; umask 022; two executions per case",
        entropy="Capture-only ptrace replaces main-thread getrandom before kernel execution with repeated published BIP39 vector 0 bytes. The pinned RNG derives synthetic public entropy; no unpredictable phrase is drawn or retained.",
        fixture="packages/bitcoin/test-data/bip39-english-vectors.json",
        fixture_sha256=hashlib.sha256((ROOT / "packages/bitcoin/test-data/bip39-english-vectors.json").read_bytes()).hexdigest(),
        script_sha256={p:hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in bound}), cases=rows)
    (APP / "test/golden/private-output-reference.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("private output reference: 5/5 outcomes; two identical public-entropy executions each")


if __name__ == "__main__":
    main()
