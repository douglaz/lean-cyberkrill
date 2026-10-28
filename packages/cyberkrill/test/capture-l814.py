#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Observe the mandatory L814 reference stop gate before implementation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cases import APP, BUILD, PIN, ROOT


def main():
    source = ROOT / "packages/lightning/test-data/bolt11.json"
    vectors = json.loads(source.read_bytes())
    inventory = {name: len(vectors[name]) for name in
                 ["valid", "invalid", "negative", "positive", "nfields"]}
    assert inventory == dict(valid=16, invalid=15, negative=20, positive=4, nfields=2)
    matches = [row for row in vectors["invalid"] if row["name"] == "L814"]
    assert len(matches) == 1 and matches[0]["line"] == 814
    row = matches[0]
    logs = APP / ".lake/l814-stop"
    logs.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    build = subprocess.run(BUILD, cwd=ROOT, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=1800)
    build_seconds = time.monotonic() - started
    for stream in ["stdout", "stderr"]:
        (logs / f"build.{stream}").write_bytes(getattr(build, stream))
    (logs / "build.status").write_text(str(build.returncode) + "\n")
    (logs / "build.seconds").write_text(str(build_seconds) + "\n")
    assert build.returncode == 0, "required pinned producer build failed; see separate build logs"
    producer = Path(build.stdout.decode().strip()) / "bin/cyberkrill"
    assert producer.is_file()
    args = ["ln-decode-invoice", row["invoice"]]
    command = ["unshare", "-rn", "sh", "-c",
               'ip link set lo up && exec timeout --foreground 15 "$@"',
               "capture", str(producer), *args]
    home = Path(tempfile.mkdtemp(prefix="l814-capture-", dir=os.environ["TMPDIR"]))
    try:
        started = time.monotonic()
        proc = subprocess.run(command, cwd=home, env={**os.environ, "HOME": str(home)},
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        seconds = time.monotonic() - started
    finally:
        home.rmdir()
    assert proc.returncode not in [124, 137], "reference stop gate timed out"
    assert b"unshare:" not in proc.stderr and b"ip:" not in proc.stderr, "capture isolation failed"
    for stream in ["stdout", "stderr"]:
        (logs / f"capture.{stream}").write_bytes(getattr(proc, stream))
    (logs / "capture.status").write_text(str(proc.returncode) + "\n")
    record = {
        "id": "invalid/L814", "args": args,
        "source": "packages/lightning/test-data/bolt11.json",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "inventory": inventory, "captures": 1,
        "result": {"status": proc.returncode, "stdout": proc.stdout.decode(),
                   "stderr": proc.stderr.decode()},
        "seconds": seconds,
    }
    golden = APP / "test/golden/l814-reference.json"
    golden.write_text(json.dumps(record, indent=2) + "\n")
    provenance = {
        "source": "https://github.com/douglaz/cyberkrill", "commit": PIN,
        "paths": ["cyberkrill/src/main.rs", "cyberkrill-core/src/decoder.rs"],
        "licence": "MIT OR Apache-2.0, taken under MIT",
        "build": BUILD, "build_status": build.returncode, "build_seconds": build_seconds,
        "producer": "$PRODUCER",
        "execution": 'unshare -rn sh -c \'ip link set lo up && exec timeout --foreground 15 "$@"\' capture "$PRODUCER" ln-decode-invoice "$INVOICE"',
        "isolation": "temporary HOME and cwd; closed stdin; separate byte-preserving streams and status",
        "input_provenance": {
            "source": "https://github.com/lightning/bolts", "commit": "191462825ae341f0a27098765c075f01ca9bc6c2",
            "path": "11-payment-encoding.md", "line": 814,
            "attribution": "lightning/bolts contributors", "licence": "CC-BY-4.0",
            "changes": "extracted and reformatted; invoice bytes unchanged",
        },
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "record_sha256": hashlib.sha256(golden.read_bytes()).hexdigest(),
    }
    (golden.parent / "l814-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"BOLT11 source inventory: {sum(inventory.values())}/57; stop-gate captures: 1/1")
    print(f"producer build: status {build.returncode}, {build_seconds:.3f}s")
    print(f"invalid/L814: status {proc.returncode}, {seconds:.3f}s")
    print("stdout:", repr(proc.stdout))
    print("stderr:", repr(proc.stderr))


if __name__ == "__main__":
    main()
