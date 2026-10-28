#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture only deterministic offline behavior from the one permitted producer."""
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from cases import APP, BUILD, PIN, ROOT, WORD_COUNT_FAILURES, cases


def main():
    logs = APP / ".lake/capture"
    logs.mkdir(parents=True, exist_ok=True)
    build = subprocess.run(BUILD, cwd=ROOT, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=1800)
    for stream in ["stdout", "stderr"]:
        (logs / f"build.{stream}").write_bytes(getattr(build, stream))
    (logs / "build.status").write_text(str(build.returncode) + "\n")
    if build.returncode:
        raise RuntimeError("Required producer build failed; see separate build logs")
    producer = Path(build.stdout.decode().strip()) / "bin/cyberkrill"
    assert producer.is_file()
    records = []
    home = Path(tempfile.mkdtemp(prefix="cli-capture-", dir=os.environ["TMPDIR"]))
    try:
        for case in cases():
            args = case["args"]
            if args[0] == "convert-amount":
                # Reject every recognizable fiat suffix, including malformed numbers.
                for token in args[1:]:
                    match = re.search(r"[0-9.,]([^0-9.,]*)$", token.strip())
                    if match:
                        unit = match[1].strip().lower()
                        assert not (len(unit) == 3 and unit.isascii() and unit.isalpha()
                                    and unit not in ["btc", "sat"])
            if args[0] == "generate-mnemonic":
                safe = {("-w", "11"), ("-w", "bad"), ("--seed", "unused"),
                        ("-w", "12", "--words", "24")}
                safe.update(("-w", value) for value in WORD_COUNT_FAILURES)
                assert tuple(args[1:]) in safe, "only enumerated pre-entropy mnemonic failures"
            command = ["unshare", "-rn", "sh", "-c",
                       'ip link set lo up && exec timeout --foreground 15 "$@"', "capture",
                       str(producer), *args]
            proc = subprocess.run(command, cwd=home, env={**os.environ, "HOME": str(home)},
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
            assert proc.returncode not in [124, 137], case["id"]
            if args[0] == "generate-mnemonic":
                assert proc.returncode != 0 and proc.stdout == b"", "mnemonic capture must refuse before entropy"
            records.append({**case, "result": {"status": proc.returncode,
                            "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode()}})
    finally:
        # These commands create no files in HOME. Refuse cleanup of unexpected content.
        home.rmdir()
    path = APP / "test/golden/reference.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, ensure_ascii=True, indent=2) + "\n")
    (path.parent / "provenance.json").write_text(json.dumps({
        "source": "https://github.com/douglaz/cyberkrill", "commit": PIN,
        "path": "cyberkrill/src/main.rs", "licence": "MIT OR Apache-2.0, taken under MIT",
        "build": BUILD, "build_status": build.returncode,
        "producer": str(producer), "cases": len(records),
        "construction": "Authored synthetic inputs from cases.py, including the 124 existing amount grammar cases; not published vectors",
        "execution": "unshare -rn sh -c 'ip link set lo up && exec timeout --foreground 15 \"$@\"' capture \"$PRODUCER\" ...; temporary HOME; closed stdin; separate streams/status",
    }, indent=2) + "\n")
    bound = [path, path.parent / "provenance.json", Path(__file__), Path(__file__).with_name("cases.py")]
    (path.parent / "capture-digests.json").write_text(json.dumps({
        str(p.relative_to(APP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound
    }, indent=2) + "\n")
    assert len(records) == 179
    print(f"reference captures: {len(records)}/179")


if __name__ == "__main__":
    main()
