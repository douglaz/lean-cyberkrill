#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture synthetic regression inputs from the isolated pinned offline CLI."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

from cases import APP, BUILD, PIN, ROOT
import revisions


def main():
    logs = APP / ".lake/revision-capture"
    logs.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    build = subprocess.run(BUILD, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=1800)
    seconds = round(time.monotonic() - start, 3)
    for stream in ["stdout", "stderr"]: (logs / ("build." + stream)).write_bytes(getattr(build, stream))
    (logs / "build.status").write_text(str(build.returncode) + "\n")
    assert build.returncode == 0, "required pinned producer build"
    producer = Path(build.stdout.decode().strip()) / "bin/cyberkrill"
    original = json.loads((APP / "test/golden/lightning-reference.json").read_bytes())
    inputs = revisions.CASES.cases(original)
    rows = []
    for row in inputs:
        result, outputs, elapsed = revisions.execute(producer, row, isolated=True)
        rows.append({**row, "result": result, "output_bytes": outputs, "seconds": elapsed})
    row = revisions.CASES.decode_case(rows)
    result, outputs, elapsed = revisions.execute(producer, row, isolated=True)
    rows.append({**row, "result": result, "output_bytes": outputs, "seconds": elapsed})
    revisions.GOLDEN.write_text(json.dumps(rows, indent=2, ensure_ascii=True) + "\n")
    bound = [revisions.GOLDEN, APP / "test/capture-revisions.py", APP / "test/revision-cases.py",
             APP / "test/revisions.py", APP / "test/golden/lightning-reference.json", APP / "test/public-forms.py"]
    provenance = dict(source="https://github.com/douglaz/cyberkrill", commit=PIN,
                      paths=["cyberkrill/src/main.rs", "cyberkrill-core/src/decoder.rs"],
                      licence="MIT OR Apache-2.0, taken under MIT", build=BUILD, build_status=0,
                      build_seconds=seconds, producer=str(producer), count=len(rows),
                      construction="Synthetic JSON substitutions and disposable files derived from the published L410/L516 captures; decompression-only public key forms. Existing BOLT11 CC-BY-4.0 provenance retained.",
                      execution='unshare -rn sh -c \'ip link set lo up && exec timeout --foreground 15 "$@"\' capture "$PRODUCER" ...',
                      isolation="Temporary HOME/cwd; separate stdout/stderr/status and output existence/bytes; deterministic supplied input or closed stdin; finite foreground processes.",
                      parser_source="https://docs.rs/crate/chrono/0.4.42/source/src/format/parse.rs; scan.rs; parsed.rs; datetime/serde.rs",
                      sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound})
    (APP / "test/golden/revision-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"revision captures: {len(rows)}; producer build exit 0, {seconds:.3f}s")
    for group in ["timestamp", "unicode", "sequence", "simnet", "output"]:
        selected = [r for r in rows if r["id"].startswith(group + "/")]
        print(group, len(selected), "accepted", sum(r["result"]["status"] == 0 for r in selected))


if __name__ == "__main__": main()
