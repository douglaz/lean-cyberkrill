#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture offline Lightning handlers from the required isolated pinned producer."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cases import APP, BUILD, PIN, ROOT


def main():
    cases = importlib.import_module("lightning-cases")
    logs = APP / ".lake/lightning-capture"
    logs.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    build = subprocess.run(BUILD, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=1800)
    build_seconds = time.monotonic() - started
    for stream in ["stdout", "stderr"]: (logs / ("build." + stream)).write_bytes(getattr(build, stream))
    (logs / "build.status").write_text(str(build.returncode) + "\n")
    assert build.returncode == 0, "required producer build failed"
    producer = Path(build.stdout.decode().strip()) / "bin/cyberkrill"
    assert producer.is_file()
    home = Path(tempfile.mkdtemp(prefix="lightning-capture-", dir=os.environ["TMPDIR"]))
    records = []
    routing = []

    def capture(row):
        args = [cases.SPEC_KEY if a == "{published_key}" else a for a in row["args"]]
        command = ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec timeout --foreground 15 "$@"',
                   "capture", str(producer), *args]
        payload = row.get("input")
        started = time.monotonic()
        proc = subprocess.run(command, cwd=home, env={**os.environ, "HOME": str(home)},
                              input=payload.encode() if payload is not None else None,
                              stdin=subprocess.DEVNULL if payload is None else None,
                              capture_output=True, timeout=20)
        assert proc.returncode not in [124, 137], row["id"]
        assert b"unshare:" not in proc.stderr and b"ip:" not in proc.stderr, row["id"]
        assert cases.SPEC_KEY.encode() not in proc.stdout + proc.stderr, "key disclosure"
        item = {**row, "result": dict(status=proc.returncode, stdout=proc.stdout.decode(), stderr=proc.stderr.decode()),
                "seconds": time.monotonic() - started}
        records.append(item)
        return item

    try:
        for row in cases.inventory():
            item = capture(row)
            if row["id"] == "invalid/L814":
                assert item["result"]["status"] == 0, "L814 stop: record and defer before continuing"
        spec = [r for r in records if r.get("spec")]
        assert len(spec) == 31
        for row in spec:
            row["encoding_applicability"] = "decoded reference JSON" if row["result"]["status"] == 0 else "reference decode failed; no JSON"
            if row["result"]["status"] == 0:
                capture(dict(id="encode/" + row["id"], args=["ln-encode-invoice", "-", "-k", "{published_key}"],
                             input=row["result"]["stdout"]))
        for row in cases.builder_cases(records): capture(row)
        for row in cases.json_cases(records): capture(row)
        for row in cases.routing_cases(records):
            paths = set(row["files"]) | set(row["outputs"])
            try:
                for name, value in row["files"].items(): (home / name).write_text(value, encoding="utf-8")
                item = capture(row)
                item["output_bytes"] = {name: (home / name).read_bytes().hex() if (home / name).is_file() else None for name in row["outputs"]}
                routing.append(records.pop())
            finally:
                for name in paths:
                    path = home / name
                    if path.exists(): path.unlink()
    finally:
        home.rmdir()
    golden = APP / "test/golden/lightning-reference.json"
    golden.write_text(json.dumps(records, indent=2, ensure_ascii=True) + "\n")
    routing_golden = golden.parent / "lightning-routing-reference.json"
    routing_golden.write_text(json.dumps(routing, indent=2, ensure_ascii=True) + "\n")
    inputs = [ROOT / "packages/lightning/test-data" / n for n in
              ["bolt11.json", "bolt11.json.provenance", "lnurl.json", "lnurl.json.provenance",
               "lnurl-reference.json", "lnurl-reference.json.provenance"]]
    bound = inputs + [Path(__file__), APP / "test/lightning-cases.py", APP / "test/public-forms.py", golden, routing_golden]
    provenance = dict(source="https://github.com/douglaz/cyberkrill", commit=PIN,
                      paths=["cyberkrill/src/main.rs", "cyberkrill-core/src/decoder.rs"],
                      licence="MIT OR Apache-2.0, taken under MIT", build=BUILD, build_status=build.returncode,
                      build_seconds=build_seconds, producer=str(producer),
                      execution='unshare -rn sh -c \'ip link set lo up && exec timeout --foreground 15 "$@"\' capture "$PRODUCER" ...',
                      isolation="temporary HOME/cwd; closed stdin except published JSON; separate streams/status",
                      construction="Published BOLT11 vectors with their unchanged CC-BY-4.0 provenance; authored LNURL vectors and synthetic derived builder JSON. See bound provenance sidecars.",
                      counts=dict(bolt11=57, lnurl=92, spec=31, encoded_spec=sum(r['id'].startswith('encode/') for r in records),
                                  builder=34, json=sum(r['id'].startswith('json/') for r in records),
                                  routing=len(routing), total=len(records) + len(routing)),
                      sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound})
    (golden.parent / "lightning-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps(provenance["counts"], sort_keys=True))
    print(f"producer build: exit {build.returncode}, {build_seconds:.3f}s")


if __name__ == "__main__":
    main()
