#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Reintroduce nine historical production defects against current unchanged tests."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from cases import APP


def edits():
    app, driver, compare = "Cyberkrill/App.lean", "test/driver.py", "test/compare.py"
    rows = [
        ("word-count-rejections", app,
         "!digits.toList.all (fun c => '0' ≤ c && c ≤ '9')", 'false',
         "word-count rejection before entropy"),
        ("word-count-plus", app,
         "String.ofList (match s.toList with | '+' :: rest => rest | cs => cs)", "s",
         "mnemonic exact status 0"),
        ("bare-negative-zero", app,
         "  let (cmd, p) ← (parser.parse args)",
         '  let args := match args with\n    | ["convert-amount", input] =>\n      if ["-0", "-0.0btc", "-0.000sat"].contains input then\n        ["convert-amount", "--", input] else args\n    | _ => args\n  let (cmd, p) ← (parser.parse args)',
         "bare negative-zero refused 0"),
    ]
    for stream in ["stdout", "stderr"]:
        for ending in ["crlf", "cr"]:
            old = f'proc.{stream}.decode("utf-8")'
            rows.append((f"{stream}-{ending}", driver, old,
                         old + '.replace("\\r\\n", "\\n").replace("\\r", "\\n")',
                         f"subprocess {stream} {'CRLF' if ending == 'crlf' else 'CR'} preserved"))
    for kind in ["dotted", "bracket"]:
        rows.append((kind + "-collision", compare,
                     'field + "[" + json.dumps(key, ensure_ascii=True) + "]"',
                     'field + "." + key', kind + " leaf collision refused"))
    assert len(rows) == 9
    return rows


def main():
    os.chdir(APP)
    logs = Path(".lake/regression-refresh")
    logs.mkdir(parents=True, exist_ok=True)
    targets = [Path(p) for p in ["Cyberkrill/App.lean", "test/driver.py", "test/compare.py"]]
    originals = {p: p.read_bytes() for p in targets}
    signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def write(path, data):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            path.write_bytes(data)
            assert path.read_bytes() == data, "regression source bytes"
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def restore():
        for p, data in originals.items():
            write(p, data)

    def interrupted(signum, _):
        restore()
        raise SystemExit(128 + signum)

    for signum in signals:
        signal.signal(signum, interrupted)

    def command(label, args):
        bounded = ["timeout", "--foreground", "180", *args]
        start = time.monotonic()
        p = subprocess.run(bounded, stdin=subprocess.DEVNULL, capture_output=True, timeout=190)
        for stream in ["stdout", "stderr"]:
            (logs / f"{label}.{stream}").write_bytes(getattr(p, stream))
        (logs / f"{label}.status").write_text(str(p.returncode) + "\n")
        return p, dict(command=bounded, status=p.returncode, seconds=round(time.monotonic() - start, 3))

    bound = targets + sorted(Path("CyberkrillTests").glob("*.lean")) + [Path(p) for p in [
        "CyberkrillTests.lean", "test/regressions.py", "test/record-regressions.py",
        "test/refresh-regressions.py", "test/output-regressions.py", "test/golden/regression-record.json"]]
    def fingerprints():
        return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound}
    hashes = fingerprints()
    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    records = []
    print("historical production reintroductions: 9/9", flush=True)
    try:
        for name, relative, old, new, assertion in edits():
            path = Path(relative)
            source = originals[path].decode()
            assert source.count(old) == 1, "unique regression target: " + name
            args = ["python3", "-B", "test/regressions.py", name]
            try:
                write(path, source.replace(old, new, 1).encode())
                compiled, compilation = command(name + "-build", build)
                assert compiled.returncode == 0, "reintroduced regression must compile: " + name
                p, red = command(name + "-red", args)
                assert p.returncode == 1 and assertion in p.stderr.decode() and "AssertionError:" in p.stderr.decode(), "regression detecting assertion: " + name
            finally:
                write(path, originals[path])
            p, restored = command(name + "-restore-build", build)
            assert p.returncode == 0, "restored compilation: " + name
            p, green = command(name + "-green", args)
            assert p.returncode == 0, "restored regression: " + name
            records.append(dict(property=name, file=relative, replace=old, with_text=new,
                                build=compilation, red=red, restore_build=restored, green=green,
                                detecting_assertion=assertion))
            print(f"{name}: runtime red 1 ({assertion}); restored green 0", flush=True)
        p, final = command("final-ten", ["python3", "-B", "test/regressions.py"])
        assert p.returncode == 0, "all ten final regression checks"
        assert fingerprints() == hashes, "regression sources restored exactly"
        Path("test/golden/regression-refresh.json").write_text(json.dumps(dict(
            source_sha256=hashes, count=9, reintroductions=records, restored_all=final), indent=2) + "\n")
        print("current regression evidence: 9/9 runtime reds; 10/10 final greens", flush=True)
    finally:
        restore()


if __name__ == "__main__":
    main()
