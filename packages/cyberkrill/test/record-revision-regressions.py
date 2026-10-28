#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Record independent unfixed regression failures and passing controls once."""
import hashlib
import json
import subprocess
import time

from cases import APP
import revisions


def main():
    target = APP / "test/golden/revision-regression-record.json"
    assert not target.exists(), "preserve the original regression observations"
    rows = revisions.captures()
    checks = [(r["id"], ["--case", r["id"]]) for r in rows]
    checks += [("scope/" + name, ["--scope", name]) for name in revisions.SCOPE_CASES]
    logs = APP / ".lake/revision-regressions"
    logs.mkdir(parents=True, exist_ok=True)
    records = []
    for i, (name, args) in enumerate(checks):
        command = ["timeout", "--foreground", "30", "python3", "-B", "test/revisions.py", *args]
        start = time.monotonic()
        proc = subprocess.run(command, cwd=APP, stdin=subprocess.DEVNULL, capture_output=True, timeout=35)
        for stream in ["stdout", "stderr"]: (logs / f"{i}.{stream}").write_bytes(getattr(proc, stream))
        assert proc.returncode in [0, 1], name + " baseline execution"
        failure = proc.stderr.decode().splitlines()[-1] if proc.stderr else ""
        assert proc.returncode == 0 or failure.startswith("AssertionError:"), name + " baseline assertion"
        records.append(dict(property=name, command=command, status=proc.returncode,
                            stdout=proc.stdout.decode(), stderr_sha256=hashlib.sha256(proc.stderr).hexdigest(),
                            assertion=failure, seconds=round(time.monotonic() - start, 3)))
    bound = [APP / p for p in ["Cyberkrill/App.lean", "Cyberkrill/Lightning.lean", "Cyberkrill/InvoiceJson.lean",
                               "test/scope.py", "test/revisions.py", "test/revision-cases.py", "test/record-revision-regressions.py",
                               "test/golden/revision-reference.json", "test/golden/revision-provenance.json"]]
    record = dict(count=len(records), reds=sum(r["status"] == 1 for r in records),
                  source_sha256={str(p.relative_to(APP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound}, checks=records)
    target.write_text(json.dumps(record, indent=2) + "\n")
    print(f"unfixed revision regressions: {record['reds']} assertion failures; {len(records)-record['reds']} passing controls")
    for row in records:
        if row["status"]: print(row["property"], row["assertion"])


if __name__ == "__main__": main()
