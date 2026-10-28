#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Check that capture/mutation evidence still belongs to the current sources."""
import hashlib
import json
from pathlib import Path
import sys

from cases import APP, BUILD, PIN, cases
from driver import fixtures


def main():
    fixtures()
    captured = json.loads((APP / "test/golden/reference.json").read_text())
    assert [{k: v for k, v in row.items() if k != "result"} for row in captured] == cases()
    provenance = json.loads((APP / "test/golden/provenance.json").read_text())
    assert provenance["build"] == BUILD and provenance["commit"] == PIN
    assert provenance["build_status"] == 0 and provenance["cases"] == 179
    captures = json.loads((APP / "test/golden/capture-digests.json").read_text())
    assert len(captures) == 4
    for relative, expected in captures.items():
        assert hashlib.sha256((APP / relative).read_bytes()).hexdigest() == expected, "stale capture: " + relative
    print("bound capture files: 4/4; captures: 179/179")
    regression = json.loads((APP / "test/golden/regression-record.json").read_text())
    before, after = regression["before"], regression["after"]
    assert before["tests_sha256"] == after["tests_sha256"]
    assert len(before["checks"]) == len(after["checks"]) == 10
    for red, green in zip(before["checks"], after["checks"]):
        assert red["property"] == green["property"] and red["command"] == green["command"]
        assert red["status"] == (0 if red["property"] == "delimited-negative-zero" else 1)
        assert green["status"] == 0
        assert red["status"] == 0 or red["detecting_assertion"]
    print("historical regression evidence: 9/9 runtime reds; 10/10 former greens")
    # The original observations stay byte-for-byte historical. Current tests
    # have independent production reintroductions, never substituted hashes.
    refreshed = json.loads((APP / "test/golden/regression-refresh.json").read_text())
    for relative, expected in refreshed["source_sha256"].items():
        assert hashlib.sha256((APP / relative).read_bytes()).hexdigest() == expected, "stale refreshed regression: " + relative
    assert refreshed["count"] == len(refreshed["reintroductions"]) == 9
    from importlib import import_module
    refresh_edits = import_module("refresh-regressions").edits()
    for row, (name, path, old, new, assertion) in zip(refreshed["reintroductions"], refresh_edits):
        assert (row["property"], row["file"], row["replace"], row["with_text"], row["detecting_assertion"]) == (name, path, old, new, assertion)
        assert row["build"]["status"] == row["restore_build"]["status"] == row["green"]["status"] == 0
        assert row["red"]["status"] == 1
        assert row["red"]["command"] == row["green"]["command"]
    assert refreshed["restored_all"]["status"] == 0
    print("current regression evidence: 9/9 reintroduced runtime reds; 10/10 final greens")
    output = json.loads((APP / "test/golden/output-regression-record.json").read_text())
    before_output, after_output = output["before"], output["after"]
    assert before_output["tests_sha256"] == after_output["tests_sha256"]
    output_args = import_module("output-regressions").ARGS
    assert len(before_output["checks"]) == len(after_output["checks"]) == len(output_args) == 18
    for i, (red, green, args) in enumerate(zip(before_output["checks"], after_output["checks"], output_args)):
        assert red["case"] == green["case"] == i and red["args"] == green["args"] == args
        assert red["command"] == green["command"] == ["timeout", "--foreground", "30", ".lake/build/bin/CyberkrillTests", "--output-refusal", str(i)]
        assert red["status"] == 1 and green["status"] == 0
        assert red["detecting_assertion"] == f"output refusal {i} status" and green["detecting_assertion"] == ""
    print("historical output evidence: 18/18 runtime reds; 18/18 former greens")
    output_refresh = json.loads((APP / "test/golden/output-regression-refresh.json").read_text())
    for relative, expected in output_refresh["source_sha256"].items():
        assert hashlib.sha256((APP / relative).read_bytes()).hexdigest() == expected, "stale refreshed output: " + relative
    assert output_refresh["file"] == "Cyberkrill/App.lean"
    assert output_refresh["replace"] == "unless outputArgsValid args.tail do throw .invalidArguments"
    assert output_refresh["with_text"] == "pure ()"
    assert output_refresh["build"]["status"] == output_refresh["restore_build"]["status"] == 0
    assert output_refresh["restored_all"]["status"] == 0
    assert len(output_refresh["checks"]) == 18
    for i, (row, args) in enumerate(zip(output_refresh["checks"], output_args)):
        assert row["case"] == i and row["args"] == args
        assert row["detecting_assertion"] == f"output refusal {i} status"
        assert row["red"]["status"] == 1 and row["green"]["status"] == 0
        assert row["red"]["command"] == row["green"]["command"] == ["timeout", "--foreground", "180", ".lake/build/bin/CyberkrillTests", "--output-refusal", str(i)]
    print("current output evidence: 18/18 reintroduced reds; 18/18 restored greens")
    attached = json.loads((APP / "test/golden/attached-output-regression-record.json").read_text())
    before_attached, after_attached = attached["before"], attached["after"]
    assert before_attached["tests_sha256"] == after_attached["tests_sha256"]
    attached_cases = import_module("attached-output-regressions").CASES
    assert len(before_attached["checks"]) == len(after_attached["checks"]) == len(attached_cases) == 8
    for i, (red, green, token) in enumerate(zip(before_attached["checks"], after_attached["checks"], attached_cases)):
        assert red["case"] == green["case"] == i and red["token"] == green["token"] == token
        assert red["command"] == green["command"] == ["timeout", "--foreground", "30", ".lake/build/bin/CyberkrillTests", "--output-equals", str(i)]
        assert red["status"] == (1 if i < 4 else 0) and green["status"] == 0
        assert red["detecting_assertion"] == (f"output equals {i} status" if i < 4 else "")
        assert green["detecting_assertion"] == ""
    print("historical attached output: 4/4 runtime reds; 4/4 controls; 8/8 former greens")
    attached_refresh = json.loads((APP / "test/golden/attached-output-refresh.json").read_bytes())
    for relative, expected in attached_refresh["source_sha256"].items():
        assert hashlib.sha256((APP / relative).read_bytes()).hexdigest() == expected, "stale attached refresh: " + relative
    assert attached_refresh["build"]["status"] == attached_refresh["restore_build"]["status"] == 0
    assert len(attached_refresh["checks"]) == 8
    for i, row in enumerate(attached_refresh["checks"]):
        assert row["token"] == attached_cases[i] and row["case"] == i
        assert row["red"]["status"] == (1 if i < 4 else 0) and row["green"]["status"] == 0
        assert row["red"]["command"] == row["green"]["command"]
        assert row["detecting_assertion"] == (f"output equals {i} status" if i < 4 else "")
    print("current attached output: 4/4 runtime reds; 4/4 controls; 8/8 restored greens")
    private = json.loads((APP / "test/golden/private-output-reference.json").read_bytes())
    provenance = private["provenance"]
    assert provenance["commit"] == PIN and provenance["build"] == BUILD and provenance["build_status"] == 0
    for relative, expected in provenance["script_sha256"].items():
        assert hashlib.sha256((APP / relative).read_bytes()).hexdigest() == expected, "stale private reference: " + relative
    assert hashlib.sha256((APP.parents[1] / provenance["fixture"]).read_bytes()).hexdigest() == provenance["fixture_sha256"]
    assert len(private["cases"]) == 5
    for row in private["cases"]:
        assert row["reference"] == dict(status=0, stdout="", stderr="")
        a, b = row["repetitions"]
        assert a == b and a["status"] == 0 and 32 in a["getrandom_sizes"]
    print("private output captures: 5/5, each repeated with controlled public entropy")
    record = json.loads((APP / "test/golden/mutation-record.json").read_text())
    assert record["count"] == len(record["mutations"]) == 26
    assert len({m["property"] for m in record["mutations"]}) == 26
    assert len({(m["file"], m["replace"], m["with_text"]) for m in record["mutations"]}) == 26
    for relative, expected in record["source_sha256"].items():
        assert hashlib.sha256((APP / relative).read_bytes()).hexdigest() == expected, "stale mutation evidence: " + relative
    for mutation in record["mutations"]:
        assert mutation["status"] == 1 and mutation["restored_status"] == mutation["build_status"] == 0
        assert mutation["replace"] != mutation["with_text"] and mutation["detecting_assertion"]
    assert record["restored_full"]["status"] == 0
    print("bound production mutations: 26/26 distinct edits; restored suite: exit 0")
    lightning = import_module("lightning")
    lightning.captures()
    import_module("lightning-mutate").verify()
    revision = import_module("revisions")
    revision.captures()
    baseline_path = APP / "test/golden/revision-regression-record.json"
    assert hashlib.sha256(baseline_path.read_bytes()).hexdigest() == "60c8074b198e76e211b17deb1cfcec57fc644b0aa1f184356dd846698d135379", "historical revision observations changed"
    baseline = json.loads(baseline_path.read_bytes())
    assert baseline["count"] == len(baseline["checks"]) == 183 and baseline["reds"] == 61
    assert sum(r["status"] == 1 for r in baseline["checks"]) == 61
    for row in baseline["checks"]:
        assert row["status"] in [0, 1] and len(row["stderr_sha256"]) == 64
        assert row["status"] == 0 or row["assertion"].startswith("AssertionError:")
    print("historical revision regressions: 61 assertion failures; 122 passing controls; fixed digest retained")
    import_module("revision-mutate").verify()
    l814 = json.loads((APP / "test/golden/l814-reference.json").read_bytes())
    l814_provenance = json.loads((APP / "test/golden/l814-provenance.json").read_bytes())
    assert l814["id"] == "invalid/L814" and l814["result"]["status"] == 0 and l814["result"]["stderr"] == ""
    assert l814_provenance["commit"] == PIN and l814_provenance["build"] == BUILD and l814_provenance["build_status"] == 0
    assert l814_provenance["script_sha256"] == hashlib.sha256((APP / "test/capture-l814.py").read_bytes()).hexdigest()
    assert l814_provenance["record_sha256"] == hashlib.sha256((APP / "test/golden/l814-reference.json").read_bytes()).hexdigest()
    assert l814["source_sha256"] == hashlib.sha256((APP.parents[1] / l814["source"]).read_bytes()).hexdigest()
    assert json.loads(l814["result"]["stdout"])["destination"] == lightning.COMPARE.PAYEE
    planned = [r for module in ["mutate", "lightning-mutate", "revision-mutate"] for r in import_module(module).mutations()]
    assert len({tuple(r[1:4]) for r in planned}) == 85, "combined distinct production edits"
    print("L814 early stop gate: observed acceptance, exit 0, empty stderr; production edits: 85 distinct including historical 26")
    # The README must mirror every exact pin, including its output field/stream.
    readme = (APP.parents[1] / "README.md").read_text()
    section = readme.split("## Exact amounts vs cyberkrill\n", 1)[1].split("### Phase 7a checks", 1)[0]
    entries = json.loads((APP / "test/golden/exact-amount-diffs.json").read_text())
    rows = [line for line in section.splitlines() if line.startswith("| ")][1:]
    assert len(rows) == len(entries) == 20, "README amount row count"
    for e, row in zip(entries, rows):
        assert row.startswith(f"| {e['case']} | {e['field']} |"), "README amount row identity"
        for side in ["reference", "port"]:
            value = e[side].replace("\n", "\\n") or "empty"
            assert value in row, "README amount pin: " + e['case']
    print("README exact pins: 20/20")


if __name__ == "__main__":
    main()
