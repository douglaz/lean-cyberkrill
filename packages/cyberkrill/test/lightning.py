#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Actual offline CLI/FFI, exact builder goldens and narrow parity exceptions."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cases import APP, ROOT
from compare import exact_json

CASES = importlib.import_module("lightning-cases")
COMPARE = importlib.import_module("lightning-compare")
EXE = APP / ".lake/build/bin/cyberkrill"


def captures():
    rows = json.loads((APP / "test/golden/lightning-reference.json").read_bytes())
    assert len(rows) == 339 and len({r['id'] for r in rows}) == 339, "Lightning capture count"
    original = CASES.inventory()
    assert [{k: v for k, v in r.items() if k not in ["result", "seconds", "encoding_applicability"]}
            for r in rows[:149]] == original, "Lightning source inventory"
    assert [r for r in rows if r["id"].startswith("builder/")] == [
        {**case, "result": r["result"], "seconds": r["seconds"]}
        for case, r in zip(CASES.builder_cases(rows), rows[166:200])], "builder capture construction"
    assert [{k: v for k, v in r.items() if k not in ["result", "seconds"]} for r in rows[200:]] == CASES.json_cases(rows)
    provenance = json.loads((APP / "test/golden/lightning-provenance.json").read_bytes())
    assert provenance["counts"] == dict(bolt11=57, lnurl=92, spec=31, encoded_spec=17, builder=34, json=139, routing=18, total=357)
    assert provenance["build_status"] == 0
    for path, expected in provenance["sha256"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, "stale Lightning capture: " + path
    print("BOLT11 inventory: valid 16, invalid 15, negative 20, positive 4, nfields 2; 57/57")
    print("LNURL inventory: supported 35, refusal 13, error 23, positive 8, negative 12, reference 1; 92/92")
    print("Lightning reference captures: 339/339 (149 decode, 17 spec encode, 34 builder, 139 JSON)")
    return rows


def run(args, payload=None, cwd=APP, **kw):
    p = subprocess.run([str(EXE), *args], cwd=cwd,
                       input=payload.encode() if isinstance(payload, str) else payload,
                       stdin=subprocess.DEVNULL if payload is None else None,
                       capture_output=True, timeout=20, **kw)
    return dict(status=p.returncode, stdout=p.stdout.decode(), stderr=p.stderr.decode())


def refuse(result, error, name):
    assert result["status"] == 1, name + " status"
    assert result["stdout"] == "", name + " stdout"
    assert result["stderr"] and (not error or result["stderr"].startswith(error + ":")), name + " diagnostic"
    assert CASES.SPEC_KEY not in result["stderr"] and "Traceback" not in result["stderr"], name + " privacy"


def goldens(rows, only=None):
    comparator = COMPARE.LightningComparator(rows)
    selected = [r for r in rows if only is None or r["id"] == only]
    assert selected, "Lightning selected case"
    for row in selected:
        args = [CASES.SPEC_KEY if arg == "{published_key}" else arg for arg in row["args"]]
        port = run(args, row.get("input"))
        comparator.compare(row, row["result"], port)
    if only is None: comparator.finish()
    # Signing an explicit n different from the signing key must succeed; a
    # subsequent actual FFI verification must refuse that signed invoice.
    if only in [None, "builder/explicit-n-mismatch"]:
        row = next(r for r in rows if r["id"] == "builder/explicit-n-mismatch")
        refuse(run(["ln-decode-invoice", row["result"]["stdout"].removesuffix("\n")]),
               "verifyFailed", "explicit n later verification")
    print(f"Lightning executable goldens: {len(selected)}/{len(selected)}")


def routing(rows):
    by_id = {r['id']: r for r in rows}
    base = by_id["valid/L410"]
    encoded = by_id["encode/valid/L410"]["result"]["stdout"]
    payload = base["result"]["stdout"]
    url = by_id["lnurl-reference/cyberkrill"]
    home = Path(tempfile.mkdtemp(prefix="lightning-io-", dir=os.environ["TMPDIR"]))
    created = []
    checks = 0

    def file(name, data):
        path = home / name
        path.write_bytes(data); created.append(path)
        return path

    try:
        for row in [base, url]:
            command, literal = row["args"]
            assert exact_json(run([command], literal)["stdout"]) == exact_json(row["result"]["stdout"]), "decoder EOF stdin"
            checks += 1
            newline = run([command], literal + "\n")
            if command == "ln-decode-lnurl":
                assert newline["status"] == 0 and newline["stderr"] == "", "LNURL trimmed stdin"
                assert exact_json(newline["stdout"]) == exact_json(row["result"]["stdout"]), "LNURL newline value"
            else:
                refuse(newline, "", "invoice untrimmed stdin")
            checks += 1
            refuse(run([command, "-"], literal), "", "decoder literal dash"); checks += 1
            assert run([command, "--", literal])["status"] == 0, "decoder option terminator"
            checks += 1
        input_file = file("in=é.json", payload.encode())
        for args, stdin in [(["ln-encode-invoice", "-k", CASES.SPEC_KEY], payload),
                            (["ln-encode-invoice", "-", "--private-key=" + CASES.SPEC_KEY], payload + "\n"),
                            (["ln-encode-invoice", str(input_file), "-k" + CASES.SPEC_KEY], None)]:
            assert run(args, stdin) == dict(status=0, stdout=encoded, stderr=""), "encoder input routing"
            checks += 1
        utf8 = json.loads(payload); utf8["description"] = "é coffee"
        expected_utf8 = by_id["builder/description-first"]["result"]["stdout"]
        input_file.write_text(json.dumps(utf8, ensure_ascii=False), encoding="utf-8")
        assert run(["ln-encode-invoice", str(input_file), "-k", CASES.SPEC_KEY])["stdout"] == expected_utf8, "UTF-8 JSON file"
        checks += 1
        dash_file = file("-input=é.json", payload.encode())
        assert run(["ln-encode-invoice", "-k", CASES.SPEC_KEY, "--", dash_file.name], cwd=home) == dict(
            status=0, stdout=encoded, stderr=""), "encoder option terminator filename"
        checks += 1
        for row in [base, url, by_id["encode/valid/L410"]]:
            args = [CASES.SPEC_KEY if a == "{published_key}" else a for a in row["args"]]
            expected = run(args, row.get("input"))["stdout"].removesuffix("\n")
            for i, option in enumerate([["-o", "out=one"], ["--output", "out=two"], ["-oout=three"],
                                        ["-o=-out=four"], ["--output=-out=five"], ["-o", "-"]]):
                name = ["out=one", "out=two", "out=three", "-out=four", "-out=five", "-"][i]
                path = home / name
                if path not in created: file(name, b"old output")
                output = run([*args, *option], row.get("input"), cwd=home)
                assert output == dict(status=0, stdout="", stderr=""), "ordinary output status/streams"
                assert path.read_bytes() == expected.encode(), "ordinary output overwrite exact bytes"
                checks += 1
        for command in ["ln-decode-invoice", "ln-decode-lnurl", "ln-encode-invoice"]:
            help_result = run([command, "--help"])
            assert help_result["status"] == 0 and help_result["stderr"] == "" and "--output" in help_result["stdout"], "Lightning command help"
            checks += 1
            for tail in [["extra", "extra"], ["--fee", "15sats"], ["--unknown"], ["-o"],
                         ["-o", "--help"], ["--output=a", "-o", "b"]]:
                refuse(run([command, *tail]), "invalidArguments", "Lightning parser boundary"); checks += 1
        for tail in [[], ["-k"], ["-k", "--help"], ["-k", CASES.SPEC_KEY, "--private-key", CASES.SPEC_KEY]]:
            refuse(run(["ln-encode-invoice", *tail], payload), "invalidArguments", "required/duplicate signing option"); checks += 1
        for key in ["zz", "0", "", "00" * 32, format(2**256-1, "064x")]:
            refuse(run(["ln-encode-invoice", "-k=" + key], payload), "badPrivateKey", "invalid signing key"); checks += 1
        for name in ["absent.json", "."]:
            refuse(run(["ln-encode-invoice", name, "-k", CASES.SPEC_KEY], cwd=home), "inputFailure", "JSON file read failure"); checks += 1
        invalid_utf8 = file("invalid.json", b"\xff")
        refuse(run(["ln-encode-invoice", str(invalid_utf8), "-k", CASES.SPEC_KEY]), "inputFailure", "UTF-8 file refusal"); checks += 1
        for command in ["ln-decode-invoice", "ln-decode-lnurl", "ln-encode-invoice"]:
            args = [command] + (["-k", CASES.SPEC_KEY] if command == "ln-encode-invoice" else [])
            refuse(run(args, b"\xff"), "inputFailure", "UTF-8 stdin refusal"); checks += 1
        fd = os.open(home, os.O_RDONLY)
        try:
            p = subprocess.run([str(EXE), "ln-decode-invoice"], stdin=fd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=20)
        finally:
            os.close(fd)
        refuse(dict(status=p.returncode, stdout=p.stdout.decode(), stderr=p.stderr.decode()),
               "inputFailure", "stdin read failure")
        checks += 1
        full_path = home / "full-output"
        full_path.symlink_to("/dev/full"); created.append(full_path)
        refuse(run([*base["args"], "-o", str(full_path)]), "outputFailure", "ordinary write failure")
        checks += 1
        for destination in [str(home), str(home / "missing/out")]:
            refuse(run([*base["args"], "-o", destination]), "outputFailure", "ordinary file error"); checks += 1
        with open("/dev/full", "wb") as full:
            p = subprocess.run([str(EXE), *base["args"]], stdout=full, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, timeout=20)
        assert p.returncode == 1 and p.stderr.startswith(b"outputFailure:"), "Lightning stdout write failure"
        checks += 1
    finally:
        for path in created: path.unlink()
        home.rmdir()
    assert checks == 72, "Lightning routing check count"
    print("Lightning routing/parser/IO checks: 72/72")


def routing_goldens(rows):
    captures = json.loads((APP / "test/golden/lightning-routing-reference.json").read_bytes())
    assert len(captures) == 18
    assert [{k: v for k, v in r.items() if k not in ["result", "seconds", "output_bytes"]}
            for r in captures] == CASES.routing_cases(rows), "routing reference inventory"
    home = Path(tempfile.mkdtemp(prefix="lightning-routing-", dir=os.environ["TMPDIR"]))
    try:
        for row in captures:
            paths = set(row["files"]) | set(row["outputs"])
            try:
                for name, value in row["files"].items(): (home / name).write_text(value, encoding="utf-8")
                args = [CASES.SPEC_KEY if a == "{published_key}" else a for a in row["args"]]
                actual = run(args, row.get("input"), cwd=home)
                mode = "failure" if row["result"]["status"] else "scalar" if args[0] == "ln-encode-invoice" else "json"
                # File-only success has empty stdout on both implementations.
                if row["outputs"]:
                    if row["result"]["status"]:
                        refuse(actual, row.get("error", ""), "routing golden failure")
                    else:
                        assert actual == row["result"] == dict(status=0, stdout="", stderr=""), "routing golden streams"
                    for name, hex_bytes in row["output_bytes"].items():
                        if hex_bytes is None:
                            assert not (home / name).exists(), "routing failed output absent"
                            continue
                        data = (home / name).read_bytes()
                        reference = bytes.fromhex(hex_bytes)
                        if row["result"]["status"] or args[0] == "ln-encode-invoice":
                            assert data == reference, "routing golden invoice file bytes"
                        else:
                            assert exact_json(data) == exact_json(reference), "routing golden JSON file"
                            assert data.endswith(b"\n") == reference.endswith(b"\n") == False, "routing golden file newline"
                else:
                    from compare import Comparator
                    Comparator().compare(dict(id=row["id"], mode=mode), row["result"], actual)
            finally:
                for name in paths:
                    path = home / name
                    if path.exists(): path.unlink()
    finally:
        home.rmdir()
    print("Lightning reference routing captures: 18/18; total reference captures: 357/357")


def main():
    global EXE
    if sys.argv[1:] == ["--installed"]:
        EXE = ROOT / "result/bin/cyberkrill"
        rows = captures()
        for name in ["valid/L410", "valid/L516", "lnurl-reference/cyberkrill", "encode/valid/L410", "builder/amount-0"]:
            goldens(rows, name)
        print("installed Lightning exact commands: 5/5")
        return
    rows = captures()
    if sys.argv[1:] == ["--selftest"]: COMPARE.selftest(rows)
    elif sys.argv[1:] == ["--routing"]: routing(rows); routing_goldens(rows)
    elif len(sys.argv) == 3 and sys.argv[1] == "--case": goldens(rows, sys.argv[2])
    else:
        assert not sys.argv[1:]
        COMPARE.selftest(rows); goldens(rows); routing(rows); routing_goldens(rows)


if __name__ == "__main__":
    main()
