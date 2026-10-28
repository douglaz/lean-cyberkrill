#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independently selectable parser, byte-capture and leaf-identity regressions."""
import json
import sys

from compare import Comparator, differences, exact_json
from driver import EXE, TEST, mnemonic, run


def word_counts():
    p = run([str(TEST), "--word-count-rejections"])
    assert p["status"] == 0, "word-count rejection before entropy: " + p["stderr"]
    print(p["stdout"], end="")


def negative_zero(delimited):
    values = ["-0", "-0.0btc", "-0.000sat"]
    print(f"{'delimited' if delimited else 'bare'} negative-zero cases: {len(values)}/3", flush=True)
    assert len(values) == 3
    for i, value in enumerate(values):
        p = run([str(EXE), "convert-amount", *(["--"] if delimited else []), value])
        if delimited:
            assert p["status"] == 0 and p["stderr"] == "", f"delimited negative-zero accepted {i}"
            assert exact_json(p["stdout"]) == dict(input=value, btc=0, sats=0, msats=0), f"delimited negative-zero exact input {i}"
        else:
            assert p["status"] == 1 and p["stdout"] == "" and p["stderr"].startswith("invalidArguments:"), f"bare negative-zero refused {i}"


def line_endings(stream, ending):
    data = b"1" + ending
    p = run([sys.executable, "-I", "-c", f"import os; os.write({1 if stream == 'stdout' else 2}, {data!r})"])
    label = f"subprocess {stream} {'CRLF' if ending == bytes([13, 10]) else 'CR'} preserved"
    assert p == dict(status=0, stdout=data.decode() if stream == "stdout" else "",
                     stderr=data.decode() if stream == "stderr" else ""), label
    ref = dict(p, **{stream: "1\n"})
    try:
        c = Comparator()
        c.compare(dict(id="synthetic-line-endings", mode="scalar"), ref, p)
        c.finish()
    except AssertionError as e:
        assert "unlisted difference" in str(e), label + " comparison assertion"
    else:
        raise AssertionError(label + " exact comparison refused")


def collision(kind):
    reference, single, both = (
        ({"a": {"b": 1}, "a.b": 1}, {"a": {"b": 2}, "a.b": 1}, {"a": {"b": 2}, "a.b": 2})
        if kind == "dotted" else
        ({"a": [1], "a[0]": 1}, {"a": [2], "a[0]": 1}, {"a": [2], "a[0]": 2}))
    # Identify exactly the first changed leaf, using the comparator's public path encoding.
    field, _, _ = differences(exact_json(json.dumps(reference)), exact_json(json.dumps(single)))[0]
    case = dict(id="synthetic-collision", mode="json")
    entry = dict(case=case["id"], field=field, kind="number", reference="1", port="2")
    def compared(value):
        c = Comparator([entry])
        c.compare(case, dict(status=0, stdout=json.dumps(reference), stderr=""),
                  dict(status=0, stdout=json.dumps(value), stderr=""))
        c.finish()
    compared(single)
    try:
        compared(both)
    except AssertionError as e:
        assert "unlisted difference" in str(e), kind + " collision detecting assertion"
    else:
        raise AssertionError(kind + " leaf collision refused")


CHECKS = {
    "word-count-rejections": word_counts,
    "word-count-plus": lambda: mnemonic(plus=True),
    "bare-negative-zero": lambda: negative_zero(False),
    "delimited-negative-zero": lambda: negative_zero(True),
    "stdout-crlf": lambda: line_endings("stdout", b"\r\n"),
    "stdout-cr": lambda: line_endings("stdout", b"\r"),
    "stderr-crlf": lambda: line_endings("stderr", b"\r\n"),
    "stderr-cr": lambda: line_endings("stderr", b"\r"),
    "dotted-collision": lambda: collision("dotted"),
    "bracket-collision": lambda: collision("bracket"),
}


def main():
    names = sys.argv[1:] or list(CHECKS)
    for name in names:
        CHECKS[name]()
        print(f"regression {name}: passed", flush=True)
    print(f"regression properties: {len(names)}/{len(names)}", flush=True)


if __name__ == "__main__":
    main()
