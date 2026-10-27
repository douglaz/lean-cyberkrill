# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Deterministic authored CLI cases; no mnemonic success invokes OS entropy."""
import json
from pathlib import Path

APP = Path(__file__).resolve().parents[1]
ROOT = APP.parents[1]
PIN = "27cad1faba86260b06665a89f0af5134d23525c2"
BUILD = ["nix", "build", "--no-link", "--print-out-paths", "--max-jobs", "2",
         "--cores", "4", f"github:douglaz/cyberkrill/{PIN}"]
WORD_COUNT_FAILURES = ["1_2", "1_5", "1_8", "2_1", "2_4", "+13", "1_3", "4294967296"]


def cases():
    source = json.loads((ROOT / "packages/bitcoin/test-data/cli.json").read_text())
    assert len(source) == 124
    result = [{"id": "version", "args": ["version"], "mode": "version"}]
    for row in source:
        args = ["convert-amount", "--", row["input"]]
        item = {"id": row["name"], "args": args, "mode": "json"}
        if row["msat"] is None:
            item["mode"] = "failure"
            if row.get("delta"):
                item["error"] = "subMillisatoshi" if row["delta"] == "sub-msat" else "invalidNumber"
        result.append(item)
    for name, value in [("fractional-sat", "1.5sat"), ("fractional-1499", "1499msat"),
                        ("fractional-500", "500msat"), ("fractional-001", "0.001sat"),
                        ("fractional-1", "1msat"), ("fractional-1999", "1999msat"),
                        ("large-exact", "20999999.99999999999")]:
        for mode in [None, "btc", "sats", "msats"]:
            args = ["convert-amount", value] + (["--as", mode] if mode else [])
            result.append({"id": f"{name}-{mode or 'json'}", "args": args,
                           "mode": "scalar" if mode else "json"})
    invalid = [
        ["convert-amount"], ["convert-amount", "1", "2"],
        ["convert-amount", "1", "--as", "sat"], ["convert-amount", "1", "--as"],
        ["convert-amount", "1", "--as", "btc", "--as", "sats"],
        ["convert-amount", "1", "--output", "unused"], ["version", "extra"],
        ["version", "--output", "unused"], ["unknown"], ["ln-decode-invoice"],
        ["--electrum", "unused"], ["generate-mnemonic", "-w", "11"],
        ["generate-mnemonic", "-w", "bad"], ["generate-mnemonic", "--seed", "unused"],
        ["generate-mnemonic", "-w", "12", "--words", "24"],
    ]
    for i, args in enumerate(invalid):
        result.append({"id": f"parser-{i:02}", "args": args, "mode": "failure"})
    for i, value in enumerate(["-0", "-0.0btc", "-0.000sat"]):
        result.append({"id": f"bare-negative-zero-{i}", "args": ["convert-amount", value], "mode": "failure"})
    for i, value in enumerate(WORD_COUNT_FAILURES):
        result.append({"id": f"word-count-{i}", "args": ["generate-mnemonic", "-w", value], "mode": "failure"})
    assert len(result) == 179 and len({r['id'] for r in result}) == 179
    return result
